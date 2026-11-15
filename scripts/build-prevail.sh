#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
#
# build-prevail.sh — reproducible build of the PREVAIL eBPF verifier.
#
# The bytecode-level verification gate (prevail-check.sh) needs the
# `prevail` CLI binary from vbpf/prevail (abstract-interpretation
# eBPF verifier, PLDI 2020).  This script clones and builds it so
# the gate no longer depends on a transient binary left in /tmp by
# an earlier session.
#
# Usage: build-prevail.sh [dest-dir] [source-dir]
#   dest-dir   where to place the `prevail` binary
#              (default: <source-dir>/bin — upstream's own layout)
#   source-dir where to clone/keep the sources
#              (default: /tmp/opencode/prevail)
#
# Requirements: git, cmake, make, a C++20 compiler, and network
# access for the initial clone (submodules included).
#
# Validated: vbpf/prevail @ 8364e78 (Nov 9 2026) — builds with the
# default cmake make generator; the CLI target is `prevail-cli`,
# installed as bin/prevail.  Reproduced the gate result of the
# transient binary: 8 programs checked, 2 expected failures
# (scripts/prevail-expected-failures.txt).
#
# After building, run the gate with:
#   scripts/prevail-check.sh <dest-dir>/prevail <build-dir>

set -euo pipefail

DEST=${1:-}
SRC=${2:-/tmp/opencode/prevail}
REPO=https://github.com/vbpf/prevail

if [ -z "$DEST" ]; then
    DEST="$SRC/bin"
fi

need() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: $1 not found" >&2; exit 1; }; }
need git; need cmake; need make

if [ ! -d "$SRC/.git" ]; then
    echo "=== Cloning vbpf/prevail (with submodules) into $SRC ==="
    git clone --recurse-submodules "$REPO" "$SRC"
else
    echo "=== Using existing checkout at $SRC ==="
    git -C "$SRC" submodule update --init --recursive
fi

BUILD="$SRC/build"
echo "=== Configuring cmake build in $BUILD ==="
cmake -S "$SRC" -B "$BUILD" -DCMAKE_BUILD_TYPE=Release

echo "=== Building prevail-cli (output: <src>/bin/prevail) ==="
cmake --build "$BUILD" --target prevail-cli --parallel "$(nproc)"

# The prevail-cli target's OUTPUT_NAME is `prevail`, placed in the
# source tree's bin/ directory by CMake (RUNTIME_OUTPUT_DIRECTORY).
BIN="$SRC/bin/prevail"
if [ ! -x "$BIN" ]; then
    BIN="$(find "$BUILD" "$SRC/bin" -name prevail -type f -perm -u+x 2>/dev/null | head -1 || true)"
fi
[ -n "$BIN" ] && [ -x "$BIN" ] || { echo "ERROR: prevail binary not found" >&2; exit 1; }

mkdir -p "$DEST"
install -m 0755 "$BIN" "$DEST/prevail"
echo "=== Installed: $DEST/prevail ==="
"$DEST/prevail" --help 2>&1 | head -2 || true
echo "Gate: scripts/prevail-check.sh $DEST/prevail <build-dir>"
