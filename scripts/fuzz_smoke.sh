#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
#
# fuzz_smoke.sh — short-burst fuzzing gate.
#
# Usage: fuzz_smoke.sh <build-dir>
#
# 1. Builds every fuzz target available in <build-dir> (targets from
#    disabled features are skipped).
# 2. Replays each committed corpus through its harness (deterministic
#    regression check — catches reintroduced crashes instantly).
# 3. Runs each harness's 10-second random-burst standalone mode.
#
# For full memory-safety coverage configure <build-dir> with
# -Db_sanitize=address (gcc; clang cannot compile the ebpf-graph-lib
# subproject with -Wpedantic -Werror).
#
# Exits 0 only if every replay and burst run completes without crash.

set -u

BUILDDIR=${1:?usage: fuzz_smoke.sh <build-dir>}
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

fail=0

# target -> corpus directory (empty: no corpus committed yet)
TARGETS=(
    "fuzz_goose_decoder:"
    "fuzz_sv_decoder:"
    "fuzz_goose_encoder:"
    "fuzz_mms_decoder:mms_decoder"
    "fuzz_iso_stack:iso_stack"
    "fuzz_scl_parser:scl_parser"
)

if ! ninja -C "$BUILDDIR" -t targets all >/dev/null 2>&1; then
    echo "FAIL  cannot enumerate targets in $BUILDDIR (broken build dir?)"
    exit 1
fi

for entry in "${TARGETS[@]}"; do
    target="${entry%%:*}"
    corpus="${entry#*:}"

    if ! ninja -C "$BUILDDIR" -t targets all 2>/dev/null | grep -q "tests/${target}:"; then
        echo "SKIP  ${target} (not built in this configuration)"
        continue
    fi

    if ! ninja -C "$BUILDDIR" "tests/$target" >/dev/null 2>&1; then
        echo "FAIL  ${target} (build error)"
        fail=1
        continue
    fi

    bin="$BUILDDIR/tests/$target"

    if [ -n "$corpus" ] && [ -d "$ROOT/tests/fuzz/corpora/$corpus" ]; then
        if ! "$bin" "$ROOT/tests/fuzz/corpora/$corpus" >/dev/null 2>&1; then
            echo "FAIL  ${target} (corpus replay crashed)"
            fail=1
            continue
        fi
        echo "OK    ${target} (corpus replay)"
    else
        echo "note  ${target} (no committed corpus; replay skipped)"
    fi

    if ! "$bin" >/dev/null 2>&1; then
        echo "FAIL  ${target} (random burst crashed)"
        fail=1
        continue
    fi
    echo "OK    ${target} (random burst)"
done

if [ "$fail" -ne 0 ]; then
    echo "fuzz smoke: FAILURES detected"
    exit 1
fi
echo "fuzz smoke: all targets clean"
