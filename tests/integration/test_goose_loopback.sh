#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
#
# GOOSE Loopback Integration Test
#
# Creates a veth pair, builds and runs the GOOSE loopback test binary
# to verify end-to-end GOOSE message delivery via raw sockets.
#
# Requires: CAP_NET_ADMIN + CAP_NET_RAW (run as root or with sudo)
#
# Usage: sudo ./test_goose_loopback.sh [builddir]

set -euo pipefail

VETH0="goose_test0"
VETH1="goose_test1"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILDDIR="${1:-${PROJECT_DIR}/builddir}"

cleanup() {
    echo "Cleaning up..."
    ip link del "$VETH0" 2>/dev/null || true
}
trap cleanup EXIT

echo "=== GOOSE Loopback Integration Test ==="

# Check privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This test requires root privileges"
    echo "Run: sudo $0 [builddir]"
    exit 1
fi

# Build the loopback test binary
echo "Building goose_loopback..."
if ! ninja -C "$BUILDDIR" tests/goose_loopback 2>/dev/null; then
    echo "ERROR: Failed to build goose_loopback"
    echo "Make sure to run: meson setup $BUILDDIR && meson compile -C $BUILDDIR"
    exit 1
fi

BINARY="$BUILDDIR/tests/goose_loopback"
if [ ! -x "$BINARY" ]; then
    echo "ERROR: $BINARY not found or not executable"
    exit 1
fi

# Create veth pair
echo "Creating veth pair: $VETH0 <-> $VETH1"
ip link del "$VETH0" 2>/dev/null || true
ip link add "$VETH0" type veth peer name "$VETH1"
ip link set "$VETH0" up
ip link set "$VETH1" up

# Disable IPv6 to reduce noise
sysctl -q -w "net.ipv6.conf.${VETH0}.disable_ipv6=1" 2>/dev/null || true
sysctl -q -w "net.ipv6.conf.${VETH1}.disable_ipv6=1" 2>/dev/null || true

echo "Interfaces created and up"
echo ""

# Run the test binary
"$BINARY" "$VETH0" "$VETH1"
RET=$?

echo ""
if [ $RET -eq 0 ]; then
    echo "=== GOOSE Loopback Test PASSED ==="
else
    echo "=== GOOSE Loopback Test FAILED (exit code: $RET) ==="
fi

exit $RET
