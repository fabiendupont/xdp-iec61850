#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
#
# Run privileged integration tests (require root)
#
# Usage: sudo ./tests/integration/run_privileged_tests.sh [builddir]
#
# Runs packet_io_raw_veth and packet_io_xsk_veth tests,
# plus the existing GOOSE and SV loopback tests.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
BUILDDIR="${1:-${PROJECT_DIR}/builddir-full}"

if [ "$(id -u)" -ne 0 ]; then
    echo "ERROR: This script requires root privileges"
    echo "Run: sudo $0 [builddir]"
    exit 1
fi

FAILED=0

run_test() {
    local name="$1"
    local binary="$2"
    shift 2

    echo ""
    echo "=== $name ==="
    if [ ! -x "$binary" ]; then
        echo "SKIP: $binary not found (build with meson compile -C $BUILDDIR)"
        return
    fi
    if "$binary" "$@"; then
        echo "=== $name: PASSED ==="
    else
        echo "=== $name: FAILED ==="
        FAILED=1
    fi
}

echo "Privileged Integration Tests"
echo "Build dir: $BUILDDIR"

# IEC 61850 XDP graph (BPF node registration + dispatch)
run_test "IEC 61850 XDP graph" "$BUILDDIR/tests/test_iec61850_graph"

# Packet I/O tests (self-contained veth)
run_test "packet_io_raw + veth" "$BUILDDIR/tests/test_packet_io_raw_veth"
run_test "packet_io_xsk + veth" "$BUILDDIR/tests/test_packet_io_xsk_veth"

# GOOSE/SV loopback tests (need external veth)
VETH0="iec_lb0"
VETH1="iec_lb1"

cleanup() {
    ip link del "$VETH0" 2>/dev/null || true
}
trap cleanup EXIT

ip link del "$VETH0" 2>/dev/null || true
ip link add "$VETH0" type veth peer name "$VETH1"
ip link set "$VETH0" up
ip link set "$VETH1" up
sysctl -q -w "net.ipv6.conf.${VETH0}.disable_ipv6=1" 2>/dev/null || true
sysctl -q -w "net.ipv6.conf.${VETH1}.disable_ipv6=1" 2>/dev/null || true

run_test "GOOSE loopback" "$BUILDDIR/tests/goose_loopback" "$VETH0" "$VETH1"
run_test "SV loopback" "$BUILDDIR/tests/sv_loopback" "$VETH0" "$VETH1"

echo ""
if [ "$FAILED" -eq 0 ]; then
    echo "All privileged tests PASSED"
else
    echo "Some tests FAILED"
    exit 1
fi
