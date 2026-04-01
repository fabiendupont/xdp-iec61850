#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
#
# test_sv_vm_e2e.sh — SV publisher/subscriber E2E via network namespaces
#
# Creates a network namespace with a veth pair, runs the SV loopback test
# binary inside it to verify end-to-end sample delivery with isolation.
#
# Requires: root (CAP_NET_ADMIN + CAP_NET_RAW)
# Usage: sudo ./test_sv_vm_e2e.sh [builddir]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=helpers.sh
source "$SCRIPT_DIR/helpers.sh"

BUILDDIR="${1:-$BUILDDIR}"

NS_TEST="iec-sv-test"
VETH_A="sv-veth0"
VETH_B="sv-veth1"

TMPDIR_TEST=""

cleanup() {
    echo "Cleaning up..."
    kill_bg_pids
    ip netns del "$NS_TEST" 2>/dev/null || true
    if [ -n "$TMPDIR_TEST" ] && [ -d "$TMPDIR_TEST" ]; then
        rm -rf "$TMPDIR_TEST"
    fi
}
trap cleanup EXIT

echo "=== SV VM E2E Test (netns isolation) ==="

check_root

SV_LOOPBACK="$(find_binary sv_loopback)"
echo "Binary: $SV_LOOPBACK"

TMPDIR_TEST="$(mktemp -d)"

# ---- Test 1: SV loopback inside namespace ----

test_start "sv loopback inside netns"

ip netns del "$NS_TEST" 2>/dev/null || true
ip netns add "$NS_TEST"
ip netns exec "$NS_TEST" ip link set lo up
ip netns exec "$NS_TEST" ip link add "$VETH_A" type veth peer name "$VETH_B"
ip netns exec "$NS_TEST" ip link set "$VETH_A" up
ip netns exec "$NS_TEST" ip link set "$VETH_B" up
ip netns exec "$NS_TEST" sysctl -q -w "net.ipv6.conf.${VETH_A}.disable_ipv6=1" 2>/dev/null || true
ip netns exec "$NS_TEST" sysctl -q -w "net.ipv6.conf.${VETH_B}.disable_ipv6=1" 2>/dev/null || true

OUTPUT="$TMPDIR_TEST/sv_loopback.out"
if ip netns exec "$NS_TEST" "$SV_LOOPBACK" "$VETH_A" "$VETH_B" > "$OUTPUT" 2>&1; then
    if grep -q "SV Loopback Test PASSED" "$OUTPUT"; then
        test_pass
    else
        test_fail "binary passed but output missing PASSED marker"
        cat "$OUTPUT"
    fi
else
    test_fail "exit code $?"
    cat "$OUTPUT"
fi

ip netns del "$NS_TEST" 2>/dev/null || true

# ---- Test 2: SV traffic isolation ----

test_start "sv namespace network isolation"

NS_A="iec-sv-a"
NS_B="iec-sv-b"
VETH_PA="sv-pa0"
VETH_PB="sv-pb0"

create_netns_pair "$NS_A" "$NS_B" "$VETH_PA" "$VETH_PB"

# Verify each namespace sees only its own interface
IF_A="$(ip netns exec "$NS_A" ip -o link show | grep -c "$VETH_PA" || true)"
IF_B_IN_A="$(ip netns exec "$NS_A" ip -o link show | grep -c "$VETH_PB" || true)"

if [ "$IF_A" -eq 1 ] && [ "$IF_B_IN_A" -eq 0 ]; then
    test_pass
else
    test_fail "namespace isolation broken (A sees $IF_A own, $IF_B_IN_A peer)"
fi

cleanup_netns "$NS_A" "$NS_B"

# ---- Test 3: SV sequential samples across namespace ----

test_start "sv sequential samples in isolated namespace"

ip netns del "$NS_TEST" 2>/dev/null || true
ip netns add "$NS_TEST"
ip netns exec "$NS_TEST" ip link set lo up
ip netns exec "$NS_TEST" ip link add "$VETH_A" type veth peer name "$VETH_B"
ip netns exec "$NS_TEST" ip link set "$VETH_A" up
ip netns exec "$NS_TEST" ip link set "$VETH_B" up
ip netns exec "$NS_TEST" sysctl -q -w "net.ipv6.conf.${VETH_A}.disable_ipv6=1" 2>/dev/null || true
ip netns exec "$NS_TEST" sysctl -q -w "net.ipv6.conf.${VETH_B}.disable_ipv6=1" 2>/dev/null || true

# Run the packet_io_raw_veth test which includes SV round-trip inside the namespace
PACKET_IO_TEST="$(find_binary test_packet_io_raw_veth)" || true
if [ -n "$PACKET_IO_TEST" ] && [ -x "$PACKET_IO_TEST" ]; then
    OUTPUT="$TMPDIR_TEST/sv_packet_io.out"
    if ip netns exec "$NS_TEST" "$PACKET_IO_TEST" > "$OUTPUT" 2>&1; then
        if grep -q "sv_roundtrip_veth" "$OUTPUT" && grep -q "PASS" "$OUTPUT"; then
            test_pass
        elif grep -q "SKIP" "$OUTPUT"; then
            echo "SKIP (nested veth in netns)"
        else
            test_fail "sv roundtrip not found in output"
            cat "$OUTPUT"
        fi
    else
        RET=$?
        if grep -q "SKIP" "$OUTPUT" 2>/dev/null || grep -q "skipped" "$OUTPUT" 2>/dev/null; then
            echo "SKIP (nested veth in netns)"
        else
            test_fail "exit code $RET"
            cat "$OUTPUT"
        fi
    fi
else
    echo "SKIP (test_packet_io_raw_veth not built)"
fi

ip netns del "$NS_TEST" 2>/dev/null || true

# ---- Summary ----

echo ""
test_summary
exit $?
