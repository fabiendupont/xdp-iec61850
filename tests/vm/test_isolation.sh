#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
#
# test_isolation.sh — APPID filtering isolation test via network namespaces
#
# Verifies that subscribers correctly filter by APPID when multiple
# publishers send on the same network. Uses the goose_loopback binary's
# built-in APPID filter test, run inside an isolated namespace.
#
# Also tests cross-namespace isolation: traffic in one namespace must
# not be visible in another unconnected namespace.
#
# Requires: root (CAP_NET_ADMIN + CAP_NET_RAW)
# Usage: sudo ./test_isolation.sh [builddir]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=helpers.sh
source "$SCRIPT_DIR/helpers.sh"

BUILDDIR="${1:-$BUILDDIR}"

TMPDIR_TEST=""

cleanup() {
    echo "Cleaning up..."
    kill_bg_pids
    ip netns del iec-iso-a 2>/dev/null || true
    ip netns del iec-iso-b 2>/dev/null || true
    ip netns del iec-iso-c 2>/dev/null || true
    if [ -n "$TMPDIR_TEST" ] && [ -d "$TMPDIR_TEST" ]; then
        rm -rf "$TMPDIR_TEST"
    fi
}
trap cleanup EXIT

echo "=== APPID Filtering Isolation Test (netns) ==="

check_root

GOOSE_LOOPBACK="$(find_binary goose_loopback)"
echo "Binary: $GOOSE_LOOPBACK"

TMPDIR_TEST="$(mktemp -d)"

# ---- Test 1: APPID filter (built into goose_loopback) ----

test_start "appid filter rejects wrong appid"

NS_FILTER="iec-iso-a"
VETH_F0="iso-f0"
VETH_F1="iso-f1"

ip netns del "$NS_FILTER" 2>/dev/null || true
ip netns add "$NS_FILTER"
ip netns exec "$NS_FILTER" ip link set lo up
ip netns exec "$NS_FILTER" ip link add "$VETH_F0" type veth peer name "$VETH_F1"
ip netns exec "$NS_FILTER" ip link set "$VETH_F0" up
ip netns exec "$NS_FILTER" ip link set "$VETH_F1" up
ip netns exec "$NS_FILTER" sysctl -q -w "net.ipv6.conf.${VETH_F0}.disable_ipv6=1" 2>/dev/null || true
ip netns exec "$NS_FILTER" sysctl -q -w "net.ipv6.conf.${VETH_F1}.disable_ipv6=1" 2>/dev/null || true

# goose_loopback has a built-in "APPID filter" test (Test 3)
# It publishes with APPID 0x9999 and verifies the subscriber
# (configured for 0x0001) ignores the frame.
OUTPUT="$TMPDIR_TEST/appid_filter.out"
if ip netns exec "$NS_FILTER" "$GOOSE_LOOPBACK" "$VETH_F0" "$VETH_F1" > "$OUTPUT" 2>&1; then
    if grep -q "APPID filter.*PASS" "$OUTPUT"; then
        test_pass
    else
        test_fail "APPID filter test not found in output"
        cat "$OUTPUT"
    fi
else
    test_fail "exit code $?"
    cat "$OUTPUT"
fi

ip netns del "$NS_FILTER" 2>/dev/null || true

# ---- Test 2: Cross-namespace isolation ----

test_start "traffic in namespace A invisible in namespace B"

NS_A="iec-iso-b"
NS_B="iec-iso-c"

ip netns del "$NS_A" 2>/dev/null || true
ip netns del "$NS_B" 2>/dev/null || true
ip netns add "$NS_A"
ip netns add "$NS_B"

# Create a veth pair inside NS_A only — NS_B has no connection
VETH_A0="iso-a0"
VETH_A1="iso-a1"
ip netns exec "$NS_A" ip link set lo up
ip netns exec "$NS_A" ip link add "$VETH_A0" type veth peer name "$VETH_A1"
ip netns exec "$NS_A" ip link set "$VETH_A0" up
ip netns exec "$NS_A" ip link set "$VETH_A1" up

ip netns exec "$NS_B" ip link set lo up

# NS_B should have no interfaces besides lo
NS_B_IF_COUNT="$(ip netns exec "$NS_B" ip -o link show | grep -cv "^[0-9]*: lo:" || true)"
if [ "$NS_B_IF_COUNT" -eq 0 ]; then
    test_pass
else
    test_fail "namespace B has $NS_B_IF_COUNT non-lo interfaces (expected 0)"
fi

ip netns del "$NS_A" 2>/dev/null || true
ip netns del "$NS_B" 2>/dev/null || true

# ---- Test 3: Parallel namespaces do not interfere ----

test_start "parallel namespaces with same interface names"

NS_X="iec-iso-b"
NS_Y="iec-iso-c"
# Use identical veth names in both namespaces — they should not conflict
COMMON_VETH0="iec-v0"
COMMON_VETH1="iec-v1"

ip netns del "$NS_X" 2>/dev/null || true
ip netns del "$NS_Y" 2>/dev/null || true
ip netns add "$NS_X"
ip netns add "$NS_Y"

ip netns exec "$NS_X" ip link set lo up
ip netns exec "$NS_X" ip link add "$COMMON_VETH0" type veth peer name "$COMMON_VETH1"
ip netns exec "$NS_X" ip link set "$COMMON_VETH0" up
ip netns exec "$NS_X" ip link set "$COMMON_VETH1" up

ip netns exec "$NS_Y" ip link set lo up
ip netns exec "$NS_Y" ip link add "$COMMON_VETH0" type veth peer name "$COMMON_VETH1"
ip netns exec "$NS_Y" ip link set "$COMMON_VETH0" up
ip netns exec "$NS_Y" ip link set "$COMMON_VETH1" up

# Both should work independently — run goose_loopback in both
OUTPUT_X="$TMPDIR_TEST/parallel_x.out"
OUTPUT_Y="$TMPDIR_TEST/parallel_y.out"

ip netns exec "$NS_X" "$GOOSE_LOOPBACK" "$COMMON_VETH0" "$COMMON_VETH1" \
    > "$OUTPUT_X" 2>&1 &
PID_X=$!

ip netns exec "$NS_Y" "$GOOSE_LOOPBACK" "$COMMON_VETH0" "$COMMON_VETH1" \
    > "$OUTPUT_Y" 2>&1 &
PID_Y=$!

wait "$PID_X" || true
RET_X=$?
wait "$PID_Y" || true
RET_Y=$?

if [ "$RET_X" -eq 0 ] && [ "$RET_Y" -eq 0 ]; then
    if grep -q "PASSED" "$OUTPUT_X" && grep -q "PASSED" "$OUTPUT_Y"; then
        test_pass
    else
        test_fail "one or both runs missing PASSED"
        echo "--- NS_X ---"
        cat "$OUTPUT_X"
        echo "--- NS_Y ---"
        cat "$OUTPUT_Y"
    fi
else
    test_fail "exit codes: X=$RET_X Y=$RET_Y"
    echo "--- NS_X ---"
    cat "$OUTPUT_X"
    echo "--- NS_Y ---"
    cat "$OUTPUT_Y"
fi

ip netns del "$NS_X" 2>/dev/null || true
ip netns del "$NS_Y" 2>/dev/null || true

# ---- Summary ----

echo ""
test_summary
exit $?
