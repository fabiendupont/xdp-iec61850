#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
#
# test_rsv_vm_e2e.sh — R-SV (IEC TR 61850-90-5) pub/sub E2E via
# network namespaces
#
# WP-4e (r-integration).  Exercises the routable Sampled Values
# profile across namespace boundaries:
#
#   1. Full in-process suite (plain UDP round trip with smpCnt
#      continuity, wire-level replay injection, secure sign→verify
#      round trip, tamper-in-transit rejection, replay rejection)
#      inside an isolated namespace.
#   2. Plain-mode pub→sub across a real namespace boundary (veth pair
#      with IPv4 addresses): 6 sequential samples + 1 replay, the
#      subscriber drops the replay by SPDU-number tracking.
#   3. Secure-mode pub→sub across the namespace boundary (raw signed
#      frames): 3 verified + 1 tamper rejection + 1 replay rejection.
#
# The scenario binary (tests/integration/test_rsv_veth.c) is compiled
# from the build tree per the WP-2d deviation pattern (meson
# registration is orchestrator-owned — see the WP-4e report).
#
# Requires: root (CAP_NET_ADMIN + CAP_NET_RAW), built meson tree.
# Usage: sudo ./test_rsv_vm_e2e.sh [builddir]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=helpers.sh
source "$SCRIPT_DIR/helpers.sh"

BUILDDIR="${1:-$BUILDDIR}"

NS_SELF="iec-rsv-self"
NS_PUB="iec-rsv-pub"
NS_SUB="iec-rsv-sub"
VETH_PUB="rsv-pub0"
VETH_SUB="rsv-sub0"
PORT=48103
SUBNET=62   # 10.212.$SUBNET.0/30

TMPDIR_TEST=""

cleanup() {
    echo "Cleaning up..."
    kill_bg_pids
    ip netns del "$NS_SELF" 2>/dev/null || true
    ip netns del "$NS_PUB" 2>/dev/null || true
    ip netns del "$NS_SUB" 2>/dev/null || true
    if [ -n "$TMPDIR_TEST" ] && [ -d "$TMPDIR_TEST" ]; then
        rm -rf "$TMPDIR_TEST"
    fi
}
trap cleanup EXIT

echo "=== R-SV VM E2E Test (netns isolation) ==="

check_root

# Probe netns usability: `ip netns` needs a writable /run/netns with
# mount propagation, which some containers do not provide even as
# root — skip cleanly there.
if ! ip netns add iec-probe-$$ 2>/dev/null; then
    echo "SKIP: ip netns is not usable in this environment (needs /run/netns mount propagation)"
    exit 0
fi
ip netns del iec-probe-$$ 2>/dev/null || true

TMPDIR_TEST="$(mktemp -d)"

SCENARIO="$TMPDIR_TEST/test_rsv_veth"
if ! build_scenario test_rsv_veth "$SCENARIO"; then
    echo "SKIP: cannot build test_rsv_veth from $BUILDDIR (missing build tree or compiler)"
    exit 0
fi
echo "Scenario: $SCENARIO"

# ---- Test 1: in-process suite inside an isolated namespace ----

test_start "rsv self suite in isolated netns"

ip netns del "$NS_SELF" 2>/dev/null || true
ip netns add "$NS_SELF"
ip netns exec "$NS_SELF" ip link set lo up

OUTPUT="$TMPDIR_TEST/self.out"
if ip netns exec "$NS_SELF" "$SCENARIO" self > "$OUTPUT" 2>&1; then
    if grep -q "failed" "$OUTPUT" && ! grep -q " 0 failed" "$OUTPUT"; then
        test_fail "suite reported failures"
        cat "$OUTPUT"
    elif grep -qE "^[0-9]+/[0-9]+ passed" "$OUTPUT"; then
        test_pass
    else
        test_fail "unexpected output"
        cat "$OUTPUT"
    fi
else
    test_fail "exit code $?"
    cat "$OUTPUT"
fi

ip netns del "$NS_SELF" 2>/dev/null || true

# ---- Test 2: plain pub/sub across the namespace boundary ----

test_start "rsv plain pub/sub across netns boundary"

ip netns del "$NS_PUB" 2>/dev/null || true
ip netns del "$NS_SUB" 2>/dev/null || true
ip netns add "$NS_PUB"
ip netns add "$NS_SUB"

ip link add "$VETH_PUB" type veth peer name "$VETH_SUB"
ip link set "$VETH_PUB" netns "$NS_PUB"
ip link set "$VETH_SUB" netns "$NS_SUB"

ip netns exec "$NS_PUB" ip link set lo up
ip netns exec "$NS_PUB" ip link set "$VETH_PUB" up
ip netns exec "$NS_PUB" ip addr add "10.212.$SUBNET.1/30" dev "$VETH_PUB"
ip netns exec "$NS_PUB" sysctl -q -w "net.ipv6.conf.${VETH_PUB}.disable_ipv6=1" 2>/dev/null || true

ip netns exec "$NS_SUB" ip link set lo up
ip netns exec "$NS_SUB" ip link set "$VETH_SUB" up
ip netns exec "$NS_SUB" ip addr add "10.212.$SUBNET.2/30" dev "$VETH_SUB"
ip netns exec "$NS_SUB" sysctl -q -w "net.ipv6.conf.${VETH_SUB}.disable_ipv6=1" 2>/dev/null || true

SUB_OUT="$TMPDIR_TEST/sub_plain.out"
ip netns exec "$NS_SUB" "$SCENARIO" sub "$PORT" 6 > "$SUB_OUT" 2>&1 &
SUB_PID=$!
register_bg_pid "$SUB_PID"
sleep 1

ip netns exec "$NS_PUB" "$SCENARIO" pub "10.212.$SUBNET.2" "$PORT" 6 \
    > "$TMPDIR_TEST/pub_plain.out" 2>&1

if wait_for_output "$SUB_PID" "PASS" 20 "$SUB_OUT"; then
    if grep -q "6/6 samples" "$SUB_OUT" && grep -q "1 replay drops" "$SUB_OUT"; then
        test_pass
    else
        test_fail "unexpected sub summary"
        cat "$SUB_OUT"
    fi
else
    test_fail "subscriber did not report PASS"
    echo "--- sub ---"; cat "$SUB_OUT"
    echo "--- pub ---"; cat "$TMPDIR_TEST/pub_plain.out"
fi
kill_bg_pids

ip netns del "$NS_PUB" 2>/dev/null || true
ip netns del "$NS_SUB" 2>/dev/null || true

# ---- Test 3: secure pub/sub across the namespace boundary ----

test_start "rsv secure pub/sub across netns boundary"

ip netns add "$NS_PUB"
ip netns add "$NS_SUB"

ip link add "$VETH_PUB" type veth peer name "$VETH_SUB"
ip link set "$VETH_PUB" netns "$NS_PUB"
ip link set "$VETH_SUB" netns "$NS_SUB"

ip netns exec "$NS_PUB" ip link set lo up
ip netns exec "$NS_PUB" ip link set "$VETH_PUB" up
ip netns exec "$NS_PUB" ip addr add "10.212.$SUBNET.1/30" dev "$VETH_PUB"
ip netns exec "$NS_PUB" sysctl -q -w "net.ipv6.conf.${VETH_PUB}.disable_ipv6=1" 2>/dev/null || true

ip netns exec "$NS_SUB" ip link set lo up
ip netns exec "$NS_SUB" ip link set "$VETH_SUB" up
ip netns exec "$NS_SUB" ip addr add "10.212.$SUBNET.2/30" dev "$VETH_SUB"
ip netns exec "$NS_SUB" sysctl -q -w "net.ipv6.conf.${VETH_SUB}.disable_ipv6=1" 2>/dev/null || true

SUB_OUT="$TMPDIR_TEST/sub_secure.out"
ip netns exec "$NS_SUB" "$SCENARIO" sub-secure "$VETH_SUB" 3 \
    > "$SUB_OUT" 2>&1 &
SUB_PID=$!
register_bg_pid "$SUB_PID"
sleep 1

ip netns exec "$NS_PUB" "$SCENARIO" pub-secure "$VETH_PUB" \
    "10.212.$SUBNET.1" "10.212.$SUBNET.2" "$PORT" 3 \
    > "$TMPDIR_TEST/pub_secure.out" 2>&1

if wait_for_output "$SUB_PID" "PASS" 20 "$SUB_OUT"; then
    if grep -q "3/3 signed samples" "$SUB_OUT" && \
       grep -q "1 tamper rejects" "$SUB_OUT" && \
       grep -q "1 replay drops" "$SUB_OUT"; then
        test_pass
    else
        test_fail "unexpected sub summary"
        cat "$SUB_OUT"
    fi
else
    RET="$(grep -c "secure modes need" "$SUB_OUT" || true)"
    if [ "$RET" -ne 0 ]; then
        echo "SKIP (build without -Denable_security)"
    else
        test_fail "subscriber did not report PASS"
        echo "--- sub ---"; cat "$SUB_OUT"
        echo "--- pub ---"; cat "$TMPDIR_TEST/pub_secure.out"
    fi
fi
kill_bg_pids

ip netns del "$NS_PUB" 2>/dev/null || true
ip netns del "$NS_SUB" 2>/dev/null || true

# ---- Summary ----

echo ""
test_summary
exit $?
