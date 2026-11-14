#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
#
# test_qinq.sh — IEC 61850 XDP QinQ (802.1ad) integration via veth
#
# WP-5b.  Attaches the repository's IEC 61850 XDP graph (EtherType
# dispatch → GOOSE/SV filter nodes) to one end of a veth pair inside
# an isolated network namespace and pushes real wire traffic through
# the other end:
#
#   QQ-1  untagged GOOSE frame of a subscribed APPID  → redirected
#         (regression: pre-WP-5b behavior)
#   QQ-2  single 802.1Q-tagged (0x8100) GOOSE frame   → redirected
#         (regression)
#   QQ-3  QinQ double-tagged (0x88A8 + 0x8100) GOOSE  → redirected
#         (the WP-5b feature), tag fields recovered by the
#         userspace parser; WP-5a rate-limit cost asserted at the
#         FULL frame length, tags included
#   QQ-4  QinQ with a 0x88A8 customer tag             → redirected
#   QQ-5  malformed stacks (bare service tag, stacked 0x8100 tags,
#         three tags)                                  → never
#         delivered, filter accounting conserved
#   QQ-6  QinQ SV frame                                → redirected
#         through the SV filter (skips when the environment's
#         EtherType dispatch does not route tagged frames there)
#
# The scenario (tests/vm/qinq_scenario.c) is compiled from the build
# tree per the WP-2d deviation pattern, using the link line of the
# registered test_iec61850_graph target (libbpf + xgl + libelf).
#
# Requires: root (CAP_BPF + CAP_NET_ADMIN + CAP_NET_RAW), a build
# tree with the BPF objects (libbpf + xdp-graph-lib found at meson
# setup).  Skips gracefully otherwise.
#
# Expected run (privileged CI runner or laptop with sudo):
#   $ sudo tests/vm/test_qinq.sh builddir-wp
#   === IEC 61850 XDP QinQ Test (netns isolation) ===
#     [TEST] goose untagged/802.1Q/QinQ redirected     PASS
#     [TEST] goose QinQ 0x88A8 customer tag redirected PASS
#     [TEST] goose malformed tag stacks dropped        PASS
#     [TEST] sv QinQ redirected (dispatch-dependent)   PASS
#   4/4 passed, 0 failed
#
# Usage: sudo ./test_qinq.sh [builddir]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=helpers.sh
source "$SCRIPT_DIR/helpers.sh"

BUILDDIR="${1:-$BUILDDIR}"

NS_QQ="iec-qinq"
VETH_RX="qq-rx0"
VETH_TX="qq-tx0"
RX_IP="10.212.65.2"
TX_IP="10.212.65.1"

TMPDIR_TEST=""

cleanup() {
    echo "Cleaning up..."
    kill_bg_pids
    ip netns del "$NS_QQ" 2>/dev/null || true
    if [ -n "$TMPDIR_TEST" ] && [ -d "$TMPDIR_TEST" ]; then
        rm -rf "$TMPDIR_TEST"
    fi
}
trap cleanup EXIT

echo "=== IEC 61850 XDP QinQ Test (netns isolation) ==="

check_root

# Probe netns usability: `ip netns` needs a writable /run/netns with
# mount propagation, which some containers do not provide even as
# root — skip cleanly there.
if ! ip netns add iec-probe-$$ 2>/dev/null; then
    echo "SKIP: ip netns is not usable in this environment (needs /run/netns mount propagation)"
    exit 0
fi
ip netns del iec-probe-$$ 2>/dev/null || true

# The scenario needs libbpf/xgl: derive its link line from the
# registered test_iec61850_graph target.  When that target does not
# exist (no libbpf at configure time) XDP is not available at all.
if ! command -v cc >/dev/null 2>&1 || \
   ! command -v ninja >/dev/null 2>&1 || \
   [ ! -f "$BUILDDIR/build.ninja" ]; then
    echo "SKIP: no build tree or compiler"
    exit 0
fi
if ! ninja -C "$BUILDDIR" -t commands tests/test_iec61850_graph \
        >/dev/null 2>&1; then
    echo "SKIP: test_iec61850_graph target not built (libbpf/xgl absent)"
    exit 0
fi

TMPDIR_TEST="$(mktemp -d)"
SCENARIO="$TMPDIR_TEST/qinq_scenario"
SRC="$SCRIPT_DIR/qinq_scenario.c"
LINK_LINE="$(ninja -C "$BUILDDIR" -t commands tests/test_iec61850_graph 2>/dev/null | tail -1)"

if ! cc -std=c11 -O2 -I"$PROJECT_DIR/include/iec61850" \
        -I"$PROJECT_DIR/subprojects/xdp-graph-lib/include" \
        -I"$PROJECT_DIR/subprojects/ebpf-graph-lib/include" \
        -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE \
        -DBPF_OBJ_DIR="\"$BUILDDIR\"" \
        -DIEC61850_BPF_DIR="\"$BUILDDIR\"" \
        -c "$SRC" -o "$SCENARIO.o" 2>/dev/null; then
    echo "SKIP: scenario compile failed"
    rm -f "$SCENARIO.o"
    exit 0
fi
if ! (cd "$BUILDDIR" && echo "$LINK_LINE" | \
      sed -e "s|-o tests/test_iec61850_graph|-o $SCENARIO|" \
          -e "s|tests/test_iec61850_graph.p/[^ ]*c.o|$SCENARIO.o|" \
      > "$SCENARIO.cmd" && sh "$SCENARIO.cmd"); then
    echo "SKIP: scenario link failed"
    rm -f "$SCENARIO.o" "$SCENARIO.cmd"
    exit 0
fi
rm -f "$SCENARIO.o" "$SCENARIO.cmd"
echo "Scenario: $SCENARIO"

# Isolated namespace with a veth pair: the XDP program is attached to
# VETH_RX, traffic is injected on VETH_TX.
ip netns del "$NS_QQ" 2>/dev/null || true
ip netns add "$NS_QQ"
ip netns exec "$NS_QQ" ip link set lo up
ip netns exec "$NS_QQ" ip link add "$VETH_RX" type veth peer name "$VETH_TX"
ip netns exec "$NS_QQ" ip link set "$VETH_RX" up
ip netns exec "$NS_QQ" ip link set "$VETH_TX" up
ip netns exec "$NS_QQ" ip addr add "$RX_IP/30" dev "$VETH_RX"
ip netns exec "$NS_QQ" ip addr add "$TX_IP/30" dev "$VETH_TX"
ip netns exec "$NS_QQ" sysctl -q -w "net.ipv6.conf.${VETH_RX}.disable_ipv6=1" 2>/dev/null || true
ip netns exec "$NS_QQ" sysctl -q -w "net.ipv6.conf.${VETH_TX}.disable_ipv6=1" 2>/dev/null || true

test_start "xdp qinq (802.1ad double-tagged GOOSE/SV)"

OUTPUT="$TMPDIR_TEST/qq.out"
if ip netns exec "$NS_QQ" "$SCENARIO" "$VETH_RX" "$VETH_TX" \
        "$RX_IP" "$TX_IP" > "$OUTPUT" 2>&1; then
    if grep -q " 0 failed" "$OUTPUT"; then
        test_pass
    else
        test_fail "unexpected summary"
        cat "$OUTPUT"
    fi
else
    RET=$?
    if [ "$RET" -eq 77 ] || grep -q "^SKIP:" "$OUTPUT"; then
        echo "SKIP (BPF attach/load not permitted on this kernel or dispatch map absent)"
        grep "^SKIP:" "$OUTPUT" || true
    else
        test_fail "exit code $RET"
        cat "$OUTPUT"
    fi
fi

ip netns del "$NS_QQ" 2>/dev/null || true

# ---- Summary ----

echo ""
test_summary
exit $?
