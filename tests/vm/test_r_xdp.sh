#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
#
# test_r_xdp.sh — IEC 61850-90-5 XDP datapath integration via veth
#
# WP-4e (r-integration).  Attaches the repository's IEC 61850 XDP
# graph (EtherType dispatch → UDP dport filter → R-GOOSE/R-SV SPDU
# parse) to one end of a veth pair inside an isolated network
# namespace and drives real R-GOOSE wire traffic through the other
# end:
#
#   RX-1  registered dport (r_filter)   → redirected to AF_XDP and
#         delivered to the XSK backend
#   RX-2  unregistered dport            → dropped at XDP (udp-filter
#         node stats + XSK silence)
#   RX-3  duplicate SPDU number         → second copy dropped by the
#         BPF per-APPID SPDU-number dedup (rgoose_state_map)
#
# The scenario (tests/vm/r_xdp_scenario.c) is compiled from the build
# tree per the WP-2d deviation pattern, using the link line of the
# registered test_iec61850_graph target (libbpf + xgl + libelf).
#
# Requires: root (CAP_BPF + CAP_NET_ADMIN + CAP_NET_RAW), a build
# tree with the BPF objects (libbpf + xdp-graph-lib found at meson
# setup).  Skips gracefully otherwise.
#
# Usage: sudo ./test_r_xdp.sh [builddir]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=helpers.sh
source "$SCRIPT_DIR/helpers.sh"

BUILDDIR="${1:-$BUILDDIR}"

NS_XDP="iec-rxdp"
VETH_RX="rxdp-rx0"
VETH_TX="rxdp-tx0"
RX_IP="10.212.63.2"
TX_IP="10.212.63.1"

TMPDIR_TEST=""

cleanup() {
    echo "Cleaning up..."
    kill_bg_pids
    ip netns del "$NS_XDP" 2>/dev/null || true
    if [ -n "$TMPDIR_TEST" ] && [ -d "$TMPDIR_TEST" ]; then
        rm -rf "$TMPDIR_TEST"
    fi
}
trap cleanup EXIT

echo "=== IEC 61850-90-5 XDP Datapath Test (netns isolation) ==="

check_root

# Probe netns usability: `ip netns` needs a writable /run/netns with
# mount propagation, which some containers do not provide even as
# root — skip cleanly there.
if ! ip netns add iec-probe-$$ 2>/dev/null; then
    echo "SKIP: ip netns is not usable in this environment (needs /run/netns mount propagation)"
    exit 0
fi
ip netns del iec-probe-$$ 2>/dev/null || true

# The XDP scenario needs libbpf/xgl: derive its link line from the
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
SCENARIO="$TMPDIR_TEST/r_xdp_scenario"
SRC="$SCRIPT_DIR/r_xdp_scenario.c"
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
ip netns del "$NS_XDP" 2>/dev/null || true
ip netns add "$NS_XDP"
ip netns exec "$NS_XDP" ip link set lo up
ip netns exec "$NS_XDP" ip link add "$VETH_RX" type veth peer name "$VETH_TX"
ip netns exec "$NS_XDP" ip link set "$VETH_RX" up
ip netns exec "$NS_XDP" ip link set "$VETH_TX" up
ip netns exec "$NS_XDP" ip addr add "$RX_IP/30" dev "$VETH_RX"
ip netns exec "$NS_XDP" ip addr add "$TX_IP/30" dev "$VETH_TX"
ip netns exec "$NS_XDP" sysctl -q -w "net.ipv6.conf.${VETH_RX}.disable_ipv6=1" 2>/dev/null || true
ip netns exec "$NS_XDP" sysctl -q -w "net.ipv6.conf.${VETH_TX}.disable_ipv6=1" 2>/dev/null || true

test_start "r-xdp datapath (dport filter + AF_XDP + spdu dedup)"

OUTPUT="$TMPDIR_TEST/xdp.out"
# NOTE: each `ip netns exec` unshares a fresh mount namespace, so the
# bpffs mount MUST happen in the same exec as the scenario — a mount
# in a previous exec dies with it (the graph library pins shared maps
# under /sys/fs/bpf/egl, and the netns's fresh sysfs has no bpffs).
if ip netns exec "$NS_XDP" sh -c '
        mkdir -p /sys/fs/bpf 2>/dev/null || true
        mount -t bpf bpf /sys/fs/bpf 2>/dev/null || true
        exec "$0" "$@"' \
        "$SCENARIO" "$VETH_RX" "$VETH_TX" "$RX_IP" "$TX_IP" > "$OUTPUT" 2>&1; then
    if grep -q " 0 failed" "$OUTPUT"; then
        test_pass
    else
        test_fail "unexpected summary"
        cat "$OUTPUT"
    fi
else
    RET=$?
    if [ "$RET" -eq 77 ] || grep -q "^SKIP:" "$OUTPUT"; then
        echo "SKIP (scenario skipped — full diagnostics below)"
        cat "$OUTPUT"
    else
        test_fail "exit code $RET"
        cat "$OUTPUT"
    fi
fi

ip netns del "$NS_XDP" 2>/dev/null || true

# ---- Summary ----

echo ""
test_summary
exit $?
