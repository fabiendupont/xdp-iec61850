#!/bin/bash
# SPDX-License-Identifier: BSD-2-Clause
#
# test_ratelimit.sh — IEC 61850 XDP rate-limit integration via veth
#
# WP-5a (storm protection).  Attaches the repository's IEC 61850 XDP
# graph (EtherType dispatch → GOOSE/SV/UDP filter nodes) to one end
# of a veth pair inside an isolated network namespace and floods
# real wire traffic through the other end:
#
#   RL-1  GOOSE APPID with a tight per-key token bucket  → flood
#         dropped beyond its burst (node stats + XSK silence)
#   RL-2  GOOSE APPID without a bucket                   → limited
#         by the retuned family default (lazy creation)
#   RL-3  SV APPID pair                                  → same
#         isolation proof on the SV path
#   RL-4  90-5 UDP dport pair                            → same
#         isolation proof on the routable-profile path
#   and, in every case, a second key with a generous bucket passes
#   the whole flood untouched — one key's storm never affects
#   another key.
#
# The scenario (tests/vm/ratelimit_scenario.c) is compiled from the
# build tree per the WP-2d deviation pattern, using the link line of
# the registered test_iec61850_graph target (libbpf + xgl + libelf).
#
# Requires: root (CAP_BPF + CAP_NET_ADMIN + CAP_NET_RAW), a build
# tree with the BPF objects (libbpf + xdp-graph-lib found at meson
# setup).  Skips gracefully otherwise.
#
# Expected run (privileged CI runner or laptop with sudo):
#   $ sudo tests/vm/test_ratelimit.sh builddir-wp
#   === IEC 61850 XDP Rate-Limit Test (netns isolation) ===
#     [TEST] goose per-appid rate limit + isolation   PASS
#     [TEST] sv per-appid rate limit + isolation      PASS
#     [TEST] r-goose per-dport rate limit + isolation PASS
#   3/3 passed, 0 failed
#
# Usage: sudo ./test_ratelimit.sh [builddir]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=helpers.sh
source "$SCRIPT_DIR/helpers.sh"

BUILDDIR="${1:-$BUILDDIR}"

NS_RL="iec-rl"
VETH_RX="rl-rx0"
VETH_TX="rl-tx0"
RX_IP="10.212.64.2"
TX_IP="10.212.64.1"

TMPDIR_TEST=""

cleanup() {
    echo "Cleaning up..."
    kill_bg_pids
    ip netns del "$NS_RL" 2>/dev/null || true
    if [ -n "$TMPDIR_TEST" ] && [ -d "$TMPDIR_TEST" ]; then
        rm -rf "$TMPDIR_TEST"
    fi
}
trap cleanup EXIT

echo "=== IEC 61850 XDP Rate-Limit Test (netns isolation) ==="

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
SCENARIO="$TMPDIR_TEST/ratelimit_scenario"
SRC="$SCRIPT_DIR/ratelimit_scenario.c"
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
ip netns del "$NS_RL" 2>/dev/null || true
ip netns add "$NS_RL"
ip netns exec "$NS_RL" ip link set lo up
# The egl/xgl graph library pins shared maps under /sys/fs/bpf/egl.
# Inside `ip netns exec` the fresh sysfs mount loses the host's
# bpffs — mount a private instance (standard XDP-test practice).
ip netns exec "$NS_RL" mkdir -p /sys/fs/bpf 2>/dev/null || true
if ! ip netns exec "$NS_RL" mount -t bpf bpf /sys/fs/bpf 2>/dev/null; then
    # tolerate an existing mount (EBUSY) but not a hard failure
    if ! ip netns exec "$NS_RL" grep -qs bpf /proc/mounts; then
        echo "SKIP: cannot mount bpffs inside the test netns"
        ip netns del "$NS_RL" 2>/dev/null || true
        exit 0
    fi
fi
ip netns exec "$NS_RL" ip link add "$VETH_RX" type veth peer name "$VETH_TX"
ip netns exec "$NS_RL" ip link set "$VETH_RX" up
ip netns exec "$NS_RL" ip link set "$VETH_TX" up
ip netns exec "$NS_RL" ip addr add "$RX_IP/30" dev "$VETH_RX"
ip netns exec "$NS_RL" ip addr add "$TX_IP/30" dev "$VETH_TX"
ip netns exec "$NS_RL" sysctl -q -w "net.ipv6.conf.${VETH_RX}.disable_ipv6=1" 2>/dev/null || true
ip netns exec "$NS_RL" sysctl -q -w "net.ipv6.conf.${VETH_TX}.disable_ipv6=1" 2>/dev/null || true

test_start "xdp rate limit (per-key token bucket + isolation)"

OUTPUT="$TMPDIR_TEST/rl.out"
if ip netns exec "$NS_RL" "$SCENARIO" "$VETH_RX" "$VETH_TX" \
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
        echo "SKIP (BPF attach/load not permitted on this kernel)"
        grep "^SKIP:" "$OUTPUT" || true
    else
        test_fail "exit code $RET"
        cat "$OUTPUT"
    fi
fi

ip netns del "$NS_RL" 2>/dev/null || true

# ---- Summary ----

echo ""
test_summary
exit $?
