#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Wire capture test: SV frame validation via tshark.
#
# Requires: root, tshark
# Optional: LIBIEC61850_BUILD_DIR for cross-validation

set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "SKIP: requires root"
    exit 77
fi

if ! command -v tshark >/dev/null 2>&1; then
    echo "SKIP: tshark not found"
    exit 77
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
for d in "$MESON_BUILD_ROOT" "$SCRIPT_DIR/../../../builddir-full" "$SCRIPT_DIR/../../../builddir"; do
    [ -x "$d/tests/sv_wire_pub" ] && SV_PUB="$d/tests/sv_wire_pub" && break
done
if [ -z "$SV_PUB" ]; then
    echo "SKIP: sv_wire_pub not built"
    exit 77
fi

LIBIEC="${LIBIEC61850_BUILD_DIR:-}"
LIBIEC_SV=""
if [ -n "$LIBIEC" ] && [ -x "$LIBIEC/examples/sv_publisher/sv_publisher_example" ]; then
    LIBIEC_SV="$LIBIEC/examples/sv_publisher/sv_publisher_example"
    export LD_LIBRARY_PATH="$LIBIEC/src${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi

PASS=0; FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

cleanup() {
    ip link del igt_ws0 2>/dev/null || true
    rm -f /tmp/_ws_*.pcap
}
trap cleanup EXIT

ip link add igt_ws0 type veth peer name igt_ws1
ip link set igt_ws0 up
ip link set igt_ws1 up
ip link set igt_ws0 promisc on
ip link set igt_ws1 promisc on

echo "=== Wire SV Tests ==="

echo ""
echo "--- WS-01: Our SV publisher ---"
tshark -i igt_ws1 -a duration:5 -w /tmp/_ws_ours.pcap &>/dev/null &
TSH=$!
sleep 1
timeout 3 "$SV_PUB" igt_ws0
wait $TSH 2>/dev/null
C=$(tshark -r /tmp/_ws_ours.pcap -Y "sv || eth.type==0x88ba" 2>/dev/null | wc -l)
[ "$C" -gt 0 ] && pass "WS-01: $C SV frames captured" || fail "WS-01: 0 frames"

G=$(tshark -r /tmp/_ws_ours.pcap -Y "sv" 2>/dev/null | wc -l)
[ "$G" -gt 0 ] && pass "WS-02: tshark decoded as valid SV" || fail "WS-02: not decoded as SV"

APPID=$(tshark -r /tmp/_ws_ours.pcap -Y "sv" -T fields -e sv.appid 2>/dev/null | head -1)
[ -n "$APPID" ] && pass "WS-03: APPID=$APPID" || fail "WS-03: no APPID field"

if [ -n "$LIBIEC_SV" ]; then
    echo ""
    echo "--- WS-04: libiec61850 SV publisher ---"
    tshark -i igt_ws1 -a duration:5 -w /tmp/_ws_lib.pcap &>/dev/null &
    TSH=$!
    sleep 1
    timeout 2 "$LIBIEC_SV" igt_ws0 &>/dev/null || true
    wait $TSH 2>/dev/null
    C=$(tshark -r /tmp/_ws_lib.pcap -Y "sv" 2>/dev/null | wc -l)
    [ "$C" -gt 0 ] && pass "WS-04: libiec61850 SV: $C frames" || fail "WS-04: libiec61850 0 frames"
else
    echo ""
    echo "  SKIP: WS-04 (LIBIEC61850_BUILD_DIR not set)"
fi

echo ""
echo "Wire SV: $PASS passed, $FAIL failed"
exit $FAIL
