#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Wire capture test: GOOSE frame validation via tshark.
#
# Tests our GOOSE publisher output and optionally libiec61850's.
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

# Find our wire publisher (built by meson)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
for d in "$MESON_BUILD_ROOT" "$SCRIPT_DIR/../../../builddir-full" "$SCRIPT_DIR/../../../builddir"; do
    [ -x "$d/tests/goose_wire_pub" ] && GOOSE_PUB="$d/tests/goose_wire_pub" && break
done
if [ -z "$GOOSE_PUB" ]; then
    echo "SKIP: goose_wire_pub not built"
    exit 77
fi

# Find libiec61850 goose publisher (optional)
LIBIEC="${LIBIEC61850_BUILD_DIR:-}"
LIBIEC_GOOSE=""
if [ -n "$LIBIEC" ] && [ -x "$LIBIEC/examples/goose_publisher/goose_publisher_example" ]; then
    LIBIEC_GOOSE="$LIBIEC/examples/goose_publisher/goose_publisher_example"
    export LD_LIBRARY_PATH="$LIBIEC/src${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
fi

PASS=0; FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

cleanup() {
    ip link del igt_wg0 2>/dev/null || true
    rm -f /tmp/_wg_*.pcap
}
trap cleanup EXIT

ip link add igt_wg0 type veth peer name igt_wg1
ip link set igt_wg0 up
ip link set igt_wg1 up
ip link set igt_wg0 promisc on
ip link set igt_wg1 promisc on

echo "=== Wire GOOSE Tests ==="

# WG-01: Our GOOSE publisher produces valid frames
echo ""
echo "--- WG-01: Our GOOSE publisher ---"
tshark -i igt_wg1 -a duration:5 -w /tmp/_wg_ours.pcap &>/dev/null &
TSH=$!
sleep 1
timeout 3 "$GOOSE_PUB" igt_wg0
wait $TSH 2>/dev/null
C=$(tshark -r /tmp/_wg_ours.pcap -Y "goose || eth.type==0x88b8" 2>/dev/null | wc -l)
[ "$C" -gt 0 ] && pass "WG-01: $C GOOSE frames captured" || fail "WG-01: 0 frames"

# WG-02: tshark decodes our frames as valid GOOSE
G=$(tshark -r /tmp/_wg_ours.pcap -Y "goose" 2>/dev/null | wc -l)
[ "$G" -gt 0 ] && pass "WG-02: tshark decoded as valid GOOSE" || fail "WG-02: not decoded as GOOSE"

# WG-03: APPID field present
APPID=$(tshark -r /tmp/_wg_ours.pcap -Y "goose" -T fields -e goose.appid 2>/dev/null | head -1)
[ -n "$APPID" ] && pass "WG-03: APPID=$APPID" || fail "WG-03: no APPID field"

# WG-04: libiec61850 GOOSE publisher (optional cross-validation)
if [ -n "$LIBIEC_GOOSE" ]; then
    echo ""
    echo "--- WG-04: libiec61850 GOOSE publisher ---"
    tshark -i igt_wg1 -a duration:5 -w /tmp/_wg_lib.pcap &>/dev/null &
    TSH=$!
    sleep 1
    timeout 2 "$LIBIEC_GOOSE" igt_wg0 &>/dev/null || true
    wait $TSH 2>/dev/null
    C=$(tshark -r /tmp/_wg_lib.pcap -Y "goose" 2>/dev/null | wc -l)
    [ "$C" -gt 0 ] && pass "WG-04: libiec61850 GOOSE: $C frames" || fail "WG-04: libiec61850 0 frames"
else
    echo ""
    echo "  SKIP: WG-04 (LIBIEC61850_BUILD_DIR not set)"
fi

echo ""
echo "Wire GOOSE: $PASS passed, $FAIL failed"
exit $FAIL
