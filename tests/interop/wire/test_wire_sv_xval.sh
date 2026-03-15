#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Wire cross-validation test: compare our SV output against libiec61850.
#
# Captures frames from both publishers on veth pairs and checks that
# tshark decodes both as valid SV with matching EtherType.
# Requires: root, tshark, LIBIEC61850_BUILD_DIR

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
if [ -z "$LIBIEC" ] || [ ! -x "$LIBIEC/examples/sv_publisher/sv_publisher_example" ]; then
    echo "SKIP: libiec61850 SV publisher not found (set LIBIEC61850_BUILD_DIR)"
    exit 77
fi
LIBIEC_SV="$LIBIEC/examples/sv_publisher/sv_publisher_example"
export LD_LIBRARY_PATH="$LIBIEC/src${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

PASS=0; FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

cleanup() {
    ip link del igt_xs0 2>/dev/null || true
    rm -f /tmp/_xs_*.pcap
}
trap cleanup EXIT

ip link add igt_xs0 type veth peer name igt_xs1
ip link set igt_xs0 up
ip link set igt_xs1 up
ip link set igt_xs0 promisc on
ip link set igt_xs1 promisc on

echo "=== Wire SV Cross-Validation ==="

# XS-01: libiec61850 SV frames decoded by tshark
echo ""
echo "--- XS-01: libiec61850 SV publisher ---"
tshark -i igt_xs1 -a duration:5 -w /tmp/_xs_lib.pcap &>/dev/null &
TSH=$!
sleep 1
timeout 2 "$LIBIEC_SV" igt_xs0 &>/dev/null || true
wait $TSH 2>/dev/null
LIB_C=$(tshark -r /tmp/_xs_lib.pcap -Y "sv" 2>/dev/null | wc -l)
[ "$LIB_C" -gt 0 ] && pass "XS-01: libiec61850 SV: $LIB_C frames" || fail "XS-01: libiec61850 0 frames"

# XS-02: Our SV uses same EtherType as libiec61850
echo ""
echo "--- XS-02: EtherType match ---"
tshark -i igt_xs1 -a duration:5 -w /tmp/_xs_ours.pcap &>/dev/null &
TSH=$!
sleep 1
timeout 3 "$SV_PUB" igt_xs0
wait $TSH 2>/dev/null
OUR_ET=$(tshark -r /tmp/_xs_ours.pcap -Y "sv" -T fields -e eth.type 2>/dev/null | head -1)
LIB_ET=$(tshark -r /tmp/_xs_lib.pcap -Y "sv" -T fields -e eth.type 2>/dev/null | head -1)
if [ -n "$OUR_ET" ] && [ -n "$LIB_ET" ] && [ "$OUR_ET" = "$LIB_ET" ]; then
    pass "XS-02: EtherType match ($OUR_ET)"
elif [ -z "$OUR_ET" ] || [ -z "$LIB_ET" ]; then
    fail "XS-02: missing EtherType (ours=$OUR_ET lib=$LIB_ET)"
else
    fail "XS-02: EtherType mismatch (ours=$OUR_ET lib=$LIB_ET)"
fi

# XS-03: Our publisher produces decodable svID
echo ""
echo "--- XS-03: svID field present ---"
OUR_SVID=$(tshark -r /tmp/_xs_ours.pcap -Y "sv" -T fields -e sv.svID 2>/dev/null | head -1)
[ -n "$OUR_SVID" ] && pass "XS-03: svID=$OUR_SVID" || fail "XS-03: no svID"

echo ""
echo "Wire SV Cross-Validation: $PASS passed, $FAIL failed"
exit $FAIL
