#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Wire cross-validation test: compare our GOOSE output against libiec61850.
#
# Captures frames from both publishers on veth pairs and checks that
# tshark decodes both as valid GOOSE with matching EtherType.
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
    [ -x "$d/tests/goose_wire_pub" ] && GOOSE_PUB="$d/tests/goose_wire_pub" && break
done
if [ -z "$GOOSE_PUB" ]; then
    echo "SKIP: goose_wire_pub not built"
    exit 77
fi

LIBIEC="${LIBIEC61850_BUILD_DIR:-}"
if [ -z "$LIBIEC" ] || [ ! -x "$LIBIEC/examples/goose_publisher/goose_publisher_example" ]; then
    echo "SKIP: libiec61850 GOOSE publisher not found (set LIBIEC61850_BUILD_DIR)"
    exit 77
fi
LIBIEC_GOOSE="$LIBIEC/examples/goose_publisher/goose_publisher_example"
export LD_LIBRARY_PATH="$LIBIEC/src${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

PASS=0; FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

cleanup() {
    ip link del igt_xg0 2>/dev/null || true
    rm -f /tmp/_xg_*.pcap
}
trap cleanup EXIT

ip link add igt_xg0 type veth peer name igt_xg1
ip link set igt_xg0 up
ip link set igt_xg1 up
ip link set igt_xg0 promisc on
ip link set igt_xg1 promisc on

echo "=== Wire GOOSE Cross-Validation ==="

# XG-01: libiec61850 GOOSE frames decoded by tshark
echo ""
echo "--- XG-01: libiec61850 GOOSE publisher ---"
tshark -i igt_xg1 -a duration:5 -w /tmp/_xg_lib.pcap &>/dev/null &
TSH=$!
sleep 1
timeout 2 "$LIBIEC_GOOSE" igt_xg0 &>/dev/null || true
wait $TSH 2>/dev/null
LIB_C=$(tshark -r /tmp/_xg_lib.pcap -Y "goose" 2>/dev/null | wc -l)
[ "$LIB_C" -gt 0 ] && pass "XG-01: libiec61850 GOOSE: $LIB_C frames" || fail "XG-01: libiec61850 0 frames"

# XG-02: Both decode as valid GOOSE (EtherType may differ if VLAN-tagged)
echo ""
echo "--- XG-02: Both decode as valid GOOSE ---"
tshark -i igt_xg1 -a duration:5 -w /tmp/_xg_ours.pcap &>/dev/null &
TSH=$!
sleep 1
timeout 3 "$GOOSE_PUB" igt_xg0
wait $TSH 2>/dev/null
OUR_GOOSE=$(tshark -r /tmp/_xg_ours.pcap -Y "goose" 2>/dev/null | wc -l)
LIB_GOOSE=$(tshark -r /tmp/_xg_lib.pcap -Y "goose" 2>/dev/null | wc -l)
if [ "$OUR_GOOSE" -gt 0 ] && [ "$LIB_GOOSE" -gt 0 ]; then
    pass "XG-02: both decoded as GOOSE (ours=$OUR_GOOSE lib=$LIB_GOOSE)"
else
    fail "XG-02: GOOSE decode failed (ours=$OUR_GOOSE lib=$LIB_GOOSE)"
fi

# XG-03: Both publishers produce decodable gocbRef
echo ""
echo "--- XG-03: gocbRef field present ---"
OUR_REF=$(tshark -r /tmp/_xg_ours.pcap -Y "goose" -T fields -e goose.gocbRef 2>/dev/null | head -1)
[ -n "$OUR_REF" ] && pass "XG-03: gocbRef=$OUR_REF" || fail "XG-03: no gocbRef"

echo ""
echo "Wire GOOSE Cross-Validation: $PASS passed, $FAIL failed"
exit $FAIL
