#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Wire capture test: GOOSE frame validation via tshark.
#
# Tests our GOOSE publisher output and optionally libiec61850's.
# Requires: root or a rootless user-namespace fallback
# (unshare -Urn + tcpdump on lo), and tshark.
# Optional: LIBIEC61850_BUILD_DIR for cross-validation
#
# WG-01..WG-04: ordinary GOOSE frames (5 sent by goose_wire_pub).
# WG-05..WG-08 (WP-6x): the publisher also sends one test-mode
# frame (IEC 61850-8-1 PDU [7] test bit) and one simulation frame
# (Ed.2 frame-level simulation bit, the reserved1 LSB). Both bits
# are asserted with tshark byte patterns on the captured frames:
# the publisher sends untagged frames (vlan_id=0), so reserved1 is
# the first octet after the PDU length field — frame offset 18 —
# and the PDU test bit is the [7] IMPLICIT BOOLEAN (tag 0x87,
# length 1, 0x01 = TRUE, 0x00 = FALSE).

set -e

if ! command -v tshark >/dev/null 2>&1; then
    echo "SKIP: tshark not found"
    exit 77
fi

# Find our wire publisher (built by meson)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
for d in "$MESON_BUILD_ROOT" "$SCRIPT_DIR/../../../builddir-full" \
         "$SCRIPT_DIR/../../../builddir" "$SCRIPT_DIR/../../../builddir-wp"; do
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

# Capture method: root (veth pair, matches the original setup) or
# rootless user+net namespace with the publisher and capture on lo.
CAPTURE_MODE="none"
if [ "$(id -u)" -eq 0 ]; then
    CAPTURE_MODE="veth"
elif command -v unshare >/dev/null 2>&1 && \
     command -v tcpdump >/dev/null 2>&1 && \
     unshare -Urn sh -c 'ip link set lo up' 2>/dev/null; then
    CAPTURE_MODE="userns"
fi

if [ "$CAPTURE_MODE" = "none" ]; then
    echo "SKIP: requires root or unshare+tcpdump"
    exit 77
fi

echo "=== Wire GOOSE Tests ($CAPTURE_MODE capture) ==="

if [ "$CAPTURE_MODE" = "veth" ]; then
    ip link add igt_wg0 type veth peer name igt_wg1
    ip link set igt_wg0 up
    ip link set igt_wg1 up
    ip link set igt_wg0 promisc on
    ip link set igt_wg1 promisc on

    OURS_IFACE=igt_wg0
    # WG-01: Our GOOSE publisher produces valid frames
    echo ""
    echo "--- WG-01: Our GOOSE publisher ---"
    tshark -i igt_wg1 -a duration:5 -w /tmp/_wg_ours.pcap &>/dev/null &
    TSH=$!
    sleep 1
    timeout 3 "$GOOSE_PUB" igt_wg0
    wait $TSH 2>/dev/null
else
    OURS_IFACE=lo
    echo ""
    echo "--- WG-01: Our GOOSE publisher (rootless, lo) ---"
    unshare -Urn sh -c '
        ip link set lo up 2>/dev/null || true
        tcpdump -i lo -w /tmp/_wg_ours.pcap -Z root 2>/dev/null &
        TPID=$!
        sleep 1
        timeout 3 '"$GOOSE_PUB"' lo
        sleep 1
        kill -TERM $TPID 2>/dev/null || true
        wait $TPID 2>/dev/null || true
    '
fi

C=$(tshark -r /tmp/_wg_ours.pcap -Y "goose || eth.type==0x88b8" 2>/dev/null | wc -l)
[ "$C" -gt 0 ] && pass "WG-01: $C GOOSE frames captured" || fail "WG-01: 0 frames"

# WG-02: tshark decodes our frames as valid GOOSE
G=$(tshark -r /tmp/_wg_ours.pcap -Y "goose" 2>/dev/null | wc -l)
[ "$G" -gt 0 ] && pass "WG-02: tshark decoded as valid GOOSE" || fail "WG-02: not decoded as GOOSE"

# WG-03: APPID field present
APPID=$(tshark -r /tmp/_wg_ours.pcap -Y "goose" -T fields -e goose.appid 2>/dev/null | head -1)
[ -n "$APPID" ] && pass "WG-03: APPID=$APPID" || fail "WG-03: no APPID field"

# WG-04: libiec61850 GOOSE publisher (optional cross-validation,
# root/veth path only — it needs the veth pair)
if [ "$CAPTURE_MODE" = "veth" ] && [ -n "$LIBIEC_GOOSE" ]; then
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
    echo "  SKIP: WG-04 (root/veth + LIBIEC61850_BUILD_DIR not available)"
fi

echo ""
echo "--- WG-05..WG-08: Ed.2 test/simulation bits (WP-6x) ---"

# The publisher sends 5 ordinary + 1 test-mode + 1 simulation frame.
# WG-05: all seven are on the wire and dissect as GOOSE
N=$(tshark -r /tmp/_wg_ours.pcap -Y "goose" 2>/dev/null | wc -l)
[ "$N" -eq 7 ] && pass "WG-05: 5 ordinary + 1 test + 1 simulation frame ($N)" || fail "WG-05: expected 7 GOOSE frames, got $N"

# WG-06: exactly one test-mode frame — the PDU [7] test bit is the
# IMPLICIT BOOLEAN 87:01:01 in the GOOSE APDU (untagged frames:
# byte pattern unique to the test field)
T=$(tshark -r /tmp/_wg_ours.pcap -Y "goose && frame contains 87:01:01" 2>/dev/null | wc -l)
[ "$T" -eq 1 ] && pass "WG-06: one test-mode frame (PDU [7] test bit set)" || fail "WG-06: expected 1 test-mode frame, got $T"

# WG-06b: tshark's own decode of the PDU test bit agrees
TS=$(tshark -r /tmp/_wg_ours.pcap -Y "goose && goose.simulation == True" 2>/dev/null | wc -l)
[ "$TS" -eq 1 ] && pass "WG-06b: tshark decodes the PDU test bit" || fail "WG-06b: expected 1 frame with the PDU test bit, got $TS"

# WG-07: exactly one simulation frame — the Ed.2 frame-level
# simulation bit is the LSB of reserved1, frame offset 18 in the
# publisher's untagged frames
S=$(tshark -r /tmp/_wg_ours.pcap -Y "goose && frame[18] == 1" 2>/dev/null | wc -l)
[ "$S" -eq 1 ] && pass "WG-07: one simulation frame (reserved1 LSB set)" || fail "WG-07: expected 1 simulation frame, got $S"

# WG-08: the five ordinary frames carry neither bit
O=$(tshark -r /tmp/_wg_ours.pcap -Y "goose && frame[18] == 0 && !(frame contains 87:01:01)" 2>/dev/null | wc -l)
[ "$O" -eq 5 ] && pass "WG-08: 5 ordinary frames (no test, no simulation)" || fail "WG-08: expected 5 ordinary frames, got $O"

echo ""
echo "Wire GOOSE: $PASS passed, $FAIL failed"
exit $FAIL
