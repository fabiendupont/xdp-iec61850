#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Wire capture test: MMS/ISO transport validation via tshark.
#
# Tests: WM-01 (TPKT), WM-02 (COTP), WM-03 (InitiateResponse)
# No root needed — TCP loopback.
# Requires: tshark

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_DIR="$(dirname "$SCRIPT_DIR")"
HELPER_DIR="${INTEROP_HELPER_DIR:-$INTEROP_DIR/helpers}"
PCAP_FILE="/tmp/interop_mms_$$.pcap"
PORT=10600

if ! command -v tshark >/dev/null 2>&1; then
    echo "SKIP: tshark not found"
    exit 77
fi

if [ ! -x "$HELPER_DIR/mms_server_helper" ] || \
   [ ! -x "$HELPER_DIR/mms_client_helper" ]; then
    echo "SKIP: libiec61850 helpers not built"
    exit 77
fi

ICD_FILE="$INTEROP_DIR/scl/interop_test.icd"
if [ ! -f "$ICD_FILE" ]; then
    echo "SKIP: ICD file not found"
    exit 77
fi

cleanup() {
    kill $SERVER_PID 2>/dev/null || true
    kill $TSHARK_PID 2>/dev/null || true
    rm -f "$PCAP_FILE"
}
trap cleanup EXIT

# Start tshark capture on loopback
tshark -i lo -f "tcp port $PORT" -w "$PCAP_FILE" -a duration:10 &
TSHARK_PID=$!
sleep 1

# Start libiec61850 server
"$HELPER_DIR/mms_server_helper" $PORT "$ICD_FILE" &
SERVER_PID=$!
sleep 2

# Run client operations
"$HELPER_DIR/mms_client_helper" 127.0.0.1 $PORT getdomains || true
"$HELPER_DIR/mms_client_helper" 127.0.0.1 $PORT read IED1LD0 "LLN0.Beh.stVal" || true

kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true
sleep 1
kill $TSHARK_PID 2>/dev/null || true
wait $TSHARK_PID 2>/dev/null || true

TESTS_PASSED=0
TESTS_FAILED=0

echo "=== Wire MMS Tests ==="

# WM-01: TPKT framing (version=3)
echo -n "  [WIRE] WM-01: TPKT framing ... "
TPKT=$(tshark -r "$PCAP_FILE" -Y "tpkt" -T fields -e tpkt.version 2>/dev/null | head -1)
if [ "$TPKT" = "3" ]; then
    echo "PASS"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "FAIL: TPKT version=$TPKT"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# WM-02: COTP CR/CC handshake
echo -n "  [WIRE] WM-02: COTP handshake ... "
COTP_CR=$(tshark -r "$PCAP_FILE" -Y "cotp.type == 0xe0" 2>/dev/null | wc -l)
COTP_CC=$(tshark -r "$PCAP_FILE" -Y "cotp.type == 0xd0" 2>/dev/null | wc -l)
if [ "$COTP_CR" -ge 1 ] && [ "$COTP_CC" -ge 1 ]; then
    echo "PASS"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "FAIL: CR=$COTP_CR CC=$COTP_CC"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# WM-03: MMS PDU present
echo -n "  [WIRE] WM-03: MMS PDU ... "
MMS=$(tshark -r "$PCAP_FILE" -Y "mms" 2>/dev/null | wc -l)
if [ "$MMS" -ge 1 ]; then
    echo "PASS"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "FAIL: no MMS PDUs found"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

echo ""
echo "Wire MMS: $TESTS_PASSED passed, $TESTS_FAILED failed"
exit $TESTS_FAILED
