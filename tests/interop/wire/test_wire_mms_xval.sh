#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Wire cross-validation test: MMS session establishment against libiec61850.
#
# Captures the TCP handshake + ISO stack negotiation between our MMS
# client and a libiec61850 server, then validates with tshark.
# Requires: tshark, libiec61850 helpers
# No root needed — TCP loopback.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INTEROP_DIR="$(dirname "$SCRIPT_DIR")"
HELPER_DIR="${INTEROP_HELPER_DIR:-$INTEROP_DIR/helpers}"
PCAP_FILE="/tmp/interop_mms_xval_$$.pcap"
PORT=10601

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

# Run multiple client operations for richer capture
"$HELPER_DIR/mms_client_helper" 127.0.0.1 $PORT getdomains || true
"$HELPER_DIR/mms_client_helper" 127.0.0.1 $PORT read IED1LD0 "LLN0.Beh.stVal" || true

kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true
sleep 1
kill $TSHARK_PID 2>/dev/null || true
wait $TSHARK_PID 2>/dev/null || true

TESTS_PASSED=0
TESTS_FAILED=0

echo "=== Wire MMS Cross-Validation ==="

# XM-01: Session layer present (ISO 8327)
echo -n "  [WIRE] XM-01: Session layer ... "
SESSION=$(tshark -r "$PCAP_FILE" -Y "ses" 2>/dev/null | wc -l)
if [ "$SESSION" -ge 1 ]; then
    echo "PASS"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "FAIL: no session PDUs found"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# XM-02: Presentation layer present (ISO 8823)
echo -n "  [WIRE] XM-02: Presentation layer ... "
PRES=$(tshark -r "$PCAP_FILE" -Y "pres" 2>/dev/null | wc -l)
if [ "$PRES" -ge 1 ]; then
    echo "PASS"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "FAIL: no presentation PDUs found"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# XM-03: MMS InitiateResponse present
echo -n "  [WIRE] XM-03: MMS Initiate ... "
INIT=$(tshark -r "$PCAP_FILE" -Y "mms.initiateResponsePDU" 2>/dev/null | wc -l)
if [ "$INIT" -ge 1 ]; then
    echo "PASS"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "FAIL: no MMS InitiateResponse found"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

echo ""
echo "Wire MMS Cross-Validation: $TESTS_PASSED passed, $TESTS_FAILED failed"
exit $TESTS_FAILED
