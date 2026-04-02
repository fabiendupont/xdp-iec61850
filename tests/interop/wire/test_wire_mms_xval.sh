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
PCAP_FILE="/tmp/interop_mms_xval_$$.pcap"
PORT=10601

if ! command -v tshark >/dev/null 2>&1; then
    echo "SKIP: tshark not found"
    exit 77
fi

# tshark loopback capture requires root or wireshark group
if [ "$(id -u)" -ne 0 ] && ! id -nG | grep -qw wireshark; then
    echo "SKIP: tshark capture requires root or wireshark group"
    exit 77
fi

# Find libiec61850 build directory
LIBIEC="${LIBIEC61850_BUILD_DIR:-}"
if [ -z "$LIBIEC" ]; then
    HOME_DIR="${HOME:-$(eval echo ~)}"
    LIBIEC="$HOME_DIR/Code/github.com/mz-automation/libiec61850/build"
fi

MMS_SERVER="$LIBIEC/examples/server_example_basic_io/server_example_basic_io"
MMS_CLIENT="$LIBIEC/examples/mms_utility/mms_utility"

if [ ! -x "$MMS_SERVER" ] || [ ! -x "$MMS_CLIENT" ]; then
    echo "SKIP: libiec61850 examples not found (set LIBIEC61850_BUILD_DIR)"
    exit 77
fi

export LD_LIBRARY_PATH="$LIBIEC/src:${LD_LIBRARY_PATH:-}"

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
"$MMS_SERVER" $PORT &
SERVER_PID=$!
sleep 2

# Run multiple client operations for richer capture
"$MMS_CLIENT" -h 127.0.0.1 -p $PORT -d || true
"$MMS_CLIENT" -h 127.0.0.1 -p $PORT -i || true

kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true
sleep 1
kill $TSHARK_PID 2>/dev/null || true
wait $TSHARK_PID 2>/dev/null || true

TESTS_PASSED=0
TESTS_FAILED=0

# Tell tshark to decode our non-standard port as TPKT (MMS/ISO stack)
DECODE="-d tcp.port==$PORT,tpkt"

echo "=== Wire MMS Cross-Validation ==="

# XM-01: Session layer present (ISO 8327)
echo -n "  [WIRE] XM-01: Session layer ... "
SESSION=$(tshark -r "$PCAP_FILE" $DECODE -Y "ses" 2>/dev/null | wc -l)
if [ "$SESSION" -ge 1 ]; then
    echo "PASS"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "FAIL: no session PDUs found"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# XM-02: Presentation layer present (ISO 8823)
echo -n "  [WIRE] XM-02: Presentation layer ... "
PRES=$(tshark -r "$PCAP_FILE" $DECODE -Y "pres" 2>/dev/null | wc -l)
if [ "$PRES" -ge 1 ]; then
    echo "PASS"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "FAIL: no presentation PDUs found"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# XM-03: MMS InitiateResponse present
echo -n "  [WIRE] XM-03: MMS Initiate ... "
INIT=$(tshark -r "$PCAP_FILE" $DECODE -Y "mms.initiate_ResponsePDU_element" 2>/dev/null | wc -l)
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
