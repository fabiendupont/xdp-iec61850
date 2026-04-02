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
PCAP_FILE="/tmp/interop_mms_$$.pcap"
PORT=10600

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
    # Auto-detect common location
    HOME_DIR="${HOME:-$(eval echo ~)}"
    LIBIEC="$HOME_DIR/Code/github.com/mz-automation/libiec61850/build"
fi

MMS_SERVER="$LIBIEC/examples/server_example_basic_io/server_example_basic_io"
MMS_CLIENT="$LIBIEC/examples/mms_utility/mms_utility"

if [ ! -x "$MMS_SERVER" ] || [ ! -x "$MMS_CLIENT" ]; then
    echo "SKIP: libiec61850 examples not found (set LIBIEC61850_BUILD_DIR)"
    exit 77
fi

# Set LD_LIBRARY_PATH for shared lib
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

# Run client operations (mms_utility: -h host -p port -d list domains)
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

echo "=== Wire MMS Tests ==="

# WM-01: TPKT framing (version=3)
echo -n "  [WIRE] WM-01: TPKT framing ... "
TPKT=$(tshark -r "$PCAP_FILE" $DECODE -Y "tpkt" -T fields -e tpkt.version 2>/dev/null | head -1)
if [ "$TPKT" = "3" ]; then
    echo "PASS"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "FAIL: TPKT version=$TPKT"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# WM-02: COTP CR/CC handshake
echo -n "  [WIRE] WM-02: COTP handshake ... "
COTP_CR=$(tshark -r "$PCAP_FILE" $DECODE -Y "cotp.type == 0x0e" 2>/dev/null | wc -l)
COTP_CC=$(tshark -r "$PCAP_FILE" $DECODE -Y "cotp.type == 0x0d" 2>/dev/null | wc -l)
if [ "$COTP_CR" -ge 1 ] && [ "$COTP_CC" -ge 1 ]; then
    echo "PASS"
    TESTS_PASSED=$((TESTS_PASSED + 1))
else
    echo "FAIL: CR=$COTP_CR CC=$COTP_CC"
    TESTS_FAILED=$((TESTS_FAILED + 1))
fi

# WM-03: MMS PDU present
echo -n "  [WIRE] WM-03: MMS PDU ... "
MMS=$(tshark -r "$PCAP_FILE" $DECODE -Y "mms" 2>/dev/null | wc -l)
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
