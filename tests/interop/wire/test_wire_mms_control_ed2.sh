#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Wire capture test: MMS Ed.2 control (select-before-operate) via tshark.
#
# Runs the repo's own mms_control_wire scenario (server with a control
# manager configured for strict sboClass objects, driven by a client
# using the repo's control services) on TCP loopback, captures the
# session on lo and validates the on-wire bytes with the neutral tshark
# MMS dissector.
#
# Tests: WC-01..WC-14 (ISO stack, Read context, Select/Operate/Cancel
# requests and responses, Ed.2 operate-without-select rejection as a
# ConfirmedError PDU; both directions).
#
# NOTE (asserted as-emitted): the repository's control services are
# house-encoded confirmed services (Select=[7], SelectWithValue=[8],
# Operate=[9], Cancel=[10] in confirmedServiceRequest). These CHOICE
# tags do not exist in ISO 9506-2 MMS (they collide with
# defineNamedVariable/defineScatteredAccess/getScatteredAccessAttributes/
# deleteVariableAccess), so tshark flags the service bodies as
# malformed while still decoding the confirmed request/response PDU
# structure, invokeIDs and the control object names in the payload.
# The assertions below check that structure and the payload strings.
# The Ed.2 rejection is a well-formed ConfirmedError PDU. Ed.2
# CommandTermination is delivered through the in-process termination
# callback (not as an MMS PDU), asserted as a negative check.
#
# Requires: tshark. Loopback capture needs root or the wireshark
# group; without either, falls back to a rootless user-namespace
# (unshare -Urn) + tcpdump capture when the environment allows it.
# Skips (77) when no capture method or no compiler/build tree is
# available.
#
# The scenario binary is compiled from tests/interop/wire/mms_control_wire.c
# against the meson build tree (the meson registration for new wire
# executables is a plain list addition only for scripts — see the WP-2d
# report). A prebuilt $BUILD/tests/mms_control_wire is preferred when
# present.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PCAP_FILE="/tmp/interop_mms_control_$$.pcap"
PORT=10611
SCENARIO_SRC="mms_control_wire.c"
SCENARIO_NAME="mms_control_wire"

if ! command -v tshark >/dev/null 2>&1; then
    echo "SKIP: tshark not found"
    exit 77
fi

# ------------------------------------------------------------------
# Build-tree / scenario-binary discovery
# ------------------------------------------------------------------
BUILD=""
for d in "$MESON_BUILD_ROOT" "$SCRIPT_DIR/../../../builddir" \
         "$SCRIPT_DIR/../../../builddir-full" \
         "$SCRIPT_DIR/../../../builddir-wp"; do
    if [ -n "$d" ] && [ -f "$d/build.ninja" ]; then
        BUILD="$(cd "$d" && pwd)"
        break
    fi
done

SCENARIO=""
if [ -n "$BUILD" ] && [ -x "$BUILD/tests/$SCENARIO_NAME" ]; then
    # Registered/prebuilt scenario binary (preferred).
    SCENARIO="$BUILD/tests/$SCENARIO_NAME"
elif [ -n "$BUILD" ] && command -v ninja >/dev/null 2>&1 && \
     command -v cc >/dev/null 2>&1; then
    # Compile the scenario against the build tree. The link line is
    # taken from the existing goose_wire_pub target so the exact set of
    # libraries and dependency paths the build configured is reused.
    OBJ="/tmp/${SCENARIO_NAME}_$$.o"
    SCENARIO="/tmp/${SCENARIO_NAME}_$$"
    SRC_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
    LINK_LINE="$(ninja -C "$BUILD" -t commands tests/goose_wire_pub 2>/dev/null | tail -1 || true)"
    if [ -z "$LINK_LINE" ]; then
        echo "SKIP: cannot derive a link line from the build tree"
        exit 77
    fi
    if ! cc -std=c11 -O2 -I"$SRC_ROOT/include/iec61850" \
         -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE \
         -c "$SCRIPT_DIR/$SCENARIO_SRC" -o "$OBJ"; then
        echo "SKIP: scenario compile failed"
        exit 77
    fi
    # shellcheck disable=SC2086 # LINK_LINE is a single cc invocation
    if ! (cd "$BUILD" && echo "$LINK_LINE" | \
          sed -e "s|-o tests/goose_wire_pub|-o $SCENARIO|" \
              -e "s|tests/goose_wire_pub.p/[^ ]*c.o|$OBJ|" \
              > /tmp/wp_link_cmd_$$ && sh /tmp/wp_link_cmd_$$); then
        rm -f /tmp/wp_link_cmd_$$ "$OBJ" "$SCENARIO"
        echo "SKIP: scenario link failed"
        exit 77
    fi
    rm -f /tmp/wp_link_cmd_$$ "$OBJ"
fi

if [ -z "$SCENARIO" ] || [ ! -x "$SCENARIO" ]; then
    echo "SKIP: $SCENARIO_NAME not built and cannot be compiled (need MESON_BUILD_ROOT)"
    exit 77
fi

# ------------------------------------------------------------------
# Capture method: direct tshark (root/wireshark group) or rootless
# user-namespace + tcpdump fallback.
# ------------------------------------------------------------------
CAPTURE_MODE="none"
if [ "$(id -u)" -eq 0 ] || id -nG | grep -qw wireshark; then
    CAPTURE_MODE="direct"
elif command -v unshare >/dev/null 2>&1 && \
     command -v tcpdump >/dev/null 2>&1 && \
     unshare -Urn sh -c 'ip link set lo up' 2>/dev/null; then
    CAPTURE_MODE="userns"
fi

if [ "$CAPTURE_MODE" = "none" ]; then
    echo "SKIP: loopback capture requires root, wireshark group, or unshare+tcpdump"
    exit 77
fi

cleanup() {
    [ -n "$SCENARIO_PID" ] && kill "$SCENARIO_PID" 2>/dev/null || true
    rm -f "$PCAP_FILE" "/tmp/${SCENARIO_NAME}_$$" "/tmp/wp_link_cmd_$$" \
          "/tmp/${SCENARIO_NAME}_$$.o"
}
trap cleanup EXIT

# Run the scenario under a loopback capture of the MMS port.
run_captured() {
    if [ "$CAPTURE_MODE" = "direct" ]; then
        tshark -i lo -f "tcp port $PORT" -w "$PCAP_FILE" \
               -a duration:120 >/dev/null 2>&1 &
        CAP_PID=$!
        sleep 1
        timeout 120 "$SCENARIO"
        RC=$?
        kill "$CAP_PID" 2>/dev/null || true
        wait "$CAP_PID" 2>/dev/null || true
        return $RC
    fi
    # Rootless: user+net namespace, lo up, tcpdump -Z root (the mapped
    # uid 0 keeps capture capabilities after the privilege drop).
    unshare -Urn sh -c '
        ip link set lo up 2>/dev/null || true
        tcpdump -i lo -f "tcp port '"$PORT"'" -w '"$PCAP_FILE"' \
                -Z root 2>/dev/null &
        TPID=$!
        sleep 1
        timeout 120 '"$SCENARIO"'
        RC=$?
        kill -TERM $TPID 2>/dev/null || true
        wait $TPID 2>/dev/null || true
        exit $RC
    '
}

echo "=== Wire MMS Ed.2 Control Tests ($CAPTURE_MODE capture) ==="

SCENARIO_PID=""
if ! run_captured; then
    echo "FAIL: mms_control_wire scenario failed"
    exit 1
fi

if [ ! -s "$PCAP_FILE" ]; then
    echo "FAIL: no packets captured"
    exit 1
fi

# Tell tshark to decode our non-standard port as TPKT (MMS/ISO stack)
DECODE="-d tcp.port==$PORT,tpkt"
C2S="tcp.dstport==$PORT"
S2C="tcp.srcport==$PORT"

PASS=0; FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

count_pkts() {
    tshark -r "$PCAP_FILE" $DECODE -Y "$1" 2>/dev/null | wc -l
}

# check_ge <id> <desc> <filter> <min>
check_ge() {
    C=$(count_pkts "$3")
    if [ "$C" -ge "$4" ]; then
        pass "$1: $2 ($C)"
    else
        fail "$1: $2 ($C < $4)"
    fi
}

# check_eq <id> <desc> <filter> <expected>
check_eq() {
    C=$(count_pkts "$3")
    if [ "$C" -eq "$4" ]; then
        pass "$1: $2 ($C)"
    else
        fail "$1: $2 ($C != $4)"
    fi
}

echo ""
echo "--- ISO transport + MMS association (both directions) ---"

# WC-01/02: TPKT framing on both directions
check_ge WC-01 "TPKT v3 client->server" "$C2S && tpkt.version==3" 3
check_ge WC-02 "TPKT v3 server->client" "$S2C && tpkt.version==3" 3

# WC-03: COTP CR/CC handshake
check_ge WC-03 "COTP CR + CC handshake" "cotp.type==0x0e || cotp.type==0x0d" 2

# WC-04: MMS Initiate request (c->s) and response (s->c)
check_ge WC-04 "MMS Initiate request (c->s)" "$C2S && mms.initiate_RequestPDU_element" 1
check_ge WC-05 "MMS Initiate response (s->c)" "$S2C && mms.initiate_ResponsePDU_element" 1

echo ""
echo "--- status-point read (object context) ---"

# WC-06: Read of the controllable object's status point (c->s) and
# its success response (s->c)
check_ge WC-06 "Read XCBR1\$ST\$Pos\$stVal (c->s)" \
    "$C2S && mms.read_element && mms.objectName_domain_specific_itemId == \"XCBR1\$ST\$Pos\$stVal\"" 1
check_ge WC-07 "Read response success (s->c)" \
    "$S2C && mms.read_element && mms.success" 1

echo ""
echo "--- Select / Operate / Cancel (house-encoded services) ---"

# WC-08: Select (SBO) request on the strict object (c->s); service tag
# [7], control object name in the payload
check_eq WC-08 "Select request on XCBR1 (c->s)" \
    "$C2S && mms.confirmedServiceRequest==7 && tcp.payload contains \"XCBR1\$CO\$Pos\"" 1

# WC-09: Select responses (s->c) — one per Select (XCBR1 + CSWI1)
check_eq WC-09 "Select responses (s->c)" \
    "$S2C && mms.confirmedServiceResponse==7" 2

# WC-10: Operate request with the selection (c->s), service tag [9]
check_eq WC-10 "Operate request on XCBR1 (c->s)" \
    "$C2S && mms.confirmedServiceRequest==9 && tcp.payload contains \"XCBR1\$CO\$Pos\"" 1

# WC-11: Operate response (s->c)
check_eq WC-11 "Operate response (s->c)" \
    "$S2C && mms.confirmedServiceResponse==9" 1

# WC-12: Select then Cancel on the second (rejection-target) object
check_eq WC-12 "Select request on CSWI1 (c->s)" \
    "$C2S && mms.confirmedServiceRequest==7 && tcp.payload contains \"CSWI1\$CO\$Pos\"" 1
check_eq WC-13 "Cancel request on CSWI1 (c->s)" \
    "$C2S && mms.confirmedServiceRequest==10 && tcp.payload contains \"CSWI1\$CO\$Pos\"" 1
check_eq WC-14 "Cancel response (s->c)" \
    "$S2C && mms.confirmedServiceResponse==10" 1

echo ""
echo "--- Ed.2 rejection: operate without select on a strict object ---"

# WC-15: the bare Operate on the (now unselected) strict object (c->s)
check_eq WC-15 "Operate-without-select on CSWI1 (c->s)" \
    "$C2S && mms.confirmedServiceRequest==9 && tcp.payload contains \"CSWI1\$CO\$Pos\"" 1

# WC-16: ... is answered by a ConfirmedError PDU (s->c), correlated
# with the rejected operate's invokeID
check_eq WC-16 "ConfirmedError PDU (s->c)" \
    "$S2C && mms.confirmed_ErrorPDU_element" 1
ERR_INVOKE=$(tshark -r "$PCAP_FILE" $DECODE -Y "$S2C && mms.confirmed_ErrorPDU_element" \
             -T fields -e mms.invokeID 2>/dev/null | head -1)
REJ_INVOKE=$(tshark -r "$PCAP_FILE" $DECODE \
             -Y "$C2S && mms.confirmedServiceRequest==9 && tcp.payload contains \"CSWI1\$CO\$Pos\"" \
             -T fields -e mms.invokeID 2>/dev/null | head -1)
if [ -n "$ERR_INVOKE" ] && [ "$ERR_INVOKE" = "$REJ_INVOKE" ]; then
    pass "WC-17: ConfirmedError invokeID matches rejected operate ($ERR_INVOKE)"
else
    fail "WC-17: ConfirmedError invokeID ($ERR_INVOKE) != operate invokeID ($REJ_INVOKE)"
fi

# WC-18: no operate response for the rejected command (only ONE
# operate response in the capture, for the successful XCBR1 operate)
check_eq WC-18 "exactly one Operate response" \
    "$S2C && mms.confirmedServiceResponse==9" 1

echo ""
echo "--- CommandTermination (as-emitted check) ---"

# WC-19: Ed.2 command termination is delivered through the in-process
# termination callback in this implementation, NOT as an MMS PDU —
# no InformationReport may appear in the control capture.
check_eq WC-19 "no InformationReport on the wire" \
    "mms.informationReport_element" 0

echo ""
echo "--- JSON field validation (validate_pcap.py) ---"

# WC-20: tshark JSON field assertions (any-packet semantics)
if python3 "$SCRIPT_DIR/validate_pcap.py" "$PCAP_FILE" mms_control_ed2 \
        --decode-as "tcp.port==$PORT,tpkt" >/tmp/val_wp_$$ 2>&1; then
    pass "WC-20: validate_pcap.py mms_control_ed2 defaults (tpkt/Select/Operate tags)"
else
    fail "WC-20: validate_pcap.py mms_control_ed2 defaults"
    cat /tmp/val_wp_$$
fi
rm -f /tmp/val_wp_$$

echo ""
echo "Wire MMS Ed.2 Control: $PASS passed, $FAIL failed"
exit $FAIL
