#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Wire capture test: MMS Ed.2 reporting (RCB enrollment + reports) via tshark.
#
# Runs the repo's own mms_report_wire scenario (server with an RCB
# manager + SCL-auto-configured RCBs, driven by the repo's own MMS
# client) on TCP loopback, captures the session on lo and validates
# the on-wire bytes with the neutral tshark MMS dissector.
#
# Tests: WR-01..WR-31 (ISO stack, RCB discovery, Ed.2 component
# writes, InformationReports, BRCB EntryID/resume/purge; both
# directions). Since WP-2z the server emits conformant IEC 61850-7-2
# report bodies (mms_encode_iec61850_report): the report assertions
# check the dissected AccessResult fields (rptID/seqNum/entryID) and
# require BER-error-free dissection, replacing the pre-WP-2z
# non-conformant-layout byte patterns.
#
# Requires: tshark. Loopback capture needs root or the wireshark
# group; without either, falls back to a rootless user-namespace
# (unshare -Urn) + tcpdump capture when the environment allows it.
# Skips (77) when no capture method or no compiler/build tree is
# available.
#
# The scenario binary is compiled from tests/interop/wire/mms_report_wire.c
# against the meson build tree (the meson registration for new wire
# executables is a plain list addition only for scripts — see the WP-2d
# report). A prebuilt $BUILD/tests/mms_report_wire is preferred when
# present.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PCAP_FILE="/tmp/interop_mms_report_$$.pcap"
PORT=10610
SCENARIO_SRC="mms_report_wire.c"
SCENARIO_NAME="mms_report_wire"

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

echo "=== Wire MMS Ed.2 Report Tests ($CAPTURE_MODE capture) ==="

SCENARIO_PID=""
if ! run_captured; then
    echo "FAIL: mms_report_wire scenario failed"
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

# WR-01: TPKT framing on both directions
check_ge WR-01 "TPKT v3 client->server" "$C2S && tpkt.version==3" 5
check_ge WR-02 "TPKT v3 server->client" "$S2C && tpkt.version==3" 5

# WR-03: COTP CR/CC handshake
check_ge WR-03 "COTP CR + CC handshake" "cotp.type==0x0e || cotp.type==0x0d" 2

# WR-04: ISO session + presentation layers present
check_ge WR-04 "session + presentation PDUs" "ses && pres" 2

# WR-05: MMS Initiate request (c->s) and response (s->c)
check_ge WR-05 "MMS Initiate request (c->s)" "$C2S && mms.initiate_RequestPDU_element" 1
check_ge WR-06 "MMS Initiate response (s->c)" "$S2C && mms.initiate_ResponsePDU_element" 1

echo ""
echo "--- RCB discovery + component reads ---"

# WR-07: GetNameList discovers the RCB component objects (c->s request)
check_ge WR-07 "GetNameList request (c->s)" "$C2S && mms.getNameList_element" 1

# WR-08: discovery response lists the $-separated component names (s->c)
check_ge WR-08 "URCB components in namelist (s->c)" \
    "$S2C && mms.Identifier == \"LLN0\$RP\$URCB01\$RptEna\"" 1
check_ge WR-09 "BRCB components in namelist (s->c)" \
    "$S2C && mms.Identifier == \"LLN0\$BR\$BRCB01\$EntryID\"" 1

# WR-10: component Reads carry the correct object names (c->s)
check_ge WR-10 "Read LLN0\$RP\$URCB01\$RptEna (c->s)" \
    "$C2S && mms.objectName_domain_specific_itemId == \"LLN0\$RP\$URCB01\$RptEna\"" 3
check_ge WR-11 "Read LLN0\$BR\$BRCB01\$EntryID (c->s)" \
    "$C2S && mms.objectName_domain_specific_itemId == \"LLN0\$BR\$BRCB01\$EntryID\"" 2

echo ""
echo "--- Ed.2 enrollment writes (client -> server) ---"

# WR-12: Ed.2 rejection first — RptEna=TRUE on an unreserved URCB
check_ge WR-12 "Write RptEna=TRUE (c->s)" \
    "$C2S && mms.write_element && mms.objectName_domain_specific_itemId == \"LLN0\$RP\$URCB01\$RptEna\" && mms.boolean==True" 2

# WR-13: ... is rejected in-band by the server as a Write failure
# (DataAccessError temporarily-unavailable (2))
check_eq WR-13 "Write-Response failure=2 (s->c)" \
    "$S2C && mms.failure==2" 1

# WR-14: reservation + configuration component writes (Ed.2 order)
check_ge WR-14 "Write Resv=TRUE (c->s)" \
    "$C2S && mms.write_element && mms.objectName_domain_specific_itemId == \"LLN0\$RP\$URCB01\$Resv\" && mms.boolean==True" 1
check_ge WR-15 "Write RptID (c->s)" \
    "$C2S && mms.write_element && mms.objectName_domain_specific_itemId == \"LLN0\$RP\$URCB01\$RptID\"" 1
check_ge WR-16 "Write DatSet (c->s)" \
    "$C2S && mms.write_element && mms.objectName_domain_specific_itemId == \"LLN0\$RP\$URCB01\$DatSet\"" 1
check_ge WR-17 "Write OptFlds + TrgOps (c->s)" \
    "$C2S && mms.write_element && (mms.objectName_domain_specific_itemId == \"LLN0\$RP\$URCB01\$OptFlds\" || mms.objectName_domain_specific_itemId == \"LLN0\$RP\$URCB01\$TrgOps\")" 2

# WR-18: GI armed through the GI component (after enrollment)
check_eq WR-18 "Write GI=TRUE (c->s)" \
    "$C2S && mms.write_element && mms.objectName_domain_specific_itemId == \"LLN0\$RP\$URCB01\$GI\" && mms.boolean==True" 1

echo ""
echo "--- InformationReports (server -> client) ---"

# WR-19: the reports fired by the scenario: 1 dchg + 1 GI (URCB R1) +
# 2 live + 2 resume + 1 post-resume (BRCB B1) = 7, all server->client
check_eq WR-19 "InformationReports (s->c)" \
    "$S2C && mms.informationReport_element" 7

# WR-20: report rptID on the wire — WP-2z conformant layout: the VAS
# is the vmd-specific "RPT" marker and the rptID is the first
# AccessResult, dissected by tshark as mms.iec61850.rptid (URCB
# reports R1, BRCB reports B1); the report bodies carry no BER errors
check_eq WR-20 "reports with rptID R1" \
    "mms.informationReport_element && mms.iec61850.rptid == \"R1\"" 2
check_eq WR-21 "reports with rptID B1" \
    "mms.informationReport_element && mms.iec61850.rptid == \"B1\"" 5

# WR-22: report seqNum — WP-2z conformant layout: seqNum is an
# AccessResult unsigned [6] (mms.iec61850.seqnum), no longer the
# non-conformant trailing [2] field; sqNum 1 for the first URCB
# data-change report, 2 for the GI report
check_eq WR-22 "sqNum=1 in R1 report" \
    "mms.informationReport_element && mms.iec61850.rptid == \"R1\" && mms.iec61850.seqnum == 1" 1
check_eq WR-23 "sqNum=2 in R1 report (GI)" \
    "mms.informationReport_element && mms.iec61850.rptid == \"R1\" && mms.iec61850.seqnum == 2" 1

# WR-24: BRCB EntryID in reports — WP-2z conformant layout: entryID
# is an AccessResult octet string [9] between datSet and confRev
# (mms.data.octet-string), no longer the non-conformant trailing [6]
# field: live entries 1+2, resume entries 3+4, post-resume 5
check_eq WR-24 "EntryID=1 in B1 report" \
    "mms.informationReport_element && mms.iec61850.rptid == \"B1\" && mms.data.octet-string == 00:00:00:00:00:00:00:01" 1
check_eq WR-25 "EntryID=3+4 in resume reports" \
    "mms.informationReport_element && mms.iec61850.rptid == \"B1\" && (mms.data.octet-string == 00:00:00:00:00:00:00:03 || mms.data.octet-string == 00:00:00:00:00:00:00:04)" 2
check_eq WR-26 "EntryID=5 in post-resume report" \
    "mms.informationReport_element && mms.iec61850.rptid == \"B1\" && mms.data.octet-string == 00:00:00:00:00:00:00:05" 1

# WR-26b: WP-2z conformant layout: every report body dissects cleanly
# in tshark — no BER errors (the pre-WP-2z layout raised "Wrong field
# in SEQUENCE" / "beyond the end of the known sequence definition" on
# every InformationReport; only the unrelated ACSE release PDUs keep
# their pre-existing dissector quirk)
check_eq WR-26b "report bodies free of BER errors" \
    "mms.informationReport_element && _ws.malformed" 0

echo ""
echo "--- BRCB EntryID / PurgeBuf component writes ---"

# WR-27: resume armed by an EntryID component write (octet string,
# 8-byte big-endian 2)
check_eq WR-27 "Write EntryID=2 (c->s)" \
    "$C2S && mms.write_element && mms.objectName_domain_specific_itemId == \"LLN0\$BR\$BRCB01\$EntryID\" && tcp.payload contains 89:08:00:00:00:00:00:00:00:02" 1

# WR-28: PurgeBuf component write
check_ge WR-28 "Write PurgeBuf (c->s)" \
    "$C2S && mms.write_element && mms.objectName_domain_specific_itemId == \"LLN0\$BR\$BRCB01\$PurgeBuf\"" 1

# WR-29: monitored data-point writes from the client (dataset members)
check_ge WR-29 "Write stVal data point (c->s)" \
    "$C2S && mms.write_element && mms.objectName_domain_specific_itemId == \"XCBR1\$ST\$Pos\$stVal\"" 3
check_ge WR-30 "Write Hz data point (c->s)" \
    "$C2S && mms.write_element && mms.objectName_domain_specific_itemId == \"MMXU1\$MX\$Hz\$mag\$f\"" 1

echo ""
echo "--- JSON field validation (validate_pcap.py) ---"

# WR-31..WR-33: tshark JSON field assertions (any-packet semantics)
if python3 "$SCRIPT_DIR/validate_pcap.py" "$PCAP_FILE" mms_report \
        --decode-as "tcp.port==$PORT,tpkt" >/tmp/val_wp_$$ 2>&1; then
    pass "WR-31: validate_pcap.py mms_report defaults (tpkt/rptID/Ed.2 failure)"
else
    fail "WR-31: validate_pcap.py mms_report defaults"
    cat /tmp/val_wp_$$
fi
rm -f /tmp/val_wp_$$

echo ""
echo "Wire MMS Ed.2 Report: $PASS passed, $FAIL failed"
exit $FAIL
