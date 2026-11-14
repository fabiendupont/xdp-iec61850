#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Wire capture test: MMS setting groups (SGCB, IEC 61850-7-2 §14)
# via tshark.
#
# Runs the repo's own mms_setting_groups_wire scenario (server with
# an SG manager wired through the SGCB bridge, driven by the repo's
# own MMS client) on TCP loopback, captures the session on lo and
# validates the on-wire bytes with the neutral tshark MMS
# dissector.
#
# Tests: WS-01..WS-16 (ISO stack, SGCB attribute reads, the
# read-only $SG$ active-group view, the SE edit-session visibility
# rule, SelectEditSG, the SE-value write, SelectActiveSG
# activation and the release; both directions). The object names
# follow the 8-1 mapping wire-verified against the libiec61850
# reference server (WP-6x): LLN0$SP$SGCB$<attr>, <LN>$SE$<path>
# and <LN>$SG$<path>.
#
# Requires: tshark. Loopback capture needs root or the wireshark
# group; without either, falls back to a rootless user-namespace
# (unshare -Urn) + tcpdump capture when the environment allows it.
# Skips (77) when no capture method or no compiler/build tree is
# available.
#
# The scenario binary is compiled from
# tests/interop/wire/mms_setting_groups_wire.c against the meson
# build tree (the meson registration for new wire executables is a
# plain list addition only for scripts — see the WP-2d report). A
# prebuilt $BUILD/tests/mms_setting_groups_wire is preferred when
# present.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PCAP_FILE="/tmp/interop_mms_sgcb_$$.pcap"
PORT=10612
SCENARIO_SRC="mms_setting_groups_wire.c"
SCENARIO_NAME="mms_setting_groups_wire"

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
    # taken from the existing goose_wire_pub target so the exact set
    # of libraries and dependency paths the build configured is
    # reused.
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

echo "=== Wire MMS Setting Groups Tests ($CAPTURE_MODE capture) ==="

SCENARIO_PID=""
if ! run_captured; then
    echo "FAIL: mms_setting_groups_wire scenario failed"
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

# WS-01: TPKT framing on both directions
check_ge WS-01 "TPKT v3 client->server" "$C2S && tpkt.version==3" 5
check_ge WS-02 "TPKT v3 server->client" "$S2C && tpkt.version==3" 5

# WS-03: MMS Initiate request (c->s) and response (s->c)
check_ge WS-03 "MMS Initiate request (c->s)" "$C2S && mms.initiate_RequestPDU_element" 1
check_ge WS-04 "MMS Initiate response (s->c)" "$S2C && mms.initiate_ResponsePDU_element" 1

echo ""
echo "--- SGCB attribute reads (client -> server) ---"

# WS-05: SGCB component Reads carry the 8-1 object names (c->s).
# (Write requests carry the object name too, so read-only counts
# exclude mms.write_element.)
check_eq WS-05 "Read LLN0\$SP\$SGCB\$NumOfSG (c->s)" \
    "$C2S && mms.objectName_domain_specific_itemId == \"LLN0\$SP\$SGCB\$NumOfSG\" && !mms.write_element" 1
check_eq WS-06 "Read LLN0\$SP\$SGCB\$ActSG (c->s)" \
    "$C2S && mms.objectName_domain_specific_itemId == \"LLN0\$SP\$SGCB\$ActSG\" && !mms.write_element" 2
check_eq WS-07 "Read LLN0\$SP\$SGCB\$EditSG (c->s)" \
    "$C2S && mms.objectName_domain_specific_itemId == \"LLN0\$SP\$SGCB\$EditSG\" && !mms.write_element" 3
check_eq WS-08 "Read LLN0\$SP\$SGCB\$ResvTms (c->s)" \
    "$C2S && mms.objectName_domain_specific_itemId == \"LLN0\$SP\$SGCB\$ResvTms\" && !mms.write_element" 3

# WS-09: the SGCB reads are answered (s->c) with the expected
# unsigned values (NumOfSG=3, ActSG 1 -> 2, EditSG 0 -> 2 -> 0,
# ResvTms 0 -> 30 -> 0)
check_eq WS-09 "NumOfSG response = 3 (s->c)" \
    "$S2C && mms.read_element && mms.unsigned==3" 1
check_eq WS-09b "ResvTms response = 30 while reserved (s->c)" \
    "$S2C && mms.read_element && mms.unsigned==30" 1

echo ""
echo "--- setting-group value views (SE / SG) ---"

# WS-10: read-only active-group view ($SG$): before activation 100,
# after SelectActiveSG 200
check_eq WS-10 "Read PTOC1\$SG\$Mod\$setVal (c->s)" \
    "$C2S && mms.objectName_domain_specific_itemId == \"PTOC1\$SG\$Mod\$setVal\"" 3
check_eq WS-10b "\$SG\$ view response = 100 before activation (s->c)" \
    "$S2C && mms.read_element && mms.integer==100" 2
# WS-10c: after SelectActiveSG the $SG$ view serves the edited
# value — two integer-200 read responses overall: the in-session SE
# readback and the post-activation $SG$ view
check_eq WS-10c "integer 200 read responses: SE session + activated \$SG\$ (s->c)" \
    "$S2C && mms.read_element && mms.integer==200" 2

# WS-11: SE read outside an edit session: the request goes on the
# wire, but is answered with an MMS confirmed error (SE is the
# edit-session view — the store has no such object). The second SE
# read happens inside the edit session and succeeds.
check_eq WS-11 "Read PTOC1\$SE\$Mod\$setVal (c->s, reads only)" \
    "$C2S && mms.objectName_domain_specific_itemId == \"PTOC1\$SE\$Mod\$setVal\" && !mms.write_element" 2
check_eq WS-11b "SE read without session rejected: MMS error response (s->c)" \
    "$S2C && mms.confirmed_ErrorPDU_element" 1

echo ""
echo "--- edit session (SelectEditSG + SE write) ---"

# WS-12: SelectEditSG write (unsigned 2)
check_eq WS-12 "Write LLN0\$SP\$SGCB\$EditSG=2 (c->s)" \
    "$C2S && mms.write_element && mms.objectName_domain_specific_itemId == \"LLN0\$SP\$SGCB\$EditSG\" && mms.unsigned==2" 1

# WS-13: SE-value write into the edit group (integer 200)
check_eq WS-13 "Write PTOC1\$SE\$Mod\$setVal=200 (c->s)" \
    "$C2S && mms.write_element && mms.objectName_domain_specific_itemId == \"PTOC1\$SE\$Mod\$setVal\" && mms.integer==200" 1

# WS-14: the SE read inside the edit session is served with the
# edited value (200) — same response frame population as WS-10c's
# integer readbacks
check_ge WS-14 "Read PTOC1\$SE\$Mod\$setVal in session served (s->c)" \
    "$S2C && mms.read_element && mms.integer==200" 1

echo ""
echo "--- activation + release ---"

# WS-15: SelectActiveSG write (unsigned 2)
check_eq WS-15 "Write LLN0\$SP\$SGCB\$ActSG=2 (c->s)" \
    "$C2S && mms.write_element && mms.objectName_domain_specific_itemId == \"LLN0\$SP\$SGCB\$ActSG\" && mms.unsigned==2" 1

# WS-16: release write (EditSG=0)
check_eq WS-16 "Write LLN0\$SP\$SGCB\$EditSG=0 (c->s)" \
    "$C2S && mms.write_element && mms.objectName_domain_specific_itemId == \"LLN0\$SP\$SGCB\$EditSG\" && mms.unsigned==0" 1

echo ""
echo "--- JSON field validation (validate_pcap.py) ---"

# WS-17: tshark JSON field assertions (any-packet semantics)
if python3 "$SCRIPT_DIR/validate_pcap.py" "$PCAP_FILE" mms_setting_groups \
        --decode-as "tcp.port==$PORT,tpkt" >/tmp/val_sgcb_$$ 2>&1; then
    pass "WS-17: validate_pcap.py mms_setting_groups defaults"
else
    fail "WS-17: validate_pcap.py mms_setting_groups defaults"
    cat /tmp/val_sgcb_$$
fi
rm -f /tmp/val_sgcb_$$

echo ""
echo "Wire MMS Setting Groups: $PASS passed, $FAIL failed"
exit $FAIL
