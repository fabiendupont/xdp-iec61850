#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Wire capture test: IEC TR 61850-90-5 routable profiles (R-GOOSE /
# R-SV) via tshark.
#
# Runs the repo's own rgoose_wire_pub scenario (plain + secured
# R-GOOSE and R-SV on UDP loopback), captures the traffic on lo and
# validates the on-wire bytes with the neutral tshark UDP/IP
# dissectors plus raw byte-pattern assertions at the offsets
# documented in src/asn1/rgoose_ber.c (there is no 90-5 dissector in
# tshark, so the SPDU session header is asserted as raw hex, like
# the GOOSE/SV wire tests do for payload bytes).
#
# Tests: RW-01..RW-34 (live capture, when available) and RR-01..RR-06
# (committed reference capture, always).
#
# Requires: tshark. Loopback capture needs root or the wireshark
# group; without either, falls back to a rootless user-namespace
# (unshare -Urn) + tcpdump capture when the environment allows it.
# When no capture method is available the scenario still runs
# unprivileged (plain-mode self-verification via its PLAIN_RX
# markers) and all tshark byte assertions run against the committed
# reference capture tests/interop/wire/reference/rgoose_rsv.pcap.
# Skips (77) when tshark is missing or no compiler/build tree is
# available.
#
# The scenario binary is compiled from
# tests/interop/wire/rgoose_wire_pub.c against the meson build tree
# (the meson registration for new wire executables is a plain list
# addition only for scripts — see the WP-2d report; a prebuilt
# $BUILD/tests/rgoose_wire_pub is preferred when present).

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PCAP_FILE="/tmp/interop_rgoose_rsv_$$.pcap"
SCENARIO_SRC="rgoose_wire_pub.c"
SCENARIO_NAME="rgoose_wire_pub"
REFERENCE_PCAP="$SCRIPT_DIR/reference/rgoose_rsv.pcap"

PORT_PLAIN_RGOOSE=10201
PORT_PLAIN_RSV=10202
PORT_SEC_RGOOSE=10203
PORT_SEC_RSV=10204
CAP_FILTER="not icmp and (udp port $PORT_PLAIN_RGOOSE or udp port $PORT_PLAIN_RSV or udp port $PORT_SEC_RGOOSE or udp port $PORT_SEC_RSV)"

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
    SEC_CFLAGS=""
    if ninja -C "$BUILD" -t commands tests/test_rgoose_pubsub 2>/dev/null | \
       grep -q IEC61850_SECURITY_ENABLED; then
        SEC_CFLAGS="-DIEC61850_SECURITY_ENABLED"
    fi
    if ! cc -std=c11 -O2 -I"$SRC_ROOT/include/iec61850" \
         -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE $SEC_CFLAGS \
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

cleanup() {
    rm -f "$PCAP_FILE" "/tmp/${SCENARIO_NAME}_$$" "/tmp/wp_link_cmd_$$" \
          "/tmp/${SCENARIO_NAME}_$$.o" "/tmp/rw_scenario_$$.out"
}
trap cleanup EXIT

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

PASS=0; FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

count_pkts() {
    tshark -r "$1" -Y "$2" 2>/dev/null | wc -l
}

# check_eq <id> <desc> <pcap> <filter> <expected>
check_eq() {
    C=$(count_pkts "$3" "$4")
    if [ "$C" -eq "$5" ]; then
        pass "$1: $2 ($C)"
    else
        fail "$1: $2 ($C != $5)"
    fi
}

# ------------------------------------------------------------------
# Run the scenario (under capture when available) and validate the
# live bytes. Offsets are relative to udp.payload (the SPDU) and
# follow the byte-offset table in src/asn1/rgoose_ber.c:
#   plain: SI@0 LI@1 PI@2 LI@3 SPDUlen@4 SpduNum@8 Version@12,
#          H=14: PayloadLen@H Type@H+4 Sim@H+5 APPID@H+6 APDUlen@H+8
#   secured: H=26, security ext TimeOfKey@14 TimeToNext@18
#          Algos@20 KeyID@22, signature TLV (0x85 len) trails the
#          APDU (34 trailing bytes for the 32-octet HMAC-SHA256).
# ------------------------------------------------------------------

LIVE_PCAP=""
SCEN_OUT="/tmp/rw_scenario_$$.out"

if [ "$CAPTURE_MODE" = "direct" ]; then
    tshark -i lo -f "$CAP_FILTER" -w "$PCAP_FILE" -a duration:30 \
           >/dev/null 2>&1 &
    CAP_PID=$!
    sleep 1
    timeout 25 "$SCENARIO" > "$SCEN_OUT" 2>&1
    kill "$CAP_PID" 2>/dev/null || true
    wait "$CAP_PID" 2>/dev/null || true
    LIVE_PCAP="$PCAP_FILE"
elif [ "$CAPTURE_MODE" = "userns" ]; then
    # Rootless: user+net namespace, lo up, tcpdump -Z root (the
    # mapped uid 0 keeps capture capabilities after the drop).
    unshare -Urn sh -c '
        ip link set lo up 2>/dev/null || true
        timeout 30 tcpdump -i lo -n -Z root -w '"$PCAP_FILE"' \
                "'"$CAP_FILTER"'" 2>/dev/null &
        TPID=$!
        sleep 1
        timeout 25 '"$SCENARIO"'
        RC=$?
        sleep 1
        kill -TERM $TPID 2>/dev/null || true
        wait $TPID 2>/dev/null || true
        exit $RC
    ' > "$SCEN_OUT" 2>&1
    if [ -s "$PCAP_FILE" ]; then
        LIVE_PCAP="$PCAP_FILE"
    fi
else
    # No capture method: run the scenario unprivileged so the
    # plain-mode traffic is still generated and self-verified.
    timeout 25 "$SCENARIO" > "$SCEN_OUT" 2>&1 || true
fi

echo "=== Wire R-GOOSE / R-SV Tests ($CAPTURE_MODE capture) ==="

# ---- Scenario self-verification (plain-mode pub → sub on loopback)

if grep -q "PLAIN_RX rgoose 5" "$SCEN_OUT" && \
   grep -q "PLAIN_RX rsv 5" "$SCEN_OUT"; then
    pass "RW-32: scenario plain-mode self-verification (5 R-GOOSE + 5 R-SV delivered)"
else
    fail "RW-32: scenario plain-mode self-verification"
    cat "$SCEN_OUT"
fi

# ---- Live capture assertions -------------------------------------

if [ -n "$LIVE_PCAP" ]; then
    echo ""
    echo "--- Live loopback capture (IPv4/UDP structure) ---"

    check_eq RW-01 "plain R-GOOSE datagrams (dport $PORT_PLAIN_RGOOSE)" \
        "$LIVE_PCAP" "udp.port==$PORT_PLAIN_RGOOSE" 5
    check_eq RW-02 "plain R-SV datagrams (dport $PORT_PLAIN_RSV)" \
        "$LIVE_PCAP" "udp.port==$PORT_PLAIN_RSV" 5
    check_eq RW-03 "secured R-GOOSE datagrams (dport $PORT_SEC_RGOOSE)" \
        "$LIVE_PCAP" "udp.port==$PORT_SEC_RGOOSE" 3
    check_eq RW-04 "secured R-SV datagrams (dport $PORT_SEC_RSV)" \
        "$LIVE_PCAP" "udp.port==$PORT_SEC_RSV" 3
    check_eq RW-05 "all packets are IPv4" \
        "$LIVE_PCAP" "ip.version==4 && udp" 16
    check_eq RW-06 "all packets are UDP (ip.proto 17)" \
        "$LIVE_PCAP" "ip.proto==17" 16

    echo ""
    echo "--- Plain R-GOOSE SPDU session header (90-5 A-profile) ---"

    check_eq RW-07 "SI=0xA1, LI=12, PI=0x80, common LI=10" \
        "$LIVE_PCAP" "udp.port==$PORT_PLAIN_RGOOSE && udp.payload[0:4] == a1:0c:80:0a" 5
    check_eq RW-08 "Version = 1" \
        "$LIVE_PCAP" "udp.port==$PORT_PLAIN_RGOOSE && udp.payload[12:2] == 00:01" 5
    check_eq RW-09 "Payload Type = 0x81 (non-tunneled GOOSE)" \
        "$LIVE_PCAP" "udp.port==$PORT_PLAIN_RGOOSE && udp.payload[18:1] == 0x81" 5
    check_eq RW-10 "Simulation = false" \
        "$LIVE_PCAP" "udp.port==$PORT_PLAIN_RGOOSE && udp.payload[19:1] == 0x00" 5
    check_eq RW-11 "APPID = 0x1001" \
        "$LIVE_PCAP" "udp.port==$PORT_PLAIN_RGOOSE && udp.payload[20:2] == 10:01" 5
    check_eq RW-12 "SPDU Length = 0x6f (111 = SPDU total 119 - 8)" \
        "$LIVE_PCAP" "udp.port==$PORT_PLAIN_RGOOSE && udp.payload[4:4] == 00:00:00:6f" 5
    check_eq RW-13 "SPDU Number = 2 in 3rd message (counter)" \
        "$LIVE_PCAP" "udp.port==$PORT_PLAIN_RGOOSE && udp.payload[8:4] == 00:00:00:02" 1
    check_eq RW-14 "gocbRef 'IED1LD0/LLN0\$GO\$gcb01' in APDU" \
        "$LIVE_PCAP" "udp.port==$PORT_PLAIN_RGOOSE && udp.payload contains 49:45:44:31:4c:44:30:2f:4c:4c:4e:30:24:47:4f:24:67:63:62:30:31" 5
    check_eq RW-15 "int32 dataset value 1234 (85:02:04:d2)" \
        "$LIVE_PCAP" "udp.port==$PORT_PLAIN_RGOOSE && udp.payload contains 85:02:04:d2" 5

    echo ""
    echo "--- Plain R-SV SPDU session header ---"

    check_eq RW-16 "SI=0xA2, LI=12, PI=0x80, common LI=10" \
        "$LIVE_PCAP" "udp.port==$PORT_PLAIN_RSV && udp.payload[0:4] == a2:0c:80:0a" 5
    check_eq RW-17 "Payload Type = 0x82 (non-tunneled SV)" \
        "$LIVE_PCAP" "udp.port==$PORT_PLAIN_RSV && udp.payload[18:1] == 0x82" 5
    check_eq RW-18 "APPID = 0x2001" \
        "$LIVE_PCAP" "udp.port==$PORT_PLAIN_RSV && udp.payload[20:2] == 20:01" 5
    check_eq RW-19 "svID 'IED1MU/LLN0\$SV\$smv01' in APDU" \
        "$LIVE_PCAP" "udp.port==$PORT_PLAIN_RSV && udp.payload contains 49:45:44:31:4d:55:2f:4c:4c:4e:30:24:53:56:24:73:6d:76:30:31" 5

    echo ""
    echo "--- Secured R-GOOSE (HMAC-SHA256, 62351-6 routable adaptation) ---"

    check_eq RW-20 "SI=0xA1, LI=24, PI=0x80, common LI=22" \
        "$LIVE_PCAP" "udp.port==$PORT_SEC_RGOOSE && udp.payload[0:4] == a1:18:80:16" 3
    check_eq RW-21 "Time to Next Key = 720 min (02:d0)" \
        "$LIVE_PCAP" "udp.port==$PORT_SEC_RGOOSE && udp.payload[18:2] == 02:d0" 3
    check_eq RW-22 "Security Algorithms = 0x0100 (HMAC-SHA256)" \
        "$LIVE_PCAP" "udp.port==$PORT_SEC_RGOOSE && udp.payload[20:2] == 01:00" 3
    check_eq RW-23 "Key ID = 0xCAFEBABE" \
        "$LIVE_PCAP" "udp.port==$PORT_SEC_RGOOSE && udp.payload[22:4] == ca:fe:ba:be" 3
    check_eq RW-24 "secured APPID = 0x1001 (offset H+6 = 32)" \
        "$LIVE_PCAP" "udp.port==$PORT_SEC_RGOOSE && udp.payload[32:2] == 10:01" 3
    check_eq RW-25 "signature TLV 85:20 (32-octet HMAC) at SPDU offset 131" \
        "$LIVE_PCAP" "udp.port==$PORT_SEC_RGOOSE && udp.payload[131:2] == 85:20" 3
    check_eq RW-26 "secure-mode UDP checksum = 0 (RFC 768 not-used)" \
        "$LIVE_PCAP" "udp.port==$PORT_SEC_RGOOSE && udp.checksum == 0" 3

    echo ""
    echo "--- Secured R-SV ---"

    check_eq RW-27 "SI=0xA2, LI=24, PI=0x80, common LI=22" \
        "$LIVE_PCAP" "udp.port==$PORT_SEC_RSV && udp.payload[0:4] == a2:18:80:16" 3
    check_eq RW-28 "Key ID = 0xFEEDBEEF" \
        "$LIVE_PCAP" "udp.port==$PORT_SEC_RSV && udp.payload[22:4] == fe:ed:be:ef" 3
    check_eq RW-29 "Payload Type = 0x82 at offset H+4 = 30" \
        "$LIVE_PCAP" "udp.port==$PORT_SEC_RSV && udp.payload[30:1] == 0x82" 3
    check_eq RW-30 "signature TLV 85:20 at SPDU offset 134" \
        "$LIVE_PCAP" "udp.port==$PORT_SEC_RSV && udp.payload[134:2] == 85:20" 3
    check_eq RW-31 "secure-mode UDP checksum = 0" \
        "$LIVE_PCAP" "udp.port==$PORT_SEC_RSV && udp.checksum == 0" 3
else
    echo ""
    echo "  SKIP: live capture unavailable (no root/wireshark group/unshare)"
    echo "        (byte assertions run against the committed reference below)"
fi

# ---- Reference capture assertions (always) ------------------------

echo ""
echo "--- Committed reference capture (reference/rgoose_rsv.pcap) ---"

if [ -s "$REFERENCE_PCAP" ]; then
    check_eq RR-01 "reference: 16 UDP packets" \
        "$REFERENCE_PCAP" "udp" 16
    check_eq RR-02 "reference: plain R-GOOSE session header" \
        "$REFERENCE_PCAP" "udp.port==$PORT_PLAIN_RGOOSE && udp.payload[0:4] == a1:0c:80:0a" 5
    check_eq RR-03 "reference: plain R-SV session header" \
        "$REFERENCE_PCAP" "udp.port==$PORT_PLAIN_RSV && udp.payload[0:4] == a2:0c:80:0a" 5
    check_eq RR-04 "reference: secured R-GOOSE session header" \
        "$REFERENCE_PCAP" "udp.port==$PORT_SEC_RGOOSE && udp.payload[0:4] == a1:18:80:16" 3
    check_eq RR-05 "reference: secured R-SV signature TLV" \
        "$REFERENCE_PCAP" "udp.port==$PORT_SEC_RSV && udp.payload[134:2] == 85:20" 3
    check_eq RR-06 "reference: secure UDP checksums zero" \
        "$REFERENCE_PCAP" "(udp.port==$PORT_SEC_RGOOSE || udp.port==$PORT_SEC_RSV) && udp.checksum == 0" 6
else
    fail "RR-00: reference capture missing"
fi

# ---- JSON field validation (validate_pcap.py) ---------------------

echo ""
echo "--- JSON field validation (validate_pcap.py) ---"

if [ -s "$REFERENCE_PCAP" ]; then
    if python3 "$SCRIPT_DIR/validate_pcap.py" "$REFERENCE_PCAP" rgoose \
            >/tmp/val_rw_$$ 2>&1; then
        pass "RW-33: validate_pcap.py rgoose defaults (IPv4/UDP/dport)"
    else
        fail "RW-33: validate_pcap.py rgoose defaults"
        cat /tmp/val_rw_$$
    fi
    if python3 "$SCRIPT_DIR/validate_pcap.py" "$REFERENCE_PCAP" rgoose_secure \
            >/tmp/val_rw_$$ 2>&1; then
        pass "RW-34: validate_pcap.py rgoose_secure defaults (ports + zero checksum)"
    else
        fail "RW-34: validate_pcap.py rgoose_secure defaults"
        cat /tmp/val_rw_$$
    fi
    rm -f /tmp/val_rw_$$
fi

echo ""
echo "Wire R-GOOSE/R-SV: $PASS passed, $FAIL failed"
exit $FAIL
