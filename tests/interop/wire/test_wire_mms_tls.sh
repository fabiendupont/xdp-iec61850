#!/bin/sh
# SPDX-License-Identifier: BSD-2-Clause
# Wire capture test: MMS-over-TLS (IEC 62351-4) via tshark — WP-3d.
#
# Runs the repo's own mms_tls_wire scenario (dual-listener MMS
# server with a TLS listener + the repo's own TLS-armed MMS client)
# on TCP loopback, captures the session on lo and validates the
# on-wire bytes with the neutral tshark TLS dissector:
#
#   - TLS record structure: handshake records (ClientHello /
#     ServerHello, and — when TLS 1.2 is negotiated — the
#     Certificate / CertificateRequest / Finished messages in the
#     clear), ChangeCipherSpec, application-data records in both
#     directions
#   - the TPKT/MMS PDUs of the session ride inside TLS
#     application-data records only: with the TLS port force-decoded
#     as TPKT, zero MMS PDUs are dissectable (nothing leaks in a
#     dissectable form)
#   - SNI and ALPN are absent from the ClientHello (our client sets
#     neither — plain IP/port addressing per IEC 62351-4)
#   - nothing leaks in plaintext: neither the marker domain name
#     ("TLSDOM") nor the marker value ("TLSWIREMARK") appears in any
#     TCP payload on the TLS port
#   - differential control: the same server's plain listener shows
#     the exchange dissectable as TPKT/MMS in the clear (proving
#     the capture and dissectors work, so the TLS-port absences are
#     meaningful)
#
# Tests: WT-01..WT-16
#
# Requires: tshark. Loopback capture needs root or the wireshark
# group; without either, falls back to a rootless user-namespace
# (unshare -Urn) + tcpdump capture when the environment allows it.
# Skips (77) when no capture method, no compiler/build tree, or no
# security support in the build is available.
#
# The scenario binary is compiled from tests/interop/wire/mms_tls_wire.c
# against the meson build tree (the meson registration for new wire
# executables is a plain list addition only for scripts — see the
# WP-2d report). A prebuilt $BUILD/tests/mms_tls_wire is preferred
# when present.

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PCAP_FILE="/tmp/interop_mms_tls_$$.pcap"
PORT=10613
PLAIN_PORT=10612
SCENARIO_SRC="mms_tls_wire.c"
SCENARIO_NAME="mms_tls_wire"

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

# Run the scenario under a loopback capture of both listeners (the
# TLS port and the plain control port of the dual-listener server).
run_captured() {
    if [ "$CAPTURE_MODE" = "direct" ]; then
        tshark -i lo -f "tcp port $PORT or tcp port $PLAIN_PORT" \
               -w "$PCAP_FILE" -a duration:120 >/dev/null 2>&1 &
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
        tcpdump -i lo -f "tcp port '"$PORT"' or tcp port '"$PLAIN_PORT"'" \
                -w '"$PCAP_FILE"' -Z root 2>/dev/null &
        TPID=$!
        sleep 1
        timeout 120 '"$SCENARIO"'
        RC=$?
        kill -TERM $TPID 2>/dev/null || true
        wait $TPID 2>/dev/null || true
        exit $RC
    '
}

echo "=== Wire MMS-over-TLS Tests ($CAPTURE_MODE capture) ==="

SCENARIO_PID=""
RC=0
run_captured || RC=$?
if [ "$RC" = "77" ]; then
    echo "SKIP: scenario reports no security support in the build"
    exit 77
fi
if [ "$RC" != "0" ]; then
    echo "FAIL: mms_tls_wire scenario failed (rc=$RC)"
    exit 1
fi

if [ ! -s "$PCAP_FILE" ]; then
    echo "FAIL: no packets captured"
    exit 1
fi

# Pass A: decode the TLS port as TLS, the plain control port as TPKT.
DECODE_TLS="-d tcp.port==$PORT,tls -d tcp.port==$PLAIN_PORT,tpkt"
# Pass B: force-decode the TLS port as TPKT — even then, no MMS PDU
# may be dissectable (the TPKT/MMS traffic only exists inside
# encrypted TLS records).
DECODE_TPKT="-d tcp.port==$PORT,tpkt -d tcp.port==$PLAIN_PORT,tpkt"

TLSP="tcp.port==$PORT"
PLAINP="tcp.port==$PLAIN_PORT"

PASS=0; FAIL=0
pass() { echo "  PASS: $1"; PASS=$((PASS+1)); }
fail() { echo "  FAIL: $1"; FAIL=$((FAIL+1)); }

count_tls() {
    tshark -r "$PCAP_FILE" $DECODE_TLS -Y "$1" 2>/dev/null | wc -l
}

count_tpkt() {
    tshark -r "$PCAP_FILE" $DECODE_TPKT -Y "$1" 2>/dev/null | wc -l
}

# check_ge <id> <desc> <filter> <min>
check_ge() {
    C=$(count_tls "$3")
    if [ "$C" -ge "$4" ]; then
        pass "$1: $2 ($C)"
    else
        fail "$1: $2 ($C < $4)"
    fi
}

# check_eq <id> <desc> <filter> <expected>
check_eq() {
    C=$(count_tls "$3")
    if [ "$C" -eq "$4" ]; then
        pass "$1: $2 ($C)"
    else
        fail "$1: $2 ($C != $4)"
    fi
}

echo ""
echo "--- TLS record structure ---"

# WT-01: ClientHello (handshake record, client -> server)
check_ge WT-01 "TLS ClientHello" "tls.handshake.type == 1" 1

# WT-02: ServerHello (handshake record, server -> client)
check_ge WT-02 "TLS ServerHello" "tls.handshake.type == 2" 1

# WT-03: handshake records exist in both directions
check_ge WT-03 "TLS handshake records (c->s)" \
    "tls.record.content_type == 22 && tcp.dstport == $PORT" 1
check_ge WT-04 "TLS handshake records (s->c)" \
    "tls.record.content_type == 22 && tcp.srcport == $PORT" 1

# WT-05: record version 0x0303 (TLS 1.2 legacy record-layer version
# on ServerHello and application-data records)
check_ge WT-05 "TLS record version 0x0303" "tls.record.version == 0x0303" 1

# WT-06/07: application-data records carry the session (both
# directions; the scenario exchanges initiate + 3 reads + 1 write +
# reports/teardown). tshark 4.x splits the record-type field: TLS
# 1.2 exposes content_type==23 in the clear, TLS 1.3 encrypted
# records carry opaque_type==23 — accept either.
check_ge WT-06 "application-data records (c->s)" \
    "(tls.record.content_type == 23 || tls.record.opaque_type == 23) && tcp.dstport == $PORT" 5
check_ge WT-07 "application-data records (s->c)" \
    "(tls.record.content_type == 23 || tls.record.opaque_type == 23) && tcp.srcport == $PORT" 5

# WT-08/09: SNI and ALPN are absent from the ClientHello (our
# client uses neither — IEC 62351-4 addressing is IP/port)
check_eq WT-08 "SNI absent in ClientHello" \
    "tls.handshake.extensions_server_name" 0
check_eq WT-09 "ALPN absent in ClientHello" \
    "tls.handshake.extensions_alpn_str" 0

echo ""
echo "--- TLS 1.2 vs 1.3 handshake visibility ---"

# WT-10: with TLS 1.2 the certificate messages are in the clear:
# server Certificate (11), CertificateRequest (13) — our server
# always requests peer certificates — and Finished (20) in both
# directions. With TLS 1.3 everything after ServerHello is
# encrypted: those are invisible by design; the middlebox-compat
# ChangeCipherSpec (20) is still visible.
CERTS=$(count_tls "tls.handshake.type == 11")
if [ "$CERTS" -ge 1 ]; then
    pass "WT-10: server Certificate visible (TLS 1.2 negotiated)"
    check_ge WT-11 "CertificateRequest (server wants our client cert)" \
        "tls.handshake.type == 13" 1
    check_ge WT-12 "Finished messages (both directions)" \
        "tls.handshake.type == 20" 2
    check_ge WT-13 "ChangeCipherSpec records" \
        "tls.record.content_type == 20" 2
else
    pass "WT-10: post-ServerHello handshake encrypted (TLS 1.3 negotiated)"
    check_ge WT-11 "ChangeCipherSpec (compat) records" \
        "tls.record.content_type == 20" 1
    check_eq WT-12 "client Certificate not visible (encrypted handshake)" \
        "tls.handshake.type == 11 && tcp.srcport == $PORT" 0
    check_ge WT-13 "encrypted records (s->c)" \
        "(tls.record.content_type == 23 || tls.record.opaque_type == 23) && tcp.srcport == $PORT" 5
fi

echo ""
echo "--- MMS-inside-TLS + plaintext-leak assertions ---"

# WT-14: with the TLS port force-decoded as TPKT, no MMS PDU is
# dissectable — the TPKT/MMS PDUs exist only inside encrypted
# application-data records
C=$(count_tpkt "mms && $TLSP")
if [ "$C" -eq 0 ]; then
    pass "WT-14: no dissectable MMS PDU on the TLS port (forced tpkt decode)"
else
    fail "WT-14: MMS dissectable on the TLS port ($C) — plaintext leak"
fi

# WT-15: nothing leaks in plaintext — neither the marker domain
# ("TLSDOM") nor the marker value ("TLSWIREMARK") appears in any TCP
# payload on the TLS port
C=$(count_tls "$TLSP && tcp.payload contains \"TLSDOM\"")
if [ "$C" -eq 0 ]; then
    pass "WT-15: no plaintext domain marker on the TLS port"
else
    fail "WT-15: plaintext domain marker on the TLS port ($C packets)"
fi
C=$(count_tls "$TLSP && tcp.payload contains \"TLSWIREMARK\"")
if [ "$C" -eq 0 ]; then
    pass "WT-15b: no plaintext value marker on the TLS port"
else
    fail "WT-15b: plaintext value marker on the TLS port ($C packets)"
fi

# WT-16: differential control — the same server's plain listener
# carries the same exchange dissectable as TPKT/MMS in the clear,
# proving the capture and dissectors work (so WT-14/WT-15 absences
# are meaningful)
C=$(count_tpkt "mms && $PLAINP")
if [ "$C" -ge 1 ]; then
    pass "WT-16: control session dissectable on the plain port ($C MMS PDUs)"
else
    fail "WT-16: no dissectable MMS on the plain control port"
fi
C=$(count_tpkt "$PLAINP && tcp.payload contains \"TLSDOM\"")
if [ "$C" -ge 1 ]; then
    pass "WT-16b: domain marker visible in the clear on the plain port"
else
    fail "WT-16b: domain marker not visible on the plain control port"
fi
C=$(count_tpkt "$PLAINP && tcp.payload contains \"TLSWIREMARK\"")
if [ "$C" -ge 1 ]; then
    pass "WT-16c: value marker visible in the clear on the plain port"
else
    fail "WT-16c: value marker not visible on the plain control port"
fi

echo ""
echo "--- JSON field validation (validate_pcap.py) ---"

# WT-17: tshark JSON field assertions (any-packet semantics)
if python3 "$SCRIPT_DIR/validate_pcap.py" "$PCAP_FILE" mms_tls \
        --decode-as "tcp.port==$PORT,tls" \
        --decode-as "tcp.port==$PLAIN_PORT,tpkt" >/tmp/val_wt_$$ 2>&1; then
    pass "WT-17: validate_pcap.py mms_tls defaults (records/handshake)"
else
    fail "WT-17: validate_pcap.py mms_tls defaults"
    cat /tmp/val_wt_$$
fi
rm -f /tmp/val_wt_$$

echo ""
echo "Wire MMS-over-TLS: $PASS passed, $FAIL failed"
exit $FAIL
