#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""
Validate IEC 61850 pcap captures using tshark JSON output.

Usage:
    validate_pcap.py <pcap_file> <protocol> [field=expected ...]
                     [--decode-as SPEC ...]

Protocols: goose, sv, mms, mms_report, mms_control_ed2,
           mms_setting_groups, mms_tls, rgoose, rgoose_secure,
           rsv, rsv_secure

Options:
    --decode-as SPEC  Passed to tshark as `-d SPEC` (repeatable). Use it
                      when the capture runs MMS on a non-standard TCP port,
                      e.g. --decode-as tcp.port==10610,tpkt

Examples:
    validate_pcap.py capture.pcap goose eth.type=0x88b8 goose.appid=1
    validate_pcap.py capture.pcap sv eth.type=0x88ba
    validate_pcap.py capture.pcap mms tpkt.version=3
    validate_pcap.py capture.pcap mms_report --decode-as tcp.port==10610,tpkt
    validate_pcap.py capture.pcap mms_control_ed2 \
        --decode-as tcp.port==10611,tpkt
    validate_pcap.py capture.pcap mms_tls \
        --decode-as tcp.port==10613,tls --decode-as tcp.port==10612,tpkt
    validate_pcap.py capture.pcap rgoose ip.version=4 udp.dstport=10201

Field names are tshark display-filter fields (tshark -T json nests them
under per-layer trees; the lookup here searches those trees recursively).
Values are compared as strings; a check passes when at least one packet
in the capture carries the expected value.
"""

import json
import subprocess
import sys


def run_tshark_json(pcap_file, decode_as):
    """Run tshark and return JSON-decoded packets."""
    # --no-duplicate-keys: repeated JSON keys (e.g. one
    # mms.AccessResult per report member) are merged into arrays so
    # no field is lost to dict-key collapsing.
    cmd = ["tshark", "-r", pcap_file, "-T", "json", "--no-duplicate-keys"]
    for spec in decode_as:
        cmd += ["-d", spec]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            print(f"ERROR: tshark failed: {result.stderr}", file=sys.stderr)
            return []
        return json.loads(result.stdout)
    except FileNotFoundError:
        print("ERROR: tshark not found", file=sys.stderr)
        return []
    except json.JSONDecodeError:
        print("ERROR: invalid tshark JSON output", file=sys.stderr)
        return []


def find_field_deep(node, field_path):
    """Recursively search a tshark JSON layer tree for an exact key."""
    if isinstance(node, dict):
        if field_path in node:
            return node[field_path]
        for value in node.values():
            found = find_field_deep(value, field_path)
            if found is not None:
                return found
    elif isinstance(node, list):
        for item in node:
            found = find_field_deep(item, field_path)
            if found is not None:
                return found
    return None


def find_field(packet, field_path):
    """Find a field value in a tshark JSON packet."""
    layers = packet.get("_source", {}).get("layers", {})
    parts = field_path.split(".")

    # Try direct lookup in layers (flat fields, e.g. tpkt.version)
    for layer_name, layer_data in layers.items():
        if isinstance(layer_data, dict):
            key = field_path.replace(".", "_")
            if field_path in layer_data:
                return layer_data[field_path]
            if key in layer_data:
                return layer_data[key]

    # Try nested lookup (legacy dotted-path walk)
    current = layers
    for part in parts:
        if isinstance(current, dict):
            if part in current:
                current = current[part]
            else:
                # Try with full dotted path
                found = False
                for k, v in current.items():
                    if k == field_path:
                        return v
                    if isinstance(v, dict) and field_path in v:
                        return v[field_path]
                if not found:
                    current = None
                    break
        else:
            current = None
            break
    if isinstance(current, str):
        return current

    # Deep recursive search (tshark nests mms.* fields under *_tree keys)
    return find_field_deep(layers, field_path)


def validate(pcap_file, protocol, checks, decode_as):
    """Validate pcap fields."""
    packets = run_tshark_json(pcap_file, decode_as)
    if not packets:
        print(f"FAIL: no packets in {pcap_file}")
        return False

    passed = 0
    failed = 0

    for field_check in checks:
        if "=" not in field_check:
            print(f"SKIP: invalid check format: {field_check}")
            continue

        field, expected = field_check.split("=", 1)
        found = False
        matched = False
        first_value = None

        for pkt in packets:
            value = find_field(pkt, field)
            if value is not None:
                found = True
                if first_value is None:
                    first_value = value
                if str(value) == expected:
                    matched = True
                    break

        if matched:
            print(f"  PASS: {field} = {expected}")
            passed += 1
        elif found:
            print(f"  FAIL: {field} = {first_value} (expected {expected})")
            failed += 1
        else:
            print(f"  FAIL: field {field} not found in any packet")
            failed += 1

    print(f"\nResults: {passed} passed, {failed} failed")
    return failed == 0


# Default checks per protocol. mms_report / mms_control_ed2 cover the
# WP-2d/WP-2z/WP-2w Ed.2 wire scenarios: the RCB enrollment exchange,
# report metadata and the IEC 61850-8-1 control-object flow (Select is
# a Read of "$SBO" answered with the reference string, Operate/Cancel
# are Writes of the 8-1 originator structure, the CommandTermination
# is an InformationReport on the "$Oper" object) — all dissected by
# the neutral tshark MMS dissector.
DEFAULT_CHECKS = {
    "goose": ["eth.type=0x000088b8"],
    "sv": ["eth.type=0x000088ba"],
    "mms": ["tpkt.version=3"],
    # WP-2z: the report bodies are conformant IEC 61850-7-2 reports —
    # the VAS is the vmd-specific "RPT" marker and rptID/seqNum are
    # dissected from listOfAccessResult (previously the non-conformant
    # layout only exposed the rptID as a domainId and raised BER
    # errors in tshark).
    "mms_report": [
        "tpkt.version=3",
        "mms.vmd_specific=RPT",       # report VAS: vmd-specific "RPT"
        "mms.iec61850.rptid=R1",      # rptID dissected from the report body
        "mms.iec61850.rptid=B1",
        "mms.iec61850.seqnum=1",      # sqNum dissected as an AccessResult
        "mms.failure=2",              # Ed.2 rejection: in-band DataAccessError
    ],
    "mms_setting_groups": [
        "tpkt.version=3",
        "mms.objectName_domain_specific_itemId=LLN0$SP$SGCB$NumOfSG",  # SGCB read
        "mms.objectName_domain_specific_itemId=PTOC1$SE$Mod$setVal",   # SE edit write
        "mms.objectName_domain_specific_itemId=PTOC1$SG$Mod$setVal",   # SG active view
        "mms.unsigned=2",               # SelectEditSG / SelectActiveSG values
        "mms.integer=200",              # the SE setting value
    ],
    # WP-2w: the control flow is conformant IEC 61850-8-1 — ordinary
    # Reads/Writes on the CO objects (no house-encoded confirmed
    # service tags), the SBO read answer, the Oper structure fields
    # and the CommandTermination InformationReport on "$Oper".
    # (tshark's IEC 61850 knowledge renames the ctlModel read response
    # integer to mms.iec61850.ctlmodel and renders booleans as 0/1.)
    "mms_control_ed2": [
        "tpkt.version=3",
        "mms.objectName_domain_specific_itemId=XCBR1$ST$Pos$stVal",  # status Read
        "mms.objectName_domain_specific_itemId=XCBR1$CF$Pos$ctlModel",  # ctlModel Read
        "mms.iec61850.ctlmodel=2",     # ctlModel = sbo-with-normal-security
        "mms.objectName_domain_specific_itemId=XCBR1$CO$Pos$SBO",    # select Read
        "mms.data.visible-string=LD/XCBR1$CO$Pos",  # SBO answer: reference
        "mms.objectName_domain_specific_itemId=XCBR1$CO$Pos$Oper",   # operate Write + CT
        "mms.objectName_domain_specific_itemId=CSWI1$CO$Pos$Cancel", # cancel Write
        "mms.objectName_domain_specific_itemId=CSWI1$CO$Pos$Oper",   # rejected operate
        "mms.boolean=1",               # Oper structure: ctlVal
        "mms.unsigned=1",              # Oper structure: ctlNum
        "mms.failure=2",               # Ed.2 rejection: in-band DataAccessError
    ],
    # WP-3d (IEC 62351-4): MMS-over-TLS wire profile. Presence
    # checks only (the script's any-packet semantics cannot express
    # absence) — the SNI/ALPN-absent and plaintext-leak-absent
    # assertions live in test_wire_mms_tls.sh as count==0 checks.
    # Handshake types: ClientHello(1)/ServerHello(2) are visible in
    # every TLS version; Certificate(11) only when TLS 1.2 is
    # negotiated (post-ServerHello messages are encrypted in 1.3).
    # Application data: TLS 1.3 encrypted records expose
    # tls.record.opaque_type==23 (tshark 4.x); with TLS 1.2 the
    # clear-text tls.record.content_type==23 applies — the shell
    # test accepts either.
    "mms_tls": [
        "tls.record.version=0x0303",
        "tls.record.opaque_type=23",       # application data (session)
        "tls.record.content_type=22",      # handshake records
        "tls.handshake.type=1",            # ClientHello
        "tls.handshake.type=2",            # ServerHello
    ],
    # 90-5 routable profiles (WP-4e): the wire scenario publishes
    # plain R-GOOSE on UDP 10201 / plain R-SV on 10202 and the
    # HMAC-signed variants on 10203 / 10204 (loopback, kernel-built
    # IP/UDP for plain; hand-built headers with a zero UDP checksum
    # for secured).
    "rgoose": [
        "ip.version=4",
        "ip.proto=17",
        "udp.dstport=10201",
    ],
    "rgoose_secure": [
        "udp.dstport=10203",
        "udp.srcport=10203",
        "udp.checksum=0x0000",
    ],
    "rsv": [
        "ip.version=4",
        "ip.proto=17",
        "udp.dstport=10202",
    ],
    "rsv_secure": [
        "udp.dstport=10204",
        "udp.srcport=10204",
        "udp.checksum=0x0000",
    ],
}


def main():
    args = sys.argv[1:]
    decode_as = []
    positional = []
    i = 0
    while i < len(args):
        if args[i] == "--decode-as":
            i += 1
            if i >= len(args):
                print("ERROR: --decode-as requires an argument",
                      file=sys.stderr)
                sys.exit(1)
            decode_as.append(args[i])
        else:
            positional.append(args[i])
        i += 1

    if len(positional) < 2:
        print(__doc__)
        sys.exit(1)

    pcap_file = positional[0]
    protocol = positional[1]
    checks = positional[2:]

    if not checks:
        checks = DEFAULT_CHECKS.get(protocol, [])
        if not checks:
            print(f"ERROR: unknown protocol: {protocol}", file=sys.stderr)
            sys.exit(1)

    success = validate(pcap_file, protocol, checks, decode_as)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
