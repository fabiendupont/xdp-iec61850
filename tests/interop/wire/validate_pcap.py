#!/usr/bin/env python3
# SPDX-License-Identifier: BSD-2-Clause
"""
Validate IEC 61850 pcap captures using tshark JSON output.

Usage:
    validate_pcap.py <pcap_file> <protocol> [field=expected ...]

Protocols: goose, sv, mms

Examples:
    validate_pcap.py capture.pcap goose eth.type=0x88b8 goose.appid=1
    validate_pcap.py capture.pcap sv eth.type=0x88ba
    validate_pcap.py capture.pcap mms tpkt.version=3
"""

import json
import subprocess
import sys


def run_tshark_json(pcap_file):
    """Run tshark and return JSON-decoded packets."""
    try:
        result = subprocess.run(
            ["tshark", "-r", pcap_file, "-T", "json"],
            capture_output=True, text=True, timeout=30
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


def find_field(packet, field_path):
    """Find a field value in a tshark JSON packet."""
    layers = packet.get("_source", {}).get("layers", {})
    parts = field_path.split(".")

    # Try direct lookup in layers
    for layer_name, layer_data in layers.items():
        if isinstance(layer_data, dict):
            key = field_path.replace(".", "_")
            if field_path in layer_data:
                return layer_data[field_path]
            if key in layer_data:
                return layer_data[key]

    # Try nested lookup
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
                    return None
        else:
            return None

    return current


def validate(pcap_file, protocol, checks):
    """Validate pcap fields."""
    packets = run_tshark_json(pcap_file)
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

        for pkt in packets:
            value = find_field(pkt, field)
            if value is not None:
                found = True
                if str(value) == expected:
                    print(f"  PASS: {field} = {expected}")
                    passed += 1
                else:
                    print(f"  FAIL: {field} = {value} (expected {expected})")
                    failed += 1
                break

        if not found:
            print(f"  FAIL: field {field} not found in any packet")
            failed += 1

    print(f"\nResults: {passed} passed, {failed} failed")
    return failed == 0


def main():
    if len(sys.argv) < 3:
        print(__doc__)
        sys.exit(1)

    pcap_file = sys.argv[1]
    protocol = sys.argv[2]
    checks = sys.argv[3:]

    if not checks:
        # Default checks per protocol
        defaults = {
            "goose": ["eth.type=0x000088b8"],
            "sv": ["eth.type=0x000088ba"],
            "mms": ["tpkt.version=3"],
        }
        checks = defaults.get(protocol, [])

    success = validate(pcap_file, protocol, checks)
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
