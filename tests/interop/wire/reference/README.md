# Reference Packet Captures

Canonical wire captures of IEC 61850 protocol exchanges between
libiec61850 client and server programs. These are black-box captures
of compiled binaries — no source code was read or copied.

Use these to verify encoding correctness during development:

```sh
tshark -r mms_canonical.pcap -d 'tcp.port==10400,tpkt' -Y mms -V -O mms
tshark -r goose_sv.pcap -Y 'goose or sv' -V
```

## Captures

| File | Protocol | Contents |
|------|----------|----------|
| `mms_canonical.pcap` | MMS/TCP | Identify, GetNameList (domains + variables), Read — minimal reference |
| `mms_services.pcap` | MMS/TCP | All mms_utility operations + client_example1 read/write cycle |
| `mms_control.pcap` | MMS/TCP | Control server: Read, Write, GetVariableAccessAttributes patterns |
| `goose_sv.pcap` | GOOSE + SV | GOOSE publisher (1 frame) + SV publisher (40 frames) on veth |
| `mms_report.pcap` | MMS/TCP | Ed.2 reporting (WP-2d, self-conformance): RCB discovery, component reads/writes (Resv/RptEna/DatSet/OptFlds/TrgOps/GI/EntryID/PurgeBuf), Ed.2 enable-without-reserve rejection, 7 InformationReports (URCB dchg + GI, BRCB live/resume/post-resume), client loss + EntryID resume after reconnect |
| `mms_control_ed2.pcap` | MMS/TCP | Ed.2 control (WP-2d, self-conformance): status Read, Select/Operate (SBO) with command termination, Select + Cancel, operate-without-select on a strict object rejected as a ConfirmedError PDU |

## How captured

- MMS: `server_example_basic_io` / `server_example_control` on port 10400,
  queried by `mms_utility` and `client_example_control`
- GOOSE/SV: `goose_publisher_example` / `sv_publisher_example` on veth pair
- All on loopback/veth, captured with tshark
- libiec61850 version: 1.6.x
- `mms_report.pcap` / `mms_control_ed2.pcap`: this repository's own
  server + client (tests/interop/wire/mms_report_wire.c,
  mms_control_wire.c) on TCP loopback ports 10610/10611, captured with
  tcpdump on lo (Ed.2 wire conformance — our bytes dissected by the
  neutral tshark MMS dissector)

```sh
tshark -r mms_report.pcap -d 'tcp.port==10610,tpkt' -Y mms
tshark -r mms_control_ed2.pcap -d 'tcp.port==10611,tpkt' -Y mms
```
