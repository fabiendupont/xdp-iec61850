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

## How captured

- MMS: `server_example_basic_io` / `server_example_control` on port 10400,
  queried by `mms_utility` and `client_example_control`
- GOOSE/SV: `goose_publisher_example` / `sv_publisher_example` on veth pair
- All on loopback/veth, captured with tshark
- libiec61850 version: 1.6.x
