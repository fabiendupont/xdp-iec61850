# xdp-iec61850

IEC 61850 GOOSE + SV + MMS stack on XDP, functionally equivalent to
the iec-61850 C++ stack.

## Overview

Split-plane architecture: XDP fast path for EtherType/APPID filtering
and shallow BER parsing, with full protocol processing in userspace
via AF_XDP sockets. Replaces DPDK with native Linux XDP.

## Features

- GOOSE publisher/subscriber (IEC 61850-8-1)
- Sampled Values publisher/subscriber (IEC 61850-9-2)
- MMS server/client (IEC 61850-8-1, optional)
- XDP fast-path filtering (EtherType + APPID)
- AF_XDP zero-copy packet I/O
- BER ASN.1 encoder/decoder (Frama-C verified)
- IEC 62351-6 security (HMAC-SHA256 / AES-GMAC, optional)
- SCL/SCD configuration parser
- TLA+ verified protocol state machines
- Optional HSR/PRP redundancy via xdp-hsr-prp

## Building

```sh
meson setup builddir
meson compile -C builddir
meson test -C builddir
```

## Dependencies

- xdp-graph-lib
- libbpf >= 1.0, libelf
- libxml2 (SCL parser)
- OpenSSL (security, optional)
- libyaml (configuration, optional)
- xdp-hsr-prp (redundancy, optional)

## License

BSD-2-Clause
