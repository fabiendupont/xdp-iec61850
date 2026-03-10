# xdp-iec61850 Architecture

## Overview

xdp-iec61850 implements the IEC 61850 GOOSE + SV + MMS protocol stack
using XDP for fast-path filtering and AF_XDP for zero-copy userspace
packet I/O. It is functionally equivalent to the iec-61850 C++/DPDK
implementation, rewritten in pure C11.

## Split-Plane Architecture

```
                    ┌──────────────────────────────────┐
                    │  Userspace (C11)                  │
                    │  ┌────────┐ ┌────────┐           │
                    │  │ GOOSE  │ │  SV    │           │
                    │  │pub/sub │ │pub/sub │           │
                    │  └───┬────┘ └───┬────┘           │
                    │      │          │                 │
                    │  ┌───┴──────────┴───┐            │
                    │  │ Full BER decode  │            │
                    │  │ State machines   │            │
                    │  │ Security (HMAC)  │            │
                    │  └───────┬──────────┘            │
                    │          │ AF_XDP (zero-copy)     │
                    ├──────────┼────────────────────────┤
                    │          │ Kernel (XDP)           │
                    │  ┌───────┴──────────┐            │
                    │  │ XDP fast path    │            │
                    │  │ EtherType filter │            │
                    │  │ APPID filter     │            │
                    │  │ Shallow BER      │            │
                    │  │ (stNum/sqNum)    │            │
                    │  └──────────────────┘            │
                    │          NIC                      │
                    └──────────────────────────────────┘
```

### XDP Fast Path (Kernel)

BPF programs filter packets at wire speed:
- `node_goose_filter`: Filters by APPID, redirects to AF_XDP
- `node_sv_filter`: Same for Sampled Values
- `node_goose_parse`: Optional shallow BER walker (bounded, max 10 iterations)
- `node_sv_parse`: 9-2LE smpCnt extraction and gap detection

### Userspace (AF_XDP)

Full protocol processing after XDP accepts the packet:
- BER decode (GOOSE APDU, SV APDU)
- State machine (stNum/sqNum tracking, duplicate detection)
- Retransmission scheduling (exponential backoff)
- Security verification (HMAC-SHA256, AES-GMAC)
- Application callbacks

## Dependency Chain

```
ebpf-graph-lib (egl_*)    ← Generic: PROG_ARRAY, DAG, stats
└── xdp-graph-lib (xgl_*) ← XDP: metadata, actions, AF_XDP zero-copy
    └── xdp-iec61850       ← This project
```

## Module Structure

| Module | Purpose | Phase |
|--------|---------|-------|
| containers/ | Fixed-capacity string, array, ring buffer | 1 |
| transport/ | packet_io abstraction (XSK + raw socket) | 1 |
| logging/ | Thread-safe logger | 1 |
| asn1/ | BER encoder/decoder for GOOSE, SV, MMS | 2 |
| goose/ | GOOSE publisher, subscriber, retransmission | 3 |
| bpf/ | XDP filter and parse nodes | 4 |
| sv/ | SV publisher, subscriber | 5 |
| verification/ | CBMC, Frama-C, TLA+ | 6 |
| security/ | Key manager, HMAC verification | 7 |
| ied/ | IED data model and types | 7 |
| mms/ | MMS data store | 7 |
| scl/ | SCL/SCD XML parser | 7 |
| config/ | Configuration management | 7 |
| monitoring/ | System health monitoring | 7 |
