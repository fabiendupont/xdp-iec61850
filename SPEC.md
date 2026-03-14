# xdp-iec61850 — Technical Specification

## Overview

- **Purpose**: IEC 61850 GOOSE + SV + MMS stack on XDP, functionally equivalent to the iec-61850 C++ stack
- **Language**: Pure C11
- **Build system**: Meson
- **License**: BSD-3-Clause
- **Depends on**: xdp-graph-lib (which depends on ebpf-graph-lib), optionally xdp-hsr-prp
- **Research doc**: `~/Work/Sandbox/research/03-iec61850-xdp-stack.md`
- **Primary reference**: `~/Code/github.com/smgglrs/iec-61850/` (C++/DPDK — the complete implementation being replaced)
- **Secondary reference**: `~/Code/github.com/smgglrs/iec-61850-c/iec-61850-c/` (partial C11 reimplementation — useful for C patterns and Frama-C harnesses)

## Dependency Chain

```
ebpf-graph-lib (egl_*)    ← generic: PROG_ARRAY, DAG, stats, reconfig
└── xdp-graph-lib (xgl_*) ← XDP: metadata, actions, AF_XDP zero-copy (xgl_xsk_*)
    └── xdp-iec61850       ← THIS PROJECT: IEC 61850 stack on XDP
```

AF_XDP zero-copy packet I/O uses `xgl_xsk_*` from xdp-graph-lib.
This replaces the need for a custom AF_XDP socket wrapper — the
`packet_io` abstraction layer delegates to `xgl_xsk_*` for zero-copy
with automatic fallback to copy mode if the NIC driver doesn't support it.

## Directory Structure

```
xdp-iec61850/
├── meson.build
├── meson_options.txt                # enable_mms, enable_security, enable_hsr_prp
├── LICENSE
├── README.md
├── include/
│   └── iec61850/
│       ├── asn1/
│       │   ├── goose_ber.h          # GOOSE BER encode/decode
│       │   ├── goose_ber_decode.h
│       │   ├── sv_ber.h             # SV BER encode/decode
│       │   └── mms_ber.h            # MMS BER encode/decode
│       ├── containers/
│       │   ├── fixed_string.h       # Fixed-capacity string
│       │   ├── fixed_array.h
│       │   └── ring_buffer.h
│       ├── goose/
│       │   ├── goose_publisher.h
│       │   ├── goose_subscriber.h
│       │   └── goose_retransmission.h
│       ├── sv/
│       │   ├── sv_publisher.h
│       │   └── sv_subscriber.h
│       ├── transport/
│       │   ├── packet_io.h          # Abstract packet I/O interface
│       │   ├── tcp_socket.h         # TCP for MMS
│       │   ├── tcp_listener.h       # TCP listener for incoming MMS connections
│       │   ├── tpkt.h               # TPKT (RFC 1006) framing for MMS
│       │   ├── iso_session.h        # ISO 8327 session layer
│       │   ├── iso_presentation.h   # ISO 8823 presentation layer
│       │   ├── iso_acse.h           # ISO ACSE (Association Control)
│       │   ├── iso_connection.h     # Full ISO stack (TPKT+session+presentation+ACSE)
│       │   └── eth_frame.h          # Ethernet frame builder (MAC, VLAN, EtherType, PDU header)
│       ├── security/
│       │   ├── key_manager.h
│       │   ├── cert_manager.h       # X.509 certificate loading, key ID, public key extraction
│       │   └── hmac_verify.h        # HMAC-SHA256 / AES-GMAC (IEC 62351-6:2020)
│       ├── config/
│       │   ├── config_manager.h
│       │   └── yaml_parser.h
│       ├── scl/
│       │   ├── scl_parser.h         # SCL/SCD XML parser
│       │   └── scl_ied_builder.h
│       ├── ied/
│       │   ├── ied_data_model.h
│       │   ├── ied_types.h
│       │   └── logical_device.h
│       ├── mms/
│       │   ├── mms_server.h
│       │   ├── mms_client.h
│       │   ├── mms_session.h        # MMS PDU dispatch and association management
│       │   ├── mms_data_store.h
│       │   ├── mms_variable_binding.h
│       │   ├── mms_file_service.h   # GetFileDirectory, FileRead, FileWrite
│       │   └── mms_report.h         # ReportControlBlock, BufferedRcb, UnbufferedRcb, RcbManager
│       ├── monitoring/
│       │   └── system_monitor.h
│       └── logging/
│           └── logger.h
├── src/
│   ├── bpf/                         # XDP fast-path programs
│   │   ├── node_goose_filter.bpf.c  # EtherType 0x88B8, APPID + MAC filtering
│   │   ├── node_goose_parse.bpf.c   # Shallow BER: extract stNum, sqNum
│   │   ├── node_sv_filter.bpf.c     # EtherType 0x88BA, APPID filtering
│   │   ├── node_sv_parse.bpf.c      # 9-2LE fixed-format: smpCnt, smpSynch
│   │   ├── iec61850_maps.bpf.h      # Filter maps (APPID→action), stats maps
│   │   └── ber_shallow.bpf.h        # Inline: bounded TLV walker for BER headers
│   ├── asn1/                        # Full BER codec (userspace)
│   │   ├── goose_ber.c
│   │   ├── goose_ber_decode.c
│   │   ├── sv_ber.c
│   │   └── mms_ber.c
│   ├── containers/
│   │   ├── fixed_string.c
│   │   ├── fixed_array.c
│   │   └── ring_buffer.c
│   ├── goose/
│   │   ├── goose_publisher.c
│   │   ├── goose_subscriber.c
│   │   └── goose_retransmission.c
│   ├── sv/
│   │   ├── sv_publisher.c
│   │   └── sv_subscriber.c
│   ├── transport/
│   │   ├── packet_io_xsk.c          # Packet I/O via xgl_xsk_* (zero-copy AF_XDP)
│   │   ├── packet_io_raw.c          # Raw socket fallback for testing
│   │   ├── tcp_socket.c             # TCP for MMS
│   │   ├── tcp_listener.c           # TCP listener for incoming MMS connections
│   │   ├── tpkt.c                   # TPKT (RFC 1006) framing
│   │   ├── iso_session.c            # ISO 8327 session layer
│   │   ├── iso_presentation.c       # ISO 8823 presentation layer
│   │   ├── iso_acse.c               # ISO ACSE (Association Control)
│   │   ├── iso_connection.c         # Full ISO stack combining TPKT+session+pres+ACSE
│   │   └── eth_frame.c              # Ethernet frame builder for GOOSE/SV
│   ├── security/
│   │   ├── key_manager.c
│   │   ├── cert_manager.c           # X.509 certificate management
│   │   └── hmac_verify.c
│   ├── config/
│   │   ├── config_manager.c
│   │   └── yaml_parser.c
│   ├── scl/
│   │   ├── scl_parser.c
│   │   └── scl_ied_builder.c        # Build IED data model from SCL parse results
│   ├── ied/
│   │   ├── ied_data_model.c
│   │   └── ied_types.c
│   ├── mms/
│   │   ├── mms_data_store.c
│   │   ├── mms_server.c             # MMS server with PDU dispatch
│   │   ├── mms_client.c             # MMS client (GetNameList, Read, Write, etc.)
│   │   ├── mms_session.c            # MMS session and association management
│   │   ├── mms_variable_binding.c   # Variable binding for request/response
│   │   ├── mms_file_service.c       # File services
│   │   └── mms_report.c             # Report control blocks (BRCB, URCB, RcbManager)
│   ├── monitoring/
│   │   └── system_monitor.c
│   └── logging/
│       └── logger.c
├── tests/
│   ├── unit/
│   │   ├── test_goose_ber.c
│   │   ├── test_sv_ber.c
│   │   ├── test_goose_pubsub.c
│   │   ├── test_sv_pubsub.c
│   │   ├── test_containers.c
│   │   ├── test_eth_frame.c         # Ethernet frame construction/parsing
│   │   ├── test_scl_full.c          # Full SCL: ReportControl, DataSet, SclIedBuilder
│   │   ├── test_iso_stack.c         # TPKT, ISO session/presentation/ACSE
│   │   ├── test_mms_server.c        # MMS services: GetNameList, Read, Write, Report
│   │   ├── test_mms_client.c        # MMS client operations
│   │   └── test_cert_manager.c      # X.509 cert loading, key ID, pub key extraction
│   ├── property/
│   │   ├── test_goose_properties.c
│   │   ├── test_sv_properties.c
│   │   ├── test_ber_codec_properties.c
│   │   └── test_malformed_inputs.c
│   └── integration/
│       ├── test_goose_loopback.sh
│       └── test_sv_loopback.sh
├── verification/
│   ├── cbmc/
│   │   ├── ber_decoder_harness.c    # Prove no OOB for any 1500-byte input
│   │   ├── ber_encoder_harness.c    # Prove output never exceeds buffer
│   │   └── shallow_ber_harness.c    # Prove XDP BER parser safety
│   ├── frama-c/
│   │   ├── goose_ber_harness.c
│   │   └── sv_ber_harness.c
│   └── tlaplus/
│       ├── GOOSEProtocol.tla        # COPY FROM iec-61850 project
│       ├── GOOSEProtocol.cfg
│       ├── SampledValuesProtocol.tla # COPY FROM iec-61850 project
│       └── SampledValuesProtocol.cfg
├── examples/
│   ├── goose_publisher.c
│   ├── goose_subscriber.c
│   ├── sv_publisher.c
│   ├── sv_subscriber.c
│   └── latency/
│       └── goose_latency.c
├── docs/
│   ├── architecture.md
│   └── formal/
│       └── verification-guide.md
└── subprojects/
    ├── xdp-graph-lib.wrap
    ├── libbpf.wrap
    └── libxml2.wrap
```

---

## Split-Plane Architecture

```
                    ┌──────────────────────────────┐
                    │  Userspace (C11, MISRA C)     │
                    │  ┌────────┐ ┌────────┐       │
                    │  │ GOOSE  │ │  SV    │       │
                    │  │pub/sub │ │pub/sub │       │
                    │  └───┬────┘ └───┬────┘       │
                    │      │          │             │
                    │  ┌───┴──────────┴───┐        │
                    │  │ Full BER decode  │        │
                    │  │ State machines   │        │
                    │  │ Security (HMAC)  │        │
                    │  └───────┬──────────┘        │
                    │          │ AF_XDP             │
                    ├──────────┼────────────────────┤
                    │          │ Kernel             │
                    │  ┌───────┴──────────┐        │
                    │  │ XDP fast path    │        │
                    │  │ EtherType filter │        │
                    │  │ APPID filter     │        │
                    │  │ Shallow BER      │        │
                    │  │ (stNum/sqNum)    │        │
                    │  └──────────────────┘        │
                    │          NIC                  │
                    └──────────────────────────────┘
```

**Design rationale**:
- XDP fast path handles filtering (drop unsubscribed APPIDs) and shallow parsing
- Accepted packets pass to userspace via AF_XDP for full BER decoding
- This avoids complex BER parsing in BPF (verifier limits) while still
  benefiting from early filtering at wire speed

---

## BPF Fast Path

### Node Indices — DYNAMIC (no hardcoded constants)

Extension node indices MUST be dynamically allocated via
`egl_graph_alloc_index()` at registration time. BPF programs read
their target indices from a config map (indirection table) at runtime.

```c
/* In iec61850_maps.bpf.h — config map for dynamic indices: */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);       /* role ID */
    __type(value, __u32);     /* PROG_ARRAY index (set by userspace) */
} iec61850_node_config SEC(".maps");

/* Logical roles (not PROG_ARRAY indices): */
#define IEC61850_ROLE_GOOSE_FILTER   0
#define IEC61850_ROLE_GOOSE_PARSE    1
#define IEC61850_ROLE_SV_FILTER      2
#define IEC61850_ROLE_SV_PARSE       3
#define IEC61850_ROLE_ETH_INPUT      4  /* groutx node to return to */
```

```c
/* In BPF program — lookup target index at runtime: */
__u32 role = IEC61850_ROLE_ETH_INPUT;
__u32 *idx = bpf_map_lookup_elem(&iec61850_node_config, &role);
if (idx)
    XGL_NEXT(ctx, egl_prog_array, *idx);
XGL_DROP();  /* fallback if config not populated */
```

```c
/* In userspace (iec61850_graph.c) — allocate + register: */
int goose_idx = egl_graph_alloc_index(g);
egl_graph_add_node(g, goose_idx, "node_goose_filter.bpf.o", "node_goose_filter");

/* Populate config map so BPF knows where to tail-call: */
__u32 role = IEC61850_ROLE_ETH_INPUT;
__u32 eth_input_idx = 1;  /* groutx core, always 1 */
bpf_map_update_elem(config_fd, &role, &eth_input_idx, BPF_ANY);

/* Populate ext_dispatch so groutx routes EtherType to us: */
uint16_t goose_et = 0x88B8;
bpf_map_update_elem(dispatch_fd, &goose_et, &goose_idx, BPF_ANY);
```

See ebpf-graph-lib CLAUDE.md "Dynamic Node Index Allocation" for the
full design pattern. This prevents index collisions with groutx K8s
nodes (conntrack=13, snat=14, ndp=15) and xdp-hsr-prp extension nodes.

### BPF Maps — `src/bpf/iec61850_maps.bpf.h`

```c
/* GOOSE subscription filter: APPID → action
 * value: 0 = drop, 1 = pass to AF_XDP */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);       /* APPID (network byte order) */
    __type(value, __u8);      /* action: 0=drop, 1=accept */
} goose_filter SEC(".maps");

/* SV subscription filter: APPID → action */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);
    __type(value, __u8);
} sv_filter SEC(".maps");

/* AF_XDP socket map: queue_id → xsk fd */
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 4);
    __type(key, __u32);
    __type(value, __u32);
} xsk_map SEC(".maps");

/* GOOSE state tracking: APPID → {stNum, sqNum} for change detection */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);
    __type(value, struct goose_state);
} goose_state_map SEC(".maps");

/* Per-node statistics */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, EGL_DEFAULT_MAX_NODES);
    __type(key, __u32);
    __type(value, struct egl_node_stats);
} iec61850_stats SEC(".maps");
```

### `node_goose_filter.bpf.c` — GOOSE Filtering

- **Input**: Packet with EtherType 0x88B8 (dispatched from groutx `node_eth_input`)
- **Processing**:
  1. Validate minimum GOOSE PDU length (>= 8 bytes after Ethernet header)
  2. Extract APPID from bytes 0-1 of GOOSE header
  3. Lookup APPID in `goose_filter` map
  4. If not found or value == 0: drop (unsubscribed)
  5. If value == 1: redirect to AF_XDP via `bpf_redirect_map(&xsk_map, queue_id, 0)`
- **Output**: `XDP_REDIRECT` to AF_XDP socket, or `XDP_DROP`
- **Maps**: `goose_filter` (read), `xsk_map` (read), `iec61850_stats` (write)

### `node_goose_parse.bpf.c` — Shallow GOOSE BER Parse (Optional)

- **Input**: GOOSE packet accepted by filter
- **Processing**:
  1. Use bounded TLV walker (`ber_shallow.bpf.h`) to find stNum and sqNum
  2. Compare against `goose_state_map`: if stNum unchanged and sqNum is
     retransmission, optionally drop (dedup at XDP level)
  3. Update `goose_state_map` with new stNum/sqNum
  4. Redirect to AF_XDP
- **Constraint**: BER parsing in BPF must be bounded (max 10 TLV iterations)
  to satisfy verifier. See `ber_shallow.bpf.h`.

### `node_sv_filter.bpf.c` — SV Filtering

- **Input**: Packet with EtherType 0x88BA
- **Processing**: Same pattern as GOOSE filter but for SV APPIDs
- **Output**: `XDP_REDIRECT` to AF_XDP or `XDP_DROP`

### `node_sv_parse.bpf.c` — SV Fixed-Format Parse (Optional)

- **Input**: SV packet accepted by filter
- **Processing**:
  1. IEC 61850-9-2LE has fixed-format encoding: smpCnt at known offset
  2. Extract smpCnt and smpSynch directly (no BER walking needed)
  3. Check for sample counter gaps (missed samples)
  4. Redirect to AF_XDP
- **Advantage**: 9-2LE fixed format avoids complex BER in BPF

### `src/bpf/ber_shallow.bpf.h` — Bounded BER Walker

```c
/*
 * Shallow TLV walker for BPF.
 *
 * Walks BER TLV structure with a BOUNDED loop (max_iterations).
 * Returns offset of the target tag, or -1 if not found.
 *
 * CRITICAL: The loop MUST be bounded for the BPF verifier.
 * Use #pragma unroll or explicit iteration limit.
 */

#define BER_MAX_ITERATIONS  10

static inline int ber_find_tag(const __u8 *data, int data_len,
                               __u8 target_tag, int max_iter)
{
    int offset = 0;
    for (int i = 0; i < max_iter && i < BER_MAX_ITERATIONS; i++) {
        if (offset >= data_len)
            return -1;
        __u8 tag = data[offset];
        /* ... parse length, skip to next TLV ... */
        if (tag == target_tag)
            return offset;
        /* advance past this TLV */
    }
    return -1;
}
```

---

## Userspace Protocol Stack

### Transport Layer — AF_XDP Zero-Copy

AF_XDP sockets are provided by xdp-graph-lib via `xgl_xsk_*` API.
This project does NOT implement its own AF_XDP wrapper — it uses the
zero-copy sockets from the graph library, which prefer `XDP_ZEROCOPY`
mode and fall back to `XDP_COPY` automatically.

#### `include/iec61850/transport/packet_io.h`

Abstract packet I/O interface (strategy pattern):

```c
struct packet_io;

struct packet_io_ops {
    int  (*open)(struct packet_io *io, const char *ifname, int queue_id);
    int  (*recv)(struct packet_io *io, void **pkt_data, size_t *pkt_len);
    int  (*send)(struct packet_io *io, const void *pkt_data, size_t pkt_len);
    void (*release)(struct packet_io *io);  /* release received packet buffer */
    void (*close)(struct packet_io *io);
};

struct packet_io {
    const struct packet_io_ops *ops;
    void *priv;  /* implementation-specific state */
};

/* Factory — uses xgl_xsk_* from xdp-graph-lib for zero-copy AF_XDP */
struct packet_io *packet_io_create_xsk(void);
struct packet_io *packet_io_create_raw(void);  /* fallback: raw sockets */
```

#### `src/transport/packet_io_xsk.c`

Implements `packet_io_ops` by delegating to xdp-graph-lib's `xgl_xsk_*`:

```c
#include <xgl/xgl_xsk.h>

/* open  → xgl_xsk_create(ifname, queue_id, 4096, 4096) */
/* recv  → xgl_xsk_recv() — returns pointer directly into UMEM */
/* send  → xgl_xsk_send_alloc() + memcpy + xgl_xsk_send_complete() */
/* release → xgl_xsk_recv_release() */
/* close → xgl_xsk_destroy() */
```

Zero-copy is preferred automatically — `xgl_xsk_create()` tries
`XDP_ZEROCOPY` first. Callers can check `xgl_xsk_is_zerocopy()` to
confirm which mode was obtained.

### ASN.1 BER Codec

**Translate from** `~/Code/github.com/smgglrs/iec-61850/` (C++/DPDK):

| New file | Reference source | Adaptation needed |
|----------|-----------------|-------------------|
| `src/asn1/goose_ber.c` | `iec-61850/src/asn1/` (C++) | Translate to C11, remove DPDK, use packet_io.h |
| `src/asn1/goose_ber_decode.c` | `iec-61850/src/asn1/` (C++) | Translate to C11 |
| `src/asn1/sv_ber.c` | `iec-61850/src/asn1/` (C++) | Translate to C11, remove DPDK |
| `src/asn1/mms_ber.c` | `iec-61850/src/asn1/` (C++) | Translate to C11, remove DPDK |

The C++ reference has corresponding Frama-C verification. Write ACSL contracts
on the C11 translations for Frama-C verification.

### Containers

**Translate from** `~/Code/github.com/smgglrs/iec-61850/` (C++):
- `fixed_string.c` / `.h` — Fixed-capacity string (no heap allocation)
- `fixed_array.c` / `.h` — Fixed-capacity array
- `ring_buffer.c` / `.h` — Lock-free SPSC ring buffer

### GOOSE Protocol

#### `include/iec61850/goose/goose_publisher.h`

```c
struct goose_publisher;

struct goose_publisher_config {
    const char *go_cb_ref;     /* GOOSE Control Block reference */
    const char *dat_set;       /* DataSet reference */
    __u16       appid;         /* APPID */
    __u8        dst_mac[6];    /* Multicast destination MAC */
    __u32       conf_rev;      /* Configuration revision */
};

struct goose_publisher *goose_publisher_create(
    struct packet_io *io, const struct goose_publisher_config *cfg);
void goose_publisher_destroy(struct goose_publisher *pub);

/* Publish a GOOSE message (increments stNum, resets sqNum) */
int goose_publisher_publish(struct goose_publisher *pub,
                            const void *data, size_t data_len);

/* Retransmit current state (increments sqNum only) */
int goose_publisher_retransmit(struct goose_publisher *pub);

/* Get current stNum/sqNum */
__u32 goose_publisher_get_stnum(const struct goose_publisher *pub);
__u32 goose_publisher_get_sqnum(const struct goose_publisher *pub);
```

#### `include/iec61850/goose/goose_subscriber.h`

```c
struct goose_subscriber;

typedef void (*goose_callback_t)(const struct goose_subscriber *sub,
                                  __u32 stNum, __u32 sqNum,
                                  const void *data, size_t data_len,
                                  void *user_data);

struct goose_subscriber_config {
    __u16           appid;
    __u8            src_mac[6];  /* Expected source MAC (or all-zero for any) */
    goose_callback_t callback;
    void            *user_data;
};

struct goose_subscriber *goose_subscriber_create(
    struct packet_io *io, const struct goose_subscriber_config *cfg);
void goose_subscriber_destroy(struct goose_subscriber *sub);

/* Process one received packet (non-blocking) */
int goose_subscriber_poll(struct goose_subscriber *sub, int timeout_ms);

/* Get subscription statistics */
int goose_subscriber_get_stats(const struct goose_subscriber *sub,
                                __u64 *received, __u64 *dropped, __u64 *errors);
```

#### `include/iec61850/goose/goose_retransmission.h`

```c
/*
 * GOOSE retransmission timer.
 *
 * After a state change (stNum increment), GOOSE retransmits with
 * exponentially increasing intervals until reaching maxTime:
 *
 *   minTime → 2*minTime → 4*minTime → ... → maxTime → maxTime → ...
 *
 * Default: minTime=1ms, maxTime=1000ms
 */

struct goose_retransmit;

struct goose_retransmit *goose_retransmit_create(
    struct goose_publisher *pub, __u32 min_time_ms, __u32 max_time_ms);
void goose_retransmit_destroy(struct goose_retransmit *rt);

/* Signal a state change (resets retransmission timer) */
void goose_retransmit_trigger(struct goose_retransmit *rt);

/* Call periodically: sends retransmissions when timers expire */
int goose_retransmit_tick(struct goose_retransmit *rt);
```

### Sampled Values Protocol

#### `include/iec61850/sv/sv_publisher.h`

```c
struct sv_publisher;

struct sv_publisher_config {
    const char *sv_cb_ref;
    __u16       appid;
    __u8        dst_mac[6];
    __u32       conf_rev;
    __u16       no_asdu;         /* Number of ASDUs per SV message (usually 1) */
    __u16       smp_rate;        /* Samples per second (e.g., 4000, 4800) */
};

struct sv_publisher *sv_publisher_create(
    struct packet_io *io, const struct sv_publisher_config *cfg);
void sv_publisher_destroy(struct sv_publisher *pub);

/* Publish one sample (smpCnt auto-increments, wraps at smp_rate) */
int sv_publisher_publish(struct sv_publisher *pub,
                         const void *sample_data, size_t sample_len,
                         __u8 smp_synch);
```

#### `include/iec61850/sv/sv_subscriber.h`

```c
struct sv_subscriber;

typedef void (*sv_callback_t)(const struct sv_subscriber *sub,
                               __u16 smpCnt, __u8 smpSynch,
                               const void *sample_data, size_t sample_len,
                               void *user_data);

struct sv_subscriber_config {
    __u16        appid;
    sv_callback_t callback;
    void         *user_data;
};

struct sv_subscriber *sv_subscriber_create(
    struct packet_io *io, const struct sv_subscriber_config *cfg);
void sv_subscriber_destroy(struct sv_subscriber *sub);
int sv_subscriber_poll(struct sv_subscriber *sub, int timeout_ms);
```

### Security — IEC 62351-6

#### `include/iec61850/security/hmac_verify.h`

```c
/* HMAC-SHA256 verification for GOOSE/SV (IEC 62351-6:2020) */

int hmac_sha256_verify(const __u8 *key, size_t key_len,
                       const __u8 *data, size_t data_len,
                       const __u8 *expected_mac, size_t mac_len);

int hmac_sha256_sign(const __u8 *key, size_t key_len,
                     const __u8 *data, size_t data_len,
                     __u8 *out_mac, size_t mac_len);

/* AES-GMAC for IEC 62351-6:2020 extended authentication */
int aes_gmac_verify(const __u8 *key, size_t key_len,
                    const __u8 *iv, size_t iv_len,
                    const __u8 *aad, size_t aad_len,
                    const __u8 *expected_tag, size_t tag_len);
```

Uses OpenSSL EVP API. Reference: `iec-61850/src/security/` (C++).

---

## Build System (Meson)

```meson
project('xdp-iec61850', 'c',
    version: '0.1.0',
    license: 'BSD-2-Clause',
    meson_version: '>=0.56.0',
    default_options: ['c_std=c11', 'warning_level=3', 'buildtype=debug', 'werror=true'])

cc = meson.get_compiler('c')
extra_c_args = cc.get_supported_arguments(
    '-Wconversion', '-Wshadow', '-Wstrict-prototypes', '-Wmissing-prototypes')

# Required dependencies (xgl_dep transitively brings egl_dep and libbpf_dep)
xgl_dep = dependency('xdp-graph-lib', fallback: ['xdp-graph-lib', 'xgl_dep'])
libbpf_dep = dependency('libbpf', version: '>=1.0')
libelf_dep = dependency('libelf')
thread_dep = dependency('threads')

# Optional dependencies
libxml2_dep = dependency('libxml-2.0', required: get_option('enable_mms'))
openssl_dep = dependency('openssl', required: get_option('enable_security'))
libyaml_dep = dependency('yaml-0.1', required: false)
hsr_prp_dep = dependency('xdp-hsr-prp', required: get_option('enable_hsr_prp'),
                          fallback: ['xdp-hsr-prp', 'hsr_prp_dep'])

# BPF programs
clang = find_program('clang')
bpf_cflags = ['-target', 'bpf', '-O2', '-g', '-Wall', '-Wextra',
              '-D__TARGET_ARCH_x86',
              '-I' + meson.current_source_dir() / 'include',
              '-I' + meson.current_source_dir() / 'src/bpf']

bpf_nodes = ['node_goose_filter', 'node_goose_parse',
             'node_sv_filter', 'node_sv_parse']
foreach node : bpf_nodes
    custom_target(node + '.bpf.o',
        input: 'src/bpf/' + node + '.bpf.c',
        output: node + '.bpf.o',
        command: [clang, bpf_cflags, '-c', '@INPUT@', '-o', '@OUTPUT@'])
endforeach

# Core library sources (always built)
core_sources = files(
    'src/asn1/goose_ber.c', 'src/asn1/goose_ber_decode.c', 'src/asn1/sv_ber.c',
    'src/containers/fixed_string.c', 'src/containers/fixed_array.c',
    'src/containers/ring_buffer.c',
    'src/goose/goose_publisher.c', 'src/goose/goose_subscriber.c',
    'src/goose/goose_retransmission.c',
    'src/sv/sv_publisher.c', 'src/sv/sv_subscriber.c',
    'src/transport/packet_io_xsk.c',
    'src/ied/ied_data_model.c', 'src/ied/ied_types.c',
    'src/config/config_manager.c',
    'src/monitoring/system_monitor.c',
    'src/logging/logger.c',
)

core_deps = [xgl_dep, libbpf_dep, libelf_dep, thread_dep]

# Optional sources
if get_option('enable_mms')
    core_sources += files('src/asn1/mms_ber.c', 'src/mms/mms_data_store.c',
                          'src/transport/tcp_socket.c', 'src/scl/scl_parser.c')
    core_deps += [libxml2_dep]
endif

if get_option('enable_security')
    core_sources += files('src/security/key_manager.c', 'src/security/hmac_verify.c')
    core_deps += [openssl_dep]
endif

if libyaml_dep.found()
    core_sources += files('src/config/yaml_parser.c')
    core_deps += [libyaml_dep]
endif

iec61850_lib = static_library('iec61850',
    core_sources,
    include_directories: include_directories('include'),
    dependencies: core_deps,
    c_args: extra_c_args)

iec61850_dep = declare_dependency(
    link_with: iec61850_lib,
    include_directories: include_directories('include'),
    dependencies: core_deps)
```

### `meson_options.txt`

```meson
option('enable_mms', type: 'boolean', value: false,
       description: 'Build MMS server/client (requires libxml2)')
option('enable_security', type: 'boolean', value: false,
       description: 'Build IEC 62351-6 security (requires OpenSSL)')
option('enable_hsr_prp', type: 'boolean', value: false,
       description: 'Enable HSR/PRP redundancy support')
option('enable_tests', type: 'boolean', value: true,
       description: 'Build tests')
option('enable_examples', type: 'boolean', value: true,
       description: 'Build example programs')
```

---

## Testing

### Unit Tests

**`test_goose_ber.c`**: BER encoder/decoder round-trip for GOOSE PDUs.
- Encode a GOOSE message, decode it, verify all fields match
- Test with varying data sizes (0, 1, 100, 1400 bytes)
- Test with all ASN.1 types (BOOLEAN, INTEGER, VISIBLE_STRING, BIT_STRING, etc.)

**`test_sv_ber.c`**: BER encoder/decoder for SV PDUs.
- Encode SV ASDU, decode, verify smpCnt, smpSynch, data values
- Test 9-2LE fixed format compliance

**`test_goose_pubsub.c`**: GOOSE publisher/subscriber lifecycle.
- Create publisher, publish, verify stNum/sqNum increments
- Create subscriber with mock packet_io, verify callback invocation
- Test retransmission timer behavior

**`test_sv_pubsub.c`**: SV publisher/subscriber lifecycle.
- Publish samples, verify smpCnt wraps correctly
- Verify sample data integrity

**`test_containers.c`**: Fixed-capacity container tests.
- fixed_string: append, capacity, overflow behavior
- fixed_array: push, pop, capacity, overflow
- ring_buffer: enqueue/dequeue, wraparound, full/empty detection

### Property-Based Tests

**`test_goose_properties.c`**: 16,500+ iterations of random GOOSE data.
- Property: encode(x) then decode produces x (round-trip)
- Property: stNum monotonically increases
- Property: sqNum resets on stNum change

**`test_sv_properties.c`**: Random SV data.
- Property: smpCnt increments correctly (modulo smp_rate)
- Property: sample data is preserved through encode/decode

**`test_ber_codec_properties.c`**: Random BER inputs.
- Property: decoder never crashes on ANY input (no OOB, no UB)
- Property: encoder output is always valid BER

**`test_malformed_inputs.c`**: Fuzz-like testing.
- Truncated packets at every byte offset
- Invalid BER lengths (overflow, negative)
- Invalid tags, wrong ASN.1 types

### Integration Tests

**`test_goose_loopback.sh`**: GOOSE pub/sub on veth pair.
- Create veth pair, load XDP programs, start publisher and subscriber
- Verify subscriber receives GOOSE messages
- Verify APPID filtering works (unsubscribed APPIDs are dropped)

**`test_sv_loopback.sh`**: SV pub/sub on veth pair.
- Same pattern as GOOSE but for Sampled Values

---

## Verification

### CBMC

**`ber_decoder_harness.c`**:
- Prove: for ANY byte sequence up to 1500 bytes, the BER decoder never
  reads out of bounds and never triggers undefined behavior
- Bound: MTU-sized packets (1500 bytes)

**`ber_encoder_harness.c`**:
- Prove: encoder output never exceeds the provided buffer size
- Prove: encoded output is valid BER (tag-length-value structure)

**`shallow_ber_harness.c`**:
- Prove: the XDP BER walker (ber_shallow.bpf.h) is safe for any input
- Prove: loop terminates within BER_MAX_ITERATIONS
- Prove: no out-of-bounds access on any packet

### Frama-C

**`goose_ber_harness.c`**: ACSL-annotated verification of GOOSE BER encoder.
- Reference: `iec-61850/verification/` (C++ project) and `iec-61850-c/verification/` (C harnesses if available)
- Copy and adapt ACSL contracts from the reference

**`sv_ber_harness.c`**: ACSL-annotated verification of SV BER encoder.
- Reference: `iec-61850/verification/` and `iec-61850-c/verification/`

### TLA+

**`GOOSEProtocol.tla`** and **`GOOSEProtocol.cfg`**:
- COPY FROM: `~/Code/github.com/smgglrs/iec-61850/docs/formal/GOOSEProtocol.tla`
- COPY FROM: `~/Code/github.com/smgglrs/iec-61850/docs/formal/GOOSEProtocol_Comprehensive.cfg`
- Properties verified: StateNumberMonotonic, SequenceNumberResets,
  SubscriberDataConsistent, EventualDelivery

**`SampledValuesProtocol.tla`** and **`SampledValuesProtocol.cfg`**:
- COPY FROM: `~/Code/github.com/smgglrs/iec-61850/docs/formal/SampledValuesProtocol.tla`
- COPY FROM: `~/Code/github.com/smgglrs/iec-61850/docs/formal/SampledValuesProtocol_Comprehensive.cfg`
- Properties verified: SampleCounterMonotonic, SamplingIntervalMaintained,
  LatencyBound, GapDetectionQuality

---

## Gap Analysis vs C++ Reference (iec-61850)

Last reviewed: 2026-03-05. Fresh expert panel re-review (4 specialists).
Prior reviews: 7 specialists total across two rounds.

### FIXED (verified across 4 review rounds, 15+ specialists)

All original bugs (BUG-0 through BUG-17) plus all P1 items are now FIXED:

- BPF graph integration (XGL_NODE, XGL_META_GET, XGL_STATS_INC_*)
- GOOSE subscriber state machine, SV smpCnt wraparound, BER_MAX_ITERATIONS
- ISO stack (COTP, TCP reads, DATA SPDU, A0 wrapper, PI tag, session length)
- MMS: 27/27 services dispatched (including Status, Identify, all file/journal/control)
- MMS control: full state machine with action callback (select/operate/cancel)
- Security: two-phase verification (signature then per-publisher replay),
  key ID 20 bytes, cert chain validation, PDU length updated, inside PDU
- GOOSE replay chicken-and-egg: FIXED (two-phase design)
- SV replay per-publisher: FIXED (sv_verify_security_replay)
- SCL MAC-Address from Communication section: FIXED
- Data model: 24 BasicTypes, 24 CDC types, 22 CDC factory functions,
  all 13 FCs, DA callback documented, GI non-empty
- BPF: redirect return fixed, graph registration, install targets,
  standard map names (xgl_tx_ports, xgl_xsk_map), ext_dispatch uint16_t
- XSKMAP disconnect: FIXED (egl_graph_get_map_fd, no subproject divergence)
- Verification: 20 logs (TLA+ 1B+ states, CBMC 5/5, Frama-C 4/4)
- 51 test files, 62 passing, ASAN clean, CI pipeline, real integration tests

### P0 — No critical bugs remain

All previously identified critical bugs (BUG-0 through BUG-13, plus
ext_dispatch key type, replay detection, MMS dispatch, control callback,
SCL MAC-Address) are FIXED. The XSKMAP disconnect in xdp-graph-lib is
also fixed (subproject matches standalone, uses egl_graph_get_map_fd).

### P0 — INTEROP-BREAKING (libiec61850 compatibility, 5th review)

**GPL NOTE**: libiec61850 is GPL. We MUST NOT read its source code. We
verify against the IEC 61850 STANDARD and test interop as a black box.
GPL contamination audit: CLEAN (all files BSD-3-Clause, no GPL references).

**INTEROP-1: GOOSE BitString encoding missing ASN.1 "unused bits" prefix**

`goose_ber.c` encodes BitString via `ber_encode_octetstring()` — raw bytes
without the required leading "unused bits" byte. A standard subscriber
misinterprets the first data byte as padding count. Quality attributes
(BitString) in every GOOSE exchange will be incompatible.

**Fix**: prepend `0x00` byte before BitString data in encoder. Skip first
byte in decoder.

**INTEROP-2: SV sample data uses typed ASN.1, not flat OCTET STRING**

`sv_ber.c` encodes each channel as individual INTEGER + BIT STRING TLVs.
IEC 61850-9-2LE specifies tag [7] as a single OCTET STRING of packed
bytes (8 bytes/channel: 4-byte value + 4-byte quality). No standard
9-2LE implementation will parse the current format.

**Fix**: encode as single OCTET STRING with `noChannels * 8` packed bytes.

**INTEROP-3: SV Quality is 1 byte, standard requires 4 bytes (32 bits)**

**Fix**: expand `sv_sample_quality` to 4 bytes matching IEC 61850-7-3.

**INTEROP-4: MMS InitiateResponse missing `initResponseDetail` [4]**

Contains services-supported bit string + parameter CBB. Without it,
standard clients may reject association or assume no services.

**Fix**: add [4] with services-supported bits for all 27 dispatched services.

**INTEROP-5: Missing GOOSE allData types**

Only 6 of 13 standard types supported. Missing: VisibleString [10],
Structure [2] CONSTRUCTED, Array [1], UtcTime [17], GeneralizedTime [11],
BinaryTime [12], BCD [13]. libiec61850 publishers using strings or complex
types will have data silently dropped.

**Fix**: add at minimum VisibleString [10] (0x8A), Structure [2] (0xA2),
UtcTime [17] (0x91).

### P0.5 — STANDARD VIOLATIONS (non-interop-breaking but incorrect)

**PROTO-1**: Security keyID 20 bytes (SHA-1), standard specifies 4 bytes.
**PROTO-2**: Dual security encoding paths with different field semantics.
**PROTO-3**: SCL DataTypeTemplates not parsed — custom LN types ignored.
**PROTO-4**: No IED model → MMS `LN$FC$DO$DA` naming bridge. A standard
client doing `GetNameList` + `Read("LLN0$ST$Beh$stVal")` gets nothing
unless the application manually creates MMS named variables.

### P1 — HIGH (from 4th review)

**TLA+ GOOSE Stress temporal violation** — `tlaplus_goose_stress.log`
shows a liveness property violation caused by missing fairness constraints.
Not a safety invariant violation, but the safety case claims "0 errors
for all TLA+ runs" which is now false. Fix: add `FAIRNESS` to the stress
.cfg file, or document the liveness gap in the safety case.

**Certificate expiry not checked at runtime** —
`iec61850_cert_manager_is_valid_time()` exists but is never called during
`poll()`. A certificate that expires after `enable_security()` continues
to be accepted. Fix: check expiry periodically (e.g., once per second
in poll) or on every security verification call.

**MMS session threads detached** — `pthread_detach()` in `mms_server.c`
prevents join on shutdown. `iec61850_mms_server_stop()` sets stop flag
and joins accept thread but cannot wait for session threads. Potential
use-after-free if server struct freed while sessions running. Fix: use
joinable threads and wait for all sessions in stop().

**SV multi-ASDU drops remaining after first accept** —
`sv_subscriber_poll()` returns after first ASDU `process()` returns true.
Remaining ASDUs in multi-ASDU frames are silently dropped. Fix: process
ALL ASDUs regardless of individual return values.

### P2 — MEDIUM

**Coverage stalled at 46%** — 7 source files at 0% despite having test
files (config_manager, yaml_parser, logger, system_monitor, packet_io_raw,
packet_io_xsk, mms_client). Tests may exercise mock paths only.

**Safety case evidence stale** — test counts (49 vs 62), Frama-C coverage
percentages, TLA+ stress result don't match actual logs. Traceability
matrix has stale file references (test_mms_client_server.c doesn't exist,
should be test_mms_e2e.c). SR-010 lists no test file but test_mms_control.c
exists.

**MISRA deviation record unsigned** — draft exists with proper structure
but no signatures for SIL 2 compliance.

**Static analysis doesn't gate CI** — all analysis jobs `allow_failure: true`.

**Loopback tests unreachable** — goose_loopback.c and sv_loopback.c are
`build_by_default: false` and not registered as meson tests.

**MX3 and DEL3 CDC factories missing** — 22/24 CDC types have factories.

### What's Working Well

- 27/27 MMS services dispatched (was 4 originally)
- 22 CDC factory functions (was 5; C++ has 20 — C11 is a superset)
- 62/62 tests pass under ASAN (was 28 originally)
- 51 test files, real integration tests (no more stubs)
- 20 verification logs: TLA+ 1B+ states, CBMC 5 proofs (including
  decoder APDU 0/1902 and SV decoder APDU 0/3056), Frama-C 4 analyses
  (all 0 alarms)
- Two-phase security verification (signature then per-publisher replay)
- Full ISO transport stack, full MMS control with action callbacks
- Standard map names, no subproject divergence
- MISRA deviation record created (draft)
- CI pipeline with build/test/analysis/verification stages

### Not a Gap (by design)

- **HSR/PRP**: handled by xdp-hsr-prp project
- **DPDK I/O**: replaced by AF_XDP via xgl_xsk_*
- **DPDK flow rules / lcore workers**: replaced by XDP/BPF
- **Transport factory**: architectural simplification

### C11 Advantages over C++

- HMAC-SHA256 + AES-GMAC (IEC 62351-6:2020 symmetric auth)
- Multi-ASDU SV processing (C++ only processes first ASDU)
- More accurate ECDSA signature sizes (72/104 vs 64/96)
- Stricter compiler warnings (-Werror, -Wconversion, -Wshadow)
- More LN classes in IED builder (LPHD, XSWI, PTOC, GGIO)
- PDU Length calculation correct per IEC 61850-8-1 (C++ has bug)
- XDP/BPF fast path + AF_XDP zero-copy (no C++ equivalent)
- BER codec byte-for-byte identical — zero wire format interop risk

---

## Interoperability Test Suite (libiec61850)

### GPL Boundary

libiec61850 is GPL. Our code is BSD-3-Clause. The interop test suite uses
**subprocess isolation**: our test harness (BSD-3) launches libiec61850 helper
programs (GPL binaries) as subprocesses. Communication is wire-only. No linking
against GPL in our binaries. GPL audit: CLEAN (all 131 files BSD-3-Clause).

### Test Architecture

```
tests/interop/
├── helpers/                    # GPL binaries (built separately)
│   ├── goose_pub_helper.c     # libiec61850 GOOSE publisher
│   ├── goose_sub_helper.c     # libiec61850 GOOSE subscriber
│   ├── sv_pub_helper.c        # libiec61850 SV publisher
│   ├── sv_sub_helper.c        # libiec61850 SV subscriber
│   ├── mms_server_helper.c    # libiec61850 MMS server
│   ├── mms_client_helper.c    # libiec61850 MMS client
│   ├── Makefile               # Builds against pkg-config libiec61850
│   └── build_libiec61850_helpers.sh
├── goose/                     # BSD-3 test harnesses
│   ├── test_goose_interop_sub.c   # lib61850 pub → xdp sub (12 scenarios)
│   └── test_goose_interop_pub.c   # xdp pub → lib61850 sub (8 scenarios)
├── sv/
│   ├── test_sv_interop_sub.c      # lib61850 pub → xdp sub (7 scenarios)
│   └── test_sv_interop_pub.c      # xdp pub → lib61850 sub (4 scenarios)
├── mms/
│   ├── test_mms_interop_client.c  # xdp client → lib server (9 scenarios)
│   └── test_mms_interop_server.c  # lib client → xdp server (8 scenarios)
├── wire/
│   ├── test_wire_goose.sh         # pcap + tshark validation
│   ├── test_wire_sv.sh
│   ├── test_wire_mms.sh
│   └── validate_pcap.py           # tshark JSON field validator
└── scl/
    └── interop_test.icd           # Shared SCL model (DataTypeTemplates)
```

### Test Matrix (55 scenarios)

| Protocol | Direction | Scenarios | Issues Tested |
|----------|-----------|-----------|---------------|
| GOOSE | lib61850 → xdp | 12 | INTEROP-1, INTEROP-5 |
| GOOSE | xdp → lib61850 | 8 | INTEROP-1, INTEROP-5 |
| GOOSE | bidirectional | 1 | all GOOSE |
| SV | lib61850 → xdp | 7 | INTEROP-2, INTEROP-3 |
| SV | xdp → lib61850 | 4 | INTEROP-2, INTEROP-3 |
| MMS | xdp client → lib server | 9 | INTEROP-4, PROTO-4 |
| MMS | lib client → xdp server | 8 | INTEROP-4, PROTO-4 |
| Wire | pcap capture | 6 | all INTEROP issues |

### Expected Failures Before Fixes

| INTEROP Issue | Tests That Will Fail |
|---------------|---------------------|
| INTEROP-1 (BitString) | GS-03, GP-02, GP-06, WG-03 |
| INTEROP-2 (SV sample) | SS-01, SS-06, SP-01, WS-01, WS-02 |
| INTEROP-3 (SV Quality) | SS-02, SS-07, SP-02, SP-04, WS-03 |
| INTEROP-4 (MMS InitResp) | MC-01, MS-01, WM-02, WM-03 |
| INTEROP-5 (allData types) | GS-04, GS-05, GS-06, GP-03, GP-04, GP-05 |
| PROTO-4 (MMS naming) | MC-03, MC-04, MS-02, MS-03, WM-04 |

Fix an INTEROP issue → corresponding tests start passing.

### Prerequisites

- `pkg-config libiec61850` (system package or built from source)
- `tshark` (for wire capture tests)
- Root access (GOOSE/SV tests need raw sockets on veth pairs)
- MMS tests use TCP loopback — no root needed

Tests skip with exit code 77 if prerequisites are missing.

---

## Reference Code Mapping

| New file | Reference source | Notes |
|----------|-----------------|-------|
| `src/asn1/*.c` | `iec-61850/src/asn1/` (C++) | Translate to C11, remove DPDK |
| `src/containers/*.c` | `iec-61850/src/` (C++) | Translate to C11 (fixed-capacity, no heap) |
| `src/goose/*.c` | `iec-61850/src/goose/` (C++) | Translate to C11, replace DPDK I/O with packet_io.h |
| `src/sv/*.c` | `iec-61850/src/sv/` (C++) | Translate to C11, replace DPDK I/O with packet_io.h |
| `src/transport/packet_io_xsk.c` | `xdp-graph-lib xgl_xsk_*` | Delegates to xgl_xsk_* for zero-copy AF_XDP |
| `src/transport/eth_frame.c` | `iec-61850/src/goose/GoosePublisher::prepare_packet()` | Ethernet frame construction for GOOSE/SV |
| `src/transport/tpkt.c` | `iec-61850/src/transport/TpktConnection` | RFC 1006 framing |
| `src/transport/iso_session.c` | `iec-61850/src/transport/IsoSession` | ISO 8327 session layer |
| `src/transport/iso_presentation.c` | `iec-61850/src/transport/IsoPresentation` | ISO 8823 presentation |
| `src/transport/iso_acse.c` | `iec-61850/src/transport/IsoAcse` | ISO ACSE |
| `src/transport/iso_connection.c` | `iec-61850/src/transport/IsoConnection` | Full ISO stack |
| `src/transport/tcp_listener.c` | `iec-61850/src/transport/TcpSocketListener` | TCP listener for MMS |
| `src/security/cert_manager.c` | `iec-61850/src/security/CertificateManager` | X.509 cert ops |
| `src/security/*.c` | `iec-61850/src/security/` (C++) | Translate to C11 |
| `src/config/*.c` | `iec-61850/src/config/` (C++) | Translate to C11 |
| `src/scl/scl_parser.c` | `iec-61850/src/scl/SclParser` | Full SCL: add ReportControl + DataSet/FCDA |
| `src/scl/scl_ied_builder.c` | `iec-61850/src/scl/SclIedBuilder` | Build IED model from SCL |
| `src/ied/*.c` | `iec-61850/src/ied/` (C++) | Translate to C11 |
| `src/mms/mms_server.c` | `iec-61850/src/mms/MmsServer` | MMS server with service dispatch |
| `src/mms/mms_client.c` | `iec-61850/src/mms/MmsClient` | All MMS client services |
| `src/mms/mms_session.c` | `iec-61850/src/mms/MmsSession` | Association + PDU encode/decode |
| `src/mms/mms_report.c` | `iec-61850/src/mms/ReportControlBlock+RcbManager` | RCB with trigger eval |
| `src/mms/mms_file_service.c` | `iec-61850/src/mms/MmsFileManager` | File services |
| `src/mms/mms_variable_binding.c` | `iec-61850/src/mms/MmsVariableBinding` | Var binding |
| `verification/tlaplus/*.tla` | `iec-61850/docs/formal/*.tla` | Copy directly |
| `verification/frama-c/*.c` | `iec-61850/verification/` + `iec-61850-c/verification/` | Adapt ACSL contracts for C11 |
| `docs/formal/verification-guide.md` | `iec-61850/docs/formal/verification-guide.md` | Copy and adapt |
