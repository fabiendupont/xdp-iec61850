/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850 BPF Maps
 *
 * Application-specific map definitions for GOOSE/SV XDP filter nodes
 * and routable-profile (IEC TR 61850-90-5) UDP nodes.
 * Graph infrastructure maps (egl_prog_array, egl_node_stats, xgl_xsk_map,
 * xgl_tx_ports) are provided by xgl_common.bpf.h.
 */

#ifndef IEC61850_MAPS_BPF_H
#define IEC61850_MAPS_BPF_H

#include <xgl/bpf/xgl_common.bpf.h>

/* GOOSE state tracking for change detection */
struct goose_state {
    __u32 st_num;
    __u32 sq_num;
};

/* GOOSE subscription filter: APPID -> action
 * value: 0 = drop, 1 = pass to AF_XDP */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);       /* APPID (network byte order) */
    __type(value, __u8);      /* action: 0=drop, 1=accept */
} goose_filter SEC(".maps");

/* SV subscription filter: APPID -> action */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);
    __type(value, __u8);
} sv_filter SEC(".maps");

/* Routable-profile (90-5) UDP subscription filter: UDP destination
 * port -> action
 * key:   UDP destination port (network byte order)
 * value: 0 = drop, 1 = pass to AF_XDP */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);       /* UDP dport (network byte order) */
    __type(value, __u32);     /* action: 0=drop, 1=accept */
} r_filter SEC(".maps");

/* EtherType dispatch: protocol EtherType (host byte order) -> filter
 * node's PROG_ARRAY index. Populated from userspace by
 * iec61850_graph_setup_dispatch(); consumed by node_dispatch. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 16);
    __type(key, __u16);       /* EtherType (host byte order) */
    __type(value, __u32);     /* PROG_ARRAY index of the filter node */
} iec61850_dispatch SEC(".maps");

/* GOOSE state tracking: APPID -> {stNum, sqNum} for change detection */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);
    __type(value, struct goose_state);
} goose_state_map SEC(".maps");

/* R-GOOSE dedup state: APPID -> last-accepted 90-5 SPDU Number for
 * duplicate/out-of-order detection (WP-4a-reconciled semantics).
 * key:   APPID (network byte order)
 * value: last-accepted SPDU Number (host byte order) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);       /* APPID (network byte order) */
    __type(value, __u32);     /* last-accepted SPDU Number */
} rgoose_state_map SEC(".maps");

/* R-SV dedup state: same shape as rgoose_state_map */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);       /* APPID (network byte order) */
    __type(value, __u32);     /* last-accepted SPDU Number */
} rsv_state_map SEC(".maps");

/* =====================================================================
 * WP-5A: per-key token-bucket rate limiting (storm protection)
 * =====================================================================
 *
 * Storm protection at XDP: every filter node (GOOSE, SV, 90-5 UDP)
 * runs a token bucket per filtered key AFTER the subscription filter
 * accepts a packet, so a misbehaving publisher flooding one APPID
 * (or 90-5 dport) is dropped at wire speed without affecting any
 * other key.
 *
 * COST MODEL — BYTES.  The cost of a packet is its full frame length
 * (data_end - data, i.e. the ethernet frame bytes as seen by XDP,
 * FCS excluded).  Bytes rather than packets because a storm's impact
 * on a substation network is bandwidth: GOOSE/SV frame sizes vary by
 * an order of magnitude (a 100-byte SV sample and a 1500-byte GOOSE
 * event must not cost the same), and the resource a flood exhausts
 * is measured in bytes per second.
 *
 * REFILL MATH (all intermediates 64-bit):
 *
 *   elapsed = min(now - last_ns, IEC61850_RL_MAX_ELAPSED_NS)
 *   refill  = elapsed * rate / 1e9                    [bytes]
 *   tokens  = min(tokens + refill, burst)
 *   admit   iff tokens >= frame_length, then tokens -= frame_length
 *
 * The elapsed-time cap keeps elapsed * rate below 2^63 for
 * helper-validated rates (<= 2^31 B/s), so the refill multiply can
 * never overflow; it is semantically invisible while the bucket is
 * full and only under-refills a partially empty bucket left idle for
 * more than ~4.3 s.  Limits written directly to the maps bypassing
 * the userspace helper can at worst distort the token count (BPF
 * arithmetic wraps), never violate memory safety.
 *
 * Buckets start FULL (tokens = burst), so the first packets of a
 * legitimate GOOSE/R-GOOSE event burst always pass; see the default
 * values and their rationale next to IEC61850_RL_DEFAULT_* in
 * include/iec61850/iec61850_graph.h.
 *
 * CONCURRENCY: bucket updates are lock-free read-modify-write.  On a
 * multi-queue NIC two CPUs may race on one bucket and briefly
 * over-admit; this is the standard XDP token-bucket trade-off (the
 * flood being dropped far exceeds any race window, and the fast path
 * stays spinlock-free).  Exact accounting is not a goal.
 */

/* Token-bucket state for one key (APPID or 90-5 dport).  Buckets are
 * created lazily by the filter nodes (inheriting the family default)
 * or explicitly from userspace via iec61850_graph_set_rate_limit().
 * rate == 0 disables limiting for the key. */
struct iec61850_rl_bucket {
    __u64 rate;      /* refill limit, bytes per second (0 = unlimited) */
    __u64 burst;     /* bucket capacity, bytes */
    __u64 tokens;    /* current tokens, bytes (always <= burst) */
    __u64 last_ns;   /* bpf_ktime_get_ns() of the last evaluation */
};

/* Family default limits used to initialize buckets lazily.
 * iec61850_graph_register() seeds documented defaults;
 * iec61850_graph_set_rate_default() retunes them.  rate == 0 stops
 * lazy bucket creation for the family (existing per-key buckets keep
 * their own limits). */
struct iec61850_rl_config {
    __u64 rate;      /* bytes per second (0 = unlimited) */
    __u64 burst;     /* bytes */
};

/* Rate-limit families (indices into iec61850_rl_config); mirror the
 * IEC61850_RL_FAMILY_* constants in include/iec61850/iec61850_graph.h */
#define IEC61850_RL_FAMILY_GOOSE  0
#define IEC61850_RL_FAMILY_SV     1
#define IEC61850_RL_FAMILY_R      2
#define IEC61850_RL_FAMILY_COUNT  3

/* Elapsed-time cap for the refill computation (~4.29 s < 2^32 ns):
 * with rate <= 2^31-1 B/s the elapsed * rate product stays below
 * 2^63, so the refill multiply cannot overflow 64 bits. */
#define IEC61850_RL_MAX_ELAPSED_NS  4000000000ULL

/* Nanoseconds per second, named for readability of the refill math */
#define IEC61850_RL_NS_PER_SEC      1000000000ULL

/* GOOSE rate-limit state: APPID -> token bucket
 * key: APPID (network byte order, matching goose_filter) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);
    __type(value, struct iec61850_rl_bucket);
} goose_rl SEC(".maps");

/* SV rate-limit state: APPID -> token bucket */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);       /* APPID (network byte order) */
    __type(value, struct iec61850_rl_bucket);
} sv_rl SEC(".maps");

/* 90-5 rate-limit state: UDP dport -> token bucket
 * key: UDP destination port (network byte order, matching r_filter) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);       /* UDP dport (network byte order) */
    __type(value, struct iec61850_rl_bucket);
} r_rl SEC(".maps");

/* Family default limits: family index -> {rate, burst} */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, IEC61850_RL_FAMILY_COUNT);
    __type(key, __u32);       /* IEC61850_RL_FAMILY_* */
    __type(value, struct iec61850_rl_config);
} iec61850_rl_config SEC(".maps");

/* Refill and consume from an initialized bucket.  Returns 1 when a
 * packet of `cost` bytes is admitted, 0 when it must be dropped.
 *
 * Straight-line 64-bit arithmetic only — no loops, no pointers
 * derived from packet data (PREVAIL-friendly structure). */
static __always_inline int
iec61850_rl_admit(struct iec61850_rl_bucket *b, __u64 cost, __u64 now)
{
    __u64 tokens;
    __u64 elapsed = 0;
    __u64 refill;

    if (b->rate == 0) {
        return 1;    /* unlimited */
    }

    tokens = b->tokens;
    if (tokens > b->burst) {
        tokens = b->burst;    /* self-stabilizing after a retune */
    }

    if (now > b->last_ns) {
        elapsed = now - b->last_ns;
        if (elapsed > IEC61850_RL_MAX_ELAPSED_NS) {
            elapsed = IEC61850_RL_MAX_ELAPSED_NS;
        }
    }

    refill = (elapsed * b->rate) / IEC61850_RL_NS_PER_SEC;
    if (refill > b->burst) {
        refill = b->burst;
    }
    if (refill > b->burst - tokens) {
        refill = b->burst - tokens;    /* tokens <= burst here */
    }
    tokens += refill;

    b->last_ns = now;

    if (tokens < cost) {
        b->tokens = tokens;
        return 0;
    }

    b->tokens = tokens - cost;
    return 1;
}

/* Full rate-limit evaluation for one packet.  rl_map is the family
 * bucket map (key = APPID / dport in network byte order, matching
 * the filter-map convention), cfg_map the family-default ARRAY.  A
 * key without a bucket inherits the family default (created lazily,
 * starting full); a missing or disabled default leaves the key
 * unlimited.  Returns 1 when `cost` bytes are admitted, 0 when the
 * packet must be dropped.
 *
 * Always inlined, so the map pointers stay concrete at each call
 * site for the verifier. */
static __always_inline int
iec61850_rl_evaluate(void *rl_map, void *cfg_map, __u32 family,
                     const void *key, __u64 cost)
{
    struct iec61850_rl_bucket *b = bpf_map_lookup_elem(rl_map, key);
    struct iec61850_rl_config *cfg;
    struct iec61850_rl_bucket fresh;
    __u64 now = bpf_ktime_get_ns();

    if (b) {
        return iec61850_rl_admit(b, cost, now);
    }

    cfg = bpf_map_lookup_elem(cfg_map, &family);
    if (!cfg || cfg->rate == 0) {
        return 1;    /* no limits configured for this family */
    }

    /* Lazy bucket creation: start full so the first burst of a
     * legitimate publisher always passes.  BPF_NOEXIST keeps a
     * racing CPU from clobbering an existing entry; the rare loser
     * evaluates its local copy, over-admitting at most one burst,
     * once. */
    fresh.rate = cfg->rate;
    fresh.burst = cfg->burst;
    fresh.tokens = cfg->burst;
    fresh.last_ns = now;
    bpf_map_update_elem(rl_map, key, &fresh, BPF_NOEXIST);

    return iec61850_rl_admit(&fresh, cost, now);
}

/* =====================================================================
 * WP-4A-RECONCILED: IEC TR 61850-90-5 session-header wire offsets
 * =====================================================================
 *
 * ALL 90-5 session-header wire-format constants live in this single
 * block.  Reconciled with WP-4a's clean-room derivation
 * (src/asn1/rgoose_ber.c, sources [S1][S2][S3] cited there).
 *
 * UDP payload = SPDU:
 *
 *   octet 0      SI: 0xA1 (R-GOOSE) / 0xA2 (R-SV)
 *   octet 1      LI: session-header parameter area length
 *                  = 12 (plain) / 24 (secured)
 *   octet 2      PI: 0x80 (common session header)
 *   octet 3      LI: common-header parameter value length
 *                  = 10 (plain) / 22 (secured)
 *   octet 4-7    SPDU Length (u32, network order): covers
 *                  SPDU Number -> end of signature
 *   octet 8-11   SPDU Number (u32, network order):
 *                  duplicate/out-of-order detection
 *   octet 12-13  Version (u16) = 1
 *   --- secured only (LI@1 == 24) ---
 *   octet 14-17  Time of Current Key (u32, epoch seconds)
 *   octet 18-19  Time to Next Key (u16, minutes)
 *   octet 20-21  Security Algorithms (u16)
 *   octet 22-25  Key ID (u32)
 *   --- payload attributes at H = 14 (plain) / 26 (secured) ---
 *   H+0-3        Payload Length (u32)
 *   H+4          Payload Type: 0x81 (GOOSE) / 0x82 (SV)
 *   H+5          Simulation (u8)
 *   H+6-7        APPID (u16, network order)
 *   H+8-9        APDU Length (u16): PDU length + 2
 *   H+10...      GOOSE/SV PDU (BER)
 *   end          [secured only] 0x85 tag, 1-byte length, signature
 */

/* Session-identifier (SI) octet */
#define IEC61850_905_SI_OFFSET           0
#define IEC61850_905_SI_RGOOSE           0xA1  /* non-tunneled R-GOOSE */
#define IEC61850_905_SI_RSV              0xA2  /* non-tunneled R-SV */

/* Session-header parameter-area length (LI at octet 1) */
#define IEC61850_905_LI_OFFSET           1
#define IEC61850_905_PARAM_AREA_PLAIN    12
#define IEC61850_905_PARAM_AREA_SECURED  24

/* Common-header PI / parameter-value length (LI at octet 3) */
#define IEC61850_905_PI_COMMON_HEADER    0x80
#define IEC61850_905_COMMON_LEN_PLAIN    10
#define IEC61850_905_COMMON_LEN_SECURED  22

/* Common session-header fields */
#define IEC61850_905_SPDU_LENGTH_OFFSET  4   /* u32: SPDU Number -> end of signature */
#define IEC61850_905_SPDU_NUMBER_OFFSET  8   /* u32: duplicate/out-of-order detection */
#define IEC61850_905_VERSION_OFFSET      12  /* u16: = 1 in this profile */

/* Security extension (secured only, LI@1 == 24) */
#define IEC61850_905_TCK_OFFSET          14  /* u32: Time of Current Key (epoch s) */
#define IEC61850_905_TNK_OFFSET          18  /* u16: Time to Next Key (minutes) */
#define IEC61850_905_ALGOS_OFFSET        20  /* u16: Security Algorithms */
#define IEC61850_905_KEY_ID_OFFSET       22  /* u32: Key ID */

/* Payload-attribute base H = 14 (plain) / 26 (secured) */
#define IEC61850_905_USERINFO_BASE_PLAIN   14
#define IEC61850_905_USERINFO_BASE_SECURED 26
#define IEC61850_905_PAYLOAD_LEN_REL     0   /* u32 @ H+0 */
#define IEC61850_905_PAYLOAD_TYPE_REL    4   /* u8  @ H+4: 0x81 GOOSE / 0x82 SV */
#define IEC61850_905_SIMULATION_REL      5   /* u8  @ H+5 */
#define IEC61850_905_APPID_REL           6   /* u16 @ H+6 (network order) */
#define IEC61850_905_APDU_LEN_REL        8   /* u16 @ H+8 */

/* Flattened APPID offsets (H + 6): one compile-time constant per
 * LI branch — node_rgoose_parse / node_rsv_parse read the APPID
 * inside the branch so every packet access stays fixed-offset */
#define IEC61850_905_APPID_OFFSET_PLAIN    20  /* 14 + 6 */
#define IEC61850_905_APPID_OFFSET_SECURED  32  /* 26 + 6 */

/* Plain session-header length (SI + LI + parameter area of 12):
 * minimum SPDU bytes for SI/LI/SPDU Length/SPDU Number/Version */
#define IEC61850_905_SESSION_HDR_LEN     14

/* Minimum SPDU Length field value: must cover SPDU Number (4) +
 * Version (2).  Total SPDU size = 8 + SPDU Length. */
#define IEC61850_905_SPDU_LEN_MIN        6

/* Logical roles (not PROG_ARRAY indices — indices are dynamic) */
#define IEC61850_ROLE_DISPATCH      7  /* WP-C4: our root dispatcher */
#define IEC61850_ROLE_GOOSE_FILTER   0
#define IEC61850_ROLE_GOOSE_PARSE    1
#define IEC61850_ROLE_SV_FILTER      2
#define IEC61850_ROLE_SV_PARSE       3
#define IEC61850_ROLE_UDP_FILTER     4  /* WP-S4: 90-5 IPv4/UDP dispatch */
#define IEC61850_ROLE_RGOOSE_PARSE   5  /* WP-S4: 90-5 R-GOOSE parse */
#define IEC61850_ROLE_RSV_PARSE      6  /* WP-S4: 90-5 R-SV parse */
#define IEC61850_ROLE_COUNT          8

/* Config map: role → PROG_ARRAY index (populated by userspace) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u32);
} iec61850_node_config SEC(".maps");

/* EtherType constants */
#define ETH_P_GOOSE         0x88B8
#define ETH_P_SV            0x88BA
#define ETH_P_8021Q         0x8100

/* GOOSE PDU header (after EtherType) */
struct goose_pdu_header {
    __u16 appid;
    __u16 length;
    __u16 reserved1;
    __u16 reserved2;
} __attribute__((packed));

/* SV PDU header (after EtherType) */
struct sv_pdu_header {
    __u16 appid;
    __u16 length;
    __u16 reserved1;
    __u16 reserved2;
} __attribute__((packed));

#endif /* IEC61850_MAPS_BPF_H */
