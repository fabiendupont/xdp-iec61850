/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850 XDP Graph Registration
 *
 * Registers IEC 61850 BPF nodes (GOOSE filter/parse, SV filter/parse)
 * into an xgl_graph at dynamically allocated PROG_ARRAY indices.
 */

#ifndef IEC61850_GRAPH_H
#define IEC61850_GRAPH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct xgl_graph;

/* Logical roles matching BPF-side IEC61850_ROLE_* constants */
#define IEC61850_ROLE_GOOSE_FILTER  0
#define IEC61850_ROLE_GOOSE_PARSE   1
#define IEC61850_ROLE_SV_FILTER     2
#define IEC61850_ROLE_SV_PARSE      3
#define IEC61850_ROLE_UDP_FILTER    4
#define IEC61850_ROLE_RGOOSE_PARSE  5
#define IEC61850_ROLE_RSV_PARSE     6

/**
 * Dynamically allocated PROG_ARRAY indices for IEC 61850 nodes.
 * Populated by iec61850_graph_register().
 */
struct iec61850_graph_indices {
    int goose_filter;
    int goose_parse;
    int sv_filter;
    int sv_parse;
    int udp_filter;
    int rgoose_parse;
    int rsv_parse;
};

/**
 * Register IEC 61850 BPF nodes into the graph.
 *
 * Dynamically allocates PROG_ARRAY indices via xgl_graph_alloc_index()
 * and loads BPF object files from bpf_dir. Populates the
 * iec61850_node_config map so BPF programs know their own indices.
 *
 * @param g        Graph instance
 * @param bpf_dir  Directory containing .bpf.o files
 * @param out      Output: allocated indices (may be NULL if not needed)
 * @return 0 on success, negative errno on failure
 */
int iec61850_graph_register(struct xgl_graph *g, const char *bpf_dir,
                             struct iec61850_graph_indices *out);

/**
 * Populate EtherType dispatch map entries.
 *
 * Configures the dispatch map to route:
 *   - EtherType 0x88B8 (GOOSE) → GOOSE filter node
 *   - EtherType 0x88BA (SV)    → SV filter node
 *   - EtherType 0x0800 (IPv4)  → UDP filter node (90-5 dispatch)
 *
 * @param dispatch_map_fd  BPF map fd for EtherType dispatch (BPF_MAP_TYPE_HASH)
 * @param indices          Allocated indices from iec61850_graph_register()
 * @return 0 on success, negative errno on failure
 */
int iec61850_graph_setup_dispatch(int dispatch_map_fd,
                                   const struct iec61850_graph_indices *indices);

/**
 * Return the EtherType dispatched to a filter role.
 *
 * Pure helper (no kernel interaction — safe to call unprivileged):
 *   - IEC61850_ROLE_GOOSE_FILTER → 0x88B8
 *   - IEC61850_ROLE_SV_FILTER    → 0x88BA
 *   - IEC61850_ROLE_UDP_FILTER   → 0x0800 (ETH_P_IP)
 *
 * @param role  Logical role constant
 * @return EtherType (host byte order), or -EINVAL for roles that are
 *         not dispatched by EtherType
 */
int iec61850_graph_dispatch_ethtype(int role);

/**
 * Get the BPF map fd for a named IEC 61850 filter map.
 *
 * Retrieves pinned map fd by name from the graph. Useful for
 * populating GOOSE/SV subscription filters at runtime:
 *   - "goose_filter" → APPID-based GOOSE accept/drop
 *   - "sv_filter"    → APPID-based SV accept/drop
 *   - "r_filter"     → UDP-dport-based 90-5 accept/drop
 *
 * @param g         Graph instance (must have IEC 61850 nodes loaded)
 * @param map_name  Map name (e.g. "goose_filter", "sv_filter")
 * @return map fd on success, negative errno on failure
 */
int iec61850_graph_get_filter_map_fd(struct xgl_graph *g,
                                      const char *map_name);

/* ===== WP-5a: per-key token-bucket rate limiting (storm protection) ===== */

/* Rate-limit families (indices into the iec61850_rl_config ARRAY);
 * mirror the BPF-side IEC61850_RL_FAMILY_* constants in
 * src/bpf/iec61850_maps.bpf.h */
#define IEC61850_RL_FAMILY_GOOSE  0
#define IEC61850_RL_FAMILY_SV     1
#define IEC61850_RL_FAMILY_R      2
#define IEC61850_RL_FAMILY_COUNT  3

/*
 * Default family limits seeded by iec61850_graph_register().
 *
 * COST MODEL: bytes.  A packet's cost is its full frame length; a
 * storm's impact on the network is bandwidth, and GOOSE/SV frame
 * sizes vary by an order of magnitude.
 *
 * RATIONALE: a GOOSE event storm of ~10 packets/ms at maximum frame
 * size (~1.5 KiB) consumes ~15 MiB/s sustained, and a 100 ms burst
 * of it ~1.5 MiB.  The 32 MiB/s default rate therefore admits a
 * full event storm indefinitely with >2x headroom, and the 4 MiB
 * default burst (>2500 max-size frames, >2.5x a 100 ms storm) never
 * blocks the first packets of a legitimate retransmission burst.
 * SV streams (4 kHz x ~1.5 KiB = ~6 MiB/s) fit with ~5x headroom.
 * A wire-rate flood (100 MiB/s and up per key) is contained while
 * every other key is unaffected.  Retune per deployment with
 * iec61850_graph_set_rate_default() / iec61850_graph_set_rate_limit().
 */
#define IEC61850_RL_DEFAULT_RATE_BYTES   (32ULL * 1024ULL * 1024ULL)
#define IEC61850_RL_DEFAULT_BURST_BYTES  (4ULL * 1024ULL * 1024ULL)

/*
 * Limits accepted by the setters.  The BPF refill math caps elapsed
 * time at ~4.3 s (IEC61850_RL_MAX_ELAPSED_NS); with rate <= 2^31-1
 * B/s the elapsed*rate product stays below 2^63, so the refill
 * multiply cannot overflow 64 bits.
 */
#define IEC61850_RL_MAX_RATE_BYTES   ((1ULL << 31) - 1ULL) /* ~2.1 GB/s */
#define IEC61850_RL_MAX_BURST_BYTES  (1ULL << 40)          /* 1 TiB */

/**
 * Rate-limit limits for one key or family default.
 *
 * rate  — refill limit in bytes per second; 0 disables limiting.
 * burst — bucket capacity in bytes; must be >= 1 when rate > 0.
 *         Must never block a legitimate burst (buckets start full).
 */
struct iec61850_rl_limits {
    uint64_t rate;
    uint64_t burst;
};

/**
 * Set the token-bucket limits for one key of a rate-limit family.
 *
 * Writes the bucket entry (starting full, clock anchored at the
 * first packet after the call) into the family's bucket map, so the
 * limits apply immediately to that key and override the family
 * default.  rate == 0 removes the limit for that key.
 *
 * Usage example (limit APPID 0x0004 on the wire to 1 MiB/s with a
 * 128 KiB burst, leaving every other GOOSE APPID untouched):
 *
 *     struct iec61850_rl_limits lim = {
 *         .rate = 1024 * 1024, .burst = 128 * 1024,
 *     };
 *     rc = iec61850_graph_set_rate_limit(g, IEC61850_RL_FAMILY_GOOSE,
 *                                        htons(0x0004), &lim);
 *
 * @param g       Graph instance (must have IEC 61850 nodes loaded)
 * @param family  IEC61850_RL_FAMILY_GOOSE / _SV / _R
 * @param key     APPID (GOOSE/SV) or UDP dport (R) in network byte
 *                order, matching the filter-map key convention
 * @param limits  Rate/burst limits (validated)
 * @return 0 on success, negative errno on failure
 */
int iec61850_graph_set_rate_limit(struct xgl_graph *g, int family,
                                  uint16_t key,
                                  const struct iec61850_rl_limits *limits);

/**
 * Set the default token-bucket limits for a rate-limit family.
 *
 * Applies to keys of that family that have no explicit bucket: the
 * filter nodes create their bucket lazily (starting full) on the
 * first accepted packet.  Existing per-key buckets are unchanged.
 * rate == 0 stops lazy bucket creation for the family.
 *
 * iec61850_graph_register() seeds every family with
 * IEC61850_RL_DEFAULT_RATE_BYTES / IEC61850_RL_DEFAULT_BURST_BYTES.
 *
 * @param g       Graph instance (must have IEC 61850 nodes loaded)
 * @param family  IEC61850_RL_FAMILY_GOOSE / _SV / _R
 * @param limits  Rate/burst limits (validated)
 * @return 0 on success, negative errno on failure
 */
int iec61850_graph_set_rate_default(struct xgl_graph *g, int family,
                                    const struct iec61850_rl_limits *limits);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_GRAPH_H */
