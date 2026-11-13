/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * XDP R-GOOSE Parse Node (IEC TR 61850-90-5)
 *
 * Shallow parse of R-GOOSE SPDUs (session header + 90-5 security
 * timestamp) for BPF-side replay checks.
 *
 * WP-S4 scaffold: WP-4c (bpf-udp-nodes) implements the full node.
 */

#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>

#include "iec61850_maps.bpf.h"

char LICENSE[] SEC("license") = "BSD-2-Clause";

XGL_NODE(node_rgoose_parse)
{
    struct xgl_meta *meta = XGL_META_GET(ctx);
    if (!meta)
        XGL_DROP();

    __u32 role = IEC61850_ROLE_RGOOSE_PARSE;
    __u32 *my_idx = bpf_map_lookup_elem(&iec61850_node_config, &role);
    if (!my_idx)
        XGL_DROP();
    __u32 idx = *my_idx;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 pkt_len = data_end - data;

    XGL_STATS_INC_RX(egl_node_stats, idx, pkt_len);

    /* 90-5 session-header extraction + replay-state map is WP-4c.
     * The stub conservatively drops (unreachable until dispatch). */
    XGL_STATS_INC_DROP(egl_node_stats, idx);
    XGL_DROP();
}
