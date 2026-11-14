/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * XDP Sampled Values Filter Node
 *
 * Filters SV packets (EtherType 0x88BA) by APPID.
 * Accepted packets are redirected to AF_XDP for userspace processing.
 *
 * WP-5a: after the subscription lookup accepts a packet, a per-APPID
 * token bucket (sv_rl, limits from iec61850_rl_config) drops floods
 * beyond the configured rate/burst without affecting other APPIDs.
 *
 * WP-5b: the L2 parse accepts 802.1ad QinQ double-tagged frames
 * (service-provider outer tag + customer inner tag), in addition to
 * untagged and single 802.1Q-tagged frames.  The token-bucket cost
 * stays the full frame length regardless of tag depth.
 */

#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>

#include "iec61850_maps.bpf.h"

char LICENSE[] SEC("license") = "BSD-2-Clause";

/* VLAN / QinQ tag header (the TPID was already consumed as eth_type) */
struct vlan_tag {
    __u16 tci;
    __u16 inner_proto;
} __attribute__((packed));

XGL_NODE(node_sv_filter)
{
    struct xgl_meta *meta = XGL_META_GET(ctx);
    if (!meta)
        XGL_DROP();

    /* Look up own PROG_ARRAY index from config map */
    __u32 role = IEC61850_ROLE_SV_FILTER;
    __u32 *my_idx = bpf_map_lookup_elem(&iec61850_node_config, &role);
    if (!my_idx)
        XGL_DROP();
    __u32 idx = *my_idx;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    /* 64-bit: u32 forces 32-bit pointer arithmetic,
         * which PREVAIL rejects */
    __u64 pkt_len = data_end - data;

    XGL_STATS_INC_RX(egl_node_stats, idx, pkt_len);

    /* Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        XGL_STATS_INC_DROP(egl_node_stats, idx);
        XGL_DROP();
    }

    /* Check EtherType — handle VLAN-tagged frames.
     *
     * WP-5b accepted tag stacks (bounded to TWO stacked tags total,
     * matching realistic substation deployments):
     *   - untagged
     *   - one 802.1Q tag (0x8100)
     *   - 802.1ad QinQ (0x88A8): outer service tag followed by
     *     exactly one customer tag (0x8100 or another 0x88A8)
     * Anything else (a bare service tag, 0x8100 stacks, three or
     * more tags) falls through to the EtherType check and drops.
     *
     * The payload pointer is re-selected per branch (phi'd) and
     * bounds-checked before every read — no loops, fixed shape. */
    __u16 eth_type = bpf_ntohs(eth->h_proto);
    void *pdu_start = (void *)(eth + 1);

    if (eth_type == ETH_P_8021AD) {
        /* QinQ: outer service tag, then the customer tag */
        struct vlan_tag *outer = pdu_start;

        if ((void *)(outer + 1) > data_end) {
            XGL_STATS_INC_DROP(egl_node_stats, idx);
            XGL_DROP();
        }

        __u16 inner_tpid = bpf_ntohs(outer->inner_proto);
        if (inner_tpid != ETH_P_8021Q && inner_tpid != ETH_P_8021AD) {
            /* Not a customer tag — bare service tag or protocol
             * straight after the service tag: reject. */
            XGL_STATS_INC_DROP(egl_node_stats, idx);
            XGL_DROP();
        }

        struct vlan_tag *inner = (void *)(outer + 1);
        if ((void *)(inner + 1) > data_end) {
            XGL_STATS_INC_DROP(egl_node_stats, idx);
            XGL_DROP();
        }

        eth_type = bpf_ntohs(inner->inner_proto);
        pdu_start = (void *)(inner + 1);
    } else if (eth_type == ETH_P_8021Q) {
        /* Single 802.1Q tag */
        struct vlan_tag *vlan = pdu_start;

        if ((void *)(vlan + 1) > data_end) {
            XGL_STATS_INC_DROP(egl_node_stats, idx);
            XGL_DROP();
        }

        eth_type = bpf_ntohs(vlan->inner_proto);
        pdu_start = (void *)(vlan + 1);
    }

    if (eth_type != ETH_P_SV) {
        XGL_STATS_INC_DROP(egl_node_stats, idx);
        XGL_DROP();
    }

    /* SV PDU header */
    struct sv_pdu_header *pdu = pdu_start;
    if ((void *)(pdu + 1) > data_end) {
        XGL_STATS_INC_DROP(egl_node_stats, idx);
        XGL_DROP();
    }

    /* Lookup APPID in SV filter map */
    __u16 appid = pdu->appid;
    __u8 *action = bpf_map_lookup_elem(&sv_filter, &appid);

    if (!action || *action == 0) {
        XGL_STATS_INC_DROP(egl_node_stats, idx);
        XGL_DROP();
    }

    /* Subscribed — per-APPID token-bucket rate limit (WP-5a).
     * The packet's cost is its full frame length in bytes. */
    if (!iec61850_rl_evaluate(&sv_rl, &iec61850_rl_config,
                              IEC61850_RL_FAMILY_SV, &appid,
                              pkt_len)) {
        XGL_STATS_INC_DROP(egl_node_stats, idx);
        XGL_DROP();
    }

    /* Accepted — chain to the parse node for BPF-side dedup;
     * it redirects to AF_XDP after its checks. Falls back to a
     * direct redirect when the parse node is not configured. */
    {
        __u32 prole = IEC61850_ROLE_SV_PARSE;
        __u32 *parse_idx =
            bpf_map_lookup_elem(&iec61850_node_config, &prole);
        if (parse_idx && (*parse_idx != 0U)) {
            XGL_STATS_INC_TX(egl_node_stats, idx, pkt_len);
            XGL_NEXT_SAFE(ctx, egl_prog_array, *parse_idx,
                          egl_node_stats, idx);
        }
    }

    __u32 queue_id = ctx->rx_queue_index;
    XGL_STATS_INC_TX(egl_node_stats, idx, pkt_len);

    return XGL_REDIRECT_XSK(xgl_xsk_map, queue_id, XDP_DROP);
}
