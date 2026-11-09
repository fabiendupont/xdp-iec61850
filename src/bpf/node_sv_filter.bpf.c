/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * XDP Sampled Values Filter Node
 *
 * Filters SV packets (EtherType 0x88BA) by APPID.
 * Accepted packets are redirected to AF_XDP for userspace processing.
 */

#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>

#include "iec61850_maps.bpf.h"

char LICENSE[] SEC("license") = "BSD-3-Clause";

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

    /* Check EtherType — handle VLAN-tagged frames */
    __u16 eth_type = bpf_ntohs(eth->h_proto);
    void *pdu_start = (void *)(eth + 1);

    if (eth_type == ETH_P_8021Q) {
        struct {
            __u16 tci;
            __u16 inner_proto;
        } __attribute__((packed)) *vlan = pdu_start;

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

    /* Accepted — redirect to AF_XDP */
    __u32 queue_id = ctx->rx_queue_index;
    XGL_STATS_INC_TX(egl_node_stats, idx, pkt_len);

    return XGL_REDIRECT_XSK(xgl_xsk_map, queue_id, XDP_DROP);
}
