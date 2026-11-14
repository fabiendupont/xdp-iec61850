/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850 Root Dispatcher Node
 *
 * The graph root: allocates XGL metadata, parses the L2 header
 * (EtherType, one 802.1Q/802.1ad tag pair tolerated), and tail-calls
 * the filter node registered for that EtherType via the
 * iec61850_dispatch map (populated from userspace by
 * iec61850_graph_setup_dispatch). Unknown/unregistered EtherTypes
 * are dropped. Replaces the shipped xgl_dispatch as the pipeline
 * root (which self-loops when inserted at PROG_ARRAY index 0).
 *
 * WP-C4: implemented from the privileged-run diagnosis.
 */

#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>

#include "iec61850_maps.bpf.h"

char LICENSE[] SEC("license") = "BSD-2-Clause";

XGL_NODE(node_dispatch)
{
    struct xgl_meta *meta = XGL_META_ALLOC(ctx);
    if (!meta)
        XGL_DROP();

    __u32 role = IEC61850_ROLE_DISPATCH;
    __u32 *my_idx = bpf_map_lookup_elem(&iec61850_node_config, &role);
    if (!my_idx)
        XGL_DROP();
    __u32 idx = *my_idx;

    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u64 pkt_len = data_end - data;

    XGL_STATS_INC_RX(egl_node_stats, idx, pkt_len);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        XGL_STATS_INC_DROP(egl_node_stats, idx);
        XGL_DROP();
    }

    __u16 eth_type = bpf_ntohs(eth->h_proto);
    void *pdu_start = (void *)(eth + 1);

    /* One VLAN tag (802.1Q or 802.1ad outer + customer) tolerated,
     * mirroring the filter nodes' L2 walk. */
    if (eth_type == ETH_P_8021Q || eth_type == ETH_P_8021AD) {
        struct {
            __u16 tci;
            __u16 inner_proto;
        } __attribute__((packed)) *vlan = pdu_start;

        if ((void *)(vlan + 1) > data_end) {
            XGL_STATS_INC_DROP(egl_node_stats, idx);
            XGL_DROP();
        }

        __u16 inner = bpf_ntohs(vlan->inner_proto);
        if (eth_type == ETH_P_8021AD &&
            (inner == ETH_P_8021Q || inner == ETH_P_8021AD)) {
            /* QinQ: skip the customer tag too */
            void *inner_vlan = (void *)(vlan + 1);
            if ((void *)((struct { __u16 t; __u16 p; } *)inner_vlan + 1)
                    > data_end) {
                XGL_STATS_INC_DROP(egl_node_stats, idx);
                XGL_DROP();
            }
            eth_type = bpf_ntohs(
                ((struct { __u16 t; __u16 p; } *)inner_vlan)->p);
        } else {
            eth_type = inner;
        }
    }

    /* EtherType -> filter node index (populated by userspace). */
    __u16 key = eth_type;
    __u32 *next = bpf_map_lookup_elem(&iec61850_dispatch, &key);
    if (!next) {
        XGL_STATS_INC_DROP(egl_node_stats, idx);
        XGL_DROP();
    }

    meta->next_node = *next;
    XGL_NEXT_SAFE(ctx, egl_prog_array, *next, egl_node_stats, idx);

    XGL_STATS_INC_DROP(egl_node_stats, idx);
    XGL_DROP();
}
