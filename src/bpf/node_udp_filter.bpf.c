/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * XDP UDP Filter Node (IEC TR 61850-90-5)
 *
 * Filters routable-profile packets (R-GOOSE / R-SV) by UDP
 * destination port after IPv4 dispatch.
 *
 * WP-S4 scaffold: WP-4c (bpf-udp-nodes) implements the full node
 * (port-map lookup, redirect/drop). Not reachable until the
 * EtherType dispatch is extended for IPv4.
 */

#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>

#include "iec61850_maps.bpf.h"

char LICENSE[] SEC("license") = "BSD-2-Clause";

XGL_NODE(node_udp_filter)
{
    struct xgl_meta *meta = XGL_META_GET(ctx);
    if (!meta)
        XGL_DROP();

    __u32 role = IEC61850_ROLE_UDP_FILTER;
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

    /* IPv4 only; full UDP header validation + port filtering is
     * WP-4c. The stub conservatively drops. */
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP) {
        XGL_STATS_INC_DROP(egl_node_stats, idx);
        XGL_DROP();
    }

    XGL_STATS_INC_DROP(egl_node_stats, idx);
    XGL_DROP();
}
