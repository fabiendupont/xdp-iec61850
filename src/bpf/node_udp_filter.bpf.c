/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * XDP UDP Filter Node (IEC TR 61850-90-5)
 *
 * Filters routable-profile packets (R-GOOSE / R-SV) by UDP
 * destination port after IPv4 dispatch.
 *
 * Ethernet → (VLAN) → IPv4 → UDP → dport lookup in r_filter.
 * Accepted packets are redirected to AF_XDP for userspace
 * processing; unsubscribed ports are dropped at wire speed.
 *
 * The IPv4 walk is deliberately fixed-offset (IHL == 5, no IP
 * options): all packet pointer arithmetic stays static, mirroring
 * the verifier-conscious style of node_goose_filter.  Substation
 * profiles (IEC 61850-90-4) do not use IP options; frames carrying
 * them are conservatively dropped.
 *
 * Input: Packet dispatched from graph root (metadata already allocated)
 * Output: XDP_REDIRECT to AF_XDP or XDP_DROP
 */

#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>

#include "iec61850_maps.bpf.h"

char LICENSE[] SEC("license") = "BSD-2-Clause";

/* IPv4 header (fixed 20-byte form, no options).  Local clean-room
 * definition (RFC 791) avoids linux/ip.h bitfield layout concerns
 * on the BPF target. */
struct ipv4_hdr {
    __u8  ver_ihl;   /* version (4 bits) | IHL (4 bits) */
    __u8  tos;
    __u16 tot_len;   /* network byte order */
    __u16 id;        /* network byte order */
    __u16 frag_off;  /* network byte order: flags(3) | fragment offset(13) */
    __u8  ttl;
    __u8  protocol;
    __u16 check;     /* network byte order */
    __u32 saddr;     /* network byte order */
    __u32 daddr;     /* network byte order */
} __attribute__((packed));

/* UDP header (RFC 768) */
struct udp_hdr {
    __u16 source;   /* network byte order */
    __u16 dest;     /* network byte order */
    __u16 len;      /* network byte order */
    __u16 check;    /* network byte order */
} __attribute__((packed));

#define IPPROTO_UDP_BPF  17
#define IPV4_IHL_WORDS   5   /* fixed 20-byte header, no options */

XGL_NODE(node_udp_filter)
{
    struct xgl_meta *meta = XGL_META_GET(ctx);
    if (!meta)
        XGL_DROP();

    /* Look up own PROG_ARRAY index from config map */
    __u32 role = IEC61850_ROLE_UDP_FILTER;
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
    void *l3_start = (void *)(eth + 1);

    if (eth_type == ETH_P_8021Q) {
        /* Skip 4-byte VLAN tag */
        struct {
            __u16 tci;
            __u16 inner_proto;
        } __attribute__((packed)) *vlan = l3_start;

        if ((void *)(vlan + 1) > data_end) {
            XGL_STATS_INC_DROP(egl_node_stats, idx);
            XGL_DROP();
        }

        eth_type = bpf_ntohs(vlan->inner_proto);
        l3_start = (void *)(vlan + 1);
    }

    if (eth_type != ETH_P_IP) {
        XGL_STATS_INC_DROP(egl_node_stats, idx);
        XGL_DROP();
    }

    /* IPv4 header: fixed 20-byte form (see file comment) */
    struct ipv4_hdr *ip = l3_start;
    if ((void *)(ip + 1) > data_end) {
        XGL_STATS_INC_DROP(egl_node_stats, idx);
        XGL_DROP();
    }

    if ((ip->ver_ihl >> 4) != 4) {
        /* Not IPv4 */
        XGL_STATS_INC_DROP(egl_node_stats, idx);
        XGL_DROP();
    }

    if ((ip->ver_ihl & 0x0F) != IPV4_IHL_WORDS) {
        /* IP options present — conservatively dropped to keep the
         * L4 pointer offset static for the verifier */
        XGL_STATS_INC_DROP(egl_node_stats, idx);
        XGL_DROP();
    }

    /* Total length sanity: covers 20-byte IP header + 8-byte UDP
     * header, and must not exceed the bytes actually received
     * (ethernet padding may make the frame longer — that is fine) */
    __u16 tot_len = bpf_ntohs(ip->tot_len);
    if (tot_len < sizeof(*ip) + sizeof(struct udp_hdr)) {
        XGL_STATS_INC_DROP(egl_node_stats, idx);
        XGL_DROP();
    }
    __u64 l3_len = (__u64)((__u8 *)data_end - (__u8 *)ip);
    if ((__u64)tot_len > l3_len) {
        XGL_STATS_INC_DROP(egl_node_stats, idx);
        XGL_DROP();
    }

    /* No fragments: MF flag set or nonzero fragment offset */
    __u16 frag = bpf_ntohs(ip->frag_off);
    if (frag & 0x3FFF) {
        XGL_STATS_INC_DROP(egl_node_stats, idx);
        XGL_DROP();
    }

    /* UDP protocol check */
    if (ip->protocol != IPPROTO_UDP_BPF) {
        XGL_STATS_INC_DROP(egl_node_stats, idx);
        XGL_DROP();
    }

    /* UDP header: fixed offset right after the 20-byte IPv4 header */
    struct udp_hdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end) {
        XGL_STATS_INC_DROP(egl_node_stats, idx);
        XGL_DROP();
    }

    /* UDP length sanity: header itself, and consistent with the
     * IPv4 total length */
    __u16 udp_len = bpf_ntohs(udp->len);
    if (udp_len < sizeof(*udp) ||
        (__u32)udp_len + sizeof(*ip) > (__u32)tot_len) {
        XGL_STATS_INC_DROP(egl_node_stats, idx);
        XGL_DROP();
    }

    /* Lookup destination port in filter map.
     * Key is in network byte order, mirroring the APPID convention
     * of goose_filter/sv_filter. */
    __u16 dport = udp->dest;
    __u32 *action = bpf_map_lookup_elem(&r_filter, &dport);

    if (!action || *action == 0) {
        /* Not subscribed — drop */
        XGL_STATS_INC_DROP(egl_node_stats, idx);
        XGL_DROP();
    }

    /* Accepted — redirect to AF_XDP */
    __u32 queue_id = ctx->rx_queue_index;
    XGL_STATS_INC_TX(egl_node_stats, idx, pkt_len);

    return XGL_REDIRECT_XSK(xgl_xsk_map, queue_id, XDP_DROP);
}
