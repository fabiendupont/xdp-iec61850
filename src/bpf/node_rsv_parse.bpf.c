/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * XDP R-SV Parse Node (IEC TR 61850-90-5)
 *
 * Shallow parse of R-SV SPDUs (session header + 90-5 security
 * TimeOfDay) for BPF-side anti-replay checks, mirroring the
 * stNum/sqNum dedup structure of node_goose_parse.
 *
 * Ethernet → (VLAN) → IPv4 → UDP → SPDU session header.
 * The session identifier and security TimeOfDay are extracted at
 * fixed offsets (IEC61850_905_* constants in iec61850_maps.bpf.h,
 * WP-4A-RECONCILE) and checked against rsv_state_map: SPDUs
 * whose TimeOfDay is older than the last accepted value minus the
 * 90-5 replay window are dropped at XDP; in-window SPDUs slide the
 * window forward.  Parse failures fail open (redirect) — full
 * 62351-6 validation stays in userspace.
 *
 * The IPv4 walk is fixed-offset (IHL == 5, no IP options) to keep
 * all packet pointer arithmetic static for the verifier, mirroring
 * node_sv_parse's style.
 *
 * Input: Packet dispatched from node_udp_filter (already dport-filtered)
 * Output: XDP_REDIRECT to AF_XDP or XDP_DROP (replay)
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
    __u16 frag_off;  /* network byte order */
    __u8  ttl;
    __u8  protocol;
    __u16 check;
    __u32 saddr;
    __u32 daddr;
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

XGL_NODE(node_rsv_parse)
{
    struct xgl_meta *meta = XGL_META_GET(ctx);
    if (!meta)
        XGL_DROP();

    /* Look up own PROG_ARRAY index from config map */
    __u32 role = IEC61850_ROLE_RSV_PARSE;
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

    /* Skip Ethernet header */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        goto redirect;

    void *l3_start = (void *)(eth + 1);
    __u16 eth_type = bpf_ntohs(eth->h_proto);

    /* Skip VLAN if present */
    if (eth_type == ETH_P_8021Q) {
        struct {
            __u16 tci;
            __u16 inner_proto;
        } __attribute__((packed)) *vlan = l3_start;
        if ((void *)(vlan + 1) > data_end)
            goto redirect;

        eth_type = bpf_ntohs(vlan->inner_proto);
        l3_start = (void *)(vlan + 1);
    }

    if (eth_type != ETH_P_IP)
        goto redirect;

    /* IPv4 header: fixed 20-byte form (see file comment) */
    struct ipv4_hdr *ip = l3_start;
    if ((void *)(ip + 1) > data_end)
        goto redirect;

    if ((ip->ver_ihl >> 4) != 4)
        goto redirect;
    if ((ip->ver_ihl & 0x0F) != IPV4_IHL_WORDS)
        goto redirect;  /* IP options — let userspace handle */

    /* Total length sanity */
    __u16 tot_len = bpf_ntohs(ip->tot_len);
    if (tot_len < sizeof(*ip) + sizeof(struct udp_hdr))
        goto redirect;
    __u64 l3_len = (__u64)((__u8 *)data_end - (__u8 *)ip);
    if ((__u64)tot_len > l3_len)
        goto redirect;

    /* No fragments */
    __u16 frag = bpf_ntohs(ip->frag_off);
    if (frag & 0x3FFF)
        goto redirect;

    if (ip->protocol != IPPROTO_UDP_BPF)
        goto redirect;

    /* UDP header */
    struct udp_hdr *udp = (void *)(ip + 1);
    if ((void *)(udp + 1) > data_end)
        goto redirect;

    __u16 udp_len = bpf_ntohs(udp->len);
    if (udp_len < sizeof(*udp) ||
        (__u32)udp_len + sizeof(*ip) > (__u32)tot_len)
        goto redirect;

    /* UDP payload (SPDU).  64-bit pointer subtraction: (int)/(long)
     * casts make clang emit 32-bit ops on the pointers, which
     * PREVAIL rejects. */
    __u8 *spdu = (__u8 *)(udp + 1);
    __u64 payload_len = (__u64)((__u8 *)data_end - spdu);

    /* Session header must fit — all IEC61850_905_* offset accesses
     * below are inside this bounds-checked window */
    if (payload_len < IEC61850_905_SESSION_HDR_LEN)
        goto redirect;
    if ((void *)(spdu + IEC61850_905_SESSION_HDR_LEN) > data_end)
        goto redirect;

    /* SPDU length sanity (WP-4A-RECONCILE offsets) */
    __u16 spdu_len =
        ((__u16)spdu[IEC61850_905_SPDU_LEN_OFFSET] << 8) |
        spdu[IEC61850_905_SPDU_LEN_OFFSET + 1];
    if (spdu_len < IEC61850_905_SESSION_HDR_LEN ||
        (__u64)spdu_len > payload_len)
        goto redirect;

    /* Session identifier — network byte order map key, mirroring
     * the APPID convention of goose_state_map */
    __u16 session_id =
        ((__u16)spdu[IEC61850_905_SESSION_ID_OFFSET] << 8) |
        spdu[IEC61850_905_SESSION_ID_OFFSET + 1];

    /* Security TimeOfDay — 32-bit, network byte order */
    __u32 tod =
        ((__u32)spdu[IEC61850_905_TOD_OFFSET] << 24) |
        ((__u32)spdu[IEC61850_905_TOD_OFFSET + 1] << 16) |
        ((__u32)spdu[IEC61850_905_TOD_OFFSET + 2] << 8) |
        (__u32)spdu[IEC61850_905_TOD_OFFSET + 3];

    /* Anti-replay check against last accepted TimeOfDay.
     * 64-bit math on 32-bit values avoids wraparound pitfalls. */
    __u32 *last_tod = bpf_map_lookup_elem(&rsv_state_map, &session_id);
    if (last_tod) {
        __u64 tod64 = (__u64)tod;
        __u64 last64 = (__u64)*last_tod;

        if (tod64 < last64 &&
            (last64 - tod64) > IEC61850_905_REPLAY_WINDOW_TOD) {
            /* Stale / replayed — drop at XDP */
            XGL_STATS_INC_DROP(egl_node_stats, idx);
            XGL_DROP();
        }

        /* Slide the window forward only — never backward */
        if (tod64 > last64)
            *last_tod = tod;
    } else {
        __u32 init_tod = tod;
        bpf_map_update_elem(&rsv_state_map, &session_id,
                            &init_tod, BPF_ANY);
    }

redirect:
    /* Redirect to AF_XDP */
    XGL_STATS_INC_TX(egl_node_stats, idx, pkt_len);
    __u32 queue_id = ctx->rx_queue_index;
    return XGL_REDIRECT_XSK(xgl_xsk_map, queue_id, XDP_DROP);
}
