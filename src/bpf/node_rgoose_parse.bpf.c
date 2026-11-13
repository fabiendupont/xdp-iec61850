/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * XDP R-GOOSE Parse Node (IEC TR 61850-90-5)
 *
 * Shallow parse of R-GOOSE SPDUs (session header + SPDU Number) for
 * BPF-side duplicate/out-of-order detection, mirroring the
 * stNum/sqNum dedup structure of node_goose_parse.
 *
 * Ethernet → (VLAN) → IPv4 → UDP → SPDU session header.
 * The APPID and SPDU Number are extracted at fixed offsets
 * (IEC61850_905_* constants in iec61850_maps.bpf.h, reconciled with
 * WP-4a's derivation) and checked against rgoose_state_map: SPDUs
 * whose SPDU Number is <= the last accepted value for the APPID are
 * duplicates or out-of-order and dropped at XDP; strictly newer
 * numbers update the map.  A wrong SI octet (not 0xA1) is a
 * confident profile mismatch — dropped with stats.  Every other
 * parse failure fails open (redirect) — full 62351-6 validation
 * stays in userspace.
 *
 * The LI@1 branch (plain 12 / secured 24 parameter area) selects
 * between two fixed APPID offsets (20 / 32); both paths are
 * straight-line with compile-time constant offsets, keeping all
 * packet pointer arithmetic static for the verifier, mirroring
 * node_goose_parse's style.
 *
 * Input: Packet dispatched from node_udp_filter (already dport-filtered)
 * Output: XDP_REDIRECT to AF_XDP or XDP_DROP (duplicate/out-of-order,
 *         or wrong profile SI)
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

XGL_NODE(node_rgoose_parse)
{
    struct xgl_meta *meta = XGL_META_GET(ctx);
    if (!meta)
        XGL_DROP();

    /* Look up own PROG_ARRAY index from config map */
    __u32 role = IEC61850_ROLE_RGOOSE_PARSE;
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

    /* Plain session header (SI + LI + SPDU Length + SPDU Number +
     * Version) must fit — the fixed-offset accesses below stay
     * inside bounds-checked windows */
    if (payload_len < IEC61850_905_SESSION_HDR_LEN)
        goto redirect;
    if ((void *)(spdu + IEC61850_905_SESSION_HDR_LEN) > data_end)
        goto redirect;

    /* Profile gate: SI must be R-GOOSE.  A wrong SI is a confident
     * mismatch (the packet belongs to another profile) — drop with
     * stats rather than fail-open. */
    if (spdu[IEC61850_905_SI_OFFSET] != IEC61850_905_SI_RGOOSE) {
        XGL_STATS_INC_DROP(egl_node_stats, idx);
        XGL_DROP();
    }

    /* Session-header parameter-area length selects the plain vs
     * secured layout; anything else is not this profile — parse
     * failure, fail open */
    __u8 param_area = spdu[IEC61850_905_LI_OFFSET];
    if (param_area != IEC61850_905_PARAM_AREA_PLAIN &&
        param_area != IEC61850_905_PARAM_AREA_SECURED)
        goto redirect;

    /* SPDU Length sanity (WP-4A-RECONCILED): the field covers
     * SPDU Number (octet 8) through the end of the signature, so
     * the total SPDU size is 8 + SPDU Length and must fit in the
     * received payload; the minimum covers SPDU Number + Version */
    __u32 spdu_len_field =
        ((__u32)spdu[IEC61850_905_SPDU_LENGTH_OFFSET] << 24) |
        ((__u32)spdu[IEC61850_905_SPDU_LENGTH_OFFSET + 1] << 16) |
        ((__u32)spdu[IEC61850_905_SPDU_LENGTH_OFFSET + 2] << 8) |
        (__u32)spdu[IEC61850_905_SPDU_LENGTH_OFFSET + 3];
    if (spdu_len_field < IEC61850_905_SPDU_LEN_MIN)
        goto redirect;
    if (8 + (__u64)spdu_len_field > payload_len)
        goto redirect;

    /* SPDU Number — fixed offset, network byte order */
    __u32 spdu_number =
        ((__u32)spdu[IEC61850_905_SPDU_NUMBER_OFFSET] << 24) |
        ((__u32)spdu[IEC61850_905_SPDU_NUMBER_OFFSET + 1] << 16) |
        ((__u32)spdu[IEC61850_905_SPDU_NUMBER_OFFSET + 2] << 8) |
        (__u32)spdu[IEC61850_905_SPDU_NUMBER_OFFSET + 3];

    /* APPID — location selected by the LI branch (one fixed offset
     * per profile), with a single bounds check on the selected
     * pointer.  Keeping the check on the merged pointer (rather
     * than per-branch length checks, which the compiler folds away
     * and the verifier then cannot use) preserves the offset ↔
     * packet-size relation PREVAIL needs.  Network byte order map
     * key, mirroring the APPID convention of goose_state_map. */
    __u8 *appid_p;
    if (param_area == IEC61850_905_PARAM_AREA_PLAIN) {
        appid_p = spdu + IEC61850_905_APPID_OFFSET_PLAIN;
    } else {
        appid_p = spdu + IEC61850_905_APPID_OFFSET_SECURED;
    }
    if ((void *)(appid_p + 2) > data_end)
        goto redirect;

    __u16 appid = ((__u16)appid_p[0] << 8) | appid_p[1];

    /* Duplicate / out-of-order detection keyed by APPID.
     * Drop iff spdu_number <= last accepted: strictly out-of-order
     * or duplicate, mirroring node_goose_parse's sqNum comparison
     * semantics. */
    __u32 *last_num = bpf_map_lookup_elem(&rgoose_state_map, &appid);
    if (last_num) {
        if (spdu_number <= *last_num) {
            /* Duplicate or out-of-order — drop at XDP */
            XGL_STATS_INC_DROP(egl_node_stats, idx);
            XGL_DROP();
        }
        *last_num = spdu_number;
    } else {
        __u32 init_num = spdu_number;
        bpf_map_update_elem(&rgoose_state_map, &appid,
                            &init_num, BPF_ANY);
    }

redirect:
    /* Redirect to AF_XDP */
    XGL_STATS_INC_TX(egl_node_stats, idx, pkt_len);
    __u32 queue_id = ctx->rx_queue_index;
    return XGL_REDIRECT_XSK(xgl_xsk_map, queue_id, XDP_DROP);
}
