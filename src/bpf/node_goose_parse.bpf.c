/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * XDP GOOSE Shallow BER Parse Node (Optional)
 *
 * After GOOSE filter accepts a packet, this node extracts stNum and
 * sqNum for XDP-level dedup before passing to userspace via AF_XDP.
 *
 * Uses a bounded byte-scan for tag 0x85 (stNum) followed by tag 0x86
 * (sqNum) instead of a TLV walker loop: the rolled loop keeps the
 * program small for the kernel verifier and the load pattern below
 * keeps every packet access provable for PREVAIL (WP-5c).
 *
 * Verifier discipline (WP-5c, mirroring node_rgoose_parse): every
 * load reads through a single merged pointer that was bounds-checked
 * immediately before, at constant offsets only.  Writing the checks
 * and the loads on different pointer expressions of the same address
 * lets the compiler split them across registers, and PREVAIL's
 * analysis then cannot relate the variable-offset check to the load
 * (the pre-WP-5c form — see prevail-expected-failures.txt history).
 */

#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>

#include "iec61850_maps.bpf.h"
#include "ber_shallow.bpf.h"

/* Pin a variable to a single SSA definition: without this, the
 * compiler rematerializes "base + i" into a fresh register for every
 * load in the scan loop, and PREVAIL's difference-constraint domain
 * can no longer relate the bounds check to the loads (WP-5c). */
#define IEC61850_BARRIER_VAR(var) asm volatile("" : "+r"(var))

char LICENSE[] SEC("license") = "BSD-2-Clause";

/* GOOSE APDU context-specific tags */
#define GOOSE_BPF_TAG_STNUM  0x85  /* [5] stNum */
#define GOOSE_BPF_TAG_SQNUM  0x86  /* [6] sqNum */
#define GOOSE_BPF_APDU_TAG   0x61  /* APPLICATION 1 | CONSTRUCTED */

XGL_NODE(node_goose_parse)
{
    struct xgl_meta *meta = XGL_META_GET(ctx);
    if (!meta)
        XGL_DROP();

    /* Look up own PROG_ARRAY index from config map */
    __u32 role = IEC61850_ROLE_GOOSE_PARSE;
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

    void *pdu_start = (void *)(eth + 1);
    __u16 eth_type = bpf_ntohs(eth->h_proto);

    /* Skip VLAN if present */
    if (eth_type == ETH_P_8021Q) {
        pdu_start += 4;
        if (pdu_start > data_end)
            goto redirect;
    }

    /* Skip PDU header (8 bytes: APPID + Length + Reserved) */
    struct goose_pdu_header *pdu = pdu_start;
    if ((void *)(pdu + 1) > data_end)
        goto redirect;

    __u16 appid = pdu->appid;
    __u8 *apdu_data = (__u8 *)(pdu + 1);
    /* 64-bit pointer subtraction: (int)/(long) casts make clang
     * emit 32-bit ops on the pointers, which PREVAIL rejects. */
    __u64 apdu_len = (__u64)((__u8 *)data_end - apdu_data);

    if (apdu_len <= 0 || apdu_len > 1500)
        goto redirect;

    /* Bounds check for verifier */
    if ((void *)apdu_data + apdu_len > data_end)
        goto redirect;

    /* Scan for stNum tag (0x85) in the APDU.
     * GOOSE APDU tags are in order: 0x80..0x8B. stNum is 0x85.
     * Byte-scan in a bounded window for the tag pattern:
     *   0x85 <len> <value bytes...> 0x86 <len> <value bytes...>
     * stNum/sqNum are INTEGER, typically 1-4 bytes each. */

    __u32 st_num = 0;
    __u32 sq_num = 0;
    int found = 0;

    /* Scan window: start after APDU tag+length (min 2 bytes),
     * search up to 256 bytes in (covers all mandatory fields). */
    int scan_limit = apdu_len < 256 ? apdu_len : 256;

    for (int i = 2; i < 200; i++) {
        if (i >= scan_limit)
            break;

        /* Merged scan pointer: bounds check and loads both go
         * through p, at constant offsets only (WP-5c).  The +8
         * window covers tag, length, up to 4 value bytes and the
         * head of the following sqNum TLV.  The barriers pin p to
         * one SSA value so the check and the loads stay related. */
        __u8 *p = apdu_data + i;
        IEC61850_BARRIER_VAR(p);
        if ((__u8 *)(p + 8) > (__u8 *)data_end)
            break;
        IEC61850_BARRIER_VAR(p);

        if (p[0] != GOOSE_BPF_TAG_STNUM)
            continue;

        __u8 slen = p[1];
        if (slen < 1 || slen > 4)
            continue;

        /* Extract stNum (big-endian, 1-4 bytes) through p */
        __u32 v = 0;
        if (slen >= 1) v = p[2];
        if (slen >= 2) v = (v << 8) | p[3];
        if (slen >= 3) v = (v << 8) | p[4];
        if (slen >= 4) v = (v << 8) | p[5];
        st_num = v;

        /* sqNum should follow immediately: its own merged pointer
         * with its own bounds check (constant offsets from q). */
        __u8 *q = p + 2 + slen;
        IEC61850_BARRIER_VAR(q);
        if ((__u8 *)(q + 8) > (__u8 *)data_end)
            break;
        IEC61850_BARRIER_VAR(q);

        if (q[0] == GOOSE_BPF_TAG_SQNUM) {
            __u8 qlen = q[1];
            if (qlen >= 1 && qlen <= 4) {
                __u32 w = 0;
                if (qlen >= 1) w = q[2];
                if (qlen >= 2) w = (w << 8) | q[3];
                if (qlen >= 3) w = (w << 8) | q[4];
                if (qlen >= 4) w = (w << 8) | q[5];
                sq_num = w;
            }
        }
        found = 1;
        break;
    }

    if (!found)
        goto redirect;

    /* Check state map for dedup */
    struct goose_state *state = bpf_map_lookup_elem(&goose_state_map, &appid);
    if (state) {
        if (st_num == state->st_num && sq_num <= state->sq_num) {
            /* Duplicate or older retransmission — drop at XDP */
            XGL_STATS_INC_DROP(egl_node_stats, idx);
            XGL_DROP();
        }
    }

    /* Update state map */
    struct goose_state new_state = {
        .st_num = st_num,
        .sq_num = sq_num,
    };
    bpf_map_update_elem(&goose_state_map, &appid, &new_state, BPF_ANY);

redirect:
    /* Redirect to AF_XDP */
    XGL_STATS_INC_TX(egl_node_stats, idx, pkt_len);
    __u32 queue_id = ctx->rx_queue_index;
    return XGL_REDIRECT_XSK(xgl_xsk_map, queue_id, XDP_DROP);
}
