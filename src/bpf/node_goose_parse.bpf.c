/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * XDP GOOSE Shallow BER Parse Node (Optional)
 *
 * After GOOSE filter accepts a packet, this node extracts stNum and
 * sqNum for XDP-level dedup before passing to userspace via AF_XDP.
 *
 * Uses a byte-scan approach instead of a TLV walker loop to stay
 * within the BPF verifier's 1M instruction limit. Scans for tag 0x85
 * (stNum) followed by tag 0x86 (sqNum) in a bounded window.
 */

#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>

#include "iec61850_maps.bpf.h"
#include "ber_shallow.bpf.h"

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
     * Instead of a TLV walker loop (which explodes verifier state),
     * scan byte-by-byte in a bounded window for the tag pattern:
     *   0x85 <len> <value bytes...> 0x86 <len> <value bytes...>
     * stNum/sqNum are INTEGER, typically 1-4 bytes each. */

    __u32 st_num = 0;
    __u32 sq_num = 0;
    int found = 0;

    /* Scan window: start after APDU tag+length (min 2 bytes),
     * search up to 256 bytes in (covers all mandatory fields). */
    int scan_limit = apdu_len < 256 ? apdu_len : 256;

    #pragma unroll
    for (int i = 2; i < 200; i++) {
        if (i >= scan_limit)
            break;

        if ((void *)(apdu_data + i + 6) > data_end)
            break;

        if (apdu_data[i] == GOOSE_BPF_TAG_STNUM) {
            __u8 slen = apdu_data[i + 1];
            if (slen >= 1 && slen <= 4 &&
                (void *)(apdu_data + i + 2 + slen) <= data_end) {
                /* Extract stNum (big-endian, 1-4 bytes) */
                st_num = 0;
                if (slen >= 1) st_num = apdu_data[i + 2];
                if (slen >= 2) st_num = (st_num << 8) | apdu_data[i + 3];
                if (slen >= 3) st_num = (st_num << 8) | apdu_data[i + 4];
                if (slen >= 4) st_num = (st_num << 8) | apdu_data[i + 5];

                /* sqNum should follow immediately */
                int sq_off = i + 2 + slen;
                if ((void *)(apdu_data + sq_off + 6) <= data_end &&
                    apdu_data[sq_off] == GOOSE_BPF_TAG_SQNUM) {
                    __u8 qlen = apdu_data[sq_off + 1];
                    if (qlen >= 1 && qlen <= 4 &&
                        (void *)(apdu_data + sq_off + 2 + qlen) <= data_end) {
                        sq_num = 0;
                        if (qlen >= 1) sq_num = apdu_data[sq_off + 2];
                        if (qlen >= 2) sq_num = (sq_num << 8) | apdu_data[sq_off + 3];
                        if (qlen >= 3) sq_num = (sq_num << 8) | apdu_data[sq_off + 4];
                        if (qlen >= 4) sq_num = (sq_num << 8) | apdu_data[sq_off + 5];
                    }
                }
                found = 1;
                break;
            }
        }
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
