/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * XDP Sampled Values Parse Node (Optional)
 *
 * Extracts smpCnt from SV APDU for gap detection at XDP level.
 * Uses a bounded byte-scan for the smpCnt tag (0x82) — see the
 * verifier-discipline note in node_goose_parse.bpf.c (WP-5c).
 */

#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>

#include "iec61850_maps.bpf.h"

/* Pin a variable to a single SSA definition: without this, the
 * compiler rematerializes "base + i" into a fresh register for every
 * load in the scan loop, and PREVAIL's difference-constraint domain
 * can no longer relate the bounds check to the loads (WP-5c). */
#define IEC61850_BARRIER_VAR(var) asm volatile("" : "+r"(var))

char LICENSE[] SEC("license") = "BSD-2-Clause";

/* SV APDU tags */
#define SV_BPF_APDU_TAG     0x60  /* APPLICATION 0 | CONSTRUCTED (savPdu) */
#define SV_BPF_TAG_SMPCNT   0x82  /* [2] smpCnt within ASDU */

/* Per-publisher SV state for gap detection */
struct sv_state {
    __u16 last_smp_cnt;
    __u16 smp_wrap;
    __u32 gap_count;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);
    __type(value, struct sv_state);
} sv_state_map SEC(".maps");

XGL_NODE(node_sv_parse)
{
    struct xgl_meta *meta = XGL_META_GET(ctx);
    if (!meta)
        XGL_DROP();

    /* Look up own PROG_ARRAY index from config map */
    __u32 role = IEC61850_ROLE_SV_PARSE;
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

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        goto redirect;

    void *pdu_start = (void *)(eth + 1);
    __u16 eth_type = bpf_ntohs(eth->h_proto);

    if (eth_type == ETH_P_8021Q) {
        pdu_start += 4;
        if (pdu_start > data_end)
            goto redirect;
    }

    struct sv_pdu_header *pdu = pdu_start;
    if ((void *)(pdu + 1) > data_end)
        goto redirect;

    __u16 appid = pdu->appid;
    __u8 *apdu_data = (__u8 *)(pdu + 1);
    /* 64-bit pointer subtraction: (int)/(long) casts make clang
     * emit 32-bit ops on the pointers, which PREVAIL rejects. */
    __u64 apdu_len = (__u64)((__u8 *)data_end - apdu_data);

    if (apdu_len <= 0 || apdu_len > 1500)
        goto redirect;
    if ((void *)apdu_data + apdu_len > data_end)
        goto redirect;

    /* Scan for smpCnt tag (0x82) in the SV APDU.
     * SV structure: savPdu → noASDU → seqASDU → ASDU SEQUENCE → smpCnt.
     * The smpCnt tag appears after svID [0x80] and datSet [0x81].
     * Byte-scan in a bounded window — merged scan pointer with the
     * barrier pin, constant offsets only (WP-5c, see
     * node_goose_parse.bpf.c). */

    __u16 smp_cnt = 0;
    int found = 0;

    int scan_limit = apdu_len < 128 ? apdu_len : 128;

    for (int i = 2; i < 100; i++) {
        if (i >= scan_limit)
            break;

        __u8 *p = apdu_data + i;
        IEC61850_BARRIER_VAR(p);
        if ((__u8 *)(p + 4) > (__u8 *)data_end)
            break;
        IEC61850_BARRIER_VAR(p);

        if (p[0] != SV_BPF_TAG_SMPCNT)
            continue;

        __u8 slen = p[1];
        if (slen < 1 || slen > 2)
            continue;

        if (slen == 1) {
            smp_cnt = p[2];
        } else {
            smp_cnt = ((__u16)p[2] << 8) | p[3];
        }
        found = 1;
        break;
    }

    if (!found)
        goto redirect;

    /* Gap detection with modular arithmetic */
    struct sv_state *state = bpf_map_lookup_elem(&sv_state_map, &appid);
    if (state) {
        __u16 wrap = state->smp_wrap > 0 ? state->smp_wrap : 4000;
        __u16 expected = (__u16)((state->last_smp_cnt + 1) % wrap);
        if (smp_cnt != expected) {
            state->gap_count++;
        }
        state->last_smp_cnt = smp_cnt;
    } else {
        struct sv_state new_state = {
            .last_smp_cnt = smp_cnt,
            .gap_count = 0,
        };
        bpf_map_update_elem(&sv_state_map, &appid, &new_state, BPF_ANY);
    }

redirect:
    XGL_STATS_INC_TX(egl_node_stats, idx, pkt_len);
    __u32 queue_id = ctx->rx_queue_index;
    return XGL_REDIRECT_XSK(xgl_xsk_map, queue_id, XDP_DROP);
}
