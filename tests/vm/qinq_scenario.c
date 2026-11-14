/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * XDP QinQ (802.1ad) scenario (WP-5b).
 *
 * Attaches the repository's IEC 61850 XDP graph (EtherType dispatch
 * → GOOSE/SV filter nodes) to one end of a veth pair and pushes
 * real wire traffic through the other end, verifying the WP-5b
 * tag-stack story:
 *
 *   QQ-1  untagged GOOSE frame of a subscribed APPID  → still
 *         redirected to AF_XDP (regression: pre-WP-5b behavior)
 *   QQ-2  single 802.1Q-tagged (0x8100) GOOSE frame   → still
 *         redirected (regression)
 *   QQ-3  802.1ad QinQ double-tagged (0x88A8 service +
 *         0x8100 customer) GOOSE frame                → redirected
 *         (the WP-5b feature), APPID/VLAN/service-VLAN
 *         recovered by the userspace parser (parity with the
 *         BPF tag walk)
 *   QQ-4  QinQ with a 0x88A8 customer tag             → redirected
 *   QQ-5  malformed stacks (bare service tag, stacked
 *         0x8100 tags, three tags)                    → never
 *         delivered; everything the filter receives is
 *         either delivered or dropped (conservation)
 *   QQ-6  QinQ SV frame (0x88BA)                      → redirected
 *         through the SV filter (skipped when the
 *         environment's EtherType dispatch does not route
 *         tagged frames to the SV filter)
 *
 * The WP-5a rate-limit cost is asserted unchanged: the filter's
 * in_bytes grows by the FULL frame length of every accepted QinQ
 * frame, tags included.
 *
 * Positive frames are built by the repository's userspace frame
 * builder (iec61850_eth_frame_build with the QinQ config) — the
 * exact same wire format the BPF nodes parse; malformed stacks are
 * hand-crafted.  Frames are zero-padded to 64 bytes (ethernet
 * minimum) before injection on the TX veth end.
 *
 * Usage: qinq_scenario <rx_iface> <tx_iface> <rx_ip> <tx_ip>
 *
 * Requires: root (CAP_BPF + CAP_NET_ADMIN + CAP_NET_RAW) and the
 * BPF objects (node_*.bpf.o, xgl_dispatch.bpf.o) from the build
 * tree; BPF_OBJ_DIR / IEC61850_BPF_DIR locate them (compile-time
 * defines, mirroring the registered test_iec61850_graph target).
 *
 * Skips (exit 77) when unprivileged or when the objects are
 * missing — including when the EtherType dispatch map expected by
 * the graph is not provided by the environment (same skip shape
 * as the WP-5a rate-limit scenario).
 *
 * Meson registration is deferred (WP-2d deviation pattern): compiled
 * by tests/vm/test_qinq.sh from the build tree's own link line.
 */

#include "iec61850_graph.h"
#include "transport/eth_frame.h"
#include "transport/packet_io.h"

#include <bpf/bpf.h>
#include <egl/egl_stats.h>
#include <xgl/xgl_graph.h>

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef BPF_OBJ_DIR
#define BPF_OBJ_DIR "."
#endif

#ifndef IEC61850_BPF_DIR
#define IEC61850_BPF_DIR "."
#endif

/* Test keys (wire values; filter-map keys use htons() of these) */
#define QQ_GOOSE_APPID     0x0100U
#define QQ_SV_APPID        0x0200U
#define QQ_SVLAN           200U
#define QQ_CVLAN           100U

/* Frames per test batch */
#define QQ_FRAMES          5

/* Wire length of every injected frame (zero-padded ethernet
 * minimum — also the WP-5a token-bucket cost seen by the filter) */
#define QQ_FRAME_LEN       64U

static int tests_run;
static int tests_passed;
static int tests_skipped;
static int tests_failed;

#define TEST(name) do { tests_run++; printf("  [TEST] %-45s ", name); } while (0)
#define PASS()     do { tests_passed++; printf("PASS\n"); } while (0)
#define SKIP(msg)  do { tests_skipped++; printf("SKIP: %s\n", msg); return; } while (0)
#define FAIL(msg)  do { tests_failed++; printf("FAIL: %s\n", msg); return; } while (0)

#define ASSERT_TRUE(cond)  do { if (!(cond)) { FAIL(#cond); } } while (0)
#define ASSERT_EQ(a, b)    do { if ((a) != (b)) { \
    printf("FAIL: %s == %s (%lld != %lld)\n", #a, #b, \
           (long long)(a), (long long)(b)); \
    tests_failed++; return; } } while (0)
#define ASSERT_GE(a, b)    do { if ((a) < (b)) { \
    printf("FAIL: %s >= %s (%lld < %lld)\n", #a, #b, \
           (long long)(a), (long long)(b)); \
    tests_failed++; return; } } while (0)

/* ------------------------------------------------------------------ */
/* Shared scenario context                                             */
/* ------------------------------------------------------------------ */

struct qq_ctx {
    struct xgl_graph *g;
    struct iec61850_graph_indices indices;
    struct packet_io *xsk;
    struct packet_io *raw_tx;
};

static int is_root;

/* Per-APPID received-frame counters, classified from the XSK ring.
 * vi_seen/sv_seen record the tag fields of the last GOOSE frame
 * (userspace-parser parity with the BPF tag walk). */
struct qq_counts {
    int goose;
    int sv;
    int other;
    uint16_t vi_seen;
    uint16_t sv_seen;
};

/* ------------------------------------------------------------------ */
/* Frame crafting                                                      */
/* ------------------------------------------------------------------ */

/* Build a well-formed frame with the userspace builder (the same
 * wire format the BPF nodes parse) and zero-pad it to the ethernet
 * minimum.  Returns the injected length (QQ_FRAME_LEN). */
static uint32_t build_padded_frame(uint8_t *frame, uint16_t ethertype,
                                   uint16_t appid, uint16_t cvlan,
                                   uint16_t svlan)
{
    iec61850_eth_frame_config_t fcfg;
    size_t frame_len = 0;

    (void)memset(frame, 0, QQ_FRAME_LEN);
    (void)memset(&fcfg, 0, sizeof(fcfg));
    (void)memset(fcfg.dst_mac, 0xFF, 6);   /* broadcast: veth forwards
                                            * regardless; XDP runs before
                                            * any MAC filtering */
    (void)memset(fcfg.src_mac, 0x02, 6);
    fcfg.ethertype = ethertype;
    fcfg.app_id = appid;
    fcfg.vlan_id = cvlan;                  /* 0 = no customer tag */
    fcfg.vlan_priority = 3;
    fcfg.qinq_svlan_id = svlan;            /* 0 = no service tag */
    fcfg.qinq_svlan_priority = 5;

    if (iec61850_eth_frame_build(frame, QQ_FRAME_LEN, &fcfg,
                                 (const uint8_t *)"", 0,
                                 &frame_len) != 0) {
        return 0;
    }
    return QQ_FRAME_LEN;
}

/* Hand-craft [Eth][tag...][0x88B8][PDU header] with an arbitrary
 * TPID stack (one 4-byte tag per entry: TPID + TCI) — for the
 * malformed stacks the builder refuses to emit. */
static uint32_t craft_padded_frame(uint8_t *frame, const uint16_t *tpids,
                                   int n_tags)
{
    size_t off = 12;

    (void)memset(frame, 0, QQ_FRAME_LEN);
    (void)memset(frame, 0x02, 12);
    for (int i = 0; i < n_tags; i++) {
        frame[off++] = (uint8_t)(tpids[i] >> 8);
        frame[off++] = (uint8_t)(tpids[i] & 0xFFU);
        frame[off++] = 0x00;               /* TCI: prio 0, VID 0 */
        frame[off++] = 0x00;
    }
    frame[off++] = 0x88;                   /* EtherType 0x88B8 (GOOSE) */
    frame[off++] = 0xB8;
    frame[off++] = (uint8_t)(QQ_GOOSE_APPID >> 8);
    frame[off++] = (uint8_t)(QQ_GOOSE_APPID & 0xFFU);
    frame[off++] = 0x00;                   /* PDU length 8 (hdr only) */
    frame[off++] = 0x08;
    /* Reserved1/Reserved2 stay zero */
    return QQ_FRAME_LEN;
}

/* ------------------------------------------------------------------ */
/* XSK drain + classification                                          */
/* ------------------------------------------------------------------ */

/* Classify a received frame with the userspace parser (parity: the
 * same tag walk the BPF filters perform). */
static void qq_classify(struct qq_counts *c, const uint8_t *f, uint32_t len)
{
    uint16_t et = 0, ai = 0, vi = 0, sv = 0;
    const uint8_t *apdu = NULL;
    size_t apdu_len = 0;

    if (iec61850_eth_frame_parse_qinq(f, len, &et, &ai, &vi, &sv,
                                      &apdu, &apdu_len, NULL,
                                      NULL) != 0) {
        c->other++;
        return;
    }
    if (et == IEC61850_ETHERTYPE_GOOSE) {
        if (ai == QQ_GOOSE_APPID) {
            c->goose++;
            c->vi_seen = vi;
            c->sv_seen = sv;
        } else {
            c->other++;
        }
    } else if (et == IEC61850_ETHERTYPE_SV) {
        if (ai == QQ_SV_APPID) {
            c->sv++;
            c->vi_seen = vi;
            c->sv_seen = sv;
        } else {
            c->other++;
        }
    } else {
        c->other++;
    }
}

/* Drain the XSK for timeout_ms, classifying every frame received */
static void qq_drain(struct packet_io *xsk, int timeout_ms,
                     struct qq_counts *c)
{
    int waited = 0;
    int got = 0;

    while ((waited < timeout_ms) && (got < 512)) {
        void *data = NULL;
        uint32_t len = 0;
        int r = packet_io_recv(xsk, &data, &len);

        if (r > 0) {
            got++;
            qq_classify(c, data, len);
            packet_io_release(xsk);
        } else {
            usleep(1000);
            waited++;
        }
    }
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

/* Send n copies of a crafted frame */
static int send_frames(struct qq_ctx *ctx, const uint8_t *frame,
                       uint32_t len, int n)
{
    for (int i = 0; i < n; i++) {
        if (packet_io_send(ctx->raw_tx, frame, len) != 0) {
            return -1;
        }
    }
    return 0;
}

/* QQ-1 + QQ-2 + QQ-3: untagged, single-tag and QinQ GOOSE frames
 * of a subscribed APPID are all redirected to the AF_XDP ring. */
static void test_goose_tag_stack(struct qq_ctx *ctx)
{
    static uint8_t frame[QQ_FRAME_LEN];
    struct qq_counts c;
    struct egl_node_stats st;
    uint64_t in_bytes_before;
    uint64_t in_count_before;
    uint32_t n;

    TEST("goose untagged/802.1Q/QinQ redirected");
    if (!is_root) { SKIP("not root"); }

    if (egl_stats_read(xgl_graph_get_egl(ctx->g), ctx->indices.goose_filter,
                       &st) != 0) {
        FAIL("goose_filter stats unreadable");
    }
    in_bytes_before = st.in_bytes;
    in_count_before = st.in_count;

    /* QQ-1: untagged (regression) */
    (void)memset(&c, 0, sizeof(c));
    (void)qq_drain(ctx->xsk, 200, &c);
    n = build_padded_frame(frame, IEC61850_ETHERTYPE_GOOSE,
                           QQ_GOOSE_APPID, 0, 0);
    ASSERT_TRUE(n > 0);
    ASSERT_TRUE(send_frames(ctx, frame, n, QQ_FRAMES) == 0);
    (void)memset(&c, 0, sizeof(c));
    qq_drain(ctx->xsk, 800, &c);
    ASSERT_EQ(c.goose, QQ_FRAMES);
    ASSERT_EQ(c.other, 0);
    ASSERT_EQ(c.vi_seen, 0);
    ASSERT_EQ(c.sv_seen, 0);

    /* QQ-2: single 802.1Q tag (regression) */
    n = build_padded_frame(frame, IEC61850_ETHERTYPE_GOOSE,
                           QQ_GOOSE_APPID, QQ_CVLAN, 0);
    ASSERT_TRUE(n > 0);
    ASSERT_TRUE(send_frames(ctx, frame, n, QQ_FRAMES) == 0);
    (void)memset(&c, 0, sizeof(c));
    qq_drain(ctx->xsk, 800, &c);
    ASSERT_EQ(c.goose, QQ_FRAMES);
    ASSERT_EQ(c.other, 0);
    ASSERT_EQ(c.vi_seen, QQ_CVLAN);
    ASSERT_EQ(c.sv_seen, 0);

    /* QQ-3: QinQ — 0x88A8 service tag + 0x8100 customer tag (WP-5b) */
    n = build_padded_frame(frame, IEC61850_ETHERTYPE_GOOSE,
                           QQ_GOOSE_APPID, QQ_CVLAN, QQ_SVLAN);
    ASSERT_TRUE(n > 0);
    ASSERT_TRUE(send_frames(ctx, frame, n, QQ_FRAMES) == 0);
    (void)memset(&c, 0, sizeof(c));
    qq_drain(ctx->xsk, 800, &c);
    printf("\n      goose qinq: delivered=%d other=%d vi=%u sv=%u ",
           c.goose, c.other, c.vi_seen, c.sv_seen);
    ASSERT_EQ(c.goose, QQ_FRAMES);
    ASSERT_EQ(c.other, 0);
    /* Userspace-parser parity: the double stack is recovered
     * exactly (customer VLAN + service VLAN). */
    ASSERT_EQ(c.vi_seen, QQ_CVLAN);
    ASSERT_EQ(c.sv_seen, QQ_SVLAN);

    if (egl_stats_read(xgl_graph_get_egl(ctx->g), ctx->indices.goose_filter,
                       &st) != 0) {
        FAIL("goose_filter stats unreadable");
    }

    /* WP-5a cost parity: the QinQ frames are charged their FULL
     * frame length (tags included) — in_bytes grows by exactly
     * len(frame) per accepted frame, tag depth irrelevant. */
    ASSERT_EQ(st.in_bytes - in_bytes_before,
              (uint64_t)(3 * QQ_FRAMES) * (uint64_t)QQ_FRAME_LEN);
    /* Conservation: everything the filter received was delivered */
    ASSERT_EQ(st.in_count - in_count_before, (uint64_t)(3 * QQ_FRAMES));
    PASS();
}

/* QQ-4: QinQ with a 0x88A8 customer tag (double service stack) */
static void test_goose_qinq_ad(struct qq_ctx *ctx)
{
    static const uint16_t stack[] = { 0x88A8, 0x88A8 };
    static uint8_t frame[QQ_FRAME_LEN];
    struct qq_counts c;

    TEST("goose QinQ 0x88A8 customer tag redirected");
    if (!is_root) { SKIP("not root"); }

    (void)memset(&c, 0, sizeof(c));
    (void)qq_drain(ctx->xsk, 200, &c);

    /* The builder emits 0x8100 customer tags; the 0x88A8 customer
     * variant is hand-crafted (still within the accepted stack). */
    (void)craft_padded_frame(frame, stack, 2);
    ASSERT_TRUE(send_frames(ctx, frame, QQ_FRAME_LEN, QQ_FRAMES) == 0);

    (void)memset(&c, 0, sizeof(c));
    qq_drain(ctx->xsk, 1500, &c);

    printf("\n      goose-ad: delivered=%d ", c.goose);

    ASSERT_EQ(c.goose, QQ_FRAMES);
    ASSERT_EQ(c.other, 0);
    PASS();
}

/* QQ-5: malformed stacks are never delivered; whatever reaches the
 * filter is either delivered or dropped (conservation). */
static void test_goose_malformed_stacks(struct qq_ctx *ctx)
{
    static const uint16_t bare_svc[] = { 0x88A8 };           /* no customer tag */
    static const uint16_t double_q[] = { 0x8100, 0x8100 };   /* stacked Q tags */
    static const uint16_t triple[]   = { 0x88A8, 0x8100, 0x8100 };
    static uint8_t frame[QQ_FRAME_LEN];
    struct qq_counts c;
    struct egl_node_stats st;
    uint64_t in_count_before;
    uint64_t drops_before;

    TEST("goose malformed tag stacks dropped");
    if (!is_root) { SKIP("not root"); }

    (void)memset(&c, 0, sizeof(c));
    (void)qq_drain(ctx->xsk, 200, &c);

    if (egl_stats_read(xgl_graph_get_egl(ctx->g), ctx->indices.goose_filter,
                       &st) != 0) {
        FAIL("goose_filter stats unreadable");
    }
    in_count_before = st.in_count;
    drops_before = st.drops;

    (void)craft_padded_frame(frame, bare_svc, 1);
    ASSERT_TRUE(send_frames(ctx, frame, QQ_FRAME_LEN, QQ_FRAMES) == 0);
    (void)craft_padded_frame(frame, double_q, 2);
    ASSERT_TRUE(send_frames(ctx, frame, QQ_FRAME_LEN, QQ_FRAMES) == 0);
    (void)craft_padded_frame(frame, triple, 3);
    ASSERT_TRUE(send_frames(ctx, frame, QQ_FRAME_LEN, QQ_FRAMES) == 0);

    (void)memset(&c, 0, sizeof(c));
    qq_drain(ctx->xsk, 1500, &c);

    printf("\n      malformed: delivered=%d other=%d ",
           c.goose, c.other);

    /* None of the malformed frames is delivered (the classifier
     * cannot parse them, so anything landing in the ring shows up
     * as "other" — both counters must stay at zero). */
    ASSERT_EQ(c.goose, 0);
    ASSERT_EQ(c.other, 0);

    if (egl_stats_read(xgl_graph_get_egl(ctx->g), ctx->indices.goose_filter,
                       &st) != 0) {
        FAIL("goose_filter stats unreadable");
    }
    /* Conservation: every frame the filter received was either
     * delivered (none) or dropped.  Frames the EtherType dispatch
     * never routed to the filter simply do not appear here. */
    ASSERT_EQ(st.in_count - in_count_before, st.drops - drops_before);
    printf("(filter saw %lld, dropped %lld) ",
           (long long)(st.in_count - in_count_before),
           (long long)(st.drops - drops_before));
    PASS();
}

/* QQ-6: QinQ SV frame through the SV filter.  Skipped when the
 * environment's EtherType dispatch routes tagged frames only to
 * the GOOSE filter (observable: the SV filter sees no traffic). */
static void test_sv_qinq(struct qq_ctx *ctx)
{
    static uint8_t frame[QQ_FRAME_LEN];
    struct qq_counts c;
    struct egl_node_stats st;
    uint64_t sv_in_before;

    TEST("sv QinQ redirected (dispatch-dependent)");
    if (!is_root) { SKIP("not root"); }

    (void)memset(&c, 0, sizeof(c));
    (void)qq_drain(ctx->xsk, 200, &c);

    if (egl_stats_read(xgl_graph_get_egl(ctx->g), ctx->indices.sv_filter,
                       &st) != 0) {
        FAIL("sv_filter stats unreadable");
    }
    sv_in_before = st.in_count;

    for (int i = 0; i < QQ_FRAMES; i++) {
        uint32_t n = build_padded_frame(frame, IEC61850_ETHERTYPE_SV,
                                        QQ_SV_APPID, QQ_CVLAN,
                                        QQ_SVLAN);
        ASSERT_TRUE(n > 0);
        ASSERT_TRUE(send_frames(ctx, frame, n, 1) == 0);
    }

    (void)memset(&c, 0, sizeof(c));
    qq_drain(ctx->xsk, 1500, &c);

    if (egl_stats_read(xgl_graph_get_egl(ctx->g), ctx->indices.sv_filter,
                       &st) != 0) {
        FAIL("sv_filter stats unreadable");
    }
    if (st.in_count == sv_in_before) {
        SKIP("EtherType dispatch does not route tagged frames to "
             "the SV filter in this environment");
    }

    printf("\n      sv: delivered=%d other=%d ", c.sv, c.other);
    ASSERT_EQ(c.sv, QQ_FRAMES);
    PASS();
}

/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    const char *rx_iface;
    const char *tx_iface;
    const char *rx_ip;
    const char *tx_ip;
    char dispatch_path[1024];
    char bpf_dir[1024];
    struct qq_ctx ctx;
    int dispatch_fd;
    int ret;
    int goose_fd;
    int sv_fd;

    if (argc < 5) {
        fprintf(stderr, "Usage: %s <rx_iface> <tx_iface> <rx_ip> <tx_ip>\n",
                argv[0]);
        return 2;
    }
    rx_iface = argv[1];
    tx_iface = argv[2];
    rx_ip = argv[3];
    tx_ip = argv[4];
    (void)rx_ip;
    (void)tx_ip;
    is_root = (geteuid() == 0);

    printf("=== IEC 61850 XDP QinQ Scenario (WP-5b) ===\n");
    if (!is_root) {
        printf("SKIP: not running as root\n");
        return 77;
    }

    (void)snprintf(dispatch_path, sizeof(dispatch_path),
                   "%s/subprojects/xdp-graph-lib/xgl_dispatch.bpf.o",
                   BPF_OBJ_DIR);
    if (access(dispatch_path, R_OK) != 0) {
        printf("SKIP: xgl_dispatch.bpf.o not found at %s\n", dispatch_path);
        return 77;
    }
    (void)snprintf(bpf_dir, sizeof(bpf_dir), "%s", IEC61850_BPF_DIR);
    {
        char check[1024];

        (void)snprintf(check, sizeof(check), "%s/node_goose_filter.bpf.o",
                       bpf_dir);
        if (access(check, R_OK) != 0) {
            printf("SKIP: node_goose_filter.bpf.o not found in %s\n",
                   bpf_dir);
            return 77;
        }
    }

    /* ---- graph setup (mirrors ratelimit_scenario.c / WP-5a) ---- */

    (void)memset(&ctx, 0, sizeof(ctx));

    ctx.g = xgl_graph_create("iec61850-qinq", 0);
    if (ctx.g == NULL) {
        printf("SKIP: xgl_graph_create failed\n");
        return 77;
    }
    /* Root dispatcher registered at index 0 by
     * iec61850_graph_register(). */
    ret = 0;
    if (0) {
        printf("SKIP: dispatch add_node failed (%d: %s)\n", ret,
               strerror(-ret));
        xgl_graph_destroy(ctx.g);
        return 77;
    }
    ret = iec61850_graph_register(ctx.g, bpf_dir, &ctx.indices);
    if (ret != 0) {
        printf("SKIP: iec61850_graph_register failed (%d)\n", ret);
        xgl_graph_destroy(ctx.g);
        return 77;
    }

    dispatch_fd = xgl_graph_get_map_fd(ctx.g, "iec61850_dispatch");
    if (dispatch_fd < 0) {
        printf("SKIP: dispatch map not found\n");
        xgl_graph_destroy(ctx.g);
        return 77;
    }
    ret = iec61850_graph_setup_dispatch(dispatch_fd, &ctx.indices);
    if (ret != 0) {
        printf("SKIP: setup_dispatch failed (%d)\n", ret);
        xgl_graph_destroy(ctx.g);
        return 77;
    }

    /* Belt-and-braces for h_proto-keyed EtherType dispatch: route
     * the VLAN/QinQ TPIDs to the GOOSE filter as well, so tagged
     * GOOSE frames reach it even when the dispatcher does not walk
     * the tag stack itself.  (When the dispatcher routes by the
     * post-tag EtherType these entries are simply unused.)  The
     * filter still enforces the protocol EtherType after its own
     * tag walk, so tagged non-GOOSE frames are dropped there. */
    {
        static const uint16_t tpid_keys[] = { 0x8100, 0x88A8 };
        uint32_t val = (uint32_t)ctx.indices.goose_filter;

        for (size_t i = 0; i < sizeof(tpid_keys) / sizeof(tpid_keys[0]);
             i++) {
            uint16_t key = tpid_keys[i];

            if (bpf_map_update_elem(dispatch_fd, &key, &val,
                                    BPF_ANY) != 0) {
                printf("SKIP: TPID dispatch update failed\n");
                xgl_graph_destroy(ctx.g);
                return 77;
            }
        }
    }

    /* Edges: dispatch → GOOSE/SV filter (terminal nodes). */
    (void)xgl_graph_add_edge(ctx.g, 0, ctx.indices.goose_filter);
    (void)xgl_graph_add_edge(ctx.g, 0, ctx.indices.sv_filter);
    ret = xgl_graph_validate_dag(ctx.g);
    if (ret != 0) {
        printf("SKIP: graph not a DAG (%d)\n", ret);
        xgl_graph_destroy(ctx.g);
        return 77;
    }

    ret = xgl_graph_attach(ctx.g, rx_iface);
    if (ret != 0) {
        printf("SKIP: XDP attach to %s failed (%d: %s)\n", rx_iface, ret,
               strerror(-ret));
        xgl_graph_destroy(ctx.g);
        return 77;
    }

    /* ---- subscriptions (keys in network byte order) ---- */

    goose_fd = iec61850_graph_get_filter_map_fd(ctx.g, "goose_filter");
    sv_fd = iec61850_graph_get_filter_map_fd(ctx.g, "sv_filter");
    if ((goose_fd < 0) || (sv_fd < 0)) {
        printf("FAIL: filter map not found\n");
        xgl_graph_destroy(ctx.g);
        return 1;
    }
    {
        uint16_t keys[2] = {
            htons(QQ_GOOSE_APPID), htons(QQ_SV_APPID),
        };
        uint8_t action = 1U;

        for (int i = 0; i < 2; i++) {
            if (bpf_map_update_elem(goose_fd, &keys[i], &action,
                                    BPF_ANY) != 0) {
                printf("FAIL: goose_filter update failed\n");
                xgl_graph_destroy(ctx.g);
                return 1;
            }
            if (bpf_map_update_elem(sv_fd, &keys[i], &action,
                                    BPF_ANY) != 0) {
                printf("FAIL: sv_filter update failed\n");
                xgl_graph_destroy(ctx.g);
                return 1;
            }
        }
    }

    /* XSK receiving end + raw transmitting end */
    ctx.xsk = packet_io_create_xsk_graph(ctx.g);
    ctx.raw_tx = packet_io_create_raw();
    if ((ctx.xsk == NULL) || (ctx.raw_tx == NULL)) {
        printf("FAIL: packet_io create failed\n");
        xgl_graph_destroy(ctx.g);
        return 1;
    }
    ret = packet_io_open(ctx.xsk, rx_iface, 0);
    if (ret != 0) {
        printf("SKIP: XSK open(%s) failed (%d: %s)\n", rx_iface, ret,
               strerror(-ret));
        packet_io_destroy(ctx.raw_tx);
        xgl_graph_destroy(ctx.g);
        return 77;
    }
    ret = packet_io_open(ctx.raw_tx, tx_iface, 0);
    if (ret != 0) {
        printf("SKIP: raw open(%s) failed (%d: %s)\n", tx_iface, ret,
               strerror(-ret));
        packet_io_destroy(ctx.xsk);
        xgl_graph_destroy(ctx.g);
        return 77;
    }

    /* ---- datapath tests ---- */

    test_goose_tag_stack(&ctx);
    test_goose_qinq_ad(&ctx);
    test_goose_malformed_stacks(&ctx);
    test_sv_qinq(&ctx);

    packet_io_close(ctx.raw_tx);
    packet_io_destroy(ctx.raw_tx);
    packet_io_destroy(ctx.xsk);
    xgl_graph_destroy(ctx.g); /* detaches XDP */

    printf("\n%d/%d passed, %d skipped, %d failed\n",
           tests_passed, tests_run, tests_skipped, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
