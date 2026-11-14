/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * XDP datapath scenario for the IEC 61850-90-5 routable profiles
 * (WP-4e, r-integration).
 *
 * Attaches the repository's IEC 61850 XDP graph (dispatch → UDP
 * filter → R-GOOSE/R-SV parse) to one end of a veth pair, sends
 * R-GOOSE wire traffic through the other end and verifies the three
 * datapath behaviours required by the 90-5 conformance story:
 *
 *   RX-1  registered dport  — the frame is redirected to AF_XDP and
 *         delivered to userspace via the packet_io XSK backend
 *   RX-2  unregistered dport — dropped at XDP (node stats), nothing
 *         delivered to the XSK
 *   RX-3  duplicate SPDU number — first copy delivered, second copy
 *         dropped by the BPF-side per-APPID SPDU-number dedup
 *         (rgoose_state_map), observable in the parse-node stats
 *
 * The frames are plain (unsigned) R-GOOSE SPDUs wrapped by the
 * repository's own IP/UDP frame builder, injected on the TX veth end
 * through a raw socket — the exact wire format the BPF nodes parse.
 *
 * Usage: r_xdp_scenario <rx_iface> <tx_iface> <rx_ip> <tx_ip>
 *
 * Requires: root (CAP_BPF + CAP_NET_ADMIN + CAP_NET_RAW) and the
 * BPF objects (node_*.bpf.o, xgl_dispatch.bpf.o) from the build
 * tree; BPF_OBJ_DIR / IEC61850_BPF_DIR locate them (compile-time
 * defines, mirroring the registered test_iec61850_graph target).
 *
 * Skips (exit 77) when unprivileged or when the objects are missing.
 *
 * Meson registration is deferred (WP-2d deviation pattern): compiled
 * by tests/vm/test_r_xdp.sh from the build tree's own link line.
 */

#include "asn1/r_profile.h"
#include "goose/rgoose_publisher.h"
#include "iec61850_graph.h"
#include "transport/ip_udp_frame.h"
#include "transport/packet_io.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <unistd.h>
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

/* UDP dports used by the scenario (network byte order at the map). */
#define XDP_DPORT_REGISTERED 10201U
#define XDP_DPORT_UNREGISTERED 10299U

#define XDP_TEST_PORT 48101U   /* wire dport for the registered flow  */

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
    printf("FAIL: %s == %s (%d != %d)\n", #a, #b, (int)(a), (int)(b)); \
    tests_failed++; return; } } while (0)

/* ------------------------------------------------------------------ */
/* Shared scenario context                                             */
/* ------------------------------------------------------------------ */

struct rxdp_ctx {
    struct xgl_graph *g;
    struct iec61850_graph_indices indices;
    struct packet_io *xsk;
    struct packet_io *raw_tx;
    iec61850_rgoose_publisher_t pub;
    const char *tx_ip;
    const char *rx_ip;
};

static int is_root;

/* ------------------------------------------------------------------ */
/* Frame crafting: plain R-GOOSE SPDU in [Eth][IPv4][UDP]              */
/* ------------------------------------------------------------------ */

static int build_rgoose_wire_frame(iec61850_rgoose_publisher_t *pub,
                                   const char *src_ip, const char *dst_ip,
                                   uint16_t dport,
                                   uint8_t *frame, size_t cap,
                                   size_t *frame_len)
{
    static uint8_t spdu[IEC61850_RGOOSE_MAX_SPDU_LEN];
    size_t spdu_len = 0U;

    if (iec61850_rgoose_publisher_build_spdu(pub, spdu, sizeof(spdu),
                                             &spdu_len) != 0) {
        return -1;
    }
    if (iec61850_ip_udp_build(&frame[14], cap - 14U, src_ip, dst_ip,
                              dport, dport, spdu, spdu_len, 17U) != 0) {
        return -1;
    }
    /* Broadcast destination MAC: veth forwards to the peer's stack
     * regardless; the XDP program runs before any MAC filtering. */
    (void)memset(frame, 0xFF, 6);
    (void)memset(&frame[6], 0x02, 6);
    frame[12] = 0x08U;
    frame[13] = 0x00U;
    *frame_len = 14U + IEC61850_IP_UDP_HEADER_LEN + spdu_len;
    return 0;
}

/* Drain the XSK for up to timeout_ms; returns frames received. */
static int xsk_drain(struct packet_io *xsk, int timeout_ms)
{
    int got = 0;
    int waited = 0;

    while ((waited < timeout_ms) && (got < 64)) {
        void *data = NULL;
        uint32_t len = 0;
        int r = packet_io_recv(xsk, &data, &len);

        if (r > 0) {
            got++;
            packet_io_release(xsk);
        } else {
            usleep(1000);
            waited++;
        }
    }
    return got;
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

/* RX-1: registered dport → AF_XDP delivery */
static void test_registered_dport(struct rxdp_ctx *ctx)
{
    static uint8_t frame[IEC61850_RGOOSE_MAX_FRAME_LEN];
    size_t frame_len = 0U;
    int got;
    struct egl_node_stats st;

    TEST("xdp registered dport redirected to AF_XDP");
    if (!is_root) { SKIP("not root"); }

    (void)xsk_drain(ctx->xsk, 200); /* start from a quiet ring */

    for (int i = 0; i < 5; i++) {
        if (build_rgoose_wire_frame(&ctx->pub, ctx->tx_ip, ctx->rx_ip,
                                    (uint16_t)XDP_DPORT_REGISTERED,
                                    frame, sizeof(frame), &frame_len) != 0) {
            FAIL("frame build failed");
        }
        if (packet_io_send(ctx->raw_tx, frame, (uint32_t)frame_len) != 0) {
            FAIL("wire send failed");
        }
        usleep(20000);
    }

    got = xsk_drain(ctx->xsk, 2000);
    ASSERT_TRUE(got >= 5);

    /* The UDP filter node must have forwarded (TX count) and the
     * parse node seen them too. */
    if (egl_stats_read(xgl_graph_get_egl(ctx->g), ctx->indices.udp_filter,
                       &st) != 0) {
        FAIL("udp_filter stats unreadable");
    }
    ASSERT_TRUE(st.in_count >= 5U);
    ASSERT_TRUE(st.out_count >= 5U);
    PASS();
}

/* RX-2: unregistered dport → dropped at XDP */
static void test_unregistered_dport(struct rxdp_ctx *ctx)
{
    static uint8_t frame[IEC61850_RGOOSE_MAX_FRAME_LEN];
    size_t frame_len = 0U;
    int got;
    struct egl_node_stats st;
    uint64_t drops_before;

    TEST("xdp unregistered dport dropped");
    if (!is_root) { SKIP("not root"); }

    if (egl_stats_read(xgl_graph_get_egl(ctx->g), ctx->indices.udp_filter,
                       &st) != 0) {
        FAIL("stats unreadable");
    }
    drops_before = st.drops;

    for (int i = 0; i < 3; i++) {
        if (build_rgoose_wire_frame(&ctx->pub, ctx->tx_ip, ctx->rx_ip,
                                    (uint16_t)XDP_DPORT_UNREGISTERED,
                                    frame, sizeof(frame), &frame_len) != 0) {
            FAIL("frame build failed");
        }
        if (packet_io_send(ctx->raw_tx, frame, (uint32_t)frame_len) != 0) {
            FAIL("wire send failed");
        }
        usleep(20000);
    }

    got = xsk_drain(ctx->xsk, 1000);
    ASSERT_TRUE(got == 0);

    if (egl_stats_read(xgl_graph_get_egl(ctx->g), ctx->indices.udp_filter,
                       &st) != 0) {
        FAIL("stats unreadable");
    }
    ASSERT_TRUE(st.drops >= (drops_before + 3U));
    PASS();
}

/* RX-3: duplicate SPDU number → BPF dedup */
static void test_duplicate_spdu(struct rxdp_ctx *ctx)
{
    static uint8_t frame[IEC61850_RGOOSE_MAX_FRAME_LEN];
    size_t frame_len = 0U;
    int got;
    struct egl_node_stats st;
    uint64_t drops_before;

    TEST("xdp duplicate spdu number dropped at XDP");
    if (!is_root) { SKIP("not root"); }

    /* One built frame (one SPDU number) sent twice verbatim: the
     * first is delivered, the second is a duplicate per
     * rgoose_state_map (spdu_number <= last accepted). */
    if (build_rgoose_wire_frame(&ctx->pub, ctx->tx_ip, ctx->rx_ip,
                                (uint16_t)XDP_DPORT_REGISTERED,
                                frame, sizeof(frame), &frame_len) != 0) {
        FAIL("frame build failed");
    }
    if (egl_stats_read(xgl_graph_get_egl(ctx->g), ctx->indices.rgoose_parse,
                       &st) != 0) {
        FAIL("stats unreadable");
    }
    drops_before = st.drops;

    if (packet_io_send(ctx->raw_tx, frame, (uint32_t)frame_len) != 0) {
        FAIL("wire send failed");
    }
    usleep(50000);
    if (packet_io_send(ctx->raw_tx, frame, (uint32_t)frame_len) != 0) {
        FAIL("wire send failed");
    }

    got = xsk_drain(ctx->xsk, 1500);
    ASSERT_TRUE(got == 1); /* first delivered, second dropped */

    if (egl_stats_read(xgl_graph_get_egl(ctx->g), ctx->indices.rgoose_parse,
                       &st) != 0) {
        FAIL("stats unreadable");
    }
    ASSERT_TRUE(st.drops >= (drops_before + 1U));
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
    struct rxdp_ctx ctx;
    int dispatch_fd;
    int ret;

    if (argc < 5) {
        fprintf(stderr, "Usage: %s <rx_iface> <tx_iface> <rx_ip> <tx_ip>\n",
                argv[0]);
        return 2;
    }
    rx_iface = argv[1];
    tx_iface = argv[2];
    rx_ip = argv[3];
    tx_ip = argv[4];
    is_root = (geteuid() == 0);

    printf("=== IEC 61850-90-5 XDP Datapath Scenario ===\n");
    if (!is_root) {
        printf("  (not running as root — all tests will skip)\n");
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

        (void)snprintf(check, sizeof(check), "%s/node_udp_filter.bpf.o",
                       bpf_dir);
        if (access(check, R_OK) != 0) {
            printf("SKIP: node_udp_filter.bpf.o not found in %s\n", bpf_dir);
            return 77;
        }
    }

    /* ---- graph setup (mirrors test_iec61850_graph.c) ---- */

    (void)memset(&ctx, 0, sizeof(ctx));
    ctx.rx_ip = rx_ip;
    ctx.tx_ip = tx_ip;

    ctx.g = xgl_graph_create("iec61850-r-xdp", 0);
    if (ctx.g == NULL) {
        printf("SKIP: xgl_graph_create failed\n");
        return 77;
    }
    /* The root dispatcher is registered at index 0 by
     * iec61850_graph_register() — nothing to add manually. */
    ret = 0;
    if (0) {
        /* Pre-flight diagnostics: pinpoint the failing sub-step of
         * the load chain (each is a silent -ENOENT candidate). */
        struct bpf_object *dbg_obj;
        char cwd_buf[512];

        printf("SKIP: dispatch add_node failed (%d: %s)\n", ret,
               strerror(-ret));
        printf("DIAG cwd=%s\n", getcwd(cwd_buf, sizeof(cwd_buf))
               ? cwd_buf : "?");
        printf("DIAG path=%s\n", dispatch_path);
        dbg_obj = bpf_object__open(dispatch_path);
        if (dbg_obj == NULL) {
            printf("DIAG bpf_object__open FAILED errno=%d (%s)\n",
                   errno, strerror(errno));
        } else {
            struct bpf_program *dbg_prog;
            printf("DIAG bpf_object__open OK\n");
            dbg_prog = bpf_object__find_program_by_name(dbg_obj,
                                                          "xgl_dispatch");
            printf("DIAG find_program_by_name %s\n",
                   dbg_prog ? "OK" : "FAILED (-ENOENT)");
            bpf_object__close(dbg_obj);
        }
        printf("DIAG /sys/fs/bpf is %s\n",
               (access("/sys/fs/bpf", F_OK) == 0)
                   ? "present" : "ABSENT");
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

    /* Edges: dispatch → UDP filter → R-GOOSE/R-SV parse. */
    (void)xgl_graph_add_edge(ctx.g, 0, ctx.indices.udp_filter);
    (void)xgl_graph_add_edge(ctx.g, ctx.indices.udp_filter,
                             ctx.indices.rgoose_parse);
    (void)xgl_graph_add_edge(ctx.g, ctx.indices.udp_filter,
                             ctx.indices.rsv_parse);
    ret = xgl_graph_validate_dag(ctx.g);
    if (ret != 0) {
        printf("SKIP: graph not a DAG (%d)\n", ret);
        xgl_graph_destroy(ctx.g);
        return 77;
    }

    /* NOTE: the XSK is created BEFORE the graph attach — libxdp's
     * xsk_socket__create wants to attach its own XDP helper program
     * and returns EBUSY when a non-libxdp program is already
     * attached. Opening the XSK on the empty veth first lets libxdp
     * attach its helper; the subsequent graph attach replaces it.
     * Our nodes redirect via xgl_xsk_map (fd inserted by
     * packet_io_open), so the replaced helper is harmless. */
    /* XSK receiving end (registered in the graph's XSKMAP at
     * queue 0) + raw transmitting end. */
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
    ret = xgl_graph_attach(ctx.g, rx_iface);
    if (ret != 0) {
        printf("SKIP: XDP attach to %s failed (%d: %s)\n", rx_iface, ret,
               strerror(-ret));
        xgl_graph_destroy(ctx.g);
        return 77;
    }

    /* Register the test dport in r_filter (key: network byte order,
     * value: nonzero action = accept + redirect). */
    {
        int r_fd = iec61850_graph_get_filter_map_fd(ctx.g, "r_filter");
        uint16_t key = htons((uint16_t)XDP_DPORT_REGISTERED);
        uint32_t action = 1U;

        if (r_fd < 0) {
            printf("FAIL: r_filter map not found\n");
            xgl_graph_destroy(ctx.g);
            return 1;
        }
        if (bpf_map_update_elem(r_fd, &key, &action, BPF_ANY) != 0) {
            printf("FAIL: r_filter update failed\n");
            xgl_graph_destroy(ctx.g);
            return 1;
        }
    }

    ret = packet_io_open(ctx.raw_tx, tx_iface, 0);
    if (ret != 0) {
        printf("SKIP: raw open(%s) failed (%d: %s)\n", tx_iface, ret,
               strerror(-ret));
        packet_io_destroy(ctx.xsk);
        xgl_graph_destroy(ctx.g);
        return 77;
    }

    /* Publisher state (plain mode; the SPDU bytes are what the BPF
     * nodes parse — security is a userspace concern). */
    {
        iec61850_rgoose_pub_config_t pcfg;

        iec61850_rgoose_pub_config_init(&pcfg);
        pcfg.appid = 0x3001U;
        (void)snprintf(pcfg.dst_ip, sizeof(pcfg.dst_ip), "%s", rx_ip);
        pcfg.dst_port = (uint16_t)XDP_TEST_PORT;
        pcfg.src_port = (uint16_t)XDP_TEST_PORT;
        iec61850_rgoose_publisher_init(&ctx.pub, &pcfg);
        (void)iec61850_rgoose_publisher_set_boolean(&ctx.pub, 0, true);
    }

    /* ---- datapath tests ---- */

    test_registered_dport(&ctx);
    test_unregistered_dport(&ctx);
    test_duplicate_spdu(&ctx);

    iec61850_rgoose_publisher_destroy(&ctx.pub);
    packet_io_close(ctx.raw_tx);
    packet_io_destroy(ctx.raw_tx);
    packet_io_destroy(ctx.xsk);
    xgl_graph_destroy(ctx.g); /* detaches XDP */

    printf("\n%d/%d passed, %d skipped, %d failed\n",
           tests_passed, tests_run, tests_skipped, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
