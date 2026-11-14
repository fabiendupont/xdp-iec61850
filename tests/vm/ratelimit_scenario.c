/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * XDP rate-limit scenario (WP-5a, storm protection).
 *
 * Attaches the repository's IEC 61850 XDP graph (EtherType dispatch
 * → GOOSE/SV/UDP filter nodes) to one end of a veth pair, floods
 * wire traffic through the other end and verifies the per-key
 * token-bucket rate limiting required by the WP-5a story:
 *
 *   RL-1  GOOSE: a flooded APPID with a tight per-key bucket is
 *         dropped beyond its burst (goose_filter stats + XSK
 *         silence) while a second APPID with a generous bucket
 *         passes every frame — the flood of one key never affects
 *         the other.
 *   RL-2  GOOSE: an APPID without an explicit bucket inherits the
 *         (retuned) family default via lazy bucket creation and is
 *         limited by it.
 *   RL-3  SV: same as RL-1 on the SV path (EtherType 0x88BA).
 *   RL-4  90-5 UDP: same as RL-1 on the routable profile path
 *         (IPv4/UDP dport-keyed bucket).
 *
 * GOOSE/SV frames are minimal raw ethernet frames (the filter node
 * only reads the APPID); 90-5 frames are real R-GOOSE SPDUs wrapped
 * by the repository's IP/UDP frame builder, injected on the TX veth
 * end through a raw socket — the exact wire format the BPF nodes
 * parse.
 *
 * Usage: ratelimit_scenario <rx_iface> <tx_iface> <rx_ip> <tx_ip>
 *
 * Requires: root (CAP_BPF + CAP_NET_ADMIN + CAP_NET_RAW) and the
 * BPF objects (node_*.bpf.o, xgl_dispatch.bpf.o) from the build
 * tree; BPF_OBJ_DIR / IEC61850_BPF_DIR locate them (compile-time
 * defines, mirroring the registered test_iec61850_graph target).
 *
 * Skips (exit 77) when unprivileged or when the objects are missing.
 *
 * Meson registration is deferred (WP-2d deviation pattern): compiled
 * by tests/vm/test_ratelimit.sh from the build tree's own link line.
 */

#include "asn1/r_profile.h"
#include "goose/rgoose_publisher.h"
#include "iec61850_graph.h"
#include "transport/ip_udp_frame.h"
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

/* Test keys (wire values; map keys use htons() of these) */
#define GOOSE_APPID_LIMITED   0x0100U
#define GOOSE_APPID_FREE      0x0101U
#define GOOSE_APPID_LAZY      0x0102U
#define SV_APPID_LIMITED      0x0200U
#define SV_APPID_FREE         0x0201U
#define R_DPORT_LIMITED       10301U
#define R_DPORT_FREE          10302U

/* Flood shape: 30 frames per key.  Tight buckets hold a burst of
 * exactly 4 frames, so at most ~4+slack frames of the flood pass;
 * generous buckets pass everything. */
#define RL_FLOOD_FRAMES       30
#define RL_ADMIT_MIN          1
#define RL_ADMIT_MAX          6
#define RL_FREE_MIN           28

/* GOOSE/SV test frame length (>= 64-byte minimum ethernet frame) */
#define RL_FRAME_LEN          128U

#define ETH_P_GOOSE_WIRE      0x88B8U
#define ETH_P_SV_WIRE         0x88BAU

static int tests_run;
static int tests_passed;
static int tests_skipped;
static int tests_failed;

#define TEST(name) do { tests_run++; printf("  [TEST] %-45s ", name); } while (0)
#define PASS()     do { tests_passed++; printf("PASS\n"); } while (0)
#define SKIP(msg)  do { tests_skipped++; printf("SKIP: %s\n", msg); return; } while (0)
#define FAIL(msg)  do { tests_failed++; printf("FAIL: %s\n", msg); return; } while (0)

#define ASSERT_TRUE(cond)  do { if (!(cond)) { FAIL(#cond); } } while (0)
#define ASSERT_GE(a, b)    do { if ((a) < (b)) { \
    printf("FAIL: %s >= %s (%d < %d)\n", #a, #b, (int)(a), (int)(b)); \
    tests_failed++; return; } } while (0)
#define ASSERT_LE(a, b)    do { if ((a) > (b)) { \
    printf("FAIL: %s <= %s (%d > %d)\n", #a, #b, (int)(a), (int)(b)); \
    tests_failed++; return; } } while (0)

/* ------------------------------------------------------------------ */
/* Shared scenario context                                             */
/* ------------------------------------------------------------------ */

struct rl_ctx {
    struct xgl_graph *g;
    struct iec61850_graph_indices indices;
    struct packet_io *xsk;
    struct packet_io *raw_tx;
    iec61850_rgoose_publisher_t pub;
    const char *tx_ip;
    const char *rx_ip;
};

static int is_root;

/* Per-key received-frame counters, classified from the XSK ring */
struct rl_counts {
    int goose_limited;
    int goose_free;
    int goose_lazy;
    int sv_limited;
    int sv_free;
    int r_limited;
    int r_free;
    int other;
};

/* ------------------------------------------------------------------ */
/* Frame crafting                                                      */
/* ------------------------------------------------------------------ */

/* Minimal GOOSE/SV frame: [Eth][8-byte PDU header (APPID + zeros)].
 * The filter nodes only read the APPID, so length/reserved/padding
 * stay zero.  APPID is written in wire (network) byte order. */
static void build_goose_sv_frame(uint8_t *frame, uint16_t ethertype,
                                 uint16_t wire_appid)
{
    (void)memset(frame, 0, RL_FRAME_LEN);
    /* Broadcast destination MAC: veth forwards to the peer's stack
     * regardless; the XDP program runs before any MAC filtering. */
    (void)memset(frame, 0xFF, 6);
    (void)memset(&frame[6], 0x02, 6);
    frame[12] = (uint8_t)(ethertype >> 8);
    frame[13] = (uint8_t)(ethertype & 0xFFU);
    frame[14] = (uint8_t)(wire_appid >> 8);
    frame[15] = (uint8_t)(wire_appid & 0xFFU);
}

/* Plain R-GOOSE SPDU in [Eth][IPv4][UDP] (see r_xdp_scenario.c) */
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
    (void)memset(frame, 0xFF, 6);
    (void)memset(&frame[6], 0x02, 6);
    frame[12] = 0x08U;
    frame[13] = 0x00U;
    *frame_len = 14U + IEC61850_IP_UDP_HEADER_LEN + spdu_len;
    return 0;
}

/* ------------------------------------------------------------------ */
/* XSK drain + classification                                          */
/* ------------------------------------------------------------------ */

static void rl_classify(struct rl_counts *c, const uint8_t *f, uint32_t len)
{
    uint16_t et;
    uint16_t key;

    if (len < 38U) {
        c->other++;
        return;
    }
    et = (uint16_t)(((uint16_t)f[12] << 8) | f[13]);
    if (et == ETH_P_GOOSE_WIRE) {
        key = (uint16_t)(((uint16_t)f[14] << 8) | f[15]);
        if (key == GOOSE_APPID_LIMITED) {
            c->goose_limited++;
        } else if (key == GOOSE_APPID_FREE) {
            c->goose_free++;
        } else if (key == GOOSE_APPID_LAZY) {
            c->goose_lazy++;
        } else {
            c->other++;
        }
    } else if (et == ETH_P_SV_WIRE) {
        key = (uint16_t)(((uint16_t)f[14] << 8) | f[15]);
        if (key == SV_APPID_LIMITED) {
            c->sv_limited++;
        } else if (key == SV_APPID_FREE) {
            c->sv_free++;
        } else {
            c->other++;
        }
    } else if (et == 0x0800U) {
        /* UDP dport: 14 (Eth) + 20 (IPv4) + 2 (UDP src) */
        key = (uint16_t)(((uint16_t)f[36] << 8) | f[37]);
        if (key == R_DPORT_LIMITED) {
            c->r_limited++;
        } else if (key == R_DPORT_FREE) {
            c->r_free++;
        } else {
            c->other++;
        }
    } else {
        c->other++;
    }
}

/* Drain the XSK for timeout_ms, classifying every frame received */
static void rl_drain(struct packet_io *xsk, int timeout_ms,
                     struct rl_counts *c)
{
    int waited = 0;
    int got = 0;

    while ((waited < timeout_ms) && (got < 512)) {
        void *data = NULL;
        uint32_t len = 0;
        int r = packet_io_recv(xsk, &data, &len);

        if (r > 0) {
            got++;
            rl_classify(c, data, len);
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

/* RL-1 + RL-2: GOOSE per-key limit, key isolation, lazy default */
static void test_goose_ratelimit(struct rl_ctx *ctx)
{
    static uint8_t frame[RL_FRAME_LEN];
    struct rl_counts c;
    struct egl_node_stats st;
    uint64_t drops_before;
    int i;

    TEST("goose per-appid rate limit + isolation");
    if (!is_root) { SKIP("not root"); }

    (void)memset(&c, 0, sizeof(c));
    (void)rl_drain(ctx->xsk, 200, &c); /* start from a quiet ring */

    if (egl_stats_read(xgl_graph_get_egl(ctx->g), ctx->indices.goose_filter,
                       &st) != 0) {
        FAIL("goose_filter stats unreadable");
    }
    drops_before = st.drops;

    /* Interleaved flood: limited key, free key, lazy-default key */
    for (i = 0; i < RL_FLOOD_FRAMES; i++) {
        build_goose_sv_frame(frame, ETH_P_GOOSE_WIRE, GOOSE_APPID_LIMITED);
        if (packet_io_send(ctx->raw_tx, frame, RL_FRAME_LEN) != 0) {
            FAIL("wire send failed");
        }
        build_goose_sv_frame(frame, ETH_P_GOOSE_WIRE, GOOSE_APPID_FREE);
        if (packet_io_send(ctx->raw_tx, frame, RL_FRAME_LEN) != 0) {
            FAIL("wire send failed");
        }
        build_goose_sv_frame(frame, ETH_P_GOOSE_WIRE, GOOSE_APPID_LAZY);
        if (packet_io_send(ctx->raw_tx, frame, RL_FRAME_LEN) != 0) {
            FAIL("wire send failed");
        }
    }

    (void)memset(&c, 0, sizeof(c));
    rl_drain(ctx->xsk, 1500, &c);

    printf("\n      goose: limited=%d free=%d lazy=%d other=%d ",
           c.goose_limited, c.goose_free, c.goose_lazy, c.other);

    /* Flooded key: only its burst (4 frames) gets through */
    ASSERT_GE(c.goose_limited, RL_ADMIT_MIN);
    ASSERT_LE(c.goose_limited, RL_ADMIT_MAX);
    /* Key without a bucket: limited by the retuned family default */
    ASSERT_GE(c.goose_lazy, RL_ADMIT_MIN);
    ASSERT_LE(c.goose_lazy, RL_ADMIT_MAX);
    /* Neighbor key: unaffected by the flood of the other two */
    ASSERT_GE(c.goose_free, RL_FREE_MIN);

    if (egl_stats_read(xgl_graph_get_egl(ctx->g), ctx->indices.goose_filter,
                       &st) != 0) {
        FAIL("goose_filter stats unreadable");
    }
    ASSERT_GE(st.drops, drops_before +
              (uint64_t)(2 * (RL_FLOOD_FRAMES - RL_ADMIT_MAX)));
    PASS();
}

/* RL-3: SV per-key limit + isolation */
static void test_sv_ratelimit(struct rl_ctx *ctx)
{
    static uint8_t frame[RL_FRAME_LEN];
    struct rl_counts c;
    struct egl_node_stats st;
    uint64_t drops_before;
    int i;

    TEST("sv per-appid rate limit + isolation");
    if (!is_root) { SKIP("not root"); }

    (void)memset(&c, 0, sizeof(c));
    (void)rl_drain(ctx->xsk, 200, &c);

    if (egl_stats_read(xgl_graph_get_egl(ctx->g), ctx->indices.sv_filter,
                       &st) != 0) {
        FAIL("sv_filter stats unreadable");
    }
    drops_before = st.drops;

    for (i = 0; i < RL_FLOOD_FRAMES; i++) {
        build_goose_sv_frame(frame, ETH_P_SV_WIRE, SV_APPID_LIMITED);
        if (packet_io_send(ctx->raw_tx, frame, RL_FRAME_LEN) != 0) {
            FAIL("wire send failed");
        }
        build_goose_sv_frame(frame, ETH_P_SV_WIRE, SV_APPID_FREE);
        if (packet_io_send(ctx->raw_tx, frame, RL_FRAME_LEN) != 0) {
            FAIL("wire send failed");
        }
    }

    (void)memset(&c, 0, sizeof(c));
    rl_drain(ctx->xsk, 1500, &c);

    printf("\n      sv: limited=%d free=%d other=%d ",
           c.sv_limited, c.sv_free, c.other);

    ASSERT_GE(c.sv_limited, RL_ADMIT_MIN);
    ASSERT_LE(c.sv_limited, RL_ADMIT_MAX);
    ASSERT_GE(c.sv_free, RL_FREE_MIN);

    if (egl_stats_read(xgl_graph_get_egl(ctx->g), ctx->indices.sv_filter,
                       &st) != 0) {
        FAIL("sv_filter stats unreadable");
    }
    ASSERT_GE(st.drops, drops_before +
              (uint64_t)(RL_FLOOD_FRAMES - RL_ADMIT_MAX));
    PASS();
}

/* RL-4: 90-5 UDP dport-keyed limit + isolation */
static void test_r_ratelimit(struct rl_ctx *ctx)
{
    static uint8_t frame[IEC61850_RGOOSE_MAX_FRAME_LEN];
    struct rl_counts c;
    struct egl_node_stats st;
    uint64_t drops_before;
    size_t frame_len = 0U;
    int i;

    TEST("r-goose per-dport rate limit + isolation");
    if (!is_root) { SKIP("not root"); }

    (void)memset(&c, 0, sizeof(c));
    (void)rl_drain(ctx->xsk, 200, &c);

    if (egl_stats_read(xgl_graph_get_egl(ctx->g), ctx->indices.udp_filter,
                       &st) != 0) {
        FAIL("udp_filter stats unreadable");
    }
    drops_before = st.drops;

    for (i = 0; i < RL_FLOOD_FRAMES; i++) {
        if (build_rgoose_wire_frame(&ctx->pub, ctx->tx_ip, ctx->rx_ip,
                                    (uint16_t)R_DPORT_LIMITED, frame,
                                    sizeof(frame), &frame_len) != 0) {
            FAIL("frame build failed");
        }
        if (packet_io_send(ctx->raw_tx, frame, (uint32_t)frame_len) != 0) {
            FAIL("wire send failed");
        }
        if (build_rgoose_wire_frame(&ctx->pub, ctx->tx_ip, ctx->rx_ip,
                                    (uint16_t)R_DPORT_FREE, frame,
                                    sizeof(frame), &frame_len) != 0) {
            FAIL("frame build failed");
        }
        if (packet_io_send(ctx->raw_tx, frame, (uint32_t)frame_len) != 0) {
            FAIL("wire send failed");
        }
    }

    (void)memset(&c, 0, sizeof(c));
    rl_drain(ctx->xsk, 1500, &c);

    printf("\n      r: limited=%d free=%d other=%d ",
           c.r_limited, c.r_free, c.other);

    ASSERT_GE(c.r_limited, RL_ADMIT_MIN);
    ASSERT_LE(c.r_limited, RL_ADMIT_MAX);
    ASSERT_GE(c.r_free, RL_FREE_MIN);

    if (egl_stats_read(xgl_graph_get_egl(ctx->g), ctx->indices.udp_filter,
                       &st) != 0) {
        FAIL("udp_filter stats unreadable");
    }
    ASSERT_GE(st.drops, drops_before +
              (uint64_t)(RL_FLOOD_FRAMES - RL_ADMIT_MAX));
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
    struct rl_ctx ctx;
    struct iec61850_rl_limits tight;
    struct iec61850_rl_limits generous;
    struct iec61850_rl_limits r_tight;
    int dispatch_fd;
    int ret;
    int goose_fd;
    int sv_fd;
    int r_fd;
    size_t r_frame_len = 0U;

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

    printf("=== IEC 61850 XDP Rate-Limit Scenario (WP-5a) ===\n");
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
            printf("SKIP: node_goose_filter.bpf.o not found in %s\n", bpf_dir);
            return 77;
        }
    }

    /* ---- graph setup (mirrors test_iec61850_graph.c) ---- */

    (void)memset(&ctx, 0, sizeof(ctx));
    ctx.rx_ip = rx_ip;
    ctx.tx_ip = tx_ip;

    ctx.g = xgl_graph_create("iec61850-ratelimit", 0);
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

    /* Edges: dispatch → GOOSE/SV/UDP filter (terminal nodes — no
     * parse edges: rate limiting happens inside the filters). */
    (void)xgl_graph_add_edge(ctx.g, 0, ctx.indices.goose_filter);
    (void)xgl_graph_add_edge(ctx.g, 0, ctx.indices.sv_filter);
    (void)xgl_graph_add_edge(ctx.g, 0, ctx.indices.udp_filter);
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
    r_fd = iec61850_graph_get_filter_map_fd(ctx.g, "r_filter");
    if ((goose_fd < 0) || (sv_fd < 0) || (r_fd < 0)) {
        printf("FAIL: filter map not found\n");
        xgl_graph_destroy(ctx.g);
        return 1;
    }

    {
        uint16_t keys[3] = {
            htons(GOOSE_APPID_LIMITED), htons(GOOSE_APPID_FREE),
            htons(GOOSE_APPID_LAZY),
        };
        uint8_t action = 1U;

        for (int i = 0; i < 3; i++) {
            if (bpf_map_update_elem(goose_fd, &keys[i], &action,
                                    BPF_ANY) != 0) {
                printf("FAIL: goose_filter update failed\n");
                xgl_graph_destroy(ctx.g);
                return 1;
            }
        }
    }
    {
        uint16_t keys[2] = {
            htons(SV_APPID_LIMITED), htons(SV_APPID_FREE),
        };
        uint8_t action = 1U;

        for (int i = 0; i < 2; i++) {
            if (bpf_map_update_elem(sv_fd, &keys[i], &action,
                                    BPF_ANY) != 0) {
                printf("FAIL: sv_filter update failed\n");
                xgl_graph_destroy(ctx.g);
                return 1;
            }
        }
    }
    {
        uint16_t keys[2] = {
            htons(R_DPORT_LIMITED), htons(R_DPORT_FREE),
        };
        uint32_t action = 1U;

        for (int i = 0; i < 2; i++) {
            if (bpf_map_update_elem(r_fd, &keys[i], &action,
                                    BPF_ANY) != 0) {
                printf("FAIL: r_filter update failed\n");
                xgl_graph_destroy(ctx.g);
                return 1;
            }
        }
    }

    /* ---- rate limits ---- */

    /* Tight buckets: burst = exactly 4 GOOSE/SV test frames, refill
     * ~8 frames/s — the ~10 ms flood admits only the burst.
     * Generous buckets: 1 MiB/s + 1 MiB — the flood passes whole. */
    tight.rate = 1024U;
    tight.burst = 4U * (uint64_t)RL_FRAME_LEN;
    generous.rate = 1U << 20;
    generous.burst = 1U << 20;

    /* GOOSE: per-key limit on one APPID, generous on its neighbor,
     * and a retuned family default for the bucket-less APPID. */
    if (iec61850_graph_set_rate_limit(ctx.g, IEC61850_RL_FAMILY_GOOSE,
                                      htons(GOOSE_APPID_LIMITED),
                                      &tight) != 0 ||
        iec61850_graph_set_rate_limit(ctx.g, IEC61850_RL_FAMILY_GOOSE,
                                      htons(GOOSE_APPID_FREE),
                                      &generous) != 0 ||
        iec61850_graph_set_rate_default(ctx.g, IEC61850_RL_FAMILY_GOOSE,
                                        &tight) != 0) {
        printf("FAIL: goose rate-limit config failed\n");
        xgl_graph_destroy(ctx.g);
        return 1;
    }

    /* SV: per-key limit on one APPID, generous on its neighbor */
    if (iec61850_graph_set_rate_limit(ctx.g, IEC61850_RL_FAMILY_SV,
                                      htons(SV_APPID_LIMITED),
                                      &tight) != 0 ||
        iec61850_graph_set_rate_limit(ctx.g, IEC61850_RL_FAMILY_SV,
                                      htons(SV_APPID_FREE),
                                      &generous) != 0) {
        printf("FAIL: sv rate-limit config failed\n");
        xgl_graph_destroy(ctx.g);
        return 1;
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

    /* Publisher state (plain mode; the SPDU bytes are what the BPF
     * nodes parse — security is a userspace concern). */
    {
        iec61850_rgoose_pub_config_t pcfg;

        iec61850_rgoose_pub_config_init(&pcfg);
        pcfg.appid = 0x3001U;
        (void)snprintf(pcfg.dst_ip, sizeof(pcfg.dst_ip), "%s", rx_ip);
        pcfg.dst_port = (uint16_t)R_DPORT_LIMITED;
        pcfg.src_port = (uint16_t)R_DPORT_LIMITED;
        iec61850_rgoose_publisher_init(&ctx.pub, &pcfg);
        (void)iec61850_rgoose_publisher_set_boolean(&ctx.pub, 0, true);
    }

    /* 90-5: size the tight bucket to the real R-GOOSE frame length
     * (burst = 4 frames, refill = 1 frame/s) */
    {
        static uint8_t probe[IEC61850_RGOOSE_MAX_FRAME_LEN];

        if (build_rgoose_wire_frame(&ctx.pub, ctx.tx_ip, ctx.rx_ip,
                                    (uint16_t)R_DPORT_LIMITED, probe,
                                    sizeof(probe), &r_frame_len) != 0) {
            printf("FAIL: probe frame build failed\n");
            iec61850_rgoose_publisher_destroy(&ctx.pub);
            packet_io_close(ctx.raw_tx);
            packet_io_destroy(ctx.raw_tx);
            packet_io_destroy(ctx.xsk);
            xgl_graph_destroy(ctx.g);
            return 1;
        }
    }
    r_tight.rate = (uint64_t)r_frame_len;
    r_tight.burst = 4U * (uint64_t)r_frame_len;

    if (iec61850_graph_set_rate_limit(ctx.g, IEC61850_RL_FAMILY_R,
                                      htons(R_DPORT_LIMITED),
                                      &r_tight) != 0 ||
        iec61850_graph_set_rate_limit(ctx.g, IEC61850_RL_FAMILY_R,
                                      htons(R_DPORT_FREE),
                                      &generous) != 0) {
        printf("FAIL: r rate-limit config failed\n");
        iec61850_rgoose_publisher_destroy(&ctx.pub);
        packet_io_close(ctx.raw_tx);
        packet_io_destroy(ctx.raw_tx);
        packet_io_destroy(ctx.xsk);
        xgl_graph_destroy(ctx.g);
        return 1;
    }

    /* ---- datapath tests ---- */

    test_goose_ratelimit(&ctx);
    test_sv_ratelimit(&ctx);
    test_r_ratelimit(&ctx);

    iec61850_rgoose_publisher_destroy(&ctx.pub);
    packet_io_close(ctx.raw_tx);
    packet_io_destroy(ctx.raw_tx);
    packet_io_destroy(ctx.xsk);
    xgl_graph_destroy(ctx.g); /* detaches XDP */

    printf("\n%d/%d passed, %d skipped, %d failed\n",
           tests_passed, tests_run, tests_skipped, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
