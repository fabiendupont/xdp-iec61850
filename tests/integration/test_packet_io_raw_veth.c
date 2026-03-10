/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Integration Test: packet_io_raw on veth pair
 *
 * Self-contained test that creates a veth pair, exercises the full
 * packet_io_raw lifecycle (create → open → send → recv → release →
 * close → destroy), and runs GOOSE + SV round-trips through it.
 *
 * Requires: root (CAP_NET_ADMIN + CAP_NET_RAW).
 * Skips gracefully when not root.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "transport/packet_io.h"
#include "transport/eth_frame.h"
#include "goose/goose_publisher.h"
#include "goose/goose_subscriber.h"
#include "sv/sv_publisher.h"
#include "sv/sv_subscriber.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#define VETH0 "iec_raw0"
#define VETH1 "iec_raw1"

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

static int is_root;

static int create_veth_pair(void)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip link del %s 2>/dev/null", VETH0);
    (void)system(cmd);

    snprintf(cmd, sizeof(cmd),
             "ip link add %s type veth peer name %s 2>/dev/null",
             VETH0, VETH1);
    if (system(cmd) != 0) { return -1; }

    snprintf(cmd, sizeof(cmd), "ip link set %s up 2>/dev/null", VETH0);
    (void)system(cmd);
    snprintf(cmd, sizeof(cmd), "ip link set %s up 2>/dev/null", VETH1);
    (void)system(cmd);

    /* Suppress IPv6 noise */
    snprintf(cmd, sizeof(cmd),
             "sysctl -q -w net.ipv6.conf.%s.disable_ipv6=1 2>/dev/null", VETH0);
    (void)system(cmd);
    snprintf(cmd, sizeof(cmd),
             "sysctl -q -w net.ipv6.conf.%s.disable_ipv6=1 2>/dev/null", VETH1);
    (void)system(cmd);

    return 0;
}

static void destroy_veth_pair(void)
{
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ip link del %s 2>/dev/null", VETH0);
    (void)system(cmd);
}

/* ===== raw lifecycle tests ===== */

static void test_raw_open_send_recv_close(void)
{
    TEST("raw_open_send_recv_close");
    if (!is_root) { SKIP("not root"); }
    if (create_veth_pair() != 0) { SKIP("veth creation failed"); }

    struct packet_io *tx = packet_io_create_raw();
    struct packet_io *rx = packet_io_create_raw();
    ASSERT_TRUE(tx != NULL);
    ASSERT_TRUE(rx != NULL);

    ASSERT_EQ(packet_io_open(tx, VETH0, 0), 0);
    ASSERT_EQ(packet_io_open(rx, VETH1, 0), 0);

    /* Build a minimal Ethernet frame (broadcast dst, arbitrary src, ethertype 0x88B8 = GOOSE) */
    uint8_t frame[64];
    memset(frame, 0xff, 6);       /* dst: broadcast */
    memset(frame + 6, 0xaa, 6);   /* src: aa:aa:... */
    frame[12] = 0x88;
    frame[13] = 0xB8;             /* ethertype: GOOSE */
    memset(frame + 14, 0xDE, 50); /* payload */

    ASSERT_EQ(packet_io_send(tx, frame, 64), 0);

    /* Poll for the frame */
    void *pkt = NULL;
    uint32_t pkt_len = 0;
    int got = 0;
    for (int i = 0; i < 100 && !got; i++) {
        int ret = packet_io_recv(rx, &pkt, &pkt_len);
        if (ret > 0) {
            got = 1;
        } else {
            usleep(1000);
        }
    }

    ASSERT_TRUE(got);
    ASSERT_TRUE(pkt_len >= 64);

    packet_io_release(rx);

    /* Close and re-open should work */
    packet_io_close(tx);
    packet_io_close(rx);

    ASSERT_EQ(packet_io_open(tx, VETH0, 0), 0);
    packet_io_close(tx);

    packet_io_destroy(tx);
    packet_io_destroy(rx);
    destroy_veth_pair();
    PASS();
}

static void test_raw_double_open(void)
{
    TEST("raw_double_open");
    if (!is_root) { SKIP("not root"); }
    if (create_veth_pair() != 0) { SKIP("veth creation failed"); }

    struct packet_io *io = packet_io_create_raw();
    ASSERT_TRUE(io != NULL);

    ASSERT_EQ(packet_io_open(io, VETH0, 0), 0);
    /* Double open should fail with -EALREADY */
    ASSERT_TRUE(packet_io_open(io, VETH0, 0) < 0);

    packet_io_destroy(io);
    destroy_veth_pair();
    PASS();
}

static void test_raw_send_multiple(void)
{
    TEST("raw_send_multiple_frames");
    if (!is_root) { SKIP("not root"); }
    if (create_veth_pair() != 0) { SKIP("veth creation failed"); }

    struct packet_io *tx = packet_io_create_raw();
    struct packet_io *rx = packet_io_create_raw();
    ASSERT_TRUE(tx != NULL && rx != NULL);

    ASSERT_EQ(packet_io_open(tx, VETH0, 0), 0);
    ASSERT_EQ(packet_io_open(rx, VETH1, 0), 0);

    /* Send 5 frames */
    uint8_t frame[64];
    memset(frame, 0xff, 6);
    memset(frame + 6, 0xbb, 6);
    frame[12] = 0x08;
    frame[13] = 0x00;

    for (int i = 0; i < 5; i++) {
        frame[14] = (uint8_t)i;
        ASSERT_EQ(packet_io_send(tx, frame, 64), 0);
    }

    /* Receive them */
    int count = 0;
    for (int i = 0; i < 200 && count < 5; i++) {
        void *pkt = NULL;
        uint32_t len = 0;
        int ret = packet_io_recv(rx, &pkt, &len);
        if (ret > 0) {
            count++;
            packet_io_release(rx);
        } else {
            usleep(1000);
        }
    }

    ASSERT_TRUE(count >= 5);

    packet_io_destroy(tx);
    packet_io_destroy(rx);
    destroy_veth_pair();
    PASS();
}

/* ===== GOOSE round-trip ===== */

static int goose_rx_count;
static uint32_t goose_rx_stnum;
static char goose_rx_gocbref[128];

static void on_goose(const iec61850_goose_message_t *msg, void *ctx)
{
    (void)ctx;
    goose_rx_count++;
    goose_rx_stnum = msg->apdu.stNum;
    (void)strncpy(goose_rx_gocbref, msg->apdu.gocbRef, sizeof(goose_rx_gocbref) - 1);
}

static void test_goose_roundtrip_veth(void)
{
    TEST("goose_roundtrip_veth");
    if (!is_root) { SKIP("not root"); }
    if (create_veth_pair() != 0) { SKIP("veth creation failed"); }

    struct packet_io *tx_io = packet_io_create_raw();
    struct packet_io *rx_io = packet_io_create_raw();
    ASSERT_TRUE(tx_io != NULL && rx_io != NULL);

    ASSERT_EQ(packet_io_open(tx_io, VETH0, 0), 0);
    ASSERT_EQ(packet_io_open(rx_io, VETH1, 0), 0);

    /* Publisher */
    iec61850_goose_config_t pub_cfg;
    iec61850_goose_config_init(&pub_cfg);
    pub_cfg.app_id = 0x0001;
    (void)strncpy(pub_cfg.gocb_ref, "IED1LD0/LLN0$GO$gcb01",
                  GOOSE_MAX_GOCBREF_LEN - 1);
    (void)strncpy(pub_cfg.dataset, "IED1LD0/LLN0$DS1",
                  GOOSE_MAX_DATSET_LEN - 1);

    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, &pub_cfg);
    iec61850_goose_publisher_set_boolean(&pub, 0, true);

    /* Subscriber */
    iec61850_goose_sub_config_t sub_cfg;
    iec61850_goose_sub_config_init(&sub_cfg);
    sub_cfg.filter_appid = 0x0001;
    sub_cfg.timeout_ms = 5000;

    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, &sub_cfg);
    iec61850_goose_subscriber_set_callback(&sub, on_goose, NULL);

    /* Encode APDU, then wrap in Ethernet frame */
    uint8_t apdu_buf[1024];
    size_t apdu_len = 0;
    uint8_t frame[1518];
    size_t frame_len = 0;

    int ret = iec61850_goose_publisher_prepare(&pub, apdu_buf, sizeof(apdu_buf), &apdu_len);
    ASSERT_EQ(ret, 0);

    iec61850_eth_frame_config_t fcfg;
    memset(&fcfg, 0, sizeof(fcfg));
    memcpy(fcfg.dst_mac, pub_cfg.dst_mac, 6);
    fcfg.ethertype = IEC61850_ETHERTYPE_GOOSE;
    fcfg.app_id = pub_cfg.app_id;

    ret = iec61850_eth_frame_build(frame, sizeof(frame), &fcfg,
                                     apdu_buf, apdu_len, &frame_len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(packet_io_send(tx_io, frame, (uint32_t)frame_len), 0);

    /* Receive */
    goose_rx_count = 0;
    for (int i = 0; i < 100 && goose_rx_count == 0; i++) {
        iec61850_goose_subscriber_poll(&sub, rx_io);
        usleep(1000);
    }

    ASSERT_TRUE(goose_rx_count > 0);
    ASSERT_TRUE(strcmp(goose_rx_gocbref, "IED1LD0/LLN0$GO$gcb01") == 0);
    uint32_t first_stnum = goose_rx_stnum;

    /* Drain any queued noise packets before state change test */
    for (int d = 0; d < 50; d++) {
        void *drain_pkt = NULL;
        uint32_t drain_len = 0;
        if (packet_io_recv(rx_io, &drain_pkt, &drain_len) <= 0) { break; }
        packet_io_release(rx_io);
    }

    /* State change */
    iec61850_goose_publisher_state_change(&pub);
    iec61850_goose_publisher_set_boolean(&pub, 0, false);
    ret = iec61850_goose_publisher_prepare(&pub, apdu_buf, sizeof(apdu_buf), &apdu_len);
    ASSERT_EQ(ret, 0);
    ret = iec61850_eth_frame_build(frame, sizeof(frame), &fcfg,
                                     apdu_buf, apdu_len, &frame_len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(packet_io_send(tx_io, frame, (uint32_t)frame_len), 0);

    goose_rx_count = 0;
    goose_rx_stnum = 0;
    for (int i = 0; i < 200 && goose_rx_stnum <= first_stnum; i++) {
        iec61850_goose_subscriber_poll(&sub, rx_io);
        usleep(1000);
    }
    ASSERT_TRUE(goose_rx_stnum > first_stnum);

    iec61850_goose_publisher_destroy(&pub);
    iec61850_goose_subscriber_destroy(&sub);
    packet_io_destroy(tx_io);
    packet_io_destroy(rx_io);
    destroy_veth_pair();
    PASS();
}

/* ===== SV round-trip ===== */

static int sv_rx_count;
static uint16_t sv_rx_smpcnt;
static int sv_rx_gap;

static void on_sv(const iec61850_sv_message_t *msg, void *ctx)
{
    (void)ctx;
    sv_rx_count++;
    sv_rx_smpcnt = msg->asdu.smpCnt;
    if (msg->has_gap) { sv_rx_gap = 1; }
}

static void test_sv_roundtrip_veth(void)
{
    TEST("sv_roundtrip_veth");
    if (!is_root) { SKIP("not root"); }
    if (create_veth_pair() != 0) { SKIP("veth creation failed"); }

    struct packet_io *tx_io = packet_io_create_raw();
    struct packet_io *rx_io = packet_io_create_raw();
    ASSERT_TRUE(tx_io != NULL && rx_io != NULL);

    ASSERT_EQ(packet_io_open(tx_io, VETH0, 0), 0);
    ASSERT_EQ(packet_io_open(rx_io, VETH1, 0), 0);

    /* Publisher */
    iec61850_sv_config_t pub_cfg;
    iec61850_sv_config_init(&pub_cfg);
    pub_cfg.app_id = 0x4000;
    (void)strncpy(pub_cfg.sv_id, "IED1MU/LLN0$SV$smv01",
                  SV_MAX_SVID_LEN - 1);
    pub_cfg.smp_rate = 80;

    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, &pub_cfg);

    /* Subscriber */
    iec61850_sv_sub_config_t sub_cfg;
    iec61850_sv_sub_config_init(&sub_cfg);
    sub_cfg.filter_appid = 0x4000;
    sub_cfg.smp_rate = 80;
    sub_cfg.timeout_ms = 5000;

    iec61850_sv_subscriber_t sub;
    iec61850_sv_subscriber_init(&sub, &sub_cfg);
    iec61850_sv_subscriber_set_callback(&sub, on_sv, NULL);

    /* Send 5 sequential samples — build full Ethernet frame */
    int32_t samples[4] = {1000, 2000, -500, 750};
    uint8_t apdu_buf[1024];
    size_t apdu_len = 0;
    uint8_t frame[1518];
    size_t frame_len = 0;

    iec61850_eth_frame_config_t fcfg;
    memset(&fcfg, 0, sizeof(fcfg));
    /* SV multicast MAC: 01:0C:CD:04:xx:xx */
    fcfg.dst_mac[0] = 0x01; fcfg.dst_mac[1] = 0x0C; fcfg.dst_mac[2] = 0xCD;
    fcfg.dst_mac[3] = 0x04; fcfg.dst_mac[4] = 0x00; fcfg.dst_mac[5] = 0x01;
    fcfg.ethertype = IEC61850_ETHERTYPE_SV;
    fcfg.app_id = pub_cfg.app_id;

    sv_rx_count = 0;
    sv_rx_gap = 0;

    for (int i = 0; i < 5; i++) {
        samples[0] = 1000 + i;
        iec61850_sv_publisher_set_samples(&pub, samples, 4);
        int ret = iec61850_sv_publisher_prepare(&pub, apdu_buf, sizeof(apdu_buf), &apdu_len);
        ASSERT_EQ(ret, 0);
        ret = iec61850_eth_frame_build(frame, sizeof(frame), &fcfg,
                                         apdu_buf, apdu_len, &frame_len);
        ASSERT_EQ(ret, 0);
        ASSERT_EQ(packet_io_send(tx_io, frame, (uint32_t)frame_len), 0);
        usleep(1000);
    }

    /* Receive */
    for (int i = 0; i < 200 && sv_rx_count < 5; i++) {
        iec61850_sv_subscriber_poll(&sub, rx_io);
        usleep(1000);
    }

    ASSERT_TRUE(sv_rx_count >= 5);
    ASSERT_TRUE(sv_rx_gap == 0);

    iec61850_sv_publisher_destroy(&pub);
    iec61850_sv_subscriber_destroy(&sub);
    packet_io_destroy(tx_io);
    packet_io_destroy(rx_io);
    destroy_veth_pair();
    PASS();
}

int main(void)
{
    is_root = (geteuid() == 0);
    printf("=== Packet I/O Raw + veth Integration Tests ===\n");
    if (!is_root) {
        printf("  (not running as root — all tests will skip)\n");
    }

    test_raw_open_send_recv_close();
    test_raw_double_open();
    test_raw_send_multiple();
    test_goose_roundtrip_veth();
    test_sv_roundtrip_veth();

    printf("\n%d/%d passed, %d skipped, %d failed\n",
           tests_passed, tests_run, tests_skipped, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
