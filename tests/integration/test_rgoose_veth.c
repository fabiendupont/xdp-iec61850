/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Integration Test: IEC TR 61850-90-5 R-GOOSE over a veth pair
 *
 * WP-4e (r-integration).  Exercises the routable-profile pub/sub
 * across a real kernel network path (veth pair with IPv4 addresses),
 * not just in-process buffers:
 *
 *   self                          in-process suite over a self-created
 *                                 veth pair (both ends in the current
 *                                 network namespace):
 *     1. plain-mode pub -> sub over UDP (kernel IP/UDP stack on the
 *        veth path), N messages, state-change semantics
 *     2. duplicate + stale-SPDU-number replay injection on the wire
 *        (raw [Eth][IPv4][UDP][SPDU] frame) rejected by the
 *        subscriber's per-APPID SPDU-number tracking
 *     3. secure-mode sign -> wire -> verify round trip (raw frames)
 *     4. tamper-in-transit: the signed frame is flipped one payload
 *        bit and re-injected onto the wire -> HMAC rejection
 *     5. verbatim replay of a validly signed frame -> SPDU-number
 *        replay rejection
 *
 *   pub <dst_ip> <dst_port> <n>   plain-mode publisher: n messages to
 *                                 dst_ip:dst_port, then a verbatim
 *                                 replay of the last SPDU (the
 *                                 subscriber must drop it)
 *
 *   sub <listen_port> <n>         plain-mode subscriber: accept n
 *                                 messages + drop exactly 1 replay
 *
 *   pub-secure <iface> <src_ip> <dst_ip> <dst_port> <n> [dst_mac]
 *                                 secure-mode publisher: n signed
 *                                 [Eth][IPv4][UDP][SPDU] frames on a
 *                                 raw socket, then one tampered copy
 *                                 (payload bit flipped, signature
 *                                 stale) and one verbatim replay
 *
 *   sub-secure <iface> <n>        secure-mode subscriber: n verified
 *                                 messages + 1 security failure
 *                                 (tamper) + 1 replay drop
 *
 * The pub/sub split modes drive a publisher and subscriber in
 * separate network namespaces (see tests/vm/test_rgoose_vm_e2e.sh).
 *
 * Requires: root (CAP_NET_ADMIN for veth + CAP_NET_RAW for raw
 * sockets) for the networked tests.  `self` skips gracefully when
 * not root; pub-secure/sub-secure exit 77 when AF_PACKET is denied.
 *
 * Meson registration is deferred (WP-2d deviation pattern): this
 * scenario is compiled by tests/vm/test_rgoose_vm_e2e.sh from the
 * build tree's own link line.  See the WP-4e report.
 */

#include "asn1/r_profile.h"
#include "goose/rgoose_publisher.h"
#include "goose/rgoose_subscriber.h"
#include "transport/eth_frame.h"
#include "transport/ip_udp_frame.h"
#include "transport/packet_io.h"

#include <errno.h>
#include <net/if.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define VETH_A "iec-rgv0"
#define VETH_B "iec-rgv1"
#define IP_A   "10.212.61.1"
#define IP_B   "10.212.61.2"
#define PREFIX "10.212.61.0/30"

/* Unique high ports within the test suite (routable-profile tests). */
#define RGOOSE_VETH_PORT 48101U

#define PLAIN_COUNT   5
#define SECURE_COUNT  3

#define TEST_GOCBREF "IED1LD0/LLN0$GO$gcb01"
#define TEST_DATSET  "IED1LD0/LLN0$DS1"
#define TEST_GOID    "IED1LD0GO"

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

/* ------------------------------------------------------------------ */
/* Environment helpers                                                 */
/* ------------------------------------------------------------------ */

static int sh(const char *fmt, ...)
{
    char cmd[512];
    va_list ap;
    int ret;

    va_start(ap, fmt);
    ret = vsnprintf(cmd, sizeof(cmd), fmt, ap);
    va_end(ap);
    if (ret < 0) {
        return -1;
    }
    return system(cmd);
}

static int create_veth_pair(void)
{
    (void)sh("ip link del %s 2>/dev/null", VETH_A);
    if (sh("ip link add %s type veth peer name %s", VETH_A, VETH_B) != 0) {
        return -1;
    }
    (void)sh("ip link set %s up", VETH_A);
    (void)sh("ip link set %s up", VETH_B);
    (void)sh("ip addr add %s/30 dev %s", IP_A, VETH_A);
    (void)sh("ip addr add %s/30 dev %s", IP_B, VETH_B);
    (void)sh("sysctl -q -w net.ipv6.conf.%s.disable_ipv6=1 2>/dev/null", VETH_A);
    (void)sh("sysctl -q -w net.ipv6.conf.%s.disable_ipv6=1 2>/dev/null", VETH_B);
    /* The raw wire-replay injection carries VETH_A's own address as
     * its IP source; without accept_local the receiving stack treats
     * it as a martian (local source on a non-loopback interface) and
     * silently drops it before UDP delivery.  A real two-node network
     * would not have 10.212.61.1 local to the receiver. */
    (void)sh("sysctl -q -w net.ipv4.conf.%s.accept_local=1 2>/dev/null", VETH_B);
    return 0;
}

static void destroy_veth_pair(void)
{
    (void)sh("ip link del %s 2>/dev/null", VETH_A);
}

/* Read an interface MAC via SIOCGIFHWADDR (netns-correct: sysfs
 * may still refer to the mount-time network namespace). */
static int read_mac(const char *iface, uint8_t *out)
{
    struct ifreq ifr;
    int fd;
    int r;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -1;
    }
    (void)memset(&ifr, 0, sizeof(ifr));
    (void)snprintf(ifr.ifr_name, IF_NAMESIZE, "%s", iface);
    r = ioctl(fd, SIOCGIFHWADDR, &ifr);
    (void)close(fd);
    if (r != 0) {
        return -1;
    }
    if ((unsigned char)ifr.ifr_hwaddr.sa_family != 1U) { /* ARPHRD_ETHER */
        return -1;
    }
    (void)memcpy(out, ifr.ifr_hwaddr.sa_data, 6);
    return 0;
}

static int parse_mac(const char *str, uint8_t *out)
{
    unsigned int m[6];

    if (sscanf(str, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4],
               &m[5]) != 6) {
        return -1;
    }
    for (int i = 0; i < 6; i++) {
        out[i] = (uint8_t)m[i];
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Shared publisher/subscriber setup                                   */
/* ------------------------------------------------------------------ */

static void fill_pub_config(iec61850_rgoose_pub_config_t *cfg,
                            const char *dst_ip, uint16_t port)
{
    iec61850_rgoose_pub_config_init(cfg);
    (void)snprintf(cfg->gocb_ref, sizeof(cfg->gocb_ref), "%s", TEST_GOCBREF);
    (void)snprintf(cfg->dataset, sizeof(cfg->dataset), "%s", TEST_DATSET);
    (void)snprintf(cfg->goose_id, sizeof(cfg->goose_id), "%s", TEST_GOID);
    cfg->appid = 0x1001U;
    (void)snprintf(cfg->dst_ip, sizeof(cfg->dst_ip), "%s", dst_ip);
    cfg->dst_port = port;
    cfg->src_port = port;
}

static int rgoose_rx_count;
static uint32_t rgoose_rx_stnum;
static uint32_t rgoose_rx_sqnum;
static uint16_t rgoose_rx_appid;
static int rgoose_rx_secure;

static void on_rgoose(const iec61850_rgoose_message_t *msg, void *ctx)
{
    (void)ctx;
    rgoose_rx_count++;
    rgoose_rx_stnum = msg->apdu.stNum;
    rgoose_rx_sqnum = msg->apdu.sqNum;
    rgoose_rx_appid = msg->header.appid;
    rgoose_rx_secure = msg->header.security.present ? 1 : 0;
}

#ifdef IEC61850_SECURITY_ENABLED

static const uint8_t sec_key[16] = {
    0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U,
    0x99U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU, 0x00U
};
#define SEC_KEY_ID 0xCAFEBABEU

static void make_pub_sec(iec61850_rgoose_pub_security_t *s)
{
    (void)memset(s, 0, sizeof(*s));
    s->algo = (uint16_t)IEC61850_RGOOSE_PUB_SEC_ALGO_HMAC_SHA256;
    (void)memcpy(s->key, sec_key, sizeof(sec_key));
    s->key_len = sizeof(sec_key);
    s->key_id = SEC_KEY_ID;
    s->time_to_next_key = 720U;
}

static void make_sub_sec(iec61850_rgoose_sub_security_t *s)
{
    (void)memset(s, 0, sizeof(*s));
    s->algo = (uint16_t)IEC61850_RGOOSE_SUB_SEC_ALGO_HMAC_SHA256;
    (void)memcpy(s->key, sec_key, sizeof(sec_key));
    s->key_len = sizeof(sec_key);
    s->expected_key_id = SEC_KEY_ID;
}

#endif /* IEC61850_SECURITY_ENABLED */

/* ------------------------------------------------------------------ */
/* self mode: in-process suite over a veth pair                        */
/* ------------------------------------------------------------------ */

static void test_plain_udp_roundtrip(void)
{
    iec61850_rgoose_pub_config_t pcfg;
    iec61850_rgoose_sub_config_t scfg;
    iec61850_rgoose_publisher_t pub;
    iec61850_rgoose_subscriber_t sub;
    struct packet_io *tx;
    struct packet_io *rx;

    TEST("rgoose_plain_udp_veth_roundtrip");
    if (!is_root) { SKIP("not root"); }
    if (create_veth_pair() != 0) { SKIP("veth creation failed"); }

    fill_pub_config(&pcfg, IP_B, (uint16_t)RGOOSE_VETH_PORT);
    iec61850_rgoose_publisher_init(&pub, &pcfg);
    ASSERT_EQ(iec61850_rgoose_publisher_set_boolean(&pub, 0, true), 0);
    ASSERT_EQ(iec61850_rgoose_publisher_set_int32(&pub, 1, 1234), 0);

    iec61850_rgoose_sub_config_init(&scfg);
    scfg.filter_appid = 0x1001U;
    scfg.timeout_ms = 30000U;
    iec61850_rgoose_subscriber_init(&sub, &scfg);
    iec61850_rgoose_subscriber_set_callback(&sub, on_rgoose, NULL);
    rgoose_rx_count = 0;

    tx = packet_io_create_udp_sender(IP_B, (uint16_t)RGOOSE_VETH_PORT, false);
    rx = packet_io_create_udp_receiver((uint16_t)RGOOSE_VETH_PORT, NULL);
    ASSERT_TRUE(tx != NULL && rx != NULL);
    ASSERT_EQ(packet_io_open(rx, NULL, 0), 0);
    ASSERT_EQ(packet_io_open(tx, NULL, 0), 0);
    iec61850_rgoose_publisher_set_io(&pub, tx);

    /* Publish PLAIN_COUNT messages: every one must traverse the veth
     * IP/UDP path and reach the subscriber. */
    for (int i = 0; i < PLAIN_COUNT; i++) {
        ASSERT_EQ(iec61850_rgoose_publisher_publish(&pub), 0);
    }
    {
        int waited = 0;
        while ((rgoose_rx_count < PLAIN_COUNT) && (waited < 5000)) {
            (void)iec61850_rgoose_subscriber_poll(&sub, rx);
            usleep(1000);
            waited++;
        }
    }
    ASSERT_EQ(rgoose_rx_count, PLAIN_COUNT);
    ASSERT_EQ(rgoose_rx_appid, 0x1001U);

    /* State change: stNum bumps, message flagged as new state. */
    {
        uint32_t st_before = rgoose_rx_stnum;

        iec61850_rgoose_publisher_state_change(&pub);
        ASSERT_EQ(iec61850_rgoose_publisher_publish(&pub), 0);
        {
            int waited = 0;
            while ((rgoose_rx_count < PLAIN_COUNT + 1) && (waited < 5000)) {
                (void)iec61850_rgoose_subscriber_poll(&sub, rx);
                usleep(1000);
                waited++;
            }
        }
        ASSERT_EQ(rgoose_rx_count, PLAIN_COUNT + 1);
        ASSERT_TRUE(rgoose_rx_stnum == (st_before + 1U));
    }

    iec61850_rgoose_publisher_destroy(&pub);
    iec61850_rgoose_subscriber_destroy(&sub);
    packet_io_close(rx);
    packet_io_close(tx);
    packet_io_destroy(rx);
    packet_io_destroy(tx);
    destroy_veth_pair();
    PASS();
}

static void test_plain_wire_replay(void)
{
    iec61850_rgoose_pub_config_t pcfg;
    iec61850_rgoose_sub_config_t scfg;
    iec61850_rgoose_publisher_t pub;
    iec61850_rgoose_subscriber_t sub;
    struct packet_io *tx;
    struct packet_io *rx;
    struct packet_io *raw_tx;
    static uint8_t spdu[IEC61850_RGOOSE_MAX_SPDU_LEN];
    static uint8_t frame[IEC61850_RGOOSE_MAX_FRAME_LEN];
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    size_t spdu_len = 0U;
    size_t ip_len;
    uint64_t repl_before;

    TEST("rgoose_plain_wire_replay_rejected");
    if (!is_root) { SKIP("not root"); }
    if (create_veth_pair() != 0) { SKIP("veth creation failed"); }
    if (read_mac(VETH_B, dst_mac) != 0 || read_mac(VETH_A, src_mac) != 0) {
        destroy_veth_pair();
        SKIP("cannot read veth MACs");
    }

    fill_pub_config(&pcfg, IP_B, (uint16_t)RGOOSE_VETH_PORT);
    iec61850_rgoose_publisher_init(&pub, &pcfg);
    (void)iec61850_rgoose_publisher_set_boolean(&pub, 0, true);

    iec61850_rgoose_sub_config_init(&scfg);
    scfg.filter_appid = 0x1001U;
    iec61850_rgoose_subscriber_init(&sub, &scfg);
    iec61850_rgoose_subscriber_set_callback(&sub, on_rgoose, NULL);
    rgoose_rx_count = 0;

    tx = packet_io_create_udp_sender(IP_B, (uint16_t)RGOOSE_VETH_PORT, false);
    rx = packet_io_create_udp_receiver((uint16_t)RGOOSE_VETH_PORT, NULL);
    raw_tx = packet_io_create_raw();
    ASSERT_TRUE(tx != NULL && rx != NULL && raw_tx != NULL);
    ASSERT_EQ(packet_io_open(rx, NULL, 0), 0);
    ASSERT_EQ(packet_io_open(tx, NULL, 0), 0);
    ASSERT_EQ(packet_io_open(raw_tx, VETH_A, 0), 0);
    iec61850_rgoose_publisher_set_io(&pub, tx);

    /* Capture the FIRST SPDU (number 0) for later replay.
     * build_spdu() consumes the sequence counters (L2 prepare()
     * semantics), so the captured bytes are exactly what the first
     * publish would have put on the wire. */
    ASSERT_EQ(iec61850_rgoose_publisher_build_spdu(&pub, spdu,
                                                    sizeof(spdu), &spdu_len),
              0);
    ASSERT_EQ(packet_io_send(tx, spdu, (uint32_t)spdu_len), 0);
    /* Message 1 via the regular publish path (number 1). */
    ASSERT_EQ(iec61850_rgoose_publisher_publish(&pub), 0);
    {
        int waited = 0;
        while ((rgoose_rx_count < 2) && (waited < 5000)) {
            (void)iec61850_rgoose_subscriber_poll(&sub, rx);
            usleep(1000);
            waited++;
        }
    }
    ASSERT_EQ(rgoose_rx_count, 2);

    /* Duplicate injection over the plain UDP path: the captured
     * SPDU number 0 again -> the subscriber's per-APPID SPDU-number
     * tracking must drop it. */
    repl_before = sub.total_replays;
    ASSERT_EQ(packet_io_send(tx, spdu, (uint32_t)spdu_len), 0);
    {
        int waited = 0;
        while ((sub.total_replays < (repl_before + 1U)) && (waited < 5000)) {
            (void)iec61850_rgoose_subscriber_poll(&sub, rx);
            usleep(1000);
            waited++;
        }
    }
    ASSERT_EQ(sub.total_replays, repl_before + 1U);
    ASSERT_EQ(rgoose_rx_count, 2);

    /* Stale-number replay injected as a raw [Eth][IPv4][UDP][SPDU]
     * frame on the wire (a relay/replay device, not a socket peer):
     * the kernel IP stack on VETH_B delivers it to the UDP receiver,
     * and the subscriber must still reject it by SPDU number. */
    ip_len = 0U;
    ASSERT_EQ(iec61850_ip_udp_build(&frame[14], sizeof(frame) - 14U,
                                    IP_A, IP_B,
                                    (uint16_t)RGOOSE_VETH_PORT,
                                    (uint16_t)RGOOSE_VETH_PORT,
                                    spdu, spdu_len, 17U), 0);
    ip_len = IEC61850_IP_UDP_HEADER_LEN + spdu_len;
    (void)memcpy(frame, dst_mac, 6);
    (void)memcpy(&frame[6], src_mac, 6);
    frame[12] = 0x08U;
    frame[13] = 0x00U;
    repl_before = sub.total_replays;
    ASSERT_EQ(packet_io_send(raw_tx, frame, (uint32_t)(14U + ip_len)), 0);
    {
        int waited = 0;
        while ((sub.total_replays < (repl_before + 1U)) && (waited < 5000)) {
            (void)iec61850_rgoose_subscriber_poll(&sub, rx);
            usleep(1000);
            waited++;
        }
    }
    ASSERT_EQ(sub.total_replays, repl_before + 1U);
    ASSERT_EQ(rgoose_rx_count, 2);

    iec61850_rgoose_publisher_destroy(&pub);
    iec61850_rgoose_subscriber_destroy(&sub);
    packet_io_close(rx);
    packet_io_close(tx);
    packet_io_close(raw_tx);
    packet_io_destroy(rx);
    packet_io_destroy(tx);
    packet_io_destroy(raw_tx);
    destroy_veth_pair();
    PASS();
}

#ifdef IEC61850_SECURITY_ENABLED

static void test_secure_roundtrip(void)
{
    iec61850_rgoose_pub_config_t pcfg;
    iec61850_rgoose_sub_config_t scfg;
    iec61850_rgoose_pub_security_t ps;
    iec61850_rgoose_sub_security_t ss;
    iec61850_rgoose_publisher_t pub;
    iec61850_rgoose_subscriber_t sub;
    struct packet_io *tx;
    struct packet_io *rx;
    uint8_t dst_mac[6];
    uint8_t src_mac[6];

    TEST("rgoose_secure_veth_roundtrip");
    if (!is_root) { SKIP("not root"); }
    if (create_veth_pair() != 0) { SKIP("veth creation failed"); }
    if (read_mac(VETH_B, dst_mac) != 0 || read_mac(VETH_A, src_mac) != 0) {
        destroy_veth_pair();
        SKIP("cannot read veth MACs");
    }

    fill_pub_config(&pcfg, IP_B, (uint16_t)RGOOSE_VETH_PORT);
    (void)snprintf(pcfg.src_ip, sizeof(pcfg.src_ip), "%s", IP_A);
    (void)memcpy(pcfg.dst_mac, dst_mac, 6);
    (void)memcpy(pcfg.src_mac, src_mac, 6);
    iec61850_rgoose_publisher_init(&pub, &pcfg);
    ASSERT_EQ(iec61850_rgoose_publisher_set_boolean(&pub, 0, true), 0);
    make_pub_sec(&ps);
    ASSERT_EQ(iec61850_rgoose_publisher_enable_security(&pub, &ps), 0);

    iec61850_rgoose_sub_config_init(&scfg);
    scfg.filter_appid = 0x1001U;
    iec61850_rgoose_subscriber_init(&sub, &scfg);
    iec61850_rgoose_subscriber_set_callback(&sub, on_rgoose, NULL);
    make_sub_sec(&ss);
    ASSERT_EQ(iec61850_rgoose_subscriber_enable_security(&sub, &ss), 0);
    rgoose_rx_count = 0;

    tx = packet_io_create_raw();
    rx = packet_io_create_raw();
    ASSERT_TRUE(tx != NULL && rx != NULL);
    ASSERT_EQ(packet_io_open(tx, VETH_A, 0), 0);
    ASSERT_EQ(packet_io_open(rx, VETH_B, 0), 0);
    iec61850_rgoose_publisher_set_io(&pub, tx);

    for (int i = 0; i < SECURE_COUNT; i++) {
        ASSERT_EQ(iec61850_rgoose_publisher_publish(&pub), 0);
    }
    {
        int waited = 0;
        while ((rgoose_rx_count < SECURE_COUNT) && (waited < 5000)) {
            (void)iec61850_rgoose_subscriber_poll(&sub, rx);
            usleep(1000);
            waited++;
        }
    }
    ASSERT_EQ(rgoose_rx_count, SECURE_COUNT);
    ASSERT_TRUE(rgoose_rx_secure == 1);
    ASSERT_EQ(sub.total_security_failures, 0U);

    iec61850_rgoose_publisher_destroy(&pub);
    iec61850_rgoose_subscriber_destroy(&sub);
    packet_io_close(rx);
    packet_io_close(tx);
    packet_io_destroy(rx);
    packet_io_destroy(tx);
    destroy_veth_pair();
    PASS();
}

/* Sign -> wire -> tamper (flip one APDU payload bit) -> re-inject:
 * the HMAC-SHA256 over IP+UDP+SPDU must reject the modified frame. */
static void test_secure_tamper_and_replay(void)
{
    iec61850_rgoose_pub_config_t pcfg;
    iec61850_rgoose_sub_config_t scfg;
    iec61850_rgoose_pub_security_t ps;
    iec61850_rgoose_sub_security_t ss;
    iec61850_rgoose_publisher_t pub;
    iec61850_rgoose_subscriber_t sub;
    struct packet_io *tx;
    struct packet_io *rx;
    static uint8_t frame[IEC61850_RGOOSE_MAX_FRAME_LEN];
    size_t frame_len = 0U;
    uint64_t fails_before;
    uint64_t repl_before;
    uint8_t dst_mac[6];
    uint8_t src_mac[6];

    TEST("rgoose_secure_tamper_and_replay_rejected");
    if (!is_root) { SKIP("not root"); }
    if (create_veth_pair() != 0) { SKIP("veth creation failed"); }
    if (read_mac(VETH_B, dst_mac) != 0 || read_mac(VETH_A, src_mac) != 0) {
        destroy_veth_pair();
        SKIP("cannot read veth MACs");
    }

    fill_pub_config(&pcfg, IP_B, (uint16_t)RGOOSE_VETH_PORT);
    (void)snprintf(pcfg.src_ip, sizeof(pcfg.src_ip), "%s", IP_A);
    (void)memcpy(pcfg.dst_mac, dst_mac, 6);
    (void)memcpy(pcfg.src_mac, src_mac, 6);
    iec61850_rgoose_publisher_init(&pub, &pcfg);
    ASSERT_EQ(iec61850_rgoose_publisher_set_int32(&pub, 0, 777), 0);
    make_pub_sec(&ps);
    ASSERT_EQ(iec61850_rgoose_publisher_enable_security(&pub, &ps), 0);

    iec61850_rgoose_sub_config_init(&scfg);
    scfg.filter_appid = 0x1001U;
    iec61850_rgoose_subscriber_init(&sub, &scfg);
    iec61850_rgoose_subscriber_set_callback(&sub, on_rgoose, NULL);
    make_sub_sec(&ss);
    ASSERT_EQ(iec61850_rgoose_subscriber_enable_security(&sub, &ss), 0);
    rgoose_rx_count = 0;

    tx = packet_io_create_raw();
    rx = packet_io_create_raw();
    ASSERT_TRUE(tx != NULL && rx != NULL);
    ASSERT_EQ(packet_io_open(tx, VETH_A, 0), 0);
    ASSERT_EQ(packet_io_open(rx, VETH_B, 0), 0);
    iec61850_rgoose_publisher_set_io(&pub, tx);

    /* One signed frame on the wire, verified by the subscriber. */
    ASSERT_EQ(iec61850_rgoose_publisher_build_frame(&pub, frame,
                                                    sizeof(frame),
                                                    &frame_len), 0);
    ASSERT_EQ(packet_io_send(tx, frame, (uint32_t)frame_len), 0);
    {
        int waited = 0;
        while ((rgoose_rx_count < 1) && (waited < 5000)) {
            (void)iec61850_rgoose_subscriber_poll(&sub, rx);
            usleep(1000);
            waited++;
        }
    }
    ASSERT_EQ(rgoose_rx_count, 1);

    /* Tamper-in-transit: flip one bit inside the GOOSE APDU payload
     * (before the trailing signature TLV) and re-inject the frame. */
    {
        static uint8_t bad[IEC61850_RGOOSE_MAX_FRAME_LEN];
        size_t apdu_byte = frame_len - 40U; /* inside the APDU, ahead
                                             * of sig tag+len+32 */

        (void)memcpy(bad, frame, frame_len);
        bad[apdu_byte] ^= 0x01U;
        fails_before = sub.total_security_failures;
        ASSERT_EQ(packet_io_send(tx, bad, (uint32_t)frame_len), 0);
        {
            int waited = 0;
            while ((sub.total_security_failures < (fails_before + 1U)) &&
                   (waited < 5000)) {
                (void)iec61850_rgoose_subscriber_poll(&sub, rx);
                usleep(1000);
                waited++;
            }
        }
        ASSERT_EQ(sub.total_security_failures, fails_before + 1U);
        ASSERT_EQ(rgoose_rx_count, 1); /* no delivery */
    }

    /* Verbatim replay of the still-valid signed frame: signature
     * verifies, but the SPDU number is stale -> replay rejection. */
    repl_before = sub.total_replays;
    ASSERT_EQ(packet_io_send(tx, frame, (uint32_t)frame_len), 0);
    {
        int waited = 0;
        while ((sub.total_replays < (repl_before + 1U)) && (waited < 5000)) {
            (void)iec61850_rgoose_subscriber_poll(&sub, rx);
            usleep(1000);
            waited++;
        }
    }
    ASSERT_EQ(sub.total_replays, repl_before + 1U);
    ASSERT_EQ(rgoose_rx_count, 1);
    ASSERT_EQ(sub.total_security_failures, 1U);

    iec61850_rgoose_publisher_destroy(&pub);
    iec61850_rgoose_subscriber_destroy(&sub);
    packet_io_close(rx);
    packet_io_close(tx);
    packet_io_destroy(rx);
    packet_io_destroy(tx);
    destroy_veth_pair();
    PASS();
}

#endif /* IEC61850_SECURITY_ENABLED */

static int run_self(void)
{
    printf("=== R-GOOSE veth Integration Tests ===\n");
    if (!is_root) {
        printf("  (not running as root — all tests will skip)\n");
    }

    test_plain_udp_roundtrip();
    test_plain_wire_replay();
#ifdef IEC61850_SECURITY_ENABLED
    test_secure_roundtrip();
    test_secure_tamper_and_replay();
#else
    printf("  (built without -Denable_security — secure tests not compiled)\n");
#endif

    printf("\n%d/%d passed, %d skipped, %d failed\n",
           tests_passed, tests_run, tests_skipped, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}

/* ------------------------------------------------------------------ */
/* pub / sub split modes (cross-namespace E2E)                         */
/* ------------------------------------------------------------------ */

static int run_pub(const char *dst_ip, int port, int count)
{
    iec61850_rgoose_pub_config_t pcfg;
    iec61850_rgoose_publisher_t pub;
    struct packet_io *tx;
    static uint8_t spdu[IEC61850_RGOOSE_MAX_SPDU_LEN];
    size_t spdu_len = 0U;

    fill_pub_config(&pcfg, dst_ip, (uint16_t)port);
    iec61850_rgoose_publisher_init(&pub, &pcfg);
    (void)iec61850_rgoose_publisher_set_boolean(&pub, 0, true);
    (void)iec61850_rgoose_publisher_set_int32(&pub, 1, -42);

    tx = packet_io_create_udp_sender(dst_ip, (uint16_t)port, false);
    if (tx == NULL) {
        fprintf(stderr, "pub: udp sender create failed\n");
        return 1;
    }
    if (packet_io_open(tx, NULL, 0) != 0) {
        fprintf(stderr, "pub: udp sender open failed\n");
        packet_io_destroy(tx);
        return 1;
    }
    iec61850_rgoose_publisher_set_io(&pub, tx);

    /* First message via build_spdu (captured for the replay), the
     * rest via the regular publish path. */
    if (iec61850_rgoose_publisher_build_spdu(&pub, spdu, sizeof(spdu),
                                             &spdu_len) != 0) {
        fprintf(stderr, "pub: build_spdu failed\n");
        return 1;
    }
    if (packet_io_send(tx, spdu, (uint32_t)spdu_len) != 0) {
        fprintf(stderr, "pub: first send failed\n");
        return 1;
    }
    usleep(20000);

    for (int i = 1; i < count; i++) {
        if (iec61850_rgoose_publisher_publish(&pub) != 0) {
            fprintf(stderr, "pub: publish %d failed\n", i);
            return 1;
        }
        usleep(20000);
    }

    /* Replay injection: the captured first SPDU (stale number)
     * verbatim. */
    if (packet_io_send(tx, spdu, (uint32_t)spdu_len) != 0) {
        fprintf(stderr, "pub: replay send failed\n");
        return 1;
    }

    printf("PUB: sent %d plain R-GOOSE SPDUs + 1 replay to %s:%d\n",
           count, dst_ip, port);
    iec61850_rgoose_publisher_destroy(&pub);
    packet_io_close(tx);
    packet_io_destroy(tx);
    return 0;
}

static int run_sub(int port, int count)
{
    iec61850_rgoose_sub_config_t scfg;
    iec61850_rgoose_subscriber_t sub;
    struct packet_io *rx;
    int waited = 0;
    int ok;

    iec61850_rgoose_sub_config_init(&scfg);
    scfg.filter_appid = 0x1001U;
    scfg.timeout_ms = 30000U;
    iec61850_rgoose_subscriber_init(&sub, &scfg);
    iec61850_rgoose_subscriber_set_callback(&sub, on_rgoose, NULL);
    rgoose_rx_count = 0;

    rx = packet_io_create_udp_receiver((uint16_t)port, NULL);
    if (rx == NULL) {
        fprintf(stderr, "sub: udp receiver create failed\n");
        return 1;
    }
    if (packet_io_open(rx, NULL, 0) != 0) {
        fprintf(stderr, "sub: udp receiver open failed\n");
        packet_io_destroy(rx);
        return 1;
    }

    /* Wait for count accepted messages + 1 replay drop (or timeout). */
    while ((waited < 15000) &&
           !((rgoose_rx_count >= count) && (sub.total_replays >= 1U))) {
        (void)iec61850_rgoose_subscriber_poll(&sub, rx);
        usleep(1000);
        waited++;
    }
    usleep(200000); /* drain any stragglers */

    ok = (rgoose_rx_count == count) && (sub.total_replays == 1U);
    printf("SUB: received %d/%d messages, %llu replay drops -> %s\n",
           rgoose_rx_count, count,
           (unsigned long long)sub.total_replays, ok ? "PASS" : "FAIL");

    iec61850_rgoose_subscriber_destroy(&sub);
    packet_io_close(rx);
    packet_io_destroy(rx);
    return ok ? 0 : 1;
}

#ifdef IEC61850_SECURITY_ENABLED

static int run_pub_secure(const char *iface, const char *src_ip,
                          const char *dst_ip, int port, int count,
                          const char *mac_str)
{
    iec61850_rgoose_pub_config_t pcfg;
    iec61850_rgoose_pub_security_t ps;
    iec61850_rgoose_publisher_t pub;
    struct packet_io *tx;
    static uint8_t frame[IEC61850_RGOOSE_MAX_FRAME_LEN];
    size_t frame_len = 0U;

    fill_pub_config(&pcfg, dst_ip, (uint16_t)port);
    (void)snprintf(pcfg.src_ip, sizeof(pcfg.src_ip), "%s", src_ip);
    if ((mac_str != NULL) && (parse_mac(mac_str, pcfg.dst_mac) == 0)) {
        /* explicit peer MAC */
    } else {
        (void)memset(pcfg.dst_mac, 0xFF, 6); /* broadcast */
    }
    (void)memset(pcfg.src_mac, 0x02, 6);
    iec61850_rgoose_publisher_init(&pub, &pcfg);
    (void)iec61850_rgoose_publisher_set_boolean(&pub, 0, true);
    make_pub_sec(&ps);
    if (iec61850_rgoose_publisher_enable_security(&pub, &ps) != 0) {
        fprintf(stderr, "pub-secure: enable_security failed\n");
        return 1;
    }

    tx = packet_io_create_raw();
    if (tx == NULL) {
        fprintf(stderr, "pub-secure: raw create failed\n");
        return 1;
    }
    if (packet_io_open(tx, iface, 0) != 0) {
        int err = errno;

        fprintf(stderr, "pub-secure: raw open(%s) failed: %s\n", iface,
                strerror(err));
        packet_io_destroy(tx);
        return (err == EPERM) ? 77 : 1;
    }
    iec61850_rgoose_publisher_set_io(&pub, tx);

    /* First frame via build_frame (captured for tamper + replay),
     * the rest via the regular publish path. */
    if (iec61850_rgoose_publisher_build_frame(&pub, frame, sizeof(frame),
                                              &frame_len) != 0) {
        fprintf(stderr, "pub-secure: build_frame failed\n");
        return 1;
    }
    if (packet_io_send(tx, frame, (uint32_t)frame_len) != 0) {
        fprintf(stderr, "pub-secure: first send failed\n");
        return 1;
    }
    usleep(20000);

    for (int i = 1; i < count; i++) {
        if (iec61850_rgoose_publisher_publish(&pub) != 0) {
            fprintf(stderr, "pub-secure: publish %d failed\n", i);
            return 1;
        }
        usleep(20000);
    }

    /* Tampered copy of the captured frame: flip one APDU byte (the
     * signature is not recomputed — in-transit modification). */
    {
        static uint8_t bad[IEC61850_RGOOSE_MAX_FRAME_LEN];

        (void)memcpy(bad, frame, frame_len);
        bad[frame_len - 40U] ^= 0x01U;
        if (packet_io_send(tx, bad, (uint32_t)frame_len) != 0) {
            fprintf(stderr, "pub-secure: tampered send failed\n");
            return 1;
        }
    }
    usleep(20000);

    /* Verbatim replay of the validly signed frame. */
    if (packet_io_send(tx, frame, (uint32_t)frame_len) != 0) {
        fprintf(stderr, "pub-secure: replay send failed\n");
        return 1;
    }

    printf("PUB: sent %d signed R-GOOSE frames + 1 tampered + 1 replay "
           "on %s -> %s:%d\n", count, iface, dst_ip, port);
    iec61850_rgoose_publisher_destroy(&pub);
    packet_io_close(tx);
    packet_io_destroy(tx);
    return 0;
}

static int run_sub_secure(const char *iface, int count)
{
    iec61850_rgoose_sub_config_t scfg;
    iec61850_rgoose_sub_security_t ss;
    iec61850_rgoose_subscriber_t sub;
    struct packet_io *rx;
    int waited = 0;
    int ok;

    iec61850_rgoose_sub_config_init(&scfg);
    scfg.filter_appid = 0x1001U;
    scfg.timeout_ms = 30000U;
    iec61850_rgoose_subscriber_init(&sub, &scfg);
    iec61850_rgoose_subscriber_set_callback(&sub, on_rgoose, NULL);
    make_sub_sec(&ss);
    if (iec61850_rgoose_subscriber_enable_security(&sub, &ss) != 0) {
        fprintf(stderr, "sub-secure: enable_security failed\n");
        return 1;
    }
    rgoose_rx_count = 0;

    rx = packet_io_create_raw();
    if (rx == NULL) {
        fprintf(stderr, "sub-secure: raw create failed\n");
        return 1;
    }
    if (packet_io_open(rx, iface, 0) != 0) {
        int err = errno;

        fprintf(stderr, "sub-secure: raw open(%s) failed: %s\n", iface,
                strerror(err));
        packet_io_destroy(rx);
        return (err == EPERM) ? 77 : 1;
    }

    while ((waited < 15000) &&
           !((rgoose_rx_count >= count) &&
             (sub.total_security_failures >= 1U) &&
             (sub.total_replays >= 1U))) {
        (void)iec61850_rgoose_subscriber_poll(&sub, rx);
        usleep(1000);
        waited++;
    }
    usleep(200000);

    ok = (rgoose_rx_count == count) &&
         (sub.total_security_failures == 1U) && (sub.total_replays == 1U);
    printf("SUB: verified %d/%d signed messages, %llu tamper rejects, "
           "%llu replay drops -> %s\n",
           rgoose_rx_count, count,
           (unsigned long long)sub.total_security_failures,
           (unsigned long long)sub.total_replays, ok ? "PASS" : "FAIL");

    iec61850_rgoose_subscriber_destroy(&sub);
    packet_io_close(rx);
    packet_io_destroy(rx);
    return ok ? 0 : 1;
}

#endif /* IEC61850_SECURITY_ENABLED */

/* ------------------------------------------------------------------ */

int main(int argc, char **argv)
{
    is_root = (geteuid() == 0);

    if (argc < 2) {
        goto usage;
    }
    if (strcmp(argv[1], "self") == 0) {
        return run_self();
    }
    if (strcmp(argv[1], "pub") == 0) {
        if (argc < 5) {
            goto usage;
        }
        return run_pub(argv[2], atoi(argv[3]), atoi(argv[4]));
    }
    if (strcmp(argv[1], "sub") == 0) {
        if (argc < 4) {
            goto usage;
        }
        return run_sub(atoi(argv[2]), atoi(argv[3]));
    }
#ifdef IEC61850_SECURITY_ENABLED
    if (strcmp(argv[1], "pub-secure") == 0) {
        if (argc < 7) {
            goto usage;
        }
        return run_pub_secure(argv[2], argv[3], argv[4], atoi(argv[5]),
                              atoi(argv[6]),
                              (argc > 7) ? argv[7] : NULL);
    }
    if (strcmp(argv[1], "sub-secure") == 0) {
        if (argc < 4) {
            goto usage;
        }
        return run_sub_secure(argv[2], atoi(argv[3]));
    }
#else
    if ((strcmp(argv[1], "pub-secure") == 0) ||
        (strcmp(argv[1], "sub-secure") == 0)) {
        fprintf(stderr, "secure modes need -Denable_security=true\n");
        return 77;
    }
#endif

usage:
    fprintf(stderr,
            "Usage: %s self\n"
            "       %s pub <dst_ip> <dst_port> <count>\n"
            "       %s sub <listen_port> <count>\n"
#ifdef IEC61850_SECURITY_ENABLED
            "       %s pub-secure <iface> <src_ip> <dst_ip> <dst_port> "
            "<count> [dst_mac]\n"
            "       %s sub-secure <iface> <count>\n"
#endif
            , argv[0], argv[0], argv[0]
#ifdef IEC61850_SECURITY_ENABLED
            , argv[0], argv[0]
#endif
            );
    return 2;
}
