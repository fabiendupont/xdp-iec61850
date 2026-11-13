/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for the packet_io UDP Backend + IP/UDP framing helpers
 *
 * WP-4b (udp-transport): real-socket loopback tests over 127.0.0.1
 * (unicast and multicast), framing build/parse roundtrips with
 * checksum recomputation, malformed-frame rejection, and error paths.
 *
 * Ports are fixed high ports unique to this file; tests must tolerate
 * being run alongside the other socket tests (verification uses
 * --num-processes 1). The multicast test skips gracefully if the
 * environment forbids joining a group on lo (EADDRNOTAVAIL/EPERM).
 */

#include "transport/packet_io.h"
#include "transport/ip_udp_frame.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { tests_run++; printf("  [TEST] %s ... ", name); } while (0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while (0)
#define SKIP(msg) do { tests_passed++; printf("SKIP (%s)\n", msg); } while (0)
#define FAIL(msg) do { tests_failed++; printf("FAIL: %s\n", msg); return; } while (0)
#define ASSERT_TRUE(cond) do { if (!(cond)) { FAIL(#cond); } } while (0)
#define ASSERT_EQ(a, b) do { if ((a) != (b)) { \
    printf("FAIL: %s == %s (%d != %d)\n", #a, #b, (int)(a), (int)(b)); \
    tests_failed++; return; } } while (0)

/* Fixed high ports, unique within the test suite. */
#define PORT_UNICAST   47891U
#define PORT_BATCH     47893U
#define PORT_BATCH_CAP 47897U
#define PORT_REOPEN    47901U
#define PORT_ROLES     47907U
#define PORT_DBL_OPEN  47909U
#define PORT_MCAST     47911U

/* Administratively-scoped multicast group (239.192.0.0/16, org-local),
 * used on the loopback interface for the multicast roundtrip test. */
#define MCAST_GROUP "239.192.42.100"

/* ------------------------------------------------------------------ */
/* Test-local checksum recompute (independent of the implementation)   */
/* ------------------------------------------------------------------ */

static uint16_t test_cksum_fold(const uint8_t *data, size_t len, uint32_t seed)
{
    uint32_t sum = seed;
    size_t i = 0U;

    while ((i + 2U) <= len) {
        sum += (uint32_t)(((uint32_t)data[i] << 8) | (uint32_t)data[i + 1U]);
        i += 2U;
    }
    if (i < len) {
        sum += (uint32_t)((uint32_t)data[i] << 8);
    }
    while ((sum >> 16) != 0U) {
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }
    return (uint16_t)sum;
}

/* Verify the IPv4 header checksum of a frame by recomputation:
 * zero the field, recompute, compare with the stored value. */
static int test_verify_ip_cksum(const uint8_t *frame, size_t len)
{
    uint8_t hdr[20];
    uint16_t stored;
    uint16_t recomputed;

    if (len < 20U) {
        return -1;
    }
    (void)memcpy(hdr, frame, 20U);
    stored = (uint16_t)(((uint16_t)hdr[10] << 8) | (uint16_t)hdr[11]);
    hdr[10] = 0U;
    hdr[11] = 0U;
    recomputed = (uint16_t)(~(uint32_t)test_cksum_fold(hdr, 20U, 0U));
    return (stored == recomputed) ? 0 : -1;
}

/* Verify the UDP checksum by recomputation over pseudo-header +
 * UDP header (checksum field zeroed) + payload. */
static int test_verify_udp_cksum(const uint8_t *frame, size_t len)
{
    uint8_t pseudo[12];
    uint16_t stored;
    uint16_t udp_len;
    uint32_t seed;
    uint16_t recomputed;
    size_t ip_hdr_len;

    if (len < 28U) {
        return -1;
    }
    ip_hdr_len = (size_t)((frame[0] & 0x0FU) * 4U);
    if (len < (ip_hdr_len + 8U)) {
        return -1;
    }

    (void)memcpy(&pseudo[0], &frame[12], 4U);
    (void)memcpy(&pseudo[4], &frame[16], 4U);
    pseudo[8] = 0U;
    pseudo[9] = 17U; /* IPPROTO_UDP */
    udp_len = (uint16_t)(len - ip_hdr_len);
    pseudo[10] = (uint8_t)(udp_len >> 8);
    pseudo[11] = (uint8_t)(udp_len & 0xFFU);

    stored = (uint16_t)(((uint16_t)frame[ip_hdr_len + 6U] << 8) |
                        (uint16_t)frame[ip_hdr_len + 7U]);

    /* Sum pseudo-header, then UDP header + payload with checksum zeroed
     * (odd tail zero-padded by the fold helper). */
    seed = (uint32_t)test_cksum_fold(pseudo, 12U, 0U);
    {
        /* Fold in two parts so the stored checksum can be skipped. */
        uint32_t sum = seed;
        uint8_t hdr8[8];
        (void)memcpy(hdr8, &frame[ip_hdr_len], 8U);
        hdr8[6] = 0U;
        hdr8[7] = 0U;
        sum = test_cksum_fold(hdr8, 8U, sum);
        sum = test_cksum_fold(&frame[ip_hdr_len + 8U], len - ip_hdr_len - 8U, sum);
        recomputed = (uint16_t)(~(uint32_t)sum);
    }
    if (recomputed == 0U) {
        recomputed = 0xFFFFU;
    }
    return (stored == recomputed) ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* Backend: create/destroy + constructor error paths                   */
/* ------------------------------------------------------------------ */

static void test_udp_create_destroy(void)
{
    TEST("udp_create_destroy");
    struct packet_io *tx = packet_io_create_udp_sender("127.0.0.1",
                                                       PORT_UNICAST, false);
    struct packet_io *rx = packet_io_create_udp_receiver(PORT_UNICAST, NULL);
    ASSERT_TRUE(tx != NULL);
    ASSERT_TRUE(rx != NULL);
    ASSERT_TRUE(tx->ops != NULL);
    ASSERT_TRUE(rx->ops != NULL);
    packet_io_destroy(tx);
    packet_io_destroy(rx);
    packet_io_destroy(NULL); /* must not crash */
    PASS();
}

static void test_udp_sender_invalid_args(void)
{
    TEST("udp_sender_invalid_args");
    errno = 0;
    ASSERT_TRUE(packet_io_create_udp_sender(NULL, 102, false) == NULL);
    ASSERT_TRUE(errno == EINVAL);
    errno = 0;
    ASSERT_TRUE(packet_io_create_udp_sender("not-an-ip", 102, false) == NULL);
    ASSERT_TRUE(errno == EINVAL);
    errno = 0;
    ASSERT_TRUE(packet_io_create_udp_sender("999.1.2.3", 102, false) == NULL);
    ASSERT_TRUE(errno == EINVAL);
    /* multicast flag must match the address class */
    errno = 0;
    ASSERT_TRUE(packet_io_create_udp_sender("127.0.0.1", 102, true) == NULL);
    ASSERT_TRUE(errno == EINVAL);
    errno = 0;
    ASSERT_TRUE(packet_io_create_udp_sender(MCAST_GROUP, 102, false) == NULL);
    ASSERT_TRUE(errno == EINVAL);
    PASS();
}

static void test_udp_receiver_invalid_args(void)
{
    TEST("udp_receiver_invalid_args");
    errno = 0;
    ASSERT_TRUE(packet_io_create_udp_receiver(102, "not-an-ip") == NULL);
    ASSERT_TRUE(errno == EINVAL);
    errno = 0;
    /* group must be a multicast address */
    ASSERT_TRUE(packet_io_create_udp_receiver(102, "127.0.0.1") == NULL);
    ASSERT_TRUE(errno == EINVAL);
    errno = 0;
    ASSERT_TRUE(packet_io_create_udp_receiver(102, "8.8.8.8") == NULL);
    ASSERT_TRUE(errno == EINVAL);
    PASS();
}

/* ------------------------------------------------------------------ */
/* Backend: unicast loopback send/recv                                 */
/* ------------------------------------------------------------------ */

static void test_udp_loopback_unicast(void)
{
    TEST("udp_loopback_unicast");
    const uint8_t msg[] = "rGOOSE-payload-01";
    void *pkt = NULL;
    uint32_t len = 0;

    struct packet_io *rx = packet_io_create_udp_receiver(PORT_UNICAST, NULL);
    struct packet_io *tx = packet_io_create_udp_sender("127.0.0.1",
                                                       PORT_UNICAST, false);
    ASSERT_TRUE(rx != NULL);
    ASSERT_TRUE(tx != NULL);

    ASSERT_EQ(packet_io_open(rx, NULL, 0), 0);
    ASSERT_EQ(packet_io_open(tx, NULL, 0), 0);

    /* Nothing queued yet: recv returns 0 (raw-backend semantics). */
    ASSERT_EQ(packet_io_recv(rx, &pkt, &len), 0);

    ASSERT_EQ(packet_io_send(tx, msg, (uint32_t)sizeof(msg)), 0);

    ASSERT_EQ(packet_io_recv(rx, &pkt, &len), 1);
    ASSERT_EQ(len, (uint32_t)sizeof(msg));
    ASSERT_TRUE(memcmp(pkt, msg, len) == 0);
    packet_io_release(rx); /* no-op for UDP, must not crash */

    /* Queue drained. */
    ASSERT_EQ(packet_io_recv(rx, &pkt, &len), 0);

    packet_io_close(rx);
    packet_io_close(tx);
    packet_io_destroy(rx);
    packet_io_destroy(tx);
    PASS();
}

static void test_udp_recv_batch(void)
{
    TEST("udp_recv_batch");
    uint8_t msg[3][16];
    void *pkts[8] = {0};
    uint32_t lens[8] = {0};
    int n;

    struct packet_io *rx = packet_io_create_udp_receiver(PORT_BATCH, NULL);
    struct packet_io *tx = packet_io_create_udp_sender("127.0.0.1",
                                                       PORT_BATCH, false);
    ASSERT_TRUE(rx != NULL);
    ASSERT_TRUE(tx != NULL);
    ASSERT_EQ(packet_io_open(rx, NULL, 0), 0);
    ASSERT_EQ(packet_io_open(tx, NULL, 0), 0);

    /* Empty batch. */
    ASSERT_EQ(packet_io_recv_batch(rx, pkts, lens, 8), 0);

    for (int i = 0; i < 3; i++) {
        (void)memset(msg[i], (uint8_t)('A' + i), sizeof(msg[i]));
        ASSERT_EQ(packet_io_send(tx, msg[i], (uint32_t)sizeof(msg[i])), 0);
    }

    n = packet_io_recv_batch(rx, pkts, lens, 8);
    ASSERT_EQ(n, 3);
    for (int i = 0; i < 3; i++) {
        ASSERT_EQ(lens[i], (uint32_t)sizeof(msg[i]));
        ASSERT_TRUE(memcmp(pkts[i], msg[i], lens[i]) == 0);
    }
    packet_io_release_batch(rx, 3); /* no-op for UDP, must not crash */

    /* Drained. */
    ASSERT_EQ(packet_io_recv_batch(rx, pkts, lens, 8), 0);

    packet_io_close(rx);
    packet_io_close(tx);
    packet_io_destroy(rx);
    packet_io_destroy(tx);
    PASS();
}

static void test_udp_batch_cap(void)
{
    TEST("udp_batch_cap");
    uint8_t msg[32];
    void *pkts[16] = {0};
    uint32_t lens[16] = {0};
    int n;

    struct packet_io *rx = packet_io_create_udp_receiver(PORT_BATCH_CAP, NULL);
    struct packet_io *tx = packet_io_create_udp_sender("127.0.0.1",
                                                       PORT_BATCH_CAP, false);
    ASSERT_TRUE(rx != NULL);
    ASSERT_TRUE(tx != NULL);
    ASSERT_EQ(packet_io_open(rx, NULL, 0), 0);
    ASSERT_EQ(packet_io_open(tx, NULL, 0), 0);

    (void)memset(msg, 0x5AU, sizeof(msg));
    for (int i = 0; i < 12; i++) {
        ASSERT_EQ(packet_io_send(tx, msg, (uint32_t)sizeof(msg)), 0);
    }

    /* Internal batch cap (8) applies even when max is larger. */
    n = packet_io_recv_batch(rx, pkts, lens, 16);
    ASSERT_EQ(n, 8);
    for (int i = 0; i < 8; i++) {
        ASSERT_EQ(lens[i], (uint32_t)sizeof(msg));
    }

    /* The remaining 4 come back on the next call. */
    n = packet_io_recv_batch(rx, pkts, lens, 16);
    ASSERT_EQ(n, 4);

    packet_io_close(rx);
    packet_io_close(tx);
    packet_io_destroy(rx);
    packet_io_destroy(tx);
    PASS();
}

static void test_udp_close_reopen(void)
{
    TEST("udp_close_reopen");
    const uint8_t msg[] = "reopen";
    void *pkt = NULL;
    uint32_t len = 0;

    struct packet_io *rx = packet_io_create_udp_receiver(PORT_REOPEN, NULL);
    struct packet_io *tx = packet_io_create_udp_sender("127.0.0.1",
                                                       PORT_REOPEN, false);
    ASSERT_TRUE(rx != NULL);
    ASSERT_TRUE(tx != NULL);
    ASSERT_EQ(packet_io_open(rx, NULL, 0), 0);
    ASSERT_EQ(packet_io_open(tx, NULL, 0), 0);

    ASSERT_EQ(packet_io_send(tx, msg, (uint32_t)sizeof(msg)), 0);
    ASSERT_EQ(packet_io_recv(rx, &pkt, &len), 1);
    ASSERT_TRUE(memcmp(pkt, msg, len) == 0);

    packet_io_close(rx);
    packet_io_close(tx);
    packet_io_close(rx); /* double close: no-op, must not crash */

    /* Closed: recv/send fail. */
    ASSERT_TRUE(packet_io_recv(rx, &pkt, &len) < 0);
    ASSERT_TRUE(packet_io_send(tx, msg, (uint32_t)sizeof(msg)) < 0);

    /* Reopen and do a full roundtrip again. */
    ASSERT_EQ(packet_io_open(rx, NULL, 0), 0);
    ASSERT_EQ(packet_io_open(tx, NULL, 0), 0);
    ASSERT_EQ(packet_io_send(tx, msg, (uint32_t)sizeof(msg)), 0);
    ASSERT_EQ(packet_io_recv(rx, &pkt, &len), 1);
    ASSERT_TRUE(memcmp(pkt, msg, len) == 0);

    packet_io_close(rx);
    packet_io_close(tx);
    packet_io_destroy(rx);
    packet_io_destroy(tx);
    PASS();
}

static void test_udp_double_open(void)
{
    TEST("udp_double_open");
    struct packet_io *rx = packet_io_create_udp_receiver(PORT_DBL_OPEN, NULL);
    ASSERT_TRUE(rx != NULL);
    ASSERT_EQ(packet_io_open(rx, NULL, 0), 0);
    ASSERT_EQ(packet_io_open(rx, NULL, 0), -EALREADY);
    packet_io_close(rx);
    packet_io_destroy(rx);
    PASS();
}

static void test_udp_ops_before_open(void)
{
    TEST("udp_ops_before_open");
    const uint8_t msg[] = "x";
    void *pkt = NULL;
    uint32_t len = 0;

    struct packet_io *rx = packet_io_create_udp_receiver(PORT_ROLES, NULL);
    struct packet_io *tx = packet_io_create_udp_sender("127.0.0.1",
                                                       PORT_ROLES, false);
    ASSERT_TRUE(rx != NULL);
    ASSERT_TRUE(tx != NULL);

    /* close before open: no crash. */
    packet_io_close(rx);

    ASSERT_TRUE(packet_io_recv(rx, &pkt, &len) < 0);
    ASSERT_TRUE(packet_io_recv_batch(rx, &pkt, &len, 1) < 0);
    ASSERT_TRUE(packet_io_send(tx, msg, (uint32_t)sizeof(msg)) < 0);

    packet_io_destroy(rx);
    packet_io_destroy(tx);
    PASS();
}

static void test_udp_role_misuse(void)
{
    TEST("udp_role_misuse");
    const uint8_t msg[] = "y";
    void *pkt = NULL;
    uint32_t len = 0;

    struct packet_io *rx = packet_io_create_udp_receiver(PORT_ROLES, NULL);
    struct packet_io *tx = packet_io_create_udp_sender("127.0.0.1",
                                                       PORT_ROLES, false);
    ASSERT_TRUE(rx != NULL);
    ASSERT_TRUE(tx != NULL);
    ASSERT_EQ(packet_io_open(rx, NULL, 0), 0);
    ASSERT_EQ(packet_io_open(tx, NULL, 0), 0);

    /* Receivers do not send. */
    ASSERT_EQ(packet_io_send(rx, msg, (uint32_t)sizeof(msg)), -EOPNOTSUPP);
    /* Senders do not receive. */
    ASSERT_EQ(packet_io_recv(tx, &pkt, &len), -EOPNOTSUPP);
    ASSERT_EQ(packet_io_recv_batch(tx, &pkt, &len, 1), -EOPNOTSUPP);
    /* NULL output arguments. */
    ASSERT_EQ(packet_io_recv(rx, NULL, &len), -EINVAL);
    ASSERT_EQ(packet_io_recv(rx, &pkt, NULL), -EINVAL);
    ASSERT_EQ(packet_io_send(tx, NULL, 4), -EINVAL);

    packet_io_close(rx);
    packet_io_close(tx);
    packet_io_destroy(rx);
    packet_io_destroy(tx);
    PASS();
}

static void test_udp_send_oversized(void)
{
    TEST("udp_send_oversized");
    static uint8_t big[70000];

    struct packet_io *tx = packet_io_create_udp_sender("127.0.0.1",
                                                       PORT_ROLES, false);
    ASSERT_TRUE(tx != NULL);
    ASSERT_EQ(packet_io_open(tx, NULL, 0), 0);

    /* Larger than the maximum possible IPv4/UDP datagram. */
    ASSERT_EQ(packet_io_send(tx, big, (uint32_t)sizeof(big)), -EMSGSIZE);

    packet_io_close(tx);
    packet_io_destroy(tx);
    PASS();
}

/* ------------------------------------------------------------------ */
/* Backend: multicast roundtrip on lo                                  */
/* ------------------------------------------------------------------ */

static void test_udp_multicast_loopback(void)
{
    TEST("udp_multicast_loopback");
    const uint8_t msg[] = "mcast-payload";
    void *pkt = NULL;
    uint32_t len = 0;
    int ret;

    struct packet_io *rx = packet_io_create_udp_receiver(PORT_MCAST,
                                                         MCAST_GROUP);
    struct packet_io *tx = packet_io_create_udp_sender(MCAST_GROUP,
                                                       PORT_MCAST, true);
    ASSERT_TRUE(rx != NULL);
    ASSERT_TRUE(tx != NULL);

    ret = packet_io_open(rx, "lo", 0);
    if ((ret == -EADDRNOTAVAIL) || (ret == -EPERM) || (ret == -ENODEV)) {
        packet_io_destroy(rx);
        packet_io_destroy(tx);
        SKIP("environment forbids multicast join on lo");
    }
    ASSERT_EQ(ret, 0);

    /* Enable loopback delivery for this same-host test rig (senders
     * default to loop-off). Configured before open: stored + applied. */
    ASSERT_EQ(packet_io_udp_set_mcast_loop(tx, true), 0);
    ret = packet_io_open(tx, "lo", 0);
    if ((ret == -EADDRNOTAVAIL) || (ret == -EPERM) || (ret == -ENODEV)) {
        packet_io_destroy(rx);
        packet_io_destroy(tx);
        SKIP("environment forbids multicast egress on lo");
    }
    ASSERT_EQ(ret, 0);

    ASSERT_EQ(packet_io_send(tx, msg, (uint32_t)sizeof(msg)), 0);
    ASSERT_EQ(packet_io_recv(rx, &pkt, &len), 1);
    ASSERT_EQ(len, (uint32_t)sizeof(msg));
    ASSERT_TRUE(memcmp(pkt, msg, len) == 0);
    packet_io_release(rx);

    /* Re-configuring after open (immediate setsockopt path) still works. */
    ASSERT_EQ(packet_io_udp_set_mcast_loop(tx, false), 0);
    ASSERT_EQ(packet_io_udp_set_mcast_loop(tx, true), 0);
    ASSERT_EQ(packet_io_send(tx, msg, (uint32_t)sizeof(msg)), 0);
    ASSERT_EQ(packet_io_recv(rx, &pkt, &len), 1);
    ASSERT_TRUE(memcmp(pkt, msg, len) == 0);

    packet_io_close(rx);
    packet_io_close(tx);
    packet_io_destroy(rx);
    packet_io_destroy(tx);
    PASS();
}

static void test_udp_set_mcast_loop_errors(void)
{
    TEST("udp_set_mcast_loop_errors");
    struct packet_io *rx = packet_io_create_udp_receiver(PORT_ROLES, NULL);
    struct packet_io *raw = packet_io_create_raw();

    ASSERT_TRUE(rx != NULL);
    ASSERT_TRUE(raw != NULL);

    ASSERT_EQ(packet_io_udp_set_mcast_loop(NULL, true), -EINVAL);
    /* Not a UDP sender: receiver rejected... */
    ASSERT_EQ(packet_io_udp_set_mcast_loop(rx, true), -EINVAL);
    /* ...and a non-UDP backend is rejected too. */
    ASSERT_EQ(packet_io_udp_set_mcast_loop(raw, true), -EINVAL);

    packet_io_destroy(rx);
    packet_io_destroy(raw);
    PASS();
}

/* ------------------------------------------------------------------ */
/* Framing helpers                                                     */
/* ------------------------------------------------------------------ */

static void test_framing_roundtrip(void)
{
    TEST("framing_roundtrip");
    static uint8_t frame[2048];
    const uint8_t payload[] = "hello-r goose"; /* odd length on purpose */
    char src_ip[64] = {0};
    char dst_ip[64] = {0};
    uint16_t sp = 0;
    uint16_t dp = 0;
    const uint8_t *pl = NULL;
    size_t plen = 0;
    size_t flen = 28U + sizeof(payload);

    ASSERT_EQ(iec61850_ip_udp_build(frame, sizeof(frame), "192.168.1.10",
                                    "239.192.42.100", 4096, 102, payload,
                                    sizeof(payload), 17U), 0);

    /* Header fields the parser does not expose. */
    ASSERT_EQ(frame[0], 0x45U); /* v4, IHL 5 */
    ASSERT_EQ(frame[9], 17U);   /* UDP */
    ASSERT_EQ(frame[6] & 0x3FU, 0x00U); /* fragment offset 0 */
    ASSERT_EQ(((uint32_t)frame[2] << 8) | frame[3], flen);

    /* Both checksums verified by independent recomputation. */
    ASSERT_EQ(test_verify_ip_cksum(frame, flen), 0);
    ASSERT_EQ(test_verify_udp_cksum(frame, flen), 0);

    ASSERT_EQ(iec61850_ip_udp_parse(frame, flen, src_ip, sizeof(src_ip),
                                    dst_ip, sizeof(dst_ip), &sp, &dp,
                                    &pl, &plen), 0);
    ASSERT_TRUE(strcmp(src_ip, "192.168.1.10") == 0);
    ASSERT_TRUE(strcmp(dst_ip, "239.192.42.100") == 0);
    ASSERT_EQ(sp, 4096U);
    ASSERT_EQ(dp, 102U);
    ASSERT_EQ(plen, sizeof(payload));
    ASSERT_TRUE(memcmp(pl, payload, plen) == 0);
    PASS();
}

static void test_framing_edge_lengths(void)
{
    TEST("framing_edge_lengths");
    static uint8_t frame[65535];
    static uint8_t payload[65507];
    char sip[64];
    char dip[64];
    uint16_t sp;
    uint16_t dp;
    const uint8_t *pl;
    size_t plen;
    size_t cases[] = { 0U, 1U, 5U, 1000U, sizeof(payload) };
    int ret;

    (void)memset(payload, 0xA5U, sizeof(payload));

    for (size_t i = 0U; i < (sizeof(cases) / sizeof(cases[0])); i++) {
        size_t plen_in = cases[i];
        size_t flen = 28U + plen_in;

        ret = iec61850_ip_udp_build(frame, sizeof(frame), "10.0.0.1",
                                    "10.0.0.2", 1234, 5678, payload,
                                    plen_in, 17U);
        ASSERT_EQ(ret, 0);

        ASSERT_EQ(test_verify_ip_cksum(frame, flen), 0);
        ASSERT_EQ(test_verify_udp_cksum(frame, flen), 0);

        ret = iec61850_ip_udp_parse(frame, flen, sip, sizeof(sip), dip,
                                    sizeof(dip), &sp, &dp, &pl, &plen);
        ASSERT_EQ(ret, 0);
        ASSERT_EQ(sp, 1234U);
        ASSERT_EQ(dp, 5678U);
        ASSERT_EQ(plen, plen_in);
        if (plen_in > 0U) {
            ASSERT_TRUE(memcmp(pl, payload, plen) == 0);
        }
    }
    PASS();
}

static void test_framing_malformed(void)
{
    TEST("framing_malformed");
    static uint8_t frame[2048];
    const uint8_t payload[] = "malformed-target";
    char sip[64];
    char dip[64];
    uint16_t sp;
    uint16_t dp;
    const uint8_t *pl;
    size_t plen;
    size_t flen = 28U + sizeof(payload);

    ASSERT_EQ(iec61850_ip_udp_build(frame, sizeof(frame), "10.1.1.1",
                                    "10.1.1.2", 1, 2, payload,
                                    sizeof(payload), 17U), 0);

    /* Truncations. */
    ASSERT_EQ(iec61850_ip_udp_parse(frame, flen - 1U, sip, sizeof(sip),
                                    dip, sizeof(dip), &sp, &dp, &pl,
                                    &plen), -EBADMSG);
    ASSERT_EQ(iec61850_ip_udp_parse(frame, 10U, sip, sizeof(sip), dip,
                                    sizeof(dip), &sp, &dp, &pl, &plen),
              -EBADMSG);
    ASSERT_EQ(iec61850_ip_udp_parse(frame, 0U, sip, sizeof(sip), dip,
                                    sizeof(dip), &sp, &dp, &pl, &plen),
              -EBADMSG);

    /* Bad IHL (header claims options that are not there). */
    {
        uint8_t saved = frame[0];
        frame[0] = 0x44U; /* IHL 4 */
        ASSERT_EQ(iec61850_ip_udp_parse(frame, flen, sip, sizeof(sip),
                                        dip, sizeof(dip), &sp, &dp, &pl,
                                        &plen), -EBADMSG);
        frame[0] = 0x4FU; /* IHL 15 -> 60-byte header > frame */
        ASSERT_EQ(iec61850_ip_udp_parse(frame, flen, sip, sizeof(sip),
                                        dip, sizeof(dip), &sp, &dp, &pl,
                                        &plen), -EBADMSG);
        frame[0] = saved;
    }

    /* Wrong IP version. */
    {
        uint8_t saved = frame[0];
        frame[0] = 0x65U; /* version 6 */
        ASSERT_EQ(iec61850_ip_udp_parse(frame, flen, sip, sizeof(sip),
                                        dip, sizeof(dip), &sp, &dp, &pl,
                                        &plen), -EPROTONOSUPPORT);
        frame[0] = saved;
    }

    /* Fragment offset != 0 rejected; MF flag alone (first fragment,
     * offset 0) accepted per the frozen contract. */
    {
        uint8_t saved7 = frame[7];
        frame[7] = 0x02U; /* offset 2 */
        ASSERT_EQ(iec61850_ip_udp_parse(frame, flen, sip, sizeof(sip),
                                        dip, sizeof(dip), &sp, &dp, &pl,
                                        &plen), -EPROTO);
        frame[7] = saved7;
        frame[6] = 0x20U; /* MF set, offset 0 */
        ASSERT_EQ(iec61850_ip_udp_parse(frame, flen, sip, sizeof(sip),
                                        dip, sizeof(dip), &sp, &dp, &pl,
                                        &plen), 0);
        frame[6] = 0x40U; /* restore DF */
    }

    /* Non-UDP protocol. */
    {
        uint8_t saved = frame[9];
        frame[9] = 6U; /* TCP */
        ASSERT_EQ(iec61850_ip_udp_parse(frame, flen, sip, sizeof(sip),
                                        dip, sizeof(dip), &sp, &dp, &pl,
                                        &plen), -EPROTONOSUPPORT);
        frame[9] = saved;
    }

    /* Total Length field inconsistencies. */
    {
        uint8_t saved2 = frame[2];
        uint8_t saved3 = frame[3];
        frame[2] = 0U; /* total length 10 < header + UDP */
        frame[3] = 10U;
        ASSERT_EQ(iec61850_ip_udp_parse(frame, flen, sip, sizeof(sip),
                                        dip, sizeof(dip), &sp, &dp, &pl,
                                        &plen), -EBADMSG);
        frame[3] = 0xFFU; /* total length 255 > buflen (flen < 255) */
        ASSERT_EQ(iec61850_ip_udp_parse(frame, flen, sip, sizeof(sip),
                                        dip, sizeof(dip), &sp, &dp, &pl,
                                        &plen), -EBADMSG);
        frame[2] = saved2;
        frame[3] = saved3;
    }

    /* Address output buffers too small. */
    {
        char tiny[4];
        ASSERT_EQ(iec61850_ip_udp_parse(frame, flen, tiny, sizeof(tiny),
                                        dip, sizeof(dip), &sp, &dp, &pl,
                                        &plen), -ENOSPC);
    }

    /* NULL arguments. */
    ASSERT_EQ(iec61850_ip_udp_parse(NULL, flen, sip, sizeof(sip), dip,
                                    sizeof(dip), &sp, &dp, &pl, &plen),
              -EINVAL);
    ASSERT_EQ(iec61850_ip_udp_parse(frame, flen, NULL, sizeof(sip), dip,
                                    sizeof(dip), &sp, &dp, &pl, &plen),
              -EINVAL);
    ASSERT_EQ(iec61850_ip_udp_parse(frame, flen, sip, sizeof(sip), dip,
                                    sizeof(dip), &sp, &dp, NULL, &plen),
              -EINVAL);
    ASSERT_EQ(iec61850_ip_udp_parse(frame, flen, sip, sizeof(sip), dip,
                                    sizeof(dip), &sp, &dp, &pl, NULL),
              -EINVAL);
    PASS();
}

static void test_framing_build_errors(void)
{
    TEST("framing_build_errors");
    static uint8_t buf[1024];
    static uint8_t big[65508];
    const uint8_t payload[] = "p";

    /* NULL arguments. */
    ASSERT_EQ(iec61850_ip_udp_build(NULL, sizeof(buf), "1.2.3.4", "5.6.7.8",
                                    1, 2, payload, sizeof(payload), 17U),
              -EINVAL);
    ASSERT_EQ(iec61850_ip_udp_build(buf, sizeof(buf), NULL, "5.6.7.8",
                                    1, 2, payload, sizeof(payload), 17U),
              -EINVAL);
    ASSERT_EQ(iec61850_ip_udp_build(buf, sizeof(buf), "1.2.3.4", NULL,
                                    1, 2, payload, sizeof(payload), 17U),
              -EINVAL);
    ASSERT_EQ(iec61850_ip_udp_build(buf, sizeof(buf), "1.2.3.4", "5.6.7.8",
                                    1, 2, NULL, 4U, 17U), -EINVAL);

    /* Bad addresses. */
    ASSERT_EQ(iec61850_ip_udp_build(buf, sizeof(buf), "bogus", "5.6.7.8",
                                    1, 2, payload, sizeof(payload), 17U),
              -EINVAL);
    ASSERT_EQ(iec61850_ip_udp_build(buf, sizeof(buf), "1.2.3.4", "bogus",
                                    1, 2, payload, sizeof(payload), 17U),
              -EINVAL);

    /* Payload too large for an IPv4/UDP datagram. */
    ASSERT_EQ(iec61850_ip_udp_build(buf, sizeof(buf), "1.2.3.4", "5.6.7.8",
                                    1, 2, big, sizeof(big), 17U),
              -EMSGSIZE);

    /* Output buffer too small. */
    ASSERT_EQ(iec61850_ip_udp_build(buf, 28U, "1.2.3.4", "5.6.7.8",
                                    1, 2, payload, sizeof(payload), 17U),
              -ENOSPC);

    /* Only IPPROTO_UDP accepted today. */
    ASSERT_EQ(iec61850_ip_udp_build(buf, sizeof(buf), "1.2.3.4", "5.6.7.8",
                                    1, 2, payload, sizeof(payload), 6U),
              -EPROTONOSUPPORT);
    PASS();
}

int main(void)
{
    printf("=== packet_io UDP Unit Tests ===\n");

    test_udp_create_destroy();
    test_udp_sender_invalid_args();
    test_udp_receiver_invalid_args();
    test_udp_loopback_unicast();
    test_udp_recv_batch();
    test_udp_batch_cap();
    test_udp_close_reopen();
    test_udp_double_open();
    test_udp_ops_before_open();
    test_udp_role_misuse();
    test_udp_send_oversized();
    test_udp_multicast_loopback();
    test_udp_set_mcast_loop_errors();
    test_framing_roundtrip();
    test_framing_edge_lengths();
    test_framing_malformed();
    test_framing_build_errors();

    printf("\n=== Summary: %d run, %d passed, %d failed ===\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
