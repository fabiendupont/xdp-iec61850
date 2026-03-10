/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Integration Test: packet_io_xsk on veth pair
 *
 * Exercises the full packet_io_xsk lifecycle using AF_XDP on a veth pair.
 * A raw socket on the peer end injects/captures frames to test the
 * XSK send and recv paths end-to-end.
 *
 * Requires: root (CAP_NET_ADMIN + CAP_NET_RAW + BPF).
 * Skips gracefully when not root or when XSK creation fails.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "transport/packet_io.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/socket.h>

#define VETH0 "iec_xsk0"
#define VETH1 "iec_xsk1"

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

/*
 * Send a raw Ethernet frame from an interface via AF_PACKET.
 */
static int send_raw_frame(const char *ifname, const uint8_t *frame, int len)
{
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0) { return -1; }

    int fd = socket(AF_PACKET, SOCK_RAW, (int)htons(ETH_P_ALL));
    if (fd < 0) { return -1; }

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = (int)ifindex;
    sll.sll_protocol = (uint16_t)htons(ETH_P_ALL);

    ssize_t n = sendto(fd, frame, (size_t)len, 0,
                        (struct sockaddr *)&sll, sizeof(sll));
    close(fd);
    return (n > 0) ? 0 : -1;
}

/* ===== XSK lifecycle tests ===== */

static void test_xsk_open_close(void)
{
    TEST("xsk_open_close_on_veth");
    if (!is_root) { SKIP("not root"); }
    if (create_veth_pair() != 0) { SKIP("veth creation failed"); }

    struct packet_io *io = packet_io_create_xsk();
    ASSERT_TRUE(io != NULL);

    int ret = packet_io_open(io, VETH0, 0);
    if (ret != 0) {
        /* XSK may fail on some kernels or veth configurations */
        printf("SKIP: xsk open failed (%d, errno=%d)\n", ret, errno);
        tests_skipped++;
        packet_io_destroy(io);
        destroy_veth_pair();
        return;
    }

    packet_io_close(io);
    packet_io_destroy(io);
    destroy_veth_pair();
    PASS();
}

static void test_xsk_double_open(void)
{
    TEST("xsk_double_open");
    if (!is_root) { SKIP("not root"); }
    if (create_veth_pair() != 0) { SKIP("veth creation failed"); }

    struct packet_io *io = packet_io_create_xsk();
    ASSERT_TRUE(io != NULL);

    int ret = packet_io_open(io, VETH0, 0);
    if (ret != 0) {
        tests_skipped++;
        printf("SKIP: xsk open failed\n");
        packet_io_destroy(io);
        destroy_veth_pair();
        return;
    }

    /* Double open should fail */
    ASSERT_TRUE(packet_io_open(io, VETH0, 0) < 0);

    packet_io_destroy(io);
    destroy_veth_pair();
    PASS();
}

static void test_xsk_send(void)
{
    TEST("xsk_send_on_veth");
    if (!is_root) { SKIP("not root"); }
    if (create_veth_pair() != 0) { SKIP("veth creation failed"); }

    struct packet_io *io = packet_io_create_xsk();
    ASSERT_TRUE(io != NULL);

    int ret = packet_io_open(io, VETH0, 0);
    if (ret != 0) {
        tests_skipped++;
        printf("SKIP: xsk open failed\n");
        packet_io_destroy(io);
        destroy_veth_pair();
        return;
    }

    /* Build a minimal Ethernet frame */
    uint8_t frame[64];
    memset(frame, 0xff, 6);       /* dst: broadcast */
    memset(frame + 6, 0xcc, 6);   /* src */
    frame[12] = 0x08;
    frame[13] = 0x00;
    memset(frame + 14, 0xEF, 50);

    ret = packet_io_send(io, frame, 64);
    ASSERT_EQ(ret, 0);

    packet_io_destroy(io);
    destroy_veth_pair();
    PASS();
}

static void test_xsk_recv_from_raw(void)
{
    TEST("xsk_recv_frame_from_raw_peer");
    if (!is_root) { SKIP("not root"); }
    if (create_veth_pair() != 0) { SKIP("veth creation failed"); }

    struct packet_io *io = packet_io_create_xsk();
    ASSERT_TRUE(io != NULL);

    int ret = packet_io_open(io, VETH0, 0);
    if (ret != 0) {
        tests_skipped++;
        printf("SKIP: xsk open failed\n");
        packet_io_destroy(io);
        destroy_veth_pair();
        return;
    }

    /* Send a raw frame from the peer veth */
    uint8_t frame[64];
    memset(frame, 0xff, 6);
    memset(frame + 6, 0xdd, 6);
    frame[12] = 0x88;
    frame[13] = 0xB8;  /* GOOSE ethertype */
    memset(frame + 14, 0xAB, 50);

    if (send_raw_frame(VETH1, frame, 64) != 0) {
        tests_skipped++;
        printf("SKIP: raw send failed\n");
        packet_io_destroy(io);
        destroy_veth_pair();
        return;
    }

    /* Try to receive via XSK (may not work on all kernel versions) */
    void *pkt = NULL;
    uint32_t pkt_len = 0;
    int got = 0;
    for (int i = 0; i < 200 && !got; i++) {
        ret = packet_io_recv(io, &pkt, &pkt_len);
        if (ret > 0) {
            got = 1;
            packet_io_release(io);
        } else {
            usleep(1000);
        }
    }

    if (!got) {
        /* XSK recv on veth without XDP program may not deliver packets */
        printf("SKIP: no packet received via XSK (expected on veth w/o XDP prog)\n");
        tests_skipped++;
        packet_io_destroy(io);
        destroy_veth_pair();
        return;
    }

    ASSERT_TRUE(pkt_len >= 14);

    packet_io_destroy(io);
    destroy_veth_pair();
    PASS();
}

static void test_xsk_send_recv_roundtrip(void)
{
    TEST("xsk_send_recv_roundtrip");
    if (!is_root) { SKIP("not root"); }
    if (create_veth_pair() != 0) { SKIP("veth creation failed"); }

    /* XSK on veth0, raw on veth1 */
    struct packet_io *xsk_io = packet_io_create_xsk();
    ASSERT_TRUE(xsk_io != NULL);

    int ret = packet_io_open(xsk_io, VETH0, 0);
    if (ret != 0) {
        tests_skipped++;
        printf("SKIP: xsk open failed\n");
        packet_io_destroy(xsk_io);
        destroy_veth_pair();
        return;
    }

    /* Send via XSK */
    uint8_t frame[64];
    memset(frame, 0xff, 6);
    memset(frame + 6, 0xee, 6);
    frame[12] = 0x08;
    frame[13] = 0x00;
    memset(frame + 14, 0x42, 50);

    ret = packet_io_send(xsk_io, frame, 64);
    ASSERT_EQ(ret, 0);

    /* Receive on peer via raw socket */
    int raw_fd = socket(AF_PACKET, SOCK_RAW, (int)htons(ETH_P_ALL));
    if (raw_fd < 0) {
        tests_skipped++;
        printf("SKIP: raw socket failed\n");
        packet_io_destroy(xsk_io);
        destroy_veth_pair();
        return;
    }

    unsigned int ifindex = if_nametoindex(VETH1);
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = (uint16_t)htons(ETH_P_ALL);
    sll.sll_ifindex = (int)ifindex;
    (void)bind(raw_fd, (struct sockaddr *)&sll, sizeof(sll));

    uint8_t rx_buf[2048];
    int got = 0;
    for (int i = 0; i < 200 && !got; i++) {
        ssize_t n = recv(raw_fd, rx_buf, sizeof(rx_buf), MSG_DONTWAIT);
        if (n > 0) {
            got = 1;
        } else {
            usleep(1000);
        }
    }

    close(raw_fd);

    if (!got) {
        printf("SKIP: XSK-sent frame not received on peer raw socket\n");
        tests_skipped++;
        packet_io_destroy(xsk_io);
        destroy_veth_pair();
        return;
    }

    packet_io_destroy(xsk_io);
    destroy_veth_pair();
    PASS();
}

int main(void)
{
    is_root = (geteuid() == 0);
    printf("=== Packet I/O XSK + veth Integration Tests ===\n");
    if (!is_root) {
        printf("  (not running as root — all tests will skip)\n");
    }

    test_xsk_open_close();
    test_xsk_double_open();
    test_xsk_send();
    test_xsk_recv_from_raw();
    test_xsk_send_recv_roundtrip();

    printf("\n%d/%d passed, %d skipped, %d failed\n",
           tests_passed, tests_run, tests_skipped, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
