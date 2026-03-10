/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for Packet I/O (raw + xsk backends)
 *
 * Tests create/destroy lifecycle and error paths.
 * Raw socket open requires CAP_NET_RAW (or root).
 */

#include "transport/packet_io.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { tests_run++; printf("  [TEST] %s ... ", name); } while (0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg) do { tests_failed++; printf("FAIL: %s\n", msg); } while (0)
#define ASSERT_TRUE(cond) do { if (!(cond)) { FAIL(#cond); return; } } while (0)
#define ASSERT_EQ(a, b) do { if ((a) != (b)) { \
    printf("FAIL: %s == %s (%d != %d)\n", #a, #b, (int)(a), (int)(b)); \
    tests_failed++; return; } } while (0)

static void test_raw_create_destroy(void)
{
    TEST("raw_create_destroy");
    struct packet_io *io = packet_io_create_raw();
    ASSERT_TRUE(io != NULL);
    ASSERT_TRUE(io->ops != NULL);
    packet_io_destroy(io);
    PASS();
}

static void test_raw_recv_before_open(void)
{
    TEST("raw_recv_before_open");
    struct packet_io *io = packet_io_create_raw();
    ASSERT_TRUE(io != NULL);

    void *pkt = NULL;
    uint32_t len = 0;
    int ret = packet_io_recv(io, &pkt, &len);
    ASSERT_TRUE(ret < 0);  /* Should fail — not opened */

    packet_io_destroy(io);
    PASS();
}

static void test_raw_send_before_open(void)
{
    TEST("raw_send_before_open");
    struct packet_io *io = packet_io_create_raw();
    ASSERT_TRUE(io != NULL);

    uint8_t data[] = {0x00, 0x01, 0x02};
    int ret = packet_io_send(io, data, sizeof(data));
    ASSERT_TRUE(ret < 0);  /* Should fail — not opened */

    packet_io_destroy(io);
    PASS();
}

static void test_raw_open_nonexistent_if(void)
{
    TEST("raw_open_nonexistent_if");
    struct packet_io *io = packet_io_create_raw();
    ASSERT_TRUE(io != NULL);

    /* This will either fail with EPERM (no root) or ENODEV (no such interface) */
    int ret = packet_io_open(io, "nonexistent_iface_xyz999", 0);
    ASSERT_TRUE(ret < 0);

    packet_io_destroy(io);
    PASS();
}

static void test_raw_open_lo(void)
{
    TEST("raw_open_lo");
    struct packet_io *io = packet_io_create_raw();
    ASSERT_TRUE(io != NULL);

    int ret = packet_io_open(io, "lo", 0);
    if (ret == 0) {
        /* Opened successfully (running as root or CAP_NET_RAW) */
        printf("(root) ");

        /* Release should not crash */
        packet_io_release(io);

        /* Recv should return 0 (no packets on loopback) */
        void *pkt = NULL;
        uint32_t len = 0;
        ret = packet_io_recv(io, &pkt, &len);
        /* Could be 0 (no packet) or 1 (loopback traffic) */
        ASSERT_TRUE(ret >= 0);

        packet_io_close(io);

        /* Double open should fail */
        /* (fd is now -1 after close, so re-open should work) */
    } else {
        /* Expected when not root */
        printf("(no root, skipped) ");
    }

    packet_io_destroy(io);
    PASS();
}

static void test_xsk_create_destroy(void)
{
    TEST("xsk_create_destroy");
    struct packet_io *io = packet_io_create_xsk();
    ASSERT_TRUE(io != NULL);
    ASSERT_TRUE(io->ops != NULL);
    packet_io_destroy(io);
    PASS();
}

static void test_xsk_recv_before_open(void)
{
    TEST("xsk_recv_before_open");
    struct packet_io *io = packet_io_create_xsk();
    ASSERT_TRUE(io != NULL);

    void *pkt = NULL;
    uint32_t len = 0;
    int ret = packet_io_recv(io, &pkt, &len);
    ASSERT_TRUE(ret < 0);

    packet_io_destroy(io);
    PASS();
}

static void test_xsk_graph_null(void)
{
    TEST("xsk_graph_null");
    struct packet_io *io = packet_io_create_xsk_graph(NULL);
    ASSERT_TRUE(io == NULL);
    PASS();
}

static void test_destroy_null(void)
{
    TEST("destroy_null");
    packet_io_destroy(NULL);  /* Should not crash */
    PASS();
}

static void test_inline_wrappers_null(void)
{
    TEST("inline_wrappers_null");
    ASSERT_EQ(packet_io_open(NULL, "lo", 0), -1);
    ASSERT_EQ(packet_io_recv(NULL, NULL, NULL), -1);
    ASSERT_EQ(packet_io_send(NULL, NULL, 0), -1);
    packet_io_release(NULL);  /* Should not crash */
    packet_io_close(NULL);    /* Should not crash */
    PASS();
}

int main(void)
{
    printf("=== Packet I/O Tests ===\n");

    test_raw_create_destroy();
    test_raw_recv_before_open();
    test_raw_send_before_open();
    test_raw_open_nonexistent_if();
    test_raw_open_lo();
    test_xsk_create_destroy();
    test_xsk_recv_before_open();
    test_xsk_graph_null();
    test_destroy_null();
    test_inline_wrappers_null();

    printf("\nTests: %d run, %d passed, %d failed\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
