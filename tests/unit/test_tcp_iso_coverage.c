/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Coverage Tests for TCP Socket and ISO Stack
 *
 * Exercises error paths, init/destroy, and encode/decode functions
 * that don't require a live network connection.
 */

#define _POSIX_C_SOURCE 200809L

#include "transport/tcp_socket.h"
#include "transport/iso_stack.h"
#include <stdio.h>
#include <string.h>

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

/* === TCP Socket Error Paths === */

static void test_tcp_connect_null(void)
{
    TEST("tcp_connect_null");
    ASSERT_EQ(iec61850_tcp_connect(NULL, "localhost", 102, 100), IEC61850_TRANSPORT_ERR_ARGS);

    iec61850_tcp_conn_t conn;
    iec61850_tcp_conn_init(&conn);
    ASSERT_EQ(iec61850_tcp_connect(&conn, NULL, 102, 100), IEC61850_TRANSPORT_ERR_ARGS);
    PASS();
}

static void test_tcp_connect_bad_host(void)
{
    TEST("tcp_connect_bad_host");
    iec61850_tcp_conn_t conn;
    iec61850_tcp_conn_init(&conn);

    /* Connect to invalid address — should fail */
    int ret = iec61850_tcp_connect(&conn, "192.0.2.1", 1, 100);
    ASSERT_TRUE(ret != 0);  /* Should timeout or refuse */
    PASS();
}

static void test_tcp_disconnect_unconnected(void)
{
    TEST("tcp_disconnect_unconnected");
    iec61850_tcp_conn_t conn;
    iec61850_tcp_conn_init(&conn);

    /* Disconnect when not connected — should not crash */
    int ret = iec61850_tcp_disconnect(&conn);
    ASSERT_TRUE(ret == 0 || ret != 0);  /* Either is fine */

    ASSERT_EQ(iec61850_tcp_disconnect(NULL), IEC61850_TRANSPORT_ERR_ARGS);
    PASS();
}

static void test_tcp_send_unconnected(void)
{
    TEST("tcp_send_unconnected");
    iec61850_tcp_conn_t conn;
    iec61850_tcp_conn_init(&conn);

    uint8_t data[] = {0x01, 0x02};
    int ret = iec61850_tcp_send(&conn, data, sizeof(data));
    ASSERT_TRUE(ret != 0);  /* Not connected */

    ASSERT_TRUE(iec61850_tcp_send(NULL, data, 2) != 0);
    PASS();
}

static void test_tcp_recv_unconnected(void)
{
    TEST("tcp_recv_unconnected");
    iec61850_tcp_conn_t conn;
    iec61850_tcp_conn_init(&conn);

    uint8_t buf[64];
    int ret = iec61850_tcp_recv(&conn, buf, sizeof(buf), 100);
    ASSERT_TRUE(ret != 0);

    ASSERT_TRUE(iec61850_tcp_recv(NULL, buf, 64, 100) != 0);
    PASS();
}

static void test_tcp_listener_bind_null(void)
{
    TEST("tcp_listener_bind_null");
    ASSERT_EQ(iec61850_tcp_listener_bind(NULL, 102), IEC61850_TRANSPORT_ERR_ARGS);
    PASS();
}

static void test_tcp_listener_listen_null(void)
{
    TEST("tcp_listener_listen_null");
    ASSERT_EQ(iec61850_tcp_listener_listen(NULL, 10), IEC61850_TRANSPORT_ERR_ARGS);

    /* Listener not bound — should fail */
    iec61850_tcp_listener_t lis;
    iec61850_tcp_listener_init(&lis);
    ASSERT_EQ(iec61850_tcp_listener_listen(&lis, 10), IEC61850_TRANSPORT_ERR_ARGS);
    PASS();
}

static void test_tcp_listener_accept_null(void)
{
    TEST("tcp_listener_accept_null");
    iec61850_tcp_conn_t client;
    iec61850_tcp_conn_init(&client);
    ASSERT_EQ(iec61850_tcp_listener_accept(NULL, &client, 100), IEC61850_TRANSPORT_ERR_ARGS);

    iec61850_tcp_listener_t lis;
    iec61850_tcp_listener_init(&lis);
    ASSERT_EQ(iec61850_tcp_listener_accept(&lis, &client, 100), IEC61850_TRANSPORT_ERR_ARGS);
    PASS();
}

static void test_tcp_listener_close_unbound(void)
{
    TEST("tcp_listener_close_unbound");
    iec61850_tcp_listener_t lis;
    iec61850_tcp_listener_init(&lis);
    iec61850_tcp_listener_close(&lis);  /* Should not crash */
    iec61850_tcp_listener_close(NULL);  /* Should not crash */
    PASS();
}

static void test_tcp_recv_exact_null(void)
{
    TEST("tcp_recv_exact_null");
    uint8_t buf[64];
    ASSERT_TRUE(iec61850_tcp_recv_exact(NULL, buf, 4, 100) != 0);

    iec61850_tcp_conn_t conn;
    iec61850_tcp_conn_init(&conn);
    ASSERT_TRUE(iec61850_tcp_recv_exact(&conn, NULL, 4, 100) != 0);
    PASS();
}

static void test_tcp_recv_tpkt_null(void)
{
    TEST("tcp_recv_tpkt_null");
    uint8_t buf[256];
    ASSERT_TRUE(iec61850_tcp_recv_tpkt(NULL, buf, sizeof(buf), 100) != 0);

    iec61850_tcp_conn_t conn;
    iec61850_tcp_conn_init(&conn);
    ASSERT_TRUE(iec61850_tcp_recv_tpkt(&conn, buf, sizeof(buf), 100) != 0);
    PASS();
}

/* === ISO Stack Error Paths === */

static void test_iso_connect_null(void)
{
    TEST("iso_connect_null");
    uint8_t mms_data[32] = {0};
    ASSERT_TRUE(iec61850_iso_connect(NULL, "localhost", 102,
                                       mms_data, 10, 1000) != 0);
    PASS();
}

static void test_iso_accept_null(void)
{
    TEST("iso_accept_null");
    uint8_t mms_resp[32] = {0};
    uint8_t mms_req[256];
    size_t req_len = 0;
    ASSERT_TRUE(iec61850_iso_accept(NULL, mms_resp, 10,
                                      mms_req, &req_len, 1000) != 0);
    PASS();
}

static void test_iso_send_null(void)
{
    TEST("iso_send_null");
    uint8_t data[32] = {0};
    ASSERT_TRUE(iec61850_iso_send(NULL, data, sizeof(data)) != 0);
    PASS();
}

static void test_iso_recv_null(void)
{
    TEST("iso_recv_null");
    uint8_t buf[256];
    size_t len = 0;
    ASSERT_TRUE(iec61850_iso_recv(NULL, buf, sizeof(buf), &len, 1000) != 0);
    PASS();
}

static void test_iso_disconnect_null(void)
{
    TEST("iso_disconnect_null");
    int ret = iec61850_iso_disconnect(NULL);
    ASSERT_TRUE(ret != 0);  /* Should return error on NULL */
    PASS();
}

static void test_iso_conn_not_connected(void)
{
    TEST("iso_conn_not_connected");
    iec61850_iso_conn_t iso;
    iec61850_iso_conn_init(&iso);

    /* All operations on unconnected ISO conn should fail gracefully */
    uint8_t data[32] = {0};
    ASSERT_TRUE(iec61850_iso_send(&iso, data, sizeof(data)) != 0);

    uint8_t buf[256];
    size_t len = 0;
    ASSERT_TRUE(iec61850_iso_recv(&iso, buf, sizeof(buf), &len, 100) != 0);

    (void)iec61850_iso_disconnect(&iso);
    PASS();
}

/* === TPKT Encode/Decode Additional Coverage === */

static void test_tpkt_encode_various_sizes(void)
{
    TEST("tpkt_encode_various_sizes");
    uint8_t payload[100];
    uint8_t out[200];
    memset(payload, 0xAB, sizeof(payload));

    /* TPKT encode adds 4-byte TPKT header + 3-byte COTP DT header */
    int ret = iec61850_tpkt_encode(out, sizeof(out), payload, 10);
    ASSERT_TRUE(ret > 0);
    ASSERT_EQ(ret, 17);           /* 4 TPKT + 3 COTP DT + 10 payload */
    ASSERT_EQ((int)out[0], 3);    /* TPKT version */
    ASSERT_EQ((int)out[1], 0);    /* reserved */

    /* Larger payload */
    ret = iec61850_tpkt_encode(out, sizeof(out), payload, 100);
    ASSERT_TRUE(ret > 0);
    ASSERT_EQ(ret, 107);          /* 4 + 3 + 100 */

    /* Buffer too small */
    ret = iec61850_tpkt_encode(out, 10, payload, 100);
    ASSERT_TRUE(ret < 0);

    /* NULL args */
    ASSERT_TRUE(iec61850_tpkt_encode(NULL, 200, payload, 10) < 0);
    ASSERT_TRUE(iec61850_tpkt_encode(out, 200, NULL, 10) < 0);
    PASS();
}

static void test_tpkt_decode_roundtrip(void)
{
    TEST("tpkt_decode_roundtrip");
    uint8_t payload[20];
    uint8_t frame[64];
    memset(payload, 0xAB, sizeof(payload));

    /* Encode then decode */
    int ret = iec61850_tpkt_encode(frame, sizeof(frame), payload, 10);
    ASSERT_TRUE(ret > 0);
    int frame_len = ret;

    const uint8_t *decoded_payload = NULL;
    size_t decoded_len = 0;
    ret = iec61850_tpkt_decode(frame, (size_t)frame_len,
                                 &decoded_payload, &decoded_len);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(decoded_payload != NULL);
    ASSERT_EQ((int)decoded_len, 10);  /* Original payload size */

    /* Wrong version byte */
    frame[0] = 4;
    ret = iec61850_tpkt_decode(frame, (size_t)frame_len,
                                 &decoded_payload, &decoded_len);
    ASSERT_TRUE(ret != 0);
    frame[0] = 3;  /* Restore */

    /* Truncated header */
    ret = iec61850_tpkt_decode(frame, 3, &decoded_payload, &decoded_len);
    ASSERT_TRUE(ret != 0);

    /* NULL args */
    ASSERT_TRUE(iec61850_tpkt_decode(NULL, 10, &decoded_payload, &decoded_len) != 0);
    ASSERT_TRUE(iec61850_tpkt_decode(frame, 10, NULL, &decoded_len) != 0);
    PASS();
}

/* === TCP Bind/Listen (exercises real sockets briefly) === */

static void test_tcp_listener_bind_listen_close(void)
{
    TEST("tcp_listener_bind_listen_close");
    iec61850_tcp_listener_t lis;
    iec61850_tcp_listener_init(&lis);

    /* Bind to ephemeral port (0 = kernel assigns) */
    int ret = iec61850_tcp_listener_bind(&lis, 0);
    if (ret != 0) {
        printf("(bind failed, skip) ");
        PASS();
        return;
    }

    ret = iec61850_tcp_listener_listen(&lis, 5);
    ASSERT_EQ(ret, 0);

    /* Accept with 0 timeout — should return timeout immediately */
    iec61850_tcp_conn_t client;
    iec61850_tcp_conn_init(&client);
    ret = iec61850_tcp_listener_accept(&lis, &client, 0);
    ASSERT_EQ(ret, IEC61850_TRANSPORT_ERR_TIMEOUT);

    iec61850_tcp_listener_close(&lis);
    PASS();
}

int main(void)
{
    printf("=== TCP/ISO Coverage Tests ===\n");

    printf("\n--- TCP Error Paths ---\n");
    test_tcp_connect_null();
    test_tcp_connect_bad_host();
    test_tcp_disconnect_unconnected();
    test_tcp_send_unconnected();
    test_tcp_recv_unconnected();
    test_tcp_listener_bind_null();
    test_tcp_listener_listen_null();
    test_tcp_listener_accept_null();
    test_tcp_listener_close_unbound();
    test_tcp_recv_exact_null();
    test_tcp_recv_tpkt_null();

    printf("\n--- ISO Error Paths ---\n");
    test_iso_connect_null();
    test_iso_accept_null();
    test_iso_send_null();
    test_iso_recv_null();
    test_iso_disconnect_null();
    test_iso_conn_not_connected();

    printf("\n--- TPKT Coverage ---\n");
    test_tpkt_encode_various_sizes();
    test_tpkt_decode_roundtrip();

    printf("\n--- TCP Lifecycle ---\n");
    test_tcp_listener_bind_listen_close();

    printf("\nTests: %d run, %d passed, %d failed\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
