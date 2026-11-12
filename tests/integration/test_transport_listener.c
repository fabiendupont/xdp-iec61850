/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Integration Test: TCP Listener and Multiple Concurrent Connections
 *
 * Tests the raw TCP listener on loopback: init, bind, listen, accept
 * single and multiple connections, stop, and post-stop behaviour.
 * Uses real POSIX TCP sockets — no MMS or ISO stack involved.
 *
 * License: BSD-2-Clause
 */


#include "transport/iso_stack.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { tests_run++; printf("  [TEST] %s ... ", name); } while (0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg) do { tests_failed++; printf("FAIL: %s\n", msg); } while (0)

#define ASSERT_TRUE(cond) do { if (!(cond)) { FAIL(#cond); return; } } while (0)
#define ASSERT_FALSE(cond) do { if ((cond)) { FAIL("!" #cond); return; } } while (0)
#define ASSERT_EQ(a, b) do { if ((a) != (b)) { \
    printf("FAIL: %s == %s (%d != %d)\n", #a, #b, (int)(a), (int)(b)); \
    tests_failed++; return; } } while (0)

#define BASE_PORT 10670
#define TIMEOUT_MS 1000

/* ------------------------------------------------------------------ */

static void test_listener_init(void)
{
    TEST("listener_init");

    iec61850_tcp_listener_t listener;
    iec61850_tcp_listener_init(&listener);

    ASSERT_EQ(listener.sockfd, -1);
    ASSERT_FALSE(listener.listening);

    PASS();
}

/* ------------------------------------------------------------------ */

static void test_listener_bind_and_listen(void)
{
    TEST("listener_bind_and_listen");

    iec61850_tcp_listener_t listener;
    iec61850_tcp_listener_init(&listener);

    int ret = iec61850_tcp_listener_bind(&listener, BASE_PORT);
    ASSERT_EQ(ret, IEC61850_TRANSPORT_OK);
    ASSERT_TRUE(listener.sockfd >= 0);
    ASSERT_FALSE(listener.listening);

    ret = iec61850_tcp_listener_listen(&listener, 5);
    ASSERT_EQ(ret, IEC61850_TRANSPORT_OK);
    ASSERT_TRUE(listener.listening);

    iec61850_tcp_listener_close(&listener);
    PASS();
}

/* ------------------------------------------------------------------ */

static void test_accept_single_connection(void)
{
    TEST("accept_single_connection");

    iec61850_tcp_listener_t listener;
    iec61850_tcp_listener_init(&listener);

    int ret = iec61850_tcp_listener_bind(&listener, BASE_PORT + 1);
    ASSERT_EQ(ret, IEC61850_TRANSPORT_OK);
    ret = iec61850_tcp_listener_listen(&listener, 5);
    ASSERT_EQ(ret, IEC61850_TRANSPORT_OK);

    /* Connect a client */
    iec61850_tcp_conn_t client;
    iec61850_tcp_conn_init(&client);
    ret = iec61850_tcp_connect(&client, "127.0.0.1", BASE_PORT + 1, TIMEOUT_MS);
    ASSERT_EQ(ret, IEC61850_TRANSPORT_OK);
    ASSERT_TRUE(iec61850_tcp_is_connected(&client));

    /* Accept on server side */
    iec61850_tcp_conn_t server_conn;
    iec61850_tcp_conn_init(&server_conn);
    ret = iec61850_tcp_listener_accept(&listener, &server_conn, TIMEOUT_MS);
    ASSERT_EQ(ret, IEC61850_TRANSPORT_OK);
    ASSERT_TRUE(server_conn.connected);
    ASSERT_TRUE(server_conn.sockfd >= 0);

    /* Verify data can flow */
    const uint8_t msg[] = {0xDE, 0xAD};
    ret = iec61850_tcp_send(&client, msg, sizeof(msg));
    ASSERT_EQ(ret, (int)sizeof(msg));

    uint8_t buf[16];
    ret = iec61850_tcp_recv(&server_conn, buf, sizeof(buf), TIMEOUT_MS);
    ASSERT_EQ(ret, (int)sizeof(msg));
    ASSERT_EQ(buf[0], 0xDE);
    ASSERT_EQ(buf[1], 0xAD);

    iec61850_tcp_disconnect(&client);
    iec61850_tcp_disconnect(&server_conn);
    iec61850_tcp_listener_close(&listener);
    PASS();
}

/* ------------------------------------------------------------------ */

static void test_accept_multiple_connections(void)
{
    TEST("accept_multiple_connections");

    iec61850_tcp_listener_t listener;
    iec61850_tcp_listener_init(&listener);

    int ret = iec61850_tcp_listener_bind(&listener, BASE_PORT + 2);
    ASSERT_EQ(ret, IEC61850_TRANSPORT_OK);
    ret = iec61850_tcp_listener_listen(&listener, 5);
    ASSERT_EQ(ret, IEC61850_TRANSPORT_OK);

    /* Connect 3 clients */
    iec61850_tcp_conn_t clients[3];
    iec61850_tcp_conn_t accepted[3];

    for (int i = 0; i < 3; i++) {
        iec61850_tcp_conn_init(&clients[i]);
        iec61850_tcp_conn_init(&accepted[i]);

        ret = iec61850_tcp_connect(&clients[i], "127.0.0.1",
                                   BASE_PORT + 2, TIMEOUT_MS);
        ASSERT_EQ(ret, IEC61850_TRANSPORT_OK);
    }

    /* Accept all 3 */
    for (int i = 0; i < 3; i++) {
        ret = iec61850_tcp_listener_accept(&listener, &accepted[i],
                                           TIMEOUT_MS);
        ASSERT_EQ(ret, IEC61850_TRANSPORT_OK);
        ASSERT_TRUE(accepted[i].connected);
    }

    /* Verify each accepted connection has a unique fd */
    ASSERT_TRUE(accepted[0].sockfd != accepted[1].sockfd);
    ASSERT_TRUE(accepted[1].sockfd != accepted[2].sockfd);
    ASSERT_TRUE(accepted[0].sockfd != accepted[2].sockfd);

    /* Send a distinguishing byte from each client, receive on server */
    for (int i = 0; i < 3; i++) {
        uint8_t tag = (uint8_t)(0xA0 + i);
        ret = iec61850_tcp_send(&clients[i], &tag, 1);
        ASSERT_EQ(ret, 1);
    }

    for (int i = 0; i < 3; i++) {
        uint8_t buf[4];
        ret = iec61850_tcp_recv(&accepted[i], buf, sizeof(buf), TIMEOUT_MS);
        ASSERT_EQ(ret, 1);
        ASSERT_EQ(buf[0], (uint8_t)(0xA0 + i));
    }

    for (int i = 0; i < 3; i++) {
        iec61850_tcp_disconnect(&clients[i]);
        iec61850_tcp_disconnect(&accepted[i]);
    }
    iec61850_tcp_listener_close(&listener);
    PASS();
}

/* ------------------------------------------------------------------ */

static void test_listener_stop(void)
{
    TEST("listener_stop");

    iec61850_tcp_listener_t listener;
    iec61850_tcp_listener_init(&listener);

    int ret = iec61850_tcp_listener_bind(&listener, BASE_PORT + 3);
    ASSERT_EQ(ret, IEC61850_TRANSPORT_OK);
    ret = iec61850_tcp_listener_listen(&listener, 5);
    ASSERT_EQ(ret, IEC61850_TRANSPORT_OK);

    /* Close the listener */
    ret = iec61850_tcp_listener_close(&listener);
    ASSERT_EQ(ret, IEC61850_TRANSPORT_OK);
    ASSERT_FALSE(listener.listening);
    ASSERT_EQ(listener.sockfd, -1);

    /* Verify port is released: a new listener can bind to same port */
    iec61850_tcp_listener_t listener2;
    iec61850_tcp_listener_init(&listener2);
    ret = iec61850_tcp_listener_bind(&listener2, BASE_PORT + 3);
    ASSERT_EQ(ret, IEC61850_TRANSPORT_OK);

    iec61850_tcp_listener_close(&listener2);
    PASS();
}

/* ------------------------------------------------------------------ */

static void test_connect_after_stop(void)
{
    TEST("connect_after_stop");

    iec61850_tcp_listener_t listener;
    iec61850_tcp_listener_init(&listener);

    int ret = iec61850_tcp_listener_bind(&listener, BASE_PORT + 4);
    ASSERT_EQ(ret, IEC61850_TRANSPORT_OK);
    ret = iec61850_tcp_listener_listen(&listener, 5);
    ASSERT_EQ(ret, IEC61850_TRANSPORT_OK);

    /* Stop the listener */
    iec61850_tcp_listener_close(&listener);

    /* Client connect should fail (short timeout — nobody listening) */
    iec61850_tcp_conn_t client;
    iec61850_tcp_conn_init(&client);
    ret = iec61850_tcp_connect(&client, "127.0.0.1", BASE_PORT + 4, 200);
    ASSERT_TRUE(ret < 0);
    ASSERT_FALSE(iec61850_tcp_is_connected(&client));

    /* Clean up in case connect partially succeeded */
    iec61850_tcp_disconnect(&client);
    PASS();
}

/* ------------------------------------------------------------------ */

int main(void)
{
    printf("=== Transport Listener Integration Tests ===\n");

    test_listener_init();
    test_listener_bind_and_listen();
    test_accept_single_connection();
    test_accept_multiple_connections();
    test_listener_stop();
    test_connect_after_stop();

    printf("\nResults: %d/%d passed, %d failed\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
