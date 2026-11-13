/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for the TLS Socket Layer
 *
 * WP-S3 scaffold: asserts the frozen contract's scaffold state.
 * WP-3b (tls-mms) replaces with handshake, loopback-session, and
 * mode-policy tests.
 */

#include "transport/tls_socket.h"

#include <errno.h>
#include <stdio.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { tests_run++; printf("  [TEST] %s ... ", name); } while (0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg) do { tests_failed++; printf("FAIL: %s\n", msg); } while (0)
#define ASSERT_EQ(a, b) do { if ((a) != (b)) { \
    printf("FAIL: %s == %s (%d != %d)\n", #a, #b, (int)(a), (int)(b)); \
    tests_failed++; return; } } while (0)
#define ASSERT_TRUE(cond) do { if (!(cond)) { FAIL(#cond); return; } } while (0)

static void test_tls_scaffold_contract(void)
{
    TEST("tls_scaffold_contract");
    iec61850_tls_conn_t conn;
    iec61850_tls_conn_init(&conn);
    ASSERT_TRUE(!conn.handshake_done);
    ASSERT_TRUE(conn.ssl == NULL);
    ASSERT_TRUE(!iec61850_tls_is_connected(&conn));

    /* Scaffold contract: functional ops are -ENOSYS until WP-3b. */
    ASSERT_EQ(iec61850_tls_connect(&conn, "127.0.0.1", 3782, 100, NULL,
                                     IEC61850_TLS_MODE_COMPATIBLE), -ENOSYS);
    ASSERT_EQ(iec61850_tls_send(&conn, NULL, 0), -ENOSYS);
    ASSERT_EQ(iec61850_tls_recv(&conn, NULL, 0, 0), -ENOSYS);

    iec61850_tls_listener_t listener;
    iec61850_tls_listener_init(&listener);
    ASSERT_EQ(iec61850_tls_listener_bind(&listener, 3782, NULL,
                                           IEC61850_TLS_MODE_COMPATIBLE),
              -ENOSYS);

    iec61850_tls_conn_init(NULL); /* must not crash */
    PASS();
}

int main(void)
{
    printf("=== TLS Socket Unit Tests ===\n");
    test_tls_scaffold_contract();
    printf("\n=== Summary: %d run, %d passed, %d failed ===\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
