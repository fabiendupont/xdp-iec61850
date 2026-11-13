/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for MMS Client Async Core
 *
 * WP-S1 scaffold: verifies the frozen lifecycle contract. WP-1a
 * (client-core) extends this file with event-loop, submission,
 * correlation, and dispatch tests.
 */

#include "mms/mms_client_core.h"

#include <errno.h>
#include <stdio.h>

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

static void test_core_init_lifecycle(void)
{
    TEST("core_init_lifecycle");
    iec61850_mms_client_core_t core;
    iec61850_mms_client_core_init(&core);

    ASSERT_TRUE(core.iso == NULL);
    ASSERT_TRUE(!core.attached);
    ASSERT_TRUE(core.report_cb == NULL);

    /* Detached operations report -ENOTCONN / -ENOSYS per contract */
    ASSERT_EQ(iec61850_mms_client_core_fd(&core), -ENOTCONN);

    iec61850_mms_client_core_init(NULL); /* must not crash */
    PASS();
}

static void test_core_attach_detach(void)
{
    TEST("core_attach_detach");
    iec61850_mms_client_core_t core;
    iec61850_iso_conn_t conn;
    iec61850_iso_conn_init(&conn);
    iec61850_mms_client_core_init(&core);

    ASSERT_EQ(iec61850_mms_client_core_attach(&core, &conn), 0);
    ASSERT_EQ(iec61850_mms_client_core_attach(&core, &conn), -EBUSY);
    ASSERT_TRUE(core.attached);
    ASSERT_TRUE(core.iso == &conn);

    iec61850_mms_client_core_detach(&core);
    ASSERT_TRUE(!core.attached);
    ASSERT_TRUE(core.iso == NULL);
    ASSERT_EQ(iec61850_mms_client_core_fd(&core), -ENOTCONN);

    /* Re-attach after detach is allowed */
    ASSERT_EQ(iec61850_mms_client_core_attach(&core, &conn), 0);
    iec61850_mms_client_core_detach(&core);

    ASSERT_EQ(iec61850_mms_client_core_attach(NULL, &conn), -EINVAL);
    ASSERT_EQ(iec61850_mms_client_core_attach(&core, NULL), -EINVAL);
    PASS();
}

static void test_core_unimplemented_returns_enosys(void)
{
    TEST("core_unimplemented_returns_enosys");
    iec61850_mms_client_core_t core;
    iec61850_iso_conn_t conn;
    iec61850_iso_conn_init(&conn);
    iec61850_mms_client_core_init(&core);
    (void)iec61850_mms_client_core_attach(&core, &conn);

    /* Scaffold contract: functional ops are -ENOSYS until WP-1a.
     * WP-1a replaces these assertions with real behavior tests. */
    ASSERT_EQ(iec61850_mms_client_core_submit(&core, NULL, 0, 1, NULL, NULL),
              -ENOSYS);
    ASSERT_EQ(iec61850_mms_client_core_poll(&core, 0), -ENOSYS);
    ASSERT_EQ(iec61850_mms_client_core_wait(&core, 1, 1), -ENOSYS);
    ASSERT_EQ(iec61850_mms_client_core_fd(&core), -ENOSYS);

    iec61850_mms_client_core_detach(&core);
    PASS();
}

int main(void)
{
    printf("=== MMS Client Core Unit Tests ===\n");

    test_core_init_lifecycle();
    test_core_attach_detach();
    test_core_unimplemented_returns_enosys();

    printf("\n=== Summary: %d run, %d passed, %d failed ===\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
