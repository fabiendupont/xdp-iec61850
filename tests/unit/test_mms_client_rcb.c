/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for MMS Client RCB Enrollment
 *
 * WP-S1 scaffold: verifies the frozen argument-validation contract.
 * WP-1c (client-rcb) extends this file with real enrollment tests
 * against a live server.
 */

#include "mms/mms_client_rcb.h"

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

static void test_rcb_scaffold_contract(void)
{
    TEST("rcb_scaffold_contract");
    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);

    /* Scaffold contract: all operations are -ENOSYS until WP-1c.
     * WP-1c replaces these assertions with real enrollment tests. */
    char names[4][IEC61850_RCB_MAX_NAME];
    uint32_t count = 0;
    ASSERT_EQ(iec61850_mms_client_rcb_list(&client, "LD0", names,
                                             &count, 4), -ENOSYS);

    iec61850_mms_client_rcb_values_t values;
    ASSERT_EQ(iec61850_mms_client_rcb_get_values(&client, "LD0", "brcb01",
                                                   &values), -ENOSYS);

    ASSERT_EQ(iec61850_mms_client_rcb_set_values(&client, "LD0", "brcb01",
                                                   &values, 0U), -ENOSYS);
    ASSERT_EQ(iec61850_mms_client_rcb_enable(&client, "LD0", "brcb01"),
              -ENOSYS);
    ASSERT_EQ(iec61850_mms_client_rcb_disable(&client, "LD0", "brcb01"),
              -ENOSYS);
    ASSERT_EQ(iec61850_mms_client_rcb_purge_buffer(&client, "LD0", "brcb01"),
              -ENOSYS);
    ASSERT_EQ(iec61850_mms_client_rcb_set_entry_id(&client, "LD0", "brcb01",
                                                     42U), -ENOSYS);
    ASSERT_EQ(iec61850_mms_client_set_report_handler(&client, NULL, NULL),
              -ENOSYS);
    PASS();
}

int main(void)
{
    printf("=== MMS Client RCB Unit Tests ===\n");

    test_rcb_scaffold_contract();

    printf("\n=== Summary: %d run, %d passed, %d failed ===\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
