/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Integration Test: Report Control Block End-to-End
 *
 * Tests: URCB enable → data change → report generated,
 * BRCB with buffer → multiple changes → buffered reports,
 * GI request generates immediate report.
 *
 * License: BSD-3-Clause
 */

#include "mms/mms_report.h"
#include "ied/ied_data_model.h"

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

/* ========================================================================
 * Report Tracking
 * ======================================================================== */

static int g_report_count = 0;
static mms_information_report_t g_last_report;

static void report_tracker(const mms_information_report_t *report, void *user_data)
{
    (void)user_data;
    g_report_count++;
    g_last_report = *report;
}

/* ========================================================================
 * URCB: Enable → Data Change → Report
 * ======================================================================== */

static void test_urcb_data_change_report(void)
{
    TEST("urcb_data_change_report");
    iec61850_rcb_t rcb;
    iec61850_rcb_init(&rcb, "URCB01", IEC61850_RCB_UNBUFFERED);
    rcb.attrs.trg_ops.data_change = true;
    iec61850_rcb_set_report_sender(&rcb, report_tracker, NULL);

    g_report_count = 0;

    /* Enable */
    ASSERT_EQ(iec61850_rcb_enable(&rcb), 0);
    ASSERT_TRUE(rcb.attrs.rpt_ena);

    /* Simulate data change */
    mms_value_t old_val, new_val;
    memset(&old_val, 0, sizeof(old_val));
    memset(&new_val, 0, sizeof(new_val));
    old_val.type = MMS_TYPE_BOOLEAN;
    old_val.value.boolean = false;
    new_val.type = MMS_TYPE_BOOLEAN;
    new_val.value.boolean = true;

    iec61850_rcb_on_data_change(&rcb, "XCBR1$ST$Pos$stVal", &old_val, &new_val);

    /* Report should have been generated */
    ASSERT_EQ(g_report_count, 1);

    iec61850_rcb_disable(&rcb);
    iec61850_rcb_destroy(&rcb);
    PASS();
}

/* ========================================================================
 * URCB: Disabled → No Report on Data Change
 * ======================================================================== */

static void test_urcb_disabled_no_report(void)
{
    TEST("urcb_disabled_no_report");
    iec61850_rcb_t rcb;
    iec61850_rcb_init(&rcb, "URCB02", IEC61850_RCB_UNBUFFERED);
    rcb.attrs.trg_ops.data_change = true;
    iec61850_rcb_set_report_sender(&rcb, report_tracker, NULL);

    g_report_count = 0;

    /* Do NOT enable — data change should NOT generate report */
    mms_value_t old_val, new_val;
    memset(&old_val, 0, sizeof(old_val));
    memset(&new_val, 0, sizeof(new_val));
    old_val.type = MMS_TYPE_INTEGER;
    new_val.type = MMS_TYPE_INTEGER;
    new_val.value.integer = 42;

    iec61850_rcb_on_data_change(&rcb, "var1", &old_val, &new_val);
    ASSERT_EQ(g_report_count, 0);

    iec61850_rcb_destroy(&rcb);
    PASS();
}

/* ========================================================================
 * BRCB: Multiple Changes → Buffered Reports
 * ======================================================================== */

static void test_brcb_buffered_reports(void)
{
    TEST("brcb_buffered_reports");

    iec61850_rcb_manager_t mgr;
    iec61850_rcb_manager_init(&mgr, "LD0");

    int idx = iec61850_rcb_manager_add_rcb(&mgr, "BRCB01",
                                              IEC61850_RCB_BUFFERED, 32);
    ASSERT_TRUE(idx >= 0);

    iec61850_rcb_t *rcb = &mgr.rcbs[idx];
    rcb->attrs.trg_ops.data_change = true;
    iec61850_rcb_set_report_sender(rcb, report_tracker, NULL);
    iec61850_rcb_enable(rcb);

    /* Get the associated buffer */
    iec61850_report_buffer_t *buf = iec61850_rcb_manager_get_buffer(&mgr, (uint32_t)idx);
    ASSERT_TRUE(buf != NULL);

    g_report_count = 0;

    /* Add entries to buffer directly (simulating data changes) */
    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;

    for (int i = 0; i < 5; i++) {
        val.value.integer = i * 10;
        iec61850_report_buffer_add(buf, IEC61850_REASON_DCHG,
                                     "XCBR1$ST$Pos$stVal", &val,
                                     (uint64_t)(i * 1000));
    }

    /* Verify buffer has 5 entries */
    iec61850_report_entry_t entries[10];
    uint32_t count = 0;
    iec61850_report_buffer_get_entries(buf, 0, entries, &count, 10);
    ASSERT_EQ((int)count, 5);

    /* Verify entry IDs are sequential */
    for (uint32_t i = 1; i < count; i++) {
        ASSERT_TRUE(entries[i].entry_id > entries[i - 1].entry_id);
    }

    iec61850_rcb_disable(rcb);
    iec61850_rcb_manager_destroy(&mgr);
    PASS();
}

/* ========================================================================
 * GI Request → Immediate Report
 * ======================================================================== */

static void test_gi_request_report(void)
{
    TEST("gi_request_report");
    iec61850_rcb_t rcb;
    iec61850_rcb_init(&rcb, "URCB01", IEC61850_RCB_UNBUFFERED);
    rcb.attrs.trg_ops.general_interrogation = true;
    iec61850_rcb_set_report_sender(&rcb, report_tracker, NULL);
    iec61850_rcb_enable(&rcb);

    g_report_count = 0;

    iec61850_rcb_trigger_gi(&rcb);
    ASSERT_EQ(g_report_count, 1);

    iec61850_rcb_disable(&rcb);
    iec61850_rcb_destroy(&rcb);
    PASS();
}

/* ========================================================================
 * RCB Manager: Broadcast Data Change to All Enabled RCBs
 * ======================================================================== */

static int g_rcb1_count = 0;
static int g_rcb2_count = 0;

static void rcb1_tracker(const mms_information_report_t *report, void *user_data)
{
    (void)report; (void)user_data;
    g_rcb1_count++;
}

static void rcb2_tracker(const mms_information_report_t *report, void *user_data)
{
    (void)report; (void)user_data;
    g_rcb2_count++;
}

static void test_rcb_manager_broadcast(void)
{
    TEST("rcb_manager_broadcast");
    iec61850_rcb_manager_t mgr;
    iec61850_rcb_manager_init(&mgr, "LD0");

    int idx1 = iec61850_rcb_manager_add_rcb(&mgr, "URCB01",
                                               IEC61850_RCB_UNBUFFERED, 0);
    int idx2 = iec61850_rcb_manager_add_rcb(&mgr, "URCB02",
                                               IEC61850_RCB_UNBUFFERED, 0);
    ASSERT_TRUE(idx1 >= 0 && idx2 >= 0);

    mgr.rcbs[idx1].attrs.trg_ops.data_change = true;
    mgr.rcbs[idx2].attrs.trg_ops.data_change = true;
    iec61850_rcb_set_report_sender(&mgr.rcbs[idx1], rcb1_tracker, NULL);
    iec61850_rcb_set_report_sender(&mgr.rcbs[idx2], rcb2_tracker, NULL);
    iec61850_rcb_enable(&mgr.rcbs[idx1]);
    iec61850_rcb_enable(&mgr.rcbs[idx2]);

    g_rcb1_count = 0;
    g_rcb2_count = 0;

    mms_value_t old_val, new_val;
    memset(&old_val, 0, sizeof(old_val));
    memset(&new_val, 0, sizeof(new_val));
    old_val.type = MMS_TYPE_BOOLEAN;
    new_val.type = MMS_TYPE_BOOLEAN;
    new_val.value.boolean = true;

    /* Broadcast to all enabled RCBs */
    iec61850_rcb_manager_on_data_change(&mgr, "var1", &old_val, &new_val);

    ASSERT_EQ(g_rcb1_count, 1);
    ASSERT_EQ(g_rcb2_count, 1);

    iec61850_rcb_disable(&mgr.rcbs[idx1]);
    iec61850_rcb_disable(&mgr.rcbs[idx2]);
    iec61850_rcb_manager_destroy(&mgr);
    PASS();
}

/* ========================================================================
 * RCB Manager: GI Broadcast
 * ======================================================================== */

static void test_rcb_manager_gi_broadcast(void)
{
    TEST("rcb_manager_gi_broadcast");
    iec61850_rcb_manager_t mgr;
    iec61850_rcb_manager_init(&mgr, "LD0");

    int idx = iec61850_rcb_manager_add_rcb(&mgr, "URCB_GI",
                                              IEC61850_RCB_UNBUFFERED, 0);
    ASSERT_TRUE(idx >= 0);
    mgr.rcbs[idx].attrs.trg_ops.general_interrogation = true;
    iec61850_rcb_set_report_sender(&mgr.rcbs[idx], report_tracker, NULL);
    iec61850_rcb_enable(&mgr.rcbs[idx]);

    g_report_count = 0;
    iec61850_rcb_manager_trigger_gi(&mgr);
    ASSERT_EQ(g_report_count, 1);

    iec61850_rcb_disable(&mgr.rcbs[idx]);
    iec61850_rcb_manager_destroy(&mgr);
    PASS();
}

int main(void)
{
    printf("\n=== RCB End-to-End Integration Tests ===\n");

    test_urcb_data_change_report();
    test_urcb_disabled_no_report();
    test_brcb_buffered_reports();
    test_gi_request_report();
    test_rcb_manager_broadcast();
    test_rcb_manager_gi_broadcast();

    printf("\n=== Test Summary ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
