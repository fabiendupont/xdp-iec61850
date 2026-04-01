/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * RCB End-to-End Integration Tests
 *
 * Tests Report Control Blocks (URCB and BRCB) end-to-end:
 * 1. URCB data change report with value verification
 * 2. URCB disabled -- no report on any trigger
 * 3. BRCB buffered reports -- multiple data changes accumulate
 * 4. General interrogation with data store snapshot
 * 5. Enable/disable lifecycle -- no report after disable
 *
 * No MMS server needed -- tests RCB directly with data store.
 */

#include "mms/mms_report.h"
#include "mms/mms_data_store.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

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

/* Captured report state */
static int g_report_count;
static mms_information_report_t g_last_report;

static void capture_report(const mms_information_report_t *report,
                           void *user_data)
{
    (void)user_data;
    g_report_count++;
    g_last_report = *report;
}

/* ========================================================================
 * Test 1: URCB data change report -- enable, trigger, verify values
 * ======================================================================== */

static void test_urcb_data_change_report(void)
{
    TEST("urcb_data_change_report");

    iec61850_rcb_t rcb;
    iec61850_rcb_init(&rcb, "URCB01", IEC61850_RCB_UNBUFFERED);
    rcb.attrs.trg_ops.data_change = true;
    rcb.attrs.opt_flds.reason_for_inclusion = true;

    g_report_count = 0;
    memset(&g_last_report, 0, sizeof(g_last_report));
    iec61850_rcb_set_report_sender(&rcb, capture_report, NULL);

    ASSERT_EQ(iec61850_rcb_enable(&rcb), 0);
    ASSERT_TRUE(rcb.attrs.rpt_ena);

    mms_value_t old_val, new_val;
    memset(&old_val, 0, sizeof(old_val));
    memset(&new_val, 0, sizeof(new_val));
    old_val.type = MMS_TYPE_BOOLEAN;
    old_val.value.boolean = false;
    new_val.type = MMS_TYPE_BOOLEAN;
    new_val.value.boolean = true;

    iec61850_rcb_on_data_change(&rcb, "XCBR1$ST$Pos$stVal",
                                &old_val, &new_val);

    /* Verify report generated */
    ASSERT_EQ(g_report_count, 1);

    /* Verify report ID matches RCB */
    ASSERT_EQ(strcmp(g_last_report.variable_list_name, "URCB01"), 0);

    /* Verify report contains the new value */
    ASSERT_EQ((int)g_last_report.num_values, 1);
    ASSERT_EQ((int)g_last_report.values[0].type, (int)MMS_TYPE_BOOLEAN);
    ASSERT_TRUE(g_last_report.values[0].value.boolean);

    /* Verify sequence number incremented */
    ASSERT_EQ((int)rcb.attrs.sq_num, 1);

    iec61850_rcb_disable(&rcb);
    iec61850_rcb_destroy(&rcb);
    PASS();
}

/* ========================================================================
 * Test 2: URCB disabled -- no report on any trigger type
 * ======================================================================== */

static void test_urcb_disabled_no_report(void)
{
    TEST("urcb_disabled_no_report");

    iec61850_rcb_t rcb;
    iec61850_rcb_init(&rcb, "URCB02", IEC61850_RCB_UNBUFFERED);
    rcb.attrs.trg_ops.data_change = true;
    rcb.attrs.trg_ops.data_update = true;
    rcb.attrs.trg_ops.general_interrogation = true;

    g_report_count = 0;
    iec61850_rcb_set_report_sender(&rcb, capture_report, NULL);
    /* Intentionally NOT enabling the RCB */

    /* Data change -- should be suppressed */
    mms_value_t old_val, new_val;
    memset(&old_val, 0, sizeof(old_val));
    memset(&new_val, 0, sizeof(new_val));
    old_val.type = MMS_TYPE_INTEGER;
    old_val.value.integer = 0;
    new_val.type = MMS_TYPE_INTEGER;
    new_val.value.integer = 42;

    iec61850_rcb_on_data_change(&rcb, "MMXU1$MX$Hz$mag$f",
                                &old_val, &new_val);
    ASSERT_EQ(g_report_count, 0);

    /* Data update -- should be suppressed */
    mms_value_t upd_val;
    memset(&upd_val, 0, sizeof(upd_val));
    upd_val.type = MMS_TYPE_INTEGER;
    upd_val.value.integer = 50;
    iec61850_rcb_on_data_update(&rcb, "MMXU1$MX$Hz$mag$f", &upd_val);
    ASSERT_EQ(g_report_count, 0);

    /* GI -- should be suppressed */
    iec61850_rcb_trigger_gi(&rcb);
    ASSERT_EQ(g_report_count, 0);

    /* Sequence number should not have changed */
    ASSERT_EQ((int)rcb.attrs.sq_num, 0);

    iec61850_rcb_destroy(&rcb);
    PASS();
}

/* ========================================================================
 * Test 3: BRCB buffered reports -- multiple data changes accumulate
 * ======================================================================== */

static void test_brcb_buffered_reports(void)
{
    TEST("brcb_buffered_reports");

    iec61850_rcb_manager_t mgr;
    iec61850_rcb_manager_init(&mgr, "LD0");

    int idx = iec61850_rcb_manager_add_rcb(&mgr, "BRCB01",
                                            IEC61850_RCB_BUFFERED, 16);
    ASSERT_TRUE(idx >= 0);

    iec61850_rcb_t *rcb = &mgr.rcbs[(uint32_t)idx];
    rcb->attrs.trg_ops.data_change = true;

    g_report_count = 0;
    iec61850_rcb_set_report_sender(rcb, capture_report, NULL);
    iec61850_rcb_enable(rcb);

    /* Generate 5 data changes through the manager */
    for (int i = 0; i < 5; i++) {
        mms_value_t old_val, new_val;
        memset(&old_val, 0, sizeof(old_val));
        memset(&new_val, 0, sizeof(new_val));
        old_val.type = MMS_TYPE_INTEGER;
        old_val.value.integer = (int32_t)i;
        new_val.type = MMS_TYPE_INTEGER;
        new_val.value.integer = (int32_t)(i + 100);

        iec61850_rcb_manager_on_data_change(&mgr, "XCBR1$ST$Pos$stVal",
                                             &old_val, &new_val);
    }

    /* All 5 reports should have fired via callback */
    ASSERT_EQ(g_report_count, 5);

    /* The report buffer should have accumulated all 5 entries */
    iec61850_report_buffer_t *buf =
        iec61850_rcb_manager_get_buffer(&mgr, (uint32_t)idx);
    ASSERT_TRUE(buf != NULL);
    ASSERT_EQ((int)buf->count, 5);

    /* Verify buffer entries */
    iec61850_report_entry_t entries[16];
    uint32_t count = 0;
    int ret = iec61850_report_buffer_get_entries(buf, 0, entries,
                                                 &count, 16);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)count, 5);

    /* All entries should be DCHG reason with correct values */
    for (uint32_t i = 0; i < count; i++) {
        ASSERT_EQ((int)entries[i].reason, (int)IEC61850_REASON_DCHG);
        ASSERT_EQ(entries[i].value.value.integer, (int32_t)(i + 100));
    }

    /* Entry IDs should be strictly increasing */
    for (uint32_t i = 1; i < count; i++) {
        ASSERT_TRUE(entries[i].entry_id > entries[i - 1].entry_id);
    }

    /* RCB entry_id should have incremented for each buffered report */
    ASSERT_EQ((int)rcb->attrs.entry_id, 5);

    iec61850_rcb_manager_destroy(&mgr);
    PASS();
}

/* ========================================================================
 * Test 4: General interrogation -- snapshot all data store values
 * ======================================================================== */

static void test_general_interrogation(void)
{
    TEST("general_interrogation");

    /* Set up a data store with a domain and variables */
    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);
    iec61850_mms_ds_create_domain(&ds, "LD0");

    mms_value_t v1 = {0};
    v1.type = MMS_TYPE_BOOLEAN;
    v1.value.boolean = true;
    iec61850_mms_ds_create_variable(&ds, "LD0", "XCBR1$ST$Pos$stVal",
                                    MMS_TYPE_BOOLEAN, &v1);

    mms_value_t v2 = {0};
    v2.type = MMS_TYPE_INTEGER;
    v2.value.integer = 60;
    iec61850_mms_ds_create_variable(&ds, "LD0", "MMXU1$MX$Hz$mag$f",
                                    MMS_TYPE_INTEGER, &v2);

    mms_value_t v3 = {0};
    v3.type = MMS_TYPE_FLOATING_POINT;
    v3.value.floating_point = 230.5f;
    iec61850_mms_ds_create_variable(&ds, "LD0", "MMXU1$MX$PhV$phsA",
                                    MMS_TYPE_FLOATING_POINT, &v3);

    /* Set up RCB with data store for GI snapshot */
    iec61850_rcb_t rcb;
    iec61850_rcb_init(&rcb, "URCB_GI", IEC61850_RCB_UNBUFFERED);
    rcb.attrs.trg_ops.general_interrogation = true;
    rcb.attrs.opt_flds.sequence_number = true;
    rcb.attrs.opt_flds.report_timestamp = true;
    rcb.attrs.opt_flds.reason_for_inclusion = true;
    rcb.data_store = &ds;
    strncpy(rcb.attrs.dat_set, "LD0/DS1", IEC61850_RCB_MAX_NAME - 1);

    g_report_count = 0;
    memset(&g_last_report, 0, sizeof(g_last_report));
    iec61850_rcb_set_report_sender(&rcb, capture_report, NULL);
    iec61850_rcb_enable(&rcb);

    /* Trigger GI */
    iec61850_rcb_trigger_gi(&rcb);

    /* Verify one report was generated */
    ASSERT_EQ(g_report_count, 1);

    /* Report should contain all 3 variables from the data store */
    ASSERT_EQ((int)g_last_report.num_values, 3);

    /* Optional fields should be present */
    ASSERT_TRUE(g_last_report.sq_num_present);
    ASSERT_TRUE(g_last_report.report_timestamp_present);
    ASSERT_TRUE(g_last_report.report_timestamp > 0);
    ASSERT_TRUE(g_last_report.reasons_present);

    /* Each reason should be GI */
    for (uint32_t i = 0; i < g_last_report.num_values; i++) {
        ASSERT_EQ((int)g_last_report.reasons[i],
                  (int)IEC61850_REASON_GI);
    }

    /* Sequence number should have incremented */
    ASSERT_EQ((int)rcb.attrs.sq_num, 1);

    iec61850_rcb_disable(&rcb);
    iec61850_rcb_destroy(&rcb);
    iec61850_mms_ds_destroy(&ds);
    PASS();
}

/* ========================================================================
 * Test 5: Enable/disable lifecycle -- no report after disable
 * ======================================================================== */

static void test_enable_disable_lifecycle(void)
{
    TEST("enable_disable_lifecycle");

    iec61850_rcb_t rcb;
    iec61850_rcb_init(&rcb, "URCB03", IEC61850_RCB_UNBUFFERED);
    rcb.attrs.trg_ops.data_change = true;

    g_report_count = 0;
    iec61850_rcb_set_report_sender(&rcb, capture_report, NULL);

    /* Phase 1: enable and trigger -- should generate report */
    ASSERT_EQ(iec61850_rcb_enable(&rcb), 0);
    ASSERT_TRUE(rcb.attrs.rpt_ena);

    mms_value_t old_val, new_val;
    memset(&old_val, 0, sizeof(old_val));
    memset(&new_val, 0, sizeof(new_val));
    old_val.type = MMS_TYPE_BOOLEAN;
    old_val.value.boolean = false;
    new_val.type = MMS_TYPE_BOOLEAN;
    new_val.value.boolean = true;

    iec61850_rcb_on_data_change(&rcb, "XCBR1$ST$Pos$stVal",
                                &old_val, &new_val);
    ASSERT_EQ(g_report_count, 1);

    /* Phase 2: disable and trigger -- should NOT generate report */
    ASSERT_EQ(iec61850_rcb_disable(&rcb), 0);
    ASSERT_TRUE(!rcb.attrs.rpt_ena);

    new_val.value.boolean = false;
    iec61850_rcb_on_data_change(&rcb, "XCBR1$ST$Pos$stVal",
                                &old_val, &new_val);
    ASSERT_EQ(g_report_count, 1);  /* Still 1 -- no new report */

    /* GI should also be suppressed when disabled */
    rcb.attrs.trg_ops.general_interrogation = true;
    iec61850_rcb_trigger_gi(&rcb);
    ASSERT_EQ(g_report_count, 1);

    /* Phase 3: re-enable and trigger -- should generate report again */
    ASSERT_EQ(iec61850_rcb_enable(&rcb), 0);
    ASSERT_TRUE(rcb.attrs.rpt_ena);

    new_val.value.boolean = true;
    iec61850_rcb_on_data_change(&rcb, "XCBR1$ST$Pos$stVal",
                                &old_val, &new_val);
    ASSERT_EQ(g_report_count, 2);

    /* Sequence number should reflect both reports sent */
    ASSERT_EQ((int)rcb.attrs.sq_num, 2);

    iec61850_rcb_disable(&rcb);
    iec61850_rcb_destroy(&rcb);
    PASS();
}

/* ======================================================================== */

int main(void)
{
    printf("\n=== RCB End-to-End Integration Tests ===\n");

    test_urcb_data_change_report();
    test_urcb_disabled_no_report();
    test_brcb_buffered_reports();
    test_general_interrogation();
    test_enable_disable_lifecycle();

    printf("\n=== Test Summary ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
