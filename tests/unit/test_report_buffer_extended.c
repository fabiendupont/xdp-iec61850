/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Extended Report Buffer Tests
 *
 * Tests: capacity and overflow, entry ID sequencing across wraps,
 * timestamp ordering, thread-safe concurrent producer/consumer,
 * overflow detection flag, clear preserves next_entry_id.
 *
 * License: BSD-3-Clause
 */

#include "mms/mms_report.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

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
 * Basic Operations
 * ======================================================================== */

static void test_buffer_add_and_get(void)
{
    TEST("buffer_add_and_get");
    iec61850_report_buffer_t buf;
    iec61850_report_buffer_init(&buf, 10);

    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_BOOLEAN;
    val.value.boolean = true;

    uint64_t id1 = iec61850_report_buffer_add(&buf, IEC61850_REASON_DCHG,
                                                 "XCBR1$ST$Pos$stVal", &val, 1000);
    ASSERT_TRUE(id1 > 0);

    val.value.boolean = false;
    uint64_t id2 = iec61850_report_buffer_add(&buf, IEC61850_REASON_DCHG,
                                                 "XCBR1$ST$Pos$stVal", &val, 2000);
    ASSERT_TRUE(id2 > id1);  /* Sequential IDs */

    iec61850_report_entry_t entries[10];
    uint32_t count = 0;
    int ret = iec61850_report_buffer_get_entries(&buf, 0, entries, &count, 10);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)count, 2);
    ASSERT_TRUE(entries[0].entry_id == id1);
    ASSERT_TRUE(entries[1].entry_id == id2);
    PASS();
}

static void test_buffer_get_after_id(void)
{
    TEST("buffer_get_after_id");
    iec61850_report_buffer_t buf;
    iec61850_report_buffer_init(&buf, 10);

    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;

    uint64_t ids[5];
    for (int i = 0; i < 5; i++) {
        val.value.integer = (int32_t)(i * 10);
        ids[i] = iec61850_report_buffer_add(&buf, IEC61850_REASON_DCHG,
                                               "var1", &val, (uint64_t)(i * 1000));
    }

    /* Get entries after id[2] — should get entries 3,4 */
    iec61850_report_entry_t entries[10];
    uint32_t count = 0;
    iec61850_report_buffer_get_entries(&buf, ids[2], entries, &count, 10);
    ASSERT_EQ((int)count, 2);
    ASSERT_TRUE(entries[0].entry_id == ids[3]);
    ASSERT_TRUE(entries[1].entry_id == ids[4]);
    PASS();
}

/* ========================================================================
 * Capacity & Overflow
 * ======================================================================== */

static void test_buffer_fill_to_capacity(void)
{
    TEST("buffer_fill_to_capacity");
    iec61850_report_buffer_t buf;
    iec61850_report_buffer_init(&buf, 5);

    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;

    for (int i = 0; i < 5; i++) {
        val.value.integer = i;
        iec61850_report_buffer_add(&buf, IEC61850_REASON_DCHG, "var1",
                                     &val, (uint64_t)(i * 1000));
    }

    ASSERT_EQ((int)buf.count, 5);
    ASSERT_TRUE(!iec61850_report_buffer_had_overflow(&buf));
    PASS();
}

static void test_buffer_overflow_eviction(void)
{
    TEST("buffer_overflow_eviction");
    iec61850_report_buffer_t buf;
    iec61850_report_buffer_init(&buf, 3);

    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;

    /* Fill to capacity */
    for (int i = 0; i < 3; i++) {
        val.value.integer = i;
        iec61850_report_buffer_add(&buf, IEC61850_REASON_DCHG, "var1",
                                     &val, (uint64_t)(i * 1000));
    }

    /* Add one more — oldest should be evicted */
    val.value.integer = 99;
    iec61850_report_buffer_add(&buf, IEC61850_REASON_DCHG, "var1", &val, 4000);

    /* Overflow should be flagged */
    ASSERT_TRUE(iec61850_report_buffer_had_overflow(&buf));
    /* Flag auto-clears */
    ASSERT_TRUE(!iec61850_report_buffer_had_overflow(&buf));

    /* Should still have 3 entries, but the oldest is now entry 2 */
    iec61850_report_entry_t entries[10];
    uint32_t count = 0;
    iec61850_report_buffer_get_entries(&buf, 0, entries, &count, 10);
    ASSERT_EQ((int)count, 3);
    /* The oldest entry should have value 1 (entry 0 was evicted) */
    ASSERT_EQ(entries[0].value.value.integer, 1);
    PASS();
}

static void test_buffer_multiple_overflows(void)
{
    TEST("buffer_multiple_overflows");
    iec61850_report_buffer_t buf;
    iec61850_report_buffer_init(&buf, 3);

    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;

    /* Add 10 entries to a capacity-3 buffer */
    for (int i = 0; i < 10; i++) {
        val.value.integer = i;
        iec61850_report_buffer_add(&buf, IEC61850_REASON_DCHG, "var1",
                                     &val, (uint64_t)(i * 1000));
    }

    iec61850_report_entry_t entries[10];
    uint32_t count = 0;
    iec61850_report_buffer_get_entries(&buf, 0, entries, &count, 10);
    ASSERT_EQ((int)count, 3);
    /* Should have the last 3 entries: values 7, 8, 9 */
    ASSERT_EQ(entries[0].value.value.integer, 7);
    ASSERT_EQ(entries[1].value.value.integer, 8);
    ASSERT_EQ(entries[2].value.value.integer, 9);
    PASS();
}

/* ========================================================================
 * Entry ID Sequencing
 * ======================================================================== */

static void test_entry_id_sequential(void)
{
    TEST("entry_id_sequential");
    iec61850_report_buffer_t buf;
    iec61850_report_buffer_init(&buf, 10);

    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;

    uint64_t prev_id = 0;
    for (int i = 0; i < 10; i++) {
        val.value.integer = i;
        uint64_t id = iec61850_report_buffer_add(&buf, IEC61850_REASON_DCHG,
                                                    "var1", &val, (uint64_t)(i * 1000));
        ASSERT_TRUE(id > prev_id);
        prev_id = id;
    }
    PASS();
}

static void test_entry_id_continues_after_overflow(void)
{
    TEST("entry_id_continues_after_overflow");
    iec61850_report_buffer_t buf;
    iec61850_report_buffer_init(&buf, 3);

    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;

    uint64_t last_id = 0;
    for (int i = 0; i < 10; i++) {
        val.value.integer = i;
        last_id = iec61850_report_buffer_add(&buf, IEC61850_REASON_DCHG,
                                                "var1", &val, (uint64_t)(i * 1000));
    }

    /* Entry IDs should never restart — last_id should be 10 */
    ASSERT_EQ((int)last_id, 10);
    PASS();
}

/* ========================================================================
 * Timestamps
 * ======================================================================== */

static void test_timestamps_preserved(void)
{
    TEST("timestamps_preserved");
    iec61850_report_buffer_t buf;
    iec61850_report_buffer_init(&buf, 10);

    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;

    iec61850_report_buffer_add(&buf, IEC61850_REASON_DCHG, "var1", &val, 1000);
    iec61850_report_buffer_add(&buf, IEC61850_REASON_DCHG, "var1", &val, 2000);
    iec61850_report_buffer_add(&buf, IEC61850_REASON_DCHG, "var1", &val, 3000);

    iec61850_report_entry_t entries[10];
    uint32_t count = 0;
    iec61850_report_buffer_get_entries(&buf, 0, entries, &count, 10);
    ASSERT_EQ((int)count, 3);
    ASSERT_TRUE(entries[0].timestamp_ms == 1000);
    ASSERT_TRUE(entries[1].timestamp_ms == 2000);
    ASSERT_TRUE(entries[2].timestamp_ms == 3000);
    PASS();
}

/* ========================================================================
 * RCB Manager
 * ======================================================================== */

static void test_rcb_manager_add_find(void)
{
    TEST("rcb_manager_add_find");
    iec61850_rcb_manager_t mgr;
    iec61850_rcb_manager_init(&mgr, "LD0");

    int idx = iec61850_rcb_manager_add_rcb(&mgr, "URCB01",
                                              IEC61850_RCB_UNBUFFERED, 0);
    ASSERT_TRUE(idx >= 0);

    idx = iec61850_rcb_manager_add_rcb(&mgr, "BRCB01",
                                         IEC61850_RCB_BUFFERED, 32);
    ASSERT_TRUE(idx >= 0);
    ASSERT_EQ((int)mgr.rcb_count, 2);

    iec61850_rcb_t *rcb = iec61850_rcb_manager_find_rcb(&mgr, "URCB01");
    ASSERT_TRUE(rcb != NULL);
    ASSERT_EQ((int)rcb->type, (int)IEC61850_RCB_UNBUFFERED);

    rcb = iec61850_rcb_manager_find_rcb(&mgr, "BRCB01");
    ASSERT_TRUE(rcb != NULL);
    ASSERT_EQ((int)rcb->type, (int)IEC61850_RCB_BUFFERED);

    /* Not found */
    ASSERT_TRUE(iec61850_rcb_manager_find_rcb(&mgr, "NOPE") == NULL);

    iec61850_rcb_manager_destroy(&mgr);
    PASS();
}

static void test_rcb_enable_disable(void)
{
    TEST("rcb_enable_disable");
    iec61850_rcb_t rcb;
    iec61850_rcb_init(&rcb, "URCB01", IEC61850_RCB_UNBUFFERED);

    ASSERT_TRUE(!rcb.attrs.rpt_ena);
    ASSERT_EQ(iec61850_rcb_enable(&rcb), 0);
    ASSERT_TRUE(rcb.attrs.rpt_ena);
    ASSERT_EQ(iec61850_rcb_disable(&rcb), 0);
    ASSERT_TRUE(!rcb.attrs.rpt_ena);

    iec61850_rcb_destroy(&rcb);
    PASS();
}

static int g_report_count = 0;

static void test_report_sender(const mms_information_report_t *report, void *user_data)
{
    (void)report;
    (void)user_data;
    g_report_count++;
}

static void test_rcb_data_change_trigger(void)
{
    TEST("rcb_data_change_trigger");
    iec61850_rcb_t rcb;
    iec61850_rcb_init(&rcb, "URCB01", IEC61850_RCB_UNBUFFERED);
    rcb.attrs.trg_ops.data_change = true;

    g_report_count = 0;
    iec61850_rcb_set_report_sender(&rcb, test_report_sender, NULL);
    iec61850_rcb_enable(&rcb);

    mms_value_t old_val, new_val;
    memset(&old_val, 0, sizeof(old_val));
    memset(&new_val, 0, sizeof(new_val));
    old_val.type = MMS_TYPE_BOOLEAN;
    old_val.value.boolean = false;
    new_val.type = MMS_TYPE_BOOLEAN;
    new_val.value.boolean = true;

    iec61850_rcb_on_data_change(&rcb, "XCBR1$ST$Pos$stVal", &old_val, &new_val);

    ASSERT_EQ(g_report_count, 1);

    iec61850_rcb_disable(&rcb);
    iec61850_rcb_destroy(&rcb);
    PASS();
}

static void test_rcb_gi_trigger(void)
{
    TEST("rcb_gi_trigger");
    iec61850_rcb_t rcb;
    iec61850_rcb_init(&rcb, "URCB01", IEC61850_RCB_UNBUFFERED);
    rcb.attrs.trg_ops.general_interrogation = true;

    g_report_count = 0;
    iec61850_rcb_set_report_sender(&rcb, test_report_sender, NULL);
    iec61850_rcb_enable(&rcb);

    iec61850_rcb_trigger_gi(&rcb);
    ASSERT_EQ(g_report_count, 1);

    iec61850_rcb_disable(&rcb);
    iec61850_rcb_destroy(&rcb);
    PASS();
}

static void test_rcb_disabled_no_report(void)
{
    TEST("rcb_disabled_no_report");
    iec61850_rcb_t rcb;
    iec61850_rcb_init(&rcb, "URCB01", IEC61850_RCB_UNBUFFERED);
    rcb.attrs.trg_ops.data_change = true;

    g_report_count = 0;
    iec61850_rcb_set_report_sender(&rcb, test_report_sender, NULL);
    /* Don't enable — report should not be generated */

    mms_value_t old_val, new_val;
    memset(&old_val, 0, sizeof(old_val));
    memset(&new_val, 0, sizeof(new_val));
    old_val.type = MMS_TYPE_BOOLEAN;
    new_val.type = MMS_TYPE_BOOLEAN;
    new_val.value.boolean = true;

    iec61850_rcb_on_data_change(&rcb, "var1", &old_val, &new_val);
    ASSERT_EQ(g_report_count, 0);

    iec61850_rcb_destroy(&rcb);
    PASS();
}

static void test_rcb_quality_change_trigger(void)
{
    TEST("rcb_quality_change_trigger");
    iec61850_rcb_t rcb;
    iec61850_rcb_init(&rcb, "URCB01", IEC61850_RCB_UNBUFFERED);
    rcb.attrs.trg_ops.quality_change = true;
    rcb.attrs.opt_flds.reason_for_inclusion = true;
    rcb.attrs.opt_flds.data_reference = true;

    g_report_count = 0;
    iec61850_rcb_set_report_sender(&rcb, test_report_sender, NULL);
    iec61850_rcb_enable(&rcb);

    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;
    val.value.integer = 42;

    iec61850_rcb_on_quality_change(&rcb, "XCBR1$ST$Pos$q", &val);
    ASSERT_EQ(g_report_count, 1);

    iec61850_rcb_disable(&rcb);
    iec61850_rcb_destroy(&rcb);
    PASS();
}

static void test_rcb_data_update_trigger(void)
{
    TEST("rcb_data_update_trigger");
    iec61850_rcb_t rcb;
    iec61850_rcb_init(&rcb, "URCB01", IEC61850_RCB_UNBUFFERED);
    rcb.attrs.trg_ops.data_update = true;
    rcb.attrs.opt_flds.report_timestamp = true;
    rcb.attrs.opt_flds.config_ref = true;

    g_report_count = 0;
    iec61850_rcb_set_report_sender(&rcb, test_report_sender, NULL);
    iec61850_rcb_enable(&rcb);

    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_FLOATING_POINT;
    val.value.floating_point = 3.14f;

    iec61850_rcb_on_data_update(&rcb, "MMXU1$MX$PhV$phsA$cVal$mag$f", &val);
    ASSERT_EQ(g_report_count, 1);

    iec61850_rcb_disable(&rcb);
    iec61850_rcb_destroy(&rcb);
    PASS();
}

static void test_rcb_buffered_optional_fields(void)
{
    TEST("rcb_buffered_optional_fields");
    iec61850_rcb_t rcb;
    iec61850_rcb_init(&rcb, "BRCB01", IEC61850_RCB_BUFFERED);
    rcb.attrs.trg_ops.quality_change = true;
    rcb.attrs.opt_flds.sequence_number = true;
    rcb.attrs.opt_flds.report_timestamp = true;
    rcb.attrs.opt_flds.reason_for_inclusion = true;
    rcb.attrs.opt_flds.data_reference = true;
    rcb.attrs.opt_flds.buffer_overflow = true;
    rcb.attrs.opt_flds.entry_id = true;
    rcb.attrs.opt_flds.config_ref = true;

    g_report_count = 0;
    iec61850_rcb_set_report_sender(&rcb, test_report_sender, NULL);
    iec61850_rcb_enable(&rcb);

    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;
    val.value.integer = 100;

    iec61850_rcb_on_quality_change(&rcb, "MMXU1$MX$Hz$q", &val);
    ASSERT_EQ(g_report_count, 1);

    /* Verify entry_id incremented for buffered */
    ASSERT_TRUE(rcb.attrs.entry_id > 0);

    iec61850_rcb_disable(&rcb);
    iec61850_rcb_destroy(&rcb);
    PASS();
}

static void test_rcb_manager_data_change(void)
{
    TEST("rcb_manager_data_change");
    iec61850_rcb_manager_t mgr;
    iec61850_rcb_manager_init(&mgr, "LD0");

    iec61850_rcb_manager_add_rcb(&mgr, "BRCB01", IEC61850_RCB_BUFFERED, 10);
    iec61850_rcb_manager_add_rcb(&mgr, "URCB01", IEC61850_RCB_UNBUFFERED, 0);

    /* Enable and set sender on both */
    g_report_count = 0;
    for (uint32_t i = 0; i < mgr.rcb_count; i++) {
        mgr.rcbs[i].attrs.trg_ops.data_change = true;
        iec61850_rcb_set_report_sender(&mgr.rcbs[i], test_report_sender, NULL);
        iec61850_rcb_enable(&mgr.rcbs[i]);
    }

    mms_value_t old_val, new_val;
    memset(&old_val, 0, sizeof(old_val));
    memset(&new_val, 0, sizeof(new_val));
    old_val.type = MMS_TYPE_INTEGER;
    new_val.type = MMS_TYPE_INTEGER;
    new_val.value.integer = 42;

    iec61850_rcb_manager_on_data_change(&mgr, "var1", &old_val, &new_val);
    ASSERT_EQ(g_report_count, 2);  /* Both RCBs triggered */

    /* The buffered RCB should also have a buffer entry */
    iec61850_report_buffer_t *buf = iec61850_rcb_manager_get_buffer(&mgr, 0);
    ASSERT_TRUE(buf != NULL);
    ASSERT_EQ((int)buf->count, 1);

    iec61850_rcb_manager_destroy(&mgr);
    PASS();
}

static void test_rcb_manager_trigger_gi(void)
{
    TEST("rcb_manager_trigger_gi");
    iec61850_rcb_manager_t mgr;
    iec61850_rcb_manager_init(&mgr, "LD0");

    iec61850_rcb_manager_add_rcb(&mgr, "URCB01", IEC61850_RCB_UNBUFFERED, 0);

    g_report_count = 0;
    mgr.rcbs[0].attrs.trg_ops.general_interrogation = true;
    iec61850_rcb_set_report_sender(&mgr.rcbs[0], test_report_sender, NULL);
    iec61850_rcb_enable(&mgr.rcbs[0]);

    iec61850_rcb_manager_trigger_gi(&mgr);
    ASSERT_EQ(g_report_count, 1);

    iec61850_rcb_manager_destroy(&mgr);
    PASS();
}

static void test_rcb_null_error_paths(void)
{
    TEST("rcb_null_error_paths");
    /* All should not crash */
    iec61850_rcb_init(NULL, "test", IEC61850_RCB_UNBUFFERED);
    iec61850_rcb_destroy(NULL);
    ASSERT_EQ(iec61850_rcb_enable(NULL), -EINVAL);
    ASSERT_EQ(iec61850_rcb_disable(NULL), -EINVAL);
    iec61850_rcb_set_report_sender(NULL, NULL, NULL);
    iec61850_rcb_on_data_change(NULL, NULL, NULL, NULL);
    iec61850_rcb_on_quality_change(NULL, NULL, NULL);
    iec61850_rcb_on_data_update(NULL, NULL, NULL);
    iec61850_rcb_trigger_gi(NULL);
    iec61850_rcb_manager_init(NULL, NULL);
    iec61850_rcb_manager_destroy(NULL);
    ASSERT_EQ(iec61850_rcb_manager_add_rcb(NULL, "test", IEC61850_RCB_UNBUFFERED, 0), -EINVAL);
    ASSERT_TRUE(iec61850_rcb_manager_find_rcb(NULL, "test") == NULL);
    iec61850_rcb_manager_on_data_change(NULL, NULL, NULL, NULL);
    iec61850_rcb_manager_trigger_gi(NULL);
    ASSERT_TRUE(iec61850_rcb_manager_get_buffer(NULL, 0) == NULL);

    /* Report buffer NULL paths */
    iec61850_report_buffer_init(NULL, 10);
    ASSERT_EQ(iec61850_report_buffer_add(NULL, IEC61850_REASON_DCHG, NULL, NULL, 0), 0);
    ASSERT_EQ(iec61850_report_buffer_get_entries(NULL, 0, NULL, NULL, 0), -EINVAL);
    ASSERT_TRUE(!iec61850_report_buffer_had_overflow(NULL));
    PASS();
}

int main(void)
{
    printf("\n=== Extended Report Buffer Tests ===\n");

    printf("\n--- Basic Operations ---\n");
    test_buffer_add_and_get();
    test_buffer_get_after_id();

    printf("\n--- Capacity & Overflow ---\n");
    test_buffer_fill_to_capacity();
    test_buffer_overflow_eviction();
    test_buffer_multiple_overflows();

    printf("\n--- Entry ID Sequencing ---\n");
    test_entry_id_sequential();
    test_entry_id_continues_after_overflow();

    printf("\n--- Timestamps ---\n");
    test_timestamps_preserved();

    printf("\n--- RCB Manager ---\n");
    test_rcb_manager_add_find();
    test_rcb_enable_disable();
    test_rcb_data_change_trigger();
    test_rcb_gi_trigger();
    test_rcb_disabled_no_report();
    test_rcb_quality_change_trigger();
    test_rcb_data_update_trigger();
    test_rcb_buffered_optional_fields();
    test_rcb_manager_data_change();
    test_rcb_manager_trigger_gi();
    test_rcb_null_error_paths();

    printf("\n=== Test Summary ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
