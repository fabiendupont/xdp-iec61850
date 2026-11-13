/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Tests for MMS Report Buffer and RCB Manager
 */


#include "mms/mms_report.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

/* ======== Report Buffer Tests ======== */

static void test_report_buffer_init(void)
{
    iec61850_report_buffer_t buf;
    iec61850_report_buffer_init(&buf, 32);

    assert(buf.capacity == 32);
    assert(buf.count == 0);
    assert(buf.head == 0);
    assert(buf.overflow == false);
    printf("  PASS: report buffer init\n");
}

static void test_report_buffer_add_and_get(void)
{
    iec61850_report_buffer_t buf;
    iec61850_report_entry_t out[16];
    uint32_t count = 0;
    mms_value_t val;

    iec61850_report_buffer_init(&buf, 32);

    (void)memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_BOOLEAN;
    val.value.boolean = true;

    uint64_t id1 = iec61850_report_buffer_add(&buf, IEC61850_REASON_DCHG,
                                                 "LD0/LLN0$ST$Beh$stVal",
                                                 &val, 1000);
    assert(id1 == 1);

    val.value.boolean = false;
    uint64_t id2 = iec61850_report_buffer_add(&buf, IEC61850_REASON_DCHG,
                                                 "LD0/LLN0$ST$Beh$stVal",
                                                 &val, 2000);
    assert(id2 == 2);

    /* Get all entries */
    int ret = iec61850_report_buffer_get_entries(&buf, 0, out, &count, 16);
    assert(ret == 0);
    assert(count == 2);
    assert(out[0].entry_id == 1);
    assert(out[1].entry_id == 2);

    /* Get entries after id1 */
    count = 0;
    ret = iec61850_report_buffer_get_entries(&buf, id1, out, &count, 16);
    assert(ret == 0);
    assert(count == 1);
    assert(out[0].entry_id == 2);

    printf("  PASS: report buffer add and get\n");
}

static void test_report_buffer_overflow(void)
{
    iec61850_report_buffer_t buf;
    mms_value_t val;

    iec61850_report_buffer_init(&buf, 4);

    (void)memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;

    /* Fill buffer */
    for (int i = 0; i < 4; i++) {
        val.value.integer = i;
        (void)iec61850_report_buffer_add(&buf, IEC61850_REASON_DCHG,
                                            "var", &val,
                                            (uint64_t)(1000 + i));
    }
    assert(buf.count == 4);
    assert(buf.overflow == false);

    /* Overflow */
    val.value.integer = 99;
    (void)iec61850_report_buffer_add(&buf, IEC61850_REASON_DCHG,
                                        "var", &val, 5000);
    assert(buf.overflow == true);

    /* Check overflow flag and clear */
    bool had_overflow = iec61850_report_buffer_had_overflow(&buf);
    assert(had_overflow == true);
    had_overflow = iec61850_report_buffer_had_overflow(&buf);
    assert(had_overflow == false);

    printf("  PASS: report buffer overflow\n");
}

/* ======== RCB Manager Tests ======== */

static int report_count;
static void test_report_sender(const mms_information_report_t *report,
                                 void *user_data)
{
    (void)report;
    (void)user_data;
    report_count++;
}

static void test_rcb_manager_init(void)
{
    iec61850_rcb_manager_t mgr;
    iec61850_rcb_manager_init(&mgr, "LD0");
    assert(mgr.rcb_count == 0);
    assert(strcmp(mgr.ld_name, "LD0") == 0);
    iec61850_rcb_manager_destroy(&mgr);
    printf("  PASS: rcb manager init\n");
}

static void test_rcb_manager_add_and_find(void)
{
    iec61850_rcb_manager_t mgr;
    iec61850_rcb_manager_init(&mgr, "LD0");

    int idx0 = iec61850_rcb_manager_add_rcb(&mgr, "RPT001",
                                               IEC61850_RCB_BUFFERED, 64);
    assert(idx0 == 0);

    int idx1 = iec61850_rcb_manager_add_rcb(&mgr, "RPT002",
                                               IEC61850_RCB_UNBUFFERED, 0);
    assert(idx1 == 1);
    assert(mgr.rcb_count == 2);

    iec61850_rcb_t *rcb = iec61850_rcb_manager_find_rcb(&mgr, "RPT001");
    assert(rcb != NULL);
    assert(rcb->type == IEC61850_RCB_BUFFERED);

    rcb = iec61850_rcb_manager_find_rcb(&mgr, "RPT002");
    assert(rcb != NULL);
    assert(rcb->type == IEC61850_RCB_UNBUFFERED);

    rcb = iec61850_rcb_manager_find_rcb(&mgr, "NONEXIST");
    assert(rcb == NULL);

    iec61850_rcb_manager_destroy(&mgr);
    printf("  PASS: rcb manager add and find\n");
}

static void test_rcb_manager_data_change(void)
{
    iec61850_rcb_manager_t mgr;
    mms_value_t old_val, new_val;

    iec61850_rcb_manager_init(&mgr, "LD0");

    int idx = iec61850_rcb_manager_add_rcb(&mgr, "RPT_DC",
                                              IEC61850_RCB_BUFFERED, 32);
    assert(idx >= 0);

    iec61850_rcb_t *rcb = &mgr.rcbs[idx];
    rcb->attrs.trg_ops.data_change = true;

    /* Set up report sender */
    report_count = 0;
    iec61850_rcb_set_report_sender(rcb, test_report_sender, NULL);

    /* Enable */
    int ret = iec61850_rcb_enable(rcb);
    assert(ret == 0);

    /* Trigger data change */
    (void)memset(&old_val, 0, sizeof(old_val));
    (void)memset(&new_val, 0, sizeof(new_val));
    old_val.type = MMS_TYPE_BOOLEAN;
    old_val.value.boolean = false;
    new_val.type = MMS_TYPE_BOOLEAN;
    new_val.value.boolean = true;

    iec61850_rcb_manager_on_data_change(&mgr, "LD0/LN0$ST$Beh$stVal",
                                           &old_val, &new_val);
    assert(report_count == 1);

    /* Check buffer has entry */
    iec61850_report_buffer_t *buffer = iec61850_rcb_manager_get_buffer(&mgr, (uint32_t)idx);
    assert(buffer != NULL);
    assert(buffer->count == 1);

    iec61850_rcb_disable(rcb);
    iec61850_rcb_manager_destroy(&mgr);
    printf("  PASS: rcb manager data change\n");
}

static void test_rcb_manager_gi(void)
{
    iec61850_rcb_manager_t mgr;

    iec61850_rcb_manager_init(&mgr, "LD0");

    int idx = iec61850_rcb_manager_add_rcb(&mgr, "RPT_GI",
                                              IEC61850_RCB_UNBUFFERED, 0);
    assert(idx >= 0);

    iec61850_rcb_t *rcb = &mgr.rcbs[idx];
    rcb->attrs.trg_ops.general_interrogation = true;

    report_count = 0;
    iec61850_rcb_set_report_sender(rcb, test_report_sender, NULL);
    (void)iec61850_rcb_enable(rcb);

    iec61850_rcb_manager_trigger_gi(&mgr);
    assert(report_count == 1);

    (void)iec61850_rcb_disable(rcb);
    iec61850_rcb_manager_destroy(&mgr);
    printf("  PASS: rcb manager GI\n");
}

/* ======== WP-2a: Ed.2 buffer semantics ======== */

static void test_report_buffer_purge(void)
{
    iec61850_report_buffer_t buf;
    iec61850_report_entry_t out[16];
    mms_value_t val;
    uint32_t count = 0;
    uint64_t id;

    iec61850_report_buffer_init(&buf, 8);

    (void)memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;
    val.value.integer = 1;
    (void)iec61850_report_buffer_add(&buf, IEC61850_REASON_DCHG, "v", &val, 100);
    val.value.integer = 2;
    (void)iec61850_report_buffer_add(&buf, IEC61850_REASON_DCHG, "v", &val, 200);
    assert(buf.count == 2);

    /* Purge clears the entries and the overflow flag... */
    iec61850_report_buffer_purge(&buf);
    assert(buf.count == 0);
    assert(buf.overflow == false);
    assert(iec61850_report_buffer_get_entries(&buf, 0, out, &count, 16) == 0);
    assert(count == 0);

    /* ...but entry IDs stay monotonic across purges (Ed.2: unique
     * per entry for the whole RCB lifetime). */
    val.value.integer = 3;
    id = iec61850_report_buffer_add(&buf, IEC61850_REASON_DCHG, "v", &val, 300);
    assert(id == 3);

    /* Overflow flag is cleared by purge. */
    iec61850_report_buffer_init(&buf, 2);
    val.value.integer = 1;
    (void)iec61850_report_buffer_add(&buf, IEC61850_REASON_DCHG, "v", &val, 1);
    (void)iec61850_report_buffer_add(&buf, IEC61850_REASON_DCHG, "v", &val, 2);
    val.value.integer = 9;
    (void)iec61850_report_buffer_add(&buf, IEC61850_REASON_DCHG, "v", &val, 3);
    assert(buf.overflow == true);
    iec61850_report_buffer_purge(&buf);
    assert(iec61850_report_buffer_had_overflow(&buf) == false);

    printf("  PASS: report buffer purge (entry IDs monotonic across purge)\n");
}

static void test_buffer_overflow_discards_oldest(void)
{
    iec61850_report_buffer_t buf;
    iec61850_report_entry_t out[8];
    mms_value_t val;
    uint32_t count = 0;
    int i;

    iec61850_report_buffer_init(&buf, 4);
    (void)memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;

    for (i = 0; i < 6; i++) {
        val.value.integer = (int32_t)i;
        (void)iec61850_report_buffer_add(&buf, IEC61850_REASON_DCHG,
                                            "v", &val, (uint64_t)(1000 + i));
    }

    /* Bounded at capacity; the two oldest entries were discarded. */
    assert(buf.count == 4);
    assert(iec61850_report_buffer_get_entries(&buf, 0, out, &count, 8) == 0);
    assert(count == 4);
    assert(out[0].entry_id == 3);   /* ids 1 and 2 evicted */
    assert(out[3].entry_id == 6);
    assert(buf.overflow == true);   /* flagged for the next report */

    printf("  PASS: buffer overflow discards oldest (bounded)\n");
}

/* Capture sender for the BufTm aggregation tests. */
static mms_information_report_t g_agg_report;
static int g_agg_count;

static void agg_report_sender(const mms_information_report_t *report,
                               void *user_data)
{
    (void)user_data;
    g_agg_report = *report;
    g_agg_count++;
}

static void test_buftm_aggregation(void)
{
    iec61850_rcb_manager_t mgr;
    iec61850_rcb_t *rcb;
    mms_value_t val;
    int idx;

    iec61850_rcb_manager_init(&mgr, "LD0");
    idx = iec61850_rcb_manager_add_rcb(&mgr, "B1",
                                          IEC61850_RCB_BUFFERED, 16);
    assert(idx >= 0);
    rcb = &mgr.rcbs[idx];
    rcb->attrs.trg_ops.data_change = true;
    rcb->attrs.opt_flds.sequence_number = true;
    rcb->attrs.opt_flds.reason_for_inclusion = true;
    rcb->attrs.opt_flds.entry_id = true;
    rcb->attrs.buf_tm = 150U;   /* 150 ms aggregation window */

    g_agg_count = 0;
    (void)memset(&g_agg_report, 0, sizeof(g_agg_report));
    iec61850_rcb_set_report_sender(rcb, agg_report_sender, NULL);
    (void)iec61850_rcb_enable(rcb);

    (void)memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;

    /* Three changes to the same member within the window (plus one
     * to a second member): all held, no report yet. */
    val.value.integer = 10;
    iec61850_rcb_manager_on_data_change(&mgr, "LD0/A", &val, &val);
    usleep(20 * 1000);
    val.value.integer = 11;
    iec61850_rcb_manager_on_data_change(&mgr, "LD0/A", &val, &val);
    usleep(20 * 1000);
    val.value.integer = 12;
    iec61850_rcb_manager_on_data_change(&mgr, "LD0/A", &val, &val);
    usleep(20 * 1000);
    val.value.integer = 50;
    iec61850_rcb_manager_on_data_change(&mgr, "LD0/B", &val, &val);

    assert(g_agg_count == 0);   /* window still open */
    assert(mgr.buffers[idx].count == 4);

    /* Window closes: one aggregated report, deduplicated by member
     * (last value of A wins), carrying the last entry's ID. */
    usleep(200 * 1000);
    iec61850_rcb_manager_flush_reports(&mgr);

    assert(g_agg_count == 1);
    assert(g_agg_report.num_values == 2);                 /* A + B */
    assert(g_agg_report.values[0].value.integer == 12);   /* last of A */
    assert(g_agg_report.values[1].value.integer == 50);
    assert(g_agg_report.entry_id_present);
    assert(g_agg_report.entry_id == 4);
    assert(g_agg_report.reasons_present);
    assert(g_agg_report.reasons[0] == (uint8_t)IEC61850_REASON_DCHG);
    assert(rcb->attrs.sq_num == 1);        /* one report, one bump */
    assert(rcb->attrs.entry_id == 4);      /* marker = last emitted */

    (void)iec61850_rcb_disable(rcb);
    iec61850_rcb_manager_destroy(&mgr);
    printf("  PASS: BufTm aggregation (dedup by dataset member)\n");
}

static void test_buftm_zero_one_report_per_entry(void)
{
    iec61850_rcb_manager_t mgr;
    iec61850_rcb_t *rcb;
    mms_value_t val;
    int idx;

    iec61850_rcb_manager_init(&mgr, "LD0");
    idx = iec61850_rcb_manager_add_rcb(&mgr, "B1",
                                          IEC61850_RCB_BUFFERED, 16);
    assert(idx >= 0);
    rcb = &mgr.rcbs[idx];
    rcb->attrs.trg_ops.data_change = true;
    rcb->attrs.opt_flds.entry_id = true;
    rcb->attrs.buf_tm = 0U;   /* no aggregation */

    g_agg_count = 0;
    iec61850_rcb_set_report_sender(rcb, agg_report_sender, NULL);
    (void)iec61850_rcb_enable(rcb);

    (void)memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;
    for (int i = 0; i < 3; i++) {
        val.value.integer = (int32_t)i;
        iec61850_rcb_manager_on_data_change(&mgr, "LD0/A", &val, &val);
        assert(g_agg_count == (i + 1));   /* delivered immediately */
        assert(g_agg_report.entry_id == (uint64_t)(i + 1));
    }

    assert(rcb->attrs.sq_num == 3);
    assert(rcb->attrs.entry_id == 3);

    (void)iec61850_rcb_disable(rcb);
    iec61850_rcb_manager_destroy(&mgr);
    printf("  PASS: BufTm=0 delivers one report per entry\n");
}

int main(void)
{
    printf("=== MMS Report Buffer & RCB Manager Tests ===\n");

    test_report_buffer_init();
    test_report_buffer_add_and_get();
    test_report_buffer_overflow();

    test_rcb_manager_init();
    test_rcb_manager_add_and_find();
    test_rcb_manager_data_change();
    test_rcb_manager_gi();

    test_report_buffer_purge();
    test_buffer_overflow_discards_oldest();
    test_buftm_aggregation();
    test_buftm_zero_one_report_per_entry();

    printf("All report buffer/RCB manager tests passed.\n");
    return 0;
}
