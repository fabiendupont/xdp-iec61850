/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Tests for MMS Report Buffer and RCB Manager
 */


#include "mms/mms_report.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

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

    printf("All report buffer/RCB manager tests passed.\n");
    return 0;
}
