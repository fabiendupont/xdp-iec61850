/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Tests for RCB Auto-Configuration from SCL
 */

#include "scl/scl_ied_builder.h"
#include "scl/scl_parser.h"
#include "mms/mms_report.h"
#include <stdio.h>
#include <string.h>
#include <assert.h>

static void test_auto_configure_rcbs(void)
{
    iec61850_scl_doc_t doc;
    iec61850_rcb_manager_t mgr;

    iec61850_scl_doc_init(&doc);
    iec61850_rcb_manager_init(&mgr, "LD0");

    /* Manually create SCL RCB entries (simulating SCL parse) */
    doc.rcb_count = 2;

    /* BRCB */
    (void)strncpy(doc.rcbs[0].ied_name, "IED1", IEC61850_SCL_MAX_NAME - 1);
    (void)strncpy(doc.rcbs[0].ld_inst, "LD0", IEC61850_SCL_MAX_NAME - 1);
    (void)strncpy(doc.rcbs[0].rpt_id, "BRCB01", IEC61850_SCL_MAX_NAME - 1);
    (void)strncpy(doc.rcbs[0].dataset, "DS_PROT", IEC61850_SCL_MAX_NAME - 1);
    doc.rcbs[0].buffered = true;
    doc.rcbs[0].buf_time = 100;
    doc.rcbs[0].intg_pd = 5000;
    doc.rcbs[0].trg_dchg = true;
    doc.rcbs[0].trg_qchg = true;
    doc.rcbs[0].trg_dupd = false;
    doc.rcbs[0].trg_period = true;
    doc.rcbs[0].trg_gi = true;
    doc.rcbs[0].opt_seq_num = true;
    doc.rcbs[0].opt_timestamp = true;
    doc.rcbs[0].opt_reason = true;
    doc.rcbs[0].opt_dataref = false;
    doc.rcbs[0].opt_entryid = true;
    doc.rcbs[0].opt_bufovfl = true;
    doc.rcbs[0].opt_configref = false;

    /* URCB */
    (void)strncpy(doc.rcbs[1].ied_name, "IED1", IEC61850_SCL_MAX_NAME - 1);
    (void)strncpy(doc.rcbs[1].ld_inst, "LD0", IEC61850_SCL_MAX_NAME - 1);
    (void)strncpy(doc.rcbs[1].rpt_id, "URCB01", IEC61850_SCL_MAX_NAME - 1);
    (void)strncpy(doc.rcbs[1].dataset, "DS_MEAS", IEC61850_SCL_MAX_NAME - 1);
    doc.rcbs[1].buffered = false;
    doc.rcbs[1].intg_pd = 0;
    doc.rcbs[1].trg_dchg = true;
    doc.rcbs[1].trg_gi = true;

    /* Auto-configure */
    int result = iec61850_scl_auto_configure_rcbs(&doc, &mgr);
    assert(result == 2);
    assert(mgr.rcb_count == 2);

    /* Verify BRCB */
    iec61850_rcb_t *brcb = iec61850_rcb_manager_find_rcb(&mgr, "BRCB01");
    assert(brcb != NULL);
    assert(brcb->type == IEC61850_RCB_BUFFERED);
    assert(brcb->attrs.trg_ops.data_change == true);
    assert(brcb->attrs.trg_ops.quality_change == true);
    assert(brcb->attrs.trg_ops.data_update == false);
    assert(brcb->attrs.trg_ops.integrity == true);
    assert(brcb->attrs.trg_ops.general_interrogation == true);
    assert(brcb->attrs.opt_flds.sequence_number == true);
    assert(brcb->attrs.opt_flds.entry_id == true);
    assert(brcb->attrs.opt_flds.buffer_overflow == true);
    assert(brcb->attrs.buf_tm == 100);
    assert(brcb->attrs.intg_pd == 5000);
    assert(strcmp(brcb->attrs.dat_set, "DS_PROT") == 0);

    /* Verify URCB */
    iec61850_rcb_t *urcb = iec61850_rcb_manager_find_rcb(&mgr, "URCB01");
    assert(urcb != NULL);
    assert(urcb->type == IEC61850_RCB_UNBUFFERED);
    assert(urcb->attrs.trg_ops.data_change == true);
    assert(urcb->attrs.trg_ops.general_interrogation == true);

    /* Verify buffer exists for BRCB */
    iec61850_report_buffer_t *buf = iec61850_rcb_manager_get_buffer(&mgr, 0);
    assert(buf != NULL);
    assert(buf->capacity == IEC61850_RCB_MAX_BUFFER);

    iec61850_rcb_manager_destroy(&mgr);
    printf("  PASS: auto-configure RCBs from SCL\n");
}

static void test_empty_scl(void)
{
    iec61850_scl_doc_t doc;
    iec61850_rcb_manager_t mgr;

    iec61850_scl_doc_init(&doc);
    iec61850_rcb_manager_init(&mgr, "LD0");

    int result = iec61850_scl_auto_configure_rcbs(&doc, &mgr);
    assert(result == 0);
    assert(mgr.rcb_count == 0);

    iec61850_rcb_manager_destroy(&mgr);
    printf("  PASS: empty SCL produces no RCBs\n");
}

int main(void)
{
    printf("=== RCB Auto-Configuration Tests ===\n");

    test_auto_configure_rcbs();
    test_empty_scl();

    printf("All RCB auto-config tests passed.\n");
    return 0;
}
