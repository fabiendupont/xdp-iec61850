/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for SCL RCB Auto-Configuration
 *
 * Tests: extract RCB configs from SCL, auto-create RCBs,
 * duplicate prevention, null arg validation, empty SCL,
 * data store binding, real SCD file parsing.
 *
 * License: BSD-2-Clause
 */

#include "scl/scl_rcb_config.h"
#include "scl/scl_parser.h"
#include "mms/mms_report.h"
#include "mms/mms_data_store.h"

#include <stdio.h>
#include <stdlib.h>
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

static void build_path(char *out, size_t out_size, const char *filename)
{
    const char *root = getenv("MESON_SOURCE_ROOT");
    if (root != NULL) {
        snprintf(out, out_size, "%s/tests/data/%s", root, filename);
    } else {
        snprintf(out, out_size, "tests/data/%s", filename);
    }
}

/*
 * Populate a doc with two synthetic RCB entries (BRCB + URCB).
 */
static void setup_synthetic_doc(iec61850_scl_doc_t *doc)
{
    iec61850_scl_doc_init(doc);
    doc->rcb_count = 2;

    /* BRCB */
    (void)strncpy(doc->rcbs[0].ied_name, "IED1", IEC61850_SCL_MAX_NAME - 1);
    (void)strncpy(doc->rcbs[0].ld_inst, "LD0", IEC61850_SCL_MAX_NAME - 1);
    (void)strncpy(doc->rcbs[0].rpt_id, "BRCB01", IEC61850_SCL_MAX_NAME - 1);
    (void)strncpy(doc->rcbs[0].dataset, "DS_PROT", IEC61850_SCL_MAX_NAME - 1);
    doc->rcbs[0].conf_rev = 1;
    doc->rcbs[0].buffered = true;
    doc->rcbs[0].buf_time = 100;
    doc->rcbs[0].intg_pd = 5000;
    doc->rcbs[0].trg_dchg = true;
    doc->rcbs[0].trg_qchg = true;
    doc->rcbs[0].trg_dupd = false;
    doc->rcbs[0].trg_period = true;
    doc->rcbs[0].trg_gi = true;
    doc->rcbs[0].opt_seq_num = true;
    doc->rcbs[0].opt_timestamp = true;
    doc->rcbs[0].opt_reason = true;
    doc->rcbs[0].opt_dataref = false;
    doc->rcbs[0].opt_entryid = true;
    doc->rcbs[0].opt_bufovfl = true;
    doc->rcbs[0].opt_configref = false;
    doc->rcbs[0].rpt_enabled_max = 1;

    /* URCB */
    (void)strncpy(doc->rcbs[1].ied_name, "IED1", IEC61850_SCL_MAX_NAME - 1);
    (void)strncpy(doc->rcbs[1].ld_inst, "LD0", IEC61850_SCL_MAX_NAME - 1);
    (void)strncpy(doc->rcbs[1].rpt_id, "URCB01", IEC61850_SCL_MAX_NAME - 1);
    (void)strncpy(doc->rcbs[1].dataset, "DS_MEAS", IEC61850_SCL_MAX_NAME - 1);
    doc->rcbs[1].conf_rev = 2;
    doc->rcbs[1].buffered = false;
    doc->rcbs[1].intg_pd = 0;
    doc->rcbs[1].trg_dchg = true;
    doc->rcbs[1].trg_gi = true;
    doc->rcbs[1].rpt_enabled_max = 3;
}

static void test_get_rcb_configs(void)
{
    TEST("get_rcb_configs");

    iec61850_scl_doc_t doc;
    setup_synthetic_doc(&doc);

    iec61850_scl_rcb_config_t configs[4];
    size_t count = 0;
    int ret = iec61850_scl_get_rcb_configs(&doc, configs, 4, &count);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)count, 2);

    /* Verify BRCB config */
    ASSERT_TRUE(strcmp(configs[0].rpt_id, "BRCB01") == 0);
    ASSERT_TRUE(strcmp(configs[0].dat_set, "DS_PROT") == 0);
    ASSERT_TRUE(configs[0].buffered);
    ASSERT_EQ((int)configs[0].buf_time, 100);
    ASSERT_EQ((int)configs[0].intg_pd, 5000);
    ASSERT_EQ((int)configs[0].conf_rev, 1);
    ASSERT_TRUE(configs[0].trg_ops.data_change);
    ASSERT_TRUE(configs[0].trg_ops.quality_change);
    ASSERT_TRUE(!configs[0].trg_ops.data_update);
    ASSERT_TRUE(configs[0].trg_ops.integrity);
    ASSERT_TRUE(configs[0].trg_ops.general_interrogation);
    ASSERT_TRUE(configs[0].opt_flds.sequence_number);
    ASSERT_TRUE(configs[0].opt_flds.entry_id);
    ASSERT_TRUE(configs[0].opt_flds.buffer_overflow);
    ASSERT_TRUE(!configs[0].opt_flds.data_reference);
    ASSERT_EQ((int)configs[0].rpt_enabled_max, 1);

    /* Verify URCB config */
    ASSERT_TRUE(strcmp(configs[1].rpt_id, "URCB01") == 0);
    ASSERT_TRUE(!configs[1].buffered);
    ASSERT_TRUE(configs[1].trg_ops.data_change);
    ASSERT_TRUE(configs[1].trg_ops.general_interrogation);
    ASSERT_EQ((int)configs[1].rpt_enabled_max, 3);

    PASS();
}

static void test_get_rcb_configs_limited(void)
{
    TEST("get_rcb_configs_limited");

    iec61850_scl_doc_t doc;
    setup_synthetic_doc(&doc);

    /* Only room for 1 config */
    iec61850_scl_rcb_config_t configs[1];
    size_t count = 0;
    int ret = iec61850_scl_get_rcb_configs(&doc, configs, 1, &count);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)count, 1);
    ASSERT_TRUE(strcmp(configs[0].rpt_id, "BRCB01") == 0);

    PASS();
}

static void test_auto_create_rcbs(void)
{
    TEST("auto_create_rcbs");

    iec61850_scl_doc_t doc;
    setup_synthetic_doc(&doc);

    iec61850_rcb_manager_t mgr;
    iec61850_rcb_manager_init(&mgr, "LD0");

    int result = iec61850_scl_auto_create_rcbs(&doc, &mgr, NULL);
    ASSERT_EQ(result, 2);
    ASSERT_EQ((int)mgr.rcb_count, 2);

    /* Verify BRCB */
    iec61850_rcb_t *brcb = iec61850_rcb_manager_find_rcb(&mgr, "BRCB01");
    ASSERT_TRUE(brcb != NULL);
    ASSERT_EQ((int)brcb->type, (int)IEC61850_RCB_BUFFERED);
    ASSERT_TRUE(brcb->attrs.trg_ops.data_change);
    ASSERT_TRUE(brcb->attrs.trg_ops.quality_change);
    ASSERT_TRUE(!brcb->attrs.trg_ops.data_update);
    ASSERT_TRUE(brcb->attrs.trg_ops.integrity);
    ASSERT_TRUE(brcb->attrs.trg_ops.general_interrogation);
    ASSERT_TRUE(brcb->attrs.opt_flds.sequence_number);
    ASSERT_TRUE(brcb->attrs.opt_flds.entry_id);
    ASSERT_TRUE(brcb->attrs.opt_flds.buffer_overflow);
    ASSERT_EQ((int)brcb->attrs.buf_tm, 100);
    ASSERT_EQ((int)brcb->attrs.intg_pd, 5000);
    ASSERT_EQ((int)brcb->attrs.conf_rev, 1);
    ASSERT_TRUE(strcmp(brcb->attrs.dat_set, "DS_PROT") == 0);

    /* Verify URCB */
    iec61850_rcb_t *urcb = iec61850_rcb_manager_find_rcb(&mgr, "URCB01");
    ASSERT_TRUE(urcb != NULL);
    ASSERT_EQ((int)urcb->type, (int)IEC61850_RCB_UNBUFFERED);
    ASSERT_TRUE(urcb->attrs.trg_ops.data_change);
    ASSERT_TRUE(urcb->attrs.trg_ops.general_interrogation);
    ASSERT_EQ((int)urcb->attrs.conf_rev, 2);

    /* Verify buffer exists for BRCB */
    iec61850_report_buffer_t *buf = iec61850_rcb_manager_get_buffer(&mgr, 0);
    ASSERT_TRUE(buf != NULL);
    ASSERT_EQ((int)buf->capacity, (int)IEC61850_RCB_MAX_BUFFER);

    iec61850_rcb_manager_destroy(&mgr);
    PASS();
}

static void test_auto_create_with_data_store(void)
{
    TEST("auto_create_with_data_store");

    iec61850_scl_doc_t doc;
    setup_synthetic_doc(&doc);

    iec61850_rcb_manager_t mgr;
    iec61850_rcb_manager_init(&mgr, "LD0");

    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);

    int result = iec61850_scl_auto_create_rcbs(&doc, &mgr, &ds);
    ASSERT_EQ(result, 2);

    /* Verify data_store is attached to RCBs */
    ASSERT_TRUE(mgr.rcbs[0].data_store == &ds);
    ASSERT_TRUE(mgr.rcbs[1].data_store == &ds);

    iec61850_mms_ds_destroy(&ds);
    iec61850_rcb_manager_destroy(&mgr);
    PASS();
}

static void test_auto_create_empty_scl(void)
{
    TEST("auto_create_empty_scl");

    iec61850_scl_doc_t doc;
    iec61850_scl_doc_init(&doc);

    iec61850_rcb_manager_t mgr;
    iec61850_rcb_manager_init(&mgr, "LD0");

    int result = iec61850_scl_auto_create_rcbs(&doc, &mgr, NULL);
    ASSERT_EQ(result, 0);
    ASSERT_EQ((int)mgr.rcb_count, 0);

    iec61850_rcb_manager_destroy(&mgr);
    PASS();
}

static void test_null_args(void)
{
    TEST("null_args");

    iec61850_scl_doc_t doc;
    iec61850_scl_doc_init(&doc);
    iec61850_rcb_manager_t mgr;
    iec61850_rcb_manager_init(&mgr, "LD0");
    iec61850_scl_rcb_config_t configs[4];
    size_t count = 0;

    /* get_rcb_configs null args */
    ASSERT_TRUE(iec61850_scl_get_rcb_configs(NULL, configs, 4, &count) != 0);
    ASSERT_TRUE(iec61850_scl_get_rcb_configs(&doc, NULL, 4, &count) != 0);
    ASSERT_TRUE(iec61850_scl_get_rcb_configs(&doc, configs, 4, NULL) != 0);

    /* auto_create_rcbs null args */
    ASSERT_TRUE(iec61850_scl_auto_create_rcbs(NULL, &mgr, NULL) < 0);
    ASSERT_TRUE(iec61850_scl_auto_create_rcbs(&doc, NULL, NULL) < 0);

    iec61850_rcb_manager_destroy(&mgr);
    PASS();
}

static void test_duplicate_prevention(void)
{
    TEST("duplicate_prevention");

    iec61850_scl_doc_t doc;
    setup_synthetic_doc(&doc);

    iec61850_rcb_manager_t mgr;
    iec61850_rcb_manager_init(&mgr, "LD0");

    /* Create RCBs once */
    int result1 = iec61850_scl_auto_create_rcbs(&doc, &mgr, NULL);
    ASSERT_EQ(result1, 2);
    ASSERT_EQ((int)mgr.rcb_count, 2);

    /* Create again -- duplicates should be skipped */
    int result2 = iec61850_scl_auto_create_rcbs(&doc, &mgr, NULL);
    ASSERT_EQ(result2, 0);
    ASSERT_EQ((int)mgr.rcb_count, 2);

    iec61850_rcb_manager_destroy(&mgr);
    PASS();
}

static void test_parse_scd_and_create_rcbs(void)
{
    TEST("parse_scd_and_create_rcbs");

    char path[512];
    build_path(path, sizeof(path), "test.scd");

    iec61850_scl_doc_t doc;
    iec61850_scl_doc_init(&doc);
    int ret = iec61850_scl_parse_file(path, "IED1", &doc);
    ASSERT_EQ(ret, 0);

    /* test.scd has URCB01 and BRCB01 */
    ASSERT_TRUE(doc.rcb_count >= 2);

    iec61850_rcb_manager_t mgr;
    iec61850_rcb_manager_init(&mgr, "LD0");

    int result = iec61850_scl_auto_create_rcbs(&doc, &mgr, NULL);
    ASSERT_TRUE(result >= 2);

    /* Verify URCB01 from real SCD */
    iec61850_rcb_t *urcb = iec61850_rcb_manager_find_rcb(&mgr, "URCB01");
    ASSERT_TRUE(urcb != NULL);
    ASSERT_EQ((int)urcb->type, (int)IEC61850_RCB_UNBUFFERED);
    ASSERT_TRUE(urcb->attrs.trg_ops.data_change);
    ASSERT_TRUE(urcb->attrs.trg_ops.quality_change);
    ASSERT_TRUE(!urcb->attrs.trg_ops.data_update);
    ASSERT_TRUE(urcb->attrs.trg_ops.general_interrogation);
    ASSERT_TRUE(urcb->attrs.opt_flds.sequence_number);
    ASSERT_TRUE(urcb->attrs.opt_flds.report_timestamp);
    ASSERT_TRUE(urcb->attrs.opt_flds.reason_for_inclusion);
    ASSERT_TRUE(!urcb->attrs.opt_flds.data_reference);
    ASSERT_TRUE(strcmp(urcb->attrs.dat_set, "DS1") == 0);

    /* Verify BRCB01 from real SCD */
    iec61850_rcb_t *brcb = iec61850_rcb_manager_find_rcb(&mgr, "BRCB01");
    ASSERT_TRUE(brcb != NULL);
    ASSERT_EQ((int)brcb->type, (int)IEC61850_RCB_BUFFERED);
    ASSERT_EQ((int)brcb->attrs.buf_tm, 500);
    ASSERT_EQ((int)brcb->attrs.intg_pd, 10000);
    ASSERT_TRUE(brcb->attrs.trg_ops.data_change);
    ASSERT_TRUE(brcb->attrs.trg_ops.quality_change);
    ASSERT_TRUE(brcb->attrs.trg_ops.data_update);
    ASSERT_TRUE(brcb->attrs.trg_ops.integrity);
    ASSERT_TRUE(brcb->attrs.trg_ops.general_interrogation);
    ASSERT_TRUE(brcb->attrs.opt_flds.entry_id);
    ASSERT_TRUE(brcb->attrs.opt_flds.buffer_overflow);
    ASSERT_TRUE(brcb->attrs.opt_flds.config_ref);

    iec61850_rcb_manager_destroy(&mgr);
    PASS();
}

static void test_get_configs_from_scd(void)
{
    TEST("get_configs_from_scd");

    char path[512];
    build_path(path, sizeof(path), "test.scd");

    iec61850_scl_doc_t doc;
    iec61850_scl_doc_init(&doc);
    int ret = iec61850_scl_parse_file(path, "IED1", &doc);
    ASSERT_EQ(ret, 0);

    iec61850_scl_rcb_config_t configs[8];
    size_t count = 0;
    ret = iec61850_scl_get_rcb_configs(&doc, configs, 8, &count);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(count >= 2);

    /* Find BRCB01 in configs */
    bool found_brcb = false;
    bool found_urcb = false;
    for (size_t i = 0; i < count; i++) {
        if (strcmp(configs[i].rpt_id, "BRCB01") == 0) {
            found_brcb = true;
            ASSERT_TRUE(configs[i].buffered);
            ASSERT_EQ((int)configs[i].intg_pd, 10000);
            ASSERT_TRUE(strcmp(configs[i].dat_set, "DS1") == 0);
        }
        if (strcmp(configs[i].rpt_id, "URCB01") == 0) {
            found_urcb = true;
            ASSERT_TRUE(!configs[i].buffered);
        }
    }
    ASSERT_TRUE(found_brcb);
    ASSERT_TRUE(found_urcb);

    PASS();
}

/* WP-6e: RCB auto-configuration works from an IID (no Communication
 * section) document as well. */
static void test_parse_iid_and_create_rcbs(void)
{
    TEST("parse_iid_and_create_rcbs");

    char path[512];
    build_path(path, sizeof(path), "test.iid");

    iec61850_scl_doc_t doc;
    iec61850_scl_doc_init(&doc);
    int ret = iec61850_scl_parse_file(path, "IEDA", &doc);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)doc.profile, (int)IEC61850_SCL_PROFILE_IID);

    iec61850_rcb_manager_t mgr;
    iec61850_rcb_manager_init(&mgr, "LD0");

    int result = iec61850_scl_auto_create_rcbs(&doc, &mgr, NULL);
    ASSERT_EQ(result, 1);

    iec61850_rcb_t *urcb = iec61850_rcb_manager_find_rcb(&mgr, "URCB_A");
    ASSERT_TRUE(urcb != NULL);
    ASSERT_EQ((int)urcb->type, (int)IEC61850_RCB_UNBUFFERED);
    ASSERT_TRUE(urcb->attrs.trg_ops.data_change);
    ASSERT_TRUE(urcb->attrs.trg_ops.quality_change);
    ASSERT_TRUE(urcb->attrs.trg_ops.integrity);
    ASSERT_TRUE(urcb->attrs.trg_ops.general_interrogation);
    ASSERT_TRUE(strcmp(urcb->attrs.dat_set, "DS_LEAF") == 0);

    iec61850_rcb_manager_destroy(&mgr);
    PASS();
}

int main(void)
{
    printf("\n=== SCL RCB Auto-Configuration Tests ===\n");

    test_get_rcb_configs();
    test_get_rcb_configs_limited();
    test_auto_create_rcbs();
    test_auto_create_with_data_store();
    test_auto_create_empty_scl();
    test_null_args();
    test_duplicate_prevention();
    test_parse_scd_and_create_rcbs();
    test_get_configs_from_scd();
    test_parse_iid_and_create_rcbs();

    printf("\n=== Test Summary ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
