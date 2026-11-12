/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for SCL IED Builder
 *
 * Tests: build IED model from SCL, verify LD/LN/DO/DA counts,
 * CDC factory produced correct data objects, path-based attribute
 * lookup, RCB auto-configuration.
 *
 * License: BSD-2-Clause
 */

#include "scl/scl_ied_builder.h"
#include "scl/scl_parser.h"
#include "ied/ied_data_model.h"
#include "mms/mms_report.h"

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

static iec61850_scl_doc_t g_doc;
static bool g_doc_loaded = false;

static void load_test_doc(void)
{
    if (g_doc_loaded) { return; }
    char path[512];
    build_path(path, sizeof(path), "test.scd");
    iec61850_scl_doc_init(&g_doc);
    if (iec61850_scl_parse_file(path, "IED1", &g_doc) == 0) {
        g_doc_loaded = true;
    }
}

/* ========================================================================
 * Build IED Model
 * ======================================================================== */

static void test_build_ied_model(void)
{
    TEST("build_ied_model");
    load_test_doc();
    ASSERT_TRUE(g_doc_loaded);

    iec61850_ied_model_t model;
    ASSERT_EQ(iec61850_scl_build_ied_model(&g_doc, &model), 0);
    ASSERT_TRUE(strcmp(model.ied_name, "IED1") == 0);
    ASSERT_TRUE(model.ld_count > 0);

    iec61850_ied_model_destroy(&model);
    PASS();
}

static void test_ld_count(void)
{
    TEST("ld_count");
    load_test_doc();

    iec61850_ied_model_t model;
    iec61850_scl_build_ied_model(&g_doc, &model);

    /* test.scd has 1 LD: LD0 */
    ASSERT_EQ((int)iec61850_ied_model_count_ld(&model), 1);

    iec61850_logical_device_t *ld = iec61850_ied_model_find_ld(&model, "LD0");
    ASSERT_TRUE(ld != NULL);

    iec61850_ied_model_destroy(&model);
    PASS();
}

static void test_ln_count(void)
{
    TEST("ln_count");
    load_test_doc();

    iec61850_ied_model_t model;
    iec61850_scl_build_ied_model(&g_doc, &model);

    /* LD0 has LLN0, LPHD1, XCBR1, MMXU1 = 4 LNs */
    ASSERT_TRUE(iec61850_ied_model_count_ln(&model) >= 4);

    iec61850_ied_model_destroy(&model);
    PASS();
}

static void test_xcbr_data_objects(void)
{
    TEST("xcbr_data_objects");
    load_test_doc();

    iec61850_ied_model_t model;
    iec61850_scl_build_ied_model(&g_doc, &model);

    iec61850_logical_device_t *ld = iec61850_ied_model_find_ld(&model, "LD0");
    ASSERT_TRUE(ld != NULL);

    /* Find XCBR1 (the builder creates LN with name = prefix+class+inst) */
    iec61850_logical_node_t *xcbr = NULL;
    for (size_t i = 0; i < ld->ln_count; i++) {
        if (strcmp(ld->logical_nodes[i]->ln_class, "XCBR") == 0) {
            xcbr = ld->logical_nodes[i];
            break;
        }
    }
    ASSERT_TRUE(xcbr != NULL);

    /* XCBR should have Pos (DPC), BlkOpn (SPS), BlkCls (SPS), Beh (INS) */
    ASSERT_TRUE(xcbr->do_count >= 4);

    iec61850_data_object_t *pos = iec61850_ln_find_do(xcbr, "Pos");
    ASSERT_TRUE(pos != NULL);
    ASSERT_EQ((int)pos->cdc, (int)IEC61850_CDC_DPC);

    iec61850_data_object_t *beh = iec61850_ln_find_do(xcbr, "Beh");
    ASSERT_TRUE(beh != NULL);
    ASSERT_EQ((int)beh->cdc, (int)IEC61850_CDC_INS);

    iec61850_ied_model_destroy(&model);
    PASS();
}

static void test_mmxu_data_objects(void)
{
    TEST("mmxu_data_objects");
    load_test_doc();

    iec61850_ied_model_t model;
    iec61850_scl_build_ied_model(&g_doc, &model);

    iec61850_logical_device_t *ld = iec61850_ied_model_find_ld(&model, "LD0");
    ASSERT_TRUE(ld != NULL);

    iec61850_logical_node_t *mmxu = NULL;
    for (size_t i = 0; i < ld->ln_count; i++) {
        if (strcmp(ld->logical_nodes[i]->ln_class, "MMXU") == 0) {
            mmxu = ld->logical_nodes[i];
            break;
        }
    }
    ASSERT_TRUE(mmxu != NULL);

    /* MMXU should have TotW, TotVAr, TotVA, Hz (all MV) */
    ASSERT_TRUE(mmxu->do_count >= 4);

    iec61850_data_object_t *totw = iec61850_ln_find_do(mmxu, "TotW");
    ASSERT_TRUE(totw != NULL);
    ASSERT_EQ((int)totw->cdc, (int)IEC61850_CDC_MV);

    iec61850_ied_model_destroy(&model);
    PASS();
}

static void test_statistics(void)
{
    TEST("statistics");
    load_test_doc();

    iec61850_ied_model_t model;
    iec61850_scl_build_ied_model(&g_doc, &model);

    size_t ld = iec61850_ied_model_count_ld(&model);
    size_t ln = iec61850_ied_model_count_ln(&model);
    size_t dobj = iec61850_ied_model_count_do(&model);
    size_t da = iec61850_ied_model_count_da(&model);

    printf("(LD=%d LN=%d DO=%d DA=%d) ", (int)ld, (int)ln, (int)dobj, (int)da);

    ASSERT_TRUE(ld >= 1);
    ASSERT_TRUE(ln >= 4);
    ASSERT_TRUE(dobj >= 10);
    ASSERT_TRUE(da >= 20);

    iec61850_ied_model_destroy(&model);
    PASS();
}

/* ========================================================================
 * NULL Arguments
 * ======================================================================== */

static void test_build_null_args(void)
{
    TEST("build_null_args");
    iec61850_ied_model_t model;
    ASSERT_TRUE(iec61850_scl_build_ied_model(NULL, &model) != 0);
    ASSERT_TRUE(iec61850_scl_build_ied_model(&g_doc, NULL) != 0);
    PASS();
}

/* ========================================================================
 * RCB Auto-Configuration
 * ======================================================================== */

static void test_rcb_auto_config(void)
{
    TEST("rcb_auto_config");
    load_test_doc();

    iec61850_rcb_manager_t mgr;
    iec61850_rcb_manager_init(&mgr, "LD0");

    int count = iec61850_scl_auto_configure_rcbs(&g_doc, &mgr);
    ASSERT_TRUE(count >= 2);  /* URCB01 + BRCB01 */

    /* Check URCB */
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

    /* Check BRCB */
    iec61850_rcb_t *brcb = iec61850_rcb_manager_find_rcb(&mgr, "BRCB01");
    ASSERT_TRUE(brcb != NULL);
    ASSERT_EQ((int)brcb->type, (int)IEC61850_RCB_BUFFERED);
    ASSERT_TRUE(brcb->attrs.trg_ops.data_change);
    ASSERT_TRUE(brcb->attrs.trg_ops.data_update);
    ASSERT_TRUE(brcb->attrs.trg_ops.integrity);
    ASSERT_TRUE(brcb->attrs.opt_flds.entry_id);
    ASSERT_TRUE(brcb->attrs.opt_flds.buffer_overflow);
    ASSERT_EQ((int)brcb->attrs.buf_tm, 500);
    ASSERT_EQ((int)brcb->attrs.intg_pd, 10000);
    ASSERT_TRUE(strcmp(brcb->attrs.dat_set, "DS1") == 0);

    iec61850_rcb_manager_destroy(&mgr);
    PASS();
}

static void test_rcb_auto_config_null_args(void)
{
    TEST("rcb_auto_config_null_args");
    iec61850_rcb_manager_t mgr;
    iec61850_rcb_manager_init(&mgr, "LD0");

    ASSERT_TRUE(iec61850_scl_auto_configure_rcbs(NULL, &mgr) < 0);
    ASSERT_TRUE(iec61850_scl_auto_configure_rcbs(&g_doc, NULL) < 0);

    iec61850_rcb_manager_destroy(&mgr);
    PASS();
}

/* ========================================================================
 * IED → MMS Naming Bridge
 * ======================================================================== */

static void test_mms_bridge_creates_domain(void)
{
    TEST("mms_bridge_creates_domain");
    load_test_doc();

    iec61850_ied_model_t model;
    iec61850_scl_build_ied_model(&g_doc, &model);

    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);

    int count = iec61850_ied_model_register_mms(&model, &ds);
    ASSERT_TRUE(count > 0);

    /* Domain should be IEDName + LDInst = "IED1LD0" */
    ASSERT_TRUE(iec61850_mms_ds_domain_exists(&ds, "IED1LD0"));

    iec61850_mms_ds_destroy(&ds);
    iec61850_ied_model_destroy(&model);
    PASS();
}

static void test_mms_bridge_variable_naming(void)
{
    TEST("mms_bridge_variable_naming");
    load_test_doc();

    iec61850_ied_model_t model;
    iec61850_scl_build_ied_model(&g_doc, &model);

    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);

    int count = iec61850_ied_model_register_mms(&model, &ds);
    printf("(registered %d vars) ", count);
    ASSERT_TRUE(count > 0);

    /* XCBR1 Pos DPC should produce: XCBR1$ST$Pos$stVal */
    ASSERT_TRUE(iec61850_mms_ds_variable_exists(&ds, "IED1LD0", "XCBR1$ST$Pos$stVal"));
    ASSERT_TRUE(iec61850_mms_ds_variable_exists(&ds, "IED1LD0", "XCBR1$ST$Pos$q"));
    ASSERT_TRUE(iec61850_mms_ds_variable_exists(&ds, "IED1LD0", "XCBR1$ST$Pos$t"));

    /* XCBR1 Beh INS */
    ASSERT_TRUE(iec61850_mms_ds_variable_exists(&ds, "IED1LD0", "XCBR1$ST$Beh$stVal"));

    /* LLN0 (LN class=LLN0, inst="", so LN name = "LLN0") */
    ASSERT_TRUE(iec61850_mms_ds_variable_exists(&ds, "IED1LD0", "LLN0$ST$Beh$stVal"));

    iec61850_mms_ds_destroy(&ds);
    iec61850_ied_model_destroy(&model);
    PASS();
}

static void test_mms_bridge_variable_types(void)
{
    TEST("mms_bridge_variable_types");
    load_test_doc();

    iec61850_ied_model_t model;
    iec61850_scl_build_ied_model(&g_doc, &model);

    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);

    iec61850_ied_model_register_mms(&model, &ds);

    /* Read a variable and check its type */
    mms_value_t val;
    int ret = iec61850_mms_ds_read_variable(&ds, "IED1LD0",
                                              "XCBR1$ST$Pos$stVal", &val);
    ASSERT_EQ(ret, (int)IEC61850_MMS_DS_OK);

    /* stVal for DPC is DBPOS → BIT_STRING in MMS */
    mms_variable_access_attrs_t attrs;
    ret = iec61850_mms_ds_get_variable_attrs(&ds, "IED1LD0",
                                               "XCBR1$ST$Pos$stVal", &attrs);
    ASSERT_EQ(ret, (int)IEC61850_MMS_DS_OK);
    ASSERT_EQ((int)attrs.type, (int)MMS_TYPE_BIT_STRING);

    iec61850_mms_ds_destroy(&ds);
    iec61850_ied_model_destroy(&model);
    PASS();
}

static void test_mms_bridge_variable_count(void)
{
    TEST("mms_bridge_variable_count");
    load_test_doc();

    iec61850_ied_model_t model;
    iec61850_scl_build_ied_model(&g_doc, &model);

    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);

    int count = iec61850_ied_model_register_mms(&model, &ds);

    /* Total DA count from IED model should match registered count */
    size_t da_count = iec61850_ied_model_count_da(&model);
    printf("(DA=%d MMS=%d) ", (int)da_count, count);
    ASSERT_EQ(count, (int)da_count);

    iec61850_mms_ds_destroy(&ds);
    iec61850_ied_model_destroy(&model);
    PASS();
}

static void test_mms_bridge_null_args(void)
{
    TEST("mms_bridge_null_args");
    iec61850_ied_model_t model;
    iec61850_mms_data_store_t ds;

    ASSERT_TRUE(iec61850_ied_model_register_mms(NULL, &ds) < 0);
    ASSERT_TRUE(iec61850_ied_model_register_mms(&model, NULL) < 0);
    PASS();
}

/* ========================================================================
 * Additional LN Class Coverage
 * ======================================================================== */

static void test_additional_ln_classes(void)
{
    TEST("additional_ln_classes");

    /* Build a synthetic SCL doc with additional LN classes to test
     * populate_ln_with_standard_dos() branches for XSWI, PTOC, CSWI, GGIO */
    iec61850_scl_doc_t doc;
    iec61850_scl_doc_init(&doc);

    strncpy(doc.ied_name, "IED2", sizeof(doc.ied_name) - 1);

    /* Set up one LD with XSWI, PTOC, CSWI, GGIO, and an unknown class */
    doc.ld_count = 1;
    iec61850_scl_ld_t *ld = &doc.lds[0];
    memset(ld, 0, sizeof(*ld));
    strncpy(ld->inst, "LD0", sizeof(ld->inst) - 1);
    ld->ln_count = 5;

    strncpy(ld->lns[0].ln_class, "XSWI", sizeof(ld->lns[0].ln_class) - 1);
    strncpy(ld->lns[0].ln_inst, "1", sizeof(ld->lns[0].ln_inst) - 1);

    strncpy(ld->lns[1].ln_class, "PTOC", sizeof(ld->lns[1].ln_class) - 1);
    strncpy(ld->lns[1].ln_inst, "1", sizeof(ld->lns[1].ln_inst) - 1);

    strncpy(ld->lns[2].ln_class, "CSWI", sizeof(ld->lns[2].ln_class) - 1);
    strncpy(ld->lns[2].ln_inst, "1", sizeof(ld->lns[2].ln_inst) - 1);

    strncpy(ld->lns[3].ln_class, "GGIO", sizeof(ld->lns[3].ln_class) - 1);
    strncpy(ld->lns[3].ln_inst, "1", sizeof(ld->lns[3].ln_inst) - 1);

    strncpy(ld->lns[4].ln_class, "UNKN", sizeof(ld->lns[4].ln_class) - 1);
    strncpy(ld->lns[4].ln_inst, "1", sizeof(ld->lns[4].ln_inst) - 1);

    iec61850_ied_model_t model;
    ASSERT_EQ(iec61850_scl_build_ied_model(&doc, &model), 0);
    ASSERT_TRUE(strcmp(model.ied_name, "IED2") == 0);

    iec61850_logical_device_t *found_ld = iec61850_ied_model_find_ld(&model, "LD0");
    ASSERT_TRUE(found_ld != NULL);
    ASSERT_EQ((int)found_ld->ln_count, 5);

    /* Verify XSWI has Pos (DPC) + Beh (INS) */
    iec61850_logical_node_t *xswi = NULL;
    iec61850_logical_node_t *ptoc = NULL;
    iec61850_logical_node_t *cswi = NULL;
    iec61850_logical_node_t *ggio = NULL;
    iec61850_logical_node_t *unkn = NULL;
    for (size_t i = 0; i < found_ld->ln_count; i++) {
        if (strcmp(found_ld->logical_nodes[i]->ln_class, "XSWI") == 0)
            xswi = found_ld->logical_nodes[i];
        else if (strcmp(found_ld->logical_nodes[i]->ln_class, "PTOC") == 0)
            ptoc = found_ld->logical_nodes[i];
        else if (strcmp(found_ld->logical_nodes[i]->ln_class, "CSWI") == 0)
            cswi = found_ld->logical_nodes[i];
        else if (strcmp(found_ld->logical_nodes[i]->ln_class, "GGIO") == 0)
            ggio = found_ld->logical_nodes[i];
        else if (strcmp(found_ld->logical_nodes[i]->ln_class, "UNKN") == 0)
            unkn = found_ld->logical_nodes[i];
    }

    ASSERT_TRUE(xswi != NULL);
    ASSERT_TRUE(xswi->do_count >= 2);
    ASSERT_TRUE(iec61850_ln_find_do(xswi, "Pos") != NULL);
    ASSERT_TRUE(iec61850_ln_find_do(xswi, "Beh") != NULL);

    ASSERT_TRUE(ptoc != NULL);
    ASSERT_TRUE(ptoc->do_count >= 3);
    ASSERT_TRUE(iec61850_ln_find_do(ptoc, "Op") != NULL);
    ASSERT_TRUE(iec61850_ln_find_do(ptoc, "Str") != NULL);
    ASSERT_TRUE(iec61850_ln_find_do(ptoc, "Beh") != NULL);

    ASSERT_TRUE(cswi != NULL);
    ASSERT_TRUE(cswi->do_count >= 2);
    ASSERT_TRUE(iec61850_ln_find_do(cswi, "Pos") != NULL);
    ASSERT_TRUE(iec61850_ln_find_do(cswi, "Beh") != NULL);

    ASSERT_TRUE(ggio != NULL);
    ASSERT_TRUE(ggio->do_count >= 3);
    ASSERT_TRUE(iec61850_ln_find_do(ggio, "Ind1") != NULL);
    ASSERT_TRUE(iec61850_ln_find_do(ggio, "Ind2") != NULL);
    ASSERT_TRUE(iec61850_ln_find_do(ggio, "SPCSO1") != NULL);

    /* Unknown LN class should have 0 pre-populated DOs */
    ASSERT_TRUE(unkn != NULL);
    ASSERT_EQ((int)unkn->do_count, 0);

    iec61850_ied_model_destroy(&model);
    PASS();
}

int main(void)
{
    printf("\n=== SCL IED Builder Tests ===\n");

    printf("\n--- Build IED Model ---\n");
    test_build_ied_model();
    test_ld_count();
    test_ln_count();

    printf("\n--- Data Object Verification ---\n");
    test_xcbr_data_objects();
    test_mmxu_data_objects();
    test_statistics();

    printf("\n--- Error Handling ---\n");
    test_build_null_args();

    printf("\n--- RCB Auto-Configuration ---\n");
    test_rcb_auto_config();
    test_rcb_auto_config_null_args();

    printf("\n--- IED→MMS Naming Bridge ---\n");
    test_mms_bridge_creates_domain();
    test_mms_bridge_variable_naming();
    test_mms_bridge_variable_types();
    test_mms_bridge_variable_count();
    test_mms_bridge_null_args();

    printf("\n--- Additional LN Classes ---\n");
    test_additional_ln_classes();

    printf("\n=== Test Summary ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
