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
#include "ied/model_binding.h"
#include "goose/goose_publisher.h"
#include "sv/sv_publisher.h"
#include "transport/packet_io.h"
#include "mms/mms_report.h"

#include <stdio.h>
#include <stdlib.h>
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

/* IID document with struct/SDO-heavy templates (WP-6e) */
static iec61850_scl_doc_t g_iid_doc;
static bool g_iid_loaded = false;

static void load_iid_doc(void)
{
    if (g_iid_loaded) { return; }
    char path[512];
    build_path(path, sizeof(path), "test.iid");
    iec61850_scl_doc_init(&g_iid_doc);
    if (iec61850_scl_parse_file(path, "IEDA", &g_iid_doc) == 0) {
        g_iid_loaded = true;
    }
}

static iec61850_logical_node_t *find_ln_by_class(
    iec61850_logical_device_t *ld, const char *ln_class)
{
    for (size_t i = 0; i < ld->ln_count; i++) {
        if (strcmp(ld->logical_nodes[i]->ln_class, ln_class) == 0) {
            return ld->logical_nodes[i];
        }
    }
    return NULL;
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

/* ========================================================================
 * Template-Driven Construction (WP-6e)
 * ======================================================================== */

static void test_template_driven_construction(void)
{
    TEST("template_driven_construction");
    load_iid_doc();
    ASSERT_TRUE(g_iid_loaded);

    iec61850_ied_model_t model;
    ASSERT_EQ(iec61850_scl_build_ied_model(&g_iid_doc, &model), 0);

    iec61850_logical_device_t *ld = iec61850_ied_model_find_ld(&model, "LD0");
    ASSERT_TRUE(ld != NULL);

    iec61850_logical_node_t *xcbr = find_ln_by_class(ld, "XCBR");
    ASSERT_TRUE(xcbr != NULL);

    /* Pos built from DPC_1: stVal, q, t, ctlVal,
     * origin.{orCat,orIdent} (struct expansion), ctlModel = 7 DAs */
    iec61850_data_object_t *pos = iec61850_ln_find_do(xcbr, "Pos");
    ASSERT_TRUE(pos != NULL);
    ASSERT_EQ((int)pos->cdc, (int)IEC61850_CDC_DPC);
    ASSERT_EQ((int)pos->attr_count, 7);

    iec61850_data_attribute_t *da =
        iec61850_do_find_attribute(pos, "stVal", IEC61850_FC_ST);
    ASSERT_TRUE(da != NULL);
    ASSERT_EQ((int)da->btype, (int)IEC61850_BTYPE_DBPOS);

    da = iec61850_do_find_attribute(pos, "origin.orCat", IEC61850_FC_CO);
    ASSERT_TRUE(da != NULL);
    ASSERT_EQ((int)da->btype, (int)IEC61850_BTYPE_ENUMERATED);

    da = iec61850_do_find_attribute(pos, "origin.orIdent", IEC61850_FC_CO);
    ASSERT_TRUE(da != NULL);
    ASSERT_EQ((int)da->btype, (int)IEC61850_BTYPE_OCTET_STRING);

    da = iec61850_do_find_attribute(pos, "ctlModel", IEC61850_FC_CF);
    ASSERT_TRUE(da != NULL);
    ASSERT_EQ((int)da->btype, (int)IEC61850_BTYPE_ENUMERATED);

    /* Deep dotted lookups now also resolve through
     * iec61850_ln_find_attribute() (WP-C2 flat-name fallback),
     * matching the DO attribute table used above. */
    da = iec61850_ln_find_attribute(xcbr, "Pos.origin.orCat",
                                     IEC61850_FC_CO);
    ASSERT_TRUE(da != NULL);
    ASSERT_EQ((int)da->btype, (int)IEC61850_BTYPE_ENUMERATED);

    /* MMXU: SDO flattening and nested struct expansion */
    iec61850_logical_node_t *mmxu = find_ln_by_class(ld, "MMXU");
    ASSERT_TRUE(mmxu != NULL);

    iec61850_data_object_t *phv = iec61850_ln_find_do(mmxu, "PhV");
    ASSERT_TRUE(phv != NULL);
    ASSERT_EQ((int)phv->cdc, (int)IEC61850_CDC_WYE);
    /* 3 SDOs x (cVal.mag.f, cVal.ang.f, q, t) */
    ASSERT_EQ((int)phv->attr_count, 12);

    da = iec61850_do_find_attribute(phv, "phsA.cVal.mag.f", IEC61850_FC_MX);
    ASSERT_TRUE(da != NULL);
    ASSERT_EQ((int)da->btype, (int)IEC61850_BTYPE_FLOAT32);

    da = iec61850_do_find_attribute(phv, "phsC.cVal.ang.f", IEC61850_FC_MX);
    ASSERT_TRUE(da != NULL);

    /* Same deep path through the LN walker (WP-C2) */
    da = iec61850_ln_find_attribute(mmxu, "PhV.phsA.cVal.mag.f",
                                     IEC61850_FC_MX);
    ASSERT_TRUE(da != NULL);
    ASSERT_EQ((int)da->btype, (int)IEC61850_BTYPE_FLOAT32);

    /* TotW (MV with Struct mag): flattened to mag.f */
    iec61850_data_object_t *totw = iec61850_ln_find_do(mmxu, "TotW");
    ASSERT_TRUE(totw != NULL);
    ASSERT_EQ((int)totw->cdc, (int)IEC61850_CDC_MV);
    da = iec61850_do_find_attribute(totw, "mag.f", IEC61850_FC_MX);
    ASSERT_TRUE(da != NULL);
    ASSERT_EQ((int)da->btype, (int)IEC61850_BTYPE_FLOAT32);

    iec61850_ied_model_destroy(&model);
    PASS();
}

static void test_template_mms_naming(void)
{
    TEST("template_mms_naming");
    load_iid_doc();
    ASSERT_TRUE(g_iid_loaded);

    iec61850_ied_model_t model;
    ASSERT_EQ(iec61850_scl_build_ied_model(&g_iid_doc, &model), 0);

    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);

    int count = iec61850_ied_model_register_mms(&model, &ds);
    printf("(registered %d vars) ", count);
    ASSERT_TRUE(count > 0);

    /* Domain: IEDName + LDInst */
    ASSERT_TRUE(iec61850_mms_ds_domain_exists(&ds, "IEDALD0"));

    /* Dotted template paths use the IEC 61850-8-1 '$' separator */
    ASSERT_TRUE(iec61850_mms_ds_variable_exists(&ds, "IEDALD0",
                                                 "XCBR1$ST$Pos$stVal"));
    ASSERT_TRUE(iec61850_mms_ds_variable_exists(&ds, "IEDALD0",
                                                 "XCBR1$CO$Pos$origin$orCat"));
    ASSERT_TRUE(iec61850_mms_ds_variable_exists(&ds, "IEDALD0",
                                                 "XCBR1$CO$Pos$origin$orIdent"));
    ASSERT_TRUE(iec61850_mms_ds_variable_exists(&ds, "IEDALD0",
                                                 "XCBR1$CF$Pos$ctlModel"));
    ASSERT_TRUE(iec61850_mms_ds_variable_exists(&ds, "IEDALD0",
                                                 "MMXU1$MX$TotW$mag$f"));
    ASSERT_TRUE(iec61850_mms_ds_variable_exists(&ds, "IEDALD0",
                                                 "MMXU1$MX$PhV$phsA$cVal$mag$f"));
    ASSERT_TRUE(iec61850_mms_ds_variable_exists(&ds, "IEDALD0",
                                                 "MMXU1$MX$PhV$phsC$cVal$ang$f"));

    /* Every model DA registers exactly once */
    size_t da_count = iec61850_ied_model_count_da(&model);
    ASSERT_EQ(count, (int)da_count);

    iec61850_mms_ds_destroy(&ds);
    iec61850_ied_model_destroy(&model);
    PASS();
}

static void test_scd_template_flat_mag(void)
{
    TEST("scd_template_flat_mag");
    load_test_doc();

    iec61850_ied_model_t model;
    ASSERT_EQ(iec61850_scl_build_ied_model(&g_doc, &model), 0);

    iec61850_logical_device_t *ld = iec61850_ied_model_find_ld(&model, "LD0");
    ASSERT_TRUE(ld != NULL);
    iec61850_logical_node_t *mmxu = find_ln_by_class(ld, "MMXU");
    ASSERT_TRUE(mmxu != NULL);

    /* test.scd MV_1 declares mag as a plain FLOAT32 DA */
    iec61850_data_attribute_t *da =
        iec61850_do_find_attribute(iec61850_ln_find_do(mmxu, "TotW"),
                                    "mag", IEC61850_FC_MX);
    ASSERT_TRUE(da != NULL);
    ASSERT_EQ((int)da->btype, (int)IEC61850_BTYPE_FLOAT32);

    iec61850_ied_model_destroy(&model);
    PASS();
}

static void test_unresolvable_lntype_fallback(void)
{
    TEST("unresolvable_lntype_fallback");

    /* LN references an LNodeType id that the templates do not
     * define: the builder must fall back to standard population */
    iec61850_scl_doc_t doc;
    iec61850_scl_doc_init(&doc);
    (void)strncpy(doc.ied_name, "IED3", sizeof(doc.ied_name) - 1);

    doc.ld_count = 1;
    iec61850_scl_ld_t *ld = &doc.lds[0];
    memset(ld, 0, sizeof(*ld));
    (void)strncpy(ld->inst, "LD0", sizeof(ld->inst) - 1);
    ld->ln_count = 1;
    (void)strncpy(ld->lns[0].ln_class, "XCBR", sizeof(ld->lns[0].ln_class) - 1);
    (void)strncpy(ld->lns[0].ln_inst, "1", sizeof(ld->lns[0].ln_inst) - 1);
    (void)strncpy(ld->lns[0].ln_type, "MissingType",
                  sizeof(ld->lns[0].ln_type) - 1);

    iec61850_ied_model_t model;
    ASSERT_EQ(iec61850_scl_build_ied_model(&doc, &model), 0);

    iec61850_logical_device_t *mld = iec61850_ied_model_find_ld(&model, "LD0");
    ASSERT_TRUE(mld != NULL);
    iec61850_logical_node_t *xcbr = find_ln_by_class(mld, "XCBR");
    ASSERT_TRUE(xcbr != NULL);
    ASSERT_TRUE(xcbr->do_count >= 2);
    ASSERT_TRUE(iec61850_ln_find_do(xcbr, "Pos") != NULL);

    iec61850_ied_model_destroy(&model);
    PASS();
}

/* ========================================================================
 * SCL Publisher Auto-Configuration (WP-6f)
 * ======================================================================== */

/* Mock packet I/O (counts published frames) */
static uint32_t g_frames_sent;

static int mock_send(struct packet_io *io, const void *pkt, uint32_t len)
{
    (void)io;
    (void)pkt;
    (void)len;
    g_frames_sent++;
    return 0;
}

static const struct packet_io_ops mock_io_ops = {
    .send = mock_send,
};

static struct packet_io mock_io = {
    .ops = &mock_io_ops,
};

/* Creation callbacks: embed the publishers in static storage (the
 * application owns publisher lifetime) and capture the prepared
 * configs for verification. Tests that create several publishers
 * (e.g. the whole-SDO SV pipeline) get one slot per call. */
static iec61850_goose_publisher_t g_goose_pub;
static iec61850_sv_publisher_t g_sv_pubs[4];
static iec61850_sv_config_t g_sv_cfgs[4];
static iec61850_goose_config_t g_last_goose_cfg;
static iec61850_sv_config_t g_last_sv_cfg;
static int g_goose_create_calls;
static int g_sv_create_calls;

static int test_goose_create(const iec61850_scl_goose_cb_t *cb,
                              const iec61850_goose_config_t *cfg,
                              iec61850_goose_publisher_t **out,
                              void *user_data)
{
    (void)cb;
    (void)user_data;
    g_goose_create_calls++;
    g_last_goose_cfg = *cfg;
    iec61850_goose_publisher_init(&g_goose_pub, cfg);
    iec61850_goose_publisher_set_io(&g_goose_pub, &mock_io);
    *out = &g_goose_pub;
    return 0;
}

static int test_sv_create(const iec61850_scl_sv_cb_t *cb,
                           const iec61850_sv_config_t *cfg,
                           iec61850_sv_publisher_t **out,
                           void *user_data)
{
    unsigned idx;

    (void)cb;
    (void)user_data;
    /* Bounded static storage: at most 4 SV publishers per test. */
    idx = (unsigned)g_sv_create_calls % 4U;
    g_sv_create_calls++;
    g_last_sv_cfg = *cfg;
    g_sv_cfgs[idx] = *cfg;
    iec61850_sv_publisher_init(&g_sv_pubs[idx], cfg);
    iec61850_sv_publisher_set_io(&g_sv_pubs[idx], &mock_io);
    *out = &g_sv_pubs[idx];
    return 0;
}

/* Creation callback that always fails (skip path). */
static int test_create_fail(const iec61850_scl_goose_cb_t *cb,
                             const iec61850_goose_config_t *cfg,
                             iec61850_goose_publisher_t **out,
                             void *user_data)
{
    (void)cb;
    (void)cfg;
    (void)out;
    (void)user_data;
    return -ENOMEM;
}

static void wr_bitstring(iec61850_data_attribute_t *da,
                          const uint8_t *data, size_t bit_count)
{
    mms_value_t v;
    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_BIT_STRING;
    v.value.bit_string.bit_count = bit_count;
    (void)memcpy(v.value.bit_string.data, data, (bit_count + 7U) / 8U);
    iec61850_da_set_value(da, &v);
}

static void wr_float(iec61850_data_attribute_t *da, float value)
{
    mms_value_t v;
    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_FLOATING_POINT;
    v.value.floating_point = value;
    iec61850_da_set_value(da, &v);
}

/* Full pipeline from test.scd: parse -> build model -> configure
 * publishers -> write a DA -> process -> verify the GOOSE dataset.
 *
 * gcb01 (DS1: XCBR1 Pos$stVal + Pos$q, Communication address
 * present) must bind; MSVCB01 must be skipped (its dataset
 * references the MMXU "A" data object, which the DataTypeTemplates
 * do not define). */
static void test_configure_publishers_pipeline(void)
{
    iec61850_ied_model_t model;
    iec61850_model_binding_t b;
    iec61850_scl_publisher_result_t res;
    iec61850_scl_publisher_ops_t ops;
    iec61850_logical_device_t *ld;
    iec61850_logical_node_t *xcbr;
    iec61850_data_object_t *pos;
    iec61850_data_attribute_t *stval;
    iec61850_data_attribute_t *q;
    int n;

    const uint8_t dbpos_on[1] = { 0x80 };         /* bit0, 2 bits */
    const uint8_t quality_bad[2] = { 0xC0, 0x80 };

    TEST("configure_publishers_pipeline");
    load_test_doc();
    ASSERT_TRUE(g_doc_loaded);

    ASSERT_EQ(iec61850_scl_build_ied_model(&g_doc, &model), 0);

    (void)memset(&b, 0, sizeof(b));
    ASSERT_EQ(iec61850_model_binding_init(&b, &model), 0);

    (void)memset(&ops, 0, sizeof(ops));
    ops.create_goose = test_goose_create;
    ops.create_sv = test_sv_create;
    g_goose_create_calls = 0;
    g_sv_create_calls = 0;
    g_frames_sent = 0U;

    n = iec61850_scl_configure_publishers(&g_doc, &b, &ops, &res);
    printf("(configured=%d goose=%d sv=%d skipped=%d) ",
           n, (int)res.goose_configured, (int)res.sv_configured,
           (int)res.skipped);
    ASSERT_EQ(n, 1);
    ASSERT_EQ((int)res.goose_configured, 1);
    ASSERT_EQ((int)res.sv_configured, 0);
    ASSERT_EQ((int)res.skipped, 1);
    ASSERT_EQ(g_goose_create_calls, 1);

    /* Publisher configuration from the SCL Communication section */
    ASSERT_EQ((int)g_last_goose_cfg.app_id, 1);
    ASSERT_EQ((int)g_last_goose_cfg.vlan_id, 100);
    ASSERT_EQ((int)g_last_goose_cfg.vlan_priority, 4);
    ASSERT_EQ((int)g_last_goose_cfg.time_allowed_to_live, 2000);
    ASSERT_TRUE(strcmp(g_last_goose_cfg.goose_id, "GOOSE_ID_1") == 0);
    ASSERT_TRUE(strcmp(g_last_goose_cfg.gocb_ref,
                       "IED1LD0/LLN0$GO$gcb01") == 0);
    ASSERT_TRUE(strcmp(g_last_goose_cfg.dataset,
                       "IED1LD0/LLN0$DS1") == 0);
    ASSERT_EQ((int)g_goose_pub.config.dst_mac[0], 0x01);
    ASSERT_EQ((int)g_goose_pub.config.dst_mac[1], 0x0C);
    ASSERT_EQ((int)g_goose_pub.config.dst_mac[2], 0xCD);
    ASSERT_EQ((int)g_goose_pub.config.dst_mac[3], 0x01);
    ASSERT_EQ((int)g_goose_pub.config.dst_mac[4], 0x00);
    ASSERT_EQ((int)g_goose_pub.config.dst_mac[5], 0x01);
    ASSERT_EQ((int)g_goose_pub.conf_rev, 1);

    /* Dataset members bound slot-for-slot */
    ASSERT_EQ((int)b.publisher_count, 1);
    ASSERT_EQ((int)b.publishers[0].ref_count, 2);
    ASSERT_EQ((int)b.watch_count, 2);
    ASSERT_TRUE(strcmp(b.publishers[0].refs[0].ld, "LD0") == 0);
    ASSERT_TRUE(strcmp(b.publishers[0].refs[0].ln, "XCBR1") == 0);
    ASSERT_TRUE(strcmp(b.publishers[0].refs[0].do_name, "Pos") == 0);
    ASSERT_TRUE(strcmp(b.publishers[0].refs[0].da_name, "stVal") == 0);
    ASSERT_EQ((int)b.publishers[0].refs[0].fc, (int)IEC61850_FC_ST);
    ASSERT_TRUE(strcmp(b.publishers[0].refs[1].da_name, "q") == 0);

    /* Write XCBR1 Pos$stVal and Pos$q through the model */
    ld = iec61850_ied_model_find_ld(&model, "LD0");
    ASSERT_TRUE(ld != NULL);
    xcbr = find_ln_by_class(ld, "XCBR");
    ASSERT_TRUE(xcbr != NULL);
    pos = iec61850_ln_find_do(xcbr, "Pos");
    ASSERT_TRUE(pos != NULL);
    stval = iec61850_do_find_attribute(pos, "stVal", IEC61850_FC_ST);
    q = iec61850_do_find_attribute(pos, "q", IEC61850_FC_ST);
    ASSERT_TRUE(stval != NULL);
    ASSERT_TRUE(q != NULL);

    wr_bitstring(stval, dbpos_on, 2U);
    wr_bitstring(q, quality_bad, 13U);
    ASSERT_TRUE(b.publishers[0].dirty);

    /* Fan out: one GOOSE frame carrying the full dataset */
    ASSERT_EQ(iec61850_model_binding_process(&b), 1);
    ASSERT_TRUE(!b.publishers[0].dirty);
    ASSERT_EQ(g_frames_sent, 1U);
    ASSERT_EQ(iec61850_goose_publisher_get_st_num(&g_goose_pub), 1U);
    ASSERT_EQ(iec61850_goose_publisher_get_sq_num(&g_goose_pub), 1U);
    ASSERT_EQ((int)g_goose_pub.data_count, 2);
    ASSERT_EQ((int)g_goose_pub.data[0].type, (int)GOOSE_DATA_BITSTRING);
    ASSERT_EQ((int)g_goose_pub.byte_storage[0].data[0], 0x80);
    ASSERT_EQ((int)g_goose_pub.data[1].type, (int)GOOSE_DATA_BITSTRING);
    ASSERT_EQ((int)g_goose_pub.byte_storage[1].data[0], 0xC0);

    /* Idempotent: no change, no publish */
    ASSERT_EQ(iec61850_model_binding_process(&b), 0);
    ASSERT_EQ(g_frames_sent, 1U);

    iec61850_model_binding_destroy(&b);
    iec61850_ied_model_destroy(&model);
    PASS();
}

/* Synthetic document: one GSE control block over a whole-DO dataset
 * (FCDA without daName). The whole DO expands to its ST leaf DAs
 * (stVal, q, t). */
static void build_whole_do_doc(iec61850_scl_doc_t *doc)
{
    iec61850_scl_do_type_t *dpc;
    iec61850_scl_dataset_t *ds;
    iec61850_scl_goose_cb_t *cb;

    iec61850_scl_doc_init(doc);
    (void)strncpy(doc->ied_name, "IEDW", sizeof(doc->ied_name) - 1);

    doc->ld_count = 1;
    (void)memset(&doc->lds[0], 0, sizeof(doc->lds[0]));
    (void)strncpy(doc->lds[0].inst, "LD0", sizeof(doc->lds[0].inst) - 1);
    doc->lds[0].ln_count = 1;
    (void)strncpy(doc->lds[0].lns[0].ln_class, "XCBR",
                  sizeof(doc->lds[0].lns[0].ln_class) - 1);
    (void)strncpy(doc->lds[0].lns[0].ln_inst, "1",
                  sizeof(doc->lds[0].lns[0].ln_inst) - 1);
    (void)strncpy(doc->lds[0].lns[0].ln_type, "XCBRW",
                  sizeof(doc->lds[0].lns[0].ln_type) - 1);

    (void)strncpy(doc->lnode_types[0].id, "XCBRW",
                  sizeof(doc->lnode_types[0].id) - 1);
    (void)strncpy(doc->lnode_types[0].ln_class, "XCBR",
                  sizeof(doc->lnode_types[0].ln_class) - 1);
    doc->lnode_types[0].do_count = 1;
    (void)strncpy(doc->lnode_types[0].dos[0].name, "Pos",
                  sizeof(doc->lnode_types[0].dos[0].name) - 1);
    (void)strncpy(doc->lnode_types[0].dos[0].type, "DPCW",
                  sizeof(doc->lnode_types[0].dos[0].type) - 1);
    doc->lnode_type_count = 1;

    dpc = &doc->do_types[0];
    (void)strncpy(dpc->id, "DPCW", sizeof(dpc->id) - 1);
    (void)strncpy(dpc->cdc, "DPC", sizeof(dpc->cdc) - 1);
    (void)strncpy(dpc->das[0].name, "stVal", sizeof(dpc->das[0].name) - 1);
    (void)strncpy(dpc->das[0].fc, "ST", sizeof(dpc->das[0].fc) - 1);
    (void)strncpy(dpc->das[0].btype, "Dbpos", sizeof(dpc->das[0].btype) - 1);
    (void)strncpy(dpc->das[1].name, "q", sizeof(dpc->das[1].name) - 1);
    (void)strncpy(dpc->das[1].fc, "ST", sizeof(dpc->das[1].fc) - 1);
    (void)strncpy(dpc->das[1].btype, "Quality", sizeof(dpc->das[1].btype) - 1);
    (void)strncpy(dpc->das[2].name, "t", sizeof(dpc->das[2].name) - 1);
    (void)strncpy(dpc->das[2].fc, "ST", sizeof(dpc->das[2].fc) - 1);
    (void)strncpy(dpc->das[2].btype, "Timestamp", sizeof(dpc->das[2].btype) - 1);
    (void)strncpy(dpc->das[3].name, "ctlVal", sizeof(dpc->das[3].name) - 1);
    (void)strncpy(dpc->das[3].fc, "CO", sizeof(dpc->das[3].fc) - 1);
    (void)strncpy(dpc->das[3].btype, "BOOLEAN", sizeof(dpc->das[3].btype) - 1);
    dpc->da_count = 4;
    doc->do_type_count = 1;

    ds = &doc->datasets[0];
    (void)strncpy(ds->name, "DS_WHOLE", sizeof(ds->name) - 1);
    ds->member_count = 1;
    (void)strncpy(ds->members[0].ld_inst, "LD0",
                  sizeof(ds->members[0].ld_inst) - 1);
    (void)strncpy(ds->members[0].ln_class, "XCBR",
                  sizeof(ds->members[0].ln_class) - 1);
    (void)strncpy(ds->members[0].ln_inst, "1",
                  sizeof(ds->members[0].ln_inst) - 1);
    (void)strncpy(ds->members[0].do_name, "Pos",
                  sizeof(ds->members[0].do_name) - 1);
    /* da_name left empty: whole-DO reference */
    (void)strncpy(ds->members[0].fc, "ST", sizeof(ds->members[0].fc) - 1);
    doc->dataset_count = 1;

    cb = &doc->goose_cbs[0];
    (void)strncpy(cb->ied_name, "IEDW", sizeof(cb->ied_name) - 1);
    (void)strncpy(cb->ld_inst, "LD0", sizeof(cb->ld_inst) - 1);
    (void)strncpy(cb->cb_name, "gcbW", sizeof(cb->cb_name) - 1);
    (void)strncpy(cb->dataset, "DS_WHOLE", sizeof(cb->dataset) - 1);
    (void)strncpy(cb->go_id, "GOOSE_W", sizeof(cb->go_id) - 1);
    (void)snprintf(cb->mac_address, sizeof(cb->mac_address),
                   "01-0C-CD-01-00-FF");
    cb->conf_rev = 7;
    cb->app_id = 0x22;
    cb->vlan_id = 200;
    cb->vlan_priority = 5;
    cb->min_time = 4;
    cb->max_time = 3000;
    doc->goose_cb_count = 1;
}

static void test_configure_publishers_whole_do(void)
{
    iec61850_scl_doc_t doc;
    iec61850_ied_model_t model;
    iec61850_model_binding_t b;
    iec61850_scl_publisher_result_t res;
    iec61850_scl_publisher_ops_t ops;
    iec61850_logical_device_t *ld;
    iec61850_logical_node_t *xcbr;
    iec61850_data_attribute_t *stval;
    const uint8_t dbpos_on[1] = { 0x80 };

    TEST("configure_publishers_whole_do");

    build_whole_do_doc(&doc);
    ASSERT_EQ(iec61850_scl_build_ied_model(&doc, &model), 0);

    (void)memset(&b, 0, sizeof(b));
    ASSERT_EQ(iec61850_model_binding_init(&b, &model), 0);

    (void)memset(&ops, 0, sizeof(ops));
    ops.create_goose = test_goose_create;
    g_frames_sent = 0U;

    ASSERT_EQ(iec61850_scl_configure_publishers(&doc, &b, &ops, &res), 1);
    ASSERT_EQ((int)res.goose_configured, 1);
    ASSERT_EQ((int)res.skipped, 0);

    /* Whole DO expanded to the ST leaves in template order */
    ASSERT_EQ((int)b.publishers[0].ref_count, 3);
    ASSERT_TRUE(strcmp(b.publishers[0].refs[0].da_name, "stVal") == 0);
    ASSERT_TRUE(strcmp(b.publishers[0].refs[1].da_name, "q") == 0);
    ASSERT_TRUE(strcmp(b.publishers[0].refs[2].da_name, "t") == 0);
    ASSERT_EQ((int)b.watch_count, 3);

    /* SCL values override the config defaults */
    ASSERT_EQ((int)g_last_goose_cfg.app_id, 0x22);
    ASSERT_EQ((int)g_last_goose_cfg.vlan_id, 200);
    ASSERT_EQ((int)g_last_goose_cfg.vlan_priority, 5);
    ASSERT_EQ((int)g_last_goose_cfg.time_allowed_to_live, 3000);
    ASSERT_EQ((int)g_goose_pub.conf_rev, 7);
    ASSERT_EQ((int)g_goose_pub.config.dst_mac[5], 0xFF);
    ASSERT_EQ((int)g_goose_pub.retransmit.config.t0_ms, 4);
    ASSERT_EQ((int)g_goose_pub.retransmit.config.t_max_ms, 3000);
    ASSERT_TRUE(g_goose_pub.has_retransmit);

    /* One DA change publishes the expanded dataset */
    ld = iec61850_ied_model_find_ld(&model, "LD0");
    ASSERT_TRUE(ld != NULL);
    xcbr = find_ln_by_class(ld, "XCBR");
    ASSERT_TRUE(xcbr != NULL);
    stval = iec61850_do_find_attribute(iec61850_ln_find_do(xcbr, "Pos"),
                                        "stVal", IEC61850_FC_ST);
    ASSERT_TRUE(stval != NULL);

    wr_bitstring(stval, dbpos_on, 2U);
    ASSERT_EQ(iec61850_model_binding_process(&b), 1);
    ASSERT_EQ(g_frames_sent, 1U);
    ASSERT_EQ((int)g_goose_pub.data_count, 3);
    ASSERT_EQ((int)g_goose_pub.data[0].type, (int)GOOSE_DATA_BITSTRING);
    ASSERT_EQ((int)g_goose_pub.byte_storage[0].data[0], 0x80);
    ASSERT_EQ((int)g_goose_pub.data[1].type, (int)GOOSE_DATA_BITSTRING);
    ASSERT_EQ((int)g_goose_pub.data[2].type, (int)GOOSE_DATA_UTCTIME);

    iec61850_model_binding_destroy(&b);
    iec61850_ied_model_destroy(&model);
    PASS();
}

/* Synthetic document: one SampledValue control block whose dataset
 * mixes a whole-DO FCDA (Amp — a flat SAV whose MX leaves are
 * svMag and q; the Timestamp leaf is excluded for SV) and a
 * leaf-DA FCDA (TotW mag). A second control block references a
 * whole-SDO dataset (PhV phsA): its leaves are flattened dotted
 * names ("phsA.cVal.mag.f"), which the WP-C2 path-walker fallback
 * resolves — that block now binds too (whole-SDO unlock). */
static void build_sv_doc(iec61850_scl_doc_t *doc)
{
    iec61850_scl_do_type_t *mv;
    iec61850_scl_do_type_t *sav;
    iec61850_scl_do_type_t *wye;
    iec61850_scl_do_type_t *cmv;
    iec61850_scl_da_type_t *vector;
    iec61850_scl_da_type_t *aval;
    iec61850_scl_dataset_t *ds;
    iec61850_scl_sv_cb_t *cb;

    iec61850_scl_doc_init(doc);
    (void)strncpy(doc->ied_name, "IEDS", sizeof(doc->ied_name) - 1);

    doc->ld_count = 1;
    (void)memset(&doc->lds[0], 0, sizeof(doc->lds[0]));
    (void)strncpy(doc->lds[0].inst, "LD0", sizeof(doc->lds[0].inst) - 1);
    doc->lds[0].ln_count = 1;
    (void)strncpy(doc->lds[0].lns[0].ln_class, "MMXU",
                  sizeof(doc->lds[0].lns[0].ln_class) - 1);
    (void)strncpy(doc->lds[0].lns[0].ln_inst, "1",
                  sizeof(doc->lds[0].lns[0].ln_inst) - 1);
    (void)strncpy(doc->lds[0].lns[0].ln_type, "MMXUW",
                  sizeof(doc->lds[0].lns[0].ln_type) - 1);

    (void)strncpy(doc->lnode_types[0].id, "MMXUW",
                  sizeof(doc->lnode_types[0].id) - 1);
    (void)strncpy(doc->lnode_types[0].ln_class, "MMXU",
                  sizeof(doc->lnode_types[0].ln_class) - 1);
    doc->lnode_types[0].do_count = 3;
    (void)strncpy(doc->lnode_types[0].dos[0].name, "TotW",
                  sizeof(doc->lnode_types[0].dos[0].name) - 1);
    (void)strncpy(doc->lnode_types[0].dos[0].type, "MVW",
                  sizeof(doc->lnode_types[0].dos[0].type) - 1);
    (void)strncpy(doc->lnode_types[0].dos[1].name, "Amp",
                  sizeof(doc->lnode_types[0].dos[1].name) - 1);
    (void)strncpy(doc->lnode_types[0].dos[1].type, "SAVW",
                  sizeof(doc->lnode_types[0].dos[1].type) - 1);
    (void)strncpy(doc->lnode_types[0].dos[2].name, "PhV",
                  sizeof(doc->lnode_types[0].dos[2].name) - 1);
    (void)strncpy(doc->lnode_types[0].dos[2].type, "WYEW",
                  sizeof(doc->lnode_types[0].dos[2].type) - 1);
    doc->lnode_type_count = 1;

    mv = &doc->do_types[0];
    (void)strncpy(mv->id, "MVW", sizeof(mv->id) - 1);
    (void)strncpy(mv->cdc, "MV", sizeof(mv->cdc) - 1);
    (void)strncpy(mv->das[0].name, "mag", sizeof(mv->das[0].name) - 1);
    (void)strncpy(mv->das[0].fc, "MX", sizeof(mv->das[0].fc) - 1);
    (void)strncpy(mv->das[0].btype, "FLOAT32", sizeof(mv->das[0].btype) - 1);
    (void)strncpy(mv->das[1].name, "q", sizeof(mv->das[1].name) - 1);
    (void)strncpy(mv->das[1].fc, "MX", sizeof(mv->das[1].fc) - 1);
    (void)strncpy(mv->das[1].btype, "Quality", sizeof(mv->das[1].btype) - 1);
    mv->da_count = 2;

    sav = &doc->do_types[1];
    (void)strncpy(sav->id, "SAVW", sizeof(sav->id) - 1);
    (void)strncpy(sav->cdc, "SAV", sizeof(sav->cdc) - 1);
    (void)strncpy(sav->das[0].name, "svMag", sizeof(sav->das[0].name) - 1);
    (void)strncpy(sav->das[0].fc, "MX", sizeof(sav->das[0].fc) - 1);
    (void)strncpy(sav->das[0].btype, "FLOAT32", sizeof(sav->das[0].btype) - 1);
    (void)strncpy(sav->das[1].name, "q", sizeof(sav->das[1].name) - 1);
    (void)strncpy(sav->das[1].fc, "MX", sizeof(sav->das[1].fc) - 1);
    (void)strncpy(sav->das[1].btype, "Quality", sizeof(sav->das[1].btype) - 1);
    (void)strncpy(sav->das[2].name, "t", sizeof(sav->das[2].name) - 1);
    (void)strncpy(sav->das[2].fc, "MX", sizeof(sav->das[2].fc) - 1);
    (void)strncpy(sav->das[2].btype, "Timestamp", sizeof(sav->das[2].btype) - 1);
    sav->da_count = 3;

    wye = &doc->do_types[2];
    (void)strncpy(wye->id, "WYEW", sizeof(wye->id) - 1);
    (void)strncpy(wye->cdc, "WYE", sizeof(wye->cdc) - 1);
    (void)strncpy(wye->das[0].name, "phsA", sizeof(wye->das[0].name) - 1);
    (void)strncpy(wye->das[0].type, "CMVW", sizeof(wye->das[0].type) - 1);
    wye->das[0].is_sdo = true;
    wye->da_count = 1;

    cmv = &doc->do_types[3];
    (void)strncpy(cmv->id, "CMVW", sizeof(cmv->id) - 1);
    (void)strncpy(cmv->cdc, "CMV", sizeof(cmv->cdc) - 1);
    (void)strncpy(cmv->das[0].name, "cVal", sizeof(cmv->das[0].name) - 1);
    (void)strncpy(cmv->das[0].fc, "MX", sizeof(cmv->das[0].fc) - 1);
    (void)strncpy(cmv->das[0].btype, "Struct", sizeof(cmv->das[0].btype) - 1);
    (void)strncpy(cmv->das[0].type, "VECW", sizeof(cmv->das[0].type) - 1);
    (void)strncpy(cmv->das[1].name, "q", sizeof(cmv->das[1].name) - 1);
    (void)strncpy(cmv->das[1].fc, "MX", sizeof(cmv->das[1].fc) - 1);
    (void)strncpy(cmv->das[1].btype, "Quality", sizeof(cmv->das[1].btype) - 1);
    (void)strncpy(cmv->das[2].name, "t", sizeof(cmv->das[2].name) - 1);
    (void)strncpy(cmv->das[2].fc, "MX", sizeof(cmv->das[2].fc) - 1);
    (void)strncpy(cmv->das[2].btype, "Timestamp", sizeof(cmv->das[2].btype) - 1);
    cmv->da_count = 3;
    doc->do_type_count = 4;

    vector = &doc->da_types[0];
    (void)strncpy(vector->id, "VECW", sizeof(vector->id) - 1);
    (void)strncpy(vector->bdas[0].name, "mag", sizeof(vector->bdas[0].name) - 1);
    (void)strncpy(vector->bdas[0].btype, "Struct", sizeof(vector->bdas[0].btype) - 1);
    (void)strncpy(vector->bdas[0].type, "AVW", sizeof(vector->bdas[0].type) - 1);
    (void)strncpy(vector->bdas[1].name, "ang", sizeof(vector->bdas[1].name) - 1);
    (void)strncpy(vector->bdas[1].btype, "Struct", sizeof(vector->bdas[1].btype) - 1);
    (void)strncpy(vector->bdas[1].type, "AVW", sizeof(vector->bdas[1].type) - 1);
    vector->bda_count = 2;

    aval = &doc->da_types[1];
    (void)strncpy(aval->id, "AVW", sizeof(aval->id) - 1);
    (void)strncpy(aval->bdas[0].name, "f", sizeof(aval->bdas[0].name) - 1);
    (void)strncpy(aval->bdas[0].btype, "FLOAT32", sizeof(aval->bdas[0].btype) - 1);
    aval->bda_count = 1;
    doc->da_type_count = 2;

    /* Bindable dataset: whole-DO (Amp) + leaf-DA (TotW mag) */
    ds = &doc->datasets[0];
    (void)strncpy(ds->name, "DS_SVW", sizeof(ds->name) - 1);
    ds->member_count = 2;
    /* Whole-DO reference: daName absent */
    (void)strncpy(ds->members[0].ld_inst, "LD0",
                  sizeof(ds->members[0].ld_inst) - 1);
    (void)strncpy(ds->members[0].ln_class, "MMXU",
                  sizeof(ds->members[0].ln_class) - 1);
    (void)strncpy(ds->members[0].ln_inst, "1",
                  sizeof(ds->members[0].ln_inst) - 1);
    (void)strncpy(ds->members[0].do_name, "Amp",
                  sizeof(ds->members[0].do_name) - 1);
    (void)strncpy(ds->members[0].fc, "MX", sizeof(ds->members[0].fc) - 1);
    /* Leaf-DA reference */
    (void)strncpy(ds->members[1].ld_inst, "LD0",
                  sizeof(ds->members[1].ld_inst) - 1);
    (void)strncpy(ds->members[1].ln_class, "MMXU",
                  sizeof(ds->members[1].ln_class) - 1);
    (void)strncpy(ds->members[1].ln_inst, "1",
                  sizeof(ds->members[1].ln_inst) - 1);
    (void)strncpy(ds->members[1].do_name, "TotW",
                  sizeof(ds->members[1].do_name) - 1);
    (void)strncpy(ds->members[1].da_name, "mag",
                  sizeof(ds->members[1].da_name) - 1);
    (void)strncpy(ds->members[1].fc, "MX", sizeof(ds->members[1].fc) - 1);

    /* Whole-SDO dataset: flattened dotted leaves (WP-C2 bindable) */
    ds = &doc->datasets[1];
    (void)strncpy(ds->name, "DS_SDOW", sizeof(ds->name) - 1);
    ds->member_count = 1;
    (void)strncpy(ds->members[0].ld_inst, "LD0",
                  sizeof(ds->members[0].ld_inst) - 1);
    (void)strncpy(ds->members[0].ln_class, "MMXU",
                  sizeof(ds->members[0].ln_class) - 1);
    (void)strncpy(ds->members[0].ln_inst, "1",
                  sizeof(ds->members[0].ln_inst) - 1);
    (void)strncpy(ds->members[0].do_name, "PhV",
                  sizeof(ds->members[0].do_name) - 1);
    (void)strncpy(ds->members[0].da_name, "phsA",
                  sizeof(ds->members[0].da_name) - 1);
    (void)strncpy(ds->members[0].fc, "MX", sizeof(ds->members[0].fc) - 1);
    doc->dataset_count = 2;

    cb = &doc->sv_cbs[0];
    (void)strncpy(cb->ied_name, "IEDS", sizeof(cb->ied_name) - 1);
    (void)strncpy(cb->ld_inst, "LD0", sizeof(cb->ld_inst) - 1);
    (void)strncpy(cb->cb_name, "MSVCBW", sizeof(cb->cb_name) - 1);
    (void)strncpy(cb->sv_id, "SV_W", sizeof(cb->sv_id) - 1);
    (void)strncpy(cb->dataset, "DS_SVW", sizeof(cb->dataset) - 1);
    (void)snprintf(cb->mac_address, sizeof(cb->mac_address),
                   "01-0C-CD-04-00-02");
    cb->conf_rev = 5;
    cb->app_id = 4000;
    cb->vlan_id = 100;
    cb->vlan_priority = 4;
    cb->smp_rate = 80;

    cb = &doc->sv_cbs[1];
    (void)strncpy(cb->ied_name, "IEDS", sizeof(cb->ied_name) - 1);
    (void)strncpy(cb->ld_inst, "LD0", sizeof(cb->ld_inst) - 1);
    (void)strncpy(cb->cb_name, "MSVCB_SDO", sizeof(cb->cb_name) - 1);
    (void)strncpy(cb->sv_id, "SV_SDO", sizeof(cb->sv_id) - 1);
    (void)strncpy(cb->dataset, "DS_SDOW", sizeof(cb->dataset) - 1);
    (void)snprintf(cb->mac_address, sizeof(cb->mac_address),
                   "01-0C-CD-04-00-03");
    cb->conf_rev = 1;
    cb->app_id = 4001;
    cb->smp_rate = 80;
    doc->sv_cb_count = 2;
}

static void test_configure_publishers_sv_pipeline(void)
{
    iec61850_scl_doc_t doc;
    iec61850_ied_model_t model;
    iec61850_model_binding_t b;
    iec61850_scl_publisher_result_t res;
    iec61850_scl_publisher_ops_t ops;
    iec61850_logical_device_t *ld;
    iec61850_logical_node_t *mmxu;
    iec61850_data_object_t *amp;
    iec61850_data_object_t *phv;
    iec61850_data_attribute_t *mag;
    iec61850_data_attribute_t *qual;
    iec61850_data_attribute_t *deep_mag;
    const uint8_t quality_bad[2] = { 0xC0, 0x80 };

    TEST("configure_publishers_sv_pipeline");

    build_sv_doc(&doc);
    ASSERT_EQ(iec61850_scl_build_ied_model(&doc, &model), 0);

    (void)memset(&b, 0, sizeof(b));
    ASSERT_EQ(iec61850_model_binding_init(&b, &model), 0);

    (void)memset(&ops, 0, sizeof(ops));
    ops.create_sv = test_sv_create;
    g_frames_sent = 0U;

    /* WP-C2 unlock: both MSVCBW and the previously skipped
     * MSVCB_SDO (whole-SDO dataset) bind. */
    ASSERT_EQ(iec61850_scl_configure_publishers(&doc, &b, &ops, &res), 2);
    ASSERT_EQ((int)res.sv_configured, 2);
    ASSERT_EQ((int)res.skipped, 0);
    ASSERT_EQ(g_sv_create_calls, 2);

    /* SV configuration from the SCL control block (first CB) */
    ASSERT_EQ((int)g_sv_cfgs[0].app_id, 4000);
    ASSERT_EQ((int)g_sv_cfgs[0].smp_rate, 80);
    ASSERT_EQ((int)g_sv_cfgs[0].conf_rev, 5);
    ASSERT_EQ((int)g_sv_cfgs[0].num_channels, 3);
    ASSERT_TRUE(strcmp(g_sv_cfgs[0].sv_id, "SV_W") == 0);
    ASSERT_EQ((int)g_sv_pubs[0].config.dst_mac[3], 0x04);

    /* Whole-DO Amp expanded to the SV-mappable leaves (the
     * Timestamp leaf is excluded), then the leaf-DA member. */
    ASSERT_EQ((int)b.publishers[0].ref_count, 3);
    ASSERT_TRUE(strcmp(b.publishers[0].refs[0].do_name, "Amp") == 0);
    ASSERT_TRUE(strcmp(b.publishers[0].refs[0].da_name, "svMag") == 0);
    ASSERT_TRUE(strcmp(b.publishers[0].refs[1].da_name, "q") == 0);
    ASSERT_TRUE(strcmp(b.publishers[0].refs[2].do_name, "TotW") == 0);
    ASSERT_TRUE(strcmp(b.publishers[0].refs[2].da_name, "mag") == 0);

    /* Whole-SDO expansion (MSVCB_SDO, slot 1): the flattened
     * dotted leaves under the phsA prefix, SV-mappable only (the
     * Timestamp leaf "phsA.t" is excluded). */
    ASSERT_EQ((int)b.publishers[1].ref_count, 3);
    ASSERT_TRUE(strcmp(b.publishers[1].refs[0].do_name, "PhV") == 0);
    ASSERT_TRUE(strcmp(b.publishers[1].refs[0].da_name,
                       "phsA.cVal.mag.f") == 0);
    ASSERT_TRUE(strcmp(b.publishers[1].refs[1].da_name,
                       "phsA.cVal.ang.f") == 0);
    ASSERT_TRUE(strcmp(b.publishers[1].refs[2].da_name, "phsA.q") == 0);
    ASSERT_EQ((int)b.publishers[1].refs[2].fc, (int)IEC61850_FC_MX);
    ASSERT_TRUE(b.publishers[1].pub == (void *)&g_sv_pubs[1]);
    /* 3 + 3 unique watched DAs across the two publishers */
    ASSERT_EQ((int)b.watch_count, 6);
    ASSERT_EQ((int)g_sv_cfgs[1].num_channels, 3);

    /* Write the sample magnitude and quality through the model */
    ld = iec61850_ied_model_find_ld(&model, "LD0");
    ASSERT_TRUE(ld != NULL);
    mmxu = find_ln_by_class(ld, "MMXU");
    ASSERT_TRUE(mmxu != NULL);
    amp = iec61850_ln_find_do(mmxu, "Amp");
    ASSERT_TRUE(amp != NULL);
    mag = iec61850_do_find_attribute(amp, "svMag", IEC61850_FC_MX);
    qual = iec61850_do_find_attribute(amp, "q", IEC61850_FC_MX);
    ASSERT_TRUE(mag != NULL);
    ASSERT_TRUE(qual != NULL);

    wr_float(mag, 220.5f);
    wr_bitstring(qual, quality_bad, 13U);
    ASSERT_TRUE(b.publishers[0].dirty);
    ASSERT_TRUE(!b.publishers[1].dirty);  /* different DAs */

    /* Fan out: one SV frame; channels follow the ref order */
    ASSERT_EQ(iec61850_model_binding_process(&b), 1);
    ASSERT_EQ(g_frames_sent, 1U);
    ASSERT_EQ((int)g_sv_pubs[0].sample_count, 3);
    ASSERT_EQ(g_sv_pubs[0].samples[0], 220);   /* Amp.svMag */
    ASSERT_EQ(iec61850_sv_publisher_get_smp_cnt(&g_sv_pubs[0]), 1U);
    ASSERT_EQ((int)g_sv_pubs[0].quality[1].validity, 3);  /* Amp.q */
    ASSERT_EQ((int)g_sv_pubs[0].quality[1].inconsistent, 1);

    /* WP-C2 verification: write a DEEP leaf DA of the whole-SDO
     * dataset (PhV phsA.cVal.mag.f) — previously unwatchable — and
     * process: the whole-SDO publisher fans out. */
    phv = iec61850_ln_find_do(mmxu, "PhV");
    ASSERT_TRUE(phv != NULL);
    deep_mag = iec61850_do_find_attribute(phv, "phsA.cVal.mag.f",
                                           IEC61850_FC_MX);
    ASSERT_TRUE(deep_mag != NULL);

    wr_float(deep_mag, 6350.25f);
    ASSERT_TRUE(b.publishers[1].dirty);
    ASSERT_TRUE(!b.publishers[0].dirty);

    ASSERT_EQ(iec61850_model_binding_process(&b), 1);
    ASSERT_EQ(g_frames_sent, 2U);
    ASSERT_EQ((int)g_sv_pubs[1].sample_count, 3);
    ASSERT_EQ(g_sv_pubs[1].samples[0], 6350);  /* phsA.cVal.mag.f */
    ASSERT_EQ(iec61850_sv_publisher_get_smp_cnt(&g_sv_pubs[1]), 1U);

    iec61850_model_binding_destroy(&b);
    iec61850_ied_model_destroy(&model);
    PASS();
}

/* WP-C2 unlock on the test.scd whole-SDO shape: DS_SV's whole-SDO
 * FCDAs (PhV phsA/phsB/phsC) expand against the built model's
 * flattened dotted leaves and bind. MSVCB01 itself remains skipped
 * in test_configure_publishers_pipeline() because DS_SV's 4th FCDA
 * (MMXU "A") names a DO that MMXUType does not define — a
 * parser-level -ENOENT under the all-or-nothing dataset contract,
 * unrelated to the deep-path gap. Here the dataset is derived from
 * the parsed test.scd with only that unresolvable FCDA dropped. */
static void test_configure_publishers_scd_whole_sdo(void)
{
    iec61850_scl_doc_t doc;
    iec61850_ied_model_t model;
    iec61850_model_binding_t b;
    iec61850_scl_publisher_result_t res;
    iec61850_scl_publisher_ops_t ops;
    iec61850_logical_device_t *ld;
    iec61850_logical_node_t *mmxu;
    iec61850_data_object_t *phv;
    iec61850_data_attribute_t *deep_mag;
    const iec61850_scl_dataset_t *src = NULL;
    iec61850_scl_dataset_t *ds;
    size_t src_idx = 0;
    int n;

    TEST("configure_publishers_scd_whole_sdo");
    load_test_doc();
    ASSERT_TRUE(g_doc_loaded);

    /* Locate DS_SV in the parsed document */
    for (size_t i = 0; i < g_doc.dataset_count; i++) {
        if (strcmp(g_doc.datasets[i].name, "DS_SV") == 0) {
            src = &g_doc.datasets[i];
            src_idx = i;
            break;
        }
    }
    ASSERT_TRUE(src != NULL);
    ASSERT_TRUE(src->member_count >= 3U);

    /* Derive: struct copy of the parsed document, keep the three
     * whole-SDO FCDAs, drop the unresolvable "A" FCDA, and repoint
     * MSVCB01 at the derived dataset. */
    doc = g_doc;
    ds = &doc.datasets[doc.dataset_count];
    (void)memset(ds, 0, sizeof(*ds));
    (void)strncpy(ds->name, "DS_SV_C2", sizeof(ds->name) - 1);
    ds->member_count = 3;
    for (size_t m = 0; m < 3U; m++) {
        ds->members[m] = g_doc.datasets[src_idx].members[m];
    }
    doc.dataset_count++;

    for (size_t i = 0; i < doc.sv_cb_count; i++) {
        if (strcmp(doc.sv_cbs[i].cb_name, "MSVCB01") == 0) {
            (void)strncpy(doc.sv_cbs[i].dataset, "DS_SV_C2",
                          sizeof(doc.sv_cbs[i].dataset) - 1);
        }
    }

    ASSERT_EQ(iec61850_scl_build_ied_model(&doc, &model), 0);
    (void)memset(&b, 0, sizeof(b));
    ASSERT_EQ(iec61850_model_binding_init(&b, &model), 0);

    (void)memset(&ops, 0, sizeof(ops));
    ops.create_goose = test_goose_create;
    ops.create_sv = test_sv_create;
    g_goose_create_calls = 0;
    g_sv_create_calls = 0;
    g_frames_sent = 0U;

    /* gcb01 (DS1) binds as before; MSVCB01 over the whole-SDO
     * dataset now binds too (previously skipped: every leaf under
     * the SDO was a flattened dotted name). */
    n = iec61850_scl_configure_publishers(&doc, &b, &ops, &res);
    printf("(configured=%d goose=%d sv=%d skipped=%d) ",
           n, (int)res.goose_configured, (int)res.sv_configured,
           (int)res.skipped);
    ASSERT_EQ(n, 2);
    ASSERT_EQ((int)res.goose_configured, 1);
    ASSERT_EQ((int)res.sv_configured, 1);
    ASSERT_EQ((int)res.skipped, 0);
    ASSERT_EQ(g_sv_create_calls, 1);

    /* Whole-SDO expansion: 3 FCDAs x (cVal.mag.f, cVal.ang.f, q);
     * the Timestamp leaves are excluded for SV. */
    ASSERT_EQ((int)b.publishers[1].ref_count, 9);
    ASSERT_TRUE(strcmp(b.publishers[1].refs[0].do_name, "PhV") == 0);
    ASSERT_TRUE(strcmp(b.publishers[1].refs[0].da_name,
                       "phsA.cVal.mag.f") == 0);
    ASSERT_TRUE(strcmp(b.publishers[1].refs[2].da_name, "phsA.q") == 0);
    ASSERT_TRUE(strcmp(b.publishers[1].refs[3].da_name,
                       "phsB.cVal.mag.f") == 0);
    ASSERT_TRUE(strcmp(b.publishers[1].refs[8].da_name, "phsC.q") == 0);
    ASSERT_EQ((int)b.publishers[1].refs[0].fc, (int)IEC61850_FC_MX);
    /* gcb01's 2 refs + 9 whole-SDO leaves, all unique DAs */
    ASSERT_EQ((int)b.watch_count, 11);
    ASSERT_EQ((int)g_sv_cfgs[0].num_channels, 9);

    /* Write a deep leaf DA of the whole-SDO dataset and process:
     * fan-out through the whole-SDO publisher. */
    ld = iec61850_ied_model_find_ld(&model, "LD0");
    ASSERT_TRUE(ld != NULL);
    mmxu = find_ln_by_class(ld, "MMXU");
    ASSERT_TRUE(mmxu != NULL);
    phv = iec61850_ln_find_do(mmxu, "PhV");
    ASSERT_TRUE(phv != NULL);
    deep_mag = iec61850_do_find_attribute(phv, "phsB.cVal.mag.f",
                                           IEC61850_FC_MX);
    ASSERT_TRUE(deep_mag != NULL);

    wr_float(deep_mag, 7200.5f);
    ASSERT_TRUE(b.publishers[1].dirty);
    ASSERT_TRUE(!b.publishers[0].dirty);

    ASSERT_EQ(iec61850_model_binding_process(&b), 1);
    ASSERT_EQ(g_frames_sent, 1U);
    ASSERT_EQ((int)g_sv_pubs[0].sample_count, 9);
    ASSERT_EQ(g_sv_pubs[0].samples[3], 7200);  /* phsB.cVal.mag.f */
    ASSERT_EQ(iec61850_sv_publisher_get_smp_cnt(&g_sv_pubs[0]), 1U);

    iec61850_model_binding_destroy(&b);
    iec61850_ied_model_destroy(&model);
    PASS();
}

/* Skip tolerance: IID documents carry no Communication section
 * (gcbA has no address); a broken datSet reference skips its block;
 * the counts always sum to the control-block total. */
static void test_configure_publishers_skip_tolerance(void)
{
    iec61850_scl_doc_t doc;
    iec61850_ied_model_t model;
    iec61850_model_binding_t b;
    iec61850_scl_publisher_result_t res;
    iec61850_scl_publisher_ops_t ops;

    TEST("configure_publishers_skip_tolerance");

    /* test.iid: gcbA resolves but has no Communication address */
    load_iid_doc();
    ASSERT_TRUE(g_iid_loaded);
    ASSERT_EQ(iec61850_scl_build_ied_model(&g_iid_doc, &model), 0);
    (void)memset(&b, 0, sizeof(b));
    ASSERT_EQ(iec61850_model_binding_init(&b, &model), 0);
    (void)memset(&ops, 0, sizeof(ops));
    ops.create_goose = test_goose_create;
    g_goose_create_calls = 0;

    ASSERT_EQ(iec61850_scl_configure_publishers(&g_iid_doc, &b, &ops, &res), 0);
    ASSERT_EQ((int)res.goose_configured, 0);
    ASSERT_EQ((int)res.skipped, 1);
    ASSERT_EQ(g_goose_create_calls, 0);  /* declined before creation */
    ASSERT_EQ((int)b.publisher_count, 0);

    iec61850_model_binding_destroy(&b);
    iec61850_ied_model_destroy(&model);

    /* Synthetic doc: GSE block with a datSet that does not exist */
    build_whole_do_doc(&doc);
    (void)strncpy(doc.goose_cbs[0].dataset, "NoSuchDS",
                  sizeof(doc.goose_cbs[0].dataset) - 1);
    ASSERT_EQ(iec61850_scl_build_ied_model(&doc, &model), 0);
    (void)memset(&b, 0, sizeof(b));
    ASSERT_EQ(iec61850_model_binding_init(&b, &model), 0);

    ASSERT_EQ(iec61850_scl_configure_publishers(&doc, &b, &ops, &res), 0);
    ASSERT_EQ((int)res.skipped, 1);
    ASSERT_EQ((int)b.publisher_count, 0);
    ASSERT_EQ(iec61850_model_binding_process(&b), 0);  /* nothing dirty */

    iec61850_model_binding_destroy(&b);
    iec61850_ied_model_destroy(&model);

    /* Creation callback failure: skipped, nothing bound */
    build_whole_do_doc(&doc);
    ASSERT_EQ(iec61850_scl_build_ied_model(&doc, &model), 0);
    (void)memset(&b, 0, sizeof(b));
    ASSERT_EQ(iec61850_model_binding_init(&b, &model), 0);
    ops.create_goose = test_create_fail;

    ASSERT_EQ(iec61850_scl_configure_publishers(&doc, &b, &ops, &res), 0);
    ASSERT_EQ((int)res.skipped, 1);
    ASSERT_EQ((int)b.publisher_count, 0);

    iec61850_model_binding_destroy(&b);
    iec61850_ied_model_destroy(&model);
    PASS();
}

/* Argument validation and the declined-kind (NULL callback)
 * accounting. */
static void test_configure_publishers_null_args(void)
{
    iec61850_ied_model_t model;
    iec61850_model_binding_t b;
    iec61850_scl_publisher_result_t res;
    iec61850_scl_publisher_ops_t ops;

    TEST("configure_publishers_null_args");
    load_test_doc();

    ASSERT_EQ(iec61850_scl_build_ied_model(&g_doc, &model), 0);
    (void)memset(&b, 0, sizeof(b));
    ASSERT_EQ(iec61850_model_binding_init(&b, &model), 0);

    ASSERT_EQ(iec61850_scl_configure_publishers(NULL, &b, &ops, &res), -EINVAL);
    ASSERT_EQ(iec61850_scl_configure_publishers(&g_doc, NULL, &ops, &res), -EINVAL);
    ASSERT_EQ(iec61850_scl_configure_publishers(&g_doc, &b, NULL, &res), -EINVAL);

    /* Uninitialized binding */
    {
        iec61850_model_binding_t b2;
        (void)memset(&b2, 0, sizeof(b2));
        (void)memset(&ops, 0, sizeof(ops));
        ops.create_goose = test_goose_create;
        ASSERT_EQ(iec61850_scl_configure_publishers(&g_doc, &b2, &ops, &res),
                  -EINVAL);
    }

    /* Both callbacks NULL: every control block is declined (skipped);
     * the result summary still accounts for all of them. */
    (void)memset(&ops, 0, sizeof(ops));
    ASSERT_EQ(iec61850_scl_configure_publishers(&g_doc, &b, &ops, &res), 0);
    ASSERT_EQ((int)res.goose_configured, 0);
    ASSERT_EQ((int)res.sv_configured, 0);
    ASSERT_EQ((int)res.skipped,
              (int)(g_doc.goose_cb_count + g_doc.sv_cb_count));
    ASSERT_EQ((int)b.publisher_count, 0);

    /* result == NULL is allowed (return value only) */
    (void)memset(&ops, 0, sizeof(ops));
    ops.create_goose = test_goose_create;
    ASSERT_EQ(iec61850_scl_configure_publishers(&g_doc, &b, &ops, NULL), 1);

    iec61850_model_binding_destroy(&b);
    iec61850_ied_model_destroy(&model);
    PASS();
}

/* Whole-DO expansion bounds discipline: an expansion exceeding
 * IEC61850_BINDING_MAX_REFS skips the control block, and a
 * functional constraint with no leaves under the DO does too. */
static void test_configure_publishers_expansion_bounds(void)
{
    iec61850_scl_doc_t doc;
    iec61850_ied_model_t model;
    iec61850_model_binding_t b;
    iec61850_scl_publisher_result_t res;
    iec61850_scl_publisher_ops_t ops;
    iec61850_scl_do_type_t *big;
    iec61850_scl_dataset_t *ds;

    TEST("configure_publishers_expansion_bounds");

    /* Three whole-DO FCDAs over a DOType with 31 ST leaves: the
     * 65-ref expansion (3 + 31 + 31) exceeds the 64-slot publisher
     * dataset. */
    build_whole_do_doc(&doc);

    big = &doc.do_types[1];
    (void)strncpy(big->id, "BIGW", sizeof(big->id) - 1);
    (void)strncpy(big->cdc, "INS", sizeof(big->cdc) - 1);
    big->da_count = 31;
    for (size_t i = 0; i < 31; i++) {
        char name[8];
        (void)snprintf(name, sizeof(name), "l%02zu", i);
        (void)strncpy(big->das[i].name, name, sizeof(big->das[i].name) - 1);
        (void)strncpy(big->das[i].fc, "ST", sizeof(big->das[i].fc) - 1);
        (void)strncpy(big->das[i].btype, "INT32",
                      sizeof(big->das[i].btype) - 1);
    }
    doc.do_type_count = 2;

    doc.lnode_types[0].do_count = 3;
    (void)strncpy(doc.lnode_types[0].dos[1].name, "D1",
                  sizeof(doc.lnode_types[0].dos[1].name) - 1);
    (void)strncpy(doc.lnode_types[0].dos[1].type, "BIGW",
                  sizeof(doc.lnode_types[0].dos[1].type) - 1);
    (void)strncpy(doc.lnode_types[0].dos[2].name, "D2",
                  sizeof(doc.lnode_types[0].dos[2].name) - 1);
    (void)strncpy(doc.lnode_types[0].dos[2].type, "BIGW",
                  sizeof(doc.lnode_types[0].dos[2].type) - 1);

    ds = &doc.datasets[0];
    ds->member_count = 3;
    for (size_t m = 0; m < 3; m++) {
        const char *do_name = (m == 0) ? "Pos" : ((m == 1) ? "D1" : "D2");
        (void)strncpy(ds->members[m].ld_inst, "LD0",
                      sizeof(ds->members[m].ld_inst) - 1);
        (void)strncpy(ds->members[m].ln_class, "XCBR",
                      sizeof(ds->members[m].ln_class) - 1);
        (void)strncpy(ds->members[m].ln_inst, "1",
                      sizeof(ds->members[m].ln_inst) - 1);
        (void)strncpy(ds->members[m].do_name, do_name,
                      sizeof(ds->members[m].do_name) - 1);
        (void)strncpy(ds->members[m].fc, "ST", sizeof(ds->members[m].fc) - 1);
    }

    ASSERT_EQ(iec61850_scl_build_ied_model(&doc, &model), 0);
    (void)memset(&b, 0, sizeof(b));
    ASSERT_EQ(iec61850_model_binding_init(&b, &model), 0);
    (void)memset(&ops, 0, sizeof(ops));
    ops.create_goose = test_goose_create;

    ASSERT_EQ(iec61850_scl_configure_publishers(&doc, &b, &ops, &res), 0);
    ASSERT_EQ((int)res.skipped, 1);
    ASSERT_EQ((int)b.publisher_count, 0);

    iec61850_model_binding_destroy(&b);
    iec61850_ied_model_destroy(&model);

    /* Whole-DO FCDA under a functional constraint no leaf has
     * (DPC has no SG data): nothing expands, block skipped. */
    build_whole_do_doc(&doc);
    (void)strncpy(doc.datasets[0].members[0].fc, "SG",
                  sizeof(doc.datasets[0].members[0].fc) - 1);
    ASSERT_EQ(iec61850_scl_build_ied_model(&doc, &model), 0);
    (void)memset(&b, 0, sizeof(b));
    ASSERT_EQ(iec61850_model_binding_init(&b, &model), 0);

    ASSERT_EQ(iec61850_scl_configure_publishers(&doc, &b, &ops, &res), 0);
    ASSERT_EQ((int)res.skipped, 1);
    ASSERT_EQ((int)b.publisher_count, 0);

    iec61850_model_binding_destroy(&b);
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

    printf("\n--- Template-Driven Construction (WP-6e) ---\n");
    test_template_driven_construction();
    test_template_mms_naming();
    test_scd_template_flat_mag();
    test_unresolvable_lntype_fallback();

    printf("\n--- SCL Publisher Auto-Configuration (WP-6f) ---\n");
    test_configure_publishers_pipeline();
    test_configure_publishers_whole_do();
    test_configure_publishers_sv_pipeline();
    test_configure_publishers_scd_whole_sdo();
    test_configure_publishers_skip_tolerance();
    test_configure_publishers_null_args();
    test_configure_publishers_expansion_bounds();

    printf("\n=== Test Summary ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
