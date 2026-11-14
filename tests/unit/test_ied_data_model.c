/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for IED Data Model (ACSI hierarchy)
 *
 * Tests: LD/LN/DO/DA creation, path-based lookup, CDC factory,
 * data attribute get/set with mutex, change callbacks,
 * FC/BType enum conversions.
 *
 * License: BSD-2-Clause
 */

#include "ied/ied_data_model.h"
#include "ied/ied_types.h"

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
 * Model Construction
 * ======================================================================== */

static void test_model_create_destroy(void)
{
    TEST("model_create_destroy");
    iec61850_ied_model_t model;
    iec61850_ied_model_init(&model, "IED1");
    ASSERT_TRUE(strcmp(model.ied_name, "IED1") == 0);
    ASSERT_EQ((int)model.ld_count, 0);
    iec61850_ied_model_destroy(&model);
    PASS();
}

static void test_add_logical_device(void)
{
    TEST("add_logical_device");
    iec61850_ied_model_t model;
    iec61850_ied_model_init(&model, "IED1");

    iec61850_logical_device_t *ld = iec61850_ld_create("LD0");
    ASSERT_TRUE(ld != NULL);
    ASSERT_EQ(iec61850_ied_model_add_ld(&model, ld), 0);
    ASSERT_EQ((int)model.ld_count, 1);

    iec61850_logical_device_t *found = iec61850_ied_model_find_ld(&model, "LD0");
    ASSERT_TRUE(found != NULL);
    ASSERT_TRUE(strcmp(found->ld_inst, "LD0") == 0);

    /* Not found */
    ASSERT_TRUE(iec61850_ied_model_find_ld(&model, "LD9") == NULL);

    iec61850_ied_model_destroy(&model);
    PASS();
}

static void test_add_logical_node(void)
{
    TEST("add_logical_node");
    iec61850_logical_device_t *ld = iec61850_ld_create("LD0");
    iec61850_logical_node_t *ln = iec61850_ln_create("LLN0", "");
    ASSERT_TRUE(ln != NULL);
    ASSERT_EQ(iec61850_ld_add_logical_node(ld, ln), 0);
    ASSERT_EQ((int)ld->ln_count, 1);

    iec61850_logical_node_t *found = iec61850_ld_find_ln(ld, "LLN0");
    ASSERT_TRUE(found != NULL);

    iec61850_ld_destroy(ld);
    PASS();
}

static void test_add_data_object(void)
{
    TEST("add_data_object");
    iec61850_logical_node_t *ln = iec61850_ln_create("XCBR", "1");
    iec61850_data_object_t *dobj = iec61850_do_create("Pos", IEC61850_CDC_DPC);
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ(iec61850_ln_add_data_object(ln, dobj), 0);
    ASSERT_EQ((int)ln->do_count, 1);

    iec61850_data_object_t *found = iec61850_ln_find_do(ln, "Pos");
    ASSERT_TRUE(found != NULL);
    ASSERT_EQ((int)found->cdc, (int)IEC61850_CDC_DPC);

    iec61850_ln_destroy(ln);
    PASS();
}

static void test_add_data_attribute(void)
{
    TEST("add_data_attribute");
    iec61850_data_object_t *dobj = iec61850_do_create("Pos", IEC61850_CDC_DPC);
    ASSERT_EQ(iec61850_do_add_attribute(dobj, "stVal", IEC61850_FC_ST,
                                          IEC61850_BTYPE_DBPOS), 0);
    ASSERT_EQ(iec61850_do_add_attribute(dobj, "q", IEC61850_FC_ST,
                                          IEC61850_BTYPE_QUALITY), 0);
    ASSERT_EQ((int)dobj->attr_count, 2);

    iec61850_data_attribute_t *da = iec61850_do_find_attribute(dobj, "stVal", IEC61850_FC_ST);
    ASSERT_TRUE(da != NULL);
    ASSERT_EQ((int)da->fc, (int)IEC61850_FC_ST);
    ASSERT_EQ((int)da->btype, (int)IEC61850_BTYPE_DBPOS);

    /* Not found: wrong FC */
    ASSERT_TRUE(iec61850_do_find_attribute(dobj, "stVal", IEC61850_FC_MX) == NULL);

    iec61850_do_destroy(dobj);
    PASS();
}

/* ========================================================================
 * Path-Based Attribute Lookup
 * ======================================================================== */

static void test_path_based_lookup(void)
{
    TEST("path_based_lookup");
    iec61850_ied_model_t model;
    iec61850_ied_model_init(&model, "IED1");

    iec61850_logical_device_t *ld = iec61850_ld_create("LD0");
    iec61850_logical_node_t *ln = iec61850_ln_create("XCBR", "1");
    iec61850_data_object_t *dobj = iec61850_do_create("Pos", IEC61850_CDC_DPC);
    iec61850_do_add_attribute(dobj, "stVal", IEC61850_FC_ST, IEC61850_BTYPE_DBPOS);
    iec61850_do_add_attribute(dobj, "q", IEC61850_FC_ST, IEC61850_BTYPE_QUALITY);
    iec61850_ln_add_data_object(ln, dobj);
    iec61850_ld_add_logical_node(ld, ln);
    iec61850_ied_model_add_ld(&model, ld);

    /* Look up via path: "LD0/XCBR1.Pos.stVal" */
    iec61850_data_attribute_t *da =
        iec61850_ied_model_find_attribute(&model, "LD0/XCBR1.Pos.stVal", IEC61850_FC_ST);
    ASSERT_TRUE(da != NULL);
    ASSERT_TRUE(strcmp(da->name, "stVal") == 0);

    /* Non-existent path */
    ASSERT_TRUE(iec61850_ied_model_find_attribute(&model, "LD0/XCBR1.Pos.nonexistent",
                IEC61850_FC_ST) == NULL);
    ASSERT_TRUE(iec61850_ied_model_find_attribute(&model, "LD9/XCBR1.Pos.stVal",
                IEC61850_FC_ST) == NULL);

    iec61850_ied_model_destroy(&model);
    PASS();
}

/* ========================================================================
 * Deep-Path Attribute Lookup (WP-C2)
 *
 * Template-flattened builders (scl_ied_builder, the CDC factories)
 * store deep leaves as dotted names inside one DataObject's
 * attribute table ("phsA.cVal.mag.f") with no sub-data-objects.
 * The walker resolves them after the sub-object-first walk misses
 * (flat-name fallback matching the full remaining dotted path),
 * while plain DO.DA and DO.SubDO.DA shapes keep resolving as
 * before.
 * ======================================================================== */

static void test_deep_path_flat_dotted_lookup(void)
{
    TEST("deep_path_flat_dotted_lookup");
    iec61850_logical_node_t *ln = iec61850_ln_create("MMXU", "1");
    iec61850_data_attribute_t *da;

    ASSERT_TRUE(ln != NULL);
    ASSERT_EQ(iec61850_ln_add_data_object(ln, iec61850_cdc_create_wye("PhV")), 0);

    /* Flat-dotted leaves under the DO (WYE factory flattens SDOs
     * into dotted DA names) resolve through the full path. */
    da = iec61850_ln_find_attribute(ln, "PhV.phsA.cVal.mag.f", IEC61850_FC_MX);
    ASSERT_TRUE(da != NULL);
    ASSERT_TRUE(strcmp(da->name, "phsA.cVal.mag.f") == 0);
    ASSERT_EQ((int)da->btype, (int)IEC61850_BTYPE_FLOAT32);

    da = iec61850_ln_find_attribute(ln, "PhV.phsB.cVal.ang.f", IEC61850_FC_MX);
    ASSERT_TRUE(da != NULL);

    /* Two-level flattening (CMV: "cVal.mag.f") */
    ASSERT_EQ(iec61850_ln_add_data_object(ln, iec61850_cdc_create_cmv("Vol")), 0);
    da = iec61850_ln_find_attribute(ln, "Vol.cVal.mag.f", IEC61850_FC_MX);
    ASSERT_TRUE(da != NULL);
    ASSERT_TRUE(strcmp(da->name, "cVal.mag.f") == 0);

    /* Plain leaf under the same DO still resolves (final segment,
     * no dots: unchanged existing behavior). */
    da = iec61850_ln_find_attribute(ln, "PhV.q", IEC61850_FC_MX);
    ASSERT_TRUE(da != NULL);
    ASSERT_TRUE(strcmp(da->name, "q") == 0);

    /* Misses remain misses: wrong FC, wrong leaf, wrong phase */
    ASSERT_TRUE(iec61850_ln_find_attribute(ln, "PhV.phsA.cVal.mag.f",
                                            IEC61850_FC_ST) == NULL);
    ASSERT_TRUE(iec61850_ln_find_attribute(ln, "PhV.phsA.cVal.mag.x",
                                            IEC61850_FC_MX) == NULL);
    ASSERT_TRUE(iec61850_ln_find_attribute(ln, "PhV.phsD.cVal.mag.f",
                                            IEC61850_FC_MX) == NULL);

    iec61850_ln_destroy(ln);
    PASS();
}

static void test_deep_path_sub_object_shapes(void)
{
    TEST("deep_path_sub_object_shapes");
    iec61850_logical_node_t *ln = iec61850_ln_create("MMXU", "1");
    iec61850_data_object_t *cmv;
    iec61850_data_object_t *cval;
    iec61850_data_attribute_t *da;

    ASSERT_TRUE(ln != NULL);

    /* Class-library shape: real sub-data-objects. */
    cmv = iec61850_do_create("Vol", IEC61850_CDC_CMV);
    cval = iec61850_do_create("cVal", IEC61850_CDC_CMV);
    ASSERT_TRUE((cmv != NULL) && (cval != NULL));
    ASSERT_EQ(iec61850_do_add_attribute(cval, "f", IEC61850_FC_MX,
                                         IEC61850_BTYPE_FLOAT32), 0);
    ASSERT_EQ(iec61850_do_add_sub_object(cmv, cval), 0);
    ASSERT_EQ(iec61850_ln_add_data_object(ln, cmv), 0);

    /* DO.SubDA.leaf (sub-object-first walk) */
    da = iec61850_ln_find_attribute(ln, "Vol.cVal.f", IEC61850_FC_MX);
    ASSERT_TRUE(da != NULL);
    ASSERT_TRUE(strcmp(da->name, "f") == 0);

    /* Mixed shape: a real sub-object whose table carries a
     * flat-dotted leaf — the walker descends into the sub-object,
     * then matches the remaining dotted path against its table. */
    ASSERT_EQ(iec61850_do_add_attribute(cval, "ang.f", IEC61850_FC_MX,
                                         IEC61850_BTYPE_FLOAT32), 0);
    da = iec61850_ln_find_attribute(ln, "Vol.cVal.ang.f", IEC61850_FC_MX);
    ASSERT_TRUE(da != NULL);
    ASSERT_TRUE(strcmp(da->name, "ang.f") == 0);

    /* Segment that matches neither a sub-object nor an attribute */
    ASSERT_TRUE(iec61850_ln_find_attribute(ln, "Vol.cVal.nosuch",
                                            IEC61850_FC_MX) == NULL);

    iec61850_ln_destroy(ln);
    PASS();
}

static void test_deep_path_full_model_lookup(void)
{
    TEST("deep_path_full_model_lookup");
    iec61850_ied_model_t model;
    iec61850_logical_device_t *ld;
    iec61850_logical_node_t *ln;
    iec61850_data_attribute_t *da;

    iec61850_ied_model_init(&model, "IED1");
    ld = iec61850_ld_create("LD0");
    ln = iec61850_ln_create("MMXU", "1");
    ASSERT_TRUE((ld != NULL) && (ln != NULL));
    ASSERT_EQ(iec61850_ln_add_data_object(ln, iec61850_cdc_create_wye("PhV")), 0);
    ASSERT_EQ(iec61850_ld_add_logical_node(ld, ln), 0);
    ASSERT_EQ(iec61850_ied_model_add_ld(&model, ld), 0);

    /* Full path through LD/LN to a flat-dotted leaf */
    da = iec61850_ied_model_find_attribute(&model,
                                            "LD0/MMXU1.PhV.phsA.cVal.mag.f",
                                            IEC61850_FC_MX);
    ASSERT_TRUE(da != NULL);
    ASSERT_TRUE(strcmp(da->name, "phsA.cVal.mag.f") == 0);

    /* Deep miss through the full-path walker */
    ASSERT_TRUE(iec61850_ied_model_find_attribute(&model,
                "LD0/MMXU1.PhV.phsA.cVal.mag.x", IEC61850_FC_MX) == NULL);

    iec61850_ied_model_destroy(&model);
    PASS();
}

/* ========================================================================
 * CDC Factory
 * ======================================================================== */

static void test_cdc_spc(void)
{
    TEST("cdc_spc");
    iec61850_data_object_t *dobj = iec61850_cdc_create_spc("Ctrl");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_SPC);
    ASSERT_TRUE(dobj->attr_count > 0);

    /* SPC should have stVal (ST/BOOLEAN), ctlVal (CO/BOOLEAN), q, t */
    iec61850_data_attribute_t *stval = iec61850_do_find_attribute(dobj, "stVal", IEC61850_FC_ST);
    ASSERT_TRUE(stval != NULL);
    ASSERT_EQ((int)stval->btype, (int)IEC61850_BTYPE_BOOLEAN);

    iec61850_do_destroy(dobj);
    PASS();
}

static void test_cdc_dpc(void)
{
    TEST("cdc_dpc");
    iec61850_data_object_t *dobj = iec61850_cdc_create_dpc("Pos");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_DPC);

    /* DPC has stVal (ST/DBPOS) */
    iec61850_data_attribute_t *stval = iec61850_do_find_attribute(dobj, "stVal", IEC61850_FC_ST);
    ASSERT_TRUE(stval != NULL);
    ASSERT_EQ((int)stval->btype, (int)IEC61850_BTYPE_DBPOS);

    iec61850_do_destroy(dobj);
    PASS();
}

static void test_cdc_ins(void)
{
    TEST("cdc_ins");
    iec61850_data_object_t *dobj = iec61850_cdc_create_ins("Health");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_INS);

    /* INS has stVal (ST/INT32) */
    iec61850_data_attribute_t *stval = iec61850_do_find_attribute(dobj, "stVal", IEC61850_FC_ST);
    ASSERT_TRUE(stval != NULL);
    ASSERT_EQ((int)stval->btype, (int)IEC61850_BTYPE_INT32);

    iec61850_do_destroy(dobj);
    PASS();
}

static void test_cdc_mv(void)
{
    TEST("cdc_mv");
    iec61850_data_object_t *dobj = iec61850_cdc_create_mv("W");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_MV);

    iec61850_do_destroy(dobj);
    PASS();
}

static void test_cdc_sps(void)
{
    TEST("cdc_sps");
    iec61850_data_object_t *dobj = iec61850_cdc_create_sps("Alm");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_SPS);

    iec61850_data_attribute_t *stval = iec61850_do_find_attribute(dobj, "stVal", IEC61850_FC_ST);
    ASSERT_TRUE(stval != NULL);
    ASSERT_EQ((int)stval->btype, (int)IEC61850_BTYPE_BOOLEAN);

    iec61850_do_destroy(dobj);
    PASS();
}

/* ========================================================================
 * Data Attribute Get/Set with Mutex
 * ======================================================================== */

static void test_da_get_set(void)
{
    TEST("da_get_set");
    iec61850_data_object_t *dobj = iec61850_cdc_create_ins("Beh");
    iec61850_data_attribute_t *da = iec61850_do_find_attribute(dobj, "stVal", IEC61850_FC_ST);
    ASSERT_TRUE(da != NULL);

    /* Set value */
    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;
    val.value.integer = 42;
    iec61850_da_set_value(da, &val);

    /* Get value */
    mms_value_t got = iec61850_da_get_value(da);
    ASSERT_EQ((int)got.type, (int)MMS_TYPE_INTEGER);
    ASSERT_EQ((int)got.value.integer, 42);

    iec61850_do_destroy(dobj);
    PASS();
}

/* ========================================================================
 * Change Callback
 * ======================================================================== */

static int g_change_cb_count = 0;
static mms_value_t g_change_cb_old;
static mms_value_t g_change_cb_new;

static void test_change_cb(const mms_value_t *old_val, const mms_value_t *new_val,
                              void *user_data)
{
    (void)user_data;
    g_change_cb_count++;
    g_change_cb_old = *old_val;
    g_change_cb_new = *new_val;
}

static void test_da_change_callback(void)
{
    TEST("da_change_callback");
    iec61850_data_object_t *dobj = iec61850_cdc_create_ins("Beh");
    iec61850_data_attribute_t *da = iec61850_do_find_attribute(dobj, "stVal", IEC61850_FC_ST);
    ASSERT_TRUE(da != NULL);

    g_change_cb_count = 0;
    iec61850_da_set_change_callback(da, test_change_cb, NULL);

    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;
    val.value.integer = 1;
    iec61850_da_set_value(da, &val);
    ASSERT_EQ(g_change_cb_count, 1);
    ASSERT_EQ((int)g_change_cb_new.value.integer, 1);

    val.value.integer = 2;
    iec61850_da_set_value(da, &val);
    ASSERT_EQ(g_change_cb_count, 2);
    ASSERT_EQ((int)g_change_cb_old.value.integer, 1);
    ASSERT_EQ((int)g_change_cb_new.value.integer, 2);

    iec61850_do_destroy(dobj);
    PASS();
}

/* ========================================================================
 * FC and BType Enum Conversions
 * ======================================================================== */

static void test_fc_conversion(void)
{
    TEST("fc_conversion");
    ASSERT_TRUE(strcmp(iec61850_fc_to_string(IEC61850_FC_ST), "ST") == 0);
    ASSERT_TRUE(strcmp(iec61850_fc_to_string(IEC61850_FC_MX), "MX") == 0);
    ASSERT_TRUE(strcmp(iec61850_fc_to_string(IEC61850_FC_CO), "CO") == 0);
    ASSERT_TRUE(strcmp(iec61850_fc_to_string(IEC61850_FC_CF), "CF") == 0);

    ASSERT_EQ((int)iec61850_string_to_fc("ST"), (int)IEC61850_FC_ST);
    ASSERT_EQ((int)iec61850_string_to_fc("MX"), (int)IEC61850_FC_MX);
    ASSERT_EQ((int)iec61850_string_to_fc("CO"), (int)IEC61850_FC_CO);

    PASS();
}

static void test_btype_conversion(void)
{
    TEST("btype_conversion");
    ASSERT_TRUE(strcmp(iec61850_btype_to_string(IEC61850_BTYPE_BOOLEAN), "BOOLEAN") == 0);
    ASSERT_TRUE(strcmp(iec61850_btype_to_string(IEC61850_BTYPE_INT32), "INT32") == 0);
    ASSERT_TRUE(strcmp(iec61850_btype_to_string(IEC61850_BTYPE_FLOAT32), "FLOAT32") == 0);
    PASS();
}

/* ========================================================================
 * Statistics
 * ======================================================================== */

static void test_model_statistics(void)
{
    TEST("model_statistics");
    iec61850_ied_model_t model;
    iec61850_ied_model_init(&model, "IED1");

    iec61850_logical_device_t *ld = iec61850_ld_create("LD0");

    /* LLN0 with Beh + Health */
    iec61850_logical_node_t *lln0 = iec61850_ln_create("LLN0", "");
    iec61850_ln_add_data_object(lln0, iec61850_cdc_create_ins("Beh"));
    iec61850_ln_add_data_object(lln0, iec61850_cdc_create_ins("Health"));
    iec61850_ld_add_logical_node(ld, lln0);

    /* XCBR1 with Pos */
    iec61850_logical_node_t *xcbr = iec61850_ln_create("XCBR", "1");
    iec61850_ln_add_data_object(xcbr, iec61850_cdc_create_dpc("Pos"));
    iec61850_ld_add_logical_node(ld, xcbr);

    iec61850_ied_model_add_ld(&model, ld);

    ASSERT_EQ((int)iec61850_ied_model_count_ld(&model), 1);
    ASSERT_EQ((int)iec61850_ied_model_count_ln(&model), 2);
    ASSERT_EQ((int)iec61850_ied_model_count_do(&model), 3);
    ASSERT_TRUE(iec61850_ied_model_count_da(&model) > 0);

    iec61850_ied_model_destroy(&model);
    PASS();
}

static void test_null_branches(void)
{
    TEST("null_branch_coverage");

    /* DA NULL paths */
    iec61850_data_attribute_t da;
    ASSERT_EQ(iec61850_da_init(NULL, "test", IEC61850_FC_ST, IEC61850_BTYPE_BOOLEAN), -1);
    ASSERT_EQ(iec61850_da_init(&da, NULL, IEC61850_FC_ST, IEC61850_BTYPE_BOOLEAN), -1);
    iec61850_da_destroy(NULL);

    /* DA get/set with NULL */
    mms_value_t val = iec61850_da_get_value(NULL);
    (void)val;
    mms_value_t wval;
    (void)memset(&wval, 0, sizeof(wval));
    iec61850_da_set_value(NULL, &wval);

    /* DO NULL paths */
    iec61850_data_object_t *dobj = iec61850_do_create(NULL, IEC61850_CDC_SPS);
    ASSERT_TRUE(dobj == NULL);
    iec61850_do_destroy(NULL);
    ASSERT_EQ(iec61850_do_add_attribute(NULL, "x", IEC61850_FC_ST, IEC61850_BTYPE_BOOLEAN), -1);
    ASSERT_TRUE(iec61850_do_find_attribute(NULL, "x", IEC61850_FC_ST) == NULL);

    /* LN NULL paths */
    iec61850_logical_node_t *ln = iec61850_ln_create(NULL, NULL);
    ASSERT_TRUE(ln == NULL);
    ln = iec61850_ln_create("LLN0", NULL);
    if (ln != NULL) iec61850_ln_destroy(ln); /* may or may not accept NULL inst */
    iec61850_ln_destroy(NULL);
    ASSERT_EQ(iec61850_ln_add_data_object(NULL, NULL), -1);
    ASSERT_TRUE(iec61850_ln_find_do(NULL, "x") == NULL);

    /* LD NULL paths */
    iec61850_logical_device_t *ld = iec61850_ld_create(NULL);
    ASSERT_TRUE(ld == NULL);
    iec61850_ld_destroy(NULL);
    ASSERT_EQ(iec61850_ld_add_logical_node(NULL, NULL), -1);
    ASSERT_TRUE(iec61850_ld_find_ln(NULL, "x") == NULL);

    /* IED Model NULL paths */
    iec61850_ied_model_t model;
    iec61850_ied_model_init(NULL, "test");
    iec61850_ied_model_destroy(NULL);
    ASSERT_EQ(iec61850_ied_model_add_ld(NULL, NULL), -1);
    ASSERT_TRUE(iec61850_ied_model_find_ld(NULL, "x") == NULL);
    ASSERT_EQ((int)iec61850_ied_model_count_ld(NULL), 0);
    ASSERT_EQ((int)iec61850_ied_model_count_ln(NULL), 0);
    ASSERT_EQ((int)iec61850_ied_model_count_do(NULL), 0);
    ASSERT_EQ((int)iec61850_ied_model_count_da(NULL), 0);

    /* Valid DO with find returning NULL for non-existent attr */
    dobj = iec61850_do_create("TestDO", IEC61850_CDC_SPS);
    ASSERT_TRUE(dobj != NULL);
    ASSERT_TRUE(iec61850_do_find_attribute(dobj, "nonexistent", IEC61850_FC_ST) == NULL);
    iec61850_do_destroy(dobj);

    /* Valid LD with find returning NULL */
    ld = iec61850_ld_create("TestLD");
    ASSERT_TRUE(ld != NULL);
    ASSERT_TRUE(iec61850_ld_find_ln(ld, "nonexistent") == NULL);
    iec61850_ld_destroy(ld);

    /* Valid model with find returning NULL */
    iec61850_ied_model_init(&model, "TestIED");
    ASSERT_TRUE(iec61850_ied_model_find_ld(&model, "nonexistent") == NULL);
    iec61850_ied_model_destroy(&model);

    PASS();
}

int main(void)
{
    printf("\n=== IED Data Model Tests ===\n");

    test_model_create_destroy();
    test_add_logical_device();
    test_add_logical_node();
    test_add_data_object();
    test_add_data_attribute();

    printf("\n=== Path-Based Lookup ===\n");
    test_path_based_lookup();

    printf("\n=== Deep-Path Attribute Lookup (WP-C2) ===\n");
    test_deep_path_flat_dotted_lookup();
    test_deep_path_sub_object_shapes();
    test_deep_path_full_model_lookup();

    printf("\n=== CDC Factory ===\n");
    test_cdc_spc();
    test_cdc_dpc();
    test_cdc_ins();
    test_cdc_mv();
    test_cdc_sps();

    printf("\n=== Data Attribute Get/Set ===\n");
    test_da_get_set();
    test_da_change_callback();

    printf("\n=== Enum Conversions ===\n");
    test_fc_conversion();
    test_btype_conversion();

    printf("\n=== Statistics ===\n");
    test_model_statistics();

    printf("\n=== NULL/Edge Branch Coverage ===\n");
    test_null_branches();

    printf("\n=== Test Summary ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
