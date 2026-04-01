/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Deep Unit Tests for IED Data Model
 *
 * Tests beyond test_ied_data_model.c: LN DO management, DA read/write
 * roundtrip for multiple types, FC filtering, nested sub-DOs, and
 * full model traversal with element counting.
 *
 * License: BSD-3-Clause
 */

#include "ied/ied_data_model.h"
#include "ied/ied_types.h"

#include <math.h>
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
 * 1. Logical Node Operations
 * ======================================================================== */

static void test_ln_multiple_dos(void)
{
    TEST("ln_multiple_dos");
    iec61850_logical_node_t *ln = iec61850_ln_create("MMXU", "1");
    ASSERT_TRUE(ln != NULL);

    iec61850_data_object_t *do1 = iec61850_do_create("TotW", IEC61850_CDC_MV);
    iec61850_data_object_t *do2 = iec61850_do_create("TotVAr", IEC61850_CDC_MV);
    iec61850_data_object_t *do3 = iec61850_do_create("Hz", IEC61850_CDC_MV);
    ASSERT_TRUE(do1 != NULL);
    ASSERT_TRUE(do2 != NULL);
    ASSERT_TRUE(do3 != NULL);

    ASSERT_EQ(iec61850_ln_add_data_object(ln, do1), 0);
    ASSERT_EQ(iec61850_ln_add_data_object(ln, do2), 0);
    ASSERT_EQ(iec61850_ln_add_data_object(ln, do3), 0);
    ASSERT_EQ((int)ln->do_count, 3);

    /* Verify each DO is findable by name */
    ASSERT_TRUE(iec61850_ln_find_do(ln, "TotW") != NULL);
    ASSERT_TRUE(iec61850_ln_find_do(ln, "TotVAr") != NULL);
    ASSERT_TRUE(iec61850_ln_find_do(ln, "Hz") != NULL);
    ASSERT_TRUE(iec61850_ln_find_do(ln, "Nonexistent") == NULL);

    /* Verify DO names match */
    ASSERT_TRUE(strcmp(iec61850_ln_find_do(ln, "TotW")->name, "TotW") == 0);
    ASSERT_TRUE(strcmp(iec61850_ln_find_do(ln, "Hz")->name, "Hz") == 0);

    iec61850_ln_destroy(ln);
    PASS();
}

/* ========================================================================
 * 2. Data Object Structure
 * ======================================================================== */

static void test_do_mixed_fc_attributes(void)
{
    TEST("do_mixed_fc_attributes");
    iec61850_data_object_t *dobj = iec61850_do_create("Pos", IEC61850_CDC_DPC);
    ASSERT_TRUE(dobj != NULL);

    /* Add attributes across different FCs */
    ASSERT_EQ(iec61850_do_add_attribute(dobj, "stVal", IEC61850_FC_ST,
                                          IEC61850_BTYPE_DBPOS), 0);
    ASSERT_EQ(iec61850_do_add_attribute(dobj, "q", IEC61850_FC_ST,
                                          IEC61850_BTYPE_QUALITY), 0);
    ASSERT_EQ(iec61850_do_add_attribute(dobj, "t", IEC61850_FC_ST,
                                          IEC61850_BTYPE_TIMESTAMP), 0);
    ASSERT_EQ(iec61850_do_add_attribute(dobj, "ctlVal", IEC61850_FC_CO,
                                          IEC61850_BTYPE_DBPOS), 0);
    ASSERT_EQ(iec61850_do_add_attribute(dobj, "ctlModel", IEC61850_FC_CF,
                                          IEC61850_BTYPE_ENUMERATED), 0);
    ASSERT_EQ(iec61850_do_add_attribute(dobj, "d", IEC61850_FC_DC,
                                          IEC61850_BTYPE_VISIBLE_STRING), 0);
    ASSERT_EQ((int)dobj->attr_count, 6);

    /* Verify correct FC assignment */
    iec61850_data_attribute_t *da;
    da = iec61850_do_find_attribute(dobj, "stVal", IEC61850_FC_ST);
    ASSERT_TRUE(da != NULL);
    ASSERT_EQ((int)da->fc, (int)IEC61850_FC_ST);

    da = iec61850_do_find_attribute(dobj, "ctlVal", IEC61850_FC_CO);
    ASSERT_TRUE(da != NULL);
    ASSERT_EQ((int)da->fc, (int)IEC61850_FC_CO);

    da = iec61850_do_find_attribute(dobj, "ctlModel", IEC61850_FC_CF);
    ASSERT_TRUE(da != NULL);
    ASSERT_EQ((int)da->fc, (int)IEC61850_FC_CF);

    da = iec61850_do_find_attribute(dobj, "d", IEC61850_FC_DC);
    ASSERT_TRUE(da != NULL);
    ASSERT_EQ((int)da->fc, (int)IEC61850_FC_DC);

    iec61850_do_destroy(dobj);
    PASS();
}

/* ========================================================================
 * 3. Data Attribute Read/Write Roundtrip
 * ======================================================================== */

static void test_da_roundtrip_integer(void)
{
    TEST("da_roundtrip_integer");
    iec61850_data_object_t *dobj = iec61850_cdc_create_ins("Beh");
    iec61850_data_attribute_t *da = iec61850_do_find_attribute(dobj, "stVal",
                                                                IEC61850_FC_ST);
    ASSERT_TRUE(da != NULL);

    mms_value_t val;
    (void)memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;
    val.value.integer = -12345;
    iec61850_da_set_value(da, &val);

    mms_value_t got = iec61850_da_get_value(da);
    ASSERT_EQ((int)got.type, (int)MMS_TYPE_INTEGER);
    ASSERT_EQ((int)got.value.integer, -12345);

    iec61850_do_destroy(dobj);
    PASS();
}

static void test_da_roundtrip_boolean(void)
{
    TEST("da_roundtrip_boolean");
    iec61850_data_object_t *dobj = iec61850_cdc_create_sps("Alm");
    iec61850_data_attribute_t *da = iec61850_do_find_attribute(dobj, "stVal",
                                                                IEC61850_FC_ST);
    ASSERT_TRUE(da != NULL);

    mms_value_t val;
    (void)memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_BOOLEAN;
    val.value.boolean = true;
    iec61850_da_set_value(da, &val);

    mms_value_t got = iec61850_da_get_value(da);
    ASSERT_EQ((int)got.type, (int)MMS_TYPE_BOOLEAN);
    ASSERT_TRUE(got.value.boolean == true);

    /* Toggle to false */
    val.value.boolean = false;
    iec61850_da_set_value(da, &val);
    got = iec61850_da_get_value(da);
    ASSERT_TRUE(got.value.boolean == false);

    iec61850_do_destroy(dobj);
    PASS();
}

static void test_da_roundtrip_float(void)
{
    TEST("da_roundtrip_float");
    iec61850_data_object_t *dobj = iec61850_cdc_create_mv("Watts");
    iec61850_data_attribute_t *da = iec61850_do_find_attribute(dobj, "mag",
                                                                IEC61850_FC_MX);
    ASSERT_TRUE(da != NULL);

    mms_value_t val;
    (void)memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_FLOATING_POINT;
    val.value.floating_point = 3.14f;
    iec61850_da_set_value(da, &val);

    mms_value_t got = iec61850_da_get_value(da);
    ASSERT_EQ((int)got.type, (int)MMS_TYPE_FLOATING_POINT);
    ASSERT_TRUE(fabsf(got.value.floating_point - 3.14f) < 0.001f);

    iec61850_do_destroy(dobj);
    PASS();
}

static void test_da_roundtrip_string(void)
{
    TEST("da_roundtrip_string");
    iec61850_data_object_t *dobj = iec61850_cdc_create_vss("Tag");
    iec61850_data_attribute_t *da = iec61850_do_find_attribute(dobj, "stVal",
                                                                IEC61850_FC_ST);
    ASSERT_TRUE(da != NULL);

    mms_value_t val;
    (void)memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_VISIBLE_STRING;
    (void)strncpy(val.value.visible_string.data, "Hello IEC61850",
                  sizeof(val.value.visible_string.data) - 1);
    val.value.visible_string.len = strlen("Hello IEC61850");
    iec61850_da_set_value(da, &val);

    mms_value_t got = iec61850_da_get_value(da);
    ASSERT_EQ((int)got.type, (int)MMS_TYPE_VISIBLE_STRING);
    ASSERT_TRUE(strcmp(got.value.visible_string.data, "Hello IEC61850") == 0);
    ASSERT_EQ((int)got.value.visible_string.len, 14);

    iec61850_do_destroy(dobj);
    PASS();
}

/* ========================================================================
 * 4. Data Attribute FC Filtering
 * ======================================================================== */

static void test_da_fc_filtering(void)
{
    TEST("da_fc_filtering");
    iec61850_data_object_t *dobj = iec61850_cdc_create_dpc("Pos");
    ASSERT_TRUE(dobj != NULL);

    /* DPC has: stVal(ST), q(ST), t(ST), ctlVal(CO), ctlModel(CF) */

    /* Count attributes per FC by scanning */
    size_t st_count = 0;
    size_t co_count = 0;
    size_t cf_count = 0;
    for (size_t i = 0; i < dobj->attr_count; i++) {
        switch (dobj->attributes[i].fc) {
        case IEC61850_FC_ST: st_count++; break;
        case IEC61850_FC_CO: co_count++; break;
        case IEC61850_FC_CF: cf_count++; break;
        default: break;
        }
    }
    ASSERT_EQ((int)st_count, 3);  /* stVal, q, t */
    ASSERT_EQ((int)co_count, 1);  /* ctlVal */
    ASSERT_EQ((int)cf_count, 1);  /* ctlModel */

    /* Verify find returns correct attribute for each FC */
    ASSERT_TRUE(iec61850_do_find_attribute(dobj, "stVal", IEC61850_FC_ST) != NULL);
    ASSERT_TRUE(iec61850_do_find_attribute(dobj, "stVal", IEC61850_FC_CO) == NULL);
    ASSERT_TRUE(iec61850_do_find_attribute(dobj, "ctlVal", IEC61850_FC_CO) != NULL);
    ASSERT_TRUE(iec61850_do_find_attribute(dobj, "ctlVal", IEC61850_FC_ST) == NULL);

    iec61850_do_destroy(dobj);
    PASS();
}

/* ========================================================================
 * 5. Nested DO Structure (sub-DataObjects)
 * ======================================================================== */

static void test_nested_sub_objects(void)
{
    TEST("nested_sub_objects");

    /* Build a CMV-like structure manually: parent DO with mag and ang sub-DOs */
    iec61850_data_object_t *cmv = iec61850_do_create("PhV", IEC61850_CDC_CMV);
    ASSERT_TRUE(cmv != NULL);

    iec61850_data_object_t *mag = iec61850_do_create("mag", IEC61850_CDC_MV);
    ASSERT_TRUE(mag != NULL);
    ASSERT_EQ(iec61850_do_add_attribute(mag, "f", IEC61850_FC_MX,
                                          IEC61850_BTYPE_FLOAT32), 0);

    iec61850_data_object_t *ang = iec61850_do_create("ang", IEC61850_CDC_MV);
    ASSERT_TRUE(ang != NULL);
    ASSERT_EQ(iec61850_do_add_attribute(ang, "f", IEC61850_FC_MX,
                                          IEC61850_BTYPE_FLOAT32), 0);

    ASSERT_EQ(iec61850_do_add_sub_object(cmv, mag), 0);
    ASSERT_EQ(iec61850_do_add_sub_object(cmv, ang), 0);
    ASSERT_EQ((int)cmv->sub_count, 2);

    /* Find sub-objects by name */
    iec61850_data_object_t *found_mag = iec61850_do_find_sub_object(cmv, "mag");
    ASSERT_TRUE(found_mag != NULL);
    ASSERT_TRUE(strcmp(found_mag->name, "mag") == 0);

    iec61850_data_object_t *found_ang = iec61850_do_find_sub_object(cmv, "ang");
    ASSERT_TRUE(found_ang != NULL);
    ASSERT_TRUE(strcmp(found_ang->name, "ang") == 0);

    ASSERT_TRUE(iec61850_do_find_sub_object(cmv, "nonexistent") == NULL);

    /* Access attribute through sub-object */
    iec61850_data_attribute_t *da = iec61850_do_find_attribute(found_mag, "f",
                                                                IEC61850_FC_MX);
    ASSERT_TRUE(da != NULL);
    ASSERT_EQ((int)da->btype, (int)IEC61850_BTYPE_FLOAT32);

    /* Set value on nested attribute */
    mms_value_t val;
    (void)memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_FLOATING_POINT;
    val.value.floating_point = 230.5f;
    iec61850_da_set_value(da, &val);

    mms_value_t got = iec61850_da_get_value(da);
    ASSERT_TRUE(fabsf(got.value.floating_point - 230.5f) < 0.01f);

    iec61850_do_destroy(cmv);  /* Recursively frees sub-objects */
    PASS();
}

static void test_nested_path_lookup(void)
{
    TEST("nested_path_lookup");

    /* Build LD0/MMXU1 with a DO that has sub-DOs */
    iec61850_ied_model_t model;
    iec61850_ied_model_init(&model, "IED1");

    iec61850_logical_device_t *ld = iec61850_ld_create("LD0");
    iec61850_logical_node_t *ln = iec61850_ln_create("MMXU", "1");

    iec61850_data_object_t *phv = iec61850_do_create("PhV", IEC61850_CDC_CMV);
    iec61850_data_object_t *mag = iec61850_do_create("mag", IEC61850_CDC_MV);
    iec61850_do_add_attribute(mag, "f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32);
    iec61850_do_add_sub_object(phv, mag);

    iec61850_ln_add_data_object(ln, phv);
    iec61850_ld_add_logical_node(ld, ln);
    iec61850_ied_model_add_ld(&model, ld);

    /* Look up nested path: "LD0/MMXU1.PhV.mag.f" */
    iec61850_data_attribute_t *da =
        iec61850_ied_model_find_attribute(&model, "LD0/MMXU1.PhV.mag.f",
                                           IEC61850_FC_MX);
    ASSERT_TRUE(da != NULL);
    ASSERT_TRUE(strcmp(da->name, "f") == 0);
    ASSERT_EQ((int)da->btype, (int)IEC61850_BTYPE_FLOAT32);

    iec61850_ied_model_destroy(&model);
    PASS();
}

/* ========================================================================
 * 6. IED Model Traversal
 * ======================================================================== */

static void test_full_model_traversal(void)
{
    TEST("full_model_traversal");

    iec61850_ied_model_t model;
    iec61850_ied_model_init(&model, "TestIED");

    /* LD0: LLN0 (Beh, Health), LPHD1 (PhyHealth) */
    iec61850_logical_device_t *ld0 = iec61850_ld_create("LD0");

    iec61850_logical_node_t *lln0 = iec61850_ln_create("LLN0", "");
    iec61850_ln_add_data_object(lln0, iec61850_cdc_create_ins("Beh"));
    iec61850_ln_add_data_object(lln0, iec61850_cdc_create_ins("Health"));
    iec61850_ld_add_logical_node(ld0, lln0);

    iec61850_logical_node_t *lphd = iec61850_ln_create("LPHD", "1");
    iec61850_ln_add_data_object(lphd, iec61850_cdc_create_ins("PhyHealth"));
    iec61850_ld_add_logical_node(ld0, lphd);

    iec61850_ied_model_add_ld(&model, ld0);

    /* LD1: XCBR1 (Pos), MMXU1 (TotW) */
    iec61850_logical_device_t *ld1 = iec61850_ld_create("LD1");

    iec61850_logical_node_t *xcbr = iec61850_ln_create("XCBR", "1");
    iec61850_ln_add_data_object(xcbr, iec61850_cdc_create_dpc("Pos"));
    iec61850_ld_add_logical_node(ld1, xcbr);

    iec61850_logical_node_t *mmxu = iec61850_ln_create("MMXU", "1");
    iec61850_ln_add_data_object(mmxu, iec61850_cdc_create_mv("TotW"));
    iec61850_ld_add_logical_node(ld1, mmxu);

    iec61850_ied_model_add_ld(&model, ld1);

    /* Count: 2 LDs, 4 LNs, 5 DOs */
    ASSERT_EQ((int)iec61850_ied_model_count_ld(&model), 2);
    ASSERT_EQ((int)iec61850_ied_model_count_ln(&model), 4);
    ASSERT_EQ((int)iec61850_ied_model_count_do(&model), 5);

    /* DA count: INS has 3 (stVal,q,t) * 3 DOs = 9
     *           DPC has 5 (stVal,q,t,ctlVal,ctlModel) = 5
     *           MV has 3 (mag,q,t) = 3
     *           Total = 17 */
    ASSERT_EQ((int)iec61850_ied_model_count_da(&model), 17);

    /* Cross-LD path lookup */
    iec61850_data_attribute_t *da;
    da = iec61850_ied_model_find_attribute(&model, "LD0/LLN0.Beh.stVal",
                                            IEC61850_FC_ST);
    ASSERT_TRUE(da != NULL);
    ASSERT_EQ((int)da->btype, (int)IEC61850_BTYPE_INT32);

    da = iec61850_ied_model_find_attribute(&model, "LD1/XCBR1.Pos.stVal",
                                            IEC61850_FC_ST);
    ASSERT_TRUE(da != NULL);
    ASSERT_EQ((int)da->btype, (int)IEC61850_BTYPE_DBPOS);

    da = iec61850_ied_model_find_attribute(&model, "LD1/MMXU1.TotW.mag",
                                            IEC61850_FC_MX);
    ASSERT_TRUE(da != NULL);
    ASSERT_EQ((int)da->btype, (int)IEC61850_BTYPE_FLOAT32);

    iec61850_ied_model_destroy(&model);
    PASS();
}

int main(void)
{
    printf("\n=== Data Model Deep Tests ===\n");

    printf("\n--- Logical Node Operations ---\n");
    test_ln_multiple_dos();

    printf("\n--- Data Object Structure ---\n");
    test_do_mixed_fc_attributes();

    printf("\n--- DA Read/Write Roundtrip ---\n");
    test_da_roundtrip_integer();
    test_da_roundtrip_boolean();
    test_da_roundtrip_float();
    test_da_roundtrip_string();

    printf("\n--- FC Filtering ---\n");
    test_da_fc_filtering();

    printf("\n--- Nested DO Structure ---\n");
    test_nested_sub_objects();
    test_nested_path_lookup();

    printf("\n--- Full Model Traversal ---\n");
    test_full_model_traversal();

    printf("\n=== Test Summary ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
