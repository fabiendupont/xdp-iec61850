/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Integration Test: SCL -> IED Model -> MMS Data Store Pipeline
 *
 * Tests the full ACSI pipeline: parse SCD file, build IED data model,
 * register into MMS data store, then verify domains, hierarchy, and
 * variable access via the data store API.
 *
 * License: BSD-2-Clause
 */

#include "scl/scl_parser.h"
#include "scl/scl_ied_builder.h"
#include "mms/mms_data_store.h"
#include "ied/ied_data_model.h"

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
#define ASSERT_STR_EQ(a, b) do { if (strcmp((a), (b)) != 0) { \
    printf("FAIL: \"%s\" != \"%s\"\n", (a), (b)); \
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

/* Shared state for the pipeline */
static iec61850_scl_doc_t g_doc;
static iec61850_ied_model_t g_model;
static iec61850_mms_data_store_t g_ds;
static bool g_pipeline_ready = false;

static void setup_pipeline(void)
{
    if (g_pipeline_ready) { return; }

    char path[512];
    build_path(path, sizeof(path), "test.scd");

    iec61850_scl_doc_init(&g_doc);
    if (iec61850_scl_parse_file(path, "IED1", &g_doc) != 0) {
        return;
    }

    if (iec61850_scl_build_ied_model(&g_doc, &g_model) != 0) {
        return;
    }

    iec61850_mms_ds_init(&g_ds);
    if (iec61850_ied_model_register_mms(&g_model, &g_ds) < 0) {
        iec61850_mms_ds_destroy(&g_ds);
        iec61850_ied_model_destroy(&g_model);
        return;
    }

    g_pipeline_ready = true;
}

static void teardown_pipeline(void)
{
    if (!g_pipeline_ready) { return; }
    iec61850_mms_ds_destroy(&g_ds);
    iec61850_ied_model_destroy(&g_model);
    g_pipeline_ready = false;
}

/* ========================================================================
 * Test 1: SCL to MMS Pipeline
 * ======================================================================== */

static void test_scl_to_mms_pipeline(void)
{
    TEST("scl_to_mms_pipeline");
    setup_pipeline();
    ASSERT_TRUE(g_pipeline_ready);

    /* Verify IED name propagated */
    ASSERT_STR_EQ(g_model.ied_name, "IED1");

    /* Verify domain exists: IEDName + LDInst = "IED1LD0" */
    ASSERT_TRUE(iec61850_mms_ds_domain_exists(&g_ds, "IED1LD0"));

    /* Verify domain count via get_domain_names */
    char names[8][MMS_MAX_DOMAIN_NAME];
    uint32_t count = 0;
    int ret = iec61850_mms_ds_get_domain_names(&g_ds, names, &count, 8);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(count >= 1);

    /* First domain should be IED1LD0 */
    bool found = false;
    for (uint32_t i = 0; i < count; i++) {
        if (strcmp(names[i], "IED1LD0") == 0) {
            found = true;
            break;
        }
    }
    ASSERT_TRUE(found);

    PASS();
}

static void test_domain_has_variables(void)
{
    TEST("domain_has_variables");
    setup_pipeline();
    ASSERT_TRUE(g_pipeline_ready);

    /* The domain should have variables registered */
    char var_names[128][MMS_MAX_VARIABLE_NAME];
    uint32_t var_count = 0;
    int ret = iec61850_mms_ds_get_var_names(&g_ds, "IED1LD0",
                                             var_names, &var_count, 128);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(var_count > 0);

    printf("(%u vars) ", var_count);

    /* Variable count should match IED model DA count */
    size_t da_count = iec61850_ied_model_count_da(&g_model);
    ASSERT_EQ((int)var_count, (int)da_count);

    PASS();
}

/* ========================================================================
 * Test 2: Hierarchy Navigation
 * ======================================================================== */

static void test_hierarchy_ied_to_ld(void)
{
    TEST("hierarchy_ied_to_ld");
    setup_pipeline();
    ASSERT_TRUE(g_pipeline_ready);

    /* IED has at least 1 LD */
    size_t ld_count = iec61850_ied_model_count_ld(&g_model);
    ASSERT_TRUE(ld_count >= 1);

    /* LD0 should be findable */
    iec61850_logical_device_t *ld = iec61850_ied_model_find_ld(&g_model, "LD0");
    ASSERT_TRUE(ld != NULL);
    ASSERT_STR_EQ(ld->ld_inst, "LD0");

    PASS();
}

static void test_hierarchy_ld_to_ln(void)
{
    TEST("hierarchy_ld_to_ln");
    setup_pipeline();
    ASSERT_TRUE(g_pipeline_ready);

    iec61850_logical_device_t *ld = iec61850_ied_model_find_ld(&g_model, "LD0");
    ASSERT_TRUE(ld != NULL);

    /* LD0 should have LLN0, LPHD1, XCBR1, MMXU1 = 4 LNs minimum */
    ASSERT_TRUE(ld->ln_count >= 4);

    /* Verify each expected LN class exists */
    bool found_lln0 = false, found_lphd = false;
    bool found_xcbr = false, found_mmxu = false;
    for (size_t i = 0; i < ld->ln_count; i++) {
        const char *cls = ld->logical_nodes[i]->ln_class;
        if (strcmp(cls, "LLN0") == 0) { found_lln0 = true; }
        if (strcmp(cls, "LPHD") == 0) { found_lphd = true; }
        if (strcmp(cls, "XCBR") == 0) { found_xcbr = true; }
        if (strcmp(cls, "MMXU") == 0) { found_mmxu = true; }
    }
    ASSERT_TRUE(found_lln0);
    ASSERT_TRUE(found_lphd);
    ASSERT_TRUE(found_xcbr);
    ASSERT_TRUE(found_mmxu);

    PASS();
}

static void test_hierarchy_ln_to_do_to_da(void)
{
    TEST("hierarchy_ln_to_do_to_da");
    setup_pipeline();
    ASSERT_TRUE(g_pipeline_ready);

    iec61850_logical_device_t *ld = iec61850_ied_model_find_ld(&g_model, "LD0");
    ASSERT_TRUE(ld != NULL);

    /* Find XCBR1 */
    iec61850_logical_node_t *xcbr = NULL;
    for (size_t i = 0; i < ld->ln_count; i++) {
        if (strcmp(ld->logical_nodes[i]->ln_class, "XCBR") == 0) {
            xcbr = ld->logical_nodes[i];
            break;
        }
    }
    ASSERT_TRUE(xcbr != NULL);
    ASSERT_TRUE(xcbr->do_count >= 4);

    /* Traverse DO -> DA: Pos should have stVal, q, t */
    iec61850_data_object_t *pos = iec61850_ln_find_do(xcbr, "Pos");
    ASSERT_TRUE(pos != NULL);
    ASSERT_TRUE(pos->attr_count >= 3);

    /* Find stVal attribute */
    iec61850_data_attribute_t *stval = iec61850_do_find_attribute(
        pos, "stVal", IEC61850_FC_ST);
    ASSERT_TRUE(stval != NULL);

    /* Find quality attribute */
    iec61850_data_attribute_t *q = iec61850_do_find_attribute(
        pos, "q", IEC61850_FC_ST);
    ASSERT_TRUE(q != NULL);

    /* Find timestamp attribute */
    iec61850_data_attribute_t *t = iec61850_do_find_attribute(
        pos, "t", IEC61850_FC_ST);
    ASSERT_TRUE(t != NULL);

    PASS();
}

static void test_hierarchy_element_counts(void)
{
    TEST("hierarchy_element_counts");
    setup_pipeline();
    ASSERT_TRUE(g_pipeline_ready);

    size_t ld = iec61850_ied_model_count_ld(&g_model);
    size_t ln = iec61850_ied_model_count_ln(&g_model);
    size_t dobj = iec61850_ied_model_count_do(&g_model);
    size_t da = iec61850_ied_model_count_da(&g_model);

    printf("(LD=%d LN=%d DO=%d DA=%d) ", (int)ld, (int)ln, (int)dobj, (int)da);

    ASSERT_TRUE(ld >= 1);
    ASSERT_TRUE(ln >= 4);
    ASSERT_TRUE(dobj >= 10);
    ASSERT_TRUE(da >= 20);

    /* DA count should be greater than DO count (each DO has multiple DAs) */
    ASSERT_TRUE(da > dobj);

    PASS();
}

/* ========================================================================
 * Test 3: Measurement Data Read via MMS Data Store
 * ======================================================================== */

static void test_mmxu_variable_read(void)
{
    TEST("mmxu_variable_read");
    setup_pipeline();
    ASSERT_TRUE(g_pipeline_ready);

    /* MMXU1 TotW is an MV CDC. Verify we can read its MMS variable */
    ASSERT_TRUE(iec61850_mms_ds_variable_exists(&g_ds, "IED1LD0",
                                                 "MMXU1$MX$TotW$mag"));

    /* Read the magnitude value */
    mms_value_t val;
    int ret = iec61850_mms_ds_read_variable(&g_ds, "IED1LD0",
                                             "MMXU1$MX$TotW$mag", &val);
    ASSERT_EQ(ret, (int)IEC61850_MMS_DS_OK);

    /* Verify the variable type via attrs */
    mms_variable_access_attrs_t attrs;
    ret = iec61850_mms_ds_get_variable_attrs(&g_ds, "IED1LD0",
                                              "MMXU1$MX$TotW$mag", &attrs);
    ASSERT_EQ(ret, (int)IEC61850_MMS_DS_OK);
    ASSERT_EQ((int)attrs.type, (int)MMS_TYPE_FLOATING_POINT);

    PASS();
}

static void test_mmxu_variable_write_read(void)
{
    TEST("mmxu_variable_write_read");
    setup_pipeline();
    ASSERT_TRUE(g_pipeline_ready);

    /* Write a measurement value, then read it back */
    mms_value_t write_val;
    memset(&write_val, 0, sizeof(write_val));
    write_val.value.floating_point = 123.456f;

    int ret = iec61850_mms_ds_write_variable(&g_ds, "IED1LD0",
                                              "MMXU1$MX$TotW$mag", &write_val);
    ASSERT_EQ(ret, (int)IEC61850_MMS_DS_OK);

    mms_value_t read_val;
    ret = iec61850_mms_ds_read_variable(&g_ds, "IED1LD0",
                                         "MMXU1$MX$TotW$mag", &read_val);
    ASSERT_EQ(ret, (int)IEC61850_MMS_DS_OK);

    /* Verify the written value was stored */
    ASSERT_TRUE(read_val.value.floating_point > 123.0f && read_val.value.floating_point < 124.0f);

    PASS();
}

static void test_mmxu_quality_and_timestamp(void)
{
    TEST("mmxu_quality_and_timestamp");
    setup_pipeline();
    ASSERT_TRUE(g_pipeline_ready);

    /* MV CDC should also have quality (q) and timestamp (t) */
    ASSERT_TRUE(iec61850_mms_ds_variable_exists(&g_ds, "IED1LD0",
                                                 "MMXU1$MX$TotW$q"));
    ASSERT_TRUE(iec61850_mms_ds_variable_exists(&g_ds, "IED1LD0",
                                                 "MMXU1$MX$TotW$t"));

    PASS();
}

/* ========================================================================
 * Test 4: Multi-Domain (each LD -> MMS domain)
 * ======================================================================== */

static void test_multi_domain_naming(void)
{
    TEST("multi_domain_naming");
    setup_pipeline();
    ASSERT_TRUE(g_pipeline_ready);

    /* Each LD becomes domain = IEDName + LDInst */
    size_t ld_count = iec61850_ied_model_count_ld(&g_model);
    for (size_t i = 0; i < ld_count; i++) {
        iec61850_logical_device_t *ld = g_model.logical_devices[i];
        char domain[MMS_MAX_DOMAIN_NAME];
        snprintf(domain, sizeof(domain), "%s%s", g_model.ied_name, ld->ld_inst);

        ASSERT_TRUE(iec61850_mms_ds_domain_exists(&g_ds, domain));
    }

    PASS();
}

static void test_multi_domain_variable_isolation(void)
{
    TEST("multi_domain_variable_isolation");
    setup_pipeline();
    ASSERT_TRUE(g_pipeline_ready);

    /* Variables from IED1LD0 should not be found in a non-existent domain */
    ASSERT_TRUE(!iec61850_mms_ds_variable_exists(&g_ds, "BOGUS",
                                                  "XCBR1$ST$Pos$stVal"));

    /* But should exist in the correct domain */
    ASSERT_TRUE(iec61850_mms_ds_variable_exists(&g_ds, "IED1LD0",
                                                 "XCBR1$ST$Pos$stVal"));

    PASS();
}

static void test_multi_domain_synthetic(void)
{
    TEST("multi_domain_synthetic");

    /* Build a synthetic SCL with 2 LDs to verify multi-domain behavior */
    iec61850_scl_doc_t doc;
    iec61850_scl_doc_init(&doc);
    strncpy(doc.ied_name, "IED2", sizeof(doc.ied_name) - 1);

    doc.ld_count = 2;
    memset(&doc.lds[0], 0, sizeof(doc.lds[0]));
    strncpy(doc.lds[0].inst, "LD0", sizeof(doc.lds[0].inst) - 1);
    doc.lds[0].ln_count = 1;
    strncpy(doc.lds[0].lns[0].ln_class, "LLN0", sizeof(doc.lds[0].lns[0].ln_class) - 1);
    strncpy(doc.lds[0].lns[0].ln_inst, "", sizeof(doc.lds[0].lns[0].ln_inst) - 1);

    memset(&doc.lds[1], 0, sizeof(doc.lds[1]));
    strncpy(doc.lds[1].inst, "LD1", sizeof(doc.lds[1].inst) - 1);
    doc.lds[1].ln_count = 1;
    strncpy(doc.lds[1].lns[0].ln_class, "LLN0", sizeof(doc.lds[1].lns[0].ln_class) - 1);
    strncpy(doc.lds[1].lns[0].ln_inst, "", sizeof(doc.lds[1].lns[0].ln_inst) - 1);

    iec61850_ied_model_t model;
    ASSERT_EQ(iec61850_scl_build_ied_model(&doc, &model), 0);
    ASSERT_EQ((int)iec61850_ied_model_count_ld(&model), 2);

    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);

    int count = iec61850_ied_model_register_mms(&model, &ds);
    ASSERT_TRUE(count > 0);

    /* Both domains should exist: IED2LD0 and IED2LD1 */
    ASSERT_TRUE(iec61850_mms_ds_domain_exists(&ds, "IED2LD0"));
    ASSERT_TRUE(iec61850_mms_ds_domain_exists(&ds, "IED2LD1"));

    /* Each domain should have LLN0 variables */
    ASSERT_TRUE(iec61850_mms_ds_variable_exists(&ds, "IED2LD0",
                                                 "LLN0$ST$Beh$stVal"));
    ASSERT_TRUE(iec61850_mms_ds_variable_exists(&ds, "IED2LD1",
                                                 "LLN0$ST$Beh$stVal"));

    iec61850_mms_ds_destroy(&ds);
    iec61850_ied_model_destroy(&model);
    PASS();
}

/* ======================================================================== */

int main(void)
{
    printf("\n=== IED ACSI Integration Tests ===\n");

    printf("\n--- SCL to MMS Pipeline ---\n");
    test_scl_to_mms_pipeline();
    test_domain_has_variables();

    printf("\n--- Hierarchy Navigation ---\n");
    test_hierarchy_ied_to_ld();
    test_hierarchy_ld_to_ln();
    test_hierarchy_ln_to_do_to_da();
    test_hierarchy_element_counts();

    printf("\n--- Measurement Data Read ---\n");
    test_mmxu_variable_read();
    test_mmxu_variable_write_read();
    test_mmxu_quality_and_timestamp();

    printf("\n--- Multi-Domain ---\n");
    test_multi_domain_naming();
    test_multi_domain_variable_isolation();
    test_multi_domain_synthetic();

    teardown_pipeline();

    printf("\n=== Test Summary ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
