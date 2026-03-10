/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for CDC Factory Functions
 *
 * Tests all CDC type factory functions produce correct data objects
 * with expected attributes.
 */

#include "ied/ied_data_model.h"

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

static void test_cdc_sps(void)
{
    TEST("cdc_sps");
    iec61850_data_object_t *dobj = iec61850_cdc_create_sps("Alm1");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_SPS);
    ASSERT_TRUE(dobj->attr_count > 0);
    /* SPS must have stVal (ST, BOOLEAN) and q (ST, QUALITY) */
    ASSERT_TRUE(iec61850_do_find_attribute(dobj, "stVal", IEC61850_FC_ST) != NULL);
    ASSERT_TRUE(iec61850_do_find_attribute(dobj, "q", IEC61850_FC_ST) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

static void test_cdc_dpc(void)
{
    TEST("cdc_dpc");
    iec61850_data_object_t *dobj = iec61850_cdc_create_dpc("Pos");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_DPC);
    ASSERT_TRUE(dobj->attr_count > 0);
    iec61850_do_destroy(dobj);
    PASS();
}

static void test_cdc_ins(void)
{
    TEST("cdc_ins");
    iec61850_data_object_t *dobj = iec61850_cdc_create_ins("Health");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_INS);
    ASSERT_TRUE(dobj->attr_count > 0);
    iec61850_do_destroy(dobj);
    PASS();
}

static void test_cdc_mv(void)
{
    TEST("cdc_mv");
    iec61850_data_object_t *dobj = iec61850_cdc_create_mv("PhV");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_MV);
    ASSERT_TRUE(dobj->attr_count > 0);
    iec61850_do_destroy(dobj);
    PASS();
}

static void test_cdc_spc(void)
{
    TEST("cdc_spc");
    iec61850_data_object_t *dobj = iec61850_cdc_create_spc("Mod");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_SPC);
    ASSERT_TRUE(dobj->attr_count > 0);
    iec61850_do_destroy(dobj);
    PASS();
}

static void test_cdc_null_name(void)
{
    TEST("cdc_null_name");
    ASSERT_TRUE(iec61850_cdc_create_sps(NULL) == NULL);
    ASSERT_TRUE(iec61850_cdc_create_dpc(NULL) == NULL);
    PASS();
}

static void test_cdc_type_strings(void)
{
    TEST("cdc_type_strings");
    ASSERT_TRUE(strcmp(iec61850_cdc_to_string(IEC61850_CDC_SPS), "SPS") == 0);
    ASSERT_TRUE(strcmp(iec61850_cdc_to_string(IEC61850_CDC_DPC), "DPC") == 0);
    ASSERT_TRUE(strcmp(iec61850_cdc_to_string(IEC61850_CDC_MV), "MV") == 0);
    ASSERT_TRUE(strcmp(iec61850_cdc_to_string(IEC61850_CDC_ENS), "ENS") == 0);
    ASSERT_TRUE(strcmp(iec61850_cdc_to_string(IEC61850_CDC_ACT), "ACT") == 0);
    ASSERT_TRUE(strcmp(iec61850_cdc_to_string(IEC61850_CDC_BSC), "BSC") == 0);
    ASSERT_TRUE(strcmp(iec61850_cdc_to_string(IEC61850_CDC_DEL), "DEL") == 0);
    ASSERT_TRUE(strcmp(iec61850_cdc_to_string(IEC61850_CDC_SPG), "SPG") == 0);
    ASSERT_TRUE(strcmp(iec61850_cdc_to_string(IEC61850_CDC_ASG), "ASG") == 0);
    PASS();
}

static void test_btype_strings(void)
{
    TEST("btype_strings");
    ASSERT_TRUE(strcmp(iec61850_btype_to_string(IEC61850_BTYPE_INT128), "INT128") == 0);
    ASSERT_TRUE(strcmp(iec61850_btype_to_string(IEC61850_BTYPE_CODED_ENUM), "CodedEnum") == 0);
    ASSERT_TRUE(strcmp(iec61850_btype_to_string(IEC61850_BTYPE_OCTET_STRING), "OctetString") == 0);
    ASSERT_TRUE(strcmp(iec61850_btype_to_string(IEC61850_BTYPE_UNICODE_STRING), "Unicode") == 0);
    ASSERT_TRUE(strcmp(iec61850_btype_to_string(IEC61850_BTYPE_CHECK), "Check") == 0);
    ASSERT_TRUE(strcmp(iec61850_btype_to_string(IEC61850_BTYPE_ENTRY_TIME), "EntryTime") == 0);
    ASSERT_TRUE(strcmp(iec61850_btype_to_string(IEC61850_BTYPE_PHYS_COMM_ADDR), "PhyComAddr") == 0);
    ASSERT_TRUE(strcmp(iec61850_btype_to_string(IEC61850_BTYPE_CURRENCY), "Currency") == 0);
    PASS();
}

int main(void)
{
    printf("=== CDC Factory Tests ===\n");

    test_cdc_sps();
    test_cdc_dpc();
    test_cdc_ins();
    test_cdc_mv();
    test_cdc_spc();
    test_cdc_null_name();
    test_cdc_type_strings();
    test_btype_strings();

    printf("\n=== Test Summary ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
