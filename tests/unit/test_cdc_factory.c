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
    ASSERT_TRUE(iec61850_cdc_create_apc(NULL) == NULL);
    ASSERT_TRUE(iec61850_cdc_create_enc(NULL) == NULL);
    ASSERT_TRUE(iec61850_cdc_create_isc(NULL) == NULL);
    ASSERT_TRUE(iec61850_cdc_create_curs(NULL) == NULL);
    ASSERT_TRUE(iec61850_cdc_create_csd(NULL) == NULL);
    ASSERT_TRUE(iec61850_cdc_create_seq(NULL) == NULL);
    ASSERT_TRUE(iec61850_cdc_create_hmv(NULL) == NULL);
    ASSERT_TRUE(iec61850_cdc_create_hwye(NULL) == NULL);
    ASSERT_TRUE(iec61850_cdc_create_hdel(NULL) == NULL);
    PASS();
}

/* 6a extension factories: APC, ENC, ISC */
static void test_cdc_apc(void)
{
    TEST("cdc_apc");
    iec61850_data_object_t *dobj = iec61850_cdc_create_apc("AOut1");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_APC);
    ASSERT_TRUE(dobj->attr_count > 0);
    ASSERT_TRUE(iec61850_do_find_attribute(dobj, "mxVal", IEC61850_FC_MX) != NULL);
    ASSERT_TRUE(iec61850_do_find_attribute(dobj, "ctlVal", IEC61850_FC_CO) != NULL);
    ASSERT_TRUE(iec61850_do_find_attribute(dobj, "ctlModel", IEC61850_FC_CF) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

static void test_cdc_enc(void)
{
    TEST("cdc_enc");
    iec61850_data_object_t *dobj = iec61850_cdc_create_enc("EnumCtl1");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_ENC);
    ASSERT_TRUE(dobj->attr_count > 0);
    ASSERT_TRUE(iec61850_do_find_attribute(dobj, "stVal", IEC61850_FC_ST) != NULL);
    ASSERT_TRUE(iec61850_do_find_attribute(dobj, "ctlVal", IEC61850_FC_CO) != NULL);
    ASSERT_TRUE(iec61850_do_find_attribute(dobj, "ctlModel", IEC61850_FC_CF) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

static void test_cdc_isc(void)
{
    TEST("cdc_isc");
    iec61850_data_object_t *dobj = iec61850_cdc_create_isc("IntCtl1");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_ISC);
    ASSERT_TRUE(dobj->attr_count > 0);
    ASSERT_TRUE(iec61850_do_find_attribute(dobj, "stVal", IEC61850_FC_ST) != NULL);
    ASSERT_TRUE(iec61850_do_find_attribute(dobj, "ctlVal", IEC61850_FC_CO) != NULL);
    ASSERT_TRUE(iec61850_do_find_attribute(dobj, "ctlModel", IEC61850_FC_CF) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

/* 6a extension factories: CURS, CSD, SEQ */
static void test_cdc_curs(void)
{
    TEST("cdc_curs");
    iec61850_data_object_t *dobj = iec61850_cdc_create_curs("Curve1");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_CURS);
    ASSERT_TRUE(dobj->attr_count > 0);
    ASSERT_TRUE(iec61850_do_find_attribute(dobj, "crvPts", IEC61850_FC_SG) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

static void test_cdc_csd(void)
{
    TEST("cdc_csd");
    iec61850_data_object_t *dobj = iec61850_cdc_create_csd("Custom1");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_CSD);
    ASSERT_TRUE(dobj->attr_count > 0);
    ASSERT_TRUE(iec61850_do_find_attribute(dobj, "setVal", IEC61850_FC_SG) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

static void test_cdc_seq(void)
{
    TEST("cdc_seq");
    iec61850_data_object_t *dobj = iec61850_cdc_create_seq("SeqSt1");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_SEQ);
    ASSERT_TRUE(dobj->attr_count > 0);
    ASSERT_TRUE(iec61850_do_find_attribute(dobj, "seqVal", IEC61850_FC_ST) != NULL);
    ASSERT_TRUE(iec61850_do_find_attribute(dobj, "q", IEC61850_FC_ST) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

/* 6a extension factories: HMV, HWYE, HDEL */
static void test_cdc_hmv(void)
{
    TEST("cdc_hmv");
    iec61850_data_object_t *dobj = iec61850_cdc_create_hmv("Hrmc1");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_HMV);
    ASSERT_TRUE(dobj->attr_count > 0);
    ASSERT_TRUE(iec61850_do_find_attribute(dobj, "hVal", IEC61850_FC_MX) != NULL);
    ASSERT_TRUE(iec61850_do_find_attribute(dobj, "q", IEC61850_FC_MX) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

static void test_cdc_hwye(void)
{
    TEST("cdc_hwye");
    iec61850_data_object_t *dobj = iec61850_cdc_create_hwye("HrmA");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_HWYE);
    ASSERT_TRUE(dobj->attr_count > 0);
    ASSERT_TRUE(iec61850_do_find_attribute(dobj, "phsA.hVal", IEC61850_FC_MX) != NULL);
    ASSERT_TRUE(iec61850_do_find_attribute(dobj, "phsB.hVal", IEC61850_FC_MX) != NULL);
    ASSERT_TRUE(iec61850_do_find_attribute(dobj, "phsC.hVal", IEC61850_FC_MX) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

static void test_cdc_hdel(void)
{
    TEST("cdc_hdel");
    iec61850_data_object_t *dobj = iec61850_cdc_create_hdel("HrmD");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_HDEL);
    ASSERT_TRUE(dobj->attr_count > 0);
    ASSERT_TRUE(iec61850_do_find_attribute(dobj, "phsAB.hVal", IEC61850_FC_MX) != NULL);
    ASSERT_TRUE(iec61850_do_find_attribute(dobj, "phsBC.hVal", IEC61850_FC_MX) != NULL);
    ASSERT_TRUE(iec61850_do_find_attribute(dobj, "phsCA.hVal", IEC61850_FC_MX) != NULL);
    iec61850_do_destroy(dobj);
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
    ASSERT_TRUE(strcmp(iec61850_cdc_to_string(IEC61850_CDC_APC), "APC") == 0);
    ASSERT_TRUE(strcmp(iec61850_cdc_to_string(IEC61850_CDC_ENC), "ENC") == 0);
    ASSERT_TRUE(strcmp(iec61850_cdc_to_string(IEC61850_CDC_ISC), "ISC") == 0);
    ASSERT_TRUE(strcmp(iec61850_cdc_to_string(IEC61850_CDC_CURS), "CURS") == 0);
    ASSERT_TRUE(strcmp(iec61850_cdc_to_string(IEC61850_CDC_CSD), "CSD") == 0);
    ASSERT_TRUE(strcmp(iec61850_cdc_to_string(IEC61850_CDC_SEQ), "SEQ") == 0);
    ASSERT_TRUE(strcmp(iec61850_cdc_to_string(IEC61850_CDC_HMV), "HMV") == 0);
    ASSERT_TRUE(strcmp(iec61850_cdc_to_string(IEC61850_CDC_HWYE), "HWYE") == 0);
    ASSERT_TRUE(strcmp(iec61850_cdc_to_string(IEC61850_CDC_HDEL), "HDEL") == 0);
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
    test_cdc_apc();
    test_cdc_enc();
    test_cdc_isc();
    test_cdc_curs();
    test_cdc_csd();
    test_cdc_seq();
    test_cdc_hmv();
    test_cdc_hwye();
    test_cdc_hdel();
    test_cdc_null_name();
    test_cdc_type_strings();
    test_btype_strings();

    printf("\n=== Test Summary ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
