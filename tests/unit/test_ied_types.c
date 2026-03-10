/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for IED Type Conversions
 *
 * Exercises all branches of fc_to_string, string_to_fc,
 * btype_to_string, and cdc_to_string.
 */

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
#define ASSERT_STREQ(a, b) do { if (strcmp((a), (b)) != 0) { \
    printf("FAIL: \"%s\" != \"%s\"\n", (a), (b)); \
    tests_failed++; return; } } while (0)
#define ASSERT_EQ(a, b) do { if ((a) != (b)) { \
    printf("FAIL: %s == %s (%d != %d)\n", #a, #b, (int)(a), (int)(b)); \
    tests_failed++; return; } } while (0)

static void test_fc_to_string_all(void)
{
    TEST("fc_to_string_all");
    ASSERT_STREQ(iec61850_fc_to_string(IEC61850_FC_ST), "ST");
    ASSERT_STREQ(iec61850_fc_to_string(IEC61850_FC_MX), "MX");
    ASSERT_STREQ(iec61850_fc_to_string(IEC61850_FC_CO), "CO");
    ASSERT_STREQ(iec61850_fc_to_string(IEC61850_FC_SP), "SP");
    ASSERT_STREQ(iec61850_fc_to_string(IEC61850_FC_SV), "SV");
    ASSERT_STREQ(iec61850_fc_to_string(IEC61850_FC_CF), "CF");
    ASSERT_STREQ(iec61850_fc_to_string(IEC61850_FC_DC), "DC");
    ASSERT_STREQ(iec61850_fc_to_string(IEC61850_FC_SG), "SG");
    ASSERT_STREQ(iec61850_fc_to_string(IEC61850_FC_SE), "SE");
    ASSERT_STREQ(iec61850_fc_to_string(IEC61850_FC_SR), "SR");
    ASSERT_STREQ(iec61850_fc_to_string(IEC61850_FC_OR), "OR");
    ASSERT_STREQ(iec61850_fc_to_string(IEC61850_FC_BL), "BL");
    ASSERT_STREQ(iec61850_fc_to_string(IEC61850_FC_EX), "EX");
    ASSERT_STREQ(iec61850_fc_to_string((iec61850_fc_t)99), "??");
    PASS();
}

static void test_string_to_fc_all(void)
{
    TEST("string_to_fc_all");
    ASSERT_EQ((int)iec61850_string_to_fc("ST"), (int)IEC61850_FC_ST);
    ASSERT_EQ((int)iec61850_string_to_fc("MX"), (int)IEC61850_FC_MX);
    ASSERT_EQ((int)iec61850_string_to_fc("CO"), (int)IEC61850_FC_CO);
    ASSERT_EQ((int)iec61850_string_to_fc("SP"), (int)IEC61850_FC_SP);
    ASSERT_EQ((int)iec61850_string_to_fc("SV"), (int)IEC61850_FC_SV);
    ASSERT_EQ((int)iec61850_string_to_fc("CF"), (int)IEC61850_FC_CF);
    ASSERT_EQ((int)iec61850_string_to_fc("DC"), (int)IEC61850_FC_DC);
    ASSERT_EQ((int)iec61850_string_to_fc("SG"), (int)IEC61850_FC_SG);
    ASSERT_EQ((int)iec61850_string_to_fc("SE"), (int)IEC61850_FC_SE);
    ASSERT_EQ((int)iec61850_string_to_fc("SR"), (int)IEC61850_FC_SR);
    ASSERT_EQ((int)iec61850_string_to_fc("OR"), (int)IEC61850_FC_OR);
    ASSERT_EQ((int)iec61850_string_to_fc("BL"), (int)IEC61850_FC_BL);
    ASSERT_EQ((int)iec61850_string_to_fc("EX"), (int)IEC61850_FC_EX);
    ASSERT_EQ((int)iec61850_string_to_fc(NULL), (int)IEC61850_FC_ST);
    ASSERT_EQ((int)iec61850_string_to_fc("XX"), (int)IEC61850_FC_ST);
    PASS();
}

static void test_btype_to_string_all(void)
{
    TEST("btype_to_string_all");
    ASSERT_STREQ(iec61850_btype_to_string(IEC61850_BTYPE_BOOLEAN), "BOOLEAN");
    ASSERT_STREQ(iec61850_btype_to_string(IEC61850_BTYPE_INT8), "INT8");
    ASSERT_STREQ(iec61850_btype_to_string(IEC61850_BTYPE_INT8U), "INT8U");
    ASSERT_STREQ(iec61850_btype_to_string(IEC61850_BTYPE_INT16), "INT16");
    ASSERT_STREQ(iec61850_btype_to_string(IEC61850_BTYPE_INT16U), "INT16U");
    ASSERT_STREQ(iec61850_btype_to_string(IEC61850_BTYPE_INT32), "INT32");
    ASSERT_STREQ(iec61850_btype_to_string(IEC61850_BTYPE_INT32U), "INT32U");
    ASSERT_STREQ(iec61850_btype_to_string(IEC61850_BTYPE_INT64), "INT64");
    ASSERT_STREQ(iec61850_btype_to_string(IEC61850_BTYPE_INT128), "INT128");
    ASSERT_STREQ(iec61850_btype_to_string(IEC61850_BTYPE_FLOAT32), "FLOAT32");
    ASSERT_STREQ(iec61850_btype_to_string(IEC61850_BTYPE_FLOAT64), "FLOAT64");
    ASSERT_STREQ(iec61850_btype_to_string(IEC61850_BTYPE_ENUMERATED), "Enum");
    ASSERT_STREQ(iec61850_btype_to_string(IEC61850_BTYPE_CODED_ENUM), "CodedEnum");
    ASSERT_STREQ(iec61850_btype_to_string(IEC61850_BTYPE_OCTET_STRING), "OctetString");
    ASSERT_STREQ(iec61850_btype_to_string(IEC61850_BTYPE_VISIBLE_STRING), "VisString");
    ASSERT_STREQ(iec61850_btype_to_string(IEC61850_BTYPE_UNICODE_STRING), "Unicode");
    ASSERT_STREQ(iec61850_btype_to_string(IEC61850_BTYPE_TIMESTAMP), "Timestamp");
    ASSERT_STREQ(iec61850_btype_to_string(IEC61850_BTYPE_QUALITY), "Quality");
    ASSERT_STREQ(iec61850_btype_to_string(IEC61850_BTYPE_CHECK), "Check");
    ASSERT_STREQ(iec61850_btype_to_string(IEC61850_BTYPE_STRUCT), "Struct");
    ASSERT_STREQ(iec61850_btype_to_string(IEC61850_BTYPE_ENTRY_TIME), "EntryTime");
    ASSERT_STREQ(iec61850_btype_to_string(IEC61850_BTYPE_PHYS_COMM_ADDR), "PhyComAddr");
    ASSERT_STREQ(iec61850_btype_to_string(IEC61850_BTYPE_CURRENCY), "Currency");
    ASSERT_STREQ(iec61850_btype_to_string(IEC61850_BTYPE_DBPOS), "Dbpos");
    ASSERT_STREQ(iec61850_btype_to_string((iec61850_btype_t)99), "UNKNOWN");
    PASS();
}

static void test_cdc_to_string_all(void)
{
    TEST("cdc_to_string_all");
    ASSERT_STREQ(iec61850_cdc_to_string(IEC61850_CDC_SPS), "SPS");
    ASSERT_STREQ(iec61850_cdc_to_string(IEC61850_CDC_DPS), "DPS");
    ASSERT_STREQ(iec61850_cdc_to_string(IEC61850_CDC_INS), "INS");
    ASSERT_STREQ(iec61850_cdc_to_string(IEC61850_CDC_ENS), "ENS");
    ASSERT_STREQ(iec61850_cdc_to_string(IEC61850_CDC_ACT), "ACT");
    ASSERT_STREQ(iec61850_cdc_to_string(IEC61850_CDC_ACD), "ACD");
    ASSERT_STREQ(iec61850_cdc_to_string(IEC61850_CDC_SEC), "SEC");
    ASSERT_STREQ(iec61850_cdc_to_string(IEC61850_CDC_BSC), "BSC");
    ASSERT_STREQ(iec61850_cdc_to_string(IEC61850_CDC_SPC), "SPC");
    ASSERT_STREQ(iec61850_cdc_to_string(IEC61850_CDC_DPC), "DPC");
    ASSERT_STREQ(iec61850_cdc_to_string(IEC61850_CDC_INC), "INC");
    ASSERT_STREQ(iec61850_cdc_to_string(IEC61850_CDC_MV), "MV");
    ASSERT_STREQ(iec61850_cdc_to_string(IEC61850_CDC_CMV), "CMV");
    ASSERT_STREQ(iec61850_cdc_to_string(IEC61850_CDC_SAV), "SAV");
    ASSERT_STREQ(iec61850_cdc_to_string(IEC61850_CDC_WYE), "WYE");
    ASSERT_STREQ(iec61850_cdc_to_string(IEC61850_CDC_DEL), "DEL");
    ASSERT_STREQ(iec61850_cdc_to_string(IEC61850_CDC_SPG), "SPG");
    ASSERT_STREQ(iec61850_cdc_to_string(IEC61850_CDC_ASG), "ASG");
    ASSERT_STREQ(iec61850_cdc_to_string(IEC61850_CDC_VSS), "VSS");
    ASSERT_STREQ(iec61850_cdc_to_string(IEC61850_CDC_LPL), "LPL");
    ASSERT_STREQ(iec61850_cdc_to_string(IEC61850_CDC_DPL), "DPL");
    ASSERT_STREQ(iec61850_cdc_to_string(IEC61850_CDC_BCR), "BCR");
    ASSERT_STREQ(iec61850_cdc_to_string(IEC61850_CDC_MX3), "MX3");
    ASSERT_STREQ(iec61850_cdc_to_string(IEC61850_CDC_DEL3), "DEL3");
    ASSERT_STREQ(iec61850_cdc_to_string((iec61850_cdc_t)99), "UNKNOWN");
    PASS();
}

int main(void)
{
    printf("=== IED Types Tests ===\n");

    test_fc_to_string_all();
    test_string_to_fc_all();
    test_btype_to_string_all();
    test_cdc_to_string_all();

    printf("\nTests: %d run, %d passed, %d failed\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
