/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for All CDC Factory Functions
 *
 * Comprehensive tests for every CDC type factory, verifying correct
 * CDC enum, attribute counts, attribute names, basic types, and FC
 * string roundtrip conversions.
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

/* Helper: find attribute and verify its btype */
static iec61850_data_attribute_t *find_attr_check(
    iec61850_data_object_t *dobj, const char *name,
    iec61850_fc_t fc, iec61850_btype_t expected_btype)
{
    iec61850_data_attribute_t *da = iec61850_do_find_attribute(dobj, name, fc);
    if (da == NULL) { return NULL; }
    if (da->btype != expected_btype) { return NULL; }
    return da;
}

/* 1. DPS: stVal DBPOS, q, t */
static void test_cdc_create_dps(void)
{
    TEST("cdc_create_dps");
    iec61850_data_object_t *dobj = iec61850_cdc_create_dps("DblSt1");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_DPS);
    ASSERT_EQ((int)dobj->attr_count, 3);
    ASSERT_TRUE(find_attr_check(dobj, "stVal", IEC61850_FC_ST, IEC61850_BTYPE_DBPOS) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "q", IEC61850_FC_ST, IEC61850_BTYPE_QUALITY) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "t", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

/* 2. ENS: stVal ENUMERATED */
static void test_cdc_create_ens(void)
{
    TEST("cdc_create_ens");
    iec61850_data_object_t *dobj = iec61850_cdc_create_ens("Health");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_ENS);
    ASSERT_EQ((int)dobj->attr_count, 3);
    ASSERT_TRUE(find_attr_check(dobj, "stVal", IEC61850_FC_ST, IEC61850_BTYPE_ENUMERATED) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "q", IEC61850_FC_ST, IEC61850_BTYPE_QUALITY) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "t", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

/* 3. ACT: general, phsA, phsB, phsC, q, t */
static void test_cdc_create_act(void)
{
    TEST("cdc_create_act");
    iec61850_data_object_t *dobj = iec61850_cdc_create_act("Op");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_ACT);
    ASSERT_EQ((int)dobj->attr_count, 6);
    ASSERT_TRUE(find_attr_check(dobj, "general", IEC61850_FC_ST, IEC61850_BTYPE_BOOLEAN) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "phsA", IEC61850_FC_ST, IEC61850_BTYPE_BOOLEAN) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "phsB", IEC61850_FC_ST, IEC61850_BTYPE_BOOLEAN) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "phsC", IEC61850_FC_ST, IEC61850_BTYPE_BOOLEAN) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "q", IEC61850_FC_ST, IEC61850_BTYPE_QUALITY) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "t", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

/* 4. ACD: general, dirGeneral, phsA, phsB, phsC, q, t */
static void test_cdc_create_acd(void)
{
    TEST("cdc_create_acd");
    iec61850_data_object_t *dobj = iec61850_cdc_create_acd("DirStr");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_ACD);
    ASSERT_EQ((int)dobj->attr_count, 7);
    ASSERT_TRUE(find_attr_check(dobj, "general", IEC61850_FC_ST, IEC61850_BTYPE_BOOLEAN) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "dirGeneral", IEC61850_FC_ST, IEC61850_BTYPE_ENUMERATED) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "phsA", IEC61850_FC_ST, IEC61850_BTYPE_BOOLEAN) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "phsB", IEC61850_FC_ST, IEC61850_BTYPE_BOOLEAN) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "phsC", IEC61850_FC_ST, IEC61850_BTYPE_BOOLEAN) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "q", IEC61850_FC_ST, IEC61850_BTYPE_QUALITY) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "t", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

/* 5. SEC: cnt INT32U, sev ENUMERATED, t */
static void test_cdc_create_sec(void)
{
    TEST("cdc_create_sec");
    iec61850_data_object_t *dobj = iec61850_cdc_create_sec("SecVio");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_SEC);
    ASSERT_EQ((int)dobj->attr_count, 3);
    ASSERT_TRUE(find_attr_check(dobj, "cnt", IEC61850_FC_ST, IEC61850_BTYPE_INT32U) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "sev", IEC61850_FC_ST, IEC61850_BTYPE_ENUMERATED) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "t", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

/* 6. INC: stVal INT32, q, t, ctlVal INT32, ctlModel ENUMERATED */
static void test_cdc_create_inc(void)
{
    TEST("cdc_create_inc");
    iec61850_data_object_t *dobj = iec61850_cdc_create_inc("TapPos");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_INC);
    ASSERT_EQ((int)dobj->attr_count, 5);
    ASSERT_TRUE(find_attr_check(dobj, "stVal", IEC61850_FC_ST, IEC61850_BTYPE_INT32) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "q", IEC61850_FC_ST, IEC61850_BTYPE_QUALITY) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "t", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "ctlVal", IEC61850_FC_CO, IEC61850_BTYPE_INT32) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "ctlModel", IEC61850_FC_CF, IEC61850_BTYPE_ENUMERATED) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

/* 7. BSC: valWTr STRUCT, q, t, ctlVal STRUCT, ctlModel ENUMERATED */
static void test_cdc_create_bsc(void)
{
    TEST("cdc_create_bsc");
    iec61850_data_object_t *dobj = iec61850_cdc_create_bsc("TapChg");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_BSC);
    ASSERT_EQ((int)dobj->attr_count, 5);
    ASSERT_TRUE(find_attr_check(dobj, "valWTr", IEC61850_FC_ST, IEC61850_BTYPE_STRUCT) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "q", IEC61850_FC_ST, IEC61850_BTYPE_QUALITY) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "t", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "ctlVal", IEC61850_FC_CO, IEC61850_BTYPE_STRUCT) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "ctlModel", IEC61850_FC_CF, IEC61850_BTYPE_ENUMERATED) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

/* 8. CMV: cVal.mag.f, cVal.ang.f, q, t */
static void test_cdc_create_cmv(void)
{
    TEST("cdc_create_cmv");
    iec61850_data_object_t *dobj = iec61850_cdc_create_cmv("PPV");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_CMV);
    ASSERT_EQ((int)dobj->attr_count, 4);
    ASSERT_TRUE(find_attr_check(dobj, "cVal.mag.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "cVal.ang.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "q", IEC61850_FC_MX, IEC61850_BTYPE_QUALITY) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "t", IEC61850_FC_MX, IEC61850_BTYPE_TIMESTAMP) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

/* 9. SAV: instMag.f FLOAT32, q, t */
static void test_cdc_create_sav(void)
{
    TEST("cdc_create_sav");
    iec61850_data_object_t *dobj = iec61850_cdc_create_sav("AmpSv");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_SAV);
    ASSERT_EQ((int)dobj->attr_count, 3);
    ASSERT_TRUE(find_attr_check(dobj, "instMag.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "q", IEC61850_FC_MX, IEC61850_BTYPE_QUALITY) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "t", IEC61850_FC_MX, IEC61850_BTYPE_TIMESTAMP) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

/* 10. WYE: phsA/B/C mag+ang, q, t (8 attrs) */
static void test_cdc_create_wye(void)
{
    TEST("cdc_create_wye");
    iec61850_data_object_t *dobj = iec61850_cdc_create_wye("PhV");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_WYE);
    ASSERT_EQ((int)dobj->attr_count, 8);
    ASSERT_TRUE(find_attr_check(dobj, "phsA.cVal.mag.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "phsA.cVal.ang.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "phsB.cVal.mag.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "phsB.cVal.ang.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "phsC.cVal.mag.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "phsC.cVal.ang.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "q", IEC61850_FC_MX, IEC61850_BTYPE_QUALITY) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "t", IEC61850_FC_MX, IEC61850_BTYPE_TIMESTAMP) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

/* 11. DEL: phsAB/BC/CA mag+ang, q, t (8 attrs) */
static void test_cdc_create_del(void)
{
    TEST("cdc_create_del");
    iec61850_data_object_t *dobj = iec61850_cdc_create_del("PPV");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_DEL);
    ASSERT_EQ((int)dobj->attr_count, 8);
    ASSERT_TRUE(find_attr_check(dobj, "phsAB.cVal.mag.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "phsAB.cVal.ang.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "phsBC.cVal.mag.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "phsBC.cVal.ang.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "phsCA.cVal.mag.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "phsCA.cVal.ang.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "q", IEC61850_FC_MX, IEC61850_BTYPE_QUALITY) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "t", IEC61850_FC_MX, IEC61850_BTYPE_TIMESTAMP) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

/* 12. SPG: setVal BOOLEAN */
static void test_cdc_create_spg(void)
{
    TEST("cdc_create_spg");
    iec61850_data_object_t *dobj = iec61850_cdc_create_spg("SetPt");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_SPG);
    ASSERT_EQ((int)dobj->attr_count, 1);
    ASSERT_TRUE(find_attr_check(dobj, "setVal", IEC61850_FC_SP, IEC61850_BTYPE_BOOLEAN) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

/* 13. ASG: setMag.f FLOAT32 */
static void test_cdc_create_asg(void)
{
    TEST("cdc_create_asg");
    iec61850_data_object_t *dobj = iec61850_cdc_create_asg("SetA");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_ASG);
    ASSERT_EQ((int)dobj->attr_count, 1);
    ASSERT_TRUE(find_attr_check(dobj, "setMag.f", IEC61850_FC_SP, IEC61850_BTYPE_FLOAT32) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

/* 14. LPL: vendor, swRev, d, configRev (DC), ldNs (EX) */
static void test_cdc_create_lpl(void)
{
    TEST("cdc_create_lpl");
    iec61850_data_object_t *dobj = iec61850_cdc_create_lpl("NamPlt");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_LPL);
    ASSERT_EQ((int)dobj->attr_count, 5);
    ASSERT_TRUE(find_attr_check(dobj, "vendor", IEC61850_FC_DC, IEC61850_BTYPE_VISIBLE_STRING) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "swRev", IEC61850_FC_DC, IEC61850_BTYPE_VISIBLE_STRING) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "d", IEC61850_FC_DC, IEC61850_BTYPE_VISIBLE_STRING) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "configRev", IEC61850_FC_DC, IEC61850_BTYPE_VISIBLE_STRING) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "ldNs", IEC61850_FC_EX, IEC61850_BTYPE_VISIBLE_STRING) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

/* 15. DPL: vendor, hwRev, swRev, serNum, model (all DC VISIBLE_STRING) */
static void test_cdc_create_dpl(void)
{
    TEST("cdc_create_dpl");
    iec61850_data_object_t *dobj = iec61850_cdc_create_dpl("PhyNam");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_DPL);
    ASSERT_EQ((int)dobj->attr_count, 5);
    ASSERT_TRUE(find_attr_check(dobj, "vendor", IEC61850_FC_DC, IEC61850_BTYPE_VISIBLE_STRING) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "hwRev", IEC61850_FC_DC, IEC61850_BTYPE_VISIBLE_STRING) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "swRev", IEC61850_FC_DC, IEC61850_BTYPE_VISIBLE_STRING) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "serNum", IEC61850_FC_DC, IEC61850_BTYPE_VISIBLE_STRING) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "model", IEC61850_FC_DC, IEC61850_BTYPE_VISIBLE_STRING) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

/* 16. BCR: actVal INT64, frVal INT64, frTm TIMESTAMP, q, t */
static void test_cdc_create_bcr(void)
{
    TEST("cdc_create_bcr");
    iec61850_data_object_t *dobj = iec61850_cdc_create_bcr("TotW");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_BCR);
    ASSERT_EQ((int)dobj->attr_count, 5);
    ASSERT_TRUE(find_attr_check(dobj, "actVal", IEC61850_FC_ST, IEC61850_BTYPE_INT64) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "frVal", IEC61850_FC_ST, IEC61850_BTYPE_INT64) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "frTm", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "q", IEC61850_FC_ST, IEC61850_BTYPE_QUALITY) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "t", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

/* 17. VSS: stVal VISIBLE_STRING, q, t */
static void test_cdc_create_vss(void)
{
    TEST("cdc_create_vss");
    iec61850_data_object_t *dobj = iec61850_cdc_create_vss("StrVal");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_VSS);
    ASSERT_EQ((int)dobj->attr_count, 3);
    ASSERT_TRUE(find_attr_check(dobj, "stVal", IEC61850_FC_ST, IEC61850_BTYPE_VISIBLE_STRING) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "q", IEC61850_FC_ST, IEC61850_BTYPE_QUALITY) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "t", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

/* 18. FC string roundtrip including SR, OR, BL, EX */
static void test_fc_string_roundtrip(void)
{
    TEST("fc_string_roundtrip");

    /* Test all 13 FC values */
    static const struct {
        iec61850_fc_t fc;
        const char *str;
    } fc_table[] = {
        { IEC61850_FC_ST, "ST" },
        { IEC61850_FC_MX, "MX" },
        { IEC61850_FC_CO, "CO" },
        { IEC61850_FC_SP, "SP" },
        { IEC61850_FC_SV, "SV" },
        { IEC61850_FC_CF, "CF" },
        { IEC61850_FC_DC, "DC" },
        { IEC61850_FC_SG, "SG" },
        { IEC61850_FC_SE, "SE" },
        { IEC61850_FC_SR, "SR" },
        { IEC61850_FC_OR, "OR" },
        { IEC61850_FC_BL, "BL" },
        { IEC61850_FC_EX, "EX" },
    };

    for (size_t i = 0; i < sizeof(fc_table) / sizeof(fc_table[0]); i++) {
        /* fc -> string */
        const char *s = iec61850_fc_to_string(fc_table[i].fc);
        ASSERT_TRUE(s != NULL);
        if (strcmp(s, fc_table[i].str) != 0) {
            printf("fc_to_string(%d) = \"%s\", want \"%s\" ",
                   (int)fc_table[i].fc, s, fc_table[i].str);
            FAIL("fc_to_string mismatch");
        }

        /* string -> fc */
        iec61850_fc_t fc = iec61850_string_to_fc(fc_table[i].str);
        ASSERT_EQ((int)fc, (int)fc_table[i].fc);
    }

    PASS();
}

/* 18. MX3: phsA/B/C mag, q, t (5 attrs) */
static void test_cdc_create_mx3(void)
{
    TEST("cdc_create_mx3");
    iec61850_data_object_t *dobj = iec61850_cdc_create_mx3("ThreePhMeas");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_MX3);
    ASSERT_EQ((int)dobj->attr_count, 5);
    ASSERT_TRUE(find_attr_check(dobj, "phsA.mag.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "phsB.mag.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "phsC.mag.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "q", IEC61850_FC_MX, IEC61850_BTYPE_QUALITY) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "t", IEC61850_FC_MX, IEC61850_BTYPE_TIMESTAMP) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

/* 19. DEL3: phsAB/BC/CA mag, q, t (5 attrs) */
static void test_cdc_create_del3(void)
{
    TEST("cdc_create_del3");
    iec61850_data_object_t *dobj = iec61850_cdc_create_del3("ThreePhDelta");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_DEL3);
    ASSERT_EQ((int)dobj->attr_count, 5);
    ASSERT_TRUE(find_attr_check(dobj, "phsAB.mag.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "phsBC.mag.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "phsCA.mag.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "q", IEC61850_FC_MX, IEC61850_BTYPE_QUALITY) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "t", IEC61850_FC_MX, IEC61850_BTYPE_TIMESTAMP) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

/* 20. APC: mxVal STRUCT, q, t, ctlVal STRUCT, ctlModel, sboClass */
static void test_cdc_create_apc(void)
{
    TEST("cdc_create_apc");
    iec61850_data_object_t *dobj = iec61850_cdc_create_apc("AoutSet");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_APC);
    ASSERT_EQ((int)dobj->attr_count, 6);
    ASSERT_TRUE(find_attr_check(dobj, "mxVal", IEC61850_FC_MX, IEC61850_BTYPE_STRUCT) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "q", IEC61850_FC_MX, IEC61850_BTYPE_QUALITY) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "t", IEC61850_FC_MX, IEC61850_BTYPE_TIMESTAMP) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "ctlVal", IEC61850_FC_CO, IEC61850_BTYPE_STRUCT) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "ctlModel", IEC61850_FC_CF, IEC61850_BTYPE_ENUMERATED) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "sboClass", IEC61850_FC_CF, IEC61850_BTYPE_ENUMERATED) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

/* 21. ENC: stVal ENUMERATED, q, t, ctlVal ENUMERATED, ctlModel */
static void test_cdc_create_enc(void)
{
    TEST("cdc_create_enc");
    iec61850_data_object_t *dobj = iec61850_cdc_create_enc("AutoRecMod");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_ENC);
    ASSERT_EQ((int)dobj->attr_count, 5);
    ASSERT_TRUE(find_attr_check(dobj, "stVal", IEC61850_FC_ST, IEC61850_BTYPE_ENUMERATED) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "q", IEC61850_FC_ST, IEC61850_BTYPE_QUALITY) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "t", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "ctlVal", IEC61850_FC_CO, IEC61850_BTYPE_ENUMERATED) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "ctlModel", IEC61850_FC_CF, IEC61850_BTYPE_ENUMERATED) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

/* 22. ISC: stVal INT32, q, t, ctlVal INT32, ctlModel */
static void test_cdc_create_isc(void)
{
    TEST("cdc_create_isc");
    iec61850_data_object_t *dobj = iec61850_cdc_create_isc("IntStCtl1");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_ISC);
    ASSERT_EQ((int)dobj->attr_count, 5);
    ASSERT_TRUE(find_attr_check(dobj, "stVal", IEC61850_FC_ST, IEC61850_BTYPE_INT32) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "q", IEC61850_FC_ST, IEC61850_BTYPE_QUALITY) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "t", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "ctlVal", IEC61850_FC_CO, IEC61850_BTYPE_INT32) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "ctlModel", IEC61850_FC_CF, IEC61850_BTYPE_ENUMERATED) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

/* 23. CURS: crvPts STRUCT (SG), xUnits/yUnits (CF) */
static void test_cdc_create_curs(void)
{
    TEST("cdc_create_curs");
    iec61850_data_object_t *dobj = iec61850_cdc_create_curs("Crv1");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_CURS);
    ASSERT_EQ((int)dobj->attr_count, 3);
    ASSERT_TRUE(find_attr_check(dobj, "crvPts", IEC61850_FC_SG, IEC61850_BTYPE_STRUCT) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "xUnits", IEC61850_FC_CF, IEC61850_BTYPE_VISIBLE_STRING) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "yUnits", IEC61850_FC_CF, IEC61850_BTYPE_VISIBLE_STRING) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

/* 24. CSD: setVal STRUCT (SG) */
static void test_cdc_create_csd(void)
{
    TEST("cdc_create_csd");
    iec61850_data_object_t *dobj = iec61850_cdc_create_csd("CusSet1");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_CSD);
    ASSERT_EQ((int)dobj->attr_count, 1);
    ASSERT_TRUE(find_attr_check(dobj, "setVal", IEC61850_FC_SG, IEC61850_BTYPE_STRUCT) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

/* 25. SEQ: seqVal STRUCT, q, t */
static void test_cdc_create_seq(void)
{
    TEST("cdc_create_seq");
    iec61850_data_object_t *dobj = iec61850_cdc_create_seq("Seq1");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_SEQ);
    ASSERT_EQ((int)dobj->attr_count, 3);
    ASSERT_TRUE(find_attr_check(dobj, "seqVal", IEC61850_FC_ST, IEC61850_BTYPE_STRUCT) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "q", IEC61850_FC_ST, IEC61850_BTYPE_QUALITY) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "t", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

/* 26. HMV: numHrv INT32U (CF), hVal STRUCT, q, t */
static void test_cdc_create_hmv(void)
{
    TEST("cdc_create_hmv");
    iec61850_data_object_t *dobj = iec61850_cdc_create_hmv("Hrm1");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_HMV);
    ASSERT_EQ((int)dobj->attr_count, 4);
    ASSERT_TRUE(find_attr_check(dobj, "numHrv", IEC61850_FC_CF, IEC61850_BTYPE_INT32U) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "hVal", IEC61850_FC_MX, IEC61850_BTYPE_STRUCT) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "q", IEC61850_FC_MX, IEC61850_BTYPE_QUALITY) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "t", IEC61850_FC_MX, IEC61850_BTYPE_TIMESTAMP) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

/* 27. HWYE: numHrv, phsA/B/C.hVal, q, t (6 attrs) */
static void test_cdc_create_hwye(void)
{
    TEST("cdc_create_hwye");
    iec61850_data_object_t *dobj = iec61850_cdc_create_hwye("HrmPhV");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_HWYE);
    ASSERT_EQ((int)dobj->attr_count, 6);
    ASSERT_TRUE(find_attr_check(dobj, "numHrv", IEC61850_FC_CF, IEC61850_BTYPE_INT32U) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "phsA.hVal", IEC61850_FC_MX, IEC61850_BTYPE_STRUCT) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "phsB.hVal", IEC61850_FC_MX, IEC61850_BTYPE_STRUCT) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "phsC.hVal", IEC61850_FC_MX, IEC61850_BTYPE_STRUCT) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "q", IEC61850_FC_MX, IEC61850_BTYPE_QUALITY) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "t", IEC61850_FC_MX, IEC61850_BTYPE_TIMESTAMP) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

/* 28. HDEL: numHrv, phsAB/BC/CA.hVal, q, t (6 attrs) */
static void test_cdc_create_hdel(void)
{
    TEST("cdc_create_hdel");
    iec61850_data_object_t *dobj = iec61850_cdc_create_hdel("HrmPPV");
    ASSERT_TRUE(dobj != NULL);
    ASSERT_EQ((int)dobj->cdc, (int)IEC61850_CDC_HDEL);
    ASSERT_EQ((int)dobj->attr_count, 6);
    ASSERT_TRUE(find_attr_check(dobj, "numHrv", IEC61850_FC_CF, IEC61850_BTYPE_INT32U) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "phsAB.hVal", IEC61850_FC_MX, IEC61850_BTYPE_STRUCT) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "phsBC.hVal", IEC61850_FC_MX, IEC61850_BTYPE_STRUCT) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "phsCA.hVal", IEC61850_FC_MX, IEC61850_BTYPE_STRUCT) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "q", IEC61850_FC_MX, IEC61850_BTYPE_QUALITY) != NULL);
    ASSERT_TRUE(find_attr_check(dobj, "t", IEC61850_FC_MX, IEC61850_BTYPE_TIMESTAMP) != NULL);
    iec61850_do_destroy(dobj);
    PASS();
}

int main(void)
{
    printf("=== CDC All Factory Tests ===\n");

    test_cdc_create_dps();
    test_cdc_create_ens();
    test_cdc_create_act();
    test_cdc_create_acd();
    test_cdc_create_sec();
    test_cdc_create_inc();
    test_cdc_create_bsc();
    test_cdc_create_cmv();
    test_cdc_create_sav();
    test_cdc_create_wye();
    test_cdc_create_del();
    test_cdc_create_spg();
    test_cdc_create_asg();
    test_cdc_create_lpl();
    test_cdc_create_dpl();
    test_cdc_create_bcr();
    test_cdc_create_vss();
    test_cdc_create_mx3();
    test_cdc_create_del3();
    test_fc_string_roundtrip();
    test_cdc_create_apc();
    test_cdc_create_enc();
    test_cdc_create_isc();
    test_cdc_create_curs();
    test_cdc_create_csd();
    test_cdc_create_seq();
    test_cdc_create_hmv();
    test_cdc_create_hwye();
    test_cdc_create_hdel();

    printf("\n%d tests: %d passed, %d failed\n",
           tests_run, tests_passed, tests_failed);

    return (tests_failed > 0) ? 1 : 0;
}
