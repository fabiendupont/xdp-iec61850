/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for SCL Parser
 *
 * Tests: load SCD file, extract GOOSE CB, extract SV CB,
 * extract RCB (URCB/BRCB), extract DataSet/FCDA,
 * query by name, nonexistent IED, communication section.
 *
 * License: BSD-2-Clause
 */

#include "scl/scl_parser.h"

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

static void test_load_valid_scd(void)
{
    TEST("load_valid_scd");
    char path[512];
    build_path(path, sizeof(path), "test.scd");

    iec61850_scl_doc_t doc;
    iec61850_scl_doc_init(&doc);
    int ret = iec61850_scl_parse_file(path, "IED1", &doc);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(strcmp(doc.ied_name, "IED1") == 0);
    PASS();
}

static void test_load_nonexistent(void)
{
    TEST("load_nonexistent");
    iec61850_scl_doc_t doc;
    iec61850_scl_doc_init(&doc);
    int ret = iec61850_scl_parse_file("/nonexistent/test.scd", "IED1", &doc);
    ASSERT_TRUE(ret != 0);
    PASS();
}

static void test_goose_cb_extraction(void)
{
    TEST("goose_cb_extraction");
    char path[512];
    build_path(path, sizeof(path), "test.scd");

    iec61850_scl_doc_t doc;
    iec61850_scl_doc_init(&doc);
    iec61850_scl_parse_file(path, "IED1", &doc);

    ASSERT_TRUE(doc.goose_cb_count >= 1);

    const iec61850_scl_goose_cb_t *gcb = iec61850_scl_find_goose_cb(&doc, "gcb01");
    ASSERT_TRUE(gcb != NULL);
    ASSERT_TRUE(strcmp(gcb->cb_name, "gcb01") == 0);
    ASSERT_TRUE(strcmp(gcb->dataset, "DS1") == 0);
    ASSERT_EQ((int)gcb->conf_rev, 1);
    /* goID from attribute */
    ASSERT_TRUE(strcmp(gcb->go_id, "GOOSE_ID_1") == 0);
    /* MAC-Address from Communication section */
    ASSERT_TRUE(strcmp(gcb->mac_address, "01-0C-CD-01-00-01") == 0);
    /* VLAN-ID parsed with auto-detect base */
    ASSERT_EQ((int)gcb->vlan_id, 100);
    ASSERT_EQ((int)gcb->vlan_priority, 4);
    PASS();
}

static void test_sv_cb_extraction(void)
{
    TEST("sv_cb_extraction");
    char path[512];
    build_path(path, sizeof(path), "test.scd");

    iec61850_scl_doc_t doc;
    iec61850_scl_doc_init(&doc);
    iec61850_scl_parse_file(path, "IED1", &doc);

    ASSERT_TRUE(doc.sv_cb_count >= 1);

    const iec61850_scl_sv_cb_t *svcb = iec61850_scl_find_sv_cb(&doc, "MSVCB01");
    ASSERT_TRUE(svcb != NULL);
    ASSERT_TRUE(strcmp(svcb->cb_name, "MSVCB01") == 0);
    ASSERT_TRUE(strcmp(svcb->sv_id, "SV_PUB_1") == 0);
    ASSERT_EQ((int)svcb->smp_rate, 80);
    PASS();
}

static void test_rcb_extraction(void)
{
    TEST("rcb_extraction");
    char path[512];
    build_path(path, sizeof(path), "test.scd");

    iec61850_scl_doc_t doc;
    iec61850_scl_doc_init(&doc);
    iec61850_scl_parse_file(path, "IED1", &doc);

    ASSERT_TRUE(doc.rcb_count >= 2);

    /* URCB */
    const iec61850_scl_rcb_t *urcb = iec61850_scl_find_rcb(&doc, "URCB01");
    ASSERT_TRUE(urcb != NULL);
    ASSERT_TRUE(!urcb->buffered);
    ASSERT_TRUE(urcb->trg_dchg);
    ASSERT_TRUE(urcb->trg_qchg);
    ASSERT_TRUE(!urcb->trg_dupd);
    ASSERT_TRUE(urcb->trg_gi);
    ASSERT_TRUE(urcb->opt_seq_num);
    ASSERT_TRUE(urcb->opt_timestamp);
    ASSERT_TRUE(urcb->opt_reason);
    ASSERT_TRUE(!urcb->opt_dataref);

    /* BRCB */
    const iec61850_scl_rcb_t *brcb = iec61850_scl_find_rcb(&doc, "BRCB01");
    ASSERT_TRUE(brcb != NULL);
    ASSERT_TRUE(brcb->buffered);
    ASSERT_EQ((int)brcb->buf_time, 500);
    ASSERT_EQ((int)brcb->intg_pd, 10000);
    ASSERT_TRUE(brcb->trg_dchg);
    ASSERT_TRUE(brcb->trg_qchg);
    ASSERT_TRUE(brcb->trg_dupd);
    ASSERT_TRUE(brcb->trg_period);
    ASSERT_TRUE(brcb->trg_gi);
    ASSERT_TRUE(brcb->opt_entryid);
    ASSERT_TRUE(brcb->opt_bufovfl);
    ASSERT_TRUE(brcb->opt_configref);
    PASS();
}

static void test_dataset_extraction(void)
{
    TEST("dataset_extraction");
    char path[512];
    build_path(path, sizeof(path), "test.scd");

    iec61850_scl_doc_t doc;
    iec61850_scl_doc_init(&doc);
    iec61850_scl_parse_file(path, "IED1", &doc);

    ASSERT_TRUE(doc.dataset_count >= 2);

    const iec61850_scl_dataset_t *ds1 = iec61850_scl_find_dataset(&doc, "DS1");
    ASSERT_TRUE(ds1 != NULL);
    ASSERT_EQ((int)ds1->member_count, 2);
    ASSERT_TRUE(strcmp(ds1->members[0].ln_class, "XCBR") == 0);
    ASSERT_TRUE(strcmp(ds1->members[0].do_name, "Pos") == 0);
    ASSERT_TRUE(strcmp(ds1->members[0].da_name, "stVal") == 0);
    ASSERT_TRUE(strcmp(ds1->members[0].fc, "ST") == 0);

    const iec61850_scl_dataset_t *ds_sv = iec61850_scl_find_dataset(&doc, "DS_SV");
    ASSERT_TRUE(ds_sv != NULL);
    ASSERT_EQ((int)ds_sv->member_count, 4);
    PASS();
}

static void test_ld_ln_structure(void)
{
    TEST("ld_ln_structure");
    char path[512];
    build_path(path, sizeof(path), "test.scd");

    iec61850_scl_doc_t doc;
    iec61850_scl_doc_init(&doc);
    iec61850_scl_parse_file(path, "IED1", &doc);

    /* Should have 1 LD */
    ASSERT_TRUE(doc.ld_count >= 1);
    ASSERT_TRUE(strcmp(doc.lds[0].inst, "LD0") == 0);

    /* LD0 should have LN0 + LPHD + XCBR + MMXU = 4 LNs */
    ASSERT_TRUE(doc.lds[0].ln_count >= 4);
    PASS();
}

static void test_query_nonexistent(void)
{
    TEST("query_nonexistent");
    char path[512];
    build_path(path, sizeof(path), "test.scd");

    iec61850_scl_doc_t doc;
    iec61850_scl_doc_init(&doc);
    iec61850_scl_parse_file(path, "IED1", &doc);

    ASSERT_TRUE(iec61850_scl_find_goose_cb(&doc, "NOPE") == NULL);
    ASSERT_TRUE(iec61850_scl_find_sv_cb(&doc, "NOPE") == NULL);
    ASSERT_TRUE(iec61850_scl_find_rcb(&doc, "NOPE") == NULL);
    ASSERT_TRUE(iec61850_scl_find_dataset(&doc, "NOPE") == NULL);
    PASS();
}

static void test_null_args(void)
{
    TEST("null_args");
    iec61850_scl_doc_t doc;
    ASSERT_TRUE(iec61850_scl_parse_file(NULL, "IED1", &doc) != 0);
    ASSERT_TRUE(iec61850_scl_parse_file("test.scd", "IED1", NULL) != 0);
    ASSERT_TRUE(iec61850_scl_find_goose_cb(NULL, "gcb01") == NULL);
    ASSERT_TRUE(iec61850_scl_find_goose_cb(&doc, NULL) == NULL);
    PASS();
}

static void test_lnode_type_extraction(void)
{
    TEST("lnode_type_extraction");
    char path[512];
    build_path(path, sizeof(path), "test.scd");

    iec61850_scl_doc_t doc;
    iec61850_scl_doc_init(&doc);
    iec61850_scl_parse_file(path, "IED1", &doc);

    ASSERT_TRUE(doc.lnode_type_count >= 4);

    const iec61850_scl_lnode_type_t *xcbr = iec61850_scl_find_lnode_type(&doc, "XCBRType");
    ASSERT_TRUE(xcbr != NULL);
    ASSERT_TRUE(strcmp(xcbr->ln_class, "XCBR") == 0);
    ASSERT_EQ((int)xcbr->do_count, 4);
    ASSERT_TRUE(strcmp(xcbr->dos[0].name, "Pos") == 0);
    ASSERT_TRUE(strcmp(xcbr->dos[0].type, "DPC_1") == 0);
    ASSERT_TRUE(strcmp(xcbr->dos[1].name, "BlkOpn") == 0);

    const iec61850_scl_lnode_type_t *mmxu = iec61850_scl_find_lnode_type(&doc, "MMXUType");
    ASSERT_TRUE(mmxu != NULL);
    ASSERT_TRUE(strcmp(mmxu->ln_class, "MMXU") == 0);
    ASSERT_EQ((int)mmxu->do_count, 4);

    ASSERT_TRUE(iec61850_scl_find_lnode_type(&doc, "NONEXISTENT") == NULL);
    ASSERT_TRUE(iec61850_scl_find_lnode_type(NULL, "XCBRType") == NULL);
    PASS();
}

static void test_do_type_extraction(void)
{
    TEST("do_type_extraction");
    char path[512];
    build_path(path, sizeof(path), "test.scd");

    iec61850_scl_doc_t doc;
    iec61850_scl_doc_init(&doc);
    iec61850_scl_parse_file(path, "IED1", &doc);

    ASSERT_TRUE(doc.do_type_count >= 7);

    const iec61850_scl_do_type_t *dpc = iec61850_scl_find_do_type(&doc, "DPC_1");
    ASSERT_TRUE(dpc != NULL);
    ASSERT_TRUE(strcmp(dpc->cdc, "DPC") == 0);
    ASSERT_TRUE(dpc->da_count >= 6);
    ASSERT_TRUE(strcmp(dpc->das[0].name, "stVal") == 0);
    ASSERT_TRUE(strcmp(dpc->das[0].fc, "ST") == 0);
    ASSERT_TRUE(strcmp(dpc->das[0].btype, "Dbpos") == 0);

    /* Check Struct-typed DA */
    ASSERT_TRUE(strcmp(dpc->das[4].name, "origin") == 0);
    ASSERT_TRUE(strcmp(dpc->das[4].btype, "Struct") == 0);
    ASSERT_TRUE(strcmp(dpc->das[4].type, "Originator_1") == 0);

    /* Check Enum-typed DA */
    ASSERT_TRUE(strcmp(dpc->das[5].name, "ctlModel") == 0);
    ASSERT_TRUE(strcmp(dpc->das[5].btype, "Enum") == 0);
    ASSERT_TRUE(strcmp(dpc->das[5].type, "CtlModels") == 0);

    /* WYE type has SDO children */
    const iec61850_scl_do_type_t *wye = iec61850_scl_find_do_type(&doc, "WYE_1");
    ASSERT_TRUE(wye != NULL);
    ASSERT_TRUE(strcmp(wye->cdc, "WYE") == 0);
    ASSERT_EQ((int)wye->da_count, 3);
    ASSERT_TRUE(strcmp(wye->das[0].name, "phsA") == 0);

    ASSERT_TRUE(iec61850_scl_find_do_type(&doc, "NONEXISTENT") == NULL);
    PASS();
}

static void test_da_type_extraction(void)
{
    TEST("da_type_extraction");
    char path[512];
    build_path(path, sizeof(path), "test.scd");

    iec61850_scl_doc_t doc;
    iec61850_scl_doc_init(&doc);
    iec61850_scl_parse_file(path, "IED1", &doc);

    ASSERT_TRUE(doc.da_type_count >= 3);

    const iec61850_scl_da_type_t *av = iec61850_scl_find_da_type(&doc, "AnalogueValue_1");
    ASSERT_TRUE(av != NULL);
    ASSERT_EQ((int)av->bda_count, 1);
    ASSERT_TRUE(strcmp(av->bdas[0].name, "f") == 0);
    ASSERT_TRUE(strcmp(av->bdas[0].btype, "FLOAT32") == 0);

    const iec61850_scl_da_type_t *vec = iec61850_scl_find_da_type(&doc, "Vector_1");
    ASSERT_TRUE(vec != NULL);
    ASSERT_EQ((int)vec->bda_count, 2);
    ASSERT_TRUE(strcmp(vec->bdas[0].name, "mag") == 0);
    ASSERT_TRUE(strcmp(vec->bdas[0].btype, "Struct") == 0);
    ASSERT_TRUE(strcmp(vec->bdas[0].type, "AnalogueValue_1") == 0);

    ASSERT_TRUE(iec61850_scl_find_da_type(&doc, "NONEXISTENT") == NULL);
    PASS();
}

static void test_enum_type_extraction(void)
{
    TEST("enum_type_extraction");
    char path[512];
    build_path(path, sizeof(path), "test.scd");

    iec61850_scl_doc_t doc;
    iec61850_scl_doc_init(&doc);
    iec61850_scl_parse_file(path, "IED1", &doc);

    ASSERT_TRUE(doc.enum_type_count >= 2);

    const iec61850_scl_enum_type_t *ctl = iec61850_scl_find_enum_type(&doc, "CtlModels");
    ASSERT_TRUE(ctl != NULL);
    ASSERT_EQ((int)ctl->val_count, 5);
    ASSERT_EQ((int)ctl->vals[0].ord, 0);
    ASSERT_TRUE(strcmp(ctl->vals[0].val, "status-only") == 0);
    ASSERT_EQ((int)ctl->vals[4].ord, 4);
    ASSERT_TRUE(strcmp(ctl->vals[4].val, "sbo-with-enhanced-security") == 0);

    const iec61850_scl_enum_type_t *orcat = iec61850_scl_find_enum_type(&doc, "OrCat");
    ASSERT_TRUE(orcat != NULL);
    ASSERT_EQ((int)orcat->val_count, 4);

    ASSERT_TRUE(iec61850_scl_find_enum_type(&doc, "NONEXISTENT") == NULL);
    PASS();
}

static void test_type_cross_references(void)
{
    TEST("type_cross_references");
    char path[512];
    build_path(path, sizeof(path), "test.scd");

    iec61850_scl_doc_t doc;
    iec61850_scl_doc_init(&doc);
    iec61850_scl_parse_file(path, "IED1", &doc);

    /* LN lnType references should resolve to LNodeType */
    ASSERT_TRUE(doc.lds[0].ln_count >= 1);
    const char *ln_type = doc.lds[0].lns[0].ln_type;
    const iec61850_scl_lnode_type_t *lt = iec61850_scl_find_lnode_type(&doc, ln_type);
    ASSERT_TRUE(lt != NULL);

    /* LNodeType DO references should resolve to DOType */
    ASSERT_TRUE(lt->do_count > 0);
    const iec61850_scl_do_type_t *dt = iec61850_scl_find_do_type(&doc, lt->dos[0].type);
    ASSERT_TRUE(dt != NULL);

    /* DOType DA with bType=Enum should resolve to EnumType */
    const iec61850_scl_do_type_t *dpc = iec61850_scl_find_do_type(&doc, "DPC_1");
    ASSERT_TRUE(dpc != NULL);
    for (size_t i = 0; i < dpc->da_count; i++) {
        if (strcmp(dpc->das[i].btype, "Enum") == 0) {
            const iec61850_scl_enum_type_t *et =
                iec61850_scl_find_enum_type(&doc, dpc->das[i].type);
            ASSERT_TRUE(et != NULL);
        }
    }

    PASS();
}

int main(void)
{
    printf("\n=== SCL Parser Tests ===\n");

    test_load_valid_scd();
    test_load_nonexistent();
    test_goose_cb_extraction();
    test_sv_cb_extraction();
    test_rcb_extraction();
    test_dataset_extraction();
    test_ld_ln_structure();
    test_query_nonexistent();
    test_null_args();
    test_lnode_type_extraction();
    test_do_type_extraction();
    test_da_type_extraction();
    test_enum_type_extraction();
    test_type_cross_references();

    printf("\n=== Test Summary ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
