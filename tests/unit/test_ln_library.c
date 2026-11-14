/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for the IEC 61850-7-4 LN Class Library (WP-6b)
 *
 * Covers the pilot class set (11 classes — the WP-6b brief says
 * "12" but enumerates 11; see the WP-6b report):
 *   group 1: LLN0, LPHD, XCBR, XSWI, CSWI, CILO
 *   group 2: PTOC, PDIS
 *   group 3: MMXU, MMTR
 *   group 4: GGIO
 *
 * Tests: lookup, per-class instantiation (M-DO tree via the model
 * introspection API), optional-DO addition with the documented
 * error codes, error paths, and an MMS closed loop (class API ->
 * IED model -> MMS data store -> DOA read).
 *
 * Like test_setting_groups / test_ptp (registered unconditionally
 * in tests/meson.build but linking MMS-gated objects), this test
 * requires -Denable_mms=true to link — the WP-6b verification
 * configuration. See the note above the closed loop for the
 * reported meson change.
 */

#include "ied/ln_schema.h"
#include "ied/ied_data_model.h"

#include "mms/mms_data_store.h"
#include "scl/scl_ied_builder.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { tests_run++; printf("  [TEST] %s ... ", name); } while (0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg) do { tests_failed++; printf("FAIL: %s\n", msg); return; } while (0)
#define ASSERT_TRUE(cond) do { if (!(cond)) { FAIL(#cond); return; } } while (0)
#define ASSERT_EQ(a, b) do { if ((a) != (b)) { \
    printf("FAIL: %s == %s (%d != %d)\n", #a, #b, (int)(a), (int)(b)); \
    tests_failed++; return; } } while (0)

/* ========================================================================
 * Pilot class expectations (independent of the tables under test)
 * ======================================================================== */

typedef struct {
    const char *name;
    iec61850_cdc_t cdc;
} do_expect_t;

typedef struct {
    const char *ln_class;
    const char *ln_inst;
    const do_expect_t *m_dos;       /* NULL-terminated */
    uint32_t total_do_count;        /* M + O per the class table */
    const char *absent_o_do;        /* spot-check: optional, not instantiated */
} class_expect_t;

static const do_expect_t m_lln0[] = {
    { "Beh", IEC61850_CDC_INS }, { "Health", IEC61850_CDC_INS },
    { "Mod", IEC61850_CDC_INC }, { "NamPlt", IEC61850_CDC_LPL },
    { NULL, (iec61850_cdc_t)0 },
};
static const do_expect_t m_lphd[] = {
    { "Beh", IEC61850_CDC_INS }, { "Health", IEC61850_CDC_INS },
    { "Mod", IEC61850_CDC_INC }, { "NamPlt", IEC61850_CDC_LPL },
    { "PhyHealth", IEC61850_CDC_ENS }, { "PhyNam", IEC61850_CDC_DPL },
    { NULL, (iec61850_cdc_t)0 },
};
static const do_expect_t m_xcbr[] = {
    { "Beh", IEC61850_CDC_INS }, { "BlkCls", IEC61850_CDC_SPS },
    { "BlkOpn", IEC61850_CDC_SPS }, { "Health", IEC61850_CDC_INS },
    { "Mod", IEC61850_CDC_INC }, { "NamPlt", IEC61850_CDC_LPL },
    { "Pos", IEC61850_CDC_DPC },
    { NULL, (iec61850_cdc_t)0 },
};
static const do_expect_t m_xswi[] = {
    { "Beh", IEC61850_CDC_INS }, { "Health", IEC61850_CDC_INS },
    { "Mod", IEC61850_CDC_INC }, { "NamPlt", IEC61850_CDC_LPL },
    { "Pos", IEC61850_CDC_DPC },
    { NULL, (iec61850_cdc_t)0 },
};
static const do_expect_t m_cswi[] = {
    { "Beh", IEC61850_CDC_INS }, { "Health", IEC61850_CDC_INS },
    { "Mod", IEC61850_CDC_INC }, { "NamPlt", IEC61850_CDC_LPL },
    { "Pos", IEC61850_CDC_DPC },
    { NULL, (iec61850_cdc_t)0 },
};
static const do_expect_t m_cilo[] = {
    { "Beh", IEC61850_CDC_INS }, { "EnaCls", IEC61850_CDC_SPS },
    { "EnaOpn", IEC61850_CDC_SPS }, { "Health", IEC61850_CDC_INS },
    { "Mod", IEC61850_CDC_INC }, { "NamPlt", IEC61850_CDC_LPL },
    { NULL, (iec61850_cdc_t)0 },
};
static const do_expect_t m_ptoc[] = {
    { "Beh", IEC61850_CDC_INS }, { "Health", IEC61850_CDC_INS },
    { "Mod", IEC61850_CDC_INC }, { "NamPlt", IEC61850_CDC_LPL },
    { "Op", IEC61850_CDC_ACT }, { "Str", IEC61850_CDC_ACD },
    { NULL, (iec61850_cdc_t)0 },
};
static const do_expect_t m_pdis[] = {
    { "Beh", IEC61850_CDC_INS }, { "Health", IEC61850_CDC_INS },
    { "Mod", IEC61850_CDC_INC }, { "NamPlt", IEC61850_CDC_LPL },
    { "Op", IEC61850_CDC_ACT }, { "Str", IEC61850_CDC_ACD },
    { NULL, (iec61850_cdc_t)0 },
};
static const do_expect_t m_mmxu[] = {
    { "Beh", IEC61850_CDC_INS }, { "Health", IEC61850_CDC_INS },
    { "Mod", IEC61850_CDC_INC }, { "NamPlt", IEC61850_CDC_LPL },
    { NULL, (iec61850_cdc_t)0 },
};
static const do_expect_t m_mmtr[] = {
    { "Beh", IEC61850_CDC_INS }, { "Health", IEC61850_CDC_INS },
    { "Mod", IEC61850_CDC_INC }, { "NamPlt", IEC61850_CDC_LPL },
    { NULL, (iec61850_cdc_t)0 },
};
static const do_expect_t m_ggio[] = {
    { "Beh", IEC61850_CDC_INS }, { "Health", IEC61850_CDC_INS },
    { "Mod", IEC61850_CDC_INC }, { "NamPlt", IEC61850_CDC_LPL },
    { NULL, (iec61850_cdc_t)0 },
};

static const class_expect_t pilot_classes[] = {
    { "LLN0", "",   m_lln0, 4U,  NULL      },
    { "LPHD", "1",  m_lphd, 7U,  "Proxy"   },
    { "XCBR", "1",  m_xcbr, 8U,  "CBOpCnt" },
    { "XSWI", "1",  m_xswi, 7U,  "BlkOpn"  },
    { "CSWI", "1",  m_cswi, 5U,  NULL      },
    { "CILO", "1",  m_cilo, 6U,  NULL      },
    { "PTOC", "1",  m_ptoc, 7U,  "StrVal"  },
    { "PDIS", "1",  m_pdis, 6U,  NULL      },
    { "MMXU", "1",  m_mmxu, 16U, "TotW"    },
    { "MMTR", "1",  m_mmtr, 16U, "TotWh"   },
    { "GGIO", "1",  m_ggio, 10U, "Ind1"    },
};

#define PILOT_CLASS_COUNT \
    (sizeof(pilot_classes) / sizeof(pilot_classes[0]))

/* ========================================================================
 * Helpers
 * ======================================================================== */

static void check_do(iec61850_logical_node_t *ln, const char *do_name,
                      iec61850_cdc_t cdc)
{
    iec61850_data_object_t *dobj = iec61850_ln_find_do(ln, do_name);
    if (dobj == NULL) {
        printf("FAIL: DO %s missing\n", do_name);
        tests_failed++;
        return;
    }
    if (dobj->cdc != cdc) {
        printf("FAIL: DO %s CDC %d != %d\n", do_name,
               (int)dobj->cdc, (int)cdc);
        tests_failed++;
        return;
    }
    if (dobj->attr_count == 0U) {
        printf("FAIL: DO %s has no attributes\n", do_name);
        tests_failed++;
    }
}

static void check_da(iec61850_logical_node_t *ln, const char *do_name,
                      const char *da_name, iec61850_fc_t fc)
{
    iec61850_data_object_t *dobj = iec61850_ln_find_do(ln, do_name);
    if (dobj == NULL) {
        printf("FAIL: DO %s missing (DA check)\n", do_name);
        tests_failed++;
        return;
    }
    if (iec61850_do_find_attribute(dobj, da_name, fc) == NULL) {
        printf("FAIL: %s.%s (FC %d) missing\n", do_name, da_name, (int)fc);
        tests_failed++;
    }
}

/* ========================================================================
 * Lookup
 * ======================================================================== */

static void test_lookup(void)
{
    TEST("class_lookup_found");
    for (size_t i = 0; i < PILOT_CLASS_COUNT; i++) {
        const iec61850_ln_class_def_t *def =
            iec61850_ln_class_lookup(pilot_classes[i].ln_class);
        if (def == NULL) {
            printf("FAIL: %s not found\n", pilot_classes[i].ln_class);
            FAIL("lookup returned NULL");
        }
        if (strcmp(def->ln_class, pilot_classes[i].ln_class) != 0) {
            FAIL("lookup returned wrong class");
        }
        if (def->do_count != pilot_classes[i].total_do_count) {
            printf("FAIL: %s do_count %u != %u\n", def->ln_class,
                   (unsigned)def->do_count,
                   (unsigned)pilot_classes[i].total_do_count);
            FAIL("do_count mismatch");
        }
    }
    PASS();

    TEST("class_lookup_not_found");
    ASSERT_TRUE(iec61850_ln_class_lookup("ZZZZ") == NULL);
    ASSERT_TRUE(iec61850_ln_class_lookup(NULL) == NULL);
    ASSERT_TRUE(iec61850_ln_class_lookup("") == NULL);
    /* case-sensitive per 7-4 naming */
    ASSERT_TRUE(iec61850_ln_class_lookup("xcbr") == NULL);
    ASSERT_TRUE(iec61850_ln_class_lookup("XCB") == NULL);
    ASSERT_TRUE(iec61850_ln_class_lookup("XCBR1") == NULL);
    PASS();

    TEST("class_count");
    ASSERT_EQ((int)iec61850_ln_class_count(), (int)PILOT_CLASS_COUNT);
    PASS();
}

/* ========================================================================
 * Instantiation
 * ======================================================================== */

static void test_all_classes_instantiate(void)
{
    TEST("all_registered_classes_instantiate");

    uint32_t n = iec61850_ln_class_count();
    uint32_t built = 0U;
    uint32_t failures = 0U;

    if (n < 11U) {
        printf("FAIL: only %u classes registered (pilot floor 11)\n",
               (unsigned)n);
        FAIL("class count below pilot floor");
    }

    for (uint32_t i = 0U; i < n; i++) {
        const iec61850_ln_class_def_t *def = iec61850_ln_class_at(i);
        iec61850_ied_model_t *model;
        iec61850_logical_device_t *ld;

        if (def == NULL) {
            printf("FAIL: class_at(%u) returned NULL\n", (unsigned)i);
            FAIL("enumeration hole");
        }
        if ((def->ln_class == NULL) || (def->ln_class[0] == '\0') ||
            (def->do_count == 0U) || (def->dos == NULL)) {
            printf("FAIL: %s malformed definition\n",
                   def->ln_class ? def->ln_class : "(null)");
            FAIL("malformed class definition");
        }

        model = calloc(1U, sizeof(*model));
        if (model == NULL) { FAIL("model alloc"); }
        (void)iec61850_ied_model_init(model, "IED1");
        ld = iec61850_ld_create("LD0");
        if ((ld == NULL) || (iec61850_ied_model_add_ld(model, ld) != 0)) {
            FAIL("model setup");
        }

        iec61850_logical_node_t *ln = iec61850_ied_model_add_ln_class(
            model, "LD0", def->ln_class, "1", "");
        if (ln == NULL) {
            printf("  %s: instantiation FAILED\n", def->ln_class);
            failures++;
        } else {
            /* Every M DO must be present in the instantiated LN. */
            for (uint32_t d = 0U; d < def->do_count; d++) {
                const iec61850_ln_do_def_t *dd = &def->dos[d];
                iec61850_data_object_t *dobj = NULL;

                if (!dd->mandatory) { continue; }
                for (uint32_t k = 0U; k < ln->do_count; k++) {
                    if (strcmp(ln->data_objects[k]->name,
                               dd->do_name) == 0) {
                        dobj = ln->data_objects[k];
                        break;
                    }
                }
                if (dobj == NULL) {
                    printf("  %s: M DO %s missing\n",
                           def->ln_class, dd->do_name);
                    failures++;
                } else if ((dobj->attr_count == 0U) &&
                           (dobj->sub_count == 0U)) {
                    printf("  %s: DO %s has an empty tree\n",
                           def->ln_class, dd->do_name);
                    failures++;
                }
            }
            built++;
        }
        /* model leaked: bounded by class count, process exits */
    }

    printf("  (%u classes: %u instantiated, %u failures)\n",
           (unsigned)n, (unsigned)built, (unsigned)failures);
    if (failures > 0U) {
        FAIL("class instantiation failures");
    }
    PASS();
}

static void test_instantiate_all_classes(void)
{
    TEST("instantiate_all_classes");

    for (size_t i = 0; i < PILOT_CLASS_COUNT; i++) {
        const class_expect_t *exp = &pilot_classes[i];
        char label[64];
        uint32_t m_count = 0U;

        iec61850_ied_model_t model;
        iec61850_ied_model_init(&model, "IED1");
        iec61850_logical_device_t *ld = iec61850_ld_create("LD0");
        ASSERT_EQ(iec61850_ied_model_add_ld(&model, ld), 0);

        iec61850_logical_node_t *ln = iec61850_ied_model_add_ln_class(
            &model, "LD0", exp->ln_class, exp->ln_inst, "");
        if (ln == NULL) {
            printf("FAIL: %s instantiation returned NULL\n", exp->ln_class);
            FAIL("add_ln_class failed");
        }

        /* LN present in the LD, correct class */
        ASSERT_EQ((int)ld->ln_count, 1);
        ASSERT_TRUE(strcmp(ln->ln_class, exp->ln_class) == 0);
        ASSERT_TRUE(iec61850_ld_find_ln(ld, exp->ln_class) == ln);

        /* Full LN name convention (prefix + class + inst, stored in
         * ln_inst — the scl_ied_builder / register_mms convention) */
        (void)snprintf(label, sizeof(label), "%s%s",
                       exp->ln_class, exp->ln_inst);
        ASSERT_TRUE(strcmp(ln->ln_inst, label) == 0);

        /* every M DO present with the expected CDC and attributes */
        for (const do_expect_t *d = exp->m_dos; d->name != NULL; d++) {
            check_do(ln, d->name, d->cdc);
            m_count++;
        }
        if (tests_failed > 0) { return; }

        /* DO count == M count (optional DOs not instantiated) */
        ASSERT_EQ((int)ln->do_count, (int)m_count);

        /* spot-check: a known optional DO is absent */
        if (exp->absent_o_do != NULL) {
            ASSERT_TRUE(iec61850_ln_find_do(ln, exp->absent_o_do) == NULL);
        }

        /* model statistics see the LN and its DOs */
        ASSERT_EQ((int)iec61850_ied_model_count_ln(&model), 1);
        ASSERT_EQ((int)iec61850_ied_model_count_do(&model), (int)m_count);
        ASSERT_TRUE(iec61850_ied_model_count_da(&model) > 0);

        iec61850_ied_model_destroy(&model);
    }
    PASS();
}

static void test_instantiate_da_trees(void)
{
    TEST("instantiate_da_trees");

    iec61850_ied_model_t model;
    iec61850_ied_model_init(&model, "IED1");
    iec61850_logical_device_t *ld = iec61850_ld_create("LD0");
    ASSERT_EQ(iec61850_ied_model_add_ld(&model, ld), 0);

    /* XCBR1: DPC Pos carries the full control attributes */
    iec61850_logical_node_t *xcbr =
        iec61850_ied_model_add_ln_class(&model, "LD0", "XCBR", "1", "");
    ASSERT_TRUE(xcbr != NULL);
    check_da(xcbr, "Pos", "stVal", IEC61850_FC_ST);
    check_da(xcbr, "Pos", "q", IEC61850_FC_ST);
    check_da(xcbr, "Pos", "t", IEC61850_FC_ST);
    check_da(xcbr, "Pos", "ctlVal", IEC61850_FC_CO);
    check_da(xcbr, "Pos", "ctlModel", IEC61850_FC_CF);
    check_da(xcbr, "Beh", "stVal", IEC61850_FC_ST);
    check_da(xcbr, "BlkOpn", "stVal", IEC61850_FC_ST);
    check_da(xcbr, "NamPlt", "vendor", IEC61850_FC_DC);
    if (tests_failed > 0) { return; }

    /* LPHD1: ENS/DPL statuses */
    iec61850_logical_node_t *lphd =
        iec61850_ied_model_add_ln_class(&model, "LD0", "LPHD", "1", "");
    ASSERT_TRUE(lphd != NULL);
    check_da(lphd, "PhyHealth", "stVal", IEC61850_FC_ST);
    check_da(lphd, "PhyNam", "vendor", IEC61850_FC_DC);
    if (tests_failed > 0) { return; }

    /* PTOC1: ACD/ACT protection statuses */
    iec61850_logical_node_t *ptoc =
        iec61850_ied_model_add_ln_class(&model, "LD0", "PTOC", "1", "");
    ASSERT_TRUE(ptoc != NULL);
    check_da(ptoc, "Str", "general", IEC61850_FC_ST);
    check_da(ptoc, "Str", "dirGeneral", IEC61850_FC_ST);
    check_da(ptoc, "Op", "general", IEC61850_FC_ST);
    if (tests_failed > 0) { return; }

    iec61850_ied_model_destroy(&model);
    PASS();
}

static void test_instantiate_prefix(void)
{
    TEST("instantiate_prefix");

    iec61850_ied_model_t model;
    iec61850_ied_model_init(&model, "IED1");
    iec61850_logical_device_t *ld = iec61850_ld_create("LD0");
    ASSERT_EQ(iec61850_ied_model_add_ld(&model, ld), 0);

    iec61850_logical_node_t *ln = iec61850_ied_model_add_ln_class(
        &model, "LD0", "XCBR", "2", "Q");
    ASSERT_TRUE(ln != NULL);
    /* prefix + class + inst */
    ASSERT_TRUE(strcmp(ln->ln_inst, "QXCBR2") == 0);
    ASSERT_TRUE(strcmp(ln->ln_class, "XCBR") == 0);
    ASSERT_TRUE(iec61850_ln_find_do(ln, "Pos") != NULL);

    iec61850_ied_model_destroy(&model);
    PASS();
}

/* ========================================================================
 * Optional-DO addition
 * ======================================================================== */

static void test_optional_do_addition(void)
{
    TEST("optional_do_addition");

    iec61850_ied_model_t model;
    iec61850_ied_model_init(&model, "IED1");
    iec61850_logical_device_t *ld = iec61850_ld_create("LD0");
    ASSERT_EQ(iec61850_ied_model_add_ld(&model, ld), 0);

    iec61850_logical_node_t *xcbr =
        iec61850_ied_model_add_ln_class(&model, "LD0", "XCBR", "1", "");
    ASSERT_TRUE(xcbr != NULL);
    size_t do_count_before = xcbr->do_count;

    /* unknown LN -> -ENOENT */
    ASSERT_EQ(iec61850_ln_add_ln_class_do(NULL, "XCBR", "CBOpCnt"), -ENOENT);
    /* unknown class -> -ENOENT */
    ASSERT_EQ(iec61850_ln_add_ln_class_do(xcbr, "ZZZZ", "Pos"), -ENOENT);
    /* unknown DO name -> -ENOENT */
    ASSERT_EQ(iec61850_ln_add_ln_class_do(xcbr, "XCBR", "NotADo"), -ENOENT);
    /* class definition does not belong to this LN -> -ENOENT */
    ASSERT_EQ(iec61850_ln_add_ln_class_do(xcbr, "XSWI", "BlkOpn"), -ENOENT);

    /* add optional CBOpCnt (BCR) */
    ASSERT_EQ(iec61850_ln_add_ln_class_do(xcbr, "XCBR", "CBOpCnt"), 0);
    ASSERT_EQ((int)xcbr->do_count, (int)do_count_before + 1);
    check_do(xcbr, "CBOpCnt", IEC61850_CDC_BCR);
    check_da(xcbr, "CBOpCnt", "actVal", IEC61850_FC_ST);
    if (tests_failed > 0) { return; }

    /* already present (optional) -> -EEXIST */
    ASSERT_EQ(iec61850_ln_add_ln_class_do(xcbr, "XCBR", "CBOpCnt"), -EEXIST);
    /* already present (mandatory) -> -EEXIST */
    ASSERT_EQ(iec61850_ln_add_ln_class_do(xcbr, "XCBR", "Pos"), -EEXIST);

    /* measurement optionals on MMXU */
    iec61850_logical_node_t *mmxu =
        iec61850_ied_model_add_ln_class(&model, "LD0", "MMXU", "1", "");
    ASSERT_TRUE(mmxu != NULL);
    ASSERT_EQ(iec61850_ln_add_ln_class_do(mmxu, "MMXU", "TotW"), 0);
    check_do(mmxu, "TotW", IEC61850_CDC_MV);
    check_da(mmxu, "TotW", "mag", IEC61850_FC_MX);
    ASSERT_EQ(iec61850_ln_add_ln_class_do(mmxu, "MMXU", "W"), 0);
    check_do(mmxu, "W", IEC61850_CDC_WYE);
    if (tests_failed > 0) { return; }

    iec61850_ied_model_destroy(&model);
    PASS();
}

/* ========================================================================
 * Error paths
 * ======================================================================== */

static void test_error_paths(void)
{
    TEST("add_ln_class_error_paths");

    iec61850_ied_model_t model;
    iec61850_ied_model_init(&model, "IED1");
    iec61850_logical_device_t *ld = iec61850_ld_create("LD0");
    ASSERT_EQ(iec61850_ied_model_add_ld(&model, ld), 0);

    /* NULL model / unknown class / unknown LD */
    ASSERT_TRUE(iec61850_ied_model_add_ln_class(NULL, "LD0", "XCBR",
                                                 "1", "") == NULL);
    ASSERT_TRUE(iec61850_ied_model_add_ln_class(&model, "LD0", "ZZZZ",
                                                 "1", "") == NULL);
    ASSERT_TRUE(iec61850_ied_model_add_ln_class(&model, "NOPE", "XCBR",
                                                 "1", "") == NULL);
    ASSERT_TRUE(iec61850_ied_model_add_ln_class(&model, NULL, "XCBR",
                                                 "1", "") == NULL);
    ASSERT_TRUE(iec61850_ied_model_add_ln_class(&model, "LD0", NULL,
                                                 "1", "") == NULL);

    /* failed instantiation must not leak an LN into the LD */
    ASSERT_EQ((int)ld->ln_count, 0);

    /* LD full: IEC61850_MAX_LN_PER_LN logical nodes max */
    for (int i = 0; i < IEC61850_MAX_LN_PER_LD; i++) {
        char inst[8];
        (void)snprintf(inst, sizeof(inst), "%d", i + 1);
        iec61850_logical_node_t *ln = iec61850_ied_model_add_ln_class(
            &model, "LD0", "GGIO", inst, "");
        if (ln == NULL) {
            printf("FAIL: GGIO %d rejected early\n", i + 1);
            FAIL("LD filled early");
        }
    }
    ASSERT_TRUE(iec61850_ied_model_add_ln_class(&model, "LD0", "GGIO",
                                                 "99", "") == NULL);
    ASSERT_EQ((int)ld->ln_count, IEC61850_MAX_LN_PER_LD);

    iec61850_ied_model_destroy(&model);
    PASS();
}

/* ========================================================================
 * Closed loop: class API -> IED model -> MMS data store -> DOA read
 *
 * NOTE (WP-6b): this loop references the MMS data store and the
 * model->store registration (src/mms/mms_data_store.c,
 * src/scl/scl_ied_builder.c), which are compiled only under
 * -Denable_mms=true — the WP-6b verification configuration. With
 * archive linking the objects are only pulled in by strong
 * references, so the test links MMS symbols directly. The frozen
 * tests/meson.build registers this target unconditionally; the
 * needed change (reported to the orchestrator) is either to move
 * it into the `if enable_mms` block or to add a project-wide
 * -DIEC61850_MMS_ENABLED define under that gate.
 * ======================================================================== */

static void test_mms_closed_loop(void)
{
    TEST("mms_closed_loop");

    iec61850_ied_model_t model;
    iec61850_ied_model_init(&model, "IED1");
    iec61850_logical_device_t *ld = iec61850_ld_create("LD0");
    ASSERT_EQ(iec61850_ied_model_add_ld(&model, ld), 0);

    /* XCBR with its M DOs, MMXU with M DOs + optional TotW */
    iec61850_logical_node_t *xcbr =
        iec61850_ied_model_add_ln_class(&model, "LD0", "XCBR", "1", "");
    ASSERT_TRUE(xcbr != NULL);
    iec61850_logical_node_t *mmxu =
        iec61850_ied_model_add_ln_class(&model, "LD0", "MMXU", "1", "");
    ASSERT_TRUE(mmxu != NULL);
    ASSERT_EQ(iec61850_ln_add_ln_class_do(mmxu, "MMXU", "TotW"), 0);

    /* Register the whole model into an MMS data store */
    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);
    int registered = iec61850_ied_model_register_mms(&model, &ds);
    ASSERT_TRUE(registered > 0);

    /* Domain: IED name + LD inst */
    ASSERT_TRUE(iec61850_mms_ds_domain_exists(&ds, "IED1LD0"));

    /* Read the XCBR Pos.stVal DOA over MMS (DPC -> BIT_STRING) */
    mms_value_t val;
    ASSERT_EQ(iec61850_mms_ds_read_variable(&ds, "IED1LD0",
              "XCBR1$ST$Pos$stVal", &val), (int)IEC61850_MMS_DS_OK);
    ASSERT_EQ((int)val.type, (int)MMS_TYPE_BIT_STRING);

    /* Read the MMXU Beh.stVal DOA over MMS (INS -> INTEGER) */
    ASSERT_EQ(iec61850_mms_ds_read_variable(&ds, "IED1LD0",
              "MMXU1$ST$Beh$stVal", &val), (int)IEC61850_MMS_DS_OK);
    ASSERT_EQ((int)val.type, (int)MMS_TYPE_INTEGER);

    /* Write-then-read a measurement DOA over MMS (MV -> FLOAT) */
    mms_value_t wval;
    (void)memset(&wval, 0, sizeof(wval));
    wval.type = MMS_TYPE_FLOATING_POINT;
    wval.value.floating_point = 123.456f;
    ASSERT_EQ(iec61850_mms_ds_write_variable(&ds, "IED1LD0",
              "MMXU1$MX$TotW$mag", &wval), (int)IEC61850_MMS_DS_OK);
    ASSERT_EQ(iec61850_mms_ds_read_variable(&ds, "IED1LD0",
              "MMXU1$MX$TotW$mag", &val), (int)IEC61850_MMS_DS_OK);
    ASSERT_EQ((int)val.type, (int)MMS_TYPE_FLOATING_POINT);
    ASSERT_TRUE(val.value.floating_point > 123.0f);
    ASSERT_TRUE(val.value.floating_point < 124.0f);

    iec61850_mms_ds_destroy(&ds);
    iec61850_ied_model_destroy(&model);
    PASS();
}

/* ======================================================================== */

int main(void)
{
    printf("=== LN Class Library Unit Tests ===\n");

    printf("\n--- Generic Sweep (every registered class) ---\n");
    test_all_classes_instantiate();

    printf("\n--- Lookup ---\n");
    test_lookup();

    printf("\n--- Instantiation ---\n");
    test_instantiate_all_classes();
    test_instantiate_da_trees();
    test_instantiate_prefix();

    printf("\n--- Optional-DO Addition ---\n");
    test_optional_do_addition();

    printf("\n--- Error Paths ---\n");
    test_error_paths();

    printf("\n--- MMS Closed Loop ---\n");
    test_mms_closed_loop();

    printf("\n=== Summary: %d run, %d passed, %d failed ===\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
