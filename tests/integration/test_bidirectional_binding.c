/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Integration Test: Bidirectional MMS <-> IED Binding
 *
 * Scenarios:
 *   1. MMS write -> binding manager -> IED DataAttribute update
 *   2. IED DataAttribute change -> DA callback fires
 *   3. Multiple independent attributes bound and written
 *
 * License: BSD-2-Clause
 */

#include "mms/mms_variable_binding.h"
#include "mms/mms_data_store.h"
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

/* ========================================================================
 * Test 1: MMS Write -> IED Update
 *
 * Simulates the full path: data store holds variable metadata,
 * binding manager maps domain+variable to a DA, MMS write propagates.
 * ======================================================================== */

static void test_mms_write_to_ied(void)
{
    TEST("mms_write_to_ied_update");

    /* Create data store and register a domain + variable */
    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);
    iec61850_mms_ds_create_domain(&ds, "IED1LD0");

    mms_value_t initial_val;
    (void)memset(&initial_val, 0, sizeof(initial_val));
    initial_val.type = MMS_TYPE_INTEGER;
    initial_val.value.integer = 0;

    iec61850_mms_ds_create_variable(&ds, "IED1LD0",
                                     "XCBR1$ST$Pos$stVal",
                                     MMS_TYPE_INTEGER, &initial_val);

    /* Create a DataAttribute */
    iec61850_data_attribute_t da;
    iec61850_da_init(&da, "stVal", IEC61850_FC_ST, IEC61850_BTYPE_INT32);

    /* Bind the MMS variable to the DA */
    iec61850_mms_binding_manager_t mgr;
    iec61850_binding_init(&mgr);
    ASSERT_EQ(iec61850_binding_bind_variable(&mgr, "IED1LD0",
              "XCBR1$ST$Pos$stVal", &da), IEC61850_BINDING_OK);

    /* Simulate MMS write */
    mms_value_t write_val;
    (void)memset(&write_val, 0, sizeof(write_val));
    write_val.type = MMS_TYPE_INTEGER;
    write_val.value.integer = 1; /* breaker closed */

    ASSERT_EQ(iec61850_binding_on_mms_write(&mgr, "IED1LD0",
              "XCBR1$ST$Pos$stVal", &write_val), IEC61850_BINDING_OK);

    /* Also update the data store to keep it in sync */
    iec61850_mms_ds_write_variable(&ds, "IED1LD0",
                                    "XCBR1$ST$Pos$stVal", &write_val);

    /* Verify the DA received the value */
    mms_value_t da_val = iec61850_da_get_value(&da);
    ASSERT_EQ(da_val.type, MMS_TYPE_INTEGER);
    ASSERT_EQ(da_val.value.integer, 1);

    /* Verify the data store also has the value */
    mms_value_t ds_val;
    iec61850_mms_ds_read_variable(&ds, "IED1LD0",
                                   "XCBR1$ST$Pos$stVal", &ds_val);
    ASSERT_EQ(ds_val.value.integer, 1);

    iec61850_da_destroy(&da);
    iec61850_binding_destroy(&mgr);
    iec61850_mms_ds_destroy(&ds);
    PASS();
}

/* ========================================================================
 * Test 2: IED Change -> Callback (DA side)
 *
 * Set DA value directly (simulating process bus update), verify the
 * change callback fires.  The binding manager is not in the direct
 * DA->callback path (the DA has its own callback), but this test
 * confirms the callback mechanism works with a bound DA.
 * ======================================================================== */

static int g_ied_cb_invoked;
static mms_value_t g_ied_old_val;
static mms_value_t g_ied_new_val;

static void ied_change_cb(const mms_value_t *old_val,
                           const mms_value_t *new_val,
                           void *user_data)
{
    (void)user_data;
    g_ied_cb_invoked = 1;
    g_ied_old_val = *old_val;
    g_ied_new_val = *new_val;
}

static void test_ied_change_callback(void)
{
    TEST("ied_change_triggers_callback");

    iec61850_data_attribute_t da;
    iec61850_da_init(&da, "mag", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32);
    iec61850_da_set_change_callback(&da, ied_change_cb, NULL);

    /* Bind it */
    iec61850_mms_binding_manager_t mgr;
    iec61850_binding_init(&mgr);
    iec61850_binding_bind_variable(&mgr, "IED1LD0",
                                    "MMXU1$MX$TotW$mag$f", &da);

    g_ied_cb_invoked = 0;

    /* Set DA value directly (simulating process bus update) */
    mms_value_t new_val;
    (void)memset(&new_val, 0, sizeof(new_val));
    new_val.type = MMS_TYPE_FLOATING_POINT;
    new_val.value.floating_point = 115.5f;
    iec61850_da_set_value(&da, &new_val);

    ASSERT_TRUE(g_ied_cb_invoked == 1);
    ASSERT_EQ(g_ied_new_val.type, MMS_TYPE_FLOATING_POINT);

    /* Also verify via binding manager lookup */
    iec61850_data_attribute_t *found =
        iec61850_binding_get_bound_attribute(&mgr, "IED1LD0",
                                             "MMXU1$MX$TotW$mag$f");
    ASSERT_TRUE(found == &da);
    mms_value_t readback = iec61850_da_get_value(found);
    ASSERT_EQ(readback.type, MMS_TYPE_FLOATING_POINT);

    iec61850_da_destroy(&da);
    iec61850_binding_destroy(&mgr);
    PASS();
}

/* ========================================================================
 * Test 3: Multiple independent attributes
 *
 * Bind three attributes from different FCs, write to each via the
 * binding manager, verify they all update independently.
 * ======================================================================== */

static void test_multiple_attributes(void)
{
    TEST("multiple_independent_attributes");

    iec61850_mms_binding_manager_t mgr;
    iec61850_binding_init(&mgr);

    /* Three DAs with different types */
    iec61850_data_attribute_t da_bool, da_int, da_float;
    iec61850_da_init(&da_bool,  "stVal",  IEC61850_FC_ST,
                      IEC61850_BTYPE_BOOLEAN);
    iec61850_da_init(&da_int,   "ctlVal", IEC61850_FC_CO,
                      IEC61850_BTYPE_INT32);
    iec61850_da_init(&da_float, "mag",    IEC61850_FC_MX,
                      IEC61850_BTYPE_FLOAT32);

    /* Bind all three */
    iec61850_binding_bind_variable(&mgr, "IED1LD0",
                                    "XCBR1$ST$Pos$stVal", &da_bool);
    iec61850_binding_bind_variable(&mgr, "IED1LD0",
                                    "CSWI1$CO$Pos$ctlVal", &da_int);
    iec61850_binding_bind_variable(&mgr, "IED1LD0",
                                    "MMXU1$MX$TotW$mag$f", &da_float);
    ASSERT_EQ(iec61850_binding_get_count(&mgr), 3);

    /* Write to each */
    mms_value_t v_bool = { .type = MMS_TYPE_BOOLEAN,
                           .value.boolean = true };
    mms_value_t v_int  = { .type = MMS_TYPE_INTEGER,
                           .value.integer = 99 };
    mms_value_t v_float = { .type = MMS_TYPE_FLOATING_POINT,
                            .value.floating_point = 33.3f };

    iec61850_binding_on_mms_write(&mgr, "IED1LD0",
                                   "XCBR1$ST$Pos$stVal", &v_bool);
    iec61850_binding_on_mms_write(&mgr, "IED1LD0",
                                   "CSWI1$CO$Pos$ctlVal", &v_int);
    iec61850_binding_on_mms_write(&mgr, "IED1LD0",
                                   "MMXU1$MX$TotW$mag$f", &v_float);

    /* Verify all three independently */
    mms_value_t r1 = iec61850_da_get_value(&da_bool);
    ASSERT_TRUE(r1.value.boolean);

    mms_value_t r2 = iec61850_da_get_value(&da_int);
    ASSERT_EQ(r2.value.integer, 99);

    mms_value_t r3 = iec61850_da_get_value(&da_float);
    ASSERT_EQ(r3.type, MMS_TYPE_FLOATING_POINT);

    /* Unbind one, verify others still work */
    iec61850_binding_unbind_variable(&mgr, "IED1LD0",
                                     "XCBR1$ST$Pos$stVal");
    ASSERT_EQ(iec61850_binding_get_count(&mgr), 2);
    ASSERT_TRUE(!iec61850_binding_is_bound(&mgr, "IED1LD0",
                "XCBR1$ST$Pos$stVal"));
    ASSERT_TRUE(iec61850_binding_is_bound(&mgr, "IED1LD0",
                "CSWI1$CO$Pos$ctlVal"));
    ASSERT_TRUE(iec61850_binding_is_bound(&mgr, "IED1LD0",
                "MMXU1$MX$TotW$mag$f"));

    iec61850_da_destroy(&da_bool);
    iec61850_da_destroy(&da_int);
    iec61850_da_destroy(&da_float);
    iec61850_binding_destroy(&mgr);
    PASS();
}

/* ========================================================================
 * Main
 * ======================================================================== */

int main(void)
{
    printf("=== Bidirectional MMS/IED Binding Integration Tests ===\n");

    test_mms_write_to_ied();
    test_ied_change_callback();
    test_multiple_attributes();

    printf("\n  Results: %d/%d passed, %d failed\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
