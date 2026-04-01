/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for MMS Variable Binding Manager
 *
 * Tests: bind/unbind lifecycle, duplicate rejection, unbind_domain,
 * unbind_all, on_mms_write propagation, unbound write error,
 * null-arg validation, concurrent bind+write (2 threads).
 *
 * License: BSD-3-Clause
 */

#include "mms/mms_variable_binding.h"

#include <stdio.h>
#include <string.h>
#include <pthread.h>

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
 * Basic bind / unbind lifecycle
 * ======================================================================== */

static void test_bind_unbind_lifecycle(void)
{
    TEST("bind_unbind_lifecycle");

    iec61850_mms_binding_manager_t mgr;
    iec61850_binding_init(&mgr);

    iec61850_data_attribute_t da;
    iec61850_da_init(&da, "stVal", IEC61850_FC_ST, IEC61850_BTYPE_BOOLEAN);

    /* Bind */
    ASSERT_EQ(iec61850_binding_bind_variable(&mgr, "IED1LD0",
              "LLN0$ST$Beh$stVal", &da), IEC61850_BINDING_OK);
    ASSERT_EQ(iec61850_binding_get_count(&mgr), 1);
    ASSERT_TRUE(iec61850_binding_is_bound(&mgr, "IED1LD0",
                "LLN0$ST$Beh$stVal"));

    /* Look up */
    iec61850_data_attribute_t *found =
        iec61850_binding_get_bound_attribute(&mgr, "IED1LD0",
                                             "LLN0$ST$Beh$stVal");
    ASSERT_TRUE(found == &da);

    /* Unbind */
    ASSERT_EQ(iec61850_binding_unbind_variable(&mgr, "IED1LD0",
              "LLN0$ST$Beh$stVal"), IEC61850_BINDING_OK);
    ASSERT_EQ(iec61850_binding_get_count(&mgr), 0);
    ASSERT_TRUE(!iec61850_binding_is_bound(&mgr, "IED1LD0",
                "LLN0$ST$Beh$stVal"));

    iec61850_da_destroy(&da);
    iec61850_binding_destroy(&mgr);
    PASS();
}

/* ========================================================================
 * Duplicate binding rejection
 * ======================================================================== */

static void test_duplicate_binding(void)
{
    TEST("duplicate_binding_rejected");

    iec61850_mms_binding_manager_t mgr;
    iec61850_binding_init(&mgr);

    iec61850_data_attribute_t da;
    iec61850_da_init(&da, "stVal", IEC61850_FC_ST, IEC61850_BTYPE_BOOLEAN);

    ASSERT_EQ(iec61850_binding_bind_variable(&mgr, "D1", "V1", &da),
              IEC61850_BINDING_OK);
    ASSERT_EQ(iec61850_binding_bind_variable(&mgr, "D1", "V1", &da),
              IEC61850_BINDING_ERR_EXISTS);
    ASSERT_EQ(iec61850_binding_get_count(&mgr), 1);

    iec61850_da_destroy(&da);
    iec61850_binding_destroy(&mgr);
    PASS();
}

/* ========================================================================
 * Unbind domain
 * ======================================================================== */

static void test_unbind_domain(void)
{
    TEST("unbind_domain");

    iec61850_mms_binding_manager_t mgr;
    iec61850_binding_init(&mgr);

    iec61850_data_attribute_t da1, da2, da3;
    iec61850_da_init(&da1, "v1", IEC61850_FC_ST, IEC61850_BTYPE_INT32);
    iec61850_da_init(&da2, "v2", IEC61850_FC_ST, IEC61850_BTYPE_INT32);
    iec61850_da_init(&da3, "v3", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32);

    iec61850_binding_bind_variable(&mgr, "DOM_A", "var1", &da1);
    iec61850_binding_bind_variable(&mgr, "DOM_A", "var2", &da2);
    iec61850_binding_bind_variable(&mgr, "DOM_B", "var3", &da3);
    ASSERT_EQ(iec61850_binding_get_count(&mgr), 3);

    ASSERT_EQ(iec61850_binding_unbind_domain(&mgr, "DOM_A"),
              IEC61850_BINDING_OK);
    ASSERT_EQ(iec61850_binding_get_count(&mgr), 1);
    ASSERT_TRUE(!iec61850_binding_is_bound(&mgr, "DOM_A", "var1"));
    ASSERT_TRUE(!iec61850_binding_is_bound(&mgr, "DOM_A", "var2"));
    ASSERT_TRUE(iec61850_binding_is_bound(&mgr, "DOM_B", "var3"));

    iec61850_da_destroy(&da1);
    iec61850_da_destroy(&da2);
    iec61850_da_destroy(&da3);
    iec61850_binding_destroy(&mgr);
    PASS();
}

/* ========================================================================
 * Unbind all
 * ======================================================================== */

static void test_unbind_all(void)
{
    TEST("unbind_all");

    iec61850_mms_binding_manager_t mgr;
    iec61850_binding_init(&mgr);

    iec61850_data_attribute_t da1, da2;
    iec61850_da_init(&da1, "a", IEC61850_FC_ST, IEC61850_BTYPE_INT32);
    iec61850_da_init(&da2, "b", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32);

    iec61850_binding_bind_variable(&mgr, "D1", "V1", &da1);
    iec61850_binding_bind_variable(&mgr, "D2", "V2", &da2);
    ASSERT_EQ(iec61850_binding_get_count(&mgr), 2);

    ASSERT_EQ(iec61850_binding_unbind_all(&mgr), IEC61850_BINDING_OK);
    ASSERT_EQ(iec61850_binding_get_count(&mgr), 0);

    iec61850_da_destroy(&da1);
    iec61850_da_destroy(&da2);
    iec61850_binding_destroy(&mgr);
    PASS();
}

/* ========================================================================
 * on_mms_write propagation
 * ======================================================================== */

static void test_on_mms_write(void)
{
    TEST("on_mms_write_propagation");

    iec61850_mms_binding_manager_t mgr;
    iec61850_binding_init(&mgr);

    iec61850_data_attribute_t da;
    iec61850_da_init(&da, "stVal", IEC61850_FC_ST, IEC61850_BTYPE_INT32);

    iec61850_binding_bind_variable(&mgr, "IED1LD0",
                                    "LLN0$ST$Beh$stVal", &da);

    /* Write via binding manager */
    mms_value_t val;
    (void)memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;
    val.value.integer = 42;

    ASSERT_EQ(iec61850_binding_on_mms_write(&mgr, "IED1LD0",
              "LLN0$ST$Beh$stVal", &val), IEC61850_BINDING_OK);

    /* Read back from DA */
    mms_value_t readback = iec61850_da_get_value(&da);
    ASSERT_EQ(readback.type, MMS_TYPE_INTEGER);
    ASSERT_EQ(readback.value.integer, 42);

    iec61850_da_destroy(&da);
    iec61850_binding_destroy(&mgr);
    PASS();
}

/* ========================================================================
 * Write to unbound variable
 * ======================================================================== */

static void test_write_unbound(void)
{
    TEST("write_unbound_variable");

    iec61850_mms_binding_manager_t mgr;
    iec61850_binding_init(&mgr);

    mms_value_t val;
    (void)memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_BOOLEAN;
    val.value.boolean = true;

    ASSERT_EQ(iec61850_binding_on_mms_write(&mgr, "DOM", "VAR", &val),
              IEC61850_BINDING_ERR_NOT_FOUND);

    iec61850_binding_destroy(&mgr);
    PASS();
}

/* ========================================================================
 * Unbind non-existent variable
 * ======================================================================== */

static void test_unbind_not_found(void)
{
    TEST("unbind_not_found");

    iec61850_mms_binding_manager_t mgr;
    iec61850_binding_init(&mgr);

    ASSERT_EQ(iec61850_binding_unbind_variable(&mgr, "DOM", "VAR"),
              IEC61850_BINDING_ERR_NOT_FOUND);

    iec61850_binding_destroy(&mgr);
    PASS();
}

/* ========================================================================
 * Null argument validation
 * ======================================================================== */

static void test_null_args(void)
{
    TEST("null_arg_validation");

    iec61850_mms_binding_manager_t mgr;
    iec61850_binding_init(&mgr);

    iec61850_data_attribute_t da;
    iec61850_da_init(&da, "x", IEC61850_FC_ST, IEC61850_BTYPE_INT32);

    mms_value_t val;
    (void)memset(&val, 0, sizeof(val));

    /* bind: null args */
    ASSERT_EQ(iec61850_binding_bind_variable(NULL, "D", "V", &da),
              IEC61850_BINDING_ERR_ARGS);
    ASSERT_EQ(iec61850_binding_bind_variable(&mgr, NULL, "V", &da),
              IEC61850_BINDING_ERR_ARGS);
    ASSERT_EQ(iec61850_binding_bind_variable(&mgr, "D", NULL, &da),
              IEC61850_BINDING_ERR_ARGS);
    ASSERT_EQ(iec61850_binding_bind_variable(&mgr, "D", "V", NULL),
              IEC61850_BINDING_ERR_ARGS);

    /* unbind: null args */
    ASSERT_EQ(iec61850_binding_unbind_variable(NULL, "D", "V"),
              IEC61850_BINDING_ERR_ARGS);
    ASSERT_EQ(iec61850_binding_unbind_domain(NULL, "D"),
              IEC61850_BINDING_ERR_ARGS);
    ASSERT_EQ(iec61850_binding_unbind_all(NULL),
              IEC61850_BINDING_ERR_ARGS);

    /* write: null args */
    ASSERT_EQ(iec61850_binding_on_mms_write(NULL, "D", "V", &val),
              IEC61850_BINDING_ERR_ARGS);
    ASSERT_EQ(iec61850_binding_on_mms_write(&mgr, "D", "V", NULL),
              IEC61850_BINDING_ERR_ARGS);

    /* lookup: null args */
    ASSERT_TRUE(iec61850_binding_get_bound_attribute(NULL, "D", "V") == NULL);
    ASSERT_TRUE(!iec61850_binding_is_bound(NULL, "D", "V"));
    ASSERT_EQ(iec61850_binding_get_count(NULL), 0);

    iec61850_da_destroy(&da);
    iec61850_binding_destroy(&mgr);
    PASS();
}

/* ========================================================================
 * on_mms_write triggers DA change callback
 * ======================================================================== */

static int g_cb_invoked;
static mms_value_t g_cb_old_val;
static mms_value_t g_cb_new_val;

static void write_change_cb(const mms_value_t *old_val,
                            const mms_value_t *new_val,
                            void *user_data)
{
    (void)user_data;
    g_cb_invoked = 1;
    g_cb_old_val = *old_val;
    g_cb_new_val = *new_val;
}

static void test_write_triggers_callback(void)
{
    TEST("write_triggers_change_callback");

    iec61850_mms_binding_manager_t mgr;
    iec61850_binding_init(&mgr);

    iec61850_data_attribute_t da;
    iec61850_da_init(&da, "mag", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32);
    iec61850_da_set_change_callback(&da, write_change_cb, NULL);

    iec61850_binding_bind_variable(&mgr, "IED1LD0",
                                    "MMXU1$MX$TotW$mag$f", &da);

    g_cb_invoked = 0;
    mms_value_t val;
    (void)memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_FLOATING_POINT;
    val.value.floating_point = 3.14f;

    iec61850_binding_on_mms_write(&mgr, "IED1LD0",
                                   "MMXU1$MX$TotW$mag$f", &val);

    ASSERT_TRUE(g_cb_invoked == 1);
    ASSERT_EQ(g_cb_new_val.type, MMS_TYPE_FLOATING_POINT);
    /* Old value should be 0 (default) */
    ASSERT_EQ(g_cb_old_val.value.integer, 0);

    iec61850_da_destroy(&da);
    iec61850_binding_destroy(&mgr);
    PASS();
}

/* ========================================================================
 * Concurrent bind + write (2 threads)
 * ======================================================================== */

typedef struct {
    iec61850_mms_binding_manager_t *mgr;
    iec61850_data_attribute_t *da;
    int thread_id;
    int iterations;
    int errors;
} thread_ctx_t;

static void *thread_bind_write(void *arg)
{
    thread_ctx_t *ctx = (thread_ctx_t *)arg;
    char var_name[MMS_MAX_VARIABLE_NAME];

    ctx->errors = 0;

    for (int i = 0; i < ctx->iterations; i++) {
        (void)snprintf(var_name, sizeof(var_name), "T%d_V%d",
                       ctx->thread_id, i);

        iec61850_binding_result_t ret =
            iec61850_binding_bind_variable(ctx->mgr, "SHARED_DOM",
                                           var_name, ctx->da);
        if (ret != IEC61850_BINDING_OK) {
            ctx->errors++;
            continue;
        }

        mms_value_t val;
        (void)memset(&val, 0, sizeof(val));
        val.type = MMS_TYPE_INTEGER;
        val.value.integer = ctx->thread_id * 1000 + i;

        ret = iec61850_binding_on_mms_write(ctx->mgr, "SHARED_DOM",
                                             var_name, &val);
        if (ret != IEC61850_BINDING_OK) {
            ctx->errors++;
        }
    }

    return NULL;
}

static void test_concurrent_bind_write(void)
{
    TEST("concurrent_bind_write");

    iec61850_mms_binding_manager_t mgr;
    iec61850_binding_init(&mgr);

    iec61850_data_attribute_t da;
    iec61850_da_init(&da, "val", IEC61850_FC_ST, IEC61850_BTYPE_INT32);

    thread_ctx_t ctx1 = { .mgr = &mgr, .da = &da,
                          .thread_id = 1, .iterations = 50, .errors = 0 };
    thread_ctx_t ctx2 = { .mgr = &mgr, .da = &da,
                          .thread_id = 2, .iterations = 50, .errors = 0 };

    pthread_t t1, t2;
    (void)pthread_create(&t1, NULL, thread_bind_write, &ctx1);
    (void)pthread_create(&t2, NULL, thread_bind_write, &ctx2);

    (void)pthread_join(t1, NULL);
    (void)pthread_join(t2, NULL);

    ASSERT_EQ(ctx1.errors, 0);
    ASSERT_EQ(ctx2.errors, 0);
    ASSERT_EQ(iec61850_binding_get_count(&mgr), 100);

    iec61850_da_destroy(&da);
    iec61850_binding_destroy(&mgr);
    PASS();
}

/* ========================================================================
 * Multiple independent bindings with distinct DAs
 * ======================================================================== */

static void test_multiple_bindings(void)
{
    TEST("multiple_independent_bindings");

    iec61850_mms_binding_manager_t mgr;
    iec61850_binding_init(&mgr);

    iec61850_data_attribute_t da1, da2, da3;
    iec61850_da_init(&da1, "stVal", IEC61850_FC_ST, IEC61850_BTYPE_BOOLEAN);
    iec61850_da_init(&da2, "mag",   IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32);
    iec61850_da_init(&da3, "ctlVal", IEC61850_FC_CO, IEC61850_BTYPE_INT32);

    iec61850_binding_bind_variable(&mgr, "IED1LD0", "XCBR1$ST$Pos$stVal", &da1);
    iec61850_binding_bind_variable(&mgr, "IED1LD0", "MMXU1$MX$TotW$mag$f", &da2);
    iec61850_binding_bind_variable(&mgr, "IED1LD0", "CSWI1$CO$Pos$ctlVal", &da3);
    ASSERT_EQ(iec61850_binding_get_count(&mgr), 3);

    /* Write to each independently */
    mms_value_t v1 = { .type = MMS_TYPE_BOOLEAN, .value.boolean = true };
    mms_value_t v2 = { .type = MMS_TYPE_FLOATING_POINT,
                       .value.floating_point = 220.5f };
    mms_value_t v3 = { .type = MMS_TYPE_INTEGER, .value.integer = 1 };

    ASSERT_EQ(iec61850_binding_on_mms_write(&mgr, "IED1LD0",
              "XCBR1$ST$Pos$stVal", &v1), IEC61850_BINDING_OK);
    ASSERT_EQ(iec61850_binding_on_mms_write(&mgr, "IED1LD0",
              "MMXU1$MX$TotW$mag$f", &v2), IEC61850_BINDING_OK);
    ASSERT_EQ(iec61850_binding_on_mms_write(&mgr, "IED1LD0",
              "CSWI1$CO$Pos$ctlVal", &v3), IEC61850_BINDING_OK);

    /* Verify each DA independently */
    mms_value_t r1 = iec61850_da_get_value(&da1);
    ASSERT_TRUE(r1.value.boolean);

    mms_value_t r2 = iec61850_da_get_value(&da2);
    ASSERT_EQ(r2.type, MMS_TYPE_FLOATING_POINT);

    mms_value_t r3 = iec61850_da_get_value(&da3);
    ASSERT_EQ(r3.value.integer, 1);

    iec61850_da_destroy(&da1);
    iec61850_da_destroy(&da2);
    iec61850_da_destroy(&da3);
    iec61850_binding_destroy(&mgr);
    PASS();
}

/* ========================================================================
 * Main
 * ======================================================================== */

int main(void)
{
    printf("=== MMS Variable Binding Manager Tests ===\n");

    test_bind_unbind_lifecycle();
    test_duplicate_binding();
    test_unbind_domain();
    test_unbind_all();
    test_on_mms_write();
    test_write_unbound();
    test_unbind_not_found();
    test_null_args();
    test_write_triggers_callback();
    test_concurrent_bind_write();
    test_multiple_bindings();

    printf("\n  Results: %d/%d passed, %d failed\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
