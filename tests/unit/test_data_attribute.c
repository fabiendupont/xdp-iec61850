/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for Data Attribute
 *
 * Tests: init/destroy, get/set value, thread safety, change callbacks.
 */

#include "ied/ied_data_model.h"

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

static int cb_count = 0;
static void change_callback(const mms_value_t *old_val,
                               const mms_value_t *new_val,
                               void *user_data)
{
    (void)old_val; (void)new_val; (void)user_data;
    cb_count++;
}

static void test_da_init(void)
{
    TEST("da_init");
    iec61850_data_attribute_t da;
    int ret = iec61850_da_init(&da, "stVal", IEC61850_FC_ST,
                                 IEC61850_BTYPE_BOOLEAN);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(da.valid);
    iec61850_da_destroy(&da);
    PASS();
}

static void test_da_get_set(void)
{
    TEST("da_get_set");
    iec61850_data_attribute_t da;
    iec61850_da_init(&da, "stVal", IEC61850_FC_ST, IEC61850_BTYPE_INT32);

    mms_value_t val;
    val.type = MMS_TYPE_INTEGER;
    val.value.integer = 42;
    iec61850_da_set_value(&da, &val);

    mms_value_t got = iec61850_da_get_value(&da);
    ASSERT_EQ(got.value.integer, 42);

    iec61850_da_destroy(&da);
    PASS();
}

static void test_da_change_callback(void)
{
    TEST("da_change_callback");
    iec61850_data_attribute_t da;
    iec61850_da_init(&da, "stVal", IEC61850_FC_ST, IEC61850_BTYPE_BOOLEAN);

    cb_count = 0;
    iec61850_da_set_change_callback(&da, change_callback, NULL);

    mms_value_t val;
    val.type = MMS_TYPE_BOOLEAN;
    val.value.boolean = true;
    iec61850_da_set_value(&da, &val);
    ASSERT_EQ(cb_count, 1);

    val.value.boolean = false;
    iec61850_da_set_value(&da, &val);
    ASSERT_EQ(cb_count, 2);

    iec61850_da_destroy(&da);
    PASS();
}

/* Thread safety test: concurrent set/get */
static iec61850_data_attribute_t shared_da;
static volatile int thread_done = 0;

static void *writer_thread(void *arg)
{
    (void)arg;
    for (int i = 0; i < 1000; i++) {
        mms_value_t val;
        val.type = MMS_TYPE_INTEGER;
        val.value.integer = i;
        iec61850_da_set_value(&shared_da, &val);
    }
    thread_done = 1;
    return NULL;
}

static void test_da_thread_safety(void)
{
    TEST("da_thread_safety");
    iec61850_da_init(&shared_da, "val", IEC61850_FC_MX, IEC61850_BTYPE_INT32);
    thread_done = 0;

    pthread_t tid;
    pthread_create(&tid, NULL, writer_thread, NULL);

    /* Reader thread (main) */
    while (!thread_done) {
        mms_value_t v = iec61850_da_get_value(&shared_da);
        (void)v;
    }

    pthread_join(tid, NULL);

    mms_value_t final = iec61850_da_get_value(&shared_da);
    ASSERT_EQ(final.value.integer, 999);

    iec61850_da_destroy(&shared_da);
    PASS();
}

int main(void)
{
    printf("=== Data Attribute Tests ===\n");

    test_da_init();
    test_da_get_set();
    test_da_change_callback();
    test_da_thread_safety();

    printf("\n=== Test Summary ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
