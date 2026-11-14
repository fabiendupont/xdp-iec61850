/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for the Model-Driven Publishing Binding
 *
 * WP-S6d scaffold: asserts the frozen contract's scaffold state.
 * WP-6d replaces with binding, fan-out, and closed-loop tests.
 */

#include "ied/model_binding.h"

#include <errno.h>
#include <stdio.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { tests_run++; printf("  [TEST] %s ... ", name); } while (0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg) do { tests_failed++; printf("FAIL: %s\n", msg); } while (0)
#define ASSERT_EQ(a, b) do { if ((a) != (b)) { \
    printf("FAIL: %s == %s (%d != %d)\n", #a, #b, (int)(a), (int)(b)); \
    tests_failed++; return; } } while (0)

static void test_model_binding_scaffold_contract(void)
{
    TEST("model_binding_scaffold_contract");
    iec61850_ied_model_t model;
    iec61850_model_binding_t b;

    /* Scaffold contract: -ENOSYS until WP-6d. */
    ASSERT_EQ(iec61850_model_binding_init(&b, &model), -ENOSYS);
    ASSERT_EQ(iec61850_model_binding_add_goose(&b, NULL, NULL, 0), -ENOSYS);
    ASSERT_EQ(iec61850_model_binding_add_sv(&b, NULL, NULL, 0), -ENOSYS);
    ASSERT_EQ(iec61850_model_binding_process(&b), -ENOSYS);
    iec61850_model_binding_destroy(&b); /* must not crash */
    iec61850_model_binding_destroy(NULL);
    PASS();
}

int main(void)
{
    printf("=== Model Binding Unit Tests ===\n");
    test_model_binding_scaffold_contract();
    printf("\n=== Summary: %d run, %d passed, %d failed ===\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
