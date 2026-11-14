/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for the IEC 61850-7-4 LN Class Library
 *
 * WP-S6 scaffold: asserts the frozen contract's scaffold state.
 * WP-6b (ln-schema-pilot) replaces with lookup, instantiation, and
 * pilot-class coverage tests.
 */

#include "ied/ln_schema.h"

#include <stdio.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { tests_run++; printf("  [TEST] %s ... ", name); } while (0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg) do { tests_failed++; printf("FAIL: %s\n", msg); } while (0)
#define ASSERT_TRUE(cond) do { if (!(cond)) { FAIL(#cond); return; } } while (0)

static void test_ln_library_scaffold_contract(void)
{
    TEST("ln_library_scaffold_contract");
    /* Scaffold contract: no classes until WP-6b populates the
     * group tables; the runtime returns the empty state. WP-6b
     * replaces these assertions with real coverage. */
    ASSERT_TRUE(iec61850_ln_class_lookup("XCBR") == NULL);
    ASSERT_TRUE(iec61850_ln_class_count() == 0U);
    ASSERT_TRUE(iec61850_ied_model_add_ln_class(NULL, "LD0", "XCBR",
                                                 "1", "") == NULL);
    ASSERT_TRUE(iec61850_ln_add_ln_class_do(NULL, "XCBR", "Pos") != 0);
    PASS();
}

int main(void)
{
    printf("=== LN Class Library Unit Tests ===\n");
    test_ln_library_scaffold_contract();
    printf("\n=== Summary: %d run, %d passed, %d failed ===\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
