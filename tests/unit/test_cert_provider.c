/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for the Certificate Provider
 *
 * WP-S3 scaffold: asserts the frozen constructors' scaffold state.
 * WP-3a (cert-provider) replaces with lifecycle, refresh, and
 * rotation tests.
 */

#include "security/cert_provider.h"

#include <stdio.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { tests_run++; printf("  [TEST] %s ... ", name); } while (0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg) do { tests_failed++; printf("FAIL: %s\n", msg); } while (0)
#define ASSERT_TRUE(cond) do { if (!(cond)) { FAIL(#cond); return; } } while (0)

static void test_cert_provider_scaffold_contract(void)
{
    TEST("cert_provider_scaffold_contract");
    /* Scaffold contract: constructors return NULL until WP-3a. */
    ASSERT_TRUE(iec61850_cert_provider_create_static("c.pem", "k.pem",
                                                      "t.pem") == NULL);
    ASSERT_TRUE(iec61850_cert_provider_create_spiffe("c.pem", "k.pem",
                                                     "t.pem") == NULL);
    iec61850_cert_provider_destroy(NULL); /* must not crash */
    PASS();
}

int main(void)
{
    printf("=== Certificate Provider Unit Tests ===\n");
    test_cert_provider_scaffold_contract();
    printf("\n=== Summary: %d run, %d passed, %d failed ===\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
