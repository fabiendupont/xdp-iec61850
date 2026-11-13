/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for IEC TR 61850-90-5 R-GOOSE / R-SV Codecs
 *
 * WP-S4 scaffold: asserts the frozen contract's scaffold state.
 * WP-4a (rgoose-codec) replaces the ENOSYS assertions with roundtrip,
 * malformed-input, and replay-window tests.
 */

#include "asn1/r_profile.h"

#include <errno.h>
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

static void test_r_profile_scaffold_contract(void)
{
    TEST("r_profile_scaffold_contract");
    goose_apdu_t apdu;
    uint8_t buf[256];

    /* Scaffold contract: codecs are -ENOSYS until WP-4a. WP-4a
     * replaces these assertions with real roundtrip tests. */
    ASSERT_EQ(iec61850_rgoose_encode(&apdu, NULL, buf, sizeof(buf)),
              -ENOSYS);
    ASSERT_EQ(iec61850_rgoose_decode(buf, sizeof(buf), &apdu, NULL),
              -ENOSYS);
    ASSERT_TRUE(!iec61850_r_time_in_window(0U, 0U));

    sv_apdu_t sv;
    ASSERT_EQ(iec61850_rsv_encode(&sv, NULL, buf, sizeof(buf)), -ENOSYS);
    ASSERT_EQ(iec61850_rsv_decode(buf, sizeof(buf), &sv, NULL), -ENOSYS);
    PASS();
}

int main(void)
{
    printf("=== R-Profile (90-5) Codec Unit Tests ===\n");

    test_r_profile_scaffold_contract();

    printf("\n=== Summary: %d run, %d passed, %d failed ===\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
