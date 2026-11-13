/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for the packet_io UDP Backend
 *
 * WP-S4 scaffold: asserts the frozen constructors' scaffold state.
 * WP-4b (udp-transport) replaces with lifecycle, loopback send/
 * receive, and multicast-join tests.
 */

#include "transport/packet_io.h"

#include <stdio.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { tests_run++; printf("  [TEST] %s ... ", name); } while (0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg) do { tests_failed++; printf("FAIL: %s\n", msg); } while (0)
#define ASSERT_TRUE(cond) do { if (!(cond)) { FAIL(#cond); return; } } while (0)

static void test_udp_scaffold_contract(void)
{
    TEST("udp_scaffold_contract");
    /* Scaffold contract: constructors return NULL until WP-4b. */
    ASSERT_TRUE(packet_io_create_udp_sender("127.0.0.1", 102, false) ==
                NULL);
    ASSERT_TRUE(packet_io_create_udp_receiver(102, NULL) == NULL);
    PASS();
}

int main(void)
{
    printf("=== packet_io UDP Unit Tests ===\n");

    test_udp_scaffold_contract();

    printf("\n=== Summary: %d run, %d passed, %d failed ===\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
