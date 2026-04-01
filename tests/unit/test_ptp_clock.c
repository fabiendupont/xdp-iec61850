/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for PTP Clock Module
 *
 * Tests system clock mode, PTP device error paths, and smpSynch values.
 */

#include "transport/ptp_clock.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>

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

/* Jan 1 2020 00:00:00 UTC in nanoseconds */
#define NS_2020 (1577836800ULL * 1000000000ULL)

static void test_system_clock_init(void)
{
    TEST("system_clock_init");

    iec61850_ptp_clock_t clock;
    int ret = iec61850_ptp_clock_init(&clock,
                                      IEC61850_PTP_SOURCE_SYSTEM_CLOCK,
                                      NULL);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(clock.initialized);
    ASSERT_EQ(clock.source, IEC61850_PTP_SOURCE_SYSTEM_CLOCK);

    uint64_t t = iec61850_ptp_clock_get_time_ns(&clock);
    ASSERT_TRUE(t > 0);

    iec61850_ptp_clock_destroy(&clock);
    PASS();
}

static void test_system_clock_reasonable_time(void)
{
    TEST("system_clock_reasonable_time");

    iec61850_ptp_clock_t clock;
    int ret = iec61850_ptp_clock_init(&clock,
                                      IEC61850_PTP_SOURCE_SYSTEM_CLOCK,
                                      NULL);
    ASSERT_EQ(ret, 0);

    uint64_t t1 = iec61850_ptp_clock_get_time_ns(&clock);
    ASSERT_TRUE(t1 > NS_2020);  /* After 2020 */

    uint64_t t2 = iec61850_ptp_clock_get_time_ns(&clock);
    ASSERT_TRUE(t2 >= t1);  /* Monotonic within a call pair */

    iec61850_ptp_clock_destroy(&clock);
    PASS();
}

static void test_system_clock_smp_synch(void)
{
    TEST("system_clock_smp_synch");

    iec61850_ptp_clock_t clock;
    int ret = iec61850_ptp_clock_init(&clock,
                                      IEC61850_PTP_SOURCE_SYSTEM_CLOCK,
                                      NULL);
    ASSERT_EQ(ret, 0);

    uint8_t synch = iec61850_ptp_clock_get_smp_synch(&clock);
    ASSERT_EQ(synch, 0);  /* System clock = unsynchronized */

    iec61850_ptp_clock_destroy(&clock);
    PASS();
}

static void test_ptp_device_nonexistent(void)
{
    TEST("ptp_device_nonexistent");

    iec61850_ptp_clock_t clock;
    int ret = iec61850_ptp_clock_init(&clock,
                                      IEC61850_PTP_SOURCE_PTP_DEVICE,
                                      "/dev/ptp99");
    ASSERT_TRUE(ret < 0);  /* Should fail — device does not exist */
    ASSERT_TRUE(!clock.initialized);

    /* Destroy should be safe even on failed init */
    iec61850_ptp_clock_destroy(&clock);
    PASS();
}

static void test_ptp_device_empty_path(void)
{
    TEST("ptp_device_empty_path");

    iec61850_ptp_clock_t clock;
    int ret = iec61850_ptp_clock_init(&clock,
                                      IEC61850_PTP_SOURCE_PTP_DEVICE,
                                      "");
    ASSERT_EQ(ret, -EINVAL);
    ASSERT_TRUE(!clock.initialized);

    iec61850_ptp_clock_destroy(&clock);
    PASS();
}

static void test_null_clock(void)
{
    TEST("null_clock");

    int ret = iec61850_ptp_clock_init(NULL,
                                      IEC61850_PTP_SOURCE_SYSTEM_CLOCK,
                                      NULL);
    ASSERT_EQ(ret, -EINVAL);

    /* These should not crash */
    ASSERT_EQ(iec61850_ptp_clock_get_time_ns(NULL), 0);
    ASSERT_EQ(iec61850_ptp_clock_get_smp_synch(NULL), 0);
    iec61850_ptp_clock_update_sync(NULL);
    iec61850_ptp_clock_destroy(NULL);

    PASS();
}

static void test_ptp_device_null_path_fallback(void)
{
    TEST("ptp_device_null_path_fallback");

    iec61850_ptp_clock_t clock;
    int ret = iec61850_ptp_clock_init(&clock,
                                      IEC61850_PTP_SOURCE_PTP_DEVICE,
                                      NULL);
    ASSERT_EQ(ret, 0);
    /* NULL path falls back to system clock */
    ASSERT_EQ(clock.source, IEC61850_PTP_SOURCE_SYSTEM_CLOCK);
    ASSERT_TRUE(clock.initialized);

    uint64_t t = iec61850_ptp_clock_get_time_ns(&clock);
    ASSERT_TRUE(t > NS_2020);

    iec61850_ptp_clock_destroy(&clock);
    PASS();
}

static void test_update_sync_system_clock(void)
{
    TEST("update_sync_system_clock");

    iec61850_ptp_clock_t clock;
    int ret = iec61850_ptp_clock_init(&clock,
                                      IEC61850_PTP_SOURCE_SYSTEM_CLOCK,
                                      NULL);
    ASSERT_EQ(ret, 0);

    iec61850_ptp_clock_update_sync(&clock);
    ASSERT_EQ(clock.sync_status, IEC61850_PTP_SYNC_UNSYNC);

    iec61850_ptp_clock_destroy(&clock);
    PASS();
}

static void test_destroy_resets_state(void)
{
    TEST("destroy_resets_state");

    iec61850_ptp_clock_t clock;
    int ret = iec61850_ptp_clock_init(&clock,
                                      IEC61850_PTP_SOURCE_SYSTEM_CLOCK,
                                      NULL);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(clock.initialized);

    iec61850_ptp_clock_destroy(&clock);
    ASSERT_TRUE(!clock.initialized);
    ASSERT_EQ(clock.sync_status, IEC61850_PTP_SYNC_UNKNOWN);
    ASSERT_EQ(clock.ptp_fd, -1);

    PASS();
}

int main(void)
{
    printf("=== PTP Clock Unit Tests ===\n");

    test_system_clock_init();
    test_system_clock_reasonable_time();
    test_system_clock_smp_synch();
    test_ptp_device_nonexistent();
    test_ptp_device_empty_path();
    test_null_clock();
    test_ptp_device_null_path_fallback();
    test_update_sync_system_clock();
    test_destroy_resets_state();

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
