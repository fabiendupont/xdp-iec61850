/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for System Monitor and Metrics Exporter
 */


#include "monitoring/system_monitor.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

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

static void test_monitor_init(void)
{
    TEST("monitor_init");
    iec61850_system_monitor_t mon;
    iec61850_monitor_init(&mon);
    ASSERT_TRUE(mon.pub_sent == 0);
    ASSERT_TRUE(mon.sub_received == 0);
    ASSERT_TRUE(mon.mempool.total_capacity == 0);
    /* NULL should not crash */
    iec61850_monitor_init(NULL);
    PASS();
}

static void test_mempool_stats(void)
{
    TEST("mempool_stats");
    iec61850_system_monitor_t mon;
    iec61850_monitor_init(&mon);

    iec61850_monitor_set_mempool(&mon, 1000, 800);
    ASSERT_TRUE(mon.mempool.total_capacity == 1000);
    ASSERT_TRUE(mon.mempool.available == 800);
    ASSERT_TRUE(mon.mempool.in_use == 200);
    ASSERT_TRUE(mon.mempool.usage_percent > 19.0f && mon.mempool.usage_percent < 21.0f);

    /* NULL should not crash */
    iec61850_monitor_set_mempool(NULL, 100, 50);
    PASS();
}

static void test_health_healthy(void)
{
    TEST("health_healthy");
    iec61850_system_monitor_t mon;
    iec61850_monitor_init(&mon);
    iec61850_monitor_set_mempool(&mon, 1000, 900);
    iec61850_monitor_update_pub(&mon, &(iec61850_pub_stats_t){.sent=100, .errors=0});
    iec61850_monitor_update_sub(&mon, &(iec61850_sub_stats_t){.received=200, .duplicates=0, .timeouts=0});

    iec61850_system_health_t h = iec61850_monitor_get_health(&mon);
    ASSERT_EQ((int)h.status, (int)IEC61850_HEALTH_HEALTHY);
    ASSERT_TRUE(h.memory_healthy);
    ASSERT_TRUE(h.publisher_healthy);
    ASSERT_TRUE(h.subscriber_healthy);
    PASS();
}

static void test_health_critical_memory(void)
{
    TEST("health_critical_memory");
    iec61850_system_monitor_t mon;
    iec61850_monitor_init(&mon);
    iec61850_monitor_set_mempool(&mon, 1000, 100);  /* 90% usage */

    iec61850_system_health_t h = iec61850_monitor_get_health(&mon);
    ASSERT_EQ((int)h.status, (int)IEC61850_HEALTH_CRITICAL);
    ASSERT_TRUE(!h.memory_healthy);
    PASS();
}

static void test_health_warning(void)
{
    TEST("health_warning");
    iec61850_system_monitor_t mon;
    iec61850_monitor_init(&mon);
    iec61850_monitor_set_mempool(&mon, 1000, 350);  /* 65% usage */
    iec61850_monitor_update_pub(&mon, &(iec61850_pub_stats_t){.sent=100, .errors=0});
    iec61850_monitor_update_sub(&mon, &(iec61850_sub_stats_t){.received=200, .duplicates=0, .timeouts=0});

    iec61850_system_health_t h = iec61850_monitor_get_health(&mon);
    ASSERT_EQ((int)h.status, (int)IEC61850_HEALTH_WARNING);
    PASS();
}

static void test_health_null(void)
{
    TEST("health_null");
    iec61850_system_health_t h = iec61850_monitor_get_health(NULL);
    ASSERT_EQ((int)h.status, (int)IEC61850_HEALTH_CRITICAL);
    PASS();
}

static void test_health_status_to_string(void)
{
    TEST("health_status_to_string");
    ASSERT_TRUE(strcmp(iec61850_health_status_to_string(IEC61850_HEALTH_HEALTHY), "HEALTHY") == 0);
    ASSERT_TRUE(strcmp(iec61850_health_status_to_string(IEC61850_HEALTH_WARNING), "WARNING") == 0);
    ASSERT_TRUE(strcmp(iec61850_health_status_to_string(IEC61850_HEALTH_DEGRADED), "DEGRADED") == 0);
    ASSERT_TRUE(strcmp(iec61850_health_status_to_string(IEC61850_HEALTH_CRITICAL), "CRITICAL") == 0);
    ASSERT_TRUE(strcmp(iec61850_health_status_to_string((iec61850_health_status_t)99), "UNKNOWN") == 0);
    PASS();
}

static void test_metrics_json(void)
{
    TEST("metrics_json");
    iec61850_system_monitor_t mon;
    iec61850_monitor_init(&mon);
    iec61850_monitor_set_mempool(&mon, 1000, 800);
    iec61850_monitor_update_pub(&mon, &(iec61850_pub_stats_t){.sent=50, .errors=2});
    iec61850_monitor_update_sub(&mon, &(iec61850_sub_stats_t){.received=100, .duplicates=5, .timeouts=3});

    iec61850_system_health_t h = iec61850_monitor_get_health(&mon);

    char buf[2048];
    int n = iec61850_metrics_to_json(&h, buf, sizeof(buf));
    ASSERT_TRUE(n > 0);
    ASSERT_TRUE(strstr(buf, "\"status\"") != NULL);
    ASSERT_TRUE(strstr(buf, "\"memory\"") != NULL);
    ASSERT_TRUE(strstr(buf, "\"publisher\"") != NULL);
    ASSERT_TRUE(strstr(buf, "\"subscriber\"") != NULL);

    /* NULL / small buffer */
    ASSERT_EQ(iec61850_metrics_to_json(NULL, buf, sizeof(buf)), -1);
    ASSERT_EQ(iec61850_metrics_to_json(&h, NULL, sizeof(buf)), -1);
    ASSERT_EQ(iec61850_metrics_to_json(&h, buf, 10), -1);
    PASS();
}

static void test_metrics_csv(void)
{
    TEST("metrics_csv");
    iec61850_system_monitor_t mon;
    iec61850_monitor_init(&mon);
    iec61850_monitor_update_pub(&mon, &(iec61850_pub_stats_t){.sent=10, .errors=0});

    iec61850_system_health_t h = iec61850_monitor_get_health(&mon);

    char buf[512];
    int n = iec61850_metrics_to_csv(&h, buf, sizeof(buf));
    ASSERT_TRUE(n > 0);
    ASSERT_TRUE(strstr(buf, "HEALTHY") != NULL || strstr(buf, "WARNING") != NULL);

    /* NULL */
    ASSERT_EQ(iec61850_metrics_to_csv(NULL, buf, sizeof(buf)), -1);
    ASSERT_EQ(iec61850_metrics_to_csv(&h, NULL, sizeof(buf)), -1);
    PASS();
}

static void test_metrics_csv_header(void)
{
    TEST("metrics_csv_header");
    char buf[256];
    int n = iec61850_metrics_csv_header(buf, sizeof(buf));
    ASSERT_TRUE(n > 0);
    ASSERT_TRUE(strstr(buf, "timestamp") != NULL);
    ASSERT_TRUE(strstr(buf, "status") != NULL);

    ASSERT_EQ(iec61850_metrics_csv_header(NULL, 256), -1);
    PASS();
}

static void test_update_null(void)
{
    TEST("update_null");
    /* Should not crash */
    iec61850_monitor_update_pub(NULL, &(iec61850_pub_stats_t){.sent=0, .errors=0});
    iec61850_monitor_update_sub(NULL, &(iec61850_sub_stats_t){.received=0, .duplicates=0, .timeouts=0});
    PASS();
}

static void test_health_degraded_pub(void)
{
    TEST("health_degraded_pub");
    iec61850_system_monitor_t mon;
    iec61850_monitor_init(&mon);
    iec61850_monitor_set_mempool(&mon, 1000, 900);

    /* First health check to establish baseline */
    iec61850_system_health_t h1 = iec61850_monitor_get_health(&mon);
    (void)h1;

    /* Simulate a burst of publisher errors */
    iec61850_monitor_update_pub(&mon, &(iec61850_pub_stats_t){.sent=100, .errors=50000});

    /* Small sleep to get a non-zero elapsed time */
    struct timespec ts = {0, 10000000L};  /* 10ms */
    (void)nanosleep(&ts, NULL);

    iec61850_system_health_t h2 = iec61850_monitor_get_health(&mon);
    /* With 50000 errors in ~10ms, error rate >> 1.0 → DEGRADED */
    ASSERT_EQ((int)h2.status, (int)IEC61850_HEALTH_DEGRADED);
    ASSERT_TRUE(!h2.publisher_healthy);
    PASS();
}

static void test_health_degraded_sub(void)
{
    TEST("health_degraded_sub");
    iec61850_system_monitor_t mon;
    iec61850_monitor_init(&mon);
    iec61850_monitor_set_mempool(&mon, 1000, 900);

    /* First health check to establish baseline */
    (void)iec61850_monitor_get_health(&mon);

    /* Simulate a burst of subscriber timeouts */
    iec61850_monitor_update_sub(&mon, &(iec61850_sub_stats_t){.received=100, .duplicates=0, .timeouts=50000});

    struct timespec ts = {0, 10000000L};  /* 10ms */
    (void)nanosleep(&ts, NULL);

    iec61850_system_health_t h = iec61850_monitor_get_health(&mon);
    ASSERT_EQ((int)h.status, (int)IEC61850_HEALTH_DEGRADED);
    ASSERT_TRUE(!h.subscriber_healthy);
    PASS();
}

static void test_health_warning_with_errors(void)
{
    TEST("health_warning_with_errors");
    iec61850_system_monitor_t mon;
    iec61850_monitor_init(&mon);
    iec61850_monitor_set_mempool(&mon, 1000, 900);  /* Low memory usage */
    iec61850_monitor_update_pub(&mon, &(iec61850_pub_stats_t){.sent=100, .errors=1});
    iec61850_monitor_update_sub(&mon, &(iec61850_sub_stats_t){.received=200, .duplicates=0, .timeouts=1});

    /* Wait so the first health check enters rate calculation block */
    struct timespec ts = {0, 5000000L};  /* 5ms */
    (void)nanosleep(&ts, NULL);

    /* First health check: rate is high, but we don't care — sets last = current */
    (void)iec61850_monitor_get_health(&mon);

    /* Wait again so second check enters rate block too */
    (void)nanosleep(&ts, NULL);

    /* No new errors since last check → rate = 0, total > 0 → WARNING */
    iec61850_system_health_t h = iec61850_monitor_get_health(&mon);
    ASSERT_EQ((int)h.status, (int)IEC61850_HEALTH_WARNING);
    PASS();
}

int main(void)
{
    printf("=== System Monitor Tests ===\n");

    test_monitor_init();
    test_mempool_stats();
    test_health_healthy();
    test_health_critical_memory();
    test_health_warning();
    test_health_null();
    test_health_status_to_string();
    test_metrics_json();
    test_metrics_csv();
    test_metrics_csv_header();
    test_update_null();
    test_health_degraded_pub();
    test_health_degraded_sub();
    test_health_warning_with_errors();

    printf("\nTests: %d run, %d passed, %d failed\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
