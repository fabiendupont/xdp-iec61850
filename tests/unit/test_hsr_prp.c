/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for HSR/PRP Redundancy Wrapper
 *
 * These tests exercise the wrapper API without requiring the actual
 * xdp-hsr-prp library.  When compiled without IEC61850_HSR_PRP_ENABLED,
 * init/start/stats return -ENOTSUP and all config validation still works.
 */

#include "redundancy/hsr_prp_wrapper.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

static int tests_run;
static int tests_passed;
static int tests_failed;

#define TEST(name) do { tests_run++; printf("  [TEST] %s ... ", name); } while (0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg) do { tests_failed++; printf("FAIL: %s\n", msg); return; } while (0)
#define ASSERT_TRUE(cond) do { if (!(cond)) { FAIL(#cond); } } while (0)
#define ASSERT_EQ(a, b) do { if ((a) != (b)) { \
    printf("FAIL: %s == %s (%d != %d)\n", #a, #b, (int)(a), (int)(b)); \
    tests_failed++; return; } } while (0)

/* ------------------------------------------------------------------ */
/* Config init tests                                                   */
/* ------------------------------------------------------------------ */

static void test_config_init_defaults(void)
{
    TEST("config_init_defaults");

    iec61850_hsr_prp_config_t cfg;
    int ret = iec61850_hsr_prp_config_init(&cfg, IEC61850_HSR_PRP_MODE_HSR,
                                           "eth0", "eth1");
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)cfg.mode, (int)IEC61850_HSR_PRP_MODE_HSR);
    ASSERT_EQ((int)cfg.supervision_interval_ms, 2000);
    ASSERT_EQ((int)cfg.node_timeout_ms, 60000);
    ASSERT_TRUE(strcmp(cfg.port_a, "eth0") == 0);
    ASSERT_TRUE(strcmp(cfg.port_b, "eth1") == 0);

    PASS();
}

static void test_config_init_prp_mode(void)
{
    TEST("config_init_prp_mode");

    iec61850_hsr_prp_config_t cfg;
    int ret = iec61850_hsr_prp_config_init(&cfg, IEC61850_HSR_PRP_MODE_PRP,
                                           "enp1s0", "enp2s0");
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)cfg.mode, (int)IEC61850_HSR_PRP_MODE_PRP);
    ASSERT_TRUE(strcmp(cfg.port_a, "enp1s0") == 0);
    ASSERT_TRUE(strcmp(cfg.port_b, "enp2s0") == 0);

    PASS();
}

static void test_config_init_null_config(void)
{
    TEST("config_init_null_config");

    int ret = iec61850_hsr_prp_config_init(NULL, IEC61850_HSR_PRP_MODE_HSR,
                                           "eth0", "eth1");
    ASSERT_EQ(ret, -EINVAL);

    PASS();
}

static void test_config_init_null_ports(void)
{
    TEST("config_init_null_ports");

    iec61850_hsr_prp_config_t cfg;
    int ret = iec61850_hsr_prp_config_init(&cfg, IEC61850_HSR_PRP_MODE_HSR,
                                           NULL, NULL);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(cfg.port_a[0] == '\0');
    ASSERT_TRUE(cfg.port_b[0] == '\0');

    PASS();
}

static void test_config_init_name_too_long(void)
{
    TEST("config_init_name_too_long");

    iec61850_hsr_prp_config_t cfg;
    /* 16 characters + nul = 17, exceeds IEC61850_HSR_PRP_IFNAMSIZ (16) */
    int ret = iec61850_hsr_prp_config_init(&cfg, IEC61850_HSR_PRP_MODE_HSR,
                                           "abcdefghijklmnop", "eth1");
    ASSERT_EQ(ret, -ENAMETOOLONG);

    PASS();
}

/* ------------------------------------------------------------------ */
/* Config validation tests                                             */
/* ------------------------------------------------------------------ */

static void test_config_validate_ok(void)
{
    TEST("config_validate_ok");

    iec61850_hsr_prp_config_t cfg;
    iec61850_hsr_prp_config_init(&cfg, IEC61850_HSR_PRP_MODE_HSR,
                                 "eth0", "eth1");
    int ret = iec61850_hsr_prp_config_validate(&cfg);
    ASSERT_EQ(ret, 0);

    PASS();
}

static void test_config_validate_null(void)
{
    TEST("config_validate_null");

    int ret = iec61850_hsr_prp_config_validate(NULL);
    ASSERT_EQ(ret, -EINVAL);

    PASS();
}

static void test_config_validate_empty_port_a(void)
{
    TEST("config_validate_empty_port_a");

    iec61850_hsr_prp_config_t cfg;
    iec61850_hsr_prp_config_init(&cfg, IEC61850_HSR_PRP_MODE_HSR,
                                 NULL, "eth1");
    int ret = iec61850_hsr_prp_config_validate(&cfg);
    ASSERT_EQ(ret, -EINVAL);

    PASS();
}

static void test_config_validate_empty_port_b(void)
{
    TEST("config_validate_empty_port_b");

    iec61850_hsr_prp_config_t cfg;
    iec61850_hsr_prp_config_init(&cfg, IEC61850_HSR_PRP_MODE_HSR,
                                 "eth0", NULL);
    int ret = iec61850_hsr_prp_config_validate(&cfg);
    ASSERT_EQ(ret, -EINVAL);

    PASS();
}

static void test_config_validate_zero_supervision(void)
{
    TEST("config_validate_zero_supervision");

    iec61850_hsr_prp_config_t cfg;
    iec61850_hsr_prp_config_init(&cfg, IEC61850_HSR_PRP_MODE_HSR,
                                 "eth0", "eth1");
    cfg.supervision_interval_ms = 0;
    int ret = iec61850_hsr_prp_config_validate(&cfg);
    ASSERT_EQ(ret, -EINVAL);

    PASS();
}

static void test_config_validate_zero_timeout(void)
{
    TEST("config_validate_zero_timeout");

    iec61850_hsr_prp_config_t cfg;
    iec61850_hsr_prp_config_init(&cfg, IEC61850_HSR_PRP_MODE_HSR,
                                 "eth0", "eth1");
    cfg.node_timeout_ms = 0;
    int ret = iec61850_hsr_prp_config_validate(&cfg);
    ASSERT_EQ(ret, -EINVAL);

    PASS();
}

/* ------------------------------------------------------------------ */
/* Runtime API tests (stub or real, depending on compile-time flag)     */
/* ------------------------------------------------------------------ */

static void test_init_without_library(void)
{
    TEST("init_without_library");

    iec61850_hsr_prp_config_t cfg;
    iec61850_hsr_prp_config_init(&cfg, IEC61850_HSR_PRP_MODE_HSR,
                                 "eth0", "eth1");

    int ret = iec61850_hsr_prp_init(&cfg);
    if (iec61850_hsr_prp_available()) {
        /* With real library, init may fail for other reasons (no BPF, etc.)
         * but should not return -ENOTSUP. */
        ASSERT_TRUE(ret != -ENOTSUP);
    } else {
        ASSERT_EQ(ret, -ENOTSUP);
    }

    PASS();
}

static void test_init_null_config(void)
{
    TEST("init_null_config");

    int ret = iec61850_hsr_prp_init(NULL);
    if (iec61850_hsr_prp_available()) {
        ASSERT_EQ(ret, -EINVAL);
    } else {
        ASSERT_EQ(ret, -ENOTSUP);
    }

    PASS();
}

static void test_start_without_init(void)
{
    TEST("start_without_init");

    /* Ensure clean state */
    iec61850_hsr_prp_stop();

    int ret = iec61850_hsr_prp_start();
    if (iec61850_hsr_prp_available()) {
        ASSERT_EQ(ret, -EINVAL);
    } else {
        ASSERT_EQ(ret, -ENOTSUP);
    }

    PASS();
}

static void test_stats_query_zeros(void)
{
    TEST("stats_query_zeros");

    iec61850_hsr_prp_stats_t stats;
    memset(&stats, 0xFF, sizeof(stats));

    int ret = iec61850_hsr_prp_get_stats(&stats);
    if (iec61850_hsr_prp_available()) {
        /* Without init, should return -EINVAL */
        ASSERT_EQ(ret, -EINVAL);
    } else {
        ASSERT_EQ(ret, -ENOTSUP);
    }

    /* Stats should be zeroed on both paths */
    ASSERT_EQ((int)stats.rx_count, 0);
    ASSERT_EQ((int)stats.rx_bytes, 0);
    ASSERT_EQ((int)stats.tx_count, 0);
    ASSERT_EQ((int)stats.tx_bytes, 0);
    ASSERT_EQ((int)stats.dup_drops, 0);
    ASSERT_EQ((int)stats.errors, 0);

    PASS();
}

static void test_stats_null(void)
{
    TEST("stats_null");

    int ret = iec61850_hsr_prp_get_stats(NULL);
    ASSERT_EQ(ret, -EINVAL);

    PASS();
}

static void test_stop_idempotent(void)
{
    TEST("stop_idempotent");

    /* Calling stop multiple times should not crash */
    iec61850_hsr_prp_stop();
    iec61850_hsr_prp_stop();
    iec61850_hsr_prp_stop();

    PASS();
}

static void test_available_flag(void)
{
    TEST("available_flag");

    bool avail = iec61850_hsr_prp_available();
#ifdef IEC61850_HSR_PRP_ENABLED
    ASSERT_TRUE(avail);
#else
    ASSERT_TRUE(!avail);
#endif

    PASS();
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

int main(void)
{
    printf("=== HSR/PRP Wrapper Tests ===\n");

    /* Config init */
    test_config_init_defaults();
    test_config_init_prp_mode();
    test_config_init_null_config();
    test_config_init_null_ports();
    test_config_init_name_too_long();

    /* Config validation */
    test_config_validate_ok();
    test_config_validate_null();
    test_config_validate_empty_port_a();
    test_config_validate_empty_port_b();
    test_config_validate_zero_supervision();
    test_config_validate_zero_timeout();

    /* Runtime API */
    test_init_without_library();
    test_init_null_config();
    test_start_without_init();
    test_stats_query_zeros();
    test_stats_null();
    test_stop_idempotent();
    test_available_flag();

    printf("\n=== Results: %d/%d passed, %d failed ===\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
