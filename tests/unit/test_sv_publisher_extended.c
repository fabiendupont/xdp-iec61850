/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Extended SV Publisher Tests
 *
 * Tests sample counter wraparound, multi-channel, and boundary conditions.
 */


#include "sv/sv_publisher.h"
#include "transport/eth_frame.h"
#include <stdio.h>
#include <string.h>

static int test_run = 0, test_passed = 0, test_failed = 0;
#define TEST(name) do { test_run++; printf("  [TEST] %s ...", name); } while(0)
#define PASS() do { test_passed++; printf(" PASS\n"); return; } while(0)
#define FAIL(msg) do { test_failed++; printf(" FAIL: %s\n", msg); return; } while(0)
#define ASSERT_TRUE(x) do { if (!(x)) { FAIL(#x); } } while(0)
#define ASSERT_EQ(a,b) do { if ((a) != (b)) { printf(" (got %d, want %d)", (a), (b)); FAIL(#a " != " #b); } } while(0)

static void test_smpcnt_increment(void)
{
    TEST("smpcnt_increment");
    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, NULL);
    (void)iec61850_sv_publisher_set_sample(&pub, 0, 100);

    ASSERT_EQ((int)iec61850_sv_publisher_get_smp_cnt(&pub), 0);

    uint8_t buf[512];
    size_t len = 0;
    int ret = iec61850_sv_publisher_prepare(&pub, buf, sizeof(buf), &len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)iec61850_sv_publisher_get_smp_cnt(&pub), 1);

    ret = iec61850_sv_publisher_prepare(&pub, buf, sizeof(buf), &len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)iec61850_sv_publisher_get_smp_cnt(&pub), 2);

    iec61850_sv_publisher_destroy(&pub);
    PASS();
}

static void test_smpcnt_wraparound(void)
{
    TEST("smpcnt_wraparound");
    iec61850_sv_config_t cfg;
    iec61850_sv_config_init(&cfg);
    cfg.smp_rate = 80;  /* wrap at 80*50 = 4000 */

    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, &cfg);
    (void)iec61850_sv_publisher_set_sample(&pub, 0, 0);

    uint8_t buf[512];
    size_t len = 0;

    /* Advance to near wraparound */
    pub.smp_cnt = 3998;
    (void)iec61850_sv_publisher_prepare(&pub, buf, sizeof(buf), &len);
    ASSERT_EQ((int)iec61850_sv_publisher_get_smp_cnt(&pub), 3999);

    (void)iec61850_sv_publisher_prepare(&pub, buf, sizeof(buf), &len);
    ASSERT_EQ((int)iec61850_sv_publisher_get_smp_cnt(&pub), 0);  /* wrapped */

    iec61850_sv_publisher_destroy(&pub);
    PASS();
}

static void test_reset_counter(void)
{
    TEST("reset_counter");
    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, NULL);
    pub.smp_cnt = 100;
    ASSERT_EQ((int)iec61850_sv_publisher_get_smp_cnt(&pub), 100);

    iec61850_sv_publisher_reset_counter(&pub);
    ASSERT_EQ((int)iec61850_sv_publisher_get_smp_cnt(&pub), 0);

    iec61850_sv_publisher_destroy(&pub);
    PASS();
}

static void test_multi_channel(void)
{
    TEST("multi_channel");
    iec61850_sv_config_t cfg;
    iec61850_sv_config_init(&cfg);
    cfg.num_channels = 8;

    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, &cfg);

    int32_t values[8] = {100, 200, 300, 400, -100, -200, -300, -400};
    int ret = iec61850_sv_publisher_set_samples(&pub, values, 8);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)pub.sample_count, 8);

    uint8_t buf[1024];
    size_t len = 0;
    ret = iec61850_sv_publisher_prepare(&pub, buf, sizeof(buf), &len);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(len > 0);

    iec61850_sv_publisher_destroy(&pub);
    PASS();
}

static void test_set_quality(void)
{
    TEST("set_quality");
    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, NULL);

    sv_quality_t q = {0};
    q.validity = 1;  /* questionable */
    int ret = iec61850_sv_publisher_set_quality(&pub, 0, q);
    ASSERT_EQ(ret, 0);

    /* Out of range */
    ret = iec61850_sv_publisher_set_quality(&pub, SV_MAX_SAMPLES, q);
    ASSERT_EQ(ret, -1);

    iec61850_sv_publisher_destroy(&pub);
    PASS();
}

static void test_config_defaults(void)
{
    TEST("config_defaults");
    iec61850_sv_config_t cfg;
    iec61850_sv_config_init(&cfg);

    ASSERT_EQ((int)cfg.app_id, 0x4000);
    ASSERT_EQ((int)cfg.smp_rate, 80);
    ASSERT_EQ((int)cfg.num_channels, 4);
    ASSERT_EQ((int)cfg.conf_rev, 1);
    ASSERT_EQ((int)cfg.vlan_id, 100);
    ASSERT_TRUE(cfg.dst_mac[0] == 0x01);
    ASSERT_TRUE(cfg.dst_mac[3] == 0x04);  /* SV multicast */
    PASS();
}

static void test_null_operations(void)
{
    TEST("null_operations");
    ASSERT_EQ((int)iec61850_sv_publisher_get_smp_cnt(NULL), 0);
    iec61850_sv_publisher_reset_counter(NULL);
    iec61850_sv_publisher_set_io(NULL, NULL);

    uint8_t buf[64];
    size_t len = 0;
    ASSERT_EQ(iec61850_sv_publisher_prepare(NULL, buf, sizeof(buf), &len), -1);
    PASS();
}

static void test_frame_roundtrip(void)
{
    TEST("frame_roundtrip");
    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, NULL);
    (void)iec61850_sv_publisher_set_sample(&pub, 0, 1000);
    (void)iec61850_sv_publisher_set_sample(&pub, 1, 2000);

    uint8_t apdu[512];
    size_t apdu_len = 0;
    int ret = iec61850_sv_publisher_prepare(&pub, apdu, sizeof(apdu), &apdu_len);
    ASSERT_EQ(ret, 0);

    iec61850_eth_frame_config_t fcfg;
    (void)memset(&fcfg, 0, sizeof(fcfg));
    fcfg.dst_mac[0] = 0x01; fcfg.dst_mac[1] = 0x0C; fcfg.dst_mac[2] = 0xCD;
    fcfg.dst_mac[3] = 0x04; fcfg.dst_mac[4] = 0x00; fcfg.dst_mac[5] = 0x01;
    fcfg.ethertype = IEC61850_ETHERTYPE_SV;
    fcfg.app_id = 0x4000;

    uint8_t frame[IEC61850_MAX_FRAME_SIZE];
    size_t frame_len = 0;
    ret = iec61850_eth_frame_build(frame, sizeof(frame), &fcfg,
                                    apdu, apdu_len, &frame_len);
    ASSERT_EQ(ret, 0);

    uint16_t et = 0, appid = 0, vlan = 0;
    const uint8_t *out = NULL;
    size_t out_len = 0;
    ret = iec61850_eth_frame_parse(frame, frame_len, &et, &appid, &vlan,
                                    &out, &out_len, NULL);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)et, (int)IEC61850_ETHERTYPE_SV);
    ASSERT_EQ((int)appid, 0x4000);
    ASSERT_EQ((int)out_len, (int)apdu_len);

    iec61850_sv_publisher_destroy(&pub);
    PASS();
}

int main(void)
{
    printf("\n=== SV Publisher Extended Tests ===\n");

    test_smpcnt_increment();
    test_smpcnt_wraparound();
    test_reset_counter();
    test_multi_channel();
    test_set_quality();
    test_config_defaults();
    test_null_operations();
    test_frame_roundtrip();

    printf("\n  Results: %d/%d passed\n\n", test_passed, test_run);
    return (test_failed > 0) ? 1 : 0;
}
