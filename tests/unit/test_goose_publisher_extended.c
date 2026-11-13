/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Extended GOOSE Publisher Tests
 *
 * Tests retransmission, state changes, data types, and boundary conditions.
 */


#include "goose/goose_publisher.h"
#include "transport/eth_frame.h"
#include <stdio.h>
#include <string.h>

static int test_run = 0, test_passed = 0, test_failed = 0;
#define TEST(name) do { test_run++; printf("  [TEST] %s ...", name); } while(0)
#define PASS() do { test_passed++; printf(" PASS\n"); return; } while(0)
#define FAIL(msg) do { test_failed++; printf(" FAIL: %s\n", msg); return; } while(0)
#define ASSERT_TRUE(x) do { if (!(x)) { FAIL(#x); } } while(0)
#define ASSERT_EQ(a,b) do { if ((a) != (b)) { printf(" (got %d, want %d)", (a), (b)); FAIL(#a " != " #b); } } while(0)

static void test_state_change_increments_stnum(void)
{
    TEST("state_change_increments_stnum");
    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, NULL);

    ASSERT_EQ((int)iec61850_goose_publisher_get_st_num(&pub), 0);
    ASSERT_EQ((int)iec61850_goose_publisher_get_sq_num(&pub), 0);

    iec61850_goose_publisher_state_change(&pub);
    ASSERT_EQ((int)iec61850_goose_publisher_get_st_num(&pub), 1);
    ASSERT_EQ((int)iec61850_goose_publisher_get_sq_num(&pub), 0);

    iec61850_goose_publisher_state_change(&pub);
    ASSERT_EQ((int)iec61850_goose_publisher_get_st_num(&pub), 2);
    ASSERT_EQ((int)iec61850_goose_publisher_get_sq_num(&pub), 0);

    iec61850_goose_publisher_destroy(&pub);
    PASS();
}

static void test_prepare_increments_sqnum(void)
{
    TEST("prepare_increments_sqnum");
    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, NULL);
    (void)iec61850_goose_publisher_set_boolean(&pub, 0, true);

    uint8_t buf[512];
    size_t len = 0;

    int ret = iec61850_goose_publisher_prepare(&pub, buf, sizeof(buf), &len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)iec61850_goose_publisher_get_sq_num(&pub), 1);

    ret = iec61850_goose_publisher_prepare(&pub, buf, sizeof(buf), &len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)iec61850_goose_publisher_get_sq_num(&pub), 2);

    iec61850_goose_publisher_destroy(&pub);
    PASS();
}

static void test_state_change_resets_sqnum(void)
{
    TEST("state_change_resets_sqnum");
    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, NULL);
    (void)iec61850_goose_publisher_set_boolean(&pub, 0, false);

    uint8_t buf[512];
    size_t len = 0;

    /* Publish a few times to get sqNum > 0 */
    (void)iec61850_goose_publisher_prepare(&pub, buf, sizeof(buf), &len);
    (void)iec61850_goose_publisher_prepare(&pub, buf, sizeof(buf), &len);
    (void)iec61850_goose_publisher_prepare(&pub, buf, sizeof(buf), &len);
    ASSERT_EQ((int)iec61850_goose_publisher_get_sq_num(&pub), 3);

    /* State change should reset sqNum to 0 */
    iec61850_goose_publisher_state_change(&pub);
    ASSERT_EQ((int)iec61850_goose_publisher_get_sq_num(&pub), 0);
    ASSERT_EQ((int)iec61850_goose_publisher_get_st_num(&pub), 1);

    iec61850_goose_publisher_destroy(&pub);
    PASS();
}

static void test_set_all_data_types(void)
{
    TEST("set_all_data_types");
    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, NULL);

    ASSERT_EQ(iec61850_goose_publisher_set_boolean(&pub, 0, true), 0);
    ASSERT_EQ(iec61850_goose_publisher_set_int32(&pub, 1, -100), 0);
    ASSERT_EQ(iec61850_goose_publisher_set_uint32(&pub, 2, 999), 0);
    ASSERT_EQ(iec61850_goose_publisher_set_float32(&pub, 3, 3.14f), 0);

    uint8_t bs[] = {0xC0};
    ASSERT_EQ(iec61850_goose_publisher_set_bitstring(&pub, 4, bs, 1), 0);

    uint8_t os[] = {0x01, 0x02, 0x03};
    ASSERT_EQ(iec61850_goose_publisher_set_octetstring(&pub, 5, os, 3), 0);

    /* Encode and verify it succeeds */
    uint8_t buf[1024];
    size_t len = 0;
    int ret = iec61850_goose_publisher_prepare(&pub, buf, sizeof(buf), &len);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(len > 0);

    iec61850_goose_publisher_destroy(&pub);
    PASS();
}

static void test_max_data_entries(void)
{
    TEST("max_data_entries");
    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, NULL);

    /* Fill all entries */
    for (size_t i = 0; i < GOOSE_MAX_ALLDATA_ENTRIES; i++) {
        ASSERT_EQ(iec61850_goose_publisher_set_boolean(&pub, i, true), 0);
    }

    /* Overflow should fail */
    ASSERT_EQ(iec61850_goose_publisher_set_boolean(&pub, GOOSE_MAX_ALLDATA_ENTRIES, true), -1);

    iec61850_goose_publisher_destroy(&pub);
    PASS();
}

static void test_null_publisher_operations(void)
{
    TEST("null_publisher_operations");
    ASSERT_EQ((int)iec61850_goose_publisher_get_st_num(NULL), 0);
    ASSERT_EQ((int)iec61850_goose_publisher_get_sq_num(NULL), 0);
    iec61850_goose_publisher_state_change(NULL);  /* should not crash */
    iec61850_goose_publisher_set_io(NULL, NULL);   /* should not crash */

    uint8_t buf[64];
    size_t len = 0;
    ASSERT_EQ(iec61850_goose_publisher_prepare(NULL, buf, sizeof(buf), &len), -1);
    PASS();
}

static void test_config_defaults(void)
{
    TEST("config_defaults");
    iec61850_goose_config_t cfg;
    iec61850_goose_config_init(&cfg);

    ASSERT_EQ((int)cfg.app_id, 1);
    ASSERT_EQ((int)cfg.time_allowed_to_live, 2000);
    ASSERT_EQ((int)cfg.vlan_id, 100);
    ASSERT_EQ((int)cfg.vlan_priority, 4);
    ASSERT_TRUE(cfg.dst_mac[0] == 0x01);
    ASSERT_TRUE(cfg.dst_mac[1] == 0x0C);
    ASSERT_TRUE(cfg.dst_mac[2] == 0xCD);
    ASSERT_TRUE(cfg.dst_mac[3] == 0x01);
    PASS();
}

static void test_frame_build_and_parse(void)
{
    TEST("frame_build_and_parse");
    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, NULL);
    (void)iec61850_goose_publisher_set_boolean(&pub, 0, true);

    uint8_t apdu[512];
    size_t apdu_len = 0;
    int ret = iec61850_goose_publisher_prepare(&pub, apdu, sizeof(apdu), &apdu_len);
    ASSERT_EQ(ret, 0);

    /* Build frame */
    iec61850_eth_frame_config_t fcfg;
    (void)memset(&fcfg, 0, sizeof(fcfg));
    fcfg.dst_mac[0] = 0x01; fcfg.dst_mac[1] = 0x0C; fcfg.dst_mac[2] = 0xCD;
    fcfg.dst_mac[3] = 0x01; fcfg.dst_mac[4] = 0x00; fcfg.dst_mac[5] = 0x01;
    fcfg.ethertype = IEC61850_ETHERTYPE_GOOSE;
    fcfg.app_id = 1;

    uint8_t frame[IEC61850_MAX_FRAME_SIZE];
    size_t frame_len = 0;
    ret = iec61850_eth_frame_build(frame, sizeof(frame), &fcfg,
                                    apdu, apdu_len, &frame_len);
    ASSERT_EQ(ret, 0);

    /* Parse frame */
    uint16_t et = 0, appid = 0, vlan = 0;
    const uint8_t *out_apdu = NULL;
    size_t out_len = 0;
    ret = iec61850_eth_frame_parse(frame, frame_len, &et, &appid, &vlan,
                                    &out_apdu, &out_len, NULL, NULL);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)et, (int)IEC61850_ETHERTYPE_GOOSE);
    ASSERT_EQ((int)appid, 1);
    ASSERT_EQ((int)out_len, (int)apdu_len);
    ASSERT_TRUE(memcmp(out_apdu, apdu, apdu_len) == 0);

    iec61850_goose_publisher_destroy(&pub);
    PASS();
}

static void test_retransmit_config(void)
{
    TEST("retransmit_config");
    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, NULL);

    iec61850_retransmit_config_t rcfg;
    rcfg.t0_ms = 2;
    rcfg.t_max_ms = 1000;

    iec61850_goose_publisher_enable_retransmit(&pub, &rcfg);
    ASSERT_TRUE(pub.has_retransmit);

    iec61850_goose_publisher_destroy(&pub);
    PASS();
}

int main(void)
{
    printf("\n=== GOOSE Publisher Extended Tests ===\n");

    test_state_change_increments_stnum();
    test_prepare_increments_sqnum();
    test_state_change_resets_sqnum();
    test_set_all_data_types();
    test_max_data_entries();
    test_null_publisher_operations();
    test_config_defaults();
    test_frame_build_and_parse();
    test_retransmit_config();

    printf("\n  Results: %d/%d passed\n\n", test_passed, test_run);
    return (test_failed > 0) ? 1 : 0;
}
