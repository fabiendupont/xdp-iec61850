/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Integration Test: GOOSE Publisher → Subscriber Round-Trip
 *
 * Tests the complete GOOSE pipeline: publisher encodes APDU,
 * builds Ethernet frame, subscriber parses frame and decodes APDU,
 * verifies data integrity through the entire chain.
 *
 * This test does NOT require networking — it passes the encoded
 * frame buffer directly from publisher to subscriber decode path.
 *
 * License: BSD-3-Clause
 */


#include "goose/goose_publisher.h"
#include "goose/goose_subscriber.h"
#include "sv/sv_publisher.h"
#include "sv/sv_subscriber.h"
#include "transport/eth_frame.h"
#include "ied/ied_data_model.h"
#include "asn1/goose_ber.h"
#include "asn1/goose_ber_decode.h"

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

/* ========================================================================
 * GOOSE Encode → Decode Round-Trip via Ethernet Frame
 * ======================================================================== */

static void test_goose_frame_roundtrip(void)
{
    TEST("goose_frame_roundtrip");

    /* Setup publisher */
    iec61850_goose_config_t cfg;
    iec61850_goose_config_init(&cfg);
    cfg.app_id = 0x0001;
    cfg.vlan_id = 100;

    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, &cfg);

    /* Add data */
    iec61850_goose_publisher_set_boolean(&pub, 0, true);
    iec61850_goose_publisher_set_int32(&pub, 1, -42);
    iec61850_goose_publisher_set_uint32(&pub, 2, 1000);
    iec61850_goose_publisher_set_float32(&pub, 3, 3.14f);

    /* Encode APDU */
    uint8_t apdu_buf[GOOSE_MAX_APDU_SIZE];
    size_t apdu_len = 0;
    int ret = iec61850_goose_publisher_prepare(&pub, apdu_buf, sizeof(apdu_buf),
                                                 &apdu_len);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(apdu_len > 0);

    /* Build Ethernet frame */
    uint8_t frame[IEC61850_MAX_FRAME_SIZE];
    size_t frame_len = 0;
    iec61850_eth_frame_config_t fcfg;
    memset(&fcfg, 0, sizeof(fcfg));
    memcpy(fcfg.dst_mac, cfg.dst_mac, 6);
    memcpy(fcfg.src_mac, cfg.src_mac, 6);
    fcfg.ethertype = IEC61850_ETHERTYPE_GOOSE;
    fcfg.app_id = cfg.app_id;
    fcfg.vlan_id = cfg.vlan_id;
    fcfg.vlan_priority = cfg.vlan_priority;

    ret = iec61850_eth_frame_build(frame, sizeof(frame), &fcfg,
                                     apdu_buf, apdu_len, &frame_len);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(frame_len > apdu_len);

    /* Parse Ethernet frame */
    uint16_t ethertype = 0;
    uint16_t app_id = 0;
    uint16_t vlan_id = 0;
    const uint8_t *apdu_out = NULL;
    size_t apdu_out_len = 0;

    ret = iec61850_eth_frame_parse(frame, frame_len, &ethertype, &app_id,
                                     &vlan_id, &apdu_out, &apdu_out_len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)ethertype, (int)IEC61850_ETHERTYPE_GOOSE);
    ASSERT_EQ((int)app_id, 0x0001);
    ASSERT_EQ((int)vlan_id, 100);

    /* Decode APDU */
    goose_apdu_t decoded;
    goose_apdu_init(&decoded);
    ret = goose_decode_apdu(apdu_out, apdu_out_len, &decoded);
    ASSERT_EQ(ret, 0);

    /* Verify decoded data matches original */
    ASSERT_TRUE(strcmp(decoded.gocbRef, cfg.gocb_ref) == 0);
    ASSERT_TRUE(strcmp(decoded.datSet, cfg.dataset) == 0);
    ASSERT_EQ((int)decoded.numDatSetEntries, 4);
    ASSERT_TRUE(decoded.allData[0].type == GOOSE_DATA_BOOLEAN);
    ASSERT_TRUE(decoded.allData[0].value.boolean == true);
    ASSERT_TRUE(decoded.allData[1].type == GOOSE_DATA_INT32);
    ASSERT_EQ(decoded.allData[1].value.int32, -42);
    ASSERT_TRUE(decoded.allData[2].type == GOOSE_DATA_UINT32);
    ASSERT_TRUE(decoded.allData[2].value.uint32 == 1000);
    ASSERT_TRUE(decoded.allData[3].type == GOOSE_DATA_FLOAT32);

    /* Verify subscriber processes it correctly */
    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, NULL);
    bool accepted = iec61850_goose_subscriber_process(&sub, &decoded, 1000000ULL);
    ASSERT_TRUE(accepted);
    ASSERT_EQ((int)sub.total_messages, 1);

    iec61850_goose_publisher_destroy(&pub);
    iec61850_goose_subscriber_destroy(&sub);
    PASS();
}

/* ========================================================================
 * Multiple State Changes with stNum/sqNum Tracking
 * ======================================================================== */

static int g_cb_count = 0;
static iec61850_goose_message_t g_last_msg;

static void track_callback(const iec61850_goose_message_t *msg, void *user_data)
{
    (void)user_data;
    g_cb_count++;
    g_last_msg = *msg;
}

static void test_goose_state_change_e2e(void)
{
    TEST("goose_state_change_e2e");

    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, NULL);
    iec61850_goose_publisher_set_boolean(&pub, 0, false);

    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, NULL);
    g_cb_count = 0;
    iec61850_goose_subscriber_set_callback(&sub, track_callback, NULL);

    uint8_t apdu_buf[GOOSE_MAX_APDU_SIZE];
    size_t apdu_len;

    /* Initial publish: stNum=0, sqNum=0 */
    int ret = iec61850_goose_publisher_prepare(&pub, apdu_buf, sizeof(apdu_buf), &apdu_len);
    ASSERT_EQ(ret, 0);

    goose_apdu_t decoded;
    goose_apdu_init(&decoded);
    goose_decode_apdu(apdu_buf, apdu_len, &decoded);
    iec61850_goose_subscriber_process(&sub, &decoded, 1000000ULL);
    ASSERT_EQ(g_cb_count, 1);
    ASSERT_TRUE(g_last_msg.is_new_state);

    /* Retransmission: stNum=0, sqNum=1 */
    ret = iec61850_goose_publisher_prepare(&pub, apdu_buf, sizeof(apdu_buf), &apdu_len);
    ASSERT_EQ(ret, 0);
    goose_apdu_init(&decoded);
    goose_decode_apdu(apdu_buf, apdu_len, &decoded);
    iec61850_goose_subscriber_process(&sub, &decoded, 2000000ULL);
    ASSERT_EQ(g_cb_count, 2);
    ASSERT_TRUE(g_last_msg.is_retransmission);

    /* State change: stNum=1, sqNum=0 */
    iec61850_goose_publisher_state_change(&pub);
    iec61850_goose_publisher_set_boolean(&pub, 0, true);
    ret = iec61850_goose_publisher_prepare(&pub, apdu_buf, sizeof(apdu_buf), &apdu_len);
    ASSERT_EQ(ret, 0);
    goose_apdu_init(&decoded);
    goose_decode_apdu(apdu_buf, apdu_len, &decoded);
    iec61850_goose_subscriber_process(&sub, &decoded, 3000000ULL);
    ASSERT_EQ(g_cb_count, 3);
    ASSERT_TRUE(g_last_msg.is_new_state);
    ASSERT_TRUE(g_last_msg.apdu.allData[0].value.boolean == true);

    iec61850_goose_publisher_destroy(&pub);
    iec61850_goose_subscriber_destroy(&sub);
    PASS();
}

/* ========================================================================
 * APPID Filtering Through Frame Build/Parse
 * ======================================================================== */

static void test_goose_appid_filter(void)
{
    TEST("goose_appid_filter");

    iec61850_goose_config_t cfg;
    iec61850_goose_config_init(&cfg);
    cfg.app_id = 0x0042;

    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, &cfg);
    iec61850_goose_publisher_set_boolean(&pub, 0, true);

    uint8_t apdu_buf[GOOSE_MAX_APDU_SIZE];
    size_t apdu_len;
    iec61850_goose_publisher_prepare(&pub, apdu_buf, sizeof(apdu_buf), &apdu_len);

    /* Build frame with APPID 0x0042 */
    uint8_t frame[IEC61850_MAX_FRAME_SIZE];
    size_t frame_len;
    iec61850_eth_frame_config_t fcfg;
    memset(&fcfg, 0, sizeof(fcfg));
    memcpy(fcfg.dst_mac, cfg.dst_mac, 6);
    fcfg.ethertype = IEC61850_ETHERTYPE_GOOSE;
    fcfg.app_id = 0x0042;
    fcfg.vlan_id = cfg.vlan_id;
    iec61850_eth_frame_build(frame, sizeof(frame), &fcfg,
                               apdu_buf, apdu_len, &frame_len);

    /* Parse and check APPID */
    uint16_t et, ai, vi;
    const uint8_t *apdu_out;
    size_t apdu_out_len;
    iec61850_eth_frame_parse(frame, frame_len, &et, &ai, &vi, &apdu_out, &apdu_out_len);
    ASSERT_EQ((int)ai, 0x0042);

    iec61850_goose_publisher_destroy(&pub);
    PASS();
}

/* ========================================================================
 * SV Publisher → Subscriber Round-Trip
 * ======================================================================== */

static void test_sv_frame_roundtrip(void)
{
    TEST("sv_frame_roundtrip");

    iec61850_sv_config_t cfg;
    iec61850_sv_config_init(&cfg);
    cfg.app_id = 0x4000;
    cfg.smp_rate = 80;

    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, &cfg);

    int32_t samples[] = {1000, -2000, 3000, -4000};
    iec61850_sv_publisher_set_samples(&pub, samples, 4);

    /* Encode */
    uint8_t apdu_buf[1500];
    size_t apdu_len;
    int ret = iec61850_sv_publisher_prepare(&pub, apdu_buf, sizeof(apdu_buf), &apdu_len);
    ASSERT_EQ(ret, 0);

    /* Build frame */
    uint8_t frame[IEC61850_MAX_FRAME_SIZE];
    size_t frame_len;
    iec61850_eth_frame_config_t fcfg;
    memset(&fcfg, 0, sizeof(fcfg));
    memcpy(fcfg.dst_mac, cfg.dst_mac, 6);
    fcfg.ethertype = IEC61850_ETHERTYPE_SV;
    fcfg.app_id = cfg.app_id;
    fcfg.vlan_id = cfg.vlan_id;
    iec61850_eth_frame_build(frame, sizeof(frame), &fcfg,
                               apdu_buf, apdu_len, &frame_len);

    /* Parse frame */
    uint16_t et, ai, vi;
    const uint8_t *apdu_out;
    size_t apdu_out_len;
    ret = iec61850_eth_frame_parse(frame, frame_len, &et, &ai, &vi,
                                     &apdu_out, &apdu_out_len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)et, (int)IEC61850_ETHERTYPE_SV);
    ASSERT_EQ((int)ai, 0x4000);

    /* Decode SV APDU */
    sv_apdu_t sv_decoded;
    sv_apdu_init(&sv_decoded);
    ret = sv_decode_apdu(apdu_out, apdu_out_len, &sv_decoded);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(sv_decoded.noASDU >= 1);
    ASSERT_TRUE(strcmp(sv_decoded.asdu[0].svID, "SV_PUB_1") == 0);
    ASSERT_EQ((int)sv_decoded.asdu[0].smpCnt, 0);

    /* Process through subscriber */
    iec61850_sv_subscriber_t sub;
    iec61850_sv_subscriber_init(&sub, NULL);
    bool accepted = iec61850_sv_subscriber_process(&sub, &sv_decoded.asdu[0], 1000000ULL);
    ASSERT_TRUE(accepted);

    iec61850_sv_publisher_destroy(&pub);
    iec61850_sv_subscriber_destroy(&sub);
    PASS();
}

/* ========================================================================
 * SV smpCnt Incrementing Through Multiple Publishes
 * ======================================================================== */

static void test_sv_smpcnt_sequence(void)
{
    TEST("sv_smpcnt_sequence");

    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, NULL);
    iec61850_sv_publisher_set_sample(&pub, 0, 1000);

    iec61850_sv_subscriber_t sub;
    iec61850_sv_subscriber_init(&sub, NULL);

    uint8_t apdu_buf[1500];
    size_t apdu_len;

    for (int i = 0; i < 10; i++) {
        iec61850_sv_publisher_prepare(&pub, apdu_buf, sizeof(apdu_buf), &apdu_len);

        sv_apdu_t decoded;
        sv_apdu_init(&decoded);
        sv_decode_apdu(apdu_buf, apdu_len, &decoded);
        ASSERT_EQ((int)decoded.asdu[0].smpCnt, i);

        iec61850_sv_subscriber_process(&sub, &decoded.asdu[0], (uint64_t)(i * 1000000));
    }

    ASSERT_EQ((int)sub.total_messages, 10);
    ASSERT_EQ((int)sub.total_gaps, 0);

    iec61850_sv_publisher_destroy(&pub);
    iec61850_sv_subscriber_destroy(&sub);
    PASS();
}

/* ========================================================================
 * IED Model → Data Store Integration
 * ======================================================================== */

static void test_ied_model_data_roundtrip(void)
{
    TEST("ied_model_data_roundtrip");

    /* Build a minimal IED model */
    iec61850_ied_model_t model;
    iec61850_ied_model_init(&model, "IED1");

    iec61850_logical_device_t *ld = iec61850_ld_create("LD0");
    iec61850_logical_node_t *xcbr = iec61850_ln_create("XCBR", "1");
    iec61850_data_object_t *pos = iec61850_cdc_create_dpc("Pos");
    iec61850_ln_add_data_object(xcbr, pos);
    iec61850_ld_add_logical_node(ld, xcbr);
    iec61850_ied_model_add_ld(&model, ld);

    /* Find attribute via path */
    iec61850_data_attribute_t *stval =
        iec61850_ied_model_find_attribute(&model, "LD0/XCBR1.Pos.stVal", IEC61850_FC_ST);
    ASSERT_TRUE(stval != NULL);

    /* Set and get value */
    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;
    val.value.integer = 2;  /* DBPOS intermediate */
    iec61850_da_set_value(stval, &val);

    mms_value_t got = iec61850_da_get_value(stval);
    ASSERT_EQ((int)got.type, (int)MMS_TYPE_INTEGER);
    ASSERT_EQ(got.value.integer, 2);

    iec61850_ied_model_destroy(&model);
    PASS();
}

int main(void)
{
    printf("\n=== GOOSE Round-Trip Integration Tests ===\n");
    test_goose_frame_roundtrip();
    test_goose_state_change_e2e();
    test_goose_appid_filter();

    printf("\n=== SV Round-Trip Integration Tests ===\n");
    test_sv_frame_roundtrip();
    test_sv_smpcnt_sequence();

    printf("\n=== IED Model Integration ===\n");
    test_ied_model_data_roundtrip();

    printf("\n=== Test Summary ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
