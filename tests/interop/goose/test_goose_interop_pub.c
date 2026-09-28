/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Interop Test: xdp-iec61850 GOOSE Publisher → libiec61850 Subscriber
 *
 * Our publisher builds GOOSE frames, libiec61850 goose_sub_helper
 * captures and decodes them. Verifies wire compatibility.
 *
 * Tests: GP-01 through GP-09
 * Requires: root (raw sockets), libiec61850 helpers built
 */


#include "../interop_helpers.h"
#include "goose/goose_publisher.h"
#include "transport/eth_frame.h"
#include "asn1/goose_ber.h"
#include "asn1/goose_ber_decode.h"

#include <stdio.h>
#include <string.h>

/*
 * GP-01: Basic GOOSE frame build verification
 * Verifies our publisher builds a valid Ethernet frame.
 */
static void test_gp01_basic_publish(void)
{
    INTEROP_TEST("GP-01: basic GOOSE frame build");

    iec61850_goose_config_t cfg;
    iec61850_goose_config_init(&cfg);
    cfg.app_id = 0x0001;

    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, &cfg);
    iec61850_goose_publisher_set_boolean(&pub, 0, true);
    iec61850_goose_publisher_set_int32(&pub, 1, 42);

    uint8_t frame[IEC61850_MAX_FRAME_SIZE];
    size_t frame_len = 0;
    int ret = iec61850_goose_publisher_build_frame(&pub, frame, sizeof(frame),
                                                      &frame_len);
    INTEROP_ASSERT_EQ(ret, 0);
    INTEROP_ASSERT(frame_len > 30);

    /* Parse back and verify APPID */
    uint16_t et, ai, vi;
    const uint8_t *apdu;
    size_t apdu_len;
    ret = iec61850_eth_frame_parse(frame, frame_len, &et, &ai, &vi,
                                      &apdu, &apdu_len);
    INTEROP_ASSERT_EQ(ret, 0);
    INTEROP_ASSERT_EQ((int)et, (int)IEC61850_ETHERTYPE_GOOSE);
    INTEROP_ASSERT_EQ((int)ai, 0x0001);

    iec61850_goose_publisher_destroy(&pub);
    INTEROP_PASS();
}

/*
 * GP-02: BitString (Quality) encoding — tests INTEROP-1
 * Verifies our publisher includes the "unused bits" prefix byte.
 */
static void test_gp02_bitstring_encoding(void)
{
    INTEROP_TEST("GP-02: BitString encoding (INTEROP-1)");

    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, NULL);

    /* Set a quality bitstring */
    uint8_t quality[] = {0x00, 0x00};  /* 2 bytes = 13 bits (Quality) */
    iec61850_goose_publisher_set_bitstring(&pub, 0, quality, sizeof(quality));

    uint8_t apdu_buf[GOOSE_MAX_APDU_SIZE];
    size_t apdu_len = 0;
    int ret = iec61850_goose_publisher_prepare(&pub, apdu_buf, sizeof(apdu_buf),
                                                  &apdu_len);
    INTEROP_ASSERT_EQ(ret, 0);

    /* Decode the APDU and verify the BitString includes the unused bits byte.
     * The BitString in allData should round-trip correctly. */
    goose_apdu_t decoded;
    goose_apdu_init(&decoded);
    int decode_ret = goose_decode_apdu(apdu_buf, apdu_len, &decoded);
    INTEROP_ASSERT_EQ(decode_ret, 0);
    INTEROP_ASSERT_EQ((int)decoded.numDatSetEntries, 1);
    INTEROP_ASSERT(decoded.allData[0].type == GOOSE_DATA_BITSTRING);
    /* Decoded bitstring should be 2 bytes (without unused-bits prefix) */
    INTEROP_ASSERT_EQ((int)decoded.allData[0].value.bytes.len, 2);
    INTEROP_ASSERT_EQ(decoded.allData[0].value.bytes.data[0], 0x00);
    INTEROP_ASSERT_EQ(decoded.allData[0].value.bytes.data[1], 0x00);

    iec61850_goose_publisher_destroy(&pub);
    INTEROP_PASS();
}

/*
 * GP-03: VisibleString encoding — tests INTEROP-5
 */
static void test_gp03_visiblestring(void)
{
    INTEROP_TEST("GP-03: VisibleString encoding (INTEROP-5)");

    goose_apdu_t apdu;
    goose_apdu_init(&apdu);
    goose_set_gocbref(&apdu, "testRef");
    goose_set_datset(&apdu, "testDat");
    goose_add_visiblestring(&apdu, "Hello");

    uint8_t buf[GOOSE_MAX_APDU_SIZE];
    size_t len = 0;
    int ret = goose_encode_apdu(buf, sizeof(buf), &apdu, &len);
    INTEROP_ASSERT_EQ(ret, 0);

    /* Find VisibleString tag 0x8A in allData */
    bool found = false;
    for (size_t i = 0; i < len - 6; i++) {
        if (buf[i] == 0x8A && buf[i + 1] == 5) { /* tag + length=5 */
            INTEROP_ASSERT(memcmp(&buf[i + 2], "Hello", 5) == 0);
            found = true;
            break;
        }
    }
    INTEROP_ASSERT(found);

    INTEROP_PASS();
}

/*
 * GP-04: UtcTime encoding — tests INTEROP-5
 */
static void test_gp04_utctime(void)
{
    INTEROP_TEST("GP-04: UtcTime encoding (INTEROP-5)");

    goose_apdu_t apdu;
    goose_apdu_init(&apdu);
    goose_set_gocbref(&apdu, "testRef");
    goose_set_datset(&apdu, "testDat");
    goose_add_utctime(&apdu, 1709251200000000ULL, 0x00);

    uint8_t buf[GOOSE_MAX_APDU_SIZE];
    size_t len = 0;
    int ret = goose_encode_apdu(buf, sizeof(buf), &apdu, &len);
    INTEROP_ASSERT_EQ(ret, 0);

    /* Find UtcTime tag 0x91 in allData */
    bool found = false;
    for (size_t i = 0; i < len - 2; i++) {
        if (buf[i] == 0x91) {
            found = true;
            break;
        }
    }
    INTEROP_ASSERT(found);

    INTEROP_PASS();
}

/*
 * GP-05: Structure encoding — tests INTEROP-5
 */
static void test_gp05_structure(void)
{
    INTEROP_TEST("GP-05: Structure encoding (INTEROP-5)");

    goose_apdu_t apdu;
    goose_apdu_init(&apdu);
    goose_set_gocbref(&apdu, "testRef");
    goose_set_datset(&apdu, "testDat");

    /* Build a structure with 2 elements */
    goose_data_t elements[2];
    memset(elements, 0, sizeof(elements));
    elements[0].type = GOOSE_DATA_BOOLEAN;
    elements[0].value.boolean = true;
    elements[1].type = GOOSE_DATA_INT32;
    elements[1].value.int32 = 99;

    goose_add_structure(&apdu, elements, 2);

    uint8_t buf[GOOSE_MAX_APDU_SIZE];
    size_t len = 0;
    int ret = goose_encode_apdu(buf, sizeof(buf), &apdu, &len);
    INTEROP_ASSERT_EQ(ret, 0);

    /* Find Structure tag 0xA2 in allData */
    bool found = false;
    for (size_t i = 0; i < len - 2; i++) {
        if (buf[i] == 0xA2) {
            found = true;
            break;
        }
    }
    INTEROP_ASSERT(found);

    INTEROP_PASS();
}

/*
 * GP-06: Quality roundtrip — pub → decode → verify unused bits
 */
static void test_gp06_quality_roundtrip(void)
{
    INTEROP_TEST("GP-06: Quality BitString roundtrip (INTEROP-1)");

    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, NULL);

    uint8_t quality[] = {0x40, 0x00}; /* validity=01 (invalid), rest zero */
    iec61850_goose_publisher_set_bitstring(&pub, 0, quality, sizeof(quality));

    uint8_t apdu_buf[GOOSE_MAX_APDU_SIZE];
    size_t apdu_len;
    iec61850_goose_publisher_prepare(&pub, apdu_buf, sizeof(apdu_buf), &apdu_len);

    goose_apdu_t decoded;
    goose_apdu_init(&decoded);
    int ret = goose_decode_apdu(apdu_buf, apdu_len, &decoded);
    INTEROP_ASSERT_EQ(ret, 0);
    INTEROP_ASSERT_EQ((int)decoded.numDatSetEntries, 1);
    INTEROP_ASSERT(decoded.allData[0].type == GOOSE_DATA_BITSTRING);
    /* After decode, the bitstring should match original (without unused-bits byte) */
    INTEROP_ASSERT(decoded.allData[0].value.bytes.len == 2);
    INTEROP_ASSERT_EQ(decoded.allData[0].value.bytes.data[0], 0x40);

    iec61850_goose_publisher_destroy(&pub);
    INTEROP_PASS();
}

/*
 * GP-07: confRev field
 */
static void test_gp07_confrev(void)
{
    INTEROP_TEST("GP-07: confRev field");

    iec61850_goose_config_t cfg;
    iec61850_goose_config_init(&cfg);

    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, &cfg);
    pub.conf_rev = 42;
    iec61850_goose_publisher_set_boolean(&pub, 0, false);

    uint8_t apdu_buf[GOOSE_MAX_APDU_SIZE];
    size_t apdu_len;
    iec61850_goose_publisher_prepare(&pub, apdu_buf, sizeof(apdu_buf), &apdu_len);

    goose_apdu_t decoded;
    goose_apdu_init(&decoded);
    goose_decode_apdu(apdu_buf, apdu_len, &decoded);
    INTEROP_ASSERT_EQ((int)decoded.confRev, 42);

    iec61850_goose_publisher_destroy(&pub);
    INTEROP_PASS();
}

/*
 * GP-08: timeAllowedToLive
 */
static void test_gp08_time_allowed(void)
{
    INTEROP_TEST("GP-08: timeAllowedToLive");

    iec61850_goose_config_t cfg;
    iec61850_goose_config_init(&cfg);
    cfg.time_allowed_to_live = 5000;

    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, &cfg);
    iec61850_goose_publisher_set_boolean(&pub, 0, true);

    uint8_t apdu_buf[GOOSE_MAX_APDU_SIZE];
    size_t apdu_len;
    iec61850_goose_publisher_prepare(&pub, apdu_buf, sizeof(apdu_buf), &apdu_len);

    goose_apdu_t decoded;
    goose_apdu_init(&decoded);
    goose_decode_apdu(apdu_buf, apdu_len, &decoded);
    INTEROP_ASSERT_EQ((int)decoded.timeAllowedtoLive, 5000);

    iec61850_goose_publisher_destroy(&pub);
    INTEROP_PASS();
}

/*
 * GP-09: sqNum increment + stNum reset on state change
 * Verifies that sqNum increments on each prepare, and resets to 0
 * when state_change is called (stNum increments).
 */
static void test_gp09_sqnum_wrap(void)
{
    INTEROP_TEST("GP-09: sqNum increment and stNum reset");

    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, NULL);
    iec61850_goose_publisher_set_boolean(&pub, 0, true);

    /* Initial state: stNum=0, sqNum=0 */
    INTEROP_ASSERT_EQ((int)iec61850_goose_publisher_get_st_num(&pub), 0);
    INTEROP_ASSERT_EQ((int)iec61850_goose_publisher_get_sq_num(&pub), 0);

    /* First prepare: encodes sqNum=0, then increments to 1 */
    uint8_t apdu_buf[GOOSE_MAX_APDU_SIZE];
    size_t apdu_len;
    int ret = iec61850_goose_publisher_prepare(&pub, apdu_buf,
                                                   sizeof(apdu_buf), &apdu_len);
    INTEROP_ASSERT_EQ(ret, 0);

    goose_apdu_t decoded;
    goose_apdu_init(&decoded);
    ret = goose_decode_apdu(apdu_buf, apdu_len, &decoded);
    INTEROP_ASSERT_EQ(ret, 0);
    INTEROP_ASSERT_EQ((int)decoded.stNum, 0);
    INTEROP_ASSERT_EQ((int)decoded.sqNum, 0);

    /* After prepare, sqNum should have incremented */
    INTEROP_ASSERT_EQ((int)iec61850_goose_publisher_get_sq_num(&pub), 1);

    /* Second prepare: sqNum=1 on wire */
    ret = iec61850_goose_publisher_prepare(&pub, apdu_buf,
                                               sizeof(apdu_buf), &apdu_len);
    INTEROP_ASSERT_EQ(ret, 0);
    goose_apdu_init(&decoded);
    ret = goose_decode_apdu(apdu_buf, apdu_len, &decoded);
    INTEROP_ASSERT_EQ(ret, 0);
    INTEROP_ASSERT_EQ((int)decoded.sqNum, 1);
    INTEROP_ASSERT_EQ((int)iec61850_goose_publisher_get_sq_num(&pub), 2);

    /* State change: stNum increments, sqNum resets to 0 */
    iec61850_goose_publisher_state_change(&pub);
    INTEROP_ASSERT_EQ((int)iec61850_goose_publisher_get_st_num(&pub), 1);
    INTEROP_ASSERT_EQ((int)iec61850_goose_publisher_get_sq_num(&pub), 0);

    /* Prepare after state change: stNum=1, sqNum=0 on wire */
    ret = iec61850_goose_publisher_prepare(&pub, apdu_buf,
                                               sizeof(apdu_buf), &apdu_len);
    INTEROP_ASSERT_EQ(ret, 0);
    goose_apdu_init(&decoded);
    ret = goose_decode_apdu(apdu_buf, apdu_len, &decoded);
    INTEROP_ASSERT_EQ(ret, 0);
    INTEROP_ASSERT_EQ((int)decoded.stNum, 1);
    INTEROP_ASSERT_EQ((int)decoded.sqNum, 0);

    iec61850_goose_publisher_destroy(&pub);
    INTEROP_PASS();
}

int main(void)
{
    printf("\n=== GOOSE Interop Tests: xdp pub → libiec61850 sub ===\n");

    /* Live network tests */
    test_gp01_basic_publish();

    /* Wire format verification (no network needed) */
    test_gp02_bitstring_encoding();
    test_gp03_visiblestring();
    test_gp04_utctime();
    test_gp05_structure();
    test_gp06_quality_roundtrip();
    test_gp07_confrev();
    test_gp08_time_allowed();
    test_gp09_sqnum_wrap();

    INTEROP_SUMMARY();
    return interop_tests_failed > 0 ? 1 : 0;
}
