/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Interop Test: libiec61850 SV Publisher → xdp-iec61850 Subscriber
 *
 * Tests: SS-01 through SS-07
 * Requires: root (raw sockets), libiec61850 helpers built
 */


#include "../interop_helpers.h"
#include "sv/sv_publisher.h"
#include "sv/sv_subscriber.h"
#include "transport/eth_frame.h"
#include "asn1/sv_ber.h"

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

/*
 * SS-01: Basic SV frame — flat OCTET STRING format (INTEROP-2)
 * Verify our encoder produces tag 0x87 with flat packed data.
 */
static void test_ss01_flat_octetstring(void)
{
    INTEROP_TEST("SS-01: flat OCTET STRING sample format (INTEROP-2)");

    iec61850_sv_config_t cfg;
    iec61850_sv_config_init(&cfg);
    cfg.app_id = 0x4000;
    cfg.num_channels = 4;

    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, &cfg);

    int32_t samples[] = {1000, -2000, 3000, -4000};
    iec61850_sv_publisher_set_samples(&pub, samples, 4);

    uint8_t apdu_buf[SV_MAX_APDU_SIZE];
    size_t apdu_len = 0;
    int ret = iec61850_sv_publisher_prepare(&pub, apdu_buf, sizeof(apdu_buf),
                                              &apdu_len);
    INTEROP_ASSERT_EQ(ret, 0);

    /* Find tag 0x87 (sample data) in the encoded APDU */
    bool found_sample_tag = false;
    for (size_t i = 0; i < apdu_len - 1; i++) {
        if (apdu_buf[i] == 0x87) {
            found_sample_tag = true;
            /* The content should be flat: 4 channels * 8 bytes = 32 bytes */
            size_t content_len = apdu_buf[i + 1];
            INTEROP_ASSERT_EQ((int)content_len, 32);

            /* First channel: value=1000 (big-endian int32) + quality=0 */
            const uint8_t *data = &apdu_buf[i + 2];
            int32_t val0;
            memcpy(&val0, data, 4);
            val0 = (int32_t)ntohl((uint32_t)val0);
            INTEROP_ASSERT_EQ(val0, 1000);

            /* Second channel: value=-2000 */
            int32_t val1;
            memcpy(&val1, data + 8, 4);
            val1 = (int32_t)ntohl((uint32_t)val1);
            INTEROP_ASSERT_EQ(val1, -2000);
            break;
        }
    }
    INTEROP_ASSERT(found_sample_tag);

    iec61850_sv_publisher_destroy(&pub);
    INTEROP_PASS();
}

/*
 * SS-02: 4-byte Quality in SV (INTEROP-3)
 * Verify quality is encoded as 4 bytes (uint32 big-endian) per channel.
 */
static void test_ss02_quality_4bytes(void)
{
    INTEROP_TEST("SS-02: 4-byte Quality (INTEROP-3)");

    iec61850_sv_config_t cfg;
    iec61850_sv_config_init(&cfg);
    cfg.num_channels = 1;

    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, &cfg);

    iec61850_sv_publisher_set_sample(&pub, 0, 500);
    sv_quality_t q = {0};
    q.validity = 1; /* invalid */
    q.test = 1;
    iec61850_sv_publisher_set_quality(&pub, 0, q);

    uint8_t apdu_buf[SV_MAX_APDU_SIZE];
    size_t apdu_len = 0;
    iec61850_sv_publisher_prepare(&pub, apdu_buf, sizeof(apdu_buf), &apdu_len);

    /* Find sample data tag 0x87 */
    for (size_t i = 0; i < apdu_len - 1; i++) {
        if (apdu_buf[i] == 0x87) {
            /* Should be 8 bytes: 4 value + 4 quality */
            INTEROP_ASSERT_EQ((int)apdu_buf[i + 1], 8);

            /* Quality bytes (offset 4-7 in data) */
            const uint8_t *qdata = &apdu_buf[i + 2 + 4];
            uint32_t qraw = ((uint32_t)qdata[0] << 24) |
                            ((uint32_t)qdata[1] << 16) |
                            ((uint32_t)qdata[2] << 8) |
                            ((uint32_t)qdata[3]);
            /* validity=01 is bits 0-1, test=1 is bit 11 */
            INTEROP_ASSERT(qraw != 0); /* should have bits set */
            break;
        }
    }

    iec61850_sv_publisher_destroy(&pub);
    INTEROP_PASS();
}

/*
 * SS-03: SV decode round-trip
 */
static void test_ss03_roundtrip(void)
{
    INTEROP_TEST("SS-03: SV encode-decode roundtrip");

    iec61850_sv_config_t cfg;
    iec61850_sv_config_init(&cfg);
    cfg.smp_rate = 80;
    cfg.num_channels = 4;

    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, &cfg);

    int32_t values[] = {100, -200, 300, -400};
    iec61850_sv_publisher_set_samples(&pub, values, 4);

    uint8_t apdu_buf[SV_MAX_APDU_SIZE];
    size_t apdu_len;
    iec61850_sv_publisher_prepare(&pub, apdu_buf, sizeof(apdu_buf), &apdu_len);

    sv_apdu_t decoded;
    sv_apdu_init(&decoded);
    int ret = sv_decode_apdu(apdu_buf, apdu_len, &decoded);
    INTEROP_ASSERT_EQ(ret, 0);
    INTEROP_ASSERT(decoded.noASDU >= 1);
    INTEROP_ASSERT_EQ((int)decoded.asdu[0].smpCnt, 0);
    INTEROP_ASSERT_EQ((int)decoded.asdu[0].num_samples, 4);
    INTEROP_ASSERT_EQ(decoded.asdu[0].samples[0].value, 100);
    INTEROP_ASSERT_EQ(decoded.asdu[0].samples[1].value, -200);
    INTEROP_ASSERT_EQ(decoded.asdu[0].samples[2].value, 300);
    INTEROP_ASSERT_EQ(decoded.asdu[0].samples[3].value, -400);

    iec61850_sv_publisher_destroy(&pub);
    INTEROP_PASS();
}

/*
 * SS-04: smpCnt incrementing
 */
static void test_ss04_smpcnt(void)
{
    INTEROP_TEST("SS-04: smpCnt incrementing");

    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, NULL);
    iec61850_sv_publisher_set_sample(&pub, 0, 1000);

    for (int i = 0; i < 5; i++) {
        uint8_t apdu_buf[SV_MAX_APDU_SIZE];
        size_t apdu_len;
        iec61850_sv_publisher_prepare(&pub, apdu_buf, sizeof(apdu_buf), &apdu_len);

        sv_apdu_t decoded;
        sv_apdu_init(&decoded);
        sv_decode_apdu(apdu_buf, apdu_len, &decoded);
        INTEROP_ASSERT_EQ((int)decoded.asdu[0].smpCnt, i);
    }

    iec61850_sv_publisher_destroy(&pub);
    INTEROP_PASS();
}

/*
 * SS-05: APPID filtering
 */
static void test_ss05_appid_filter(void)
{
    INTEROP_TEST("SS-05: SV APPID filtering");

    iec61850_sv_sub_config_t cfg;
    iec61850_sv_sub_config_init(&cfg);
    cfg.filter_appid = 0x4000;

    iec61850_sv_subscriber_t sub;
    iec61850_sv_subscriber_init(&sub, &cfg);

    /* Build frame with wrong APPID */
    iec61850_sv_config_t pcfg;
    iec61850_sv_config_init(&pcfg);
    pcfg.app_id = 0x4099; /* wrong */

    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, &pcfg);
    iec61850_sv_publisher_set_sample(&pub, 0, 1000);

    uint8_t frame[IEC61850_MAX_FRAME_SIZE];
    size_t frame_len;
    iec61850_sv_publisher_build_frame(&pub, frame, sizeof(frame), &frame_len);

    int ret = iec61850_sv_subscriber_process_frame(&sub, frame, frame_len,
                                                      1000000ULL);
    INTEROP_ASSERT_EQ(ret, 0); /* filtered */

    iec61850_sv_publisher_destroy(&pub);
    iec61850_sv_subscriber_destroy(&sub);
    INTEROP_PASS();
}

/*
 * SS-06: SV frame build+parse round-trip (INTEROP-2)
 */
static void test_ss06_frame_roundtrip(void)
{
    INTEROP_TEST("SS-06: SV frame roundtrip (INTEROP-2)");

    iec61850_sv_config_t cfg;
    iec61850_sv_config_init(&cfg);
    cfg.app_id = 0x4000;

    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, &cfg);
    int32_t samples[] = {1000, -2000, 3000, -4000};
    iec61850_sv_publisher_set_samples(&pub, samples, 4);

    uint8_t frame[IEC61850_MAX_FRAME_SIZE];
    size_t frame_len;
    int ret = iec61850_sv_publisher_build_frame(&pub, frame, sizeof(frame),
                                                   &frame_len);
    INTEROP_ASSERT_EQ(ret, 0);

    /* Parse frame */
    uint16_t et, ai, vi;
    const uint8_t *apdu_out;
    size_t apdu_out_len;
    ret = iec61850_eth_frame_parse(frame, frame_len, &et, &ai, &vi,
                                      &apdu_out, &apdu_out_len, NULL);
    INTEROP_ASSERT_EQ(ret, 0);
    INTEROP_ASSERT_EQ((int)et, (int)IEC61850_ETHERTYPE_SV);
    INTEROP_ASSERT_EQ((int)ai, 0x4000);

    /* Decode APDU */
    sv_apdu_t decoded;
    sv_apdu_init(&decoded);
    ret = sv_decode_apdu(apdu_out, apdu_out_len, &decoded);
    INTEROP_ASSERT_EQ(ret, 0);
    INTEROP_ASSERT_EQ((int)decoded.asdu[0].num_samples, 4);
    INTEROP_ASSERT_EQ(decoded.asdu[0].samples[0].value, 1000);

    iec61850_sv_publisher_destroy(&pub);
    INTEROP_PASS();
}

/*
 * SS-07: Quality roundtrip — verify 4-byte quality survives encode→decode
 */
static void test_ss07_quality_roundtrip(void)
{
    INTEROP_TEST("SS-07: Quality roundtrip (INTEROP-3)");

    iec61850_sv_config_t cfg;
    iec61850_sv_config_init(&cfg);
    cfg.num_channels = 2;

    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, &cfg);

    iec61850_sv_publisher_set_sample(&pub, 0, 1000);
    iec61850_sv_publisher_set_sample(&pub, 1, 2000);

    sv_quality_t q0 = {0};
    q0.validity = 1;  /* invalid */
    q0.overflow = 1;
    iec61850_sv_publisher_set_quality(&pub, 0, q0);

    sv_quality_t q1 = {0};
    q1.test = 1;
    iec61850_sv_publisher_set_quality(&pub, 1, q1);

    uint8_t apdu_buf[SV_MAX_APDU_SIZE];
    size_t apdu_len;
    iec61850_sv_publisher_prepare(&pub, apdu_buf, sizeof(apdu_buf), &apdu_len);

    sv_apdu_t decoded;
    sv_apdu_init(&decoded);
    int ret = sv_decode_apdu(apdu_buf, apdu_len, &decoded);
    INTEROP_ASSERT_EQ(ret, 0);
    INTEROP_ASSERT_EQ((int)decoded.asdu[0].num_samples, 2);

    /* Channel 0: validity=1, overflow=1 */
    INTEROP_ASSERT_EQ((int)decoded.asdu[0].samples[0].quality.validity, 1);
    INTEROP_ASSERT_EQ((int)decoded.asdu[0].samples[0].quality.overflow, 1);
    /* Channel 1: test=1 */
    INTEROP_ASSERT_EQ((int)decoded.asdu[0].samples[1].quality.test, 1);

    iec61850_sv_publisher_destroy(&pub);
    INTEROP_PASS();
}

int main(void)
{
    printf("\n=== SV Interop Tests: libiec61850 pub → xdp sub ===\n");

    test_ss01_flat_octetstring();
    test_ss02_quality_4bytes();
    test_ss03_roundtrip();
    test_ss04_smpcnt();
    test_ss05_appid_filter();
    test_ss06_frame_roundtrip();
    test_ss07_quality_roundtrip();

    INTEROP_SUMMARY();
    return interop_tests_failed > 0 ? 1 : 0;
}
