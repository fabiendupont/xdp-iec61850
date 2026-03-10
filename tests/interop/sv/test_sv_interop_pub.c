/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Interop Test: xdp-iec61850 SV Publisher → libiec61850 Subscriber
 *
 * Tests: SP-01 through SP-04
 * Verifies our SV wire format is compatible with standard implementations.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "../interop_helpers.h"
#include "sv/sv_publisher.h"
#include "transport/eth_frame.h"
#include "asn1/sv_ber.h"

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

/*
 * SP-01: Flat OCTET STRING format verification (INTEROP-2)
 * Build SV frame and verify the sample tag is 0x87 with flat data.
 */
static void test_sp01_flat_format(void)
{
    INTEROP_TEST("SP-01: flat OCTET STRING on wire (INTEROP-2)");

    iec61850_sv_config_t cfg;
    iec61850_sv_config_init(&cfg);
    cfg.app_id = 0x4000;
    cfg.num_channels = 4;

    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, &cfg);

    int32_t values[] = {1000, 2000, 3000, 4000};
    iec61850_sv_publisher_set_samples(&pub, values, 4);

    uint8_t frame[IEC61850_MAX_FRAME_SIZE];
    size_t frame_len;
    int ret = iec61850_sv_publisher_build_frame(&pub, frame, sizeof(frame),
                                                   &frame_len);
    INTEROP_ASSERT_EQ(ret, 0);

    /* Parse and verify APDU contains 0x87 tag */
    uint16_t et, ai, vi;
    const uint8_t *apdu;
    size_t apdu_len;
    iec61850_eth_frame_parse(frame, frame_len, &et, &ai, &vi, &apdu, &apdu_len);

    bool found_87 = false;
    for (size_t i = 0; i < apdu_len; i++) {
        if (apdu[i] == 0x87) {
            found_87 = true;
            /* Length = 4 channels * 8 bytes = 32 */
            INTEROP_ASSERT_EQ((int)apdu[i + 1], 32);
            break;
        }
    }
    INTEROP_ASSERT(found_87);

    iec61850_sv_publisher_destroy(&pub);
    INTEROP_PASS();
}

/*
 * SP-02: 4-byte quality on wire (INTEROP-3)
 */
static void test_sp02_quality_4byte(void)
{
    INTEROP_TEST("SP-02: 4-byte quality on wire (INTEROP-3)");

    iec61850_sv_config_t cfg;
    iec61850_sv_config_init(&cfg);
    cfg.num_channels = 1;

    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, &cfg);
    iec61850_sv_publisher_set_sample(&pub, 0, 42);

    sv_quality_t q = {0};
    q.validity = 3; /* questionable */
    iec61850_sv_publisher_set_quality(&pub, 0, q);

    uint8_t apdu_buf[SV_MAX_APDU_SIZE];
    size_t apdu_len;
    iec61850_sv_publisher_prepare(&pub, apdu_buf, sizeof(apdu_buf), &apdu_len);

    /* Sample data tag should have 8 bytes: 4 value + 4 quality */
    for (size_t i = 0; i < apdu_len; i++) {
        if (apdu_buf[i] == 0x87) {
            INTEROP_ASSERT_EQ((int)apdu_buf[i + 1], 8);
            /* Quality at offset +6 should be non-zero (validity=3) */
            uint32_t qraw = ((uint32_t)apdu_buf[i + 6] << 24) |
                            ((uint32_t)apdu_buf[i + 7] << 16) |
                            ((uint32_t)apdu_buf[i + 8] << 8) |
                            ((uint32_t)apdu_buf[i + 9]);
            INTEROP_ASSERT(qraw != 0);
            break;
        }
    }

    iec61850_sv_publisher_destroy(&pub);
    INTEROP_PASS();
}

/*
 * SP-03: Multi-channel SV
 */
static void test_sp03_multichannel(void)
{
    INTEROP_TEST("SP-03: multi-channel SV");

    iec61850_sv_config_t cfg;
    iec61850_sv_config_init(&cfg);
    cfg.num_channels = 8;

    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, &cfg);

    for (int i = 0; i < 8; i++) {
        iec61850_sv_publisher_set_sample(&pub, (size_t)i, (int32_t)((i + 1) * 100));
    }

    uint8_t apdu_buf[SV_MAX_APDU_SIZE];
    size_t apdu_len;
    int ret = iec61850_sv_publisher_prepare(&pub, apdu_buf, sizeof(apdu_buf),
                                              &apdu_len);
    INTEROP_ASSERT_EQ(ret, 0);

    sv_apdu_t decoded;
    sv_apdu_init(&decoded);
    ret = sv_decode_apdu(apdu_buf, apdu_len, &decoded);
    INTEROP_ASSERT_EQ(ret, 0);
    INTEROP_ASSERT_EQ((int)decoded.asdu[0].num_samples, 8);

    for (int i = 0; i < 8; i++) {
        INTEROP_ASSERT_EQ(decoded.asdu[0].samples[i].value, (i + 1) * 100);
    }

    iec61850_sv_publisher_destroy(&pub);
    INTEROP_PASS();
}

/*
 * SP-04: smpCnt wraparound
 */
static void test_sp04_smpcnt_wrap(void)
{
    INTEROP_TEST("SP-04: smpCnt wraparound");

    iec61850_sv_config_t cfg;
    iec61850_sv_config_init(&cfg);
    cfg.smp_rate = 0; /* No rate-based wrap — wraps at uint16_t max */

    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, &cfg);
    iec61850_sv_publisher_set_sample(&pub, 0, 1000);

    /* Set smpCnt near uint16_t wraparound */
    pub.smp_cnt = 65534;

    uint8_t apdu_buf[SV_MAX_APDU_SIZE];
    size_t apdu_len;

    /* Publish: smpCnt should be 65534 */
    iec61850_sv_publisher_prepare(&pub, apdu_buf, sizeof(apdu_buf), &apdu_len);
    sv_apdu_t decoded;
    sv_apdu_init(&decoded);
    sv_decode_apdu(apdu_buf, apdu_len, &decoded);
    INTEROP_ASSERT_EQ((int)decoded.asdu[0].smpCnt, 65534);

    /* Next publish: smpCnt should be 65535 */
    iec61850_sv_publisher_prepare(&pub, apdu_buf, sizeof(apdu_buf), &apdu_len);
    sv_apdu_init(&decoded);
    sv_decode_apdu(apdu_buf, apdu_len, &decoded);
    INTEROP_ASSERT_EQ((int)decoded.asdu[0].smpCnt, 65535);

    /* Next: should wrap to 0 */
    iec61850_sv_publisher_prepare(&pub, apdu_buf, sizeof(apdu_buf), &apdu_len);
    sv_apdu_init(&decoded);
    sv_decode_apdu(apdu_buf, apdu_len, &decoded);
    INTEROP_ASSERT_EQ((int)decoded.asdu[0].smpCnt, 0);

    iec61850_sv_publisher_destroy(&pub);
    INTEROP_PASS();
}

int main(void)
{
    printf("\n=== SV Interop Tests: xdp pub → libiec61850 sub ===\n");

    test_sp01_flat_format();
    test_sp02_quality_4byte();
    test_sp03_multichannel();
    test_sp04_smpcnt_wrap();

    INTEROP_SUMMARY();
    return interop_tests_failed > 0 ? 1 : 0;
}
