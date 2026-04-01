/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for IEC 61850 Sampled Values Publisher/Subscriber
 *
 * License: BSD-3-Clause
 */

#define _POSIX_C_SOURCE 199309L

#include "property_test.h"
#include "sv/sv_publisher.h"
#include "sv/sv_subscriber.h"
#include "asn1/sv_ber.h"

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
 * Publisher Tests
 * ======================================================================== */

static void test_sv_publisher_create_destroy(void)
{
    TEST("sv_publisher_create_destroy");
    iec61850_sv_publisher_t pub;
    iec61850_sv_config_t cfg;
    iec61850_sv_config_init(&cfg);
    iec61850_sv_publisher_init(&pub, &cfg);
    ASSERT_EQ(iec61850_sv_publisher_get_smp_cnt(&pub), (uint16_t)0);
    ASSERT_EQ(pub.sample_count, cfg.num_channels);
    iec61850_sv_publisher_destroy(&pub);
    PASS();
}

static void test_sv_publisher_set_samples(void)
{
    TEST("sv_publisher_set_samples");
    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, NULL);

    ASSERT_EQ(iec61850_sv_publisher_set_sample(&pub, 0, 1000), 0);
    ASSERT_EQ(iec61850_sv_publisher_set_sample(&pub, 1, -2000), 0);
    ASSERT_EQ(iec61850_sv_publisher_set_sample(&pub, 2, 3000), 0);
    ASSERT_EQ(iec61850_sv_publisher_set_sample(&pub, 3, -4000), 0);

    ASSERT_EQ(pub.samples[0], 1000);
    ASSERT_EQ(pub.samples[1], -2000);
    ASSERT_EQ(pub.samples[2], 3000);
    ASSERT_EQ(pub.samples[3], -4000);

    iec61850_sv_publisher_destroy(&pub);
    PASS();
}

static void test_sv_publisher_set_samples_batch(void)
{
    TEST("sv_publisher_set_samples_batch");
    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, NULL);

    int32_t vals[] = {100, 200, 300, 400};
    ASSERT_EQ(iec61850_sv_publisher_set_samples(&pub, vals, 4), 0);
    ASSERT_EQ(pub.samples[0], 100);
    ASSERT_EQ(pub.samples[3], 400);
    ASSERT_EQ(pub.sample_count, 4);

    iec61850_sv_publisher_destroy(&pub);
    PASS();
}

static void test_sv_publisher_prepare_packet(void)
{
    TEST("sv_publisher_prepare_packet");
    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, NULL);

    int32_t vals[] = {1000, -1000, 500, -500};
    iec61850_sv_publisher_set_samples(&pub, vals, 4);

    uint8_t buf[SV_MAX_APDU_SIZE];
    size_t encoded = 0;
    int ret = iec61850_sv_publisher_prepare(&pub, buf, sizeof(buf), &encoded);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(encoded > 0);

    /* smpCnt should have incremented */
    ASSERT_EQ(iec61850_sv_publisher_get_smp_cnt(&pub), (uint16_t)1);

    iec61850_sv_publisher_destroy(&pub);
    PASS();
}

static void test_sv_publisher_sample_counter(void)
{
    TEST("sv_publisher_sample_counter");
    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, NULL);
    iec61850_sv_publisher_set_sample(&pub, 0, 0);

    uint8_t buf[SV_MAX_APDU_SIZE];
    size_t encoded;

    iec61850_sv_publisher_prepare(&pub, buf, sizeof(buf), &encoded);
    ASSERT_EQ(iec61850_sv_publisher_get_smp_cnt(&pub), (uint16_t)1);

    iec61850_sv_publisher_prepare(&pub, buf, sizeof(buf), &encoded);
    ASSERT_EQ(iec61850_sv_publisher_get_smp_cnt(&pub), (uint16_t)2);

    iec61850_sv_publisher_reset_counter(&pub);
    ASSERT_EQ(iec61850_sv_publisher_get_smp_cnt(&pub), (uint16_t)0);

    iec61850_sv_publisher_destroy(&pub);
    PASS();
}

static void test_sv_publisher_quality(void)
{
    TEST("sv_publisher_quality");
    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, NULL);

    sv_quality_t q;
    memset(&q, 0, sizeof(q));
    q.validity = 1;
    q.overflow = 1;

    ASSERT_EQ(iec61850_sv_publisher_set_quality(&pub, 0, q), 0);
    ASSERT_EQ(pub.quality[0].validity, (uint8_t)1);
    ASSERT_EQ(pub.quality[0].overflow, (uint8_t)1);

    iec61850_sv_publisher_destroy(&pub);
    PASS();
}

/* ========================================================================
 * Subscriber Tests
 * ======================================================================== */

static int g_sv_cb_count = 0;
static iec61850_sv_message_t g_sv_last_msg;

static void sv_test_callback(const iec61850_sv_message_t *msg, void *user_data)
{
    (void)user_data;
    g_sv_cb_count++;
    g_sv_last_msg = *msg;
}

static void test_sv_subscriber_process(void)
{
    TEST("sv_subscriber_process");
    iec61850_sv_subscriber_t sub;
    iec61850_sv_subscriber_init(&sub, NULL);
    g_sv_cb_count = 0;
    iec61850_sv_subscriber_set_callback(&sub, sv_test_callback, NULL);

    sv_asdu_t asdu;
    sv_asdu_init(&asdu);
    sv_set_svid(&asdu, "SV_PUB_1");
    asdu.smpCnt = 0;
    sv_add_sample(&asdu, 1000, (sv_quality_t){0});

    bool accepted = iec61850_sv_subscriber_process(&sub, &asdu, 1000000);
    ASSERT_TRUE(accepted);
    ASSERT_EQ(g_sv_cb_count, 1);
    ASSERT_TRUE(g_sv_last_msg.is_new_sample);

    iec61850_sv_subscriber_destroy(&sub);
    PASS();
}

static void test_sv_subscriber_duplicate(void)
{
    TEST("sv_subscriber_duplicate");
    iec61850_sv_subscriber_t sub;
    iec61850_sv_subscriber_init(&sub, NULL);
    g_sv_cb_count = 0;
    iec61850_sv_subscriber_set_callback(&sub, sv_test_callback, NULL);

    sv_asdu_t asdu;
    sv_asdu_init(&asdu);
    sv_set_svid(&asdu, "SV_PUB_1");
    asdu.smpCnt = 5;

    iec61850_sv_subscriber_process(&sub, &asdu, 1000000);
    bool accepted = iec61850_sv_subscriber_process(&sub, &asdu, 2000000);
    ASSERT_TRUE(!accepted);
    ASSERT_EQ(g_sv_cb_count, 1);
    ASSERT_EQ((int)sub.total_duplicates, 1);

    iec61850_sv_subscriber_destroy(&sub);
    PASS();
}

static void test_sv_subscriber_gap_detection(void)
{
    TEST("sv_subscriber_gap_detection");
    iec61850_sv_subscriber_t sub;
    iec61850_sv_subscriber_init(&sub, NULL);
    g_sv_cb_count = 0;
    iec61850_sv_subscriber_set_callback(&sub, sv_test_callback, NULL);

    sv_asdu_t asdu;
    sv_asdu_init(&asdu);
    sv_set_svid(&asdu, "SV_PUB_1");

    /* smpCnt=0 */
    asdu.smpCnt = 0;
    iec61850_sv_subscriber_process(&sub, &asdu, 1000000);

    /* smpCnt=5 (gap of 4) */
    asdu.smpCnt = 5;
    iec61850_sv_subscriber_process(&sub, &asdu, 2000000);
    ASSERT_TRUE(g_sv_last_msg.has_gap);
    ASSERT_EQ((int)g_sv_last_msg.gap_count, 4);
    ASSERT_EQ((int)sub.total_gaps, 4);

    iec61850_sv_subscriber_destroy(&sub);
    PASS();
}

static void test_sv_subscriber_filtering(void)
{
    TEST("sv_subscriber_filtering");
    iec61850_sv_sub_config_t cfg;
    iec61850_sv_sub_config_init(&cfg);
    (void)strncpy(cfg.filter_svid, "SV_PUB_1", SV_MAX_SVID_LEN - 1);

    iec61850_sv_subscriber_t sub;
    iec61850_sv_subscriber_init(&sub, &cfg);

    sv_asdu_t asdu;
    sv_asdu_init(&asdu);

    sv_set_svid(&asdu, "SV_PUB_1");
    asdu.smpCnt = 0;
    ASSERT_TRUE(iec61850_sv_subscriber_process(&sub, &asdu, 1000));

    sv_set_svid(&asdu, "SV_PUB_OTHER");
    asdu.smpCnt = 0;
    ASSERT_TRUE(!iec61850_sv_subscriber_process(&sub, &asdu, 2000));

    iec61850_sv_subscriber_destroy(&sub);
    PASS();
}

/* ========================================================================
 * Property Test: SV encode-decode roundtrip
 * ======================================================================== */

static void test_sv_encode_decode_roundtrip(void)
{
    printf("\n");
    PROPERTY_TEST("SV encode-decode roundtrip", 1000) {
        iec61850_sv_config_t cfg;
        iec61850_sv_config_init(&cfg);
        int num_channels = 1 + (rand() % 8);
        cfg.num_channels = (uint8_t)num_channels;

        iec61850_sv_publisher_t pub;
        iec61850_sv_publisher_init(&pub, &cfg);

        int32_t vals[8] = {0};
        for (int j = 0; j < num_channels; j++) {
            vals[j] = random_int32();
        }
        iec61850_sv_publisher_set_samples(&pub, vals, (size_t)num_channels);

        uint8_t buf[SV_MAX_APDU_SIZE];
        size_t encoded = 0;
        int ret = iec61850_sv_publisher_prepare(&pub, buf, sizeof(buf), &encoded);
        PROPERTY_ASSERT(ret == 0, "encode failed");
        PROPERTY_ASSERT(encoded > 0, "encoded length is 0");

        sv_apdu_t decoded;
        sv_apdu_init(&decoded);
        ret = sv_decode_apdu(buf, encoded, &decoded);
        PROPERTY_ASSERT(ret == 0, "decode failed");
        PROPERTY_ASSERT(decoded.asdu[0].num_samples == (uint16_t)num_channels,
                        "channel count mismatch");

        iec61850_sv_publisher_destroy(&pub);
    }
    PROPERTY_TEST_END();

    tests_run++;
    if (_prop_failures == 0) { tests_passed++; } else { tests_failed++; }
}

/* ========================================================================
 * Direct SV BER API Tests (coverage)
 * ======================================================================== */

static void test_sv_set_datset(void)
{
    TEST("sv_set_datset");
    sv_asdu_t asdu;
    (void)memset(&asdu, 0, sizeof(asdu));

    int ret = sv_set_datset(&asdu, "IED1LD0/LLN0$DS1");
    ASSERT_TRUE(ret == 0);
    ASSERT_TRUE(asdu.has_datSet);
    ASSERT_TRUE(strcmp(asdu.datSet, "IED1LD0/LLN0$DS1") == 0);

    /* NULL args */
    ASSERT_TRUE(sv_set_datset(NULL, "test") != 0);
    ASSERT_TRUE(sv_set_datset(&asdu, NULL) != 0);
    PASS();
}

static void test_sv_encode_decode_with_datset(void)
{
    TEST("sv_encode_decode_with_datset");
    sv_apdu_t apdu;
    sv_apdu_init(&apdu);
    apdu.noASDU = 1;
    sv_set_svid(&apdu.asdu[0], "SV_DS1");
    sv_set_datset(&apdu.asdu[0], "IED1LD0/LLN0$DS1");
    sv_add_sample(&apdu.asdu[0], 500, (sv_quality_t){0});
    apdu.asdu[0].smpCnt = 10;
    apdu.asdu[0].confRev = 1;

    uint8_t buf[SV_MAX_APDU_SIZE];
    size_t encoded = 0;
    int ret = sv_encode_apdu(buf, sizeof(buf), &apdu, &encoded);
    ASSERT_TRUE(ret == 0);
    ASSERT_TRUE(encoded > 0);

    sv_apdu_t decoded;
    sv_apdu_init(&decoded);
    ret = sv_decode_apdu(buf, encoded, &decoded);
    ASSERT_TRUE(ret == 0);
    ASSERT_TRUE(decoded.asdu[0].has_datSet);
    ASSERT_TRUE(strcmp(decoded.asdu[0].datSet, "IED1LD0/LLN0$DS1") == 0);
    PASS();
}

static void test_sv_encode_null_args(void)
{
    TEST("sv_encode_null_args");
    sv_apdu_t apdu;
    sv_apdu_init(&apdu);
    uint8_t buf[64];
    size_t len = 0;

    ASSERT_TRUE(sv_encode_apdu(NULL, 64, &apdu, &len) != 0);
    ASSERT_TRUE(sv_encode_apdu(buf, 64, NULL, &len) != 0);
    ASSERT_TRUE(sv_encode_apdu(buf, 64, &apdu, NULL) != 0);
    ASSERT_TRUE(sv_decode_apdu(NULL, 64, &apdu) != 0);
    ASSERT_TRUE(sv_decode_apdu(buf, 64, NULL) != 0);
    PASS();
}

static void test_sv_add_sample_overflow(void)
{
    TEST("sv_add_sample_overflow");
    sv_asdu_t asdu;
    (void)memset(&asdu, 0, sizeof(asdu));

    /* Fill to capacity */
    for (uint8_t i = 0; i < SV_MAX_SAMPLES; i++) {
        int ret = sv_add_sample(&asdu, i, (sv_quality_t){0});
        ASSERT_TRUE(ret == 0);
    }

    /* Overflow */
    int ret = sv_add_sample(&asdu, 999, (sv_quality_t){0});
    ASSERT_TRUE(ret != 0);

    /* NULL */
    ASSERT_TRUE(sv_add_sample(NULL, 0, (sv_quality_t){0}) != 0);
    PASS();
}

static void test_sv_set_svid_null(void)
{
    TEST("sv_set_svid_null");
    sv_asdu_t asdu;
    (void)memset(&asdu, 0, sizeof(asdu));

    ASSERT_TRUE(sv_set_svid(NULL, "test") != 0);
    ASSERT_TRUE(sv_set_svid(&asdu, NULL) != 0);
    PASS();
}

static void test_sv_encode_with_optional_fields(void)
{
    TEST("sv_encode_with_optional_fields");
    sv_apdu_t apdu;
    sv_apdu_init(&apdu);
    apdu.noASDU = 1;
    sv_set_svid(&apdu.asdu[0], "SV_OPT");
    sv_set_datset(&apdu.asdu[0], "IED1LD0/LLN0$OptDS");
    sv_add_sample(&apdu.asdu[0], 200, (sv_quality_t){0});
    apdu.asdu[0].smpCnt = 5;
    apdu.asdu[0].confRev = 2;
    apdu.asdu[0].has_refrTm = true;
    apdu.asdu[0].refrTm = 1700000000000000ULL;
    apdu.asdu[0].has_smpRate = true;
    apdu.asdu[0].smpRate = 4000;
    apdu.asdu[0].has_smpMod = true;
    apdu.asdu[0].smpMod = 2;
    apdu.asdu[0].smpSynch = SV_SMPSYNCH_LOCAL;

    uint8_t buf[SV_MAX_APDU_SIZE];
    size_t encoded = 0;
    int ret = sv_encode_apdu(buf, sizeof(buf), &apdu, &encoded);
    ASSERT_TRUE(ret == 0);
    ASSERT_TRUE(encoded > 0);

    sv_apdu_t decoded;
    sv_apdu_init(&decoded);
    ret = sv_decode_apdu(buf, encoded, &decoded);
    ASSERT_TRUE(ret == 0);
    ASSERT_TRUE(decoded.asdu[0].has_datSet);
    ASSERT_TRUE(decoded.asdu[0].has_refrTm);
    ASSERT_TRUE(decoded.asdu[0].has_smpRate);
    ASSERT_EQ((int)decoded.asdu[0].smpRate, 4000);
    ASSERT_TRUE(decoded.asdu[0].has_smpMod);
    ASSERT_EQ((int)decoded.asdu[0].smpMod, 2);
    PASS();
}

static void test_sv_encode_multi_sample(void)
{
    TEST("sv_encode_multi_sample");
    sv_apdu_t apdu;
    sv_apdu_init(&apdu);
    apdu.noASDU = 1;
    sv_set_svid(&apdu.asdu[0], "SV_MULTI");
    apdu.asdu[0].smpCnt = 0;
    apdu.asdu[0].confRev = 1;

    /* Add 8 samples */
    for (int i = 0; i < 8; i++) {
        sv_add_sample(&apdu.asdu[0], (int32_t)(i * 1000),
                      (sv_quality_t){0});
    }

    uint8_t buf[SV_MAX_APDU_SIZE];
    size_t encoded = 0;
    int ret = sv_encode_apdu(buf, sizeof(buf), &apdu, &encoded);
    ASSERT_TRUE(ret == 0);

    sv_apdu_t decoded;
    sv_apdu_init(&decoded);
    ret = sv_decode_apdu(buf, encoded, &decoded);
    ASSERT_TRUE(ret == 0);
    ASSERT_EQ((int)decoded.asdu[0].num_samples, 8);

    for (int i = 0; i < 8; i++) {
        ASSERT_EQ(decoded.asdu[0].samples[i].value, (int32_t)(i * 1000));
    }
    PASS();
}

static void test_sv_encode_small_buffer(void)
{
    TEST("sv_encode_small_buffer");
    sv_apdu_t apdu;
    sv_apdu_init(&apdu);
    apdu.noASDU = 1;
    sv_set_svid(&apdu.asdu[0], "SV1");
    sv_add_sample(&apdu.asdu[0], 100, (sv_quality_t){0});
    apdu.asdu[0].smpCnt = 1;
    apdu.asdu[0].confRev = 1;

    uint8_t small_buf[4];
    size_t len = 0;
    int ret = sv_encode_apdu(small_buf, sizeof(small_buf), &apdu, &len);
    ASSERT_TRUE(ret != 0);  /* Buffer too small */
    PASS();
}

/* ========================================================================
 * Main
 * ======================================================================== */

/* Test: 4-byte quality roundtrip with all flag combinations */
static void test_sv_quality_4byte_roundtrip(void)
{
    TEST("sv_quality_4byte_roundtrip");

    sv_apdu_t apdu_in, apdu_out;
    uint8_t buf[512];
    size_t encoded_len;

    sv_apdu_init(&apdu_in);
    sv_set_svid(&apdu_in.asdu[0], "SV_QUAL_TEST");
    apdu_in.asdu[0].confRev = 1;

    /* Add sample with all quality flags set */
    sv_quality_t q_all;
    memset(&q_all, 0, sizeof(q_all));
    q_all.validity = 1;       /* invalid */
    q_all.overflow = 1;
    q_all.out_of_range = 1;
    q_all.bad_reference = 1;
    q_all.oscillatory = 1;
    q_all.failure = 1;
    q_all.old_data = 1;
    q_all.inconsistent = 1;
    q_all.inaccurate = 1;
    q_all.source = 1;         /* substituted */
    q_all.test = 1;
    q_all.operator_blocked = 1;

    sv_add_sample(&apdu_in.asdu[0], 12345, q_all);

    /* Add sample with good quality (all zeros) */
    sv_add_sample(&apdu_in.asdu[0], -9999, (sv_quality_t){0});

    int ret = sv_encode_apdu(buf, sizeof(buf), &apdu_in, &encoded_len);
    ASSERT_EQ(ret, 0);

    ret = sv_decode_apdu(buf, encoded_len, &apdu_out);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(apdu_out.asdu[0].num_samples, 2);

    /* Verify first sample: all flags set */
    ASSERT_EQ(apdu_out.asdu[0].samples[0].value, 12345);
    ASSERT_EQ(apdu_out.asdu[0].samples[0].quality.validity, 1);
    ASSERT_EQ(apdu_out.asdu[0].samples[0].quality.overflow, 1);
    ASSERT_EQ(apdu_out.asdu[0].samples[0].quality.out_of_range, 1);
    ASSERT_EQ(apdu_out.asdu[0].samples[0].quality.bad_reference, 1);
    ASSERT_EQ(apdu_out.asdu[0].samples[0].quality.oscillatory, 1);
    ASSERT_EQ(apdu_out.asdu[0].samples[0].quality.failure, 1);
    ASSERT_EQ(apdu_out.asdu[0].samples[0].quality.old_data, 1);
    ASSERT_EQ(apdu_out.asdu[0].samples[0].quality.inconsistent, 1);
    ASSERT_EQ(apdu_out.asdu[0].samples[0].quality.inaccurate, 1);
    ASSERT_EQ(apdu_out.asdu[0].samples[0].quality.source, 1);
    ASSERT_EQ(apdu_out.asdu[0].samples[0].quality.test, 1);
    ASSERT_EQ(apdu_out.asdu[0].samples[0].quality.operator_blocked, 1);

    /* Verify second sample: all zeros */
    ASSERT_EQ(apdu_out.asdu[0].samples[1].value, -9999);
    ASSERT_EQ(apdu_out.asdu[0].samples[1].quality.validity, 0);
    ASSERT_EQ(apdu_out.asdu[0].samples[1].quality.overflow, 0);
    ASSERT_EQ(apdu_out.asdu[0].samples[1].quality.test, 0);

    PASS();
}

/* Test: SV sample data is flat OCTET STRING (8 bytes per channel) */
static void test_sv_flat_octet_string_format(void)
{
    TEST("sv_flat_octet_string_format");

    sv_apdu_t apdu;
    uint8_t buf[512];
    size_t encoded_len;

    sv_apdu_init(&apdu);
    sv_set_svid(&apdu.asdu[0], "SV_FLAT");
    apdu.asdu[0].confRev = 1;

    /* 4 channels typical for 3-phase + neutral */
    sv_add_sample(&apdu.asdu[0], 1000, (sv_quality_t){0});
    sv_add_sample(&apdu.asdu[0], 2000, (sv_quality_t){0});
    sv_add_sample(&apdu.asdu[0], 3000, (sv_quality_t){0});
    sv_add_sample(&apdu.asdu[0], 4000, (sv_quality_t){0});

    int ret = sv_encode_apdu(buf, sizeof(buf), &apdu, &encoded_len);
    ASSERT_EQ(ret, 0);

    /* Find the [7] sample tag (0x87) in the encoded data */
    bool found_tag = false;
    for (size_t i = 0; i < encoded_len - 1; i++) {
        if (buf[i] == 0x87) {
            found_tag = true;
            /* The next byte(s) should encode length = 32 (4 * 8 bytes) */
            ASSERT_EQ(buf[i + 1], 32);  /* 4 channels × 8 bytes = 32 */
            break;
        }
    }
    ASSERT_TRUE(found_tag);

    /* Decode and verify roundtrip */
    sv_apdu_t decoded;
    ret = sv_decode_apdu(buf, encoded_len, &decoded);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(decoded.asdu[0].num_samples, 4);
    ASSERT_EQ(decoded.asdu[0].samples[0].value, 1000);
    ASSERT_EQ(decoded.asdu[0].samples[3].value, 4000);

    PASS();
}

/* Test: SV quality with validity=3 (questionable, 2-bit field) */
static void test_sv_quality_questionable(void)
{
    TEST("sv_quality_questionable");

    sv_apdu_t apdu_in, apdu_out;
    uint8_t buf[256];
    size_t encoded_len;

    sv_apdu_init(&apdu_in);
    sv_set_svid(&apdu_in.asdu[0], "SV_Q3");
    apdu_in.asdu[0].confRev = 1;

    sv_quality_t q;
    memset(&q, 0, sizeof(q));
    q.validity = 3;  /* questionable (2 bits) */
    sv_add_sample(&apdu_in.asdu[0], 500, q);

    int ret = sv_encode_apdu(buf, sizeof(buf), &apdu_in, &encoded_len);
    ASSERT_EQ(ret, 0);

    ret = sv_decode_apdu(buf, encoded_len, &apdu_out);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(apdu_out.asdu[0].samples[0].quality.validity, 3);

    PASS();
}

static void test_sv_multi_asdu(void)
{
    TEST("sv_multi_asdu_encode_decode");
    sv_apdu_t apdu_in, apdu_out;
    uint8_t buf[SV_MAX_APDU_SIZE];
    size_t encoded_len;

    sv_apdu_init(&apdu_in);
    apdu_in.noASDU = 3;

    /* ASDU 0: svpub1 with 2 samples */
    sv_set_svid(&apdu_in.asdu[0], "svpub1");
    apdu_in.asdu[0].confRev = 1;
    apdu_in.asdu[0].smpCnt = 100;
    sv_add_sample(&apdu_in.asdu[0], 1000, (sv_quality_t){0});
    sv_add_sample(&apdu_in.asdu[0], 2000, (sv_quality_t){0});

    /* ASDU 1: svpub2 with 1 sample */
    sv_set_svid(&apdu_in.asdu[1], "svpub2");
    apdu_in.asdu[1].confRev = 2;
    apdu_in.asdu[1].smpCnt = 200;
    sv_add_sample(&apdu_in.asdu[1], 3000, (sv_quality_t){0});

    /* ASDU 2: svpub3 with 2 samples */
    sv_set_svid(&apdu_in.asdu[2], "svpub3");
    apdu_in.asdu[2].confRev = 3;
    apdu_in.asdu[2].smpCnt = 300;
    sv_add_sample(&apdu_in.asdu[2], 4000, (sv_quality_t){0});
    sv_add_sample(&apdu_in.asdu[2], 5000, (sv_quality_t){0});

    int ret = sv_encode_apdu(buf, sizeof(buf), &apdu_in, &encoded_len);
    ASSERT_EQ(ret, 0);

    sv_apdu_init(&apdu_out);
    ret = sv_decode_apdu(buf, encoded_len, &apdu_out);
    ASSERT_EQ(ret, 0);

    /* Verify all 3 ASDUs decoded */
    ASSERT_EQ((int)apdu_out.noASDU, 3);

    /* ASDU 0 */
    ASSERT_TRUE(strcmp(apdu_out.asdu[0].svID, "svpub1") == 0);
    ASSERT_EQ((int)apdu_out.asdu[0].smpCnt, 100);
    ASSERT_EQ((int)apdu_out.asdu[0].confRev, 1);
    ASSERT_EQ((int)apdu_out.asdu[0].num_samples, 2);
    ASSERT_EQ(apdu_out.asdu[0].samples[0].value, 1000);
    ASSERT_EQ(apdu_out.asdu[0].samples[1].value, 2000);

    /* ASDU 1 */
    ASSERT_TRUE(strcmp(apdu_out.asdu[1].svID, "svpub2") == 0);
    ASSERT_EQ((int)apdu_out.asdu[1].smpCnt, 200);
    ASSERT_EQ((int)apdu_out.asdu[1].confRev, 2);
    ASSERT_EQ((int)apdu_out.asdu[1].num_samples, 1);
    ASSERT_EQ(apdu_out.asdu[1].samples[0].value, 3000);

    /* ASDU 2 */
    ASSERT_TRUE(strcmp(apdu_out.asdu[2].svID, "svpub3") == 0);
    ASSERT_EQ((int)apdu_out.asdu[2].smpCnt, 300);
    ASSERT_EQ((int)apdu_out.asdu[2].confRev, 3);
    ASSERT_EQ((int)apdu_out.asdu[2].num_samples, 2);
    ASSERT_EQ(apdu_out.asdu[2].samples[0].value, 4000);
    ASSERT_EQ(apdu_out.asdu[2].samples[1].value, 5000);

    PASS();
}

int main(void)
{
    property_test_init();

    printf("\n=== SV Publisher Tests ===\n");
    test_sv_publisher_create_destroy();
    test_sv_publisher_set_samples();
    test_sv_publisher_set_samples_batch();
    test_sv_publisher_prepare_packet();
    test_sv_publisher_sample_counter();
    test_sv_publisher_quality();

    printf("\n=== SV Subscriber Tests ===\n");
    test_sv_subscriber_process();
    test_sv_subscriber_duplicate();
    test_sv_subscriber_gap_detection();
    test_sv_subscriber_filtering();

    printf("\n=== SV BER API Tests ===\n");
    test_sv_set_datset();
    test_sv_encode_decode_with_datset();
    test_sv_encode_null_args();
    test_sv_add_sample_overflow();
    test_sv_set_svid_null();
    test_sv_encode_small_buffer();
    test_sv_encode_with_optional_fields();
    test_sv_encode_multi_sample();

    printf("\n=== SV Quality / Format Tests ===\n");
    test_sv_quality_4byte_roundtrip();
    test_sv_flat_octet_string_format();
    test_sv_quality_questionable();

    printf("\n=== SV Multi-ASDU Tests ===\n");
    test_sv_multi_asdu();

    printf("\n=== Property Tests ===\n");
    test_sv_encode_decode_roundtrip();

    printf("\n=== Test Summary ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    if (tests_failed > 0) {
        printf("\nFAILED\n");
        return 1;
    }

    printf("\nAll tests PASSED\n");
    return 0;
}
