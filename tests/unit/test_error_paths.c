/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for Error Paths
 *
 * Systematic NULL pointer, buffer overflow, and invalid enum coverage
 * across all public API functions.
 *
 * License: BSD-3-Clause
 */

#include "asn1/goose_ber.h"
#include "asn1/goose_ber_decode.h"
#include "asn1/sv_ber.h"
#include "goose/goose_publisher.h"
#include "goose/goose_subscriber.h"
#include "sv/sv_publisher.h"
#include "sv/sv_subscriber.h"
#include "transport/eth_frame.h"

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
 * GOOSE Publisher Error Paths
 * ======================================================================== */

static void test_publisher_null_inputs(void)
{
    TEST("publisher_null_inputs");
    /* NULL pub */
    ASSERT_EQ(iec61850_goose_publisher_set_boolean(NULL, 0, true), -1);
    ASSERT_EQ(iec61850_goose_publisher_set_int32(NULL, 0, 0), -1);
    ASSERT_EQ(iec61850_goose_publisher_set_uint32(NULL, 0, 0), -1);
    ASSERT_EQ(iec61850_goose_publisher_set_float32(NULL, 0, 0.0f), -1);

    uint8_t data[] = {0x01};
    ASSERT_EQ(iec61850_goose_publisher_set_bitstring(NULL, 0, data, 1), -1);
    ASSERT_EQ(iec61850_goose_publisher_set_octetstring(NULL, 0, data, 1), -1);

    /* NULL data for byte types */
    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, NULL);
    ASSERT_EQ(iec61850_goose_publisher_set_bitstring(&pub, 0, NULL, 1), -1);
    ASSERT_EQ(iec61850_goose_publisher_set_octetstring(&pub, 0, NULL, 1), -1);

    /* prepare with NULL args */
    uint8_t buf[64];
    size_t encoded;
    ASSERT_EQ(iec61850_goose_publisher_prepare(NULL, buf, 64, &encoded), -1);
    ASSERT_EQ(iec61850_goose_publisher_prepare(&pub, NULL, 64, &encoded), -1);
    ASSERT_EQ(iec61850_goose_publisher_prepare(&pub, buf, 64, NULL), -1);

    iec61850_goose_publisher_destroy(&pub);
    PASS();
}

static void test_publisher_index_overflow(void)
{
    TEST("publisher_index_overflow");
    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, NULL);

    /* Index beyond max entries */
    ASSERT_EQ(iec61850_goose_publisher_set_boolean(&pub, GOOSE_MAX_ALLDATA_ENTRIES, true), -1);
    ASSERT_EQ(iec61850_goose_publisher_set_int32(&pub, GOOSE_MAX_ALLDATA_ENTRIES, 0), -1);

    iec61850_goose_publisher_destroy(&pub);
    PASS();
}

static void test_publisher_byte_too_long(void)
{
    TEST("publisher_byte_too_long");
    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, NULL);

    uint8_t big[IEC61850_GOOSE_MAX_BYTE_ENTRY_LEN + 1];
    memset(big, 0xAA, sizeof(big));

    ASSERT_EQ(iec61850_goose_publisher_set_bitstring(&pub, 0, big, sizeof(big)), -1);
    ASSERT_EQ(iec61850_goose_publisher_set_octetstring(&pub, 0, big, sizeof(big)), -1);

    iec61850_goose_publisher_destroy(&pub);
    PASS();
}

/* ========================================================================
 * GOOSE Subscriber Error Paths
 * ======================================================================== */

static void test_subscriber_null_inputs(void)
{
    TEST("subscriber_null_inputs");
    /* process with NULL sub/apdu */
    goose_apdu_t apdu;
    goose_apdu_init(&apdu);

    ASSERT_TRUE(!iec61850_goose_subscriber_process(NULL, &apdu, 0));
    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, NULL);
    ASSERT_TRUE(!iec61850_goose_subscriber_process(&sub, NULL, 0));

    /* get_pub_state with NULL */
    ASSERT_TRUE(iec61850_goose_subscriber_get_pub_state(NULL, "test") == NULL);
    ASSERT_TRUE(iec61850_goose_subscriber_get_pub_state(&sub, NULL) == NULL);

    /* poll with NULL */
    ASSERT_TRUE(iec61850_goose_subscriber_poll(NULL, (struct packet_io *)0x1) < 0);
    ASSERT_TRUE(iec61850_goose_subscriber_poll(&sub, NULL) < 0);

    iec61850_goose_subscriber_destroy(&sub);
    PASS();
}

/* ========================================================================
 * SV Publisher Error Paths
 * ======================================================================== */

static void test_sv_publisher_null_inputs(void)
{
    TEST("sv_publisher_null_inputs");
    ASSERT_EQ(iec61850_sv_publisher_set_sample(NULL, 0, 0), -1);
    sv_quality_t q = {0};
    ASSERT_EQ(iec61850_sv_publisher_set_quality(NULL, 0, q), -1);
    ASSERT_EQ(iec61850_sv_publisher_set_samples(NULL, NULL, 0), -1);

    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, NULL);
    ASSERT_EQ(iec61850_sv_publisher_set_samples(&pub, NULL, 1), -1);

    /* Channel overflow */
    ASSERT_EQ(iec61850_sv_publisher_set_sample(&pub, SV_MAX_SAMPLES, 0), -1);
    ASSERT_EQ(iec61850_sv_publisher_set_quality(&pub, SV_MAX_SAMPLES, q), -1);

    /* prepare NULL args */
    uint8_t buf[64];
    size_t encoded;
    ASSERT_EQ(iec61850_sv_publisher_prepare(NULL, buf, 64, &encoded), -1);
    ASSERT_EQ(iec61850_sv_publisher_prepare(&pub, NULL, 64, &encoded), -1);
    ASSERT_EQ(iec61850_sv_publisher_prepare(&pub, buf, 64, NULL), -1);

    iec61850_sv_publisher_destroy(&pub);
    PASS();
}

/* ========================================================================
 * SV Subscriber Error Paths
 * ======================================================================== */

static void test_sv_subscriber_null_inputs(void)
{
    TEST("sv_subscriber_null_inputs");
    sv_asdu_t asdu;
    sv_asdu_init(&asdu);

    ASSERT_TRUE(!iec61850_sv_subscriber_process(NULL, &asdu, 0));
    iec61850_sv_subscriber_t sub;
    iec61850_sv_subscriber_init(&sub, NULL);
    ASSERT_TRUE(!iec61850_sv_subscriber_process(&sub, NULL, 0));

    ASSERT_TRUE(iec61850_sv_subscriber_get_pub_state(NULL, "test") == NULL);
    ASSERT_TRUE(iec61850_sv_subscriber_get_pub_state(&sub, NULL) == NULL);

    ASSERT_TRUE(iec61850_sv_subscriber_poll(NULL, (struct packet_io *)0x1) < 0);
    ASSERT_TRUE(iec61850_sv_subscriber_poll(&sub, NULL) < 0);

    iec61850_sv_subscriber_destroy(&sub);
    PASS();
}

/* ========================================================================
 * BER Encode Error Paths
 * ======================================================================== */

static void test_ber_encode_null_args(void)
{
    TEST("ber_encode_null_args");
    uint8_t buf[16];
    size_t offset = 0;

    /* NULL buffer */
    ASSERT_EQ(ber_encode_tag(NULL, 16, &offset, 0x80), GOOSE_BER_ERR_INVALID_ARG);
    ASSERT_EQ(ber_encode_length(NULL, 16, &offset, 1), GOOSE_BER_ERR_INVALID_ARG);
    ASSERT_EQ(ber_encode_boolean(NULL, 16, &offset, 0x80, true), GOOSE_BER_ERR_INVALID_ARG);
    ASSERT_EQ(ber_encode_int32(NULL, 16, &offset, 0x80, 0), GOOSE_BER_ERR_INVALID_ARG);
    ASSERT_EQ(ber_encode_uint32(NULL, 16, &offset, 0x80, 0), GOOSE_BER_ERR_INVALID_ARG);
    ASSERT_EQ(ber_encode_visiblestring(NULL, 16, &offset, 0x80, "test"), GOOSE_BER_ERR_INVALID_ARG);
    ASSERT_EQ(ber_encode_utctime(NULL, 16, &offset, 0x80, 0, 0), GOOSE_BER_ERR_INVALID_ARG);

    /* NULL offset */
    ASSERT_EQ(ber_encode_tag(buf, 16, NULL, 0x80), GOOSE_BER_ERR_INVALID_ARG);
    ASSERT_EQ(ber_encode_length(buf, 16, NULL, 1), GOOSE_BER_ERR_INVALID_ARG);
    ASSERT_EQ(ber_encode_boolean(buf, 16, NULL, 0x80, true), GOOSE_BER_ERR_INVALID_ARG);
    ASSERT_EQ(ber_encode_int32(buf, 16, NULL, 0x80, 0), GOOSE_BER_ERR_INVALID_ARG);
    ASSERT_EQ(ber_encode_uint32(buf, 16, NULL, 0x80, 0), GOOSE_BER_ERR_INVALID_ARG);

    /* NULL string */
    ASSERT_EQ(ber_encode_visiblestring(buf, 16, &offset, 0x80, NULL), GOOSE_BER_ERR_INVALID_ARG);

    PASS();
}

static void test_ber_encode_buffer_full(void)
{
    TEST("ber_encode_buffer_full");
    uint8_t buf[2];
    size_t offset = 0;

    /* Buffer too small for boolean (tag+len+val = 3 bytes) */
    ASSERT_EQ(ber_encode_boolean(buf, 2, &offset, 0x80, true), GOOSE_BER_ERR_BUFFER_FULL);

    /* Tag at end */
    offset = 2;
    ASSERT_EQ(ber_encode_tag(buf, 2, &offset, 0x80), GOOSE_BER_ERR_BUFFER_FULL);

    PASS();
}

/* ========================================================================
 * BER Decode Error Paths
 * ======================================================================== */

static void test_ber_decode_null_args(void)
{
    TEST("ber_decode_null_args");
    uint8_t buf[4] = {0x80, 0x01, 0x00, 0x00};
    size_t offset = 0;
    uint8_t tag;
    size_t len;

    ASSERT_EQ(ber_decode_tag(NULL, 4, &offset, &tag), GOOSE_BER_ERR_INVALID_ARG);
    ASSERT_EQ(ber_decode_tag(buf, 4, NULL, &tag), GOOSE_BER_ERR_INVALID_ARG);
    ASSERT_EQ(ber_decode_tag(buf, 4, &offset, NULL), GOOSE_BER_ERR_INVALID_ARG);

    ASSERT_EQ(ber_decode_length(NULL, 4, &offset, &len), GOOSE_BER_ERR_INVALID_ARG);
    ASSERT_EQ(ber_decode_length(buf, 4, NULL, &len), GOOSE_BER_ERR_INVALID_ARG);
    ASSERT_EQ(ber_decode_length(buf, 4, &offset, NULL), GOOSE_BER_ERR_INVALID_ARG);

    PASS();
}

static void test_ber_decode_buffer_underflow(void)
{
    TEST("ber_decode_buffer_underflow");
    uint8_t buf[1] = {0x80};
    size_t offset = 1;
    uint8_t tag;

    /* offset at end */
    ASSERT_EQ(ber_decode_tag(buf, 1, &offset, &tag), GOOSE_BER_ERR_BUFFER_FULL);

    /* Empty buffer for length */
    offset = 0;
    size_t len;
    ASSERT_EQ(ber_decode_length(buf, 0, &offset, &len), GOOSE_BER_ERR_BUFFER_FULL);

    PASS();
}

/* ========================================================================
 * GOOSE APDU Error Paths
 * ======================================================================== */

static void test_goose_apdu_null_args(void)
{
    TEST("goose_apdu_null_args");
    uint8_t buf[64];
    size_t enc;
    goose_apdu_t apdu;
    goose_apdu_init(&apdu);

    /* encode NULL args */
    ASSERT_TRUE(goose_encode_apdu(NULL, 64, &apdu, &enc) != GOOSE_BER_OK);
    ASSERT_TRUE(goose_encode_apdu(buf, 64, NULL, &enc) != GOOSE_BER_OK);
    ASSERT_TRUE(goose_encode_apdu(buf, 64, &apdu, NULL) != GOOSE_BER_OK);

    /* decode NULL args */
    ASSERT_TRUE(goose_decode_apdu(NULL, 0, &apdu) != 0);
    ASSERT_TRUE(goose_decode_apdu(buf, 64, NULL) != 0);

    /* set_gocbref NULL */
    ASSERT_TRUE(goose_set_gocbref(NULL, "test") != GOOSE_BER_OK);
    ASSERT_TRUE(goose_set_gocbref(&apdu, NULL) != GOOSE_BER_OK);

    /* add NULL */
    ASSERT_TRUE(goose_add_boolean(NULL, true) != GOOSE_BER_OK);

    PASS();
}

static void test_goose_decode_malformed(void)
{
    TEST("goose_decode_malformed");
    goose_apdu_t decoded;

    /* Random garbage */
    uint8_t garbage[] = {0xFF, 0xFF, 0xFF, 0xFF};
    goose_apdu_init(&decoded);
    ASSERT_TRUE(goose_decode_apdu(garbage, sizeof(garbage), &decoded) != 0);

    /* Truncated APDU */
    uint8_t truncated[] = {GOOSE_APDU_TAG, 0x82, 0x10};
    goose_apdu_init(&decoded);
    ASSERT_TRUE(goose_decode_apdu(truncated, sizeof(truncated), &decoded) != 0);

    /* Zero length */
    goose_apdu_init(&decoded);
    ASSERT_TRUE(goose_decode_apdu(garbage, 0, &decoded) != 0);

    PASS();
}

/* ========================================================================
 * Eth Frame Error Paths
 * ======================================================================== */

static void test_eth_frame_null_args(void)
{
    TEST("eth_frame_null_args");
    uint8_t frame[256];
    size_t frame_len;
    iec61850_eth_frame_config_t cfg;
    uint8_t apdu[] = {0x01, 0x02};

    memset(&cfg, 0, sizeof(cfg));
    cfg.ethertype = IEC61850_ETHERTYPE_GOOSE;

    /* Build: NULL args */
    ASSERT_TRUE(iec61850_eth_frame_build(NULL, 256, &cfg, apdu, 2, &frame_len) != 0);
    ASSERT_TRUE(iec61850_eth_frame_build(frame, 256, NULL, apdu, 2, &frame_len) != 0);
    ASSERT_TRUE(iec61850_eth_frame_build(frame, 256, &cfg, NULL, 2, &frame_len) != 0);
    ASSERT_TRUE(iec61850_eth_frame_build(frame, 256, &cfg, apdu, 2, NULL) != 0);

    /* Build: buffer too small */
    ASSERT_TRUE(iec61850_eth_frame_build(frame, 10, &cfg, apdu, 2, &frame_len) != 0);

    /* Parse: NULL args */
    uint16_t et, ai, vi;
    const uint8_t *apdu_out;
    size_t apdu_len;
    ASSERT_TRUE(iec61850_eth_frame_parse(NULL, 100, &et, &ai, &vi, &apdu_out, &apdu_len, NULL) != 0);

    /* Parse: too short */
    uint8_t short_frame[5] = {0};
    ASSERT_TRUE(iec61850_eth_frame_parse(short_frame, 5, &et, &ai, &vi,
                &apdu_out, &apdu_len, NULL) != 0);

    PASS();
}

/* ========================================================================
 * Publisher State Number Edge Cases
 * ======================================================================== */

static void test_publisher_state_null(void)
{
    TEST("publisher_state_null");
    ASSERT_EQ(iec61850_goose_publisher_get_st_num(NULL), (uint32_t)0);
    ASSERT_EQ(iec61850_goose_publisher_get_sq_num(NULL), (uint32_t)0);
    ASSERT_EQ(iec61850_sv_publisher_get_smp_cnt(NULL), (uint16_t)0);
    PASS();
}

int main(void)
{
    printf("\n=== Error Path Tests ===\n");

    printf("\n--- GOOSE Publisher ---\n");
    test_publisher_null_inputs();
    test_publisher_index_overflow();
    test_publisher_byte_too_long();

    printf("\n--- GOOSE Subscriber ---\n");
    test_subscriber_null_inputs();

    printf("\n--- SV Publisher ---\n");
    test_sv_publisher_null_inputs();

    printf("\n--- SV Subscriber ---\n");
    test_sv_subscriber_null_inputs();

    printf("\n--- BER Encode ---\n");
    test_ber_encode_null_args();
    test_ber_encode_buffer_full();

    printf("\n--- BER Decode ---\n");
    test_ber_decode_null_args();
    test_ber_decode_buffer_underflow();

    printf("\n--- GOOSE APDU ---\n");
    test_goose_apdu_null_args();
    test_goose_decode_malformed();

    printf("\n--- Eth Frame ---\n");
    test_eth_frame_null_args();

    printf("\n--- State Numbers ---\n");
    test_publisher_state_null();

    printf("\n=== Test Summary ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
