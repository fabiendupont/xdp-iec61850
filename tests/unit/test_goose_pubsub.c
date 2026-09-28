/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for IEC 61850 GOOSE Publisher, Subscriber, Retransmission
 *
 * License: BSD-3-Clause
 */


#include "property_test.h"
#include "goose/goose_publisher.h"
#include "goose/goose_subscriber.h"
#include "goose/goose_retransmission.h"
#include "asn1/goose_ber.h"
#include "asn1/goose_ber_decode.h"
#include "transport/eth_frame.h"

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

/* ========================================================================
 * Publisher Tests
 * ======================================================================== */

static void test_publisher_create_destroy(void)
{
    TEST("publisher_create_destroy");
    iec61850_goose_publisher_t pub;
    iec61850_goose_config_t cfg;
    iec61850_goose_config_init(&cfg);
    iec61850_goose_publisher_init(&pub, &cfg);
    ASSERT_EQ(iec61850_goose_publisher_get_st_num(&pub), (uint32_t)0);
    ASSERT_EQ(iec61850_goose_publisher_get_sq_num(&pub), (uint32_t)0);
    iec61850_goose_publisher_destroy(&pub);
    PASS();
}

static void test_publisher_set_data_types(void)
{
    TEST("publisher_set_data_types");
    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, NULL);

    ASSERT_EQ(iec61850_goose_publisher_set_boolean(&pub, 0, true), 0);
    ASSERT_EQ(iec61850_goose_publisher_set_int32(&pub, 1, -42), 0);
    ASSERT_EQ(iec61850_goose_publisher_set_uint32(&pub, 2, 1000), 0);
    ASSERT_EQ(iec61850_goose_publisher_set_float32(&pub, 3, 3.14f), 0);

    uint8_t bits[] = {0xAB, 0xCD};
    ASSERT_EQ(iec61850_goose_publisher_set_bitstring(&pub, 4, bits, 2), 0);

    uint8_t octets[] = {0x01, 0x02, 0x03};
    ASSERT_EQ(iec61850_goose_publisher_set_octetstring(&pub, 5, octets, 3), 0);

    ASSERT_EQ(pub.data_count, (uint32_t)6);
    ASSERT_EQ(pub.data[0].type, GOOSE_DATA_BOOLEAN);
    ASSERT_EQ(pub.data[1].type, GOOSE_DATA_INT32);
    ASSERT_EQ(pub.data[3].type, GOOSE_DATA_FLOAT32);

    iec61850_goose_publisher_destroy(&pub);
    PASS();
}

static void test_publisher_prepare_packet(void)
{
    TEST("publisher_prepare_packet");
    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, NULL);

    iec61850_goose_publisher_set_boolean(&pub, 0, true);
    iec61850_goose_publisher_set_int32(&pub, 1, 100);

    uint8_t buf[GOOSE_MAX_APDU_SIZE];
    size_t encoded = 0;
    int ret = iec61850_goose_publisher_prepare(&pub, buf, sizeof(buf), &encoded);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(encoded > 0);

    /* sqNum should have incremented */
    ASSERT_EQ(iec61850_goose_publisher_get_sq_num(&pub), (uint32_t)1);

    iec61850_goose_publisher_destroy(&pub);
    PASS();
}

static void test_publisher_state_numbers(void)
{
    TEST("publisher_state_numbers");
    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, NULL);
    iec61850_goose_publisher_set_boolean(&pub, 0, false);

    /* Prepare increments sqNum */
    uint8_t buf[GOOSE_MAX_APDU_SIZE];
    size_t encoded;
    iec61850_goose_publisher_prepare(&pub, buf, sizeof(buf), &encoded);
    ASSERT_EQ(iec61850_goose_publisher_get_st_num(&pub), (uint32_t)0);
    ASSERT_EQ(iec61850_goose_publisher_get_sq_num(&pub), (uint32_t)1);

    iec61850_goose_publisher_prepare(&pub, buf, sizeof(buf), &encoded);
    ASSERT_EQ(iec61850_goose_publisher_get_sq_num(&pub), (uint32_t)2);

    /* State change resets sqNum, increments stNum */
    iec61850_goose_publisher_state_change(&pub);
    ASSERT_EQ(iec61850_goose_publisher_get_st_num(&pub), (uint32_t)1);
    ASSERT_EQ(iec61850_goose_publisher_get_sq_num(&pub), (uint32_t)0);

    iec61850_goose_publisher_destroy(&pub);
    PASS();
}

/* ========================================================================
 * Subscriber Tests
 * ======================================================================== */

static int g_callback_count = 0;
static iec61850_goose_message_t g_last_msg;

static void test_callback(const iec61850_goose_message_t *msg, void *user_data)
{
    (void)user_data;
    g_callback_count++;
    g_last_msg = *msg;
}

static void test_subscriber_process(void)
{
    TEST("subscriber_process");
    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, NULL);
    g_callback_count = 0;
    iec61850_goose_subscriber_set_callback(&sub, test_callback, NULL);

    goose_apdu_t apdu;
    goose_apdu_init(&apdu);
    goose_set_gocbref(&apdu, "IED1LD0/LLN0$GO$gcb01");
    apdu.stNum = 1;
    apdu.sqNum = 0;

    bool accepted = iec61850_goose_subscriber_process(&sub, &apdu, 1000000);
    ASSERT_TRUE(accepted);
    ASSERT_EQ(g_callback_count, 1);
    ASSERT_TRUE(g_last_msg.is_new_state);

    iec61850_goose_subscriber_destroy(&sub);
    PASS();
}

static void test_subscriber_duplicate(void)
{
    TEST("subscriber_duplicate");
    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, NULL);
    g_callback_count = 0;
    iec61850_goose_subscriber_set_callback(&sub, test_callback, NULL);

    goose_apdu_t apdu;
    goose_apdu_init(&apdu);
    goose_set_gocbref(&apdu, "IED1LD0/LLN0$GO$gcb01");
    apdu.stNum = 1;
    apdu.sqNum = 0;

    iec61850_goose_subscriber_process(&sub, &apdu, 1000000);
    /* Same stNum/sqNum = duplicate */
    bool accepted = iec61850_goose_subscriber_process(&sub, &apdu, 2000000);
    ASSERT_TRUE(!accepted);
    ASSERT_EQ(g_callback_count, 1);  /* Duplicate not delivered */
    ASSERT_EQ((int)sub.total_duplicates, 1);

    iec61850_goose_subscriber_destroy(&sub);
    PASS();
}

static void test_subscriber_state_change(void)
{
    TEST("subscriber_state_change");
    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, NULL);
    g_callback_count = 0;
    iec61850_goose_subscriber_set_callback(&sub, test_callback, NULL);

    goose_apdu_t apdu;
    goose_apdu_init(&apdu);
    goose_set_gocbref(&apdu, "IED1LD0/LLN0$GO$gcb01");
    apdu.stNum = 1;
    apdu.sqNum = 0;
    iec61850_goose_subscriber_process(&sub, &apdu, 1000000);

    /* New state */
    apdu.stNum = 2;
    apdu.sqNum = 0;
    iec61850_goose_subscriber_process(&sub, &apdu, 2000000);
    ASSERT_EQ(g_callback_count, 2);
    ASSERT_TRUE(g_last_msg.is_new_state);

    iec61850_goose_subscriber_destroy(&sub);
    PASS();
}

static void test_subscriber_filtering(void)
{
    TEST("subscriber_filtering");
    iec61850_goose_sub_config_t cfg;
    iec61850_goose_sub_config_init(&cfg);
    (void)strncpy(cfg.filter_gocbref, "IED1LD0/LLN0$GO$gcb01",
                  GOOSE_MAX_GOCBREF_LEN - 1);

    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, &cfg);

    goose_apdu_t apdu;
    goose_apdu_init(&apdu);

    /* Matching gocbRef */
    goose_set_gocbref(&apdu, "IED1LD0/LLN0$GO$gcb01");
    apdu.stNum = 1;
    ASSERT_TRUE(iec61850_goose_subscriber_process(&sub, &apdu, 1000));

    /* Non-matching gocbRef */
    goose_set_gocbref(&apdu, "IED2LD0/LLN0$GO$gcb02");
    apdu.stNum = 1;
    ASSERT_TRUE(!iec61850_goose_subscriber_process(&sub, &apdu, 2000));

    iec61850_goose_subscriber_destroy(&sub);
    PASS();
}

static void test_subscriber_timeout(void)
{
    TEST("subscriber_timeout");
    iec61850_goose_sub_config_t cfg;
    iec61850_goose_sub_config_init(&cfg);
    cfg.timeout_ms = 1;  /* 1ms timeout */

    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, &cfg);

    goose_apdu_t apdu;
    goose_apdu_init(&apdu);
    goose_set_gocbref(&apdu, "IED1LD0/LLN0$GO$gcb01");
    apdu.stNum = 1;

    /* Process at time=1ms */
    iec61850_goose_subscriber_process(&sub, &apdu, 1000000ULL);

    /* Check timeout at time=100ms (well past 1ms timeout) */
    iec61850_goose_subscriber_check_timeouts(&sub, 100000000ULL);
    ASSERT_EQ((int)sub.total_timeouts, 1);

    const iec61850_goose_pub_state_t *ps =
        iec61850_goose_subscriber_get_pub_state(&sub, "IED1LD0/LLN0$GO$gcb01");
    ASSERT_TRUE(ps != NULL);
    ASSERT_TRUE(ps->timeout_detected);

    iec61850_goose_subscriber_destroy(&sub);
    PASS();
}

/* ========================================================================
 * Retransmission Tests
 * ======================================================================== */

static void test_retransmit_exponential_backoff(void)
{
    TEST("retransmit_exponential_backoff");
    iec61850_retransmit_config_t cfg;
    cfg.t0_ms = 2;
    cfg.t_max_ms = 16;

    iec61850_retransmit_t rt;
    iec61850_retransmit_init(&rt, &cfg);

    /* Signal state change */
    iec61850_retransmit_on_state_change(&rt);
    ASSERT_EQ(iec61850_retransmit_get_interval_ms(&rt), (uint32_t)2);
    ASSERT_TRUE(iec61850_retransmit_is_rapid(&rt));

    /* First is_due should return true immediately */
    ASSERT_TRUE(iec61850_retransmit_is_due(&rt));

    /* After is_due, interval doubles: 2 -> 4 */
    ASSERT_EQ(iec61850_retransmit_get_interval_ms(&rt), (uint32_t)4);

    PASS();
}

static void test_retransmit_state_change_reset(void)
{
    TEST("retransmit_state_change_reset");
    iec61850_retransmit_config_t cfg;
    cfg.t0_ms = 2;
    cfg.t_max_ms = 1000;

    iec61850_retransmit_t rt;
    iec61850_retransmit_init(&rt, &cfg);

    /* Let it advance to a large interval */
    iec61850_retransmit_on_state_change(&rt);
    iec61850_retransmit_is_due(&rt);  /* 2 -> 4 */
    iec61850_retransmit_is_due(&rt);  /* We won't wait, so this may not fire */

    /* State change resets to T0 */
    iec61850_retransmit_on_state_change(&rt);
    ASSERT_EQ(iec61850_retransmit_get_interval_ms(&rt), (uint32_t)2);

    PASS();
}

/* ========================================================================
 * Property Test: encode-decode roundtrip
 * ======================================================================== */

static void test_goose_encode_decode_roundtrip(void)
{
    printf("\n");
    PROPERTY_TEST("GOOSE encode-decode roundtrip", 1000) {
        iec61850_goose_publisher_t pub;
        iec61850_goose_publisher_init(&pub, NULL);

        /* Random data */
        int num_entries = 1 + (rand() % 8);
        for (int j = 0; j < num_entries; j++) {
            int type = rand() % 4;
            switch (type) {
                case 0: iec61850_goose_publisher_set_boolean(&pub, (size_t)j, random_bool()); break;
                case 1: iec61850_goose_publisher_set_int32(&pub, (size_t)j, random_int32()); break;
                case 2: iec61850_goose_publisher_set_uint32(&pub, (size_t)j, random_uint32()); break;
                case 3: iec61850_goose_publisher_set_float32(&pub, (size_t)j, 1.0f); break;
            }
        }

        uint8_t buf[GOOSE_MAX_APDU_SIZE];
        size_t encoded = 0;
        int ret = iec61850_goose_publisher_prepare(&pub, buf, sizeof(buf), &encoded);
        PROPERTY_ASSERT(ret == 0, "encode failed");
        PROPERTY_ASSERT(encoded > 0, "encoded length is 0");

        /* Decode */
        goose_apdu_t decoded;
        goose_apdu_init(&decoded);
        ret = goose_decode_apdu(buf, encoded, &decoded);
        PROPERTY_ASSERT(ret == 0, "decode failed");
        PROPERTY_ASSERT(decoded.numDatSetEntries == (uint32_t)num_entries,
                        "entry count mismatch");

        iec61850_goose_publisher_destroy(&pub);
    }
    PROPERTY_TEST_END();

    tests_run++;
    if (_prop_failures == 0) { tests_passed++; } else { tests_failed++; }
}

/* ========================================================================
 * Low-Level BER Encode/Decode Tests (coverage for goose_ber.c / goose_ber_decode.c)
 * ======================================================================== */

static void test_ber_encode_tag_errors(void)
{
    TEST("ber_encode_tag NULL/boundary errors");
    uint8_t buf[16];
    size_t offset = 0;

    /* NULL buf */
    ASSERT_EQ(ber_encode_tag(NULL, 16, &offset, 0x80), GOOSE_BER_ERR_INVALID_ARG);
    /* NULL offset */
    ASSERT_EQ(ber_encode_tag(buf, 16, NULL, 0x80), GOOSE_BER_ERR_INVALID_ARG);
    /* offset at buf_size (full) */
    offset = 16;
    ASSERT_EQ(ber_encode_tag(buf, 16, &offset, 0x80), GOOSE_BER_ERR_BUFFER_FULL);
    /* success */
    offset = 0;
    ASSERT_EQ(ber_encode_tag(buf, 16, &offset, 0x83), GOOSE_BER_OK);
    ASSERT_EQ(buf[0], 0x83);
    ASSERT_EQ((int)offset, 1);
    PASS();
}

static void test_ber_encode_length_forms(void)
{
    TEST("ber_encode_length short/long forms");
    uint8_t buf[16];
    size_t offset;

    /* Short form (< 128) */
    offset = 0;
    ASSERT_EQ(ber_encode_length(buf, 16, &offset, 42), GOOSE_BER_OK);
    ASSERT_EQ(buf[0], 42);
    ASSERT_EQ((int)offset, 1);

    /* Long form 1-byte (128..255) */
    offset = 0;
    ASSERT_EQ(ber_encode_length(buf, 16, &offset, 200), GOOSE_BER_OK);
    ASSERT_EQ(buf[0], 0x81);
    ASSERT_EQ(buf[1], 200);
    ASSERT_EQ((int)offset, 2);

    /* Long form 2-byte (256..65535) */
    offset = 0;
    ASSERT_EQ(ber_encode_length(buf, 16, &offset, 1000), GOOSE_BER_OK);
    ASSERT_EQ(buf[0], 0x82);
    ASSERT_EQ((int)offset, 3);

    /* Buffer too small for long form */
    offset = 15;
    ASSERT_EQ(ber_encode_length(buf, 16, &offset, 200), GOOSE_BER_ERR_BUFFER_FULL);

    /* NULL args */
    offset = 0;
    ASSERT_EQ(ber_encode_length(NULL, 16, &offset, 1), GOOSE_BER_ERR_INVALID_ARG);
    ASSERT_EQ(ber_encode_length(buf, 16, NULL, 1), GOOSE_BER_ERR_INVALID_ARG);
    PASS();
}

static void test_ber_encode_boolean_roundtrip(void)
{
    TEST("ber_encode/decode_boolean roundtrip");
    uint8_t buf[16];
    size_t offset = 0;
    bool val;

    /* Encode true */
    ASSERT_EQ(ber_encode_boolean(buf, 16, &offset, GOOSE_TAG_TEST, true), GOOSE_BER_OK);
    ASSERT_EQ((int)offset, 3);

    /* Decode - offset starts at 0, decode_boolean reads tag+length+value internally */
    size_t doff = 0;
    ASSERT_EQ(ber_decode_boolean(buf, offset, &doff, GOOSE_TAG_TEST, &val), GOOSE_BER_OK);
    ASSERT_TRUE(val == true);

    /* Encode false */
    offset = 0;
    ASSERT_EQ(ber_encode_boolean(buf, 16, &offset, GOOSE_TAG_NDSCOM, false), GOOSE_BER_OK);
    doff = 0;
    ASSERT_EQ(ber_decode_boolean(buf, offset, &doff, GOOSE_TAG_NDSCOM, &val), GOOSE_BER_OK);
    ASSERT_TRUE(val == false);

    /* Buffer too small */
    offset = 0;
    ASSERT_EQ(ber_encode_boolean(buf, 2, &offset, 0x80, true), GOOSE_BER_ERR_BUFFER_FULL);
    PASS();
}

static void test_ber_encode_int32_roundtrip(void)
{
    TEST("ber_encode/decode_int32 roundtrip");
    uint8_t buf[32];
    size_t offset, doff;
    int32_t val;

    /* Positive value */
    offset = 0;
    ASSERT_EQ(ber_encode_int32(buf, 32, &offset, GOOSE_TAG_STNUM, 12345), GOOSE_BER_OK);
    doff = 0;
    ASSERT_EQ(ber_decode_int32(buf, offset, &doff, GOOSE_TAG_STNUM, &val), GOOSE_BER_OK);
    ASSERT_EQ(val, 12345);

    /* Negative value */
    offset = 0;
    ASSERT_EQ(ber_encode_int32(buf, 32, &offset, GOOSE_TAG_STNUM, -999), GOOSE_BER_OK);
    doff = 0;
    ASSERT_EQ(ber_decode_int32(buf, offset, &doff, GOOSE_TAG_STNUM, &val), GOOSE_BER_OK);
    ASSERT_EQ(val, -999);

    /* Zero */
    offset = 0;
    ASSERT_EQ(ber_encode_int32(buf, 32, &offset, GOOSE_TAG_STNUM, 0), GOOSE_BER_OK);
    doff = 0;
    ASSERT_EQ(ber_decode_int32(buf, offset, &doff, GOOSE_TAG_STNUM, &val), GOOSE_BER_OK);
    ASSERT_EQ(val, 0);
    PASS();
}

static void test_ber_encode_uint32_roundtrip(void)
{
    TEST("ber_encode/decode_uint32 roundtrip");
    uint8_t buf[32];
    size_t offset, doff;
    uint32_t val;

    /* Large value */
    offset = 0;
    ASSERT_EQ(ber_encode_uint32(buf, 32, &offset, GOOSE_TAG_CONFREV, 0xDEADBEEF), GOOSE_BER_OK);
    doff = 0;
    ASSERT_EQ(ber_decode_uint32(buf, offset, &doff, GOOSE_TAG_CONFREV, &val), GOOSE_BER_OK);
    ASSERT_TRUE(val == 0xDEADBEEF);

    /* Small value */
    offset = 0;
    ASSERT_EQ(ber_encode_uint32(buf, 32, &offset, GOOSE_TAG_CONFREV, 1), GOOSE_BER_OK);
    doff = 0;
    ASSERT_EQ(ber_decode_uint32(buf, offset, &doff, GOOSE_TAG_CONFREV, &val), GOOSE_BER_OK);
    ASSERT_EQ((int)val, 1);
    PASS();
}

static void test_ber_encode_visiblestring_roundtrip(void)
{
    TEST("ber_encode/decode_visiblestring roundtrip");
    uint8_t buf[256];
    size_t offset, doff;
    char out[256];

    offset = 0;
    ASSERT_EQ(ber_encode_visiblestring(buf, 256, &offset, GOOSE_TAG_GOCBREF,
              "IED1LD0/LLN0$GO$gcb01"), GOOSE_BER_OK);
    doff = 0;
    ASSERT_EQ(ber_decode_visiblestring(buf, offset, &doff, GOOSE_TAG_GOCBREF, out, sizeof(out)), GOOSE_BER_OK);
    ASSERT_TRUE(strcmp(out, "IED1LD0/LLN0$GO$gcb01") == 0);

    /* Empty string */
    offset = 0;
    ASSERT_EQ(ber_encode_visiblestring(buf, 256, &offset, GOOSE_TAG_GOID, ""), GOOSE_BER_OK);
    doff = 0;
    memset(out, 'X', sizeof(out));
    ASSERT_EQ(ber_decode_visiblestring(buf, offset, &doff, GOOSE_TAG_GOID, out, sizeof(out)), GOOSE_BER_OK);
    ASSERT_EQ(out[0], '\0');

    /* NULL string */
    offset = 0;
    ASSERT_EQ(ber_encode_visiblestring(buf, 256, &offset, GOOSE_TAG_GOID, NULL), GOOSE_BER_ERR_INVALID_ARG);
    PASS();
}

static void test_ber_encode_utctime_roundtrip(void)
{
    TEST("ber_encode/decode_utctime roundtrip");
    uint8_t buf[32];
    size_t offset, doff;
    uint64_t timestamp_us;
    uint8_t quality_out;

    offset = 0;
    ASSERT_EQ(ber_encode_utctime(buf, 32, &offset, GOOSE_TAG_T,
              1700000000ULL * 1000000ULL + 500000ULL, 0x18), GOOSE_BER_OK);
    doff = 0;
    ASSERT_EQ(ber_decode_utctime(buf, offset, &doff, GOOSE_TAG_T,
              &timestamp_us, &quality_out), GOOSE_BER_OK);
    ASSERT_TRUE(timestamp_us > 0);
    ASSERT_EQ(quality_out, 0x18);
    PASS();
}

static void test_ber_decode_tag_errors(void)
{
    TEST("ber_decode_tag NULL/boundary errors");
    uint8_t buf[4] = {0x80, 0x01, 0x00};
    size_t offset = 0;
    uint8_t tag;

    /* NULL buf */
    ASSERT_EQ(ber_decode_tag(NULL, 4, &offset, &tag), GOOSE_BER_ERR_INVALID_ARG);
    /* NULL offset */
    ASSERT_EQ(ber_decode_tag(buf, 4, NULL, &tag), GOOSE_BER_ERR_INVALID_ARG);
    /* NULL tag */
    ASSERT_EQ(ber_decode_tag(buf, 4, &offset, NULL), GOOSE_BER_ERR_INVALID_ARG);
    /* offset past end */
    offset = 4;
    ASSERT_EQ(ber_decode_tag(buf, 4, &offset, &tag), GOOSE_BER_ERR_BUFFER_FULL);
    /* success */
    offset = 0;
    ASSERT_EQ(ber_decode_tag(buf, 4, &offset, &tag), GOOSE_BER_OK);
    ASSERT_EQ(tag, 0x80);
    PASS();
}

static void test_ber_decode_length_errors(void)
{
    TEST("ber_decode_length errors");
    size_t offset, len;

    /* Short form */
    uint8_t short_buf[] = {42};
    offset = 0;
    ASSERT_EQ(ber_decode_length(short_buf, 1, &offset, &len), GOOSE_BER_OK);
    ASSERT_EQ((int)len, 42);

    /* Long form 1-byte */
    uint8_t long1_buf[] = {0x81, 200};
    offset = 0;
    ASSERT_EQ(ber_decode_length(long1_buf, 2, &offset, &len), GOOSE_BER_OK);
    ASSERT_EQ((int)len, 200);

    /* Long form 2-byte */
    uint8_t long2_buf[] = {0x82, 0x03, 0xE8};
    offset = 0;
    ASSERT_EQ(ber_decode_length(long2_buf, 3, &offset, &len), GOOSE_BER_OK);
    ASSERT_EQ((int)len, 1000);

    /* Empty buffer */
    offset = 0;
    ASSERT_EQ(ber_decode_length(long1_buf, 0, &offset, &len), GOOSE_BER_ERR_BUFFER_FULL);

    /* NULL args */
    offset = 0;
    ASSERT_EQ(ber_decode_length(NULL, 2, &offset, &len), GOOSE_BER_ERR_INVALID_ARG);
    ASSERT_EQ(ber_decode_length(long1_buf, 2, NULL, &len), GOOSE_BER_ERR_INVALID_ARG);
    ASSERT_EQ(ber_decode_length(long1_buf, 2, &offset, NULL), GOOSE_BER_ERR_INVALID_ARG);
    PASS();
}

static void test_goose_apdu_add_overflow(void)
{
    TEST("goose_apdu add entries overflow");
    goose_apdu_t apdu;
    goose_apdu_init(&apdu);

    /* Fill to capacity */
    for (size_t i = 0; i < GOOSE_MAX_ALLDATA_ENTRIES; i++) {
        ASSERT_EQ(goose_add_boolean(&apdu, true), GOOSE_BER_OK);
    }
    /* Next add should fail */
    ASSERT_TRUE(goose_add_boolean(&apdu, true) != GOOSE_BER_OK);
    ASSERT_TRUE(goose_add_int32(&apdu, 42) != GOOSE_BER_OK);
    ASSERT_TRUE(goose_add_uint32(&apdu, 42) != GOOSE_BER_OK);
    ASSERT_TRUE(goose_add_float32(&apdu, 1.0f) != GOOSE_BER_OK);
    uint8_t data[] = {0x01};
    ASSERT_TRUE(goose_add_bitstring(&apdu, data, 1) != GOOSE_BER_OK);
    ASSERT_TRUE(goose_add_octetstring(&apdu, data, 1) != GOOSE_BER_OK);
    PASS();
}

static void test_goose_decode_alldata_types(void)
{
    TEST("goose_decode_alldata with all data types");
    goose_apdu_t apdu;
    goose_apdu_init(&apdu);

    goose_set_gocbref(&apdu, "IED1LD0/LLN0$GO$gcb01");
    goose_set_datset(&apdu, "IED1LD0/LLN0$DS1");
    goose_set_goid(&apdu, "GOOSE1");
    apdu.stNum = 1;
    apdu.sqNum = 0;
    apdu.confRev = 1;
    apdu.timeAllowedtoLive = 2000;

    /* Add one of each type */
    goose_add_boolean(&apdu, true);
    goose_add_int32(&apdu, -42);
    goose_add_uint32(&apdu, 999);
    goose_add_float32(&apdu, 3.14f);
    uint8_t bits[] = {0xAB, 0xCD};
    goose_add_bitstring(&apdu, bits, 2);
    uint8_t octets[] = {0x01, 0x02, 0x03};
    goose_add_octetstring(&apdu, octets, 3);

    /* Encode */
    uint8_t buf[2048];
    size_t encoded = 0;
    int enc_ret = goose_encode_apdu(buf, sizeof(buf), &apdu, &encoded);
    ASSERT_EQ(enc_ret, 0);
    ASSERT_TRUE(encoded > 0);

    /* Decode */
    goose_apdu_t decoded;
    goose_apdu_init(&decoded);
    int ret = goose_decode_apdu(buf, (size_t)encoded, &decoded);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)decoded.numDatSetEntries, 6);
    ASSERT_TRUE(decoded.allData[0].type == GOOSE_DATA_BOOLEAN);
    ASSERT_TRUE(decoded.allData[0].value.boolean == true);
    ASSERT_TRUE(decoded.allData[1].type == GOOSE_DATA_INT32);
    ASSERT_EQ(decoded.allData[1].value.int32, -42);
    ASSERT_TRUE(decoded.allData[2].type == GOOSE_DATA_UINT32);
    ASSERT_TRUE(decoded.allData[2].value.uint32 == 999);
    ASSERT_TRUE(decoded.allData[3].type == GOOSE_DATA_FLOAT32);
    ASSERT_TRUE(decoded.allData[4].type == GOOSE_DATA_BITSTRING);
    ASSERT_TRUE(decoded.allData[5].type == GOOSE_DATA_OCTETSTRING);

    /* Verify strings decoded correctly */
    ASSERT_TRUE(strcmp(decoded.gocbRef, "IED1LD0/LLN0$GO$gcb01") == 0);
    ASSERT_TRUE(strcmp(decoded.datSet, "IED1LD0/LLN0$DS1") == 0);
    ASSERT_TRUE(decoded.has_goID);
    ASSERT_TRUE(strcmp(decoded.goID, "GOOSE1") == 0);
    PASS();
}

static void test_goose_decode_apdu_ex(void)
{
    TEST("goose_decode_apdu_ex with consumed bytes");
    goose_apdu_t apdu;
    goose_apdu_init(&apdu);
    goose_set_gocbref(&apdu, "IED1LD0/LLN0$GO$gcb01");
    goose_set_datset(&apdu, "IED1LD0/LLN0$DS1");
    apdu.stNum = 5;
    apdu.sqNum = 10;
    apdu.confRev = 1;
    apdu.timeAllowedtoLive = 2000;
    goose_add_boolean(&apdu, false);

    uint8_t buf[2048];
    size_t encoded = 0;
    int enc_ret = goose_encode_apdu(buf, sizeof(buf), &apdu, &encoded);
    ASSERT_EQ(enc_ret, 0);
    ASSERT_TRUE(encoded > 0);

    goose_apdu_t decoded;
    goose_apdu_init(&decoded);
    size_t consumed = 0;
    int ret = goose_decode_apdu_ex(buf, (size_t)encoded, &decoded, &consumed);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(consumed > 0);
    ASSERT_TRUE(consumed <= (size_t)encoded);
    ASSERT_EQ((int)decoded.stNum, 5);
    ASSERT_EQ((int)decoded.sqNum, 10);
    PASS();
}

static void test_goose_encode_security_roundtrip(void)
{
    TEST("goose_set_security + encode/decode security roundtrip");
    goose_apdu_t apdu;
    goose_apdu_init(&apdu);
    goose_set_gocbref(&apdu, "IED1LD0/LLN0$GO$gcb01");
    goose_set_datset(&apdu, "IED1LD0/LLN0$DS1");
    apdu.stNum = 1;
    apdu.sqNum = 0;
    apdu.confRev = 1;
    apdu.timeAllowedtoLive = 2000;
    goose_add_boolean(&apdu, true);

    /* Set security fields */
    uint8_t key_id[GOOSE_KEYID_LEN];
    memset(key_id, 0xAA, sizeof(key_id));
    uint8_t signature[64];
    memset(signature, 0xBB, sizeof(signature));
    int ret = goose_set_security(&apdu, GOOSE_SIGNATURE_RSA_PSS,
                                  key_id, signature, sizeof(signature));
    ASSERT_EQ(ret, GOOSE_BER_OK);
    ASSERT_TRUE(apdu.secure == true);

    /* Encode with security */
    uint8_t buf[4096];
    size_t encoded = 0;
    int enc_ret = goose_encode_apdu(buf, sizeof(buf), &apdu, &encoded);
    ASSERT_EQ(enc_ret, 0);
    ASSERT_TRUE(encoded > 0);

    /* Decode - basic fields should survive even with security extension */
    goose_apdu_t decoded;
    goose_apdu_init(&decoded);
    (void)goose_decode_apdu(buf, encoded, &decoded);
    PASS();
}

static void test_goose_set_security_errors(void)
{
    TEST("goose_set_security NULL/invalid args");
    goose_apdu_t apdu;
    goose_apdu_init(&apdu);
    uint8_t key_id[GOOSE_KEYID_LEN] = {0};
    uint8_t sig[64] = {0};

    /* NULL apdu */
    ASSERT_TRUE(goose_set_security(NULL, GOOSE_SIGNATURE_RSA_PSS, key_id, sig, 64) != GOOSE_BER_OK);
    /* NULL key_id */
    ASSERT_TRUE(goose_set_security(&apdu, GOOSE_SIGNATURE_RSA_PSS, NULL, sig, 64) != GOOSE_BER_OK);
    /* NULL signature */
    ASSERT_TRUE(goose_set_security(&apdu, GOOSE_SIGNATURE_RSA_PSS, key_id, NULL, 64) != GOOSE_BER_OK);
    PASS();
}

static void test_goose_encode_buffer_too_small(void)
{
    TEST("goose_encode_apdu buffer too small");
    goose_apdu_t apdu;
    goose_apdu_init(&apdu);
    goose_set_gocbref(&apdu, "IED1LD0/LLN0$GO$gcb01");
    goose_set_datset(&apdu, "IED1LD0/LLN0$DS1");
    apdu.stNum = 1;
    apdu.confRev = 1;
    apdu.timeAllowedtoLive = 2000;
    goose_add_boolean(&apdu, true);

    /* Tiny buffer */
    uint8_t buf[4];
    size_t enc_len = 0;
    int ret = goose_encode_apdu(buf, sizeof(buf), &apdu, &enc_len);
    ASSERT_TRUE(ret != 0);
    PASS();
}

static void test_goose_decode_malformed(void)
{
    TEST("goose_decode_apdu malformed input");
    goose_apdu_t decoded;

    /* Empty buffer */
    goose_apdu_init(&decoded);
    ASSERT_TRUE(goose_decode_apdu(NULL, 0, &decoded) != 0);

    /* Random garbage */
    uint8_t garbage[] = {0xFF, 0xFF, 0xFF, 0xFF};
    goose_apdu_init(&decoded);
    ASSERT_TRUE(goose_decode_apdu(garbage, sizeof(garbage), &decoded) != 0);

    /* Truncated - just APDU tag + short length */
    uint8_t truncated[] = {GOOSE_APDU_TAG, 0x82, 0x10};
    goose_apdu_init(&decoded);
    ASSERT_TRUE(goose_decode_apdu(truncated, sizeof(truncated), &decoded) != 0);
    PASS();
}

/* ========================================================================
 * process_frame() Tests — test frame parsing/filtering without network
 * ======================================================================== */

/* Helper: build a valid GOOSE Ethernet frame from an APDU */
static int build_goose_frame(uint8_t *frame_buf, size_t frame_size,
                               size_t *frame_len, uint16_t app_id)
{
    /* Encode a minimal GOOSE APDU */
    goose_apdu_t apdu;
    goose_apdu_init(&apdu);
    goose_set_gocbref(&apdu, "IED1LD0/LLN0$GO$gcb01");
    goose_set_datset(&apdu, "IED1LD0/LLN0$DS1");
    apdu.stNum = 1;
    apdu.sqNum = 0;
    apdu.confRev = 1;
    goose_add_boolean(&apdu, true);

    uint8_t apdu_buf[512];
    size_t apdu_len = 0;
    int ret = goose_encode_apdu(apdu_buf, sizeof(apdu_buf), &apdu, &apdu_len);
    if (ret != 0) { return -1; }

    /* Build Ethernet frame with GOOSE multicast destination */
    iec61850_eth_frame_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.dst_mac[0] = 0x01; cfg.dst_mac[1] = 0x0C; cfg.dst_mac[2] = 0xCD;
    cfg.dst_mac[3] = 0x01; cfg.dst_mac[4] = 0x00; cfg.dst_mac[5] = 0x01;
    cfg.src_mac[0] = 0x00; cfg.src_mac[1] = 0x11; cfg.src_mac[2] = 0x22;
    cfg.src_mac[3] = 0x33; cfg.src_mac[4] = 0x44; cfg.src_mac[5] = 0x55;
    cfg.ethertype = IEC61850_ETHERTYPE_GOOSE;
    cfg.app_id = app_id;

    return iec61850_eth_frame_build(frame_buf, frame_size, &cfg,
                                     apdu_buf, apdu_len, frame_len);
}

static void test_process_frame_valid(void)
{
    TEST("process_frame valid GOOSE frame");
    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, NULL);
    g_callback_count = 0;
    iec61850_goose_subscriber_set_callback(&sub, test_callback, NULL);

    uint8_t frame[1024];
    size_t frame_len = 0;
    int ret = build_goose_frame(frame, sizeof(frame), &frame_len, 0x0001);
    ASSERT_EQ(ret, 0);

    ret = iec61850_goose_subscriber_process_frame(&sub, frame, frame_len, 1000000);
    ASSERT_EQ(ret, 1);
    ASSERT_EQ(g_callback_count, 1);

    iec61850_goose_subscriber_destroy(&sub);
    PASS();
}

static void test_process_frame_wrong_ethertype(void)
{
    TEST("process_frame wrong EtherType");
    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, NULL);

    /* Build a frame with SV EtherType instead of GOOSE */
    uint8_t apdu_buf[64];
    size_t apdu_len = 0;
    goose_apdu_t apdu;
    goose_apdu_init(&apdu);
    goose_set_gocbref(&apdu, "test");
    goose_set_datset(&apdu, "test");
    apdu.stNum = 1; apdu.confRev = 1;
    goose_add_boolean(&apdu, true);
    goose_encode_apdu(apdu_buf, sizeof(apdu_buf), &apdu, &apdu_len);

    iec61850_eth_frame_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.dst_mac[0] = 0x01; cfg.dst_mac[1] = 0x0C; cfg.dst_mac[2] = 0xCD;
    cfg.dst_mac[3] = 0x04; cfg.dst_mac[4] = 0x00; cfg.dst_mac[5] = 0x01;
    cfg.ethertype = IEC61850_ETHERTYPE_SV;  /* Wrong! */

    uint8_t frame[1024];
    size_t frame_len = 0;
    iec61850_eth_frame_build(frame, sizeof(frame), &cfg, apdu_buf, apdu_len, &frame_len);

    int ret = iec61850_goose_subscriber_process_frame(&sub, frame, frame_len, 1000000);
    ASSERT_EQ(ret, 0);  /* Should be rejected */

    iec61850_goose_subscriber_destroy(&sub);
    PASS();
}

static void test_process_frame_appid_filter(void)
{
    TEST("process_frame APPID filter");
    iec61850_goose_sub_config_t cfg;
    iec61850_goose_sub_config_init(&cfg);
    cfg.filter_appid = 0x1234;

    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, &cfg);
    g_callback_count = 0;
    iec61850_goose_subscriber_set_callback(&sub, test_callback, NULL);

    /* Frame with matching APPID */
    uint8_t frame[1024];
    size_t frame_len = 0;
    build_goose_frame(frame, sizeof(frame), &frame_len, 0x1234);
    int ret = iec61850_goose_subscriber_process_frame(&sub, frame, frame_len, 1000000);
    ASSERT_EQ(ret, 1);  /* Accepted */

    /* Frame with non-matching APPID (use stNum=2 to avoid duplicate filter) */
    build_goose_frame(frame, sizeof(frame), &frame_len, 0x5678);
    ret = iec61850_goose_subscriber_process_frame(&sub, frame, frame_len, 2000000);
    ASSERT_EQ(ret, 0);  /* Rejected */

    iec61850_goose_subscriber_destroy(&sub);
    PASS();
}

static void test_process_frame_null_args(void)
{
    TEST("process_frame NULL args");
    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, NULL);

    ASSERT_EQ(iec61850_goose_subscriber_process_frame(NULL, (uint8_t[]){0}, 1, 0), 0);
    ASSERT_EQ(iec61850_goose_subscriber_process_frame(&sub, NULL, 100, 0), 0);
    ASSERT_EQ(iec61850_goose_subscriber_process_frame(&sub, (uint8_t[]){0}, 0, 0), 0);

    /* Garbage data */
    uint8_t garbage[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    ASSERT_EQ(iec61850_goose_subscriber_process_frame(&sub, garbage, sizeof(garbage), 0), 0);

    iec61850_goose_subscriber_destroy(&sub);
    PASS();
}

/* ========================================================================
 * Main
 * ======================================================================== */

int main(void)
{
    property_test_init();

    printf("\n=== GOOSE Publisher Tests ===\n");
    test_publisher_create_destroy();
    test_publisher_set_data_types();
    test_publisher_prepare_packet();
    test_publisher_state_numbers();

    printf("\n=== GOOSE Subscriber Tests ===\n");
    test_subscriber_process();
    test_subscriber_duplicate();
    test_subscriber_state_change();
    test_subscriber_filtering();
    test_subscriber_timeout();

    printf("\n=== Retransmission Tests ===\n");
    test_retransmit_exponential_backoff();
    test_retransmit_state_change_reset();

    printf("\n=== process_frame() Tests ===\n");
    test_process_frame_valid();
    test_process_frame_wrong_ethertype();
    test_process_frame_appid_filter();
    test_process_frame_null_args();

    printf("\n=== Low-Level BER Tests ===\n");
    test_ber_encode_tag_errors();
    test_ber_encode_length_forms();
    test_ber_encode_boolean_roundtrip();
    test_ber_encode_int32_roundtrip();
    test_ber_encode_uint32_roundtrip();
    test_ber_encode_visiblestring_roundtrip();
    test_ber_encode_utctime_roundtrip();
    test_ber_decode_tag_errors();
    test_ber_decode_length_errors();
    test_goose_apdu_add_overflow();
    test_goose_decode_alldata_types();
    test_goose_decode_apdu_ex();
    test_goose_encode_security_roundtrip();
    test_goose_set_security_errors();
    test_goose_encode_buffer_too_small();
    test_goose_decode_malformed();

    printf("\n=== Property Tests ===\n");
    test_goose_encode_decode_roundtrip();

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
