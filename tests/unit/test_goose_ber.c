/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit tests for BER encoder/decoder
 *
 * These tests verify the encode→decode roundtrip property:
 * For all valid inputs: decode(encode(x)) == x
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "asn1/goose_ber.h"
#include "asn1/goose_ber_decode.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

/* Test counter */
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, msg); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define TEST_PASS() do { \
    tests_passed++; \
    printf("."); \
    fflush(stdout); \
} while(0)

/***************************************************************************
 * Low-Level BER Encoding Tests
 ***************************************************************************/

/**
 * Test: BER short form length encoding (0-127 bytes)
 */
static void test_ber_length_encoding_short_form(void)
{
    uint8_t buf[16];
    size_t offset;
    size_t length;
    int ret;

    /* Test length = 0 */
    offset = 0;
    ret = ber_encode_length(buf, sizeof(buf), &offset, 0);
    TEST_ASSERT(ret == GOOSE_BER_OK, "encode length 0 failed");
    TEST_ASSERT(offset == 1, "short form should be 1 byte");
    TEST_ASSERT(buf[0] == 0x00, "length 0 encoding");

    /* Test length = 127 (max short form) */
    offset = 0;
    ret = ber_encode_length(buf, sizeof(buf), &offset, 127);
    TEST_ASSERT(ret == GOOSE_BER_OK, "encode length 127 failed");
    TEST_ASSERT(offset == 1, "short form should be 1 byte");
    TEST_ASSERT(buf[0] == 0x7F, "length 127 encoding");

    /* Decode and verify */
    offset = 0;
    ret = ber_decode_length(buf, sizeof(buf), &offset, &length);
    TEST_ASSERT(ret == GOOSE_BER_OK, "decode length 127 failed");
    TEST_ASSERT(length == 127, "decoded length mismatch");

    TEST_PASS();
}

/**
 * Test: BER long form length encoding (128-255 bytes, 1 length byte)
 */
static void test_ber_length_encoding_long_form_1byte(void)
{
    uint8_t buf[16];
    size_t offset;
    size_t length;
    int ret;

    /* Test length = 128 (min long form 1-byte) */
    offset = 0;
    ret = ber_encode_length(buf, sizeof(buf), &offset, 128);
    TEST_ASSERT(ret == GOOSE_BER_OK, "encode length 128 failed");
    TEST_ASSERT(offset == 2, "long form 1-byte should be 2 bytes total");
    TEST_ASSERT(buf[0] == 0x81, "long form 1-byte indicator");
    TEST_ASSERT(buf[1] == 0x80, "length 128 encoding");

    /* Decode and verify */
    offset = 0;
    ret = ber_decode_length(buf, sizeof(buf), &offset, &length);
    TEST_ASSERT(ret == GOOSE_BER_OK, "decode length 128 failed");
    TEST_ASSERT(length == 128, "decoded length mismatch");

    /* Test length = 255 (max long form 1-byte) */
    offset = 0;
    ret = ber_encode_length(buf, sizeof(buf), &offset, 255);
    TEST_ASSERT(ret == GOOSE_BER_OK, "encode length 255 failed");
    TEST_ASSERT(offset == 2, "long form 1-byte should be 2 bytes total");
    TEST_ASSERT(buf[0] == 0x81, "long form 1-byte indicator");
    TEST_ASSERT(buf[1] == 0xFF, "length 255 encoding");

    /* Decode and verify */
    offset = 0;
    ret = ber_decode_length(buf, sizeof(buf), &offset, &length);
    TEST_ASSERT(ret == GOOSE_BER_OK, "decode length 255 failed");
    TEST_ASSERT(length == 255, "decoded length mismatch");

    TEST_PASS();
}

/**
 * Test: BER long form length encoding (256-65535 bytes, 2 length bytes)
 * THIS WOULD HAVE CAUGHT BUG #2 (off-by-1 in encoder)
 */
static void test_ber_length_encoding_long_form_2byte(void)
{
    uint8_t buf[16];
    size_t offset;
    size_t length;
    int ret;

    /* Test length = 256 (min long form 2-byte) */
    offset = 0;
    ret = ber_encode_length(buf, sizeof(buf), &offset, 256);
    TEST_ASSERT(ret == GOOSE_BER_OK, "encode length 256 failed");
    TEST_ASSERT(offset == 3, "long form 2-byte should be 3 bytes total (0x82 + 2 bytes)");
    TEST_ASSERT(buf[0] == 0x82, "long form 2-byte indicator");
    TEST_ASSERT(buf[1] == 0x01, "length 256 high byte");
    TEST_ASSERT(buf[2] == 0x00, "length 256 low byte");

    /* Decode and verify */
    offset = 0;
    ret = ber_decode_length(buf, sizeof(buf), &offset, &length);
    TEST_ASSERT(ret == GOOSE_BER_OK, "decode length 256 failed");
    TEST_ASSERT(length == 256, "decoded length mismatch");

    /* Test length = 277 (the length from our actual GOOSE packets) */
    offset = 0;
    ret = ber_encode_length(buf, sizeof(buf), &offset, 277);
    TEST_ASSERT(ret == GOOSE_BER_OK, "encode length 277 failed");
    TEST_ASSERT(offset == 3, "long form 2-byte should be 3 bytes total");
    TEST_ASSERT(buf[0] == 0x82, "long form 2-byte indicator");
    TEST_ASSERT(buf[1] == 0x01, "length 277 high byte");
    TEST_ASSERT(buf[2] == 0x15, "length 277 low byte (0x0115 = 277)");

    /* Decode and verify */
    offset = 0;
    ret = ber_decode_length(buf, sizeof(buf), &offset, &length);
    TEST_ASSERT(ret == GOOSE_BER_OK, "decode length 277 failed");
    TEST_ASSERT(length == 277, "decoded length mismatch");

    TEST_PASS();
}

/**
 * Test: BER integer encoding/decoding roundtrip
 */
static void test_ber_int32_roundtrip(void)
{
    uint8_t buf[16];
    size_t offset;
    int32_t value_in, value_out;
    int ret;

    /* Test positive value */
    offset = 0;
    value_in = 12345;
    ret = ber_encode_int32(buf, sizeof(buf), &offset, ASN1_CLASS_CONTEXT | 0x05, value_in);
    TEST_ASSERT(ret == GOOSE_BER_OK, "encode int32 failed");

    offset = 0;
    ret = ber_decode_int32(buf, sizeof(buf), &offset, ASN1_CLASS_CONTEXT | 0x05, &value_out);
    TEST_ASSERT(ret == GOOSE_BER_OK, "decode int32 failed");
    TEST_ASSERT(value_out == value_in, "int32 roundtrip failed");

    /* Test negative value */
    offset = 0;
    value_in = -12345;
    ret = ber_encode_int32(buf, sizeof(buf), &offset, ASN1_CLASS_CONTEXT | 0x05, value_in);
    TEST_ASSERT(ret == GOOSE_BER_OK, "encode negative int32 failed");

    offset = 0;
    ret = ber_decode_int32(buf, sizeof(buf), &offset, ASN1_CLASS_CONTEXT | 0x05, &value_out);
    TEST_ASSERT(ret == GOOSE_BER_OK, "decode negative int32 failed");
    TEST_ASSERT(value_out == value_in, "negative int32 roundtrip failed");

    TEST_PASS();
}

/**
 * Test: BER unsigned integer encoding/decoding roundtrip
 */
static void test_ber_uint32_roundtrip(void)
{
    uint8_t buf[16];
    size_t offset;
    uint32_t value_in, value_out;
    int ret;

    /* Test various uint32 values */
    uint32_t test_values[] = {0, 1, 127, 128, 255, 256, 65535, 0x12345678};

    for (size_t i = 0; i < sizeof(test_values)/sizeof(test_values[0]); i++) {
        offset = 0;
        value_in = test_values[i];
        ret = ber_encode_uint32(buf, sizeof(buf), &offset, ASN1_CLASS_CONTEXT | 0x06, value_in);
        TEST_ASSERT(ret == GOOSE_BER_OK, "encode uint32 failed");

        offset = 0;
        ret = ber_decode_uint32(buf, sizeof(buf), &offset, ASN1_CLASS_CONTEXT | 0x06, &value_out);
        TEST_ASSERT(ret == GOOSE_BER_OK, "decode uint32 failed");
        TEST_ASSERT(value_out == value_in, "uint32 roundtrip failed");
    }

    TEST_PASS();
}

/**
 * Test: BER boolean encoding/decoding roundtrip
 */
static void test_ber_boolean_roundtrip(void)
{
    uint8_t buf[16];
    size_t offset;
    bool value_in, value_out;
    int ret;

    /* Test true */
    offset = 0;
    value_in = true;
    ret = ber_encode_boolean(buf, sizeof(buf), &offset, ASN1_CLASS_CONTEXT | 0x03, value_in);
    TEST_ASSERT(ret == GOOSE_BER_OK, "encode boolean true failed");

    offset = 0;
    ret = ber_decode_boolean(buf, sizeof(buf), &offset, ASN1_CLASS_CONTEXT | 0x03, &value_out);
    TEST_ASSERT(ret == GOOSE_BER_OK, "decode boolean true failed");
    TEST_ASSERT(value_out == value_in, "boolean true roundtrip failed");

    /* Test false */
    offset = 0;
    value_in = false;
    ret = ber_encode_boolean(buf, sizeof(buf), &offset, ASN1_CLASS_CONTEXT | 0x03, value_in);
    TEST_ASSERT(ret == GOOSE_BER_OK, "encode boolean false failed");

    offset = 0;
    ret = ber_decode_boolean(buf, sizeof(buf), &offset, ASN1_CLASS_CONTEXT | 0x03, &value_out);
    TEST_ASSERT(ret == GOOSE_BER_OK, "decode boolean false failed");
    TEST_ASSERT(value_out == value_in, "boolean false roundtrip failed");

    TEST_PASS();
}

/**
 * Test: BER VisibleString encoding/decoding roundtrip
 */
static void test_ber_visiblestring_roundtrip(void)
{
    uint8_t buf[256];
    size_t offset;
    char str_in[129];
    char str_out[129];
    int ret;

    /* Test short string */
    strcpy(str_in, "GOOSE_TEST_PUB");
    offset = 0;
    ret = ber_encode_visiblestring(buf, sizeof(buf), &offset, GOOSE_TAG_GOCBREF, str_in);
    TEST_ASSERT(ret == GOOSE_BER_OK, "encode visiblestring failed");

    offset = 0;
    ret = ber_decode_visiblestring(buf, sizeof(buf), &offset, GOOSE_TAG_GOCBREF,
                                    str_out, sizeof(str_out));
    TEST_ASSERT(ret == GOOSE_BER_OK, "decode visiblestring failed");
    TEST_ASSERT(strcmp(str_out, str_in) == 0, "visiblestring roundtrip failed");

    /* Test long string (> 127 chars to trigger long form length encoding) */
    memset(str_in, 'A', 128);
    str_in[128] = '\0';
    offset = 0;
    ret = ber_encode_visiblestring(buf, sizeof(buf), &offset, GOOSE_TAG_GOCBREF, str_in);
    TEST_ASSERT(ret == GOOSE_BER_OK, "encode long visiblestring failed");

    offset = 0;
    ret = ber_decode_visiblestring(buf, sizeof(buf), &offset, GOOSE_TAG_GOCBREF,
                                    str_out, sizeof(str_out));
    TEST_ASSERT(ret == GOOSE_BER_OK, "decode long visiblestring failed");
    TEST_ASSERT(strcmp(str_out, str_in) == 0, "long visiblestring roundtrip failed");

    TEST_PASS();
}

/***************************************************************************
 * GOOSE APDU Tests
 ***************************************************************************/

/**
 * Test: Minimal GOOSE APDU encode→decode roundtrip
 * THIS WOULD HAVE CAUGHT BOTH BUG #1 and BUG #2
 */
static void test_goose_apdu_minimal_roundtrip(void)
{
    uint8_t buf[512];
    size_t encoded_len;
    goose_apdu_t apdu_in, apdu_out;
    int ret;

    /* Initialize minimal APDU */
    goose_apdu_init(&apdu_in);
    ret = goose_set_gocbref(&apdu_in, "GOOSE_TEST_PUB");
    TEST_ASSERT(ret == GOOSE_BER_OK, "set gocbRef failed");

    ret = goose_set_datset(&apdu_in, "TestDataSet");
    TEST_ASSERT(ret == GOOSE_BER_OK, "set datSet failed");

    apdu_in.stNum = 1;
    apdu_in.sqNum = 0;
    apdu_in.timestamp = 1234567890ULL * 1000000ULL;  /* microseconds */
    apdu_in.timeAllowedtoLive = 5000;
    apdu_in.confRev = 1;
    apdu_in.test = false;
    apdu_in.ndsCom = false;
    apdu_in.numDatSetEntries = 0;  /* No data */

    /* Encode */
    ret = goose_encode_apdu(buf, sizeof(buf), &apdu_in, &encoded_len);
    TEST_ASSERT(ret == GOOSE_BER_OK, "encode APDU failed");
    TEST_ASSERT(encoded_len > 0 && encoded_len < sizeof(buf), "encoded length invalid");

    /* Decode */
    ret = goose_decode_apdu(buf, encoded_len, &apdu_out);
    TEST_ASSERT(ret == GOOSE_BER_OK, "decode APDU failed");

    /* Verify all fields */
    TEST_ASSERT(strcmp(apdu_out.gocbRef, apdu_in.gocbRef) == 0, "gocbRef mismatch");
    TEST_ASSERT(strcmp(apdu_out.datSet, apdu_in.datSet) == 0, "datSet mismatch");
    TEST_ASSERT(apdu_out.stNum == apdu_in.stNum, "stNum mismatch");
    TEST_ASSERT(apdu_out.sqNum == apdu_in.sqNum, "sqNum mismatch");
    TEST_ASSERT(apdu_out.timestamp == apdu_in.timestamp, "timestamp mismatch");
    TEST_ASSERT(apdu_out.timeAllowedtoLive == apdu_in.timeAllowedtoLive, "timeAllowedtoLive mismatch");
    TEST_ASSERT(apdu_out.confRev == apdu_in.confRev, "confRev mismatch");
    TEST_ASSERT(apdu_out.test == apdu_in.test, "test mismatch");
    TEST_ASSERT(apdu_out.ndsCom == apdu_in.ndsCom, "ndsCom mismatch");
    TEST_ASSERT(apdu_out.numDatSetEntries == apdu_in.numDatSetEntries, "numDatSetEntries mismatch");

    TEST_PASS();
}

/**
 * Test: GOOSE APDU with allData encode→decode roundtrip
 * THIS WOULD HAVE CAUGHT BUG #2 (off-by-1 in encoder)
 */
static void test_goose_apdu_with_alldata_roundtrip(void)
{
    uint8_t buf[512];
    size_t encoded_len;
    goose_apdu_t apdu_in, apdu_out;
    int ret;

    /* Initialize APDU with data */
    goose_apdu_init(&apdu_in);
    ret = goose_set_gocbref(&apdu_in, "GOOSE_TEST_PUB");
    TEST_ASSERT(ret == GOOSE_BER_OK, "set gocbRef failed");

    ret = goose_set_datset(&apdu_in, "TestDataSet");
    TEST_ASSERT(ret == GOOSE_BER_OK, "set datSet failed");

    apdu_in.stNum = 1;
    apdu_in.sqNum = 0;
    apdu_in.timestamp = 1234567890ULL * 1000000ULL;
    apdu_in.timeAllowedtoLive = 5000;
    apdu_in.confRev = 1;
    apdu_in.test = false;
    apdu_in.ndsCom = false;

    /* Add multiple data items to trigger larger encoding */
    ret = goose_add_boolean(&apdu_in, true);
    TEST_ASSERT(ret == GOOSE_BER_OK, "add boolean failed");

    ret = goose_add_int32(&apdu_in, 12345);
    TEST_ASSERT(ret == GOOSE_BER_OK, "add int32 failed");

    ret = goose_add_int32(&apdu_in, -67890);
    TEST_ASSERT(ret == GOOSE_BER_OK, "add int32 failed");

    /* Encode */
    ret = goose_encode_apdu(buf, sizeof(buf), &apdu_in, &encoded_len);
    TEST_ASSERT(ret == GOOSE_BER_OK, "encode APDU with allData failed");
    TEST_ASSERT(encoded_len > 0 && encoded_len < sizeof(buf), "encoded length invalid");

    /* Decode */
    ret = goose_decode_apdu(buf, encoded_len, &apdu_out);
    TEST_ASSERT(ret == GOOSE_BER_OK, "decode APDU with allData failed");

    /* Verify metadata */
    TEST_ASSERT(strcmp(apdu_out.gocbRef, apdu_in.gocbRef) == 0, "gocbRef mismatch");
    TEST_ASSERT(apdu_out.numDatSetEntries == apdu_in.numDatSetEntries, "numDatSetEntries mismatch");

    /* Verify allData */
    TEST_ASSERT(apdu_out.allData[0].type == GOOSE_DATA_BOOLEAN, "allData[0] type mismatch");
    TEST_ASSERT(apdu_out.allData[0].value.boolean == true, "allData[0] value mismatch");

    TEST_ASSERT(apdu_out.allData[1].type == GOOSE_DATA_INT32, "allData[1] type mismatch");
    TEST_ASSERT(apdu_out.allData[1].value.int32 == 12345, "allData[1] value mismatch");

    TEST_ASSERT(apdu_out.allData[2].type == GOOSE_DATA_INT32, "allData[2] type mismatch");
    TEST_ASSERT(apdu_out.allData[2].value.int32 == -67890, "allData[2] value mismatch");

    TEST_PASS();
}

/**
 * Test: Various packet sizes to verify length encoding
 * Specifically tests the boundary cases that trigger different BER length encodings
 */
static void test_goose_apdu_various_sizes(void)
{
    uint8_t buf[1518];
    size_t encoded_len;
    goose_apdu_t apdu_in, apdu_out;
    int ret;

    /* Test with different numbers of data items to vary packet size */
    int data_counts[] = {0, 1, 5, 10, 20};  /* Different packet sizes */

    for (size_t i = 0; i < sizeof(data_counts)/sizeof(data_counts[0]); i++) {
        goose_apdu_init(&apdu_in);
        ret = goose_set_gocbref(&apdu_in, "GOOSE_TEST_PUB");
        TEST_ASSERT(ret == GOOSE_BER_OK, "set gocbRef failed");

        ret = goose_set_datset(&apdu_in, "TestDataSet");
        TEST_ASSERT(ret == GOOSE_BER_OK, "set datSet failed");

        apdu_in.stNum = (uint32_t)i;
        apdu_in.sqNum = 0;
        apdu_in.timestamp = 1234567890ULL * 1000000ULL;

        /* Add varying number of data items */
        for (int j = 0; j < data_counts[i]; j++) {
            ret = goose_add_int32(&apdu_in, j * 100);
            TEST_ASSERT(ret == GOOSE_BER_OK, "add int32 failed");
        }

        /* Encode */
        ret = goose_encode_apdu(buf, sizeof(buf), &apdu_in, &encoded_len);
        TEST_ASSERT(ret == GOOSE_BER_OK, "encode APDU failed");

        /* Decode */
        ret = goose_decode_apdu(buf, encoded_len, &apdu_out);
        TEST_ASSERT(ret == GOOSE_BER_OK, "decode APDU failed");

        /* Verify count */
        TEST_ASSERT(apdu_out.numDatSetEntries == apdu_in.numDatSetEntries,
                    "numDatSetEntries mismatch");
    }

    TEST_PASS();
}

/***************************************************************************
 * Error Handling Tests
 ***************************************************************************/

/**
 * Test: Buffer overflow protection in encode
 */
static void test_encode_buffer_overflow(void)
{
    goose_apdu_t apdu;
    goose_apdu_init(&apdu);
    goose_set_gocbref(&apdu, "TEST");
    goose_set_datset(&apdu, "DS");
    goose_set_goid(&apdu, "GOID");

    /* Try to encode into tiny buffer (should fail) */
    uint8_t tiny_buf[10];
    size_t len;
    int ret = goose_encode_apdu(tiny_buf, sizeof(tiny_buf), &apdu, &len);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should fail on tiny buffer");

    TEST_PASS();
}

/**
 * Test: NULL pointer protection
 */
static void test_null_pointer_protection(void)
{
    goose_apdu_t apdu;
    goose_apdu_init(&apdu);
    uint8_t buf[256];
    size_t len;

    /* NULL buffer */
    int ret = goose_encode_apdu(NULL, 256, &apdu, &len);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should fail on NULL buffer");

    /* NULL APDU */
    ret = goose_encode_apdu(buf, sizeof(buf), NULL, &len);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should fail on NULL APDU");

    /* NULL length pointer */
    ret = goose_encode_apdu(buf, sizeof(buf), &apdu, NULL);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should fail on NULL length");

    TEST_PASS();
}

/**
 * Test: Invalid decode input
 */
static void test_decode_invalid_input(void)
{
    goose_apdu_t apdu;

    /* Empty buffer */
    uint8_t empty[1] = {0};
    int ret = goose_decode_apdu(empty, 0, &apdu);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should fail on empty buffer");

    /* Invalid tag */
    uint8_t invalid_tag[10] = {0xFF, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    ret = goose_decode_apdu(invalid_tag, sizeof(invalid_tag), &apdu);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should fail on invalid tag");

    TEST_PASS();
}

/**
 * Test: String length limits
 */
static void test_string_length_limits(void)
{
    goose_apdu_t apdu;
    goose_apdu_init(&apdu);

    /* Very long strings (at limits) */
    char long_str[GOOSE_MAX_GOCBREF_LEN + 10];
    memset(long_str, 'A', sizeof(long_str) - 1);
    long_str[sizeof(long_str) - 1] = '\0';

    /* These should be safely truncated, not crash */
    goose_set_gocbref(&apdu, long_str);
    goose_set_datset(&apdu, long_str);
    goose_set_goid(&apdu, long_str);

    /* Verify encoding still works */
    uint8_t buf[2048];
    size_t len;
    int ret = goose_encode_apdu(buf, sizeof(buf), &apdu, &len);
    TEST_ASSERT(ret == GOOSE_BER_OK, "Should encode with long strings");

    TEST_PASS();
}

/**
 * Test: Maximum allData entries
 */
static void test_max_alldata_entries(void)
{
    goose_apdu_t apdu;
    goose_apdu_init(&apdu);
    goose_set_gocbref(&apdu, "TEST");
    goose_set_datset(&apdu, "DS");
    goose_set_goid(&apdu, "GOID");

    /* Fill up to max entries */
    unsigned int i;
    for (i = 0; i < GOOSE_MAX_ALLDATA_ENTRIES; i++) {
        int ret = goose_add_boolean(&apdu, true);
        if (ret != GOOSE_BER_OK) break;
    }

    /* Verify we got close to max */
    TEST_ASSERT(i >= GOOSE_MAX_ALLDATA_ENTRIES - 1, "Should accept many entries");

    /* Try to add beyond max (should fail gracefully) */
    int ret = goose_add_boolean(&apdu, true);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should reject beyond max entries");

    TEST_PASS();
}

/**
 * Test: Decode with insufficient data
 */
static void test_decode_insufficient_data(void)
{
    /* Create valid APDU */
    goose_apdu_t apdu_in, apdu_out;
    goose_apdu_init(&apdu_in);
    goose_set_gocbref(&apdu_in, "TEST");
    goose_set_datset(&apdu_in, "DS");
    goose_set_goid(&apdu_in, "GOID");
    goose_add_int32(&apdu_in, 12345);

    uint8_t buf[256];
    size_t len;
    int ret = goose_encode_apdu(buf, sizeof(buf), &apdu_in, &len);
    TEST_ASSERT(ret == GOOSE_BER_OK, "Encode should succeed");

    /* Try to decode with truncated data */
    if (len > 10) {
        ret = goose_decode_apdu(buf, len - 10, &apdu_out);
        TEST_ASSERT(ret != GOOSE_BER_OK, "Should fail on truncated data");
    }

    TEST_PASS();
}

/***************************************************************************
 * Main Test Runner
 ***************************************************************************/

/***************************************************************************
 * New allData Type Tests (VisibleString, UtcTime, Structure, BitString)
 ***************************************************************************/

/**
 * Test: BitString encode/decode roundtrip with unused-bits prefix byte
 */
static void test_bitstring_roundtrip(void)
{
    uint8_t buf[256];
    size_t encoded_len;
    goose_apdu_t apdu_in, apdu_out;
    int ret;

    goose_apdu_init(&apdu_in);
    goose_set_gocbref(&apdu_in, "IED1LD0/LLN0$GO$gcb01");
    goose_set_datset(&apdu_in, "IED1LD0/LLN0$DS1");
    apdu_in.stNum = 1;
    apdu_in.confRev = 1;

    /* Quality bitstring: 2 bytes (e.g., 0x00 0x00 = good quality) */
    uint8_t quality[] = {0x00, 0x00};
    ret = goose_add_bitstring(&apdu_in, quality, sizeof(quality));
    TEST_ASSERT(ret == GOOSE_BER_OK, "add bitstring failed");

    /* Encode */
    ret = goose_encode_apdu(buf, sizeof(buf), &apdu_in, &encoded_len);
    TEST_ASSERT(ret == GOOSE_BER_OK, "encode bitstring APDU failed");

    /* Decode */
    ret = goose_decode_apdu(buf, encoded_len, &apdu_out);
    TEST_ASSERT(ret == GOOSE_BER_OK, "decode bitstring APDU failed");
    TEST_ASSERT(apdu_out.numDatSetEntries == 1, "wrong count");
    TEST_ASSERT(apdu_out.allData[0].type == GOOSE_DATA_BITSTRING, "wrong type");
    /* After decode, len should be 2 (unused-bits byte stripped) */
    TEST_ASSERT(apdu_out.allData[0].value.bytes.len == 2, "wrong bitstring len");

    TEST_PASS();
}

/**
 * Test: VisibleString encode/decode roundtrip
 */
static void test_visiblestring_alldata_roundtrip(void)
{
    uint8_t buf[512];
    size_t encoded_len;
    goose_apdu_t apdu_in, apdu_out;
    int ret;

    goose_apdu_init(&apdu_in);
    goose_set_gocbref(&apdu_in, "IED1LD0/LLN0$GO$gcb01");
    goose_set_datset(&apdu_in, "IED1LD0/LLN0$DS1");
    apdu_in.stNum = 1;
    apdu_in.confRev = 1;

    ret = goose_add_boolean(&apdu_in, true);
    TEST_ASSERT(ret == GOOSE_BER_OK, "add boolean failed");

    ret = goose_add_visiblestring(&apdu_in, "Hello IEC61850");
    TEST_ASSERT(ret == GOOSE_BER_OK, "add visiblestring failed");

    ret = goose_add_int32(&apdu_in, 42);
    TEST_ASSERT(ret == GOOSE_BER_OK, "add int32 failed");

    /* Encode */
    ret = goose_encode_apdu(buf, sizeof(buf), &apdu_in, &encoded_len);
    TEST_ASSERT(ret == GOOSE_BER_OK, "encode failed");

    /* Decode */
    ret = goose_decode_apdu(buf, encoded_len, &apdu_out);
    TEST_ASSERT(ret == GOOSE_BER_OK, "decode failed");
    TEST_ASSERT(apdu_out.numDatSetEntries == 3, "wrong count");
    TEST_ASSERT(apdu_out.allData[0].type == GOOSE_DATA_BOOLEAN, "wrong type[0]");
    TEST_ASSERT(apdu_out.allData[1].type == GOOSE_DATA_VISIBLESTRING, "wrong type[1]");
    TEST_ASSERT(apdu_out.allData[2].type == GOOSE_DATA_INT32, "wrong type[2]");

    TEST_PASS();
}

/**
 * Test: UtcTime encode/decode roundtrip
 */
static void test_utctime_alldata_roundtrip(void)
{
    uint8_t buf[512];
    size_t encoded_len;
    goose_apdu_t apdu_in, apdu_out;
    int ret;

    goose_apdu_init(&apdu_in);
    goose_set_gocbref(&apdu_in, "IED1LD0/LLN0$GO$gcb01");
    goose_set_datset(&apdu_in, "IED1LD0/LLN0$DS1");
    apdu_in.stNum = 1;
    apdu_in.confRev = 1;

    uint64_t ts = 1700000000ULL * 1000000ULL;  /* ~2023-11-14 */
    ret = goose_add_utctime(&apdu_in, ts, 0x18);
    TEST_ASSERT(ret == GOOSE_BER_OK, "add utctime failed");

    ret = goose_add_boolean(&apdu_in, false);
    TEST_ASSERT(ret == GOOSE_BER_OK, "add boolean failed");

    /* Encode */
    ret = goose_encode_apdu(buf, sizeof(buf), &apdu_in, &encoded_len);
    TEST_ASSERT(ret == GOOSE_BER_OK, "encode failed");

    /* Decode */
    ret = goose_decode_apdu(buf, encoded_len, &apdu_out);
    TEST_ASSERT(ret == GOOSE_BER_OK, "decode failed");
    TEST_ASSERT(apdu_out.numDatSetEntries == 2, "wrong count");
    TEST_ASSERT(apdu_out.allData[0].type == GOOSE_DATA_UTCTIME, "wrong type[0]");
    /* UtcTime roundtrip: check timestamp is close (rounding) */
    int64_t diff = (int64_t)apdu_out.allData[0].value.utctime.timestamp_us - (int64_t)ts;
    TEST_ASSERT(diff >= -1 && diff <= 1, "utctime timestamp drift");
    TEST_ASSERT(apdu_out.allData[0].value.utctime.time_quality == 0x18, "wrong quality");
    TEST_ASSERT(apdu_out.allData[1].type == GOOSE_DATA_BOOLEAN, "wrong type[1]");

    TEST_PASS();
}

/**
 * Test: Structure encode/decode roundtrip
 */
static void test_structure_alldata_roundtrip(void)
{
    uint8_t buf[512];
    size_t encoded_len;
    goose_apdu_t apdu_in, apdu_out;
    int ret;

    goose_apdu_init(&apdu_in);
    goose_set_gocbref(&apdu_in, "IED1LD0/LLN0$GO$gcb01");
    goose_set_datset(&apdu_in, "IED1LD0/LLN0$DS1");
    apdu_in.stNum = 1;
    apdu_in.confRev = 1;

    /* Create a structure with 2 sub-elements */
    goose_data_t sub_elements[2];
    memset(sub_elements, 0, sizeof(sub_elements));
    sub_elements[0].type = GOOSE_DATA_BOOLEAN;
    sub_elements[0].value.boolean = true;
    sub_elements[1].type = GOOSE_DATA_INT32;
    sub_elements[1].value.int32 = -100;

    ret = goose_add_structure(&apdu_in, sub_elements, 2);
    TEST_ASSERT(ret == GOOSE_BER_OK, "add structure failed");

    ret = goose_add_uint32(&apdu_in, 999);
    TEST_ASSERT(ret == GOOSE_BER_OK, "add uint32 failed");

    /* Encode */
    ret = goose_encode_apdu(buf, sizeof(buf), &apdu_in, &encoded_len);
    TEST_ASSERT(ret == GOOSE_BER_OK, "encode failed");

    /* Decode */
    ret = goose_decode_apdu(buf, encoded_len, &apdu_out);
    TEST_ASSERT(ret == GOOSE_BER_OK, "decode failed");
    TEST_ASSERT(apdu_out.numDatSetEntries == 2, "wrong count");
    TEST_ASSERT(apdu_out.allData[0].type == GOOSE_DATA_STRUCTURE, "wrong type[0]");
    TEST_ASSERT(apdu_out.allData[1].type == GOOSE_DATA_UINT32, "wrong type[1]");
    TEST_ASSERT(apdu_out.allData[1].value.uint32 == 999, "wrong uint32 value");

    TEST_PASS();
}

/**
 * Test: goose_add_visiblestring / goose_add_utctime / goose_add_structure error paths
 */
static void test_new_alldata_helpers_errors(void)
{
    goose_apdu_t apdu;
    goose_apdu_init(&apdu);
    goose_data_t dummy = {0};

    /* NULL apdu */
    TEST_ASSERT(goose_add_visiblestring(NULL, "test") != GOOSE_BER_OK, "NULL apdu vs");
    TEST_ASSERT(goose_add_utctime(NULL, 0, 0) != GOOSE_BER_OK, "NULL apdu utc");
    TEST_ASSERT(goose_add_structure(NULL, &dummy, 1) != GOOSE_BER_OK, "NULL apdu struct");

    /* NULL str/elements */
    TEST_ASSERT(goose_add_visiblestring(&apdu, NULL) != GOOSE_BER_OK, "NULL str");
    TEST_ASSERT(goose_add_structure(&apdu, NULL, 1) != GOOSE_BER_OK, "NULL elements");

    TEST_PASS();
}

/**
 * Test: Mixed allData with all types in one APDU
 */
static void test_all_types_roundtrip(void)
{
    uint8_t buf[1024];
    size_t encoded_len;
    goose_apdu_t apdu_in, apdu_out;
    int ret;

    goose_apdu_init(&apdu_in);
    goose_set_gocbref(&apdu_in, "IED1LD0/LLN0$GO$gcb01");
    goose_set_datset(&apdu_in, "IED1LD0/LLN0$DS1");
    apdu_in.stNum = 5;
    apdu_in.sqNum = 10;
    apdu_in.confRev = 1;

    goose_add_boolean(&apdu_in, true);
    goose_add_int32(&apdu_in, -42);
    goose_add_uint32(&apdu_in, 100);
    goose_add_float32(&apdu_in, 3.14f);
    uint8_t bs[] = {0xC0};
    goose_add_bitstring(&apdu_in, bs, 1);
    uint8_t os[] = {0xDE, 0xAD};
    goose_add_octetstring(&apdu_in, os, 2);
    goose_add_visiblestring(&apdu_in, "test61850");
    goose_add_utctime(&apdu_in, 1700000000000000ULL, 0x00);

    TEST_ASSERT(apdu_in.numDatSetEntries == 8, "wrong entry count");

    /* Encode */
    ret = goose_encode_apdu(buf, sizeof(buf), &apdu_in, &encoded_len);
    TEST_ASSERT(ret == GOOSE_BER_OK, "encode all types failed");

    /* Decode */
    ret = goose_decode_apdu(buf, encoded_len, &apdu_out);
    TEST_ASSERT(ret == GOOSE_BER_OK, "decode all types failed");
    TEST_ASSERT(apdu_out.numDatSetEntries == 8, "wrong decoded count");

    TEST_ASSERT(apdu_out.allData[0].type == GOOSE_DATA_BOOLEAN, "type[0]");
    TEST_ASSERT(apdu_out.allData[0].value.boolean == true, "val[0]");
    TEST_ASSERT(apdu_out.allData[1].type == GOOSE_DATA_INT32, "type[1]");
    TEST_ASSERT(apdu_out.allData[1].value.int32 == -42, "val[1]");
    TEST_ASSERT(apdu_out.allData[2].type == GOOSE_DATA_UINT32, "type[2]");
    TEST_ASSERT(apdu_out.allData[2].value.uint32 == 100, "val[2]");
    TEST_ASSERT(apdu_out.allData[3].type == GOOSE_DATA_FLOAT32, "type[3]");
    TEST_ASSERT(apdu_out.allData[4].type == GOOSE_DATA_BITSTRING, "type[4]");
    TEST_ASSERT(apdu_out.allData[4].value.bytes.len == 1, "bitstring len");
    TEST_ASSERT(apdu_out.allData[5].type == GOOSE_DATA_OCTETSTRING, "type[5]");
    TEST_ASSERT(apdu_out.allData[5].value.bytes.len == 2, "octetstring len");
    TEST_ASSERT(apdu_out.allData[6].type == GOOSE_DATA_VISIBLESTRING, "type[6]");
    TEST_ASSERT(apdu_out.allData[7].type == GOOSE_DATA_UTCTIME, "type[7]");

    TEST_PASS();
}

int main(void)
{
    printf("Running BER encoder/decoder unit tests...\n");
    printf("=========================================\n\n");

    /* Low-level BER encoding tests */
    printf("Low-level BER encoding tests:\n");
    test_ber_length_encoding_short_form();
    test_ber_length_encoding_long_form_1byte();
    test_ber_length_encoding_long_form_2byte();
    test_ber_int32_roundtrip();
    test_ber_uint32_roundtrip();
    test_ber_boolean_roundtrip();
    test_ber_visiblestring_roundtrip();
    printf("\n");

    /* GOOSE APDU tests */
    printf("GOOSE APDU tests:\n");
    test_goose_apdu_minimal_roundtrip();
    test_goose_apdu_with_alldata_roundtrip();
    test_goose_apdu_various_sizes();
    printf("\n");

    /* New allData type tests */
    printf("New allData type tests:\n");
    test_bitstring_roundtrip();
    test_visiblestring_alldata_roundtrip();
    test_utctime_alldata_roundtrip();
    test_structure_alldata_roundtrip();
    test_new_alldata_helpers_errors();
    test_all_types_roundtrip();
    printf("\n");

    /* Error handling tests */
    printf("Error handling tests:\n");
    test_encode_buffer_overflow();
    test_null_pointer_protection();
    test_decode_invalid_input();
    test_string_length_limits();
    test_max_alldata_entries();
    test_decode_insufficient_data();
    printf("\n");

    /* Summary */
    printf("\n=========================================\n");
    printf("Test Results:\n");
    printf("  Passed: %d\n", tests_passed);
    printf("  Failed: %d\n", tests_failed);
    printf("=========================================\n");

    if (tests_failed > 0) {
        printf("FAILURE: %d test(s) failed\n", tests_failed);
        return 1;
    }

    printf("SUCCESS: All tests passed\n");
    return 0;
}
