/* SPDX-License-Identifier: BSD-2-Clause */
// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2024 IEC-61850 DPDK Project

/**
 * Low-level BER encoder/decoder error path tests
 *
 * These tests target uncovered error handling paths to maximize coverage
 */

#include "asn1/goose_ber.h"
#include "asn1/goose_ber_decode.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

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
 * BER Encoder Error Path Tests
 ***************************************************************************/

static void test_ber_encode_tag_null_buffer(void)
{
    size_t offset = 0;
    int ret = ber_encode_tag(NULL, 100, &offset, 0x80);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL buffer");
    TEST_PASS();
}

static void test_ber_encode_tag_null_offset(void)
{
    uint8_t buf[10];
    int ret = ber_encode_tag(buf, sizeof(buf), NULL, 0x80);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL offset");
    TEST_PASS();
}

static void test_ber_encode_tag_buffer_full(void)
{
    uint8_t buf[10];
    size_t offset = sizeof(buf);  // Already at end
    int ret = ber_encode_tag(buf, sizeof(buf), &offset, 0x80);
    TEST_ASSERT(ret == GOOSE_BER_ERR_BUFFER_FULL, "Should detect buffer full");
    TEST_PASS();
}

static void test_ber_encode_length_null_buffer(void)
{
    size_t offset = 0;
    int ret = ber_encode_length(NULL, 100, &offset, 50);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL buffer");
    TEST_PASS();
}

static void test_ber_encode_length_null_offset(void)
{
    uint8_t buf[10];
    int ret = ber_encode_length(buf, sizeof(buf), NULL, 50);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL offset");
    TEST_PASS();
}

static void test_ber_encode_length_short_form_overflow(void)
{
    uint8_t buf[10];
    size_t offset = sizeof(buf);  // No space
    int ret = ber_encode_length(buf, sizeof(buf), &offset, 50);  // Short form
    TEST_ASSERT(ret == GOOSE_BER_ERR_BUFFER_FULL, "Should detect overflow in short form");
    TEST_PASS();
}

static void test_ber_encode_length_long_form_1byte_overflow(void)
{
    uint8_t buf[10];
    size_t offset = sizeof(buf) - 1;  // Only 1 byte left, need 2
    int ret = ber_encode_length(buf, sizeof(buf), &offset, 200);  // Long form 1-byte
    TEST_ASSERT(ret == GOOSE_BER_ERR_BUFFER_FULL, "Should detect overflow in long form 1-byte");
    TEST_PASS();
}

static void test_ber_encode_length_long_form_2byte_overflow(void)
{
    uint8_t buf[10];
    size_t offset = sizeof(buf) - 2;  // Only 2 bytes left, need 3
    int ret = ber_encode_length(buf, sizeof(buf), &offset, 300);  // Long form 2-byte
    TEST_ASSERT(ret == GOOSE_BER_ERR_BUFFER_FULL, "Should detect overflow in long form 2-byte");
    TEST_PASS();
}

static void test_ber_encode_length_too_large(void)
{
    uint8_t buf[100];
    size_t offset = 0;
    int ret = ber_encode_length(buf, sizeof(buf), &offset, 0x10000);  // > 0xFFFF
    TEST_ASSERT(ret == GOOSE_BER_ERR_ENCODING, "Should reject length > 65535");
    TEST_PASS();
}

static void test_ber_encode_int32_null_buffer(void)
{
    size_t offset = 0;
    int ret = ber_encode_int32(NULL, 100, &offset, ASN1_TAG_INTEGER, 12345);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL buffer");
    TEST_PASS();
}

static void test_ber_encode_int32_null_offset(void)
{
    uint8_t buf[10];
    int ret = ber_encode_int32(buf, sizeof(buf), NULL, ASN1_TAG_INTEGER, 12345);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL offset");
    TEST_PASS();
}

static void test_ber_encode_int32_buffer_overflow(void)
{
    uint8_t buf[3];  // Too small
    size_t offset = 0;
    int ret = ber_encode_int32(buf, sizeof(buf), &offset, ASN1_TAG_INTEGER, 12345);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should detect buffer overflow");
    TEST_PASS();
}

static void test_ber_encode_uint32_null_buffer(void)
{
    size_t offset = 0;
    int ret = ber_encode_uint32(NULL, 100, &offset, ASN1_TAG_INTEGER, 12345);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL buffer");
    TEST_PASS();
}

static void test_ber_encode_uint32_null_offset(void)
{
    uint8_t buf[10];
    int ret = ber_encode_uint32(buf, sizeof(buf), NULL, ASN1_TAG_INTEGER, 12345);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL offset");
    TEST_PASS();
}

static void test_ber_encode_boolean_null_buffer(void)
{
    size_t offset = 0;
    int ret = ber_encode_boolean(NULL, 100, &offset, ASN1_TAG_BOOLEAN, true);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL buffer");
    TEST_PASS();
}

static void test_ber_encode_boolean_null_offset(void)
{
    uint8_t buf[10];
    int ret = ber_encode_boolean(buf, sizeof(buf), NULL, ASN1_TAG_BOOLEAN, true);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL offset");
    TEST_PASS();
}

static void test_ber_encode_boolean_buffer_overflow(void)
{
    uint8_t buf[2];  // Too small
    size_t offset = 0;
    int ret = ber_encode_boolean(buf, sizeof(buf), &offset, ASN1_TAG_BOOLEAN, true);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should detect buffer overflow");
    TEST_PASS();
}

static void test_ber_encode_boolean_overflow_after_tag(void)
{
    uint8_t buf[1];  // Only 1 byte - tag writes, then length fails
    size_t offset = 0;
    int ret = ber_encode_boolean(buf, sizeof(buf), &offset, ASN1_TAG_BOOLEAN, true);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should detect overflow after tag");
    TEST_PASS();
}

static void test_ber_encode_int32_overflow_after_tag(void)
{
    uint8_t buf[1];  // Only 1 byte - tag writes, then length fails
    size_t offset = 0;
    int ret = ber_encode_int32(buf, sizeof(buf), &offset, ASN1_TAG_INTEGER, 12345);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should detect overflow after tag");
    TEST_PASS();
}

static void test_ber_encode_int32_overflow_after_length(void)
{
    uint8_t buf[2];  // 2 bytes - tag+length write, then value fails
    size_t offset = 0;
    int ret = ber_encode_int32(buf, sizeof(buf), &offset, ASN1_TAG_INTEGER, 12345);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should detect overflow after length");
    TEST_PASS();
}

static void test_ber_encode_uint32_overflow_after_tag(void)
{
    uint8_t buf[1];  // Only 1 byte
    size_t offset = 0;
    int ret = ber_encode_uint32(buf, sizeof(buf), &offset, ASN1_TAG_INTEGER, 12345);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should detect overflow after tag");
    TEST_PASS();
}

static void test_ber_encode_visiblestring_overflow_after_tag(void)
{
    uint8_t buf[1];  // Only 1 byte
    size_t offset = 0;
    int ret = ber_encode_visiblestring(buf, sizeof(buf), &offset, ASN1_TAG_VISIBLESTRING, "TEST");
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should detect overflow after tag");
    TEST_PASS();
}

static void test_ber_encode_visiblestring_overflow_after_length(void)
{
    uint8_t buf[2];  // 2 bytes - tag+length write, then string fails
    size_t offset = 0;
    int ret = ber_encode_visiblestring(buf, sizeof(buf), &offset, ASN1_TAG_VISIBLESTRING, "TEST");
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should detect overflow after length");
    TEST_PASS();
}

static void test_ber_encode_utctime_overflow_after_tag(void)
{
    uint8_t buf[1];  // Only 1 byte
    size_t offset = 0;
    int ret = ber_encode_utctime(buf, sizeof(buf), &offset, ASN1_TAG_UTCTIME, 1234567890ULL, 0x00U);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should detect overflow after tag");
    TEST_PASS();
}

static void test_ber_encode_visiblestring_null_buffer(void)
{
    size_t offset = 0;
    int ret = ber_encode_visiblestring(NULL, 100, &offset, ASN1_TAG_VISIBLESTRING, "test");
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL buffer");
    TEST_PASS();
}

static void test_ber_encode_visiblestring_null_offset(void)
{
    uint8_t buf[10];
    int ret = ber_encode_visiblestring(buf, sizeof(buf), NULL, ASN1_TAG_VISIBLESTRING, "test");
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL offset");
    TEST_PASS();
}

static void test_ber_encode_visiblestring_null_str(void)
{
    uint8_t buf[10];
    size_t offset = 0;
    int ret = ber_encode_visiblestring(buf, sizeof(buf), &offset, ASN1_TAG_VISIBLESTRING, NULL);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL string");
    TEST_PASS();
}

static void test_ber_encode_visiblestring_buffer_overflow(void)
{
    uint8_t buf[5];  // Too small for "long string"
    size_t offset = 0;
    int ret = ber_encode_visiblestring(buf, sizeof(buf), &offset, ASN1_TAG_VISIBLESTRING, "long string");
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should detect buffer overflow");
    TEST_PASS();
}

static void test_ber_encode_utctime_null_buffer(void)
{
    size_t offset = 0;
    int ret = ber_encode_utctime(NULL, 100, &offset, ASN1_TAG_UTCTIME, 1234567890ULL, 0x00U);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL buffer");
    TEST_PASS();
}

static void test_ber_encode_utctime_null_offset(void)
{
    uint8_t buf[20];
    int ret = ber_encode_utctime(buf, sizeof(buf), NULL, ASN1_TAG_UTCTIME, 1234567890ULL, 0x00U);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL offset");
    TEST_PASS();
}

/***************************************************************************
 * BER Decoder Error Path Tests
 ***************************************************************************/

static void test_ber_decode_tag_null_buffer(void)
{
    size_t offset = 0;
    uint8_t tag;
    int ret = ber_decode_tag(NULL, 100, &offset, &tag);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL buffer");
    TEST_PASS();
}

static void test_ber_decode_tag_null_offset(void)
{
    uint8_t buf[10] = {0x80, 0x05, 0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t tag;
    int ret = ber_decode_tag(buf, sizeof(buf), NULL, &tag);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL offset");
    TEST_PASS();
}

static void test_ber_decode_tag_null_output(void)
{
    uint8_t buf[10] = {0x80, 0x05, 0, 0, 0, 0, 0, 0, 0, 0};
    size_t offset = 0;
    int ret = ber_decode_tag(buf, sizeof(buf), &offset, NULL);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL tag output");
    TEST_PASS();
}

static void test_ber_decode_tag_buffer_underflow(void)
{
    uint8_t buf[10] = {0x80, 0x05, 0, 0, 0, 0, 0, 0, 0, 0};
    size_t offset = sizeof(buf);  // At end
    uint8_t tag;
    int ret = ber_decode_tag(buf, sizeof(buf), &offset, &tag);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should detect buffer underflow");
    TEST_PASS();
}

static void test_ber_decode_length_null_buffer(void)
{
    size_t offset = 0;
    size_t length;
    int ret = ber_decode_length(NULL, 100, &offset, &length);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL buffer");
    TEST_PASS();
}

static void test_ber_decode_length_null_offset(void)
{
    uint8_t buf[10] = {0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    size_t length;
    int ret = ber_decode_length(buf, sizeof(buf), NULL, &length);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL offset");
    TEST_PASS();
}

static void test_ber_decode_length_null_output(void)
{
    uint8_t buf[10] = {0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    size_t offset = 0;
    int ret = ber_decode_length(buf, sizeof(buf), &offset, NULL);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL length output");
    TEST_PASS();
}

static void test_ber_decode_length_buffer_underflow(void)
{
    uint8_t buf[10] = {0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    size_t offset = sizeof(buf);
    size_t length;
    int ret = ber_decode_length(buf, sizeof(buf), &offset, &length);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should detect buffer underflow");
    TEST_PASS();
}

static void test_ber_decode_int32_null_buffer(void)
{
    size_t offset = 0;
    int32_t value;
    int ret = ber_decode_int32(NULL, 100, &offset, ASN1_TAG_INTEGER, &value);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL buffer");
    TEST_PASS();
}

static void test_ber_decode_int32_null_offset(void)
{
    uint8_t buf[10] = {0x02, 0x04, 0x00, 0x00, 0x30, 0x39, 0, 0, 0, 0};
    int32_t value;
    int ret = ber_decode_int32(buf, sizeof(buf), NULL, ASN1_TAG_INTEGER, &value);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL offset");
    TEST_PASS();
}

static void test_ber_decode_int32_null_output(void)
{
    uint8_t buf[10] = {0x02, 0x04, 0x00, 0x00, 0x30, 0x39, 0, 0, 0, 0};
    size_t offset = 0;
    int ret = ber_decode_int32(buf, sizeof(buf), &offset, ASN1_TAG_INTEGER, NULL);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL value output");
    TEST_PASS();
}

static void test_ber_decode_int32_buffer_underflow(void)
{
    uint8_t buf[3] = {0x02, 0x04, 0x00};  // Says length=4 but not enough data
    size_t offset = 0;
    int32_t value;
    int ret = ber_decode_int32(buf, sizeof(buf), &offset, ASN1_TAG_INTEGER, &value);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should detect buffer underflow");
    TEST_PASS();
}

static void test_ber_decode_boolean_null_buffer(void)
{
    size_t offset = 0;
    bool value;
    int ret = ber_decode_boolean(NULL, 100, &offset, ASN1_TAG_BOOLEAN, &value);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL buffer");
    TEST_PASS();
}

static void test_ber_decode_boolean_null_offset(void)
{
    uint8_t buf[10] = {0x01, 0x01, 0xFF, 0, 0, 0, 0, 0, 0, 0};
    bool value;
    int ret = ber_decode_boolean(buf, sizeof(buf), NULL, ASN1_TAG_BOOLEAN, &value);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL offset");
    TEST_PASS();
}

static void test_ber_decode_boolean_null_output(void)
{
    uint8_t buf[10] = {0x01, 0x01, 0xFF, 0, 0, 0, 0, 0, 0, 0};
    size_t offset = 0;
    int ret = ber_decode_boolean(buf, sizeof(buf), &offset, ASN1_TAG_BOOLEAN, NULL);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL value output");
    TEST_PASS();
}

static void test_ber_decode_boolean_buffer_underflow(void)
{
    uint8_t buf[2] = {0x01, 0x01};  // Says length=1 but no data
    size_t offset = 0;
    bool value;
    int ret = ber_decode_boolean(buf, sizeof(buf), &offset, ASN1_TAG_BOOLEAN, &value);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should detect buffer underflow");
    TEST_PASS();
}

static void test_ber_decode_visiblestring_null_buffer(void)
{
    size_t offset = 0;
    char str[10];
    int ret = ber_decode_visiblestring(NULL, 100, &offset, ASN1_TAG_VISIBLESTRING, str, sizeof(str));
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL buffer");
    TEST_PASS();
}

static void test_ber_decode_visiblestring_null_offset(void)
{
    uint8_t buf[10] = {0x1A, 0x04, 'T', 'E', 'S', 'T', 0, 0, 0, 0};
    char str[10];
    int ret = ber_decode_visiblestring(buf, sizeof(buf), NULL, ASN1_TAG_VISIBLESTRING, str, sizeof(str));
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL offset");
    TEST_PASS();
}

static void test_ber_decode_visiblestring_null_output(void)
{
    uint8_t buf[10] = {0x1A, 0x04, 'T', 'E', 'S', 'T', 0, 0, 0, 0};
    size_t offset = 0;
    int ret = ber_decode_visiblestring(buf, sizeof(buf), &offset, ASN1_TAG_VISIBLESTRING, NULL, 10);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL string output");
    TEST_PASS();
}

static void test_ber_decode_visiblestring_buffer_underflow(void)
{
    uint8_t buf[4] = {0x1A, 0x10, 'T', 'E'};  // Says length=16 but not enough data
    size_t offset = 0;
    char str[20];
    int ret = ber_decode_visiblestring(buf, sizeof(buf), &offset, ASN1_TAG_VISIBLESTRING, str, sizeof(str));
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should detect buffer underflow");
    TEST_PASS();
}

static void test_ber_decode_tag_mismatch(void)
{
    uint8_t buf[10] = {0x80, 0x05, 0, 0, 0, 0, 0, 0, 0, 0};
    size_t offset = 0;
    uint8_t tag;
    int ret = ber_decode_tag(buf, sizeof(buf), &offset, &tag);
    TEST_ASSERT(ret == GOOSE_BER_OK, "Should decode tag");
    TEST_ASSERT(tag == 0x80, "Tag should be 0x80");
    TEST_PASS();
}

static void test_ber_decode_int32_tag_mismatch(void)
{
    uint8_t buf[10] = {0x80, 0x04, 0x00, 0x00, 0x30, 0x39, 0, 0, 0, 0};  // Wrong tag (0x80 instead of 0x02)
    size_t offset = 0;
    int32_t value;
    int ret = ber_decode_int32(buf, sizeof(buf), &offset, ASN1_TAG_INTEGER, &value);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should reject tag mismatch");
    TEST_PASS();
}

static void test_ber_decode_boolean_tag_mismatch(void)
{
    uint8_t buf[10] = {0x80, 0x01, 0xFF, 0, 0, 0, 0, 0, 0, 0};  // Wrong tag
    size_t offset = 0;
    bool value;
    int ret = ber_decode_boolean(buf, sizeof(buf), &offset, ASN1_TAG_BOOLEAN, &value);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should reject tag mismatch");
    TEST_PASS();
}

static void test_ber_decode_visiblestring_tag_mismatch(void)
{
    uint8_t buf[10] = {0x80, 0x04, 'T', 'E', 'S', 'T', 0, 0, 0, 0};  // Wrong tag
    size_t offset = 0;
    char str[10];
    int ret = ber_decode_visiblestring(buf, sizeof(buf), &offset, ASN1_TAG_VISIBLESTRING, str, sizeof(str));
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should reject tag mismatch");
    TEST_PASS();
}

static void test_ber_decode_length_long_form_underflow(void)
{
    uint8_t buf[3] = {0x81, 0x00, 0x00};  // Says 1 length byte follows, but wrong format
    size_t offset = 0;
    size_t length;
    int ret = ber_decode_length(buf, sizeof(buf), &offset, &length);
    (void)ret;  // Intentionally unused - just verify no crash
    // May succeed or fail depending on implementation, just verify no crash
    TEST_PASS();
}

static void test_ber_decode_int32_wrong_length(void)
{
    uint8_t buf[10] = {0x02, 0x05, 0x00, 0x00, 0x00, 0x30, 0x39, 0, 0, 0};  // 5-byte int (invalid)
    size_t offset = 0;
    int32_t value;
    int ret = ber_decode_int32(buf, sizeof(buf), &offset, ASN1_TAG_INTEGER, &value);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should reject 5-byte integer");
    TEST_PASS();
}

static void test_ber_decode_boolean_wrong_length(void)
{
    uint8_t buf[10] = {0x01, 0x02, 0xFF, 0x00, 0, 0, 0, 0, 0, 0};  // 2-byte boolean (invalid)
    size_t offset = 0;
    bool value;
    int ret = ber_decode_boolean(buf, sizeof(buf), &offset, ASN1_TAG_BOOLEAN, &value);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should reject 2-byte boolean");
    TEST_PASS();
}

static void test_ber_decode_visiblestring_output_buffer_too_small(void)
{
    uint8_t buf[10] = {0x1A, 0x06, 'T', 'E', 'S', 'T', 'E', 'D', 0, 0};  // 6-char string
    size_t offset = 0;
    char str[4];  // Buffer too small (needs 7 with null terminator)
    int ret = ber_decode_visiblestring(buf, sizeof(buf), &offset, ASN1_TAG_VISIBLESTRING, str, sizeof(str));
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should reject when output buffer too small");
    TEST_PASS();
}

static void test_ber_decode_uint32_null_buffer(void)
{
    size_t offset = 0;
    uint32_t value;
    int ret = ber_decode_uint32(NULL, 100, &offset, ASN1_TAG_INTEGER, &value);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL buffer");
    TEST_PASS();
}

static void test_ber_decode_uint32_null_offset(void)
{
    uint8_t buf[10] = {0x02, 0x04, 0x00, 0x00, 0x30, 0x39, 0, 0, 0, 0};
    uint32_t value;
    int ret = ber_decode_uint32(buf, sizeof(buf), NULL, ASN1_TAG_INTEGER, &value);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL offset");
    TEST_PASS();
}

static void test_ber_decode_uint32_null_output(void)
{
    uint8_t buf[10] = {0x02, 0x04, 0x00, 0x00, 0x30, 0x39, 0, 0, 0, 0};
    size_t offset = 0;
    int ret = ber_decode_uint32(buf, sizeof(buf), &offset, ASN1_TAG_INTEGER, NULL);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL value output");
    TEST_PASS();
}

static void test_ber_decode_uint32_buffer_underflow(void)
{
    uint8_t buf[3] = {0x02, 0x04, 0x00};  // Says length=4 but not enough data
    size_t offset = 0;
    uint32_t value;
    int ret = ber_decode_uint32(buf, sizeof(buf), &offset, ASN1_TAG_INTEGER, &value);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should detect buffer underflow");
    TEST_PASS();
}

static void test_ber_decode_uint32_tag_mismatch(void)
{
    uint8_t buf[10] = {0x80, 0x04, 0x00, 0x00, 0x30, 0x39, 0, 0, 0, 0};  // Wrong tag
    size_t offset = 0;
    uint32_t value;
    int ret = ber_decode_uint32(buf, sizeof(buf), &offset, ASN1_TAG_INTEGER, &value);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should reject tag mismatch");
    TEST_PASS();
}

static void test_ber_decode_utctime_null_buffer(void)
{
    size_t offset = 0;
    uint64_t value;
    int ret = ber_decode_utctime(NULL, 100, &offset, ASN1_TAG_UTCTIME, &value, NULL);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL buffer");
    TEST_PASS();
}

static void test_ber_decode_utctime_null_offset(void)
{
    uint8_t buf[20] = {0x17, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    uint64_t value;
    int ret = ber_decode_utctime(buf, sizeof(buf), NULL, ASN1_TAG_UTCTIME, &value, NULL);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL offset");
    TEST_PASS();
}

static void test_ber_decode_utctime_null_output(void)
{
    uint8_t buf[20] = {0x17, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    size_t offset = 0;
    int ret = ber_decode_utctime(buf, sizeof(buf), &offset, ASN1_TAG_UTCTIME, NULL, NULL);
    TEST_ASSERT(ret == GOOSE_BER_ERR_INVALID_ARG, "Should reject NULL value output");
    TEST_PASS();
}

static void test_ber_decode_utctime_buffer_underflow(void)
{
    uint8_t buf[4] = {0x17, 0x08, 0x00, 0x00};  // Says length=8 but not enough data
    size_t offset = 0;
    uint64_t value;
    int ret = ber_decode_utctime(buf, sizeof(buf), &offset, ASN1_TAG_UTCTIME, &value, NULL);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should detect buffer underflow");
    TEST_PASS();
}

static void test_ber_decode_utctime_tag_mismatch(void)
{
    uint8_t buf[20] = {0x80, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};  // Wrong tag
    size_t offset = 0;
    uint64_t value;
    int ret = ber_decode_utctime(buf, sizeof(buf), &offset, ASN1_TAG_UTCTIME, &value, NULL);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should reject tag mismatch");
    TEST_PASS();
}

static void test_ber_decode_length_too_many_bytes(void)
{
    uint8_t buf[20] = {0x89, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};  // 9 length bytes (too many)
    size_t offset = 0;
    size_t length;
    int ret = ber_decode_length(buf, sizeof(buf), &offset, &length);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should reject length encoding with too many bytes");
    TEST_PASS();
}

static void test_ber_decode_int32_zero_length(void)
{
    uint8_t buf[10] = {0x02, 0x00, 0, 0, 0, 0, 0, 0, 0, 0};  // 0-length int (invalid)
    size_t offset = 0;
    int32_t value;
    int ret = ber_decode_int32(buf, sizeof(buf), &offset, ASN1_TAG_INTEGER, &value);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should reject 0-length integer");
    TEST_PASS();
}

static void test_ber_decode_uint32_zero_length(void)
{
    uint8_t buf[10] = {0x02, 0x00, 0, 0, 0, 0, 0, 0, 0, 0};  // 0-length int (invalid)
    size_t offset = 0;
    uint32_t value;
    int ret = ber_decode_uint32(buf, sizeof(buf), &offset, ASN1_TAG_INTEGER, &value);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should reject 0-length integer");
    TEST_PASS();
}

static void test_ber_decode_uint32_wrong_length(void)
{
    uint8_t buf[10] = {0x02, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0, 0};  // 6-byte uint (invalid)
    size_t offset = 0;
    uint32_t value;
    int ret = ber_decode_uint32(buf, sizeof(buf), &offset, ASN1_TAG_INTEGER, &value);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should reject 6-byte unsigned integer");
    TEST_PASS();
}

static void test_ber_decode_utctime_wrong_length(void)
{
    uint8_t buf[20] = {0x17, 0x09, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};  // 9-byte time (invalid)
    size_t offset = 0;
    uint64_t value;
    int ret = ber_decode_utctime(buf, sizeof(buf), &offset, ASN1_TAG_UTCTIME, &value, NULL);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should reject 9-byte utctime");
    TEST_PASS();
}

static void test_ber_decode_visiblestring_zero_length(void)
{
    uint8_t buf[10] = {0x1A, 0x00, 0, 0, 0, 0, 0, 0, 0, 0};  // 0-length string
    size_t offset = 0;
    char str[10];
    int ret = ber_decode_visiblestring(buf, sizeof(buf), &offset, ASN1_TAG_VISIBLESTRING, str, sizeof(str));
    (void)ret;  // Intentionally unused - just verify no crash
    // May succeed or fail depending on implementation
    TEST_PASS();
}

static void test_ber_decode_int32_at_buffer_edge(void)
{
    uint8_t buf[6] = {0x02, 0x04, 0x00, 0x00, 0x30, 0x39};  // Exactly fills buffer
    size_t offset = 0;
    int32_t value;
    int ret = ber_decode_int32(buf, sizeof(buf), &offset, ASN1_TAG_INTEGER, &value);
    TEST_ASSERT(ret == GOOSE_BER_OK, "Should decode int32 at buffer edge");
    TEST_ASSERT(value == 12345, "Value should be 12345");
    TEST_PASS();
}

static void test_ber_decode_boolean_zero_length(void)
{
    uint8_t buf[10] = {0x01, 0x00, 0, 0, 0, 0, 0, 0, 0, 0};  // 0-length boolean (invalid)
    size_t offset = 0;
    bool value;
    int ret = ber_decode_boolean(buf, sizeof(buf), &offset, ASN1_TAG_BOOLEAN, &value);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should reject 0-length boolean");
    TEST_PASS();
}

static void test_ber_decode_length_insufficient_bytes_for_long_form(void)
{
    uint8_t buf[2] = {0x82, 0x01};  // Says 2 length bytes follow, but only 1 present
    size_t offset = 0;
    size_t length;
    int ret = ber_decode_length(buf, sizeof(buf), &offset, &length);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should detect insufficient bytes for long-form length");
    TEST_PASS();
}

static void test_ber_decode_int32_offset_at_buffer_end(void)
{
    uint8_t buf[10] = {0x02, 0x04, 0x00, 0x00, 0x30, 0x39, 0, 0, 0, 0};
    size_t offset = sizeof(buf);  // Offset at end - tag decode will fail
    int32_t value;
    int ret = ber_decode_int32(buf, sizeof(buf), &offset, ASN1_TAG_INTEGER, &value);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should fail when offset at buffer end");
    TEST_PASS();
}

static void test_ber_decode_uint32_offset_at_buffer_end(void)
{
    uint8_t buf[10] = {0x02, 0x04, 0x00, 0x00, 0x30, 0x39, 0, 0, 0, 0};
    size_t offset = sizeof(buf);  // Offset at end
    uint32_t value;
    int ret = ber_decode_uint32(buf, sizeof(buf), &offset, ASN1_TAG_INTEGER, &value);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should fail when offset at buffer end");
    TEST_PASS();
}

static void test_ber_decode_boolean_offset_at_buffer_end(void)
{
    uint8_t buf[10] = {0x01, 0x01, 0xFF, 0, 0, 0, 0, 0, 0, 0};
    size_t offset = sizeof(buf);  // Offset at end
    bool value;
    int ret = ber_decode_boolean(buf, sizeof(buf), &offset, ASN1_TAG_BOOLEAN, &value);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should fail when offset at buffer end");
    TEST_PASS();
}

static void test_ber_decode_visiblestring_offset_at_buffer_end(void)
{
    uint8_t buf[10] = {0x1A, 0x04, 'T', 'E', 'S', 'T', 0, 0, 0, 0};
    size_t offset = sizeof(buf);  // Offset at end
    char str[10];
    int ret = ber_decode_visiblestring(buf, sizeof(buf), &offset, ASN1_TAG_VISIBLESTRING, str, sizeof(str));
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should fail when offset at buffer end");
    TEST_PASS();
}

static void test_ber_decode_utctime_offset_at_buffer_end(void)
{
    uint8_t buf[20] = {0x17, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    size_t offset = sizeof(buf);  // Offset at end
    uint64_t value;
    int ret = ber_decode_utctime(buf, sizeof(buf), &offset, ASN1_TAG_UTCTIME, &value, NULL);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should fail when offset at buffer end");
    TEST_PASS();
}

static void test_ber_decode_int32_offset_after_tag(void)
{
    uint8_t buf[10] = {0x02, 0x04, 0x00, 0x00, 0x30, 0x39, 0, 0, 0, 0};
    size_t offset = 1;  // Skip tag - length decode will trigger error propagation
    int32_t value;
    // This will fail because it expects the tag at offset, but finds length byte
    int ret = ber_decode_int32(buf, sizeof(buf), &offset, ASN1_TAG_INTEGER, &value);
    TEST_ASSERT(ret != GOOSE_BER_OK, "Should fail with mismatched tag");
    TEST_PASS();
}

/***************************************************************************
 * Main Test Runner
 ***************************************************************************/

int main(void)
{
    printf("Running low-level BER error path tests...\n");
    printf("=========================================\n\n");

    /* Encoder tests */
    printf("BER encoder error paths:\n");
    test_ber_encode_tag_null_buffer();
    test_ber_encode_tag_null_offset();
    test_ber_encode_tag_buffer_full();
    test_ber_encode_length_null_buffer();
    test_ber_encode_length_null_offset();
    test_ber_encode_length_short_form_overflow();
    test_ber_encode_length_long_form_1byte_overflow();
    test_ber_encode_length_long_form_2byte_overflow();
    test_ber_encode_length_too_large();
    test_ber_encode_int32_null_buffer();
    test_ber_encode_int32_null_offset();
    test_ber_encode_int32_buffer_overflow();
    test_ber_encode_int32_overflow_after_tag();
    test_ber_encode_int32_overflow_after_length();
    test_ber_encode_uint32_null_buffer();
    test_ber_encode_uint32_null_offset();
    test_ber_encode_uint32_overflow_after_tag();
    test_ber_encode_boolean_null_buffer();
    test_ber_encode_boolean_null_offset();
    test_ber_encode_boolean_buffer_overflow();
    test_ber_encode_boolean_overflow_after_tag();
    test_ber_encode_visiblestring_null_buffer();
    test_ber_encode_visiblestring_null_offset();
    test_ber_encode_visiblestring_null_str();
    test_ber_encode_visiblestring_buffer_overflow();
    test_ber_encode_visiblestring_overflow_after_tag();
    test_ber_encode_visiblestring_overflow_after_length();
    test_ber_encode_utctime_null_buffer();
    test_ber_encode_utctime_null_offset();
    test_ber_encode_utctime_overflow_after_tag();
    printf("\n");

    /* Decoder tests */
    printf("BER decoder error paths:\n");
    test_ber_decode_tag_null_buffer();
    test_ber_decode_tag_null_offset();
    test_ber_decode_tag_null_output();
    test_ber_decode_tag_buffer_underflow();
    test_ber_decode_tag_mismatch();
    test_ber_decode_length_null_buffer();
    test_ber_decode_length_null_offset();
    test_ber_decode_length_null_output();
    test_ber_decode_length_buffer_underflow();
    test_ber_decode_length_long_form_underflow();
    test_ber_decode_int32_null_buffer();
    test_ber_decode_int32_null_offset();
    test_ber_decode_int32_null_output();
    test_ber_decode_int32_buffer_underflow();
    test_ber_decode_int32_tag_mismatch();
    test_ber_decode_int32_wrong_length();
    test_ber_decode_boolean_null_buffer();
    test_ber_decode_boolean_null_offset();
    test_ber_decode_boolean_null_output();
    test_ber_decode_boolean_buffer_underflow();
    test_ber_decode_boolean_tag_mismatch();
    test_ber_decode_boolean_wrong_length();
    test_ber_decode_visiblestring_null_buffer();
    test_ber_decode_visiblestring_null_offset();
    test_ber_decode_visiblestring_null_output();
    test_ber_decode_visiblestring_buffer_underflow();
    test_ber_decode_visiblestring_tag_mismatch();
    test_ber_decode_visiblestring_output_buffer_too_small();
    test_ber_decode_uint32_null_buffer();
    test_ber_decode_uint32_null_offset();
    test_ber_decode_uint32_null_output();
    test_ber_decode_uint32_buffer_underflow();
    test_ber_decode_uint32_tag_mismatch();
    test_ber_decode_utctime_null_buffer();
    test_ber_decode_utctime_null_offset();
    test_ber_decode_utctime_null_output();
    test_ber_decode_utctime_buffer_underflow();
    test_ber_decode_utctime_tag_mismatch();
    test_ber_decode_utctime_wrong_length();
    test_ber_decode_length_too_many_bytes();
    test_ber_decode_length_insufficient_bytes_for_long_form();
    test_ber_decode_int32_zero_length();
    test_ber_decode_int32_at_buffer_edge();
    test_ber_decode_uint32_zero_length();
    test_ber_decode_uint32_wrong_length();
    test_ber_decode_boolean_zero_length();
    test_ber_decode_visiblestring_zero_length();
    test_ber_decode_int32_offset_at_buffer_end();
    test_ber_decode_uint32_offset_at_buffer_end();
    test_ber_decode_boolean_offset_at_buffer_end();
    test_ber_decode_visiblestring_offset_at_buffer_end();
    test_ber_decode_utctime_offset_at_buffer_end();
    test_ber_decode_int32_offset_after_tag();
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
