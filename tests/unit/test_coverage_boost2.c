/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Coverage Boost Tests — Part 2
 *
 * Targets uncovered code paths in:
 *   - goose_ber_decode.c: allData type dispatch, security decode, error paths
 *   - goose_ber.c: encode with all data types, buffer overflow, structure
 *   - key_manager.c: sign/verify lifecycle with generated RSA key
 *   - mms_report.c: RCB lifecycle, trigger evaluation, report generation
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>

#include "asn1/goose_ber.h"
#include "asn1/goose_ber_decode.h"
#include "mms/mms_report.h"

#ifdef IEC61850_SECURITY_ENABLED
#include "security/key_manager.h"
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#endif

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
 * Target 1: goose_ber_decode.c error/edge paths
 ***************************************************************************/

/* Test ber_decode_tag/length NULL args and boundary */
static void test_decode_tag_null_args(void)
{
    uint8_t buf[] = {0x80};
    size_t offset = 0;
    uint8_t tag = 0;

    TEST_ASSERT(ber_decode_tag(NULL, 1, &offset, &tag) == GOOSE_BER_ERR_INVALID_ARG,
                "NULL buf should fail");
    TEST_ASSERT(ber_decode_tag(buf, 1, NULL, &tag) == GOOSE_BER_ERR_INVALID_ARG,
                "NULL offset should fail");
    TEST_ASSERT(ber_decode_tag(buf, 1, &offset, NULL) == GOOSE_BER_ERR_INVALID_ARG,
                "NULL tag should fail");

    /* Offset past end */
    offset = 5;
    TEST_ASSERT(ber_decode_tag(buf, 1, &offset, &tag) == GOOSE_BER_ERR_BUFFER_FULL,
                "offset past end should fail");
    TEST_PASS();
}

static void test_decode_length_long_form(void)
{
    /* Long form: 0x81 0xFF = 255 */
    uint8_t buf[] = {0x81, 0xFF};
    size_t offset = 0;
    size_t length = 0;

    int ret = ber_decode_length(buf, sizeof(buf), &offset, &length);
    TEST_ASSERT(ret == GOOSE_BER_OK, "long form decode should succeed");
    TEST_ASSERT(length == 255, "length should be 255");

    /* Long form with too many bytes */
    uint8_t bad[] = {0x89, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
    offset = 0;
    ret = ber_decode_length(bad, sizeof(bad), &offset, &length);
    TEST_ASSERT(ret == GOOSE_BER_ERR_ENCODING, "too many length bytes should fail");

    /* Long form with insufficient data */
    uint8_t short_buf[] = {0x82};
    offset = 0;
    ret = ber_decode_length(short_buf, sizeof(short_buf), &offset, &length);
    TEST_ASSERT(ret == GOOSE_BER_ERR_ENCODING, "truncated long form should fail");

    /* NULL args */
    TEST_ASSERT(ber_decode_length(NULL, 1, &offset, &length) == GOOSE_BER_ERR_INVALID_ARG,
                "NULL buf should fail");
    TEST_PASS();
}

static void test_decode_int32_edge_cases(void)
{
    /* Negative value: -1 encoded as 0x85 0x01 0xFF */
    uint8_t neg_buf[] = {0x85, 0x01, 0xFF};
    size_t offset = 0;
    int32_t val = 0;

    int ret = ber_decode_int32(neg_buf, sizeof(neg_buf), &offset, 0x85, &val);
    TEST_ASSERT(ret == GOOSE_BER_OK, "decode -1 should succeed");
    TEST_ASSERT(val == -1, "value should be -1");

    /* Zero-length integer */
    uint8_t zero_len[] = {0x85, 0x00};
    offset = 0;
    ret = ber_decode_int32(zero_len, sizeof(zero_len), &offset, 0x85, &val);
    TEST_ASSERT(ret == GOOSE_BER_ERR_ENCODING, "zero length int should fail");

    /* Too-long integer (>4 bytes) */
    uint8_t long_int[] = {0x85, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05};
    offset = 0;
    ret = ber_decode_int32(long_int, sizeof(long_int), &offset, 0x85, &val);
    TEST_ASSERT(ret == GOOSE_BER_ERR_ENCODING, "5-byte int should fail");

    /* Wrong tag */
    uint8_t wrong_tag[] = {0x86, 0x01, 0x42};
    offset = 0;
    ret = ber_decode_int32(wrong_tag, sizeof(wrong_tag), &offset, 0x85, &val);
    TEST_ASSERT(ret == GOOSE_BER_ERR_ENCODING, "wrong tag should fail");

    /* NULL args */
    offset = 0;
    TEST_ASSERT(ber_decode_int32(NULL, 3, &offset, 0x85, &val) ==
                GOOSE_BER_ERR_INVALID_ARG, "NULL buf");
    TEST_PASS();
}

static void test_decode_uint32_edge_cases(void)
{
    /* uint32 with length overflow beyond buffer */
    uint8_t overflow[] = {0x86, 0x04, 0x01, 0x02};  /* says 4 bytes but only 2 available */
    size_t offset = 0;
    uint32_t val = 0;

    int ret = ber_decode_uint32(overflow, sizeof(overflow), &offset, 0x86, &val);
    TEST_ASSERT(ret == GOOSE_BER_ERR_ENCODING, "overflow should fail");

    /* uint32 with 5 bytes (max for unsigned with leading zero) */
    uint8_t five_bytes[] = {0x86, 0x05, 0x00, 0xFF, 0xFF, 0xFF, 0xFF};
    offset = 0;
    ret = ber_decode_uint32(five_bytes, sizeof(five_bytes), &offset, 0x86, &val);
    TEST_ASSERT(ret == GOOSE_BER_OK, "5-byte uint32 should succeed");
    TEST_ASSERT(val == 0xFFFFFFFF, "value should be 0xFFFFFFFF");

    /* uint32 too long (6 bytes) */
    uint8_t six_bytes[] = {0x86, 0x06, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    offset = 0;
    ret = ber_decode_uint32(six_bytes, sizeof(six_bytes), &offset, 0x86, &val);
    TEST_ASSERT(ret == GOOSE_BER_ERR_ENCODING, "6-byte uint32 should fail");

    /* Wrong tag for uint32 */
    uint8_t wrong[] = {0x85, 0x01, 0x01};
    offset = 0;
    ret = ber_decode_uint32(wrong, sizeof(wrong), &offset, 0x86, &val);
    TEST_ASSERT(ret == GOOSE_BER_ERR_ENCODING, "wrong tag should fail");
    TEST_PASS();
}

/* Build a valid GOOSE APDU with all data types for decode testing */
static size_t build_goose_apdu_all_types(uint8_t *buf, size_t buf_size)
{
    goose_apdu_t apdu;
    goose_apdu_init(&apdu);
    goose_set_gocbref(&apdu, "TestRef");
    goose_set_datset(&apdu, "TestDatSet");
    goose_set_goid(&apdu, "TestGoID");
    apdu.timestamp = 1000000ULL;
    apdu.stNum = 1;
    apdu.sqNum = 0;

    /* Add all data types */
    goose_add_boolean(&apdu, true);
    goose_add_int32(&apdu, -42);
    goose_add_uint32(&apdu, 12345);
    goose_add_float32(&apdu, 3.14f);

    uint8_t bs_data[] = {0xAA, 0xBB};
    goose_add_bitstring(&apdu, bs_data, 2);

    uint8_t os_data[] = {0x01, 0x02, 0x03};
    goose_add_octetstring(&apdu, os_data, 3);

    goose_add_visiblestring(&apdu, "hello");
    goose_add_utctime(&apdu, 2000000ULL, 0x0A);

    /* Add a structure with one boolean sub-element */
    goose_data_t sub_elems[1];
    sub_elems[0].type = GOOSE_DATA_BOOLEAN;
    sub_elems[0].value.boolean = false;
    goose_add_structure(&apdu, sub_elems, 1);

    size_t encoded_len = 0;
    int ret = goose_encode_apdu(buf, buf_size, &apdu, &encoded_len);
    if (ret != GOOSE_BER_OK) {
        return 0;
    }
    return encoded_len;
}

static void test_decode_apdu_all_types(void)
{
    uint8_t buf[1024];
    size_t len = build_goose_apdu_all_types(buf, sizeof(buf));
    TEST_ASSERT(len > 0, "encode should succeed");

    goose_apdu_t apdu;
    int ret = goose_decode_apdu(buf, len, &apdu);
    TEST_ASSERT(ret == GOOSE_BER_OK, "decode should succeed");
    TEST_ASSERT(strcmp(apdu.gocbRef, "TestRef") == 0, "gocbRef should match");
    TEST_ASSERT(strcmp(apdu.datSet, "TestDatSet") == 0, "datSet should match");
    TEST_ASSERT(apdu.has_goID == true, "should have goID");
    TEST_ASSERT(strcmp(apdu.goID, "TestGoID") == 0, "goID should match");
    TEST_ASSERT(apdu.numDatSetEntries == 9, "should have 9 data entries");

    /* Verify data types */
    TEST_ASSERT(apdu.allData[0].type == GOOSE_DATA_BOOLEAN, "type 0 boolean");
    TEST_ASSERT(apdu.allData[0].value.boolean == true, "boolean true");
    TEST_ASSERT(apdu.allData[1].type == GOOSE_DATA_INT32, "type 1 int32");
    TEST_ASSERT(apdu.allData[1].value.int32 == -42, "int32 -42");
    TEST_ASSERT(apdu.allData[2].type == GOOSE_DATA_UINT32, "type 2 uint32");
    TEST_ASSERT(apdu.allData[2].value.uint32 == 12345, "uint32 12345");
    TEST_ASSERT(apdu.allData[3].type == GOOSE_DATA_FLOAT32, "type 3 float32");
    TEST_ASSERT(apdu.allData[4].type == GOOSE_DATA_BITSTRING, "type 4 bitstring");
    TEST_ASSERT(apdu.allData[5].type == GOOSE_DATA_OCTETSTRING, "type 5 octetstring");
    TEST_ASSERT(apdu.allData[6].type == GOOSE_DATA_VISIBLESTRING, "type 6 visiblestring");
    TEST_ASSERT(apdu.allData[7].type == GOOSE_DATA_UTCTIME, "type 7 utctime");
    TEST_ASSERT(apdu.allData[8].type == GOOSE_DATA_STRUCTURE, "type 8 structure");
    TEST_PASS();
}

static void test_decode_apdu_truncated(void)
{
    uint8_t buf[1024];
    size_t len = build_goose_apdu_all_types(buf, sizeof(buf));
    TEST_ASSERT(len > 0, "encode should succeed");

    goose_apdu_t apdu;

    /* Empty buffer */
    TEST_ASSERT(goose_decode_apdu(buf, 0, &apdu) != GOOSE_BER_OK,
                "empty buffer should fail");

    /* Just the APDU tag, no length */
    TEST_ASSERT(goose_decode_apdu(buf, 1, &apdu) != GOOSE_BER_OK,
                "1 byte should fail");

    /* Truncated in the middle of fields */
    TEST_ASSERT(goose_decode_apdu(buf, 10, &apdu) != GOOSE_BER_OK,
                "truncated in gocbRef should fail");

    /* NULL args */
    TEST_ASSERT(goose_decode_apdu(NULL, len, &apdu) == GOOSE_BER_ERR_INVALID_ARG,
                "NULL buf should fail");
    TEST_ASSERT(goose_decode_apdu(buf, len, NULL) == GOOSE_BER_ERR_INVALID_ARG,
                "NULL apdu should fail");

    /* Wrong APDU tag */
    uint8_t bad_tag[] = {0x62, 0x00};
    TEST_ASSERT(goose_decode_apdu(bad_tag, sizeof(bad_tag), &apdu) ==
                GOOSE_BER_ERR_ENCODING, "wrong APDU tag should fail");
    TEST_PASS();
}

static void test_decode_apdu_ex(void)
{
    uint8_t buf[1024];
    size_t len = build_goose_apdu_all_types(buf, sizeof(buf));
    TEST_ASSERT(len > 0, "encode should succeed");

    goose_apdu_t apdu;
    size_t consumed = 0;

    /* NULL consumed */
    TEST_ASSERT(goose_decode_apdu_ex(buf, len, &apdu, NULL) ==
                GOOSE_BER_ERR_INVALID_ARG, "NULL consumed should fail");

    /* Valid decode */
    int ret = goose_decode_apdu_ex(buf, len, &apdu, &consumed);
    TEST_ASSERT(ret == GOOSE_BER_OK, "decode_ex should succeed");
    TEST_ASSERT(consumed == len, "consumed should equal encoded length");
    TEST_PASS();
}

/* Build a fake security extension and decode it */
static void test_decode_security(void)
{
    /* Build security extension:
     * [12] CONSTRUCTED {
     *   [0] algo (uint32)
     *   [1] keyID (octet string, 4 bytes)
     *   [2] timestamp (utctime, 8 bytes)
     *   [3] signature (octet string, variable)
     * }
     */
    uint8_t sec_buf[128];
    size_t offset = 0;

    /* Tag: 0xAC (GOOSE_TAG_SECURITY) */
    sec_buf[offset++] = 0xAC;

    /* We'll fill in the length after encoding content */
    size_t len_pos = offset;
    offset++;  /* reserve 1 byte for length (short form) */
    size_t content_start = offset;

    /* [0] algo = 1 (RSA-PSS) */
    sec_buf[offset++] = 0x80;  /* GOOSE_TAG_SECURITY_ALGO */
    sec_buf[offset++] = 0x01;
    sec_buf[offset++] = 0x01;

    /* [1] keyID = 4 bytes */
    sec_buf[offset++] = 0x81;  /* GOOSE_TAG_SECURITY_KEYID */
    sec_buf[offset++] = 0x04;
    sec_buf[offset++] = 0xDE;
    sec_buf[offset++] = 0xAD;
    sec_buf[offset++] = 0xBE;
    sec_buf[offset++] = 0xEF;

    /* [2] timestamp (utctime 8 bytes) */
    sec_buf[offset++] = 0x82;  /* GOOSE_TAG_SECURITY_TIMESTAMP */
    sec_buf[offset++] = 0x08;
    /* seconds=1000 big-endian */
    sec_buf[offset++] = 0x00;
    sec_buf[offset++] = 0x00;
    sec_buf[offset++] = 0x03;
    sec_buf[offset++] = 0xE8;
    /* fraction=0 */
    sec_buf[offset++] = 0x00;
    sec_buf[offset++] = 0x00;
    sec_buf[offset++] = 0x00;
    /* quality=0 */
    sec_buf[offset++] = 0x00;

    /* [3] signature = 8 bytes */
    sec_buf[offset++] = 0x83;  /* GOOSE_TAG_SECURITY_SIGNATURE */
    sec_buf[offset++] = 0x08;
    for (int i = 0; i < 8; i++) {
        sec_buf[offset++] = (uint8_t)(0x10 + i);
    }

    /* Fill in length */
    sec_buf[len_pos] = (uint8_t)(offset - content_start);

    goose_apdu_t apdu;
    goose_apdu_init(&apdu);
    size_t sec_offset = 0;

    int ret = goose_decode_security(sec_buf, offset, &sec_offset, &apdu);
    TEST_ASSERT(ret == GOOSE_BER_OK, "security decode should succeed");
    TEST_ASSERT(apdu.secure == true, "secure flag should be set");
    TEST_ASSERT(apdu.signature_algo == GOOSE_SIGNATURE_RSA_PSS, "algo should be RSA-PSS");
    TEST_ASSERT(apdu.key_id[0] == 0xDE, "keyID byte 0");
    TEST_ASSERT(apdu.key_id[3] == 0xEF, "keyID byte 3");
    TEST_ASSERT(apdu.signature_len == 8, "sig len should be 8");
    TEST_ASSERT(apdu.signature[0] == 0x10, "sig byte 0");
    TEST_PASS();
}

static void test_decode_security_absent(void)
{
    goose_apdu_t apdu;
    goose_apdu_init(&apdu);

    /* No data at all — security is optional */
    uint8_t empty[] = {0x00};
    size_t offset = 1;  /* past end */
    int ret = goose_decode_security(empty, 1, &offset, &apdu);
    TEST_ASSERT(ret == GOOSE_BER_OK, "no security data should be OK");
    TEST_ASSERT(apdu.secure == false, "secure should be false");

    /* Data present but not security tag */
    uint8_t non_sec[] = {0x80, 0x01, 0x00};
    offset = 0;
    ret = goose_decode_security(non_sec, sizeof(non_sec), &offset, &apdu);
    TEST_ASSERT(ret == GOOSE_BER_OK, "non-security tag should be OK");
    TEST_ASSERT(apdu.secure == false, "secure should remain false");

    /* NULL args */
    offset = 0;
    TEST_ASSERT(goose_decode_security(NULL, 1, &offset, &apdu) ==
                GOOSE_BER_ERR_INVALID_ARG, "NULL buf");
    TEST_ASSERT(goose_decode_security(non_sec, 3, NULL, &apdu) ==
                GOOSE_BER_ERR_INVALID_ARG, "NULL offset");
    TEST_ASSERT(goose_decode_security(non_sec, 3, &offset, NULL) ==
                GOOSE_BER_ERR_INVALID_ARG, "NULL apdu");
    TEST_PASS();
}

static void test_decode_security_malformed(void)
{
    goose_apdu_t apdu;
    goose_apdu_init(&apdu);

    /* Security tag with length exceeding buffer */
    uint8_t bad_len[] = {0xAC, 0xFF};
    size_t offset = 0;
    int ret = goose_decode_security(bad_len, sizeof(bad_len), &offset, &apdu);
    TEST_ASSERT(ret != GOOSE_BER_OK, "bad length should fail");

    /* Security tag with wrong algo tag inside */
    uint8_t bad_algo[] = {0xAC, 0x03, 0x81, 0x01, 0x01};  /* wrong inner tag 0x81 instead of 0x80 */
    offset = 0;
    ret = goose_decode_security(bad_algo, sizeof(bad_algo), &offset, &apdu);
    TEST_ASSERT(ret != GOOSE_BER_OK, "wrong inner tag should fail");

    /* Security tag with wrong keyID length (3 instead of 4) */
    uint8_t bad_keyid[] = {
        0xAC, 0x08,
        0x80, 0x01, 0x01,              /* algo=1 */
        0x81, 0x03, 0xDE, 0xAD, 0xBE  /* keyID 3 bytes instead of 4 */
    };
    offset = 0;
    ret = goose_decode_security(bad_keyid, sizeof(bad_keyid), &offset, &apdu);
    TEST_ASSERT(ret == GOOSE_BER_ERR_ENCODING, "wrong keyID length should fail");
    TEST_PASS();
}

static void test_decode_octetstring(void)
{
    /* Valid octet string */
    uint8_t buf[] = {0x81, 0x03, 0xAA, 0xBB, 0xCC};
    size_t offset = 0;
    uint8_t data[16];
    size_t actual_len = 0;

    int ret = ber_decode_octetstring(buf, sizeof(buf), &offset, 0x81,
                                     data, sizeof(data), &actual_len);
    TEST_ASSERT(ret == GOOSE_BER_OK, "decode octetstring should succeed");
    TEST_ASSERT(actual_len == 3, "length should be 3");
    TEST_ASSERT(data[0] == 0xAA, "byte 0");

    /* Buffer too small */
    offset = 0;
    uint8_t small[2];
    ret = ber_decode_octetstring(buf, sizeof(buf), &offset, 0x81,
                                 small, 2, &actual_len);
    TEST_ASSERT(ret == GOOSE_BER_ERR_BUFFER_FULL, "small buffer should fail");

    /* Data extends past buffer */
    uint8_t trunc[] = {0x81, 0x05, 0xAA, 0xBB};  /* says 5 bytes but only 2 available */
    offset = 0;
    ret = ber_decode_octetstring(trunc, sizeof(trunc), &offset, 0x81,
                                 data, sizeof(data), &actual_len);
    TEST_ASSERT(ret == GOOSE_BER_ERR_BUFFER_FULL, "truncated data should fail");

    /* NULL args */
    offset = 0;
    TEST_ASSERT(ber_decode_octetstring(NULL, 5, &offset, 0x81, data, 16, &actual_len) ==
                GOOSE_BER_ERR_INVALID_ARG, "NULL buf");
    TEST_ASSERT(ber_decode_octetstring(buf, 5, &offset, 0x81, data, 16, NULL) ==
                GOOSE_BER_ERR_INVALID_ARG, "NULL actual_len");

    /* Offset past end */
    offset = 100;
    TEST_ASSERT(ber_decode_octetstring(buf, sizeof(buf), &offset, 0x81,
                                       data, sizeof(data), &actual_len) ==
                GOOSE_BER_ERR_BUFFER_FULL, "offset past end");

    /* Wrong tag */
    offset = 0;
    TEST_ASSERT(ber_decode_octetstring(buf, sizeof(buf), &offset, 0x82,
                                       data, sizeof(data), &actual_len) ==
                GOOSE_BER_ERR_ENCODING, "wrong tag");
    TEST_PASS();
}

/* Test allData with various malformed data elements */
static void test_decode_alldata_error_paths(void)
{
    goose_data_t data[16];
    size_t count = 0;

    /* NULL args */
    size_t offset = 0;
    TEST_ASSERT(goose_decode_alldata(NULL, 10, &offset, data, 16, &count) ==
                GOOSE_BER_ERR_INVALID_ARG, "NULL buf");

    /* Wrong allData tag */
    uint8_t wrong_tag[] = {0xAA, 0x00};  /* wrong tag */
    offset = 0;
    int ret = goose_decode_alldata(wrong_tag, sizeof(wrong_tag), &offset,
                                    data, 16, &count);
    TEST_ASSERT(ret == GOOSE_BER_ERR_ENCODING, "wrong allData tag");

    /* allData with length exceeding buffer */
    uint8_t bad_len[] = {0xAB, 0xFF};
    offset = 0;
    ret = goose_decode_alldata(bad_len, sizeof(bad_len), &offset,
                                data, 16, &count);
    TEST_ASSERT(ret == GOOSE_BER_ERR_ENCODING, "length overflow");

    /* allData length decode failure (truncated long form) */
    uint8_t trunc_len[] = {0xAB, 0x82};
    offset = 0;
    ret = goose_decode_alldata(trunc_len, sizeof(trunc_len), &offset,
                                data, 16, &count);
    TEST_ASSERT(ret != GOOSE_BER_OK, "truncated length should fail");

    /* Empty allData (valid) */
    uint8_t empty[] = {0xAB, 0x00};
    offset = 0;
    ret = goose_decode_alldata(empty, sizeof(empty), &offset,
                                data, 16, &count);
    TEST_ASSERT(ret == GOOSE_BER_OK, "empty allData should succeed");
    TEST_ASSERT(count == 0, "count should be 0");
    TEST_PASS();
}

/* Test allData with an unknown data type tag */
static void test_decode_alldata_unknown_type(void)
{
    /* allData with unknown type tag 0x8F (context [15]) */
    uint8_t buf[] = {
        0xAB, 0x04,           /* allData tag + length=4 */
        0x8F, 0x02, 0x01, 0x02  /* unknown type [15], length 2, data */
    };
    goose_data_t data[16];
    size_t count = 0;
    size_t offset = 0;

    int ret = goose_decode_alldata(buf, sizeof(buf), &offset, data, 16, &count);
    TEST_ASSERT(ret == GOOSE_BER_OK, "unknown type should be skipped");
    TEST_ASSERT(count == 0, "no decoded elements for unknown type");
    TEST_PASS();
}

/***************************************************************************
 * Target 2: goose_ber.c encode error/edge paths
 ***************************************************************************/

static void test_encode_apdu_all_types(void)
{
    uint8_t buf[1024];
    size_t len = build_goose_apdu_all_types(buf, sizeof(buf));
    TEST_ASSERT(len > 0, "encode with all types should succeed");
    /* Verify it can be decoded back */
    goose_apdu_t decoded;
    int ret = goose_decode_apdu(buf, len, &decoded);
    TEST_ASSERT(ret == GOOSE_BER_OK, "round-trip decode should succeed");
    TEST_PASS();
}

static void test_encode_apdu_buffer_too_small(void)
{
    goose_apdu_t apdu;
    goose_apdu_init(&apdu);
    goose_set_gocbref(&apdu, "TestRef");
    goose_set_datset(&apdu, "TestDatSet");
    apdu.timestamp = 1000000ULL;
    goose_add_boolean(&apdu, true);

    uint8_t buf[4];  /* Way too small */
    size_t encoded_len = 0;
    int ret = goose_encode_apdu(buf, sizeof(buf), &apdu, &encoded_len);
    TEST_ASSERT(ret != GOOSE_BER_OK, "tiny buffer should fail");

    /* Various sizes to hit different overflow points */
    uint8_t buf2[16];
    ret = goose_encode_apdu(buf2, sizeof(buf2), &apdu, &encoded_len);
    TEST_ASSERT(ret != GOOSE_BER_OK, "small buffer should fail");

    uint8_t buf3[32];
    ret = goose_encode_apdu(buf3, sizeof(buf3), &apdu, &encoded_len);
    TEST_ASSERT(ret != GOOSE_BER_OK, "medium-small buffer should fail");
    TEST_PASS();
}

static void test_encode_apdu_null_args(void)
{
    goose_apdu_t apdu;
    goose_apdu_init(&apdu);
    uint8_t buf[256];
    size_t encoded_len = 0;

    TEST_ASSERT(goose_encode_apdu(NULL, 256, &apdu, &encoded_len) ==
                GOOSE_BER_ERR_INVALID_ARG, "NULL buf");
    TEST_ASSERT(goose_encode_apdu(buf, 256, NULL, &encoded_len) ==
                GOOSE_BER_ERR_INVALID_ARG, "NULL apdu");
    TEST_ASSERT(goose_encode_apdu(buf, 256, &apdu, NULL) ==
                GOOSE_BER_ERR_INVALID_ARG, "NULL encoded_len");
    TEST_PASS();
}

static void test_encode_alldata_null_args(void)
{
    uint8_t buf[64];
    size_t offset = 0;
    goose_data_t data[1];
    data[0].type = GOOSE_DATA_BOOLEAN;
    data[0].value.boolean = true;

    TEST_ASSERT(goose_encode_alldata(NULL, 64, &offset, data, 1) ==
                GOOSE_BER_ERR_INVALID_ARG, "NULL buf");
    TEST_ASSERT(goose_encode_alldata(buf, 64, &offset, NULL, 1) ==
                GOOSE_BER_ERR_INVALID_ARG, "NULL data");

    /* Too many entries */
    TEST_ASSERT(goose_encode_alldata(buf, 64, &offset, data,
                                      GOOSE_MAX_ALLDATA_ENTRIES + 1) ==
                GOOSE_BER_ERR_INVALID_ARG, "too many entries");
    TEST_PASS();
}

static void test_encode_long_form_length(void)
{
    /* Build an APDU with enough data to require long-form length */
    goose_apdu_t apdu;
    goose_apdu_init(&apdu);

    /* Use a long gocbRef to push payload > 127 bytes */
    char long_ref[120];
    memset(long_ref, 'A', sizeof(long_ref) - 1);
    long_ref[sizeof(long_ref) - 1] = '\0';
    goose_set_gocbref(&apdu, long_ref);
    goose_set_datset(&apdu, long_ref);
    apdu.timestamp = 1000000ULL;
    goose_add_boolean(&apdu, true);

    uint8_t buf[1024];
    size_t encoded_len = 0;
    int ret = goose_encode_apdu(buf, sizeof(buf), &apdu, &encoded_len);
    TEST_ASSERT(ret == GOOSE_BER_OK, "long-form encode should succeed");
    TEST_ASSERT(encoded_len > 130, "encoded length should be > 130");

    /* Verify decode */
    goose_apdu_t decoded;
    ret = goose_decode_apdu(buf, encoded_len, &decoded);
    TEST_ASSERT(ret == GOOSE_BER_OK, "long-form decode should succeed");
    TEST_PASS();
}

static void test_encode_ber_primitives_error(void)
{
    uint8_t buf[4];
    size_t offset = 0;

    /* ber_encode_tag: NULL args */
    TEST_ASSERT(ber_encode_tag(NULL, 4, &offset, 0x80) ==
                GOOSE_BER_ERR_INVALID_ARG, "NULL buf");
    TEST_ASSERT(ber_encode_tag(buf, 4, NULL, 0x80) ==
                GOOSE_BER_ERR_INVALID_ARG, "NULL offset");

    /* ber_encode_tag: offset at end */
    offset = 4;
    TEST_ASSERT(ber_encode_tag(buf, 4, &offset, 0x80) ==
                GOOSE_BER_ERR_BUFFER_FULL, "offset at end");

    /* ber_encode_length: NULL args */
    offset = 0;
    TEST_ASSERT(ber_encode_length(NULL, 4, &offset, 1) ==
                GOOSE_BER_ERR_INVALID_ARG, "NULL buf");
    TEST_ASSERT(ber_encode_length(buf, 4, NULL, 1) ==
                GOOSE_BER_ERR_INVALID_ARG, "NULL offset");

    /* ber_encode_boolean: buffer too small */
    offset = 3;
    TEST_ASSERT(ber_encode_boolean(buf, 4, &offset, 0x87, true) ==
                GOOSE_BER_ERR_BUFFER_FULL, "boolean buf too small");

    /* ber_encode_visiblestring: NULL string */
    offset = 0;
    TEST_ASSERT(ber_encode_visiblestring(buf, 4, &offset, 0x80, NULL) ==
                GOOSE_BER_ERR_INVALID_ARG, "NULL string");

    /* ber_encode_utctime: buffer too small */
    offset = 0;
    TEST_ASSERT(ber_encode_utctime(buf, 4, &offset, 0x84, 1000000, 0) ==
                GOOSE_BER_ERR_BUFFER_FULL, "utctime buf too small");
    TEST_PASS();
}

static void test_encode_set_security(void)
{
    goose_apdu_t apdu;
    goose_apdu_init(&apdu);

    uint8_t key_id[GOOSE_KEYID_LEN] = {0xDE, 0xAD, 0xBE, 0xEF};
    uint8_t sig[32];
    memset(sig, 0x42, sizeof(sig));

    int ret = goose_set_security(&apdu, GOOSE_SIGNATURE_RSA_PSS, key_id, sig, 32);
    TEST_ASSERT(ret == GOOSE_BER_OK, "set_security should succeed");
    TEST_ASSERT(apdu.secure == true, "secure flag");
    TEST_ASSERT(apdu.signature_algo == GOOSE_SIGNATURE_RSA_PSS, "algo");
    TEST_ASSERT(memcmp(apdu.key_id, key_id, GOOSE_KEYID_LEN) == 0, "key_id");
    TEST_ASSERT(apdu.signature_len == 32, "sig_len");

    /* NULL args */
    TEST_ASSERT(goose_set_security(NULL, GOOSE_SIGNATURE_RSA_PSS, key_id, sig, 32) ==
                GOOSE_BER_ERR_INVALID_ARG, "NULL apdu");
    TEST_ASSERT(goose_set_security(&apdu, GOOSE_SIGNATURE_RSA_PSS, NULL, sig, 32) ==
                GOOSE_BER_ERR_INVALID_ARG, "NULL key_id");
    TEST_ASSERT(goose_set_security(&apdu, GOOSE_SIGNATURE_RSA_PSS, key_id, NULL, 32) ==
                GOOSE_BER_ERR_INVALID_ARG, "NULL sig");

    /* Signature too large */
    TEST_ASSERT(goose_set_security(&apdu, GOOSE_SIGNATURE_RSA_PSS, key_id, sig,
                                    GOOSE_MAX_SIGNATURE_LEN + 1) ==
                GOOSE_BER_ERR_INVALID_ARG, "sig too large");
    TEST_PASS();
}

static void test_encode_add_helpers(void)
{
    goose_apdu_t apdu;
    goose_apdu_init(&apdu);

    /* Test all add helpers */
    TEST_ASSERT(goose_add_boolean(&apdu, true) == GOOSE_BER_OK, "add bool");
    TEST_ASSERT(goose_add_int32(&apdu, -1) == GOOSE_BER_OK, "add int32");
    TEST_ASSERT(goose_add_uint32(&apdu, 42) == GOOSE_BER_OK, "add uint32");
    TEST_ASSERT(goose_add_float32(&apdu, 1.0f) == GOOSE_BER_OK, "add float32");

    uint8_t bs[] = {0xAA};
    TEST_ASSERT(goose_add_bitstring(&apdu, bs, 1) == GOOSE_BER_OK, "add bitstring");

    uint8_t os[] = {0xBB};
    TEST_ASSERT(goose_add_octetstring(&apdu, os, 1) == GOOSE_BER_OK, "add octetstring");
    TEST_ASSERT(goose_add_visiblestring(&apdu, "hi") == GOOSE_BER_OK, "add visiblestring");
    TEST_ASSERT(goose_add_utctime(&apdu, 0, 0) == GOOSE_BER_OK, "add utctime");

    goose_data_t elems[1];
    elems[0].type = GOOSE_DATA_BOOLEAN;
    elems[0].value.boolean = false;
    TEST_ASSERT(goose_add_structure(&apdu, elems, 1) == GOOSE_BER_OK, "add structure");

    /* NULL args for each */
    TEST_ASSERT(goose_add_boolean(NULL, true) == GOOSE_BER_ERR_INVALID_ARG, "null bool");
    TEST_ASSERT(goose_add_int32(NULL, 0) == GOOSE_BER_ERR_INVALID_ARG, "null int32");
    TEST_ASSERT(goose_add_uint32(NULL, 0) == GOOSE_BER_ERR_INVALID_ARG, "null uint32");
    TEST_ASSERT(goose_add_float32(NULL, 0) == GOOSE_BER_ERR_INVALID_ARG, "null float32");
    TEST_ASSERT(goose_add_bitstring(NULL, bs, 1) == GOOSE_BER_ERR_INVALID_ARG, "null bs");
    TEST_ASSERT(goose_add_bitstring(&apdu, NULL, 1) == GOOSE_BER_ERR_INVALID_ARG, "null bs data");
    TEST_ASSERT(goose_add_octetstring(NULL, os, 1) == GOOSE_BER_ERR_INVALID_ARG, "null os");
    TEST_ASSERT(goose_add_octetstring(&apdu, NULL, 1) == GOOSE_BER_ERR_INVALID_ARG, "null os data");
    TEST_ASSERT(goose_add_visiblestring(NULL, "x") == GOOSE_BER_ERR_INVALID_ARG, "null vs");
    TEST_ASSERT(goose_add_visiblestring(&apdu, NULL) == GOOSE_BER_ERR_INVALID_ARG, "null vs str");
    TEST_ASSERT(goose_add_utctime(NULL, 0, 0) == GOOSE_BER_ERR_INVALID_ARG, "null utctime");
    TEST_ASSERT(goose_add_structure(NULL, elems, 1) == GOOSE_BER_ERR_INVALID_ARG, "null struct");
    TEST_ASSERT(goose_add_structure(&apdu, NULL, 1) == GOOSE_BER_ERR_INVALID_ARG, "null struct elems");
    TEST_PASS();
}

/***************************************************************************
 * Target 3: key_manager.c sign/verify
 ***************************************************************************/

#ifdef IEC61850_SECURITY_ENABLED

static char rsa_key_path[64];

static char *generate_rsa_key_file(void)
{
    (void)snprintf(rsa_key_path, sizeof(rsa_key_path),
                   "/tmp/test_km_rsa_XXXXXX");
    int fd = mkstemp(rsa_key_path);
    char *path = rsa_key_path;
    if (fd < 0) return NULL;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) { close(fd); return NULL; }

    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY *key = NULL;
    EVP_PKEY_keygen(ctx, &key);
    EVP_PKEY_CTX_free(ctx);

    if (!key) { close(fd); return NULL; }

    FILE *fp = fdopen(fd, "w");
    if (!fp) { close(fd); EVP_PKEY_free(key); return NULL; }

    PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL);
    fclose(fp);
    EVP_PKEY_free(key);
    return path;
}

static char ec_key_path[64];

static char *generate_ec_key_file(void)
{
    (void)snprintf(ec_key_path, sizeof(ec_key_path),
                   "/tmp/test_km_ec_XXXXXX");
    int fd = mkstemp(ec_key_path);
    char *path = ec_key_path;
    if (fd < 0) return NULL;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) { close(fd); return NULL; }

    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1);
    EVP_PKEY *key = NULL;
    EVP_PKEY_keygen(ctx, &key);
    EVP_PKEY_CTX_free(ctx);

    if (!key) { close(fd); return NULL; }

    FILE *fp = fdopen(fd, "w");
    if (!fp) { close(fd); EVP_PKEY_free(key); return NULL; }

    PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL);
    fclose(fp);
    EVP_PKEY_free(key);
    return path;
}

static void test_key_manager_rsa_lifecycle(void)
{
    char *key_path = generate_rsa_key_file();
    TEST_ASSERT(key_path != NULL, "generate RSA key file");

    iec61850_key_manager_t km;
    iec61850_key_manager_init(&km);

    TEST_ASSERT(!iec61850_key_manager_is_loaded(&km), "key not loaded initially");
    TEST_ASSERT(iec61850_key_manager_get_key_type(&km) == IEC61850_KEY_UNKNOWN,
                "key type unknown initially");

    /* Load key */
    int ret = iec61850_key_manager_load_private_key(&km, key_path, NULL);
    TEST_ASSERT(ret == IEC61850_SEC_OK, "load RSA key should succeed");
    TEST_ASSERT(iec61850_key_manager_is_loaded(&km), "key should be loaded");
    TEST_ASSERT(iec61850_key_manager_get_key_type(&km) == IEC61850_KEY_RSA_2048,
                "key type should be RSA 2048");
    TEST_ASSERT(iec61850_key_manager_get_sig_algo(&km) == IEC61850_SIG_RSA_PSS_SHA256,
                "sig algo should be RSA-PSS");
    TEST_ASSERT(iec61850_key_manager_get_sig_size(&km) == 256,
                "sig size should be 256");

    /* Sign */
    uint8_t test_data[] = "Hello, IEC 61850!";
    uint8_t sig[512];
    size_t sig_len = 0;

    ret = iec61850_key_manager_sign(&km, test_data, sizeof(test_data) - 1,
                                     sig, sizeof(sig), &sig_len);
    TEST_ASSERT(ret == IEC61850_SEC_OK, "sign should succeed");
    TEST_ASSERT(sig_len > 0, "sig_len should be > 0");
    TEST_ASSERT(sig_len <= 256, "sig_len should be <= 256");

    /* Verify with the private key (RSA private key contains public key) */
    ret = iec61850_key_manager_verify(test_data, sizeof(test_data) - 1,
                                       sig, sig_len, km.private_key);
    TEST_ASSERT(ret == IEC61850_SEC_OK, "verify should succeed");

    /* Verify with wrong data */
    uint8_t wrong_data[] = "Wrong data!";
    ret = iec61850_key_manager_verify(wrong_data, sizeof(wrong_data) - 1,
                                       sig, sig_len, km.private_key);
    TEST_ASSERT(ret != IEC61850_SEC_OK, "verify with wrong data should fail");

    iec61850_key_manager_destroy(&km);
    TEST_ASSERT(!iec61850_key_manager_is_loaded(&km), "key unloaded after destroy");

    unlink(key_path);
    TEST_PASS();
}

static void test_key_manager_ec_lifecycle(void)
{
    char *key_path = generate_ec_key_file();
    TEST_ASSERT(key_path != NULL, "generate EC key file");

    iec61850_key_manager_t km;
    iec61850_key_manager_init(&km);

    int ret = iec61850_key_manager_load_private_key(&km, key_path, NULL);
    TEST_ASSERT(ret == IEC61850_SEC_OK, "load EC key should succeed");
    TEST_ASSERT(iec61850_key_manager_get_key_type(&km) == IEC61850_KEY_ECDSA_P256,
                "key type should be ECDSA P256");
    TEST_ASSERT(iec61850_key_manager_get_sig_algo(&km) == IEC61850_SIG_ECDSA_SHA256,
                "sig algo should be ECDSA-SHA256");
    TEST_ASSERT(iec61850_key_manager_get_sig_size(&km) == 72,
                "sig size should be 72");

    /* Sign */
    uint8_t test_data[] = "EC signing test";
    uint8_t sig[256];
    size_t sig_len = 0;

    ret = iec61850_key_manager_sign(&km, test_data, sizeof(test_data) - 1,
                                     sig, sizeof(sig), &sig_len);
    TEST_ASSERT(ret == IEC61850_SEC_OK, "EC sign should succeed");
    TEST_ASSERT(sig_len > 0, "sig_len > 0");

    /* Verify */
    ret = iec61850_key_manager_verify(test_data, sizeof(test_data) - 1,
                                       sig, sig_len, km.private_key);
    TEST_ASSERT(ret == IEC61850_SEC_OK, "EC verify should succeed");

    /* Verify with wrong data */
    uint8_t wrong[] = "wrong";
    ret = iec61850_key_manager_verify(wrong, sizeof(wrong) - 1,
                                       sig, sig_len, km.private_key);
    TEST_ASSERT(ret != IEC61850_SEC_OK, "EC verify wrong data should fail");

    iec61850_key_manager_destroy(&km);
    unlink(key_path);
    TEST_PASS();
}

static void test_key_manager_null_args(void)
{
    iec61850_key_manager_t km;

    /* init with NULL */
    iec61850_key_manager_init(NULL);  /* should not crash */

    /* destroy with NULL */
    iec61850_key_manager_destroy(NULL);  /* should not crash */

    /* is_loaded with NULL */
    TEST_ASSERT(!iec61850_key_manager_is_loaded(NULL), "NULL is not loaded");

    /* get_key_type with NULL */
    TEST_ASSERT(iec61850_key_manager_get_key_type(NULL) == IEC61850_KEY_UNKNOWN,
                "NULL key type unknown");

    /* get_sig_algo with NULL */
    TEST_ASSERT(iec61850_key_manager_get_sig_algo(NULL) == IEC61850_SIG_RSA_PSS_SHA256,
                "NULL sig algo default");

    /* get_sig_size with NULL */
    TEST_ASSERT(iec61850_key_manager_get_sig_size(NULL) == 0,
                "NULL sig size 0");

    /* load_private_key with NULL args */
    iec61850_key_manager_init(&km);
    TEST_ASSERT(iec61850_key_manager_load_private_key(NULL, "/tmp/x", NULL) ==
                IEC61850_SEC_ERR_ARGS, "NULL km");
    TEST_ASSERT(iec61850_key_manager_load_private_key(&km, NULL, NULL) ==
                IEC61850_SEC_ERR_ARGS, "NULL path");

    /* load non-existent file */
    TEST_ASSERT(iec61850_key_manager_load_private_key(&km, "/tmp/nonexistent_key_12345.pem", NULL) ==
                IEC61850_SEC_ERR_FILE, "non-existent file");

    /* sign with NULL args */
    uint8_t data[] = "test";
    uint8_t sig[64];
    size_t sig_len = 0;
    TEST_ASSERT(iec61850_key_manager_sign(NULL, data, 4, sig, 64, &sig_len) ==
                IEC61850_SEC_ERR_ARGS, "NULL km sign");
    TEST_ASSERT(iec61850_key_manager_sign(&km, NULL, 4, sig, 64, &sig_len) ==
                IEC61850_SEC_ERR_ARGS, "NULL data sign");
    TEST_ASSERT(iec61850_key_manager_sign(&km, data, 4, NULL, 64, &sig_len) ==
                IEC61850_SEC_ERR_ARGS, "NULL sig_out sign");
    TEST_ASSERT(iec61850_key_manager_sign(&km, data, 4, sig, 64, NULL) ==
                IEC61850_SEC_ERR_ARGS, "NULL sig_len sign");

    /* sign without loaded key */
    TEST_ASSERT(iec61850_key_manager_sign(&km, data, 4, sig, 64, &sig_len) ==
                IEC61850_SEC_ERR_ARGS, "no key sign");

    /* verify with NULL args */
    TEST_ASSERT(iec61850_key_manager_verify(NULL, 4, sig, 64, (EVP_PKEY *)1) ==
                IEC61850_SEC_ERR_ARGS, "NULL data verify");
    TEST_ASSERT(iec61850_key_manager_verify(data, 4, NULL, 64, (EVP_PKEY *)1) ==
                IEC61850_SEC_ERR_ARGS, "NULL sig verify");
    TEST_ASSERT(iec61850_key_manager_verify(data, 4, sig, 64, NULL) ==
                IEC61850_SEC_ERR_ARGS, "NULL pubkey verify");

    iec61850_key_manager_destroy(&km);
    TEST_PASS();
}

static void test_key_manager_load_invalid_file(void)
{
    /* Create a file with garbage content */
    char path[] = "/tmp/test_km_bad_XXXXXX";
    int fd = mkstemp(path);
    TEST_ASSERT(fd >= 0, "create temp file");
    const char *garbage = "this is not a PEM key";
    (void)write(fd, garbage, strlen(garbage));
    close(fd);

    iec61850_key_manager_t km;
    iec61850_key_manager_init(&km);

    int ret = iec61850_key_manager_load_private_key(&km, path, NULL);
    TEST_ASSERT(ret == IEC61850_SEC_ERR_PARSE, "garbage file should fail with parse error");

    iec61850_key_manager_destroy(&km);
    unlink(path);
    TEST_PASS();
}

static void test_key_manager_reload_key(void)
{
    char *key_path = generate_rsa_key_file();
    TEST_ASSERT(key_path != NULL, "generate RSA key file");

    iec61850_key_manager_t km;
    iec61850_key_manager_init(&km);

    /* Load first time */
    int ret = iec61850_key_manager_load_private_key(&km, key_path, NULL);
    TEST_ASSERT(ret == IEC61850_SEC_OK, "first load should succeed");

    /* Reload (should free old key first) */
    ret = iec61850_key_manager_load_private_key(&km, key_path, NULL);
    TEST_ASSERT(ret == IEC61850_SEC_OK, "reload should succeed");
    TEST_ASSERT(iec61850_key_manager_is_loaded(&km), "key still loaded after reload");

    iec61850_key_manager_destroy(&km);
    unlink(key_path);
    TEST_PASS();
}

#endif /* IEC61850_SECURITY_ENABLED */

/***************************************************************************
 * Target 4: mms_report.c RCB lifecycle
 ***************************************************************************/

static void test_rcb_init_defaults(void)
{
    iec61850_rcb_t rcb;
    iec61850_rcb_init(&rcb, "TestRpt01", IEC61850_RCB_UNBUFFERED);

    TEST_ASSERT(strcmp(rcb.attrs.rpt_id, "TestRpt01") == 0, "rpt_id");
    TEST_ASSERT(rcb.type == IEC61850_RCB_UNBUFFERED, "type");
    TEST_ASSERT(rcb.attrs.rpt_ena == false, "rpt_ena false");
    TEST_ASSERT(rcb.attrs.conf_rev == 1, "conf_rev 1");
    TEST_ASSERT(rcb.attrs.sq_num == 0, "sq_num 0");
    TEST_ASSERT(rcb.attrs.trg_ops.data_change == true, "trg dchg");
    TEST_ASSERT(rcb.attrs.trg_ops.general_interrogation == true, "trg gi");
    TEST_ASSERT(rcb.attrs.opt_flds.sequence_number == true, "opt seq_num");
    TEST_ASSERT(rcb.attrs.opt_flds.report_timestamp == true, "opt timestamp");
    TEST_ASSERT(rcb.initialized == true, "initialized");

    iec61850_rcb_destroy(&rcb);
    TEST_ASSERT(rcb.initialized == false, "destroyed");

    /* NULL init and destroy should not crash */
    iec61850_rcb_init(NULL, "x", IEC61850_RCB_UNBUFFERED);
    iec61850_rcb_destroy(NULL);
    TEST_PASS();
}

static void test_rcb_init_null_rptid(void)
{
    iec61850_rcb_t rcb;
    iec61850_rcb_init(&rcb, NULL, IEC61850_RCB_BUFFERED);
    TEST_ASSERT(rcb.attrs.rpt_id[0] == '\0', "NULL rpt_id gives empty string");
    TEST_ASSERT(rcb.type == IEC61850_RCB_BUFFERED, "type buffered");
    iec61850_rcb_destroy(&rcb);
    TEST_PASS();
}

static void test_rcb_enable_disable(void)
{
    iec61850_rcb_t rcb;
    iec61850_rcb_init(&rcb, "TestRpt02", IEC61850_RCB_UNBUFFERED);

    /* Enable */
    int ret = iec61850_rcb_enable(&rcb);
    TEST_ASSERT(ret == 0, "enable should succeed");
    TEST_ASSERT(rcb.attrs.rpt_ena == true, "rpt_ena true");

    /* Enable again (already enabled) */
    ret = iec61850_rcb_enable(&rcb);
    TEST_ASSERT(ret == 0, "re-enable should succeed (already enabled)");

    /* Disable */
    ret = iec61850_rcb_disable(&rcb);
    TEST_ASSERT(ret == 0, "disable should succeed");
    TEST_ASSERT(rcb.attrs.rpt_ena == false, "rpt_ena false");

    /* NULL/uninitialized args */
    TEST_ASSERT(iec61850_rcb_enable(NULL) == -EINVAL, "NULL enable");
    TEST_ASSERT(iec61850_rcb_disable(NULL) == -EINVAL, "NULL disable");

    iec61850_rcb_destroy(&rcb);
    TEST_PASS();
}

static int report_count = 0;
static mms_information_report_t last_report;

static void test_report_sender(const mms_information_report_t *report,
                                void *user_data)
{
    (void)user_data;
    report_count++;
    if (report) {
        last_report = *report;
    }
}

static void test_rcb_data_change(void)
{
    iec61850_rcb_t rcb;
    iec61850_rcb_init(&rcb, "TestRpt03", IEC61850_RCB_UNBUFFERED);

    iec61850_rcb_set_report_sender(&rcb, test_report_sender, NULL);

    /* Data change without enable — should not trigger */
    report_count = 0;
    mms_value_t old_val = {0};
    mms_value_t new_val = {0};
    new_val.type = MMS_TYPE_BOOLEAN;
    new_val.value.boolean = true;

    iec61850_rcb_on_data_change(&rcb, "testVar", &old_val, &new_val);
    TEST_ASSERT(report_count == 0, "no report when not enabled");

    /* Enable and trigger data change */
    iec61850_rcb_enable(&rcb);
    iec61850_rcb_on_data_change(&rcb, "testVar", &old_val, &new_val);
    TEST_ASSERT(report_count == 1, "report after enable");

    /* NULL rcb should not crash */
    iec61850_rcb_on_data_change(NULL, "x", &old_val, &new_val);

    iec61850_rcb_disable(&rcb);
    iec61850_rcb_destroy(&rcb);
    TEST_PASS();
}

static void test_rcb_quality_change(void)
{
    iec61850_rcb_t rcb;
    iec61850_rcb_init(&rcb, "TestRpt04", IEC61850_RCB_UNBUFFERED);
    rcb.attrs.trg_ops.quality_change = true;
    rcb.attrs.opt_flds.reason_for_inclusion = true;
    rcb.attrs.opt_flds.data_reference = true;
    rcb.attrs.opt_flds.buffer_overflow = true;
    rcb.attrs.opt_flds.entry_id = true;
    rcb.attrs.opt_flds.config_ref = true;

    iec61850_rcb_set_report_sender(&rcb, test_report_sender, NULL);
    iec61850_rcb_enable(&rcb);

    report_count = 0;
    mms_value_t val = {0};
    val.type = MMS_TYPE_INTEGER;
    val.value.integer = 42;

    iec61850_rcb_on_quality_change(&rcb, "qualVar", &val);
    TEST_ASSERT(report_count == 1, "quality change report");

    /* Without trigger enabled */
    rcb.attrs.trg_ops.quality_change = false;
    iec61850_rcb_on_quality_change(&rcb, "qualVar", &val);
    TEST_ASSERT(report_count == 1, "no report without qchg trigger");

    /* NULL rcb */
    iec61850_rcb_on_quality_change(NULL, "x", &val);

    iec61850_rcb_disable(&rcb);
    iec61850_rcb_destroy(&rcb);
    TEST_PASS();
}

static void test_rcb_data_update(void)
{
    iec61850_rcb_t rcb;
    iec61850_rcb_init(&rcb, "TestRpt05", IEC61850_RCB_BUFFERED);
    rcb.attrs.trg_ops.data_update = true;

    iec61850_rcb_set_report_sender(&rcb, test_report_sender, NULL);
    iec61850_rcb_enable(&rcb);

    report_count = 0;
    mms_value_t val = {0};
    val.type = MMS_TYPE_FLOATING_POINT;
    val.value.floating_point = 3.14f;

    iec61850_rcb_on_data_update(&rcb, "updVar", &val);
    TEST_ASSERT(report_count == 1, "data update report");

    /* Verify entry_id incremented for buffered */
    TEST_ASSERT(rcb.attrs.entry_id > 0, "entry_id incremented");

    /* Without trigger */
    rcb.attrs.trg_ops.data_update = false;
    iec61850_rcb_on_data_update(&rcb, "updVar", &val);
    TEST_ASSERT(report_count == 1, "no report without dupd trigger");

    /* NULL rcb */
    iec61850_rcb_on_data_update(NULL, "x", &val);

    iec61850_rcb_disable(&rcb);
    iec61850_rcb_destroy(&rcb);
    TEST_PASS();
}

static void test_rcb_trigger_gi(void)
{
    iec61850_rcb_t rcb;
    iec61850_rcb_init(&rcb, "TestRpt06", IEC61850_RCB_BUFFERED);

    iec61850_rcb_set_report_sender(&rcb, test_report_sender, NULL);
    iec61850_rcb_enable(&rcb);

    report_count = 0;
    iec61850_rcb_trigger_gi(&rcb);
    TEST_ASSERT(report_count == 1, "GI report");

    /* Without GI trigger enabled */
    rcb.attrs.trg_ops.general_interrogation = false;
    iec61850_rcb_trigger_gi(&rcb);
    TEST_ASSERT(report_count == 1, "no report without GI trigger");

    /* NULL */
    iec61850_rcb_trigger_gi(NULL);

    iec61850_rcb_disable(&rcb);
    iec61850_rcb_destroy(&rcb);
    TEST_PASS();
}

static void test_rcb_enable_with_integrity(void)
{
    iec61850_rcb_t rcb;
    iec61850_rcb_init(&rcb, "TestRpt07", IEC61850_RCB_UNBUFFERED);
    rcb.attrs.intg_pd = 100;  /* 100ms integrity period */
    rcb.attrs.trg_ops.integrity = true;

    iec61850_rcb_set_report_sender(&rcb, test_report_sender, NULL);

    int ret = iec61850_rcb_enable(&rcb);
    TEST_ASSERT(ret == 0, "enable with integrity should succeed");
    TEST_ASSERT(rcb.has_integrity_thread == true, "integrity thread started");

    /* Let it run briefly */
    struct timespec ts = {0, 50000000L};  /* 50ms */
    (void)nanosleep(&ts, NULL);

    iec61850_rcb_disable(&rcb);
    TEST_ASSERT(rcb.has_integrity_thread == false, "integrity thread stopped");

    iec61850_rcb_destroy(&rcb);
    TEST_PASS();
}

static void test_rcb_set_report_sender_null(void)
{
    /* NULL rcb should not crash */
    iec61850_rcb_set_report_sender(NULL, test_report_sender, NULL);
    TEST_PASS();
}

static void test_rcb_manager_lifecycle(void)
{
    iec61850_rcb_manager_t mgr;
    iec61850_rcb_manager_init(&mgr, "TestLD");

    TEST_ASSERT(strcmp(mgr.ld_name, "TestLD") == 0, "ld_name");
    TEST_ASSERT(mgr.rcb_count == 0, "initial count 0");

    /* Add RCBs */
    int idx0 = iec61850_rcb_manager_add_rcb(&mgr, "Rpt01", IEC61850_RCB_UNBUFFERED, 0);
    TEST_ASSERT(idx0 == 0, "first RCB index 0");

    int idx1 = iec61850_rcb_manager_add_rcb(&mgr, "Rpt02", IEC61850_RCB_BUFFERED, 32);
    TEST_ASSERT(idx1 == 1, "second RCB index 1");

    TEST_ASSERT(mgr.rcb_count == 2, "count 2");

    /* Find RCB */
    iec61850_rcb_t *found = iec61850_rcb_manager_find_rcb(&mgr, "Rpt01");
    TEST_ASSERT(found != NULL, "find Rpt01");
    TEST_ASSERT(strcmp(found->attrs.rpt_id, "Rpt01") == 0, "found rpt_id");

    iec61850_rcb_t *not_found = iec61850_rcb_manager_find_rcb(&mgr, "NoSuchRpt");
    TEST_ASSERT(not_found == NULL, "not found");

    /* Get buffer */
    iec61850_report_buffer_t *buf = iec61850_rcb_manager_get_buffer(&mgr, 1);
    TEST_ASSERT(buf != NULL, "get buffer for BRCB");
    TEST_ASSERT(buf->capacity == 32, "buffer capacity 32");

    iec61850_report_buffer_t *bad_buf = iec61850_rcb_manager_get_buffer(&mgr, 99);
    TEST_ASSERT(bad_buf == NULL, "bad index returns NULL");

    /* NULL args */
    TEST_ASSERT(iec61850_rcb_manager_add_rcb(NULL, "x", IEC61850_RCB_UNBUFFERED, 0) < 0,
                "NULL mgr add");
    TEST_ASSERT(iec61850_rcb_manager_add_rcb(&mgr, NULL, IEC61850_RCB_UNBUFFERED, 0) < 0,
                "NULL rpt_id add");
    TEST_ASSERT(iec61850_rcb_manager_find_rcb(NULL, "x") == NULL, "NULL mgr find");
    TEST_ASSERT(iec61850_rcb_manager_find_rcb(&mgr, NULL) == NULL, "NULL rpt_id find");
    TEST_ASSERT(iec61850_rcb_manager_get_buffer(NULL, 0) == NULL, "NULL mgr get_buffer");

    iec61850_rcb_manager_destroy(&mgr);
    TEST_ASSERT(mgr.rcb_count == 0, "count 0 after destroy");

    /* NULL destroy */
    iec61850_rcb_manager_destroy(NULL);

    /* NULL init */
    iec61850_rcb_manager_init(NULL, "x");
    TEST_PASS();
}

static void test_rcb_manager_data_change(void)
{
    iec61850_rcb_manager_t mgr;
    iec61850_rcb_manager_init(&mgr, "TestLD2");
    iec61850_rcb_manager_add_rcb(&mgr, "Rpt01", IEC61850_RCB_BUFFERED, 16);

    iec61850_rcb_t *rcb = iec61850_rcb_manager_find_rcb(&mgr, "Rpt01");
    TEST_ASSERT(rcb != NULL, "find rcb");
    iec61850_rcb_set_report_sender(rcb, test_report_sender, NULL);
    iec61850_rcb_enable(rcb);

    report_count = 0;
    mms_value_t old_val = {0};
    mms_value_t new_val = {0};
    new_val.type = MMS_TYPE_INTEGER;
    new_val.value.integer = 100;

    iec61850_rcb_manager_on_data_change(&mgr, "testVar", &old_val, &new_val);
    TEST_ASSERT(report_count == 1, "manager data change report");

    /* Check buffer got the entry */
    iec61850_report_buffer_t *buf = iec61850_rcb_manager_get_buffer(&mgr, 0);
    TEST_ASSERT(buf != NULL, "buffer exists");
    TEST_ASSERT(buf->count == 1, "buffer has 1 entry");

    /* NULL mgr */
    iec61850_rcb_manager_on_data_change(NULL, "x", &old_val, &new_val);

    iec61850_rcb_disable(rcb);
    iec61850_rcb_manager_destroy(&mgr);
    TEST_PASS();
}

static void test_rcb_manager_trigger_gi(void)
{
    iec61850_rcb_manager_t mgr;
    iec61850_rcb_manager_init(&mgr, "TestLD3");
    iec61850_rcb_manager_add_rcb(&mgr, "RptGI", IEC61850_RCB_UNBUFFERED, 0);

    iec61850_rcb_t *rcb = iec61850_rcb_manager_find_rcb(&mgr, "RptGI");
    iec61850_rcb_set_report_sender(rcb, test_report_sender, NULL);
    iec61850_rcb_enable(rcb);

    report_count = 0;
    iec61850_rcb_manager_trigger_gi(&mgr);
    TEST_ASSERT(report_count == 1, "manager GI report");

    /* NULL mgr */
    iec61850_rcb_manager_trigger_gi(NULL);

    iec61850_rcb_disable(rcb);
    iec61850_rcb_manager_destroy(&mgr);
    TEST_PASS();
}

static void test_report_buffer_overflow(void)
{
    iec61850_report_buffer_t buf;
    iec61850_report_buffer_init(&buf, 4);

    TEST_ASSERT(buf.capacity == 4, "capacity 4");
    TEST_ASSERT(buf.count == 0, "initial count 0");
    TEST_ASSERT(!iec61850_report_buffer_had_overflow(&buf), "no overflow initially");

    /* Fill buffer */
    for (int i = 0; i < 4; i++) {
        mms_value_t val = {0};
        val.type = MMS_TYPE_INTEGER;
        val.value.integer = i;
        uint64_t eid = iec61850_report_buffer_add(&buf, IEC61850_REASON_DCHG,
                                                    "var", &val,
                                                    (uint64_t)i * 1000);
        TEST_ASSERT(eid > 0, "entry_id > 0");
    }
    TEST_ASSERT(buf.count == 4, "count 4");

    /* Add one more to trigger overflow */
    mms_value_t extra = {0};
    iec61850_report_buffer_add(&buf, IEC61850_REASON_DCHG, "var", &extra, 5000);
    TEST_ASSERT(iec61850_report_buffer_had_overflow(&buf), "overflow occurred");
    /* Second call should be false (flag cleared) */
    TEST_ASSERT(!iec61850_report_buffer_had_overflow(&buf), "overflow cleared");

    /* Get entries */
    iec61850_report_entry_t entries[8];
    uint32_t count = 0;
    int ret = iec61850_report_buffer_get_entries(&buf, 0, entries, &count, 8);
    TEST_ASSERT(ret == 0, "get entries ok");
    TEST_ASSERT(count > 0, "got entries");

    /* Get entries after a specific ID */
    ret = iec61850_report_buffer_get_entries(&buf, 3, entries, &count, 8);
    TEST_ASSERT(ret == 0, "get entries after id ok");

    /* NULL args */
    TEST_ASSERT(iec61850_report_buffer_get_entries(NULL, 0, entries, &count, 8) == -EINVAL,
                "NULL buf");
    TEST_ASSERT(iec61850_report_buffer_get_entries(&buf, 0, NULL, &count, 8) == -EINVAL,
                "NULL out");
    TEST_ASSERT(iec61850_report_buffer_get_entries(&buf, 0, entries, NULL, 8) == -EINVAL,
                "NULL count");

    /* NULL for buffer init */
    iec61850_report_buffer_init(NULL, 4);

    /* NULL for overflow check */
    TEST_ASSERT(!iec61850_report_buffer_had_overflow(NULL), "NULL overflow false");

    /* NULL for add */
    TEST_ASSERT(iec61850_report_buffer_add(NULL, IEC61850_REASON_DCHG, "x", NULL, 0) == 0,
                "NULL buf add returns 0");

    /* Add with NULL var_ref and NULL value */
    iec61850_report_buffer_add(&buf, IEC61850_REASON_DCHG, NULL, NULL, 0);

    /* Capacity clamping */
    iec61850_report_buffer_t big;
    iec61850_report_buffer_init(&big, IEC61850_RCB_MAX_BUFFER + 100);
    TEST_ASSERT(big.capacity == IEC61850_RCB_MAX_BUFFER, "capacity clamped");

    /* Empty buffer get_entries */
    iec61850_report_buffer_t empty;
    iec61850_report_buffer_init(&empty, 4);
    ret = iec61850_report_buffer_get_entries(&empty, 0, entries, &count, 8);
    TEST_ASSERT(ret == 0, "empty get ok");
    TEST_ASSERT(count == 0, "empty count 0");
    TEST_PASS();
}

/***************************************************************************
 * Main
 ***************************************************************************/

int main(void)
{
    printf("coverage_boost2: ");

    /* Target 1: goose_ber_decode.c */
    test_decode_tag_null_args();
    test_decode_length_long_form();
    test_decode_int32_edge_cases();
    test_decode_uint32_edge_cases();
    test_decode_apdu_all_types();
    test_decode_apdu_truncated();
    test_decode_apdu_ex();
    test_decode_security();
    test_decode_security_absent();
    test_decode_security_malformed();
    test_decode_octetstring();
    test_decode_alldata_error_paths();
    test_decode_alldata_unknown_type();

    /* Target 2: goose_ber.c */
    test_encode_apdu_all_types();
    test_encode_apdu_buffer_too_small();
    test_encode_apdu_null_args();
    test_encode_alldata_null_args();
    test_encode_long_form_length();
    test_encode_ber_primitives_error();
    test_encode_set_security();
    test_encode_add_helpers();

    /* Target 3: key_manager.c */
#ifdef IEC61850_SECURITY_ENABLED
    test_key_manager_rsa_lifecycle();
    test_key_manager_ec_lifecycle();
    test_key_manager_null_args();
    test_key_manager_load_invalid_file();
    test_key_manager_reload_key();
#endif

    /* Target 4: mms_report.c */
    test_rcb_init_defaults();
    test_rcb_init_null_rptid();
    test_rcb_enable_disable();
    test_rcb_data_change();
    test_rcb_quality_change();
    test_rcb_data_update();
    test_rcb_trigger_gi();
    test_rcb_enable_with_integrity();
    test_rcb_set_report_sender_null();
    test_rcb_manager_lifecycle();
    test_rcb_manager_data_change();
    test_rcb_manager_trigger_gi();
    test_report_buffer_overflow();

    printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
