/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for MMS BER Encoding/Decoding
 *
 * Tests encode/decode round-trips for each MMS service type:
 * InitiateRequest/Response, ConfirmedRequest/Response (Read, Write,
 * GetNameList), Error PDU, InformationReport, helper functions.
 *
 * License: BSD-2-Clause
 */

#include "asn1/mms_ber.h"

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
 * Helper: Length Encode/Decode
 * ======================================================================== */

static void test_encode_decode_length_short(void)
{
    TEST("encode_decode_length_short");
    uint8_t buf[16];
    int enc_len = mms_encode_length(42, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    size_t dec_len = 0;
    int consumed = mms_decode_length(buf, (size_t)enc_len, &dec_len);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)dec_len, 42);
    PASS();
}

static void test_encode_decode_length_long(void)
{
    TEST("encode_decode_length_long");
    uint8_t buf[16];
    int enc_len = mms_encode_length(1000, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    size_t dec_len = 0;
    int consumed = mms_decode_length(buf, (size_t)enc_len, &dec_len);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)dec_len, 1000);
    PASS();
}

/* ========================================================================
 * Helper: Value Encode/Decode
 * ======================================================================== */

static void test_encode_decode_boolean_value(void)
{
    TEST("encode_decode_boolean_value");
    uint8_t buf[64];
    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_BOOLEAN;
    val.value.boolean = true;

    int enc_len = mms_encode_value(&val, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_value_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int consumed = mms_decode_value(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)decoded.type, (int)MMS_TYPE_BOOLEAN);
    ASSERT_TRUE(decoded.value.boolean == true);
    PASS();
}

static void test_encode_decode_integer_value(void)
{
    TEST("encode_decode_integer_value");
    uint8_t buf[64];
    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;
    val.value.integer = -42;

    int enc_len = mms_encode_value(&val, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_value_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int consumed = mms_decode_value(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)decoded.type, (int)MMS_TYPE_INTEGER);
    ASSERT_EQ(decoded.value.integer, -42);
    PASS();
}

static void test_encode_decode_unsigned_value(void)
{
    TEST("encode_decode_unsigned_value");
    uint8_t buf[64];
    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_UNSIGNED;
    val.value.unsigned_val = 65535;

    int enc_len = mms_encode_value(&val, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_value_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int consumed = mms_decode_value(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)decoded.type, (int)MMS_TYPE_UNSIGNED);
    ASSERT_TRUE(decoded.value.unsigned_val == 65535);
    PASS();
}

static void test_encode_decode_float_value(void)
{
    TEST("encode_decode_float_value");
    uint8_t buf[64];
    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_FLOATING_POINT;
    val.value.floating_point = 3.14f;

    int enc_len = mms_encode_value(&val, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_value_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int consumed = mms_decode_value(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)decoded.type, (int)MMS_TYPE_FLOATING_POINT);
    /* Float comparison with tolerance */
    float diff = decoded.value.floating_point - 3.14f;
    ASSERT_TRUE(diff > -0.01f && diff < 0.01f);
    PASS();
}

static void test_encode_decode_visiblestring_value(void)
{
    TEST("encode_decode_visiblestring_value");
    uint8_t buf[256];
    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_VISIBLE_STRING;
    strncpy(val.value.visible_string.data, "Hello MMS", MMS_MAX_STRING_LENGTH - 1);
    val.value.visible_string.len = strlen("Hello MMS");

    int enc_len = mms_encode_value(&val, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_value_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int consumed = mms_decode_value(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)decoded.type, (int)MMS_TYPE_VISIBLE_STRING);
    ASSERT_TRUE(strcmp(decoded.value.visible_string.data, "Hello MMS") == 0);
    PASS();
}

/* ========================================================================
 * Initiate Request/Response
 * ======================================================================== */

static void test_initiate_request_roundtrip(void)
{
    TEST("initiate_request_roundtrip");
    uint8_t buf[512];
    mms_initiate_request_t req;
    memset(&req, 0, sizeof(req));
    req.proposed_max_pdu_size = 65000;
    req.proposed_data_structure_nesting_level = 10;
    req.proposed_version_number = 1;

    int enc_len = mms_encode_initiate_request(&req, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_initiate_request_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int consumed = mms_decode_initiate_request(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)decoded.proposed_max_pdu_size, 65000);
    PASS();
}

static void test_initiate_response_roundtrip(void)
{
    TEST("initiate_response_roundtrip");
    uint8_t buf[512];
    mms_initiate_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.negotiated_max_pdu_size = 32000;
    resp.negotiated_data_structure_nesting_level = 10;
    resp.negotiated_version_number = 1;

    int enc_len = mms_encode_initiate_response(&resp, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_initiate_response_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int consumed = mms_decode_initiate_response(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)decoded.negotiated_max_pdu_size, 32000);
    PASS();
}

/* ========================================================================
 * Conclude Request/Response
 * ======================================================================== */

static void test_conclude_request_roundtrip(void)
{
    TEST("conclude_request_roundtrip");
    uint8_t buf[64];
    mms_conclude_request_t req;
    memset(&req, 0, sizeof(req));

    int enc_len = mms_encode_conclude_request(&req, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_conclude_request_t decoded;
    int consumed = mms_decode_conclude_request(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    PASS();
}

/* ========================================================================
 * Confirmed Request/Response (Read)
 * ======================================================================== */

static void test_read_request_roundtrip(void)
{
    TEST("read_request_roundtrip");
    uint8_t buf[1024];
    mms_confirmed_request_t req;
    memset(&req, 0, sizeof(req));
    req.invoke_id = 1;
    req.service = MMS_SERVICE_TYPE_READ;
    strncpy(req.params.read.variable_spec.domain, "IED1LD0", MMS_MAX_DOMAIN_NAME - 1);
    strncpy(req.params.read.variable_spec.item_id, "XCBR1$ST$Pos$stVal", MMS_MAX_VARIABLE_NAME - 1);

    int enc_len = mms_encode_confirmed_request(&req, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_confirmed_request_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int consumed = mms_decode_confirmed_request(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)decoded.invoke_id, 1);
    ASSERT_EQ((int)decoded.service, (int)MMS_SERVICE_TYPE_READ);
    ASSERT_TRUE(strcmp(decoded.params.read.variable_spec.domain, "IED1LD0") == 0);
    ASSERT_TRUE(strcmp(decoded.params.read.variable_spec.item_id, "XCBR1$ST$Pos$stVal") == 0);
    PASS();
}

static void test_read_response_roundtrip(void)
{
    TEST("read_response_roundtrip");
    uint8_t buf[1024];
    mms_confirmed_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.invoke_id = 1;
    resp.service = MMS_SERVICE_TYPE_READ;
    resp.params.read.value.type = MMS_TYPE_INTEGER;
    resp.params.read.value.value.integer = 42;

    int enc_len = mms_encode_confirmed_response(&resp, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_confirmed_response_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int consumed = mms_decode_confirmed_response(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)decoded.invoke_id, 1);
    ASSERT_EQ((int)decoded.service, (int)MMS_SERVICE_TYPE_READ);
    ASSERT_EQ((int)decoded.params.read.value.type, (int)MMS_TYPE_INTEGER);
    ASSERT_EQ(decoded.params.read.value.value.integer, 42);
    PASS();
}

/* ========================================================================
 * Write Request
 * ======================================================================== */

static void test_write_request_roundtrip(void)
{
    TEST("write_request_roundtrip");
    uint8_t buf[1024];
    mms_confirmed_request_t req;
    memset(&req, 0, sizeof(req));
    req.invoke_id = 2;
    req.service = MMS_SERVICE_TYPE_WRITE;
    strncpy(req.params.write.variable_spec.domain, "IED1LD0", MMS_MAX_DOMAIN_NAME - 1);
    strncpy(req.params.write.variable_spec.item_id, "XCBR1$CO$Pos$ctlVal", MMS_MAX_VARIABLE_NAME - 1);
    req.params.write.value.type = MMS_TYPE_BOOLEAN;
    req.params.write.value.value.boolean = true;

    int enc_len = mms_encode_confirmed_request(&req, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_confirmed_request_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int consumed = mms_decode_confirmed_request(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)decoded.service, (int)MMS_SERVICE_TYPE_WRITE);
    ASSERT_TRUE(decoded.params.write.value.value.boolean == true);
    PASS();
}

/* ========================================================================
 * GetNameList Request
 * ======================================================================== */

static void test_getnamelist_request_roundtrip(void)
{
    TEST("getnamelist_request_roundtrip");
    uint8_t buf[1024];
    mms_confirmed_request_t req;
    memset(&req, 0, sizeof(req));
    req.invoke_id = 3;
    req.service = MMS_SERVICE_TYPE_GET_NAMELIST;
    req.params.getnamelist.object_class = MMS_OBJECT_CLASS_NAMED_VARIABLE;
    strncpy(req.params.getnamelist.domain, "IED1LD0", MMS_MAX_DOMAIN_NAME - 1);

    int enc_len = mms_encode_confirmed_request(&req, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_confirmed_request_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int consumed = mms_decode_confirmed_request(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)decoded.service, (int)MMS_SERVICE_TYPE_GET_NAMELIST);
    ASSERT_EQ((int)decoded.params.getnamelist.object_class, (int)MMS_OBJECT_CLASS_NAMED_VARIABLE);
    PASS();
}

/* ========================================================================
 * Confirmed Error
 * ======================================================================== */

static void test_confirmed_error_roundtrip(void)
{
    TEST("confirmed_error_roundtrip");
    uint8_t buf[512];
    mms_confirmed_error_t err;
    memset(&err, 0, sizeof(err));
    err.invoke_id = 5;
    err.error.error_class = MMS_ERROR_CLASS_ACCESS;
    err.error.error_code = MMS_ACCESS_ERROR_OBJECT_NON_EXISTENT;

    int enc_len = mms_encode_confirmed_error(&err, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_confirmed_error_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int consumed = mms_decode_confirmed_error(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)decoded.invoke_id, 5);
    ASSERT_EQ((int)decoded.error.error_class, (int)MMS_ERROR_CLASS_ACCESS);
    PASS();
}

/* ========================================================================
 * InformationReport
 * ======================================================================== */

static void test_information_report_roundtrip(void)
{
    TEST("information_report_roundtrip");
    uint8_t buf[4096];
    mms_information_report_t report;
    memset(&report, 0, sizeof(report));
    strncpy(report.variable_list_name, "DS1", MMS_MAX_VARIABLE_NAME - 1);
    report.num_values = 2;
    report.values[0].type = MMS_TYPE_BOOLEAN;
    report.values[0].value.boolean = true;
    report.values[1].type = MMS_TYPE_INTEGER;
    report.values[1].value.integer = 100;

    int enc_len = mms_encode_information_report(&report, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_information_report_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int consumed = mms_decode_information_report(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    ASSERT_TRUE(strcmp(decoded.variable_list_name, "DS1") == 0);
    ASSERT_EQ((int)decoded.num_values, 2);
    ASSERT_TRUE(decoded.values[0].value.boolean == true);
    ASSERT_EQ(decoded.values[1].value.integer, 100);
    PASS();
}

/* ========================================================================
 * Error Handling
 * ======================================================================== */

static void test_null_parameters(void)
{
    TEST("null_parameters");
    uint8_t buf[64];

    ASSERT_TRUE(mms_encode_initiate_request(NULL, buf, 64) < 0);
    ASSERT_TRUE(mms_encode_confirmed_request(NULL, buf, 64) < 0);
    ASSERT_TRUE(mms_encode_confirmed_response(NULL, buf, 64) < 0);
    ASSERT_TRUE(mms_encode_information_report(NULL, buf, 64) < 0);
    ASSERT_TRUE(mms_encode_value(NULL, buf, 64) < 0);

    mms_initiate_request_t req;
    ASSERT_TRUE(mms_encode_initiate_request(&req, NULL, 64) < 0);
    ASSERT_TRUE(mms_decode_initiate_request(NULL, 64, &req) < 0);

    mms_value_t val;
    ASSERT_TRUE(mms_decode_value(NULL, 64, &val) < 0);
    ASSERT_TRUE(mms_decode_value(buf, 64, NULL) < 0);
    PASS();
}

static void test_buffer_too_small(void)
{
    TEST("buffer_too_small");
    uint8_t buf[2];
    mms_initiate_request_t req;
    memset(&req, 0, sizeof(req));
    req.proposed_max_pdu_size = 65000;

    int ret = mms_encode_initiate_request(&req, buf, sizeof(buf));
    ASSERT_TRUE(ret < 0);
    PASS();
}

static void test_error_string_mapping(void)
{
    TEST("error_string_mapping");
    /* MMS_OK should map to something non-empty */
    const char *s = mms_error_string(MMS_OK);
    ASSERT_TRUE(s != NULL);
    ASSERT_TRUE(strlen(s) > 0);

    /* Error codes should map */
    s = mms_error_string(MMS_ERROR_BUFFER_TOO_SMALL);
    ASSERT_TRUE(s != NULL);
    ASSERT_TRUE(strlen(s) > 0);

    s = mms_error_string(MMS_ERROR_INVALID_PARAM);
    ASSERT_TRUE(s != NULL);
    ASSERT_TRUE(strlen(s) > 0);
    PASS();
}

/* ========================================================================
 * Control Services (Select/Operate/Cancel)
 * ======================================================================== */

static void test_select_request_roundtrip(void)
{
    TEST("select_request_roundtrip");
    uint8_t buf[512];
    mms_select_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.control_object.domain, "IED1LD0", MMS_MAX_DOMAIN_NAME - 1);
    strncpy(req.control_object.item_id, "XCBR1$CO$Pos", MMS_MAX_VARIABLE_NAME - 1);
    req.check_value = 0x03;
    req.select_timeout_ms = 30000;

    int enc_len = mms_encode_select_request(&req, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_select_request_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int consumed = mms_decode_select_request(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    ASSERT_TRUE(strcmp(decoded.control_object.domain, "IED1LD0") == 0);
    ASSERT_TRUE(strcmp(decoded.control_object.item_id, "XCBR1$CO$Pos") == 0);
    PASS();
}

static void test_operate_request_roundtrip(void)
{
    TEST("operate_request_roundtrip");
    uint8_t buf[512];
    mms_operate_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.control_object.domain, "IED1LD0", MMS_MAX_DOMAIN_NAME - 1);
    strncpy(req.control_object.item_id, "XCBR1$CO$Pos", MMS_MAX_VARIABLE_NAME - 1);
    req.selection_id = 42;
    req.has_control_value = true;
    req.control_value.type = MMS_TYPE_BOOLEAN;
    req.control_value.value.boolean = true;

    int enc_len = mms_encode_operate_request(&req, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_operate_request_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int consumed = mms_decode_operate_request(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)decoded.selection_id, 42);
    PASS();
}

static void test_cancel_request_roundtrip(void)
{
    TEST("cancel_request_roundtrip");
    uint8_t buf[512];
    mms_cancel_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.control_object.domain, "IED1LD0", MMS_MAX_DOMAIN_NAME - 1);
    strncpy(req.control_object.item_id, "XCBR1$CO$Pos", MMS_MAX_VARIABLE_NAME - 1);
    req.selection_id = 42;

    int enc_len = mms_encode_cancel_request(&req, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_cancel_request_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int consumed = mms_decode_cancel_request(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)decoded.selection_id, 42);
    PASS();
}

/* ========================================================================
 * Conclude Response
 * ======================================================================== */

static void test_conclude_response_roundtrip(void)
{
    TEST("conclude_response_roundtrip");
    uint8_t buf[64];
    mms_conclude_response_t resp;
    memset(&resp, 0, sizeof(resp));

    int enc_len = mms_encode_conclude_response(&resp, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_conclude_response_t decoded;
    int consumed = mms_decode_conclude_response(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    PASS();
}

/* ========================================================================
 * Select Response
 * ======================================================================== */

static void test_select_response_roundtrip(void)
{
    TEST("select_response_roundtrip");
    uint8_t buf[512];
    mms_select_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.state = MMS_CONTROL_STATE_SELECTED;
    resp.selection_id = 99;

    int enc_len = mms_encode_select_response(&resp, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_select_response_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int consumed = mms_decode_select_response(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)decoded.state, (int)MMS_CONTROL_STATE_SELECTED);
    ASSERT_EQ((int)decoded.selection_id, 99);
    PASS();
}

/* ========================================================================
 * SelectWithValue Request/Response
 * ======================================================================== */

static void test_select_with_value_request_roundtrip(void)
{
    TEST("select_with_value_request_roundtrip");
    uint8_t buf[512];
    mms_select_with_value_request_t req;
    memset(&req, 0, sizeof(req));
    strncpy(req.control_object.domain, "IED1LD0", MMS_MAX_DOMAIN_NAME - 1);
    strncpy(req.control_object.item_id, "CSWI$CO$Pos", MMS_MAX_VARIABLE_NAME - 1);
    req.control_value.type = MMS_TYPE_BOOLEAN;
    req.control_value.value.boolean = true;

    int enc_len = mms_encode_select_with_value_request(&req, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_select_with_value_request_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int consumed = mms_decode_select_with_value_request(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    ASSERT_TRUE(strcmp(decoded.control_object.domain, "IED1LD0") == 0);
    ASSERT_TRUE(decoded.control_value.value.boolean == true);
    PASS();
}

static void test_select_with_value_response_roundtrip(void)
{
    TEST("select_with_value_response_roundtrip");
    uint8_t buf[512];
    mms_select_with_value_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.state = MMS_CONTROL_STATE_SELECTED;
    resp.selection_id = 77;

    int enc_len = mms_encode_select_with_value_response(&resp, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_select_with_value_response_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int consumed = mms_decode_select_with_value_response(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)decoded.selection_id, 77);
    PASS();
}

/* ========================================================================
 * Operate Response
 * ======================================================================== */

static void test_operate_response_roundtrip(void)
{
    TEST("operate_response_roundtrip");
    uint8_t buf[512];
    mms_operate_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.state = MMS_CONTROL_STATE_READY;
    resp.success = true;

    int enc_len = mms_encode_operate_response(&resp, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_operate_response_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int consumed = mms_decode_operate_response(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    ASSERT_TRUE(decoded.success);
    PASS();
}

/* ========================================================================
 * Cancel Response
 * ======================================================================== */

static void test_cancel_response_roundtrip(void)
{
    TEST("cancel_response_roundtrip");
    uint8_t buf[512];
    mms_cancel_response_t resp;
    memset(&resp, 0, sizeof(resp));

    int enc_len = mms_encode_cancel_response(&resp, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_cancel_response_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int consumed = mms_decode_cancel_response(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    PASS();
}

/* ========================================================================
 * Command Termination
 * ======================================================================== */

static void test_command_termination_roundtrip(void)
{
    TEST("command_termination_roundtrip");
    uint8_t buf[512];
    mms_command_termination_t term;
    memset(&term, 0, sizeof(term));
    strncpy(term.control_object.domain, "IED1LD0", MMS_MAX_DOMAIN_NAME - 1);
    strncpy(term.control_object.item_id, "XCBR1$CO$Pos", MMS_MAX_VARIABLE_NAME - 1);
    term.selection_id = 55;
    term.success = true;
    term.termination_reason = 0;

    int enc_len = mms_encode_command_termination(&term, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_command_termination_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int consumed = mms_decode_command_termination(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    ASSERT_TRUE(strcmp(decoded.control_object.domain, "IED1LD0") == 0);
    ASSERT_EQ((int)decoded.selection_id, 55);
    ASSERT_TRUE(decoded.success);
    PASS();
}

/* ========================================================================
 * Additional Value Types
 * ======================================================================== */

static void test_encode_decode_octetstring_value(void)
{
    TEST("encode_decode_octetstring_value");
    uint8_t buf[256];
    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_OCTET_STRING;
    val.value.octet_string.data[0] = 0xDE;
    val.value.octet_string.data[1] = 0xAD;
    val.value.octet_string.data[2] = 0xBE;
    val.value.octet_string.data[3] = 0xEF;
    val.value.octet_string.len = 4;

    int enc_len = mms_encode_value(&val, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_value_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int consumed = mms_decode_value(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)decoded.type, (int)MMS_TYPE_OCTET_STRING);
    ASSERT_EQ((int)decoded.value.octet_string.len, 4);
    ASSERT_EQ((int)decoded.value.octet_string.data[0], 0xDE);
    ASSERT_EQ((int)decoded.value.octet_string.data[3], 0xEF);
    PASS();
}

static void test_encode_decode_utctime_value(void)
{
    TEST("encode_decode_utctime_value");
    uint8_t buf[256];
    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_UTC_TIME;
    val.value.utc_time = 1709654400ULL;  /* arbitrary timestamp */

    int enc_len = mms_encode_value(&val, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_value_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int consumed = mms_decode_value(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)decoded.type, (int)MMS_TYPE_UTC_TIME);
    PASS();
}

static void test_encode_decode_bitstring_value(void)
{
    TEST("encode_decode_bitstring_value");
    uint8_t buf[256];
    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_BIT_STRING;
    val.value.bit_string.data[0] = 0xA5;
    val.value.bit_string.data[1] = 0x5A;
    val.value.bit_string.bit_count = 16;

    int enc_len = mms_encode_value(&val, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_value_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int consumed = mms_decode_value(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)decoded.type, (int)MMS_TYPE_BIT_STRING);
    PASS();
}

/* ========================================================================
 * Malformed PDU Regression Tests (WP-0x MMS BER hardening)
 *
 * Crash reproducers found by the WP-0a fuzz harness
 * (tests/fuzz/fuzz_mms_decoder.c) plus systematic truncation checks:
 * every decoder must return a negative error code on truncated or
 * length-overflowing input instead of reading out of bounds.
 * ======================================================================== */

static void test_decode_initiate_request_field_len_oob(void)
{
    TEST("decode_initiate_request_field_len_oob");
    /* Reproducer: tests/fuzz/corpora/mms_decoder/
     * crash_initiate_request_field_len_oob.bin
     * Outer length (6) fits the 8-byte buffer, but the [0] field inside
     * declares a 0xffffffff length that runs past the end. */
    static const uint8_t pdu[] = {
        0xa8, 0x06, 0x80, 0x84, 0xff, 0xff, 0xff, 0xff
    };
    mms_initiate_request_t req;
    memset(&req, 0, sizeof(req));
    ASSERT_TRUE(mms_decode_initiate_request(pdu, sizeof(pdu), &req) < 0);
    PASS();
}

static void test_decode_command_termination_oob_read(void)
{
    TEST("decode_command_termination_oob_read");
    /* Reproducer: tests/fuzz/corpora/mms_decoder/
     * crash_command_termination_oob_read.bin
     * [2] success field declares length 0 — reading the value byte
     * ran one byte past the end of the 4-byte buffer. */
    static const uint8_t pdu[] = { 0xa0, 0x02, 0x82, 0x00 };
    mms_command_termination_t term;
    memset(&term, 0, sizeof(term));
    ASSERT_TRUE(mms_decode_command_termination(pdu, sizeof(pdu), &term) < 0);
    PASS();
}

static void test_decode_command_termination_identify_pdu(void)
{
    TEST("decode_command_termination_identify_pdu");
    /* Reproducer: tests/fuzz/corpora/mms_decoder/
     * pcap_mms_canonical_f54.bin — a genuine 7-byte Identify response
     * PDU that hits the same unguarded zero-length [2] field read in
     * mms_decode_command_termination(). */
    static const uint8_t pdu[] = { 0xa0, 0x05, 0x02, 0x01, 0x01, 0x82, 0x00 };
    mms_command_termination_t term;
    memset(&term, 0, sizeof(term));
    ASSERT_TRUE(mms_decode_command_termination(pdu, sizeof(pdu), &term) < 0);
    PASS();
}

static void test_decode_cancel_request_truncated(void)
{
    TEST("decode_cancel_request_truncated");
    /* 2-byte input "aa 01": declared content length (1) reaches past
     * the end of the buffer — the loop used to read buffer[2]. */
    static const uint8_t pdu[] = { 0xaa, 0x01 };
    mms_cancel_request_t req;
    memset(&req, 0, sizeof(req));
    ASSERT_TRUE(mms_decode_cancel_request(pdu, sizeof(pdu), &req) < 0);
    PASS();
}

/* ---- systematic truncation checks ------------------------------- */

typedef int (*trunc_decode_fn)(const uint8_t *, size_t, void *);

/* Decode output area large enough for the biggest mms_*_t used below.
 * uint64_t alignment so every struct member is properly aligned. */
static uint64_t trunc_out[80 * 1024];

static int trunc_dec_initiate_req(const uint8_t *b, size_t l, void *o)
{ return mms_decode_initiate_request(b, l, (mms_initiate_request_t *)o); }

static int trunc_dec_initiate_resp(const uint8_t *b, size_t l, void *o)
{ return mms_decode_initiate_response(b, l, (mms_initiate_response_t *)o); }

static int trunc_dec_conclude_req(const uint8_t *b, size_t l, void *o)
{ return mms_decode_conclude_request(b, l, (mms_conclude_request_t *)o); }

static int trunc_dec_conclude_resp(const uint8_t *b, size_t l, void *o)
{ return mms_decode_conclude_response(b, l, (mms_conclude_response_t *)o); }

static int trunc_dec_confirmed_req(const uint8_t *b, size_t l, void *o)
{ return mms_decode_confirmed_request(b, l, (mms_confirmed_request_t *)o); }

static int trunc_dec_confirmed_resp(const uint8_t *b, size_t l, void *o)
{ return mms_decode_confirmed_response(b, l, (mms_confirmed_response_t *)o); }

static int trunc_dec_confirmed_err(const uint8_t *b, size_t l, void *o)
{ return mms_decode_confirmed_error(b, l, (mms_confirmed_error_t *)o); }

static int trunc_dec_info_report(const uint8_t *b, size_t l, void *o)
{ return mms_decode_information_report(b, l, (mms_information_report_t *)o); }

static int trunc_dec_select_req(const uint8_t *b, size_t l, void *o)
{ return mms_decode_select_request(b, l, (mms_select_request_t *)o); }

static int trunc_dec_select_resp(const uint8_t *b, size_t l, void *o)
{ return mms_decode_select_response(b, l, (mms_select_response_t *)o); }

static int trunc_dec_select_wv_req(const uint8_t *b, size_t l, void *o)
{ return mms_decode_select_with_value_request(b, l, (mms_select_with_value_request_t *)o); }

static int trunc_dec_select_wv_resp(const uint8_t *b, size_t l, void *o)
{ return mms_decode_select_with_value_response(b, l, (mms_select_with_value_response_t *)o); }

static int trunc_dec_operate_req(const uint8_t *b, size_t l, void *o)
{ return mms_decode_operate_request(b, l, (mms_operate_request_t *)o); }

static int trunc_dec_operate_resp(const uint8_t *b, size_t l, void *o)
{ return mms_decode_operate_response(b, l, (mms_operate_response_t *)o); }

static int trunc_dec_cancel_req(const uint8_t *b, size_t l, void *o)
{ return mms_decode_cancel_request(b, l, (mms_cancel_request_t *)o); }

static int trunc_dec_cancel_resp(const uint8_t *b, size_t l, void *o)
{ return mms_decode_cancel_response(b, l, (mms_cancel_response_t *)o); }

static int trunc_dec_cmd_term(const uint8_t *b, size_t l, void *o)
{ return mms_decode_command_termination(b, l, (mms_command_termination_t *)o); }

/* Assert that every truncation of a valid encoded PDU is rejected
 * with a negative return value (no crash, no OOB access). */
static void assert_truncations_rejected(const char *name,
                                        trunc_decode_fn decode,
                                        const uint8_t *wire, size_t wire_len)
{
    for (size_t cut = 0; cut < wire_len; cut++) {
        memset(trunc_out, 0, sizeof(trunc_out));
        int ret = decode(wire, cut, (void *)trunc_out);
        if (ret >= 0) {
            printf("FAIL: %s accepted truncated PDU (cut=%zu, ret=%d)\n",
                   name, cut, ret);
            tests_failed++;
            return;
        }
    }
}

static void test_decode_truncated_pdus(void)
{
    TEST("decode_truncated_pdus");

    static uint8_t wire[4096];
    int enc_len;

    /* Association management */
    {
        mms_initiate_request_t in;
        memset(&in, 0, sizeof(in));
        in.proposed_max_pdu_size = 65000;
        in.proposed_data_structure_nesting_level = 10;
        enc_len = mms_encode_initiate_request(&in, wire, sizeof(wire));
        ASSERT_TRUE(enc_len > 0);
        assert_truncations_rejected("initiate_request",
                                    trunc_dec_initiate_req,
                                    wire, (size_t)enc_len);
    }
    {
        mms_initiate_response_t in;
        memset(&in, 0, sizeof(in));
        in.negotiated_max_pdu_size = 32000;
        enc_len = mms_encode_initiate_response(&in, wire, sizeof(wire));
        ASSERT_TRUE(enc_len > 0);
        assert_truncations_rejected("initiate_response",
                                    trunc_dec_initiate_resp,
                                    wire, (size_t)enc_len);
    }
    {
        mms_conclude_request_t in;
        memset(&in, 0, sizeof(in));
        enc_len = mms_encode_conclude_request(&in, wire, sizeof(wire));
        ASSERT_TRUE(enc_len > 0);
        assert_truncations_rejected("conclude_request",
                                    trunc_dec_conclude_req,
                                    wire, (size_t)enc_len);
    }
    {
        mms_conclude_response_t in;
        memset(&in, 0, sizeof(in));
        enc_len = mms_encode_conclude_response(&in, wire, sizeof(wire));
        ASSERT_TRUE(enc_len > 0);
        assert_truncations_rejected("conclude_response",
                                    trunc_dec_conclude_resp,
                                    wire, (size_t)enc_len);
    }

    /* Confirmed services: Read, Write, GetNameList requests */
    {
        mms_confirmed_request_t in;
        memset(&in, 0, sizeof(in));
        in.invoke_id = 1;
        in.service = MMS_SERVICE_TYPE_READ;
        strncpy(in.params.read.variable_spec.domain, "IED1LD0", MMS_MAX_DOMAIN_NAME - 1);
        strncpy(in.params.read.variable_spec.item_id, "XCBR1$ST$Pos$stVal", MMS_MAX_VARIABLE_NAME - 1);
        enc_len = mms_encode_confirmed_request(&in, wire, sizeof(wire));
        ASSERT_TRUE(enc_len > 0);
        assert_truncations_rejected("confirmed_request(read)",
                                    trunc_dec_confirmed_req,
                                    wire, (size_t)enc_len);
    }
    {
        mms_confirmed_request_t in;
        memset(&in, 0, sizeof(in));
        in.invoke_id = 2;
        in.service = MMS_SERVICE_TYPE_WRITE;
        strncpy(in.params.write.variable_spec.domain, "IED1LD0", MMS_MAX_DOMAIN_NAME - 1);
        strncpy(in.params.write.variable_spec.item_id, "XCBR1$CO$Pos$ctlVal", MMS_MAX_VARIABLE_NAME - 1);
        in.params.write.value.type = MMS_TYPE_BOOLEAN;
        in.params.write.value.value.boolean = true;
        enc_len = mms_encode_confirmed_request(&in, wire, sizeof(wire));
        ASSERT_TRUE(enc_len > 0);
        assert_truncations_rejected("confirmed_request(write)",
                                    trunc_dec_confirmed_req,
                                    wire, (size_t)enc_len);
    }
    {
        mms_confirmed_request_t in;
        memset(&in, 0, sizeof(in));
        in.invoke_id = 3;
        in.service = MMS_SERVICE_TYPE_GET_NAMELIST;
        in.params.getnamelist.object_class = MMS_OBJECT_CLASS_NAMED_VARIABLE;
        strncpy(in.params.getnamelist.domain, "IED1LD0", MMS_MAX_DOMAIN_NAME - 1);
        enc_len = mms_encode_confirmed_request(&in, wire, sizeof(wire));
        ASSERT_TRUE(enc_len > 0);
        assert_truncations_rejected("confirmed_request(getnamelist)",
                                    trunc_dec_confirmed_req,
                                    wire, (size_t)enc_len);
    }

    /* Confirmed response / error */
    {
        mms_confirmed_response_t in;
        memset(&in, 0, sizeof(in));
        in.invoke_id = 1;
        in.service = MMS_SERVICE_TYPE_READ;
        in.params.read.value.type = MMS_TYPE_INTEGER;
        in.params.read.value.value.integer = 42;
        enc_len = mms_encode_confirmed_response(&in, wire, sizeof(wire));
        ASSERT_TRUE(enc_len > 0);
        assert_truncations_rejected("confirmed_response(read)",
                                    trunc_dec_confirmed_resp,
                                    wire, (size_t)enc_len);
    }
    {
        mms_confirmed_error_t in;
        memset(&in, 0, sizeof(in));
        in.invoke_id = 5;
        in.error.error_class = MMS_ERROR_CLASS_ACCESS;
        in.error.error_code = MMS_ACCESS_ERROR_OBJECT_NON_EXISTENT;
        enc_len = mms_encode_confirmed_error(&in, wire, sizeof(wire));
        ASSERT_TRUE(enc_len > 0);
        assert_truncations_rejected("confirmed_error",
                                    trunc_dec_confirmed_err,
                                    wire, (size_t)enc_len);
    }

    /* Unconfirmed service */
    {
        mms_information_report_t in;
        memset(&in, 0, sizeof(in));
        strncpy(in.variable_list_name, "DS1", MMS_MAX_VARIABLE_NAME - 1);
        in.num_values = 2;
        in.values[0].type = MMS_TYPE_BOOLEAN;
        in.values[0].value.boolean = true;
        in.values[1].type = MMS_TYPE_INTEGER;
        in.values[1].value.integer = 100;
        enc_len = mms_encode_information_report(&in, wire, sizeof(wire));
        ASSERT_TRUE(enc_len > 0);
        assert_truncations_rejected("information_report",
                                    trunc_dec_info_report,
                                    wire, (size_t)enc_len);
    }

    /* Control services */
    {
        mms_select_request_t in;
        memset(&in, 0, sizeof(in));
        strncpy(in.control_object.domain, "IED1LD0", MMS_MAX_DOMAIN_NAME - 1);
        strncpy(in.control_object.item_id, "XCBR1$CO$Pos", MMS_MAX_VARIABLE_NAME - 1);
        in.check_value = 0x03;
        in.select_timeout_ms = 30000;
        enc_len = mms_encode_select_request(&in, wire, sizeof(wire));
        ASSERT_TRUE(enc_len > 0);
        assert_truncations_rejected("select_request",
                                    trunc_dec_select_req,
                                    wire, (size_t)enc_len);
    }
    {
        mms_select_response_t in;
        memset(&in, 0, sizeof(in));
        in.state = MMS_CONTROL_STATE_SELECTED;
        in.selection_id = 99;
        enc_len = mms_encode_select_response(&in, wire, sizeof(wire));
        ASSERT_TRUE(enc_len > 0);
        assert_truncations_rejected("select_response",
                                    trunc_dec_select_resp,
                                    wire, (size_t)enc_len);
    }
    {
        mms_select_with_value_request_t in;
        memset(&in, 0, sizeof(in));
        strncpy(in.control_object.domain, "IED1LD0", MMS_MAX_DOMAIN_NAME - 1);
        strncpy(in.control_object.item_id, "CSWI$CO$Pos", MMS_MAX_VARIABLE_NAME - 1);
        in.control_value.type = MMS_TYPE_BOOLEAN;
        in.control_value.value.boolean = true;
        enc_len = mms_encode_select_with_value_request(&in, wire, sizeof(wire));
        ASSERT_TRUE(enc_len > 0);
        assert_truncations_rejected("select_with_value_request",
                                    trunc_dec_select_wv_req,
                                    wire, (size_t)enc_len);
    }
    {
        mms_select_with_value_response_t in;
        memset(&in, 0, sizeof(in));
        in.state = MMS_CONTROL_STATE_SELECTED;
        in.selection_id = 77;
        enc_len = mms_encode_select_with_value_response(&in, wire, sizeof(wire));
        ASSERT_TRUE(enc_len > 0);
        assert_truncations_rejected("select_with_value_response",
                                    trunc_dec_select_wv_resp,
                                    wire, (size_t)enc_len);
    }
    {
        mms_operate_request_t in;
        memset(&in, 0, sizeof(in));
        strncpy(in.control_object.domain, "IED1LD0", MMS_MAX_DOMAIN_NAME - 1);
        strncpy(in.control_object.item_id, "XCBR1$CO$Pos", MMS_MAX_VARIABLE_NAME - 1);
        in.selection_id = 42;
        in.has_control_value = true;
        in.control_value.type = MMS_TYPE_BOOLEAN;
        in.control_value.value.boolean = true;
        enc_len = mms_encode_operate_request(&in, wire, sizeof(wire));
        ASSERT_TRUE(enc_len > 0);
        assert_truncations_rejected("operate_request",
                                    trunc_dec_operate_req,
                                    wire, (size_t)enc_len);
    }
    {
        mms_operate_response_t in;
        memset(&in, 0, sizeof(in));
        in.state = MMS_CONTROL_STATE_READY;
        in.success = true;
        enc_len = mms_encode_operate_response(&in, wire, sizeof(wire));
        ASSERT_TRUE(enc_len > 0);
        assert_truncations_rejected("operate_response",
                                    trunc_dec_operate_resp,
                                    wire, (size_t)enc_len);
    }
    {
        mms_cancel_request_t in;
        memset(&in, 0, sizeof(in));
        strncpy(in.control_object.domain, "IED1LD0", MMS_MAX_DOMAIN_NAME - 1);
        strncpy(in.control_object.item_id, "XCBR1$CO$Pos", MMS_MAX_VARIABLE_NAME - 1);
        in.selection_id = 42;
        enc_len = mms_encode_cancel_request(&in, wire, sizeof(wire));
        ASSERT_TRUE(enc_len > 0);
        assert_truncations_rejected("cancel_request",
                                    trunc_dec_cancel_req,
                                    wire, (size_t)enc_len);
    }
    {
        mms_cancel_response_t in;
        memset(&in, 0, sizeof(in));
        enc_len = mms_encode_cancel_response(&in, wire, sizeof(wire));
        ASSERT_TRUE(enc_len > 0);
        assert_truncations_rejected("cancel_response",
                                    trunc_dec_cancel_resp,
                                    wire, (size_t)enc_len);
    }
    {
        mms_command_termination_t in;
        memset(&in, 0, sizeof(in));
        strncpy(in.control_object.domain, "IED1LD0", MMS_MAX_DOMAIN_NAME - 1);
        strncpy(in.control_object.item_id, "XCBR1$CO$Pos", MMS_MAX_VARIABLE_NAME - 1);
        in.selection_id = 55;
        in.success = true;
        in.termination_reason = 0;
        enc_len = mms_encode_command_termination(&in, wire, sizeof(wire));
        ASSERT_TRUE(enc_len > 0);
        assert_truncations_rejected("command_termination",
                                    trunc_dec_cmd_term,
                                    wire, (size_t)enc_len);
    }

    PASS();
}

static void test_decode_value_length_overflow(void)
{
    TEST("decode_value_length_overflow");
    /* Found by 60s libFuzzer run: a 90-octet BER length whose value wraps
     * to SIZE_MAX-2 made the offset+length bounds check in
     * mms_decode_value() overflow and pass, causing a 1-byte OOB read in
     * the BIT_STRING case. */
    static const uint8_t pdu[92] = {
        0x84, 0xda,                                     /* tag + 90-octet length */
        0x01, 0xfd, 0xa5, 0x5a, 0x01, 0x00, 0x00, 0x00, /* length octets... */
        0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x77, 0x00, 0x00, 0x00, 0xa0, 0x00, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xdf, 0xff,
        0xff, 0xff, 0xff, 0xff, 0x83, 0x00, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd  /* ...wraps to SIZE_MAX-2 */
    };
    mms_value_t value;
    memset(&value, 0, sizeof(value));
    ASSERT_TRUE(mms_decode_value(pdu, sizeof(pdu), &value) < 0);
    PASS();
}

/* Oversized declared lengths must be rejected on every PDU entry point,
 * not just the ones covered by the committed reproducers. */
static void test_decode_oversized_outer_lengths(void)
{
    TEST("decode_oversized_outer_lengths");

    static const uint8_t initiate_req[] = {
        0xa8, 0x84, 0xff, 0xff, 0xff, 0xff, 0x80, 0x01, 0x01
    };
    static const uint8_t confirmed_req[] = {
        0xa0, 0x84, 0xff, 0xff, 0xff, 0xff, 0x80, 0x01, 0x01
    };
    static const uint8_t confirmed_resp[] = {
        0xa1, 0x84, 0xff, 0xff, 0xff, 0xff, 0x80, 0x01, 0x01
    };
    static const uint8_t confirmed_err[] = {
        0xa2, 0x84, 0xff, 0xff, 0xff, 0xff, 0x80, 0x01, 0x01
    };
    static const uint8_t info_report[] = {
        0xa3, 0x84, 0xff, 0xff, 0xff, 0xff, 0x80, 0x01, 0x01
    };

    mms_initiate_request_t initiate_req_out;
    mms_confirmed_request_t confirmed_req_out;
    mms_confirmed_response_t confirmed_resp_out;
    mms_confirmed_error_t confirmed_err_out;
    mms_information_report_t info_report_out;

    memset(&initiate_req_out, 0, sizeof(initiate_req_out));
    ASSERT_TRUE(mms_decode_initiate_request(initiate_req, sizeof(initiate_req),
                                            &initiate_req_out) < 0);
    memset(&confirmed_req_out, 0, sizeof(confirmed_req_out));
    ASSERT_TRUE(mms_decode_confirmed_request(confirmed_req, sizeof(confirmed_req),
                                             &confirmed_req_out) < 0);
    memset(&confirmed_resp_out, 0, sizeof(confirmed_resp_out));
    ASSERT_TRUE(mms_decode_confirmed_response(confirmed_resp, sizeof(confirmed_resp),
                                              &confirmed_resp_out) < 0);
    memset(&confirmed_err_out, 0, sizeof(confirmed_err_out));
    ASSERT_TRUE(mms_decode_confirmed_error(confirmed_err, sizeof(confirmed_err),
                                           &confirmed_err_out) < 0);
    memset(&info_report_out, 0, sizeof(info_report_out));
    ASSERT_TRUE(mms_decode_information_report(info_report, sizeof(info_report),
                                              &info_report_out) < 0);
    PASS();
}

int main(void)
{
    printf("\n=== MMS BER Codec Tests ===\n");

    printf("\n--- Length Helpers ---\n");
    test_encode_decode_length_short();
    test_encode_decode_length_long();

    printf("\n--- Value Encode/Decode ---\n");
    test_encode_decode_boolean_value();
    test_encode_decode_integer_value();
    test_encode_decode_unsigned_value();
    test_encode_decode_float_value();
    test_encode_decode_visiblestring_value();
    test_encode_decode_octetstring_value();
    test_encode_decode_utctime_value();
    test_encode_decode_bitstring_value();

    printf("\n--- Initiate/Conclude ---\n");
    test_initiate_request_roundtrip();
    test_initiate_response_roundtrip();
    test_conclude_request_roundtrip();
    test_conclude_response_roundtrip();

    printf("\n--- Confirmed Services ---\n");
    test_read_request_roundtrip();
    test_read_response_roundtrip();
    test_write_request_roundtrip();
    test_getnamelist_request_roundtrip();
    test_confirmed_error_roundtrip();

    printf("\n--- InformationReport ---\n");
    test_information_report_roundtrip();

    printf("\n--- Error Handling ---\n");
    test_null_parameters();
    test_buffer_too_small();
    test_error_string_mapping();

    printf("\n--- Control Services ---\n");
    test_select_request_roundtrip();
    test_select_response_roundtrip();
    test_select_with_value_request_roundtrip();
    test_select_with_value_response_roundtrip();
    test_operate_request_roundtrip();
    test_operate_response_roundtrip();
    test_cancel_request_roundtrip();
    test_cancel_response_roundtrip();
    test_command_termination_roundtrip();

    printf("\n--- Malformed PDU Regression (WP-0x) ---\n");
    test_decode_initiate_request_field_len_oob();
    test_decode_command_termination_oob_read();
    test_decode_command_termination_identify_pdu();
    test_decode_cancel_request_truncated();
    test_decode_truncated_pdus();
    test_decode_value_length_overflow();
    test_decode_oversized_outer_lengths();

    printf("\n=== Test Summary ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
