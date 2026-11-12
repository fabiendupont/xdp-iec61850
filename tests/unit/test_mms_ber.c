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

    printf("\n=== Test Summary ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
