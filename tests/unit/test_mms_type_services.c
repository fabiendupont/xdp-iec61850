/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for MMS Named Type Services BER Encoding/Decoding
 *
 * Tests encode/decode round-trips for DefineNamedType, DeleteNamedType,
 * and GetNamedTypeAttributes at the BER level (confirmed request and
 * confirmed response envelopes).
 *
 * Named types are not used in IEC 61850 but are part of ISO 9506-2.
 * The server returns serviceError for these services.
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
#define ASSERT_STR_EQ(a, b) do { if (strcmp((a), (b)) != 0) { \
    printf("FAIL: \"%s\" != \"%s\"\n", (a), (b)); \
    tests_failed++; return; } } while (0)

/* ========================================================================
 * DefineNamedType
 * ======================================================================== */

static void test_define_named_type_roundtrip(void)
{
    TEST("define_named_type_request_roundtrip");

    mms_confirmed_request_t req;
    memset(&req, 0, sizeof(req));
    req.invoke_id = 10;
    req.service = MMS_SERVICE_TYPE_DEFINE_NAMED_TYPE;
    snprintf(req.params.definenamedtype.domain,
             sizeof(req.params.definenamedtype.domain), "TestDomain");
    snprintf(req.params.definenamedtype.type_name,
             sizeof(req.params.definenamedtype.type_name), "MyIntType");
    req.params.definenamedtype.type_spec = MMS_TYPE_INTEGER;

    uint8_t buf[512];
    int enc = mms_encode_confirmed_request(&req, buf, sizeof(buf));
    ASSERT_TRUE(enc > 0);

    mms_confirmed_request_t dec;
    memset(&dec, 0, sizeof(dec));
    int consumed = mms_decode_confirmed_request(buf, (size_t)enc, &dec);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)dec.invoke_id, 10);
    ASSERT_EQ((int)dec.service, (int)MMS_SERVICE_TYPE_DEFINE_NAMED_TYPE);
    ASSERT_STR_EQ(dec.params.definenamedtype.domain, "TestDomain");
    ASSERT_STR_EQ(dec.params.definenamedtype.type_name, "MyIntType");
    ASSERT_EQ((int)dec.params.definenamedtype.type_spec, (int)MMS_TYPE_INTEGER);

    PASS();
}

static void test_define_named_type_vmd_scope(void)
{
    TEST("define_named_type_vmd_scope");

    /* VMD-scope: empty domain */
    mms_confirmed_request_t req;
    memset(&req, 0, sizeof(req));
    req.invoke_id = 11;
    req.service = MMS_SERVICE_TYPE_DEFINE_NAMED_TYPE;
    req.params.definenamedtype.domain[0] = '\0';
    snprintf(req.params.definenamedtype.type_name,
             sizeof(req.params.definenamedtype.type_name), "GlobalType");
    req.params.definenamedtype.type_spec = MMS_TYPE_BOOLEAN;

    uint8_t buf[512];
    int enc = mms_encode_confirmed_request(&req, buf, sizeof(buf));
    ASSERT_TRUE(enc > 0);

    mms_confirmed_request_t dec;
    memset(&dec, 0, sizeof(dec));
    int consumed = mms_decode_confirmed_request(buf, (size_t)enc, &dec);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)dec.service, (int)MMS_SERVICE_TYPE_DEFINE_NAMED_TYPE);
    ASSERT_STR_EQ(dec.params.definenamedtype.type_name, "GlobalType");
    ASSERT_EQ((int)dec.params.definenamedtype.type_spec, (int)MMS_TYPE_BOOLEAN);

    PASS();
}

/* ========================================================================
 * DeleteNamedType
 * ======================================================================== */

static void test_delete_named_type_roundtrip(void)
{
    TEST("delete_named_type_request_roundtrip");

    mms_confirmed_request_t req;
    memset(&req, 0, sizeof(req));
    req.invoke_id = 20;
    req.service = MMS_SERVICE_TYPE_DELETE_NAMED_TYPE;
    snprintf(req.params.deletenamedtype.domain,
             sizeof(req.params.deletenamedtype.domain), "Dom1");
    snprintf(req.params.deletenamedtype.type_name,
             sizeof(req.params.deletenamedtype.type_name), "OldType");

    uint8_t buf[512];
    int enc = mms_encode_confirmed_request(&req, buf, sizeof(buf));
    ASSERT_TRUE(enc > 0);

    mms_confirmed_request_t dec;
    memset(&dec, 0, sizeof(dec));
    int consumed = mms_decode_confirmed_request(buf, (size_t)enc, &dec);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)dec.invoke_id, 20);
    ASSERT_EQ((int)dec.service, (int)MMS_SERVICE_TYPE_DELETE_NAMED_TYPE);
    ASSERT_STR_EQ(dec.params.deletenamedtype.domain, "Dom1");
    ASSERT_STR_EQ(dec.params.deletenamedtype.type_name, "OldType");

    PASS();
}

/* ========================================================================
 * GetNamedTypeAttributes
 * ======================================================================== */

static void test_get_named_type_attrs_roundtrip(void)
{
    TEST("get_named_type_attrs_request_roundtrip");

    mms_confirmed_request_t req;
    memset(&req, 0, sizeof(req));
    req.invoke_id = 30;
    req.service = MMS_SERVICE_TYPE_GET_NAMED_TYPE_ATTRS;
    snprintf(req.params.getnamedtypeattrs.domain,
             sizeof(req.params.getnamedtypeattrs.domain), "LD0");
    snprintf(req.params.getnamedtypeattrs.type_name,
             sizeof(req.params.getnamedtypeattrs.type_name), "MeasFloat");

    uint8_t buf[512];
    int enc = mms_encode_confirmed_request(&req, buf, sizeof(buf));
    ASSERT_TRUE(enc > 0);

    mms_confirmed_request_t dec;
    memset(&dec, 0, sizeof(dec));
    int consumed = mms_decode_confirmed_request(buf, (size_t)enc, &dec);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)dec.invoke_id, 30);
    ASSERT_EQ((int)dec.service, (int)MMS_SERVICE_TYPE_GET_NAMED_TYPE_ATTRS);
    ASSERT_STR_EQ(dec.params.getnamedtypeattrs.domain, "LD0");
    ASSERT_STR_EQ(dec.params.getnamedtypeattrs.type_name, "MeasFloat");

    PASS();
}

/* ========================================================================
 * Response Encoding/Decoding
 * ======================================================================== */

static void test_define_named_type_response(void)
{
    TEST("define_named_type_response_roundtrip");

    mms_confirmed_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.invoke_id = 10;
    resp.service = MMS_SERVICE_TYPE_DEFINE_NAMED_TYPE;

    uint8_t buf[512];
    int enc = mms_encode_confirmed_response(&resp, buf, sizeof(buf));
    ASSERT_TRUE(enc > 0);

    mms_confirmed_response_t dec;
    memset(&dec, 0, sizeof(dec));
    int consumed = mms_decode_confirmed_response(buf, (size_t)enc, &dec);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)dec.invoke_id, 10);
    ASSERT_EQ((int)dec.service, (int)MMS_SERVICE_TYPE_DEFINE_NAMED_TYPE);

    PASS();
}

static void test_delete_named_type_response(void)
{
    TEST("delete_named_type_response_roundtrip");

    mms_confirmed_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.invoke_id = 20;
    resp.service = MMS_SERVICE_TYPE_DELETE_NAMED_TYPE;

    uint8_t buf[512];
    int enc = mms_encode_confirmed_response(&resp, buf, sizeof(buf));
    ASSERT_TRUE(enc > 0);

    mms_confirmed_response_t dec;
    memset(&dec, 0, sizeof(dec));
    int consumed = mms_decode_confirmed_response(buf, (size_t)enc, &dec);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)dec.invoke_id, 20);
    ASSERT_EQ((int)dec.service, (int)MMS_SERVICE_TYPE_DELETE_NAMED_TYPE);

    PASS();
}

static void test_get_named_type_attrs_response(void)
{
    TEST("get_named_type_attrs_response_roundtrip");

    mms_confirmed_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.invoke_id = 30;
    resp.service = MMS_SERVICE_TYPE_GET_NAMED_TYPE_ATTRS;
    resp.params.getnamedtypeattrs.type_spec = MMS_TYPE_FLOATING_POINT;

    uint8_t buf[512];
    int enc = mms_encode_confirmed_response(&resp, buf, sizeof(buf));
    ASSERT_TRUE(enc > 0);

    mms_confirmed_response_t dec;
    memset(&dec, 0, sizeof(dec));
    int consumed = mms_decode_confirmed_response(buf, (size_t)enc, &dec);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)dec.invoke_id, 30);
    ASSERT_EQ((int)dec.service, (int)MMS_SERVICE_TYPE_GET_NAMED_TYPE_ATTRS);
    ASSERT_EQ((int)dec.params.getnamedtypeattrs.type_spec,
              (int)MMS_TYPE_FLOATING_POINT);

    PASS();
}

/* ========================================================================
 * Error path: type services should produce serviceError on server
 *
 * The server handler (process_request) is static, so we test at the
 * BER level: encode a confirmed error with the expected error class
 * and verify the roundtrip preserves the error information.
 * ======================================================================== */

static void test_type_service_error_roundtrip(void)
{
    TEST("type_service_error_roundtrip");

    /* Simulate the error the server would return for type services */
    mms_confirmed_error_t err;
    memset(&err, 0, sizeof(err));
    err.invoke_id = 40;
    err.error.error_class = MMS_ERROR_CLASS_SERVICE;
    err.error.error_code = MMS_SERVICE_ERROR_OTHER;

    uint8_t buf[512];
    int enc = mms_encode_confirmed_error(&err, buf, sizeof(buf));
    ASSERT_TRUE(enc > 0);

    mms_confirmed_error_t dec;
    memset(&dec, 0, sizeof(dec));
    int consumed = mms_decode_confirmed_error(buf, (size_t)enc, &dec);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)dec.invoke_id, 40);
    ASSERT_EQ((int)dec.error.error_class, (int)MMS_ERROR_CLASS_SERVICE);
    ASSERT_EQ((int)dec.error.error_code, (int)MMS_SERVICE_ERROR_OTHER);

    PASS();
}

/* ========================================================================
 * Main
 * ======================================================================== */

int main(void)
{
    printf("MMS Named Type Services BER Tests\n");
    printf("==================================\n");

    /* Request roundtrips */
    test_define_named_type_roundtrip();
    test_define_named_type_vmd_scope();
    test_delete_named_type_roundtrip();
    test_get_named_type_attrs_roundtrip();

    /* Response roundtrips */
    test_define_named_type_response();
    test_delete_named_type_response();
    test_get_named_type_attrs_response();

    /* Error path */
    test_type_service_error_roundtrip();

    printf("\n  Results: %d/%d passed, %d failed\n",
           tests_passed, tests_run, tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
