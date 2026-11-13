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

static void test_getnamelist_response_long_list(void)
{
    TEST("getnamelist_response_long_list");
    /* Regression for the short-form length bug: >127 content bytes in
     * listOfIdentifier previously produced a corrupted PDU. */
    uint8_t buf[MMS_MAX_PDU_SIZE];
    mms_confirmed_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.invoke_id = 7;
    resp.service = MMS_SERVICE_TYPE_GET_NAMELIST;
    resp.params.getnamelist.num_identifiers = 30;
    for (uint32_t i = 0; i < 30; i++) {
        (void)snprintf(resp.params.getnamelist.identifiers[i],
                       MMS_MAX_VARIABLE_NAME, "var%02uabcdefghijklmnop", i);
    }

    int enc_len = mms_encode_confirmed_response(&resp, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_confirmed_response_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int consumed = mms_decode_confirmed_response(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)decoded.params.getnamelist.num_identifiers, 30);
    for (uint32_t i = 0; i < 30; i++) {
        ASSERT_TRUE(strcmp(decoded.params.getnamelist.identifiers[i],
                           resp.params.getnamelist.identifiers[i]) == 0);
    }
    ASSERT_TRUE(!decoded.params.getnamelist.more_follows);

    /* Control: a short list still uses the canonical short form */
    memset(&resp, 0, sizeof(resp));
    resp.invoke_id = 8;
    resp.service = MMS_SERVICE_TYPE_GET_NAMELIST;
    resp.params.getnamelist.num_identifiers = 2;
    (void)snprintf(resp.params.getnamelist.identifiers[0], MMS_MAX_VARIABLE_NAME, "a");
    (void)snprintf(resp.params.getnamelist.identifiers[1], MMS_MAX_VARIABLE_NAME, "b");
    enc_len = mms_encode_confirmed_response(&resp, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);
    memset(&decoded, 0, sizeof(decoded));
    consumed = mms_decode_confirmed_response(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)decoded.params.getnamelist.num_identifiers, 2);
    PASS();
}

static void test_readnamedvarlist_response_long_list(void)
{
    TEST("readnamedvarlist_response_long_list");
    /* Regression for the short-form length bug in listOfAccessResult. */
    uint8_t buf[MMS_MAX_PDU_SIZE];
    mms_confirmed_response_t resp;
    memset(&resp, 0, sizeof(resp));
    resp.invoke_id = 9;
    resp.service = MMS_SERVICE_TYPE_READ_NAMED_VARLIST;
    resp.params.readnamedvarlist.num_values = 12;
    for (uint32_t i = 0; i < 12; i++) {
        resp.params.readnamedvarlist.values[i].type = MMS_TYPE_VISIBLE_STRING;
        (void)snprintf(resp.params.readnamedvarlist.values[i].value.visible_string.data,
                       MMS_MAX_STRING_LENGTH, "value%02u_0123456789abcdef", i);
        resp.params.readnamedvarlist.values[i].value.visible_string.len =
            strlen(resp.params.readnamedvarlist.values[i].value.visible_string.data);
    }

    int enc_len = mms_encode_confirmed_response(&resp, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_confirmed_response_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int consumed = mms_decode_confirmed_response(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(consumed > 0);
    ASSERT_EQ((int)decoded.params.readnamedvarlist.num_values, 12);
    for (uint32_t i = 0; i < 12; i++) {
        ASSERT_EQ((int)decoded.params.readnamedvarlist.values[i].value.visible_string.len,
                  (int)resp.params.readnamedvarlist.values[i].value.visible_string.len);
        ASSERT_TRUE(memcmp(decoded.params.readnamedvarlist.values[i].value.visible_string.data,
                           resp.params.readnamedvarlist.values[i].value.visible_string.data,
                           resp.params.readnamedvarlist.values[i].value.visible_string.len) == 0);
    }
    PASS();
}

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
 * IEC 61850-7-2 URCB Report Decode (WP-1b)
 *
 * Roundtrip and malformed-input coverage for
 * mms_decode_iec61850_report(), the decoder counterpart of
 * mms_encode_iec61850_report().
 * ======================================================================== */

/* Build a standard 3-member test report. opt_flds carries optFlds
 * bits 0-7 (b1 seqNum=0x40, b2 timeOfEntry=0x20, b3 reason=0x10,
 * b4 datSet=0x08, b5 dataRef=0x04, b6 bufOvfl=0x02, b7 entryID=0x01);
 * the confRev bit (b8) is carried by conf_rev_present. */
static void fill_61850_report(mms_iec61850_report_t* r, uint8_t opt_flds,
                              bool conf_rev_on)
{
    memset(r, 0, sizeof(*r));
    strncpy(r->rpt_id, "ied1ld0/rp1", MMS_MAX_STRING_LENGTH - 1);
    strncpy(r->dat_set, "ied1ld0/DS1", MMS_MAX_STRING_LENGTH - 1);
    r->opt_flds_byte = opt_flds;
    r->sq_num = 4711;
    r->sq_num_present = (opt_flds & 0x40u) != 0;
    r->time_of_entry[0] = 0x11;
    r->time_of_entry[1] = 0x22;
    r->time_of_entry[2] = 0x33;
    r->time_of_entry[3] = 0x44;
    r->time_of_entry[4] = 0x55;
    r->time_of_entry[5] = 0x66;
    r->time_of_entry_present = (opt_flds & 0x20u) != 0;
    r->conf_rev = 1234;
    r->conf_rev_present = conf_rev_on;
    /* WP-1f (BUG-R4): bufOvfl / entryID are emitted iff the
     * corresponding optFlds bit is set. */
    r->buffer_overflow = true;
    r->entry_id = 0x1122334455667788ULL;
    r->num_members = 3;
    r->reason_code = 0x2A;
    r->num_values = 3;
    r->values[0].type = MMS_TYPE_BOOLEAN;
    r->values[0].value.boolean = true;
    r->values[1].type = MMS_TYPE_INTEGER;
    r->values[1].value.integer = -1234;
    r->values[2].type = MMS_TYPE_UNSIGNED;
    r->values[2].value.unsigned_val = 98765;
}

static bool value_equals_61850(const mms_value_t* a, const mms_value_t* b)
{
    if (a->type != b->type) {
        return false;
    }
    switch (a->type) {
        case MMS_TYPE_BOOLEAN:
            return a->value.boolean == b->value.boolean;
        case MMS_TYPE_INTEGER:
            return a->value.integer == b->value.integer;
        case MMS_TYPE_UNSIGNED:
            return a->value.unsigned_val == b->value.unsigned_val;
        default:
            return false;
    }
}

/* Verify a decoded report against the encoded input and the optFlds
 * combination used. */
static void verify_61850_decode(const mms_information_report_t* d,
                                const mms_iec61850_report_t* in,
                                uint8_t opt_flds, bool conf_rev_on)
{
    ASSERT_TRUE(strcmp(d->rpt_id, in->rpt_id) == 0);
    /* datSet: always emitted by the encoder (bit set or consumed by
     * the decoder's datSet leniency), so it must always roundtrip */
    ASSERT_TRUE(strcmp(d->dat_set, in->dat_set) == 0);
    ASSERT_TRUE(strcmp(d->variable_list_name, "RPT") == 0);

    /* optFlds-driven presence */
    ASSERT_TRUE(d->sq_num_present == ((opt_flds & 0x40u) != 0));
    if (opt_flds & 0x40u) {
        ASSERT_EQ((int)d->sq_num, 4711);
    }
    ASSERT_TRUE(d->report_timestamp_present == ((opt_flds & 0x20u) != 0));
    if (opt_flds & 0x20u) {
        ASSERT_TRUE(d->report_timestamp == 0x112233445566ULL);
    }
    ASSERT_TRUE(d->reasons_present == ((opt_flds & 0x10u) != 0));
    if (opt_flds & 0x10u) {
        for (int i = 0; i < 3; i++) {
            ASSERT_EQ((int)d->reasons[i], 0x2A);
        }
    }
    ASSERT_TRUE(d->conf_rev_present == conf_rev_on);
    if (conf_rev_on) {
        ASSERT_EQ((int)d->conf_rev, 1234);
    }

    /* WP-1f (BUG-R4): bufOvfl / entryID presence and values follow
     * the optFlds bits (the encoder emits them iff the bit is set). */
    ASSERT_TRUE(d->buffer_overflow_present == ((opt_flds & 0x02u) != 0));
    if (opt_flds & 0x02u) {
        ASSERT_TRUE(d->buffer_overflow);
    }
    ASSERT_TRUE(d->entry_id_present == ((opt_flds & 0x01u) != 0));
    if (opt_flds & 0x01u) {
        ASSERT_TRUE(d->entry_id == 0x1122334455667788ULL);
    }

    /* Fields the 7-2 encoder never emits must stay absent */
    ASSERT_TRUE(d->data_references_present == false);
    ASSERT_TRUE(d->config_ref_present == false);

    /* Inclusion bit string: 3 members, first byte 0xE0 */
    ASSERT_EQ((int)d->incl_bit_str_len, 1);
    ASSERT_EQ((int)d->incl_bit_str[0], 0xE0);

    /* Values: one per included member */
    ASSERT_EQ((int)d->num_values, 3);
    ASSERT_TRUE(value_equals_61850(&d->values[0], &in->values[0]));
    ASSERT_TRUE(value_equals_61850(&d->values[1], &in->values[1]));
    ASSERT_TRUE(value_equals_61850(&d->values[2], &in->values[2]));
}

static void test_iec61850_report_roundtrip_all_off(void)
{
    TEST("iec61850_report_roundtrip_all_off");
    uint8_t buf[512];
    mms_iec61850_report_t in;
    fill_61850_report(&in, 0x00, false);

    int enc_len = mms_encode_iec61850_report(&in, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_information_report_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int ret = mms_decode_iec61850_report(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(ret > 0);
    ASSERT_EQ(ret, enc_len);
    verify_61850_decode(&decoded, &in, 0x00, false);
    PASS();
}

static void test_iec61850_report_roundtrip_all_on(void)
{
    TEST("iec61850_report_roundtrip_all_on");
    uint8_t buf[512];
    mms_iec61850_report_t in;
    /* b1..b7 set (reserved b0 clear), confRev on */
    fill_61850_report(&in, 0x7Eu, true);

    int enc_len = mms_encode_iec61850_report(&in, buf, sizeof(buf));
    ASSERT_TRUE(enc_len > 0);

    mms_information_report_t decoded;
    memset(&decoded, 0, sizeof(decoded));
    int ret = mms_decode_iec61850_report(buf, (size_t)enc_len, &decoded);
    ASSERT_TRUE(ret > 0);
    ASSERT_EQ(ret, enc_len);
    verify_61850_decode(&decoded, &in, 0x7Eu, true);
    PASS();
}

static void test_iec61850_report_roundtrip_each_optfld(void)
{
    TEST("iec61850_report_roundtrip_each_optfld");
    static const struct {
        uint8_t opt_flds;
        bool conf_rev_on;
        const char* name;
    } cases[] = {
        { 0x40u, false, "seqNum" },
        { 0x20u, false, "timeOfEntry" },
        { 0x10u, false, "reason" },
        { 0x08u, false, "datSet" },
        { 0x04u, false, "dataRef (no wire field)" },
        { 0x02u, false, "bufferOverflow" },
        { 0x01u, false, "entryID" },
        { 0x00u, true,  "confRev" },
    };
    uint8_t buf[512];

    for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
        mms_iec61850_report_t in;
        fill_61850_report(&in, cases[c].opt_flds, cases[c].conf_rev_on);

        int enc_len = mms_encode_iec61850_report(&in, buf, sizeof(buf));
        if (enc_len <= 0) {
            printf("FAIL: encode %s (ret=%d)\n", cases[c].name, enc_len);
            tests_failed++;
            return;
        }

        mms_information_report_t decoded;
        memset(&decoded, 0, sizeof(decoded));
        int ret = mms_decode_iec61850_report(buf, (size_t)enc_len, &decoded);
        if (ret != enc_len) {
            printf("FAIL: decode %s (ret=%d enc=%d)\n",
                   cases[c].name, ret, enc_len);
            tests_failed++;
            return;
        }
        verify_61850_decode(&decoded, &in,
                            cases[c].opt_flds, cases[c].conf_rev_on);
    }
    PASS();
}

static void test_iec61850_report_null_params(void)
{
    TEST("iec61850_report_null_params");
    uint8_t buf[64];
    mms_information_report_t report;
    memset(&report, 0, sizeof(report));

    ASSERT_TRUE(mms_decode_iec61850_report(NULL, sizeof(buf), &report) < 0);
    ASSERT_TRUE(mms_decode_iec61850_report(buf, sizeof(buf), NULL) < 0);
    ASSERT_TRUE(mms_decode_iec61850_report(buf, 0, &report) < 0);
    ASSERT_TRUE(mms_decode_iec61850_report(buf, 1, &report) < 0);
    PASS();
}

/* Wrap a listOfAccessResult content blob into a full 7-2 report PDU:
 * A3 len ( A0 len ( A1 05 80 03 "RPT" ) ( A0 len list ) ).
 * Returns the encoded length, or 0 if it does not fit / is too long
 * for short-form lengths. */
static size_t wrap_61850_list(uint8_t* out, size_t out_sz,
                              const uint8_t* list, size_t list_len)
{
    if (list_len > 127) {
        return 0;
    }
    size_t ir_len = 7 + 2 + list_len;
    if (out_sz < 4 + ir_len) {
        return 0;
    }

    size_t pos = 0;
    out[pos++] = 0xA3;
    out[pos++] = (uint8_t)(2 + ir_len);
    out[pos++] = 0xA0;
    out[pos++] = (uint8_t)ir_len;
    out[pos++] = 0xA1;
    out[pos++] = 0x05;
    out[pos++] = 0x80;
    out[pos++] = 0x03;
    out[pos++] = 0x52;  /* 'R' */
    out[pos++] = 0x50;  /* 'P' */
    out[pos++] = 0x54;  /* 'T' */
    out[pos++] = 0xA0;
    out[pos++] = (uint8_t)list_len;
    memcpy(out + pos, list, list_len);
    return pos + list_len;
}

/* Assert that a hand-built listOfAccessResult is rejected. */
static void assert_61850_list_rejected(const char* name,
                                       const uint8_t* list, size_t list_len)
{
    uint8_t wire[256];
    size_t wire_len = wrap_61850_list(wire, sizeof(wire), list, list_len);
    if (wire_len == 0) {
        printf("FAIL: %s wrap failed\n", name);
        tests_failed++;
        return;
    }

    mms_information_report_t report;
    memset(&report, 0, sizeof(report));
    int ret = mms_decode_iec61850_report(wire, wire_len, &report);
    if (ret >= 0) {
        printf("FAIL: %s accepted malformed list (ret=%d)\n", name, ret);
        tests_failed++;
        return;
    }
}

static void test_iec61850_report_malformed_fields(void)
{
    TEST("iec61850_report_malformed_fields");
    /* rptID missing (wrong first tag) */
    assert_61850_list_rejected("no_rptid",
        (const uint8_t[]){ 0x86, 0x01, 0x01 }, 3);

    /* rptID wire length exceeds the list parent */
    assert_61850_list_rejected("rptid_len_overflow",
        (const uint8_t[]){ 0x8A, 0x84, 0xFF, 0xFF, 0xFF, 0xFF }, 6);

    /* optFlds zero-length */
    assert_61850_list_rejected("optflds_zero_len",
        (const uint8_t[]){ 0x8A, 0x01, 'R', 0x84, 0x00 }, 5);

    /* optFlds wire length exceeds the list parent */
    assert_61850_list_rejected("optflds_len_overflow",
        (const uint8_t[]){ 0x8A, 0x01, 'R', 0x84, 0x84,
                           0xFF, 0xFF, 0xFF, 0xFF }, 9);

    /* optFlds unused-bit count 8 (invalid BER, > 7) */
    assert_61850_list_rejected("optflds_unused_8",
        (const uint8_t[]){ 0x8A, 0x01, 'R', 0x84, 0x02, 0x08, 0x00 }, 7);

    /* optFlds empty bit string with non-zero unused count */
    assert_61850_list_rejected("optflds_empty_nonzero_unused",
        (const uint8_t[]){ 0x8A, 0x01, 'R', 0x84, 0x01, 0x01 }, 6);

    /* seqNum optFld set but no seqNum field follows */
    assert_61850_list_rejected("seqnum_missing",
        (const uint8_t[]){ 0x8A, 0x01, 'R', 0x84, 0x03, 0x06, 0x40, 0x00,
                           0x8A, 0x01, 'D', 0x84, 0x02, 0x05, (uint8_t)0xE0 },
        15);

    /* seqNum zero-length */
    assert_61850_list_rejected("seqnum_zero_len",
        (const uint8_t[]){ 0x8A, 0x01, 'R', 0x84, 0x03, 0x06, 0x40, 0x00,
                           0x86, 0x00 }, 10);

    /* seqNum wire length exceeds the list parent */
    assert_61850_list_rejected("seqnum_len_overflow",
        (const uint8_t[]){ 0x8A, 0x01, 'R', 0x84, 0x03, 0x06, 0x40, 0x00,
                           0x86, 0x84, 0xFF, 0xFF, 0xFF, 0xFF }, 14);

    /* timeOfEntry wrong size (5 bytes instead of 6) */
    assert_61850_list_rejected("timeofentry_bad_size",
        (const uint8_t[]){ 0x8A, 0x01, 'R', 0x84, 0x03, 0x06, 0x20, 0x00,
                           0x8C, 0x05, 1, 2, 3, 4, 5 }, 15);

    /* timeOfEntry wire length exceeds the list parent */
    assert_61850_list_rejected("timeofentry_len_overflow",
        (const uint8_t[]){ 0x8A, 0x01, 'R', 0x84, 0x03, 0x06, 0x20, 0x00,
                           0x8C, 0x84, 0xFF, 0xFF, 0xFF, 0xFF }, 14);

    /* datSet wire length exceeds the list parent */
    assert_61850_list_rejected("datset_len_overflow",
        (const uint8_t[]){ 0x8A, 0x01, 'R', 0x84, 0x03, 0x06, 0x08, 0x00,
                           0x8A, 0x84, 0xFF, 0xFF, 0xFF, 0xFF }, 14);

    /* bufOvfl optFld set but no BOOLEAN [3] field follows (WP-1f) */
    assert_61850_list_rejected("bufovfl_missing",
        (const uint8_t[]){ 0x8A, 0x01, 'R', 0x84, 0x03, 0x06, 0x02, 0x00,
                           0x8A, 0x01, 'D', 0x84, 0x02, 0x05, (uint8_t)0xE0 },
        15);

    /* bufOvfl zero-length */
    assert_61850_list_rejected("bufovfl_zero_len",
        (const uint8_t[]){ 0x8A, 0x01, 'R', 0x84, 0x03, 0x06, 0x02, 0x00,
                           0x8A, 0x01, 'D', 0x83, 0x00 }, 13);

    /* bufOvfl wire length exceeds the list parent */
    assert_61850_list_rejected("bufovfl_len_overflow",
        (const uint8_t[]){ 0x8A, 0x01, 'R', 0x84, 0x03, 0x06, 0x02, 0x00,
                           0x8A, 0x01, 'D', 0x83, 0x84,
                           0xFF, 0xFF, 0xFF, 0xFF }, 17);

    /* entryID optFld set but no OCTET STRING [9] field follows (WP-1f) */
    assert_61850_list_rejected("entryid_missing",
        (const uint8_t[]){ 0x8A, 0x01, 'R', 0x84, 0x03, 0x06, 0x01, 0x00,
                           0x8A, 0x01, 'D', 0x84, 0x02, 0x05, (uint8_t)0xE0 },
        15);

    /* entryID bad size (9 bytes instead of <= 8) */
    assert_61850_list_rejected("entryid_bad_size",
        (const uint8_t[]){ 0x8A, 0x01, 'R', 0x84, 0x03, 0x06, 0x01, 0x00,
                           0x8A, 0x01, 'D', 0x89, 0x09,
                           1, 2, 3, 4, 5, 6, 7, 8, 9 }, 21);

    /* entryID wire length exceeds the list parent */
    assert_61850_list_rejected("entryid_len_overflow",
        (const uint8_t[]){ 0x8A, 0x01, 'R', 0x84, 0x03, 0x06, 0x01, 0x00,
                           0x8A, 0x01, 'D', 0x89, 0x84,
                           0xFF, 0xFF, 0xFF, 0xFF }, 17);

    /* confRev optFld set but no confRev field follows */
    assert_61850_list_rejected("confrev_missing",
        (const uint8_t[]){ 0x8A, 0x01, 'R', 0x84, 0x03, 0x06, 0x00, 0x80,
                           0x8A, 0x01, 'D', 0x84, 0x02, 0x05, (uint8_t)0xE0 },
        15);

    /* confRev zero-length */
    assert_61850_list_rejected("confrev_zero_len",
        (const uint8_t[]){ 0x8A, 0x01, 'R', 0x84, 0x03, 0x06, 0x00, 0x80,
                           0x8A, 0x01, 'D', 0x86, 0x00 }, 13);

    /* inclusion-bitstring missing entirely */
    assert_61850_list_rejected("inclbitstr_missing",
        (const uint8_t[]){ 0x8A, 0x01, 'R', 0x84, 0x03, 0x06, 0x00, 0x00 }, 8);

    /* inclusion-bitstring zero-length */
    assert_61850_list_rejected("inclbitstr_zero_len",
        (const uint8_t[]){ 0x8A, 0x01, 'R', 0x84, 0x03, 0x06, 0x00, 0x00,
                           0x8A, 0x01, 'D', 0x84, 0x00 }, 13);

    /* inclusion-bitstring wire length exceeds the list parent */
    assert_61850_list_rejected("inclbitstr_len_overflow",
        (const uint8_t[]){ 0x8A, 0x01, 'R', 0x84, 0x03, 0x06, 0x00, 0x00,
                           0x8A, 0x01, 'D', 0x84, 0x84,
                           0xFF, 0xFF, 0xFF, 0xFF }, 17);

    /* inclusion-bitstring with 33 value bytes (exceeds the 32-byte
     * incl_bit_str field) */
    {
        uint8_t list[64];
        size_t n = 0;
        list[n++] = 0x8A; list[n++] = 0x01; list[n++] = 'R';
        list[n++] = 0x84; list[n++] = 0x03; list[n++] = 0x06;
        list[n++] = 0x00; list[n++] = 0x00;
        list[n++] = 0x8A; list[n++] = 0x01; list[n++] = 'D';
        list[n++] = 0x84; list[n++] = 0x22; list[n++] = 0x00;
        for (int i = 0; i < 33; i++) {
            list[n++] = 0xFF;
        }
        assert_61850_list_rejected("inclbitstr_oversized", list, n);
    }

    /* inclusion-bitstring announces 2 members but no values follow */
    assert_61850_list_rejected("values_missing",
        (const uint8_t[]){ 0x8A, 0x01, 'R', 0x84, 0x03, 0x06, 0x00, 0x00,
                           0x8A, 0x01, 'D', 0x84, 0x02, 0x06, (uint8_t)0xC0 },
        15);

    /* reason optFld set, 2 members, values present but no reasons */
    assert_61850_list_rejected("reasons_missing",
        (const uint8_t[]){ 0x8A, 0x01, 'R', 0x84, 0x03, 0x06, 0x10, 0x00,
                           0x8A, 0x01, 'D', 0x84, 0x02, 0x06, (uint8_t)0xC0,
                           0x83, 0x01, 0xFF, 0x86, 0x01, 0x2A }, 21);

    /* reason code zero-length */
    assert_61850_list_rejected("reason_zero_len",
        (const uint8_t[]){ 0x8A, 0x01, 'R', 0x84, 0x03, 0x06, 0x10, 0x00,
                           0x8A, 0x01, 'D', 0x84, 0x02, 0x06, (uint8_t)0xC0,
                           0x83, 0x01, 0xFF, 0x86, 0x01, 0x2A,
                           0x84, 0x00 }, 23);

    /* reason code with invalid unused-bit count 8 */
    assert_61850_list_rejected("reason_unused_8",
        (const uint8_t[]){ 0x8A, 0x01, 'R', 0x84, 0x03, 0x06, 0x10, 0x00,
                           0x8A, 0x01, 'D', 0x84, 0x02, 0x06, (uint8_t)0xC0,
                           0x83, 0x01, 0xFF, 0x86, 0x01, 0x2A,
                           0x84, 0x02, 0x08, 0x2A }, 25);

    /* reason code wire length exceeds the list parent */
    assert_61850_list_rejected("reason_len_overflow",
        (const uint8_t[]){ 0x8A, 0x01, 'R', 0x84, 0x03, 0x06, 0x10, 0x00,
                           0x8A, 0x01, 'D', 0x84, 0x02, 0x06, (uint8_t)0xC0,
                           0x83, 0x01, 0xFF, 0x86, 0x01, 0x2A,
                           0x84, 0x84, 0xFF, 0xFF, 0xFF, 0xFF }, 27);

    PASS();
}

static void test_iec61850_report_oversized_lengths(void)
{
    TEST("iec61850_report_oversized_lengths");

    /* unconfirmedPDU outer length exceeds the buffer */
    static const uint8_t outer_overflow[] = {
        0xA3, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0xA0, 0x05, 0x01
    };
    /* informationReport [0] length exceeds the unconfirmedPDU parent */
    static const uint8_t ir_overflow[] = {
        0xA3, 0x08, 0xA0, 0x84, 0xFF, 0xFF, 0xFF, 0xFF,
        0xA1, 0x05, 0x80, 0x03, 0x52, 0x50, 0x54
    };
    /* variableAccessSpecification length exceeds its parent */
    static const uint8_t vas_overflow[] = {
        0xA3, 0x0A, 0xA0, 0x08, 0xA1, 0x84, 0xFF, 0xFF, 0xFF, 0xFF,
        0x80, 0x03, 0x52
    };
    /* listOfAccessResult length exceeds the informationReport parent */
    static const uint8_t list_overflow[] = {
        0xA3, 0x0D, 0xA0, 0x0B, 0xA1, 0x05, 0x80, 0x03, 0x52, 0x50, 0x54,
        0xA0, 0x84, 0xFF, 0xFF, 0xFF, 0xFF
    };
    /* wrong outer tag (confirmed response, not unconfirmedPDU) */
    static const uint8_t wrong_tag[] = {
        0xA1, 0x0A, 0xA0, 0x08, 0xA1, 0x05, 0x80, 0x03, 0x52, 0x50, 0x54,
        0xA0, 0x00
    };
    /* wrong informationReport tag */
    static const uint8_t wrong_ir_tag[] = {
        0xA3, 0x0A, 0xA1, 0x08, 0xA1, 0x05, 0x80, 0x03, 0x52, 0x50, 0x54,
        0xA0, 0x00
    };
    /* wrong variableAccessSpecification tag (flat [0] form) */
    static const uint8_t wrong_vas_tag[] = {
        0xA3, 0x0A, 0xA0, 0x08, 0xA0, 0x05, 0x80, 0x03, 0x52, 0x50, 0x54,
        0xA0, 0x00
    };
    /* wrong listOfAccessResult tag */
    static const uint8_t wrong_list_tag[] = {
        0xA3, 0x0A, 0xA0, 0x08, 0xA1, 0x05, 0x80, 0x03, 0x52, 0x50, 0x54,
        0xA1, 0x00
    };

    mms_information_report_t report;
    memset(&report, 0, sizeof(report));
    ASSERT_TRUE(mms_decode_iec61850_report(outer_overflow,
        sizeof(outer_overflow), &report) < 0);
    ASSERT_TRUE(mms_decode_iec61850_report(ir_overflow,
        sizeof(ir_overflow), &report) < 0);
    ASSERT_TRUE(mms_decode_iec61850_report(vas_overflow,
        sizeof(vas_overflow), &report) < 0);
    ASSERT_TRUE(mms_decode_iec61850_report(list_overflow,
        sizeof(list_overflow), &report) < 0);
    ASSERT_TRUE(mms_decode_iec61850_report(wrong_tag,
        sizeof(wrong_tag), &report) < 0);
    ASSERT_TRUE(mms_decode_iec61850_report(wrong_ir_tag,
        sizeof(wrong_ir_tag), &report) < 0);
    ASSERT_TRUE(mms_decode_iec61850_report(wrong_vas_tag,
        sizeof(wrong_vas_tag), &report) < 0);
    ASSERT_TRUE(mms_decode_iec61850_report(wrong_list_tag,
        sizeof(wrong_list_tag), &report) < 0);
    PASS();
}

/* ========================================================================
 * WP-1f: in-band service failures (BUG-R2 / BUG-R3) and the oracle's
 * bufOvfl/entryID report fields (BUG-R4)
 * ======================================================================== */

/* Read-Response carrying a failure AccessResult (wire-observed on the
 * reference server for a read of an absent object):
 *   a1 0a 02 01 01 a4 05 a1 03 80 01 0a
 * (ConfirmedResponse/invokeID 1/read/listOfAccessResult/
 *  failure DataAccessError=10). Valid MMS: must decode. */
static void test_read_response_inband_failure(void)
{
    TEST("read_response_inband_failure");
    static const uint8_t wire[] = {
        0xA1, 0x0A, 0x02, 0x01, 0x01, 0xA4, 0x05, 0xA1, 0x03,
        0x80, 0x01, 0x0A
    };
    mms_confirmed_response_t resp;

    memset(&resp, 0, sizeof(resp));
    int ret = mms_decode_confirmed_response(wire, sizeof(wire), &resp);
    ASSERT_TRUE(ret == (int)sizeof(wire));
    ASSERT_EQ((int)resp.service, (int)MMS_SERVICE_TYPE_READ);
    ASSERT_TRUE(resp.params.read.failure);
    ASSERT_EQ((int)resp.params.read.access_error, 10);
    PASS();
}

/* Write-Response result CHOICE: failure [0] DataAccessError vs
 * success [1] NULL. Wire-observed on the reference server for a
 * rejected Resv write: a1 08 02 01 01 a5 03 80 01 02. */
static void test_write_response_failure_choice(void)
{
    TEST("write_response_failure_choice");
    static const uint8_t failure_wire[] = {
        0xA1, 0x08, 0x02, 0x01, 0x01, 0xA5, 0x03, 0x80, 0x01, 0x02
    };
    static const uint8_t success_wire[] = {
        0xA1, 0x07, 0x02, 0x01, 0x01, 0xA5, 0x02, 0x81, 0x00
    };
    mms_confirmed_response_t resp;
    mms_confirmed_response_t roundtrip;
    uint8_t buf[256];

    memset(&resp, 0, sizeof(resp));
    int ret = mms_decode_confirmed_response(failure_wire,
                                            sizeof(failure_wire), &resp);
    ASSERT_TRUE(ret == (int)sizeof(failure_wire));
    ASSERT_EQ((int)resp.service, (int)MMS_SERVICE_TYPE_WRITE);
    ASSERT_TRUE(resp.params.write.failure);
    ASSERT_EQ((int)resp.params.write.access_error, 2);

    memset(&resp, 0, sizeof(resp));
    ret = mms_decode_confirmed_response(success_wire,
                                        sizeof(success_wire), &resp);
    ASSERT_TRUE(ret == (int)sizeof(success_wire));
    ASSERT_TRUE(!resp.params.write.failure);

    /* Encode/decode roundtrip of the failure CHOICE. */
    memset(&resp, 0, sizeof(resp));
    resp.invoke_id = 1;
    resp.service = MMS_SERVICE_TYPE_WRITE;
    resp.params.write.failure = true;
    resp.params.write.access_error = 2;
    int len = mms_encode_confirmed_response(&resp, buf, sizeof(buf));
    ASSERT_TRUE(len > 0);
    memset(&roundtrip, 0, sizeof(roundtrip));
    ret = mms_decode_confirmed_response(buf, (size_t)len, &roundtrip);
    ASSERT_TRUE(ret == len);
    ASSERT_TRUE(roundtrip.params.write.failure);
    ASSERT_EQ((int)roundtrip.params.write.access_error, 2);
    PASS();
}

/* ReadNamedVariableList response with one member answered as a
 * failure AccessResult: valid MMS, decoded with the failure flagged
 * and the successful members preserved. */
static void test_readnamedvarlist_member_failure(void)
{
    TEST("readnamedvarlist_member_failure");
    static const uint8_t wire[] = {
        0xA1, 0x13, 0x02, 0x01, 0x01, 0xA4, 0x0E, 0xA1, 0x0C,
        0x83, 0x01, 0xFF,             /* member 1: boolean TRUE */
        0x80, 0x01, 0x03,             /* member 2: failure, code 3 */
        0x86, 0x01, 0x2A,             /* member 3: unsigned 42 */
        0x85, 0x01, 0x07              /* member 4: integer 7 */
    };
    mms_confirmed_response_t resp;

    memset(&resp, 0, sizeof(resp));
    int ret = mms_decode_confirmed_response(wire, sizeof(wire), &resp);
    ASSERT_TRUE(ret == (int)sizeof(wire));
    ASSERT_EQ((int)resp.service, (int)MMS_SERVICE_TYPE_READ_NAMED_VARLIST);
    ASSERT_EQ((int)resp.params.readnamedvarlist.num_values, 3);
    ASSERT_TRUE(resp.params.readnamedvarlist.values[0].value.boolean);
    ASSERT_EQ((int)resp.params.readnamedvarlist.values[1].value.unsigned_val, 42);
    ASSERT_EQ((int)resp.params.readnamedvarlist.values[2].value.integer, 7);
    ASSERT_TRUE(resp.params.readnamedvarlist.failure);
    ASSERT_EQ((int)resp.params.readnamedvarlist.access_error, 3);
    PASS();
}

/* BRCB report in the reference server's default-options shape
 * (optFlds 0x7a/0x7b): the bufOvfl BOOLEAN [3] sits between datSet
 * and confRev (wire evidence, WP-1d MR-04b); the 0x7b variant adds
 * the entryID octet string. Both must decode. */
static void test_iec61850_report_oracle_default_optflds(void)
{
    TEST("iec61850_report_oracle_default_optflds");
    static const uint8_t list_7a[] = {
        0x8A, 0x07, 'E', 'v', 'e', 'n', 't', 's', '2',   /* rptID */
        0x84, 0x03, 0x06, 0x7A, 0x80,                    /* optFlds */
        0x86, 0x01, 0x00,                                /* seqNum */
        0x8C, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,  /* timeOfEntry */
        0x8A, 0x08, 'L', 'L', 'N', '0', '$', 'D', 'S', '1', /* datSet */
        0x83, 0x01, 0x01,                                /* bufOvfl TRUE */
        0x86, 0x01, 0x01,                                /* confRev */
        0x84, 0x02, 0x06, 0xC0,                          /* inclBitStr */
        0x83, 0x01, 0xFF,                                /* value: bool */
        0x86, 0x01, 0x2A,                                /* value: uint */
        0x84, 0x02, 0x02, 0x01,                          /* reason */
        0x84, 0x02, 0x02, 0x02                           /* reason */
    };
    static const uint8_t list_7b[] = {
        0x8A, 0x07, 'E', 'v', 'e', 'n', 't', 's', '2',
        0x84, 0x03, 0x06, 0x7B, 0x80,
        0x86, 0x01, 0x00,
        0x8C, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x8A, 0x08, 'L', 'L', 'N', '0', '$', 'D', 'S', '1',
        0x83, 0x01, 0x01,                                /* bufOvfl TRUE */
        0x89, 0x08, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, /* entryID */
        0x86, 0x01, 0x01,                                /* confRev */
        0x84, 0x02, 0x06, 0xC0,                          /* inclBitStr */
        0x83, 0x01, 0xFF,
        0x86, 0x01, 0x2A,
        0x84, 0x02, 0x02, 0x01,
        0x84, 0x02, 0x02, 0x02
    };
    uint8_t wire[256];
    size_t wire_len;
    mms_information_report_t report;

    wire_len = wrap_61850_list(wire, sizeof(wire), list_7a, sizeof(list_7a));
    ASSERT_TRUE(wire_len > 0);
    memset(&report, 0, sizeof(report));
    int ret = mms_decode_iec61850_report(wire, wire_len, &report);
    ASSERT_TRUE(ret == (int)wire_len);
    ASSERT_TRUE(strcmp(report.rpt_id, "Events2") == 0);
    ASSERT_TRUE(strcmp(report.dat_set, "LLN0$DS1") == 0);
    ASSERT_TRUE(report.sq_num_present);
    ASSERT_TRUE(report.report_timestamp_present);
    ASSERT_TRUE(report.conf_rev_present);
    ASSERT_EQ((int)report.conf_rev, 1);
    ASSERT_TRUE(report.buffer_overflow_present);   /* BUG-R4 */
    ASSERT_TRUE(report.buffer_overflow);
    ASSERT_TRUE(!report.entry_id_present);
    ASSERT_EQ((int)report.num_values, 2);
    ASSERT_TRUE(report.values[0].value.boolean);
    ASSERT_EQ((int)report.values[1].value.unsigned_val, 42);
    ASSERT_TRUE(report.reasons_present);

    wire_len = wrap_61850_list(wire, sizeof(wire), list_7b, sizeof(list_7b));
    ASSERT_TRUE(wire_len > 0);
    memset(&report, 0, sizeof(report));
    ret = mms_decode_iec61850_report(wire, wire_len, &report);
    ASSERT_TRUE(ret == (int)wire_len);
    ASSERT_TRUE(report.buffer_overflow_present);
    ASSERT_TRUE(report.buffer_overflow);
    ASSERT_TRUE(report.entry_id_present);          /* BUG-R4 */
    ASSERT_TRUE(report.entry_id == 0x1122334455667788ULL);
    ASSERT_EQ((int)report.num_values, 2);
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

static int trunc_dec_iec61850_report(const uint8_t *b, size_t l, void *o)
{ return mms_decode_iec61850_report(b, l, (mms_information_report_t *)o); }

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

static void test_iec61850_report_truncated(void)
{
    TEST("iec61850_report_truncated");

    static uint8_t wire[512];
    int enc_len;

    /* All optional fields off (minimal report) */
    {
        mms_iec61850_report_t in;
        fill_61850_report(&in, 0x00, false);
        enc_len = mms_encode_iec61850_report(&in, wire, sizeof(wire));
        ASSERT_TRUE(enc_len > 0);
        assert_truncations_rejected("iec61850_report(all_off)",
                                    trunc_dec_iec61850_report,
                                    wire, (size_t)enc_len);
    }
    /* All optional fields on */
    {
        mms_iec61850_report_t in;
        fill_61850_report(&in, 0x7Eu, true);
        enc_len = mms_encode_iec61850_report(&in, wire, sizeof(wire));
        ASSERT_TRUE(enc_len > 0);
        assert_truncations_rejected("iec61850_report(all_on)",
                                    trunc_dec_iec61850_report,
                                    wire, (size_t)enc_len);
    }
    PASS();
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
    test_getnamelist_response_long_list();
    test_readnamedvarlist_response_long_list();
    test_write_request_roundtrip();
    test_getnamelist_request_roundtrip();
    test_confirmed_error_roundtrip();

    printf("\n--- InformationReport ---\n");
    test_information_report_roundtrip();

    printf("\n--- IEC 61850-7-2 Report Decode (WP-1b) ---\n");
    test_iec61850_report_roundtrip_all_off();
    test_iec61850_report_roundtrip_all_on();
    test_iec61850_report_roundtrip_each_optfld();
    test_iec61850_report_null_params();
    test_iec61850_report_malformed_fields();
    test_iec61850_report_oversized_lengths();
    test_iec61850_report_truncated();

    printf("\n--- WP-1f: in-band failures + bufOvfl/entryID ---\n");
    test_read_response_inband_failure();
    test_write_response_failure_choice();
    test_readnamedvarlist_member_failure();
    test_iec61850_report_oracle_default_optflds();

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
