/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Coverage Boost Tests
 *
 * Targets uncovered code paths in:
 *   - sv_ber.c: security encode/decode, encode error paths
 *   - mms_server.c: process_request (all service types)
 *   - goose_subscriber.c: frame processing, state machine
 *   - sv_subscriber.c: frame processing, smpCnt continuity
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <arpa/inet.h>

/* Pull in mms_server.c statics for testing */
#include "../../src/mms/mms_server.c"

#include "asn1/sv_ber.h"
#include "asn1/goose_ber.h"
#include "asn1/goose_ber_decode.h"
#include "goose/goose_subscriber.h"
#include "sv/sv_subscriber.h"
#include "transport/eth_frame.h"

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
 * Target 1: sv_ber.c security encode/decode
 ***************************************************************************/

static void test_sv_set_security_valid(void)
{
    sv_asdu_t asdu;
    sv_asdu_init(&asdu);

    uint8_t key_id[4] = {0xDE, 0xAD, 0xBE, 0xEF};
    uint8_t sig[64];
    memset(sig, 0x42, sizeof(sig));

    int ret = sv_set_security(&asdu, SV_SIGNATURE_RSA_PSS, key_id, sig, 64);
    TEST_ASSERT(ret == SV_BER_OK, "sv_set_security should succeed");
    TEST_ASSERT(asdu.secure == true, "secure flag should be set");
    TEST_ASSERT(asdu.signature_algo == SV_SIGNATURE_RSA_PSS, "algo should match");
    TEST_ASSERT(memcmp(asdu.key_id, key_id, 4) == 0, "key_id should match");
    TEST_ASSERT(asdu.signature_len == 64, "sig len should be 64");
    TEST_ASSERT(memcmp(asdu.signature, sig, 64) == 0, "sig data should match");
    TEST_ASSERT(asdu.security_timestamp > 0, "timestamp should be set");
    TEST_PASS();
}

static void test_sv_set_security_null_args(void)
{
    sv_asdu_t asdu;
    sv_asdu_init(&asdu);
    uint8_t key_id[4] = {0};
    uint8_t sig[64] = {0};

    TEST_ASSERT(sv_set_security(NULL, SV_SIGNATURE_RSA_PSS, key_id, sig, 64)
                == SV_BER_ERR_INVALID_ARG, "NULL asdu should fail");
    TEST_ASSERT(sv_set_security(&asdu, SV_SIGNATURE_RSA_PSS, NULL, sig, 64)
                == SV_BER_ERR_INVALID_ARG, "NULL key_id should fail");
    TEST_ASSERT(sv_set_security(&asdu, SV_SIGNATURE_RSA_PSS, key_id, NULL, 64)
                == SV_BER_ERR_INVALID_ARG, "NULL signature should fail");
    TEST_PASS();
}

static void test_sv_set_security_sig_too_large(void)
{
    sv_asdu_t asdu;
    sv_asdu_init(&asdu);
    uint8_t key_id[4] = {0};
    uint8_t sig[1] = {0};

    int ret = sv_set_security(&asdu, SV_SIGNATURE_RSA_PSS, key_id, sig,
                              SV_MAX_SIGNATURE_LEN + 1);
    TEST_ASSERT(ret == SV_BER_ERR_INVALID_ARG, "too-large sig should fail");
    TEST_PASS();
}

static void test_sv_encode_security_roundtrip(void)
{
    sv_apdu_t apdu;
    sv_apdu_init(&apdu);
    apdu.noASDU = 1;
    sv_asdu_init(&apdu.asdu[0]);
    (void)sv_set_svid(&apdu.asdu[0], "TestSV01");
    apdu.asdu[0].smpCnt = 42;
    apdu.asdu[0].confRev = 1;
    apdu.asdu[0].smpSynch = SV_SMPSYNCH_GLOBAL;

    /* Add some samples */
    sv_quality_t q = {0};
    (void)sv_add_sample(&apdu.asdu[0], 1000, q);
    (void)sv_add_sample(&apdu.asdu[0], 2000, q);

    /* Set security */
    uint8_t key_id[4] = {0x11, 0x22, 0x33, 0x44};
    uint8_t sig[64];
    memset(sig, 0xAB, sizeof(sig));
    (void)sv_set_security(&apdu.asdu[0], SV_SIGNATURE_RSA_PSS, key_id, sig, 64);

    /* Encode */
    uint8_t buf[1500];
    size_t encoded_len = 0;
    int ret = sv_encode_apdu(buf, sizeof(buf), &apdu, &encoded_len);
    TEST_ASSERT(ret == SV_BER_OK, "encode should succeed");
    TEST_ASSERT(encoded_len > 0, "encoded_len should be > 0");

    /* Decode */
    sv_apdu_t decoded;
    sv_apdu_init(&decoded);
    ret = sv_decode_apdu(buf, encoded_len, &decoded);
    TEST_ASSERT(ret == SV_BER_OK, "decode should succeed");
    TEST_ASSERT(decoded.noASDU == 1, "noASDU should be 1");
    TEST_ASSERT(strcmp(decoded.asdu[0].svID, "TestSV01") == 0, "svID should match");
    TEST_ASSERT(decoded.asdu[0].smpCnt == 42, "smpCnt should match");
    TEST_ASSERT(decoded.asdu[0].num_samples == 2, "num_samples should be 2");
    /* Security fields should be decoded */
    TEST_ASSERT(decoded.asdu[0].secure == true, "secure flag should be set");
    TEST_ASSERT(decoded.asdu[0].signature_algo == SV_SIGNATURE_RSA_PSS, "algo should match");
    TEST_ASSERT(memcmp(decoded.asdu[0].key_id, key_id, 4) == 0, "key_id should match");
    TEST_ASSERT(decoded.asdu[0].signature_len == 64, "sig len should be 64");
    TEST_ASSERT(memcmp(decoded.asdu[0].signature, sig, 64) == 0, "sig should match");
    TEST_PASS();
}

static void test_sv_encode_security_no_security(void)
{
    uint8_t buf[256];
    size_t offset = 0;
    sv_asdu_t asdu;
    sv_asdu_init(&asdu);
    /* secure = false by default */
    int ret = sv_encode_security(buf, sizeof(buf), &offset, &asdu);
    TEST_ASSERT(ret == SV_BER_OK, "no-security encode should succeed");
    TEST_ASSERT(offset == 0, "offset should be 0 (nothing written)");
    TEST_PASS();
}

static void test_sv_encode_security_null_args(void)
{
    sv_asdu_t asdu;
    sv_asdu_init(&asdu);
    uint8_t buf[256];
    size_t offset = 0;

    TEST_ASSERT(sv_encode_security(NULL, 256, &offset, &asdu) == SV_BER_ERR_INVALID_ARG,
                "NULL buf should fail");
    TEST_ASSERT(sv_encode_security(buf, 256, NULL, &asdu) == SV_BER_ERR_INVALID_ARG,
                "NULL offset should fail");
    TEST_ASSERT(sv_encode_security(buf, 256, &offset, NULL) == SV_BER_ERR_INVALID_ARG,
                "NULL asdu should fail");
    TEST_PASS();
}

static void test_sv_multi_asdu_roundtrip(void)
{
    sv_apdu_t apdu;
    sv_apdu_init(&apdu);
    apdu.noASDU = 2;

    sv_quality_t q = {0};
    for (uint8_t i = 0; i < 2; i++) {
        sv_asdu_init(&apdu.asdu[i]);
        char svid[16];
        (void)snprintf(svid, sizeof(svid), "SV%u", (unsigned)i);
        (void)sv_set_svid(&apdu.asdu[i], svid);
        apdu.asdu[i].smpCnt = (uint16_t)(100 + i);
        apdu.asdu[i].confRev = 1;
        apdu.asdu[i].smpSynch = SV_SMPSYNCH_LOCAL;
        (void)sv_add_sample(&apdu.asdu[i], (int32_t)(1000 * (i + 1)), q);
    }

    uint8_t buf[1500];
    size_t encoded_len = 0;
    int ret = sv_encode_apdu(buf, sizeof(buf), &apdu, &encoded_len);
    TEST_ASSERT(ret == SV_BER_OK, "multi-ASDU encode should succeed");

    sv_apdu_t decoded;
    sv_apdu_init(&decoded);
    ret = sv_decode_apdu(buf, encoded_len, &decoded);
    TEST_ASSERT(ret == SV_BER_OK, "multi-ASDU decode should succeed");
    TEST_ASSERT(decoded.noASDU == 2, "noASDU should be 2");
    TEST_ASSERT(strcmp(decoded.asdu[0].svID, "SV0") == 0, "first svID");
    TEST_ASSERT(strcmp(decoded.asdu[1].svID, "SV1") == 0, "second svID");
    TEST_ASSERT(decoded.asdu[0].smpCnt == 100, "first smpCnt");
    TEST_ASSERT(decoded.asdu[1].smpCnt == 101, "second smpCnt");
    TEST_PASS();
}

static void test_sv_encode_buffer_too_small(void)
{
    sv_apdu_t apdu;
    sv_apdu_init(&apdu);
    apdu.noASDU = 1;
    sv_asdu_init(&apdu.asdu[0]);
    (void)sv_set_svid(&apdu.asdu[0], "TestSV");
    apdu.asdu[0].smpCnt = 1;
    apdu.asdu[0].confRev = 1;
    sv_quality_t q = {0};
    (void)sv_add_sample(&apdu.asdu[0], 1000, q);

    uint8_t buf[10]; /* Way too small */
    size_t encoded_len = 0;
    int ret = sv_encode_apdu(buf, sizeof(buf), &apdu, &encoded_len);
    TEST_ASSERT(ret != SV_BER_OK, "buffer too small should fail");
    TEST_PASS();
}

static void test_sv_decode_truncated(void)
{
    /* Build a valid encoding first */
    sv_apdu_t apdu;
    sv_apdu_init(&apdu);
    apdu.noASDU = 1;
    sv_asdu_init(&apdu.asdu[0]);
    (void)sv_set_svid(&apdu.asdu[0], "TestSV");
    apdu.asdu[0].smpCnt = 1;
    apdu.asdu[0].confRev = 1;
    sv_quality_t q = {0};
    (void)sv_add_sample(&apdu.asdu[0], 1000, q);

    uint8_t buf[1500];
    size_t encoded_len = 0;
    (void)sv_encode_apdu(buf, sizeof(buf), &apdu, &encoded_len);

    /* Try decoding truncated buffer */
    sv_apdu_t decoded;
    int ret = sv_decode_apdu(buf, 3, &decoded); /* Only 3 bytes */
    TEST_ASSERT(ret != SV_BER_OK, "truncated decode should fail");

    ret = sv_decode_apdu(buf, 0, &decoded);
    TEST_ASSERT(ret != SV_BER_OK, "empty decode should fail");

    ret = sv_decode_apdu(NULL, 100, &decoded);
    TEST_ASSERT(ret != SV_BER_OK, "NULL buf decode should fail");

    ret = sv_decode_apdu(buf, 100, NULL);
    TEST_ASSERT(ret != SV_BER_OK, "NULL apdu decode should fail");
    TEST_PASS();
}

static void test_sv_decode_malformed(void)
{
    /* Wrong application tag */
    uint8_t buf[10] = {0x61, 0x05, 0x80, 0x01, 0x01, 0xA1, 0x00, 0, 0, 0};
    sv_apdu_t decoded;
    int ret = sv_decode_apdu(buf, 7, &decoded);
    TEST_ASSERT(ret != SV_BER_OK, "wrong tag decode should fail");
    TEST_PASS();
}

/***************************************************************************
 * Target 2: mms_server.c process_request
 ***************************************************************************/

/* Helper: set up a minimal session with data store */
static void setup_session(iec61850_mms_session_t *session,
                          iec61850_mms_data_store_t *ds)
{
    (void)memset(session, 0, sizeof(*session));
    iec61850_mms_ds_init(ds);

    /* Create a domain with a variable */
    (void)iec61850_mms_ds_create_domain(ds, "TestDomain");
    mms_value_t val;
    (void)memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;
    val.value.integer = 42;
    (void)iec61850_mms_ds_create_variable(ds, "TestDomain", "TestVar",
                                          MMS_TYPE_INTEGER, &val);

    session->data_store = ds;
    session->control_manager = NULL;
    session->file_service = NULL;
    session->journal = NULL;
    session->max_pdu_size = IEC61850_MMS_MAX_PDU_SIZE;
    session->session_id = 1;
}

static void test_process_request_status(void)
{
    iec61850_mms_session_t session;
    iec61850_mms_data_store_t ds;
    setup_session(&session, &ds);

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    mms_confirmed_error_t err;
    (void)memset(&req, 0, sizeof(req));
    req.invoke_id = 1;
    req.service = MMS_SERVICE_TYPE_STATUS;

    int ret = process_request(&session, &req, &resp, &err);
    TEST_ASSERT(ret == 0, "Status should succeed");
    TEST_ASSERT(resp.params.status.vmd_logical_status == 0, "logical status=0");
    TEST_ASSERT(resp.params.status.vmd_physical_status == 0, "physical status=0");

    iec61850_mms_ds_destroy(&ds);
    TEST_PASS();
}

static void test_process_request_identify(void)
{
    iec61850_mms_session_t session;
    iec61850_mms_data_store_t ds;
    setup_session(&session, &ds);

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    mms_confirmed_error_t err;
    (void)memset(&req, 0, sizeof(req));
    req.invoke_id = 2;
    req.service = MMS_SERVICE_TYPE_IDENTIFY;

    int ret = process_request(&session, &req, &resp, &err);
    TEST_ASSERT(ret == 0, "Identify should succeed");
    TEST_ASSERT(strcmp(resp.params.identify.vendor_name, "xdp-iec61850") == 0,
                "vendor should be xdp-iec61850");

    iec61850_mms_ds_destroy(&ds);
    TEST_PASS();
}

static void test_process_request_read(void)
{
    iec61850_mms_session_t session;
    iec61850_mms_data_store_t ds;
    setup_session(&session, &ds);

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    mms_confirmed_error_t err;
    (void)memset(&req, 0, sizeof(req));
    req.invoke_id = 3;
    req.service = MMS_SERVICE_TYPE_READ;
    (void)strncpy(req.params.read.variable_spec.domain, "TestDomain",
                  MMS_MAX_DOMAIN_NAME - 1);
    (void)strncpy(req.params.read.variable_spec.item_id, "TestVar",
                  MMS_MAX_VARIABLE_NAME - 1);

    int ret = process_request(&session, &req, &resp, &err);
    TEST_ASSERT(ret == 0, "Read should succeed");
    TEST_ASSERT(resp.params.read.value.value.integer == 42, "value should be 42");

    iec61850_mms_ds_destroy(&ds);
    TEST_PASS();
}

static void test_process_request_read_not_found(void)
{
    iec61850_mms_session_t session;
    iec61850_mms_data_store_t ds;
    setup_session(&session, &ds);

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    mms_confirmed_error_t err;
    (void)memset(&req, 0, sizeof(req));
    req.service = MMS_SERVICE_TYPE_READ;
    (void)strncpy(req.params.read.variable_spec.domain, "TestDomain",
                  MMS_MAX_DOMAIN_NAME - 1);
    (void)strncpy(req.params.read.variable_spec.item_id, "NoSuchVar",
                  MMS_MAX_VARIABLE_NAME - 1);

    int ret = process_request(&session, &req, &resp, &err);
    TEST_ASSERT(ret == 1, "Read non-existent should return error");
    TEST_ASSERT(err.error.error_class == MMS_ERROR_CLASS_ACCESS, "error class ACCESS");

    iec61850_mms_ds_destroy(&ds);
    TEST_PASS();
}

static void test_process_request_write(void)
{
    iec61850_mms_session_t session;
    iec61850_mms_data_store_t ds;
    setup_session(&session, &ds);

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    mms_confirmed_error_t err;
    (void)memset(&req, 0, sizeof(req));
    req.service = MMS_SERVICE_TYPE_WRITE;
    (void)strncpy(req.params.write.variable_spec.domain, "TestDomain",
                  MMS_MAX_DOMAIN_NAME - 1);
    (void)strncpy(req.params.write.variable_spec.item_id, "TestVar",
                  MMS_MAX_VARIABLE_NAME - 1);
    req.params.write.value.type = MMS_TYPE_INTEGER;
    req.params.write.value.value.integer = 99;

    int ret = process_request(&session, &req, &resp, &err);
    TEST_ASSERT(ret == 0, "Write should succeed");

    /* Verify the write took effect */
    mms_value_t read_val;
    (void)iec61850_mms_ds_read_variable(&ds, "TestDomain", "TestVar", &read_val);
    TEST_ASSERT(read_val.value.integer == 99, "Written value should be 99");

    iec61850_mms_ds_destroy(&ds);
    TEST_PASS();
}

static void test_process_request_getnamelist_domains(void)
{
    iec61850_mms_session_t session;
    iec61850_mms_data_store_t ds;
    setup_session(&session, &ds);

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    mms_confirmed_error_t err;
    (void)memset(&req, 0, sizeof(req));
    req.service = MMS_SERVICE_TYPE_GET_NAMELIST;
    req.params.getnamelist.object_class = MMS_OBJECT_CLASS_DOMAIN;

    int ret = process_request(&session, &req, &resp, &err);
    TEST_ASSERT(ret == 0, "GetNameList(domains) should succeed");
    TEST_ASSERT(resp.params.getnamelist.num_identifiers == 1, "should have 1 domain");
    TEST_ASSERT(strcmp(resp.params.getnamelist.identifiers[0], "TestDomain") == 0,
                "domain name should match");

    iec61850_mms_ds_destroy(&ds);
    TEST_PASS();
}

static void test_process_request_getnamelist_variables(void)
{
    iec61850_mms_session_t session;
    iec61850_mms_data_store_t ds;
    setup_session(&session, &ds);

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    mms_confirmed_error_t err;
    (void)memset(&req, 0, sizeof(req));
    req.service = MMS_SERVICE_TYPE_GET_NAMELIST;
    req.params.getnamelist.object_class = MMS_OBJECT_CLASS_NAMED_VARIABLE;
    (void)strncpy(req.params.getnamelist.domain, "TestDomain",
                  MMS_MAX_DOMAIN_NAME - 1);

    int ret = process_request(&session, &req, &resp, &err);
    TEST_ASSERT(ret == 0, "GetNameList(vars) should succeed");
    TEST_ASSERT(resp.params.getnamelist.num_identifiers == 1, "should have 1 var");

    iec61850_mms_ds_destroy(&ds);
    TEST_PASS();
}

static void test_process_request_get_variable_attrs(void)
{
    iec61850_mms_session_t session;
    iec61850_mms_data_store_t ds;
    setup_session(&session, &ds);

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    mms_confirmed_error_t err;
    (void)memset(&req, 0, sizeof(req));
    req.service = MMS_SERVICE_TYPE_GET_VARIABLE_ATTRS;
    (void)strncpy(req.params.getvariableattrs.variable_spec.domain, "TestDomain",
                  MMS_MAX_DOMAIN_NAME - 1);
    (void)strncpy(req.params.getvariableattrs.variable_spec.item_id, "TestVar",
                  MMS_MAX_VARIABLE_NAME - 1);

    int ret = process_request(&session, &req, &resp, &err);
    TEST_ASSERT(ret == 0, "GetVariableAttrs should succeed");
    TEST_ASSERT(resp.params.getvariableattrs.attributes.type == MMS_TYPE_INTEGER,
                "type should be INTEGER");

    iec61850_mms_ds_destroy(&ds);
    TEST_PASS();
}

static void test_process_request_get_variable_attrs_not_found(void)
{
    iec61850_mms_session_t session;
    iec61850_mms_data_store_t ds;
    setup_session(&session, &ds);

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    mms_confirmed_error_t err;
    (void)memset(&req, 0, sizeof(req));
    req.service = MMS_SERVICE_TYPE_GET_VARIABLE_ATTRS;
    (void)strncpy(req.params.getvariableattrs.variable_spec.domain, "TestDomain",
                  MMS_MAX_DOMAIN_NAME - 1);
    (void)strncpy(req.params.getvariableattrs.variable_spec.item_id, "NoSuchVar",
                  MMS_MAX_VARIABLE_NAME - 1);

    int ret = process_request(&session, &req, &resp, &err);
    TEST_ASSERT(ret == 1, "GetVariableAttrs not found should return error");

    iec61850_mms_ds_destroy(&ds);
    TEST_PASS();
}

static void test_process_request_define_delete_varlist(void)
{
    iec61850_mms_session_t session;
    iec61850_mms_data_store_t ds;
    setup_session(&session, &ds);

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    mms_confirmed_error_t err;

    /* DefineNamedVarList */
    (void)memset(&req, 0, sizeof(req));
    req.service = MMS_SERVICE_TYPE_DEFINE_NAMED_VARLIST;
    (void)strncpy(req.params.definenamedvarlist.domain, "TestDomain",
                  MMS_MAX_DOMAIN_NAME - 1);
    (void)strncpy(req.params.definenamedvarlist.list_name, "MyList",
                  MMS_MAX_VARIABLE_NAME - 1);
    (void)strncpy(req.params.definenamedvarlist.variables[0].domain, "TestDomain",
                  MMS_MAX_DOMAIN_NAME - 1);
    (void)strncpy(req.params.definenamedvarlist.variables[0].item_id, "TestVar",
                  MMS_MAX_VARIABLE_NAME - 1);
    req.params.definenamedvarlist.num_variables = 1;

    int ret = process_request(&session, &req, &resp, &err);
    TEST_ASSERT(ret == 0, "DefineNamedVarList should succeed");

    /* GetNamedVarListAttrs */
    (void)memset(&req, 0, sizeof(req));
    req.service = MMS_SERVICE_TYPE_GET_NAMED_VARLIST_ATTRS;
    (void)strncpy(req.params.getnamedvarlistattrs.domain, "TestDomain",
                  MMS_MAX_DOMAIN_NAME - 1);
    (void)strncpy(req.params.getnamedvarlistattrs.list_name, "MyList",
                  MMS_MAX_VARIABLE_NAME - 1);

    ret = process_request(&session, &req, &resp, &err);
    TEST_ASSERT(ret == 0, "GetNamedVarListAttrs should succeed");
    TEST_ASSERT(resp.params.getnamedvarlistattrs.num_variables == 1, "should have 1 var");

    /* DeleteNamedVarList */
    (void)memset(&req, 0, sizeof(req));
    req.service = MMS_SERVICE_TYPE_DELETE_NAMED_VARLIST;
    (void)strncpy(req.params.deletenamedvarlist.domain, "TestDomain",
                  MMS_MAX_DOMAIN_NAME - 1);
    (void)strncpy(req.params.deletenamedvarlist.list_name, "MyList",
                  MMS_MAX_VARIABLE_NAME - 1);

    ret = process_request(&session, &req, &resp, &err);
    TEST_ASSERT(ret == 0, "DeleteNamedVarList should succeed");

    /* Delete again should fail */
    ret = process_request(&session, &req, &resp, &err);
    TEST_ASSERT(ret == 1, "Double delete should fail");

    iec61850_mms_ds_destroy(&ds);
    TEST_PASS();
}

static void test_process_request_file_null_service(void)
{
    iec61850_mms_session_t session;
    iec61850_mms_data_store_t ds;
    setup_session(&session, &ds);

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    mms_confirmed_error_t err;

    mms_service_type_t file_services[] = {
        MMS_SERVICE_TYPE_FILE_OPEN,
        MMS_SERVICE_TYPE_FILE_READ,
        MMS_SERVICE_TYPE_FILE_CLOSE,
        MMS_SERVICE_TYPE_FILE_DELETE,
        MMS_SERVICE_TYPE_FILE_DIRECTORY
    };

    for (size_t i = 0; i < sizeof(file_services) / sizeof(file_services[0]); i++) {
        (void)memset(&req, 0, sizeof(req));
        req.service = file_services[i];
        int ret = process_request(&session, &req, &resp, &err);
        TEST_ASSERT(ret == 1, "File service with NULL file_service should error");
        TEST_ASSERT(err.error.error_class == MMS_ERROR_CLASS_SERVICE,
                    "error class should be SERVICE");
    }

    iec61850_mms_ds_destroy(&ds);
    TEST_PASS();
}

static void test_process_request_journal_null(void)
{
    iec61850_mms_session_t session;
    iec61850_mms_data_store_t ds;
    setup_session(&session, &ds);

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    mms_confirmed_error_t err;

    mms_service_type_t journal_services[] = {
        MMS_SERVICE_TYPE_READ_JOURNAL,
        MMS_SERVICE_TYPE_INITIALIZE_JOURNAL
    };

    for (size_t i = 0; i < sizeof(journal_services) / sizeof(journal_services[0]); i++) {
        (void)memset(&req, 0, sizeof(req));
        req.service = journal_services[i];
        int ret = process_request(&session, &req, &resp, &err);
        TEST_ASSERT(ret == 1, "Journal service with NULL journal should error");
    }

    iec61850_mms_ds_destroy(&ds);
    TEST_PASS();
}

static void test_process_request_control_null(void)
{
    iec61850_mms_session_t session;
    iec61850_mms_data_store_t ds;
    setup_session(&session, &ds);

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    mms_confirmed_error_t err;

    mms_service_type_t control_services[] = {
        MMS_SERVICE_TYPE_SELECT,
        MMS_SERVICE_TYPE_SELECT_WITH_VALUE,
        MMS_SERVICE_TYPE_OPERATE,
        MMS_SERVICE_TYPE_CANCEL
    };

    for (size_t i = 0; i < sizeof(control_services) / sizeof(control_services[0]); i++) {
        (void)memset(&req, 0, sizeof(req));
        req.service = control_services[i];
        int ret = process_request(&session, &req, &resp, &err);
        TEST_ASSERT(ret == 1, "Control service with NULL control_manager should error");
        TEST_ASSERT(err.error.error_class == MMS_ERROR_CLASS_SERVICE,
                    "error class should be SERVICE");
    }

    iec61850_mms_ds_destroy(&ds);
    TEST_PASS();
}

static void test_process_request_named_types(void)
{
    iec61850_mms_session_t session;
    iec61850_mms_data_store_t ds;
    setup_session(&session, &ds);

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    mms_confirmed_error_t err;

    mms_service_type_t type_services[] = {
        MMS_SERVICE_TYPE_DEFINE_NAMED_TYPE,
        MMS_SERVICE_TYPE_DELETE_NAMED_TYPE,
        MMS_SERVICE_TYPE_GET_NAMED_TYPE_ATTRS
    };

    for (size_t i = 0; i < sizeof(type_services) / sizeof(type_services[0]); i++) {
        (void)memset(&req, 0, sizeof(req));
        req.service = type_services[i];
        int ret = process_request(&session, &req, &resp, &err);
        TEST_ASSERT(ret == 1, "Named type services should return error");
        TEST_ASSERT(err.error.error_class == MMS_ERROR_CLASS_SERVICE,
                    "error class should be SERVICE");
    }

    iec61850_mms_ds_destroy(&ds);
    TEST_PASS();
}

static void test_process_request_command_termination(void)
{
    iec61850_mms_session_t session;
    iec61850_mms_data_store_t ds;
    setup_session(&session, &ds);

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    mms_confirmed_error_t err;
    (void)memset(&req, 0, sizeof(req));
    req.service = MMS_SERVICE_TYPE_COMMAND_TERMINATION;

    int ret = process_request(&session, &req, &resp, &err);
    TEST_ASSERT(ret == 1, "CommandTermination as request should error");

    iec61850_mms_ds_destroy(&ds);
    TEST_PASS();
}

static void test_process_request_unknown_service(void)
{
    iec61850_mms_session_t session;
    iec61850_mms_data_store_t ds;
    setup_session(&session, &ds);

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    mms_confirmed_error_t err;
    (void)memset(&req, 0, sizeof(req));
    req.service = (mms_service_type_t)999;

    int ret = process_request(&session, &req, &resp, &err);
    TEST_ASSERT(ret == 1, "Unknown service should error");
    TEST_ASSERT(err.error.error_class == MMS_ERROR_CLASS_SERVICE,
                "error class should be SERVICE");

    iec61850_mms_ds_destroy(&ds);
    TEST_PASS();
}

static void test_process_request_read_named_varlist(void)
{
    iec61850_mms_session_t session;
    iec61850_mms_data_store_t ds;
    setup_session(&session, &ds);

    /* Create a named variable list first */
    mms_variable_spec_t vars[1];
    (void)memset(vars, 0, sizeof(vars));
    (void)strncpy(vars[0].domain, "TestDomain", MMS_MAX_DOMAIN_NAME - 1);
    (void)strncpy(vars[0].item_id, "TestVar", MMS_MAX_VARIABLE_NAME - 1);
    (void)iec61850_mms_ds_define_list(&ds, "TestDomain", "ReadList", vars, 1);

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    mms_confirmed_error_t err;
    (void)memset(&req, 0, sizeof(req));
    req.service = MMS_SERVICE_TYPE_READ_NAMED_VARLIST;
    (void)strncpy(req.params.readnamedvarlist.domain, "TestDomain",
                  MMS_MAX_DOMAIN_NAME - 1);
    (void)strncpy(req.params.readnamedvarlist.list_name, "ReadList",
                  MMS_MAX_VARIABLE_NAME - 1);

    int ret = process_request(&session, &req, &resp, &err);
    TEST_ASSERT(ret == 0, "ReadNamedVarList should succeed");
    TEST_ASSERT(resp.params.readnamedvarlist.num_values == 1, "should have 1 value");
    TEST_ASSERT(resp.params.readnamedvarlist.values[0].value.integer == 42,
                "value should be 42");

    iec61850_mms_ds_destroy(&ds);
    TEST_PASS();
}

static void test_process_request_write_named_varlist(void)
{
    iec61850_mms_session_t session;
    iec61850_mms_data_store_t ds;
    setup_session(&session, &ds);

    /* Create a named variable list */
    mms_variable_spec_t vars[1];
    (void)memset(vars, 0, sizeof(vars));
    (void)strncpy(vars[0].domain, "TestDomain", MMS_MAX_DOMAIN_NAME - 1);
    (void)strncpy(vars[0].item_id, "TestVar", MMS_MAX_VARIABLE_NAME - 1);
    (void)iec61850_mms_ds_define_list(&ds, "TestDomain", "WriteList", vars, 1);

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    mms_confirmed_error_t err;
    (void)memset(&req, 0, sizeof(req));
    req.service = MMS_SERVICE_TYPE_WRITE_NAMED_VARLIST;
    (void)strncpy(req.params.writenamedvarlist.domain, "TestDomain",
                  MMS_MAX_DOMAIN_NAME - 1);
    (void)strncpy(req.params.writenamedvarlist.list_name, "WriteList",
                  MMS_MAX_VARIABLE_NAME - 1);
    req.params.writenamedvarlist.num_values = 1;
    req.params.writenamedvarlist.values[0].type = MMS_TYPE_INTEGER;
    req.params.writenamedvarlist.values[0].value.integer = 77;

    int ret = process_request(&session, &req, &resp, &err);
    TEST_ASSERT(ret == 0, "WriteNamedVarList should succeed");

    /* Verify write took effect */
    mms_value_t read_val;
    (void)iec61850_mms_ds_read_variable(&ds, "TestDomain", "TestVar", &read_val);
    TEST_ASSERT(read_val.value.integer == 77, "Written value should be 77");

    iec61850_mms_ds_destroy(&ds);
    TEST_PASS();
}

static void test_process_request_write_named_varlist_count_mismatch(void)
{
    iec61850_mms_session_t session;
    iec61850_mms_data_store_t ds;
    setup_session(&session, &ds);

    mms_variable_spec_t vars[1];
    (void)memset(vars, 0, sizeof(vars));
    (void)strncpy(vars[0].domain, "TestDomain", MMS_MAX_DOMAIN_NAME - 1);
    (void)strncpy(vars[0].item_id, "TestVar", MMS_MAX_VARIABLE_NAME - 1);
    (void)iec61850_mms_ds_define_list(&ds, "TestDomain", "WList2", vars, 1);

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    mms_confirmed_error_t err;
    (void)memset(&req, 0, sizeof(req));
    req.service = MMS_SERVICE_TYPE_WRITE_NAMED_VARLIST;
    (void)strncpy(req.params.writenamedvarlist.domain, "TestDomain",
                  MMS_MAX_DOMAIN_NAME - 1);
    (void)strncpy(req.params.writenamedvarlist.list_name, "WList2",
                  MMS_MAX_VARIABLE_NAME - 1);
    req.params.writenamedvarlist.num_values = 2; /* Mismatch: list has 1 */

    int ret = process_request(&session, &req, &resp, &err);
    TEST_ASSERT(ret == 1, "Count mismatch should error");
    TEST_ASSERT(err.error.error_code == MMS_ACCESS_ERROR_TYPE_INCONSISTENT,
                "should be type inconsistent");

    iec61850_mms_ds_destroy(&ds);
    TEST_PASS();
}

static void test_process_request_journal_with_journal(void)
{
    iec61850_mms_session_t session;
    iec61850_mms_data_store_t ds;
    setup_session(&session, &ds);

    iec61850_journal_t journal;
    iec61850_journal_init(&journal, "TestJournal");
    session.journal = &journal;

    /* Add an entry */
    mms_value_t jval;
    (void)memset(&jval, 0, sizeof(jval));
    jval.type = MMS_TYPE_INTEGER;
    jval.value.integer = 100;
    (void)iec61850_journal_add_entry(&journal, "TestVar", &jval, 1000);

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    mms_confirmed_error_t err;

    /* ReadJournal by time */
    (void)memset(&req, 0, sizeof(req));
    req.service = MMS_SERVICE_TYPE_READ_JOURNAL;
    req.params.readjournal.start_time = 0;
    req.params.readjournal.end_time = 0;
    req.params.readjournal.start_entry_id = 0;
    req.params.readjournal.max_entries = 0;

    int ret = process_request(&session, &req, &resp, &err);
    TEST_ASSERT(ret == 0, "ReadJournal by time should succeed");
    TEST_ASSERT(resp.params.readjournal.num_entries == 1, "should have 1 entry");

    /* ReadJournal by ID */
    (void)memset(&req, 0, sizeof(req));
    req.service = MMS_SERVICE_TYPE_READ_JOURNAL;
    req.params.readjournal.start_entry_id = 1;  /* nonzero triggers by-id path */
    req.params.readjournal.max_entries = 10;

    ret = process_request(&session, &req, &resp, &err);
    TEST_ASSERT(ret == 0, "ReadJournal by ID should succeed");

    /* InitializeJournal */
    (void)memset(&req, 0, sizeof(req));
    req.service = MMS_SERVICE_TYPE_INITIALIZE_JOURNAL;
    (void)strncpy(req.params.initializejournal.journal_name, "TestJournal",
                  MMS_MAX_VARIABLE_NAME - 1);

    ret = process_request(&session, &req, &resp, &err);
    TEST_ASSERT(ret == 0, "InitializeJournal should succeed");

    iec61850_mms_ds_destroy(&ds);
    TEST_PASS();
}

/***************************************************************************
 * Target 3: goose_subscriber.c frame processing
 ***************************************************************************/

/* Build a minimal valid GOOSE Ethernet frame */
static size_t build_goose_frame(uint8_t *frame, size_t frame_size,
                                uint16_t appid, const char *gocbref,
                                uint32_t stNum, uint32_t sqNum)
{
    /* First encode the GOOSE APDU */
    goose_apdu_t apdu;
    goose_apdu_init(&apdu);
    (void)goose_set_gocbref(&apdu, gocbref);
    (void)goose_set_datset(&apdu, "DataSet01");
    apdu.timeAllowedtoLive = 2000;
    apdu.timestamp = 1000000ULL;
    apdu.stNum = stNum;
    apdu.sqNum = sqNum;
    apdu.confRev = 1;
    apdu.numDatSetEntries = 1;
    (void)goose_add_boolean(&apdu, true);

    uint8_t apdu_buf[1024];
    size_t apdu_len = 0;
    int ret = goose_encode_apdu(apdu_buf, sizeof(apdu_buf), &apdu, &apdu_len);
    if (ret != GOOSE_BER_OK) {
        return 0;
    }

    /* Build Ethernet frame around the APDU */
    iec61850_eth_frame_config_t cfg;
    (void)memset(&cfg, 0, sizeof(cfg));
    /* GOOSE multicast MAC: 01:0C:CD:01:xx:xx */
    cfg.dst_mac[0] = 0x01;
    cfg.dst_mac[1] = 0x0C;
    cfg.dst_mac[2] = 0xCD;
    cfg.dst_mac[3] = 0x01;
    cfg.dst_mac[4] = 0x00;
    cfg.dst_mac[5] = 0x01;
    /* Source MAC */
    cfg.src_mac[0] = 0x02;
    cfg.src_mac[1] = 0x00;
    cfg.src_mac[2] = 0x00;
    cfg.src_mac[3] = 0x00;
    cfg.src_mac[4] = 0x00;
    cfg.src_mac[5] = 0x01;
    cfg.ethertype = IEC61850_ETHERTYPE_GOOSE;
    cfg.app_id = appid;

    size_t frame_len = 0;
    ret = iec61850_eth_frame_build(frame, frame_size, &cfg,
                                   apdu_buf, apdu_len, &frame_len);
    if (ret != 0) {
        return 0;
    }

    return frame_len;
}

static void test_goose_subscriber_process_frame_valid(void)
{
    iec61850_goose_sub_config_t cfg;
    iec61850_goose_sub_config_init(&cfg);

    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, &cfg);

    uint8_t frame[1544];
    size_t frame_len = build_goose_frame(frame, sizeof(frame), 0x1000,
                                         "TestGoCB", 1, 0);
    TEST_ASSERT(frame_len > 0, "Frame build should succeed");

    int ret = iec61850_goose_subscriber_process_frame(&sub, frame, frame_len,
                                                      1000000000ULL);
    TEST_ASSERT(ret == 1, "First frame should be processed");

    const iec61850_goose_pub_state_t *ps =
        iec61850_goose_subscriber_get_pub_state(&sub, "TestGoCB");
    TEST_ASSERT(ps != NULL, "Publisher state should exist");
    TEST_ASSERT(ps->latest_st_num == 1, "stNum should be 1");
    TEST_ASSERT(ps->latest_sq_num == 0, "sqNum should be 0");

    iec61850_goose_subscriber_destroy(&sub);
    TEST_PASS();
}

static void test_goose_subscriber_state_transitions(void)
{
    iec61850_goose_sub_config_t cfg;
    iec61850_goose_sub_config_init(&cfg);

    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, &cfg);

    uint8_t frame[1544];
    size_t frame_len;
    int ret;

    /* Initial frame: stNum=1, sqNum=0 */
    frame_len = build_goose_frame(frame, sizeof(frame), 0x1000, "GoCB1", 1, 0);
    ret = iec61850_goose_subscriber_process_frame(&sub, frame, frame_len,
                                                  1000000000ULL);
    TEST_ASSERT(ret == 1, "Initial frame accepted");

    /* Retransmission: stNum=1, sqNum=1 */
    frame_len = build_goose_frame(frame, sizeof(frame), 0x1000, "GoCB1", 1, 1);
    ret = iec61850_goose_subscriber_process_frame(&sub, frame, frame_len,
                                                  2000000000ULL);
    TEST_ASSERT(ret == 1, "Retransmission accepted");

    /* Duplicate: stNum=1, sqNum=0 (already seen) */
    frame_len = build_goose_frame(frame, sizeof(frame), 0x1000, "GoCB1", 1, 0);
    ret = iec61850_goose_subscriber_process_frame(&sub, frame, frame_len,
                                                  3000000000ULL);
    TEST_ASSERT(ret == 0, "Duplicate should be filtered");
    TEST_ASSERT(sub.total_duplicates == 1, "Should count duplicate");

    /* New event: stNum=2, sqNum=0 */
    frame_len = build_goose_frame(frame, sizeof(frame), 0x1000, "GoCB1", 2, 0);
    ret = iec61850_goose_subscriber_process_frame(&sub, frame, frame_len,
                                                  4000000000ULL);
    TEST_ASSERT(ret == 1, "New event accepted");

    const iec61850_goose_pub_state_t *ps =
        iec61850_goose_subscriber_get_pub_state(&sub, "GoCB1");
    TEST_ASSERT(ps != NULL, "Publisher state should exist");
    TEST_ASSERT(ps->latest_st_num == 2, "stNum should be 2");

    /* Old state: stNum=1 (< latest=2) */
    frame_len = build_goose_frame(frame, sizeof(frame), 0x1000, "GoCB1", 1, 5);
    ret = iec61850_goose_subscriber_process_frame(&sub, frame, frame_len,
                                                  5000000000ULL);
    TEST_ASSERT(ret == 0, "Old state should be discarded");

    iec61850_goose_subscriber_destroy(&sub);
    TEST_PASS();
}

static void test_goose_subscriber_timeout(void)
{
    iec61850_goose_sub_config_t cfg;
    iec61850_goose_sub_config_init(&cfg);
    cfg.timeout_ms = 100; /* 100ms timeout */

    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, &cfg);

    uint8_t frame[1544];
    size_t frame_len = build_goose_frame(frame, sizeof(frame), 0x1000,
                                         "GoCBTimeout", 1, 0);
    (void)iec61850_goose_subscriber_process_frame(&sub, frame, frame_len,
                                                  1000000000ULL);

    /* Check timeout before timeout period */
    iec61850_goose_subscriber_check_timeouts(&sub, 1050000000ULL);
    TEST_ASSERT(sub.total_timeouts == 0, "No timeout yet");

    /* Check timeout after timeout period (100ms = 100000000ns) */
    iec61850_goose_subscriber_check_timeouts(&sub, 1200000000ULL);
    TEST_ASSERT(sub.total_timeouts == 1, "Should detect timeout");

    iec61850_goose_subscriber_destroy(&sub);
    TEST_PASS();
}

static void test_goose_subscriber_appid_filter(void)
{
    iec61850_goose_sub_config_t cfg;
    iec61850_goose_sub_config_init(&cfg);
    cfg.filter_appid = 0x2000;

    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, &cfg);

    uint8_t frame[1544];
    /* Frame with APPID 0x1000 - should be filtered */
    size_t frame_len = build_goose_frame(frame, sizeof(frame), 0x1000,
                                         "GoCBFilter", 1, 0);
    int ret = iec61850_goose_subscriber_process_frame(&sub, frame, frame_len,
                                                      1000000000ULL);
    TEST_ASSERT(ret == 0, "Wrong APPID should be filtered");

    /* Frame with APPID 0x2000 - should pass */
    frame_len = build_goose_frame(frame, sizeof(frame), 0x2000,
                                  "GoCBFilter", 1, 0);
    ret = iec61850_goose_subscriber_process_frame(&sub, frame, frame_len,
                                                  2000000000ULL);
    TEST_ASSERT(ret == 1, "Matching APPID should pass");

    iec61850_goose_subscriber_destroy(&sub);
    TEST_PASS();
}

static void test_goose_subscriber_gocbref_filter(void)
{
    iec61850_goose_sub_config_t cfg;
    iec61850_goose_sub_config_init(&cfg);
    (void)strncpy(cfg.filter_gocbref, "WantedGoCB",
                  GOOSE_MAX_GOCBREF_LEN - 1);

    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, &cfg);

    uint8_t frame[1544];
    /* Frame with wrong gocbRef */
    size_t frame_len = build_goose_frame(frame, sizeof(frame), 0x1000,
                                         "OtherGoCB", 1, 0);
    int ret = iec61850_goose_subscriber_process_frame(&sub, frame, frame_len,
                                                      1000000000ULL);
    TEST_ASSERT(ret == 0, "Wrong gocbRef should be filtered");

    /* Frame with matching gocbRef */
    frame_len = build_goose_frame(frame, sizeof(frame), 0x1000,
                                  "WantedGoCB", 1, 0);
    ret = iec61850_goose_subscriber_process_frame(&sub, frame, frame_len,
                                                  2000000000ULL);
    TEST_ASSERT(ret == 1, "Matching gocbRef should pass");

    iec61850_goose_subscriber_destroy(&sub);
    TEST_PASS();
}

static void test_goose_subscriber_null_args(void)
{
    int ret = iec61850_goose_subscriber_process_frame(NULL, NULL, 0, 0);
    TEST_ASSERT(ret == 0, "NULL sub should return 0");

    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, NULL);
    ret = iec61850_goose_subscriber_process_frame(&sub, NULL, 0, 0);
    TEST_ASSERT(ret == 0, "NULL frame should return 0");

    iec61850_goose_subscriber_destroy(&sub);
    TEST_PASS();
}

static int goose_callback_count = 0;

static void goose_test_cb(const iec61850_goose_message_t *msg, void *ud)
{
    (void)msg;
    (void)ud;
    goose_callback_count++;
}

static void test_goose_subscriber_callback(void)
{
    goose_callback_count = 0;

    iec61850_goose_sub_config_t cfg;
    iec61850_goose_sub_config_init(&cfg);

    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, &cfg);
    iec61850_goose_subscriber_set_callback(&sub, goose_test_cb, NULL);

    uint8_t frame[1544];
    size_t frame_len = build_goose_frame(frame, sizeof(frame), 0x1000,
                                         "GoCBCB", 1, 0);
    (void)iec61850_goose_subscriber_process_frame(&sub, frame, frame_len,
                                                  1000000000ULL);
    TEST_ASSERT(goose_callback_count == 1, "Callback should be called once");

    iec61850_goose_subscriber_destroy(&sub);
    TEST_PASS();
}

/***************************************************************************
 * Target 4: sv_subscriber.c frame processing
 ***************************************************************************/

/* Build a minimal valid SV Ethernet frame */
static size_t build_sv_frame(uint8_t *frame, size_t frame_size,
                             uint16_t appid, const char *svid,
                             uint16_t smpCnt)
{
    sv_apdu_t apdu;
    sv_apdu_init(&apdu);
    apdu.noASDU = 1;
    sv_asdu_init(&apdu.asdu[0]);
    (void)sv_set_svid(&apdu.asdu[0], svid);
    apdu.asdu[0].smpCnt = smpCnt;
    apdu.asdu[0].confRev = 1;
    apdu.asdu[0].smpSynch = SV_SMPSYNCH_GLOBAL;

    sv_quality_t q = {0};
    (void)sv_add_sample(&apdu.asdu[0], 1000, q);

    uint8_t apdu_buf[1024];
    size_t apdu_len = 0;
    int ret = sv_encode_apdu(apdu_buf, sizeof(apdu_buf), &apdu, &apdu_len);
    if (ret != SV_BER_OK) {
        return 0;
    }

    /* Build Ethernet frame */
    iec61850_eth_frame_config_t cfg;
    (void)memset(&cfg, 0, sizeof(cfg));
    /* SV multicast MAC: 01:0C:CD:04:xx:xx */
    cfg.dst_mac[0] = 0x01;
    cfg.dst_mac[1] = 0x0C;
    cfg.dst_mac[2] = 0xCD;
    cfg.dst_mac[3] = 0x04;
    cfg.dst_mac[4] = 0x00;
    cfg.dst_mac[5] = 0x01;
    cfg.src_mac[0] = 0x02;
    cfg.ethertype = IEC61850_ETHERTYPE_SV;
    cfg.app_id = appid;

    size_t frame_len = 0;
    ret = iec61850_eth_frame_build(frame, frame_size, &cfg,
                                   apdu_buf, apdu_len, &frame_len);
    if (ret != 0) {
        return 0;
    }

    return frame_len;
}

static int sv_cb_count = 0;

static void sv_test_cb(const iec61850_sv_message_t *msg, void *ud)
{
    (void)msg;
    (void)ud;
    sv_cb_count++;
}

static void test_sv_subscriber_process_frame_valid(void)
{
    iec61850_sv_sub_config_t cfg;
    iec61850_sv_sub_config_init(&cfg);

    iec61850_sv_subscriber_t sub;
    iec61850_sv_subscriber_init(&sub, &cfg);

    sv_cb_count = 0;
    iec61850_sv_subscriber_set_callback(&sub, sv_test_cb, NULL);

    uint8_t frame[1544];
    size_t frame_len = build_sv_frame(frame, sizeof(frame), 0x4000,
                                      "TestSV01", 0);
    TEST_ASSERT(frame_len > 0, "SV frame build should succeed");

    int ret = iec61850_sv_subscriber_process_frame(&sub, frame, frame_len,
                                                   1000000000ULL);
    TEST_ASSERT(ret == 1, "First SV frame should be processed");
    TEST_ASSERT(sv_cb_count == 1, "Callback should be called");

    const iec61850_sv_pub_state_t *ps =
        iec61850_sv_subscriber_get_pub_state(&sub, "TestSV01");
    TEST_ASSERT(ps != NULL, "Publisher state should exist");
    TEST_ASSERT(ps->latest_smp_cnt == 0, "smpCnt should be 0");

    iec61850_sv_subscriber_destroy(&sub);
    TEST_PASS();
}

static void test_sv_subscriber_smp_continuity(void)
{
    iec61850_sv_sub_config_t cfg;
    iec61850_sv_sub_config_init(&cfg);
    cfg.smp_rate = 80; /* 80 samples/cycle, 50Hz → wrap at 4000 */

    iec61850_sv_subscriber_t sub;
    iec61850_sv_subscriber_init(&sub, &cfg);

    uint8_t frame[1544];
    size_t frame_len;
    int ret;

    /* smpCnt=0 */
    frame_len = build_sv_frame(frame, sizeof(frame), 0x4000, "SV1", 0);
    ret = iec61850_sv_subscriber_process_frame(&sub, frame, frame_len,
                                               1000000000ULL);
    TEST_ASSERT(ret == 1, "smpCnt=0 accepted");

    /* smpCnt=1 (continuous) */
    frame_len = build_sv_frame(frame, sizeof(frame), 0x4000, "SV1", 1);
    ret = iec61850_sv_subscriber_process_frame(&sub, frame, frame_len,
                                               2000000000ULL);
    TEST_ASSERT(ret == 1, "smpCnt=1 accepted");
    TEST_ASSERT(sub.total_gaps == 0, "No gaps expected");

    /* smpCnt=5 (gap of 3) */
    frame_len = build_sv_frame(frame, sizeof(frame), 0x4000, "SV1", 5);
    ret = iec61850_sv_subscriber_process_frame(&sub, frame, frame_len,
                                               3000000000ULL);
    TEST_ASSERT(ret == 1, "smpCnt=5 accepted");
    TEST_ASSERT(sub.total_gaps == 3, "Should detect gap of 3");

    /* Duplicate: smpCnt=5 again */
    frame_len = build_sv_frame(frame, sizeof(frame), 0x4000, "SV1", 5);
    ret = iec61850_sv_subscriber_process_frame(&sub, frame, frame_len,
                                               4000000000ULL);
    TEST_ASSERT(ret == 1, "SV duplicate still processed at frame level");
    TEST_ASSERT(sub.total_duplicates == 1, "Should count duplicate");

    iec61850_sv_subscriber_destroy(&sub);
    TEST_PASS();
}

static void test_sv_subscriber_appid_filter(void)
{
    iec61850_sv_sub_config_t cfg;
    iec61850_sv_sub_config_init(&cfg);
    cfg.filter_appid = 0x5000;

    iec61850_sv_subscriber_t sub;
    iec61850_sv_subscriber_init(&sub, &cfg);

    uint8_t frame[1544];
    /* Wrong APPID */
    size_t frame_len = build_sv_frame(frame, sizeof(frame), 0x4000, "SV1", 0);
    int ret = iec61850_sv_subscriber_process_frame(&sub, frame, frame_len,
                                                   1000000000ULL);
    TEST_ASSERT(ret == 0, "Wrong SV APPID should be filtered");

    /* Matching APPID */
    frame_len = build_sv_frame(frame, sizeof(frame), 0x5000, "SV1", 0);
    ret = iec61850_sv_subscriber_process_frame(&sub, frame, frame_len,
                                               2000000000ULL);
    TEST_ASSERT(ret == 1, "Matching SV APPID should pass");

    iec61850_sv_subscriber_destroy(&sub);
    TEST_PASS();
}

static void test_sv_subscriber_svid_filter(void)
{
    iec61850_sv_sub_config_t cfg;
    iec61850_sv_sub_config_init(&cfg);
    (void)strncpy(cfg.filter_svid, "WantedSV", SV_MAX_SVID_LEN - 1);

    iec61850_sv_subscriber_t sub;
    iec61850_sv_subscriber_init(&sub, &cfg);

    uint8_t frame[1544];
    /* Wrong svID */
    size_t frame_len = build_sv_frame(frame, sizeof(frame), 0x4000,
                                      "OtherSV", 0);
    int ret = iec61850_sv_subscriber_process_frame(&sub, frame, frame_len,
                                                   1000000000ULL);
    /* Frame should be processed at the frame level but filtered at ASDU level */
    /* The process_frame decodes then calls subscriber_process which filters */
    TEST_ASSERT(sub.total_messages == 0, "Wrong svID should be filtered");

    /* Matching svID */
    frame_len = build_sv_frame(frame, sizeof(frame), 0x4000, "WantedSV", 0);
    ret = iec61850_sv_subscriber_process_frame(&sub, frame, frame_len,
                                               2000000000ULL);
    TEST_ASSERT(ret == 1, "Matching svID should pass");

    iec61850_sv_subscriber_destroy(&sub);
    TEST_PASS();
}

static void test_sv_subscriber_timeout(void)
{
    iec61850_sv_sub_config_t cfg;
    iec61850_sv_sub_config_init(&cfg);
    cfg.timeout_ms = 50; /* 50ms timeout */

    iec61850_sv_subscriber_t sub;
    iec61850_sv_subscriber_init(&sub, &cfg);

    uint8_t frame[1544];
    size_t frame_len = build_sv_frame(frame, sizeof(frame), 0x4000,
                                      "SVTimeout", 0);
    (void)iec61850_sv_subscriber_process_frame(&sub, frame, frame_len,
                                               1000000000ULL);

    /* Before timeout */
    iec61850_sv_subscriber_check_timeouts(&sub, 1030000000ULL);
    TEST_ASSERT(sub.total_timeouts == 0, "No timeout yet");

    /* After timeout (50ms = 50000000ns) */
    iec61850_sv_subscriber_check_timeouts(&sub, 1060000000ULL);
    TEST_ASSERT(sub.total_timeouts == 1, "Should detect timeout");

    iec61850_sv_subscriber_destroy(&sub);
    TEST_PASS();
}

static void test_sv_subscriber_null_args(void)
{
    int ret = iec61850_sv_subscriber_process_frame(NULL, NULL, 0, 0);
    TEST_ASSERT(ret == 0, "NULL sub should return 0");

    iec61850_sv_subscriber_t sub;
    iec61850_sv_subscriber_init(&sub, NULL);
    ret = iec61850_sv_subscriber_process_frame(&sub, NULL, 0, 0);
    TEST_ASSERT(ret == 0, "NULL frame should return 0");

    iec61850_sv_subscriber_destroy(&sub);
    TEST_PASS();
}

/***************************************************************************
 * Main Test Runner
 ***************************************************************************/

int main(void)
{
    printf("Running coverage boost tests...\n");
    printf("=========================================\n\n");

    /* Target 1: SV BER security */
    printf("SV BER security encode/decode:\n");
    test_sv_set_security_valid();
    test_sv_set_security_null_args();
    test_sv_set_security_sig_too_large();
    test_sv_encode_security_roundtrip();
    test_sv_encode_security_no_security();
    test_sv_encode_security_null_args();
    test_sv_multi_asdu_roundtrip();
    test_sv_encode_buffer_too_small();
    test_sv_decode_truncated();
    test_sv_decode_malformed();
    printf("\n");

    /* Target 2: MMS Server process_request */
    printf("MMS Server process_request:\n");
    test_process_request_status();
    test_process_request_identify();
    test_process_request_read();
    test_process_request_read_not_found();
    test_process_request_write();
    test_process_request_getnamelist_domains();
    test_process_request_getnamelist_variables();
    test_process_request_get_variable_attrs();
    test_process_request_get_variable_attrs_not_found();
    test_process_request_define_delete_varlist();
    test_process_request_read_named_varlist();
    test_process_request_write_named_varlist();
    test_process_request_write_named_varlist_count_mismatch();
    test_process_request_file_null_service();
    test_process_request_journal_null();
    test_process_request_control_null();
    test_process_request_named_types();
    test_process_request_command_termination();
    test_process_request_unknown_service();
    test_process_request_journal_with_journal();
    printf("\n");

    /* Target 3: GOOSE Subscriber */
    printf("GOOSE subscriber frame processing:\n");
    test_goose_subscriber_process_frame_valid();
    test_goose_subscriber_state_transitions();
    test_goose_subscriber_timeout();
    test_goose_subscriber_appid_filter();
    test_goose_subscriber_gocbref_filter();
    test_goose_subscriber_null_args();
    test_goose_subscriber_callback();
    printf("\n");

    /* Target 4: SV Subscriber */
    printf("SV subscriber frame processing:\n");
    test_sv_subscriber_process_frame_valid();
    test_sv_subscriber_smp_continuity();
    test_sv_subscriber_appid_filter();
    test_sv_subscriber_svid_filter();
    test_sv_subscriber_timeout();
    test_sv_subscriber_null_args();
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
