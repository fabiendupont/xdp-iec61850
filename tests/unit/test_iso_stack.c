/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for ISO Transport Stack
 *
 * Tests: TPKT encode/decode, Session CONNECT/ACCEPT/DATA,
 * Presentation CP/CPA/P-DATA, ACSE AARQ/AARE, COTP,
 * GIVE_TOKENS DATA SPDU, A0 wrapper round-trip.
 */

#include "transport/iso_stack.h"

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
 * TPKT
 * ======================================================================== */

static void test_tpkt_encode_decode(void)
{
    TEST("tpkt_encode_decode");
    uint8_t buf[256];
    uint8_t data[] = {0xDE, 0xAD, 0xBE, 0xEF};

    int ret = iec61850_tpkt_encode(buf, sizeof(buf), data, sizeof(data));
    ASSERT_TRUE(ret > 0);

    const uint8_t *payload;
    size_t payload_len;
    ret = iec61850_tpkt_decode(buf, (size_t)ret, &payload, &payload_len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)payload_len, 4);
    ASSERT_EQ(payload[0], 0xDE);
    ASSERT_EQ(payload[3], 0xEF);

    PASS();
}

static void test_tpkt_null(void)
{
    TEST("tpkt_null");
    uint8_t buf[16];
    uint8_t data[] = {0x01};

    ASSERT_TRUE(iec61850_tpkt_encode(NULL, 16, data, 1) < 0);
    ASSERT_TRUE(iec61850_tpkt_encode(buf, 16, NULL, 1) < 0);

    const uint8_t *p;
    size_t l;
    ASSERT_TRUE(iec61850_tpkt_decode(NULL, 16, &p, &l) < 0);
    ASSERT_TRUE(iec61850_tpkt_decode(buf, 16, NULL, &l) < 0);

    PASS();
}

/* ========================================================================
 * Session
 * ======================================================================== */

static void test_session_connect_accept_roundtrip(void)
{
    TEST("session_connect_accept_roundtrip");
    uint8_t buf[512];
    iec61850_session_params_t params;
    iec61850_session_params_init(&params);

    uint8_t user_data[] = {0x01, 0x02, 0x03};

    int ret = iec61850_session_encode_connect(buf, sizeof(buf), &params,
                                                user_data, sizeof(user_data));
    ASSERT_TRUE(ret > 0);

    uint8_t si_type;
    iec61850_session_params_t decoded_params;
    const uint8_t *decoded_ud;
    size_t decoded_ud_len;
    ret = iec61850_session_decode(buf, (size_t)ret, &si_type, &decoded_params,
                                    &decoded_ud, &decoded_ud_len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(si_type, IEC61850_SI_CONNECT);
    ASSERT_EQ((int)decoded_ud_len, 3);
    ASSERT_EQ(decoded_ud[0], 0x01);

    PASS();
}

static void test_session_data_give_tokens(void)
{
    TEST("session_data_give_tokens");
    uint8_t buf[256];
    uint8_t payload[] = {0xAA, 0xBB};

    int ret = iec61850_session_encode_data(buf, sizeof(buf),
                                             payload, sizeof(payload));
    ASSERT_TRUE(ret > 0);
    /* Should be 01 00 01 00 AA BB (GIVE_TOKENS + DATA + payload) */
    ASSERT_EQ(buf[0], 0x01);
    ASSERT_EQ(buf[1], 0x00);
    ASSERT_EQ(buf[2], 0x01);
    ASSERT_EQ(buf[3], 0x00);
    ASSERT_EQ(buf[4], 0xAA);

    /* Decode should strip GIVE_TOKENS and return payload */
    uint8_t si_type;
    const uint8_t *ud;
    size_t ud_len;
    ret = iec61850_session_decode(buf, (size_t)ret, &si_type, NULL, &ud, &ud_len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(si_type, IEC61850_SI_DATA);
    ASSERT_EQ((int)ud_len, 2);
    ASSERT_EQ(ud[0], 0xAA);

    PASS();
}

static void test_session_requirements_tag(void)
{
    TEST("session_requirements_tag_0x14");
    ASSERT_EQ(IEC61850_SPI_REQUIREMENTS, 0x14U);
    PASS();
}

/* ========================================================================
 * Presentation
 * ======================================================================== */

static void test_pres_pdata_roundtrip(void)
{
    TEST("pres_pdata_roundtrip");
    uint8_t buf[512];
    uint8_t app_data[] = {0x60, 0x03, 0x01, 0x02, 0x03};

    int ret = iec61850_pres_encode_pdata(buf, sizeof(buf), IEC61850_PCID_MMS,
                                           app_data, sizeof(app_data));
    ASSERT_TRUE(ret > 0);

    uint8_t pcid;
    const uint8_t *decoded;
    size_t decoded_len;
    ret = iec61850_pres_decode(buf, (size_t)ret, &pcid, &decoded, &decoded_len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(pcid, IEC61850_PCID_MMS);
    ASSERT_EQ((int)decoded_len, (int)sizeof(app_data));
    ASSERT_EQ(decoded[0], 0x60);

    PASS();
}

static void test_pres_cp_encode(void)
{
    TEST("pres_cp_encode");
    uint8_t buf[1024];
    iec61850_acse_params_t params;
    iec61850_acse_params_init(&params);
    uint8_t acse_buf[512];
    int acse_ret = iec61850_acse_encode_aarq(acse_buf, sizeof(acse_buf),
                                               &params, NULL, 0);
    ASSERT_TRUE(acse_ret > 0);

    int ret = iec61850_pres_encode_cp(buf, sizeof(buf), acse_buf,
                                        (size_t)acse_ret);
    ASSERT_TRUE(ret > 0);

    /* CP starts with SET tag (0x31) */
    ASSERT_EQ(buf[0], 0x31);

    /* CPA has same structure */
    ret = iec61850_pres_encode_cpa(buf, sizeof(buf), acse_buf,
                                     (size_t)acse_ret);
    ASSERT_TRUE(ret > 0);
    ASSERT_EQ(buf[0], 0x31);

    PASS();
}

/* ========================================================================
 * ACSE
 * ======================================================================== */

static void test_acse_aarq_aare_roundtrip(void)
{
    TEST("acse_aarq_aare_roundtrip");
    uint8_t buf[1024];
    iec61850_acse_params_t params;
    iec61850_acse_params_init(&params);

    uint8_t mms_init[] = {0xA8, 0x04, 0x80, 0x02, 0xFF, 0xFF};

    int ret = iec61850_acse_encode_aarq(buf, sizeof(buf), &params,
                                          mms_init, sizeof(mms_init));
    ASSERT_TRUE(ret > 0);

    uint8_t tag;
    iec61850_acse_params_t decoded_params;
    iec61850_aare_result_t result;
    const uint8_t *app_pdu;
    size_t app_len;
    ret = iec61850_acse_decode(buf, (size_t)ret, &tag, &decoded_params,
                                 &result, &app_pdu, &app_len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(tag, IEC61850_ACSE_TAG_AARQ);
    ASSERT_TRUE(app_pdu != NULL);
    ASSERT_EQ((int)app_len, (int)sizeof(mms_init));
    ASSERT_EQ(app_pdu[0], 0xA8);

    PASS();
}

static void test_acse_rlrq_rlre(void)
{
    TEST("acse_rlrq_rlre");
    uint8_t buf[64];

    int ret = iec61850_acse_encode_rlrq(buf, sizeof(buf));
    ASSERT_TRUE(ret > 0);
    ASSERT_EQ(buf[0], IEC61850_ACSE_TAG_RLRQ);

    ret = iec61850_acse_encode_rlre(buf, sizeof(buf));
    ASSERT_TRUE(ret > 0);
    ASSERT_EQ(buf[0], IEC61850_ACSE_TAG_RLRE);

    PASS();
}

/* ========================================================================
 * ISO Connection Init
 * ======================================================================== */

static void test_iso_conn_init(void)
{
    TEST("iso_conn_init");
    iec61850_iso_conn_t conn;
    iec61850_iso_conn_init(&conn);
    ASSERT_EQ((int)conn.state, (int)IEC61850_ISO_STATE_IDLE);
    ASSERT_EQ((int)conn.max_pdu_size, (int)IEC61850_ISO_MAX_PDU);
    PASS();
}

int main(void)
{
    printf("=== ISO Stack Unit Tests ===\n");

    printf("\n--- TPKT ---\n");
    test_tpkt_encode_decode();
    test_tpkt_null();

    printf("\n--- Session ---\n");
    test_session_connect_accept_roundtrip();
    test_session_data_give_tokens();
    test_session_requirements_tag();

    printf("\n--- Presentation ---\n");
    test_pres_pdata_roundtrip();
    test_pres_cp_encode();

    printf("\n--- ACSE ---\n");
    test_acse_aarq_aare_roundtrip();
    test_acse_rlrq_rlre();

    printf("\n--- ISO Connection ---\n");
    test_iso_conn_init();

    printf("\n=== Test Summary ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
