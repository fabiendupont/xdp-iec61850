/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit tests for ISO Transport Stack (TPKT, Session, Presentation)
 */


#include "transport/iso_stack.h"

#include <stdio.h>
#include <string.h>

/* ---- Minimal test framework ---- */
static int test_run = 0, test_passed = 0, test_failed = 0;
#define TEST(name) do { test_run++; printf("  [TEST] %s ...", name); } while(0)
#define PASS() do { test_passed++; printf(" PASS\n"); return; } while(0)
#define FAIL(msg) do { test_failed++; printf(" FAIL: %s\n", msg); return; } while(0)
#define ASSERT_TRUE(x) do { if (!(x)) { FAIL(#x); } } while(0)
#define ASSERT_EQ(a,b) do { if ((a) != (b)) { printf(" (got %d, want %d)", (a), (b)); FAIL(#a " != " #b); } } while(0)

/* ---- Tests ---- */

static void test_tcp_listener_init(void)
{
    TEST("tcp_listener_init");
    iec61850_tcp_listener_t listener;
    memset(&listener, 0xFF, sizeof(listener));
    iec61850_tcp_listener_init(&listener);
    ASSERT_EQ(listener.sockfd, -1);
    ASSERT_TRUE(listener.listening == false);
    PASS();
}

static void test_tcp_conn_init(void)
{
    TEST("tcp_conn_init");
    iec61850_tcp_conn_t conn;
    memset(&conn, 0xFF, sizeof(conn));
    iec61850_tcp_conn_init(&conn);
    ASSERT_EQ(conn.sockfd, -1);
    ASSERT_TRUE(conn.connected == false);
    PASS();
}

static void test_iso_conn_init(void)
{
    TEST("iso_conn_init");
    iec61850_iso_conn_t conn;
    memset(&conn, 0xFF, sizeof(conn));
    iec61850_iso_conn_init(&conn);
    ASSERT_EQ(conn.tcp.sockfd, -1);
    ASSERT_TRUE(conn.tcp.connected == false);
    ASSERT_EQ((int)conn.state, (int)IEC61850_ISO_STATE_IDLE);
    ASSERT_EQ((int)conn.max_pdu_size, (int)IEC61850_ISO_MAX_PDU);
    /* session params should also be initialized */
    ASSERT_EQ(conn.session_params.version, 2);
    ASSERT_EQ(conn.session_params.user_requirements, 0x0002);
    PASS();
}

static void test_session_params_init(void)
{
    TEST("session_params_init");
    iec61850_session_params_t params;
    memset(&params, 0xFF, sizeof(params));
    iec61850_session_params_init(&params);
    ASSERT_EQ(params.version, 2);
    ASSERT_EQ(params.user_requirements, 0x0002);
    ASSERT_EQ((int)params.calling_ssel_len, 2);
    ASSERT_EQ((int)params.called_ssel_len, 2);
    PASS();
}

static void test_session_encode_data(void)
{
    TEST("session_encode_data");
    uint8_t buf[64];
    const uint8_t payload[] = {0xAA, 0xBB, 0xCC};
    int ret = iec61850_session_encode_data(buf, sizeof(buf), payload, sizeof(payload));
    /* Expected: 01 00 01 00 AA BB CC = 7 bytes */
    ASSERT_TRUE(ret > 0);
    ASSERT_EQ(ret, 7);
    /* GIVE_TOKENS SPDU: SI=0x01, LI=0x00 */
    ASSERT_EQ((int)buf[0], 0x01);
    ASSERT_EQ((int)buf[1], 0x00);
    /* DATA SPDU: SI=0x01, LI=0x00 */
    ASSERT_EQ((int)buf[2], 0x01);
    ASSERT_EQ((int)buf[3], 0x00);
    /* Payload */
    ASSERT_EQ((int)buf[4], 0xAA);
    ASSERT_EQ((int)buf[5], 0xBB);
    ASSERT_EQ((int)buf[6], 0xCC);
    PASS();
}

static void test_session_decode_data(void)
{
    TEST("session_decode_data");
    /* First encode a DATA SPDU */
    uint8_t buf[64];
    const uint8_t payload[] = {0xAA, 0xBB, 0xCC};
    int ret = iec61850_session_encode_data(buf, sizeof(buf), payload, sizeof(payload));
    ASSERT_TRUE(ret > 0);

    /* Now decode it */
    uint8_t si_type = 0;
    iec61850_session_params_t params;
    const uint8_t *user_data = NULL;
    size_t user_data_len = 0;

    int dret = iec61850_session_decode(buf, (size_t)ret, &si_type, &params,
                                       &user_data, &user_data_len);
    ASSERT_EQ(dret, 0);
    ASSERT_EQ((int)si_type, (int)IEC61850_SI_DATA);
    ASSERT_TRUE(user_data != NULL);
    ASSERT_EQ((int)user_data_len, 3);
    ASSERT_EQ((int)user_data[0], 0xAA);
    ASSERT_EQ((int)user_data[1], 0xBB);
    ASSERT_EQ((int)user_data[2], 0xCC);
    PASS();
}

static void test_session_encode_connect_small(void)
{
    TEST("session_encode_connect_small");
    iec61850_session_params_t params;
    iec61850_session_params_init(&params);

    /* Small user data (< 254 bytes) should use single-byte length */
    uint8_t user_data[10];
    memset(user_data, 0x42, sizeof(user_data));

    uint8_t buf[256];
    int ret = iec61850_session_encode_connect(buf, sizeof(buf), &params,
                                              user_data, sizeof(user_data));
    ASSERT_TRUE(ret > 0);
    /* First byte must be SI_CONNECT = 0x0D */
    ASSERT_EQ((int)buf[0], (int)IEC61850_SI_CONNECT);
    /* Second byte is the SPDU length (single byte since content < 254):
     * content = 8 (PGI 0x05: proto_opts + version) + 4 (requirements PI) +
     *           4 (calling SSEL) + 4 (called SSEL) +
     *           1 (user_data PI) + 1 (len byte) + 10 (data) = 32 */
    ASSERT_EQ((int)buf[1], 32);
    PASS();
}

static void test_session_encode_finish(void)
{
    TEST("session_encode_finish");
    uint8_t buf[64];
    const uint8_t payload[] = {0xDE, 0xAD};
    int ret = iec61850_session_encode_finish(buf, sizeof(buf), payload, sizeof(payload));
    ASSERT_TRUE(ret > 0);
    /* First byte is SI_FINISH = 0x09 */
    ASSERT_EQ((int)buf[0], (int)IEC61850_SI_FINISH);
    /* Content length = 1 (user_data PI) + 1 (length byte) + 2 (data) = 4
     * Single-byte length since 4 <= 254 */
    ASSERT_EQ((int)buf[1], 4);
    /* User data PI = 0xC1 */
    ASSERT_EQ((int)buf[2], (int)IEC61850_SPI_USER_DATA);
    /* User data length = 2 */
    ASSERT_EQ((int)buf[3], 2);
    /* Payload */
    ASSERT_EQ((int)buf[4], 0xDE);
    ASSERT_EQ((int)buf[5], 0xAD);
    ASSERT_EQ(ret, 6);
    PASS();
}

static void test_tpkt_wrap_unwrap(void)
{
    TEST("tpkt_wrap_unwrap");
    uint8_t buf[64];
    const uint8_t data[] = {0x11, 0x22, 0x33};

    /* Encode: TPKT header (4) + COTP DT header (3) + data (3) = 10 */
    int ret = iec61850_tpkt_encode(buf, sizeof(buf), data, sizeof(data));
    ASSERT_TRUE(ret > 0);
    ASSERT_EQ(ret, 10);

    /* Verify TPKT header */
    ASSERT_EQ((int)buf[0], IEC61850_TPKT_VERSION);  /* version = 3 */
    ASSERT_EQ((int)buf[1], 0);                       /* reserved = 0 */
    /* Length = 10 in big-endian */
    ASSERT_EQ((int)buf[2], 0);
    ASSERT_EQ((int)buf[3], 10);

    /* COTP DT header */
    ASSERT_EQ((int)buf[4], 0x02);  /* LI = 2 */
    ASSERT_EQ((int)buf[5], 0xF0);  /* DT type */
    ASSERT_EQ((int)buf[6], 0x80);  /* EOT */

    /* Now decode */
    const uint8_t *payload = NULL;
    size_t payload_len = 0;
    int dret = iec61850_tpkt_decode(buf, (size_t)ret, &payload, &payload_len);
    ASSERT_EQ(dret, 0);
    ASSERT_TRUE(payload != NULL);
    ASSERT_EQ((int)payload_len, 3);
    ASSERT_EQ((int)payload[0], 0x11);
    ASSERT_EQ((int)payload[1], 0x22);
    ASSERT_EQ((int)payload[2], 0x33);
    PASS();
}

static void test_presentation_encode_cp(void)
{
    TEST("presentation_encode_cp");
    uint8_t buf[512];
    /* Use a minimal fake ACSE PDU */
    const uint8_t acse[] = {0x60, 0x03, 0x01, 0x02, 0x03};

    int ret = iec61850_pres_encode_cp(buf, sizeof(buf), acse, sizeof(acse));
    ASSERT_TRUE(ret > 0);
    /* First byte must be CP tag = 0x31 (SET) */
    ASSERT_EQ((int)buf[0], 0x31);
    /* The output should contain the ACSE data somewhere inside */
    /* Verify it's a reasonable size (header overhead + acse) */
    ASSERT_TRUE(ret > (int)sizeof(acse));
    PASS();
}

/* ---- Main ---- */

int main(void)
{
    printf("=== test_transport ===\n");

    test_tcp_listener_init();
    test_tcp_conn_init();
    test_iso_conn_init();
    test_session_params_init();
    test_session_encode_data();
    test_session_decode_data();
    test_session_encode_connect_small();
    test_session_encode_finish();
    test_tpkt_wrap_unwrap();
    test_presentation_encode_cp();

    printf("  %d/%d passed, %d failed\n", test_passed, test_run, test_failed);
    return (test_failed > 0) ? 1 : 0;
}
