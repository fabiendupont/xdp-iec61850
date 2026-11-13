/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for MMS Client Async Core
 *
 * WP-1a: lifecycle contract, pending-table semantics, detach
 * cancellation, invokeID correlation dispatch, unsolicited report
 * dispatch, and timeout behavior. The decode path is exercised
 * end-to-end without a live server by attaching the core to a
 * socketpair-backed ISO connection and feeding crafted, ISO-wrapped
 * MMS PDUs through poll().
 */

#include "mms/mms_client_core.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { tests_run++; printf("  [TEST] %s ... ", name); } while (0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg) do { tests_failed++; printf("FAIL: %s\n", msg); return; } while (0)
#define ASSERT_TRUE(cond) do { if (!(cond)) { FAIL(#cond); return; } } while (0)
#define ASSERT_EQ(a, b) do { if ((a) != (b)) { \
    printf("FAIL: %s == %s (%d != %d)\n", #a, #b, (int)(a), (int)(b)); \
    tests_failed++; return; } } while (0)

/* ========================================================================
 * Test infrastructure
 * ======================================================================== */

#define CAP_MAX 16

/* Response-callback capture */
typedef struct {
    int count;
    int status[CAP_MAX];
    bool has_response[CAP_MAX];
    bool has_error[CAP_MAX];
    uint32_t invoke_id[CAP_MAX];
    int service[CAP_MAX];
    int value_type[CAP_MAX];
    bool bool_value[CAP_MAX];
} capture_t;

static void capture_cb(int status,
                        const mms_confirmed_response_t *response,
                        const mms_confirmed_error_t *error,
                        void *user_data)
{
    capture_t *cap = (capture_t *)user_data;
    int idx;

    if (cap->count >= CAP_MAX) { return; }
    idx = cap->count;
    cap->status[idx] = status;
    cap->has_response[idx] = (response != NULL);
    cap->has_error[idx] = (error != NULL);
    cap->invoke_id[idx] = 0;
    cap->service[idx] = -1;
    cap->value_type[idx] = -1;
    cap->bool_value[idx] = false;
    if (response != NULL) {
        cap->invoke_id[idx] = response->invoke_id;
        cap->service[idx] = (int)response->service;
        cap->value_type[idx] = (int)response->params.read.value.type;
        cap->bool_value[idx] = response->params.read.value.value.boolean;
    }
    if (error != NULL) {
        cap->invoke_id[idx] = error->invoke_id;
    }
    cap->count++;
}

/* Report-callback capture */
typedef struct {
    int count;
    char name[MMS_MAX_VARIABLE_NAME];
    uint32_t num_values;
    bool bool_value;
} report_capture_t;

static void report_capture_cb(const mms_information_report_t *report,
                               void *user_data)
{
    report_capture_t *rc = (report_capture_t *)user_data;

    if (rc->count == 0) {
        (void)strncpy(rc->name, report->variable_list_name,
                       sizeof(rc->name) - 1U);
        rc->name[sizeof(rc->name) - 1U] = '\0';
        rc->num_values = report->num_values;
        rc->bool_value = ((report->num_values > 0U) &&
                          (report->values[0].type == MMS_TYPE_BOOLEAN))
                         ? report->values[0].value.boolean : false;
    }
    rc->count++;
}

/* Build a socketpair-backed ISO connection in the connected state. */
static int make_loopback_conn(iec61850_iso_conn_t *conn, int *peer)
{
    int fds[2];

    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) {
        return -1;
    }
    iec61850_iso_conn_init(conn);
    conn->tcp.sockfd = fds[0];
    conn->tcp.connected = true;
    conn->state = IEC61850_ISO_STATE_CONNECTED;
    *peer = fds[1];
    return 0;
}

/* Wrap an MMS PDU (pres → session → TPKT) and write it to the peer
 * side of the loopback connection. */
static int send_wrapped_pdu(int peer, const uint8_t *pdu, size_t len)
{
    uint8_t pres_buf[IEC61850_ISO_MAX_PDU];
    uint8_t sess_buf[IEC61850_ISO_MAX_PDU];
    uint8_t tpkt_buf[IEC61850_ISO_MAX_PDU];
    ssize_t n;
    int ret;

    ret = iec61850_pres_encode_pdata(pres_buf, sizeof(pres_buf),
                                      IEC61850_PCID_MMS, pdu, len);
    if (ret < 0) { return -1; }
    ret = iec61850_session_encode_data(sess_buf, sizeof(sess_buf),
                                        pres_buf, (size_t)ret);
    if (ret < 0) { return -1; }
    ret = iec61850_tpkt_encode(tpkt_buf, sizeof(tpkt_buf),
                                 sess_buf, (size_t)ret);
    if (ret < 0) { return -1; }

    n = write(peer, tpkt_buf, (size_t)ret);
    return (n == (ssize_t)ret) ? 0 : -1;
}

static int craft_read_response(uint32_t invoke_id, uint8_t *buf, size_t buflen)
{
    mms_confirmed_response_t resp;

    (void)memset(&resp, 0, sizeof(resp));
    resp.invoke_id = invoke_id;
    resp.service = MMS_SERVICE_TYPE_READ;
    resp.params.read.value.type = MMS_TYPE_BOOLEAN;
    resp.params.read.value.value.boolean = true;
    return mms_encode_confirmed_response(&resp, buf, buflen);
}

static int craft_error_pdu(uint32_t invoke_id, uint8_t *buf, size_t buflen)
{
    mms_confirmed_error_t err;

    (void)memset(&err, 0, sizeof(err));
    err.invoke_id = invoke_id;
    err.error.error_class = MMS_ERROR_CLASS_DEFINITION;
    err.error.error_code = MMS_ACCESS_ERROR_OBJECT_NON_EXISTENT;
    return mms_encode_confirmed_error(&err, buf, buflen);
}

static int craft_report(uint8_t *buf, size_t buflen)
{
    mms_information_report_t rpt;

    (void)memset(&rpt, 0, sizeof(rpt));
    (void)strncpy(rpt.variable_list_name, "testLD/DS123",
                   sizeof(rpt.variable_list_name) - 1U);
    rpt.num_values = 1;
    rpt.values[0].type = MMS_TYPE_BOOLEAN;
    rpt.values[0].value.boolean = true;
    return mms_encode_information_report(&rpt, buf, buflen);
}

static int table_in_use_count(const iec61850_mms_client_core_t *core)
{
    int n = 0;

    for (size_t i = 0; i < IEC61850_CLIENT_CORE_MAX_PENDING; i++) {
        if (core->pending[i].in_use) { n++; }
    }
    return n;
}

/* ========================================================================
 * Lifecycle (WP-S1 contract, retained)
 * ======================================================================== */

static void test_core_init_lifecycle(void)
{
    TEST("core_init_lifecycle");
    iec61850_mms_client_core_t core;
    iec61850_mms_client_core_init(&core);

    ASSERT_TRUE(core.iso == NULL);
    ASSERT_TRUE(!core.attached);
    ASSERT_TRUE(core.report_cb == NULL);

    /* Detached operations report -ENOTCONN per contract */
    ASSERT_EQ(iec61850_mms_client_core_fd(&core), -ENOTCONN);

    iec61850_mms_client_core_init(NULL); /* must not crash */
    PASS();
}

static void test_core_attach_detach(void)
{
    TEST("core_attach_detach");
    iec61850_mms_client_core_t core;
    iec61850_iso_conn_t conn;
    iec61850_iso_conn_init(&conn);
    iec61850_mms_client_core_init(&core);

    ASSERT_EQ(iec61850_mms_client_core_attach(&core, &conn), 0);
    ASSERT_EQ(iec61850_mms_client_core_attach(&core, &conn), -EBUSY);
    ASSERT_TRUE(core.attached);
    ASSERT_TRUE(core.iso == &conn);

    iec61850_mms_client_core_detach(&core);
    ASSERT_TRUE(!core.attached);
    ASSERT_TRUE(core.iso == NULL);
    ASSERT_EQ(iec61850_mms_client_core_fd(&core), -ENOTCONN);

    /* Re-attach after detach is allowed */
    ASSERT_EQ(iec61850_mms_client_core_attach(&core, &conn), 0);
    iec61850_mms_client_core_detach(&core);

    ASSERT_EQ(iec61850_mms_client_core_attach(NULL, &conn), -EINVAL);
    ASSERT_EQ(iec61850_mms_client_core_attach(&core, NULL), -EINVAL);
    PASS();
}

/* ========================================================================
 * fd()
 * ======================================================================== */

static void test_core_fd(void)
{
    TEST("core_fd");
    iec61850_mms_client_core_t core;
    iec61850_iso_conn_t conn;

    iec61850_iso_conn_init(&conn);
    conn.tcp.sockfd = 42; /* pretend fd */
    iec61850_mms_client_core_init(&core);

    ASSERT_EQ(iec61850_mms_client_core_fd(NULL), -EINVAL);
    ASSERT_EQ(iec61850_mms_client_core_fd(&core), -ENOTCONN);

    ASSERT_EQ(iec61850_mms_client_core_attach(&core, &conn), 0);
    ASSERT_EQ(iec61850_mms_client_core_fd(&core), 42);

    iec61850_mms_client_core_detach(&core);
    ASSERT_EQ(iec61850_mms_client_core_fd(&core), -ENOTCONN);
    PASS();
}

/* ========================================================================
 * submit(): argument validation and pending-table capacity
 * ======================================================================== */

static void test_submit_validation(void)
{
    TEST("submit_validation");
    iec61850_mms_client_core_t core;
    iec61850_iso_conn_t conn;
    uint8_t pdu[4] = {0U, 0U, 0U, 0U};
    int peer;

    ASSERT_EQ(make_loopback_conn(&conn, &peer), 0);
    iec61850_mms_client_core_init(&core);

    /* NULL core */
    ASSERT_EQ(iec61850_mms_client_core_submit(NULL, pdu, sizeof(pdu),
                                               1U, capture_cb, NULL),
              -EINVAL);
    /* detached */
    ASSERT_EQ(iec61850_mms_client_core_submit(&core, pdu, sizeof(pdu),
                                               1U, capture_cb, NULL),
              -ENOTCONN);

    ASSERT_EQ(iec61850_mms_client_core_attach(&core, &conn), 0);

    /* NULL pdu / zero length / NULL callback */
    ASSERT_EQ(iec61850_mms_client_core_submit(&core, NULL, sizeof(pdu),
                                               1U, capture_cb, NULL),
              -EINVAL);
    ASSERT_EQ(iec61850_mms_client_core_submit(&core, pdu, 0,
                                               1U, capture_cb, NULL),
              -EINVAL);
    ASSERT_EQ(iec61850_mms_client_core_submit(&core, pdu, sizeof(pdu),
                                               1U, NULL, NULL),
              -EINVAL);

    /* poll/wait validation */
    ASSERT_EQ(iec61850_mms_client_core_poll(NULL, 0), -EINVAL);
    ASSERT_EQ(iec61850_mms_client_core_poll(&core, -1), -EINVAL);
    ASSERT_EQ(iec61850_mms_client_core_wait(NULL, 1U, 1), -EINVAL);
    ASSERT_EQ(iec61850_mms_client_core_wait(&core, 1U, -1), -EINVAL);

    iec61850_mms_client_core_detach(&core);
    ASSERT_EQ(iec61850_mms_client_core_poll(&core, 0), -ENOTCONN);
    (void)close(peer);
    PASS();
}

static void test_submit_fills_pending_table(void)
{
    TEST("submit_fills_pending_table");
    iec61850_mms_client_core_t core;
    iec61850_iso_conn_t conn;
    capture_t cap;
    uint8_t pdu[4] = {0xA0U, 0x02U, 0x80U, 0x01U};
    int peer;
    int i;

    ASSERT_EQ(make_loopback_conn(&conn, &peer), 0);
    iec61850_mms_client_core_init(&core);
    (void)memset(&cap, 0, sizeof(cap));
    ASSERT_EQ(iec61850_mms_client_core_attach(&core, &conn), 0);

    /* Fill all 8 slots */
    for (i = 0; i < IEC61850_CLIENT_CORE_MAX_PENDING; i++) {
        ASSERT_EQ(iec61850_mms_client_core_submit(&core, pdu, sizeof(pdu),
                                                   (uint32_t)(i + 1),
                                                   capture_cb, &cap),
                  0);
    }
    ASSERT_EQ(table_in_use_count(&core), IEC61850_CLIENT_CORE_MAX_PENDING);

    /* Table full of outstanding requests: -EAGAIN */
    ASSERT_EQ(iec61850_mms_client_core_submit(&core, pdu, sizeof(pdu),
                                               99U, capture_cb, &cap),
              -EAGAIN);

    /* Each submit must have sent a TPKT frame to the peer: drain one
     * full frame per submission and validate its header. */
    for (i = 0; i < IEC61850_CLIENT_CORE_MAX_PENDING; i++) {
        uint8_t hdr[4];
        uint16_t total_len;
        ssize_t n = read(peer, hdr, sizeof(hdr));
        ASSERT_TRUE(n == (ssize_t)sizeof(hdr));
        ASSERT_EQ(hdr[0], IEC61850_TPKT_VERSION);
        ASSERT_EQ(hdr[1], 0);
        total_len = (uint16_t)(((uint16_t)hdr[2] << 8) | (uint16_t)hdr[3]);
        ASSERT_TRUE(total_len > 4U);
        while (total_len > 4U) {
            uint8_t rest[512];
            size_t want = ((size_t)total_len - 4U > sizeof(rest))
                          ? sizeof(rest) : ((size_t)total_len - 4U);
            n = read(peer, rest, want);
            ASSERT_TRUE(n > 0);
            total_len = (uint16_t)(total_len - (uint16_t)n);
        }
    }

    /* Detach cancels all 8 outstanding entries with -ECANCELED */
    iec61850_mms_client_core_detach(&core);
    ASSERT_EQ(cap.count, IEC61850_CLIENT_CORE_MAX_PENDING);
    for (i = 0; i < IEC61850_CLIENT_CORE_MAX_PENDING; i++) {
        ASSERT_EQ(cap.status[i], -ECANCELED);
        ASSERT_TRUE(!cap.has_response[i]);
        ASSERT_TRUE(!cap.has_error[i]);
    }
    ASSERT_EQ(table_in_use_count(&core), 0);

    (void)close(peer);
    PASS();
}

static void test_detach_cancels_pending(void)
{
    TEST("detach_cancels_pending");
    iec61850_mms_client_core_t core;
    iec61850_iso_conn_t conn;
    capture_t cap;
    uint8_t pdu[4] = {0xA0U, 0x02U, 0x80U, 0x01U};
    int peer;

    ASSERT_EQ(make_loopback_conn(&conn, &peer), 0);
    iec61850_mms_client_core_init(&core);
    (void)memset(&cap, 0, sizeof(cap));
    ASSERT_EQ(iec61850_mms_client_core_attach(&core, &conn), 0);

    ASSERT_EQ(iec61850_mms_client_core_submit(&core, pdu, sizeof(pdu),
                                               7U, capture_cb, &cap), 0);
    ASSERT_EQ(iec61850_mms_client_core_submit(&core, pdu, sizeof(pdu),
                                               8U, capture_cb, &cap), 0);
    ASSERT_EQ(iec61850_mms_client_core_submit(&core, pdu, sizeof(pdu),
                                               9U, capture_cb, &cap), 0);

    iec61850_mms_client_core_detach(&core);

    ASSERT_EQ(cap.count, 3);
    ASSERT_EQ(cap.status[0], -ECANCELED);
    ASSERT_EQ(cap.status[1], -ECANCELED);
    ASSERT_EQ(cap.status[2], -ECANCELED);
    ASSERT_EQ(table_in_use_count(&core), 0);
    ASSERT_TRUE(!core.attached);

    /* Re-attach after a canceling detach is allowed */
    ASSERT_EQ(iec61850_mms_client_core_attach(&core, &conn), 0);
    iec61850_mms_client_core_detach(&core);

    (void)close(peer);
    PASS();
}

/* ========================================================================
 * poll(): dispatch through the real decode path
 * ======================================================================== */

static void test_poll_no_data_returns_zero(void)
{
    TEST("poll_no_data_returns_zero");
    iec61850_mms_client_core_t core;
    iec61850_iso_conn_t conn;
    int peer;

    ASSERT_EQ(make_loopback_conn(&conn, &peer), 0);
    iec61850_mms_client_core_init(&core);
    ASSERT_EQ(iec61850_mms_client_core_attach(&core, &conn), 0);

    /* Non-blocking poll with no data: 0 events, not an error */
    ASSERT_EQ(iec61850_mms_client_core_poll(&core, 0), 0);
    /* Short-timeout poll with no data: 0 events */
    ASSERT_EQ(iec61850_mms_client_core_poll(&core, 50), 0);

    iec61850_mms_client_core_detach(&core);
    (void)close(peer);
    PASS();
}

static void test_response_correlation(void)
{
    TEST("response_correlation");
    iec61850_mms_client_core_t core;
    iec61850_iso_conn_t conn;
    capture_t cap;
    uint8_t req[4] = {0xA0U, 0x02U, 0x80U, 0x07U};
    uint8_t pdu_buf[1024];
    int ret;
    int peer;

    ASSERT_EQ(make_loopback_conn(&conn, &peer), 0);
    iec61850_mms_client_core_init(&core);
    (void)memset(&cap, 0, sizeof(cap));
    ASSERT_EQ(iec61850_mms_client_core_attach(&core, &conn), 0);

    ASSERT_EQ(iec61850_mms_client_core_submit(&core, req, sizeof(req),
                                               7U, capture_cb, &cap), 0);

    ret = craft_read_response(7U, pdu_buf, sizeof(pdu_buf));
    ASSERT_TRUE(ret > 0);
    ASSERT_EQ(send_wrapped_pdu(peer, pdu_buf, (size_t)ret), 0);

    /* One PDU queued: exactly one event dispatched */
    ASSERT_EQ(iec61850_mms_client_core_poll(&core, 200), 1);
    /* Nothing left: no further events */
    ASSERT_EQ(iec61850_mms_client_core_poll(&core, 0), 0);

    ASSERT_EQ(cap.count, 1);
    ASSERT_EQ(cap.status[0], 0);
    ASSERT_TRUE(cap.has_response[0]);
    ASSERT_TRUE(!cap.has_error[0]);
    ASSERT_EQ(cap.invoke_id[0], 7U);
    ASSERT_EQ(cap.service[0], (int)MMS_SERVICE_TYPE_READ);
    ASSERT_EQ(cap.value_type[0], (int)MMS_TYPE_BOOLEAN);
    ASSERT_TRUE(cap.bool_value[0]);

    /* Delivered entry is reaped by wait() with its recorded status */
    ASSERT_EQ(iec61850_mms_client_core_wait(&core, 7U, 0), 0);
    ASSERT_EQ(table_in_use_count(&core), 0);
    /* Reaped: no longer known */
    ASSERT_EQ(iec61850_mms_client_core_wait(&core, 7U, 0), -EINVAL);

    iec61850_mms_client_core_detach(&core);
    (void)close(peer);
    PASS();
}

static void test_error_pdu_correlation(void)
{
    TEST("error_pdu_correlation");
    iec61850_mms_client_core_t core;
    iec61850_iso_conn_t conn;
    capture_t cap;
    uint8_t req[4] = {0xA0U, 0x02U, 0x80U, 0x09U};
    uint8_t pdu_buf[1024];
    int ret;
    int peer;

    ASSERT_EQ(make_loopback_conn(&conn, &peer), 0);
    iec61850_mms_client_core_init(&core);
    (void)memset(&cap, 0, sizeof(cap));
    ASSERT_EQ(iec61850_mms_client_core_attach(&core, &conn), 0);

    ASSERT_EQ(iec61850_mms_client_core_submit(&core, req, sizeof(req),
                                               9U, capture_cb, &cap), 0);

    ret = craft_error_pdu(9U, pdu_buf, sizeof(pdu_buf));
    ASSERT_TRUE(ret > 0);
    ASSERT_EQ(send_wrapped_pdu(peer, pdu_buf, (size_t)ret), 0);

    ASSERT_EQ(iec61850_mms_client_core_poll(&core, 200), 1);

    ASSERT_EQ(cap.count, 1);
    ASSERT_EQ(cap.status[0], 0);          /* PDU decoded: status 0 */
    ASSERT_TRUE(!cap.has_response[0]);
    ASSERT_TRUE(cap.has_error[0]);
    ASSERT_EQ(cap.invoke_id[0], 9U);

    ASSERT_EQ(iec61850_mms_client_core_wait(&core, 9U, 0), 0);

    iec61850_mms_client_core_detach(&core);
    (void)close(peer);
    PASS();
}

static void test_unmatched_response_ignored(void)
{
    TEST("unmatched_response_ignored");
    iec61850_mms_client_core_t core;
    iec61850_iso_conn_t conn;
    capture_t cap;
    uint8_t req[4] = {0xA0U, 0x02U, 0x80U, 0x07U};
    uint8_t pdu_buf[1024];
    int ret;
    int peer;

    ASSERT_EQ(make_loopback_conn(&conn, &peer), 0);
    iec61850_mms_client_core_init(&core);
    (void)memset(&cap, 0, sizeof(cap));
    ASSERT_EQ(iec61850_mms_client_core_attach(&core, &conn), 0);

    ASSERT_EQ(iec61850_mms_client_core_submit(&core, req, sizeof(req),
                                               7U, capture_cb, &cap), 0);

    /* Response for an invokeID we never submitted: ignored */
    ret = craft_read_response(99U, pdu_buf, sizeof(pdu_buf));
    ASSERT_TRUE(ret > 0);
    ASSERT_EQ(send_wrapped_pdu(peer, pdu_buf, (size_t)ret), 0);
    ASSERT_EQ(iec61850_mms_client_core_poll(&core, 200), 0);
    ASSERT_EQ(cap.count, 0);
    ASSERT_TRUE(core.pending[0].in_use && !core.pending[0].delivered);

    /* The real response still completes the request */
    ret = craft_read_response(7U, pdu_buf, sizeof(pdu_buf));
    ASSERT_TRUE(ret > 0);
    ASSERT_EQ(send_wrapped_pdu(peer, pdu_buf, (size_t)ret), 0);
    ASSERT_EQ(iec61850_mms_client_core_poll(&core, 200), 1);
    ASSERT_EQ(cap.count, 1);
    ASSERT_EQ(cap.invoke_id[0], 7U);

    iec61850_mms_client_core_detach(&core);
    (void)close(peer);
    PASS();
}

static void test_report_dispatch(void)
{
    TEST("report_dispatch");
    iec61850_mms_client_core_t core;
    iec61850_iso_conn_t conn;
    report_capture_t rcap;
    uint8_t pdu_buf[2048];
    int ret;
    int peer;

    ASSERT_EQ(make_loopback_conn(&conn, &peer), 0);
    iec61850_mms_client_core_init(&core);
    (void)memset(&rcap, 0, sizeof(rcap));
    ASSERT_EQ(iec61850_mms_client_core_attach(&core, &conn), 0);

    ret = craft_report(pdu_buf, sizeof(pdu_buf));
    ASSERT_TRUE(ret > 0);

    /* Without a handler the report is discarded silently */
    ASSERT_EQ(send_wrapped_pdu(peer, pdu_buf, (size_t)ret), 0);
    ASSERT_EQ(iec61850_mms_client_core_poll(&core, 200), 0);

    /* With a handler it is decoded and dispatched */
    iec61850_mms_client_core_set_report_handler(&core, report_capture_cb,
                                                  &rcap);
    ASSERT_EQ(send_wrapped_pdu(peer, pdu_buf, (size_t)ret), 0);
    ASSERT_EQ(iec61850_mms_client_core_poll(&core, 200), 1);

    ASSERT_EQ(rcap.count, 1);
    ASSERT_EQ(strcmp(rcap.name, "testLD/DS123"), 0);
    ASSERT_EQ(rcap.num_values, 1U);
    ASSERT_TRUE(rcap.bool_value);

    /* Handler can be cleared again */
    iec61850_mms_client_core_set_report_handler(&core, NULL, NULL);
    ASSERT_TRUE(core.report_cb == NULL);

    iec61850_mms_client_core_detach(&core);
    (void)close(peer);
    PASS();
}

static void test_malformed_pdu_is_ebadmsg(void)
{
    TEST("malformed_pdu_is_ebadmsg");
    iec61850_mms_client_core_t core;
    iec61850_iso_conn_t conn;
    capture_t cap;
    uint8_t req[4] = {0xA0U, 0x02U, 0x80U, 0x03U};
    uint8_t bad_pdu[3] = {0xA1U, 0x01U, 0x99U}; /* tag ok, body broken */
    uint8_t pdu_buf[1024];
    int ret;
    int peer;

    ASSERT_EQ(make_loopback_conn(&conn, &peer), 0);
    iec61850_mms_client_core_init(&core);
    (void)memset(&cap, 0, sizeof(cap));
    ASSERT_EQ(iec61850_mms_client_core_attach(&core, &conn), 0);

    ASSERT_EQ(iec61850_mms_client_core_submit(&core, req, sizeof(req),
                                               3U, capture_cb, &cap), 0);

    ASSERT_EQ(send_wrapped_pdu(peer, bad_pdu, sizeof(bad_pdu)), 0);
    ASSERT_EQ(iec61850_mms_client_core_poll(&core, 200), -EBADMSG);

    /* A malformed PDU must not cancel the pending request */
    ASSERT_EQ(cap.count, 0);
    ASSERT_TRUE(core.pending[0].in_use && !core.pending[0].delivered);

    /* The association stays usable: a good response still delivers */
    ret = craft_read_response(3U, pdu_buf, sizeof(pdu_buf));
    ASSERT_TRUE(ret > 0);
    ASSERT_EQ(send_wrapped_pdu(peer, pdu_buf, (size_t)ret), 0);
    ASSERT_EQ(iec61850_mms_client_core_poll(&core, 200), 1);
    ASSERT_EQ(cap.count, 1);
    ASSERT_EQ(cap.status[0], 0);

    iec61850_mms_client_core_detach(&core);
    (void)close(peer);
    PASS();
}

static void test_connection_lost_fails_pending(void)
{
    TEST("connection_lost_fails_pending");
    iec61850_mms_client_core_t core;
    iec61850_iso_conn_t conn;
    capture_t cap;
    uint8_t req[4] = {0xA0U, 0x02U, 0x80U, 0x01U};
    int peer;

    ASSERT_EQ(make_loopback_conn(&conn, &peer), 0);
    iec61850_mms_client_core_init(&core);
    (void)memset(&cap, 0, sizeof(cap));
    ASSERT_EQ(iec61850_mms_client_core_attach(&core, &conn), 0);

    ASSERT_EQ(iec61850_mms_client_core_submit(&core, req, sizeof(req),
                                               1U, capture_cb, &cap), 0);

    /* Peer goes away: pending entries are failed with -ECONNRESET */
    (void)shutdown(peer, SHUT_WR);
    ASSERT_EQ(iec61850_mms_client_core_poll(&core, 200), -ECONNRESET);
    ASSERT_EQ(cap.count, 1);
    ASSERT_EQ(cap.status[0], -ECONNRESET);
    ASSERT_TRUE(!cap.has_response[0]);
    ASSERT_TRUE(!cap.has_error[0]);

    /* wait() reports the recorded failure status */
    ASSERT_EQ(iec61850_mms_client_core_wait(&core, 1U, 0), -ECONNRESET);
    ASSERT_EQ(table_in_use_count(&core), 0);

    iec61850_mms_client_core_detach(&core);
    (void)close(peer);
    PASS();
}

/* ========================================================================
 * wait()
 * ======================================================================== */

static void test_wait_unknown_invoke_id(void)
{
    TEST("wait_unknown_invoke_id");
    iec61850_mms_client_core_t core;
    iec61850_iso_conn_t conn;
    int peer;

    ASSERT_EQ(make_loopback_conn(&conn, &peer), 0);
    iec61850_mms_client_core_init(&core);
    ASSERT_EQ(iec61850_mms_client_core_attach(&core, &conn), 0);

    ASSERT_EQ(iec61850_mms_client_core_wait(&core, 1234U, 10), -EINVAL);

    iec61850_mms_client_core_detach(&core);
    (void)close(peer);
    PASS();
}

static void test_wait_timeout_and_late_delivery(void)
{
    TEST("wait_timeout_and_late_delivery");
    iec61850_mms_client_core_t core;
    iec61850_iso_conn_t conn;
    capture_t cap;
    uint8_t req[4] = {0xA0U, 0x02U, 0x80U, 0x05U};
    uint8_t pdu_buf[1024];
    int ret;
    int peer;

    ASSERT_EQ(make_loopback_conn(&conn, &peer), 0);
    iec61850_mms_client_core_init(&core);
    (void)memset(&cap, 0, sizeof(cap));
    ASSERT_EQ(iec61850_mms_client_core_attach(&core, &conn), 0);

    ASSERT_EQ(iec61850_mms_client_core_submit(&core, req, sizeof(req),
                                               5U, capture_cb, &cap), 0);

    /* No response ever arrives within the window */
    ASSERT_EQ(iec61850_mms_client_core_wait(&core, 5U, 60), -ETIMEDOUT);

    /* The entry stays pending after a timeout */
    ASSERT_EQ(cap.count, 0);
    ASSERT_EQ(table_in_use_count(&core), 1);
    ASSERT_TRUE(core.pending[0].in_use && !core.pending[0].delivered);

    /* A late response still delivers, and wait() reaps it with the
     * recorded status even with a zero timeout */
    ret = craft_read_response(5U, pdu_buf, sizeof(pdu_buf));
    ASSERT_TRUE(ret > 0);
    ASSERT_EQ(send_wrapped_pdu(peer, pdu_buf, (size_t)ret), 0);
    ASSERT_EQ(iec61850_mms_client_core_poll(&core, 200), 1);
    ASSERT_EQ(cap.count, 1);
    ASSERT_EQ(cap.status[0], 0);
    ASSERT_EQ(iec61850_mms_client_core_wait(&core, 5U, 0), 0);
    ASSERT_EQ(table_in_use_count(&core), 0);

    iec61850_mms_client_core_detach(&core);
    (void)close(peer);
    PASS();
}

static void test_wait_dispatches_response_end_to_end(void)
{
    TEST("wait_dispatches_response_end_to_end");
    iec61850_mms_client_core_t core;
    iec61850_iso_conn_t conn;
    capture_t cap;
    uint8_t req[4] = {0xA0U, 0x02U, 0x80U, 0x0BU};
    uint8_t pdu_buf[1024];
    int ret;
    int peer;

    ASSERT_EQ(make_loopback_conn(&conn, &peer), 0);
    iec61850_mms_client_core_init(&core);
    (void)memset(&cap, 0, sizeof(cap));
    ASSERT_EQ(iec61850_mms_client_core_attach(&core, &conn), 0);

    ASSERT_EQ(iec61850_mms_client_core_submit(&core, req, sizeof(req),
                                               11U, capture_cb, &cap), 0);

    /* Response queued before wait(): wait() polls, dispatches the
     * callback, and returns the entry status. */
    ret = craft_read_response(11U, pdu_buf, sizeof(pdu_buf));
    ASSERT_TRUE(ret > 0);
    ASSERT_EQ(send_wrapped_pdu(peer, pdu_buf, (size_t)ret), 0);

    ASSERT_EQ(iec61850_mms_client_core_wait(&core, 11U, 500), 0);
    ASSERT_EQ(cap.count, 1);
    ASSERT_EQ(cap.status[0], 0);
    ASSERT_TRUE(cap.has_response[0]);
    ASSERT_EQ(cap.invoke_id[0], 11U);
    ASSERT_EQ(table_in_use_count(&core), 0);

    iec61850_mms_client_core_detach(&core);
    (void)close(peer);
    PASS();
}

/* ========================================================================
 * Pending-slot recycling (delivered entries are not outstanding)
 * ======================================================================== */

static void test_delivered_slots_are_recycled(void)
{
    TEST("delivered_slots_are_recycled");
    iec61850_mms_client_core_t core;
    iec61850_iso_conn_t conn;
    capture_t cap;
    uint8_t req[4] = {0xA0U, 0x02U, 0x80U, 0x01U};
    uint8_t pdu_buf[1024];
    int ret;
    int peer;
    int i;

    ASSERT_EQ(make_loopback_conn(&conn, &peer), 0);
    iec61850_mms_client_core_init(&core);
    (void)memset(&cap, 0, sizeof(cap));
    ASSERT_EQ(iec61850_mms_client_core_attach(&core, &conn), 0);

    /* Submit and deliver MAX_PENDING requests, reaping each with
     * wait() — the classic blocking-client pattern. */
    for (i = 0; i < IEC61850_CLIENT_CORE_MAX_PENDING; i++) {
        uint32_t id = (uint32_t)(i + 1);

        ASSERT_EQ(iec61850_mms_client_core_submit(&core, req, sizeof(req),
                                                   id, capture_cb, &cap),
                  0);
        ret = craft_read_response(id, pdu_buf, sizeof(pdu_buf));
        ASSERT_TRUE(ret > 0);
        ASSERT_EQ(send_wrapped_pdu(peer, pdu_buf, (size_t)ret), 0);
        ASSERT_EQ(iec61850_mms_client_core_wait(&core, id, 500), 0);
    }
    ASSERT_EQ(cap.count, IEC61850_CLIENT_CORE_MAX_PENDING);
    ASSERT_EQ(table_in_use_count(&core), 0);

    /* Even without reaping: delivered tombstones are not outstanding,
     * so submit() must not fail with -EAGAIN. */
    for (i = 0; i < IEC61850_CLIENT_CORE_MAX_PENDING; i++) {
        uint32_t id = (uint32_t)(i + 100);

        ASSERT_EQ(iec61850_mms_client_core_submit(&core, req, sizeof(req),
                                                   id, capture_cb, &cap),
                  0);
        ret = craft_read_response(id, pdu_buf, sizeof(pdu_buf));
        ASSERT_TRUE(ret > 0);
        ASSERT_EQ(send_wrapped_pdu(peer, pdu_buf, (size_t)ret), 0);
        ASSERT_EQ(iec61850_mms_client_core_poll(&core, 200), 1);
    }
    ASSERT_EQ(iec61850_mms_client_core_submit(&core, req, sizeof(req),
                                               999U, capture_cb, &cap),
              0); /* recycles a tombstone slot */

    iec61850_mms_client_core_detach(&core);
    (void)close(peer);
    PASS();
}

int main(void)
{
    printf("=== MMS Client Core Unit Tests ===\n");

    test_core_init_lifecycle();
    test_core_attach_detach();
    test_core_fd();
    test_submit_validation();
    test_submit_fills_pending_table();
    test_detach_cancels_pending();
    test_poll_no_data_returns_zero();
    test_response_correlation();
    test_error_pdu_correlation();
    test_unmatched_response_ignored();
    test_report_dispatch();
    test_malformed_pdu_is_ebadmsg();
    test_connection_lost_fails_pending();
    test_wait_unknown_invoke_id();
    test_wait_timeout_and_late_delivery();
    test_wait_dispatches_response_end_to_end();
    test_delivered_slots_are_recycled();

    printf("\n=== Summary: %d run, %d passed, %d failed ===\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
