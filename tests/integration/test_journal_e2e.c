/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Journal Service End-to-End Test
 *
 * Tests journal services over the full MMS client/server TCP stack:
 * - InitializeJournal request accepted by server
 * - Add entries server-side, read back via client time-range query
 * - Read from empty journal returns 0 entries
 * - Circular buffer overwrites oldest entries when full
 */


#include "mms/mms_server.h"
#include "mms/mms_client.h"
#include "mms/mms_data_store.h"
#include "mms/mms_journal.h"
#include "asn1/mms_ber.h"
#include "transport/iso_stack.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Minimal test framework */
static int test_run = 0, test_passed = 0, test_failed = 0;
#define TEST(name) do { test_run++; printf("  [TEST] %s ...", name); } while(0)
#define PASS() do { test_passed++; printf(" PASS\n"); } while(0)
#define FAIL(msg) do { test_failed++; printf(" FAIL: %s\n", msg); return; } while(0)
#define ASSERT_TRUE(x) do { if (!(x)) { FAIL(#x); } } while(0)
#define ASSERT_EQ(a,b) do { if ((a) != (b)) { printf(" (got %d, want %d)", (int)(a), (int)(b)); FAIL(#a " != " #b); } } while(0)

/* Test port — unique to avoid conflicts with other integration tests */
#define TEST_PORT 10660

/* Shared infrastructure */
static iec61850_mms_data_store_t g_ds;
static iec61850_mms_server_t g_server;
static iec61850_journal_t g_journal;

static void setup_server(void)
{
    iec61850_mms_ds_init(&g_ds);
    iec61850_mms_ds_create_domain(&g_ds, "journalLD");

    mms_value_t val;
    (void)memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;
    val.value.integer = 0;
    iec61850_mms_ds_create_variable(&g_ds, "journalLD", "LLN0$ST$Beh$stVal",
                                     MMS_TYPE_INTEGER, &val);

    iec61850_journal_init(&g_journal, "journalLD$LLN0$EventLog");

    iec61850_mms_server_config_t cfg;
    iec61850_mms_server_config_init(&cfg);
    cfg.port = TEST_PORT;

    iec61850_mms_server_init(&g_server, &cfg, &g_ds);
    g_server.journal = &g_journal;

    iec61850_mms_server_start(&g_server);
    usleep(200000);
}

static void teardown_server(void)
{
    iec61850_mms_server_stop(&g_server);
    iec61850_mms_ds_destroy(&g_ds);
}

/*
 * Send a confirmed request and receive the response.
 * Mirrors the static transact() in mms_client.c.
 */
static int transact(iec61850_mms_client_t *client,
                      const mms_confirmed_request_t *req,
                      mms_confirmed_response_t *resp)
{
    uint8_t req_buf[4096];
    uint8_t resp_buf[IEC61850_ISO_MAX_PDU];
    size_t resp_len;
    int ret;

    ret = mms_encode_confirmed_request(req, req_buf, sizeof(req_buf));
    if (ret <= 0) { return IEC61850_MMS_CLIENT_ERR_ENCODE; }

    ret = iec61850_iso_send(&client->iso, req_buf, (size_t)ret);
    if (ret < 0) { return IEC61850_MMS_CLIENT_ERR_TRANSPORT; }

    ret = iec61850_iso_recv(&client->iso, resp_buf, sizeof(resp_buf),
                              &resp_len, client->request_timeout_ms);
    if (ret != 0) { return IEC61850_MMS_CLIENT_ERR_TRANSPORT; }

    ret = mms_decode_confirmed_response(resp_buf, resp_len, resp);
    if (ret < 0) { return IEC61850_MMS_CLIENT_ERR_DECODE; }

    return IEC61850_MMS_CLIENT_OK;
}

static iec61850_mms_client_t *connect_client(void)
{
    static iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", TEST_PORT, 5000);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        return NULL;
    }
    return &client;
}

/* ======================================================================== */
/* Test: InitializeJournal — client sends request, server accepts           */
/* ======================================================================== */
static void test_initialize_journal(void)
{
    TEST("initialize_journal");

    iec61850_mms_client_t *client = connect_client();
    ASSERT_TRUE(client != NULL);

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    (void)memset(&req, 0, sizeof(req));
    (void)memset(&resp, 0, sizeof(resp));

    req.invoke_id = 1;
    req.service = MMS_SERVICE_TYPE_INITIALIZE_JOURNAL;
    (void)strncpy(req.params.initializejournal.journal_name,
                  "journalLD$LLN0$EventLog",
                  MMS_MAX_VARIABLE_NAME - 1);

    int ret = transact(client, &req, &resp);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ((int)resp.service, (int)MMS_SERVICE_TYPE_INITIALIZE_JOURNAL);

    /* Journal should be empty after initialization */
    ASSERT_EQ((int)iec61850_journal_get_count(&g_journal), 0);

    iec61850_mms_client_disconnect(client);
    PASS();
}

/* ======================================================================== */
/* Test: Add entries server-side, read back via client with time range      */
/* ======================================================================== */
static void test_add_and_read_by_time(void)
{
    TEST("add_entries_and_read_by_time");

    /* Re-initialize journal and add entries server-side */
    iec61850_journal_init(&g_journal, "journalLD$LLN0$EventLog");

    mms_value_t v1, v2, v3;
    (void)memset(&v1, 0, sizeof(v1));
    (void)memset(&v2, 0, sizeof(v2));
    (void)memset(&v3, 0, sizeof(v3));

    v1.type = MMS_TYPE_INTEGER;
    v1.value.integer = 10;
    v2.type = MMS_TYPE_INTEGER;
    v2.value.integer = 20;
    v3.type = MMS_TYPE_INTEGER;
    v3.value.integer = 30;

    uint64_t id1 = iec61850_journal_add_entry(&g_journal, "LLN0$ST$Beh$stVal",
                                                &v1, 1000);
    uint64_t id2 = iec61850_journal_add_entry(&g_journal, "LLN0$ST$Beh$stVal",
                                                &v2, 2000);
    uint64_t id3 = iec61850_journal_add_entry(&g_journal, "LLN0$ST$Beh$stVal",
                                                &v3, 3000);
    ASSERT_TRUE(id1 > 0);
    ASSERT_TRUE(id2 > 0);
    ASSERT_TRUE(id3 > 0);
    ASSERT_EQ((int)iec61850_journal_get_count(&g_journal), 3);

    /* Client reads journal with time range covering all entries */
    iec61850_mms_client_t *client = connect_client();
    ASSERT_TRUE(client != NULL);

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    (void)memset(&req, 0, sizeof(req));
    (void)memset(&resp, 0, sizeof(resp));

    req.invoke_id = 2;
    req.service = MMS_SERVICE_TYPE_READ_JOURNAL;
    (void)strncpy(req.params.readjournal.journal_name,
                  "journalLD$LLN0$EventLog",
                  MMS_MAX_VARIABLE_NAME - 1);
    req.params.readjournal.start_time = 1000;
    req.params.readjournal.end_time = 3000;
    req.params.readjournal.max_entries = 50;

    int ret = transact(client, &req, &resp);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ((int)resp.service, (int)MMS_SERVICE_TYPE_READ_JOURNAL);
    ASSERT_EQ((int)resp.params.readjournal.num_entries, 3);

    /* Verify entries are in chronological order */
    ASSERT_EQ((int)resp.params.readjournal.entries[0].timestamp, 1000);
    ASSERT_EQ((int)resp.params.readjournal.entries[1].timestamp, 2000);
    ASSERT_EQ((int)resp.params.readjournal.entries[2].timestamp, 3000);

    iec61850_mms_client_disconnect(client);
    PASS();
}

/* ======================================================================== */
/* Test: Read from empty journal returns 0 entries                          */
/* ======================================================================== */
static void test_read_empty_journal(void)
{
    TEST("read_empty_journal");

    /* Re-initialize to clear all entries */
    iec61850_journal_init(&g_journal, "journalLD$LLN0$EventLog");
    ASSERT_EQ((int)iec61850_journal_get_count(&g_journal), 0);

    iec61850_mms_client_t *client = connect_client();
    ASSERT_TRUE(client != NULL);

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    (void)memset(&req, 0, sizeof(req));
    (void)memset(&resp, 0, sizeof(resp));

    req.invoke_id = 3;
    req.service = MMS_SERVICE_TYPE_READ_JOURNAL;
    (void)strncpy(req.params.readjournal.journal_name,
                  "journalLD$LLN0$EventLog",
                  MMS_MAX_VARIABLE_NAME - 1);
    req.params.readjournal.start_time = 0;
    req.params.readjournal.end_time = 0;
    req.params.readjournal.max_entries = 50;

    int ret = transact(client, &req, &resp);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ((int)resp.service, (int)MMS_SERVICE_TYPE_READ_JOURNAL);
    ASSERT_EQ((int)resp.params.readjournal.num_entries, 0);

    iec61850_mms_client_disconnect(client);
    PASS();
}

/* ======================================================================== */
/* Test: Circular buffer — fill past capacity, oldest entries overwritten   */
/* ======================================================================== */
static void test_journal_circular_buffer(void)
{
    TEST("journal_circular_buffer");

    /* Re-initialize and fill to capacity + some extra */
    iec61850_journal_init(&g_journal, "journalLD$LLN0$EventLog");

    mms_value_t val;
    (void)memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;

    uint32_t capacity = IEC61850_JOURNAL_MAX_ENTRIES;
    uint32_t total = capacity + 10;

    for (uint32_t i = 0; i < total; i++) {
        val.value.integer = (int32_t)i;
        uint64_t id = iec61850_journal_add_entry(
            &g_journal, "LLN0$ST$Beh$stVal", &val,
            (uint64_t)(1000 + i));
        ASSERT_TRUE(id > 0);
    }

    /* Count should be capped at capacity */
    ASSERT_EQ((int)iec61850_journal_get_count(&g_journal), (int)capacity);

    /* Read via client — should return newest entries, not the overwritten ones */
    iec61850_mms_client_t *client = connect_client();
    ASSERT_TRUE(client != NULL);

    mms_confirmed_request_t req;
    mms_confirmed_response_t resp;
    (void)memset(&req, 0, sizeof(req));
    (void)memset(&resp, 0, sizeof(resp));

    req.invoke_id = 4;
    req.service = MMS_SERVICE_TYPE_READ_JOURNAL;
    (void)strncpy(req.params.readjournal.journal_name,
                  "journalLD$LLN0$EventLog",
                  MMS_MAX_VARIABLE_NAME - 1);
    /* Query for the earliest entries that were overwritten */
    req.params.readjournal.start_time = 1000;
    req.params.readjournal.end_time = 1005;
    req.params.readjournal.max_entries = 50;

    int ret = transact(client, &req, &resp);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ((int)resp.service, (int)MMS_SERVICE_TYPE_READ_JOURNAL);
    /* Entries 0..9 were overwritten by entries 1024..1033, so time 1000..1005
     * should return 0 entries (those timestamps no longer exist) */
    ASSERT_EQ((int)resp.params.readjournal.num_entries, 0);

    /* Query for the newest entries that should still exist */
    (void)memset(&req, 0, sizeof(req));
    (void)memset(&resp, 0, sizeof(resp));

    req.invoke_id = 5;
    req.service = MMS_SERVICE_TYPE_READ_JOURNAL;
    (void)strncpy(req.params.readjournal.journal_name,
                  "journalLD$LLN0$EventLog",
                  MMS_MAX_VARIABLE_NAME - 1);
    req.params.readjournal.start_time = (uint64_t)(1000 + total - 5);
    req.params.readjournal.end_time = (uint64_t)(1000 + total - 1);
    req.params.readjournal.max_entries = 50;

    ret = transact(client, &req, &resp);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ((int)resp.service, (int)MMS_SERVICE_TYPE_READ_JOURNAL);
    ASSERT_TRUE(resp.params.readjournal.num_entries > 0);

    iec61850_mms_client_disconnect(client);
    PASS();
}

/* ======================================================================== */
/* Main                                                                      */
/* ======================================================================== */

int main(void)
{
    printf("\n=== MMS Journal Service E2E Tests ===\n");

    setup_server();

    printf("\n--- Journal Operations ---\n");
    test_initialize_journal();
    test_add_and_read_by_time();
    test_read_empty_journal();
    test_journal_circular_buffer();

    teardown_server();

    printf("\n  Results: %d/%d passed\n\n", test_passed, test_run);
    return (test_failed > 0) ? 1 : 0;
}
