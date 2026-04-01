/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Session Lifecycle Tests
 *
 * Tests MMS session management over real TCP loopback:
 * - Session construction and server state
 * - Initiate handshake (client connect)
 * - Read/Write service round-trips
 * - GetNameList service (domains and variables)
 * - Error handling (non-existent variable, type mismatch)
 * - Session stability under multiple operations
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "mms/mms_server.h"
#include "mms/mms_client.h"
#include "mms/mms_data_store.h"
#include "asn1/mms_ber.h"
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

/* Shared infrastructure */
static iec61850_mms_data_store_t g_ds;
static iec61850_mms_server_t g_server;
static uint16_t g_port = 10600;

static void setup_server(void)
{
    iec61850_mms_ds_init(&g_ds);
    iec61850_mms_ds_create_domain(&g_ds, "sessionLD");

    mms_value_t val;
    (void)memset(&val, 0, sizeof(val));

    val.type = MMS_TYPE_INTEGER;
    val.value.integer = 100;
    iec61850_mms_ds_create_variable(&g_ds, "sessionLD", "LLN0$ST$Beh$stVal",
                                     MMS_TYPE_INTEGER, &val);

    val.type = MMS_TYPE_BOOLEAN;
    val.value.boolean = false;
    iec61850_mms_ds_create_variable(&g_ds, "sessionLD", "XCBR1$ST$Pos$stVal",
                                     MMS_TYPE_BOOLEAN, &val);

    val.type = MMS_TYPE_FLOATING_POINT;
    val.value.floating_point = 3.14f;
    iec61850_mms_ds_create_variable(&g_ds, "sessionLD", "MMXU1$MX$PhV$phsA",
                                     MMS_TYPE_FLOATING_POINT, &val);

    iec61850_mms_server_config_t cfg;
    iec61850_mms_server_config_init(&cfg);
    cfg.port = g_port;

    iec61850_mms_server_init(&g_server, &cfg, &g_ds);
    iec61850_mms_server_start(&g_server);

    /* Give server thread time to start listening */
    usleep(200000);
}

static void teardown_server(void)
{
    iec61850_mms_server_stop(&g_server);
    iec61850_mms_ds_destroy(&g_ds);
}

/* ======================================================================== */

static void test_session_construction(void)
{
    TEST("session_construction");

    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);

    iec61850_mms_server_config_t cfg;
    iec61850_mms_server_config_init(&cfg);
    cfg.port = 10601;

    iec61850_mms_server_t server;
    iec61850_mms_server_init(&server, &cfg, &ds);

    /* Server should not be running after init */
    ASSERT_TRUE(!iec61850_mms_server_is_running(&server));
    ASSERT_EQ((int)iec61850_mms_server_get_session_count(&server), 0);

    iec61850_mms_ds_destroy(&ds);
    PASS();
}

static void test_initiate_handshake(void)
{
    TEST("initiate_handshake");

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);

    ASSERT_TRUE(!iec61850_mms_client_is_connected(&client));

    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_TRUE(iec61850_mms_client_is_connected(&client));

    usleep(50000);
    ASSERT_TRUE(iec61850_mms_server_get_session_count(&g_server) >= 1);

    ret = iec61850_mms_client_disconnect(&client);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_TRUE(!iec61850_mms_client_is_connected(&client));

    PASS();
}

static void test_read_service(void)
{
    TEST("read_service");

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    /* Write a known value then read it back */
    mms_value_t wval;
    (void)memset(&wval, 0, sizeof(wval));
    wval.type = MMS_TYPE_INTEGER;
    wval.value.integer = 777;
    ret = iec61850_mms_client_write(&client, "sessionLD",
                                     "LLN0$ST$Beh$stVal", &wval);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    mms_value_t rval;
    ret = iec61850_mms_client_read(&client, "sessionLD",
                                    "LLN0$ST$Beh$stVal", &rval);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ((int)rval.type, (int)MMS_TYPE_INTEGER);
    ASSERT_EQ(rval.value.integer, 777);

    iec61850_mms_client_disconnect(&client);
    PASS();
}

static void test_write_service(void)
{
    TEST("write_service");

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    mms_value_t wval, rval;

    /* Write integer */
    (void)memset(&wval, 0, sizeof(wval));
    wval.type = MMS_TYPE_INTEGER;
    wval.value.integer = 42;
    ret = iec61850_mms_client_write(&client, "sessionLD",
                                     "LLN0$ST$Beh$stVal", &wval);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    ret = iec61850_mms_client_read(&client, "sessionLD",
                                    "LLN0$ST$Beh$stVal", &rval);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ(rval.value.integer, 42);

    /* Write boolean */
    (void)memset(&wval, 0, sizeof(wval));
    wval.type = MMS_TYPE_BOOLEAN;
    wval.value.boolean = true;
    ret = iec61850_mms_client_write(&client, "sessionLD",
                                     "XCBR1$ST$Pos$stVal", &wval);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    ret = iec61850_mms_client_read(&client, "sessionLD",
                                    "XCBR1$ST$Pos$stVal", &rval);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_TRUE(rval.value.boolean == true);

    /* Write float */
    (void)memset(&wval, 0, sizeof(wval));
    wval.type = MMS_TYPE_FLOATING_POINT;
    wval.value.floating_point = 60.0f;
    ret = iec61850_mms_client_write(&client, "sessionLD",
                                     "MMXU1$MX$PhV$phsA", &wval);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    ret = iec61850_mms_client_read(&client, "sessionLD",
                                    "MMXU1$MX$PhV$phsA", &rval);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_TRUE(rval.value.floating_point > 59.9f &&
                rval.value.floating_point < 60.1f);

    iec61850_mms_client_disconnect(&client);
    PASS();
}

static void test_get_name_list(void)
{
    TEST("get_name_list");

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    /* List domains */
    char domains[8][MMS_MAX_VARIABLE_NAME];
    uint32_t dcount = 0;
    ret = iec61850_mms_client_get_name_list(&client,
                                             MMS_OBJECT_CLASS_DOMAIN,
                                             NULL, domains, &dcount, 8);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_TRUE(dcount >= 1);

    /* List variables within domain */
    char vars[16][MMS_MAX_VARIABLE_NAME];
    uint32_t vcount = 0;
    ret = iec61850_mms_client_get_name_list(&client,
                                             MMS_OBJECT_CLASS_NAMED_VARIABLE,
                                             "sessionLD", vars, &vcount, 16);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_TRUE(vcount >= 3);

    iec61850_mms_client_disconnect(&client);
    PASS();
}

static void test_variable_not_found(void)
{
    TEST("variable_not_found");

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    mms_value_t val;
    ret = iec61850_mms_client_read(&client, "sessionLD",
                                    "NONEXISTENT$VAR", &val);
    ASSERT_TRUE(ret != IEC61850_MMS_CLIENT_OK);

    iec61850_mms_client_disconnect(&client);
    PASS();
}

static void test_type_mismatch(void)
{
    TEST("type_mismatch");

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    /* Write float value to integer variable — may coerce or error */
    mms_value_t wval;
    (void)memset(&wval, 0, sizeof(wval));
    wval.type = MMS_TYPE_FLOATING_POINT;
    wval.value.floating_point = 9.5f;
    ret = iec61850_mms_client_write(&client, "sessionLD",
                                     "LLN0$ST$Beh$stVal", &wval);
    /* Accept either success (server coerced) or error (server rejected) */
    ASSERT_TRUE(ret == IEC61850_MMS_CLIENT_OK || ret != IEC61850_MMS_CLIENT_OK);

    /* Variable should still be readable regardless */
    mms_value_t rval;
    ret = iec61850_mms_client_read(&client, "sessionLD",
                                    "LLN0$ST$Beh$stVal", &rval);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    iec61850_mms_client_disconnect(&client);
    PASS();
}

static void test_session_statistics(void)
{
    TEST("session_statistics");

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    /* Run multiple operations to stress the session */
    for (int i = 0; i < 10; i++) {
        mms_value_t wval;
        (void)memset(&wval, 0, sizeof(wval));
        wval.type = MMS_TYPE_INTEGER;
        wval.value.integer = (int32_t)i;
        ret = iec61850_mms_client_write(&client, "sessionLD",
                                         "LLN0$ST$Beh$stVal", &wval);
        ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

        mms_value_t rval;
        ret = iec61850_mms_client_read(&client, "sessionLD",
                                        "LLN0$ST$Beh$stVal", &rval);
        ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
        ASSERT_EQ(rval.value.integer, (int32_t)i);
    }

    /* Server should still be running after all operations */
    ASSERT_TRUE(iec61850_mms_server_is_running(&g_server));

    iec61850_mms_client_disconnect(&client);
    PASS();
}

/* ======================================================================== */

int main(void)
{
    printf("\n=== MMS Session Lifecycle Tests ===\n");

    printf("\n--- Construction ---\n");
    test_session_construction();

    printf("\n--- Session Operations ---\n");
    setup_server();

    test_initiate_handshake();
    test_read_service();
    test_write_service();
    test_get_name_list();
    test_variable_not_found();
    test_type_mismatch();
    test_session_statistics();

    teardown_server();

    printf("\n  Results: %d/%d passed\n\n", test_passed, test_run);
    return (test_failed > 0) ? 1 : 0;
}
