/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Client-Server End-to-End Test
 *
 * Tests full MMS stack over loopback TCP:
 * - Server start/stop lifecycle
 * - Client connect/disconnect via ISO stack
 * - Read/Write/GetNameList/GetVarAttrs service dispatch
 * - Conclude (clean session teardown)
 * - Error responses for non-existent variables
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "mms/mms_server.h"
#include "mms/mms_client.h"
#include "mms/mms_data_store.h"
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
static uint16_t g_port = 10300;

static void setup_server(void)
{
    iec61850_mms_ds_init(&g_ds);
    iec61850_mms_ds_create_domain(&g_ds, "testLD");

    /* Create some test variables */
    mms_value_t val;
    (void)memset(&val, 0, sizeof(val));

    val.type = MMS_TYPE_INTEGER;
    val.value.integer = 42;
    iec61850_mms_ds_create_variable(&g_ds, "testLD", "LLN0$ST$Beh$stVal",
                                     MMS_TYPE_INTEGER, &val);

    val.type = MMS_TYPE_BOOLEAN;
    val.value.boolean = true;
    iec61850_mms_ds_create_variable(&g_ds, "testLD", "XCBR1$ST$Pos$stVal",
                                     MMS_TYPE_BOOLEAN, &val);

    val.type = MMS_TYPE_FLOATING_POINT;
    val.value.floating_point = 220.5f;
    iec61850_mms_ds_create_variable(&g_ds, "testLD", "MMXU1$MX$PhV$phsA",
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

static void test_server_start_stop(void)
{
    TEST("server_start_stop");

    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);

    iec61850_mms_server_config_t cfg;
    iec61850_mms_server_config_init(&cfg);
    cfg.port = 10299;

    iec61850_mms_server_t server;
    iec61850_mms_server_init(&server, &cfg, &ds);

    int ret = iec61850_mms_server_start(&server);
    ASSERT_EQ(ret, IEC61850_MMS_SERVER_OK);
    ASSERT_TRUE(iec61850_mms_server_is_running(&server));

    ret = iec61850_mms_server_start(&server);
    ASSERT_EQ(ret, IEC61850_MMS_SERVER_ERR_RUNNING);

    ret = iec61850_mms_server_stop(&server);
    ASSERT_EQ(ret, IEC61850_MMS_SERVER_OK);
    ASSERT_TRUE(!iec61850_mms_server_is_running(&server));

    iec61850_mms_ds_destroy(&ds);
    PASS();
}

static void test_client_connect_disconnect(void)
{
    TEST("client_connect_disconnect");

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);

    ASSERT_TRUE(!iec61850_mms_client_is_connected(&client));

    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_TRUE(iec61850_mms_client_is_connected(&client));

    /* Server should see 1 session */
    usleep(50000);
    ASSERT_TRUE(iec61850_mms_server_get_session_count(&g_server) >= 1);

    ret = iec61850_mms_client_disconnect(&client);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_TRUE(!iec61850_mms_client_is_connected(&client));

    PASS();
}

static void test_read_integer(void)
{
    TEST("read_integer");

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    mms_value_t val;
    ret = iec61850_mms_client_read(&client, "testLD", "LLN0$ST$Beh$stVal", &val);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ((int)val.type, (int)MMS_TYPE_INTEGER);
    ASSERT_EQ(val.value.integer, 42);

    iec61850_mms_client_disconnect(&client);
    PASS();
}

static void test_read_boolean(void)
{
    TEST("read_boolean");

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);

    mms_value_t val;
    int ret = iec61850_mms_client_read(&client, "testLD", "XCBR1$ST$Pos$stVal", &val);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ((int)val.type, (int)MMS_TYPE_BOOLEAN);
    ASSERT_TRUE(val.value.boolean == true);

    iec61850_mms_client_disconnect(&client);
    PASS();
}

static void test_write_then_read(void)
{
    TEST("write_then_read");

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);

    /* Write new value */
    mms_value_t write_val;
    (void)memset(&write_val, 0, sizeof(write_val));
    write_val.type = MMS_TYPE_INTEGER;
    write_val.value.integer = 99;
    int ret = iec61850_mms_client_write(&client, "testLD",
                                          "LLN0$ST$Beh$stVal", &write_val);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    /* Read it back */
    mms_value_t read_val;
    ret = iec61850_mms_client_read(&client, "testLD",
                                     "LLN0$ST$Beh$stVal", &read_val);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ(read_val.value.integer, 99);

    iec61850_mms_client_disconnect(&client);
    PASS();
}

static void test_get_name_list(void)
{
    TEST("get_name_list");

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);

    char names[16][MMS_MAX_VARIABLE_NAME];
    uint32_t count = 0;
    int ret = iec61850_mms_client_get_name_list(&client,
                                                   MMS_OBJECT_CLASS_NAMED_VARIABLE,
                                                   "testLD", names, &count, 16);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_TRUE(count >= 3);  /* We created 3 variables */

    iec61850_mms_client_disconnect(&client);
    PASS();
}

static void test_get_var_attrs(void)
{
    TEST("get_var_attrs");

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);

    mms_variable_access_attrs_t attrs;
    int ret = iec61850_mms_client_get_var_attrs(&client, "testLD",
                                                   "LLN0$ST$Beh$stVal", &attrs);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ((int)attrs.type, (int)MMS_TYPE_INTEGER);

    iec61850_mms_client_disconnect(&client);
    PASS();
}

static void test_multiple_requests(void)
{
    TEST("multiple_requests");

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);

    /* Send 5 reads in sequence on the same connection */
    for (int i = 0; i < 5; i++) {
        mms_value_t val;
        int ret = iec61850_mms_client_read(&client, "testLD",
                                             "LLN0$ST$Beh$stVal", &val);
        ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    }

    iec61850_mms_client_disconnect(&client);
    PASS();
}
static void test_read_nonexistent(void)
{
    TEST("read_nonexistent");

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);

    mms_value_t val;
    int ret = iec61850_mms_client_read(&client, "testLD", "DOES_NOT_EXIST", &val);
    /* Should get an error (either MMS error or transport error) */
    ASSERT_TRUE(ret != IEC61850_MMS_CLIENT_OK);

    iec61850_mms_client_disconnect(&client);
    PASS();
}

static void test_client_null_args(void)
{
    TEST("client_null_args");

    ASSERT_EQ(iec61850_mms_client_connect(NULL, "localhost", 102, 1000),
              IEC61850_MMS_CLIENT_ERR_ARGS);

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);

    ASSERT_EQ(iec61850_mms_client_connect(&client, NULL, 102, 1000),
              IEC61850_MMS_CLIENT_ERR_ARGS);

    mms_value_t val;
    ASSERT_EQ(iec61850_mms_client_read(NULL, "d", "v", &val),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_client_read(&client, "d", "v", NULL),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    /* Not connected */
    ASSERT_EQ(iec61850_mms_client_read(&client, "d", "v", &val),
              IEC61850_MMS_CLIENT_ERR_ARGS);

    ASSERT_TRUE(!iec61850_mms_client_is_connected(NULL));

    PASS();
}

int main(void)
{
    printf("\n=== MMS Client-Server E2E Tests ===\n");

    printf("\n--- Lifecycle ---\n");
    test_server_start_stop();
    test_client_null_args();

    printf("\n--- Client-Server Communication ---\n");
    setup_server();

    test_client_connect_disconnect();
    test_read_integer();
    test_read_boolean();
    test_write_then_read();
    test_get_name_list();
    test_get_var_attrs();
    test_read_nonexistent();
    test_multiple_requests();

    teardown_server();

    printf("\n  Results: %d/%d passed\n\n", test_passed, test_run);
    return (test_failed > 0) ? 1 : 0;
}
