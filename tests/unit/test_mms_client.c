/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for MMS Client
 *
 * Tests init, error paths, and argument validation.
 * Connect/transact paths require a live server — covered by test_mms_e2e.c.
 */

#include "mms/mms_client.h"
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

static void test_init(void)
{
    TEST("init");
    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);

    ASSERT_TRUE(!client.connected);
    ASSERT_EQ((int)client.max_pdu_size, 65000);
    ASSERT_EQ((int)client.invoke_id, 0);
    ASSERT_EQ(client.request_timeout_ms, 30000);
    PASS();
}

static void test_init_null(void)
{
    TEST("init_null");
    /* Should not crash */
    iec61850_mms_client_init(NULL);
    PASS();
}

static void test_is_connected_initial(void)
{
    TEST("is_connected_initial");
    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);

    ASSERT_TRUE(!iec61850_mms_client_is_connected(&client));
    PASS();
}

static void test_is_connected_null(void)
{
    TEST("is_connected_null");
    ASSERT_TRUE(!iec61850_mms_client_is_connected(NULL));
    PASS();
}

static void test_connect_null_args(void)
{
    TEST("connect_null_args");
    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);

    ASSERT_EQ(iec61850_mms_client_connect(NULL, "host", 102, 5000),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_client_connect(&client, NULL, 102, 5000),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    PASS();
}

static void test_connect_refused(void)
{
    TEST("connect_refused");
    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);

    /* Connect to a port that's (very likely) not listening */
    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", 59999, 500);
    ASSERT_TRUE(ret != IEC61850_MMS_CLIENT_OK);
    ASSERT_TRUE(!iec61850_mms_client_is_connected(&client));
    PASS();
}

static void test_disconnect(void)
{
    TEST("disconnect");
    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);

    /* Disconnect when not connected — should succeed gracefully */
    ASSERT_EQ(iec61850_mms_client_disconnect(&client), IEC61850_MMS_CLIENT_OK);
    ASSERT_TRUE(!iec61850_mms_client_is_connected(&client));
    PASS();
}

static void test_disconnect_null(void)
{
    TEST("disconnect_null");
    ASSERT_EQ(iec61850_mms_client_disconnect(NULL),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    PASS();
}

static void test_read_null_args(void)
{
    TEST("read_null_args");
    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    mms_value_t val;

    ASSERT_EQ(iec61850_mms_client_read(NULL, "dom", "item", &val),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_client_read(&client, "dom", NULL, &val),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_client_read(&client, "dom", "item", NULL),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    PASS();
}

static void test_read_not_connected(void)
{
    TEST("read_not_connected");
    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    mms_value_t val;

    /* Not connected — should fail with ERR_ARGS (connected check) */
    ASSERT_EQ(iec61850_mms_client_read(&client, "dom", "item", &val),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    PASS();
}

static void test_write_null_args(void)
{
    TEST("write_null_args");
    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    mms_value_t val;
    (void)memset(&val, 0, sizeof(val));

    ASSERT_EQ(iec61850_mms_client_write(NULL, "dom", "item", &val),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_client_write(&client, "dom", NULL, &val),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_client_write(&client, "dom", "item", NULL),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    PASS();
}

static void test_write_not_connected(void)
{
    TEST("write_not_connected");
    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    mms_value_t val;
    (void)memset(&val, 0, sizeof(val));

    ASSERT_EQ(iec61850_mms_client_write(&client, "dom", "item", &val),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    PASS();
}

/* WP-2x: the hoisted detail variants (mms_client.h) — argument
 * validation and the access_error initialization contract. */
static void test_read_detail_null_args(void)
{
    TEST("read_detail_null_args");
    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    mms_value_t val;
    int32_t access_error = 0;

    ASSERT_EQ(iec61850_mms_client_read_detail(NULL, "dom", "item", &val,
                                               &access_error),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(access_error, -1);
    access_error = 0;
    ASSERT_EQ(iec61850_mms_client_read_detail(&client, "dom", NULL, &val,
                                               &access_error),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(access_error, -1);
    access_error = 0;
    ASSERT_EQ(iec61850_mms_client_read_detail(&client, "dom", "item", NULL,
                                               &access_error),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(access_error, -1);
    /* NULL access_error is tolerated (plain-read semantics). */
    ASSERT_EQ(iec61850_mms_client_read_detail(&client, "dom", "item", &val,
                                               NULL),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    PASS();
}

static void test_write_detail_null_args(void)
{
    TEST("write_detail_null_args");
    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    mms_value_t val;
    int32_t access_error = 0;
    (void)memset(&val, 0, sizeof(val));

    ASSERT_EQ(iec61850_mms_client_write_detail(NULL, "dom", "item", &val,
                                                &access_error),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(access_error, -1);
    access_error = 0;
    ASSERT_EQ(iec61850_mms_client_write_detail(&client, "dom", NULL, &val,
                                                &access_error),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(access_error, -1);
    access_error = 0;
    ASSERT_EQ(iec61850_mms_client_write_detail(&client, "dom", "item", NULL,
                                                &access_error),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(access_error, -1);
    /* NULL access_error is tolerated (plain-write semantics). */
    ASSERT_EQ(iec61850_mms_client_write_detail(&client, "dom", "item", &val,
                                                NULL),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    PASS();
}

static void test_get_name_list_null_args(void)
{
    TEST("get_name_list_null_args");
    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    char names[4][MMS_MAX_VARIABLE_NAME];
    uint32_t count = 0;

    ASSERT_EQ(iec61850_mms_client_get_name_list(NULL,
                  MMS_OBJECT_CLASS_NAMED_VARIABLE, "dom", names, &count, 4),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_client_get_name_list(&client,
                  MMS_OBJECT_CLASS_NAMED_VARIABLE, "dom", NULL, &count, 4),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_client_get_name_list(&client,
                  MMS_OBJECT_CLASS_NAMED_VARIABLE, "dom", names, NULL, 4),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    PASS();
}

static void test_get_name_list_not_connected(void)
{
    TEST("get_name_list_not_connected");
    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    char names[4][MMS_MAX_VARIABLE_NAME];
    uint32_t count = 0;

    ASSERT_EQ(iec61850_mms_client_get_name_list(&client,
                  MMS_OBJECT_CLASS_NAMED_VARIABLE, "dom", names, &count, 4),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    PASS();
}

static void test_get_var_attrs_null_args(void)
{
    TEST("get_var_attrs_null_args");
    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    mms_variable_access_attrs_t attrs;

    ASSERT_EQ(iec61850_mms_client_get_var_attrs(NULL, "dom", "item", &attrs),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_client_get_var_attrs(&client, "dom", NULL, &attrs),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    ASSERT_EQ(iec61850_mms_client_get_var_attrs(&client, "dom", "item", NULL),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    PASS();
}

static void test_get_var_attrs_not_connected(void)
{
    TEST("get_var_attrs_not_connected");
    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    mms_variable_access_attrs_t attrs;

    ASSERT_EQ(iec61850_mms_client_get_var_attrs(&client, "dom", "item", &attrs),
              IEC61850_MMS_CLIENT_ERR_ARGS);
    PASS();
}

int main(void)
{
    printf("=== MMS Client Tests ===\n");

    test_init();
    test_init_null();
    test_is_connected_initial();
    test_is_connected_null();
    test_connect_null_args();
    test_connect_refused();
    test_disconnect();
    test_disconnect_null();
    test_read_null_args();
    test_read_not_connected();
    test_write_null_args();
    test_write_not_connected();
    test_read_detail_null_args();
    test_write_detail_null_args();
    test_get_name_list_null_args();
    test_get_name_list_not_connected();
    test_get_var_attrs_null_args();
    test_get_var_attrs_not_connected();

    printf("\nTests: %d run, %d passed, %d failed\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
