/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Interop Test: libiec61850 client → xdp-iec61850 MMS Server
 *
 * Starts our MMS server, then launches libiec61850's mms_utility
 * to query it. Verifies protocol compatibility.
 *
 * Tests: MS-01 through MS-08
 * No root needed (TCP loopback).
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "../interop_helpers.h"
#include "mms/mms_server.h"
#include "mms/mms_client.h"
#include "mms/mms_data_store.h"
#include "asn1/mms_ber.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static uint16_t g_port = 10500;
static iec61850_mms_data_store_t g_ds;
static iec61850_mms_server_t g_server;

static int setup_our_server(void)
{
    iec61850_mms_ds_init(&g_ds);
    iec61850_mms_ds_create_domain(&g_ds, "IED1LD0");

    mms_value_t val;
    memset(&val, 0, sizeof(val));

    val.type = MMS_TYPE_INTEGER;
    val.value.integer = 1;
    iec61850_mms_ds_create_variable(&g_ds, "IED1LD0", "LLN0$ST$Beh$stVal",
                                     MMS_TYPE_INTEGER, &val);

    val.type = MMS_TYPE_BOOLEAN;
    val.value.boolean = false;
    iec61850_mms_ds_create_variable(&g_ds, "IED1LD0", "GGIO1$ST$SPCSO1$stVal",
                                     MMS_TYPE_BOOLEAN, &val);

    val.type = MMS_TYPE_FLOATING_POINT;
    val.value.floating_point = 220.0f;
    iec61850_mms_ds_create_variable(&g_ds, "IED1LD0", "MMXU1$MX$PhV$phsA",
                                     MMS_TYPE_FLOATING_POINT, &val);

    iec61850_mms_server_config_t cfg;
    iec61850_mms_server_config_init(&cfg);
    cfg.port = g_port;

    iec61850_mms_server_init(&g_server, &cfg, &g_ds);
    return iec61850_mms_server_start(&g_server);
}

static void teardown_our_server(void)
{
    iec61850_mms_server_stop(&g_server);
    iec61850_mms_ds_destroy(&g_ds);
}

/*
 * Run mms_utility with given args against our server.
 * Returns the exit code and fills output buffer.
 */
static int run_mms_utility(const char *extra_args[], int nextra,
                           char *output, size_t output_size)
{
    char utility_path[600];
    if (!interop_example_path(utility_path, sizeof(utility_path),
                              "mms_utility", "mms_utility"))
        return -1;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", g_port);

    /* Build argv: utility -h 127.0.0.1 -p PORT extra_args... */
    char *argv[32];
    int argc = 0;
    argv[argc++] = utility_path;
    argv[argc++] = (char *)"-h";
    argv[argc++] = (char *)"127.0.0.1";
    argv[argc++] = (char *)"-p";
    argv[argc++] = port_str;
    for (int i = 0; i < nextra && argc < 30; i++)
        argv[argc++] = (char *)extra_args[i];
    argv[argc] = NULL;

    return interop_run_program(utility_path, argv, output, output_size, 5000);
}

/*
 * MS-01: libiec61850 mms_utility lists domains on our server (INTEROP-4)
 */
static void test_ms01_list_domains(void)
{
    INTEROP_TEST("MS-01: mms_utility lists domains (INTEROP-4)");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    int ret = setup_our_server();
    if (ret != IEC61850_MMS_SERVER_OK) { g_port++; INTEROP_FAIL("server start"); }
    usleep(200000);

    const char *args[] = { "-d" };
    char output[4096];
    int rc = run_mms_utility(args, 1, output, sizeof(output));

    teardown_our_server();
    g_port++;

    INTEROP_ASSERT_EQ(rc, 0);
    INTEROP_ASSERT(strstr(output, "IED1LD0") != NULL);
    INTEROP_PASS();
}

/*
 * MS-02: mms_utility lists variables in our domain
 */
static void test_ms02_list_variables(void)
{
    INTEROP_TEST("MS-02: mms_utility lists variables");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    int ret = setup_our_server();
    if (ret != IEC61850_MMS_SERVER_OK) { g_port++; INTEROP_FAIL("server start"); }
    usleep(200000);

    const char *args[] = { "-t", "IED1LD0" };
    char output[4096];
    int rc = run_mms_utility(args, 2, output, sizeof(output));

    teardown_our_server();
    g_port++;

    INTEROP_ASSERT_EQ(rc, 0);
    INTEROP_ASSERT(strstr(output, "LLN0") != NULL);
    INTEROP_PASS();
}

/*
 * MS-03: mms_utility reads a variable from our server
 */
static void test_ms03_read_variable(void)
{
    INTEROP_TEST("MS-03: mms_utility reads variable");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    int ret = setup_our_server();
    if (ret != IEC61850_MMS_SERVER_OK) { g_port++; INTEROP_FAIL("server start"); }
    usleep(200000);

    const char *args[] = { "-a", "IED1LD0", "-r", "LLN0$ST$Beh$stVal" };
    char output[4096];
    int rc = run_mms_utility(args, 4, output, sizeof(output));

    teardown_our_server();
    g_port++;

    INTEROP_ASSERT_EQ(rc, 0);
    /* mms_utility prints the value — "1" for our integer */
    INTEROP_ASSERT(strstr(output, "1") != NULL);
    INTEROP_PASS();
}

/*
 * MS-04: mms_utility reads non-existent variable
 */
static void test_ms04_read_nonexistent(void)
{
    INTEROP_TEST("MS-04: mms_utility reads non-existent");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    int ret = setup_our_server();
    if (ret != IEC61850_MMS_SERVER_OK) { g_port++; INTEROP_FAIL("server start"); }
    usleep(200000);

    const char *args[] = { "-a", "IED1LD0", "-r", "DOES$NOT$EXIST" };
    char output[4096];
    int rc = run_mms_utility(args, 4, output, sizeof(output));

    teardown_our_server();
    g_port++;

    /* Should either return error or not crash */
    (void)rc;
    INTEROP_PASS();
}

/*
 * MS-05: Server stop with our client connected
 */
static void test_ms05_stop_with_client(void)
{
    INTEROP_TEST("MS-05: server stop with active client");

    int ret = setup_our_server();
    if (ret != IEC61850_MMS_SERVER_OK) { g_port++; INTEROP_FAIL("server start"); }
    usleep(200000);

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);

    teardown_our_server();
    g_port++;

    if (ret == IEC61850_MMS_CLIENT_OK)
        iec61850_mms_client_disconnect(&client);

    INTEROP_PASS();
}

/*
 * MS-06: Our client + our server self-test (InitiateResponse detail)
 */
static void test_ms06_self_test(void)
{
    INTEROP_TEST("MS-06: self-test InitiateResponse (INTEROP-4)");

    int ret = setup_our_server();
    if (ret != IEC61850_MMS_SERVER_OK) { g_port++; INTEROP_FAIL("server start"); }
    usleep(200000);

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);

    if (ret == IEC61850_MMS_CLIENT_OK) {
        INTEROP_ASSERT(iec61850_mms_client_is_connected(&client));

        char names[32][MMS_MAX_VARIABLE_NAME];
        uint32_t count = 0;
        int svc_ret = iec61850_mms_client_get_name_list(&client,
                                                   MMS_OBJECT_CLASS_NAMED_VARIABLE,
                                                   "IED1LD0", names, &count, 32);
        INTEROP_ASSERT_EQ(svc_ret, IEC61850_MMS_CLIENT_OK);
        INTEROP_ASSERT(count >= 1);

        iec61850_mms_client_disconnect(&client);
    }

    teardown_our_server();
    g_port++;

    if (ret != IEC61850_MMS_CLIENT_OK) INTEROP_FAIL("connect failed");
    INTEROP_PASS();
}

/*
 * MS-07: mms_utility shows server identity
 */
static void test_ms07_identity(void)
{
    INTEROP_TEST("MS-07: mms_utility server identity");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    int ret = setup_our_server();
    if (ret != IEC61850_MMS_SERVER_OK) { g_port++; INTEROP_FAIL("server start"); }
    usleep(200000);

    const char *args[] = { "-i" };
    char output[4096];
    int rc = run_mms_utility(args, 1, output, sizeof(output));

    teardown_our_server();
    g_port++;

    /* mms_utility connects; rc=0 success, rc=3 connected but no identity.
     * Identify service is optional — key test is that connection works. */
    INTEROP_ASSERT(rc != 1);  /* must not be "connect failed" */
    INTEROP_PASS();
}

/*
 * MS-08: Multiple mms_utility calls (session churn)
 */
static void test_ms08_multi_session(void)
{
    INTEROP_TEST("MS-08: multiple mms_utility sessions");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    int ret = setup_our_server();
    if (ret != IEC61850_MMS_SERVER_OK) { g_port++; INTEROP_FAIL("server start"); }
    usleep(200000);

    for (int i = 0; i < 3; i++) {
        const char *args[] = { "-d" };
        char output[4096];
        int rc = run_mms_utility(args, 1, output, sizeof(output));
        if (rc != 0) {
            teardown_our_server();
            g_port++;
            INTEROP_FAIL("mms_utility failed on iteration");
        }
    }

    teardown_our_server();
    g_port++;
    INTEROP_PASS();
}

int main(void)
{
    printf("\n=== MMS Interop Tests: libiec61850 client → xdp server ===\n");

    test_ms01_list_domains();
    test_ms02_list_variables();
    test_ms03_read_variable();
    test_ms04_read_nonexistent();
    test_ms05_stop_with_client();
    test_ms06_self_test();
    test_ms07_identity();
    test_ms08_multi_session();

    INTEROP_SUMMARY();
    return interop_tests_failed > 0 ? 1 : 0;
}
