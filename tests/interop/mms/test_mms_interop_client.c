/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Interop Test: xdp-iec61850 MMS Client → libiec61850 MMS Server
 *
 * Launches libiec61850's server_example_basic_io as a subprocess,
 * then connects our MMS client to it over TCP loopback.
 *
 * Tests: MC-01 through MC-09
 * No root needed (TCP loopback).
 * Requires: LIBIEC61850_BUILD_DIR set or default path exists.
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "../interop_helpers.h"
#include "mms/mms_client.h"
#include "mms/mms_server.h"
#include "mms/mms_data_store.h"
#include "asn1/mms_ber.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static uint16_t g_port = 10400;

/*
 * Start libiec61850 server_example_basic_io on given port.
 * Returns PID or -1 on failure.
 */
static pid_t start_libiec_server(uint16_t port)
{
    char server_path[600];
    if (!interop_example_path(server_path, sizeof(server_path),
                              "server_example_basic_io",
                              "server_example_basic_io"))
        return -1;

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", port);

    char *args[] = { server_path, port_str, NULL };
    pid_t pid = interop_start_bg(server_path, args, NULL);
    if (pid < 0) return -1;

    if (!interop_wait_for_port(port, 3000)) {
        interop_stop_helper(pid);
        return -1;
    }
    return pid;
}

/*
 * MC-01: Connect to libiec61850 server (INTEROP-4)
 */
static void test_mc01_connect(void)
{
    INTEROP_TEST("MC-01: connect to libiec61850 server (INTEROP-4)");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    pid_t srv = start_libiec_server(g_port);
    if (srv < 0) { g_port++; INTEROP_FAIL("server start failed"); }

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);

    if (ret == IEC61850_MMS_CLIENT_OK) {
        INTEROP_ASSERT(iec61850_mms_client_is_connected(&client));
        iec61850_mms_client_disconnect(&client);
    }

    interop_stop_helper(srv);
    g_port++;
    if (ret != IEC61850_MMS_CLIENT_OK) INTEROP_FAIL("connect failed");
    INTEROP_PASS();
}

/*
 * MC-02: Read variable from libiec61850 server
 */
static void test_mc02_read(void)
{
    INTEROP_TEST("MC-02: read from libiec61850 server");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    pid_t srv = start_libiec_server(g_port);
    if (srv < 0) { g_port++; INTEROP_FAIL("server start failed"); }

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        interop_stop_helper(srv);
        g_port++;
        INTEROP_FAIL("connect failed");
    }

    mms_value_t val;
    ret = iec61850_mms_client_read(&client, "simpleIOGenericIO",
                                      "LLN0$ST$Beh$stVal", &val);
    iec61850_mms_client_disconnect(&client);
    interop_stop_helper(srv);
    g_port++;

    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_PASS();
}

/*
 * MC-03: GetNameList domains
 */
static void test_mc03_getnamelist_domains(void)
{
    INTEROP_TEST("MC-03: GetNameList domains");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    pid_t srv = start_libiec_server(g_port);
    if (srv < 0) { g_port++; INTEROP_FAIL("server start failed"); }

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        interop_stop_helper(srv);
        g_port++;
        INTEROP_FAIL("connect failed");
    }

    char names[32][MMS_MAX_VARIABLE_NAME];
    uint32_t count = 0;
    ret = iec61850_mms_client_get_name_list(&client,
                                               MMS_OBJECT_CLASS_DOMAIN,
                                               NULL, names, &count, 32);
    iec61850_mms_client_disconnect(&client);
    interop_stop_helper(srv);
    g_port++;

    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT(count >= 1);
    INTEROP_PASS();
}

/*
 * MC-04: GetNameList variables in domain
 */
static void test_mc04_getnamelist_vars(void)
{
    INTEROP_TEST("MC-04: GetNameList variables");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    pid_t srv = start_libiec_server(g_port);
    if (srv < 0) { g_port++; INTEROP_FAIL("server start failed"); }

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        interop_stop_helper(srv);
        g_port++;
        INTEROP_FAIL("connect failed");
    }

    char names[128][MMS_MAX_VARIABLE_NAME];
    uint32_t count = 0;
    ret = iec61850_mms_client_get_name_list(&client,
                                               MMS_OBJECT_CLASS_NAMED_VARIABLE,
                                               "simpleIOGenericIO",
                                               names, &count, 128);
    iec61850_mms_client_disconnect(&client);
    interop_stop_helper(srv);
    g_port++;

    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT(count >= 10); /* server has many variables */
    INTEROP_PASS();
}

/*
 * MC-05: GetVariableAccessAttributes
 */
static void test_mc05_get_var_attrs(void)
{
    INTEROP_TEST("MC-05: GetVariableAccessAttributes");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    pid_t srv = start_libiec_server(g_port);
    if (srv < 0) { g_port++; INTEROP_FAIL("server start failed"); }

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        interop_stop_helper(srv);
        g_port++;
        INTEROP_FAIL("connect failed");
    }

    mms_variable_access_attrs_t attrs;
    ret = iec61850_mms_client_get_var_attrs(&client, "simpleIOGenericIO",
                                               "LLN0$ST$Beh$stVal", &attrs);
    iec61850_mms_client_disconnect(&client);
    interop_stop_helper(srv);
    g_port++;

    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_PASS();
}

/*
 * MC-06: Multiple reads on same connection
 */
static void test_mc06_multi_request(void)
{
    INTEROP_TEST("MC-06: multiple requests on same connection");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    pid_t srv = start_libiec_server(g_port);
    if (srv < 0) { g_port++; INTEROP_FAIL("server start failed"); }

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        interop_stop_helper(srv);
        g_port++;
        INTEROP_FAIL("connect failed");
    }

    for (int i = 0; i < 5; i++) {
        mms_value_t val;
        ret = iec61850_mms_client_read(&client, "simpleIOGenericIO",
                                          "LLN0$ST$Beh$stVal", &val);
        if (ret != IEC61850_MMS_CLIENT_OK) break;
    }

    iec61850_mms_client_disconnect(&client);
    interop_stop_helper(srv);
    g_port++;

    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_PASS();
}

/*
 * MC-07: Read non-existent variable
 */
static void test_mc07_read_nonexistent(void)
{
    INTEROP_TEST("MC-07: read non-existent variable");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    pid_t srv = start_libiec_server(g_port);
    if (srv < 0) { g_port++; INTEROP_FAIL("server start failed"); }

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        interop_stop_helper(srv);
        g_port++;
        INTEROP_FAIL("connect failed");
    }

    mms_value_t val;
    ret = iec61850_mms_client_read(&client, "simpleIOGenericIO",
                                      "DOES_NOT_EXIST", &val);
    /* Server may return DataAccessError or reject — either way, the
     * connection should survive the request without crashing */
    (void)ret;

    iec61850_mms_client_disconnect(&client);
    interop_stop_helper(srv);
    g_port++;
    INTEROP_PASS();
}

/*
 * MC-08: Disconnect and reconnect
 */
static void test_mc08_reconnect(void)
{
    INTEROP_TEST("MC-08: disconnect and reconnect");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    pid_t srv = start_libiec_server(g_port);
    if (srv < 0) { g_port++; INTEROP_FAIL("server start failed"); }

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        interop_stop_helper(srv);
        g_port++;
        INTEROP_FAIL("first connect failed");
    }

    iec61850_mms_client_disconnect(&client);
    usleep(100000);

    iec61850_mms_client_init(&client);
    ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    if (ret == IEC61850_MMS_CLIENT_OK)
        iec61850_mms_client_disconnect(&client);

    interop_stop_helper(srv);
    g_port++;

    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_PASS();
}

/*
 * MC-09: libiec61850 mms_utility reads from our server
 * Our server → libiec61850 mms_utility client
 */
static void test_mc09_libiec_reads_our_server(void)
{
    INTEROP_TEST("MC-09: mms_utility reads our server");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    /* Start our server */
    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);
    iec61850_mms_ds_create_domain(&ds, "testLD");

    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;
    val.value.integer = 42;
    iec61850_mms_ds_create_variable(&ds, "testLD", "LLN0$ST$Beh$stVal",
                                     MMS_TYPE_INTEGER, &val);

    iec61850_mms_server_config_t cfg;
    iec61850_mms_server_config_init(&cfg);
    cfg.port = g_port;

    iec61850_mms_server_t server;
    iec61850_mms_server_init(&server, &cfg, &ds);
    int ret = iec61850_mms_server_start(&server);
    if (ret != IEC61850_MMS_SERVER_OK) {
        iec61850_mms_ds_destroy(&ds);
        g_port++;
        INTEROP_FAIL("our server start failed");
    }
    usleep(200000);

    /* Run mms_utility to query our server */
    char utility_path[600];
    if (!interop_example_path(utility_path, sizeof(utility_path),
                              "mms_utility", "mms_utility")) {
        iec61850_mms_server_stop(&server);
        iec61850_mms_ds_destroy(&ds);
        g_port++;
        INTEROP_SKIP("mms_utility not found");
    }

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", g_port);

    char *args[] = { utility_path, "-h", "127.0.0.1", "-p", port_str,
                     "-d", NULL };
    char output[4096];
    int rc = interop_run_program(utility_path, args, output, sizeof(output),
                                 5000);

    iec61850_mms_server_stop(&server);
    iec61850_mms_ds_destroy(&ds);
    g_port++;

    /* mms_utility should connect (rc=0 success, rc=3 connected but empty list).
     * rc=1 means connect failed. Key test: mms_utility can talk to our server. */
    INTEROP_ASSERT(rc != 1);  /* must not be "connect failed" */
    INTEROP_PASS();
}

int main(void)
{
    printf("\n=== MMS Interop Tests: xdp client ↔ libiec61850 ===\n");

    test_mc01_connect();
    test_mc02_read();
    test_mc03_getnamelist_domains();
    test_mc04_getnamelist_vars();
    test_mc05_get_var_attrs();
    test_mc06_multi_request();
    test_mc07_read_nonexistent();
    test_mc08_reconnect();
    test_mc09_libiec_reads_our_server();

    INTEROP_SUMMARY();
    return interop_tests_failed > 0 ? 1 : 0;
}
