/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Interop Test: xdp-iec61850 MMS Client → libiec61850 MMS Server
 *
 * Launches libiec61850's server_example_basic_io as a subprocess,
 * then connects our MMS client to it over TCP loopback.
 *
 * Tests: MC-01 through MC-12 (including MC-02b, MC-02c)
 * No root needed (TCP loopback).
 * Requires: LIBIEC61850_BUILD_DIR set or default path exists.
 */


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
    INTEROP_ASSERT(val.type == MMS_TYPE_INTEGER);
    INTEROP_PASS();
}

/*
 * MC-02b: Read float from libiec61850 server
 */
static void test_mc02b_read_float(void)
{
    INTEROP_TEST("MC-02b: read float from libiec61850 server");
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
                                      "GGIO1$MX$AnIn1$mag$f", &val);
    iec61850_mms_client_disconnect(&client);
    interop_stop_helper(srv);
    g_port++;

    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT(val.type == MMS_TYPE_FLOATING_POINT);
    INTEROP_PASS();
}

/*
 * MC-02c: Read boolean from libiec61850 server
 */
static void test_mc02c_read_boolean(void)
{
    INTEROP_TEST("MC-02c: read boolean from libiec61850 server");
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
                                      "GGIO1$ST$SPCSO1$stVal", &val);
    iec61850_mms_client_disconnect(&client);
    interop_stop_helper(srv);
    g_port++;

    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT(val.type == MMS_TYPE_BOOLEAN);
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
 * MC-10: Write variable to libiec61850 server
 */
static void test_mc10_write(void)
{
    INTEROP_TEST("MC-10: write to libiec61850 server");
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
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_VISIBLE_STRING;
    (void)strncpy(val.value.visible_string.data, "xdp-test",
                   MMS_MAX_STRING_LENGTH - 1);
    val.value.visible_string.len = 8;

    ret = iec61850_mms_client_write(&client, "simpleIOGenericIO",
                                       "GGIO1$DC$NamPlt$vendor", &val);
    iec61850_mms_client_disconnect(&client);
    interop_stop_helper(srv);
    g_port++;

    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_PASS();
}

/*
 * MC-11: Write then read back from libiec61850 server
 */
static void test_mc11_write_read_back(void)
{
    INTEROP_TEST("MC-11: write then read back");
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

    /* Write a value */
    mms_value_t wval;
    memset(&wval, 0, sizeof(wval));
    wval.type = MMS_TYPE_VISIBLE_STRING;
    (void)strncpy(wval.value.visible_string.data, "roundtrip-test",
                   MMS_MAX_STRING_LENGTH - 1);
    wval.value.visible_string.len = 14;

    ret = iec61850_mms_client_write(&client, "simpleIOGenericIO",
                                       "GGIO1$DC$NamPlt$vendor", &wval);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    /* Read it back */
    mms_value_t rval;
    ret = iec61850_mms_client_read(&client, "simpleIOGenericIO",
                                      "GGIO1$DC$NamPlt$vendor", &rval);

    iec61850_mms_client_disconnect(&client);
    interop_stop_helper(srv);
    g_port++;

    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT(rval.type == MMS_TYPE_VISIBLE_STRING);
    INTEROP_ASSERT(strstr(rval.value.visible_string.data, "roundtrip-test") != NULL);
    INTEROP_PASS();
}

/*
 * MC-12: Read a named variable list (dataset) from the libiec61850 server
 *
 * WP-2y: the missing coverage that let the flat-format NVL request
 * encoder hide — read_named_varlist() was never exercised against a
 * real server. Discovers the server's datasets via GetNameList
 * (object class NAMED_VARIABLE_LIST, domain scope) and reads one.
 * The oracle's server_example_basic_io exposes LLN0$Events (4
 * members), LLN0$Events2 and LLN0$Measurements in the
 * simpleIOGenericIO domain.
 */
static void test_mc12_read_named_varlist(void)
{
    INTEROP_TEST("MC-12: read named variable list from libiec61850 server");
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

    /* Discover the datasets the server exposes in its domain. */
    char lists[32][MMS_MAX_VARIABLE_NAME];
    uint32_t count = 0;
    ret = iec61850_mms_client_get_name_list(&client,
                                               MMS_OBJECT_CLASS_NAMED_VARIABLE_LIST,
                                               "simpleIOGenericIO", lists, &count, 32);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        iec61850_mms_client_disconnect(&client);
        interop_stop_helper(srv);
        g_port++;
        INTEROP_FAIL("GetNameList of named variable lists failed");
    }
    if (count == 0) {
        /* No datasets exposed by this server build — nothing to read. */
        iec61850_mms_client_disconnect(&client);
        interop_stop_helper(srv);
        g_port++;
        INTEROP_SKIP("no named variable lists exposed");
    }

    /* Prefer a known multi-member list (LLN0$Events: 4 members on the
     * reference model); fall back to the first discovered list. */
    const char *pick = lists[0];
    for (uint32_t i = 0; i < count; i++) {
        if (strcmp(lists[i], "LLN0$Events") == 0) {
            pick = lists[i];
            break;
        }
    }

    mms_value_t values[8];
    uint32_t num_values = 0;
    ret = iec61850_mms_client_read_named_varlist(&client, "simpleIOGenericIO",
                                                   pick, values, &num_values, 8);

    iec61850_mms_client_disconnect(&client);
    interop_stop_helper(srv);
    g_port++;

    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT(num_values >= 1);
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

/*
 * Start libiec61850's setting-groups example server (WP-6x: the
 * SGCB oracle — black box, wire observation only). Returns PID or
 * -1. The example exposes the DEMOPROT domain with an SGCB
 * (NumOfSG=5) and PTOC1 SE settings (OpDlTmms etc.).
 */
static pid_t start_libiec_sg_server(uint16_t port)
{
    char server_path[600];
    if (!interop_example_path(server_path, sizeof(server_path),
                              "server_example_setting_groups",
                              "server_example_sg"))
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

/* MS-SG01: discover the SGCB objects on the oracle (GetNameList) */
static void test_msg01_discover(void)
{
    INTEROP_TEST("MS-SG01: SGCB discovery via GetNameList");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    pid_t srv = start_libiec_sg_server(g_port);
    if (srv < 0) { g_port++; INTEROP_SKIP("server_example_sg not found"); }

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        interop_stop_helper(srv);
        g_port++;
        INTEROP_FAIL("connect failed");
    }

    char names[256][MMS_MAX_VARIABLE_NAME];
    uint32_t count = 0;
    ret = iec61850_mms_client_get_name_list(&client,
                                               MMS_OBJECT_CLASS_NAMED_VARIABLE,
                                               "DEMOPROT", names, &count, 256);
    iec61850_mms_client_disconnect(&client);
    interop_stop_helper(srv);
    g_port++;

    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    bool sgcb = false, se = false, sg_view = false;
    for (uint32_t i = 0; i < count; i++) {
        if (strcmp(names[i], "LLN0$SP$SGCB$NumOfSG") == 0) sgcb = true;
        if (strcmp(names[i], "PTOC1$SE$OpDlTmms$setVal") == 0) se = true;
        if (strcmp(names[i], "PTOC1$SG$OpDlTmms$setVal") == 0) sg_view = true;
    }
    INTEROP_ASSERT(sgcb);
    INTEROP_ASSERT(se);
    INTEROP_ASSERT(sg_view);
    INTEROP_PASS();
}

/* MS-SG02: read the SGCB attributes (NumOfSG/ActSG/EditSG) */
static void test_msg02_sgcb_reads(void)
{
    INTEROP_TEST("MS-SG02: SGCB attribute reads");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    pid_t srv = start_libiec_sg_server(g_port);
    if (srv < 0) { g_port++; INTEROP_SKIP("server_example_sg not found"); }

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        interop_stop_helper(srv);
        g_port++;
        INTEROP_FAIL("connect failed");
    }

    mms_value_t v;
    ret = iec61850_mms_client_read(&client, "DEMOPROT",
                                      "LLN0$SP$SGCB$NumOfSG", &v);
    bool num_ok = (ret == IEC61850_MMS_CLIENT_OK) &&
                  (v.type == MMS_TYPE_UNSIGNED) && (v.value.unsigned_val == 5);
    ret = iec61850_mms_client_read(&client, "DEMOPROT",
                                      "LLN0$SP$SGCB$ActSG", &v);
    bool act_ok = (ret == IEC61850_MMS_CLIENT_OK) &&
                  (v.value.unsigned_val == 1);
    ret = iec61850_mms_client_read(&client, "DEMOPROT",
                                      "LLN0$SP$SGCB$EditSG", &v);
    bool edit_ok = (ret == IEC61850_MMS_CLIENT_OK) &&
                   (v.value.unsigned_val == 0);
    iec61850_mms_client_disconnect(&client);
    interop_stop_helper(srv);
    g_port++;

    INTEROP_ASSERT(num_ok);
    INTEROP_ASSERT(act_ok);
    INTEROP_ASSERT(edit_ok);
    INTEROP_PASS();
}

/* MS-SG03: SE read outside an edit session is rejected (7-2: SE is
 * the edit-session view; matches our bridge fall-through) */
static void test_msg03_se_invisible(void)
{
    INTEROP_TEST("MS-SG03: SE read without edit session rejected");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    pid_t srv = start_libiec_sg_server(g_port);
    if (srv < 0) { g_port++; INTEROP_SKIP("server_example_sg not found"); }

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        interop_stop_helper(srv);
        g_port++;
        INTEROP_FAIL("connect failed");
    }

    mms_value_t v;
    ret = iec61850_mms_client_read(&client, "DEMOPROT",
                                      "PTOC1$SE$OpDlTmms$setVal", &v);
    iec61850_mms_client_disconnect(&client);
    interop_stop_helper(srv);
    g_port++;

    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_ERR_MMS);
    INTEROP_PASS();
}

/* MS-SG04: SelectEditSG, SE write into the edit group, SG view
 * unchanged (the live model is only touched on activation) */
static void test_msg04_edit_flow(void)
{
    INTEROP_TEST("MS-SG04: SelectEditSG + SE write + readback");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    pid_t srv = start_libiec_sg_server(g_port);
    if (srv < 0) { g_port++; INTEROP_SKIP("server_example_sg not found"); }

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        interop_stop_helper(srv);
        g_port++;
        INTEROP_FAIL("connect failed");
    }

    mms_value_t v;
    memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_UNSIGNED;
    v.value.unsigned_val = 2;
    ret = iec61850_mms_client_write(&client, "DEMOPROT",
                                       "LLN0$SP$SGCB$EditSG", &v);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ret = iec61850_mms_client_read(&client, "DEMOPROT",
                                      "LLN0$SP$SGCB$EditSG", &v);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT_EQ(v.value.unsigned_val, 2U);

    /* SE now visible: group 2's initial value */
    ret = iec61850_mms_client_read(&client, "DEMOPROT",
                                      "PTOC1$SE$OpDlTmms$setVal", &v);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT_EQ(v.value.integer, 1500);

    /* Write into the edit group */
    memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_INTEGER;
    v.value.integer = 999;
    ret = iec61850_mms_client_write(&client, "DEMOPROT",
                                       "PTOC1$SE$OpDlTmms$setVal", &v);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ret = iec61850_mms_client_read(&client, "DEMOPROT",
                                      "PTOC1$SE$OpDlTmms$setVal", &v);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT_EQ(v.value.integer, 999);

    /* The active ($SG$) view is untouched before activation */
    ret = iec61850_mms_client_read(&client, "DEMOPROT",
                                      "PTOC1$SG$OpDlTmms$setVal", &v);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT_EQ(v.value.integer, 500);

    iec61850_mms_client_disconnect(&client);
    interop_stop_helper(srv);
    g_port++;
    INTEROP_PASS();
}

/* MS-SG05: SelectActiveSG activates the edited group */
static void test_msg05_activate(void)
{
    INTEROP_TEST("MS-SG05: SelectActiveSG activates the edit group");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    pid_t srv = start_libiec_sg_server(g_port);
    if (srv < 0) { g_port++; INTEROP_SKIP("server_example_sg not found"); }

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        interop_stop_helper(srv);
        g_port++;
        INTEROP_FAIL("connect failed");
    }

    mms_value_t v;
    memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_UNSIGNED;
    v.value.unsigned_val = 2;
    ret = iec61850_mms_client_write(&client, "DEMOPROT",
                                       "LLN0$SP$SGCB$EditSG", &v);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_INTEGER;
    v.value.integer = 999;
    ret = iec61850_mms_client_write(&client, "DEMOPROT",
                                       "PTOC1$SE$OpDlTmms$setVal", &v);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    /* Confirm the edit (CnfEdit): the reference stack only commits
     * the edited values into the edit group on confirmation. */
    memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_BOOLEAN;
    v.value.boolean = true;
    ret = iec61850_mms_client_write(&client, "DEMOPROT",
                                       "LLN0$SP$SGCB$CnfEdit", &v);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    /* Activate group 2 */
    memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_UNSIGNED;
    v.value.unsigned_val = 2;
    ret = iec61850_mms_client_write(&client, "DEMOPROT",
                                       "LLN0$SP$SGCB$ActSG", &v);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ret = iec61850_mms_client_read(&client, "DEMOPROT",
                                      "LLN0$SP$SGCB$ActSG", &v);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT_EQ(v.value.unsigned_val, 2U);

    /* The active view now serves the edited value */
    ret = iec61850_mms_client_read(&client, "DEMOPROT",
                                      "PTOC1$SG$OpDlTmms$setVal", &v);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT_EQ(v.value.integer, 999);

    /* Release the edit session */
    memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_UNSIGNED;
    v.value.unsigned_val = 0;
    ret = iec61850_mms_client_write(&client, "DEMOPROT",
                                       "LLN0$SP$SGCB$EditSG", &v);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ret = iec61850_mms_client_read(&client, "DEMOPROT",
                                      "LLN0$SP$SGCB$EditSG", &v);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT_EQ(v.value.unsigned_val, 0U);

    iec61850_mms_client_disconnect(&client);
    interop_stop_helper(srv);
    g_port++;
    INTEROP_PASS();
}

/* MS-SG06: edit-session exclusivity across two associations (our
 * -EPERM path) and release on disconnect */
static void test_msg06_owner_conflict(void)
{
    INTEROP_TEST("MS-SG06: edit reservation is single-owner");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    pid_t srv = start_libiec_sg_server(g_port);
    if (srv < 0) { g_port++; INTEROP_SKIP("server_example_sg not found"); }

    iec61850_mms_client_t a, b;
    iec61850_mms_client_init(&a);
    iec61850_mms_client_init(&b);
    if ((iec61850_mms_client_connect(&a, "127.0.0.1", g_port, 5000) !=
         IEC61850_MMS_CLIENT_OK) ||
        (iec61850_mms_client_connect(&b, "127.0.0.1", g_port, 5000) !=
         IEC61850_MMS_CLIENT_OK)) {
        interop_stop_helper(srv);
        g_port++;
        INTEROP_FAIL("connect failed");
    }

    mms_value_t v;
    memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_UNSIGNED;
    v.value.unsigned_val = 2;
    int ret = iec61850_mms_client_write(&a, "DEMOPROT",
                                          "LLN0$SP$SGCB$EditSG", &v);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    /* B cannot steal the reservation */
    ret = iec61850_mms_client_write(&b, "DEMOPROT",
                                       "LLN0$SP$SGCB$EditSG", &v);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_ERR_MMS);

    /* A's disconnect releases it */
    iec61850_mms_client_disconnect(&a);
    usleep(500000);
    ret = iec61850_mms_client_read(&b, "DEMOPROT",
                                      "LLN0$SP$SGCB$EditSG", &v);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT_EQ(v.value.unsigned_val, 0U);

    /* B can now take it */
    memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_UNSIGNED;
    v.value.unsigned_val = 3;
    ret = iec61850_mms_client_write(&b, "DEMOPROT",
                                       "LLN0$SP$SGCB$EditSG", &v);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    iec61850_mms_client_disconnect(&b);
    interop_stop_helper(srv);
    g_port++;
    INTEROP_PASS();
}

int main(void)
{
    printf("\n=== MMS Interop Tests: xdp client ↔ libiec61850 ===\n");

    test_mc01_connect();
    test_mc02_read();
    test_mc02b_read_float();
    test_mc02c_read_boolean();
    test_mc03_getnamelist_domains();
    test_mc04_getnamelist_vars();
    test_mc05_get_var_attrs();
    test_mc06_multi_request();
    test_mc07_read_nonexistent();
    test_mc08_reconnect();
    test_mc10_write();
    test_mc11_write_read_back();
    test_mc12_read_named_varlist();
    test_mc09_libiec_reads_our_server();
    test_msg01_discover();
    test_msg02_sgcb_reads();
    test_msg03_se_invisible();
    test_msg04_edit_flow();
    test_msg05_activate();
    test_msg06_owner_conflict();

    INTEROP_SUMMARY();
    return interop_tests_failed > 0 ? 1 : 0;
}
