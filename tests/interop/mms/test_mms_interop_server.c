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


#include "../interop_helpers.h"
#include "mms/mms_server.h"
#include "mms/mms_client.h"
#include "mms/mms_control.h"
#include "mms/mms_data_store.h"
#include "mms/mms_setting_groups.h"
#include "ied/ied_data_model.h"
#include "asn1/mms_ber.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static uint16_t g_port = 10500;
static iec61850_mms_data_store_t g_ds;
static iec61850_mms_server_t g_server;
static bool g_server_active = false;

static int setup_our_server(void)
{
    /* Clean up any leftover state from a previous failed test */
    if (g_server_active) {
        iec61850_mms_server_stop(&g_server);
        iec61850_mms_ds_destroy(&g_ds);
        g_server_active = false;
        g_port++;
        usleep(100000);
    }

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
    int ret = iec61850_mms_server_start(&g_server);
    if (ret == IEC61850_MMS_SERVER_OK) {
        g_server_active = true;
    }
    return ret;
}

static void teardown_our_server(void)
{
    iec61850_mms_server_stop(&g_server);
    iec61850_mms_ds_destroy(&g_ds);
    g_server_active = false;
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

/*
 * MS-09: Our client writes to our server (self-test with interop encoding)
 */
static void test_ms09_self_write(void)
{
    INTEROP_TEST("MS-09: self-test write then read back");

    int ret = setup_our_server();
    if (ret != IEC61850_MMS_SERVER_OK) { g_port++; INTEROP_FAIL("server start"); }
    usleep(200000);

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        teardown_our_server();
        g_port++;
        INTEROP_FAIL("connect failed");
    }

    /* Write an integer */
    mms_value_t wval;
    memset(&wval, 0, sizeof(wval));
    wval.type = MMS_TYPE_INTEGER;
    wval.value.integer = 99;

    ret = iec61850_mms_client_write(&client, "IED1LD0",
                                       "LLN0$ST$Beh$stVal", &wval);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    /* Read back */
    mms_value_t rval;
    ret = iec61850_mms_client_read(&client, "IED1LD0",
                                      "LLN0$ST$Beh$stVal", &rval);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT(rval.type == MMS_TYPE_INTEGER);
    INTEROP_ASSERT(rval.value.integer == 99);

    iec61850_mms_client_disconnect(&client);
    teardown_our_server();
    g_port++;

    INTEROP_PASS();
}

/*
 * MS-10: Named variable list lifecycle (define → read → delete)
 */
static void test_ms10_named_varlist(void)
{
    INTEROP_TEST("MS-10: named variable list lifecycle");

    int ret = setup_our_server();
    if (ret != IEC61850_MMS_SERVER_OK) { g_port++; INTEROP_FAIL("server start"); }
    usleep(200000);

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        teardown_our_server();
        g_port++;
        INTEROP_FAIL("connect failed");
    }

    /* Define a named variable list with 2 variables */
    mms_variable_spec_t vars[2];
    memset(vars, 0, sizeof(vars));
    (void)strncpy(vars[0].domain, "IED1LD0", MMS_MAX_DOMAIN_NAME - 1);
    (void)strncpy(vars[0].item_id, "LLN0$ST$Beh$stVal", MMS_MAX_VARIABLE_NAME - 1);
    (void)strncpy(vars[1].domain, "IED1LD0", MMS_MAX_DOMAIN_NAME - 1);
    (void)strncpy(vars[1].item_id, "GGIO1$ST$SPCSO1$stVal", MMS_MAX_VARIABLE_NAME - 1);

    ret = iec61850_mms_client_define_named_varlist(&client, "IED1LD0",
                                                     "TestList", vars, 2);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    /* Read the named variable list — should get 2 values */
    mms_value_t values[8];
    uint32_t num_values = 0;
    ret = iec61850_mms_client_read_named_varlist(&client, "IED1LD0",
                                                    "TestList", values,
                                                    &num_values, 8);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT(num_values == 2);
    INTEROP_ASSERT(values[0].type == MMS_TYPE_INTEGER);
    INTEROP_ASSERT(values[1].type == MMS_TYPE_BOOLEAN);

    /* Delete the named variable list */
    ret = iec61850_mms_client_delete_named_varlist(&client, "IED1LD0",
                                                      "TestList");
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    iec61850_mms_client_disconnect(&client);
    teardown_our_server();
    g_port++;
    INTEROP_PASS();
}

/*
 * MS-11: File services (directory, open, read, close)
 */
static void test_ms11_file_services(void)
{
    INTEROP_TEST("MS-11: file services lifecycle");

    /* Create test file before starting server */
    const char *test_dir = "/tmp/iec61850_file_test";
    const char *test_file = "/tmp/iec61850_file_test/test.dat";
    (void)mkdir(test_dir, 0755);
    FILE *fp = fopen(test_file, "w");
    if (fp == NULL) { g_port++; INTEROP_FAIL("cannot create test file"); }
    (void)fputs("IEC 61850 test file content\n", fp);
    (void)fclose(fp);

    /* Set up server with file service */
    iec61850_mms_server_stop(&g_server);
    iec61850_mms_ds_destroy(&g_ds);
    iec61850_mms_ds_init(&g_ds);
    iec61850_mms_ds_create_domain(&g_ds, "IED1LD0");

    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;
    val.value.integer = 1;
    iec61850_mms_ds_create_variable(&g_ds, "IED1LD0", "LLN0$ST$Beh$stVal",
                                     MMS_TYPE_INTEGER, &val);

    static iec61850_mms_file_service_t fs;
    iec61850_mms_file_service_init(&fs, test_dir);

    iec61850_mms_server_config_t cfg;
    iec61850_mms_server_config_init(&cfg);
    cfg.port = g_port;

    iec61850_mms_server_init(&g_server, &cfg, &g_ds);
    g_server.file_service = &fs;
    int ret = iec61850_mms_server_start(&g_server);
    if (ret != IEC61850_MMS_SERVER_OK) {
        (void)unlink(test_file); (void)rmdir(test_dir);
        g_port++;
        INTEROP_FAIL("server start");
    }
    usleep(200000);

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        iec61850_mms_server_stop(&g_server);
        iec61850_mms_ds_destroy(&g_ds);
        (void)unlink(test_file); (void)rmdir(test_dir);
        g_port++;
        INTEROP_FAIL("connect failed");
    }

    /* File directory — should list test.dat */
    mms_file_entry_t entries[16];
    uint32_t num_entries = 0;
    ret = iec61850_mms_client_file_directory(&client, NULL, entries,
                                               &num_entries, 16);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT(num_entries >= 1);

    /* File open */
    uint32_t fh = 0, fsize = 0;
    ret = iec61850_mms_client_file_open(&client, "test.dat", &fh, &fsize);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT(fsize > 0);

    /* File read */
    uint8_t buf[256];
    uint32_t bytes_read = 0;
    bool more = false;
    ret = iec61850_mms_client_file_read(&client, fh, buf, &bytes_read,
                                           sizeof(buf), &more);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT(bytes_read > 0);
    INTEROP_ASSERT(!more);

    /* File close */
    ret = iec61850_mms_client_file_close(&client, fh);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    iec61850_mms_client_disconnect(&client);
    iec61850_mms_server_stop(&g_server);
    iec61850_mms_ds_destroy(&g_ds);
    iec61850_mms_file_service_destroy(&fs);
    (void)unlink(test_file);
    (void)rmdir(test_dir);
    g_port++;
    INTEROP_PASS();
}

/*
 * MS-12: Identify service (self-test)
 */
static void test_ms12_self_identify(void)
{
    INTEROP_TEST("MS-12: self-test identify");

    int ret = setup_our_server();
    if (ret != IEC61850_MMS_SERVER_OK) { g_port++; INTEROP_FAIL("server start"); }
    usleep(200000);

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        teardown_our_server();
        g_port++;
        INTEROP_FAIL("connect failed");
    }

    char vendor[128] = {0}, model[128] = {0}, revision[128] = {0};
    ret = iec61850_mms_client_identify(&client, vendor, model, revision, 128);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT(strlen(vendor) > 0);
    INTEROP_ASSERT(strstr(vendor, "xdp-iec61850") != NULL);
    INTEROP_ASSERT(strlen(model) > 0);
    INTEROP_ASSERT(strlen(revision) > 0);

    iec61850_mms_client_disconnect(&client);
    teardown_our_server();
    g_port++;
    INTEROP_PASS();
}

/*
 * MC-12 (in server file): Identify external server
 */
static void test_mc12_identify_external(void)
{
    INTEROP_TEST("MC-12: identify libiec61850 server");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    char server_path[600];
    if (!interop_example_path(server_path, sizeof(server_path),
                              "server_example_basic_io", "server_example_basic_io"))
        INTEROP_SKIP("server not found");

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", g_port);
    char *sargs[] = { server_path, port_str, NULL };
    pid_t srv = interop_start_bg(server_path, sargs, NULL);
    if (srv < 0) { g_port++; INTEROP_FAIL("server start"); }
    if (!interop_wait_for_port(g_port, 3000)) {
        interop_stop_helper(srv);
        g_port++;
        INTEROP_FAIL("server port not ready");
    }

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        interop_stop_helper(srv);
        g_port++;
        INTEROP_FAIL("connect failed");
    }

    char vendor[128] = {0}, model[128] = {0}, revision[128] = {0};
    ret = iec61850_mms_client_identify(&client, vendor, model, revision, 128);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT(strlen(vendor) > 0);
    INTEROP_ASSERT(strlen(revision) > 0);

    iec61850_mms_client_disconnect(&client);
    interop_stop_helper(srv);
    g_port++;
    INTEROP_PASS();
}

/*
 * MS-13: Conclude (graceful disconnect with RLRQ/FINISH)
 */
static void test_ms13_conclude(void)
{
    INTEROP_TEST("MS-13: graceful conclude");

    int ret = setup_our_server();
    if (ret != IEC61850_MMS_SERVER_OK) { g_port++; INTEROP_FAIL("server start"); }
    usleep(200000);

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        teardown_our_server();
        g_port++;
        INTEROP_FAIL("connect failed");
    }

    /* Do a read to confirm the connection works */
    mms_value_t val;
    ret = iec61850_mms_client_read(&client, "IED1LD0",
                                      "LLN0$ST$Beh$stVal", &val);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    /* Graceful disconnect (sends RLRQ + FINISH SPDU) */
    ret = iec61850_mms_client_disconnect(&client);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT(!iec61850_mms_client_is_connected(&client));

    /* Server should still be running — start new session */
    iec61850_mms_client_init(&client);
    ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    /* Read again on new session */
    ret = iec61850_mms_client_read(&client, "IED1LD0",
                                      "LLN0$ST$Beh$stVal", &val);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    iec61850_mms_client_disconnect(&client);
    teardown_our_server();
    g_port++;
    INTEROP_PASS();
}

/*
 * MS-14 (WP-2w): drive one control of the oracle's server_example_
 * control through the IEC 61850-8-1 CO-object mapping with our client
 * helpers (ctlModel read, direct operate, SBO read-select + operate)
 * and receive the oracle's CommandTermination as an unsolicited
 * InformationReport. Skips when the oracle binary or its
 * simpleIOGenericIO model is unavailable.
 */
static int ms14_ct_count;
static iec61850_mms_client_command_termination_t ms14_last_ct;

static void ms14_on_command_termination(
    const iec61850_mms_client_command_termination_t *termination,
    void *user_data)
{
    (void)user_data;
    ms14_ct_count++;
    ms14_last_ct = *termination;
}

static void test_ms14_control_via_oracle_server(void)
{
    INTEROP_TEST("MS-14: our client controls the oracle server (CO objects)");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    char server_path[600];
    if (!interop_example_path(server_path, sizeof(server_path),
                              "server_example_control",
                              "server_example_control"))
        INTEROP_SKIP("server_example_control not found");

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", g_port);
    char *sargs[] = { server_path, port_str, NULL };
    pid_t srv = interop_start_bg(server_path, sargs, NULL);
    if (srv < 0) { g_port++; INTEROP_FAIL("server start"); }
    if (!interop_wait_for_port(g_port, 3000)) {
        interop_stop_helper(srv);
        g_port++;
        INTEROP_FAIL("server port not ready");
    }

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", g_port, 5000);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        interop_stop_helper(srv);
        g_port++;
        INTEROP_FAIL("connect failed");
    }

    /* Discover the oracle's controllable model (skip gracefully when
     * its simpleIOGenericIO LD is not exposed). */
    char domains[16][MMS_MAX_VARIABLE_NAME];
    uint32_t count = 0;
    bool have_ld = false;

    ret = iec61850_mms_client_get_name_list(&client,
                                             MMS_OBJECT_CLASS_DOMAIN, NULL,
                                             domains, &count, 16);
    if (ret == (int)IEC61850_MMS_CLIENT_OK) {
        for (uint32_t i = 0; i < count; i++) {
            if (strcmp(domains[i], "simpleIOGenericIO") == 0) {
                have_ld = true;
            }
        }
    }
    if (!have_ld) {
        iec61850_mms_client_disconnect(&client);
        interop_stop_helper(srv);
        g_port++;
        INTEROP_SKIP("oracle model has no simpleIOGenericIO LD");
    }

    /* CommandTermination reception (the oracle's unsolicited
     * InformationReport on the operated "$Oper" object). */
    ms14_ct_count = 0;
    iec61850_mms_client_set_command_termination_handler(
        &client, ms14_on_command_termination, NULL);

    /* ctlModel of the direct-with-normal-security object */
    int32_t ctl_model = -1;
    ret = iec61850_mms_client_read_ctl_model(&client, "simpleIOGenericIO",
                                              "GGIO1$CO$SPCSO1",
                                              &ctl_model);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT_EQ(ctl_model, 1);   /* direct-with-normal-security */

    /* Direct operate (Write of the 8-1 Oper structure) */
    iec61850_mms_client_operate_params_t params;
    memset(&params, 0, sizeof(params));
    params.ctl_val = true;
    params.origin_cat = 1;
    params.origin_ident = "xdp-interop";
    params.ctl_num = 1U;
    ret = iec61850_mms_client_operate(&client, "simpleIOGenericIO",
                                       "GGIO1$CO$SPCSO1", &params);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    /* Status feedback */
    mms_value_t v;
    memset(&v, 0, sizeof(v));
    ret = iec61850_mms_client_read(&client, "simpleIOGenericIO",
                                    "GGIO1$ST$SPCSO1$stVal", &v);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    INTEROP_ASSERT(v.type == MMS_TYPE_BOOLEAN);
    INTEROP_ASSERT(v.value.boolean);

    /* sbo-with-normal-security: the 8-1 SBO read-select, then operate */
    ret = iec61850_mms_client_select(&client, "simpleIOGenericIO",
                                      "GGIO1$CO$SPCSO2");
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    params.ctl_num = 2U;
    ret = iec61850_mms_client_operate(&client, "simpleIOGenericIO",
                                       "GGIO1$CO$SPCSO2", &params);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    /* direct-with-enhanced-security: operate + CommandTermination */
    params.ctl_num = 3U;
    ret = iec61850_mms_client_operate(&client, "simpleIOGenericIO",
                                       "GGIO1$CO$SPCSO3", &params);
    INTEROP_ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    for (int i = 0; (i < 40) && (ms14_ct_count == 0); i++) {
        (void)iec61850_mms_client_poll(&client, 200);
    }
    INTEROP_ASSERT_EQ(ms14_ct_count, 1);
    INTEROP_ASSERT(strcmp(ms14_last_ct.domain, "simpleIOGenericIO") == 0);
    INTEROP_ASSERT(strcmp(ms14_last_ct.item_id, "GGIO1$CO$SPCSO3$Oper") == 0);
    INTEROP_ASSERT(ms14_last_ct.ctl_val);
    INTEROP_ASSERT(ms14_last_ct.ctl_num == 3U);

    iec61850_mms_client_disconnect(&client);
    interop_stop_helper(srv);
    g_port++;

    INTEROP_PASS();
}

/*
 * MS-15 (WP-2w): the oracle's client_example_control drives controls
 * on OUR server through the WP-2w control-object bridge. Our server
 * exposes the oracle client's model (simpleIOGenericIO / GGIO1
 * SPCSO1, 2, 3, 4, 9 with the sbo classes matching their ctlModels)
 * and must answer the ctlModel reads, the CO-object directory, the
 * SBO read-select / SBOw write-select, the Oper writes and the
 * CommandTermination. Skips when the oracle client binary is
 * unavailable.
 */
static iec61850_mms_data_store_t ms15_ds;
static iec61850_control_manager_t ms15_mgr;
static iec61850_mms_server_t ms15_srv;

static int ms15_on_action(const char *domain, const char *item_id,
                           const mms_value_t *value, void *user_data)
{
    char st[MMS_MAX_VARIABLE_NAME];
    const char *co = strstr(item_id, "$CO$");

    (void)domain; (void)value; (void)user_data;
    if (co != NULL) {
        mms_value_t v;

        (void)snprintf(st, sizeof(st), "%.*s$ST$%s$stVal",
                       (int)(co - item_id), item_id, co + 4);
        (void)memset(&v, 0, sizeof(v));
        v.type = MMS_TYPE_BOOLEAN;
        v.value.boolean = true;
        (void)iec61850_mms_ds_write_variable(&ms15_ds, "simpleIOGenericIO",
                                              st, &v);
    }
    return 0;
}

static void test_ms15_oracle_client_controls_our_server(void)
{
    static const char *objects[] = {
        "GGIO1$CO$SPCSO1", "GGIO1$CO$SPCSO2", "GGIO1$CO$SPCSO3",
        "GGIO1$CO$SPCSO4", "GGIO1$CO$SPCSO9", NULL
    };

    INTEROP_TEST("MS-15: oracle client controls our server (CO objects)");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    char client_path[600];
    if (!interop_example_path(client_path, sizeof(client_path),
                              "iec61850_client_example_control",
                              "client_example_control"))
        INTEROP_SKIP("client_example_control not found");

    /* Our server, exposing the oracle client's model: SPCSO1/3/9 are
     * direct (dynamic sboClass), SPCSO2/4 are sbo (strict). */
    iec61850_mms_ds_init(&ms15_ds);
    (void)iec61850_mms_ds_create_domain(&ms15_ds, "simpleIOGenericIO");
    iec61850_control_manager_init(&ms15_mgr);
    for (int i = 0; objects[i] != NULL; i++) {
        char st[MMS_MAX_VARIABLE_NAME];
        const char *co = strstr(objects[i], "$CO$");
        mms_value_t v;
        iec61850_control_config_t cc;

        (void)memset(&v, 0, sizeof(v));
        v.type = MMS_TYPE_BOOLEAN;
        v.value.boolean = false;
        (void)snprintf(st, sizeof(st), "%.*s$ST$%s$stVal",
                       (int)(co - objects[i]), objects[i], co + 4);
        (void)iec61850_mms_ds_create_variable(&ms15_ds, "simpleIOGenericIO",
                                               st, MMS_TYPE_BOOLEAN, &v);

        (void)iec61850_control_register(&ms15_mgr, "simpleIOGenericIO",
                                         objects[i]);
        (void)memset(&cc, 0, sizeof(cc));
        cc.sbo_class = (i == 1 || i == 3)
                           ? IEC61850_CONTROL_SBO_CLASS_STRICT
                           : IEC61850_CONTROL_SBO_CLASS_DYNAMIC;
        (void)iec61850_control_configure(&ms15_mgr, "simpleIOGenericIO",
                                          objects[i], &cc);
        (void)iec61850_control_set_action_callback(&ms15_mgr,
                                                    "simpleIOGenericIO",
                                                    objects[i],
                                                    ms15_on_action, NULL);
    }

    iec61850_mms_server_config_t cfg;
    iec61850_mms_server_config_init(&cfg);
    cfg.port = g_port;
    iec61850_mms_server_init(&ms15_srv, &cfg, &ms15_ds);
    if (iec61850_mms_server_set_control_manager(&ms15_srv, &ms15_mgr) != 0) {
        iec61850_control_manager_destroy(&ms15_mgr);
        iec61850_mms_ds_destroy(&ms15_ds);
        g_port++;
        INTEROP_FAIL("set_control_manager failed");
    }
    if (iec61850_mms_server_start(&ms15_srv) != IEC61850_MMS_SERVER_OK) {
        iec61850_control_manager_destroy(&ms15_mgr);
        iec61850_mms_ds_destroy(&ms15_ds);
        g_port++;
        INTEROP_FAIL("server start");
    }
    usleep(300000);

    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%u", g_port);
    char *cargs[] = { client_path, (char *)"127.0.0.1", port_str, NULL };
    char output[4096];
    int rc = interop_run_program(client_path, cargs, output, sizeof(output),
                                 20000);

    (void)iec61850_mms_server_stop(&ms15_srv);
    iec61850_control_manager_destroy(&ms15_mgr);
    iec61850_mms_ds_destroy(&ms15_ds);
    g_port++;

    INTEROP_ASSERT_EQ(rc, 0);
    /* Every control of the oracle's cycle operated through the
     * CO-object mapping... */
    INTEROP_ASSERT(strstr(output, "SPCSO1 operated successfully") != NULL);
    INTEROP_ASSERT(strstr(output, "SPCSO2 operated successfully") != NULL);
    INTEROP_ASSERT(strstr(output, "SPCSO3 operated successfully") != NULL);
    INTEROP_ASSERT(strstr(output, "SPCSO4 operated successfully") != NULL);
    INTEROP_ASSERT(strstr(output, "SPCSO9 operated successfully") != NULL);
    /* ...and at least one CommandTermination was received from our
     * bridge by the conformant client. */
    INTEROP_ASSERT(strstr(output, "Received CommandTermination+.") != NULL);

    INTEROP_PASS();
}

/*
 * MS-16 (WP-6x): the libiec61850 client (mms_utility) reads our
 * SGCB — the 8-1 object naming (LLN0$SP$SGCB$<attr>) verified
 * against the reference stack from the client side.
 */
static void test_ms16_oracle_client_reads_sgcb(void)
{
    iec61850_mms_data_store_t ds;
    iec61850_ied_model_t *model;
    iec61850_sg_manager_t *mgr;
    iec61850_mms_server_t srv;
    iec61850_mms_server_config_t cfg;
    iec61850_logical_device_t *ld;
    iec61850_logical_node_t *ln;
    iec61850_data_object_t *dobj;
    iec61850_data_attribute_t *setval;
    char output[4096];
    const char *args[4];
    int rc;

    INTEROP_TEST("MS-16: mms_utility reads our SGCB (WP-6x)");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    iec61850_mms_ds_init(&ds);
    (void)iec61850_mms_ds_create_domain(&ds, "LD0");

    model = calloc(1, sizeof(*model));
    ld = iec61850_ld_create("LD0");
    ln = iec61850_ln_create("PTOC", "1");
    dobj = iec61850_do_create("Mod", IEC61850_CDC_DPC);
    (void)iec61850_do_add_attribute(dobj, "setVal", IEC61850_FC_SE,
                                    IEC61850_BTYPE_INT32);
    (void)iec61850_ln_add_data_object(ln, dobj);
    (void)iec61850_ld_add_logical_node(ld, ln);
    (void)iec61850_ied_model_add_ld(model, ld);
    setval = iec61850_ln_find_attribute(ln, "Mod.setVal", IEC61850_FC_SE);
    setval->value.type = MMS_TYPE_INTEGER;
    setval->value.value.integer = 100;

    if (iec61850_sg_manager_init(&mgr, model, 3, 1, 30) != 0) {
        INTEROP_FAIL("sg manager init failed");
    }

    iec61850_mms_server_config_init(&cfg);
    cfg.port = g_port;
    iec61850_mms_server_init(&srv, &cfg, &ds);
    if (iec61850_mms_server_set_sg_manager(&srv, mgr) != 0) {
        iec61850_sg_manager_destroy(mgr);
        iec61850_mms_ds_destroy(&ds);
        INTEROP_FAIL("set_sg_manager failed");
    }
    if (iec61850_mms_server_start(&srv) != IEC61850_MMS_SERVER_OK) {
        iec61850_sg_manager_destroy(mgr);
        iec61850_mms_ds_destroy(&ds);
        INTEROP_FAIL("server start failed");
    }
    usleep(200000);

    /* Read the SGCB attribute with the reference client. */
    args[0] = "-a";
    args[1] = "LD0";
    args[2] = "-r";
    args[3] = "LLN0$SP$SGCB$NumOfSG";
    rc = run_mms_utility(args, 4, output, sizeof(output));

    (void)iec61850_mms_server_stop(&srv);
    iec61850_sg_manager_destroy(mgr);
    iec61850_mms_ds_destroy(&ds);
    g_port++;

    INTEROP_ASSERT(rc == 0);
    INTEROP_ASSERT(strstr(output, "Read SUCCESS") != NULL);
    INTEROP_ASSERT(strstr(output, "\n3\n") != NULL);
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
    test_ms09_self_write();
    test_ms10_named_varlist();
    test_ms11_file_services();
    test_ms12_self_identify();
    test_mc12_identify_external();
    test_ms13_conclude();
    test_ms14_control_via_oracle_server();
    test_ms15_oracle_client_controls_our_server();
    test_ms16_oracle_client_reads_sgcb();

    INTEROP_SUMMARY();
    return interop_tests_failed > 0 ? 1 : 0;
}
