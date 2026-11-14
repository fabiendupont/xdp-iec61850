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

#ifdef IEC61850_SECURITY_ENABLED
/*
 * WP-3b (IEC 62351-4): full MMS session over TLS — initiate,
 * read/write, a report, disconnect — plus plain-TCP coexistence on
 * the dual-listener server. Security-gated.
 */
#include "mms/mms_client_rcb.h"
#include "security/cert_provider.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define TLS_PORT       12382
#define TLS_PLAIN_PORT 12302
#define TLS_LD         "tld"             /* RCB component objects */
#define TLS_URCB_REF   "LLN0$RP$u1"
#define TLS_LDD        "tldd"            /* monitored data points */
#define TLS_STVAL      "XCBR1$ST$Pos$stVal"

static char tls_ca_cert[128];
static char tls_srv_key[128];
static char tls_srv_cert[128];

static int tls_gen_fixtures(void)
{
    struct { EVP_PKEY_CTX *ctx; EVP_PKEY *key; } ca_k = {NULL, NULL};
    struct { EVP_PKEY_CTX *ctx; EVP_PKEY *key; } srv_k = {NULL, NULL};
    X509 *ca = NULL;
    X509 *srv = NULL;
    X509_NAME *name;
    FILE *f;
    int ok = -1;
    X509_EXTENSION *bc = X509V3_EXT_conf_nid(NULL, NULL,
                                              NID_basic_constraints,
                                              "critical,CA:TRUE");

    ca_k.ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    srv_k.ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if ((ca_k.ctx == NULL) || (srv_k.ctx == NULL)) { goto done; }
    if ((EVP_PKEY_keygen_init(ca_k.ctx) <= 0) ||
        (EVP_PKEY_CTX_set_rsa_keygen_bits(ca_k.ctx, 2048) <= 0) ||
        (EVP_PKEY_keygen(ca_k.ctx, &ca_k.key) <= 0)) {
        goto done;
    }
    if ((EVP_PKEY_keygen_init(srv_k.ctx) <= 0) ||
        (EVP_PKEY_CTX_set_rsa_keygen_bits(srv_k.ctx, 2048) <= 0) ||
        (EVP_PKEY_keygen(srv_k.ctx, &srv_k.key) <= 0)) {
        goto done;
    }

    ca = X509_new();
    srv = X509_new();
    if ((ca == NULL) || (srv == NULL)) { goto done; }

    /* Self-signed CA */
    X509_set_version(ca, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(ca), 1);
    X509_gmtime_adj(X509_get_notBefore(ca), 0);
    X509_gmtime_adj(X509_get_notAfter(ca), 365L * 24 * 3600);
    X509_set_pubkey(ca, ca_k.key);
    name = X509_get_subject_name(ca);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                (const unsigned char *)"TlsE2eCA", -1, -1, 0);
    X509_set_issuer_name(ca, name);
    if ((bc == NULL) || (X509_add_ext(ca, bc, -1) != 1)) { goto done; }
    if (X509_sign(ca, ca_k.key, EVP_sha256()) <= 0) { goto done; }

    /* Server leaf signed by the CA */
    X509_set_version(srv, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(srv), 2);
    X509_gmtime_adj(X509_get_notBefore(srv), 0);
    X509_gmtime_adj(X509_get_notAfter(srv), 365L * 24 * 3600);
    X509_set_pubkey(srv, srv_k.key);
    name = X509_get_subject_name(srv);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                (const unsigned char *)"TlsE2eServer", -1, -1, 0);
    X509_set_issuer_name(srv, X509_get_subject_name(ca));
    if (X509_sign(srv, ca_k.key, EVP_sha256()) <= 0) { goto done; }

    f = fopen(tls_ca_cert, "w");
    if (f == NULL) { goto done; }
    PEM_write_X509(f, ca);
    fclose(f);
    f = fopen(tls_srv_key, "w");
    if (f == NULL) { goto done; }
    PEM_write_PrivateKey(f, srv_k.key, NULL, NULL, 0, NULL, NULL);
    fclose(f);
    f = fopen(tls_srv_cert, "w");
    if (f == NULL) { goto done; }
    PEM_write_X509(f, srv);
    fclose(f);

    ok = 0;

done:
    X509_EXTENSION_free(bc);
    EVP_PKEY_CTX_free(ca_k.ctx);
    EVP_PKEY_CTX_free(srv_k.ctx);
    EVP_PKEY_free(ca_k.key);
    EVP_PKEY_free(srv_k.key);
    X509_free(ca);
    X509_free(srv);
    ERR_clear_error();
    return ok;
}

static void tls_cleanup_fixtures(void)
{
    (void)unlink(tls_ca_cert);
    (void)unlink(tls_srv_key);
    (void)unlink(tls_srv_cert);
}

static int g_tls_report_count;
static mms_information_report_t g_tls_last_report;

static void tls_report_cb(const mms_information_report_t *report,
                          void *user_data)
{
    (void)user_data;
    if (g_tls_report_count < 4) {
        g_tls_last_report = *report;
    }
    g_tls_report_count++;
}

static void test_tls_mms_session(void)
{
    iec61850_mms_data_store_t ds;
    iec61850_rcb_manager_t mgr;
    iec61850_mms_server_t server;
    iec61850_mms_client_t client;
    iec61850_cert_provider_t *server_prov;
    iec61850_cert_provider_t *client_prov;
    iec61850_mms_server_config_t cfg;
    mms_variable_spec_t members[1];
    mms_value_t v;
    iec61850_mms_client_rcb_values_t values;
    uint32_t mask;
    int waited;
    bool server_up = false;

    TEST("tls_mms_session_full");

    (void)snprintf(tls_ca_cert, sizeof(tls_ca_cert),
                   "/tmp/test_mms_e2e_tls_ca_%d.pem", (int)getpid());
    (void)snprintf(tls_srv_key, sizeof(tls_srv_key),
                   "/tmp/test_mms_e2e_tls_key_%d.pem", (int)getpid());
    (void)snprintf(tls_srv_cert, sizeof(tls_srv_cert),
                   "/tmp/test_mms_e2e_tls_cert_%d.pem", (int)getpid());

    if (tls_gen_fixtures() != 0) {
        FAIL("fixture generation");
        return;
    }

    server_prov = iec61850_cert_provider_create_static(
        tls_srv_cert, tls_srv_key, tls_ca_cert);
    client_prov = iec61850_cert_provider_create_static(
        NULL, NULL, tls_ca_cert);
    if ((server_prov == NULL) || (client_prov == NULL)) {
        FAIL("provider creation");
        goto cleanup_files;
    }

    /* Data model: RCB LD + monitored data-point LD with a dataset */
    iec61850_mms_ds_init(&ds);
    (void)iec61850_mms_ds_create_domain(&ds, TLS_LD);
    (void)iec61850_mms_ds_create_domain(&ds, TLS_LDD);

    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_BOOLEAN;
    v.value.boolean = true;
    (void)iec61850_mms_ds_create_variable(&ds, TLS_LDD, TLS_STVAL,
                                            MMS_TYPE_BOOLEAN, &v);

    (void)strncpy(members[0].domain, TLS_LDD, MMS_MAX_DOMAIN_NAME - 1);
    (void)strncpy(members[0].item_id, TLS_STVAL, MMS_MAX_VARIABLE_NAME - 1);
    (void)iec61850_mms_ds_define_list(&ds, TLS_LDD, "ds1", members, 1);

    iec61850_rcb_manager_init(&mgr, TLS_LD);
    (void)iec61850_rcb_manager_add_rcb(&mgr, "u1",
                                        IEC61850_RCB_UNBUFFERED, 0);

    /* Dual-listener server: plain + TLS (IEC 62351-4, COMPATIBLE) */
    iec61850_mms_server_config_init(&cfg);
    cfg.port = TLS_PLAIN_PORT;
    cfg.tls_enabled = true;
    cfg.tls_provider = server_prov;
    cfg.tls_mode = IEC61850_TLS_MODE_COMPATIBLE;
    cfg.tls_port = TLS_PORT;
    cfg.tls_only = false;

    iec61850_mms_server_init(&server, &cfg, &ds);
    if (iec61850_mms_server_set_rcb_manager(&server, &mgr) != 0) {
        FAIL("rcb manager registration");
        goto cleanup_all;
    }
    if (iec61850_mms_server_start(&server) != 0) {
        FAIL("server start");
        goto cleanup_all;
    }
    server_up = true;
    usleep(200000);

    /* Initiate over TLS */
    iec61850_mms_client_init(&client);
    if (iec61850_mms_client_set_tls(&client, client_prov,
                                      IEC61850_TLS_MODE_COMPATIBLE) != 0) {
        FAIL("set_tls");
        goto cleanup_all;
    }
    if (iec61850_mms_client_connect(&client, "127.0.0.1", TLS_PORT,
                                      5000) != IEC61850_MMS_CLIENT_OK) {
        FAIL("tls connect");
        goto cleanup_all;
    }

    /* Read over TLS */
    (void)memset(&v, 0, sizeof(v));
    if ((iec61850_mms_client_read(&client, TLS_LDD, TLS_STVAL, &v) !=
         IEC61850_MMS_CLIENT_OK) || (!v.value.boolean)) {
        FAIL("tls read");
        goto disconnect;
    }

    /* Write over TLS */
    v.value.boolean = false;
    if (iec61850_mms_client_write(&client, TLS_LDD, TLS_STVAL, &v) !=
        IEC61850_MMS_CLIENT_OK) {
        FAIL("tls write");
        goto disconnect;
    }
    (void)memset(&v, 0, sizeof(v));
    if ((iec61850_mms_client_read(&client, TLS_LDD, TLS_STVAL, &v) !=
         IEC61850_MMS_CLIENT_OK) || (v.value.boolean)) {
        FAIL("tls read-back");
        goto disconnect;
    }

    /* A report over TLS: enroll + enable the URCB, trigger a data
     * change, poll for the InformationReport. */
    if (iec61850_mms_client_set_report_handler(&client, tls_report_cb,
                                                 NULL) !=
        IEC61850_MMS_CLIENT_OK) {
        FAIL("report handler");
        goto disconnect;
    }

    (void)memset(&values, 0, sizeof(values));
    values.resv = true;
    (void)strncpy(values.attrs.rpt_id, "R1",
                  (size_t)IEC61850_RCB_MAX_NAME - 1U);
    (void)strncpy(values.attrs.dat_set, TLS_LDD "/ds1",
                  (size_t)IEC61850_RCB_MAX_NAME - 1U);
    values.attrs.trg_ops.data_change = true;
    values.attrs.trg_ops.general_interrogation = true;
    values.attrs.opt_flds.sequence_number = true;
    values.attrs.opt_flds.reason_for_inclusion = true;
    values.attrs.rpt_ena = true;

    mask = (uint32_t)IEC61850_RCB_FIELD_RPT_ID |
           (uint32_t)IEC61850_RCB_FIELD_RESV |
           (uint32_t)IEC61850_RCB_FIELD_DAT_SET |
           (uint32_t)IEC61850_RCB_FIELD_OPT_FLDS |
           (uint32_t)IEC61850_RCB_FIELD_TRG_OPS |
           (uint32_t)IEC61850_RCB_FIELD_RPT_ENA;
    if (iec61850_mms_client_rcb_set_values(&client, TLS_LD,
                                             TLS_URCB_REF, &values,
                                             mask) !=
        IEC61850_MMS_CLIENT_OK) {
        FAIL("urcb enrollment");
        goto disconnect;
    }

    g_tls_report_count = 0;
    v.value.boolean = true;
    if (iec61850_mms_client_write(&client, TLS_LDD, TLS_STVAL, &v) !=
        IEC61850_MMS_CLIENT_OK) {
        FAIL("trigger write");
        goto disconnect;
    }

    waited = 0;
    while ((g_tls_report_count < 1) && (waited < 5000)) {
        (void)iec61850_mms_client_poll(&client, 50);
        waited += 50;
    }
    if ((g_tls_report_count < 1) ||
        (g_tls_last_report.num_values < 1) ||
        (g_tls_last_report.values[0].type != MMS_TYPE_BOOLEAN) ||
        (!g_tls_last_report.values[0].value.boolean)) {
        FAIL("report over tls");
        goto disconnect;
    }

    /* Disconnect over TLS */
    if (iec61850_mms_client_disconnect(&client) !=
        IEC61850_MMS_CLIENT_OK) {
        FAIL("tls disconnect");
        goto cleanup_all;
    }

    /* Plain coexistence: the plain listener is still bound while
     * the TLS listener serves secure associations. */
    {
        iec61850_mms_client_t plain;

        iec61850_mms_client_init(&plain);
        if (iec61850_mms_client_connect(&plain, "127.0.0.1",
                                          TLS_PLAIN_PORT, 5000) !=
            IEC61850_MMS_CLIENT_OK) {
            FAIL("plain coexistence connect");
            goto cleanup_all;
        }
        (void)iec61850_mms_client_disconnect(&plain);
    }

    PASS();

disconnect:
    (void)iec61850_mms_client_disconnect(&client);

cleanup_all:
    if (server_up) {
        (void)iec61850_mms_server_stop(&server);
    }
    iec61850_rcb_manager_destroy(&mgr);
    iec61850_mms_ds_destroy(&ds);
    iec61850_cert_provider_destroy(server_prov);
    iec61850_cert_provider_destroy(client_prov);

cleanup_files:
    tls_cleanup_fixtures();
}
#endif /* IEC61850_SECURITY_ENABLED */

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

#ifdef IEC61850_SECURITY_ENABLED
    printf("\n--- TLS MMS (IEC 62351-4) ---\n");
    test_tls_mms_session();
#endif

    printf("\n  Results: %d/%d passed\n\n", test_passed, test_run);
    return (test_failed > 0) ? 1 : 0;
}
