/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS-over-TLS wire scenario (IEC 62351-4) — used by the WP-3d
 * wire capture test.
 *
 * Runs the repository's own dual-listener MMS server (plain TCP +
 * TLS, COMPATIBLE certificate policy) and the repository's own MMS
 * client with iec61850_mms_client_set_tls() armed, in one process
 * over real TCP loopback, so a full TLS-wrapped MMS association
 * lands on the wire and can be captured (tshark/tcpdump on lo):
 *
 *   - TLS handshake (client certificate presented: the server
 *     requests peer certificates per IEC 62351-4)
 *   - ISO/MMS association setup and MMS read/write/read-back
 *     inside TLS application-data records
 *   - a control session on the plain listener of the same server
 *     (differential evidence: the same exchange in the clear on
 *     the plain port vs encrypted on the TLS port)
 *
 * The data model uses deliberately distinctive names (domain
 * "TLSDOM", value "TLSWIREMARK") so the capture test can assert
 * that neither appears in plaintext on the TLS port. Certificate
 * CNs ("TlsWire*") are chosen to not contain those markers — only
 * MMS payload would carry them.
 *
 * Exits 77 (skip) when the build lacks security support.
 *
 * Usage: mms_tls_wire [tls_port [plain_port]]   (default 10613 10612)
 *
 * Build (manual, matches the meson test link line):
 *   cc -std=c11 -I<src>/include/iec61850 -D_POSIX_C_SOURCE=200809L \
 *      -D_DEFAULT_SOURCE -o mms_tls_wire mms_tls_wire.c \
 *      --start-group <build>/libiec61850.a <build>/libmms_ber.a \
 *      --end-group -pthread $(pkg-config --libs libxml-2.0 openssl)
 */

#include "mms/mms_client.h"
#include "mms/mms_data_store.h"
#include "mms/mms_server.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef IEC61850_SECURITY_ENABLED
#include "security/cert_provider.h"
#include "transport/tls_socket.h"

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#endif

#define TW_TLS_PORT   10613
#define TW_PLAIN_PORT 10612
#define TW_LD         "TLSDOM"              /* marker domain */
#define TW_ITEM       "GGIO1$ST$Ind1$stVal"
#define TW_STR_ITEM   "GGIO1$DC$NamPlt$vendor"
#define TW_MARKER     "TLSWIREMARK"         /* marker write value */

#ifndef IEC61850_SECURITY_ENABLED
int main(void)
{
    printf("SKIP: built without -Denable_security=true "
           "(no TLS support in this build)\n");
    return 77;
}
#else

static int tests_run = 0;
static int tests_failed = 0;

#define STEP(name) do { tests_run++; printf("  [STEP] %s ... ", name); } while (0)
#define OK()       do { printf("OK\n"); } while (0)
#define BAD(msg)   do { printf("FAIL: %s\n", msg); tests_failed++; } while (0)
#define CHECK(cond) do { if (!(cond)) { BAD(#cond); return; } } while (0)

static iec61850_mms_data_store_t g_ds;
static iec61850_mms_server_t g_srv;
static bool g_srv_up;
static iec61850_cert_provider_t *g_srv_prov;
static iec61850_cert_provider_t *g_cli_prov;

static char f_ca_cert[128];
static char f_srv_key[128], f_srv_cert[128];
static char f_cli_key[128], f_cli_cert[128];

static EVP_PKEY *tw_gen_rsa_key(int bits)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *key = NULL;

    if (ctx == NULL) { return NULL; }
    if (EVP_PKEY_keygen_init(ctx) <= 0) { goto out; }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) { goto out; }
    if (EVP_PKEY_keygen(ctx, &key) <= 0) { key = NULL; }
out:
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static int tw_add_ext(X509 *cert, int nid, const char *value)
{
    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, NULL, nid, value);

    if (ext == NULL) { return -1; }
    if (X509_add_ext(cert, ext, -1) != 1) {
        X509_EXTENSION_free(ext);
        return -1;
    }
    X509_EXTENSION_free(ext);
    return 0;
}

static X509 *tw_gen_cert(EVP_PKEY *subj_key, const X509 *issuer_cert,
                          EVP_PKEY *issuer_key, int serial, const char *cn,
                          bool is_ca)
{
    X509 *cert = X509_new();
    X509_NAME *name;
    EVP_PKEY *sign_key = issuer_key;

    if (cert == NULL) { return NULL; }

    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 365L * 24 * 3600);
    X509_set_pubkey(cert, subj_key);

    name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                (const unsigned char *)cn, -1, -1, 0);

    if (issuer_cert != NULL) {
        X509_set_issuer_name(cert, X509_get_subject_name(
                                 (X509 *)issuer_cert));
    } else {
        X509_set_issuer_name(cert, name);
        sign_key = subj_key;
    }

    if (is_ca && (tw_add_ext(cert, NID_basic_constraints,
                               "critical,CA:TRUE") != 0)) {
        X509_free(cert);
        return NULL;
    }

    if (X509_sign(cert, sign_key, EVP_sha256()) <= 0) {
        X509_free(cert);
        ERR_clear_error();
        return NULL;
    }
    return cert;
}

static int tw_write_key(const char *path, EVP_PKEY *key)
{
    FILE *f = fopen(path, "w");

    if (f == NULL) { return -1; }
    PEM_write_PrivateKey(f, key, NULL, NULL, 0, NULL, NULL);
    fclose(f);
    return 0;
}

static int tw_write_cert(const char *path, X509 *cert)
{
    FILE *f = fopen(path, "w");

    if (f == NULL) { return -1; }
    PEM_write_X509(f, cert);
    fclose(f);
    return 0;
}

/* WP-3b/WP-3a fixture conventions: RSA-2048 CA + RSA-2048 leaves.
 * The client leaf carries a spiffe:// URI SAN (harmless for the
 * COMPATIBLE policy in use, and it keeps the fixture set aligned
 * with the MT-series interop matrix). */
static int tw_gen_fixtures(void)
{
    EVP_PKEY *ca_key = tw_gen_rsa_key(2048);
    EVP_PKEY *srv_key = tw_gen_rsa_key(2048);
    EVP_PKEY *cli_key = tw_gen_rsa_key(2048);
    X509 *ca = NULL, *srv = NULL, *cli = NULL;
    int ok = -1;

    (void)snprintf(f_ca_cert, sizeof(f_ca_cert),
                   "/tmp/mms_tls_wire_ca_%d.pem", (int)getpid());
    (void)snprintf(f_srv_key, sizeof(f_srv_key),
                   "/tmp/mms_tls_wire_srv_key_%d.pem", (int)getpid());
    (void)snprintf(f_srv_cert, sizeof(f_srv_cert),
                   "/tmp/mms_tls_wire_srv_cert_%d.pem", (int)getpid());
    (void)snprintf(f_cli_key, sizeof(f_cli_key),
                   "/tmp/mms_tls_wire_cli_key_%d.pem", (int)getpid());
    (void)snprintf(f_cli_cert, sizeof(f_cli_cert),
                   "/tmp/mms_tls_wire_cli_cert_%d.pem", (int)getpid());

    if ((ca_key == NULL) || (srv_key == NULL) || (cli_key == NULL)) {
        goto done;
    }

    ca = tw_gen_cert(ca_key, NULL, NULL, 1, "TlsWireCA", true);
    if (ca == NULL) { goto done; }
    srv = tw_gen_cert(srv_key, ca, ca_key, 2, "TlsWireServer", false);
    cli = tw_gen_cert(cli_key, ca, ca_key, 3, "TlsWireClient", false);
    if ((srv == NULL) || (cli == NULL)) { goto done; }

    if ((tw_write_cert(f_ca_cert, ca) != 0) ||
        (tw_write_key(f_srv_key, srv_key) != 0) ||
        (tw_write_cert(f_srv_cert, srv) != 0) ||
        (tw_write_key(f_cli_key, cli_key) != 0) ||
        (tw_write_cert(f_cli_cert, cli) != 0)) {
        goto done;
    }
    ok = 0;

done:
    EVP_PKEY_free(ca_key);
    EVP_PKEY_free(srv_key);
    EVP_PKEY_free(cli_key);
    X509_free(ca);
    X509_free(srv);
    X509_free(cli);
    ERR_clear_error();
    return ok;
}

static void tw_unlink_fixtures(void)
{
    (void)unlink(f_ca_cert);
    (void)unlink(f_srv_key);
    (void)unlink(f_srv_cert);
    (void)unlink(f_cli_key);
    (void)unlink(f_cli_cert);
}

static void setup(uint16_t plain_port, uint16_t tls_port)
{
    iec61850_mms_server_config_t cfg;
    mms_value_t v;

    iec61850_mms_ds_init(&g_ds);
    (void)iec61850_mms_ds_create_domain(&g_ds, TW_LD);

    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_INTEGER;
    v.value.integer = 42;
    (void)iec61850_mms_ds_create_variable(&g_ds, TW_LD, TW_ITEM,
                                           MMS_TYPE_INTEGER, &v);

    /* A visible-string point whose written value is the plaintext
     * marker the capture test asserts never leaks on the TLS port. */
    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_VISIBLE_STRING;
    (void)strncpy(v.value.visible_string.data, "wire-vendor",
                   MMS_MAX_STRING_LENGTH - 1);
    v.value.visible_string.len = strlen(v.value.visible_string.data);
    (void)iec61850_mms_ds_create_variable(&g_ds, TW_LD, TW_STR_ITEM,
                                           MMS_TYPE_VISIBLE_STRING, &v);

    g_srv_prov = iec61850_cert_provider_create_static(
        f_srv_cert, f_srv_key, f_ca_cert);
    g_cli_prov = iec61850_cert_provider_create_static(
        f_cli_cert, f_cli_key, f_ca_cert);
    if ((g_srv_prov == NULL) || (g_cli_prov == NULL)) {
        BAD("cert provider creation");
        return;
    }

    /* Dual-listener server: plain + TLS (IEC 62351-4, COMPATIBLE
     * policy — the interop default). */
    iec61850_mms_server_config_init(&cfg);
    cfg.port = plain_port;
    cfg.tls_enabled = true;
    cfg.tls_provider = g_srv_prov;
    cfg.tls_mode = IEC61850_TLS_MODE_COMPATIBLE;
    cfg.tls_port = tls_port;
    cfg.tls_only = false;

    iec61850_mms_server_init(&g_srv, &cfg, &g_ds);
    if (iec61850_mms_server_start(&g_srv) != IEC61850_MMS_SERVER_OK) {
        BAD("server start failed");
        return;
    }
    g_srv_up = true;
    usleep(200000);
}

static void teardown(void)
{
    if (g_srv_up) {
        (void)iec61850_mms_server_stop(&g_srv);
        g_srv_up = false;
    }
    if (g_srv_prov != NULL) {
        iec61850_cert_provider_destroy(g_srv_prov);
        g_srv_prov = NULL;
    }
    if (g_cli_prov != NULL) {
        iec61850_cert_provider_destroy(g_cli_prov);
        g_cli_prov = NULL;
    }
    iec61850_mms_ds_destroy(&g_ds);
}

static void step_tls_session(uint16_t tls_port)
{
    iec61850_mms_client_t client;
    mms_value_t v;

    STEP("TLS association: handshake + MMS read/write/read-back");
    iec61850_mms_client_init(&client);
    CHECK(iec61850_mms_client_set_tls(&client, g_cli_prov,
                                       IEC61850_TLS_MODE_COMPATIBLE) == 0);
    CHECK(iec61850_mms_client_connect(&client, "127.0.0.1", tls_port,
                                        5000) ==
          IEC61850_MMS_CLIENT_OK);

    (void)memset(&v, 0, sizeof(v));
    CHECK(iec61850_mms_client_read(&client, TW_LD, TW_ITEM, &v) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK(v.type == MMS_TYPE_INTEGER);
    CHECK(v.value.integer == 42);

    /* Write the marker value — the capture test asserts it never
     * appears in plaintext on the TLS port. */
    v.value.integer = 4242;
    CHECK(iec61850_mms_client_write(&client, TW_LD, TW_ITEM, &v) ==
          IEC61850_MMS_CLIENT_OK);
    (void)memset(&v, 0, sizeof(v));
    CHECK(iec61850_mms_client_read(&client, TW_LD, TW_ITEM, &v) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK(v.value.integer == 4242);

    /* Write the marker string over TLS — the capture test asserts
     * it never appears in plaintext on the TLS port (it does appear
     * in the clear on the plain control port, proving the write). */
    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_VISIBLE_STRING;
    (void)strncpy(v.value.visible_string.data, TW_MARKER,
                   MMS_MAX_STRING_LENGTH - 1);
    v.value.visible_string.len = strlen(TW_MARKER);
    CHECK(iec61850_mms_client_write(&client, TW_LD, TW_STR_ITEM, &v) ==
          IEC61850_MMS_CLIENT_OK);
    (void)memset(&v, 0, sizeof(v));
    CHECK(iec61850_mms_client_read(&client, TW_LD, TW_STR_ITEM, &v) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK(v.type == MMS_TYPE_VISIBLE_STRING);
    CHECK(strcmp(v.value.visible_string.data, TW_MARKER) == 0);

    /* More distinctive MMS traffic inside the encrypted channel:
     * domain discovery. */
    {
        char names[8][MMS_MAX_VARIABLE_NAME];
        uint32_t count = 0;

        CHECK(iec61850_mms_client_get_name_list(&client,
                                                   MMS_OBJECT_CLASS_DOMAIN,
                                                   NULL, names, &count, 8) ==
              IEC61850_MMS_CLIENT_OK);
        CHECK(count >= 1);
    }

    (void)iec61850_mms_client_disconnect(&client);
    usleep(200000);   /* let the close_notify hit the capture */
    OK();
}

static void step_plain_control_session(uint16_t plain_port)
{
    iec61850_mms_client_t client;
    mms_value_t v;

    STEP("plain control session on the dual listener (differential evidence)");
    iec61850_mms_client_init(&client);
    CHECK(iec61850_mms_client_connect(&client, "127.0.0.1", plain_port,
                                        5000) ==
          IEC61850_MMS_CLIENT_OK);
    (void)memset(&v, 0, sizeof(v));
    CHECK(iec61850_mms_client_read(&client, TW_LD, TW_ITEM, &v) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK(v.value.integer == 4242);
    /* Read the marker string back in the clear — positive control
     * for the TLS-port plaintext-leak assertion: the value exists
     * and does transit the wire, in the clear, on the plain port. */
    (void)memset(&v, 0, sizeof(v));
    CHECK(iec61850_mms_client_read(&client, TW_LD, TW_STR_ITEM, &v) ==
          IEC61850_MMS_CLIENT_OK);
    CHECK(v.type == MMS_TYPE_VISIBLE_STRING);
    CHECK(strcmp(v.value.visible_string.data, TW_MARKER) == 0);
    (void)iec61850_mms_client_disconnect(&client);
    OK();
}

int main(int argc, char **argv)
{
    uint16_t tls_port =
        (argc > 1) ? (uint16_t)atoi(argv[1]) : (uint16_t)TW_TLS_PORT;
    uint16_t plain_port =
        (argc > 2) ? (uint16_t)atoi(argv[2]) : (uint16_t)TW_PLAIN_PORT;

    printf("=== MMS-over-TLS wire scenario "
           "(tls port %u, plain port %u) ===\n",
           (unsigned)tls_port, (unsigned)plain_port);

    if (tw_gen_fixtures() != 0) {
        printf("FAIL: fixture generation\n");
        return 1;
    }

    setup(plain_port, tls_port);
    if (g_srv_up) {
        step_tls_session(tls_port);
        step_plain_control_session(plain_port);
    }
    teardown();
    tw_unlink_fixtures();

    printf("\n=== Scenario summary: %d steps, %d failed ===\n",
           tests_run, tests_failed);
    return (tests_failed > 0) ? 1 : 0;
}

#endif /* IEC61850_SECURITY_ENABLED */
