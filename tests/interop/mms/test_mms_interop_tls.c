/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Interop Test: MMS-over-TLS (IEC 62351-4) — xdp-iec61850 ↔ libiec61850
 *
 * WP-3d (tls-interop). Best-effort by design: the oracle's TLS
 * support depends on how its build was configured and on which
 * example programs were compiled. Every scenario that cannot run
 * SKIPs with a documented reason instead of failing.
 *
 * CLEAN ROOM: the oracle is treated as a black box. The capability
 * discovery below works purely from binary observation — example
 * binary names, the imported-symbol tables of the built example
 * executables (nm -uC), and observed wire behavior. No oracle
 * source is read.
 *
 * Scenario matrix (MT series):
 *
 *   MT-01  Oracle TLS capability discovery (black box). Scans the
 *          oracle build's example executables for TLS wiring: an
 *          example "wires MMS TLS" when its imported symbols
 *          reference the libiec61850 MMS TLS entry points
 *          (IedServer_createWithTlsSupport / IedConnection_
 *          createWithTlsSupport / Mms[Server|Connection]_
 *          setTLSConfiguration / IsoServer_setTLSConfiguration).
 *          PASSes when the probe ran; the findings gate MT-02..05.
 *
 *   MT-02  Our client, COMPATIBLE mode → oracle TLS server.
 *   MT-03  Our client, STRICT_62351 mode → oracle TLS server.
 *   MT-04  Our client, SPIFFE mode → oracle TLS server.
 *          Each connects, performs an MMS read, disconnects.
 *
 *   MT-05  Oracle TLS client → our dual-listener TLS server
 *          (TLS listener port 3782), full session + read.
 *
 *   MT-06  Self baseline: our client COMPATIBLE → our TLS server.
 *   MT-07  Self baseline: our client STRICT_62351 → our TLS server.
 *   MT-08  Self baseline: our client SPIFFE → our TLS server.
 *          These validate the exact credential matrix the oracle
 *          scenarios would use, so that an oracle-direction SKIP
 *          is attributable to the oracle build and not to our
 *          configuration. They run whenever this build has
 *          security enabled (-Denable_security=true).
 *
 * Interop matrix vs the current oracle build
 * (libiec61850 1.6.2, ~/Code/github.com/mz-automation/libiec61850/build):
 *
 *   - The oracle static archive (libiec61850.a) carries the TLS API
 *     symbols (mbedtls 2.28 is linked in: CONFIG_EXTERNAL_MBEDTLS_*
 *     paths in the CMake cache) — the library itself is TLS-capable.
 *   - NO example executable in the build wires MMS TLS: none of the
 *     ~35 example binaries imports any of the MMS TLS entry points
 *     or any mbedtls symbol; no example name mentions TLS; the
 *     mms_utility command line has no TLS options. libiec61850's
 *     MMS TLS is an API-only feature (IedServer_createWithTlsSupport
 *     & friends) with no example program in this build.
 *
 *   Consequence: MT-02, MT-03, MT-04 and MT-05 SKIP with that
 *   reason (probed at runtime by MT-01, so a future oracle build
 *   with TLS examples flips them on automatically). MT-01 and the
 *   MT-06..08 self baselines run. Wire-level validation of our own
 *   TLS MMS session (record structure, SNI/ALPN policy, plaintext
 *   leakage) lives in tests/interop/wire/test_wire_mms_tls.sh.
 *
 *   What WOULD be needed for the oracle directions to interoperate
 *   (documented for when an oracle build provides TLS examples):
 *     - an oracle server example calling IedServer_createWithTls-
 *       Support or MmsServer_setTLSConfiguration with mbedtls
 *       TLS 1.2 (mbedtls 2.28 has no TLS 1.3 — our COMPATIBLE mode
 *       negotiates TLS 1.2 down from its 1.2 minimum, no SNI/ALPN
 *       is required by our client);
 *     - a certificate chain our COMPATIBLE client trust store
 *       validates (any X.509 chain; STRICT_62351 additionally needs
 *       RSA>=2048 / EC>=P-256 keys inside the validity window,
 *       SPIFFE needs a spiffe:// URI SAN);
 *     - an oracle client example with TLS for MT-05, presented with
 *       our server certificate (RSA-2048 leaf under a test CA,
 *       generated per the WP-3b/WP-3a fixture conventions).
 *
 * No root needed (TCP loopback). Requires: LIBIEC61850_BUILD_DIR set
 * or default path exists. Scenarios MT-02..08 additionally need a
 * security-enabled build of this repository.
 */

#include "../interop_helpers.h"
#include "asn1/mms_ber.h"
#include "mms/mms_client.h"
#include "mms/mms_data_store.h"
#include "mms/mms_server.h"

#include <stdio.h>
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

/* Plain-listener ports for the scenarios we start ourselves. The
 * existing MMS interop tests use 104xx; the wire tests 106xx. */
static uint16_t g_port = 10700;

/* Oracle TLS capability discovery results (filled by MT-01). */
static char g_oracle_tls_server[600];   /* example path or "" */
static char g_oracle_tls_client[600];   /* example path or "" */
static bool g_discovery_done = false;

#ifdef IEC61850_SECURITY_ENABLED

/* ------------------------------------------------------------------ */
/* Test certificates (WP-3b/WP-3a fixture conventions — same OpenSSL  */
/* EVP generation pattern as tests/unit/test_tls_socket.c)            */
/* ------------------------------------------------------------------ */

static char f_ca_cert[128];
static char f_srv_key[128], f_srv_cert[128];       /* plain RSA-2048 leaf */
static char f_spiffe_key[128], f_spiffe_cert[128]; /* spiffe:// URI SAN leaf */
static char f_cli_key[128], f_cli_cert[128];       /* client leaf (URI SAN) */
static bool g_fixtures_ok = false;

static EVP_PKEY *mtl_gen_rsa_key(int bits)
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

static int mtl_add_ext(X509 *cert, int nid, const char *value)
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

/*
 * One certificate. issuer_cert/issuer_key NULL = self-signed.
 * uri_san adds a URI SAN entry; is_ca sets critical basicConstraints
 * CA:TRUE.
 */
static X509 *mtl_gen_cert(EVP_PKEY *subj_key, const X509 *issuer_cert,
                           EVP_PKEY *issuer_key, int serial, const char *cn,
                           bool is_ca, const char *uri_san)
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

    name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                (const unsigned char *)cn, -1, -1, 0);
    X509_set_subject_name(cert, name);

    if (issuer_cert != NULL) {
        X509_set_issuer_name(cert, X509_get_subject_name(
                                 (X509 *)issuer_cert));
    } else {
        X509_set_issuer_name(cert, name);
        sign_key = subj_key;
    }

    if (is_ca && (mtl_add_ext(cert, NID_basic_constraints,
                                "critical,CA:TRUE") != 0)) {
        X509_free(cert);
        return NULL;
    }
    if (uri_san != NULL) {
        char san[256];
        (void)snprintf(san, sizeof(san), "URI:%s", uri_san);
        if (mtl_add_ext(cert, NID_subject_alt_name, san) != 0) {
            X509_free(cert);
            return NULL;
        }
    }

    if (X509_sign(cert, sign_key, EVP_sha256()) <= 0) {
        X509_free(cert);
        ERR_clear_error();
        return NULL;
    }
    return cert;
}

static int mtl_write_key(const char *path, EVP_PKEY *key)
{
    FILE *f = fopen(path, "w");

    if (f == NULL) { return -1; }
    PEM_write_PrivateKey(f, key, NULL, NULL, 0, NULL, NULL);
    fclose(f);
    return 0;
}

static int mtl_write_cert(const char *path, X509 *cert)
{
    FILE *f = fopen(path, "w");

    if (f == NULL) { return -1; }
    PEM_write_X509(f, cert);
    fclose(f);
    return 0;
}

static void mtl_unlink_fixtures(void)
{
    (void)unlink(f_ca_cert);
    (void)unlink(f_srv_key);
    (void)unlink(f_srv_cert);
    (void)unlink(f_spiffe_key);
    (void)unlink(f_spiffe_cert);
    (void)unlink(f_cli_key);
    (void)unlink(f_cli_cert);
}

/*
 * CA + three leaves:
 *   - server:      RSA-2048, no SAN   (COMPATIBLE / STRICT_62351)
 *   - spiffe server: RSA-2048, spiffe:// URI SAN (SPIFFE mode)
 *   - client:      RSA-2048, spiffe:// URI SAN — satisfies all three
 *     policies at once (COMPATIBLE tolerates it, STRICT_62351 checks
 *     only key type/size + validity, SPIFFE needs the URI SAN).
 */
static void mtl_gen_fixtures(void)
{
    EVP_PKEY *ca_key = mtl_gen_rsa_key(2048);
    EVP_PKEY *srv_key = mtl_gen_rsa_key(2048);
    EVP_PKEY *spiffe_key = mtl_gen_rsa_key(2048);
    EVP_PKEY *cli_key = mtl_gen_rsa_key(2048);
    X509 *ca = NULL, *srv = NULL, *spiffe = NULL, *cli = NULL;

    (void)snprintf(f_ca_cert, sizeof(f_ca_cert),
                   "/tmp/interop_tls_ca_%d.pem", (int)getpid());
    (void)snprintf(f_srv_key, sizeof(f_srv_key),
                   "/tmp/interop_tls_srv_key_%d.pem", (int)getpid());
    (void)snprintf(f_srv_cert, sizeof(f_srv_cert),
                   "/tmp/interop_tls_srv_cert_%d.pem", (int)getpid());
    (void)snprintf(f_spiffe_key, sizeof(f_spiffe_key),
                   "/tmp/interop_tls_spiffe_key_%d.pem", (int)getpid());
    (void)snprintf(f_spiffe_cert, sizeof(f_spiffe_cert),
                   "/tmp/interop_tls_spiffe_cert_%d.pem", (int)getpid());
    (void)snprintf(f_cli_key, sizeof(f_cli_key),
                   "/tmp/interop_tls_cli_key_%d.pem", (int)getpid());
    (void)snprintf(f_cli_cert, sizeof(f_cli_cert),
                   "/tmp/interop_tls_cli_cert_%d.pem", (int)getpid());

    if ((ca_key == NULL) || (srv_key == NULL) || (spiffe_key == NULL) ||
        (cli_key == NULL)) {
        goto done;
    }

    ca = mtl_gen_cert(ca_key, NULL, NULL, 1, "InteropTlsCA", true, NULL);
    if (ca == NULL) { goto done; }
    srv = mtl_gen_cert(srv_key, ca, ca_key, 2, "InteropTlsServer",
                        false, NULL);
    spiffe = mtl_gen_cert(spiffe_key, ca, ca_key, 3, "InteropTlsSpiffe",
                           false, "spiffe://example.org/ied/mms-server");
    cli = mtl_gen_cert(cli_key, ca, ca_key, 4, "InteropTlsClient",
                        false, "spiffe://example.org/ied/mms-client");
    if ((srv == NULL) || (spiffe == NULL) || (cli == NULL)) { goto done; }

    if ((mtl_write_cert(f_ca_cert, ca) != 0) ||
        (mtl_write_key(f_srv_key, srv_key) != 0) ||
        (mtl_write_cert(f_srv_cert, srv) != 0) ||
        (mtl_write_key(f_spiffe_key, spiffe_key) != 0) ||
        (mtl_write_cert(f_spiffe_cert, spiffe) != 0) ||
        (mtl_write_key(f_cli_key, cli_key) != 0) ||
        (mtl_write_cert(f_cli_cert, cli) != 0)) {
        goto done;
    }

    g_fixtures_ok = true;

done:
    EVP_PKEY_free(ca_key);
    EVP_PKEY_free(srv_key);
    EVP_PKEY_free(spiffe_key);
    EVP_PKEY_free(cli_key);
    X509_free(ca);
    X509_free(srv);
    X509_free(spiffe);
    X509_free(cli);
    ERR_clear_error();
    if (!g_fixtures_ok) {
        mtl_unlink_fixtures();
    }
}

/* ------------------------------------------------------------------ */
/* Our dual-listener TLS server (self baselines + MT-05 target)       */
/* ------------------------------------------------------------------ */

#define MTL_LD   "MTLD"
#define MTL_ITEM "GGIO1$ST$Ind1$stVal"

static iec61850_mms_data_store_t g_self_ds;
static iec61850_mms_server_t g_self_srv;
static bool g_self_up = false;
static iec61850_cert_provider_t *g_self_prov;

/*
 * Start our dual-listener server (plain + TLS) in the given
 * certificate-policy mode with the given server leaf. Returns 0 or
 * -1. mtl_server_stop() tears it down.
 */
static int mtl_server_start(uint16_t plain_port, uint16_t tls_port,
                             iec61850_tls_mode_t mode,
                             const char *cert_path, const char *key_path)
{
    iec61850_mms_server_config_t cfg;
    mms_value_t v;

    iec61850_mms_ds_init(&g_self_ds);
    (void)iec61850_mms_ds_create_domain(&g_self_ds, MTL_LD);

    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_INTEGER;
    v.value.integer = 42;
    (void)iec61850_mms_ds_create_variable(&g_self_ds, MTL_LD, MTL_ITEM,
                                           MMS_TYPE_INTEGER, &v);

    g_self_prov = iec61850_cert_provider_create_static(
        cert_path, key_path, f_ca_cert);
    if (g_self_prov == NULL) { return -1; }

    iec61850_mms_server_config_init(&cfg);
    cfg.port = plain_port;
    cfg.tls_enabled = true;
    cfg.tls_provider = g_self_prov;
    cfg.tls_mode = mode;
    cfg.tls_port = tls_port;
    cfg.tls_only = false;

    iec61850_mms_server_init(&g_self_srv, &cfg, &g_self_ds);
    if (iec61850_mms_server_start(&g_self_srv) != IEC61850_MMS_SERVER_OK) {
        iec61850_cert_provider_destroy(g_self_prov);
        g_self_prov = NULL;
        iec61850_mms_ds_destroy(&g_self_ds);
        return -1;
    }
    g_self_up = true;
    usleep(200000);
    return 0;
}

static void mtl_server_stop(void)
{
    if (g_self_up) {
        (void)iec61850_mms_server_stop(&g_self_srv);
        g_self_up = false;
    }
    if (g_self_prov != NULL) {
        iec61850_cert_provider_destroy(g_self_prov);
        g_self_prov = NULL;
    }
    iec61850_mms_ds_destroy(&g_self_ds);
}

/*
 * Drive one full TLS client session against tls_port in the given
 * mode: connect, read, write + read-back, disconnect. Returns 0
 * when the whole exchange succeeded.
 */
static int mtl_client_session(uint16_t tls_port, iec61850_tls_mode_t mode)
{
    iec61850_cert_provider_t *cli_prov = NULL;
    iec61850_mms_client_t client;
    mms_value_t v;
    int ret = -1;

    cli_prov = iec61850_cert_provider_create_static(
        f_cli_cert, f_cli_key, f_ca_cert);
    if (cli_prov == NULL) { return -1; }

    iec61850_mms_client_init(&client);
    if (iec61850_mms_client_set_tls(&client, cli_prov, mode) != 0) {
        goto out;
    }
    if (iec61850_mms_client_connect(&client, "127.0.0.1", tls_port,
                                      5000) != IEC61850_MMS_CLIENT_OK) {
        goto out;
    }

    (void)memset(&v, 0, sizeof(v));
    if ((iec61850_mms_client_read(&client, MTL_LD, MTL_ITEM, &v) !=
         IEC61850_MMS_CLIENT_OK) || (v.value.integer != 42)) {
        iec61850_mms_client_disconnect(&client);
        goto out;
    }

    v.value.integer = 43;
    if (iec61850_mms_client_write(&client, MTL_LD, MTL_ITEM, &v) !=
        IEC61850_MMS_CLIENT_OK) {
        iec61850_mms_client_disconnect(&client);
        goto out;
    }
    (void)memset(&v, 0, sizeof(v));
    if ((iec61850_mms_client_read(&client, MTL_LD, MTL_ITEM, &v) !=
         IEC61850_MMS_CLIENT_OK) || (v.value.integer != 43)) {
        iec61850_mms_client_disconnect(&client);
        goto out;
    }

    (void)iec61850_mms_client_disconnect(&client);
    ret = 0;

out:
    iec61850_cert_provider_destroy(cli_prov);
    return ret;
}

#endif /* IEC61850_SECURITY_ENABLED */

/* ------------------------------------------------------------------ */
/* Oracle TLS capability discovery (black box)                        */
/* ------------------------------------------------------------------ */

/*
 * Does this oracle example binary wire MMS TLS? Observed from the
 * binary's imported-symbol table (nm -uC) — never its source. An
 * MMS-TLS-wired example must import one of the libiec61850 MMS TLS
 * entry points.
 */
static bool oracle_binary_wires_mms_tls(const char *path)
{
    char cmd[1200];
    FILE *f;
    char line[512];
    bool found = false;

    (void)snprintf(cmd, sizeof(cmd), "nm -uC '%s' 2>/dev/null", path);
    f = popen(cmd, "r");
    if (f == NULL) { return false; }
    while (fgets(line, sizeof(line), f) != NULL) {
        if ((strstr(line, "TlsSupport") != NULL) ||
            (strstr(line, "setTLSConfiguration") != NULL)) {
            found = true;
            break;
        }
    }
    (void)pclose(f);
    return found;
}

/*
 * Scan the oracle build's example executables. Fills
 * g_oracle_tls_server / g_oracle_tls_client with the first matching
 * binary path (empty string when none). Client/server split by
 * binary name, the libiec61850 naming convention
 * (server_example_* vs iec61850_client_* / mms_utility).
 */
static void discover_oracle_tls(void)
{
    char cmd[700];
    FILE *f;
    char path[600];

    g_oracle_tls_server[0] = '\0';
    g_oracle_tls_client[0] = '\0';

    (void)snprintf(cmd, sizeof(cmd),
                   "find '%s/examples' -type f -executable 2>/dev/null",
                   g_libiec_build);
    f = popen(cmd, "r");
    if (f == NULL) { return; }

    while (fgets(path, sizeof(path), f) != NULL) {
        size_t len = strlen(path);

        if ((len > 0) && (path[len - 1] == '\n')) { path[len - 1] = '\0'; }
        if (!oracle_binary_wires_mms_tls(path)) { continue; }

        if (strstr(path, "server") != NULL) {
            if (g_oracle_tls_server[0] == '\0') {
                (void)snprintf(g_oracle_tls_server,
                               sizeof(g_oracle_tls_server), "%s", path);
            }
        } else {
            if (g_oracle_tls_client[0] == '\0') {
                (void)snprintf(g_oracle_tls_client,
                               sizeof(g_oracle_tls_client), "%s", path);
            }
        }
    }
    (void)pclose(f);
    g_discovery_done = true;
}

/* ------------------------------------------------------------------ */
/* Scenarios                                                           */
/* ------------------------------------------------------------------ */

/* MT-01: oracle TLS capability discovery (black box). The probe
 * itself is the test — its findings gate MT-02..MT-05. */
static void test_mt01_oracle_tls_discovery(void)
{
    INTEROP_TEST("MT-01: oracle TLS capability discovery (black box)");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");

    discover_oracle_tls();

    if (g_oracle_tls_server[0] != '\0') {
        printf("  .... oracle TLS server example: %s\n",
               g_oracle_tls_server);
    } else {
        printf("  .... no TLS-wired server example in the oracle build\n");
    }
    if (g_oracle_tls_client[0] != '\0') {
        printf("  .... oracle TLS client example: %s\n",
               g_oracle_tls_client);
    } else {
        printf("  .... no TLS-wired client example in the oracle build\n");
    }
    INTEROP_PASS();
}

/*
 * MT-02..MT-04 shared body: our client in the given certificate-
 * policy mode against the oracle's TLS server example. Skips when
 * the oracle build provides none (the current case — see the file
 * header interop matrix).
 */
static void mt_oracle_server_scenario(const char *id,
                                       iec61850_tls_mode_t mode)
{
    INTEROP_TEST(id);
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");
#ifndef IEC61850_SECURITY_ENABLED
    (void)mode;
    INTEROP_SKIP("built without -Denable_security=true");
#else
    char port_str[16];
    char *args[3];
    pid_t srv = -1;
    if (!g_discovery_done) { discover_oracle_tls(); }
    if (g_oracle_tls_server[0] == '\0') {
        INTEROP_SKIP("oracle build has no TLS-capable MMS server example "
                     "(MT-01 black-box discovery: no example binary "
                     "imports the libiec61850 MMS TLS server API)");
    }
    if (!g_fixtures_ok) {
        INTEROP_SKIP("client credential fixtures unavailable");
    }

    /* Best-effort driver for a future oracle TLS server example:
     * the libiec61850 example convention is "<binary> <tcp-port>".
     * Credential wiring (cert/key paths) is oracle-specific; if the
     * example needs more than a port, this will need extending when
     * such an example first appears in an oracle build. */
    (void)snprintf(port_str, sizeof(port_str), "%u", g_port);
    args[0] = g_oracle_tls_server;
    args[1] = port_str;
    args[2] = NULL;
    srv = interop_start_bg(g_oracle_tls_server, args, NULL);
    if ((srv < 0) || !interop_wait_for_port(g_port, 5000)) {
        if (srv > 0) { interop_stop_helper(srv); }
        g_port++;
        INTEROP_FAIL("oracle TLS server did not listen");
    }

    {
        iec61850_cert_provider_t *cli_prov =
            iec61850_cert_provider_create_static(
                f_cli_cert, f_cli_key, f_ca_cert);
        iec61850_mms_client_t client;
        bool ok = false;

        iec61850_mms_client_init(&client);
        if ((cli_prov != NULL) &&
            (iec61850_mms_client_set_tls(&client, cli_prov, mode) == 0) &&
            (iec61850_mms_client_connect(&client, "127.0.0.1", g_port,
                                           5000) ==
             IEC61850_MMS_CLIENT_OK)) {
            /* The oracle's model differs from ours; the interop
             * requirement is the association + one MMS exchange,
             * so a GetNameList (domains) is the portable read. */
            char names[8][MMS_MAX_VARIABLE_NAME];
            uint32_t count = 0;

            ok = iec61850_mms_client_get_name_list(
                     &client, MMS_OBJECT_CLASS_DOMAIN, NULL,
                     names, &count, 8) == IEC61850_MMS_CLIENT_OK;
            (void)iec61850_mms_client_disconnect(&client);
        }
        if (cli_prov != NULL) {
            iec61850_cert_provider_destroy(cli_prov);
        }

        interop_stop_helper(srv);
        g_port++;
        if (!ok) INTEROP_FAIL("TLS association or MMS exchange failed");
    }
    INTEROP_PASS();
#endif
}

/* MT-02: our client, COMPATIBLE mode → oracle TLS server */
static void test_mt02_oracle_tls_compatible(void)
{
    mt_oracle_server_scenario(
        "MT-02: our client COMPATIBLE -> oracle TLS server",
        IEC61850_TLS_MODE_COMPATIBLE);
}

/* MT-03: our client, STRICT_62351 mode → oracle TLS server */
static void test_mt03_oracle_tls_strict(void)
{
    mt_oracle_server_scenario(
        "MT-03: our client STRICT_62351 -> oracle TLS server",
        IEC61850_TLS_MODE_STRICT_62351);
}

/* MT-04: our client, SPIFFE mode → oracle TLS server */
static void test_mt04_oracle_tls_spiffe(void)
{
    mt_oracle_server_scenario(
        "MT-04: our client SPIFFE -> oracle TLS server",
        IEC61850_TLS_MODE_SPIFFE);
}

/* MT-05: oracle TLS client → our TLS server (port 3782) */
static void test_mt05_oracle_client_our_server(void)
{
    INTEROP_TEST("MT-05: oracle TLS client -> our TLS server (3782)");
    if (!interop_check_prerequisites()) INTEROP_SKIP("libiec61850 not found");
#ifndef IEC61850_SECURITY_ENABLED
    INTEROP_SKIP("built without -Denable_security=true");
#else
    if (!g_discovery_done) { discover_oracle_tls(); }
    if (g_oracle_tls_client[0] == '\0') {
        INTEROP_SKIP("oracle build has no TLS-capable MMS client example "
                     "(MT-01 black-box discovery: no example binary "
                     "imports the libiec61850 MMS TLS client API)");
    }
    if (!g_fixtures_ok) {
        INTEROP_SKIP("server credential fixtures unavailable");
    }

    /* Our dual-listener server on the IEC 62351-4 TLS port (3782),
     * COMPATIBLE policy so the widest set of oracle client
     * credential profiles is accepted. Our server certificate is
     * an RSA-2048 leaf under the test CA (WP-3b fixture
     * conventions). */
    if (mtl_server_start(g_port, IEC61850_TLS_MMS_PORT_DEFAULT,
                          IEC61850_TLS_MODE_COMPATIBLE,
                          f_srv_cert, f_srv_key) != 0) {
        g_port++;
        INTEROP_FAIL("our TLS server start failed");
    }

    /* Best-effort driver for a future oracle TLS client example:
     * mms_utility-style command line (-h host -p port). */
    {
        char port_str[16];
        char *args[6];
        char output[4096];
        int rc;

        (void)snprintf(port_str, sizeof(port_str), "%u",
                       (unsigned)IEC61850_TLS_MMS_PORT_DEFAULT);
        args[0] = g_oracle_tls_client;
        args[1] = "-h";
        args[2] = "127.0.0.1";
        args[3] = "-p";
        args[4] = port_str;
        args[5] = NULL;
        rc = interop_run_program(g_oracle_tls_client, args, output,
                                  sizeof(output), 10000);

        mtl_server_stop();
        g_port++;
        /* rc==1 is mms_utility's connect-failed convention. */
        INTEROP_ASSERT(rc != 1);
    }
    INTEROP_PASS();
#endif
}

#ifdef IEC61850_SECURITY_ENABLED

/* MT-06..MT-08 shared body: self baseline in one policy mode. This
 * is the credential matrix the oracle scenarios would use, proven
 * against our own dual-listener server, so oracle-direction SKIPs
 * are attributable to the oracle build alone. */
static void mt_self_scenario(const char *id, iec61850_tls_mode_t mode,
                              const char *srv_cert, const char *srv_key)
{
    uint16_t tls_port = (uint16_t)(g_port + 400);

    INTEROP_TEST(id);
    if (!g_fixtures_ok) INTEROP_SKIP("credential fixtures unavailable");

    if (mtl_server_start(g_port, tls_port, mode, srv_cert, srv_key) != 0) {
        g_port++;
        INTEROP_FAIL("our TLS server start failed");
    }

    {
        int ret = mtl_client_session(tls_port, mode);

        mtl_server_stop();
        g_port++;
        if (ret != 0) INTEROP_FAIL("TLS session (connect/read/write) failed");
    }
    INTEROP_PASS();
}

#endif

/* MT-06: self baseline — COMPATIBLE */
static void test_mt06_self_compatible(void)
{
#ifdef IEC61850_SECURITY_ENABLED
    mt_self_scenario("MT-06: self baseline COMPATIBLE (our client/server)",
                      IEC61850_TLS_MODE_COMPATIBLE, f_srv_cert, f_srv_key);
#else
    INTEROP_TEST("MT-06: self baseline COMPATIBLE (our client/server)");
    INTEROP_SKIP("built without -Denable_security=true");
#endif
}

/* MT-07: self baseline — STRICT_62351 */
static void test_mt07_self_strict(void)
{
#ifdef IEC61850_SECURITY_ENABLED
    mt_self_scenario("MT-07: self baseline STRICT_62351 (our client/server)",
                      IEC61850_TLS_MODE_STRICT_62351, f_srv_cert, f_srv_key);
#else
    INTEROP_TEST("MT-07: self baseline STRICT_62351 (our client/server)");
    INTEROP_SKIP("built without -Denable_security=true");
#endif
}

/* MT-08: self baseline — SPIFFE */
static void test_mt08_self_spiffe(void)
{
#ifdef IEC61850_SECURITY_ENABLED
    mt_self_scenario("MT-08: self baseline SPIFFE (our client/server)",
                      IEC61850_TLS_MODE_SPIFFE,
                      f_spiffe_cert, f_spiffe_key);
#else
    INTEROP_TEST("MT-08: self baseline SPIFFE (our client/server)");
    INTEROP_SKIP("built without -Denable_security=true");
#endif
}

int main(void)
{
    printf("\n=== MMS TLS Interop Tests (IEC 62351-4): "
           "xdp-iec61850 <-> libiec61850 ===\n");

#ifndef IEC61850_SECURITY_ENABLED
    (void)g_port;   /* only referenced by security-enabled scenarios */
#else
    mtl_gen_fixtures();
#endif

    test_mt01_oracle_tls_discovery();
    test_mt02_oracle_tls_compatible();
    test_mt03_oracle_tls_strict();
    test_mt04_oracle_tls_spiffe();
    test_mt05_oracle_client_our_server();
    test_mt06_self_compatible();
    test_mt07_self_strict();
    test_mt08_self_spiffe();

#ifdef IEC61850_SECURITY_ENABLED
    mtl_unlink_fixtures();
#endif

    INTEROP_SUMMARY();
    return interop_tests_failed > 0 ? 1 : 0;
}
