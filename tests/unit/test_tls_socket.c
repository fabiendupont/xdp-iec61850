/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for the TLS Socket Layer (IEC 62351-4, WP-3b)
 *
 * Tests: handshake round-trip over loopback (echo server on a
 * thread), the certificate-policy mode matrix (COMPATIBLE accepts
 * a trusted chain and tolerates weak profiles; STRICT_62351
 * enforces the key type/size + validity profile; SPIFFE requires
 * a spiffe:// URI SAN), untrusted-CA rejection, opportunistic
 * (provider-less) COMPATIBLE handshakes, send/recv/recv_exact/
 * recv_tpkt over TLS, recv timeout, plain-TCP-to-TLS-listener
 * rejection, argument/contract checks and disconnect cleanup.
 *
 * Test keys/certs are generated at start via the OpenSSL EVP API —
 * same pattern as test_cert_provider.c:
 *   - CA1/CA2: RSA-2048 self-signed CAs (basicConstraints CA:TRUE)
 *   - server:  RSA-2048 leaf signed by CA1 (no SAN)
 *   - weak:    RSA-1024 leaf signed by CA1 (STRICT profile reject)
 *   - expired: RSA-2048 leaf signed by CA1, notAfter in the past
 *   - spiffe:  RSA-2048 leaf signed by CA1 with a
 *              spiffe:// URI SAN
 *   - rogue:   RSA-2048 leaf signed by CA2 (untrusted CA)
 *
 * License: BSD-2-Clause
 */

#include "transport/tls_socket.h"
#include "transport/iso_stack.h"
#include "security/cert_provider.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { tests_run++; printf("  [TEST] %s ... ", name); } while (0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg) do { tests_failed++; printf("FAIL: %s\n", msg); return; } while (0)
#define ASSERT_EQ(a, b) do { if ((a) != (b)) { \
    printf("FAIL: %s == %s (%d != %d)\n", #a, #b, (int)(a), (int)(b)); \
    tests_failed++; return; } } while (0)
#define ASSERT_TRUE(cond) do { if (!(cond)) { FAIL(#cond); } } while (0)

/* ------------------------------------------------------------------ */
/* Fixture paths                                                       */
/* ------------------------------------------------------------------ */

static char f_ca1_key[128], f_ca1_cert[128];
static char f_ca2_key[128], f_ca2_cert[128];
static char f_srv_key[128], f_srv_cert[128];
static char f_weak_key[128], f_weak_cert[128];
static char f_exp_key[128], f_exp_cert[128];
static char f_spiffe_key[128], f_spiffe_cert[128];
static char f_rogue_key[128], f_rogue_cert[128];

/* ------------------------------------------------------------------ */
/* Certificate generation                                              */
/* ------------------------------------------------------------------ */

static EVP_PKEY *gen_rsa_key(int bits)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *key = NULL;

    if (ctx == NULL) { return NULL; }
    if (EVP_PKEY_keygen_init(ctx) <= 0) { goto out; }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0) { goto out; }
    if (EVP_PKEY_keygen(ctx, &key) <= 0) { goto out; }
    ERR_clear_error();

out:
    EVP_PKEY_CTX_free(ctx);
    return key;
}

static int add_ext(X509 *cert, int nid, const char *value)
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
 * Generate one certificate. issuer_cert/issuer_key NULL = self-
 * signed. uri_san adds a URI SAN entry; is_ca sets critical
 * basicConstraints CA:TRUE. not_before_off/not_after_off are
 * second offsets from now (negative = past).
 */
static X509 *gen_cert(EVP_PKEY *subj_key, const X509 *issuer_cert,
                       EVP_PKEY *issuer_key, int serial, const char *cn,
                       bool is_ca, const char *uri_san,
                       long not_before_off, long not_after_off)
{
    X509 *cert = X509_new();
    X509_NAME *name;
    EVP_PKEY *sign_key = issuer_key;

    if (cert == NULL) { return NULL; }

    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);
    X509_gmtime_adj(X509_get_notBefore(cert), not_before_off);
    X509_gmtime_adj(X509_get_notAfter(cert), not_after_off);
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

    if (is_ca && (add_ext(cert, NID_basic_constraints,
                            "critical,CA:TRUE") != 0)) {
        X509_free(cert);
        return NULL;
    }
    if (uri_san != NULL) {
        char san[256];
        (void)snprintf(san, sizeof(san), "URI:%s", uri_san);
        if (add_ext(cert, NID_subject_alt_name, san) != 0) {
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

static int write_key(const char *path, EVP_PKEY *key)
{
    FILE *f = fopen(path, "w");
    if (f == NULL) { return -1; }
    PEM_write_PrivateKey(f, key, NULL, NULL, 0, NULL, NULL);
    fclose(f);
    return 0;
}

static int write_cert(const char *path, X509 *cert)
{
    FILE *f = fopen(path, "w");
    if (f == NULL) { return -1; }
    PEM_write_X509(f, cert);
    fclose(f);
    return 0;
}

static int generate_fixtures(void)
{
    EVP_PKEY *ca1_key = gen_rsa_key(2048);
    EVP_PKEY *ca2_key = gen_rsa_key(2048);
    EVP_PKEY *srv_key = gen_rsa_key(2048);
    EVP_PKEY *weak_key = gen_rsa_key(1024);
    EVP_PKEY *exp_key = gen_rsa_key(2048);
    EVP_PKEY *spiffe_key = gen_rsa_key(2048);
    EVP_PKEY *rogue_key = gen_rsa_key(2048);
    X509 *ca1_cert = NULL;
    X509 *ca2_cert = NULL;
    X509 *srv_cert = NULL;
    X509 *weak_cert = NULL;
    X509 *exp_cert = NULL;
    X509 *spiffe_cert = NULL;
    X509 *rogue_cert = NULL;
    int ok = -1;

    if ((ca1_key == NULL) || (ca2_key == NULL) || (srv_key == NULL) ||
        (weak_key == NULL) || (exp_key == NULL) || (spiffe_key == NULL) ||
        (rogue_key == NULL)) {
        goto done;
    }

    ca1_cert = gen_cert(ca1_key, NULL, NULL, 1, "TestCA1", true, NULL,
                          0, 365L * 24 * 3600);
    ca2_cert = gen_cert(ca2_key, NULL, NULL, 2, "TestCA2", true, NULL,
                          0, 365L * 24 * 3600);
    if ((ca1_cert == NULL) || (ca2_cert == NULL)) { goto done; }

    srv_cert = gen_cert(srv_key, ca1_cert, ca1_key, 3, "TestServer",
                          false, NULL, 0, 365L * 24 * 3600);
    weak_cert = gen_cert(weak_key, ca1_cert, ca1_key, 4, "WeakServer",
                           false, NULL, 0, 365L * 24 * 3600);
    exp_cert = gen_cert(exp_key, ca1_cert, ca1_key, 5, "ExpiredServer",
                          false, NULL, -2L * 24 * 3600, -24L * 3600);
    spiffe_cert = gen_cert(spiffe_key, ca1_cert, ca1_key, 6,
                             "SpiffeServer", false,
                             "spiffe://example.org/ied/mms",
                             0, 365L * 24 * 3600);
    rogue_cert = gen_cert(rogue_key, ca2_cert, ca2_key, 7,
                            "RogueServer", false, NULL,
                            0, 365L * 24 * 3600);

    if ((srv_cert == NULL) || (weak_cert == NULL) || (exp_cert == NULL) ||
        (spiffe_cert == NULL) || (rogue_cert == NULL)) {
        goto done;
    }

    if ((write_key(f_ca1_key, ca1_key) != 0) ||
        (write_cert(f_ca1_cert, ca1_cert) != 0) ||
        (write_key(f_ca2_key, ca2_key) != 0) ||
        (write_cert(f_ca2_cert, ca2_cert) != 0) ||
        (write_key(f_srv_key, srv_key) != 0) ||
        (write_cert(f_srv_cert, srv_cert) != 0) ||
        (write_key(f_weak_key, weak_key) != 0) ||
        (write_cert(f_weak_cert, weak_cert) != 0) ||
        (write_key(f_exp_key, exp_key) != 0) ||
        (write_cert(f_exp_cert, exp_cert) != 0) ||
        (write_key(f_spiffe_key, spiffe_key) != 0) ||
        (write_cert(f_spiffe_cert, spiffe_cert) != 0) ||
        (write_key(f_rogue_key, rogue_key) != 0) ||
        (write_cert(f_rogue_cert, rogue_cert) != 0)) {
        goto done;
    }

    ok = 0;

done:
    EVP_PKEY_free(ca1_key);
    EVP_PKEY_free(ca2_key);
    EVP_PKEY_free(srv_key);
    EVP_PKEY_free(weak_key);
    EVP_PKEY_free(exp_key);
    EVP_PKEY_free(spiffe_key);
    EVP_PKEY_free(rogue_key);
    X509_free(ca1_cert);
    X509_free(ca2_cert);
    X509_free(srv_cert);
    X509_free(weak_cert);
    X509_free(exp_cert);
    X509_free(spiffe_cert);
    X509_free(rogue_cert);
    ERR_clear_error();
    return ok;
}

static void cleanup_fixtures(void)
{
    (void)unlink(f_ca1_key); (void)unlink(f_ca1_cert);
    (void)unlink(f_ca2_key); (void)unlink(f_ca2_cert);
    (void)unlink(f_srv_key); (void)unlink(f_srv_cert);
    (void)unlink(f_weak_key); (void)unlink(f_weak_cert);
    (void)unlink(f_exp_key); (void)unlink(f_exp_cert);
    (void)unlink(f_spiffe_key); (void)unlink(f_spiffe_cert);
    (void)unlink(f_rogue_key); (void)unlink(f_rogue_cert);
}

/* ------------------------------------------------------------------ */
/* Echo server on a thread                                             */
/* ------------------------------------------------------------------ */

typedef struct {
    iec61850_tls_listener_t listener;  /* bound by _start() */
    iec61850_cert_provider_t *provider;
    pthread_t thread;
    uint16_t port;
    int accept_rc;
    int echo_rc;
    bool running;
} echo_server_t;

static void *echo_thread(void *arg)
{
    echo_server_t *es = (echo_server_t *)arg;
    iec61850_tls_conn_t conn;

    iec61850_tls_conn_init(&conn);
    es->accept_rc = iec61850_tls_listener_accept(&es->listener, &conn,
                                                   10000);
    if (es->accept_rc != 0) {
        return NULL;
    }

    /* Raw echo: whatever arrives is sent back (the TPKT-framed
     * client scenarios reassemble the echoed bytes themselves). */
    for (;;) {
        uint8_t buf[8192];
        int n = iec61850_tls_recv(&conn, buf, sizeof(buf), 5000);
        if (n < 0) {
            es->echo_rc = n;
            break;
        }
        if (iec61850_tls_send(&conn, buf, (size_t)n) < 0) {
            es->echo_rc = IEC61850_TRANSPORT_ERR_SEND;
            break;
        }
    }

    (void)iec61850_tls_disconnect(&conn);
    return NULL;
}

/* Distinct ports per test — ephemeral binding (port 0) with the
 * assigned port retrieved via getsockname; no cross-process
 * collisions regardless of TIME_WAIT state or PID overlap. */
static int echo_server_start(echo_server_t *es, const char *cert_path,
                               const char *key_path, const char *trust_path,
                               iec61850_tls_mode_t mode)
{
    struct sockaddr_in assigned;
    socklen_t alen = sizeof(assigned);

    iec61850_tls_listener_init(&es->listener);
    es->provider = NULL;
    es->accept_rc = -1;
    es->echo_rc = 0;
    es->running = false;

    es->provider = iec61850_cert_provider_create_static(cert_path,
                                                          key_path,
                                                          trust_path);
    if (es->provider == NULL) { return -1; }

    /* Ephemeral port: bind 0, then read back the kernel assignment. */
    es->port = 0;
    if (iec61850_tls_listener_bind(&es->listener, es->port,
                                     es->provider, mode) != 0) {
        iec61850_cert_provider_destroy(es->provider);
        es->provider = NULL;
        return -1;
    }

    if ((getsockname(es->listener.tcp.sockfd,
                     (struct sockaddr *)&assigned, &alen) != 0) ||
        (assigned.sin_family != AF_INET)) {
        (void)iec61850_tls_listener_close(&es->listener);
        iec61850_cert_provider_destroy(es->provider);
        es->provider = NULL;
        return -1;
    }
    es->port = ntohs(assigned.sin_port);

    if (pthread_create(&es->thread, NULL, echo_thread, es) != 0) {
        (void)iec61850_tls_listener_close(&es->listener);
        iec61850_cert_provider_destroy(es->provider);
        es->provider = NULL;
        return -1;
    }

    es->running = true;
    return 0;
}

static void echo_server_stop(echo_server_t *es)
{
    if (es->running) {
        (void)pthread_join(es->thread, NULL);
        es->running = false;
    }
    (void)iec61850_tls_listener_close(&es->listener);
    if (es->provider != NULL) {
        iec61850_cert_provider_destroy(es->provider);
        es->provider = NULL;
    }
}

/* Client-side connect helper: trust-only provider. */
static int trust_only_connect(iec61850_tls_conn_t *conn, uint16_t port,
                               const char *trust_path,
                               iec61850_tls_mode_t mode)
{
    iec61850_cert_provider_t *p =
        iec61850_cert_provider_create_static(NULL, NULL, trust_path);
    int ret;

    if (p == NULL) { return IEC61850_TRANSPORT_ERR_ARGS; }
    ret = iec61850_tls_connect(conn, "127.0.0.1", port, 5000, p, mode);
    iec61850_cert_provider_destroy(p);
    return ret;
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

static void test_handshake_roundtrip(void)
{
    echo_server_t es;
    iec61850_tls_conn_t conn;
    uint8_t out[256];
    uint8_t in[512];
    uint8_t tpkt_in[600];
    uint8_t payload[100];
    int ret;
    size_t i;
    bool ok = true;

    TEST("handshake_roundtrip");

    if (echo_server_start(&es, f_srv_cert, f_srv_key, f_ca1_cert,
                            IEC61850_TLS_MODE_COMPATIBLE) != 0) {
        FAIL("echo server start");
        return;
    }

    iec61850_tls_conn_init(&conn);
    ret = trust_only_connect(&conn, es.port, f_ca1_cert,
                               IEC61850_TLS_MODE_COMPATIBLE);
    if (ret != 0) {
        printf("(connect %d) ", ret);
        ok = false;
        goto done;
    }
    if (!iec61850_tls_is_connected(&conn)) {
        ok = false;
        goto done;
    }

    /* Raw send / recv_exact echo */
    for (i = 0; i < sizeof(out); i++) {
        out[i] = (uint8_t)(i & 0xFFU);
    }
    ret = iec61850_tls_send(&conn, out, sizeof(out));
    if (ret != (int)sizeof(out)) {
        ok = false;
        goto done;
    }
    ret = iec61850_tls_recv_exact(&conn, in, sizeof(out), 3000);
    if ((ret != (int)sizeof(out)) ||
        (memcmp(out, in, sizeof(out)) != 0)) {
        ok = false;
        goto done;
    }

    /* TPKT frame echo */
    for (i = 0; i < sizeof(payload); i++) {
        payload[i] = (uint8_t)(0xA0U ^ (uint8_t)i);
    }
    ret = iec61850_tpkt_encode(out, sizeof(out), payload,
                                sizeof(payload));
    if (ret < 0) {
        ok = false;
        goto done;
    }
    if (iec61850_tls_send(&conn, out, (size_t)ret) != ret) {
        ok = false;
        goto done;
    }
    ret = iec61850_tls_recv_tpkt(&conn, tpkt_in, sizeof(tpkt_in), 3000);
    if ((ret < 4) || (memcmp(out, tpkt_in, (size_t)ret) != 0)) {
        ok = false;
        goto done;
    }

    /* Clean disconnect */
    if (iec61850_tls_disconnect(&conn) != 0) {
        ok = false;
        goto done2;
    }
    if (iec61850_tls_is_connected(&conn)) {
        ok = false;
    }

done:
    (void)iec61850_tls_disconnect(&conn);
done2:
    echo_server_stop(&es);
    if (ok && (es.accept_rc == 0)) {
        PASS();
    } else {
        printf("FAIL: ok=%d accept=%d\n", (int)ok, es.accept_rc);
        tests_failed++;
    }
}

static void test_opportunistic_compatible(void)
{
    echo_server_t es;
    iec61850_tls_conn_t conn;
    int ret;

    TEST("opportunistic_compatible_no_provider");

    if (echo_server_start(&es, f_srv_cert, f_srv_key, NULL,
                            IEC61850_TLS_MODE_COMPATIBLE) != 0) {
        FAIL("echo server start");
        return;
    }

    /* No provider: no client cert, no verification (encrypted,
     * unauthenticated) — the interoperability default. */
    iec61850_tls_conn_init(&conn);
    ret = iec61850_tls_connect(&conn, "127.0.0.1", es.port, 5000, NULL,
                                 IEC61850_TLS_MODE_COMPATIBLE);
    if (ret == 0) {
        (void)iec61850_tls_disconnect(&conn);
        echo_server_stop(&es);
        PASS();
    } else {
        printf("(connect %d) ", ret);
        echo_server_stop(&es);
        FAIL("connect expected 0");
    }
}

static void test_recv_timeout(void)
{
    echo_server_t es;
    iec61850_tls_conn_t conn;
    uint8_t buf[64];
    int ret;
    int recv_rc = 1;

    TEST("recv_timeout");

    if (echo_server_start(&es, f_srv_cert, f_srv_key, f_ca1_cert,
                            IEC61850_TLS_MODE_COMPATIBLE) != 0) {
        FAIL("echo server start");
        return;
    }

    iec61850_tls_conn_init(&conn);
    ret = trust_only_connect(&conn, es.port, f_ca1_cert,
                               IEC61850_TLS_MODE_COMPATIBLE);
    if (ret == 0) {
        /* Server sends nothing: bounded recv must time out */
        recv_rc = iec61850_tls_recv(&conn, buf, sizeof(buf), 300);
        (void)iec61850_tls_disconnect(&conn);
    }

    echo_server_stop(&es);
    if ((ret == 0) && (recv_rc == IEC61850_TRANSPORT_ERR_TIMEOUT)) {
        PASS();
    } else {
        printf("FAIL: connect=%d recv=%d\n", ret, recv_rc);
        tests_failed++;
    }
}

static void test_disconnect_cleanup_contract(void)
{
    iec61850_tls_conn_t conn;
    uint8_t buf[4] = {0};

    TEST("disconnect_cleanup_contract");

    iec61850_tls_conn_init(&conn);
    ASSERT_EQ(iec61850_tls_send(&conn, buf, sizeof(buf)),
               IEC61850_TRANSPORT_ERR_ARGS);
    ASSERT_EQ(iec61850_tls_recv(&conn, buf, sizeof(buf), 10),
               IEC61850_TRANSPORT_ERR_ARGS);
    ASSERT_EQ(iec61850_tls_recv_tpkt(&conn, buf, sizeof(buf), 10),
               IEC61850_TRANSPORT_ERR_ARGS);
    ASSERT_TRUE(!iec61850_tls_is_connected(&conn));

    /* Double disconnect on a fresh conn is a no-op success. */
    ASSERT_EQ(iec61850_tls_disconnect(&conn), IEC61850_TRANSPORT_OK);
    ASSERT_EQ(iec61850_tls_disconnect(NULL), IEC61850_TRANSPORT_ERR_ARGS);
    ASSERT_EQ(iec61850_tls_connect(NULL, "127.0.0.1", 1, 10, NULL,
                                     IEC61850_TLS_MODE_COMPATIBLE),
               IEC61850_TRANSPORT_ERR_ARGS);
    ASSERT_EQ(iec61850_tls_listener_bind(NULL, 1, NULL,
                                           IEC61850_TLS_MODE_COMPATIBLE),
               IEC61850_TRANSPORT_ERR_ARGS);
    ASSERT_TRUE(!iec61850_tls_is_connected(NULL));

    PASS();
}

static void test_listener_requires_provider(void)
{
    iec61850_tls_listener_t listener;

    TEST("listener_bind_requires_provider");

    iec61850_tls_listener_init(&listener);
    ASSERT_EQ(iec61850_tls_listener_bind(&listener, 0, NULL,
                                           IEC61850_TLS_MODE_COMPATIBLE),
               -EINVAL);
    ASSERT_EQ(iec61850_tls_listener_close(&listener),
               IEC61850_TRANSPORT_OK);

    PASS();
}

static void test_plain_tcp_to_tls_rejected(void)
{
    echo_server_t es;
    iec61850_tcp_conn_t raw;
    uint8_t garbage[8] = {0x16, 0x03, 0x01, 0x00, 0x50, 0x00, 0x00, 0x00};
    bool ok = false;

    TEST("plain_tcp_to_tls_listener_rejected");

    if (echo_server_start(&es, f_srv_cert, f_srv_key, f_ca1_cert,
                            IEC61850_TLS_MODE_COMPATIBLE) != 0) {
        FAIL("echo server start");
        return;
    }

    /* Raw TCP connect + garbage: the TLS handshake must fail. */
    iec61850_tcp_conn_init(&raw);
    if ((iec61850_tcp_connect(&raw, "127.0.0.1", es.port, 5000) == 0) &&
        (iec61850_tcp_send(&raw, garbage, sizeof(garbage)) > 0)) {
        usleep(200000); /* let the server fail the handshake */
        ok = true;
    }
    (void)iec61850_tcp_disconnect(&raw);

    echo_server_stop(&es);
    /* The echo thread must have failed the accept (non-zero). */
    if (ok && (es.accept_rc != 0)) {
        PASS();
    } else {
        printf("FAIL: tcp=%d accept=%d\n", (int)ok, es.accept_rc);
        tests_failed++;
    }
}

/*
 * Mode-policy matrix driver: start an echo server with the given
 * (cert, trust, mode), connect a trust-only client in the given
 * mode, and check the connect result.
 */
static void run_mode_case(const char *name, const char *server_cert,
                            const char *server_key, const char *trust,
                            iec61850_tls_mode_t mode, int expected)
{
    echo_server_t es;
    iec61850_tls_conn_t conn;
    int ret;

    TEST(name);

    if (echo_server_start(&es, server_cert, server_key, trust,
                            mode) != 0) {
        FAIL("echo server start");
        return;
    }

    iec61850_tls_conn_init(&conn);
    ret = trust_only_connect(&conn, es.port, trust, mode);
    if (ret == 0) {
        (void)iec61850_tls_disconnect(&conn);
    }

    echo_server_stop(&es);
    if (ret == expected) {
        PASS();
    } else {
        printf("FAIL: connect got %d, want %d\n", ret, expected);
        tests_failed++;
    }
}

int main(void)
{
    printf("=== TLS Socket Unit Tests ===\n");

    (void)snprintf(f_ca1_key, sizeof(f_ca1_key), "/tmp/test_tls_ca1_key_%d.pem", (int)getpid());
    (void)snprintf(f_ca1_cert, sizeof(f_ca1_cert), "/tmp/test_tls_ca1_cert_%d.pem", (int)getpid());
    (void)snprintf(f_ca2_key, sizeof(f_ca2_key), "/tmp/test_tls_ca2_key_%d.pem", (int)getpid());
    (void)snprintf(f_ca2_cert, sizeof(f_ca2_cert), "/tmp/test_tls_ca2_cert_%d.pem", (int)getpid());
    (void)snprintf(f_srv_key, sizeof(f_srv_key), "/tmp/test_tls_srv_key_%d.pem", (int)getpid());
    (void)snprintf(f_srv_cert, sizeof(f_srv_cert), "/tmp/test_tls_srv_cert_%d.pem", (int)getpid());
    (void)snprintf(f_weak_key, sizeof(f_weak_key), "/tmp/test_tls_weak_key_%d.pem", (int)getpid());
    (void)snprintf(f_weak_cert, sizeof(f_weak_cert), "/tmp/test_tls_weak_cert_%d.pem", (int)getpid());
    (void)snprintf(f_exp_key, sizeof(f_exp_key), "/tmp/test_tls_exp_key_%d.pem", (int)getpid());
    (void)snprintf(f_exp_cert, sizeof(f_exp_cert), "/tmp/test_tls_exp_cert_%d.pem", (int)getpid());
    (void)snprintf(f_spiffe_key, sizeof(f_spiffe_key), "/tmp/test_tls_spiffe_key_%d.pem", (int)getpid());
    (void)snprintf(f_spiffe_cert, sizeof(f_spiffe_cert), "/tmp/test_tls_spiffe_cert_%d.pem", (int)getpid());
    (void)snprintf(f_rogue_key, sizeof(f_rogue_key), "/tmp/test_tls_rogue_key_%d.pem", (int)getpid());
    (void)snprintf(f_rogue_cert, sizeof(f_rogue_cert), "/tmp/test_tls_rogue_cert_%d.pem", (int)getpid());

    if (generate_fixtures() != 0) {
        fprintf(stderr, "FATAL: failed to generate test certificates\n");
        cleanup_fixtures();
        return 1;
    }

    test_handshake_roundtrip();
    test_opportunistic_compatible();
    test_recv_timeout();
    test_disconnect_cleanup_contract();
    test_listener_requires_provider();
    test_plain_tcp_to_tls_rejected();

    /* Mode-policy matrix: (server credentials, client mode, expectation) */
    run_mode_case("mode_compatible_accepts_trusted_chain",
                  f_srv_cert, f_srv_key, f_ca1_cert,
                  IEC61850_TLS_MODE_COMPATIBLE, 0);
    run_mode_case("untrusted_ca_rejected_compatible",
                  f_rogue_cert, f_rogue_key, f_ca1_cert,
                  IEC61850_TLS_MODE_COMPATIBLE,
                  IEC61850_TRANSPORT_ERR_CONNECT);
    run_mode_case("untrusted_ca_rejected_strict",
                  f_rogue_cert, f_rogue_key, f_ca1_cert,
                  IEC61850_TLS_MODE_STRICT_62351,
                  IEC61850_TRANSPORT_ERR_CONNECT);
    run_mode_case("mode_strict_accepts_good_profile",
                  f_srv_cert, f_srv_key, f_ca1_cert,
                  IEC61850_TLS_MODE_STRICT_62351, 0);
    run_mode_case("mode_strict_rejects_weak_key",
                  f_weak_cert, f_weak_key, f_ca1_cert,
                  IEC61850_TLS_MODE_STRICT_62351,
                  IEC61850_TRANSPORT_ERR_CONNECT);
    run_mode_case("mode_compatible_tolerates_weak_key",
                  f_weak_cert, f_weak_key, f_ca1_cert,
                  IEC61850_TLS_MODE_COMPATIBLE, 0);
    run_mode_case("mode_strict_rejects_expired",
                  f_exp_cert, f_exp_key, f_ca1_cert,
                  IEC61850_TLS_MODE_STRICT_62351,
                  IEC61850_TRANSPORT_ERR_CONNECT);
    run_mode_case("mode_spiffe_accepts_uri_san",
                  f_spiffe_cert, f_spiffe_key, f_ca1_cert,
                  IEC61850_TLS_MODE_SPIFFE, 0);
    run_mode_case("mode_spiffe_rejects_no_uri_san",
                  f_srv_cert, f_srv_key, f_ca1_cert,
                  IEC61850_TLS_MODE_SPIFFE,
                  IEC61850_TRANSPORT_ERR_CONNECT);

    cleanup_fixtures();

    printf("\n=== Summary: %d run, %d passed, %d failed ===\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
