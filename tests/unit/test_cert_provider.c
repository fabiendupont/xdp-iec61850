/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for the Certificate Provider (IEC 62351-4)
 *
 * Tests: create (valid / missing file / invalid content / all-NULL),
 * get() borrowed pointers and NULL-component contract, rotation via
 * atomic rename (refresh() reports 1 exactly once, then 0), pointer
 * stability across no-change refresh, invalid-after-valid (last good
 * credentials stay served), static missing-file error policy, spiffe
 * one-cycle grace policy, and destroy safety.
 *
 * Test keys/certs are generated at start via the OpenSSL EVP API —
 * same pattern as test_security_publisher.c. Manual equivalent for
 * reproducing the fixtures:
 *   openssl req -x509 -newkey rsa:2048 -nodes -keyout keyA.pem \
 *     -out certA.pem -days 1 -subj "/CN=CertProvA"
 *   openssl req -x509 -newkey rsa:2048 -nodes -keyout keyB.pem \
 *     -out certB.pem -days 1 -subj "/CN=CertProvB"
 *
 * Rotation steps write a staging file and rename() it over the
 * watched path — the atomic-replacement pattern used by real
 * credential agents (spiffe-helper, certbot) and always detectable
 * through the inode change, independent of timestamp granularity.
 *
 * License: BSD-2-Clause
 */

#include "security/cert_provider.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { tests_run++; printf("  [TEST] %s ... ", name); } while (0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while (0)
#define FAIL(msg) do { tests_failed++; printf("FAIL: %s\n", msg); return; } while (0)

#define ASSERT_TRUE(cond) do { if (!(cond)) { FAIL(#cond); return; } } while (0)
#define ASSERT_EQ(a, b) do { if ((a) != (b)) { \
    printf("FAIL: %s == %s (%d != %d)\n", #a, #b, (int)(a), (int)(b)); \
    tests_failed++; return; } } while (0)

/* Golden fixtures (generated once) and mutable work copies. */
static char golden_cert_a[256];
static char golden_key_a[256];
static char golden_cert_b[256];
static char golden_key_b[256];
static char work_cert[256];
static char work_key[256];
static char work_trust[256];
static char work_bad[256];
static char stage_file[256];

/* ------------------------------------------------------------------ */
/* Fixtures and helpers                                                */
/* ------------------------------------------------------------------ */

static int generate_key_and_cert(const char *key_path, const char *cert_path,
                                 int serial, const char *cn)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY *key = NULL;
    X509 *cert = NULL;
    FILE *f;
    int ok = -1;

    if (ctx == NULL) { return -1; }
    if (EVP_PKEY_keygen_init(ctx) <= 0) { goto done; }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) { goto done; }
    if (EVP_PKEY_keygen(ctx, &key) <= 0) { goto done; }

    cert = X509_new();
    if (cert == NULL) { goto done; }
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), serial);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 365L * 24 * 3600);
    X509_set_pubkey(cert, key);
    X509_NAME *name = X509_NAME_new();
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *)cn, -1, -1, 0);
    X509_set_subject_name(cert, name);
    X509_set_issuer_name(cert, name);
    if (X509_sign(cert, key, EVP_sha256()) <= 0) { goto done; }

    f = fopen(key_path, "w");
    if (f == NULL) { goto done; }
    PEM_write_PrivateKey(f, key, NULL, NULL, 0, NULL, NULL);
    fclose(f);

    f = fopen(cert_path, "w");
    if (f == NULL) { goto done; }
    PEM_write_X509(f, cert);
    fclose(f);

    ok = 0;

done:
    X509_free(cert);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(ctx);
    return ok;
}

static int read_whole_file(const char *path, char **buf_out, size_t *len_out)
{
    FILE *f = fopen(path, "rb");
    long sz;
    char *buf;
    size_t got;

    if (f == NULL) { return -1; }
    if ((fseek(f, 0, SEEK_END) != 0) || ((sz = ftell(f)) < 0) ||
        (fseek(f, 0, SEEK_SET) != 0)) {
        fclose(f);
        return -1;
    }
    buf = malloc((size_t)sz + 1u);
    if (buf == NULL) {
        fclose(f);
        return -1;
    }
    got = fread(buf, 1u, (size_t)sz, f);
    fclose(f);
    if (got != (size_t)sz) {
        free(buf);
        return -1;
    }
    buf[sz] = '\0';
    *buf_out = buf;
    *len_out = (size_t)sz;
    return 0;
}

static int write_file(const char *path, const char *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    size_t put;

    if (f == NULL) { return -1; }
    put = fwrite(data, 1u, len, f);
    fclose(f);
    return (put == len) ? 0 : -1;
}

/* Atomic replacement: write a staging file, then rename() over dst. */
static int write_file_atomic(const char *dst, const char *data, size_t len)
{
    if (write_file(stage_file, data, len) != 0) { return -1; }
    if (rename(stage_file, dst) != 0) { return -1; }
    return 0;
}

static int copy_file_atomic(const char *dst, const char *src)
{
    char *buf = NULL;
    size_t len = 0;
    int rc;

    if (read_whole_file(src, &buf, &len) != 0) { return -1; }
    rc = write_file_atomic(dst, buf, len);
    free(buf);
    return rc;
}

static bool content_matches(const char *path, const char *data, size_t len)
{
    char *buf = NULL;
    size_t blen = 0;
    bool match = false;

    if (read_whole_file(path, &buf, &blen) != 0) { return false; }
    match = (blen == len) && (memcmp(buf, data, blen) == 0);
    free(buf);
    return match;
}

static bool pem_parsable_x509(const char *data, size_t len)
{
    BIO *bio = BIO_new_mem_buf(data, (int)len);
    X509 *x;
    bool ok;

    if (bio == NULL) { return false; }
    x = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    ok = (x != NULL);
    X509_free(x);
    BIO_free(bio);
    ERR_clear_error();
    return ok;
}

static bool pem_parsable_pkey(const char *data, size_t len)
{
    BIO *bio = BIO_new_mem_buf(data, (int)len);
    EVP_PKEY *k;
    bool ok;

    if (bio == NULL) { return false; }
    k = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    ok = (k != NULL);
    EVP_PKEY_free(k);
    BIO_free(bio);
    ERR_clear_error();
    return ok;
}

/* Reset the watched work files to the "A" credentials. */
static void reset_work_files(void)
{
    (void)copy_file_atomic(work_cert, golden_cert_a);
    (void)copy_file_atomic(work_key, golden_key_a);
    (void)copy_file_atomic(work_trust, golden_cert_a);
}

static void cleanup_temp_files(void)
{
    (void)unlink(golden_cert_a);
    (void)unlink(golden_key_a);
    (void)unlink(golden_cert_b);
    (void)unlink(golden_key_b);
    (void)unlink(work_cert);
    (void)unlink(work_key);
    (void)unlink(work_trust);
    (void)unlink(work_bad);
    (void)unlink(stage_file);
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

static void test_create_valid_and_get(void)
{
    TEST("create_static_valid_and_get");
    iec61850_cert_provider_t *p;
    const char *cert = NULL, *key = NULL, *trust = NULL;
    size_t cert_len = 0, key_len = 0, trust_len = 0;
    const char *cert2 = NULL;
    size_t cert2_len = 0;

    reset_work_files();
    p = iec61850_cert_provider_create_static(work_cert, work_key, work_trust);
    ASSERT_TRUE(p != NULL);

    ASSERT_EQ(p->get(p, &cert, &cert_len, &key, &key_len,
                     &trust, &trust_len), 0);
    ASSERT_TRUE(cert != NULL);
    ASSERT_TRUE(cert_len > 0);
    ASSERT_TRUE(key != NULL);
    ASSERT_TRUE(key_len > 0);
    ASSERT_TRUE(trust != NULL);
    ASSERT_TRUE(trust_len > 0);

    /* get() serves parseable, NUL-terminated PEM buffers */
    ASSERT_TRUE(pem_parsable_x509(cert, cert_len));
    ASSERT_TRUE(pem_parsable_pkey(key, key_len));
    ASSERT_TRUE(pem_parsable_x509(trust, trust_len));
    ASSERT_TRUE(cert[cert_len] == '\0');

    /* No change since create: refresh reports 0 and the borrowed
     * pointers remain valid and stable. */
    ASSERT_EQ(p->refresh(p), 0);
    ASSERT_EQ(p->get(p, &cert2, &cert2_len, NULL, NULL, NULL, NULL), 0);
    ASSERT_TRUE(cert2 == cert);
    ASSERT_TRUE(cert2_len == cert_len);

    iec61850_cert_provider_destroy(p);
    PASS();
}

static void test_null_components(void)
{
    TEST("null_components_per_contract");
    iec61850_cert_provider_t *p;
    const char *cert = NULL, *key = NULL, *trust = NULL;
    size_t cert_len = 0, key_len = 0, trust_len = 0;

    reset_work_files();
    /* Trust store not configured: NULL/0 per contract, rest served. */
    p = iec61850_cert_provider_create_static(work_cert, work_key, NULL);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(p->get(p, &cert, &cert_len, &key, &key_len,
                     &trust, &trust_len), 0);
    ASSERT_TRUE(cert != NULL && cert_len > 0);
    ASSERT_TRUE(key != NULL && key_len > 0);
    ASSERT_TRUE(trust == NULL && trust_len == 0);
    iec61850_cert_provider_destroy(p);

    /* Cert-only provider; individual output args may be NULL. */
    p = iec61850_cert_provider_create_static(work_cert, NULL, NULL);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(p->get(p, &cert, &cert_len, &key, &key_len,
                     &trust, &trust_len), 0);
    ASSERT_TRUE(cert != NULL && cert_len > 0);
    ASSERT_TRUE(key == NULL && key_len == 0);
    ASSERT_TRUE(trust == NULL && trust_len == 0);
    ASSERT_EQ(p->get(p, &cert, &cert_len, NULL, NULL, NULL, NULL), 0);
    ASSERT_TRUE(cert != NULL && cert_len > 0);
    iec61850_cert_provider_destroy(p);

    PASS();
}

static void test_create_failures(void)
{
    TEST("create_failures");
    static const char garbage[] = "this is not a pem file\n";

    /* Nonexistent file */
    ASSERT_TRUE(iec61850_cert_provider_create_static(
        "/nonexistent/cert.pem", NULL, NULL) == NULL);

    /* Invalid content at create: constructor fails */
    ASSERT_TRUE(write_file(work_bad, garbage, sizeof(garbage) - 1u) == 0);
    ASSERT_TRUE(iec61850_cert_provider_create_static(
        work_bad, NULL, NULL) == NULL);

    /* Key file that does not contain a private key */
    ASSERT_TRUE(iec61850_cert_provider_create_static(
        work_cert, work_bad, NULL) == NULL);

    /* No component configured at all */
    ASSERT_TRUE(iec61850_cert_provider_create_static(NULL, NULL, NULL) == NULL);
    ASSERT_TRUE(iec61850_cert_provider_create_spiffe(NULL, NULL, NULL) == NULL);

    PASS();
}

static void test_rotation_reported_once(void)
{
    TEST("rotation_reported_once");
    iec61850_cert_provider_t *p;
    const char *cert = NULL;
    size_t cert_len = 0;

    reset_work_files();
    p = iec61850_cert_provider_create_static(work_cert, work_key, work_trust);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(p->refresh(p), 0);

    /* Rotate: cert B replaces cert A via atomic rename. */
    ASSERT_TRUE(copy_file_atomic(work_cert, golden_cert_b) == 0);

    ASSERT_EQ(p->refresh(p), 1); /* change reported... */
    ASSERT_EQ(p->refresh(p), 0); /* ...exactly once */
    ASSERT_EQ(p->refresh(p), 0);

    /* get() serves the new content; old pointers are invalid. */
    ASSERT_EQ(p->get(p, &cert, &cert_len, NULL, NULL, NULL, NULL), 0);
    ASSERT_TRUE(content_matches(golden_cert_b, cert, cert_len));
    ASSERT_TRUE(pem_parsable_x509(cert, cert_len));

    iec61850_cert_provider_destroy(p);
    PASS();
}

static void test_invalid_after_valid(void)
{
    TEST("invalid_after_valid_serves_last_good");
    iec61850_cert_provider_t *p;
    const char *cert = NULL;
    size_t cert_len = 0;
    static const char garbage[] = "corrupted credentials\n";
    int r;

    reset_work_files();
    p = iec61850_cert_provider_create_static(work_cert, work_key, work_trust);
    ASSERT_TRUE(p != NULL);

    /* Corrupt the cert file after a successful create */
    ASSERT_TRUE(write_file_atomic(work_cert, garbage,
                                  sizeof(garbage) - 1u) == 0);
    r = p->refresh(p);
    ASSERT_TRUE(r < 0); /* negative errno reported */

    /* get() keeps serving the last good credentials (no swap). */
    ASSERT_EQ(p->get(p, &cert, &cert_len, NULL, NULL, NULL, NULL), 0);
    ASSERT_TRUE(content_matches(golden_cert_a, cert, cert_len));

    /* Recovery: valid (different) content is picked up as a change */
    ASSERT_TRUE(copy_file_atomic(work_cert, golden_cert_b) == 0);
    ASSERT_EQ(p->refresh(p), 1);
    ASSERT_EQ(p->get(p, &cert, &cert_len, NULL, NULL, NULL, NULL), 0);
    ASSERT_TRUE(content_matches(golden_cert_b, cert, cert_len));

    iec61850_cert_provider_destroy(p);
    PASS();
}

static void test_static_missing_after_valid(void)
{
    TEST("static_missing_file_is_error");
    iec61850_cert_provider_t *p;
    const char *cert = NULL;
    size_t cert_len = 0;
    int r;

    reset_work_files();
    p = iec61850_cert_provider_create_static(work_cert, work_key, work_trust);
    ASSERT_TRUE(p != NULL);

    ASSERT_TRUE(unlink(work_cert) == 0);
    r = p->refresh(p);
    ASSERT_TRUE(r < 0); /* static backend: missing file is an error */

    /* Last good credentials remain served. */
    ASSERT_EQ(p->get(p, &cert, &cert_len, NULL, NULL, NULL, NULL), 0);
    ASSERT_TRUE(content_matches(golden_cert_a, cert, cert_len));

    iec61850_cert_provider_destroy(p);
    PASS();
}

static void test_spiffe_grace(void)
{
    TEST("spiffe_grace_and_recovery");
    iec61850_cert_provider_t *p;
    const char *cert = NULL;
    size_t cert_len = 0;
    int r;

    reset_work_files();
    p = iec61850_cert_provider_create_spiffe(work_cert, work_key, work_trust);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(p->refresh(p), 0);

    /* Remove the file (SPIRE agent rewrite window): the first
     * refresh treats it as no change (grace). */
    ASSERT_TRUE(unlink(work_cert) == 0);
    ASSERT_EQ(p->refresh(p), 0);

    /* Still missing on the next cycle: reported as an error. */
    r = p->refresh(p);
    ASSERT_TRUE(r < 0);

    /* get() still serves the last good credentials. */
    ASSERT_EQ(p->get(p, &cert, &cert_len, NULL, NULL, NULL, NULL), 0);
    ASSERT_TRUE(content_matches(golden_cert_a, cert, cert_len));

    /* Recreate with new content: reported as a change. */
    ASSERT_TRUE(copy_file_atomic(work_cert, golden_cert_b) == 0);
    ASSERT_EQ(p->refresh(p), 1);
    ASSERT_EQ(p->get(p, &cert, &cert_len, NULL, NULL, NULL, NULL), 0);
    ASSERT_TRUE(content_matches(golden_cert_b, cert, cert_len));

    iec61850_cert_provider_destroy(p);
    PASS();
}

static void test_destroy_safety(void)
{
    TEST("destroy_null_and_double_destroy");
    iec61850_cert_provider_t *p;
    iec61850_cert_provider_t *q;
    iec61850_cert_provider_t stale;
    const char *cert = NULL;
    size_t cert_len = 0;

    /* destroy(NULL) must be a no-op (also repeatedly). */
    iec61850_cert_provider_destroy(NULL);
    iec61850_cert_provider_destroy(NULL);

    reset_work_files();
    p = iec61850_cert_provider_create_static(work_cert, NULL, NULL);
    ASSERT_TRUE(p != NULL);
    p->destroy(p);

    /* Stale heap handle: the wrapper rejects it by pointer identity
     * (no dereference of freed storage), so a repeated destroy is
     * inert. */
    iec61850_cert_provider_destroy(p);

    /* Address recycling: a new provider may land at the freed
     * address; it must be fully usable and destroyable (the guard
     * is cleared by create()). */
    q = iec61850_cert_provider_create_static(work_cert, NULL, NULL);
    ASSERT_TRUE(q != NULL);
    ASSERT_EQ(q->get(q, &cert, &cert_len, NULL, NULL, NULL, NULL), 0);
    ASSERT_TRUE(cert != NULL && cert_len > 0);
    iec61850_cert_provider_destroy(q);
    iec61850_cert_provider_destroy(q); /* repeated: still inert */

    /* Zeroed (tombstone) handle must be ignored by the wrapper. */
    memset(&stale, 0, sizeof(stale));
    iec61850_cert_provider_destroy(&stale);

    PASS();
}

int main(void)
{
    printf("\n=== Certificate Provider Tests ===\n");

    (void)snprintf(golden_cert_a, sizeof(golden_cert_a),
                   "/tmp/test_cert_prov_a_cert_%d.pem", (int)getpid());
    (void)snprintf(golden_key_a, sizeof(golden_key_a),
                   "/tmp/test_cert_prov_a_key_%d.pem", (int)getpid());
    (void)snprintf(golden_cert_b, sizeof(golden_cert_b),
                   "/tmp/test_cert_prov_b_cert_%d.pem", (int)getpid());
    (void)snprintf(golden_key_b, sizeof(golden_key_b),
                   "/tmp/test_cert_prov_b_key_%d.pem", (int)getpid());
    (void)snprintf(work_cert, sizeof(work_cert),
                   "/tmp/test_cert_prov_work_cert_%d.pem", (int)getpid());
    (void)snprintf(work_key, sizeof(work_key),
                   "/tmp/test_cert_prov_work_key_%d.pem", (int)getpid());
    (void)snprintf(work_trust, sizeof(work_trust),
                   "/tmp/test_cert_prov_work_trust_%d.pem", (int)getpid());
    (void)snprintf(work_bad, sizeof(work_bad),
                   "/tmp/test_cert_prov_bad_%d.pem", (int)getpid());
    (void)snprintf(stage_file, sizeof(stage_file),
                   "/tmp/test_cert_prov_stage_%d.pem", (int)getpid());

    if ((generate_key_and_cert(golden_key_a, golden_cert_a, 1,
                               "CertProvA") != 0) ||
        (generate_key_and_cert(golden_key_b, golden_cert_b, 2,
                               "CertProvB") != 0)) {
        fprintf(stderr, "FATAL: failed to generate test key/certs\n");
        cleanup_temp_files();
        return 1;
    }

    test_create_valid_and_get();
    test_null_components();
    test_create_failures();
    test_rotation_reported_once();
    test_invalid_after_valid();
    test_static_missing_after_valid();
    test_spiffe_grace();
    test_destroy_safety();

    cleanup_temp_files();

    printf("\n=== Test Summary ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    if (tests_failed > 0) {
        printf("\nFAILED\n");
        return 1;
    }

    printf("\nAll tests PASSED\n");
    return 0;
}
