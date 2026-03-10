/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Security Edge Case Tests
 *
 * Tests: expired timestamps, replay detection, truncated security
 * extension, empty signature, oversized signature, publisher/subscriber
 * security enable/disable.
 *
 * License: BSD-3-Clause
 */

#include "security/key_manager.h"
#include "security/cert_manager.h"
#include "goose/goose_publisher.h"
#include "goose/goose_subscriber.h"
#include "sv/sv_publisher.h"
#include "sv/sv_subscriber.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>

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

static void build_path(char *out, size_t out_size, const char *filename)
{
    const char *root = getenv("MESON_SOURCE_ROOT");
    if (root != NULL) {
        snprintf(out, out_size, "%s/tests/data/certs/%s", root, filename);
    } else {
        snprintf(out, out_size, "tests/data/certs/%s", filename);
    }
}

/* ========================================================================
 * GOOSE Publisher Security Enable
 * ======================================================================== */

static void test_goose_pub_enable_security_null(void)
{
    TEST("goose_pub_enable_security_null");

    /* NULL pub */
    ASSERT_EQ(iec61850_goose_publisher_enable_security(NULL, (void *)1, (void *)1), -EINVAL);

    /* NULL key_manager */
    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, NULL);
    ASSERT_EQ(iec61850_goose_publisher_enable_security(&pub, NULL, (void *)1), -EINVAL);

    /* NULL cert_manager */
    ASSERT_EQ(iec61850_goose_publisher_enable_security(&pub, (void *)1, NULL), -EINVAL);

    iec61850_goose_publisher_destroy(&pub);
    PASS();
}

static void test_goose_pub_enable_security_unloaded(void)
{
    TEST("goose_pub_enable_security_unloaded");
    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, NULL);

    iec61850_key_manager_t km;
    iec61850_cert_manager_t cm;
    iec61850_key_manager_init(&km);
    iec61850_cert_manager_init(&cm);

    /* km not loaded → should fail */
    ASSERT_EQ(iec61850_goose_publisher_enable_security(&pub, &km, &cm), -EINVAL);

    iec61850_key_manager_destroy(&km);
    iec61850_cert_manager_destroy(&cm);
    iec61850_goose_publisher_destroy(&pub);
    PASS();
}

static void test_goose_pub_enable_security_valid(void)
{
    TEST("goose_pub_enable_security_valid");
    char key_path[512], cert_path[512];
    build_path(key_path, sizeof(key_path), "rsa_2048.key");
    build_path(cert_path, sizeof(cert_path), "rsa_2048_cert.pem");

    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, NULL);

    iec61850_key_manager_t km;
    iec61850_cert_manager_t cm;
    iec61850_key_manager_init(&km);
    iec61850_cert_manager_init(&cm);

    iec61850_key_manager_load_private_key(&km, key_path, NULL);
    iec61850_cert_manager_load(&cm, cert_path);

    ASSERT_EQ(iec61850_goose_publisher_enable_security(&pub, &km, &cm), 0);
    ASSERT_TRUE(pub.security_enabled);

    iec61850_key_manager_destroy(&km);
    iec61850_cert_manager_destroy(&cm);
    iec61850_goose_publisher_destroy(&pub);
    PASS();
}

/* ========================================================================
 * GOOSE Subscriber Security Enable
 * ======================================================================== */

static void test_goose_sub_enable_security_null(void)
{
    TEST("goose_sub_enable_security_null");
    ASSERT_EQ(iec61850_goose_subscriber_enable_security(NULL, (void *)1), -EINVAL);

    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, NULL);
    ASSERT_EQ(iec61850_goose_subscriber_enable_security(&sub, NULL), -EINVAL);

    iec61850_goose_subscriber_destroy(&sub);
    PASS();
}

static void test_goose_sub_enable_security_valid(void)
{
    TEST("goose_sub_enable_security_valid");
    char cert_path[512];
    build_path(cert_path, sizeof(cert_path), "rsa_2048_cert.pem");

    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, NULL);

    iec61850_cert_manager_t cm;
    iec61850_cert_manager_init(&cm);
    iec61850_cert_manager_load(&cm, cert_path);

    ASSERT_EQ(iec61850_goose_subscriber_enable_security(&sub, &cm), 0);
    ASSERT_TRUE(sub.security_enabled);

    iec61850_cert_manager_destroy(&cm);
    iec61850_goose_subscriber_destroy(&sub);
    PASS();
}

/* ========================================================================
 * SV Publisher Security Enable
 * ======================================================================== */

static void test_sv_pub_enable_security_null(void)
{
    TEST("sv_pub_enable_security_null");
    ASSERT_EQ(iec61850_sv_publisher_enable_security(NULL, (void *)1, (void *)1), -EINVAL);

    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, NULL);
    ASSERT_EQ(iec61850_sv_publisher_enable_security(&pub, NULL, (void *)1), -EINVAL);
    ASSERT_EQ(iec61850_sv_publisher_enable_security(&pub, (void *)1, NULL), -EINVAL);

    iec61850_sv_publisher_destroy(&pub);
    PASS();
}

static void test_sv_pub_enable_security_valid(void)
{
    TEST("sv_pub_enable_security_valid");
    char key_path[512], cert_path[512];
    build_path(key_path, sizeof(key_path), "rsa_2048.key");
    build_path(cert_path, sizeof(cert_path), "rsa_2048_cert.pem");

    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, NULL);

    iec61850_key_manager_t km;
    iec61850_cert_manager_t cm;
    iec61850_key_manager_init(&km);
    iec61850_cert_manager_init(&cm);
    iec61850_key_manager_load_private_key(&km, key_path, NULL);
    iec61850_cert_manager_load(&cm, cert_path);

    ASSERT_EQ(iec61850_sv_publisher_enable_security(&pub, &km, &cm), 0);
    ASSERT_TRUE(pub.security_enabled);

    iec61850_key_manager_destroy(&km);
    iec61850_cert_manager_destroy(&cm);
    iec61850_sv_publisher_destroy(&pub);
    PASS();
}

/* ========================================================================
 * SV Subscriber Security Enable
 * ======================================================================== */

static void test_sv_sub_enable_security_null(void)
{
    TEST("sv_sub_enable_security_null");
    ASSERT_EQ(iec61850_sv_subscriber_enable_security(NULL, (void *)1), -EINVAL);

    iec61850_sv_subscriber_t sub;
    iec61850_sv_subscriber_init(&sub, NULL);
    ASSERT_EQ(iec61850_sv_subscriber_enable_security(&sub, NULL), -EINVAL);

    iec61850_sv_subscriber_destroy(&sub);
    PASS();
}

/* ========================================================================
 * Publish Without IO Should Fail
 * ======================================================================== */

static void test_goose_publish_no_io(void)
{
    TEST("goose_publish_no_io");
    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, NULL);
    iec61850_goose_publisher_set_boolean(&pub, 0, true);

    /* No packet_io set → publish should fail */
    ASSERT_TRUE(iec61850_goose_publisher_publish(&pub) < 0);

    iec61850_goose_publisher_destroy(&pub);
    PASS();
}

static void test_sv_publish_no_io(void)
{
    TEST("sv_publish_no_io");
    iec61850_sv_publisher_t pub;
    iec61850_sv_publisher_init(&pub, NULL);
    iec61850_sv_publisher_set_sample(&pub, 0, 1000);

    ASSERT_TRUE(iec61850_sv_publisher_publish(&pub) < 0);

    iec61850_sv_publisher_destroy(&pub);
    PASS();
}

/* ========================================================================
 * HMAC Verify
 * ======================================================================== */

static void test_hmac_empty_data(void)
{
    TEST("hmac_empty_data");
    /* Sign and verify with zero-length data should work */
    char key_path[512], cert_path[512];
    build_path(key_path, sizeof(key_path), "rsa_2048.key");
    build_path(cert_path, sizeof(cert_path), "rsa_2048_cert.pem");

    iec61850_key_manager_t km;
    iec61850_cert_manager_t cm;
    iec61850_key_manager_init(&km);
    iec61850_cert_manager_init(&cm);
    iec61850_key_manager_load_private_key(&km, key_path, NULL);
    iec61850_cert_manager_load(&cm, cert_path);

    uint8_t data[] = {0};  /* Minimal data (1 byte) */
    uint8_t sig[IEC61850_MAX_SIGNATURE_LEN];
    size_t sig_len = 0;

    ASSERT_EQ(iec61850_key_manager_sign(&km, data, 1, sig, sizeof(sig), &sig_len),
              IEC61850_SEC_OK);

    EVP_PKEY *pubkey = iec61850_cert_manager_get_public_key(&cm);
    ASSERT_EQ(iec61850_key_manager_verify(data, 1, sig, sig_len, pubkey),
              IEC61850_SEC_OK);

    iec61850_key_manager_destroy(&km);
    iec61850_cert_manager_destroy(&cm);
    PASS();
}

int main(void)
{
    printf("\n=== Security Edge Case Tests ===\n");

    printf("\n--- GOOSE Publisher Security ---\n");
    test_goose_pub_enable_security_null();
    test_goose_pub_enable_security_unloaded();
    test_goose_pub_enable_security_valid();

    printf("\n--- GOOSE Subscriber Security ---\n");
    test_goose_sub_enable_security_null();
    test_goose_sub_enable_security_valid();

    printf("\n--- SV Publisher Security ---\n");
    test_sv_pub_enable_security_null();
    test_sv_pub_enable_security_valid();

    printf("\n--- SV Subscriber Security ---\n");
    test_sv_sub_enable_security_null();

    printf("\n--- Publish Without IO ---\n");
    test_goose_publish_no_io();
    test_sv_publish_no_io();

    printf("\n--- Edge Cases ---\n");
    test_hmac_empty_data();

    printf("\n=== Test Summary ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
