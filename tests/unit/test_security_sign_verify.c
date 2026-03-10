/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for IEC 62351-6 Sign/Verify Integration
 *
 * Tests sign+verify round-trip, tamper detection, wrong key rejection,
 * and NULL input handling for the key_manager and cert_manager APIs.
 *
 * License: BSD-3-Clause
 */

#include "property_test.h"
#include "security/key_manager.h"
#include "security/cert_manager.h"

#include <stdio.h>
#include <string.h>

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

static const char *TEST_DATA_DIR = "tests/data/certs";

/* Helper: build path relative to MESON_SOURCE_ROOT or cwd */
static void build_path(char *out, size_t out_size, const char *filename)
{
    const char *root = getenv("MESON_SOURCE_ROOT");
    if (root != NULL) {
        snprintf(out, out_size, "%s/%s/%s", root, TEST_DATA_DIR, filename);
    } else {
        snprintf(out, out_size, "%s/%s", TEST_DATA_DIR, filename);
    }
}

/* ========================================================================
 * RSA Sign/Verify Round-Trip
 * ======================================================================== */

static void test_rsa_sign_verify_roundtrip(void)
{
    TEST("rsa_sign_verify_roundtrip");
    char key_path[512], cert_path[512];
    build_path(key_path, sizeof(key_path), "rsa_2048.key");
    build_path(cert_path, sizeof(cert_path), "rsa_2048_cert.pem");

    iec61850_key_manager_t km;
    iec61850_cert_manager_t cm;
    iec61850_key_manager_init(&km);
    iec61850_cert_manager_init(&cm);

    ASSERT_EQ(iec61850_key_manager_load_private_key(&km, key_path, NULL), IEC61850_SEC_OK);
    ASSERT_EQ(iec61850_cert_manager_load(&cm, cert_path), IEC61850_SEC_OK);

    /* Sign data */
    const uint8_t data[] = "Hello IEC 62351-6 GOOSE security test";
    uint8_t sig[IEC61850_MAX_SIGNATURE_LEN];
    size_t sig_len = 0;

    ASSERT_EQ(iec61850_key_manager_sign(&km, data, sizeof(data),
                                          sig, sizeof(sig), &sig_len), IEC61850_SEC_OK);
    ASSERT_TRUE(sig_len > 0);
    ASSERT_TRUE(sig_len <= 256);  /* RSA-2048 = 256 bytes */

    /* Verify with matching public key */
    EVP_PKEY *pubkey = iec61850_cert_manager_get_public_key(&cm);
    ASSERT_TRUE(pubkey != NULL);
    ASSERT_EQ(iec61850_key_manager_verify(data, sizeof(data),
                                            sig, sig_len, pubkey), IEC61850_SEC_OK);

    iec61850_key_manager_destroy(&km);
    iec61850_cert_manager_destroy(&cm);
    PASS();
}

/* ========================================================================
 * ECDSA Sign/Verify Round-Trip
 * ======================================================================== */

static void test_ecdsa_sign_verify_roundtrip(void)
{
    TEST("ecdsa_sign_verify_roundtrip");
    char key_path[512], cert_path[512];
    build_path(key_path, sizeof(key_path), "ecdsa_p256.key");
    build_path(cert_path, sizeof(cert_path), "ecdsa_p256_cert.pem");

    iec61850_key_manager_t km;
    iec61850_cert_manager_t cm;
    iec61850_key_manager_init(&km);
    iec61850_cert_manager_init(&cm);

    ASSERT_EQ(iec61850_key_manager_load_private_key(&km, key_path, NULL), IEC61850_SEC_OK);
    ASSERT_EQ(iec61850_cert_manager_load(&cm, cert_path), IEC61850_SEC_OK);

    ASSERT_EQ(iec61850_key_manager_get_key_type(&km), IEC61850_KEY_ECDSA_P256);
    ASSERT_EQ(iec61850_key_manager_get_sig_algo(&km), IEC61850_SIG_ECDSA_SHA256);

    const uint8_t data[] = "ECDSA test data for IEC 62351-6";
    uint8_t sig[IEC61850_MAX_SIGNATURE_LEN];
    size_t sig_len = 0;

    ASSERT_EQ(iec61850_key_manager_sign(&km, data, sizeof(data),
                                          sig, sizeof(sig), &sig_len), IEC61850_SEC_OK);
    ASSERT_TRUE(sig_len > 0);

    EVP_PKEY *pubkey = iec61850_cert_manager_get_public_key(&cm);
    ASSERT_EQ(iec61850_key_manager_verify(data, sizeof(data),
                                            sig, sig_len, pubkey), IEC61850_SEC_OK);

    iec61850_key_manager_destroy(&km);
    iec61850_cert_manager_destroy(&cm);
    PASS();
}

/* ========================================================================
 * Tamper Detection: Modified data fails verification
 * ======================================================================== */

static void test_tamper_detection_data(void)
{
    TEST("tamper_detection_data");
    char key_path[512], cert_path[512];
    build_path(key_path, sizeof(key_path), "rsa_2048.key");
    build_path(cert_path, sizeof(cert_path), "rsa_2048_cert.pem");

    iec61850_key_manager_t km;
    iec61850_cert_manager_t cm;
    iec61850_key_manager_init(&km);
    iec61850_cert_manager_init(&cm);

    iec61850_key_manager_load_private_key(&km, key_path, NULL);
    iec61850_cert_manager_load(&cm, cert_path);

    uint8_t data[] = "Original GOOSE APDU content here";
    uint8_t sig[IEC61850_MAX_SIGNATURE_LEN];
    size_t sig_len = 0;

    iec61850_key_manager_sign(&km, data, sizeof(data), sig, sizeof(sig), &sig_len);

    /* Tamper with data: flip one bit */
    data[0] ^= 0x01;

    EVP_PKEY *pubkey = iec61850_cert_manager_get_public_key(&cm);
    ASSERT_TRUE(iec61850_key_manager_verify(data, sizeof(data),
                                              sig, sig_len, pubkey) != IEC61850_SEC_OK);

    /* Restore and verify succeeds again */
    data[0] ^= 0x01;
    ASSERT_EQ(iec61850_key_manager_verify(data, sizeof(data),
                                            sig, sig_len, pubkey), IEC61850_SEC_OK);

    iec61850_key_manager_destroy(&km);
    iec61850_cert_manager_destroy(&cm);
    PASS();
}

/* ========================================================================
 * Tamper Detection: Modified signature fails verification
 * ======================================================================== */

static void test_tamper_detection_signature(void)
{
    TEST("tamper_detection_signature");
    char key_path[512], cert_path[512];
    build_path(key_path, sizeof(key_path), "rsa_2048.key");
    build_path(cert_path, sizeof(cert_path), "rsa_2048_cert.pem");

    iec61850_key_manager_t km;
    iec61850_cert_manager_t cm;
    iec61850_key_manager_init(&km);
    iec61850_cert_manager_init(&cm);

    iec61850_key_manager_load_private_key(&km, key_path, NULL);
    iec61850_cert_manager_load(&cm, cert_path);

    const uint8_t data[] = "GOOSE APDU payload";
    uint8_t sig[IEC61850_MAX_SIGNATURE_LEN];
    size_t sig_len = 0;

    iec61850_key_manager_sign(&km, data, sizeof(data), sig, sizeof(sig), &sig_len);

    /* Corrupt first byte of signature */
    sig[0] ^= 0xFF;
    EVP_PKEY *pubkey = iec61850_cert_manager_get_public_key(&cm);
    ASSERT_TRUE(iec61850_key_manager_verify(data, sizeof(data),
                                              sig, sig_len, pubkey) != IEC61850_SEC_OK);

    /* Corrupt last byte */
    sig[0] ^= 0xFF;  /* restore first */
    sig[sig_len - 1] ^= 0xFF;
    ASSERT_TRUE(iec61850_key_manager_verify(data, sizeof(data),
                                              sig, sig_len, pubkey) != IEC61850_SEC_OK);

    iec61850_key_manager_destroy(&km);
    iec61850_cert_manager_destroy(&cm);
    PASS();
}

/* ========================================================================
 * Wrong Key Rejection: sign with key1, verify with key2
 * ======================================================================== */

static void test_wrong_key_rejection(void)
{
    TEST("wrong_key_rejection");
    char key_path1[512], cert_path1[512], cert_path2[512];
    build_path(key_path1, sizeof(key_path1), "rsa_2048.key");
    build_path(cert_path1, sizeof(cert_path1), "rsa_2048_cert.pem");
    build_path(cert_path2, sizeof(cert_path2), "rsa_2048_other_cert.pem");

    iec61850_key_manager_t km;
    iec61850_cert_manager_t cm1, cm2;
    iec61850_key_manager_init(&km);
    iec61850_cert_manager_init(&cm1);
    iec61850_cert_manager_init(&cm2);

    iec61850_key_manager_load_private_key(&km, key_path1, NULL);
    iec61850_cert_manager_load(&cm1, cert_path1);
    iec61850_cert_manager_load(&cm2, cert_path2);

    const uint8_t data[] = "Cross-validation test data";
    uint8_t sig[IEC61850_MAX_SIGNATURE_LEN];
    size_t sig_len = 0;

    iec61850_key_manager_sign(&km, data, sizeof(data), sig, sizeof(sig), &sig_len);

    /* Verify with correct key → success */
    EVP_PKEY *pubkey1 = iec61850_cert_manager_get_public_key(&cm1);
    ASSERT_EQ(iec61850_key_manager_verify(data, sizeof(data),
                                            sig, sig_len, pubkey1), IEC61850_SEC_OK);

    /* Verify with wrong key → fail */
    EVP_PKEY *pubkey2 = iec61850_cert_manager_get_public_key(&cm2);
    ASSERT_TRUE(iec61850_key_manager_verify(data, sizeof(data),
                                              sig, sig_len, pubkey2) != IEC61850_SEC_OK);

    iec61850_key_manager_destroy(&km);
    iec61850_cert_manager_destroy(&cm1);
    iec61850_cert_manager_destroy(&cm2);
    PASS();
}

/* ========================================================================
 * NULL Input Handling
 * ======================================================================== */

static void test_null_inputs(void)
{
    TEST("null_inputs");
    iec61850_key_manager_t km;
    iec61850_key_manager_init(&km);

    uint8_t data[] = {0x01, 0x02};
    uint8_t sig[64];
    size_t sig_len = 0;

    /* Sign with NULL km */
    ASSERT_EQ(iec61850_key_manager_sign(NULL, data, 2, sig, 64, &sig_len),
              IEC61850_SEC_ERR_ARGS);

    /* Sign with NULL data */
    ASSERT_EQ(iec61850_key_manager_sign(&km, NULL, 2, sig, 64, &sig_len),
              IEC61850_SEC_ERR_ARGS);

    /* Sign with NULL sig_out */
    ASSERT_EQ(iec61850_key_manager_sign(&km, data, 2, NULL, 64, &sig_len),
              IEC61850_SEC_ERR_ARGS);

    /* Sign with NULL sig_len */
    ASSERT_EQ(iec61850_key_manager_sign(&km, data, 2, sig, 64, NULL),
              IEC61850_SEC_ERR_ARGS);

    /* Sign without key loaded */
    ASSERT_EQ(iec61850_key_manager_sign(&km, data, 2, sig, 64, &sig_len),
              IEC61850_SEC_ERR_ARGS);

    /* Verify with NULL data */
    ASSERT_EQ(iec61850_key_manager_verify(NULL, 2, sig, 32, (EVP_PKEY *)0x1),
              IEC61850_SEC_ERR_ARGS);

    /* Verify with NULL signature */
    ASSERT_EQ(iec61850_key_manager_verify(data, 2, NULL, 32, (EVP_PKEY *)0x1),
              IEC61850_SEC_ERR_ARGS);

    /* Verify with NULL public_key */
    ASSERT_EQ(iec61850_key_manager_verify(data, 2, sig, 32, NULL),
              IEC61850_SEC_ERR_ARGS);

    iec61850_key_manager_destroy(&km);
    PASS();
}

/* ========================================================================
 * Key Type Detection
 * ======================================================================== */

static void test_key_type_detection(void)
{
    TEST("key_type_detection");
    char key_path[512];
    iec61850_key_manager_t km;

    /* RSA-2048 */
    iec61850_key_manager_init(&km);
    build_path(key_path, sizeof(key_path), "rsa_2048.key");
    ASSERT_EQ(iec61850_key_manager_load_private_key(&km, key_path, NULL), IEC61850_SEC_OK);
    ASSERT_EQ(iec61850_key_manager_get_key_type(&km), IEC61850_KEY_RSA_2048);
    ASSERT_EQ(iec61850_key_manager_get_sig_algo(&km), IEC61850_SIG_RSA_PSS_SHA256);
    ASSERT_TRUE(iec61850_key_manager_get_sig_size(&km) == 256);
    iec61850_key_manager_destroy(&km);

    /* ECDSA-P256 */
    iec61850_key_manager_init(&km);
    build_path(key_path, sizeof(key_path), "ecdsa_p256.key");
    ASSERT_EQ(iec61850_key_manager_load_private_key(&km, key_path, NULL), IEC61850_SEC_OK);
    ASSERT_EQ(iec61850_key_manager_get_key_type(&km), IEC61850_KEY_ECDSA_P256);
    ASSERT_EQ(iec61850_key_manager_get_sig_algo(&km), IEC61850_SIG_ECDSA_SHA256);
    ASSERT_TRUE(iec61850_key_manager_get_sig_size(&km) > 0);
    iec61850_key_manager_destroy(&km);

    PASS();
}

/* ========================================================================
 * Key Manager Load Errors
 * ======================================================================== */

static void test_key_manager_load_errors(void)
{
    TEST("key_manager_load_errors");
    iec61850_key_manager_t km;
    iec61850_key_manager_init(&km);

    /* NULL path */
    ASSERT_EQ(iec61850_key_manager_load_private_key(&km, NULL, NULL),
              IEC61850_SEC_ERR_ARGS);

    /* Non-existent file */
    ASSERT_EQ(iec61850_key_manager_load_private_key(&km, "/nonexistent/key.pem", NULL),
              IEC61850_SEC_ERR_FILE);

    /* Not loaded */
    ASSERT_TRUE(!iec61850_key_manager_is_loaded(&km));
    ASSERT_EQ(iec61850_key_manager_get_key_type(&km), IEC61850_KEY_UNKNOWN);

    iec61850_key_manager_destroy(&km);
    PASS();
}

/* ========================================================================
 * Key Reload
 * ======================================================================== */

static void test_key_reload(void)
{
    TEST("key_reload");
    char rsa_path[512], ecdsa_path[512];
    build_path(rsa_path, sizeof(rsa_path), "rsa_2048.key");
    build_path(ecdsa_path, sizeof(ecdsa_path), "ecdsa_p256.key");

    iec61850_key_manager_t km;
    iec61850_key_manager_init(&km);

    /* Load RSA */
    ASSERT_EQ(iec61850_key_manager_load_private_key(&km, rsa_path, NULL), IEC61850_SEC_OK);
    ASSERT_EQ(iec61850_key_manager_get_key_type(&km), IEC61850_KEY_RSA_2048);

    /* Reload with ECDSA */
    ASSERT_EQ(iec61850_key_manager_load_private_key(&km, ecdsa_path, NULL), IEC61850_SEC_OK);
    ASSERT_EQ(iec61850_key_manager_get_key_type(&km), IEC61850_KEY_ECDSA_P256);

    iec61850_key_manager_destroy(&km);
    PASS();
}

/* ========================================================================
 * Signature Size
 * ======================================================================== */

static void test_sig_size(void)
{
    TEST("sig_size");
    iec61850_key_manager_t km;

    /* No key loaded */
    iec61850_key_manager_init(&km);
    ASSERT_TRUE(iec61850_key_manager_get_sig_size(&km) == 0);
    iec61850_key_manager_destroy(&km);

    /* NULL */
    ASSERT_TRUE(iec61850_key_manager_get_sig_size(NULL) == 0);

    PASS();
}

int main(void)
{
    printf("\n=== Security Sign/Verify Tests ===\n");

    test_rsa_sign_verify_roundtrip();
    test_ecdsa_sign_verify_roundtrip();
    test_tamper_detection_data();
    test_tamper_detection_signature();
    test_wrong_key_rejection();
    test_null_inputs();
    test_key_type_detection();
    test_key_manager_load_errors();
    test_key_reload();
    test_sig_size();

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
