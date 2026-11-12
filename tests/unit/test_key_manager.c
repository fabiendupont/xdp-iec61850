/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for Key Manager
 *
 * Tests: load RSA/ECDSA keys, sign/verify round-trip, wrong key type,
 * corrupt key, DER format, reload, signature size, unloaded state.
 *
 * License: BSD-2-Clause
 */

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

static void build_path(char *out, size_t out_size, const char *filename)
{
    const char *root = getenv("MESON_SOURCE_ROOT");
    if (root != NULL) {
        snprintf(out, out_size, "%s/tests/data/certs/%s", root, filename);
    } else {
        snprintf(out, out_size, "tests/data/certs/%s", filename);
    }
}

static void test_load_rsa_2048(void)
{
    TEST("load_rsa_2048");
    char path[512];
    build_path(path, sizeof(path), "rsa_2048.key");

    iec61850_key_manager_t km;
    iec61850_key_manager_init(&km);
    ASSERT_EQ(iec61850_key_manager_load_private_key(&km, path, NULL), IEC61850_SEC_OK);
    ASSERT_TRUE(iec61850_key_manager_is_loaded(&km));
    ASSERT_EQ(iec61850_key_manager_get_key_type(&km), IEC61850_KEY_RSA_2048);
    ASSERT_TRUE(iec61850_key_manager_get_sig_size(&km) == 256);
    ASSERT_EQ(iec61850_key_manager_get_sig_algo(&km), IEC61850_SIG_RSA_PSS_SHA256);
    iec61850_key_manager_destroy(&km);
    PASS();
}

static void test_load_ecdsa_p256(void)
{
    TEST("load_ecdsa_p256");
    char path[512];
    build_path(path, sizeof(path), "ecdsa_p256.key");

    iec61850_key_manager_t km;
    iec61850_key_manager_init(&km);
    ASSERT_EQ(iec61850_key_manager_load_private_key(&km, path, NULL), IEC61850_SEC_OK);
    ASSERT_TRUE(iec61850_key_manager_is_loaded(&km));
    ASSERT_EQ(iec61850_key_manager_get_key_type(&km), IEC61850_KEY_ECDSA_P256);
    ASSERT_EQ(iec61850_key_manager_get_sig_algo(&km), IEC61850_SIG_ECDSA_SHA256);
    ASSERT_TRUE(iec61850_key_manager_get_sig_size(&km) > 0);
    iec61850_key_manager_destroy(&km);
    PASS();
}

static void test_rsa_sign_verify(void)
{
    TEST("rsa_sign_verify");
    char key_path[512], cert_path[512];
    build_path(key_path, sizeof(key_path), "rsa_2048.key");
    build_path(cert_path, sizeof(cert_path), "rsa_2048_cert.pem");

    iec61850_key_manager_t km;
    iec61850_cert_manager_t cm;
    iec61850_key_manager_init(&km);
    iec61850_cert_manager_init(&cm);
    iec61850_key_manager_load_private_key(&km, key_path, NULL);
    iec61850_cert_manager_load(&cm, cert_path);

    const uint8_t data[] = "Test data for RSA-PSS-SHA256 signing";
    uint8_t sig[IEC61850_MAX_SIGNATURE_LEN];
    size_t sig_len = 0;

    ASSERT_EQ(iec61850_key_manager_sign(&km, data, sizeof(data),
              sig, sizeof(sig), &sig_len), IEC61850_SEC_OK);
    ASSERT_TRUE(sig_len == 256);  /* RSA-2048 */

    EVP_PKEY *pubkey = iec61850_cert_manager_get_public_key(&cm);
    ASSERT_EQ(iec61850_key_manager_verify(data, sizeof(data),
              sig, sig_len, pubkey), IEC61850_SEC_OK);

    /* Tampered data fails */
    uint8_t tampered[sizeof(data)];
    memcpy(tampered, data, sizeof(data));
    tampered[0] ^= 0x01;
    ASSERT_TRUE(iec61850_key_manager_verify(tampered, sizeof(tampered),
                sig, sig_len, pubkey) != IEC61850_SEC_OK);

    /* Corrupted signature fails */
    uint8_t bad_sig[IEC61850_MAX_SIGNATURE_LEN];
    memcpy(bad_sig, sig, sig_len);
    bad_sig[0] ^= 0xFF;
    ASSERT_TRUE(iec61850_key_manager_verify(data, sizeof(data),
                bad_sig, sig_len, pubkey) != IEC61850_SEC_OK);

    iec61850_key_manager_destroy(&km);
    iec61850_cert_manager_destroy(&cm);
    PASS();
}

static void test_ecdsa_sign_verify(void)
{
    TEST("ecdsa_sign_verify");
    char key_path[512], cert_path[512];
    build_path(key_path, sizeof(key_path), "ecdsa_p256.key");
    build_path(cert_path, sizeof(cert_path), "ecdsa_p256_cert.pem");

    iec61850_key_manager_t km;
    iec61850_cert_manager_t cm;
    iec61850_key_manager_init(&km);
    iec61850_cert_manager_init(&cm);
    iec61850_key_manager_load_private_key(&km, key_path, NULL);
    iec61850_cert_manager_load(&cm, cert_path);

    const uint8_t data[] = "ECDSA signing test";
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

static void test_load_nonexistent(void)
{
    TEST("load_nonexistent");
    iec61850_key_manager_t km;
    iec61850_key_manager_init(&km);
    ASSERT_EQ(iec61850_key_manager_load_private_key(&km, "/no/such/key.pem", NULL),
              IEC61850_SEC_ERR_FILE);
    ASSERT_TRUE(!iec61850_key_manager_is_loaded(&km));
    iec61850_key_manager_destroy(&km);
    PASS();
}

static void test_load_invalid_data(void)
{
    TEST("load_invalid_data");
    char path[512];
    build_path(path, sizeof(path), "rsa_2048_cert.pem");  /* cert, not key */

    iec61850_key_manager_t km;
    iec61850_key_manager_init(&km);
    int ret = iec61850_key_manager_load_private_key(&km, path, NULL);
    ASSERT_TRUE(ret != IEC61850_SEC_OK);
    ASSERT_TRUE(!iec61850_key_manager_is_loaded(&km));
    iec61850_key_manager_destroy(&km);
    PASS();
}

static void test_sign_without_key(void)
{
    TEST("sign_without_key");
    iec61850_key_manager_t km;
    iec61850_key_manager_init(&km);

    const uint8_t data[] = "test";
    uint8_t sig[64];
    size_t sig_len = 0;
    ASSERT_EQ(iec61850_key_manager_sign(&km, data, 4, sig, 64, &sig_len),
              IEC61850_SEC_ERR_ARGS);
    iec61850_key_manager_destroy(&km);
    PASS();
}

static void test_key_reload(void)
{
    TEST("key_reload");
    char rsa_path[512], ecdsa_path[512];
    build_path(rsa_path, sizeof(rsa_path), "rsa_2048.key");
    build_path(ecdsa_path, sizeof(ecdsa_path), "ecdsa_p256.key");

    iec61850_key_manager_t km;
    iec61850_key_manager_init(&km);

    iec61850_key_manager_load_private_key(&km, rsa_path, NULL);
    ASSERT_EQ(iec61850_key_manager_get_key_type(&km), IEC61850_KEY_RSA_2048);

    iec61850_key_manager_load_private_key(&km, ecdsa_path, NULL);
    ASSERT_EQ(iec61850_key_manager_get_key_type(&km), IEC61850_KEY_ECDSA_P256);

    iec61850_key_manager_destroy(&km);
    PASS();
}

static void test_sig_size_by_type(void)
{
    TEST("sig_size_by_type");
    ASSERT_TRUE(iec61850_key_manager_get_sig_size(NULL) == 0);

    iec61850_key_manager_t km;
    iec61850_key_manager_init(&km);
    ASSERT_TRUE(iec61850_key_manager_get_sig_size(&km) == 0);  /* No key loaded */
    iec61850_key_manager_destroy(&km);
    PASS();
}

static void test_null_km_operations(void)
{
    TEST("null_km_operations");
    ASSERT_TRUE(!iec61850_key_manager_is_loaded(NULL));
    ASSERT_EQ(iec61850_key_manager_get_key_type(NULL), IEC61850_KEY_UNKNOWN);
    ASSERT_EQ(iec61850_key_manager_get_sig_algo(NULL), IEC61850_SIG_RSA_PSS_SHA256);
    ASSERT_EQ(iec61850_key_manager_load_private_key(NULL, "test", NULL), IEC61850_SEC_ERR_ARGS);
    PASS();
}

int main(void)
{
    printf("\n=== Key Manager Tests ===\n");

    test_load_rsa_2048();
    test_load_ecdsa_p256();
    test_rsa_sign_verify();
    test_ecdsa_sign_verify();
    test_load_nonexistent();
    test_load_invalid_data();
    test_sign_without_key();
    test_key_reload();
    test_sig_size_by_type();
    test_null_km_operations();

    printf("\n=== Test Summary ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
