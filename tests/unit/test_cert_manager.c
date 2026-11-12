/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for Certificate Manager (IEC 62351-6)
 *
 * Tests: load PEM/DER cert, extract subject, compute key ID,
 * extract public key, invalid cert handling, reload.
 *
 * License: BSD-2-Clause
 */

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

static void test_load_valid_pem(void)
{
    TEST("load_valid_pem");
    char path[512];
    build_path(path, sizeof(path), "rsa_2048_cert.pem");

    iec61850_cert_manager_t cm;
    iec61850_cert_manager_init(&cm);
    ASSERT_EQ(iec61850_cert_manager_load(&cm, path), IEC61850_SEC_OK);
    ASSERT_TRUE(iec61850_cert_manager_is_loaded(&cm));
    iec61850_cert_manager_destroy(&cm);
    PASS();
}

static void test_extract_public_key(void)
{
    TEST("extract_public_key");
    char path[512];
    build_path(path, sizeof(path), "rsa_2048_cert.pem");

    iec61850_cert_manager_t cm;
    iec61850_cert_manager_init(&cm);
    iec61850_cert_manager_load(&cm, path);

    EVP_PKEY *pk = iec61850_cert_manager_get_public_key(&cm);
    ASSERT_TRUE(pk != NULL);
    ASSERT_TRUE(EVP_PKEY_bits(pk) == 2048);

    iec61850_cert_manager_destroy(&cm);
    PASS();
}

static void test_key_id_computation(void)
{
    TEST("key_id_computation");
    char path[512];
    build_path(path, sizeof(path), "rsa_2048_cert.pem");

    iec61850_cert_manager_t cm;
    iec61850_cert_manager_init(&cm);
    iec61850_cert_manager_load(&cm, path);

    const uint8_t *key_id = iec61850_cert_manager_get_key_id(&cm);
    ASSERT_TRUE(key_id != NULL);

    /* Key ID should not be all zeros */
    bool all_zero = true;
    for (int i = 0; i < IEC61850_CERT_KEYID_LEN; i++) {
        if (key_id[i] != 0) { all_zero = false; break; }
    }
    ASSERT_TRUE(!all_zero);

    iec61850_cert_manager_destroy(&cm);
    PASS();
}

static void test_extract_subject(void)
{
    TEST("extract_subject");
    char path[512];
    build_path(path, sizeof(path), "rsa_2048_cert.pem");

    iec61850_cert_manager_t cm;
    iec61850_cert_manager_init(&cm);
    iec61850_cert_manager_load(&cm, path);

    const char *subject = iec61850_cert_manager_get_subject(&cm);
    ASSERT_TRUE(subject != NULL);
    ASSERT_TRUE(strlen(subject) > 0);
    ASSERT_TRUE(strstr(subject, "Test IED") != NULL);

    const char *issuer = iec61850_cert_manager_get_issuer(&cm);
    ASSERT_TRUE(issuer != NULL);
    ASSERT_TRUE(strlen(issuer) > 0);

    iec61850_cert_manager_destroy(&cm);
    PASS();
}

static void test_load_nonexistent_file(void)
{
    TEST("load_nonexistent_file");
    iec61850_cert_manager_t cm;
    iec61850_cert_manager_init(&cm);

    ASSERT_EQ(iec61850_cert_manager_load(&cm, "/nonexistent/cert.pem"),
              IEC61850_SEC_ERR_FILE);
    ASSERT_TRUE(!iec61850_cert_manager_is_loaded(&cm));

    iec61850_cert_manager_destroy(&cm);
    PASS();
}

static void test_load_invalid_data(void)
{
    TEST("load_invalid_data");
    /* Try loading a key file as a cert — should fail */
    char path[512];
    build_path(path, sizeof(path), "rsa_2048.key");

    iec61850_cert_manager_t cm;
    iec61850_cert_manager_init(&cm);

    int ret = iec61850_cert_manager_load(&cm, path);
    ASSERT_TRUE(ret != IEC61850_SEC_OK);
    ASSERT_TRUE(!iec61850_cert_manager_is_loaded(&cm));

    iec61850_cert_manager_destroy(&cm);
    PASS();
}

static void test_null_inputs(void)
{
    TEST("null_inputs");

    ASSERT_EQ(iec61850_cert_manager_load(NULL, "test.pem"), IEC61850_SEC_ERR_ARGS);

    iec61850_cert_manager_t cm;
    iec61850_cert_manager_init(&cm);
    ASSERT_EQ(iec61850_cert_manager_load(&cm, NULL), IEC61850_SEC_ERR_ARGS);

    /* Operations on unloaded cert */
    ASSERT_TRUE(!iec61850_cert_manager_is_loaded(&cm));
    ASSERT_TRUE(iec61850_cert_manager_get_public_key(&cm) == NULL);
    ASSERT_TRUE(iec61850_cert_manager_get_key_id(&cm) == NULL);
    ASSERT_TRUE(strlen(iec61850_cert_manager_get_subject(&cm)) == 0);

    /* NULL cert manager */
    ASSERT_TRUE(!iec61850_cert_manager_is_loaded(NULL));
    ASSERT_TRUE(iec61850_cert_manager_get_public_key(NULL) == NULL);
    ASSERT_TRUE(iec61850_cert_manager_get_key_id(NULL) == NULL);

    iec61850_cert_manager_destroy(&cm);
    PASS();
}

static void test_cert_reload(void)
{
    TEST("cert_reload");
    char path1[512], path2[512];
    build_path(path1, sizeof(path1), "rsa_2048_cert.pem");
    build_path(path2, sizeof(path2), "rsa_2048_other_cert.pem");

    iec61850_cert_manager_t cm;
    iec61850_cert_manager_init(&cm);

    iec61850_cert_manager_load(&cm, path1);
    const char *subj1 = iec61850_cert_manager_get_subject(&cm);
    ASSERT_TRUE(strstr(subj1, "Test IED") != NULL);

    /* Reload with different cert */
    iec61850_cert_manager_load(&cm, path2);
    const char *subj2 = iec61850_cert_manager_get_subject(&cm);
    ASSERT_TRUE(strstr(subj2, "Other IED") != NULL);

    iec61850_cert_manager_destroy(&cm);
    PASS();
}

static void test_unique_key_ids(void)
{
    TEST("unique_key_ids");
    char path1[512], path2[512];
    build_path(path1, sizeof(path1), "rsa_2048_cert.pem");
    build_path(path2, sizeof(path2), "rsa_2048_other_cert.pem");

    iec61850_cert_manager_t cm1, cm2;
    iec61850_cert_manager_init(&cm1);
    iec61850_cert_manager_init(&cm2);

    iec61850_cert_manager_load(&cm1, path1);
    iec61850_cert_manager_load(&cm2, path2);

    const uint8_t *id1 = iec61850_cert_manager_get_key_id(&cm1);
    const uint8_t *id2 = iec61850_cert_manager_get_key_id(&cm2);
    ASSERT_TRUE(id1 != NULL);
    ASSERT_TRUE(id2 != NULL);

    /* Key IDs should be different */
    ASSERT_TRUE(memcmp(id1, id2, IEC61850_CERT_KEYID_LEN) != 0);

    iec61850_cert_manager_destroy(&cm1);
    iec61850_cert_manager_destroy(&cm2);
    PASS();
}

static void test_ecdsa_cert(void)
{
    TEST("ecdsa_cert");
    char path[512];
    build_path(path, sizeof(path), "ecdsa_p256_cert.pem");

    iec61850_cert_manager_t cm;
    iec61850_cert_manager_init(&cm);
    ASSERT_EQ(iec61850_cert_manager_load(&cm, path), IEC61850_SEC_OK);
    ASSERT_TRUE(iec61850_cert_manager_is_loaded(&cm));

    EVP_PKEY *pk = iec61850_cert_manager_get_public_key(&cm);
    ASSERT_TRUE(pk != NULL);
    ASSERT_TRUE(EVP_PKEY_id(pk) == EVP_PKEY_EC);

    iec61850_cert_manager_destroy(&cm);
    PASS();
}

int main(void)
{
    printf("\n=== Certificate Manager Tests ===\n");

    test_load_valid_pem();
    test_extract_public_key();
    test_key_id_computation();
    test_extract_subject();
    test_load_nonexistent_file();
    test_load_invalid_data();
    test_null_inputs();
    test_cert_reload();
    test_unique_key_ids();
    test_ecdsa_cert();

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
