/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Property-Based Tests for IEC 62351-6 Security
 *
 * Properties verified:
 *   1. For any valid APDU, sign then verify always succeeds
 *   2. For any tampered APDU, verify always fails
 *   3. Cross-validation: sign with key1, verify with key2 always fails
 *   4. Tampered signature always fails
 *
 * License: BSD-2-Clause
 */

#include "property_test.h"
#include "security/key_manager.h"
#include "security/cert_manager.h"

#include <stdio.h>
#include <string.h>

static void build_path(char *out, size_t out_size, const char *filename)
{
    const char *root = getenv("MESON_SOURCE_ROOT");
    if (root != NULL) {
        snprintf(out, out_size, "%s/tests/data/certs/%s", root, filename);
    } else {
        snprintf(out, out_size, "tests/data/certs/%s", filename);
    }
}

/* Global state shared across property tests */
static iec61850_key_manager_t g_km1, g_km2;
static iec61850_cert_manager_t g_cm1, g_cm2;
static EVP_PKEY *g_pubkey1, *g_pubkey2;

static void prop_sign_verify(void)
{
    PROPERTY_TEST("sign_then_verify_always_succeeds", 1000) {
        uint8_t data[256];
        size_t data_len = (size_t)(1 + (rand() % 255));
        for (size_t j = 0; j < data_len; j++) {
            data[j] = random_uint8();
        }

        uint8_t sig[IEC61850_MAX_SIGNATURE_LEN];
        size_t sig_len = 0;

        int ret = iec61850_key_manager_sign(&g_km1, data, data_len,
                                              sig, sizeof(sig), &sig_len);
        PROPERTY_ASSERT(ret == IEC61850_SEC_OK, "sign failed");
        PROPERTY_ASSERT(sig_len > 0, "sig_len is 0");

        ret = iec61850_key_manager_verify(data, data_len,
                                            sig, sig_len, g_pubkey1);
        PROPERTY_ASSERT(ret == IEC61850_SEC_OK, "verify failed for valid signature");
    }
    PROPERTY_TEST_END();
}

static void prop_tampered_data(void)
{
    PROPERTY_TEST("tampered_data_always_fails", 1000) {
        uint8_t data[128];
        size_t data_len = (size_t)(1 + (rand() % 127));
        for (size_t j = 0; j < data_len; j++) {
            data[j] = random_uint8();
        }

        uint8_t sig[IEC61850_MAX_SIGNATURE_LEN];
        size_t sig_len = 0;
        iec61850_key_manager_sign(&g_km1, data, data_len,
                                    sig, sizeof(sig), &sig_len);

        size_t tamper_pos = (size_t)(rand() % (int)data_len);
        uint8_t tamper_bit = (uint8_t)(1U << (rand() % 8));
        data[tamper_pos] ^= tamper_bit;

        int ret = iec61850_key_manager_verify(data, data_len,
                                                sig, sig_len, g_pubkey1);
        PROPERTY_ASSERT(ret != IEC61850_SEC_OK, "tampered data verified successfully");
    }
    PROPERTY_TEST_END();

}

static void prop_wrong_key(void)
{
    PROPERTY_TEST("wrong_key_always_fails", 500) {
        uint8_t data[64];
        size_t data_len = (size_t)(1 + (rand() % 63));
        for (size_t j = 0; j < data_len; j++) {
            data[j] = random_uint8();
        }

        uint8_t sig[IEC61850_MAX_SIGNATURE_LEN];
        size_t sig_len = 0;
        iec61850_key_manager_sign(&g_km1, data, data_len,
                                    sig, sizeof(sig), &sig_len);

        int ret = iec61850_key_manager_verify(data, data_len,
                                                sig, sig_len, g_pubkey2);
        PROPERTY_ASSERT(ret != IEC61850_SEC_OK, "wrong key verified successfully");
    }
    PROPERTY_TEST_END();

}

static void prop_tampered_sig(void)
{
    PROPERTY_TEST("tampered_signature_always_fails", 500) {
        uint8_t data[32];
        size_t data_len = (size_t)(1 + (rand() % 31));
        for (size_t j = 0; j < data_len; j++) {
            data[j] = random_uint8();
        }

        uint8_t sig[IEC61850_MAX_SIGNATURE_LEN];
        size_t sig_len = 0;
        iec61850_key_manager_sign(&g_km1, data, data_len,
                                    sig, sizeof(sig), &sig_len);

        size_t tamper_pos = (size_t)(rand() % (int)sig_len);
        sig[tamper_pos] ^= 0xFF;

        int ret = iec61850_key_manager_verify(data, data_len,
                                                sig, sig_len, g_pubkey1);
        PROPERTY_ASSERT(ret != IEC61850_SEC_OK, "tampered signature verified");
    }
    PROPERTY_TEST_END();

}

int main(void)
{
    char key_path[512], cert_path[512];
    char key_path2[512], cert_path2[512];

    build_path(key_path, sizeof(key_path), "rsa_2048.key");
    build_path(cert_path, sizeof(cert_path), "rsa_2048_cert.pem");
    build_path(key_path2, sizeof(key_path2), "rsa_2048_other.key");
    build_path(cert_path2, sizeof(cert_path2), "rsa_2048_other_cert.pem");

    property_test_init();

    iec61850_key_manager_init(&g_km1);
    iec61850_key_manager_init(&g_km2);
    iec61850_cert_manager_init(&g_cm1);
    iec61850_cert_manager_init(&g_cm2);

    if (iec61850_key_manager_load_private_key(&g_km1, key_path, NULL) != IEC61850_SEC_OK ||
        iec61850_cert_manager_load(&g_cm1, cert_path) != IEC61850_SEC_OK ||
        iec61850_key_manager_load_private_key(&g_km2, key_path2, NULL) != IEC61850_SEC_OK ||
        iec61850_cert_manager_load(&g_cm2, cert_path2) != IEC61850_SEC_OK) {
        printf("FATAL: Cannot load test keys/certs\n");
        return 1;
    }

    g_pubkey1 = iec61850_cert_manager_get_public_key(&g_cm1);
    g_pubkey2 = iec61850_cert_manager_get_public_key(&g_cm2);

    prop_sign_verify();
    prop_tampered_data();
    prop_wrong_key();
    prop_tampered_sig();

    iec61850_key_manager_destroy(&g_km1);
    iec61850_key_manager_destroy(&g_km2);
    iec61850_cert_manager_destroy(&g_cm1);
    iec61850_cert_manager_destroy(&g_cm2);

    property_test_summary();
    return property_tests_failed > 0 ? 1 : 0;
}
