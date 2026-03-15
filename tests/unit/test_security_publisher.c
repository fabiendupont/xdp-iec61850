/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Security Publisher Tests
 *
 * Covers the security extension paths in:
 *   - goose_publisher.c: enable_security, append_security_extension, build_frame
 *   - sv_publisher.c: enable_security, sv_append_security_extension, build_frame
 *
 * Generates RSA-2048 key + self-signed cert via OpenSSL API,
 * loads into key_manager/cert_manager, then exercises the publisher
 * security paths that are otherwise unreachable without real credentials.
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "goose/goose_publisher.h"
#include "sv/sv_publisher.h"
#include "security/key_manager.h"
#include "security/cert_manager.h"
#include "transport/eth_frame.h"

static int tests_passed = 0;
static int tests_failed = 0;

#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL: %s:%d: %s\n", __FILE__, __LINE__, msg); \
        tests_failed++; \
        return; \
    } \
} while(0)

#define TEST_PASS() do { \
    tests_passed++; \
    printf("."); \
    fflush(stdout); \
} while(0)

/* Temp file paths */
static char tmp_key_path[256];
static char tmp_cert_path[256];
static char tmp_ec_key_path[256];
static char tmp_ec_cert_path[256];

static int generate_test_key_and_cert(const char *key_path, const char *cert_path)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx == NULL) { return -1; }
    if (EVP_PKEY_keygen_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return -1; }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) { EVP_PKEY_CTX_free(ctx); return -1; }
    if (EVP_PKEY_keygen(ctx, &key) <= 0) { EVP_PKEY_CTX_free(ctx); return -1; }
    EVP_PKEY_CTX_free(ctx);

    /* Write private key */
    FILE *f = fopen(key_path, "w");
    if (f == NULL) { EVP_PKEY_free(key); return -1; }
    PEM_write_PrivateKey(f, key, NULL, NULL, 0, NULL, NULL);
    fclose(f);

    /* Self-signed certificate */
    X509 *cert = X509_new();
    if (cert == NULL) { EVP_PKEY_free(key); return -1; }
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 365L * 24 * 3600);
    X509_set_pubkey(cert, key);
    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *)"TestSecPub", -1, -1, 0);
    X509_set_issuer_name(cert, name);
    X509_sign(cert, key, EVP_sha256());

    FILE *cf = fopen(cert_path, "w");
    if (cf == NULL) { X509_free(cert); EVP_PKEY_free(key); return -1; }
    PEM_write_X509(cf, cert);
    fclose(cf);

    X509_free(cert);
    EVP_PKEY_free(key);
    return 0;
}

static int generate_ec_key_and_cert(const char *key_path, const char *cert_path)
{
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (ctx == NULL) { return -1; }
    if (EVP_PKEY_keygen_init(ctx) <= 0) { EVP_PKEY_CTX_free(ctx); return -1; }
    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1) <= 0) {
        EVP_PKEY_CTX_free(ctx); return -1;
    }
    if (EVP_PKEY_keygen(ctx, &key) <= 0) { EVP_PKEY_CTX_free(ctx); return -1; }
    EVP_PKEY_CTX_free(ctx);

    FILE *f = fopen(key_path, "w");
    if (f == NULL) { EVP_PKEY_free(key); return -1; }
    PEM_write_PrivateKey(f, key, NULL, NULL, 0, NULL, NULL);
    fclose(f);

    X509 *cert = X509_new();
    if (cert == NULL) { EVP_PKEY_free(key); return -1; }
    X509_set_version(cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert), 2);
    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 365L * 24 * 3600);
    X509_set_pubkey(cert, key);
    X509_NAME *name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *)"TestEC", -1, -1, 0);
    X509_set_issuer_name(cert, name);
    X509_sign(cert, key, EVP_sha256());

    FILE *cf = fopen(cert_path, "w");
    if (cf == NULL) { X509_free(cert); EVP_PKEY_free(key); return -1; }
    PEM_write_X509(cf, cert);
    fclose(cf);

    X509_free(cert);
    EVP_PKEY_free(key);
    return 0;
}

/* ECDSA publisher tests — short signatures cover the sig_len < 128 branches */
static void test_goose_build_frame_ecdsa(void)
{
    iec61850_key_manager_t km;
    iec61850_cert_manager_t cm;
    iec61850_goose_publisher_t pub;
    iec61850_goose_config_t cfg;

    iec61850_key_manager_init(&km);
    iec61850_cert_manager_init(&cm);
    (void)iec61850_key_manager_load_private_key(&km, tmp_ec_key_path, NULL);
    (void)iec61850_cert_manager_load(&cm, tmp_ec_cert_path);

    iec61850_goose_config_init(&cfg);
    iec61850_goose_publisher_init(&pub, &cfg);
    (void)iec61850_goose_publisher_set_boolean(&pub, 0, true);

    int ret = iec61850_goose_publisher_enable_security(&pub, &km, &cm);
    TEST_ASSERT(ret == 0, "ECDSA enable_security should succeed");

    uint8_t frame[IEC61850_MAX_FRAME_SIZE];
    size_t frame_len = 0;
    ret = iec61850_goose_publisher_build_frame(&pub, frame, sizeof(frame),
                                                &frame_len);
    TEST_ASSERT(ret == 0, "ECDSA GOOSE build_frame should succeed");
    TEST_ASSERT(frame_len > 0, "frame should be non-empty");

    /* ECDSA P256 signature is ~72 bytes — short form branch */
    bool found_ac = false;
    for (size_t i = 0; i < frame_len; i++) {
        if (frame[i] == 0xAC) { found_ac = true; break; }
    }
    TEST_ASSERT(found_ac, "ECDSA frame should contain 0xAC");

    iec61850_goose_publisher_destroy(&pub);
    iec61850_cert_manager_destroy(&cm);
    iec61850_key_manager_destroy(&km);
    TEST_PASS();
}

static void test_sv_build_frame_ecdsa(void)
{
    iec61850_key_manager_t km;
    iec61850_cert_manager_t cm;
    iec61850_sv_publisher_t pub;
    iec61850_sv_config_t cfg;

    iec61850_key_manager_init(&km);
    iec61850_cert_manager_init(&cm);
    (void)iec61850_key_manager_load_private_key(&km, tmp_ec_key_path, NULL);
    (void)iec61850_cert_manager_load(&cm, tmp_ec_cert_path);

    iec61850_sv_config_init(&cfg);
    iec61850_sv_publisher_init(&pub, &cfg);
    (void)iec61850_sv_publisher_set_sample(&pub, 0, 1000);

    int ret = iec61850_sv_publisher_enable_security(&pub, &km, &cm);
    TEST_ASSERT(ret == 0, "ECDSA SV enable_security should succeed");

    uint8_t frame[IEC61850_MAX_FRAME_SIZE];
    size_t frame_len = 0;
    ret = iec61850_sv_publisher_build_frame(&pub, frame, sizeof(frame),
                                             &frame_len);
    TEST_ASSERT(ret == 0, "ECDSA SV build_frame should succeed");
    TEST_ASSERT(frame_len > 0, "SV frame should be non-empty");

    bool found_a9 = false;
    for (size_t i = 0; i < frame_len; i++) {
        if (frame[i] == 0xA9) { found_a9 = true; break; }
    }
    TEST_ASSERT(found_a9, "ECDSA SV frame should contain 0xA9");

    iec61850_sv_publisher_destroy(&pub);
    iec61850_cert_manager_destroy(&cm);
    iec61850_key_manager_destroy(&km);
    TEST_PASS();
}

static void cleanup_temp_files(void)
{
    (void)unlink(tmp_key_path);
    (void)unlink(tmp_cert_path);
    (void)unlink(tmp_ec_key_path);
    (void)unlink(tmp_ec_cert_path);
}

/***************************************************************************
 * Test 1: GOOSE publisher enable_security — success path
 ***************************************************************************/
static void test_goose_enable_security_success(void)
{
    iec61850_key_manager_t km;
    iec61850_cert_manager_t cm;
    iec61850_goose_publisher_t pub;
    iec61850_goose_config_t cfg;

    iec61850_key_manager_init(&km);
    iec61850_cert_manager_init(&cm);

    int ret = iec61850_key_manager_load_private_key(&km, tmp_key_path, NULL);
    TEST_ASSERT(ret == 0, "key load should succeed");

    ret = iec61850_cert_manager_load(&cm, tmp_cert_path);
    TEST_ASSERT(ret == 0, "cert load should succeed");

    iec61850_goose_config_init(&cfg);
    iec61850_goose_publisher_init(&pub, &cfg);

    ret = iec61850_goose_publisher_enable_security(&pub, &km, &cm);
    TEST_ASSERT(ret == 0, "GOOSE enable_security should return 0");
    TEST_ASSERT(pub.security_enabled == true, "security_enabled should be true");

    iec61850_goose_publisher_destroy(&pub);
    iec61850_cert_manager_destroy(&cm);
    iec61850_key_manager_destroy(&km);
    TEST_PASS();
}

/***************************************************************************
 * Test 2: GOOSE publisher build_frame with security — tag 0xAC present
 ***************************************************************************/
static void test_goose_build_frame_with_security(void)
{
    iec61850_key_manager_t km;
    iec61850_cert_manager_t cm;
    iec61850_goose_publisher_t pub;
    iec61850_goose_config_t cfg;

    iec61850_key_manager_init(&km);
    iec61850_cert_manager_init(&cm);
    (void)iec61850_key_manager_load_private_key(&km, tmp_key_path, NULL);
    (void)iec61850_cert_manager_load(&cm, tmp_cert_path);

    iec61850_goose_config_init(&cfg);
    iec61850_goose_publisher_init(&pub, &cfg);
    (void)iec61850_goose_publisher_set_boolean(&pub, 0, true);
    (void)iec61850_goose_publisher_set_int32(&pub, 1, 42);

    int ret = iec61850_goose_publisher_enable_security(&pub, &km, &cm);
    TEST_ASSERT(ret == 0, "enable_security should succeed");

    uint8_t frame[IEC61850_MAX_FRAME_SIZE];
    size_t frame_len = 0;
    ret = iec61850_goose_publisher_build_frame(&pub, frame, sizeof(frame),
                                                &frame_len);
    TEST_ASSERT(ret == 0, "build_frame with security should succeed");
    TEST_ASSERT(frame_len > 0, "frame should have non-zero length");

    /* Search for GOOSE security extension tag 0xAC in the frame */
    bool found_ac = false;
    for (size_t i = 0; i < frame_len; i++) {
        if (frame[i] == 0xAC) {
            found_ac = true;
            break;
        }
    }
    TEST_ASSERT(found_ac, "frame should contain GOOSE security tag 0xAC");

    iec61850_goose_publisher_destroy(&pub);
    iec61850_cert_manager_destroy(&cm);
    iec61850_key_manager_destroy(&km);
    TEST_PASS();
}

/***************************************************************************
 * Test 3: SV publisher enable_security — success path
 ***************************************************************************/
static void test_sv_enable_security_success(void)
{
    iec61850_key_manager_t km;
    iec61850_cert_manager_t cm;
    iec61850_sv_publisher_t pub;
    iec61850_sv_config_t cfg;

    iec61850_key_manager_init(&km);
    iec61850_cert_manager_init(&cm);
    (void)iec61850_key_manager_load_private_key(&km, tmp_key_path, NULL);
    (void)iec61850_cert_manager_load(&cm, tmp_cert_path);

    iec61850_sv_config_init(&cfg);
    iec61850_sv_publisher_init(&pub, &cfg);

    int ret = iec61850_sv_publisher_enable_security(&pub, &km, &cm);
    TEST_ASSERT(ret == 0, "SV enable_security should return 0");
    TEST_ASSERT(pub.security_enabled == true, "security_enabled should be true");

    iec61850_sv_publisher_destroy(&pub);
    iec61850_cert_manager_destroy(&cm);
    iec61850_key_manager_destroy(&km);
    TEST_PASS();
}

/***************************************************************************
 * Test 4: SV publisher build_frame with security — tag 0xA9 present
 ***************************************************************************/
static void test_sv_build_frame_with_security(void)
{
    iec61850_key_manager_t km;
    iec61850_cert_manager_t cm;
    iec61850_sv_publisher_t pub;
    iec61850_sv_config_t cfg;

    iec61850_key_manager_init(&km);
    iec61850_cert_manager_init(&cm);
    (void)iec61850_key_manager_load_private_key(&km, tmp_key_path, NULL);
    (void)iec61850_cert_manager_load(&cm, tmp_cert_path);

    iec61850_sv_config_init(&cfg);
    cfg.num_channels = 4;
    iec61850_sv_publisher_init(&pub, &cfg);
    (void)iec61850_sv_publisher_set_sample(&pub, 0, 1000);
    (void)iec61850_sv_publisher_set_sample(&pub, 1, 2000);
    (void)iec61850_sv_publisher_set_sample(&pub, 2, 3000);
    (void)iec61850_sv_publisher_set_sample(&pub, 3, 4000);

    int ret = iec61850_sv_publisher_enable_security(&pub, &km, &cm);
    TEST_ASSERT(ret == 0, "enable_security should succeed");

    uint8_t frame[IEC61850_MAX_FRAME_SIZE];
    size_t frame_len = 0;
    ret = iec61850_sv_publisher_build_frame(&pub, frame, sizeof(frame),
                                             &frame_len);
    TEST_ASSERT(ret == 0, "build_frame with security should succeed");
    TEST_ASSERT(frame_len > 0, "frame should have non-zero length");

    /* Search for SV security extension tag 0xA9 in the frame */
    bool found_a9 = false;
    for (size_t i = 0; i < frame_len; i++) {
        if (frame[i] == 0xA9) {
            found_a9 = true;
            break;
        }
    }
    TEST_ASSERT(found_a9, "frame should contain SV security tag 0xA9");

    iec61850_sv_publisher_destroy(&pub);
    iec61850_cert_manager_destroy(&cm);
    iec61850_key_manager_destroy(&km);
    TEST_PASS();
}

/***************************************************************************
 * Test 5: enable_security NULL argument combos
 ***************************************************************************/
static void test_enable_security_null_args(void)
{
    iec61850_key_manager_t km;
    iec61850_cert_manager_t cm;
    iec61850_goose_publisher_t gpub;
    iec61850_sv_publisher_t spub;

    iec61850_key_manager_init(&km);
    iec61850_cert_manager_init(&cm);
    iec61850_goose_publisher_init(&gpub, NULL);
    iec61850_sv_publisher_init(&spub, NULL);

    /* GOOSE: NULL pub */
    int ret = iec61850_goose_publisher_enable_security(NULL, &km, &cm);
    TEST_ASSERT(ret == -EINVAL, "GOOSE NULL pub should return -EINVAL");

    /* GOOSE: NULL key_manager */
    ret = iec61850_goose_publisher_enable_security(&gpub, NULL, &cm);
    TEST_ASSERT(ret == -EINVAL, "GOOSE NULL key_manager should return -EINVAL");

    /* GOOSE: NULL cert_manager */
    ret = iec61850_goose_publisher_enable_security(&gpub, &km, NULL);
    TEST_ASSERT(ret == -EINVAL, "GOOSE NULL cert_manager should return -EINVAL");

    /* SV: NULL pub */
    ret = iec61850_sv_publisher_enable_security(NULL, &km, &cm);
    TEST_ASSERT(ret == -EINVAL, "SV NULL pub should return -EINVAL");

    /* SV: NULL key_manager */
    ret = iec61850_sv_publisher_enable_security(&spub, NULL, &cm);
    TEST_ASSERT(ret == -EINVAL, "SV NULL key_manager should return -EINVAL");

    /* SV: NULL cert_manager */
    ret = iec61850_sv_publisher_enable_security(&spub, &km, NULL);
    TEST_ASSERT(ret == -EINVAL, "SV NULL cert_manager should return -EINVAL");

    iec61850_sv_publisher_destroy(&spub);
    iec61850_goose_publisher_destroy(&gpub);
    iec61850_cert_manager_destroy(&cm);
    iec61850_key_manager_destroy(&km);
    TEST_PASS();
}

/***************************************************************************
 * Test 6: enable_security with unloaded key/cert managers
 ***************************************************************************/
static void test_enable_security_unloaded(void)
{
    iec61850_key_manager_t km;
    iec61850_cert_manager_t cm;
    iec61850_goose_publisher_t gpub;
    iec61850_sv_publisher_t spub;

    iec61850_key_manager_init(&km);
    iec61850_cert_manager_init(&cm);
    iec61850_goose_publisher_init(&gpub, NULL);
    iec61850_sv_publisher_init(&spub, NULL);

    /* Key not loaded — should fail */
    int ret = iec61850_goose_publisher_enable_security(&gpub, &km, &cm);
    TEST_ASSERT(ret == -EINVAL, "GOOSE unloaded key should return -EINVAL");

    ret = iec61850_sv_publisher_enable_security(&spub, &km, &cm);
    TEST_ASSERT(ret == -EINVAL, "SV unloaded key should return -EINVAL");

    /* Load key but not cert — should still fail */
    (void)iec61850_key_manager_load_private_key(&km, tmp_key_path, NULL);

    ret = iec61850_goose_publisher_enable_security(&gpub, &km, &cm);
    TEST_ASSERT(ret == -EINVAL, "GOOSE unloaded cert should return -EINVAL");

    ret = iec61850_sv_publisher_enable_security(&spub, &km, &cm);
    TEST_ASSERT(ret == -EINVAL, "SV unloaded cert should return -EINVAL");

    iec61850_sv_publisher_destroy(&spub);
    iec61850_goose_publisher_destroy(&gpub);
    iec61850_cert_manager_destroy(&cm);
    iec61850_key_manager_destroy(&km);
    TEST_PASS();
}

/***************************************************************************
 * Test 7: GOOSE retransmit enable + state_change resets
 ***************************************************************************/
static void test_goose_retransmit_with_state_change(void)
{
    iec61850_goose_publisher_t pub;
    iec61850_goose_config_t cfg;

    iec61850_goose_config_init(&cfg);
    iec61850_goose_publisher_init(&pub, &cfg);

    /* Enable retransmit */
    iec61850_retransmit_config_t rcfg;
    rcfg.t0_ms = 2;
    rcfg.t_max_ms = 1000;
    iec61850_goose_publisher_enable_retransmit(&pub, &rcfg);
    TEST_ASSERT(pub.has_retransmit == true, "has_retransmit should be true");

    /* Initial state */
    TEST_ASSERT(iec61850_goose_publisher_get_st_num(&pub) == 0,
                "initial stNum should be 0");
    TEST_ASSERT(iec61850_goose_publisher_get_sq_num(&pub) == 0,
                "initial sqNum should be 0");

    /* Build a frame to advance sqNum */
    uint8_t frame[IEC61850_MAX_FRAME_SIZE];
    size_t frame_len = 0;
    (void)iec61850_goose_publisher_set_boolean(&pub, 0, true);
    int ret = iec61850_goose_publisher_build_frame(&pub, frame, sizeof(frame),
                                                    &frame_len);
    TEST_ASSERT(ret == 0, "build_frame should succeed");
    TEST_ASSERT(iec61850_goose_publisher_get_sq_num(&pub) == 1,
                "sqNum should be 1 after first frame");

    /* State change resets sqNum and increments stNum */
    iec61850_goose_publisher_state_change(&pub);
    TEST_ASSERT(iec61850_goose_publisher_get_st_num(&pub) == 1,
                "stNum should be 1 after state_change");
    TEST_ASSERT(iec61850_goose_publisher_get_sq_num(&pub) == 0,
                "sqNum should be 0 after state_change");

    /* Retransmit state_changed flag should be set */
    TEST_ASSERT(pub.retransmit.state_changed == true,
                "retransmit state_changed should be true after state_change");

    /* Another state change */
    iec61850_goose_publisher_state_change(&pub);
    TEST_ASSERT(iec61850_goose_publisher_get_st_num(&pub) == 2,
                "stNum should be 2 after second state_change");

    iec61850_goose_publisher_destroy(&pub);
    TEST_PASS();
}

/***************************************************************************
 * Test 8: set_io on GOOSE and SV publishers
 ***************************************************************************/
static void test_publisher_set_io(void)
{
    iec61850_goose_publisher_t gpub;
    iec61850_sv_publisher_t spub;

    iec61850_goose_publisher_init(&gpub, NULL);
    iec61850_sv_publisher_init(&spub, NULL);

    /* Initially NULL */
    TEST_ASSERT(gpub.io == NULL, "GOOSE io should be NULL initially");
    TEST_ASSERT(spub.io == NULL, "SV io should be NULL initially");

    /* Set a dummy pointer (we only test the setter, not actual I/O) */
    struct packet_io dummy_io;
    (void)memset(&dummy_io, 0, sizeof(dummy_io));

    iec61850_goose_publisher_set_io(&gpub, &dummy_io);
    TEST_ASSERT(gpub.io == &dummy_io, "GOOSE io should be set");

    iec61850_sv_publisher_set_io(&spub, &dummy_io);
    TEST_ASSERT(spub.io == &dummy_io, "SV io should be set");

    /* Setting NULL io */
    iec61850_goose_publisher_set_io(&gpub, NULL);
    TEST_ASSERT(gpub.io == NULL, "GOOSE io should be NULL after clearing");

    iec61850_sv_publisher_set_io(&spub, NULL);
    TEST_ASSERT(spub.io == NULL, "SV io should be NULL after clearing");

    /* NULL publisher should not crash */
    iec61850_goose_publisher_set_io(NULL, &dummy_io);
    iec61850_sv_publisher_set_io(NULL, &dummy_io);

    iec61850_sv_publisher_destroy(&spub);
    iec61850_goose_publisher_destroy(&gpub);
    TEST_PASS();
}

/***************************************************************************
 * Test 9: GOOSE security frame is larger than non-security frame
 ***************************************************************************/
static void test_goose_security_frame_size(void)
{
    iec61850_key_manager_t km;
    iec61850_cert_manager_t cm;
    iec61850_goose_publisher_t pub_plain;
    iec61850_goose_publisher_t pub_sec;
    iec61850_goose_config_t cfg;

    iec61850_key_manager_init(&km);
    iec61850_cert_manager_init(&cm);
    (void)iec61850_key_manager_load_private_key(&km, tmp_key_path, NULL);
    (void)iec61850_cert_manager_load(&cm, tmp_cert_path);

    iec61850_goose_config_init(&cfg);

    /* Plain frame */
    iec61850_goose_publisher_init(&pub_plain, &cfg);
    (void)iec61850_goose_publisher_set_boolean(&pub_plain, 0, false);

    uint8_t frame_plain[IEC61850_MAX_FRAME_SIZE];
    size_t len_plain = 0;
    int ret = iec61850_goose_publisher_build_frame(&pub_plain, frame_plain,
                                                    sizeof(frame_plain), &len_plain);
    TEST_ASSERT(ret == 0, "plain build_frame should succeed");

    /* Secured frame */
    iec61850_goose_publisher_init(&pub_sec, &cfg);
    (void)iec61850_goose_publisher_set_boolean(&pub_sec, 0, false);
    (void)iec61850_goose_publisher_enable_security(&pub_sec, &km, &cm);

    uint8_t frame_sec[IEC61850_MAX_FRAME_SIZE];
    size_t len_sec = 0;
    ret = iec61850_goose_publisher_build_frame(&pub_sec, frame_sec,
                                                sizeof(frame_sec), &len_sec);
    TEST_ASSERT(ret == 0, "security build_frame should succeed");
    TEST_ASSERT(len_sec > len_plain,
                "secured frame should be larger than plain frame");

    iec61850_goose_publisher_destroy(&pub_plain);
    iec61850_goose_publisher_destroy(&pub_sec);
    iec61850_cert_manager_destroy(&cm);
    iec61850_key_manager_destroy(&km);
    TEST_PASS();
}

/***************************************************************************
 * Test 10: SV security frame is larger than non-security frame
 ***************************************************************************/
static void test_sv_security_frame_size(void)
{
    iec61850_key_manager_t km;
    iec61850_cert_manager_t cm;
    iec61850_sv_publisher_t pub_plain;
    iec61850_sv_publisher_t pub_sec;
    iec61850_sv_config_t cfg;

    iec61850_key_manager_init(&km);
    iec61850_cert_manager_init(&cm);
    (void)iec61850_key_manager_load_private_key(&km, tmp_key_path, NULL);
    (void)iec61850_cert_manager_load(&cm, tmp_cert_path);

    iec61850_sv_config_init(&cfg);
    cfg.num_channels = 2;

    /* Plain frame */
    iec61850_sv_publisher_init(&pub_plain, &cfg);
    (void)iec61850_sv_publisher_set_sample(&pub_plain, 0, 100);
    (void)iec61850_sv_publisher_set_sample(&pub_plain, 1, 200);

    uint8_t frame_plain[IEC61850_MAX_FRAME_SIZE];
    size_t len_plain = 0;
    int ret = iec61850_sv_publisher_build_frame(&pub_plain, frame_plain,
                                                 sizeof(frame_plain), &len_plain);
    TEST_ASSERT(ret == 0, "plain SV build_frame should succeed");

    /* Secured frame */
    iec61850_sv_publisher_init(&pub_sec, &cfg);
    (void)iec61850_sv_publisher_set_sample(&pub_sec, 0, 100);
    (void)iec61850_sv_publisher_set_sample(&pub_sec, 1, 200);
    (void)iec61850_sv_publisher_enable_security(&pub_sec, &km, &cm);

    uint8_t frame_sec[IEC61850_MAX_FRAME_SIZE];
    size_t len_sec = 0;
    ret = iec61850_sv_publisher_build_frame(&pub_sec, frame_sec,
                                             sizeof(frame_sec), &len_sec);
    TEST_ASSERT(ret == 0, "security SV build_frame should succeed");
    TEST_ASSERT(len_sec > len_plain,
                "secured SV frame should be larger than plain frame");

    iec61850_sv_publisher_destroy(&pub_plain);
    iec61850_sv_publisher_destroy(&pub_sec);
    iec61850_cert_manager_destroy(&cm);
    iec61850_key_manager_destroy(&km);
    TEST_PASS();
}

/***************************************************************************
 * Test 11: build_frame NULL arguments
 ***************************************************************************/
static void test_build_frame_null_args(void)
{
    iec61850_goose_publisher_t gpub;
    iec61850_sv_publisher_t spub;
    uint8_t frame[IEC61850_MAX_FRAME_SIZE];
    size_t frame_len = 0;

    iec61850_goose_publisher_init(&gpub, NULL);
    iec61850_sv_publisher_init(&spub, NULL);

    /* GOOSE NULL args */
    int ret = iec61850_goose_publisher_build_frame(NULL, frame, sizeof(frame),
                                                    &frame_len);
    TEST_ASSERT(ret == -EINVAL, "GOOSE NULL pub should return -EINVAL");

    ret = iec61850_goose_publisher_build_frame(&gpub, NULL, sizeof(frame),
                                                &frame_len);
    TEST_ASSERT(ret == -EINVAL, "GOOSE NULL frame should return -EINVAL");

    ret = iec61850_goose_publisher_build_frame(&gpub, frame, sizeof(frame),
                                                NULL);
    TEST_ASSERT(ret == -EINVAL, "GOOSE NULL frame_len should return -EINVAL");

    /* SV NULL args */
    ret = iec61850_sv_publisher_build_frame(NULL, frame, sizeof(frame),
                                             &frame_len);
    TEST_ASSERT(ret == -EINVAL, "SV NULL pub should return -EINVAL");

    ret = iec61850_sv_publisher_build_frame(&spub, NULL, sizeof(frame),
                                             &frame_len);
    TEST_ASSERT(ret == -EINVAL, "SV NULL frame should return -EINVAL");

    ret = iec61850_sv_publisher_build_frame(&spub, frame, sizeof(frame),
                                             NULL);
    TEST_ASSERT(ret == -EINVAL, "SV NULL frame_len should return -EINVAL");

    iec61850_sv_publisher_destroy(&spub);
    iec61850_goose_publisher_destroy(&gpub);
    TEST_PASS();
}

/***************************************************************************
 * main
 ***************************************************************************/
int main(void)
{
    /* Generate temp key + cert */
    (void)snprintf(tmp_key_path, sizeof(tmp_key_path),
                   "/tmp/test_sec_pub_key_%d.pem", (int)getpid());
    (void)snprintf(tmp_cert_path, sizeof(tmp_cert_path),
                   "/tmp/test_sec_pub_cert_%d.pem", (int)getpid());

    if (generate_test_key_and_cert(tmp_key_path, tmp_cert_path) != 0) {
        fprintf(stderr, "FATAL: failed to generate test key/cert\n");
        return 1;
    }

    (void)snprintf(tmp_ec_key_path, sizeof(tmp_ec_key_path),
                   "/tmp/test_sec_pub_ec_key_%d.pem", (int)getpid());
    (void)snprintf(tmp_ec_cert_path, sizeof(tmp_ec_cert_path),
                   "/tmp/test_sec_pub_ec_cert_%d.pem", (int)getpid());

    if (generate_ec_key_and_cert(tmp_ec_key_path, tmp_ec_cert_path) != 0) {
        fprintf(stderr, "FATAL: failed to generate EC key/cert\n");
        cleanup_temp_files();
        return 1;
    }

    printf("test_security_publisher: ");

    test_goose_enable_security_success();
    test_goose_build_frame_with_security();
    test_sv_enable_security_success();
    test_sv_build_frame_with_security();
    test_enable_security_null_args();
    test_enable_security_unloaded();
    test_goose_retransmit_with_state_change();
    test_publisher_set_io();
    test_goose_security_frame_size();
    test_sv_security_frame_size();
    test_build_frame_null_args();
    test_goose_build_frame_ecdsa();
    test_sv_build_frame_ecdsa();

    cleanup_temp_files();

    printf("\n%d passed, %d failed\n", tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
