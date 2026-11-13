/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for HMAC-SHA256 and AES-GMAC
 */

#include "security/hmac_verify.h"
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

static void test_hmac_sign_verify(void)
{
    TEST("hmac_sign_verify");
    const uint8_t key[] = "test-key-for-hmac-sha256-ops!!";
    const uint8_t data[] = "Hello, IEC 61850!";
    uint8_t mac[32];

    int ret = hmac_sha256_sign(key, sizeof(key) - 1, data, sizeof(data) - 1,
                                 mac, sizeof(mac));
    ASSERT_EQ(ret, 0);

    ret = hmac_sha256_verify(key, sizeof(key) - 1, data, sizeof(data) - 1,
                               mac, sizeof(mac));
    ASSERT_EQ(ret, 0);
    PASS();
}

static void test_hmac_verify_tamper(void)
{
    TEST("hmac_verify_tamper");
    const uint8_t key[] = "test-key-for-hmac-sha256-ops!!";
    const uint8_t data[] = "Hello, IEC 61850!";
    uint8_t mac[32];

    hmac_sha256_sign(key, sizeof(key) - 1, data, sizeof(data) - 1,
                       mac, sizeof(mac));

    /* Tamper with data */
    uint8_t tampered[] = "Hello, IEC 61851!";
    int ret = hmac_sha256_verify(key, sizeof(key) - 1, tampered,
                                   sizeof(tampered) - 1, mac, sizeof(mac));
    ASSERT_EQ(ret, -1);
    PASS();
}

static void test_hmac_verify_wrong_key(void)
{
    TEST("hmac_verify_wrong_key");
    const uint8_t key[] = "correct-key-here";
    const uint8_t wrong_key[] = "wrong-key---here";
    const uint8_t data[] = "test data";
    uint8_t mac[32];

    hmac_sha256_sign(key, sizeof(key) - 1, data, sizeof(data) - 1,
                       mac, sizeof(mac));

    int ret = hmac_sha256_verify(wrong_key, sizeof(wrong_key) - 1, data,
                                   sizeof(data) - 1, mac, sizeof(mac));
    ASSERT_EQ(ret, -1);
    PASS();
}

static void test_hmac_null_args(void)
{
    TEST("hmac_null_args");
    uint8_t mac[32];
    const uint8_t key[] = "k";
    const uint8_t data[] = "d";

    ASSERT_EQ(hmac_sha256_sign(NULL, 1, data, 1, mac, 32), -2);
    ASSERT_EQ(hmac_sha256_sign(key, 1, NULL, 1, mac, 32), -2);
    ASSERT_EQ(hmac_sha256_sign(key, 1, data, 1, NULL, 32), -2);
    ASSERT_EQ(hmac_sha256_sign(key, 1, data, 1, mac, 16), -2);  /* mac_len < 32 */

    ASSERT_EQ(hmac_sha256_verify(NULL, 1, data, 1, mac, 32), -2);
    ASSERT_EQ(hmac_sha256_verify(key, 1, NULL, 1, mac, 32), -2);
    ASSERT_EQ(hmac_sha256_verify(key, 1, data, 1, NULL, 32), -2);
    ASSERT_EQ(hmac_sha256_verify(key, 1, data, 1, mac, 64), -2);  /* mac_len > 32 */
    PASS();
}

static void test_hmac_deterministic(void)
{
    TEST("hmac_deterministic");
    const uint8_t key[] = "repeatability-key";
    const uint8_t data[] = "same data";
    uint8_t mac1[32], mac2[32];

    hmac_sha256_sign(key, sizeof(key) - 1, data, sizeof(data) - 1, mac1, 32);
    hmac_sha256_sign(key, sizeof(key) - 1, data, sizeof(data) - 1, mac2, 32);

    ASSERT_TRUE(memcmp(mac1, mac2, 32) == 0);
    PASS();
}

static void test_aes_gmac_null_args(void)
{
    TEST("aes_gmac_null_args");
    uint8_t key[16] = {0};
    uint8_t iv[12] = {0};
    uint8_t aad[] = "test";
    uint8_t tag[16] = {0};

    ASSERT_EQ(aes_gmac_verify(NULL, 16, iv, 12, aad, 4, tag, 16), -2);
    ASSERT_EQ(aes_gmac_verify(key, 16, NULL, 12, aad, 4, tag, 16), -2);
    ASSERT_EQ(aes_gmac_verify(key, 16, iv, 12, NULL, 4, tag, 16), -2);
    ASSERT_EQ(aes_gmac_verify(key, 16, iv, 12, aad, 4, NULL, 16), -2);
    /* Invalid key length */
    ASSERT_EQ(aes_gmac_verify(key, 24, iv, 12, aad, 4, tag, 16), -2);
    PASS();
}

static void test_aes_gmac_bad_tag(void)
{
    TEST("aes_gmac_bad_tag");
    uint8_t key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    uint8_t iv[12] = {0};
    uint8_t aad[] = "authenticated data";
    uint8_t bad_tag[16] = {0};  /* All zeros — won't match */

    int ret = aes_gmac_verify(key, 16, iv, 12, aad, sizeof(aad) - 1,
                                bad_tag, 16);
    ASSERT_EQ(ret, -1);  /* Tag mismatch */
    PASS();
}

static void test_aes_gmac_sign_verify_roundtrip_128(void)
{
    TEST("aes_gmac_sign_verify_roundtrip_128");
    const uint8_t key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    const uint8_t iv[12] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11};
    const uint8_t aad[] = "routable-goose-span-payload";
    uint8_t tag[16];

    int ret = aes_gmac_sign(key, sizeof(key), iv, sizeof(iv),
                              aad, sizeof(aad) - 1, tag, sizeof(tag));
    ASSERT_EQ(ret, 0);

    ret = aes_gmac_verify(key, sizeof(key), iv, sizeof(iv),
                            aad, sizeof(aad) - 1, tag, sizeof(tag));
    ASSERT_EQ(ret, 0);
    PASS();
}

static void test_aes_gmac_sign_verify_roundtrip_256(void)
{
    TEST("aes_gmac_sign_verify_roundtrip_256");
    const uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    const uint8_t iv[12] = {0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5,
                              0xA6, 0xA7, 0xA8, 0xA9, 0xAA, 0xAB};
    const uint8_t aad[] = "authenticated-span-data-for-aes-256-gmac";
    uint8_t tag[16];

    int ret = aes_gmac_sign(key, sizeof(key), iv, sizeof(iv),
                              aad, sizeof(aad) - 1, tag, sizeof(tag));
    ASSERT_EQ(ret, 0);

    ret = aes_gmac_verify(key, sizeof(key), iv, sizeof(iv),
                            aad, sizeof(aad) - 1, tag, sizeof(tag));
    ASSERT_EQ(ret, 0);
    PASS();
}

static void test_aes_gmac_sign_tamper(void)
{
    TEST("aes_gmac_sign_tamper");
    const uint8_t key[16] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    const uint8_t iv[12] = {0};
    const uint8_t aad[] = "authenticated data";
    uint8_t tag[16];
    uint8_t tampered_aad[sizeof(aad)];
    uint8_t tampered_tag[16];
    int ret;

    ret = aes_gmac_sign(key, sizeof(key), iv, sizeof(iv),
                          aad, sizeof(aad) - 1, tag, sizeof(tag));
    ASSERT_EQ(ret, 0);

    /* Flip an AAD byte — verification must fail */
    memcpy(tampered_aad, aad, sizeof(aad));
    tampered_aad[3] ^= 0x01U;
    ret = aes_gmac_verify(key, sizeof(key), iv, sizeof(iv),
                            tampered_aad, sizeof(tampered_aad) - 1,
                            tag, sizeof(tag));
    ASSERT_EQ(ret, -1);

    /* Flip a tag byte — verification must fail */
    memcpy(tampered_tag, tag, sizeof(tag));
    tampered_tag[8] ^= 0x80U;
    ret = aes_gmac_verify(key, sizeof(key), iv, sizeof(iv),
                            aad, sizeof(aad) - 1,
                            tampered_tag, sizeof(tampered_tag));
    ASSERT_EQ(ret, -1);
    PASS();
}

static void test_aes_gmac_sign_empty_aad(void)
{
    TEST("aes_gmac_sign_empty_aad");
    const uint8_t key[16] = {9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9};
    const uint8_t iv[12] = {1};
    const uint8_t aad[1] = {0};  /* Non-NULL pointer, zero length */
    uint8_t tag[16];

    int ret = aes_gmac_sign(key, sizeof(key), iv, sizeof(iv),
                              aad, 0, tag, sizeof(tag));
    ASSERT_EQ(ret, 0);

    ret = aes_gmac_verify(key, sizeof(key), iv, sizeof(iv),
                            aad, 0, tag, sizeof(tag));
    ASSERT_EQ(ret, 0);

    /* A tag over empty AAD must not authenticate non-empty AAD */
    ret = aes_gmac_verify(key, sizeof(key), iv, sizeof(iv),
                            (const uint8_t *)"x", 1, tag, sizeof(tag));
    ASSERT_EQ(ret, -1);
    PASS();
}

static void test_aes_gmac_sign_null_args(void)
{
    TEST("aes_gmac_sign_null_args");
    uint8_t key[16] = {0};
    uint8_t iv[12] = {0};
    uint8_t aad[] = "test";
    uint8_t tag[16];

    ASSERT_EQ(aes_gmac_sign(NULL, 16, iv, 12, aad, 4, tag, 16), -2);
    ASSERT_EQ(aes_gmac_sign(key, 16, NULL, 12, aad, 4, tag, 16), -2);
    ASSERT_EQ(aes_gmac_sign(key, 16, iv, 12, NULL, 4, tag, 16), -2);
    ASSERT_EQ(aes_gmac_sign(key, 16, iv, 12, aad, 4, NULL, 16), -2);
    /* Invalid key length */
    ASSERT_EQ(aes_gmac_sign(key, 24, iv, 12, aad, 4, tag, 16), -2);
    /* Invalid tag lengths */
    ASSERT_EQ(aes_gmac_sign(key, 16, iv, 12, aad, 4, tag, 0), -2);
    ASSERT_EQ(aes_gmac_sign(key, 16, iv, 12, aad, 4, tag, 17), -2);
    PASS();
}

int main(void)
{
    printf("=== HMAC Verify Tests ===\n");

    test_hmac_sign_verify();
    test_hmac_verify_tamper();
    test_hmac_verify_wrong_key();
    test_hmac_null_args();
    test_hmac_deterministic();
    test_aes_gmac_null_args();
    test_aes_gmac_bad_tag();
    test_aes_gmac_sign_verify_roundtrip_128();
    test_aes_gmac_sign_verify_roundtrip_256();
    test_aes_gmac_sign_tamper();
    test_aes_gmac_sign_empty_aad();
    test_aes_gmac_sign_null_args();

    printf("\nTests: %d run, %d passed, %d failed\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed > 0 ? 1 : 0;
}
