/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Security Protocol Tests
 *
 * Combined SV security detail tests and GOOSE security edge cases.
 * Tests BER-level security extension encoding/decoding for both protocols.
 *
 * License: BSD-3-Clause
 */

#include "asn1/sv_ber.h"
#include "asn1/goose_ber.h"
#include "asn1/goose_ber_decode.h"

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
#define ASSERT_MEM_EQ(a, b, n) do { if (memcmp((a), (b), (n)) != 0) { \
    FAIL("memcmp " #a " != " #b); return; } } while (0)

/* ========================================================================
 * Helper: populate a minimal SV APDU with one ASDU
 * ======================================================================== */

static void populate_sv_apdu(sv_apdu_t *apdu)
{
    sv_apdu_init(apdu);
    apdu->noASDU = 1;
    sv_asdu_init(&apdu->asdu[0]);
    sv_set_svid(&apdu->asdu[0], "TestSV01");
    apdu->asdu[0].smpCnt = 100;
    apdu->asdu[0].confRev = 1;
    apdu->asdu[0].smpSynch = SV_SMPSYNCH_GLOBAL;
    sv_quality_t q = {0};
    sv_add_sample(&apdu->asdu[0], 1000, q);
    sv_add_sample(&apdu->asdu[0], 2000, q);
}

/* ========================================================================
 * SV Security Tests
 * ======================================================================== */

static void test_sv_encode_with_security(void)
{
    TEST("sv_encode_with_security");

    sv_apdu_t apdu;
    populate_sv_apdu(&apdu);

    /* Set security on ASDU */
    uint8_t key_id[SV_KEYID_LEN];
    memset(key_id, 0xAA, sizeof(key_id));
    uint8_t signature[64];
    memset(signature, 0xBB, sizeof(signature));
    int ret = sv_set_security(&apdu.asdu[0], SV_SIGNATURE_RSA_PSS,
                               key_id, signature, sizeof(signature));
    ASSERT_EQ(ret, SV_BER_OK);
    ASSERT_TRUE(apdu.asdu[0].secure);

    /* Encode */
    uint8_t buf[4096];
    size_t encoded = 0;
    ret = sv_encode_apdu(buf, sizeof(buf), &apdu, &encoded);
    ASSERT_EQ(ret, SV_BER_OK);
    ASSERT_TRUE(encoded > 0);

    /* Decode and verify security is present */
    sv_apdu_t decoded;
    sv_apdu_init(&decoded);
    ret = sv_decode_apdu(buf, encoded, &decoded);
    ASSERT_EQ(ret, SV_BER_OK);
    ASSERT_TRUE(decoded.asdu[0].secure);
    ASSERT_EQ((int)decoded.asdu[0].signature_algo, (int)SV_SIGNATURE_RSA_PSS);
    ASSERT_MEM_EQ(decoded.asdu[0].key_id, key_id, SV_KEYID_LEN);
    ASSERT_EQ((int)decoded.asdu[0].signature_len, 64);
    ASSERT_MEM_EQ(decoded.asdu[0].signature, signature, 64);

    PASS();
}

static void test_sv_encode_without_security(void)
{
    TEST("sv_encode_without_security");

    sv_apdu_t apdu;
    populate_sv_apdu(&apdu);
    /* Do not set security — verify backward compatibility */

    uint8_t buf[4096];
    size_t encoded = 0;
    int ret = sv_encode_apdu(buf, sizeof(buf), &apdu, &encoded);
    ASSERT_EQ(ret, SV_BER_OK);
    ASSERT_TRUE(encoded > 0);

    /* Decode and verify no security */
    sv_apdu_t decoded;
    sv_apdu_init(&decoded);
    ret = sv_decode_apdu(buf, encoded, &decoded);
    ASSERT_EQ(ret, SV_BER_OK);
    ASSERT_TRUE(!decoded.asdu[0].secure);
    ASSERT_EQ((int)decoded.asdu[0].signature_len, 0);

    /* Verify SV_TAG_SECURITY (0xA9) does NOT appear in encoded buffer */
    bool found_security_tag = false;
    for (size_t i = 0; i < encoded; i++) {
        if (buf[i] == SV_TAG_SECURITY) {
            found_security_tag = true;
        }
    }
    ASSERT_TRUE(!found_security_tag);

    PASS();
}

static void test_sv_security_tag_format(void)
{
    TEST("sv_security_tag_format");

    sv_apdu_t apdu;
    populate_sv_apdu(&apdu);

    uint8_t key_id[SV_KEYID_LEN];
    memset(key_id, 0x11, sizeof(key_id));
    uint8_t signature[32];
    memset(signature, 0x22, sizeof(signature));
    sv_set_security(&apdu.asdu[0], SV_SIGNATURE_ECDSA,
                    key_id, signature, sizeof(signature));

    uint8_t buf[4096];
    size_t encoded = 0;
    int ret = sv_encode_apdu(buf, sizeof(buf), &apdu, &encoded);
    ASSERT_EQ(ret, SV_BER_OK);

    /* Find security tag 0xA9 ([9] CONSTRUCTED) in encoded buffer */
    bool found = false;
    for (size_t i = 0; i < encoded; i++) {
        if (buf[i] == 0xA9U) {
            found = true;
            /* Verify it is [9] CONSTRUCTED = 0x80 | 0x20 | 0x09 = 0xA9 */
            ASSERT_EQ((int)buf[i], 0xA9);
            break;
        }
    }
    ASSERT_TRUE(found);

    PASS();
}

/* ========================================================================
 * GOOSE Security Tests
 * ======================================================================== */

/*
 * Helper: manually build a GOOSE APDU with security extension appended.
 *
 * Since goose_encode_apdu() does not include the security extension,
 * we encode the APDU first, then manually append the security TLVs
 * at the right position (inside the APDU SEQUENCE, after allData).
 *
 * For simplicity, we encode security separately and verify that the
 * decoder correctly parses it.
 */
static int build_goose_with_security(uint8_t *out, size_t out_size,
                                     size_t *out_len,
                                     const uint8_t *signature,
                                     size_t sig_len)
{
    goose_apdu_t apdu;
    goose_apdu_init(&apdu);
    goose_set_gocbref(&apdu, "IED1LD0/LLN0$GO$gcb01");
    goose_set_datset(&apdu, "IED1LD0/LLN0$DS1");
    apdu.stNum = 1;
    apdu.sqNum = 0;
    apdu.confRev = 1;
    apdu.timeAllowedtoLive = 2000;
    goose_add_boolean(&apdu, true);

    /* Encode base APDU (without security) */
    uint8_t base[4096];
    size_t base_len = 0;
    int ret = goose_encode_apdu(base, sizeof(base), &apdu, &base_len);
    if (ret != GOOSE_BER_OK) {
        return ret;
    }

    /*
     * The encoded APDU is: 0x61 <length> <content>
     * We need to insert security extension bytes inside the SEQUENCE,
     * so we reconstruct: 0x61 <new_length> <original_content> <security>
     */

    /* Build security extension bytes */
    uint8_t sec[1024];
    size_t sec_off = 0;

    /* Tag: [12] CONSTRUCTED = 0xAC */
    sec[sec_off++] = GOOSE_TAG_SECURITY;

    /* Build inner content first to know its length — the IEC 62351-6
     * wire layout the publisher emits:
     *   [0] timeOfCurrentKey, [1] keyID, [2] signature */
    uint8_t inner[1024];
    size_t inner_off = 0;

    /* [0] timeOfCurrentKey (8 bytes UtcTime) */
    inner[inner_off++] = GOOSE_TAG_SECURITY_TIME_OF_KEY;
    inner[inner_off++] = 0x08;
    /* Dummy timestamp: 4 bytes seconds + 3 bytes fraction + 1 byte quality */
    inner[inner_off++] = 0x00; inner[inner_off++] = 0x01;
    inner[inner_off++] = 0x02; inner[inner_off++] = 0x03;
    inner[inner_off++] = 0x00; inner[inner_off++] = 0x00;
    inner[inner_off++] = 0x00; inner[inner_off++] = 0x00;

    /* [1] Key ID */
    uint8_t key_id[GOOSE_KEYID_LEN];
    memset(key_id, 0xCC, sizeof(key_id));
    inner[inner_off++] = GOOSE_TAG_SECURITY_KEYID;
    inner[inner_off++] = GOOSE_KEYID_LEN;
    memcpy(&inner[inner_off], key_id, GOOSE_KEYID_LEN);
    inner_off += GOOSE_KEYID_LEN;

    /* [2] Signature */
    inner[inner_off++] = GOOSE_TAG_SECURITY_SIGNATURE;
    if (sig_len < 128U) {
        inner[inner_off++] = (uint8_t)sig_len;
    } else if (sig_len <= 0xFFU) {
        inner[inner_off++] = 0x81;
        inner[inner_off++] = (uint8_t)sig_len;
    } else {
        inner[inner_off++] = 0x82;
        inner[inner_off++] = (uint8_t)(sig_len >> 8);
        inner[inner_off++] = (uint8_t)(sig_len & 0xFF);
    }
    memcpy(&inner[inner_off], signature, sig_len);
    inner_off += sig_len;

    /* Encode security length */
    if (inner_off < 128U) {
        sec[sec_off++] = (uint8_t)inner_off;
    } else if (inner_off <= 0xFFU) {
        sec[sec_off++] = 0x81;
        sec[sec_off++] = (uint8_t)inner_off;
    } else {
        sec[sec_off++] = 0x82;
        sec[sec_off++] = (uint8_t)(inner_off >> 8);
        sec[sec_off++] = (uint8_t)(inner_off & 0xFF);
    }
    memcpy(&sec[sec_off], inner, inner_off);
    sec_off += inner_off;

    /*
     * Reconstruct full APDU: tag + new_length + original_content + security
     *
     * Parse original: base[0] = 0x61 (tag), then length, then content.
     */
    size_t orig_content_off;
    size_t orig_content_len;

    /* Parse original BER length */
    if (base[1] < 0x80U) {
        orig_content_off = 2;
        orig_content_len = base[1];
    } else if (base[1] == 0x81U) {
        orig_content_off = 3;
        orig_content_len = base[2];
    } else {
        /* 0x82 */
        orig_content_off = 4;
        orig_content_len = ((size_t)base[2] << 8) | base[3];
    }

    size_t new_content_len = orig_content_len + sec_off;
    size_t pos = 0;

    if (pos >= out_size) { return GOOSE_BER_ERR_BUFFER_FULL; }
    out[pos++] = GOOSE_APDU_TAG; /* 0x61 */

    /* Encode new length */
    if (new_content_len < 128U) {
        out[pos++] = (uint8_t)new_content_len;
    } else if (new_content_len <= 0xFFU) {
        out[pos++] = 0x81;
        out[pos++] = (uint8_t)new_content_len;
    } else {
        out[pos++] = 0x82;
        out[pos++] = (uint8_t)(new_content_len >> 8);
        out[pos++] = (uint8_t)(new_content_len & 0xFF);
    }

    /* Copy original content */
    memcpy(&out[pos], &base[orig_content_off], orig_content_len);
    pos += orig_content_len;

    /* Append security extension */
    memcpy(&out[pos], sec, sec_off);
    pos += sec_off;

    *out_len = pos;
    return GOOSE_BER_OK;
}

static void test_goose_security_roundtrip(void)
{
    TEST("goose_security_extension_roundtrip");

    uint8_t signature[64];
    memset(signature, 0xDD, sizeof(signature));

    uint8_t buf[4096];
    size_t buf_len = 0;
    int ret = build_goose_with_security(buf, sizeof(buf), &buf_len,
                                        signature, sizeof(signature));
    ASSERT_EQ(ret, GOOSE_BER_OK);
    ASSERT_TRUE(buf_len > 0);

    /* Decode */
    goose_apdu_t decoded;
    goose_apdu_init(&decoded);
    ret = goose_decode_apdu(buf, buf_len, &decoded);
    ASSERT_EQ(ret, GOOSE_BER_OK);
    ASSERT_TRUE(decoded.secure);

    uint8_t expected_key[GOOSE_KEYID_LEN];
    memset(expected_key, 0xCC, sizeof(expected_key));
    ASSERT_MEM_EQ(decoded.key_id, expected_key, GOOSE_KEYID_LEN);
    ASSERT_EQ((int)decoded.signature_len, 64);
    ASSERT_MEM_EQ(decoded.signature, signature, 64);

    PASS();
}

static void test_goose_security_tag_format(void)
{
    TEST("goose_security_tag_format");

    uint8_t signature[32];
    memset(signature, 0xEE, sizeof(signature));

    uint8_t buf[4096];
    size_t buf_len = 0;
    int ret = build_goose_with_security(buf, sizeof(buf), &buf_len,
                                        signature, sizeof(signature));
    ASSERT_EQ(ret, GOOSE_BER_OK);

    /* Find GOOSE_TAG_SECURITY (0xAC = [12] CONSTRUCTED) in buffer */
    bool found = false;
    for (size_t i = 0; i < buf_len; i++) {
        if (buf[i] == 0xACU) {
            found = true;
            /* 0xAC = 0x80 | 0x20 | 0x0C = context [12] constructed */
            ASSERT_EQ((int)buf[i], 0xAC);
            break;
        }
    }
    ASSERT_TRUE(found);

    PASS();
}

static void test_goose_variable_signature_lengths(void)
{
    TEST("goose_variable_signature_lengths");

    /* Property-style test: loop over different signature sizes */
    static const size_t sig_sizes[] = { 32, 64, 128, 256, 512 };
    static const size_t num_sizes = sizeof(sig_sizes) / sizeof(sig_sizes[0]);

    for (size_t i = 0; i < num_sizes; i++) {
        size_t sig_len = sig_sizes[i];
        uint8_t signature[512];
        /* Fill with pattern based on size for identification */
        memset(signature, (int)(0x10U + (i & 0x0FU)), sig_len);

        uint8_t buf[4096];
        size_t buf_len = 0;
        int ret = build_goose_with_security(buf, sizeof(buf), &buf_len,
                                            signature, sig_len);
        if (ret != GOOSE_BER_OK) {
            printf("FAIL: build_goose_with_security for sig_len=%zu\n", sig_len);
            tests_failed++;
            return;
        }

        goose_apdu_t decoded;
        goose_apdu_init(&decoded);
        ret = goose_decode_apdu(buf, buf_len, &decoded);
        if (ret != GOOSE_BER_OK) {
            printf("FAIL: decode for sig_len=%zu returned %d\n", sig_len, ret);
            tests_failed++;
            return;
        }

        if (!decoded.secure) {
            printf("FAIL: decoded.secure false for sig_len=%zu\n", sig_len);
            tests_failed++;
            return;
        }

        if (decoded.signature_len != sig_len) {
            printf("FAIL: signature_len=%zu expected=%zu\n",
                   decoded.signature_len, sig_len);
            tests_failed++;
            return;
        }

        if (memcmp(decoded.signature, signature, sig_len) != 0) {
            printf("FAIL: signature mismatch for sig_len=%zu\n", sig_len);
            tests_failed++;
            return;
        }
    }

    printf("PASS (5 sizes: 32, 64, 128, 256, 512)\n");
    tests_passed++;
}

static void test_goose_encode_without_security(void)
{
    TEST("goose_encode_without_security");

    goose_apdu_t apdu;
    goose_apdu_init(&apdu);
    goose_set_gocbref(&apdu, "IED1LD0/LLN0$GO$gcb01");
    goose_set_datset(&apdu, "IED1LD0/LLN0$DS1");
    apdu.stNum = 1;
    apdu.sqNum = 0;
    apdu.confRev = 1;
    apdu.timeAllowedtoLive = 2000;
    goose_add_boolean(&apdu, true);
    /* security NOT set */

    uint8_t buf[4096];
    size_t encoded = 0;
    int ret = goose_encode_apdu(buf, sizeof(buf), &apdu, &encoded);
    ASSERT_EQ(ret, GOOSE_BER_OK);
    ASSERT_TRUE(encoded > 0);

    /* Verify GOOSE_TAG_SECURITY (0xAC) does NOT appear in buffer */
    bool found_security = false;
    for (size_t i = 0; i < encoded; i++) {
        if (buf[i] == GOOSE_TAG_SECURITY) {
            found_security = true;
        }
    }
    ASSERT_TRUE(!found_security);

    /* Decode should succeed with secure=false */
    goose_apdu_t decoded;
    goose_apdu_init(&decoded);
    ret = goose_decode_apdu(buf, encoded, &decoded);
    ASSERT_EQ(ret, GOOSE_BER_OK);
    ASSERT_TRUE(!decoded.secure);
    ASSERT_EQ((int)decoded.signature_len, 0);

    PASS();
}

/* ========================================================================
 * Main
 * ======================================================================== */

int main(void)
{
    printf("\n=== Security Protocol Tests ===\n");

    printf("\n--- SV Security ---\n");
    test_sv_encode_with_security();
    test_sv_encode_without_security();
    test_sv_security_tag_format();

    printf("\n--- GOOSE Security Edge Cases ---\n");
    test_goose_security_roundtrip();
    test_goose_security_tag_format();
    test_goose_variable_signature_lengths();
    test_goose_encode_without_security();

    printf("\n=== Test Summary ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
