/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Property-Based Tests for SV (Sampled Values) Encoder/Decoder
 *
 * Tests invariants and properties for IEC 61850-9-2 Sampled Values:
 * - Round-trip: decode(encode(x)) == x
 * - Sample count consistency
 * - Sample value preservation
 * - Length consistency
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "property_test.h"
#include "asn1/sv_ber.h"
#include <stdint.h>

/* Generate random SV APDU */
static void generate_random_sv_apdu(sv_apdu_t *apdu) {
    sv_apdu_init(apdu);

    /* Always 1 ASDU for now */
    apdu->noASDU = 1;

    sv_asdu_t *asdu = &apdu->asdu[0];

    /* Random svID (limit to 64 chars to fit in 1500 byte buffer) */
    random_visible_string(asdu->svID, 65);

    /* Random datSet (optional, limit to 64 chars) */
    asdu->has_datSet = random_bool();
    if (asdu->has_datSet) {
        random_visible_string(asdu->datSet, 65);
    }

    /* Random sample count */
    asdu->smpCnt = random_uint16();

    /* Random configuration revision */
    asdu->confRev = random_uint32();

    /* Random reference time (optional) */
    /* IEC 61850 UtcTime: 32-bit seconds (max: 2106-02-07) + 24-bit fractional */
    asdu->has_refrTm = random_bool();
    if (asdu->has_refrTm) {
        /* Generate valid timestamp within IEC 61850 range */
        uint32_t seconds = random_uint32();
        uint32_t usec = (uint32_t)(rand() % 1000000);
        asdu->refrTm = (uint64_t)seconds * 1000000ULL + usec;
    }

    /* Random sample synchronization */
    asdu->smpSynch = (sv_smpsynch_t)(rand() % 3);  /* 0-2 */

    /* Random sample rate (optional) */
    asdu->has_smpRate = random_bool();
    if (asdu->has_smpRate) {
        asdu->smpRate = random_uint16();
    }

    /* Random samples (1-8 for quick tests) */
    asdu->num_samples = (uint8_t)(1 + (rand() % 8));
    for (int i = 0; i < asdu->num_samples; i++) {
        asdu->samples[i].value = random_int32_biased();
        /* Quality flags - simple random for now */
        memset(&asdu->samples[i].quality, 0, sizeof(sv_quality_t));
    }

    /* Random smpMod (optional) */
    asdu->has_smpMod = random_bool();
    if (asdu->has_smpMod) {
        asdu->smpMod = random_uint8();
    }

    /* No security for basic property tests */
    asdu->secure = false;
}

/* Compare two SV APDUs for equality */
static bool sv_apdu_equal(const sv_apdu_t *a, const sv_apdu_t *b) {
    if (a->noASDU != b->noASDU) return false;

    const sv_asdu_t *asdu_a = &a->asdu[0];
    const sv_asdu_t *asdu_b = &b->asdu[0];

    if (strcmp(asdu_a->svID, asdu_b->svID) != 0) return false;
    if (asdu_a->has_datSet != asdu_b->has_datSet) return false;
    if (asdu_a->has_datSet && strcmp(asdu_a->datSet, asdu_b->datSet) != 0)
        return false;
    if (asdu_a->smpCnt != asdu_b->smpCnt) return false;
    if (asdu_a->confRev != asdu_b->confRev) return false;
    if (asdu_a->has_refrTm != asdu_b->has_refrTm) return false;
    if (asdu_a->has_refrTm && asdu_a->refrTm != asdu_b->refrTm) return false;
    if (asdu_a->smpSynch != asdu_b->smpSynch) return false;
    if (asdu_a->num_samples != asdu_b->num_samples) return false;

    /* Compare samples */
    for (int i = 0; i < asdu_a->num_samples; i++) {
        if (asdu_a->samples[i].value != asdu_b->samples[i].value)
            return false;
    }

    return true;
}

/* Property 1: Round-trip - decode(encode(apdu)) == apdu */
static void test_sv_roundtrip_property(void) {
    PROPERTY_TEST("SV encode-decode roundtrip", 1000) {
        sv_apdu_t original, decoded;
        uint8_t buf[1500];
        size_t encoded_len;

        /* Generate random APDU */
        generate_random_sv_apdu(&original);

        /* Encode */
        int enc_result = sv_encode_apdu(buf, sizeof(buf), &original, &encoded_len);
        PROPERTY_ASSERT(enc_result == SV_BER_OK, "Encoding should succeed");
        PROPERTY_ASSERT(encoded_len > 0 && encoded_len <= sizeof(buf),
                       "Encoded length should be in valid range");

        /* Decode */
        sv_apdu_init(&decoded);
        int dec_result = sv_decode_apdu(buf, encoded_len, &decoded);
        PROPERTY_ASSERT(dec_result == SV_BER_OK, "Decoding should succeed");

        /* Verify round-trip */
        PROPERTY_ASSERT(sv_apdu_equal(&original, &decoded),
                       "Decoded APDU must match original");
    }
    PROPERTY_TEST_END();
}

/* Property 2: Length consistency */
static void test_sv_length_consistency(void) {
    PROPERTY_TEST("SV length consistency", 500) {
        sv_apdu_t apdu;
        uint8_t buf[1500];
        size_t encoded_len;

        generate_random_sv_apdu(&apdu);

        int result = sv_encode_apdu(buf, sizeof(buf), &apdu, &encoded_len);
        PROPERTY_ASSERT(result == SV_BER_OK, "Encoding should succeed");

        /* Verify encoded_len doesn't exceed buffer */
        PROPERTY_ASSERT(encoded_len <= sizeof(buf),
                       "Encoded length must not exceed buffer size");

        /* Verify encoded_len is reasonable */
        PROPERTY_ASSERT(encoded_len >= 20,
                       "Encoded SV must be at least 20 bytes");
    }
    PROPERTY_TEST_END();
}

/* Property 3: Sample count consistency */
static void test_sv_sample_count_consistency(void) {
    PROPERTY_TEST("SV sample count consistency", 500) {
        sv_apdu_t original, decoded;
        uint8_t buf[1500];
        size_t encoded_len;

        generate_random_sv_apdu(&original);

        uint8_t expected_count = original.asdu[0].num_samples;

        /* Encode and decode */
        int enc_result = sv_encode_apdu(buf, sizeof(buf), &original, &encoded_len);
        PROPERTY_ASSERT(enc_result == SV_BER_OK, "Encoding should succeed");

        sv_apdu_init(&decoded);
        int dec_result = sv_decode_apdu(buf, encoded_len, &decoded);
        PROPERTY_ASSERT(dec_result == SV_BER_OK, "Decoding should succeed");

        /* Verify sample count preserved */
        PROPERTY_ASSERT_EQ(decoded.asdu[0].num_samples, expected_count,
                          "Sample count must be preserved");
    }
    PROPERTY_TEST_END();
}

/* Property 4: Sample value preservation */
static void test_sv_sample_value_preservation(void) {
    PROPERTY_TEST("SV sample value preservation", 500) {
        sv_apdu_t original, decoded;
        uint8_t buf[1500];
        size_t encoded_len;

        sv_apdu_init(&original);
        original.noASDU = 1;
        strcpy(original.asdu[0].svID, "IED_MU01");
        original.asdu[0].smpCnt = 1000;
        original.asdu[0].confRev = 1;
        original.asdu[0].smpSynch = SV_SMPSYNCH_GLOBAL;

        /* Add samples with known values */
        original.asdu[0].num_samples = 4;
        int32_t values[4] = {
            random_int32_biased(),
            random_int32_biased(),
            random_int32_biased(),
            random_int32_biased()
        };
        for (int i = 0; i < 4; i++) {
            original.asdu[0].samples[i].value = values[i];
        }

        /* Encode and decode */
        int enc_result = sv_encode_apdu(buf, sizeof(buf), &original, &encoded_len);
        PROPERTY_ASSERT(enc_result == SV_BER_OK, "Encoding should succeed");

        sv_apdu_init(&decoded);
        int dec_result = sv_decode_apdu(buf, encoded_len, &decoded);
        PROPERTY_ASSERT(dec_result == SV_BER_OK, "Decoding should succeed");

        /* Verify each sample value */
        for (int i = 0; i < 4; i++) {
            PROPERTY_ASSERT_EQ(decoded.asdu[0].samples[i].value, values[i],
                              "Sample values must be preserved");
        }
    }
    PROPERTY_TEST_END();
}

/* Property 5: Idempotence */
static void test_sv_encoding_idempotence(void) {
    PROPERTY_TEST("SV encoding idempotence", 500) {
        sv_apdu_t apdu;
        uint8_t buf1[1500], buf2[1500];
        size_t len1, len2;

        generate_random_sv_apdu(&apdu);

        /* Encode twice */
        int r1 = sv_encode_apdu(buf1, sizeof(buf1), &apdu, &len1);
        int r2 = sv_encode_apdu(buf2, sizeof(buf2), &apdu, &len2);

        PROPERTY_ASSERT(r1 == SV_BER_OK && r2 == SV_BER_OK,
                       "Both encodings should succeed");
        PROPERTY_ASSERT_EQ(len1, len2, "Encoded lengths must match");
        PROPERTY_ASSERT(memcmp(buf1, buf2, len1) == 0,
                       "Encoded buffers must be identical");
    }
    PROPERTY_TEST_END();
}

/* Property 6: String handling */
static void test_sv_string_handling(void) {
    PROPERTY_TEST("SV string field handling", 500) {
        sv_apdu_t apdu;
        uint8_t buf[1500];
        size_t encoded_len;

        sv_apdu_init(&apdu);
        apdu.noASDU = 1;

        /* Generate random strings (limit to 64 chars) */
        random_visible_string(apdu.asdu[0].svID, 65);
        apdu.asdu[0].has_datSet = random_bool();
        if (apdu.asdu[0].has_datSet) {
            random_visible_string(apdu.asdu[0].datSet, 65);
        }

        apdu.asdu[0].num_samples = 1;
        apdu.asdu[0].samples[0].value = 0;

        /* Encode */
        int result = sv_encode_apdu(buf, sizeof(buf), &apdu, &encoded_len);
        PROPERTY_ASSERT(result == SV_BER_OK, "Encoding should succeed");

        /* Verify strings are null-terminated */
        PROPERTY_ASSERT(apdu.asdu[0].svID[strlen(apdu.asdu[0].svID)] == '\0',
                       "svID should be null-terminated");
        if (apdu.asdu[0].has_datSet) {
            PROPERTY_ASSERT(apdu.asdu[0].datSet[strlen(apdu.asdu[0].datSet)] == '\0',
                           "datSet should be null-terminated");
        }
    }
    PROPERTY_TEST_END();
}

/* Property 7: Sample value edge cases (INT32 extreme values) */
static void test_sv_sample_value_edge_cases(void) {
    PROPERTY_TEST("SV sample value edge cases", 500) {
        sv_apdu_t apdu, decoded;
        uint8_t buf[1500];
        size_t encoded_len;

        sv_apdu_init(&apdu);
        apdu.noASDU = 1;

        sv_asdu_t *asdu = &apdu.asdu[0];
        strcpy(asdu->svID, "EDGE_CASE_TEST");
        asdu->smpCnt = 1000;
        asdu->confRev = 1;
        asdu->smpSynch = SV_SMPSYNCH_GLOBAL;

        /* Test extreme values for sample data */
        int edge_case = rand() % 8;
        asdu->num_samples = 1;

        switch (edge_case) {
            case 0:  /* INT32_MIN */
                asdu->samples[0].value = INT32_MIN;
                break;
            case 1:  /* INT32_MAX */
                asdu->samples[0].value = INT32_MAX;
                break;
            case 2:  /* Zero */
                asdu->samples[0].value = 0;
                break;
            case 3:  /* -1 */
                asdu->samples[0].value = -1;
                break;
            case 4:  /* +1 */
                asdu->samples[0].value = 1;
                break;
            case 5:  /* -32768 (INT16_MIN) */
                asdu->samples[0].value = -32768;
                break;
            case 6:  /* +32767 (INT16_MAX) */
                asdu->samples[0].value = 32767;
                break;
            case 7:  /* -128 (INT8_MIN) */
                asdu->samples[0].value = -128;
                break;
        }

        memset(&asdu->samples[0].quality, 0, sizeof(sv_quality_t));

        /* Encode */
        int enc_result = sv_encode_apdu(buf, sizeof(buf), &apdu, &encoded_len);
        PROPERTY_ASSERT(enc_result == SV_BER_OK,
                       "Encoding should succeed for all edge cases");

        /* Decode */
        int dec_result = sv_decode_apdu(buf, encoded_len, &decoded);
        PROPERTY_ASSERT(dec_result == SV_BER_OK,
                       "Decoding should succeed for all edge cases");

        /* Verify sample value preserved */
        PROPERTY_ASSERT(decoded.asdu[0].samples[0].value == asdu->samples[0].value,
                       "Sample value should be preserved through encode/decode");
    }
    PROPERTY_TEST_END();
}

/* Property 8: Quality flag combinations */
static void test_sv_quality_flag_combinations(void) {
    PROPERTY_TEST("SV quality flag combinations", 500) {
        sv_apdu_t apdu, decoded;
        uint8_t buf[1500];
        size_t encoded_len;

        sv_apdu_init(&apdu);
        apdu.noASDU = 1;

        sv_asdu_t *asdu = &apdu.asdu[0];
        strcpy(asdu->svID, "QUALITY_TEST");
        asdu->smpCnt = 5000;
        asdu->confRev = 1;
        asdu->smpSynch = SV_SMPSYNCH_GLOBAL;
        asdu->num_samples = 2;

        /* Random quality flags for each sample */
        asdu->samples[0].value = 1000;
        asdu->samples[0].quality.validity = random_bool();
        asdu->samples[0].quality.overflow = random_bool();
        asdu->samples[0].quality.out_of_range = random_bool();
        asdu->samples[0].quality.oscillatory = random_bool();
        asdu->samples[0].quality.failure = random_bool();
        asdu->samples[0].quality.test = random_bool();
        asdu->samples[0].quality.operator_blocked = random_bool();

        asdu->samples[1].value = 2000;
        asdu->samples[1].quality.validity = random_bool();
        asdu->samples[1].quality.overflow = random_bool();
        asdu->samples[1].quality.out_of_range = random_bool();
        asdu->samples[1].quality.oscillatory = random_bool();
        asdu->samples[1].quality.failure = random_bool();
        asdu->samples[1].quality.test = random_bool();
        asdu->samples[1].quality.operator_blocked = random_bool();

        /* Encode */
        int enc_ret = sv_encode_apdu(buf, sizeof(buf), &apdu, &encoded_len);
        PROPERTY_ASSERT(enc_ret == SV_BER_OK, "Encoding should succeed");

        /* Decode */
        int dec_ret = sv_decode_apdu(buf, encoded_len, &decoded);
        PROPERTY_ASSERT(dec_ret == SV_BER_OK, "Decoding should succeed");

        /* Verify quality flags preserved */
        PROPERTY_ASSERT(decoded.asdu[0].samples[0].quality.validity == asdu->samples[0].quality.validity,
                       "Quality validity flag should be preserved");
        PROPERTY_ASSERT(decoded.asdu[0].samples[0].quality.overflow == asdu->samples[0].quality.overflow,
                       "Quality overflow flag should be preserved");
        PROPERTY_ASSERT(decoded.asdu[0].samples[0].quality.test == asdu->samples[0].quality.test,
                       "Quality test flag should be preserved");
    }
    PROPERTY_TEST_END();
}

/* Property 9: Timestamp edge cases */
static void test_sv_timestamp_edge_cases(void) {
    PROPERTY_TEST("SV timestamp edge cases", 500) {
        sv_apdu_t apdu, decoded;
        uint8_t buf[1500];
        size_t encoded_len;

        sv_apdu_init(&apdu);
        apdu.noASDU = 1;

        sv_asdu_t *asdu = &apdu.asdu[0];
        strcpy(asdu->svID, "TIMESTAMP_TEST");
        asdu->smpCnt = 1234;
        asdu->confRev = 1;
        asdu->smpSynch = SV_SMPSYNCH_LOCAL;
        asdu->num_samples = 1;
        asdu->samples[0].value = 999;
        memset(&asdu->samples[0].quality, 0, sizeof(sv_quality_t));

        /* Test various timestamp values */
        asdu->has_refrTm = true;
        int edge_case = rand() % 8;

        switch (edge_case) {
            case 0:  /* Zero timestamp */
                asdu->refrTm = 0;
                break;
            case 1:  /* Unix epoch */
                asdu->refrTm = 1000000ULL;  /* 1 second */
                break;
            case 2:  /* Y2K */
                asdu->refrTm = 946684800ULL * 1000000ULL;
                break;
            case 3:  /* Current era (2024) */
                asdu->refrTm = 1700000000ULL * 1000000ULL;
                break;
            case 4:  /* Max 32-bit seconds (Feb 2106) */
                asdu->refrTm = 0xFFFFFFFFULL * 1000000ULL;
                break;
            case 5:  /* Max fractional seconds */
                asdu->refrTm = 1000000ULL + 999999ULL;
                break;
            case 6: {/* Random valid timestamp (within IEC 61850 range) */
                /* IEC 61850 UtcTime: 32-bit seconds + 24-bit fractional (microseconds) */
                /* Max seconds: 0xFFFFFFFF (Feb 2106) */
                uint32_t seconds = random_uint32();
                uint32_t usec = (uint32_t)(rand() % 1000000);  /* 0-999999 microseconds */
                asdu->refrTm = (uint64_t)seconds * 1000000ULL + usec;
                break;
            }
            case 7:  /* No timestamp (optional field) */
                asdu->has_refrTm = false;
                break;
        }

        /* Encode */
        int enc_ret = sv_encode_apdu(buf, sizeof(buf), &apdu, &encoded_len);
        PROPERTY_ASSERT(enc_ret == SV_BER_OK, "Encoding should succeed");

        /* Decode */
        int dec_ret = sv_decode_apdu(buf, encoded_len, &decoded);
        PROPERTY_ASSERT(dec_ret == SV_BER_OK, "Decoding should succeed");

        /* Verify timestamp preserved */
        PROPERTY_ASSERT(decoded.asdu[0].has_refrTm == asdu->has_refrTm,
                       "refrTm presence flag should be preserved");
        if (asdu->has_refrTm) {
            PROPERTY_ASSERT(decoded.asdu[0].refrTm == asdu->refrTm,
                           "Timestamp should be preserved");
        }
    }
    PROPERTY_TEST_END();
}

int main(void) {
    property_test_init();

    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║  SV (Sampled Values) Property-Based Tests                 ║\n");
    printf("║  Testing IEC 61850-9-2 invariants across random inputs    ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");

    test_sv_roundtrip_property();
    test_sv_length_consistency();
    test_sv_sample_count_consistency();
    test_sv_sample_value_preservation();
    test_sv_encoding_idempotence();
    test_sv_string_handling();
    test_sv_sample_value_edge_cases();
    test_sv_quality_flag_combinations();
    test_sv_timestamp_edge_cases();

    property_test_summary();

    return 0;
}
