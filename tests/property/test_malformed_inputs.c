/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Malformed Input Property Tests
 *
 * Tests that decoders handle corrupted/malformed inputs gracefully:
 * - No crashes
 * - Proper error codes returned
 * - No buffer overruns
 * - No undefined behavior
 *
 * Uses property-based testing with random bit flips, truncation, etc.
 *
 * License: BSD-3-Clause
 */

#include "property_test.h"
#include "asn1/goose_ber.h"
#include "asn1/goose_ber_decode.h"
#include "asn1/sv_ber.h"
#include <string.h>

/* Helper: Corrupt buffer by flipping random bits */
static void flip_random_bits(uint8_t *buf, size_t len, int num_flips) {
    for (int i = 0; i < num_flips && len > 0; i++) {
        size_t byte_idx = (size_t)(rand()) % len;
        uint8_t bit_idx = (uint8_t)(rand()) % 8;
        buf[byte_idx] ^= (uint8_t)(1U << bit_idx);
    }
}

/* Property 1: GOOSE decoder handles bit flips gracefully */
static void test_goose_decoder_bit_flips(void) {
    PROPERTY_TEST("GOOSE decoder handles bit flips", 500) {
        goose_apdu_t original, decoded;
        uint8_t buf[1500];
        uint8_t corrupted[1500];
        size_t encoded_len;

        /* Create valid GOOSE message */
        goose_apdu_init(&original);
        strcpy(original.gocbRef, "TEST_CORRUPTION");
        original.timeAllowedtoLive = 2000;
        strcpy(original.datSet, "DS");
        strcpy(original.goID, "GO");
        original.timestamp = 1234567890;
        original.stNum = 1;
        original.sqNum = 1;
        original.test = false;
        original.confRev = 1;
        original.ndsCom = false;
        original.numDatSetEntries = 1;
        original.allData[0].type = GOOSE_DATA_BOOLEAN;
        original.allData[0].value.boolean = true;

        /* Encode */
        int enc_ret = goose_encode_apdu(buf, sizeof(buf), &original, &encoded_len);
        PROPERTY_ASSERT(enc_ret == GOOSE_BER_OK, "Encoding should succeed");

        /* Corrupt by flipping 1-5 random bits */
        memcpy(corrupted, buf, encoded_len);
        int num_flips = 1 + (rand() % 5);
        flip_random_bits(corrupted, encoded_len, num_flips);

        /* Decode corrupted data - should not crash */
        int dec_ret = goose_decode_apdu(corrupted, encoded_len, &decoded);

        /* Decoder should either succeed or return error code (not crash) */
        PROPERTY_ASSERT(dec_ret == GOOSE_BER_OK ||
                       dec_ret == GOOSE_BER_ERR_BUFFER_FULL ||
                       dec_ret == GOOSE_BER_ERR_INVALID_ARG ||
                       dec_ret == GOOSE_BER_ERR_ENCODING,
                       "Decoder should return valid error code (no crash)");
    }
    PROPERTY_TEST_END();
}

/* Property 2: GOOSE decoder handles truncation */
static void test_goose_decoder_truncation(void) {
    PROPERTY_TEST("GOOSE decoder handles truncation", 500) {
        goose_apdu_t original, decoded;
        uint8_t buf[1500];
        size_t encoded_len;

        /* Create valid GOOSE message */
        goose_apdu_init(&original);
        strcpy(original.gocbRef, "TRUNCATION_TEST");
        original.timeAllowedtoLive = 3000;
        strcpy(original.datSet, "DATASET");
        strcpy(original.goID, "GOID");
        original.timestamp = 999999;
        original.stNum = 10;
        original.sqNum = 20;
        original.test = false;
        original.confRev = 5;
        original.ndsCom = false;
        original.numDatSetEntries = 2;
        original.allData[0].type = GOOSE_DATA_INT32;
        original.allData[0].value.int32 = 1000;
        original.allData[1].type = GOOSE_DATA_UINT32;
        original.allData[1].value.uint32 = 2000;

        /* Encode */
        int enc_ret = goose_encode_apdu(buf, sizeof(buf), &original, &encoded_len);
        PROPERTY_ASSERT(enc_ret == GOOSE_BER_OK, "Encoding should succeed");

        /* Truncate to random length (at least 1 byte) */
        size_t truncated_len = (size_t)(1 + (rand() % (int)encoded_len));

        /* Decode truncated data - should not crash */
        int dec_ret = goose_decode_apdu(buf, truncated_len, &decoded);

        /* Decoder should return error (not crash) */
        PROPERTY_ASSERT(dec_ret == GOOSE_BER_OK ||
                       dec_ret == GOOSE_BER_ERR_BUFFER_FULL ||
                       dec_ret == GOOSE_BER_ERR_INVALID_ARG ||
                       dec_ret == GOOSE_BER_ERR_ENCODING,
                       "Decoder should handle truncation gracefully");
    }
    PROPERTY_TEST_END();
}

/* Property 3: SV decoder handles bit flips gracefully */
static void test_sv_decoder_bit_flips(void) {
    PROPERTY_TEST("SV decoder handles bit flips", 500) {
        sv_apdu_t original, decoded;
        uint8_t buf[1500];
        uint8_t corrupted[1500];
        size_t encoded_len;

        /* Create valid SV message */
        sv_apdu_init(&original);
        original.noASDU = 1;

        sv_asdu_t *asdu = &original.asdu[0];
        strcpy(asdu->svID, "CORRUPTION_TEST");
        asdu->smpCnt = 5000;
        asdu->confRev = 1;
        asdu->smpSynch = SV_SMPSYNCH_GLOBAL;
        asdu->num_samples = 2;
        asdu->samples[0].value = 1000;
        asdu->samples[1].value = 2000;
        memset(&asdu->samples[0].quality, 0, sizeof(sv_quality_t));
        memset(&asdu->samples[1].quality, 0, sizeof(sv_quality_t));

        /* Encode */
        int enc_ret = sv_encode_apdu(buf, sizeof(buf), &original, &encoded_len);
        PROPERTY_ASSERT(enc_ret == SV_BER_OK, "Encoding should succeed");

        /* Corrupt by flipping 1-5 random bits */
        memcpy(corrupted, buf, encoded_len);
        int num_flips = 1 + (rand() % 5);
        flip_random_bits(corrupted, encoded_len, num_flips);

        /* Decode corrupted data - should not crash */
        int dec_ret = sv_decode_apdu(corrupted, encoded_len, &decoded);

        /* Decoder should either succeed or return error code (not crash) */
        PROPERTY_ASSERT(dec_ret == SV_BER_OK ||
                       dec_ret == SV_BER_ERR_BUFFER_FULL ||
                       dec_ret == SV_BER_ERR_INVALID_ARG ||
                       dec_ret == SV_BER_ERR_ENCODING ||
                       dec_ret == SV_BER_ERR_DECODING,
                       "Decoder should return valid error code (no crash)");
    }
    PROPERTY_TEST_END();
}

/* Property 4: SV decoder handles truncation */
static void test_sv_decoder_truncation(void) {
    PROPERTY_TEST("SV decoder handles truncation", 500) {
        sv_apdu_t original, decoded;
        uint8_t buf[1500];
        size_t encoded_len;

        /* Create valid SV message */
        sv_apdu_init(&original);
        original.noASDU = 1;

        sv_asdu_t *asdu = &original.asdu[0];
        strcpy(asdu->svID, "TRUNCATION_TEST");
        asdu->smpCnt = 12345;
        asdu->confRev = 99;
        asdu->smpSynch = SV_SMPSYNCH_LOCAL;
        asdu->num_samples = 4;
        for (int i = 0; i < 4; i++) {
            asdu->samples[i].value = i * 1000;
            memset(&asdu->samples[i].quality, 0, sizeof(sv_quality_t));
        }

        /* Encode */
        int enc_ret = sv_encode_apdu(buf, sizeof(buf), &original, &encoded_len);
        PROPERTY_ASSERT(enc_ret == SV_BER_OK, "Encoding should succeed");

        /* Truncate to random length (at least 1 byte) */
        size_t truncated_len = (size_t)(1 + (rand() % (int)encoded_len));

        /* Decode truncated data - should not crash */
        int dec_ret = sv_decode_apdu(buf, truncated_len, &decoded);

        /* Decoder should return error (not crash) */
        PROPERTY_ASSERT(dec_ret == SV_BER_OK ||
                       dec_ret == SV_BER_ERR_BUFFER_FULL ||
                       dec_ret == SV_BER_ERR_INVALID_ARG ||
                       dec_ret == SV_BER_ERR_ENCODING ||
                       dec_ret == SV_BER_ERR_DECODING,
                       "Decoder should handle truncation gracefully");
    }
    PROPERTY_TEST_END();
}

/* Property 5: Random garbage data */
static void test_random_garbage_input(void) {
    PROPERTY_TEST("Decoders handle random garbage", 500) {
        uint8_t garbage[1500] = {0};  /* Initialize to silence cppcheck */
        goose_apdu_t goose_decoded;
        sv_apdu_t sv_decoded;

        /* Generate random garbage */
        size_t len = (size_t)(10 + (rand() % 1490));
        for (size_t i = 0; i < len; i++) {
            garbage[i] = (uint8_t)rand();
        }

        /* Try to decode as GOOSE - should not crash */
        int goose_ret = goose_decode_apdu(garbage, len, &goose_decoded);
        PROPERTY_ASSERT(goose_ret == GOOSE_BER_OK ||
                       goose_ret == GOOSE_BER_ERR_BUFFER_FULL ||
                       goose_ret == GOOSE_BER_ERR_INVALID_ARG ||
                       goose_ret == GOOSE_BER_ERR_ENCODING,
                       "GOOSE decoder should handle garbage gracefully");

        /* Try to decode as SV - should not crash */
        int sv_ret = sv_decode_apdu(garbage, len, &sv_decoded);
        PROPERTY_ASSERT(sv_ret == SV_BER_OK ||
                       sv_ret == SV_BER_ERR_BUFFER_FULL ||
                       sv_ret == SV_BER_ERR_INVALID_ARG ||
                       sv_ret == SV_BER_ERR_ENCODING ||
                       sv_ret == SV_BER_ERR_DECODING,
                       "SV decoder should handle garbage gracefully");
    }
    PROPERTY_TEST_END();
}

/* Property 6: Zero-filled buffers */
static void test_zero_filled_input(void) {
    PROPERTY_TEST("Decoders handle zero-filled input", 200) {
        uint8_t zeros[1500];
        goose_apdu_t goose_decoded;
        sv_apdu_t sv_decoded;

        /* Create zero-filled buffer */
        size_t len = (size_t)(10 + (rand() % 1490));
        memset(zeros, 0, len);

        /* Decode should return error (not crash) */
        int goose_ret = goose_decode_apdu(zeros, len, &goose_decoded);
        PROPERTY_ASSERT(goose_ret == GOOSE_BER_ERR_BUFFER_FULL ||
                       goose_ret == GOOSE_BER_ERR_INVALID_ARG ||
                       goose_ret == GOOSE_BER_ERR_ENCODING,
                       "GOOSE decoder should reject zero-filled input");

        int sv_ret = sv_decode_apdu(zeros, len, &sv_decoded);
        PROPERTY_ASSERT(sv_ret == SV_BER_ERR_BUFFER_FULL ||
                       sv_ret == SV_BER_ERR_INVALID_ARG ||
                       sv_ret == SV_BER_ERR_ENCODING ||
                       sv_ret == SV_BER_ERR_DECODING,
                       "SV decoder should reject zero-filled input");
    }
    PROPERTY_TEST_END();
}

/* Property 7: All 0xFF buffers */
static void test_all_ff_input(void) {
    PROPERTY_TEST("Decoders handle all-0xFF input", 200) {
        uint8_t all_ff[1500];
        goose_apdu_t goose_decoded;
        sv_apdu_t sv_decoded;

        /* Create all-0xFF buffer */
        size_t len = (size_t)(10 + (rand() % 1490));
        memset(all_ff, 0xFF, len);

        /* Decode should return error (not crash) */
        int goose_ret = goose_decode_apdu(all_ff, len, &goose_decoded);
        PROPERTY_ASSERT(goose_ret == GOOSE_BER_ERR_BUFFER_FULL ||
                       goose_ret == GOOSE_BER_ERR_INVALID_ARG ||
                       goose_ret == GOOSE_BER_ERR_ENCODING,
                       "GOOSE decoder should reject all-0xFF input");

        int sv_ret = sv_decode_apdu(all_ff, len, &sv_decoded);
        PROPERTY_ASSERT(sv_ret == SV_BER_ERR_BUFFER_FULL ||
                       sv_ret == SV_BER_ERR_INVALID_ARG ||
                       sv_ret == SV_BER_ERR_ENCODING ||
                       sv_ret == SV_BER_ERR_DECODING,
                       "SV decoder should reject all-0xFF input");
    }
    PROPERTY_TEST_END();
}

int main(void) {
    property_test_init();

    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║  Malformed Input Property Tests                           ║\n");
    printf("║  Testing decoder robustness against corrupted data        ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");

    test_goose_decoder_bit_flips();
    test_goose_decoder_truncation();
    test_sv_decoder_bit_flips();
    test_sv_decoder_truncation();
    test_random_garbage_input();
    test_zero_filled_input();
    test_all_ff_input();

    property_test_summary();

    return 0;
}
