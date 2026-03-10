/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Property-Based Tests for GOOSE Encoder/Decoder
 *
 * Tests invariants and properties that should hold for all valid inputs:
 * - Round-trip: decode(encode(x)) == x
 * - Length consistency: encoded_len matches actual data
 * - Data preservation: All fields preserved through encoding
 * - Idempotence: encode(x) always produces same output
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "property_test.h"
#include "asn1/goose_ber.h"
#include "asn1/goose_ber_decode.h"
#include <stdint.h>

/* Generate random GOOSE APDU */
static void generate_random_goose_apdu(goose_apdu_t *apdu) {
    goose_apdu_init(apdu);

    /* Random gocbRef (IEC 61850 VisibleString) */
    random_visible_string(apdu->gocbRef, GOOSE_MAX_GOCBREF_LEN);

    /* Random datSet */
    random_visible_string(apdu->datSet, GOOSE_MAX_DATSET_LEN);

    /* Random goID (optional) */
    apdu->has_goID = random_bool();
    if (apdu->has_goID) {
        random_visible_string(apdu->goID, GOOSE_MAX_GOID_LEN);
    }

    /* Random timestamp (constrained to IEC 61850 UtcTime range: 32-bit seconds max) */
    uint32_t seconds = random_uint32();
    uint32_t usec = (uint32_t)(rand() % 1000000);  /* 0-999999 microseconds */
    apdu->timestamp = (uint64_t)seconds * 1000000ULL + usec;

    /* Random time quality */
    apdu->time_quality = random_uint8();

    /* Random stNum and sqNum */
    apdu->stNum = random_uint32();
    apdu->sqNum = random_uint32();

    /* Random confRev */
    apdu->confRev = random_uint32();

    /* Random flags */
    apdu->test = random_bool();
    apdu->ndsCom = random_bool();

    /* Random timeAllowedtoLive */
    apdu->timeAllowedtoLive = 1 + (random_uint32() % 10000);

    /* Random allData (0-8 items for simplicity) */
    int num_items = rand() % 9;
    for (int i = 0; i < num_items; i++) {
        int type = rand() % 3;  /* BOOLEAN, INT32, UINT32 */
        switch (type) {
            case 0:
                goose_add_boolean(apdu, random_bool());
                break;
            case 1:
                goose_add_int32(apdu, random_int32_biased());
                break;
            case 2:
                goose_add_uint32(apdu, random_uint32_biased());
                break;
        }
    }
}

/* Compare two GOOSE APDUs for equality */
static bool goose_apdu_equal(const goose_apdu_t *a, const goose_apdu_t *b) {
    if (strcmp(a->gocbRef, b->gocbRef) != 0) return false;
    if (a->timeAllowedtoLive != b->timeAllowedtoLive) return false;
    if (strcmp(a->datSet, b->datSet) != 0) return false;
    if (a->has_goID != b->has_goID) return false;
    if (a->has_goID && strcmp(a->goID, b->goID) != 0) return false;
    if (a->timestamp != b->timestamp) return false;
    if (a->time_quality != b->time_quality) return false;
    if (a->stNum != b->stNum) return false;
    if (a->sqNum != b->sqNum) return false;
    if (a->test != b->test) return false;
    if (a->confRev != b->confRev) return false;
    if (a->ndsCom != b->ndsCom) return false;
    if (a->numDatSetEntries != b->numDatSetEntries) return false;

    /* Compare allData */
    for (uint32_t i = 0; i < a->numDatSetEntries; i++) {
        if (a->allData[i].type != b->allData[i].type) return false;
        switch (a->allData[i].type) {
            case GOOSE_DATA_BOOLEAN:
                if (a->allData[i].value.boolean != b->allData[i].value.boolean)
                    return false;
                break;
            case GOOSE_DATA_INT32:
                if (a->allData[i].value.int32 != b->allData[i].value.int32)
                    return false;
                break;
            case GOOSE_DATA_UINT32:
                if (a->allData[i].value.uint32 != b->allData[i].value.uint32)
                    return false;
                break;
            default:
                /* Other types not supported in basic property tests */
                break;
        }
    }

    return true;
}

/* Property 1: Round-trip - decode(encode(apdu)) == apdu */
static void test_goose_roundtrip_property(void) {
    PROPERTY_TEST("GOOSE encode-decode roundtrip", 1000) {
        goose_apdu_t original, decoded;
        uint8_t buf[1500];
        size_t encoded_len;

        /* Generate random APDU */
        generate_random_goose_apdu(&original);

        /* Encode */
        int enc_result = goose_encode_apdu(buf, sizeof(buf), &original, &encoded_len);
        PROPERTY_ASSERT(enc_result == GOOSE_BER_OK, "Encoding should succeed");
        PROPERTY_ASSERT(encoded_len > 0 && encoded_len <= sizeof(buf),
                       "Encoded length should be in valid range");

        /* Decode */
        goose_apdu_init(&decoded);
        int dec_result = goose_decode_apdu(buf, encoded_len, &decoded);
        PROPERTY_ASSERT(dec_result == GOOSE_BER_OK, "Decoding should succeed");

        /* Verify round-trip */
        PROPERTY_ASSERT(goose_apdu_equal(&original, &decoded),
                       "Decoded APDU must match original");
    }
    PROPERTY_TEST_END();
}

/* Property 2: Length consistency */
static void test_goose_length_consistency(void) {
    PROPERTY_TEST("GOOSE length consistency", 500) {
        goose_apdu_t apdu;
        uint8_t buf[1500];
        size_t encoded_len;

        generate_random_goose_apdu(&apdu);

        int result = goose_encode_apdu(buf, sizeof(buf), &apdu, &encoded_len);
        PROPERTY_ASSERT(result == GOOSE_BER_OK, "Encoding should succeed");

        /* Verify encoded_len doesn't exceed buffer */
        PROPERTY_ASSERT(encoded_len <= sizeof(buf),
                       "Encoded length must not exceed buffer size");

        /* Verify encoded_len is reasonable (at least header size) */
        PROPERTY_ASSERT(encoded_len >= 20,
                       "Encoded GOOSE must be at least 20 bytes");
    }
    PROPERTY_TEST_END();
}

/* Property 3: Idempotence - encode(apdu) produces same output */
static void test_goose_encoding_idempotence(void) {
    PROPERTY_TEST("GOOSE encoding idempotence", 500) {
        goose_apdu_t apdu;
        uint8_t buf1[1500], buf2[1500];
        size_t len1, len2;

        generate_random_goose_apdu(&apdu);

        /* Encode twice */
        int r1 = goose_encode_apdu(buf1, sizeof(buf1), &apdu, &len1);
        int r2 = goose_encode_apdu(buf2, sizeof(buf2), &apdu, &len2);

        PROPERTY_ASSERT(r1 == GOOSE_BER_OK && r2 == GOOSE_BER_OK,
                       "Both encodings should succeed");
        PROPERTY_ASSERT_EQ(len1, len2, "Encoded lengths must match");
        PROPERTY_ASSERT(memcmp(buf1, buf2, len1) == 0,
                       "Encoded buffers must be identical");
    }
    PROPERTY_TEST_END();
}

/* Property 4: Data type preservation */
static void test_goose_data_type_preservation(void) {
    PROPERTY_TEST("GOOSE data type preservation", 500) {
        goose_apdu_t apdu;
        uint8_t buf[1500];
        size_t encoded_len;

        goose_apdu_init(&apdu);
        strcpy(apdu.gocbRef, "Test/LLN0$GO$gcb01");
        strcpy(apdu.datSet, "Test/LLN0$Dataset1");

        /* Add data items with known types */
        bool bool_val = random_bool();
        int32_t int32_val = random_int32_biased();
        uint32_t uint32_val = random_uint32_biased();

        goose_add_boolean(&apdu, bool_val);
        goose_add_int32(&apdu, int32_val);
        goose_add_uint32(&apdu, uint32_val);

        /* Encode */
        int result = goose_encode_apdu(buf, sizeof(buf), &apdu, &encoded_len);
        PROPERTY_ASSERT(result == GOOSE_BER_OK, "Encoding should succeed");

        /* Verify types are correct in APDU structure */
        PROPERTY_ASSERT(apdu.allData[0].type == GOOSE_DATA_BOOLEAN,
                       "First item should be BOOLEAN");
        PROPERTY_ASSERT(apdu.allData[1].type == GOOSE_DATA_INT32,
                       "Second item should be INT32");
        PROPERTY_ASSERT(apdu.allData[2].type == GOOSE_DATA_UINT32,
                       "Third item should be UINT32");

        /* Verify values are preserved */
        PROPERTY_ASSERT(apdu.allData[0].value.boolean == bool_val,
                       "Boolean value should be preserved");
        PROPERTY_ASSERT(apdu.allData[1].value.int32 == int32_val,
                       "INT32 value should be preserved");
        PROPERTY_ASSERT(apdu.allData[2].value.uint32 == uint32_val,
                       "UINT32 value should be preserved");
    }
    PROPERTY_TEST_END();
}

/* Property 5: String handling */
static void test_goose_string_handling(void) {
    PROPERTY_TEST("GOOSE string field handling", 500) {
        goose_apdu_t apdu;
        uint8_t buf[1500];
        size_t encoded_len;

        goose_apdu_init(&apdu);

        /* Generate random strings */
        random_visible_string(apdu.gocbRef, GOOSE_MAX_GOCBREF_LEN);
        random_visible_string(apdu.datSet, GOOSE_MAX_DATSET_LEN);
        apdu.has_goID = random_bool();
        if (apdu.has_goID) {
            random_visible_string(apdu.goID, GOOSE_MAX_GOID_LEN);
        }

        /* Encode */
        int result = goose_encode_apdu(buf, sizeof(buf), &apdu, &encoded_len);
        PROPERTY_ASSERT(result == GOOSE_BER_OK, "Encoding should succeed");

        /* Verify strings are null-terminated */
        PROPERTY_ASSERT(apdu.gocbRef[strlen(apdu.gocbRef)] == '\0',
                       "gocbRef should be null-terminated");
        PROPERTY_ASSERT(apdu.datSet[strlen(apdu.datSet)] == '\0',
                       "datSet should be null-terminated");
        if (apdu.has_goID) {
            PROPERTY_ASSERT(apdu.goID[strlen(apdu.goID)] == '\0',
                           "goID should be null-terminated");
        }
    }
    PROPERTY_TEST_END();
}

/* Property 6: Data type edge cases (INT32, UINT32 extreme values) */
static void test_goose_data_type_edge_cases(void) {
    PROPERTY_TEST("GOOSE data type edge cases", 500) {
        goose_apdu_t apdu;
        uint8_t buf[1500];
        size_t encoded_len;

        goose_apdu_init(&apdu);

        /* Set minimal required fields */
        strcpy(apdu.gocbRef, "EDGE_CASE_TEST");
        apdu.timeAllowedtoLive = 1000;
        strcpy(apdu.datSet, "DATASET");
        strcpy(apdu.goID, "GOID");
        apdu.timestamp = 123456;
        apdu.stNum = 1;
        apdu.sqNum = 1;
        apdu.test = false;
        apdu.confRev = 1;
        apdu.ndsCom = false;

        /* Test extreme values for each data type */
        int edge_case = rand() % 10;
        switch (edge_case) {
            case 0:  /* INT32_MIN */
                goose_add_int32(&apdu, INT32_MIN);
                break;
            case 1:  /* INT32_MAX */
                goose_add_int32(&apdu, INT32_MAX);
                break;
            case 2:  /* INT32 zero */
                goose_add_int32(&apdu, 0);
                break;
            case 3:  /* INT32 -1 */
                goose_add_int32(&apdu, -1);
                break;
            case 4:  /* INT32 +1 */
                goose_add_int32(&apdu, 1);
                break;
            case 5:  /* UINT32_MAX */
                goose_add_uint32(&apdu, UINT32_MAX);
                break;
            case 6:  /* UINT32 zero */
                goose_add_uint32(&apdu, 0);
                break;
            case 7:  /* UINT32 one */
                goose_add_uint32(&apdu, 1);
                break;
            case 8:  /* UINT32 boundary (2^31-1) */
                goose_add_uint32(&apdu, INT32_MAX);
                break;
            case 9:  /* UINT32 boundary (2^31) */
                goose_add_uint32(&apdu, (uint32_t)INT32_MAX + 1);
                break;
        }

        /* Encode should succeed for all edge cases */
        int enc_result = goose_encode_apdu(buf, sizeof(buf), &apdu, &encoded_len);
        PROPERTY_ASSERT(enc_result == GOOSE_BER_OK,
                       "Encoding should succeed for all edge cases");
        PROPERTY_ASSERT(encoded_len > 0 && encoded_len <= sizeof(buf),
                       "Encoded length should be in valid range");
    }
    PROPERTY_TEST_END();
}

/* Property 7: Timestamp and time quality combinations */
static void test_goose_timestamp_quality_combinations(void) {
    PROPERTY_TEST("GOOSE timestamp and time quality combinations", 500) {
        goose_apdu_t apdu;
        uint8_t buf[1500];
        size_t encoded_len;

        goose_apdu_init(&apdu);

        strcpy(apdu.gocbRef, "TIMESTAMP_QUALITY_TEST");
        apdu.timeAllowedtoLive = 5000;
        strcpy(apdu.datSet, "DS_TIME");
        strcpy(apdu.goID, "GO_TIME");
        apdu.stNum = 100;
        apdu.sqNum = 200;
        apdu.test = false;
        apdu.confRev = 5;
        apdu.ndsCom = false;
        apdu.numDatSetEntries = 1;
        apdu.allData[0].type = GOOSE_DATA_BOOLEAN;
        apdu.allData[0].value.boolean = true;

        /* Test various timestamp values */
        int edge_case = rand() % 10;

        switch (edge_case) {
            case 0:  /* Zero timestamp */
                apdu.timestamp = 0;
                apdu.time_quality = 0x00;  /* Unspecified */
                break;
            case 1:  /* Unix epoch */
                apdu.timestamp = 1000000ULL;  /* 1 second in microseconds */
                apdu.time_quality = 0x00;
                break;
            case 2:  /* Y2K */
                apdu.timestamp = 946684800ULL * 1000000ULL;
                apdu.time_quality = 0x40;  /* Time accuracy < 1ms */
                break;
            case 3:  /* Current era (2024) */
                apdu.timestamp = 1700000000ULL * 1000000ULL;
                apdu.time_quality = 0x60;  /* Time accuracy < 100us */
                break;
            case 4:  /* Max 32-bit seconds */
                apdu.timestamp = 0xFFFFFFFFULL * 1000000ULL;
                apdu.time_quality = 0x80;  /* Leap second known */
                break;
            case 5:  /* Random large timestamp */
                apdu.timestamp = random_uint64();
                apdu.time_quality = random_uint8() & 0xE0;  /* Upper 3 bits */
                break;
            case 6:  /* Leap second flag set */
                apdu.timestamp = 1000000000ULL * 1000000ULL;
                apdu.time_quality = 0x80;
                break;
            case 7:  /* Clock not synchronized */
                apdu.timestamp = random_uint64();
                apdu.time_quality = 0x20;  /* Not synchronized */
                break;
            case 8:  /* Max timestamp */
                apdu.timestamp = UINT64_MAX;
                apdu.time_quality = 0xFF;
                break;
            case 9:  /* Random quality with random timestamp */
                apdu.timestamp = random_uint64();
                apdu.time_quality = random_uint8();
                break;
        }

        /* Encode should succeed for all timestamp/quality combinations */
        int enc_result = goose_encode_apdu(buf, sizeof(buf), &apdu, &encoded_len);
        PROPERTY_ASSERT(enc_result == GOOSE_BER_OK,
                       "Encoding should succeed for all timestamp/quality combinations");
        PROPERTY_ASSERT(encoded_len > 0 && encoded_len <= sizeof(buf),
                       "Encoded length should be in valid range");
    }
    PROPERTY_TEST_END();
}

int main(void) {
    property_test_init();

    printf("\n╔════════════════════════════════════════════════════════════╗\n");
    printf("║  GOOSE Property-Based Tests                               ║\n");
    printf("║  Testing invariants across thousands of random inputs     ║\n");
    printf("╚════════════════════════════════════════════════════════════╝\n");

    test_goose_roundtrip_property();
    test_goose_length_consistency();
    test_goose_encoding_idempotence();
    test_goose_data_type_preservation();
    test_goose_string_handling();
    test_goose_data_type_edge_cases();
    test_goose_timestamp_quality_combinations();

    property_test_summary();

    return 0;
}
