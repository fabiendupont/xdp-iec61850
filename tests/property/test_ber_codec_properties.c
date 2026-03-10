/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Property-Based Tests for BER Codec Edge Cases
 *
 * Tests low-level BER encoding/decoding properties:
 * - Length field encoding (short/long form, boundaries)
 * - Tag handling (valid/invalid, constructed/primitive)
 * - Nested structure depth limits
 * - Buffer boundary conditions
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include "property_test.h"
#include "asn1/goose_ber.h"
#include "asn1/goose_ber_decode.h"
#include <stdint.h>
#include <string.h>

/* Error codes from goose_ber.h */
#ifndef GOOSE_BER_OK
#define GOOSE_BER_OK                0
#define GOOSE_BER_ERR_BUFFER_FULL   -1
#define GOOSE_BER_ERR_INVALID_ARG   -2
#define GOOSE_BER_ERR_ENCODING      -3
#endif

/* Test BER length encoding (short form: 0-127, long form: 128+) */
static void test_ber_length_encoding_boundaries(void) {
    PROPERTY_TEST("BER length encoding boundaries", 1000) {
        uint8_t buf[1024];
        size_t offset = 0;

        /* Generate length in different ranges */
        uint32_t length = 0;  /* Initialize to satisfy static analyzer */
        int range = rand() % 5;
        switch (range) {
            case 0: length = (uint32_t)(rand() % 128); break;              // Short form (0-127)
            case 1: length = (uint32_t)(127 + (rand() % 10)); break;       // Boundary (127-136)
            case 2: length = (uint32_t)(128 + (rand() % 100)); break;      // Long form 1-byte
            case 3: length = (uint32_t)(255 + (rand() % 100)); break;      // Long form boundary
            case 4: length = (uint32_t)(256 + (rand() % 1000)); break;     // Long form 2-byte
            default: break;  /* Unreachable, but helps static analyzer */
        }

        /* Encode length */
        int ret = ber_encode_length(buf, sizeof(buf), &offset, length);

        if (length < sizeof(buf) - 10) {
            /* Should succeed if buffer has space */
            PROPERTY_ASSERT(ret == GOOSE_BER_OK, "Length encoding should succeed");

            /* Decode and verify */
            size_t decode_offset = 0;
            size_t decoded_length = 0;
            ret = ber_decode_length(buf, offset, &decode_offset, &decoded_length);

            PROPERTY_ASSERT(ret == GOOSE_BER_OK, "Length decoding should succeed");
            PROPERTY_ASSERT_EQ(length, decoded_length, "Decoded length should match original");
        }
    }
    PROPERTY_TEST_END();
}

/* Test BER tag encoding with various tag numbers and classes */
static void test_ber_tag_encoding_variations(void) {
    PROPERTY_TEST("BER tag encoding variations", 800) {
        uint8_t buf[128];
        size_t offset = 0;

        /* Generate random tag (0-30 for single-byte tags) */
        uint8_t tag = (uint8_t)(rand()) % 31;

        /* Encode tag */
        int ret = ber_encode_tag(buf, sizeof(buf), &offset, tag);
        PROPERTY_ASSERT(ret == GOOSE_BER_OK, "Tag encoding should succeed");

        /* Verify tag was written */
        PROPERTY_ASSERT(offset >= 1, "Tag should use at least 1 byte");
        PROPERTY_ASSERT(buf[0] == tag, "Encoded tag should match");
    }
    PROPERTY_TEST_END();
}

/* Test buffer overflow protection in encoding */
static void test_ber_encoding_buffer_overflow_protection(void) {
    PROPERTY_TEST("BER encoding buffer overflow protection", 600) {
        /* Use very small buffer */
        uint8_t buf[8];
        size_t offset = 0;

        /* Try to encode data that won't fit */
        uint32_t large_value = random_uint32();

        int ret = ber_encode_uint32(buf, sizeof(buf), &offset,
                                                    ASN1_TAG_INTEGER, large_value);

        /* Should either succeed (if it fits) or return BUFFER_FULL */
        PROPERTY_ASSERT(ret == GOOSE_BER_OK || ret == GOOSE_BER_ERR_BUFFER_FULL,
                       "Should handle small buffer gracefully");

        if (ret == GOOSE_BER_OK) {
            /* Verify we didn't overflow */
            PROPERTY_ASSERT(offset <= sizeof(buf), "Should not exceed buffer size");
        }
    }
    PROPERTY_TEST_END();
}

/* Test nested sequence depth limits */
static void test_nested_sequence_depth(void) {
    PROPERTY_TEST("Nested sequence depth handling", 400) {
        uint8_t buf[2048];
        size_t offset = 0;

        /* Create nested sequences (depth 1-5) */
        int depth = 1 + (rand() % 5);

        /* Start each sequence */
        size_t sequence_starts[5];
        (void)sequence_starts;
        for (int i = 0; i < depth; i++) {
            sequence_starts[i] = offset;
            int ret = ber_encode_tag(buf, sizeof(buf), &offset,
                                                     ASN1_TAG_SEQUENCE);
            PROPERTY_ASSERT(ret == GOOSE_BER_OK, "Sequence tag encoding should succeed");

            /* Reserve space for length (will update later) */
            offset += 2;
        }

        /* Add some data in innermost sequence */
        int ret = ber_encode_boolean(buf, sizeof(buf), &offset,
                                                     ASN1_TAG_BOOLEAN, true);
        PROPERTY_ASSERT(ret == GOOSE_BER_OK, "Boolean encoding in nested sequence should succeed");

        /* Verify we didn't overflow */
        PROPERTY_ASSERT(offset < sizeof(buf), "Should not overflow buffer");
    }
    PROPERTY_TEST_END();
}

/* Test length field with maximum values */
static void test_ber_length_maximum_values(void) {
    PROPERTY_TEST("BER length maximum values", 500) {
        uint8_t buf[1024];
        size_t offset = 0;

        /* Test lengths near boundaries */
        uint32_t test_lengths[] = {
            0, 1, 127, 128, 255, 256, 65535
        };
        int num_tests = sizeof(test_lengths) / sizeof(test_lengths[0]);
        uint32_t length = test_lengths[rand() % num_tests];

        int ret = ber_encode_length(buf, sizeof(buf), &offset, length);

        if (length < sizeof(buf) - 10) {
            PROPERTY_ASSERT(ret == GOOSE_BER_OK, "Length encoding should succeed");

            /* Verify correct encoding */
            if (length < 128) {
                /* Short form: 1 byte */
                PROPERTY_ASSERT(offset == 1, "Short form should use 1 byte");
                PROPERTY_ASSERT(buf[0] == length, "Short form value should match");
            } else {
                /* Long form: 1+ bytes */
                PROPERTY_ASSERT(offset >= 2, "Long form should use 2+ bytes");
                PROPERTY_ASSERT(buf[0] & 0x80, "Long form should have bit 7 set");
            }
        }
    }
    PROPERTY_TEST_END();
}

/* Test decoding with truncated input */
static void test_ber_decode_truncated_input(void) {
    PROPERTY_TEST("BER decode truncated input", 600) {
        uint8_t buf[256];

        /* Create valid encoded data first */
        size_t encode_offset = 0;
        uint32_t value = random_uint32();
        int ret = ber_encode_uint32(buf, sizeof(buf), &encode_offset,
                                                    ASN1_TAG_INTEGER, value);

        if (ret == GOOSE_BER_OK && encode_offset > 2) {
            /* Truncate the buffer randomly */
            size_t truncate_len = (size_t)(1 + (rand() % (int)(encode_offset - 1)));

            /* Try to decode truncated data */
            size_t decode_offset = 0;
            uint8_t decoded_tag;
            ret = ber_decode_tag(buf, truncate_len, &decode_offset, &decoded_tag);

            /* Should either succeed (if tag fits) or return error */
            PROPERTY_ASSERT(ret == GOOSE_BER_OK || ret == GOOSE_BER_ERR_INVALID_ARG || ret == GOOSE_BER_ERR_ENCODING,
                           "Truncated decode should handle gracefully");
        }
    }
    PROPERTY_TEST_END();
}

/* Test encoding with offset at buffer boundaries */
static void test_ber_encoding_offset_boundaries(void) {
    PROPERTY_TEST("BER encoding with offset at boundaries", 500) {
        uint8_t buf[128];

        /* Start with random offset near end of buffer */
        size_t initial_offset = sizeof(buf) - (size_t)(rand() % 10);
        size_t offset = initial_offset;

        /* Try to encode something */
        int ret = ber_encode_boolean(buf, sizeof(buf), &offset,
                                                     ASN1_TAG_BOOLEAN, true);

        /* Should return BUFFER_FULL if not enough space (need 3 bytes) */
        if (initial_offset > sizeof(buf) - 3) {
            PROPERTY_ASSERT(ret == GOOSE_BER_ERR_BUFFER_FULL,
                           "Should detect insufficient buffer space");
        } else {
            /* Should succeed if we have exactly 3 or more bytes */
            PROPERTY_ASSERT(ret == GOOSE_BER_OK,
                           "Should succeed with sufficient buffer space");
        }
    }
    PROPERTY_TEST_END();
}

/* Test tag decoding with invalid tags */
static void test_ber_decode_invalid_tags(void) {
    PROPERTY_TEST("BER decode invalid/unknown tags", 400) {
        uint8_t buf[64];

        /* Create buffer with random tag */
        buf[0] = random_uint8();

        size_t offset = 0;
        uint8_t tag;
        int ret = ber_decode_tag(buf, sizeof(buf), &offset, &tag);

        /* Tag decoding itself should always succeed (just reads byte) */
        PROPERTY_ASSERT(ret == GOOSE_BER_OK, "Tag decode should succeed");
        PROPERTY_ASSERT(tag == buf[0], "Decoded tag should match buffer");
        PROPERTY_ASSERT(offset == 1, "Should advance offset by 1");
    }
    PROPERTY_TEST_END();
}

/* Test length decoding with malformed long-form encoding */
static void test_ber_decode_malformed_length(void) {
    PROPERTY_TEST("BER decode malformed length encoding", 400) {
        uint8_t buf[64];

        /* Create malformed long-form length */
        /* Set bit 7 (long form) but with invalid length-of-length */
        buf[0] = (uint8_t)(0x80 | (rand() % 10));  // Long form marker with 0-9 bytes

        /* Fill rest with random data */
        for (int i = 1; i < 10 && i < (int)sizeof(buf); i++) {
            buf[i] = random_uint8();
        }

        size_t offset = 0;
        size_t length;
        int ret = ber_decode_length(buf, sizeof(buf), &offset, &length);

        /* Should handle malformed input gracefully (succeed or return error) */
        PROPERTY_ASSERT(ret == GOOSE_BER_OK || ret == GOOSE_BER_ERR_INVALID_ARG ||
                       ret == GOOSE_BER_ERR_ENCODING,
                       "Should handle malformed length gracefully");
    }
    PROPERTY_TEST_END();
}

/* Test zero-length sequences */
static void test_ber_zero_length_sequences(void) {
    PROPERTY_TEST("BER zero-length sequence handling", 300) {
        uint8_t buf[128];
        size_t offset = 0;

        /* Encode sequence tag */
        int ret = ber_encode_tag(buf, sizeof(buf), &offset, ASN1_TAG_SEQUENCE);
        PROPERTY_ASSERT(ret == GOOSE_BER_OK, "Sequence tag should encode");

        /* Encode zero length */
        ret = ber_encode_length(buf, sizeof(buf), &offset, 0);
        PROPERTY_ASSERT(ret == GOOSE_BER_OK, "Zero length should encode");

        /* Verify encoding */
        PROPERTY_ASSERT(offset == 2, "Empty sequence should be 2 bytes");
        PROPERTY_ASSERT(buf[0] == ASN1_TAG_SEQUENCE, "Tag should be sequence");
        PROPERTY_ASSERT(buf[1] == 0, "Length should be 0");
    }
    PROPERTY_TEST_END();
}

int main(void) {
    property_test_init();

    printf("\n=== BER Codec Property-Based Tests ===\n");

    test_ber_length_encoding_boundaries();
    test_ber_tag_encoding_variations();
    test_ber_encoding_buffer_overflow_protection();
    test_nested_sequence_depth();
    test_ber_length_maximum_values();
    test_ber_decode_truncated_input();
    test_ber_encoding_offset_boundaries();
    test_ber_decode_invalid_tags();
    test_ber_decode_malformed_length();
    test_ber_zero_length_sequences();

    property_test_summary();

    return 0;
}
