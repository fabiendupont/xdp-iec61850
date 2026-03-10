/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Lightweight Property-Based Testing Framework for C
 *
 * Provides QuickCheck-style property testing without external dependencies.
 * Generates random inputs and tests invariants/properties.
 *
 * Usage:
 *   PROPERTY_TEST("encode-decode roundtrip", 1000) {
 *       uint32_t value = random_uint32();
 *       // Test that decode(encode(value)) == value
 *       PROPERTY_ASSERT(decode(encode(value)) == value, "roundtrip failed");
 *   }
 *   PROPERTY_TEST_END();
 */

#ifndef PROPERTY_TEST_H
#define PROPERTY_TEST_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <time.h>
#include <assert.h>

/* Global state */
static unsigned int property_test_seed = 0;
static int property_tests_run = 0;
static int property_tests_passed = 0;
static int property_tests_failed = 0;

/* Initialize random seed */
static inline void property_test_init(void) {
    property_test_seed = (unsigned int)time(NULL);
    srand(property_test_seed);
    printf("Property testing initialized (seed: %u)\n", property_test_seed);
}

/* Random generators */
static inline uint8_t random_uint8(void) {
    return (uint8_t)(rand() % 256);
}

static inline uint16_t random_uint16(void) {
    return (uint16_t)(rand() % 65536);
}

static inline uint32_t random_uint32(void) {
    return ((uint32_t)rand() << 16) | (uint32_t)rand();
}

static inline uint64_t random_uint64(void) {
    return ((uint64_t)random_uint32() << 32) | (uint64_t)random_uint32();
}

static inline int32_t random_int32(void) {
    return (int32_t)random_uint32();
}

static inline bool random_bool(void) {
    return (rand() % 2) == 1;
}

/* Random string generator (printable ASCII) */
static inline void random_string(char *buf, size_t max_len) {
    size_t len = (size_t)(1 + (rand() % (int)(max_len - 1)));
    for (size_t i = 0; i < len; i++) {
        buf[i] = (char)(32 + (rand() % 95));
    }
    buf[len] = '\0';
}

/* Random visible string (IEC 61850 compatible: [A-Za-z0-9_/.]) */
static inline void random_visible_string(char *buf, size_t max_len) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_/.$";
    size_t len = (size_t)(1 + (rand() % (int)(max_len - 1)));
    for (size_t i = 0; i < len; i++) {
        buf[i] = charset[(size_t)rand() % (sizeof(charset) - 1)];
    }
    buf[len] = '\0';
}

/* Property test runner macro */
#define PROPERTY_TEST(name, iterations) \
    printf("\n=== Property Test: %s ===\n", name); \
    printf("Running %d iterations...\n", iterations); \
    int _prop_failures = 0; \
    int _prop_iterations = iterations; \
    for (int _prop_i = 0; _prop_i < iterations; _prop_i++)

/* Property assertion macros */
#define PROPERTY_ASSERT(cond, msg) \
    do { \
        if (!(cond)) { \
            printf("  FAILED at iteration %d: %s\n", _prop_i, msg); \
            printf("    Condition: %s\n", #cond); \
            _prop_failures++; \
            if (_prop_failures >= 10) { \
                printf("  Too many failures, aborting test\n"); \
                break; \
            } \
        } \
    } while (0)

#define PROPERTY_ASSERT_EQ(a, b, msg) \
    do { \
        if ((a) != (b)) { \
            printf("  FAILED at iteration %d: %s\n", _prop_i, msg); \
            printf("    Expected: %lld\n", (long long)(a)); \
            printf("    Got:      %lld\n", (long long)(b)); \
            _prop_failures++; \
            if (_prop_failures >= 10) { \
                printf("  Too many failures, aborting test\n"); \
                break; \
            } \
        } \
    } while (0)

#define PROPERTY_ASSERT_STREQ(a, b, msg) \
    do { \
        if (strcmp(a, b) != 0) { \
            printf("  FAILED at iteration %d: %s\n", _prop_i, msg); \
            printf("    Expected: \"%s\"\n", a); \
            printf("    Got:      \"%s\"\n", b); \
            _prop_failures++; \
            if (_prop_failures >= 10) { \
                printf("  Too many failures, aborting test\n"); \
                break; \
            } \
        } \
    } while (0)

/* Property test summary */
#define PROPERTY_TEST_END() \
    do { \
        property_tests_run++; \
        if (_prop_failures == 0) { \
            property_tests_passed++; \
            printf("  PASSED: All iterations succeeded\n"); \
        } else { \
            property_tests_failed++; \
            printf("  FAILED: %d/%d iterations failed\n", _prop_failures, _prop_iterations); \
        } \
    } while (0)

/* Final summary */
static inline void property_test_summary(void) {
    printf("\n=== Property Test Summary ===\n");
    printf("Tests run:    %d\n", property_tests_run);
    printf("Tests passed: %d\n", property_tests_passed);
    printf("Tests failed: %d\n", property_tests_failed);

    if (property_tests_failed > 0) {
        printf("\nSome property tests FAILED\n");
        exit(1);
    } else {
        printf("\nAll property tests PASSED\n");
    }
}

/* Edge case generators (boundary values) */
static inline uint32_t random_uint32_biased(void) {
    int choice = rand() % 10;
    switch (choice) {
        case 0: return 0;
        case 1: return 1;
        case 2: return UINT32_MAX;
        case 3: return UINT32_MAX - 1;
        default: return random_uint32();
    }
}

static inline int32_t random_int32_biased(void) {
    int choice = rand() % 10;
    switch (choice) {
        case 0: return 0;
        case 1: return 1;
        case 2: return -1;
        case 3: return INT32_MAX;
        case 4: return INT32_MIN;
        default: return random_int32();
    }
}

#endif /* PROPERTY_TEST_H */
