/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for IEC 61850 C Fixed-Capacity Containers
 *
 * Tests cover: fixed_string, fixed_array, ring_buffer
 */

#include "property_test.h"
#include "containers/fixed_string.h"
#include "containers/fixed_array.h"
#include "containers/ring_buffer.h"

#include <stdio.h>
#include <string.h>
#include <assert.h>

/* ========================================================================
 * Test counters
 * ======================================================================== */

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) \
    do { \
        tests_run++; \
        printf("  [TEST] %s ... ", name); \
    } while (0)

#define PASS() \
    do { \
        tests_passed++; \
        printf("PASS\n"); \
    } while (0)

#define FAIL(msg) \
    do { \
        tests_failed++; \
        printf("FAIL: %s\n", msg); \
    } while (0)

#define ASSERT_TRUE(cond) \
    do { \
        if (!(cond)) { \
            FAIL(#cond); \
            return; \
        } \
    } while (0)

#define ASSERT_EQ(a, b) \
    do { \
        if ((a) != (b)) { \
            printf("FAIL: %s == %s (%lld != %lld)\n", \
                   #a, #b, (long long)(a), (long long)(b)); \
            tests_failed++; \
            return; \
        } \
    } while (0)

#define ASSERT_STREQ(a, b) \
    do { \
        if (strcmp((a), (b)) != 0) { \
            printf("FAIL: %s == %s (\"%s\" != \"%s\")\n", \
                   #a, #b, (a), (b)); \
            tests_failed++; \
            return; \
        } \
    } while (0)

/* ========================================================================
 * fixed_string tests (iec61850_str129_t as primary, also str32 and str256)
 * ======================================================================== */

static void test_str129_init(void)
{
    TEST("str129_init");

    iec61850_str129_t s;
    iec61850_str129_init(&s);

    ASSERT_EQ(iec61850_str129_len(&s), (size_t)0);
    ASSERT_TRUE(iec61850_str129_empty(&s));
    ASSERT_STREQ(iec61850_str129_cstr(&s), "");
    ASSERT_EQ(iec61850_str129_capacity(&s), (size_t)129);

    PASS();
}

static void test_str129_assign(void)
{
    TEST("str129_assign");

    iec61850_str129_t s;
    iec61850_str129_init(&s);

    int ret = iec61850_str129_assign(&s, "HelloWorld");
    ASSERT_EQ(ret, 0);
    ASSERT_STREQ(iec61850_str129_cstr(&s), "HelloWorld");
    ASSERT_EQ(iec61850_str129_len(&s), (size_t)10);
    ASSERT_TRUE(!iec61850_str129_empty(&s));

    PASS();
}

static void test_str129_assign_null(void)
{
    TEST("str129_assign_null");

    iec61850_str129_t s;
    iec61850_str129_init(&s);

    int ret = iec61850_str129_assign(&s, NULL);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(iec61850_str129_len(&s), (size_t)0);
    ASSERT_STREQ(iec61850_str129_cstr(&s), "");

    PASS();
}

static void test_str129_truncation(void)
{
    TEST("str129_truncation");

    iec61850_str129_t s;
    iec61850_str129_init(&s);

    /* Build a string longer than 129 characters */
    char long_str[256];
    memset(long_str, 'A', 255);
    long_str[255] = '\0';

    int ret = iec61850_str129_assign(&s, long_str);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(iec61850_str129_len(&s), (size_t)129);

    /* Must be null-terminated */
    const char *cstr = iec61850_str129_cstr(&s);
    ASSERT_EQ(cstr[129], '\0');

    PASS();
}

static void test_str129_compare(void)
{
    TEST("str129_compare");

    iec61850_str129_t a, b;
    iec61850_str129_init(&a);
    iec61850_str129_init(&b);

    iec61850_str129_assign(&a, "alpha");
    iec61850_str129_assign(&b, "alpha");
    ASSERT_TRUE(iec61850_str129_equal(&a, &b));
    ASSERT_EQ(iec61850_str129_compare(&a, &b), 0);

    iec61850_str129_assign(&b, "beta");
    ASSERT_TRUE(!iec61850_str129_equal(&a, &b));
    ASSERT_TRUE(iec61850_str129_compare(&a, &b) < 0);

    PASS();
}

static void test_str129_compare_cstr(void)
{
    TEST("str129_compare_cstr");

    iec61850_str129_t s;
    iec61850_str129_init(&s);
    iec61850_str129_assign(&s, "test");

    ASSERT_TRUE(iec61850_str129_equal_cstr(&s, "test"));
    ASSERT_TRUE(!iec61850_str129_equal_cstr(&s, "other"));
    ASSERT_TRUE(!iec61850_str129_equal_cstr(&s, "tes"));
    ASSERT_TRUE(!iec61850_str129_equal_cstr(&s, "test1"));

    PASS();
}

static void test_str129_clear(void)
{
    TEST("str129_clear");

    iec61850_str129_t s;
    iec61850_str129_init(&s);
    iec61850_str129_assign(&s, "not empty");
    ASSERT_TRUE(!iec61850_str129_empty(&s));

    iec61850_str129_clear(&s);
    ASSERT_TRUE(iec61850_str129_empty(&s));
    ASSERT_EQ(iec61850_str129_len(&s), (size_t)0);
    ASSERT_STREQ(iec61850_str129_cstr(&s), "");

    PASS();
}

static void test_str129_assign_n(void)
{
    TEST("str129_assign_n");

    iec61850_str129_t s;
    iec61850_str129_init(&s);

    int ret = iec61850_str129_assign_n(&s, "Hello World", 5);
    ASSERT_EQ(ret, 0);
    ASSERT_STREQ(iec61850_str129_cstr(&s), "Hello");
    ASSERT_EQ(iec61850_str129_len(&s), (size_t)5);

    PASS();
}

static void test_str32_basic(void)
{
    TEST("str32_basic");

    iec61850_str32_t s;
    iec61850_str32_init(&s);

    ASSERT_EQ(iec61850_str32_capacity(&s), (size_t)32);
    iec61850_str32_assign(&s, "short");
    ASSERT_STREQ(iec61850_str32_cstr(&s), "short");

    /* Truncation at 32 */
    char long_str[64];
    memset(long_str, 'B', 63);
    long_str[63] = '\0';
    iec61850_str32_assign(&s, long_str);
    ASSERT_EQ(iec61850_str32_len(&s), (size_t)32);

    PASS();
}

static void test_str256_basic(void)
{
    TEST("str256_basic");

    iec61850_str256_t s;
    iec61850_str256_init(&s);

    ASSERT_EQ(iec61850_str256_capacity(&s), (size_t)256);
    iec61850_str256_assign(&s, "/path/to/certificate.pem");
    ASSERT_STREQ(iec61850_str256_cstr(&s), "/path/to/certificate.pem");

    PASS();
}

/* ========================================================================
 * fixed_array tests (iec61850_int32_array64_t)
 * ======================================================================== */

static void test_int32_array_init(void)
{
    TEST("int32_array_init");

    iec61850_int32_array64_t arr;
    iec61850_int32_array64_init(&arr);

    ASSERT_EQ(iec61850_int32_array64_size(&arr), (size_t)0);
    ASSERT_TRUE(iec61850_int32_array64_empty(&arr));
    ASSERT_TRUE(!iec61850_int32_array64_full(&arr));
    ASSERT_EQ(iec61850_int32_array64_capacity(&arr), (size_t)64);

    PASS();
}

static void test_int32_array_push_pop(void)
{
    TEST("int32_array_push_pop");

    iec61850_int32_array64_t arr;
    iec61850_int32_array64_init(&arr);

    ASSERT_EQ(iec61850_int32_array64_push(&arr, 42), 0);
    ASSERT_EQ(iec61850_int32_array64_push(&arr, -7), 0);
    ASSERT_EQ(iec61850_int32_array64_push(&arr, 100), 0);

    ASSERT_EQ(iec61850_int32_array64_size(&arr), (size_t)3);
    ASSERT_EQ(*iec61850_int32_array64_get(&arr, 0), 42);
    ASSERT_EQ(*iec61850_int32_array64_get(&arr, 1), -7);
    ASSERT_EQ(*iec61850_int32_array64_get(&arr, 2), 100);

    int32_t val;
    ASSERT_EQ(iec61850_int32_array64_pop(&arr, &val), 0);
    ASSERT_EQ(val, 100);
    ASSERT_EQ(iec61850_int32_array64_size(&arr), (size_t)2);

    PASS();
}

static void test_int32_array_full_boundary(void)
{
    TEST("int32_array_full_boundary");

    iec61850_int32_array64_t arr;
    iec61850_int32_array64_init(&arr);

    /* Fill to capacity */
    for (int32_t i = 0; i < 64; i++) {
        ASSERT_EQ(iec61850_int32_array64_push(&arr, i * 10), 0);
    }
    ASSERT_TRUE(iec61850_int32_array64_full(&arr));
    ASSERT_EQ(iec61850_int32_array64_size(&arr), (size_t)64);

    /* Push when full should fail */
    ASSERT_TRUE(iec61850_int32_array64_push(&arr, 999) != 0);

    /* Values are correct */
    ASSERT_EQ(*iec61850_int32_array64_get(&arr, 0), 0);
    ASSERT_EQ(*iec61850_int32_array64_get(&arr, 63), 630);

    PASS();
}

static void test_int32_array_clear(void)
{
    TEST("int32_array_clear");

    iec61850_int32_array64_t arr;
    iec61850_int32_array64_init(&arr);

    iec61850_int32_array64_push(&arr, 1);
    iec61850_int32_array64_push(&arr, 2);
    iec61850_int32_array64_push(&arr, 3);

    iec61850_int32_array64_clear(&arr);
    ASSERT_EQ(iec61850_int32_array64_size(&arr), (size_t)0);
    ASSERT_TRUE(iec61850_int32_array64_empty(&arr));

    PASS();
}

static void test_int32_array_indexed_access(void)
{
    TEST("int32_array_indexed_access");

    iec61850_int32_array64_t arr;
    iec61850_int32_array64_init(&arr);

    iec61850_int32_array64_push(&arr, 10);
    iec61850_int32_array64_push(&arr, 20);
    iec61850_int32_array64_push(&arr, 30);

    /* Get returns pointer */
    int32_t *p = iec61850_int32_array64_get(&arr, 1);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(*p, 20);

    /* Set via pointer */
    *p = 25;
    ASSERT_EQ(*iec61850_int32_array64_get(&arr, 1), 25);

    /* Out-of-bounds returns NULL */
    ASSERT_TRUE(iec61850_int32_array64_get(&arr, 5) == NULL);

    PASS();
}

static void test_uint64_array_basic(void)
{
    TEST("uint64_array_basic");

    iec61850_uint64_array1000_t arr;
    iec61850_uint64_array1000_init(&arr);

    ASSERT_EQ(iec61850_uint64_array1000_capacity(&arr), (size_t)1000);
    ASSERT_EQ(iec61850_uint64_array1000_push(&arr, 12345678901234ULL), 0);
    ASSERT_EQ(*iec61850_uint64_array1000_get(&arr, 0), (uint64_t)12345678901234ULL);

    PASS();
}

/* ========================================================================
 * ring_buffer tests (iec61850_uint64_ring8_t)
 * ======================================================================== */

static void test_ring_buffer_init(void)
{
    TEST("ring_buffer_init");

    iec61850_uint64_ring8_t rb;
    iec61850_uint64_ring8_init(&rb);

    ASSERT_EQ(iec61850_uint64_ring8_size(&rb), (size_t)0);
    ASSERT_TRUE(iec61850_uint64_ring8_empty(&rb));
    ASSERT_TRUE(!iec61850_uint64_ring8_full(&rb));
    ASSERT_EQ(iec61850_uint64_ring8_capacity(&rb), (size_t)8);

    PASS();
}

static void test_ring_buffer_enqueue_dequeue_fifo(void)
{
    TEST("ring_buffer_enqueue_dequeue_fifo");

    iec61850_uint64_ring8_t rb;
    iec61850_uint64_ring8_init(&rb);

    iec61850_uint64_ring8_enqueue(&rb, 10);
    iec61850_uint64_ring8_enqueue(&rb, 20);
    iec61850_uint64_ring8_enqueue(&rb, 30);

    ASSERT_EQ(iec61850_uint64_ring8_size(&rb), (size_t)3);

    uint64_t val;
    ASSERT_EQ(iec61850_uint64_ring8_dequeue(&rb, &val), 0);
    ASSERT_EQ(val, (uint64_t)10);

    ASSERT_EQ(iec61850_uint64_ring8_dequeue(&rb, &val), 0);
    ASSERT_EQ(val, (uint64_t)20);

    ASSERT_EQ(iec61850_uint64_ring8_dequeue(&rb, &val), 0);
    ASSERT_EQ(val, (uint64_t)30);

    ASSERT_TRUE(iec61850_uint64_ring8_empty(&rb));

    PASS();
}

static void test_ring_buffer_overwrite_on_full(void)
{
    TEST("ring_buffer_overwrite_on_full");

    iec61850_uint64_ring8_t rb;
    iec61850_uint64_ring8_init(&rb);

    /* Fill the buffer (capacity 8) */
    for (uint64_t i = 1; i <= 8; i++) {
        iec61850_uint64_ring8_enqueue(&rb, i * 100);
    }
    ASSERT_TRUE(iec61850_uint64_ring8_full(&rb));
    ASSERT_EQ(iec61850_uint64_ring8_size(&rb), (size_t)8);

    /* Enqueue more - should overwrite oldest */
    iec61850_uint64_ring8_enqueue(&rb, 900);
    iec61850_uint64_ring8_enqueue(&rb, 1000);

    ASSERT_EQ(iec61850_uint64_ring8_size(&rb), (size_t)8);

    /* Oldest should now be 300 (100 and 200 were overwritten) */
    uint64_t val;
    ASSERT_EQ(iec61850_uint64_ring8_dequeue(&rb, &val), 0);
    ASSERT_EQ(val, (uint64_t)300);

    PASS();
}

static void test_ring_buffer_wrap_around(void)
{
    TEST("ring_buffer_wrap_around");

    iec61850_uint64_ring8_t rb;
    iec61850_uint64_ring8_init(&rb);

    /* Enqueue and dequeue to advance pointers past the boundary */
    for (uint64_t i = 0; i < 6; i++) {
        iec61850_uint64_ring8_enqueue(&rb, i);
    }
    uint64_t val;
    for (int i = 0; i < 6; i++) {
        iec61850_uint64_ring8_dequeue(&rb, &val);
    }
    ASSERT_TRUE(iec61850_uint64_ring8_empty(&rb));

    /* Now enqueue more to wrap around the internal array */
    for (uint64_t i = 100; i < 108; i++) {
        iec61850_uint64_ring8_enqueue(&rb, i);
    }
    ASSERT_TRUE(iec61850_uint64_ring8_full(&rb));

    /* Dequeue all and verify FIFO order */
    for (uint64_t i = 100; i < 108; i++) {
        ASSERT_EQ(iec61850_uint64_ring8_dequeue(&rb, &val), 0);
        ASSERT_EQ(val, i);
    }

    PASS();
}

static void test_ring_buffer_peek(void)
{
    TEST("ring_buffer_peek");

    iec61850_uint64_ring8_t rb;
    iec61850_uint64_ring8_init(&rb);

    iec61850_uint64_ring8_enqueue(&rb, 42);
    iec61850_uint64_ring8_enqueue(&rb, 99);

    const uint64_t *p = iec61850_uint64_ring8_peek(&rb);
    ASSERT_TRUE(p != NULL);
    ASSERT_EQ(*p, (uint64_t)42);

    /* Peek doesn't remove */
    ASSERT_EQ(iec61850_uint64_ring8_size(&rb), (size_t)2);

    PASS();
}

static void test_ring_buffer_indexed_access(void)
{
    TEST("ring_buffer_indexed_access");

    iec61850_uint64_ring8_t rb;
    iec61850_uint64_ring8_init(&rb);

    iec61850_uint64_ring8_enqueue(&rb, 10);
    iec61850_uint64_ring8_enqueue(&rb, 20);
    iec61850_uint64_ring8_enqueue(&rb, 30);

    /* Index 0 = oldest */
    const uint64_t *p0 = iec61850_uint64_ring8_at(&rb, 0);
    const uint64_t *p1 = iec61850_uint64_ring8_at(&rb, 1);
    const uint64_t *p2 = iec61850_uint64_ring8_at(&rb, 2);

    ASSERT_TRUE(p0 != NULL);
    ASSERT_TRUE(p1 != NULL);
    ASSERT_TRUE(p2 != NULL);
    ASSERT_EQ(*p0, (uint64_t)10);
    ASSERT_EQ(*p1, (uint64_t)20);
    ASSERT_EQ(*p2, (uint64_t)30);

    /* Out-of-bounds */
    ASSERT_TRUE(iec61850_uint64_ring8_at(&rb, 3) == NULL);

    PASS();
}

static void test_ring_buffer_clear(void)
{
    TEST("ring_buffer_clear");

    iec61850_uint64_ring8_t rb;
    iec61850_uint64_ring8_init(&rb);

    iec61850_uint64_ring8_enqueue(&rb, 1);
    iec61850_uint64_ring8_enqueue(&rb, 2);

    iec61850_uint64_ring8_clear(&rb);
    ASSERT_TRUE(iec61850_uint64_ring8_empty(&rb));
    ASSERT_EQ(iec61850_uint64_ring8_size(&rb), (size_t)0);

    PASS();
}

static void test_ring_buffer_dequeue_empty(void)
{
    TEST("ring_buffer_dequeue_empty");

    iec61850_uint64_ring8_t rb;
    iec61850_uint64_ring8_init(&rb);

    uint64_t val = 0;
    ASSERT_TRUE(iec61850_uint64_ring8_dequeue(&rb, &val) != 0);

    PASS();
}

/* ========================================================================
 * Property tests
 * ======================================================================== */

static void test_str129_property_roundtrip(void)
{
    printf("\n");

    PROPERTY_TEST("str129 assign/cstr roundtrip", 1000) {
        char input[130];
        size_t len = 1 + ((size_t)rand() % 128);
        for (size_t j = 0; j < len; j++) {
            input[j] = (char)(32 + (rand() % 95));
        }
        input[len] = '\0';

        iec61850_str129_t s;
        iec61850_str129_init(&s);
        iec61850_str129_assign(&s, input);

        /* Must roundtrip exactly for strings that fit */
        PROPERTY_ASSERT(strcmp(iec61850_str129_cstr(&s), input) == 0,
                        "assign/cstr roundtrip failed");
        PROPERTY_ASSERT(iec61850_str129_len(&s) == len,
                        "length mismatch after assign");
    }
    PROPERTY_TEST_END();

    tests_run++;
    if (_prop_failures == 0) { tests_passed++; } else { tests_failed++; }
}

static void test_int32_array_property_push_order(void)
{
    printf("\n");

    PROPERTY_TEST("int32_array push preserves order", 1000) {
        iec61850_int32_array64_t arr;
        iec61850_int32_array64_init(&arr);

        int count = 1 + (rand() % 64);
        int32_t values[64];

        for (int j = 0; j < count; j++) {
            values[j] = random_int32();
            iec61850_int32_array64_push(&arr, values[j]);
        }

        for (int j = 0; j < count; j++) {
            PROPERTY_ASSERT(*iec61850_int32_array64_get(&arr, (size_t)j) == values[j],
                            "push order not preserved");
        }
    }
    PROPERTY_TEST_END();

    tests_run++;
    if (_prop_failures == 0) { tests_passed++; } else { tests_failed++; }
}

static void test_ring_buffer_property_fifo(void)
{
    printf("\n");

    PROPERTY_TEST("ring_buffer FIFO order", 1000) {
        iec61850_uint64_ring8_t rb;
        iec61850_uint64_ring8_init(&rb);

        int count = 1 + (rand() % 8);
        uint64_t values[8];

        for (int j = 0; j < count; j++) {
            values[j] = random_uint64();
            iec61850_uint64_ring8_enqueue(&rb, values[j]);
        }

        for (int j = 0; j < count; j++) {
            uint64_t val;
            iec61850_uint64_ring8_dequeue(&rb, &val);
            PROPERTY_ASSERT(val == values[j], "FIFO order violated");
        }
    }
    PROPERTY_TEST_END();

    tests_run++;
    if (_prop_failures == 0) { tests_passed++; } else { tests_failed++; }
}

/* ========================================================================
 * Main
 * ======================================================================== */

int main(void)
{
    property_test_init();

    printf("\n=== Fixed String Tests ===\n");
    test_str129_init();
    test_str129_assign();
    test_str129_assign_null();
    test_str129_truncation();
    test_str129_compare();
    test_str129_compare_cstr();
    test_str129_clear();
    test_str129_assign_n();
    test_str32_basic();
    test_str256_basic();

    printf("\n=== Fixed Array Tests ===\n");
    test_int32_array_init();
    test_int32_array_push_pop();
    test_int32_array_full_boundary();
    test_int32_array_clear();
    test_int32_array_indexed_access();
    test_uint64_array_basic();

    printf("\n=== Ring Buffer Tests ===\n");
    test_ring_buffer_init();
    test_ring_buffer_enqueue_dequeue_fifo();
    test_ring_buffer_overwrite_on_full();
    test_ring_buffer_wrap_around();
    test_ring_buffer_peek();
    test_ring_buffer_indexed_access();
    test_ring_buffer_clear();
    test_ring_buffer_dequeue_empty();

    printf("\n=== Property Tests ===\n");
    test_str129_property_roundtrip();
    test_int32_array_property_push_order();
    test_ring_buffer_property_fifo();

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
