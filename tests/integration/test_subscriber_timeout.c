/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Integration Test: GOOSE Subscriber Timeout Detection
 *
 * Tests timeout detection, recovery, counter tracking, and
 * independent per-publisher timeout state in the GOOSE subscriber.
 *
 * Frames are built using real BER encoding via the publisher API
 * and fed directly to the subscriber's process_frame path.
 * Short timeouts (100ms) keep test execution fast.
 *
 * License: BSD-2-Clause
 */


#include "goose/goose_subscriber.h"
#include "goose/goose_publisher.h"
#include "asn1/goose_ber.h"
#include "transport/eth_frame.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

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

/* Timeout for tests: 100 ms in nanoseconds */
#define TIMEOUT_MS       100U
#define TIMEOUT_NS       (TIMEOUT_MS * 1000000ULL)

/* Helper: get current monotonic time in nanoseconds */
static uint64_t now_ns(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Helper: build a GOOSE Ethernet frame from a publisher */
static int build_goose_frame(iec61850_goose_publisher_t *pub,
                             uint8_t *frame, size_t frame_size,
                             size_t *frame_len)
{
    uint8_t apdu_buf[GOOSE_MAX_APDU_SIZE];
    size_t apdu_len = 0;

    int ret = iec61850_goose_publisher_prepare(pub, apdu_buf,
                                                sizeof(apdu_buf), &apdu_len);
    if (ret != 0) { return ret; }

    iec61850_eth_frame_config_t fcfg;
    (void)memset(&fcfg, 0, sizeof(fcfg));
    (void)memcpy(fcfg.dst_mac, pub->config.dst_mac, 6);
    (void)memcpy(fcfg.src_mac, pub->config.src_mac, 6);
    fcfg.ethertype = IEC61850_ETHERTYPE_GOOSE;
    fcfg.app_id = pub->config.app_id;
    fcfg.vlan_id = pub->config.vlan_id;
    fcfg.vlan_priority = pub->config.vlan_priority;

    return iec61850_eth_frame_build(frame, frame_size, &fcfg,
                                    apdu_buf, apdu_len, frame_len);
}

/* ========================================================================
 * Test 1: Timeout detection after timeAllowedToLive expires
 * ======================================================================== */

static void test_timeout_detection(void)
{
    TEST("timeout_detection");

    /* Setup publisher */
    iec61850_goose_config_t pcfg;
    iec61850_goose_config_init(&pcfg);
    (void)strncpy(pcfg.gocb_ref, "PUB1/LLN0$GO$gcb1",
                  GOOSE_MAX_GOCBREF_LEN - 1);
    pcfg.app_id = 0x0001;

    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, &pcfg);
    iec61850_goose_publisher_set_boolean(&pub, 0, true);

    /* Setup subscriber with 100ms timeout */
    iec61850_goose_sub_config_t scfg;
    iec61850_goose_sub_config_init(&scfg);
    scfg.timeout_ms = TIMEOUT_MS;

    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, &scfg);

    /* Send one frame */
    uint8_t frame[IEC61850_MAX_FRAME_SIZE];
    size_t frame_len = 0;
    int ret = build_goose_frame(&pub, frame, sizeof(frame), &frame_len);
    ASSERT_EQ(ret, 0);

    uint64_t t0 = now_ns();
    ret = iec61850_goose_subscriber_process_frame(&sub, frame, frame_len, t0);
    ASSERT_EQ(ret, 1);

    /* Immediately after: no timeout */
    iec61850_goose_subscriber_check_timeouts(&sub, t0 + 1000ULL);
    const iec61850_goose_pub_state_t *ps =
        iec61850_goose_subscriber_get_pub_state(&sub, pcfg.gocb_ref);
    ASSERT_TRUE(ps != NULL);
    ASSERT_TRUE(!ps->timeout_detected);

    /* After timeout_ms + margin: timeout detected */
    uint64_t t_expired = t0 + TIMEOUT_NS + 1000000ULL;
    iec61850_goose_subscriber_check_timeouts(&sub, t_expired);
    ps = iec61850_goose_subscriber_get_pub_state(&sub, pcfg.gocb_ref);
    ASSERT_TRUE(ps != NULL);
    ASSERT_TRUE(ps->timeout_detected);
    ASSERT_EQ((int)sub.total_timeouts, 1);

    iec61850_goose_publisher_destroy(&pub);
    iec61850_goose_subscriber_destroy(&sub);
    PASS();
}

/* ========================================================================
 * Test 2: Timeout recovery when frames resume
 * ======================================================================== */

static void test_timeout_recovery(void)
{
    TEST("timeout_recovery");

    iec61850_goose_config_t pcfg;
    iec61850_goose_config_init(&pcfg);
    (void)strncpy(pcfg.gocb_ref, "PUB1/LLN0$GO$gcb1",
                  GOOSE_MAX_GOCBREF_LEN - 1);
    pcfg.app_id = 0x0001;

    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, &pcfg);
    iec61850_goose_publisher_set_boolean(&pub, 0, false);

    iec61850_goose_sub_config_t scfg;
    iec61850_goose_sub_config_init(&scfg);
    scfg.timeout_ms = TIMEOUT_MS;

    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, &scfg);

    uint8_t frame[IEC61850_MAX_FRAME_SIZE];
    size_t frame_len = 0;

    /* Send initial frame */
    uint64_t t0 = now_ns();
    int ret = build_goose_frame(&pub, frame, sizeof(frame), &frame_len);
    ASSERT_EQ(ret, 0);
    ret = iec61850_goose_subscriber_process_frame(&sub, frame, frame_len, t0);
    ASSERT_EQ(ret, 1);

    /* Let it time out */
    uint64_t t_expired = t0 + TIMEOUT_NS + 1000000ULL;
    iec61850_goose_subscriber_check_timeouts(&sub, t_expired);
    const iec61850_goose_pub_state_t *ps =
        iec61850_goose_subscriber_get_pub_state(&sub, pcfg.gocb_ref);
    ASSERT_TRUE(ps != NULL);
    ASSERT_TRUE(ps->timeout_detected);

    /* Resume: send a new frame with state change */
    iec61850_goose_publisher_state_change(&pub);
    iec61850_goose_publisher_set_boolean(&pub, 0, true);
    ret = build_goose_frame(&pub, frame, sizeof(frame), &frame_len);
    ASSERT_EQ(ret, 0);

    uint64_t t_resume = t_expired + 1000000ULL;
    ret = iec61850_goose_subscriber_process_frame(&sub, frame, frame_len, t_resume);
    ASSERT_EQ(ret, 1);

    /* timeout_detected should be cleared by process() */
    ps = iec61850_goose_subscriber_get_pub_state(&sub, pcfg.gocb_ref);
    ASSERT_TRUE(ps != NULL);
    ASSERT_TRUE(!ps->timeout_detected);

    /* Confirm no new timeout if we check within the window */
    iec61850_goose_subscriber_check_timeouts(&sub, t_resume + 1000ULL);
    ps = iec61850_goose_subscriber_get_pub_state(&sub, pcfg.gocb_ref);
    ASSERT_TRUE(!ps->timeout_detected);

    iec61850_goose_publisher_destroy(&pub);
    iec61850_goose_subscriber_destroy(&sub);
    PASS();
}

/* ========================================================================
 * Test 3: Timeout counter increments correctly
 * ======================================================================== */

static void test_timeout_counter(void)
{
    TEST("timeout_counter");

    iec61850_goose_config_t pcfg;
    iec61850_goose_config_init(&pcfg);
    (void)strncpy(pcfg.gocb_ref, "PUB1/LLN0$GO$gcb1",
                  GOOSE_MAX_GOCBREF_LEN - 1);
    pcfg.app_id = 0x0001;

    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, &pcfg);
    iec61850_goose_publisher_set_boolean(&pub, 0, true);

    iec61850_goose_sub_config_t scfg;
    iec61850_goose_sub_config_init(&scfg);
    scfg.timeout_ms = TIMEOUT_MS;

    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, &scfg);

    uint8_t frame[IEC61850_MAX_FRAME_SIZE];
    size_t frame_len = 0;
    uint64_t t = now_ns();

    /* Cycle 1: send, timeout */
    int ret = build_goose_frame(&pub, frame, sizeof(frame), &frame_len);
    ASSERT_EQ(ret, 0);
    iec61850_goose_subscriber_process_frame(&sub, frame, frame_len, t);

    t += TIMEOUT_NS + 1000000ULL;
    iec61850_goose_subscriber_check_timeouts(&sub, t);
    ASSERT_EQ((int)sub.total_timeouts, 1);

    /* Repeated check should NOT increment (already flagged) */
    t += TIMEOUT_NS;
    iec61850_goose_subscriber_check_timeouts(&sub, t);
    ASSERT_EQ((int)sub.total_timeouts, 1);

    /* Cycle 2: recover, then timeout again */
    iec61850_goose_publisher_state_change(&pub);
    ret = build_goose_frame(&pub, frame, sizeof(frame), &frame_len);
    ASSERT_EQ(ret, 0);
    t += 1000000ULL;
    iec61850_goose_subscriber_process_frame(&sub, frame, frame_len, t);

    t += TIMEOUT_NS + 1000000ULL;
    iec61850_goose_subscriber_check_timeouts(&sub, t);
    ASSERT_EQ((int)sub.total_timeouts, 2);

    /* Cycle 3: recover, timeout again */
    iec61850_goose_publisher_state_change(&pub);
    ret = build_goose_frame(&pub, frame, sizeof(frame), &frame_len);
    ASSERT_EQ(ret, 0);
    t += 1000000ULL;
    iec61850_goose_subscriber_process_frame(&sub, frame, frame_len, t);

    t += TIMEOUT_NS + 1000000ULL;
    iec61850_goose_subscriber_check_timeouts(&sub, t);
    ASSERT_EQ((int)sub.total_timeouts, 3);

    iec61850_goose_publisher_destroy(&pub);
    iec61850_goose_subscriber_destroy(&sub);
    PASS();
}

/* ========================================================================
 * Test 4: Multiple publishers — independent timeout tracking
 * ======================================================================== */

static void test_multiple_publishers_timeout(void)
{
    TEST("multiple_publishers_timeout");

    /* Two publishers with different gocbRefs */
    iec61850_goose_config_t pcfg_a;
    iec61850_goose_config_init(&pcfg_a);
    (void)strncpy(pcfg_a.gocb_ref, "IED_A/LLN0$GO$gcbA",
                  GOOSE_MAX_GOCBREF_LEN - 1);
    pcfg_a.app_id = 0x0010;

    iec61850_goose_config_t pcfg_b;
    iec61850_goose_config_init(&pcfg_b);
    (void)strncpy(pcfg_b.gocb_ref, "IED_B/LLN0$GO$gcbB",
                  GOOSE_MAX_GOCBREF_LEN - 1);
    pcfg_b.app_id = 0x0020;

    iec61850_goose_publisher_t pub_a, pub_b;
    iec61850_goose_publisher_init(&pub_a, &pcfg_a);
    iec61850_goose_publisher_init(&pub_b, &pcfg_b);
    iec61850_goose_publisher_set_boolean(&pub_a, 0, true);
    iec61850_goose_publisher_set_boolean(&pub_b, 0, false);

    /* Subscriber: no gocbRef filter (accept all), 100ms timeout */
    iec61850_goose_sub_config_t scfg;
    iec61850_goose_sub_config_init(&scfg);
    scfg.timeout_ms = TIMEOUT_MS;

    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, &scfg);

    uint8_t frame[IEC61850_MAX_FRAME_SIZE];
    size_t frame_len = 0;
    uint64_t t = now_ns();
    int ret;

    /* Both publishers send at t0 */
    ret = build_goose_frame(&pub_a, frame, sizeof(frame), &frame_len);
    ASSERT_EQ(ret, 0);
    iec61850_goose_subscriber_process_frame(&sub, frame, frame_len, t);

    ret = build_goose_frame(&pub_b, frame, sizeof(frame), &frame_len);
    ASSERT_EQ(ret, 0);
    iec61850_goose_subscriber_process_frame(&sub, frame, frame_len, t);

    ASSERT_EQ((int)sub.publisher_count, 2);

    /* At t0 + 50ms: publisher A sends again, B is silent */
    uint64_t t_mid = t + 50000000ULL;
    iec61850_goose_publisher_state_change(&pub_a);
    ret = build_goose_frame(&pub_a, frame, sizeof(frame), &frame_len);
    ASSERT_EQ(ret, 0);
    iec61850_goose_subscriber_process_frame(&sub, frame, frame_len, t_mid);

    /* At t0 + 110ms: check timeouts. B should time out, A should not. */
    uint64_t t_check = t + TIMEOUT_NS + 10000000ULL;
    iec61850_goose_subscriber_check_timeouts(&sub, t_check);

    const iec61850_goose_pub_state_t *ps_a =
        iec61850_goose_subscriber_get_pub_state(&sub, pcfg_a.gocb_ref);
    const iec61850_goose_pub_state_t *ps_b =
        iec61850_goose_subscriber_get_pub_state(&sub, pcfg_b.gocb_ref);

    ASSERT_TRUE(ps_a != NULL);
    ASSERT_TRUE(ps_b != NULL);
    ASSERT_TRUE(!ps_a->timeout_detected);
    ASSERT_TRUE(ps_b->timeout_detected);
    ASSERT_EQ((int)sub.total_timeouts, 1);

    /* At t_mid + 110ms: now A also times out */
    uint64_t t_both = t_mid + TIMEOUT_NS + 10000000ULL;
    iec61850_goose_subscriber_check_timeouts(&sub, t_both);

    ps_a = iec61850_goose_subscriber_get_pub_state(&sub, pcfg_a.gocb_ref);
    ASSERT_TRUE(ps_a->timeout_detected);
    ASSERT_EQ((int)sub.total_timeouts, 2);

    /* Recover B only */
    iec61850_goose_publisher_state_change(&pub_b);
    ret = build_goose_frame(&pub_b, frame, sizeof(frame), &frame_len);
    ASSERT_EQ(ret, 0);
    iec61850_goose_subscriber_process_frame(&sub, frame, frame_len, t_both);

    ps_a = iec61850_goose_subscriber_get_pub_state(&sub, pcfg_a.gocb_ref);
    ps_b = iec61850_goose_subscriber_get_pub_state(&sub, pcfg_b.gocb_ref);
    ASSERT_TRUE(ps_a->timeout_detected);   /* A still timed out */
    ASSERT_TRUE(!ps_b->timeout_detected);  /* B recovered */

    iec61850_goose_publisher_destroy(&pub_a);
    iec61850_goose_publisher_destroy(&pub_b);
    iec61850_goose_subscriber_destroy(&sub);
    PASS();
}

/* ========================================================================
 * Main
 * ======================================================================== */

int main(void)
{
    printf("\n=== GOOSE Subscriber Timeout Integration Tests ===\n");
    test_timeout_detection();
    test_timeout_recovery();
    test_timeout_counter();
    test_multiple_publishers_timeout();

    printf("\n=== Test Summary ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
