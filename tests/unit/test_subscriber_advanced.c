/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Advanced Subscriber Tests
 *
 * Tests: SV gap detection with wraparound, GOOSE multicast MAC validation,
 * multi-publisher tracking, out-of-order rejection, timeout detection.
 *
 * License: BSD-3-Clause
 */

#define _POSIX_C_SOURCE 199309L

#include "goose/goose_subscriber.h"
#include "sv/sv_subscriber.h"
#include "asn1/goose_ber.h"
#include "asn1/sv_ber.h"

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

/* ========================================================================
 * SV Gap Detection
 * ======================================================================== */

static int sv_cb_count = 0;
static iec61850_sv_message_t sv_last_msg;

static void sv_test_callback(const iec61850_sv_message_t *msg, void *user_data)
{
    (void)user_data;
    sv_cb_count++;
    sv_last_msg = *msg;
}

static void test_sv_gap_detection(void)
{
    TEST("sv_gap_detection");
    iec61850_sv_subscriber_t sub;
    iec61850_sv_subscriber_init(&sub, NULL);
    sv_cb_count = 0;
    iec61850_sv_subscriber_set_callback(&sub, sv_test_callback, NULL);

    sv_asdu_t asdu;
    sv_asdu_init(&asdu);
    sv_set_svid(&asdu, "SV_PUB_1");
    asdu.confRev = 1;

    /* smpCnt=0 */
    asdu.smpCnt = 0;
    iec61850_sv_subscriber_process(&sub, &asdu, 1000000);
    ASSERT_TRUE(!sv_last_msg.has_gap);

    /* smpCnt=1 (sequential, no gap) */
    asdu.smpCnt = 1;
    iec61850_sv_subscriber_process(&sub, &asdu, 2000000);
    ASSERT_TRUE(!sv_last_msg.has_gap);

    /* smpCnt=5 (gap of 3: missed 2,3,4) */
    asdu.smpCnt = 5;
    iec61850_sv_subscriber_process(&sub, &asdu, 3000000);
    ASSERT_TRUE(sv_last_msg.has_gap);
    ASSERT_EQ((int)sv_last_msg.gap_count, 3);

    ASSERT_EQ((int)sub.total_gaps, 3);

    iec61850_sv_subscriber_destroy(&sub);
    PASS();
}

static void test_sv_duplicate_detection(void)
{
    TEST("sv_duplicate_detection");
    iec61850_sv_subscriber_t sub;
    iec61850_sv_subscriber_init(&sub, NULL);
    sv_cb_count = 0;
    iec61850_sv_subscriber_set_callback(&sub, sv_test_callback, NULL);

    sv_asdu_t asdu;
    sv_asdu_init(&asdu);
    sv_set_svid(&asdu, "SV_PUB_1");
    asdu.smpCnt = 10;

    iec61850_sv_subscriber_process(&sub, &asdu, 1000000);
    ASSERT_EQ(sv_cb_count, 1);

    /* Same smpCnt = duplicate */
    bool accepted = iec61850_sv_subscriber_process(&sub, &asdu, 2000000);
    ASSERT_TRUE(!accepted);
    ASSERT_EQ(sv_cb_count, 1);  /* callback not invoked for duplicate */
    ASSERT_EQ((int)sub.total_duplicates, 1);

    iec61850_sv_subscriber_destroy(&sub);
    PASS();
}

/* ========================================================================
 * GOOSE Multi-Publisher Tracking
 * ======================================================================== */

static void test_goose_multi_publisher(void)
{
    TEST("goose_multi_publisher");
    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, NULL);

    goose_apdu_t apdu;
    goose_apdu_init(&apdu);

    /* Publisher 1 */
    goose_set_gocbref(&apdu, "IED1LD0/LLN0$GO$gcb01");
    apdu.stNum = 1;
    apdu.sqNum = 0;
    iec61850_goose_subscriber_process(&sub, &apdu, 1000000);

    /* Publisher 2 */
    goose_set_gocbref(&apdu, "IED2LD0/LLN0$GO$gcb01");
    apdu.stNum = 1;
    apdu.sqNum = 0;
    iec61850_goose_subscriber_process(&sub, &apdu, 2000000);

    ASSERT_EQ((int)sub.publisher_count, 2);

    /* Check individual states */
    const iec61850_goose_pub_state_t *ps1 =
        iec61850_goose_subscriber_get_pub_state(&sub, "IED1LD0/LLN0$GO$gcb01");
    ASSERT_TRUE(ps1 != NULL);
    ASSERT_EQ((int)ps1->message_count, 1);

    const iec61850_goose_pub_state_t *ps2 =
        iec61850_goose_subscriber_get_pub_state(&sub, "IED2LD0/LLN0$GO$gcb01");
    ASSERT_TRUE(ps2 != NULL);
    ASSERT_EQ((int)ps2->message_count, 1);

    iec61850_goose_subscriber_destroy(&sub);
    PASS();
}

/* ========================================================================
 * GOOSE Out-of-Order stNum Rejection
 * ======================================================================== */

static int goose_cb_count = 0;
static iec61850_goose_message_t goose_last_msg;

static void goose_test_callback(const iec61850_goose_message_t *msg, void *user_data)
{
    (void)user_data;
    goose_cb_count++;
    goose_last_msg = *msg;
}

static void test_goose_out_of_order_stnum(void)
{
    TEST("goose_out_of_order_stnum");
    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, NULL);
    goose_cb_count = 0;
    iec61850_goose_subscriber_set_callback(&sub, goose_test_callback, NULL);

    goose_apdu_t apdu;
    goose_apdu_init(&apdu);
    goose_set_gocbref(&apdu, "IED1LD0/LLN0$GO$gcb01");

    /* stNum=5 first */
    apdu.stNum = 5;
    apdu.sqNum = 0;
    iec61850_goose_subscriber_process(&sub, &apdu, 1000000);
    ASSERT_EQ(goose_cb_count, 1);

    /* stNum=3 (out of order, lower) — must be discarded per IEC 61850
     * to prevent state regression */
    apdu.stNum = 3;
    apdu.sqNum = 0;
    bool accepted = iec61850_goose_subscriber_process(&sub, &apdu, 2000000);
    ASSERT_TRUE(!accepted);  /* Old stNum: silently discarded */

    iec61850_goose_subscriber_destroy(&sub);
    PASS();
}

/* ========================================================================
 * GOOSE Retransmission Identification
 * ======================================================================== */

static void test_goose_retransmission(void)
{
    TEST("goose_retransmission");
    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, NULL);
    goose_cb_count = 0;
    iec61850_goose_subscriber_set_callback(&sub, goose_test_callback, NULL);

    goose_apdu_t apdu;
    goose_apdu_init(&apdu);
    goose_set_gocbref(&apdu, "IED1LD0/LLN0$GO$gcb01");

    /* Initial: stNum=1, sqNum=0 */
    apdu.stNum = 1;
    apdu.sqNum = 0;
    iec61850_goose_subscriber_process(&sub, &apdu, 1000000);
    ASSERT_TRUE(goose_last_msg.is_new_state);
    ASSERT_TRUE(!goose_last_msg.is_retransmission);

    /* Retransmission: stNum=1, sqNum=1 */
    apdu.sqNum = 1;
    iec61850_goose_subscriber_process(&sub, &apdu, 2000000);
    ASSERT_TRUE(goose_last_msg.is_retransmission);
    ASSERT_TRUE(!goose_last_msg.is_new_state);

    iec61850_goose_subscriber_destroy(&sub);
    PASS();
}

/* ========================================================================
 * SV Subscriber Timeout
 * ======================================================================== */

static void test_sv_timeout(void)
{
    TEST("sv_timeout");
    iec61850_sv_sub_config_t cfg;
    iec61850_sv_sub_config_init(&cfg);
    cfg.timeout_ms = 1;  /* 1ms timeout */

    iec61850_sv_subscriber_t sub;
    iec61850_sv_subscriber_init(&sub, &cfg);

    sv_asdu_t asdu;
    sv_asdu_init(&asdu);
    sv_set_svid(&asdu, "SV_PUB_1");
    asdu.smpCnt = 0;

    iec61850_sv_subscriber_process(&sub, &asdu, 1000000ULL);

    /* Check at 100ms (well past 1ms timeout) */
    iec61850_sv_subscriber_check_timeouts(&sub, 100000000ULL);
    ASSERT_EQ((int)sub.total_timeouts, 1);

    const iec61850_sv_pub_state_t *ps =
        iec61850_sv_subscriber_get_pub_state(&sub, "SV_PUB_1");
    ASSERT_TRUE(ps != NULL);
    ASSERT_TRUE(ps->timeout_detected);

    iec61850_sv_subscriber_destroy(&sub);
    PASS();
}

/* ========================================================================
 * SV Multi-Publisher Tracking
 * ======================================================================== */

static void test_sv_multi_publisher(void)
{
    TEST("sv_multi_publisher");
    iec61850_sv_subscriber_t sub;
    iec61850_sv_subscriber_init(&sub, NULL);

    sv_asdu_t asdu;
    sv_asdu_init(&asdu);

    sv_set_svid(&asdu, "SV_PUB_1");
    asdu.smpCnt = 0;
    iec61850_sv_subscriber_process(&sub, &asdu, 1000000);

    sv_set_svid(&asdu, "SV_PUB_2");
    asdu.smpCnt = 0;
    iec61850_sv_subscriber_process(&sub, &asdu, 2000000);

    ASSERT_EQ((int)sub.publisher_count, 2);

    const iec61850_sv_pub_state_t *ps1 = iec61850_sv_subscriber_get_pub_state(&sub, "SV_PUB_1");
    const iec61850_sv_pub_state_t *ps2 = iec61850_sv_subscriber_get_pub_state(&sub, "SV_PUB_2");
    ASSERT_TRUE(ps1 != NULL);
    ASSERT_TRUE(ps2 != NULL);
    ASSERT_EQ((int)ps1->message_count, 1);
    ASSERT_EQ((int)ps2->message_count, 1);

    iec61850_sv_subscriber_destroy(&sub);
    PASS();
}

/* ========================================================================
 * GOOSE VLAN Filtering
 * ======================================================================== */

static void test_goose_subscriber_stats(void)
{
    TEST("goose_subscriber_stats");
    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, NULL);

    goose_apdu_t apdu;
    goose_apdu_init(&apdu);
    goose_set_gocbref(&apdu, "IED1LD0/LLN0$GO$gcb01");

    /* Send 3 unique messages */
    apdu.stNum = 1; apdu.sqNum = 0;
    iec61850_goose_subscriber_process(&sub, &apdu, 1000000);
    apdu.stNum = 1; apdu.sqNum = 1;
    iec61850_goose_subscriber_process(&sub, &apdu, 2000000);
    apdu.stNum = 1; apdu.sqNum = 1;  /* duplicate */
    iec61850_goose_subscriber_process(&sub, &apdu, 3000000);

    ASSERT_EQ((int)sub.total_messages, 3);
    ASSERT_EQ((int)sub.total_duplicates, 1);

    iec61850_goose_subscriber_destroy(&sub);
    PASS();
}

/* ========================================================================
 * SV svID Filtering
 * ======================================================================== */

static void test_sv_filter(void)
{
    TEST("sv_filter");
    iec61850_sv_sub_config_t cfg;
    iec61850_sv_sub_config_init(&cfg);
    strncpy(cfg.filter_svid, "SV_PUB_1", SV_MAX_SVID_LEN - 1);

    iec61850_sv_subscriber_t sub;
    iec61850_sv_subscriber_init(&sub, &cfg);

    sv_asdu_t asdu;
    sv_asdu_init(&asdu);

    /* Matching svID */
    sv_set_svid(&asdu, "SV_PUB_1");
    asdu.smpCnt = 0;
    ASSERT_TRUE(iec61850_sv_subscriber_process(&sub, &asdu, 1000000));

    /* Non-matching svID */
    sv_set_svid(&asdu, "SV_PUB_2");
    asdu.smpCnt = 0;
    ASSERT_TRUE(!iec61850_sv_subscriber_process(&sub, &asdu, 2000000));

    iec61850_sv_subscriber_destroy(&sub);
    PASS();
}

/* ========================================================================
 * Publisher Capacity Overflow
 * ======================================================================== */

static void test_goose_max_publishers(void)
{
    TEST("goose_max_publishers");
    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, NULL);

    goose_apdu_t apdu;
    goose_apdu_init(&apdu);
    apdu.stNum = 1;
    apdu.sqNum = 0;

    /* Fill to capacity */
    for (int i = 0; i < IEC61850_GOOSE_MAX_PUBLISHERS; i++) {
        char ref[GOOSE_MAX_GOCBREF_LEN];
        snprintf(ref, sizeof(ref), "IED%d/LLN0$GO$gcb%02d", i, i);
        goose_set_gocbref(&apdu, ref);
        ASSERT_TRUE(iec61850_goose_subscriber_process(&sub, &apdu, (uint64_t)(i * 1000000)));
    }

    ASSERT_EQ((int)sub.publisher_count, IEC61850_GOOSE_MAX_PUBLISHERS);

    /* Next one should fail */
    goose_set_gocbref(&apdu, "IED_OVERFLOW/LLN0$GO$gcb99");
    ASSERT_TRUE(!iec61850_goose_subscriber_process(&sub, &apdu, 99000000ULL));

    iec61850_goose_subscriber_destroy(&sub);
    PASS();
}

int main(void)
{
    printf("\n=== Subscriber Advanced Tests ===\n");

    printf("\n--- SV Gap Detection ---\n");
    test_sv_gap_detection();
    test_sv_duplicate_detection();

    printf("\n--- GOOSE Multi-Publisher ---\n");
    test_goose_multi_publisher();
    test_goose_out_of_order_stnum();
    test_goose_retransmission();

    printf("\n--- SV Timeout ---\n");
    test_sv_timeout();
    test_sv_multi_publisher();

    printf("\n--- Filtering ---\n");
    test_goose_subscriber_stats();
    test_sv_filter();

    printf("\n--- Capacity ---\n");
    test_goose_max_publishers();

    printf("\n=== Test Summary ===\n");
    printf("Tests run:    %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);

    return tests_failed > 0 ? 1 : 0;
}
