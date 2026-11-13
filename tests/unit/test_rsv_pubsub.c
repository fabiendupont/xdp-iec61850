/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for IEC TR 61850-90-5 R-SV Publisher/Subscriber
 *
 * WP-4d (r-security-replay): lifecycle and API error paths, plain
 * SPDU build/decode roundtrip (smpCnt progression + wraparound),
 * L2-style sample state machine (duplicate + gap detection), per-APPID
 * SPDU-number replay rejection, 90-5 time-window validation,
 * frame-level security roundtrip (build → sign → verify, plus a
 * tamper matrix over every signed region), plain-mode socket loopback
 * over 127.0.0.1 (UDP backend, unprivileged), and a secure-mode raw
 * socket loopback that runs only when AF_PACKET is permitted (root).
 *
 * Security-gated tests compile only with -Denable_security=true; the
 * plain build verifies that enable_security() returns -ENOTSUP.
 */

#include "asn1/r_profile.h"
#include "sv/rsv_publisher.h"
#include "sv/rsv_subscriber.h"
#include "transport/ip_udp_frame.h"
#include "transport/packet_io.h"

#ifdef IEC61850_SECURITY_ENABLED
#include "security/hmac_verify.h"
#endif

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;

#define TEST(name) do { tests_run++; printf("  [TEST] %s ... ", name); } while (0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while (0)
#define SKIP(msg) do { tests_passed++; printf("SKIP (%s)\n", msg); return; } while (0)
#define FAIL(msg) do { tests_failed++; printf("FAIL: %s\n", msg); return; } while (0)
#define ASSERT_TRUE(cond) do { if (!(cond)) { FAIL(#cond); } } while (0)
#define ASSERT_EQ(a, b) do { if ((a) != (b)) { \
    printf("FAIL: %s == %s (%d != %d)\n", #a, #b, (int)(a), (int)(b)); \
    tests_failed++; return; } } while (0)

/* Fixed high port, unique within the test suite. */
#define PORT_RSV 47931U

#define TEST_SVID "RSV_PUB_1"

/* ------------------------------------------------------------------ */
/* Callback capture                                                    */
/* ------------------------------------------------------------------ */

static iec61850_rsv_message_t cb_last_msg;
static int cb_count;

static void rsv_test_cb(const iec61850_rsv_message_t *msg, void *user_data)
{
    (void)user_data;
    cb_last_msg = *msg;
    cb_count++;
}

static void cb_reset(void)
{
    (void)memset(&cb_last_msg, 0, sizeof(cb_last_msg));
    cb_count = 0;
}

/* ------------------------------------------------------------------ */
/* SPDU crafting helper (direct codec access)                          */
/* ------------------------------------------------------------------ */

static int craft_spdu(uint8_t *buf, size_t cap, uint16_t appid,
                      uint32_t spdu_num, uint16_t smp_cnt,
                      const iec61850_r_security_t *sec)
{
    sv_apdu_t a;
    sv_quality_t q;

    sv_apdu_init(&a);
    (void)sv_set_svid(&a.asdu[0], TEST_SVID);
    (void)sv_set_datset(&a.asdu[0], "IED1LD0/LLN0$DS_MU01");
    a.asdu[0].smpCnt = smp_cnt;
    a.asdu[0].confRev = 2U;
    a.asdu[0].smpSynch = SV_SMPSYNCH_GLOBAL;
    (void)memset(&q, 0, sizeof(q));
    (void)sv_add_sample(&a.asdu[0], 12345, q);
    (void)sv_add_sample(&a.asdu[0], -678, q);

    return iec61850_rsv_encode(&a, appid, spdu_num, sec, buf, cap);
}

static uint64_t test_now_ns(void)
{
    struct timespec ts;

    (void)clock_gettime(CLOCK_REALTIME, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

/* ------------------------------------------------------------------ */
/* Publisher: config, lifecycle, sample setters                        */
/* ------------------------------------------------------------------ */

static void test_config_defaults(void)
{
    iec61850_rsv_pub_config_t cfg;

    TEST("rsv_config_defaults");
    iec61850_rsv_pub_config_init(&cfg);
    ASSERT_EQ(cfg.appid, 0x4000U);
    ASSERT_EQ(cfg.dst_port, 103U);
    ASSERT_EQ(cfg.src_port, 103U);
    ASSERT_TRUE(strcmp(cfg.dst_ip, "127.0.0.1") == 0);
    ASSERT_EQ(cfg.conf_rev, 1U);
    ASSERT_EQ(cfg.smp_rate, 80U);
    ASSERT_EQ(cfg.smp_synch, 1U);
    ASSERT_EQ(cfg.num_channels, 4U);
    iec61850_rsv_pub_config_init(NULL);
    PASS();
}

static void test_publisher_lifecycle(void)
{
    iec61850_rsv_publisher_t pub;
    iec61850_rsv_pub_config_t cfg;

    TEST("rsv_publisher_lifecycle");
    iec61850_rsv_pub_config_init(&cfg);
    cfg.appid = 0x4444U;

    iec61850_rsv_publisher_init(&pub, &cfg);
    /* Retransmission defaults OFF for R-SV. */
    ASSERT_TRUE(!pub.has_retransmit);
    ASSERT_EQ(pub.sample_count, 4U);
    ASSERT_EQ(iec61850_rsv_publisher_get_smp_cnt(&pub), 0U);
    ASSERT_EQ(iec61850_rsv_publisher_get_spdu_number(&pub), 0U);

    iec61850_rsv_publisher_enable_retransmit(&pub, NULL);
    ASSERT_TRUE(pub.has_retransmit);
    iec61850_rsv_publisher_disable_retransmit(&pub);
    ASSERT_TRUE(!pub.has_retransmit);

    iec61850_rsv_publisher_set_sample(&pub, 9, 777);
    ASSERT_EQ(pub.sample_count, 10U);
    iec61850_rsv_publisher_reset_counter(&pub);
    ASSERT_EQ(iec61850_rsv_publisher_get_smp_cnt(&pub), 0U);

    iec61850_rsv_publisher_set_io(&pub, NULL);
    iec61850_rsv_publisher_destroy(&pub);

    /* NULL safety. */
    iec61850_rsv_publisher_init(NULL, &cfg);
    iec61850_rsv_publisher_init(&pub, NULL);
    ASSERT_EQ(pub.config.appid, 0x4000U);
    iec61850_rsv_publisher_reset_counter(NULL);
    iec61850_rsv_publisher_destroy(NULL);
    ASSERT_EQ(iec61850_rsv_publisher_get_smp_cnt(NULL), 0U);
    ASSERT_EQ(iec61850_rsv_publisher_get_spdu_number(NULL), 0U);
    PASS();
}

static void test_sample_setters(void)
{
    iec61850_rsv_publisher_t pub;
    int32_t vals[4] = { 100, -200, 300, -400 };
    sv_quality_t q;

    TEST("rsv_sample_setters");
    iec61850_rsv_publisher_init(&pub, NULL);

    ASSERT_EQ(iec61850_rsv_publisher_set_sample(&pub, 0, 1111), 0);
    (void)memset(&q, 0, sizeof(q));
    q.test = 1U;
    ASSERT_EQ(iec61850_rsv_publisher_set_quality(&pub, 0, q), 0);
    ASSERT_EQ(iec61850_rsv_publisher_set_samples(&pub, vals, 4U), 0);
    ASSERT_EQ(pub.sample_count, 4U);
    ASSERT_EQ(pub.samples[3], -400);
    ASSERT_EQ(pub.quality[0].test, q.test);

    /* Error paths. */
    ASSERT_EQ(iec61850_rsv_publisher_set_sample(NULL, 0, 1), -EINVAL);
    ASSERT_EQ(iec61850_rsv_publisher_set_sample(&pub,
                                                (size_t)SV_MAX_SAMPLES, 1),
              -EINVAL);
    ASSERT_EQ(iec61850_rsv_publisher_set_quality(&pub,
                                                 (size_t)SV_MAX_SAMPLES, q),
              -EINVAL);
    ASSERT_EQ(iec61850_rsv_publisher_set_samples(&pub, NULL, 1U), -EINVAL);
    ASSERT_EQ(iec61850_rsv_publisher_set_samples(
                  &pub, vals, (size_t)SV_MAX_SAMPLES + 1U), -EINVAL);
    PASS();
}

/* ------------------------------------------------------------------ */
/* Publisher: plain SPDU build roundtrip                               */
/* ------------------------------------------------------------------ */

static void test_build_spdu_plain(void)
{
    iec61850_rsv_publisher_t pub;
    static uint8_t spdu[IEC61850_RSV_MAX_SPDU_LEN];
    sv_apdu_t apdu;
    iec61850_r_header_t hdr;
    size_t len = 0U;
    int ret;

    TEST("rsv_build_spdu_plain");
    iec61850_rsv_publisher_init(&pub, NULL);
    ASSERT_EQ(iec61850_rsv_publisher_set_sample(&pub, 0, 32510), 0);

    ASSERT_EQ(iec61850_rsv_publisher_build_spdu(&pub, spdu,
                                                sizeof(spdu), &len), 0);
    ASSERT_TRUE(len > 24U);

    ret = iec61850_rsv_decode(spdu, len, &apdu, &hdr);
    ASSERT_TRUE(ret > 0);
    ASSERT_EQ(hdr.appid, 0x4000U);
    ASSERT_EQ(hdr.spdu_number, 0U);
    ASSERT_TRUE(!hdr.security.present);
    ASSERT_EQ((uint32_t)apdu.noASDU, 1U);
    ASSERT_EQ((uint32_t)apdu.asdu[0].smpCnt, 0U);
    ASSERT_TRUE(strcmp(apdu.asdu[0].svID, TEST_SVID) == 0);
    ASSERT_EQ((int)apdu.asdu[0].samples[0].value, 32510);

    /* Counters consumed by the build. */
    ASSERT_EQ(iec61850_rsv_publisher_get_smp_cnt(&pub), 1U);
    ASSERT_EQ(iec61850_rsv_publisher_get_spdu_number(&pub), 1U);

    /* Second build: smpCnt and spdu_number advance. */
    ASSERT_EQ(iec61850_rsv_publisher_build_spdu(&pub, spdu,
                                                sizeof(spdu), &len), 0);
    ret = iec61850_rsv_decode(spdu, len, &apdu, &hdr);
    ASSERT_TRUE(ret > 0);
    ASSERT_EQ(hdr.spdu_number, 1U);
    ASSERT_EQ((uint32_t)apdu.asdu[0].smpCnt, 1U);

    /* Small publisher buffer for the smpCnt wraparound: shrink the
     * wrap period by configuring smp_rate (wrap = rate * 50). */
    {
        iec61850_rsv_pub_config_t cfg;

        iec61850_rsv_pub_config_init(&cfg);
        cfg.smp_rate = 1U; /* wrap at 50 */
        iec61850_rsv_publisher_init(&pub, &cfg);
        pub.smp_cnt = 48U;
        for (int i = 0; i < 3; i++) {
            ASSERT_EQ(iec61850_rsv_publisher_build_spdu(&pub, spdu,
                                                        sizeof(spdu),
                                                        &len), 0);
        }
        /* 48 → 49 → 0 (wrap) → 1 */
        ASSERT_EQ(iec61850_rsv_publisher_get_smp_cnt(&pub), 1U);
    }

    /* Buffer too small / argument errors. */
    ASSERT_EQ(iec61850_rsv_publisher_build_spdu(&pub, spdu, 100U, &len),
              -ENOSPC);
    ASSERT_EQ(iec61850_rsv_publisher_build_spdu(NULL, spdu,
                                                sizeof(spdu), &len),
              -EINVAL);
    ASSERT_EQ(iec61850_rsv_publisher_build_spdu(&pub, NULL,
                                                sizeof(spdu), &len),
              -EINVAL);
    ASSERT_EQ(iec61850_rsv_publisher_build_spdu(&pub, spdu,
                                                sizeof(spdu), NULL),
              -EINVAL);
    ASSERT_EQ(iec61850_rsv_publisher_publish(&pub), -EINVAL);
    ASSERT_EQ(iec61850_rsv_publisher_publish(NULL), -EINVAL);
    PASS();
}

/* ------------------------------------------------------------------ */
/* Subscriber: L2-style sample state machine (crafted SPDUs)           */
/* ------------------------------------------------------------------ */

static void test_subscriber_state_machine(void)
{
    iec61850_rsv_subscriber_t sub;
    static uint8_t spdu[512];
    int len;

    TEST("rsv_subscriber_state_machine");
    iec61850_rsv_subscriber_init(&sub, NULL);
    iec61850_rsv_subscriber_set_callback(&sub, rsv_test_cb, NULL);
    cb_reset();

    /* First sample. */
    len = craft_spdu(spdu, sizeof(spdu), 0x4000U, 10U, 0U, NULL);
    ASSERT_TRUE(len > 0);
    ASSERT_EQ(iec61850_rsv_subscriber_process_spdu(&sub, spdu,
                                                   (size_t)len,
                                                   test_now_ns()), 1);
    ASSERT_EQ(cb_count, 1);
    ASSERT_TRUE(cb_last_msg.is_new_sample);

    /* Next sample. */
    len = craft_spdu(spdu, sizeof(spdu), 0x4000U, 11U, 1U, NULL);
    ASSERT_TRUE(len > 0);
    ASSERT_EQ(iec61850_rsv_subscriber_process_spdu(&sub, spdu,
                                                   (size_t)len,
                                                   test_now_ns()), 1);
    ASSERT_EQ(cb_count, 2);
    ASSERT_TRUE(cb_last_msg.is_new_sample);
    ASSERT_TRUE(!cb_last_msg.has_gap);

    /* Skipped samples: gap reported. */
    len = craft_spdu(spdu, sizeof(spdu), 0x4000U, 12U, 5U, NULL);
    ASSERT_TRUE(len > 0);
    ASSERT_EQ(iec61850_rsv_subscriber_process_spdu(&sub, spdu,
                                                   (size_t)len,
                                                   test_now_ns()), 1);
    ASSERT_EQ(cb_count, 3);
    ASSERT_TRUE(cb_last_msg.has_gap);
    ASSERT_EQ(cb_last_msg.gap_count, 3U);

    /* Same smpCnt: duplicate, dropped. */
    len = craft_spdu(spdu, sizeof(spdu), 0x4000U, 13U, 5U, NULL);
    ASSERT_TRUE(len > 0);
    ASSERT_EQ(iec61850_rsv_subscriber_process_spdu(&sub, spdu,
                                                   (size_t)len,
                                                   test_now_ns()), 0);
    ASSERT_EQ(cb_count, 3);
    ASSERT_EQ(sub.total_duplicates, 1U);

    /* Wraparound: 3999 → 0 is a normal next sample (default wrap
     * 4000 = 80 * 50) — exercised on a fresh subscriber so the
     * 5 → 3999 jump does not pollute the gap statistics. */
    {
        iec61850_rsv_subscriber_t sub2;

        iec61850_rsv_subscriber_init(&sub2, NULL);
        iec61850_rsv_subscriber_set_callback(&sub2, rsv_test_cb, NULL);
        len = craft_spdu(spdu, sizeof(spdu), 0x4000U, 20U, 3999U, NULL);
        ASSERT_TRUE(len > 0);
        ASSERT_EQ(iec61850_rsv_subscriber_process_spdu(&sub2, spdu,
                                                       (size_t)len,
                                                       test_now_ns()), 1);
        ASSERT_TRUE(!cb_last_msg.has_gap);
        len = craft_spdu(spdu, sizeof(spdu), 0x4000U, 21U, 0U, NULL);
        ASSERT_TRUE(len > 0);
        ASSERT_EQ(iec61850_rsv_subscriber_process_spdu(&sub2, spdu,
                                                       (size_t)len,
                                                       test_now_ns()), 1);
        ASSERT_TRUE(!cb_last_msg.has_gap);
        ASSERT_EQ(sub2.total_gaps, 0U);
        iec61850_rsv_subscriber_destroy(&sub2);
    }

    ASSERT_EQ(sub.total_gaps, 3U);
    {
        const iec61850_rsv_pub_state_t *ps =
            iec61850_rsv_subscriber_get_pub_state(&sub, TEST_SVID);
        ASSERT_TRUE(ps != NULL);
        ASSERT_EQ((uint32_t)ps->message_count, 4U);
        ASSERT_EQ((uint32_t)ps->gap_count, 3U);
    }
    ASSERT_TRUE(iec61850_rsv_subscriber_get_pub_state(&sub, "no/such") ==
                NULL);
    ASSERT_TRUE(iec61850_rsv_subscriber_get_pub_state(NULL, "x") == NULL);
    ASSERT_TRUE(iec61850_rsv_subscriber_get_pub_state(&sub, NULL) == NULL);
    PASS();
}

static void test_spdu_replay_rejection(void)
{
    iec61850_rsv_subscriber_t sub;
    static uint8_t spdu[512];
    int len;

    TEST("rsv_spdu_replay_rejection");
    iec61850_rsv_subscriber_init(&sub, NULL);
    iec61850_rsv_subscriber_set_callback(&sub, rsv_test_cb, NULL);
    cb_reset();

    len = craft_spdu(spdu, sizeof(spdu), 0x4001U, 100U, 0U, NULL);
    ASSERT_TRUE(len > 0);
    ASSERT_EQ(iec61850_rsv_subscriber_process_spdu(&sub, spdu,
                                                   (size_t)len, 1U), 1);

    /* Replayed (same SPDU number, new smpCnt): dropped. */
    ASSERT_EQ(iec61850_rsv_subscriber_process_spdu(&sub, spdu,
                                                   (size_t)len, 2U), 0);
    /* Out-of-order (lower number): dropped. */
    len = craft_spdu(spdu, sizeof(spdu), 0x4001U, 99U, 1U, NULL);
    ASSERT_TRUE(len > 0);
    ASSERT_EQ(iec61850_rsv_subscriber_process_spdu(&sub, spdu,
                                                   (size_t)len, 3U), 0);
    /* Higher number: accepted. */
    len = craft_spdu(spdu, sizeof(spdu), 0x4001U, 101U, 1U, NULL);
    ASSERT_TRUE(len > 0);
    ASSERT_EQ(iec61850_rsv_subscriber_process_spdu(&sub, spdu,
                                                   (size_t)len, 4U), 1);

    ASSERT_EQ(sub.total_replays, 2U);
    ASSERT_EQ(cb_count, 2);
    {
        const iec61850_rsv_appid_state_t *as =
            iec61850_rsv_subscriber_get_appid_state(&sub, 0x4001U);
        ASSERT_TRUE(as != NULL);
        ASSERT_EQ((uint32_t)as->last_spdu_number, 101U);
        ASSERT_EQ((uint64_t)as->replay_drops, 2U);
    }
    ASSERT_TRUE(iec61850_rsv_subscriber_get_appid_state(&sub, 0x9999U) ==
                NULL);
    PASS();
}

static void test_time_window(void)
{
    iec61850_rsv_subscriber_t sub;
    iec61850_r_security_t sec;
    static uint8_t spdu[512];
    int len;

    TEST("rsv_time_window");
    iec61850_rsv_subscriber_init(&sub, NULL);
    iec61850_rsv_subscriber_set_callback(&sub, rsv_test_cb, NULL);
    cb_reset();

    (void)memset(&sec, 0, sizeof(sec));
    sec.present = true;
    sec.signature_len = 0U;

    sec.time_of_current_key = 1000000U;
    len = craft_spdu(spdu, sizeof(spdu), 0x4002U, 500U, 0U, &sec);
    ASSERT_TRUE(len > 0);
    ASSERT_EQ(iec61850_rsv_subscriber_process_spdu(&sub, spdu,
                                                   (size_t)len, 1U), 1);

    /* Within the window: accepted. */
    sec.time_of_current_key = 1000000U + 5000U;
    len = craft_spdu(spdu, sizeof(spdu), 0x4002U, 501U, 1U, &sec);
    ASSERT_TRUE(len > 0);
    ASSERT_EQ(iec61850_rsv_subscriber_process_spdu(&sub, spdu,
                                                   (size_t)len, 2U), 1);

    /* Far outside the window: rejected. */
    sec.time_of_current_key = 1000000U + 43200001U;
    len = craft_spdu(spdu, sizeof(spdu), 0x4002U, 502U, 2U, &sec);
    ASSERT_TRUE(len > 0);
    ASSERT_EQ(iec61850_rsv_subscriber_process_spdu(&sub, spdu,
                                                   (size_t)len, 3U), 0);
    ASSERT_EQ(sub.total_security_failures, 1U);
    ASSERT_EQ(cb_count, 2);
    PASS();
}

static void test_subscriber_filters_and_timeouts(void)
{
    iec61850_rsv_subscriber_t sub;
    iec61850_rsv_sub_config_t cfg;
    static uint8_t spdu[512];
    int len;

    TEST("rsv_subscriber_filters_and_timeouts");
    iec61850_rsv_sub_config_init(&cfg);
    cfg.filter_appid = 0x4003U;
    iec61850_rsv_subscriber_init(&sub, &cfg);
    iec61850_rsv_subscriber_set_callback(&sub, rsv_test_cb, NULL);
    cb_reset();

    /* APPID filter. */
    len = craft_spdu(spdu, sizeof(spdu), 0x4009U, 1U, 0U, NULL);
    ASSERT_TRUE(len > 0);
    ASSERT_EQ(iec61850_rsv_subscriber_process_spdu(&sub, spdu,
                                                   (size_t)len,
                                                   test_now_ns()), 0);
    len = craft_spdu(spdu, sizeof(spdu), 0x4003U, 1U, 0U, NULL);
    ASSERT_TRUE(len > 0);
    ASSERT_EQ(iec61850_rsv_subscriber_process_spdu(&sub, spdu,
                                                   (size_t)len,
                                                   test_now_ns()), 1);

    /* svID filter. */
    {
        iec61850_rsv_subscriber_t sub2;
        iec61850_rsv_sub_config_t cfg2;

        iec61850_rsv_sub_config_init(&cfg2);
        (void)strncpy(cfg2.filter_svid, "OTHER_MU",
                      sizeof(cfg2.filter_svid) - 1U);
        iec61850_rsv_subscriber_init(&sub2, &cfg2);
        len = craft_spdu(spdu, sizeof(spdu), 0x4004U, 1U, 0U, NULL);
        ASSERT_TRUE(len > 0);
        ASSERT_EQ(iec61850_rsv_subscriber_process_spdu(&sub2, spdu,
                                                       (size_t)len,
                                                       test_now_ns()), 0);
    }

    /* Timeout tracking. */
    {
        uint64_t now = test_now_ns();

        iec61850_rsv_subscriber_check_timeouts(&sub, now + 1U);
        {
            const iec61850_rsv_pub_state_t *ps =
                iec61850_rsv_subscriber_get_pub_state(&sub, TEST_SVID);
            ASSERT_TRUE(ps != NULL);
            ASSERT_TRUE(!ps->timeout_detected);
        }
        iec61850_rsv_subscriber_check_timeouts(
            &sub, now + (uint64_t)sub.config.timeout_ms * 1000000ULL + 2U);
        {
            const iec61850_rsv_pub_state_t *ps =
                iec61850_rsv_subscriber_get_pub_state(&sub, TEST_SVID);
            ASSERT_TRUE(ps != NULL);
            ASSERT_TRUE(ps->timeout_detected);
        }
        ASSERT_EQ(sub.total_timeouts, 1U);
    }

    iec61850_rsv_subscriber_check_timeouts(NULL, 0U);
    PASS();
}

static void test_subscriber_error_paths(void)
{
    iec61850_rsv_subscriber_t sub;
    static uint8_t spdu[512];
    uint8_t garbage[32];
    int len;

    TEST("rsv_subscriber_error_paths");
    iec61850_rsv_subscriber_init(&sub, NULL);
    iec61850_rsv_subscriber_set_callback(&sub, NULL, NULL);
    iec61850_rsv_subscriber_destroy(NULL);

    ASSERT_EQ(iec61850_rsv_subscriber_process_spdu(NULL, spdu, 4U, 0U), 0);
    ASSERT_EQ(iec61850_rsv_subscriber_process_spdu(&sub, NULL, 4U, 0U), 0);
    ASSERT_EQ(iec61850_rsv_subscriber_process_spdu(&sub, spdu, 0U, 0U), 0);
    ASSERT_EQ(iec61850_rsv_subscriber_process_frame(NULL, spdu, 4U, 0U), 0);
    ASSERT_EQ(iec61850_rsv_subscriber_poll(NULL, NULL), -EINVAL);

    (void)memset(garbage, 0xFFU, sizeof(garbage));
    ASSERT_EQ(iec61850_rsv_subscriber_process_spdu(&sub, garbage,
                                                   sizeof(garbage), 0U), 0);
    len = craft_spdu(spdu, sizeof(spdu), 0x4000U, 1U, 0U, NULL);
    ASSERT_TRUE(len > 0);
    ASSERT_EQ(iec61850_rsv_subscriber_process_spdu(&sub, spdu,
                                                   (size_t)len - 1U, 0U),
              0);
    ASSERT_EQ(iec61850_rsv_subscriber_process_frame(&sub, garbage,
                                                    sizeof(garbage), 0U),
              0);
    PASS();
}

/* ------------------------------------------------------------------ */
/* Security: frame-level roundtrip + tamper matrix (no sockets)        */
/* ------------------------------------------------------------------ */

#ifdef IEC61850_SECURITY_ENABLED

static const uint8_t sec_key[16] = {
    0x01U, 0x23U, 0x45U, 0x67U, 0x89U, 0xABU, 0xCDU, 0xEFU,
    0xFEU, 0xDCU, 0xBAU, 0x98U, 0x76U, 0x54U, 0x32U, 0x10U
};
#define SEC_KEY_ID 0xFEEDFACEU

static void make_pub_sec(iec61850_rsv_pub_security_t *s)
{
    (void)memset(s, 0, sizeof(*s));
    s->algo = (uint16_t)IEC61850_RSV_PUB_SEC_ALGO_HMAC_SHA256;
    (void)memcpy(s->key, sec_key, sizeof(sec_key));
    s->key_len = sizeof(sec_key);
    s->key_id = SEC_KEY_ID;
    s->time_to_next_key = 1440U;
}

static void make_sub_sec(iec61850_rsv_sub_security_t *s)
{
    (void)memset(s, 0, sizeof(*s));
    s->algo = (uint16_t)IEC61850_RSV_SUB_SEC_ALGO_HMAC_SHA256;
    (void)memcpy(s->key, sec_key, sizeof(sec_key));
    s->key_len = sizeof(sec_key);
    s->expected_key_id = SEC_KEY_ID;
}

static void test_enable_security_args(void)
{
    iec61850_rsv_publisher_t pub;
    iec61850_rsv_subscriber_t sub;
    iec61850_rsv_pub_security_t ps;
    iec61850_rsv_sub_security_t ss;

    TEST("rsv_enable_security_args");
    iec61850_rsv_publisher_init(&pub, NULL);
    iec61850_rsv_subscriber_init(&sub, NULL);
    make_pub_sec(&ps);
    make_sub_sec(&ss);

    ASSERT_EQ(iec61850_rsv_publisher_enable_security(NULL, &ps), -EINVAL);
    ASSERT_EQ(iec61850_rsv_publisher_enable_security(&pub, NULL), -EINVAL);
    ASSERT_EQ(iec61850_rsv_subscriber_enable_security(NULL, &ss), -EINVAL);
    ASSERT_EQ(iec61850_rsv_subscriber_enable_security(&sub, NULL), -EINVAL);

    {
        iec61850_rsv_pub_security_t bad = ps;
        bad.key_len = 0U;
        ASSERT_EQ(iec61850_rsv_publisher_enable_security(&pub, &bad),
                  -EINVAL);
        bad.key_len = (size_t)IEC61850_RSV_SEC_KEY_MAX + 1U;
        ASSERT_EQ(iec61850_rsv_publisher_enable_security(&pub, &bad),
                  -EINVAL);
    }
    {
        iec61850_rsv_pub_security_t gmac = ps;
        gmac.algo = (uint16_t)IEC61850_RSV_PUB_SEC_ALGO_AES_GMAC;
        ASSERT_EQ(iec61850_rsv_publisher_enable_security(&pub, &gmac),
                  -ENOTSUP);
    }
    {
        iec61850_rsv_sub_security_t bad = ss;
        bad.algo = 0x4242U;
        ASSERT_EQ(iec61850_rsv_subscriber_enable_security(&sub, &bad),
                  -EINVAL);
    }

    ASSERT_EQ(iec61850_rsv_publisher_enable_security(&pub, &ps), 0);
    ASSERT_EQ(iec61850_rsv_subscriber_enable_security(&sub, &ss), 0);
    PASS();
}

static int build_test_secure_frame(iec61850_rsv_publisher_t *pub,
                                   uint8_t *frame, size_t cap,
                                   size_t *frame_len)
{
    iec61850_rsv_pub_security_t ps;

    make_pub_sec(&ps);
    if (iec61850_rsv_publisher_enable_security(pub, &ps) != 0) {
        return -1;
    }
    return iec61850_rsv_publisher_build_frame(pub, frame, cap, frame_len);
}

static void test_secure_frame_roundtrip(void)
{
    iec61850_rsv_publisher_t pub;
    iec61850_rsv_subscriber_t sub;
    iec61850_rsv_sub_security_t ss;
    static uint8_t frame[IEC61850_RSV_MAX_FRAME_LEN];
    size_t frame_len = 0U;
    int ret;

    TEST("rsv_secure_frame_roundtrip");
    iec61850_rsv_publisher_init(&pub, NULL);
    ASSERT_EQ(iec61850_rsv_publisher_set_sample(&pub, 0, 32510), 0);
    ASSERT_EQ(iec61850_rsv_publisher_set_sample(&pub, 1, -812), 0);

    ret = build_test_secure_frame(&pub, frame, sizeof(frame), &frame_len);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(frame_len > (14U + 28U + 38U + 32U));

    /* Frame layout: [Eth][IPv4][UDP][SPDU]. */
    ASSERT_EQ((frame[12] << 8) | frame[13], 0x0800);
    ASSERT_EQ(frame[14] >> 4, 4);
    ASSERT_EQ(frame[14 + 9], 17);
    ASSERT_TRUE(frame[14 + 26] == 0U && frame[14 + 27] == 0U);
    ASSERT_EQ(frame[14 + 28], 0xA2); /* SPDU SI (R-SV) */

    make_sub_sec(&ss);
    iec61850_rsv_subscriber_init(&sub, NULL);
    iec61850_rsv_subscriber_set_callback(&sub, rsv_test_cb, NULL);
    ASSERT_EQ(iec61850_rsv_subscriber_enable_security(&sub, &ss), 0);
    cb_reset();

    ASSERT_EQ(iec61850_rsv_subscriber_process_frame(&sub, frame,
                                                    frame_len,
                                                    test_now_ns()), 1);
    ASSERT_EQ(cb_count, 1);
    ASSERT_TRUE(cb_last_msg.is_new_sample);
    ASSERT_TRUE(cb_last_msg.header.security.present);
    ASSERT_EQ(cb_last_msg.header.security.key_id, SEC_KEY_ID);
    ASSERT_EQ(cb_last_msg.header.security.signature_len, 32U);
    ASSERT_EQ((uint32_t)cb_last_msg.apdu.asdu[0].num_samples, 4U);
    ASSERT_EQ((int)cb_last_msg.apdu.asdu[0].samples[0].value, 32510);

    /* Second publish (new spdu_number + smpCnt) verifies. */
    ret = iec61850_rsv_publisher_build_frame(&pub, frame,
                                             sizeof(frame), &frame_len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(iec61850_rsv_subscriber_process_frame(&sub, frame,
                                                    frame_len,
                                                    test_now_ns()), 1);
    ASSERT_EQ(cb_count, 2);
    ASSERT_EQ(sub.total_security_failures, 0U);
    PASS();
}

static void test_secure_tamper_matrix(void)
{
    iec61850_rsv_publisher_t pub;
    iec61850_rsv_subscriber_t sub;
    iec61850_rsv_sub_security_t ss;
    static uint8_t frame[IEC61850_RSV_MAX_FRAME_LEN];
    static uint8_t bad[IEC61850_RSV_MAX_FRAME_LEN];
    size_t frame_len = 0U;
    size_t bad_len;
    int ret;

    TEST("rsv_secure_tamper_matrix");
    iec61850_rsv_publisher_init(&pub, NULL);
    ASSERT_EQ(iec61850_rsv_publisher_set_sample(&pub, 0, 1000), 0);
    ret = build_test_secure_frame(&pub, frame, sizeof(frame), &frame_len);
    ASSERT_EQ(ret, 0);

    make_sub_sec(&ss);
    iec61850_rsv_subscriber_init(&sub, NULL);
    iec61850_rsv_subscriber_set_callback(&sub, rsv_test_cb, NULL);
    ASSERT_EQ(iec61850_rsv_subscriber_enable_security(&sub, &ss), 0);
    cb_reset();

    ASSERT_EQ(iec61850_rsv_subscriber_process_frame(&sub, frame,
                                                    frame_len, 1U), 1);
    ASSERT_EQ(cb_count, 1);

    {
        struct {
            const char *region;
            size_t offset;
        } cases[] = {
            { "IP header (TTL)",             14U + 8U },
            { "IP header (dst addr)",        14U + 16U },
            { "UDP header (src port)",       14U + 20U },
            { "UDP header (dst port)",       14U + 22U },
            { "UDP header (checksum)",       14U + 26U },
            { "SPDU header (SPDU number)",   14U + 28U + 8U },
            { "SPDU security (key id)",      14U + 28U + 22U },
            { "APDU payload (last byte)",    frame_len - 35U },
            { "Signature TLV (tag)",         frame_len - 34U },
            { "Signature value (last byte)", frame_len - 1U },
        };
        const size_t n = sizeof(cases) / sizeof(cases[0]);

        for (size_t i = 0U; i < n; i++) {
            uint64_t fails_before = sub.total_security_failures;

            (void)memcpy(bad, frame, frame_len);
            bad[cases[i].offset] ^= 0x01U;
            bad_len = frame_len;

            ASSERT_EQ(iec61850_rsv_subscriber_process_frame(
                          &sub, bad, bad_len, (uint64_t)(i + 2U)), 0);
            if (sub.total_security_failures == fails_before) {
                printf("region not rejected: %s\n", cases[i].region);
                FAIL("tampered frame accepted");
            }
        }
        ASSERT_EQ(cb_count, 1);
    }

    /* Truncated frame. */
    ASSERT_EQ(iec61850_rsv_subscriber_process_frame(&sub, frame,
                                                    frame_len - 1U, 99U),
              0);
    PASS();
}

static void test_secure_key_id_and_bypass(void)
{
    iec61850_rsv_publisher_t pub;
    iec61850_rsv_subscriber_t sub;
    iec61850_rsv_sub_security_t ss;
    static uint8_t frame[IEC61850_RSV_MAX_FRAME_LEN];
    uint8_t spdu[IEC61850_RSV_MAX_SPDU_LEN];
    size_t frame_len = 0U;
    size_t spdu_len = 0U;
    int ret;

    TEST("rsv_secure_key_id_and_bypass");
    iec61850_rsv_publisher_init(&pub, NULL);
    ret = build_test_secure_frame(&pub, frame, sizeof(frame), &frame_len);
    ASSERT_EQ(ret, 0);

    /* Key-id mismatch. */
    make_sub_sec(&ss);
    ss.expected_key_id = SEC_KEY_ID + 1U;
    iec61850_rsv_subscriber_init(&sub, NULL);
    ASSERT_EQ(iec61850_rsv_subscriber_enable_security(&sub, &ss), 0);
    ASSERT_EQ(iec61850_rsv_subscriber_process_frame(&sub, frame,
                                                    frame_len, 1U), 0);
    ASSERT_EQ(sub.total_security_failures, 1U);

    /* expected_key_id == 0 accepts any. */
    ss.expected_key_id = 0U;
    iec61850_rsv_subscriber_init(&sub, NULL);
    ASSERT_EQ(iec61850_rsv_subscriber_enable_security(&sub, &ss), 0);
    ASSERT_EQ(iec61850_rsv_subscriber_process_frame(&sub, frame,
                                                    frame_len, 2U), 1);

    /* Bypass attempt: bare SPDU fed to a secure subscriber. */
    iec61850_rsv_publisher_init(&pub, NULL);
    ASSERT_EQ(iec61850_rsv_publisher_build_spdu(&pub, spdu,
                                                sizeof(spdu), &spdu_len),
              0);
    ASSERT_EQ(iec61850_rsv_subscriber_process_spdu(&sub, spdu, spdu_len,
                                                   3U), 0);

    /* Unsigned frame (no security extension): rejected. */
    {
        static uint8_t plain_frame[IEC61850_RSV_MAX_FRAME_LEN];
        size_t plain_len = 0U;
        int r = iec61850_ip_udp_build(&plain_frame[14],
                                      sizeof(plain_frame) - 14U,
                                      "127.0.0.1", "127.0.0.1", 103U, 103U,
                                      spdu, spdu_len, 17U);
        ASSERT_EQ(r, 0);
        (void)memcpy(plain_frame, frame, 14U);
        plain_len = 14U + 28U + spdu_len;
        ASSERT_EQ(iec61850_rsv_subscriber_process_frame(&sub, plain_frame,
                                                        plain_len, 4U), 0);
    }

    /* Port filter (secure mode only). */
    {
        iec61850_rsv_subscriber_t sub2;
        iec61850_rsv_sub_config_t cfg;

        iec61850_rsv_sub_config_init(&cfg);
        cfg.filter_port = 9999U;
        iec61850_rsv_subscriber_init(&sub2, &cfg);
        make_sub_sec(&ss);
        ASSERT_EQ(iec61850_rsv_subscriber_enable_security(&sub2, &ss), 0);
        ASSERT_EQ(iec61850_rsv_subscriber_process_frame(&sub2, frame,
                                                        frame_len, 5U), 0);
    }
    PASS();
}

/* Re-sign a (locally modified) received frame with the test key. */
static int resign_frame(uint8_t *frame, size_t frame_len)
{
    uint8_t sig[32];

    (void)memset(&frame[frame_len - 32U], 0U, 32U);
    if (hmac_sha256_sign(sec_key, sizeof(sec_key), &frame[14],
                         frame_len - 14U, sig, sizeof(sig)) != 0) {
        return -1;
    }
    (void)memcpy(&frame[frame_len - 32U], sig, sizeof(sig));
    return 0;
}

static void test_secure_time_window(void)
{
    iec61850_rsv_publisher_t pub;
    iec61850_rsv_subscriber_t sub;
    iec61850_rsv_sub_security_t ss;
    static uint8_t frame[IEC61850_RSV_MAX_FRAME_LEN];
    size_t frame_len = 0U;
    uint32_t t_ref;
    int ret;

    TEST("rsv_secure_time_window");
    iec61850_rsv_publisher_init(&pub, NULL);
    ret = build_test_secure_frame(&pub, frame, sizeof(frame), &frame_len);
    ASSERT_EQ(ret, 0);

    make_sub_sec(&ss);
    iec61850_rsv_subscriber_init(&sub, NULL);
    iec61850_rsv_subscriber_set_callback(&sub, rsv_test_cb, NULL);
    ASSERT_EQ(iec61850_rsv_subscriber_enable_security(&sub, &ss), 0);
    cb_reset();

    ASSERT_EQ(iec61850_rsv_subscriber_process_frame(&sub, frame,
                                                    frame_len, 1U), 1);
    ASSERT_EQ(cb_count, 1);
    t_ref = cb_last_msg.header.security.time_of_current_key;

    /* Fresh SPDU number, time field moved far outside the window,
     * re-signed: rejected by the window check despite the valid
     * signature. */
    ret = iec61850_rsv_publisher_build_frame(&pub, frame,
                                             sizeof(frame), &frame_len);
    ASSERT_EQ(ret, 0);
    {
        uint32_t far = t_ref + 43200001U;
        uint8_t *tok = &frame[14U + 28U + 14U];

        tok[0] = (uint8_t)(far >> 24);
        tok[1] = (uint8_t)(far >> 16);
        tok[2] = (uint8_t)(far >> 8);
        tok[3] = (uint8_t)far;
        ASSERT_EQ(resign_frame(frame, frame_len), 0);
        ASSERT_EQ(iec61850_rsv_subscriber_process_frame(&sub, frame,
                                                        frame_len, 2U), 0);
        ASSERT_EQ(cb_count, 1);
        ASSERT_EQ(sub.total_security_failures, 1U);
    }

    /* Control: unchanged second frame re-signed is accepted. */
    ret = iec61850_rsv_publisher_build_frame(&pub, frame,
                                             sizeof(frame), &frame_len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(resign_frame(frame, frame_len), 0);
    ASSERT_EQ(iec61850_rsv_subscriber_process_frame(&sub, frame,
                                                    frame_len, 3U), 1);
    ASSERT_EQ(cb_count, 2);
    PASS();
}

static void test_secure_frame_build_errors(void)
{
    iec61850_rsv_publisher_t pub;
    iec61850_rsv_pub_security_t ps;
    static uint8_t frame[IEC61850_RSV_MAX_FRAME_LEN];
    size_t frame_len = 0U;

    TEST("rsv_secure_frame_build_errors");
    iec61850_rsv_publisher_init(&pub, NULL);
    make_pub_sec(&ps);
    ASSERT_EQ(iec61850_rsv_publisher_enable_security(&pub, &ps), 0);

    ASSERT_EQ(iec61850_rsv_publisher_build_frame(&pub, frame, 100U,
                                                 &frame_len), -ENOSPC);
    ASSERT_EQ(iec61850_rsv_publisher_build_frame(NULL, frame,
                                                 sizeof(frame),
                                                 &frame_len), -EINVAL);
    ASSERT_EQ(iec61850_rsv_publisher_build_frame(&pub, frame,
                                                 sizeof(frame), NULL),
              -EINVAL);
    ASSERT_EQ(iec61850_rsv_publisher_publish(&pub), -EINVAL);
    /* Retransmission service: disabled by default → no-op. */
    ASSERT_EQ(iec61850_rsv_publisher_retransmit(&pub), 0);
    ASSERT_EQ(iec61850_rsv_publisher_retransmit(NULL), -EINVAL);
    PASS();
}

static void test_retransmit_scheduling(void)
{
    iec61850_rsv_publisher_t pub;

    TEST("rsv_retransmit_scheduling");
    iec61850_rsv_publisher_init(&pub, NULL);

    /* Default OFF: retransmit() is a no-op. */
    ASSERT_TRUE(!pub.has_retransmit);
    ASSERT_EQ(iec61850_rsv_publisher_retransmit(&pub), 0);

    /* Opt-in: due immediately after state change... there is no
     * state_change on R-SV; enable + immediate due comes from the
     * scheduler init (next_tx = now). Without io the publish fails. */
    iec61850_rsv_publisher_enable_retransmit(&pub, NULL);
    ASSERT_TRUE(pub.has_retransmit);
    ASSERT_EQ(iec61850_rsv_publisher_retransmit(&pub), -EINVAL);
    PASS();
}

#endif /* IEC61850_SECURITY_ENABLED */

/* ------------------------------------------------------------------ */
/* Plain-mode socket loopback over 127.0.0.1 (UDP backend)             */
/* ------------------------------------------------------------------ */

static void test_plain_socket_loopback(void)
{
    iec61850_rsv_pub_config_t pcfg;
    iec61850_rsv_sub_config_t scfg;
    iec61850_rsv_publisher_t pub;
    iec61850_rsv_subscriber_t sub;
    struct packet_io *tx;
    struct packet_io *rx;
    static uint8_t spdu[IEC61850_RSV_MAX_SPDU_LEN];
    size_t spdu_len = 0U;

    TEST("rsv_plain_socket_loopback");

    iec61850_rsv_pub_config_init(&pcfg);
    pcfg.dst_port = (uint16_t)PORT_RSV;
    iec61850_rsv_publisher_init(&pub, &pcfg);
    ASSERT_EQ(iec61850_rsv_publisher_set_sample(&pub, 0, 32510), 0);

    iec61850_rsv_sub_config_init(&scfg);
    scfg.timeout_ms = 30000U;
    iec61850_rsv_subscriber_init(&sub, &scfg);
    iec61850_rsv_subscriber_set_callback(&sub, rsv_test_cb, NULL);
    cb_reset();

    tx = packet_io_create_udp_sender("127.0.0.1", (uint16_t)PORT_RSV,
                                     false);
    rx = packet_io_create_udp_receiver((uint16_t)PORT_RSV, NULL);
    ASSERT_TRUE(tx != NULL);
    ASSERT_TRUE(rx != NULL);
    ASSERT_EQ(packet_io_open(rx, NULL, 0), 0);
    ASSERT_EQ(packet_io_open(tx, NULL, 0), 0);

    iec61850_rsv_publisher_set_io(&pub, tx);

    /* Nothing queued yet. */
    ASSERT_EQ(iec61850_rsv_subscriber_poll(&sub, rx), 0);

    /* Publish → poll → callback delivery. */
    ASSERT_EQ(iec61850_rsv_publisher_publish(&pub), 0);
    ASSERT_EQ(iec61850_rsv_subscriber_poll(&sub, rx), 1);
    ASSERT_EQ(cb_count, 1);
    ASSERT_TRUE(cb_last_msg.is_new_sample);
    ASSERT_EQ(cb_last_msg.header.appid, pcfg.appid);
    ASSERT_EQ(cb_last_msg.header.spdu_number, 0U);
    ASSERT_EQ((uint32_t)cb_last_msg.apdu.asdu[0].smpCnt, 0U);

    /* Second publish: next sample. */
    ASSERT_EQ(iec61850_rsv_publisher_publish(&pub), 0);
    ASSERT_EQ(iec61850_rsv_subscriber_poll(&sub, rx), 1);
    ASSERT_EQ(cb_count, 2);
    ASSERT_TRUE(cb_last_msg.is_new_sample);
    ASSERT_EQ((uint32_t)cb_last_msg.apdu.asdu[0].smpCnt, 1U);

    /* Replay detection: capture one SPDU and send it twice. */
    ASSERT_EQ(iec61850_rsv_publisher_build_spdu(&pub, spdu,
                                                sizeof(spdu), &spdu_len),
              0);
    ASSERT_EQ(packet_io_send(tx, spdu, (uint32_t)spdu_len), 0);
    ASSERT_EQ(iec61850_rsv_subscriber_poll(&sub, rx), 1);
    ASSERT_EQ(packet_io_send(tx, spdu, (uint32_t)spdu_len), 0);
    ASSERT_EQ(iec61850_rsv_subscriber_poll(&sub, rx), 0);
    ASSERT_EQ(sub.total_replays, 1U);

    /* Timeout. */
    {
        uint64_t now = test_now_ns();

        iec61850_rsv_subscriber_check_timeouts(
            &sub, now + (uint64_t)scfg.timeout_ms * 1000000ULL + 1U);
        {
            const iec61850_rsv_pub_state_t *ps =
                iec61850_rsv_subscriber_get_pub_state(&sub, TEST_SVID);
            ASSERT_TRUE(ps != NULL);
            ASSERT_TRUE(ps->timeout_detected);
        }
    }

    packet_io_close(rx);
    packet_io_close(tx);
    packet_io_destroy(rx);
    packet_io_destroy(tx);
    PASS();
}

#ifdef IEC61850_SECURITY_ENABLED
/*
 * Secure-mode raw-frame loopback on lo (root only; skipped
 * gracefully otherwise — frame-level tests carry the coverage).
 */
static void test_secure_socket_loopback(void)
{
    iec61850_rsv_pub_config_t pcfg;
    iec61850_rsv_sub_config_t scfg;
    iec61850_rsv_publisher_t pub;
    iec61850_rsv_subscriber_t sub;
    iec61850_rsv_pub_security_t ps;
    iec61850_rsv_sub_security_t ss;
    struct packet_io *tx;
    struct packet_io *rx;
    int ret;
    int got = 0;

    TEST("rsv_secure_socket_loopback");

    tx = packet_io_create_raw();
    rx = packet_io_create_raw();
    ASSERT_TRUE(tx != NULL);
    ASSERT_TRUE(rx != NULL);

    ret = packet_io_open(rx, "lo", 0);
    if ((ret == -EPERM) || (ret == -EACCES)) {
        packet_io_destroy(tx);
        packet_io_destroy(rx);
        SKIP("AF_PACKET requires root (secure loopback covered frame-level)");
    }
    ASSERT_EQ(ret, 0);
    ret = packet_io_open(tx, "lo", 0);
    if ((ret == -EPERM) || (ret == -EACCES)) {
        packet_io_destroy(tx);
        packet_io_destroy(rx);
        SKIP("AF_PACKET requires root");
    }
    ASSERT_EQ(ret, 0);

    iec61850_rsv_pub_config_init(&pcfg);
    iec61850_rsv_publisher_init(&pub, &pcfg);
    ASSERT_EQ(iec61850_rsv_publisher_set_sample(&pub, 0, 32510), 0);
    make_pub_sec(&ps);
    ASSERT_EQ(iec61850_rsv_publisher_enable_security(&pub, &ps), 0);
    iec61850_rsv_publisher_set_io(&pub, tx);

    iec61850_rsv_sub_config_init(&scfg);
    iec61850_rsv_subscriber_init(&sub, &scfg);
    iec61850_rsv_subscriber_set_callback(&sub, rsv_test_cb, NULL);
    make_sub_sec(&ss);
    ASSERT_EQ(iec61850_rsv_subscriber_enable_security(&sub, &ss), 0);
    cb_reset();

    ASSERT_EQ(iec61850_rsv_publisher_publish(&pub), 0);

    for (int i = 0; (i < 200) && (got == 0); i++) {
        int r = iec61850_rsv_subscriber_poll(&sub, rx);

        if (r == 1) {
            got = 1;
        } else if (r < 0) {
            FAIL("poll error");
        } else {
            (void)usleep(1000U);
        }
    }
    ASSERT_EQ(got, 1);
    ASSERT_EQ(cb_count, 1);
    ASSERT_TRUE(cb_last_msg.header.security.present);

    packet_io_close(rx);
    packet_io_close(tx);
    packet_io_destroy(rx);
    packet_io_destroy(tx);
    PASS();
}
#endif /* IEC61850_SECURITY_ENABLED */

/* ------------------------------------------------------------------ */
/* Plain build (no -Denable_security): enable_security → -ENOTSUP      */
/* ------------------------------------------------------------------ */

#ifndef IEC61850_SECURITY_ENABLED
static void test_notsup_without_security(void)
{
    iec61850_rsv_publisher_t pub;
    iec61850_rsv_subscriber_t sub;
    iec61850_rsv_pub_security_t ps;
    iec61850_rsv_sub_security_t ss;

    TEST("rsv_notsup_without_security");
    iec61850_rsv_publisher_init(&pub, NULL);
    iec61850_rsv_subscriber_init(&sub, NULL);
    (void)memset(&ps, 0, sizeof(ps));
    ps.algo = (uint16_t)IEC61850_RSV_PUB_SEC_ALGO_HMAC_SHA256;
    ps.key_len = 16U;
    (void)memset(&ss, 0, sizeof(ss));
    ss.algo = (uint16_t)IEC61850_RSV_SUB_SEC_ALGO_HMAC_SHA256;
    ss.key_len = 16U;

    ASSERT_EQ(iec61850_rsv_publisher_enable_security(&pub, &ps),
              -ENOTSUP);
    ASSERT_EQ(iec61850_rsv_subscriber_enable_security(&sub, &ss),
              -ENOTSUP);
    ASSERT_TRUE(!pub.security_enabled);
    ASSERT_TRUE(!sub.security_enabled);
    PASS();
}
#endif

int main(void)
{
    printf("=== R-SV Publisher/Subscriber Unit Tests ===\n");

    test_config_defaults();
    test_publisher_lifecycle();
    test_sample_setters();
    test_build_spdu_plain();
    test_subscriber_state_machine();
    test_spdu_replay_rejection();
    test_time_window();
    test_subscriber_filters_and_timeouts();
    test_subscriber_error_paths();
    test_plain_socket_loopback();

#ifdef IEC61850_SECURITY_ENABLED
    test_enable_security_args();
    test_secure_frame_roundtrip();
    test_secure_tamper_matrix();
    test_secure_key_id_and_bypass();
    test_secure_time_window();
    test_secure_frame_build_errors();
    test_retransmit_scheduling();
    test_secure_socket_loopback();
#else
    test_notsup_without_security();
#endif

    printf("\n=== Summary: %d run, %d passed, %d failed ===\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}
