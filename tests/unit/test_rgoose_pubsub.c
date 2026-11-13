/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Unit Tests for IEC TR 61850-90-5 R-GOOSE Publisher/Subscriber
 *
 * WP-4d (r-security-replay): lifecycle and API error paths, plain
 * SPDU build/decode roundtrip, L2-style state machine, per-APPID
 * SPDU-number replay rejection, 90-5 time-window validation,
 * frame-level security roundtrip (build → sign → verify, plus a
 * tamper matrix over every signed region: IP header, UDP header,
 * SPDU header, APDU payload, signature) for both HMAC-SHA256 and
 * AES-GMAC (WP-3h: GMAC sign→verify roundtrip, GMAC tamper matrix,
 * key-id mismatch and mixed HMAC/GMAC rejection), plain-mode socket
 * loopback over 127.0.0.1 (UDP backend, unprivileged), and a
 * secure-mode raw
 * socket loopback that runs only when AF_PACKET is permitted
 * (root — skipped gracefully otherwise; frame-level tests carry the
 * coverage in unprivileged runs).
 *
 * Security-gated tests compile only with -Denable_security=true; the
 * plain build verifies that enable_security() returns -ENOTSUP.
 */

#include "asn1/r_profile.h"
#include "goose/rgoose_publisher.h"
#include "goose/rgoose_subscriber.h"
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
#define PORT_RGOOSE 47921U

#define TEST_GOCBREF "IED1LD0/LLN0$GO$gcb01"

/* ------------------------------------------------------------------ */
/* Callback capture                                                    */
/* ------------------------------------------------------------------ */

static iec61850_rgoose_message_t cb_last_msg;
static int cb_count;

static void rgoose_test_cb(const iec61850_rgoose_message_t *msg,
                           void *user_data)
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
/* SPDU crafting helper (direct codec access, independent of the      */
/* publisher under test)                                               */
/* ------------------------------------------------------------------ */

static int craft_spdu(uint8_t *buf, size_t cap, uint16_t appid,
                      uint32_t spdu_num, uint32_t st, uint32_t sq,
                      const iec61850_r_security_t *sec)
{
    goose_apdu_t a;

    goose_apdu_init(&a);
    (void)goose_set_gocbref(&a, TEST_GOCBREF);
    (void)goose_set_datset(&a, "IED1LD0/LLN0$DS1");
    a.timeAllowedtoLive = 1000U;
    a.stNum = st;
    a.sqNum = sq;
    a.confRev = 1U;
    a.numDatSetEntries = 0U;

    return iec61850_rgoose_encode(&a, appid, spdu_num, sec, buf, cap);
}

static uint64_t test_now_ns(void)
{
    struct timespec ts;

    (void)clock_gettime(CLOCK_REALTIME, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

/* ------------------------------------------------------------------ */
/* Publisher: config, lifecycle, dataset setters                       */
/* ------------------------------------------------------------------ */

static void test_config_defaults(void)
{
    iec61850_rgoose_pub_config_t cfg;

    TEST("rgoose_config_defaults");
    iec61850_rgoose_pub_config_init(&cfg);
    ASSERT_EQ(cfg.appid, 0x0001U);
    ASSERT_EQ(cfg.dst_port, 102U);
    ASSERT_EQ(cfg.src_port, 102U);
    ASSERT_TRUE(strcmp(cfg.dst_ip, "127.0.0.1") == 0);
    ASSERT_TRUE(strcmp(cfg.src_ip, "127.0.0.1") == 0);
    ASSERT_EQ(cfg.conf_rev, 1U);
    ASSERT_EQ(cfg.time_allowed_to_live, 2000U);
    ASSERT_TRUE(cfg.gocb_ref[0] != '\0');
    ASSERT_TRUE(cfg.dataset[0] != '\0');
    ASSERT_TRUE(cfg.goose_id[0] != '\0');
    /* NULL safety */
    iec61850_rgoose_pub_config_init(NULL);
    PASS();
}

static void test_publisher_lifecycle(void)
{
    iec61850_rgoose_publisher_t pub;
    iec61850_rgoose_pub_config_t cfg;

    TEST("rgoose_publisher_lifecycle");
    iec61850_rgoose_pub_config_init(&cfg);
    cfg.appid = 0x0123U;

    iec61850_rgoose_publisher_init(&pub, &cfg);
    /* Retransmission defaults ON for R-GOOSE. */
    ASSERT_TRUE(pub.has_retransmit);
    ASSERT_EQ(iec61850_rgoose_publisher_get_st_num(&pub), 0U);
    ASSERT_EQ(iec61850_rgoose_publisher_get_sq_num(&pub), 0U);
    ASSERT_EQ(iec61850_rgoose_publisher_get_spdu_number(&pub), 0U);

    iec61850_rgoose_publisher_state_change(&pub);
    ASSERT_EQ(iec61850_rgoose_publisher_get_st_num(&pub), 1U);
    ASSERT_EQ(iec61850_rgoose_publisher_get_sq_num(&pub), 0U);

    iec61850_rgoose_publisher_disable_retransmit(&pub);
    ASSERT_TRUE(!pub.has_retransmit);
    iec61850_rgoose_publisher_enable_retransmit(&pub, NULL);
    ASSERT_TRUE(pub.has_retransmit);

    iec61850_rgoose_publisher_set_io(&pub, NULL);
    iec61850_rgoose_publisher_destroy(&pub);

    /* NULL safety */
    iec61850_rgoose_publisher_init(NULL, &cfg);
    iec61850_rgoose_publisher_init(&pub, NULL);
    ASSERT_EQ(pub.config.appid, 0x0001U); /* default config applied */
    iec61850_rgoose_publisher_state_change(NULL);
    iec61850_rgoose_publisher_destroy(NULL);
    ASSERT_EQ(iec61850_rgoose_publisher_get_st_num(NULL), 0U);
    ASSERT_EQ(iec61850_rgoose_publisher_get_sq_num(NULL), 0U);
    ASSERT_EQ(iec61850_rgoose_publisher_get_spdu_number(NULL), 0U);
    PASS();
}

static void test_dataset_setters(void)
{
    iec61850_rgoose_publisher_t pub;
    uint8_t bits[4] = { 0xDE, 0xAD, 0xBE, 0xEF };
    uint8_t octs[8] = { 1U, 2U, 3U, 4U, 5U, 6U, 7U, 8U };
    uint8_t too_big[257];

    TEST("rgoose_dataset_setters");
    iec61850_rgoose_publisher_init(&pub, NULL);

    ASSERT_EQ(iec61850_rgoose_publisher_set_boolean(&pub, 0, true), 0);
    ASSERT_EQ(iec61850_rgoose_publisher_set_int32(&pub, 1, -1234), 0);
    ASSERT_EQ(iec61850_rgoose_publisher_set_uint32(&pub, 2, 5678U), 0);
    ASSERT_EQ(iec61850_rgoose_publisher_set_float32(&pub, 3, 1.5f), 0);
    ASSERT_EQ(iec61850_rgoose_publisher_set_bitstring(&pub, 4, bits,
                                                      sizeof(bits)), 0);
    ASSERT_EQ(iec61850_rgoose_publisher_set_octetstring(&pub, 5, octs,
                                                        sizeof(octs)), 0);
    ASSERT_EQ(iec61850_rgoose_publisher_set_utctime(&pub, 6,
                                                    1234567890ULL, 0x0AU), 0);
    ASSERT_EQ(iec61850_rgoose_publisher_set_btime6(&pub, 7,
                                                   43210000U, 19000U), 0);
    ASSERT_EQ(pub.data_count, 8U);

    /* Indexed gap-fill */
    ASSERT_EQ(iec61850_rgoose_publisher_set_boolean(&pub, 9, false), 0);
    ASSERT_EQ(pub.data_count, 10U);

    /* Error paths */
    ASSERT_EQ(iec61850_rgoose_publisher_set_boolean(NULL, 0, true), -EINVAL);
    ASSERT_EQ(iec61850_rgoose_publisher_set_int32(&pub,
                                                  (size_t)GOOSE_MAX_ALLDATA_ENTRIES,
                                                  1), -EINVAL);
    ASSERT_EQ(iec61850_rgoose_publisher_set_bitstring(&pub, 0, NULL, 4),
              -EINVAL);
    (void)memset(too_big, 0xA5U, sizeof(too_big));
    ASSERT_EQ(iec61850_rgoose_publisher_set_bitstring(&pub, 0, too_big,
                                                      sizeof(too_big)),
              -EMSGSIZE);
    ASSERT_EQ(iec61850_rgoose_publisher_set_octetstring(&pub, 0, too_big,
                                                        sizeof(too_big)),
              -EMSGSIZE);
    PASS();
}

/* ------------------------------------------------------------------ */
/* Publisher: plain SPDU build roundtrip                               */
/* ------------------------------------------------------------------ */

static void test_build_spdu_plain(void)
{
    iec61850_rgoose_publisher_t pub;
    uint8_t spdu[IEC61850_RGOOSE_MAX_SPDU_LEN];
    uint8_t spdu2[IEC61850_RGOOSE_MAX_SPDU_LEN];
    goose_apdu_t apdu;
    iec61850_r_header_t hdr;
    size_t len = 0U;
    size_t len2 = 0U;
    int ret;

    TEST("rgoose_build_spdu_plain");
    iec61850_rgoose_publisher_init(&pub, NULL);
    ASSERT_EQ(iec61850_rgoose_publisher_set_boolean(&pub, 0, true), 0);
    ASSERT_EQ(iec61850_rgoose_publisher_set_int32(&pub, 1, -77), 0);

    ASSERT_EQ(iec61850_rgoose_publisher_build_spdu(&pub, spdu,
                                                   sizeof(spdu), &len), 0);
    ASSERT_TRUE(len > 24U);

    ret = iec61850_rgoose_decode(spdu, len, &apdu, &hdr);
    ASSERT_TRUE(ret > 0);
    ASSERT_EQ(hdr.appid, 0x0001U);
    ASSERT_EQ(hdr.spdu_number, 0U);
    ASSERT_TRUE(!hdr.security.present);
    ASSERT_EQ((uint32_t)apdu.stNum, 0U);
    ASSERT_EQ((uint32_t)apdu.sqNum, 0U);
    ASSERT_EQ((uint32_t)apdu.numDatSetEntries, 2U);
    ASSERT_TRUE(strcmp(apdu.gocbRef, TEST_GOCBREF) == 0);

    /* Counters consumed by the build. */
    ASSERT_EQ(iec61850_rgoose_publisher_get_sq_num(&pub), 1U);
    ASSERT_EQ(iec61850_rgoose_publisher_get_spdu_number(&pub), 1U);

    /* Second build: sqNum and spdu_number advance. */
    ASSERT_EQ(iec61850_rgoose_publisher_build_spdu(&pub, spdu2,
                                                   sizeof(spdu2), &len2), 0);
    ret = iec61850_rgoose_decode(spdu2, len2, &apdu, &hdr);
    ASSERT_TRUE(ret > 0);
    ASSERT_EQ(hdr.spdu_number, 1U);
    ASSERT_EQ((uint32_t)apdu.sqNum, 1U);

    /* state_change resets sqNum, increments stNum. */
    iec61850_rgoose_publisher_state_change(&pub);
    ASSERT_EQ(iec61850_rgoose_publisher_build_spdu(&pub, spdu,
                                                   sizeof(spdu), &len), 0);
    ret = iec61850_rgoose_decode(spdu, len, &apdu, &hdr);
    ASSERT_TRUE(ret > 0);
    ASSERT_EQ((uint32_t)apdu.stNum, 1U);
    ASSERT_EQ((uint32_t)apdu.sqNum, 0U);
    ASSERT_EQ(hdr.spdu_number, 2U);

    /* Buffer too small. */
    ASSERT_EQ(iec61850_rgoose_publisher_build_spdu(&pub, spdu, 100U, &len),
              -ENOSPC);
    /* Argument errors. */
    ASSERT_EQ(iec61850_rgoose_publisher_build_spdu(NULL, spdu,
                                                   sizeof(spdu), &len),
              -EINVAL);
    ASSERT_EQ(iec61850_rgoose_publisher_build_spdu(&pub, NULL,
                                                   sizeof(spdu), &len),
              -EINVAL);
    ASSERT_EQ(iec61850_rgoose_publisher_build_spdu(&pub, spdu,
                                                   sizeof(spdu), NULL),
              -EINVAL);

    /* publish() without io. */
    ASSERT_EQ(iec61850_rgoose_publisher_publish(&pub), -EINVAL);
    ASSERT_EQ(iec61850_rgoose_publisher_publish(NULL), -EINVAL);
    PASS();
}

/* ------------------------------------------------------------------ */
/* Subscriber: L2-style state machine (crafted SPDUs)                  */
/* ------------------------------------------------------------------ */

static void test_subscriber_state_machine(void)
{
    iec61850_rgoose_subscriber_t sub;
    uint8_t spdu[512];
    int len;

    TEST("rgoose_subscriber_state_machine");
    iec61850_rgoose_subscriber_init(&sub, NULL);
    iec61850_rgoose_subscriber_set_callback(&sub, rgoose_test_cb, NULL);
    cb_reset();

    /* New state (stNum 1, sqNum 0). */
    len = craft_spdu(spdu, sizeof(spdu), 0x0001U, 10U, 1U, 0U, NULL);
    ASSERT_TRUE(len > 0);
    ASSERT_EQ(iec61850_rgoose_subscriber_process_spdu(&sub, spdu,
                                                      (size_t)len,
                                                      test_now_ns()), 1);
    ASSERT_EQ(cb_count, 1);
    ASSERT_TRUE(cb_last_msg.is_new_state);

    /* Same state, higher sqNum: retransmission. */
    len = craft_spdu(spdu, sizeof(spdu), 0x0001U, 11U, 1U, 1U, NULL);
    ASSERT_TRUE(len > 0);
    ASSERT_EQ(iec61850_rgoose_subscriber_process_spdu(&sub, spdu,
                                                      (size_t)len,
                                                      test_now_ns()), 1);
    ASSERT_EQ(cb_count, 2);
    ASSERT_TRUE(cb_last_msg.is_retransmission);
    ASSERT_TRUE(!cb_last_msg.is_new_state);

    /* Same state, lower/equal sqNum: duplicate — dropped. */
    len = craft_spdu(spdu, sizeof(spdu), 0x0001U, 12U, 1U, 1U, NULL);
    ASSERT_TRUE(len > 0);
    ASSERT_EQ(iec61850_rgoose_subscriber_process_spdu(&sub, spdu,
                                                      (size_t)len,
                                                      test_now_ns()), 0);
    ASSERT_EQ(cb_count, 2);
    ASSERT_EQ(sub.total_duplicates, 1U);

    /* New state again. */
    len = craft_spdu(spdu, sizeof(spdu), 0x0001U, 13U, 2U, 0U, NULL);
    ASSERT_TRUE(len > 0);
    ASSERT_EQ(iec61850_rgoose_subscriber_process_spdu(&sub, spdu,
                                                      (size_t)len,
                                                      test_now_ns()), 1);
    ASSERT_TRUE(cb_last_msg.is_new_state);

    /* Old state (stNum < latest): silently discarded. */
    len = craft_spdu(spdu, sizeof(spdu), 0x0001U, 14U, 1U, 5U, NULL);
    ASSERT_TRUE(len > 0);
    ASSERT_EQ(iec61850_rgoose_subscriber_process_spdu(&sub, spdu,
                                                      (size_t)len,
                                                      test_now_ns()), 0);
    /* 4 messages reached the state machine; the old-state one and
     * the duplicate delivered no callback. */
    ASSERT_EQ(cb_count, 3);

    /* Publisher state visible. */
    {
        const iec61850_rgoose_pub_state_t *ps =
            iec61850_rgoose_subscriber_get_pub_state(&sub, TEST_GOCBREF);
        ASSERT_TRUE(ps != NULL);
        ASSERT_EQ((uint32_t)ps->latest_st_num, 2U);
        ASSERT_EQ((uint32_t)ps->latest_sq_num, 0U);
        ASSERT_EQ((uint32_t)ps->message_count, 4U);
    }
    ASSERT_TRUE(iec61850_rgoose_subscriber_get_pub_state(&sub, "no/such") ==
                NULL);
    ASSERT_TRUE(iec61850_rgoose_subscriber_get_pub_state(NULL, "x") == NULL);
    ASSERT_TRUE(iec61850_rgoose_subscriber_get_pub_state(&sub, NULL) == NULL);
    PASS();
}

static void test_spdu_replay_rejection(void)
{
    iec61850_rgoose_subscriber_t sub;
    uint8_t spdu[512];
    int len;

    TEST("rgoose_spdu_replay_rejection");
    iec61850_rgoose_subscriber_init(&sub, NULL);
    iec61850_rgoose_subscriber_set_callback(&sub, rgoose_test_cb, NULL);
    cb_reset();

    /* spdu_number 100 accepted. */
    len = craft_spdu(spdu, sizeof(spdu), 0x0002U, 100U, 1U, 0U, NULL);
    ASSERT_TRUE(len > 0);
    ASSERT_EQ(iec61850_rgoose_subscriber_process_spdu(&sub, spdu,
                                                      (size_t)len, 1U), 1);

    /* Replayed (same number): dropped. */
    ASSERT_EQ(iec61850_rgoose_subscriber_process_spdu(&sub, spdu,
                                                      (size_t)len, 2U), 0);
    /* Out-of-order (lower number): dropped. */
    len = craft_spdu(spdu, sizeof(spdu), 0x0002U, 99U, 1U, 9U, NULL);
    ASSERT_TRUE(len > 0);
    ASSERT_EQ(iec61850_rgoose_subscriber_process_spdu(&sub, spdu,
                                                      (size_t)len, 3U), 0);
    /* Higher number: accepted. */
    len = craft_spdu(spdu, sizeof(spdu), 0x0002U, 101U, 1U, 1U, NULL);
    ASSERT_TRUE(len > 0);
    ASSERT_EQ(iec61850_rgoose_subscriber_process_spdu(&sub, spdu,
                                                      (size_t)len, 4U), 1);

    ASSERT_EQ(sub.total_replays, 2U);
    ASSERT_EQ(cb_count, 2);
    {
        const iec61850_rgoose_appid_state_t *as =
            iec61850_rgoose_subscriber_get_appid_state(&sub, 0x0002U);
        ASSERT_TRUE(as != NULL);
        ASSERT_EQ((uint32_t)as->last_spdu_number, 101U);
        ASSERT_TRUE(as->has_last_spdu);
        ASSERT_EQ((uint64_t)as->replay_drops, 2U);
    }
    ASSERT_TRUE(iec61850_rgoose_subscriber_get_appid_state(&sub, 0x9999U) ==
                NULL);
    PASS();
}

static void test_time_window(void)
{
    iec61850_rgoose_subscriber_t sub;
    iec61850_r_security_t sec;
    uint8_t spdu[512];
    int len;

    TEST("rgoose_time_window");
    iec61850_rgoose_subscriber_init(&sub, NULL);
    iec61850_rgoose_subscriber_set_callback(&sub, rgoose_test_cb, NULL);
    cb_reset();

    (void)memset(&sec, 0, sizeof(sec));
    sec.present = true;
    sec.signature_len = 0U; /* MACNone-style: no signature material */

    /* First message establishes the time reference. */
    sec.time_of_current_key = 1000000U;
    len = craft_spdu(spdu, sizeof(spdu), 0x0003U, 500U, 1U, 0U, &sec);
    ASSERT_TRUE(len > 0);
    ASSERT_EQ(iec61850_rgoose_subscriber_process_spdu(&sub, spdu,
                                                      (size_t)len, 1U), 1);

    /* Within the acceptance window: accepted. */
    sec.time_of_current_key = 1000000U + 5000U;
    len = craft_spdu(spdu, sizeof(spdu), 0x0003U, 501U, 1U, 1U, &sec);
    ASSERT_TRUE(len > 0);
    ASSERT_EQ(iec61850_rgoose_subscriber_process_spdu(&sub, spdu,
                                                      (size_t)len, 2U), 1);

    /* Far outside the window (half a day + 1 in the window's time
     * domain): rejected as a replay/stale message. */
    sec.time_of_current_key = 1000000U + 43200001U;
    len = craft_spdu(spdu, sizeof(spdu), 0x0003U, 502U, 1U, 2U, &sec);
    ASSERT_TRUE(len > 0);
    ASSERT_EQ(iec61850_rgoose_subscriber_process_spdu(&sub, spdu,
                                                      (size_t)len, 3U), 0);
    ASSERT_EQ(sub.total_security_failures, 1U);
    ASSERT_EQ(cb_count, 2);
    PASS();
}

static void test_subscriber_filters_and_timeouts(void)
{
    iec61850_rgoose_subscriber_t sub;
    iec61850_rgoose_sub_config_t cfg;
    uint8_t spdu[512];
    int len;

    TEST("rgoose_subscriber_filters_and_timeouts");
    iec61850_rgoose_sub_config_init(&cfg);
    cfg.filter_appid = 0x0004U;
    iec61850_rgoose_subscriber_init(&sub, &cfg);
    iec61850_rgoose_subscriber_set_callback(&sub, rgoose_test_cb, NULL);
    cb_reset();

    /* APPID filter: non-matching dropped. */
    len = craft_spdu(spdu, sizeof(spdu), 0x0005U, 1U, 1U, 0U, NULL);
    ASSERT_TRUE(len > 0);
    ASSERT_EQ(iec61850_rgoose_subscriber_process_spdu(&sub, spdu,
                                                      (size_t)len,
                                                      test_now_ns()), 0);
    /* Matching accepted. */
    len = craft_spdu(spdu, sizeof(spdu), 0x0004U, 1U, 1U, 0U, NULL);
    ASSERT_TRUE(len > 0);
    ASSERT_EQ(iec61850_rgoose_subscriber_process_spdu(&sub, spdu,
                                                      (size_t)len,
                                                      test_now_ns()), 1);

    /* gocbRef filter. */
    {
        iec61850_rgoose_subscriber_t sub2;
        iec61850_rgoose_sub_config_t cfg2;

        iec61850_rgoose_sub_config_init(&cfg2);
        (void)strncpy(cfg2.filter_gocbref, "OTHER/LLN0$GO$gcbXX",
                      sizeof(cfg2.filter_gocbref) - 1U);
        iec61850_rgoose_subscriber_init(&sub2, &cfg2);
        len = craft_spdu(spdu, sizeof(spdu), 0x0006U, 1U, 1U, 0U, NULL);
        ASSERT_TRUE(len > 0);
        ASSERT_EQ(iec61850_rgoose_subscriber_process_spdu(&sub2, spdu,
                                                          (size_t)len, 1U),
                  0);
    }

    /* Timeout tracking. */
    {
        uint64_t now = test_now_ns();

        ASSERT_EQ(iec61850_rgoose_subscriber_process_spdu(&sub, spdu,
                                                          (size_t)len, now),
                  0); /* duplicate: state already recorded */

        iec61850_rgoose_subscriber_check_timeouts(&sub, now + 1U);
        {
            const iec61850_rgoose_pub_state_t *ps =
                iec61850_rgoose_subscriber_get_pub_state(&sub, TEST_GOCBREF);
            ASSERT_TRUE(ps != NULL);
            ASSERT_TRUE(!ps->timeout_detected);
        }
        iec61850_rgoose_subscriber_check_timeouts(
            &sub, now + (uint64_t)sub.config.timeout_ms * 1000000ULL + 2U);
        {
            const iec61850_rgoose_pub_state_t *ps =
                iec61850_rgoose_subscriber_get_pub_state(&sub, TEST_GOCBREF);
            ASSERT_TRUE(ps != NULL);
            ASSERT_TRUE(ps->timeout_detected);
        }
        ASSERT_EQ(sub.total_timeouts, 1U);
    }

    iec61850_rgoose_subscriber_check_timeouts(NULL, 0U);
    PASS();
}

static void test_subscriber_error_paths(void)
{
    iec61850_rgoose_subscriber_t sub;
    static uint8_t spdu[512];
    uint8_t garbage[32];
    int len;

    TEST("rgoose_subscriber_error_paths");
    iec61850_rgoose_subscriber_init(&sub, NULL);
    iec61850_rgoose_subscriber_set_callback(&sub, NULL, NULL);
    iec61850_rgoose_subscriber_destroy(NULL);

    /* NULL / empty input. */
    ASSERT_EQ(iec61850_rgoose_subscriber_process_spdu(NULL, spdu, 4U, 0U),
              0);
    ASSERT_EQ(iec61850_rgoose_subscriber_process_spdu(&sub, NULL, 4U, 0U),
              0);
    ASSERT_EQ(iec61850_rgoose_subscriber_process_spdu(&sub, spdu, 0U, 0U),
              0);
    ASSERT_EQ(iec61850_rgoose_subscriber_process_frame(NULL, spdu, 4U, 0U),
              0);
    ASSERT_EQ(iec61850_rgoose_subscriber_poll(NULL, NULL), -EINVAL);

    /* Garbage / malformed SPDUs. */
    (void)memset(garbage, 0xFFU, sizeof(garbage));
    ASSERT_EQ(iec61850_rgoose_subscriber_process_spdu(&sub, garbage,
                                                      sizeof(garbage), 0U),
              0);
    len = craft_spdu(spdu, sizeof(spdu), 0x0001U, 1U, 1U, 0U, NULL);
    ASSERT_TRUE(len > 0);
    ASSERT_EQ(iec61850_rgoose_subscriber_process_spdu(&sub, spdu,
                                                      (size_t)len - 1U, 0U),
              0); /* truncated */
    ASSERT_EQ(iec61850_rgoose_subscriber_process_spdu(&sub, spdu, 2U, 0U),
              0); /* too short */

    /* A plain (non-secure) subscriber fed an IP frame: the SI byte
     * check rejects it. */
    ASSERT_EQ(iec61850_rgoose_subscriber_process_frame(&sub, garbage,
                                                       sizeof(garbage), 0U),
              0);
    PASS();
}

/* ------------------------------------------------------------------ */
/* Security: frame-level roundtrip + tamper matrix (no sockets)        */
/* ------------------------------------------------------------------ */

#ifdef IEC61850_SECURITY_ENABLED

static const uint8_t sec_key[16] = {
    0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U,
    0x99U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU, 0x00U
};
#define SEC_KEY_ID 0xCAFEBABEU

static void make_pub_sec(iec61850_rgoose_pub_security_t *s)
{
    (void)memset(s, 0, sizeof(*s));
    s->algo = (uint16_t)IEC61850_RGOOSE_PUB_SEC_ALGO_HMAC_SHA256;
    (void)memcpy(s->key, sec_key, sizeof(sec_key));
    s->key_len = sizeof(sec_key);
    s->key_id = SEC_KEY_ID;
    s->time_to_next_key = 720U;
}

static void make_sub_sec(iec61850_rgoose_sub_security_t *s)
{
    (void)memset(s, 0, sizeof(*s));
    s->algo = (uint16_t)IEC61850_RGOOSE_SUB_SEC_ALGO_HMAC_SHA256;
    (void)memcpy(s->key, sec_key, sizeof(sec_key));
    s->key_len = sizeof(sec_key);
    s->expected_key_id = SEC_KEY_ID;
}

static void test_enable_security_args(void)
{
    iec61850_rgoose_publisher_t pub;
    iec61850_rgoose_subscriber_t sub;
    iec61850_rgoose_pub_security_t ps;
    iec61850_rgoose_sub_security_t ss;

    TEST("rgoose_enable_security_args");
    iec61850_rgoose_publisher_init(&pub, NULL);
    iec61850_rgoose_subscriber_init(&sub, NULL);
    make_pub_sec(&ps);
    make_sub_sec(&ss);

    /* NULL arguments. */
    ASSERT_EQ(iec61850_rgoose_publisher_enable_security(NULL, &ps),
              -EINVAL);
    ASSERT_EQ(iec61850_rgoose_publisher_enable_security(&pub, NULL),
              -EINVAL);
    ASSERT_EQ(iec61850_rgoose_subscriber_enable_security(NULL, &ss),
              -EINVAL);
    ASSERT_EQ(iec61850_rgoose_subscriber_enable_security(&sub, NULL),
              -EINVAL);

    /* Bad key lengths. */
    {
        iec61850_rgoose_pub_security_t bad = ps;
        bad.key_len = 0U;
        ASSERT_EQ(iec61850_rgoose_publisher_enable_security(&pub, &bad),
                  -EINVAL);
        bad.key_len = (size_t)IEC61850_RGOOSE_SEC_KEY_MAX + 1U;
        ASSERT_EQ(iec61850_rgoose_publisher_enable_security(&pub, &bad),
                  -EINVAL);
    }
    {
        iec61850_rgoose_sub_security_t bad = ss;
        bad.key_len = 0U;
        ASSERT_EQ(iec61850_rgoose_subscriber_enable_security(&sub, &bad),
                  -EINVAL);
    }

    /* Unsupported publish algorithm. */
    {
        iec61850_rgoose_pub_security_t bad = ps;
        bad.algo = 0x8181U;
        ASSERT_EQ(iec61850_rgoose_publisher_enable_security(&pub, &bad),
                  -EINVAL);
    }
    /* AES-GMAC publish: supported since WP-3h (128/256-bit keys). */
    {
        iec61850_rgoose_pub_security_t gmac = ps;

        gmac.algo = (uint16_t)IEC61850_RGOOSE_PUB_SEC_ALGO_AES_GMAC;
        ASSERT_EQ(iec61850_rgoose_publisher_enable_security(&pub, &gmac), 0);
        gmac.key_len = 15U; /* not 128/256 bits */
        ASSERT_EQ(iec61850_rgoose_publisher_enable_security(&pub, &gmac),
                  -EINVAL);
        gmac.key_len = 24U;
        ASSERT_EQ(iec61850_rgoose_publisher_enable_security(&pub, &gmac),
                  -EINVAL);
    }
    /* Unknown subscriber algorithm. */
    {
        iec61850_rgoose_sub_security_t bad = ss;
        bad.algo = 0x9999U;
        ASSERT_EQ(iec61850_rgoose_subscriber_enable_security(&sub, &bad),
                  -EINVAL);
    }

    /* Valid enable on both ends. */
    ASSERT_EQ(iec61850_rgoose_publisher_enable_security(&pub, &ps), 0);
    ASSERT_TRUE(pub.security_enabled);
    ASSERT_EQ(iec61850_rgoose_subscriber_enable_security(&sub, &ss), 0);
    ASSERT_TRUE(sub.security_enabled);
    PASS();
}

/* Build one signed frame with the standard test security config. */
static int build_test_secure_frame(iec61850_rgoose_publisher_t *pub,
                                   uint8_t *frame, size_t cap,
                                   size_t *frame_len)
{
    iec61850_rgoose_pub_security_t ps;

    make_pub_sec(&ps);
    if (iec61850_rgoose_publisher_enable_security(pub, &ps) != 0) {
        return -1;
    }
    return iec61850_rgoose_publisher_build_frame(pub, frame, cap,
                                                 frame_len);
}

/* Same, with an explicit publish algorithm (HMAC-SHA256 / AES-GMAC). */
static int build_test_secure_frame_algo(iec61850_rgoose_publisher_t *pub,
                                        uint16_t algo, uint8_t *frame,
                                        size_t cap, size_t *frame_len)
{
    iec61850_rgoose_pub_security_t ps;

    make_pub_sec(&ps);
    ps.algo = algo;
    if (iec61850_rgoose_publisher_enable_security(pub, &ps) != 0) {
        return -1;
    }
    return iec61850_rgoose_publisher_build_frame(pub, frame, cap,
                                                 frame_len);
}

static void test_secure_frame_roundtrip(void)
{
    iec61850_rgoose_publisher_t pub;
    iec61850_rgoose_subscriber_t sub;
    iec61850_rgoose_sub_security_t ss;
    static uint8_t frame[IEC61850_RGOOSE_MAX_FRAME_LEN];
    size_t frame_len = 0U;
    int ret;

    TEST("rgoose_secure_frame_roundtrip");
    iec61850_rgoose_publisher_init(&pub, NULL);
    ASSERT_EQ(iec61850_rgoose_publisher_set_boolean(&pub, 0, true), 0);
    ASSERT_EQ(iec61850_rgoose_publisher_set_int32(&pub, 1, -321), 0);

    ret = build_test_secure_frame(&pub, frame, sizeof(frame), &frame_len);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(frame_len > (14U + 28U + 38U + 32U));

    /* Frame layout: [Eth][IPv4][UDP][SPDU]. */
    ASSERT_EQ((frame[12] << 8) | frame[13], 0x0800); /* EtherType IPv4 */
    ASSERT_EQ(frame[14] >> 4, 4);                    /* IPv4 */
    ASSERT_EQ(frame[14 + 9], 17);                    /* UDP */
    ASSERT_TRUE(frame[14 + 26] == 0U && frame[14 + 27] == 0U); /* cksum 0 */
    ASSERT_EQ(frame[14 + 28], 0xA1);                 /* SPDU SI */
    /* SPDU Number at SPDU offset 8. */
    ASSERT_EQ(((uint32_t)frame[14 + 28 + 8] << 24) |
              ((uint32_t)frame[14 + 28 + 9] << 16) |
              ((uint32_t)frame[14 + 28 + 10] << 8) |
              (uint32_t)frame[14 + 28 + 11], 0U);

    /* Verify via a fresh secure subscriber. */
    make_sub_sec(&ss);
    iec61850_rgoose_subscriber_init(&sub, NULL);
    iec61850_rgoose_subscriber_set_callback(&sub, rgoose_test_cb, NULL);
    ASSERT_EQ(iec61850_rgoose_subscriber_enable_security(&sub, &ss), 0);
    cb_reset();

    ASSERT_EQ(iec61850_rgoose_subscriber_process_frame(&sub, frame,
                                                       frame_len,
                                                       test_now_ns()), 1);
    ASSERT_EQ(cb_count, 1);
    ASSERT_TRUE(cb_last_msg.is_new_state);
    ASSERT_TRUE(cb_last_msg.header.security.present);
    ASSERT_EQ(cb_last_msg.header.security.key_id, SEC_KEY_ID);
    ASSERT_EQ(cb_last_msg.header.security.signature_len, 32U);
    ASSERT_TRUE(cb_last_msg.header.security.time_of_current_key != 0U);
    ASSERT_EQ((uint32_t)cb_last_msg.apdu.numDatSetEntries, 2U);

    /* The APDU payload survived the roundtrip. */
    ASSERT_EQ(cb_last_msg.apdu.allData[0].type, GOOSE_DATA_BOOLEAN);
    ASSERT_TRUE(cb_last_msg.apdu.allData[0].value.boolean == true);
    ASSERT_EQ(cb_last_msg.apdu.allData[1].type, GOOSE_DATA_INT32);
    ASSERT_EQ(cb_last_msg.apdu.allData[1].value.int32, -321);

    /* Second publish (new spdu_number) verifies and is delivered. */
    ret = iec61850_rgoose_publisher_build_frame(&pub, frame,
                                                sizeof(frame), &frame_len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(iec61850_rgoose_subscriber_process_frame(&sub, frame,
                                                       frame_len,
                                                       test_now_ns()), 1);
    ASSERT_EQ(cb_count, 2);
    ASSERT_EQ(sub.total_security_failures, 0U);
    PASS();
}

/* Tamper matrix: every signed region must break verification. */
static void test_secure_tamper_matrix(void)
{
    iec61850_rgoose_publisher_t pub;
    iec61850_rgoose_subscriber_t sub;
    iec61850_rgoose_sub_security_t ss;
    static uint8_t frame[IEC61850_RGOOSE_MAX_FRAME_LEN];
    static uint8_t bad[IEC61850_RGOOSE_MAX_FRAME_LEN];
    size_t frame_len = 0U;
    size_t bad_len;
    int ret;

    TEST("rgoose_secure_tamper_matrix");
    iec61850_rgoose_publisher_init(&pub, NULL);
    ASSERT_EQ(iec61850_rgoose_publisher_set_boolean(&pub, 0, true), 0);
    ret = build_test_secure_frame(&pub, frame, sizeof(frame), &frame_len);
    ASSERT_EQ(ret, 0);

    make_sub_sec(&ss);
    iec61850_rgoose_subscriber_init(&sub, NULL);
    iec61850_rgoose_subscriber_set_callback(&sub, rgoose_test_cb, NULL);
    ASSERT_EQ(iec61850_rgoose_subscriber_enable_security(&sub, &ss), 0);
    cb_reset();

    /* Sanity: the untampered frame is accepted. */
    ASSERT_EQ(iec61850_rgoose_subscriber_process_frame(&sub, frame,
                                                       frame_len, 1U), 1);
    ASSERT_EQ(cb_count, 1);

    /* Each tamper case: flip one bit in the region, expect rejection
     * and no callback.  Offsets: Eth(14) IP(20) UDP(8) SPDU. */
    {
        struct {
            const char *region;
            size_t offset;
        } cases[] = {
            { "IP header (TTL)",            14U + 8U },
            { "IP header (src addr)",       14U + 12U },
            { "UDP header (src port)",      14U + 20U },
            { "UDP header (dst port)",      14U + 22U },
            { "UDP header (length)",        14U + 24U },
            { "SPDU header (SPDU number)",  14U + 28U + 8U },
            { "SPDU security (key id)",     14U + 28U + 22U },
            { "APDU payload (last byte)",   frame_len - 35U },
            { "Signature TLV (tag)",        frame_len - 34U },
            { "Signature value (last byte)", frame_len - 1U },
        };
        const size_t n = sizeof(cases) / sizeof(cases[0]);

        for (size_t i = 0U; i < n; i++) {
            uint64_t fails_before = sub.total_security_failures;

            (void)memcpy(bad, frame, frame_len);
            bad[cases[i].offset] ^= 0x01U;
            bad_len = frame_len;

            ASSERT_EQ(iec61850_rgoose_subscriber_process_frame(
                          &sub, bad, bad_len, (uint64_t)(i + 2U)), 0);
            if (sub.total_security_failures == fails_before) {
                printf("region not rejected: %s\n", cases[i].region);
                FAIL("tampered frame accepted");
            }
        }
        ASSERT_EQ(cb_count, 1); /* no additional deliveries */
    }

    /* Truncated frame. */
    ASSERT_EQ(iec61850_rgoose_subscriber_process_frame(&sub, frame,
                                                       frame_len - 1U, 99U),
              0);
    /* Garbage frame. */
    {
        static uint8_t garbage[64];

        (void)memset(garbage, 0x5AU, sizeof(garbage));
        ASSERT_EQ(iec61850_rgoose_subscriber_process_frame(&sub, garbage,
                                                           sizeof(garbage),
                                                           99U), 0);
    }
    PASS();
}

static void test_secure_key_id_and_bypass(void)
{
    iec61850_rgoose_publisher_t pub;
    iec61850_rgoose_subscriber_t sub;
    iec61850_rgoose_sub_security_t ss;
    static uint8_t frame[IEC61850_RGOOSE_MAX_FRAME_LEN];
    uint8_t spdu[IEC61850_RGOOSE_MAX_SPDU_LEN];
    size_t frame_len = 0U;
    size_t spdu_len = 0U;
    int ret;

    TEST("rgoose_secure_key_id_and_bypass");
    iec61850_rgoose_publisher_init(&pub, NULL);
    ret = build_test_secure_frame(&pub, frame, sizeof(frame), &frame_len);
    ASSERT_EQ(ret, 0);

    /* Key-id mismatch: rejected. */
    make_sub_sec(&ss);
    ss.expected_key_id = SEC_KEY_ID + 1U;
    iec61850_rgoose_subscriber_init(&sub, NULL);
    ASSERT_EQ(iec61850_rgoose_subscriber_enable_security(&sub, &ss), 0);
    ASSERT_EQ(iec61850_rgoose_subscriber_process_frame(&sub, frame,
                                                       frame_len, 1U), 0);
    ASSERT_EQ(sub.total_security_failures, 1U);

    /* expected_key_id == 0 accepts any: accepted. */
    ss.expected_key_id = 0U;
    iec61850_rgoose_subscriber_init(&sub, NULL);
    ASSERT_EQ(iec61850_rgoose_subscriber_enable_security(&sub, &ss), 0);
    ASSERT_EQ(iec61850_rgoose_subscriber_process_frame(&sub, frame,
                                                       frame_len, 2U), 1);

    /* A secure subscriber fed a BARE spdu (bypass attempt): the
     * security extension is missing and process_spdu refuses to run
     * for secure subscribers. */
    iec61850_rgoose_publisher_init(&pub, NULL);
    ASSERT_EQ(iec61850_rgoose_publisher_build_spdu(&pub, spdu,
                                                   sizeof(spdu), &spdu_len),
              0);
    ASSERT_EQ(iec61850_rgoose_subscriber_process_spdu(&sub, spdu,
                                                      spdu_len, 3U), 0);

    /* Secure subscriber fed an unsigned frame (plain SPDU wrapped in
     * IP/UDP): security extension missing → rejected. */
    {
        static uint8_t plain_frame[IEC61850_RGOOSE_MAX_FRAME_LEN];
        size_t plain_len = 0U;
        int r = iec61850_ip_udp_build(&plain_frame[14],
                                      sizeof(plain_frame) - 14U,
                                      "127.0.0.1", "127.0.0.1", 102U, 102U,
                                      spdu, spdu_len, 17U);
        ASSERT_EQ(r, 0);
        (void)memcpy(plain_frame, frame, 14U); /* reuse Ethernet header */
        plain_len = 14U + 28U + spdu_len;
        ASSERT_EQ(iec61850_rgoose_subscriber_process_frame(&sub,
                                                           plain_frame,
                                                           plain_len, 4U), 0);
    }

    /* Port filter (secure mode only). */
    {
        iec61850_rgoose_subscriber_t sub2;
        iec61850_rgoose_sub_config_t cfg;

        iec61850_rgoose_sub_config_init(&cfg);
        cfg.filter_port = 9999U;
        iec61850_rgoose_subscriber_init(&sub2, &cfg);
        make_sub_sec(&ss);
        ASSERT_EQ(iec61850_rgoose_subscriber_enable_security(&sub2, &ss), 0);
        ASSERT_EQ(iec61850_rgoose_subscriber_process_frame(&sub2, frame,
                                                           frame_len, 5U),
                  0);
    }
    PASS();
}

/* ------------------------------------------------------------------ */
/* AES-GMAC (WP-3h): frame-level roundtrip, tamper matrix, key-id and  */
/* mixed-algorithm rejection                                           */
/* ------------------------------------------------------------------ */

static void test_gmac_frame_roundtrip(void)
{
    iec61850_rgoose_publisher_t pub;
    iec61850_rgoose_subscriber_t sub;
    iec61850_rgoose_sub_security_t ss;
    static uint8_t frame[IEC61850_RGOOSE_MAX_FRAME_LEN];
    static uint8_t hmac_frame[IEC61850_RGOOSE_MAX_FRAME_LEN];
    size_t frame_len = 0U;
    size_t hmac_len = 0U;
    int ret;

    TEST("rgoose_gmac_frame_roundtrip");
    iec61850_rgoose_publisher_init(&pub, NULL);
    ASSERT_EQ(iec61850_rgoose_publisher_set_boolean(&pub, 0, true), 0);
    ASSERT_EQ(iec61850_rgoose_publisher_set_int32(&pub, 1, -321), 0);

    ret = build_test_secure_frame_algo(
        &pub, (uint16_t)IEC61850_RGOOSE_PUB_SEC_ALGO_AES_GMAC,
        frame, sizeof(frame), &frame_len);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(frame_len > (14U + 28U + 38U + 16U));

    /* The 16-byte GMAC tag TLV is exactly 16 octets shorter than the
     * 32-byte HMAC signature TLV (identical SPDU otherwise: compare
     * against an HMAC frame built from an identical fresh publisher). */
    {
        iec61850_rgoose_publisher_t pub2;

        iec61850_rgoose_publisher_init(&pub2, NULL);
        ASSERT_EQ(iec61850_rgoose_publisher_set_boolean(&pub2, 0, true), 0);
        ASSERT_EQ(iec61850_rgoose_publisher_set_int32(&pub2, 1, -321), 0);
        ret = build_test_secure_frame(&pub2, hmac_frame,
                                      sizeof(hmac_frame), &hmac_len);
        ASSERT_EQ(ret, 0);
        ASSERT_EQ(frame_len + 16U, hmac_len);
    }

    /* Frame layout: [Eth][IPv4][UDP][SPDU + 0x85 TLV (16)]. */
    ASSERT_EQ(frame[14] >> 4, 4);                    /* IPv4 */
    ASSERT_EQ(frame[14 + 9], 17);                    /* UDP */
    ASSERT_EQ(frame[frame_len - 18U], 0x85U);        /* sig TLV tag */
    ASSERT_EQ(frame[frame_len - 17U], 16U);          /* sig TLV length */
    {
        int tag_nonzero = 0;

        for (size_t i = frame_len - 16U; i < frame_len; i++) {
            if (frame[i] != 0U) {
                tag_nonzero = 1;
            }
        }
        ASSERT_TRUE(tag_nonzero == 1); /* not the zeroed placeholder */
    }

    /* Verify via a fresh GMAC subscriber. */
    make_sub_sec(&ss);
    ss.algo = (uint16_t)IEC61850_RGOOSE_SUB_SEC_ALGO_AES_GMAC;
    iec61850_rgoose_subscriber_init(&sub, NULL);
    iec61850_rgoose_subscriber_set_callback(&sub, rgoose_test_cb, NULL);
    ASSERT_EQ(iec61850_rgoose_subscriber_enable_security(&sub, &ss), 0);
    cb_reset();

    ASSERT_EQ(iec61850_rgoose_subscriber_process_frame(&sub, frame,
                                                       frame_len,
                                                       test_now_ns()), 1);
    ASSERT_EQ(cb_count, 1);
    ASSERT_TRUE(cb_last_msg.is_new_state);
    ASSERT_TRUE(cb_last_msg.header.security.present);
    ASSERT_EQ(cb_last_msg.header.security.key_id, SEC_KEY_ID);
    ASSERT_EQ(cb_last_msg.header.security.signature_len, 16U);
    ASSERT_EQ((uint32_t)cb_last_msg.apdu.numDatSetEntries, 2U);
    ASSERT_TRUE(cb_last_msg.apdu.allData[0].value.boolean == true);
    ASSERT_EQ(cb_last_msg.apdu.allData[1].value.int32, -321);

    /* Second publish (new spdu_number → new IV) verifies and is
     * delivered. */
    ret = iec61850_rgoose_publisher_build_frame(&pub, frame,
                                                sizeof(frame), &frame_len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(iec61850_rgoose_subscriber_process_frame(&sub, frame,
                                                       frame_len,
                                                       test_now_ns()), 1);
    ASSERT_EQ(cb_count, 2);
    ASSERT_EQ(sub.total_security_failures, 0U);
    PASS();
}

/* GMAC tamper matrix: every signed region must break verification. */
static void test_gmac_tamper_matrix(void)
{
    iec61850_rgoose_publisher_t pub;
    iec61850_rgoose_subscriber_t sub;
    iec61850_rgoose_sub_security_t ss;
    static uint8_t frame[IEC61850_RGOOSE_MAX_FRAME_LEN];
    static uint8_t bad[IEC61850_RGOOSE_MAX_FRAME_LEN];
    size_t frame_len = 0U;
    size_t bad_len;
    int ret;

    TEST("rgoose_gmac_tamper_matrix");
    iec61850_rgoose_publisher_init(&pub, NULL);
    ASSERT_EQ(iec61850_rgoose_publisher_set_boolean(&pub, 0, true), 0);
    ret = build_test_secure_frame_algo(
        &pub, (uint16_t)IEC61850_RGOOSE_PUB_SEC_ALGO_AES_GMAC,
        frame, sizeof(frame), &frame_len);
    ASSERT_EQ(ret, 0);

    make_sub_sec(&ss);
    ss.algo = (uint16_t)IEC61850_RGOOSE_SUB_SEC_ALGO_AES_GMAC;
    iec61850_rgoose_subscriber_init(&sub, NULL);
    iec61850_rgoose_subscriber_set_callback(&sub, rgoose_test_cb, NULL);
    ASSERT_EQ(iec61850_rgoose_subscriber_enable_security(&sub, &ss), 0);
    cb_reset();

    /* Sanity: the untampered frame is accepted. */
    ASSERT_EQ(iec61850_rgoose_subscriber_process_frame(&sub, frame,
                                                       frame_len, 1U), 1);
    ASSERT_EQ(cb_count, 1);

    /* Offsets: Eth(14) IP(20) UDP(8) SPDU, signature TLV = final
     * 2 + 16 octets. */
    {
        struct {
            const char *region;
            size_t offset;
        } cases[] = {
            { "IP header (TTL)",             14U + 8U },
            { "IP header (src addr)",        14U + 12U },
            { "UDP header (src port)",       14U + 20U },
            { "UDP header (dst port)",       14U + 22U },
            { "UDP header (length)",         14U + 24U },
            { "SPDU header (SPDU number)",   14U + 28U + 8U },
            { "SPDU security (key id)",      14U + 28U + 22U },
            { "APDU payload (last byte)",    frame_len - 19U },
            { "Signature TLV (tag)",         frame_len - 18U },
            { "Signature TLV (length)",      frame_len - 17U },
            { "Signature value (last byte)", frame_len - 1U },
        };
        const size_t n = sizeof(cases) / sizeof(cases[0]);

        for (size_t i = 0U; i < n; i++) {
            uint64_t fails_before = sub.total_security_failures;

            (void)memcpy(bad, frame, frame_len);
            bad[cases[i].offset] ^= 0x01U;
            bad_len = frame_len;

            ASSERT_EQ(iec61850_rgoose_subscriber_process_frame(
                          &sub, bad, bad_len, (uint64_t)(i + 2U)), 0);
            if (sub.total_security_failures == fails_before) {
                printf("region not rejected: %s\n", cases[i].region);
                FAIL("tampered frame accepted");
            }
        }
        ASSERT_EQ(cb_count, 1); /* no additional deliveries */
    }

    /* Truncated frame. */
    ASSERT_EQ(iec61850_rgoose_subscriber_process_frame(&sub, frame,
                                                       frame_len - 1U, 99U),
              0);
    PASS();
}

/* GMAC key-id mismatch and mixed HMAC/GMAC algorithm rejection. */
static void test_gmac_key_id_and_mixed(void)
{
    iec61850_rgoose_publisher_t pub;
    iec61850_rgoose_subscriber_t sub;
    iec61850_rgoose_sub_security_t ss;
    static uint8_t gmac_frame[IEC61850_RGOOSE_MAX_FRAME_LEN];
    static uint8_t hmac_frame[IEC61850_RGOOSE_MAX_FRAME_LEN];
    size_t gmac_len = 0U;
    size_t hmac_len = 0U;
    int ret;

    TEST("rgoose_gmac_key_id_and_mixed");

    iec61850_rgoose_publisher_init(&pub, NULL);
    ret = build_test_secure_frame_algo(
        &pub, (uint16_t)IEC61850_RGOOSE_PUB_SEC_ALGO_AES_GMAC,
        gmac_frame, sizeof(gmac_frame), &gmac_len);
    ASSERT_EQ(ret, 0);
    ret = build_test_secure_frame_algo(
        &pub, (uint16_t)IEC61850_RGOOSE_PUB_SEC_ALGO_HMAC_SHA256,
        hmac_frame, sizeof(hmac_frame), &hmac_len);
    ASSERT_EQ(ret, 0);

    /* Key-id mismatch on a GMAC frame: rejected. */
    make_sub_sec(&ss);
    ss.algo = (uint16_t)IEC61850_RGOOSE_SUB_SEC_ALGO_AES_GMAC;
    ss.expected_key_id = SEC_KEY_ID + 1U;
    iec61850_rgoose_subscriber_init(&sub, NULL);
    ASSERT_EQ(iec61850_rgoose_subscriber_enable_security(&sub, &ss), 0);
    ASSERT_EQ(iec61850_rgoose_subscriber_process_frame(&sub, gmac_frame,
                                                       gmac_len, 1U), 0);
    ASSERT_EQ(sub.total_security_failures, 1U);

    /* HMAC-signed frame against a GMAC-configured subscriber: the
     * 32-octet HMAC signature cannot be a 16-octet GMAC tag —
     * rejected. */
    make_sub_sec(&ss);
    ss.algo = (uint16_t)IEC61850_RGOOSE_SUB_SEC_ALGO_AES_GMAC;
    iec61850_rgoose_subscriber_init(&sub, NULL);
    ASSERT_EQ(iec61850_rgoose_subscriber_enable_security(&sub, &ss), 0);
    ASSERT_EQ(iec61850_rgoose_subscriber_process_frame(&sub, hmac_frame,
                                                       hmac_len, 2U), 0);
    ASSERT_EQ(sub.total_security_failures, 1U);

    /* GMAC-signed frame against an HMAC-configured subscriber: the
     * signature length (16) is not the HMAC length (32) — rejected. */
    make_sub_sec(&ss);
    ss.algo = (uint16_t)IEC61850_RGOOSE_SUB_SEC_ALGO_HMAC_SHA256;
    iec61850_rgoose_subscriber_init(&sub, NULL);
    ASSERT_EQ(iec61850_rgoose_subscriber_enable_security(&sub, &ss), 0);
    ASSERT_EQ(iec61850_rgoose_subscriber_process_frame(&sub, gmac_frame,
                                                       gmac_len, 3U), 0);
    ASSERT_EQ(sub.total_security_failures, 1U);
    PASS();
}

/* Re-sign a (locally modified) received frame with the test key —
 * whitebox helper for window/replay tests on the secure path. */
static int resign_frame(uint8_t *frame, size_t frame_len)
{
    uint8_t sig[32];

    /* Signature value is the final 32 bytes of the SPDU. */
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
    iec61850_rgoose_publisher_t pub;
    iec61850_rgoose_subscriber_t sub;
    iec61850_rgoose_sub_security_t ss;
    static uint8_t frame[IEC61850_RGOOSE_MAX_FRAME_LEN];
    size_t frame_len = 0U;
    uint32_t t_ref;
    int ret;

    TEST("rgoose_secure_time_window");
    iec61850_rgoose_publisher_init(&pub, NULL);
    ret = build_test_secure_frame(&pub, frame, sizeof(frame), &frame_len);
    ASSERT_EQ(ret, 0);

    make_sub_sec(&ss);
    iec61850_rgoose_subscriber_init(&sub, NULL);
    iec61850_rgoose_subscriber_set_callback(&sub, rgoose_test_cb, NULL);
    ASSERT_EQ(iec61850_rgoose_subscriber_enable_security(&sub, &ss), 0);
    cb_reset();

    /* Original frame accepted (establishes the time reference). */
    ASSERT_EQ(iec61850_rgoose_subscriber_process_frame(&sub, frame,
                                                       frame_len, 1U), 1);
    ASSERT_EQ(cb_count, 1);
    t_ref = cb_last_msg.header.security.time_of_current_key;

    /* Second frame: fresh SPDU number (so the session replay check
     * does not mask the window check), Time-of-Current-Key field
     * (SPDU offset 14 = frame offset 14+28+14) moved far outside the
     * window, then re-signed — must be rejected by the window check
     * despite the valid signature. */
    ret = iec61850_rgoose_publisher_build_frame(&pub, frame,
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
        ASSERT_EQ(iec61850_rgoose_subscriber_process_frame(&sub, frame,
                                                           frame_len, 2U),
                  0);
        ASSERT_EQ(cb_count, 1);
        ASSERT_EQ(sub.total_security_failures, 1U);
    }

    /* Control: the same second frame re-signed WITHOUT moving the
     * time field is accepted (fresh spdu_number, valid signature,
     * time within the window). */
    ret = iec61850_rgoose_publisher_build_frame(&pub, frame,
                                                sizeof(frame), &frame_len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(resign_frame(frame, frame_len), 0);
    ASSERT_EQ(iec61850_rgoose_subscriber_process_frame(&sub, frame,
                                                       frame_len, 3U), 1);
    ASSERT_EQ(cb_count, 2);
    PASS();
}

static void test_secure_frame_build_errors(void)
{
    iec61850_rgoose_publisher_t pub;
    iec61850_rgoose_pub_security_t ps;
    static uint8_t frame[IEC61850_RGOOSE_MAX_FRAME_LEN];
    size_t frame_len = 0U;

    TEST("rgoose_secure_frame_build_errors");
    iec61850_rgoose_publisher_init(&pub, NULL);
    make_pub_sec(&ps);
    ASSERT_EQ(iec61850_rgoose_publisher_enable_security(&pub, &ps), 0);

    /* Undersized output buffer. */
    ASSERT_EQ(iec61850_rgoose_publisher_build_frame(&pub, frame, 100U,
                                                    &frame_len), -ENOSPC);
    /* Argument errors. */
    ASSERT_EQ(iec61850_rgoose_publisher_build_frame(NULL, frame,
                                                    sizeof(frame),
                                                    &frame_len), -EINVAL);
    ASSERT_EQ(iec61850_rgoose_publisher_build_frame(&pub, NULL,
                                                    sizeof(frame),
                                                    &frame_len), -EINVAL);
    ASSERT_EQ(iec61850_rgoose_publisher_build_frame(&pub, frame,
                                                    sizeof(frame), NULL),
              -EINVAL);
    /* publish() without io. */
    ASSERT_EQ(iec61850_rgoose_publisher_publish(&pub), -EINVAL);
    /* Retransmission service without io (due after state change). */
    iec61850_rgoose_publisher_state_change(&pub);
    ASSERT_EQ(iec61850_rgoose_publisher_retransmit(&pub), -EINVAL);
    ASSERT_EQ(iec61850_rgoose_publisher_retransmit(NULL), -EINVAL);
    PASS();
}

static void test_retransmit_scheduling(void)
{
    iec61850_rgoose_publisher_t pub;
    iec61850_retransmit_config_t cfg;

    TEST("rgoose_retransmit_scheduling");
    iec61850_rgoose_publisher_init(&pub, NULL);

    /* Default ON; not due immediately after init (interval at max
     * from the L2 scheduler's init). */
    ASSERT_TRUE(pub.has_retransmit);
    ASSERT_EQ(iec61850_rgoose_publisher_retransmit(&pub), -EINVAL);

    /* Custom config. */
    cfg.t0_ms = 1U;
    cfg.t_max_ms = 8U;
    iec61850_rgoose_publisher_enable_retransmit(&pub, &cfg);
    ASSERT_EQ(iec61850_retransmit_get_interval_ms(&pub.retransmit), 8U);

    /* state_change makes the schedule due immediately. */
    iec61850_rgoose_publisher_state_change(&pub);
    ASSERT_TRUE(iec61850_retransmit_is_rapid(&pub.retransmit));

    /* Disabled: retransmit() is a no-op returning 0. */
    iec61850_rgoose_publisher_disable_retransmit(&pub);
    ASSERT_EQ(iec61850_rgoose_publisher_retransmit(&pub), 0U);
    PASS();
}

#endif /* IEC61850_SECURITY_ENABLED */

/* ------------------------------------------------------------------ */
/* Plain-mode socket loopback over 127.0.0.1 (UDP backend)             */
/* ------------------------------------------------------------------ */

static void test_plain_socket_loopback(void)
{
    iec61850_rgoose_pub_config_t pcfg;
    iec61850_rgoose_sub_config_t scfg;
    iec61850_rgoose_publisher_t pub;
    iec61850_rgoose_subscriber_t sub;
    struct packet_io *tx;
    struct packet_io *rx;
    static uint8_t spdu[IEC61850_RGOOSE_MAX_SPDU_LEN];
    size_t spdu_len = 0U;

    TEST("rgoose_plain_socket_loopback");

    iec61850_rgoose_pub_config_init(&pcfg);
    pcfg.dst_port = (uint16_t)PORT_RGOOSE;
    iec61850_rgoose_publisher_init(&pub, &pcfg);
    ASSERT_EQ(iec61850_rgoose_publisher_set_boolean(&pub, 0, true), 0);

    iec61850_rgoose_sub_config_init(&scfg);
    scfg.timeout_ms = 30000U;
    iec61850_rgoose_subscriber_init(&sub, &scfg);
    iec61850_rgoose_subscriber_set_callback(&sub, rgoose_test_cb, NULL);
    cb_reset();

    tx = packet_io_create_udp_sender("127.0.0.1", (uint16_t)PORT_RGOOSE,
                                     false);
    rx = packet_io_create_udp_receiver((uint16_t)PORT_RGOOSE, NULL);
    ASSERT_TRUE(tx != NULL);
    ASSERT_TRUE(rx != NULL);
    ASSERT_EQ(packet_io_open(rx, NULL, 0), 0);
    ASSERT_EQ(packet_io_open(tx, NULL, 0), 0);

    iec61850_rgoose_publisher_set_io(&pub, tx);

    /* Nothing queued yet. */
    ASSERT_EQ(iec61850_rgoose_subscriber_poll(&sub, rx), 0);

    /* Publish → poll → callback delivery. */
    ASSERT_EQ(iec61850_rgoose_publisher_publish(&pub), 0);
    ASSERT_EQ(iec61850_rgoose_subscriber_poll(&sub, rx), 1);
    ASSERT_EQ(cb_count, 1);
    ASSERT_TRUE(cb_last_msg.is_new_state);
    ASSERT_EQ(cb_last_msg.header.appid, pcfg.appid);
    ASSERT_EQ(cb_last_msg.header.spdu_number, 0U);

    /* Second publish: same state, higher sqNum → retransmission. */
    ASSERT_EQ(iec61850_rgoose_publisher_publish(&pub), 0);
    ASSERT_EQ(iec61850_rgoose_subscriber_poll(&sub, rx), 1);
    ASSERT_EQ(cb_count, 2);
    ASSERT_TRUE(cb_last_msg.is_retransmission);

    /* State change → new state. */
    iec61850_rgoose_publisher_state_change(&pub);
    ASSERT_EQ(iec61850_rgoose_publisher_publish(&pub), 0);
    ASSERT_EQ(iec61850_rgoose_subscriber_poll(&sub, rx), 1);
    ASSERT_EQ(cb_count, 3);
    ASSERT_TRUE(cb_last_msg.is_new_state);

    /* Replay detection: capture one SPDU and send it twice. */
    ASSERT_EQ(iec61850_rgoose_publisher_build_spdu(&pub, spdu,
                                                   sizeof(spdu),
                                                   &spdu_len), 0);
    ASSERT_EQ(packet_io_send(tx, spdu, (uint32_t)spdu_len), 0);
    ASSERT_EQ(iec61850_rgoose_subscriber_poll(&sub, rx), 1);
    ASSERT_EQ(packet_io_send(tx, spdu, (uint32_t)spdu_len), 0);
    ASSERT_EQ(iec61850_rgoose_subscriber_poll(&sub, rx), 0);
    ASSERT_EQ(sub.total_replays, 1U);

    /* Timeout: no message for > timeout_ms. */
    {
        uint64_t now = test_now_ns();

        iec61850_rgoose_subscriber_check_timeouts(
            &sub, now + (uint64_t)scfg.timeout_ms * 1000000ULL + 1U);
        {
            const iec61850_rgoose_pub_state_t *ps =
                iec61850_rgoose_subscriber_get_pub_state(&sub, TEST_GOCBREF);
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
 * Secure-mode raw-frame loopback on lo.  AF_PACKET SOCK_RAW requires
 * CAP_NET_RAW: when the environment does not permit it the test
 * skips (frame-level security coverage is provided by
 * test_secure_frame_roundtrip / test_secure_tamper_matrix above).
 */
static void test_secure_socket_loopback(void)
{
    iec61850_rgoose_pub_config_t pcfg;
    iec61850_rgoose_sub_config_t scfg;
    iec61850_rgoose_publisher_t pub;
    iec61850_rgoose_subscriber_t sub;
    iec61850_rgoose_pub_security_t ps;
    iec61850_rgoose_sub_security_t ss;
    struct packet_io *tx;
    struct packet_io *rx;
    int ret;
    int got = 0;

    TEST("rgoose_secure_socket_loopback");

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

    iec61850_rgoose_pub_config_init(&pcfg);
    iec61850_rgoose_publisher_init(&pub, &pcfg);
    ASSERT_EQ(iec61850_rgoose_publisher_set_boolean(&pub, 0, true), 0);
    make_pub_sec(&ps);
    ASSERT_EQ(iec61850_rgoose_publisher_enable_security(&pub, &ps), 0);
    iec61850_rgoose_publisher_set_io(&pub, tx);

    iec61850_rgoose_sub_config_init(&scfg);
    iec61850_rgoose_subscriber_init(&sub, &scfg);
    iec61850_rgoose_subscriber_set_callback(&sub, rgoose_test_cb, NULL);
    make_sub_sec(&ss);
    ASSERT_EQ(iec61850_rgoose_subscriber_enable_security(&sub, &ss), 0);
    cb_reset();

    ASSERT_EQ(iec61850_rgoose_publisher_publish(&pub), 0);

    /* The raw socket on lo sees all loopback traffic; poll until our
     * frame is delivered and verified (or give up). */
    for (int i = 0; (i < 200) && (got == 0); i++) {
        int r = iec61850_rgoose_subscriber_poll(&sub, rx);

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
    iec61850_rgoose_publisher_t pub;
    iec61850_rgoose_subscriber_t sub;
    iec61850_rgoose_pub_security_t ps;
    iec61850_rgoose_sub_security_t ss;

    TEST("rgoose_notsup_without_security");
    iec61850_rgoose_publisher_init(&pub, NULL);
    iec61850_rgoose_subscriber_init(&sub, NULL);
    (void)memset(&ps, 0, sizeof(ps));
    ps.algo = (uint16_t)IEC61850_RGOOSE_PUB_SEC_ALGO_HMAC_SHA256;
    ps.key_len = 16U;
    (void)memset(&ss, 0, sizeof(ss));
    ss.algo = (uint16_t)IEC61850_RGOOSE_SUB_SEC_ALGO_HMAC_SHA256;
    ss.key_len = 16U;

    ASSERT_EQ(iec61850_rgoose_publisher_enable_security(&pub, &ps),
              -ENOTSUP);
    ASSERT_EQ(iec61850_rgoose_subscriber_enable_security(&sub, &ss),
              -ENOTSUP);
    ASSERT_TRUE(!pub.security_enabled);
    ASSERT_TRUE(!sub.security_enabled);
    PASS();
}
#endif

int main(void)
{
    printf("=== R-GOOSE Publisher/Subscriber Unit Tests ===\n");

    test_config_defaults();
    test_publisher_lifecycle();
    test_dataset_setters();
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
    test_gmac_frame_roundtrip();
    test_gmac_tamper_matrix();
    test_gmac_key_id_and_mixed();
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
