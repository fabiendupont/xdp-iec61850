/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * test_ed2_conformance.c — Ed.2 conformance flag tests.
 *
 * Frame-level simulation bit (reserved1 LSB) round-trip through the
 * frame builder/parser for GOOSE and SV, subscriber filtering
 * (simulated frames rejected by default; test-mode frames flagged),
 * PDU test-bit publication, and the PTP->TimeQuality wiring.
 */

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>

#include "transport/eth_frame.h"
#include "transport/ptp_clock.h"
#include "goose/goose_publisher.h"
#include "goose/goose_subscriber.h"
#include "sv/sv_publisher.h"
#include "sv/sv_subscriber.h"

static int tests_run, tests_passed, tests_failed;

#define TEST(name) do { tests_run++; printf("  %-52s ", name); } while (0)
#define OK() do { tests_passed++; printf("PASS\n"); } while (0)
#define NO(msg) do { tests_failed++; printf("FAIL: %s\n", msg); } while (0)

static const uint8_t DST[6] = {0x01, 0x0C, 0xCD, 0x01, 0x00, 0x01};
static const uint8_t SRC[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x01};

static void test_frame_sim_bit(void)
{
    uint8_t frame[256];
    size_t frame_len = 0;
    iec61850_eth_frame_config_t fcfg = {0};
    memcpy(fcfg.dst_mac, DST, 6);
    memcpy(fcfg.src_mac, SRC, 6);
    fcfg.ethertype = 0x88B8;
    fcfg.app_id = 0x0001;

    uint16_t et, aid, vid;
    const uint8_t *apdu;
    size_t apdu_len, apdu_off;
    bool sim = false;

    TEST("simulation bit round-trips through the frame layer");
    fcfg.simulation = true;
    int n = iec61850_eth_frame_build(frame, sizeof(frame), &fcfg,
                                     (const uint8_t *)"APDU", 4, &frame_len);
    int p = iec61850_eth_frame_parse(frame, frame_len, &et, &aid,
                                     &vid, &apdu, &apdu_len, &apdu_off,
                                     &sim);
    bool got_true = (n == 0) && (p == 0) && sim;

    fcfg.simulation = false;
    n = iec61850_eth_frame_build(frame, sizeof(frame), &fcfg,
                                 (const uint8_t *)"APDU", 4, &frame_len);
    p = iec61850_eth_frame_parse(frame, frame_len, &et, &aid, &vid,
                                 &apdu, &apdu_len, &apdu_off, &sim);
    bool got_false = (n == 0) && (p == 0) && !sim;

    if (got_true && got_false) {
        OK();
    } else {
        NO("bit not carried");
    }

    TEST("simulation_out NULL is accepted (back-compat)");
    p = iec61850_eth_frame_parse(frame, frame_len, &et, &aid, &vid,
                                 &apdu, &apdu_len, &apdu_off, NULL);
    if (p == 0) { OK(); } else { NO("NULL rejected"); }
}

static void test_goose_filters(void)
{
    /* Craft an APDU via the publisher, then feed the subscriber. */
    iec61850_goose_publisher_t pub_storage;
    iec61850_goose_config_t gcfg;
    iec61850_goose_config_init(&gcfg);
    (void)snprintf(gcfg.gocb_ref, sizeof(gcfg.gocb_ref),
                   "LD0/LLN0$GO$gcb01");
    iec61850_goose_publisher_t *pub = &pub_storage;
    iec61850_goose_publisher_init(pub, &gcfg);
    (void)iec61850_goose_publisher_set_boolean(pub, 0, true);

    uint8_t apdu_buf[512];
    size_t apdu_len = 0;
    uint8_t frame[600];
    size_t frame_len = 0;

    /* Real frame (no sim, no test). */
    iec61850_goose_sub_config_t cfg;
    iec61850_goose_sub_config_init(&cfg);
    iec61850_goose_subscriber_t sub;
    iec61850_goose_subscriber_init(&sub, &cfg);
    int ret = iec61850_goose_publisher_prepare(pub, apdu_buf,
                                               sizeof(apdu_buf),
                                               &apdu_len);
    uint16_t et, aid, vid;
    const uint8_t *apdu;
    size_t apdu_len2, off;
    bool sim = false;
    goose_apdu_t decoded;

    TEST("real frame is accepted (defaults)");
    ret |= iec61850_goose_publisher_build_frame(pub, frame,
                                                sizeof(frame),
                                                &frame_len);
    (void)iec61850_eth_frame_parse(frame, frame_len, &et, &aid, &vid,
                                   &apdu, &apdu_len2, &off, &sim);
    goose_apdu_init(&decoded);
    (void)goose_decode_apdu(apdu, apdu_len2, &decoded);
    bool acc = iec61850_goose_subscriber_process(&sub, &decoded,
                                                  1000ULL, false);
    if ((ret == 0) && acc && !sim) { OK(); } else { NO("rejected"); }

    TEST("simulated frame is rejected by default");
    iec61850_goose_publisher_set_simulation(pub, true);
    (void)iec61850_goose_publisher_build_frame(pub, frame,
                                               sizeof(frame),
                                               &frame_len);
    (void)iec61850_eth_frame_parse(frame, frame_len, &et, &aid, &vid,
                                   &apdu, &apdu_len2, &off, &sim);
    goose_apdu_init(&decoded);
    (void)goose_decode_apdu(apdu, apdu_len2, &decoded);
    acc = iec61850_goose_subscriber_process(&sub, &decoded, 2000ULL,
                                            sim);
    if (!acc && sim) { OK(); } else { NO("simulated frame accepted"); }

    TEST("simulated frame accepted when configured");
    sub.config.reject_simulation = false;
    acc = iec61850_goose_subscriber_process(&sub, &decoded, 3000ULL,
                                             sim);
    if (acc) { OK(); } else { NO("still rejected"); }
    sub.config.reject_simulation = true;

    TEST("PDU test bit is published and flagged, not rejected");
    iec61850_goose_publisher_set_simulation(pub, false);
    iec61850_goose_publisher_set_test(pub, true);
    (void)iec61850_goose_publisher_build_frame(pub, frame,
                                               sizeof(frame),
                                               &frame_len);
    (void)iec61850_eth_frame_parse(frame, frame_len, &et, &aid, &vid,
                                   &apdu, &apdu_len2, &off, &sim);
    goose_apdu_init(&decoded);
    (void)goose_decode_apdu(apdu, apdu_len2, &decoded);
    acc = iec61850_goose_subscriber_process(&sub, &decoded, 4000ULL,
                                            sim);
    if (acc && decoded.test) { OK(); } else { NO("test bit wrong"); }

    TEST("test bit rejected when configured");
    sub.config.reject_test = true;
    acc = iec61850_goose_subscriber_process(&sub, &decoded, 5000ULL,
                                             sim);
    if (!acc) { OK(); } else { NO("test frame accepted"); }

    TEST("time quality is published in t");
    iec61850_goose_publisher_set_test(pub, false);
    iec61850_goose_publisher_set_time_quality(
        pub, IEC61850_TQ_LEAP_KNOWN | IEC61850_TQ_ACCURACY_1MS);
    (void)iec61850_goose_publisher_prepare(pub, apdu_buf,
                                           sizeof(apdu_buf), &apdu_len);
    goose_apdu_init(&decoded);
    (void)goose_decode_apdu(apdu_buf, apdu_len, &decoded);
    if (decoded.time_quality ==
        (IEC61850_TQ_LEAP_KNOWN | IEC61850_TQ_ACCURACY_1MS)) {
        OK();
    } else {
        NO("time quality not carried");
    }

    iec61850_goose_publisher_destroy(pub);
}

static void test_sv_sim(void)
{
    iec61850_sv_sub_config_t cfg;
    iec61850_sv_sub_config_init(&cfg);
    iec61850_sv_subscriber_t sub;
    iec61850_sv_subscriber_init(&sub, &cfg);

    sv_asdu_t asdu;
    sv_asdu_init(&asdu);
    (void)sv_set_svid(&asdu, "LD0/MU01");

    TEST("SV: simulated ASDU rejected by default");
    bool acc = iec61850_sv_subscriber_process(&sub, &asdu, 1000ULL,
                                               true);
    if (!acc) { OK(); } else { NO("accepted"); }

    TEST("SV: real ASDU accepted");
    acc = iec61850_sv_subscriber_process(&sub, &asdu, 2000ULL, false);
    if (acc) { OK(); } else { NO("rejected"); }

    TEST("SV: simulated ASDU accepted when configured");
    sub.config.reject_simulation = false;
    asdu.smpCnt++;   /* fresh sample: not a duplicate */
    acc = iec61850_sv_subscriber_process(&sub, &asdu, 3000ULL, true);
    if (acc) { OK(); } else { NO("still rejected"); }
}

static void test_time_quality(void)
{
    TEST("PTP status -> TimeQuality mapping");
    uint8_t locked = iec61850_time_quality_from_ptp(
        IEC61850_PTP_SYNC_LOCKED);
    uint8_t syncing = iec61850_time_quality_from_ptp(
        IEC61850_PTP_SYNC_SYNCING);
    uint8_t unsync = iec61850_time_quality_from_ptp(
        IEC61850_PTP_SYNC_UNSYNC);
    if ((locked == (IEC61850_TQ_LEAP_KNOWN |
                    IEC61850_TQ_ACCURACY_1MS)) &&
        ((syncing & IEC61850_TQ_CLOCK_NOT_SYNCED) != 0U) &&
        ((syncing & IEC61850_TQ_CLOCK_FAILURE) == 0U) &&
        ((unsync & IEC61850_TQ_CLOCK_FAILURE) != 0U)) {
        OK();
    } else {
        NO("mapping wrong");
    }
}

int main(void)
{
    test_frame_sim_bit();
    test_goose_filters();
    test_sv_sim();
    test_time_quality();

    printf("---\n%d run, %d passed, %d failed\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed ? 1 : 0;
}
