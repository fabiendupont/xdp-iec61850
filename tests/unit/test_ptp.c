/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * test_ptp.c — PTP message codec and slave state machine tests.
 *
 * Deterministic, no I/O: crafted messages with known values, a
 * full two-step delay exchange with a +2 ms clock offset and a
 * 5 ms path delay, BMCA takeover and timeout behavior.
 */

#include <stdio.h>
#include <string.h>
#include <math.h>
#include <errno.h>
#include <stdlib.h>

#include "transport/ptp_message.h"
#include "transport/ptp_slave.h"

static int tests_run, tests_passed, tests_failed;

#define TEST(name) do { tests_run++; printf("  %-52s ", name); } while (0)
#define OK() do { tests_passed++; printf("PASS\n"); } while (0)
#define NO(msg) do { tests_failed++; printf("FAIL: %s\n", msg); } while (0)
#define CLOSE(a, b, tol) (llabs((long long)(a) - (long long)(b)) <= (tol))

static const uint8_t MASTER_ID[8] = {0x00, 0x1B, 0x19, 0xFF, 0xFE, 0x11, 0x22, 0x33};
static const uint8_t SLAVE_ID[8]  = {0x00, 0x1B, 0x19, 0xFF, 0xFE, 0xAA, 0xBB, 0xCC};
static const uint8_t BETTER_ID[8] = {0x00, 0x1B, 0x19, 0xFF, 0xFE, 0x00, 0x00, 0x01};

/* --- codec -------------------------------------------------------- */

static void test_codec(void)
{
    uint8_t buf[PTP_MAX_MESSAGE_LEN];

    TEST("announce round-trip");
    ptp_port_identity_t src = {.port_number = 1};
    memcpy(src.clock_identity, MASTER_ID, 8);
    ptp_announce_t ann = {0};
    ann.origin_timestamp.seconds = 1000000;
    ann.origin_timestamp.nanoseconds = 123456789;
    ann.current_utc_offset = 37;
    ann.grandmaster_priority1 = 128;
    ann.grandmaster_clock_quality.clock_class = 6;   /* PRC */
    ann.grandmaster_clock_quality.clock_accuracy = 0x21;
    ann.grandmaster_clock_quality.offset_scaled_log_variance = 0x4E5D;
    ann.grandmaster_priority2 = 128;
    memcpy(ann.grandmaster_identity, MASTER_ID, 8);
    ann.steps_removed = 1;
    ann.time_source = 0x20;   /* GNSS */

    int n = ptp_build(buf, sizeof(buf), PTP_MSG_ANNOUNCE, 0, 0, 0,
                      &src, 42, 1, &ann, NULL, NULL, NULL);
    ptp_header_t h;
    ptp_announce_t out;
    int t = ptp_parse(buf, (size_t)n, &h, &out, NULL, NULL, NULL);
    if ((n != PTP_HEADER_LEN + 30) || (t != PTP_MSG_ANNOUNCE) ||
        (h.sequence_id != 42) || (h.domain_number != 0) ||
        (h.message_length != (uint16_t)n) ||
        (memcmp(h.source_port_identity.clock_identity, MASTER_ID, 8) != 0) ||
        (h.source_port_identity.port_number != 1) ||
        (out.origin_timestamp.seconds != 1000000) ||
        (out.origin_timestamp.nanoseconds != 123456789) ||
        (out.grandmaster_priority1 != 128) ||
        (out.grandmaster_clock_quality.clock_class != 6) ||
        (out.grandmaster_clock_quality.clock_accuracy != 0x21) ||
        (out.grandmaster_clock_quality.offset_scaled_log_variance != 0x4E5D) ||
        (out.current_utc_offset != 37) ||
        (memcmp(out.grandmaster_identity, MASTER_ID, 8) != 0) ||
        (out.steps_removed != 1) || (out.time_source != 0x20)) {
        NO("round-trip mismatch");
    } else {
        OK();
    }

    TEST("sync/follow_up/delay_resp round-trip");
    ptp_timestamp_t ts = {.seconds = 1000000, .nanoseconds = 500000000};
    n = ptp_build(buf, sizeof(buf), PTP_MSG_FOLLOW_UP, 0,
                  PTP_FLAG_TWO_STEP, 1000, &src, 7, 0, NULL, NULL, &ts,
                  NULL);
    ptp_header_t h2;
    ptp_follow_up_t fu;
    t = ptp_parse(buf, (size_t)n, &h2, NULL, NULL, &fu, NULL);
    int fu_ok = (t == PTP_MSG_FOLLOW_UP) &&
                (h2.correction_ns == 1000) &&
                (h2.flag_field == PTP_FLAG_TWO_STEP) &&
                (fu.precise_origin_timestamp.seconds == 1000000) &&
                (fu.precise_origin_timestamp.nanoseconds == 500000000);
    ptp_delay_resp_t dr_in = {0};
    dr_in.receive_timestamp = ts;
    dr_in.requesting_port_identity = src;
    int n2 = ptp_build(buf, sizeof(buf), PTP_MSG_DELAY_RESP, 0, 0, 0,
                       &src, 9, 0, NULL, NULL, NULL, &dr_in);
    ptp_delay_resp_t dr;
    t = ptp_parse(buf, (size_t)n2, &h2, NULL, NULL, NULL, &dr);
    if (!fu_ok || (t != PTP_MSG_DELAY_RESP) ||
        (dr.receive_timestamp.nanoseconds != 500000000) ||
        (dr.requesting_port_identity.port_number != 1)) {
        NO("round-trip mismatch");
    } else {
        OK();
    }

    TEST("rejects bad version and truncated messages");
    buf[1] = 1;   /* wrong version */
    int bad = ptp_parse(buf, (size_t)n2, &h2, NULL, NULL, NULL, NULL);
    buf[1] = 2;
    int trunc = ptp_parse(buf, 10U, &h2, NULL, NULL, NULL, NULL);
    uint8_t junk[64] = {0};
    junk[1] = 2;
    junk[0] = 0x0F;   /* invalid type */
    int type_bad = ptp_parse(junk, sizeof(junk), &h2, NULL, NULL, NULL, NULL);
    if ((bad != -EINVAL) || (trunc != -EINVAL) || (type_bad != -EINVAL)) {
        NO("malformed message accepted");
    } else {
        OK();
    }

    TEST("timestamp difference");
    ptp_timestamp_t a = {.seconds = 1000001, .nanoseconds = 100};
    ptp_timestamp_t b = {.seconds = 1000000, .nanoseconds = 999999900};
    if (ptp_timestamp_diff_ns(&a, &b) != 200) {
        NO("diff wrong");
    } else {
        OK();
    }
}

/* --- dataset comparison -------------------------------------------- */

static void test_dataset(void)
{
    ptp_clock_quality_t q_prc = {.clock_class = 6, .clock_accuracy = 0x21,
                                 .offset_scaled_log_variance = 0x4E5D};
    ptp_clock_quality_t q_worse = q_prc;
    q_worse.clock_class = 13;

    TEST("dataset comparison ordering");
    int c1 = ptp_dataset_compare(100, &q_prc, 128, MASTER_ID, 0,
                                 200, &q_prc, 128, MASTER_ID, 0);
    int c2 = ptp_dataset_compare(100, &q_worse, 128, MASTER_ID, 0,
                                 100, &q_prc, 128, MASTER_ID, 0);
    int c3 = ptp_dataset_compare(100, &q_prc, 128, MASTER_ID, 0,
                                 100, &q_prc, 128, BETTER_ID, 0);
    int c4 = ptp_dataset_compare(100, &q_prc, 128, MASTER_ID, 0,
                                 100, &q_prc, 128, MASTER_ID, 0);
    if ((c1 < 0) && (c2 > 0) && (c3 > 0) && (c4 == 0)) {
        OK();
    } else {
        NO("ordering wrong");
    }
}

/* --- slave state machine ------------------------------------------- */

/* Build a complete two-step exchange against a master with a known
 * +2 ms slave-clock offset and 5 ms path delay:
 *
 *   local  = master + 2 ms
 *   t3 (master tx) = 1_000_000.000000000 s
 *   t4 (local rx)  = t3 + path + offset = 1_000_007.002000000 s
 *   t1 (local tx)  = 1_000_010.000000000 s
 *   t2 (master rx) = t1 - offset + path = 1_000_013.000000000 s
 */
static void test_slave(void)
{
    ptp_slave_t s;
    TEST("init and first Announce adopts a master");
    if (ptp_slave_init(&s, 0, SLAVE_ID, 1) != 0) {
        NO("init failed");
        return;
    }
    ptp_port_identity_t msrc = {.port_number = 1};
    memcpy(msrc.clock_identity, MASTER_ID, 8);
    ptp_announce_t ann = {0};
    ann.grandmaster_priority1 = 128;
    ann.grandmaster_clock_quality.clock_class = 6;
    ann.grandmaster_priority2 = 128;
    memcpy(ann.grandmaster_identity, MASTER_ID, 8);

    uint8_t buf[PTP_MAX_MESSAGE_LEN];
    int n = ptp_build(buf, sizeof(buf), PTP_MSG_ANNOUNCE, 0, 0, 0,
                      &msrc, 1, 1, &ann, NULL, NULL, NULL);
    ptp_header_t h;
    ptp_announce_t a;
    (void)ptp_parse(buf, (size_t)n, &h, &a, NULL, NULL, NULL);
    int r = ptp_slave_on_announce(&s, &h, &a, 1000);
    if ((r != 1) || (s.state != PTP_SLAVE_UNCALIBRATED) ||
        (!s.have_master) || (s.announce_interval_ms != 2000)) {
        NO("first announce not adopted");
    } else {
        OK();
    }

    TEST("worse Announce does not take over");
    ptp_announce_t worse = ann;
    worse.grandmaster_priority1 = 200;
    n = ptp_build(buf, sizeof(buf), PTP_MSG_ANNOUNCE, 0, 0, 0, &msrc,
                  2, 1, &worse, NULL, NULL, NULL);
    (void)ptp_parse(buf, (size_t)n, &h, &a, NULL, NULL, NULL);
    r = ptp_slave_on_announce(&s, &h, &a, 3000);
    if ((r != 0) || (s.gm_priority1 != 128)) {
        NO("worse master took over");
    } else {
        OK();
    }

    TEST("better Announce takes over and resets delay state");
    ptp_announce_t better = ann;
    better.grandmaster_priority1 = 100;
    memcpy(better.grandmaster_identity, BETTER_ID, 8);
    n = ptp_build(buf, sizeof(buf), PTP_MSG_ANNOUNCE, 0, 0, 0, &msrc,
                  3, 1, &better, NULL, NULL, NULL);
    (void)ptp_parse(buf, (size_t)n, &h, &a, NULL, NULL, NULL);
    r = ptp_slave_on_announce(&s, &h, &a, 5000);
    if ((r != 1) || (s.gm_priority1 != 100) ||
        memcmp(s.gm_identity, BETTER_ID, 8) != 0) {
        NO("better master not adopted");
    } else {
        /* restore the original master for the delay tests */
        n = ptp_build(buf, sizeof(buf), PTP_MSG_ANNOUNCE, 0, 0, 0,
                      &msrc, 4, 1, &ann, NULL, NULL, NULL);
        (void)ptp_parse(buf, (size_t)n, &h, &a, NULL, NULL, NULL);
        (void)ptp_slave_on_announce(&s, &h, &a, 6000);
        OK();
    }

    TEST("two-step exchange yields exact offset and delay");
    /* Sync (two-step) at master t3 = 1_000_000.000000000. */
    ptp_timestamp_t t3ts = {.seconds = 1000000, .nanoseconds = 0};
    ptp_timestamp_t zero_ts = {0};
    n = ptp_build(buf, sizeof(buf), PTP_MSG_SYNC, 0, PTP_FLAG_TWO_STEP,
                  0, &msrc, 10, 0, NULL, &zero_ts, NULL, NULL);
    ptp_sync_t syncbody;
    (void)ptp_parse(buf, (size_t)n, &h, NULL, &syncbody, NULL, NULL);
    int64_t t4 = 1000000007000000LL;   /* local ns: t3 + 5ms path + 2ms offset */
    (void)ptp_slave_on_sync(&s, &h, &syncbody, t4);

    /* Follow_Up with preciseOriginTimestamp = t3. */
    n = ptp_build(buf, sizeof(buf), PTP_MSG_FOLLOW_UP, 0, 0, 0, &msrc,
                  10, 0, NULL, NULL, &t3ts, NULL);
    ptp_follow_up_t fu;
    (void)ptp_parse(buf, (size_t)n, &h, NULL, NULL, &fu, NULL);
    (void)ptp_slave_on_follow_up(&s, &h, &fu);

    /* Delay_Req egress at local t1 = 1_000_010.000000000. */
    uint16_t seq = ptp_slave_next_delay_req_seq(&s);
    int64_t t1 = 1000010000000000LL;
    /* Delay_Resp: receiveTimestamp t2 = 1_000_013.000000000 (master
     * clock), addressed to us with our sequence. */
    ptp_delay_resp_t dr = {0};
    dr.receive_timestamp.seconds = 1000010;
    dr.receive_timestamp.nanoseconds = 3000000;
    dr.requesting_port_identity = s.local_port_identity;
    n = ptp_build(buf, sizeof(buf), PTP_MSG_DELAY_RESP, 0, 0, 0, &msrc,
                  seq, 0, NULL, NULL, NULL, &dr);
    ptp_delay_resp_t dro;
    (void)ptp_parse(buf, (size_t)n, &h, NULL, NULL, NULL, &dro);

    r = ptp_slave_on_delay_resp(&s, &h, &dro, t1);
    /* path 5 ms, offset +2 ms. */
    if ((r != 1) || (s.state != PTP_SLAVE_SLAVE) ||
        !CLOSE(s.mean_path_delay_ns, 5000000, 1) ||
        !CLOSE(s.offset_from_master_ns, 2000000, 1)) {
        NO("offset/delay wrong");
    } else {
        OK();
    }

    TEST("delay_resp for another slave is ignored");
    dr.requesting_port_identity.port_number = 99;
    n = ptp_build(buf, sizeof(buf), PTP_MSG_DELAY_RESP, 0, 0, 0, &msrc,
                  seq, 0, NULL, NULL, NULL, &dr);
    (void)ptp_parse(buf, (size_t)n, &h, NULL, NULL, NULL, &dro);
    if (ptp_slave_on_delay_resp(&s, &h, &dro, t1) != 0) {
        NO("foreign response accepted");
    } else {
        OK();
    }

    TEST("servo clamps for step-sized offsets (2 ms)");
    /* +2 ms is step territory: the servo saturates negative. */
    int32_t f1 = ptp_slave_servo_step(&s, 8000);
    int32_t f2 = ptp_slave_servo_step(&s, 9000);
    if ((f1 != -s.servo.max_freq_ppb) || (f2 != f1)) {
        NO("servo not clamped");
    } else {
        OK();
    }

    TEST("servo PI is exact in the linear regime");
    /* 2 us offset: kp 0.7 ppb/ns, ki 0.3 ppb/ns*s, 1 s steps. */
    s.freq_integral = 0;
    s.last_servo_ms = 0;
    s.offset_from_master_ns = 2000;
    int32_t g1 = ptp_slave_servo_step(&s, 1000);
    int32_t g2 = ptp_slave_servo_step(&s, 2000);
    int32_t g3 = ptp_slave_servo_step(&s, 3000);
    /* P = -1400 ppb; I adds -600 ppb per step. */
    if ((g1 != -1400) || (g2 != -2000) || (g3 != -2600)) {
        NO("PI values wrong");
    } else {
        OK();
    }

    TEST("announce timeout returns to LISTENING");
    ptp_slave_tick(&s, 6000 + 2000 * 4 + 1);
    if ((s.state != PTP_SLAVE_LISTENING) || s.have_master) {
        NO("timeout did not reset state");
    } else {
        OK();
    }

    TEST("wrong-domain announce is ignored");
    (void)ptp_slave_init(&s, 0, SLAVE_ID, 1);
    n = ptp_build(buf, sizeof(buf), PTP_MSG_ANNOUNCE, 5, 0, 0, &msrc,
                  1, 1, &ann, NULL, NULL, NULL);
    (void)ptp_parse(buf, (size_t)n, &h, &a, NULL, NULL, NULL);
    if ((ptp_slave_on_announce(&s, &h, &a, 1000) != 0) ||
        (s.have_master)) {
        NO("foreign domain adopted");
    } else {
        OK();
    }
}

int main(void)
{
    test_codec();
    test_dataset();
    test_slave();

    printf("---\n%d run, %d passed, %d failed\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed ? 1 : 0;
}
