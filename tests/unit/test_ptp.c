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
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <time.h>

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
static const uint8_t FOREIGN_ID[8] = {0x00, 0x1B, 0x19, 0xFF, 0xFE, 0xDD, 0xEE, 0xFF};

static void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

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

    TEST("rejects per-type body truncation (message_length)");
    /* Announce needs 30 body bytes: claim 29. */
    ptp_announce_t ann0 = {0};
    ann0.grandmaster_priority1 = 128;
    memcpy(ann0.grandmaster_identity, MASTER_ID, 8);
    int na = ptp_build(buf, sizeof(buf), PTP_MSG_ANNOUNCE, 0, 0, 0,
                       &src, 1, 1, &ann0, NULL, NULL, NULL);
    wr16(buf + 2, (uint16_t)(na - 1));   /* messageLength one short */
    int ann_short = ptp_parse(buf, (size_t)na, &h, &out, NULL, NULL, NULL);
    /* Delay_Resp needs 20 body bytes: claim 10. */
    ptp_delay_resp_t dr0 = {0};
    ptp_delay_resp_t dr_out;
    dr0.requesting_port_identity = src;
    int nd = ptp_build(buf, sizeof(buf), PTP_MSG_DELAY_RESP, 0, 0, 0,
                       &src, 9, 0, NULL, NULL, NULL, &dr0);
    wr16(buf + 2, (uint16_t)(nd - 10));
    int dr_short = ptp_parse(buf, (size_t)nd, &h, NULL, NULL, NULL,
                             &dr_out);
    /* messageLength beyond the buffer. */
    wr16(buf + 2, (uint16_t)(nd + 1));
    int too_long = ptp_parse(buf, (size_t)nd, &h, NULL, NULL, NULL, NULL);
    /* Sync body shorter than the type requires. */
    ptp_sync_t sync_out;
    ptp_timestamp_t zero = {0};
    int ns_ = ptp_build(buf, sizeof(buf), PTP_MSG_SYNC, 0, 0, 0,
                        &src, 5, 0, NULL, &zero, NULL, NULL);
    wr16(buf + 2, (uint16_t)PTP_HEADER_LEN);
    int sync_short = ptp_parse(buf, (size_t)ns_, &h, NULL, &sync_out,
                               NULL, NULL);
    if ((ann_short != -EINVAL) || (dr_short != -EINVAL) ||
        (too_long != -EINVAL) || (sync_short != -EINVAL)) {
        NO("short body accepted");
    } else {
        OK();
    }

    TEST("negative correctionField round-trips (unsigned shift + cast)");
    /* correctionField is signed on the wire (ns * 2^16); the decode
     * shifts in the unsigned domain and casts once, so a negative
     * correction must survive the round-trip exactly. */
    n = ptp_build(buf, sizeof(buf), PTP_MSG_FOLLOW_UP, 0, 0, -1000,
                   &src, 11, 0, NULL, NULL, &ts, NULL);
    t = ptp_parse(buf, (size_t)n, &h2, NULL, NULL, &fu, NULL);
    if ((t != PTP_MSG_FOLLOW_UP) || (h2.correction_ns != -1000)) {
        NO("negative correctionField wrong");
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

    TEST("same-GM path improvement takes over (steps_removed)");
    /* Fresh slave: adopt our master as seen two hops away ... */
    (void)ptp_slave_init(&s, 0, SLAVE_ID, 1);
    ptp_announce_t far_ = ann;
    far_.steps_removed = 2;
    n = ptp_build(buf, sizeof(buf), PTP_MSG_ANNOUNCE, 0, 0, 0, &msrc,
                  5, 1, &far_, NULL, NULL, NULL);
    (void)ptp_parse(buf, (size_t)n, &h, &a, NULL, NULL, NULL);
    (void)ptp_slave_on_announce(&s, &h, &a, 6500);
    if (s.gm_steps_removed != 2) {
        NO("steps_removed not stored");
    } else {
        /* ... then the SAME grandmaster re-announced one hop
         * closer: strictly better dataset, must take over. */
        ptp_announce_t near_ = ann;
        near_.steps_removed = 1;
        n = ptp_build(buf, sizeof(buf), PTP_MSG_ANNOUNCE, 0, 0, 0,
                      &msrc, 6, 1, &near_, NULL, NULL, NULL);
        (void)ptp_parse(buf, (size_t)n, &h, &a, NULL, NULL, NULL);
        r = ptp_slave_on_announce(&s, &h, &a, 7000);
        /* ... and one hop further away: refresh only. */
        ptp_announce_t farther = ann;
        farther.steps_removed = 3;
        n = ptp_build(buf, sizeof(buf), PTP_MSG_ANNOUNCE, 0, 0, 0,
                      &msrc, 7, 1, &farther, NULL, NULL, NULL);
        (void)ptp_parse(buf, (size_t)n, &h, &a, NULL, NULL, NULL);
        int r2 = ptp_slave_on_announce(&s, &h, &a, 7500);
        if ((r != 1) || (s.gm_steps_removed != 1) || (r2 != 0)) {
            NO("steps_removed comparison wrong");
        } else {
            /* back to the canonical master/announce (steps 0) */
            n = ptp_build(buf, sizeof(buf), PTP_MSG_ANNOUNCE, 0, 0, 0,
                          &msrc, 8, 1, &ann, NULL, NULL, NULL);
            (void)ptp_parse(buf, (size_t)n, &h, &a, NULL, NULL, NULL);
            (void)ptp_slave_on_announce(&s, &h, &a, 8000);
            OK();
        }
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

    TEST("stale Follow_Up (sequence mismatch) does not corrupt t3");
    /* A new Sync (seq 11) arrives; a stale Follow_Up for the lost
     * Sync (seq 10) must be ignored, the matching one (seq 11)
     * accepted. */
    ptp_timestamp_t t3ts_new = {.seconds = 1000000, .nanoseconds = 1000000};
    n = ptp_build(buf, sizeof(buf), PTP_MSG_SYNC, 0, PTP_FLAG_TWO_STEP,
                  0, &msrc, 11, 0, NULL, &zero_ts, NULL, NULL);
    (void)ptp_parse(buf, (size_t)n, &h, NULL, &syncbody, NULL, NULL);
    (void)ptp_slave_on_sync(&s, &h, &syncbody, t4 + 1000000LL);
    n = ptp_build(buf, sizeof(buf), PTP_MSG_FOLLOW_UP, 0, 0, 0, &msrc,
                  10, 0, NULL, NULL, &t3ts, NULL);   /* stale seq */
    (void)ptp_parse(buf, (size_t)n, &h, NULL, NULL, &fu, NULL);
    (void)ptp_slave_on_follow_up(&s, &h, &fu);
    bool stale_ignored = !s.have_t3 || (s.t3_ns == 1000000000000000LL);
    n = ptp_build(buf, sizeof(buf), PTP_MSG_FOLLOW_UP, 0, 0, 0, &msrc,
                  11, 0, NULL, NULL, &t3ts_new, NULL);
    (void)ptp_parse(buf, (size_t)n, &h, NULL, NULL, &fu, NULL);
    (void)ptp_slave_on_follow_up(&s, &h, &fu);
    if (stale_ignored && s.have_t3 &&
        (s.t3_ns == 1000000001000000LL)) {
        OK();
    } else {
        NO("stale Follow_Up accepted");
    }

    TEST("one-step Sync supplies t3 directly");
    ptp_timestamp_t t3one = {.seconds = 1000000, .nanoseconds = 2500000};
    n = ptp_build(buf, sizeof(buf), PTP_MSG_SYNC, 0, 0, 1000, &msrc,
                  12, 0, NULL, &t3one, NULL, NULL);
    (void)ptp_parse(buf, (size_t)n, &h, NULL, &syncbody, NULL, NULL);
    (void)ptp_slave_on_sync(&s, &h, &syncbody, t4 + 2000000LL);
    if (s.have_t3 && (s.t3_ns == 1000000002500000LL + 1000LL)) {
        OK();
    } else {
        NO("one-step t3 wrong");
    }

    TEST("wrong-domain Sync is ignored");
    n = ptp_build(buf, sizeof(buf), PTP_MSG_SYNC, 5, 0, 0, &msrc,
                  13, 0, NULL, &t3one, NULL, NULL);
    (void)ptp_parse(buf, (size_t)n, &h, NULL, &syncbody, NULL, NULL);
    (void)ptp_slave_on_sync(&s, &h, &syncbody, t4 + 3000000LL);
    if (s.sync_seq != 13U) {
        OK();
    } else {
        NO("foreign-domain Sync accepted");
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
    /* last (refreshing) Announce arrived at 8000 ms */
    ptp_slave_tick(&s, 8000 + 2000 * 4 + 1);
    if ((s.state != PTP_SLAVE_LISTENING) || s.have_master) {
        NO("timeout did not reset state");
    } else {
        OK();
    }

    TEST("foreign worse announces do not refresh the timeout");
    /* Receipt-timeout fidelity: a worse master's same-domain traffic
     * must not keep a dead current master alive. Adopt at t=1000;
     * a foreign port (worse dataset) chatters through t=9000; the
     * window is 2000*(3+1)=8000 ms from the last CURRENT-master
     * announce, so the port must time out despite the chatter. */
    (void)ptp_slave_init(&s, 0, SLAVE_ID, 1);
    n = ptp_build(buf, sizeof(buf), PTP_MSG_ANNOUNCE, 0, 0, 0, &msrc,
                  1, 1, &ann, NULL, NULL, NULL);
    (void)ptp_parse(buf, (size_t)n, &h, &a, NULL, NULL, NULL);
    (void)ptp_slave_on_announce(&s, &h, &a, 1000);
    {
        ptp_port_identity_t fsrc = {.port_number = 7};
        ptp_announce_t foreign = ann;
        bool chatter_ok = true;

        memcpy(fsrc.clock_identity, FOREIGN_ID, 8);
        foreign.grandmaster_priority1 = 200;
        for (uint64_t t = 3000; t <= 9000; t += 2000) {
            n = ptp_build(buf, sizeof(buf), PTP_MSG_ANNOUNCE, 0, 0, 0,
                          &fsrc, 20, 1, &foreign, NULL, NULL, NULL);
            (void)ptp_parse(buf, (size_t)n, &h, &a, NULL, NULL, NULL);
            if (ptp_slave_on_announce(&s, &h, &a, t) != 0) {
                chatter_ok = false;
            }
        }
        ptp_slave_tick(&s, 9100);
        if (!chatter_ok) {
            NO("foreign master took over");
        } else if ((s.state != PTP_SLAVE_LISTENING) || s.have_master) {
            NO("foreign chatter kept the dead master alive");
        } else {
            OK();
        }
    }

    TEST("current-master chatter does refresh the timeout");
    /* The positive counterpart: the SAME master's traffic within the
     * window keeps the port calibrated. */
    (void)ptp_slave_init(&s, 0, SLAVE_ID, 1);
    n = ptp_build(buf, sizeof(buf), PTP_MSG_ANNOUNCE, 0, 0, 0, &msrc,
                  1, 1, &ann, NULL, NULL, NULL);
    (void)ptp_parse(buf, (size_t)n, &h, &a, NULL, NULL, NULL);
    (void)ptp_slave_on_announce(&s, &h, &a, 1000);
    n = ptp_build(buf, sizeof(buf), PTP_MSG_ANNOUNCE, 0, 0, 0, &msrc,
                  2, 1, &ann, NULL, NULL, NULL);
    (void)ptp_parse(buf, (size_t)n, &h, &a, NULL, NULL, NULL);
    (void)ptp_slave_on_announce(&s, &h, &a, 7000);
    ptp_slave_tick(&s, 7000 + 1000);
    if ((s.state == PTP_SLAVE_LISTENING) || !s.have_master) {
        NO("current-master refresh rejected");
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

/* --- loopback socket exchange -------------------------------------- */

/* Two PTP endpoints over UDP multicast on lo (WP-6x): a "master"
 * socket builds and sends Announce / Sync / Follow_Up / Delay_Resp
 * as real datagrams; a "slave" socket joined to the group receives
 * the wire bytes, parses them with the codec and feeds the state
 * machine. t3/t2 are crafted from the actually observed t4/t1 so
 * the recovered offset (+2 ms) and path delay (5 ms) are exact —
 * the real socket latency cancels in the paired differences.
 *
 * PTP's reserved ports (319/320) would need privileges; the codec
 * is port-agnostic, so the test uses a high port. Skips gracefully
 * when unprivileged multicast on lo is unavailable. */
static void test_loopback(void)
{
    TEST("loopback UDP exchange (multicast on lo)");
    int mfd = -1;
    int sfd = -1;
    bool ok = true;
    struct sockaddr_in grp;
    struct sockaddr_in maddr;

    (void)memset(&grp, 0, sizeof(grp));
    grp.sin_family = AF_INET;
    grp.sin_port = htons(13200);
    grp.sin_addr.s_addr = inet_addr("224.0.1.129");  /* PTP primary */
    (void)memset(&maddr, 0, sizeof(maddr));
    maddr.sin_family = AF_INET;
    maddr.sin_port = htons(13201);
    maddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    mfd = socket(AF_INET, SOCK_DGRAM, 0);
    sfd = socket(AF_INET, SOCK_DGRAM, 0);
    if ((mfd < 0) || (sfd < 0)) {
        printf("SKIP (no datagram socket)\n");
        goto out;
    }
    {
        unsigned int lo_if = (unsigned int)if_nametoindex("lo");
        struct ip_mreqn mreqn;
        struct timeval tv = {.tv_sec = 2, .tv_usec = 0};

        (void)memset(&mreqn, 0, sizeof(mreqn));
        mreqn.imr_multiaddr = grp.sin_addr;
        mreqn.imr_ifindex = (int)lo_if;
        if ((lo_if == 0U) ||
            (setsockopt(sfd, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                        &mreqn, sizeof(mreqn)) != 0) ||
            (setsockopt(mfd, IPPROTO_IP, IP_MULTICAST_IF,
                        &mreqn, sizeof(mreqn)) != 0)) {
            printf("SKIP (no multicast on lo)\n");
            goto out;
        }
        if (bind(sfd, (struct sockaddr *)&grp, sizeof(grp)) != 0) {
            printf("SKIP (bind failed)\n");
            goto out;
        }
        if (bind(mfd, (struct sockaddr *)&maddr, sizeof(maddr)) != 0) {
            printf("SKIP (master bind failed)\n");
            goto out;
        }
        (void)setsockopt(sfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        (void)setsockopt(mfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    }

    {
        ptp_slave_t s;
        ptp_port_identity_t msrc;
        ptp_announce_t ann;
        ptp_header_t h;
        uint8_t buf[PTP_MAX_MESSAGE_LEN];
        uint8_t rbuf[PTP_MAX_MESSAGE_LEN];
        struct timespec now;
        int n;

        if (ptp_slave_init(&s, 0, SLAVE_ID, 1) != 0) {
            NO("init failed");
            goto out;
        }
        (void)memset(&msrc, 0, sizeof(msrc));
        memcpy(msrc.clock_identity, MASTER_ID, 8);
        msrc.port_number = 1;

        (void)memset(&ann, 0, sizeof(ann));
        ann.grandmaster_priority1 = 128;
        ann.grandmaster_clock_quality.clock_class = 6;
        ann.grandmaster_priority2 = 128;
        memcpy(ann.grandmaster_identity, MASTER_ID, 8);

        /* 1. Announce */
        n = ptp_build(buf, sizeof(buf), PTP_MSG_ANNOUNCE, 0, 0, 0,
                      &msrc, 1, 0, &ann, NULL, NULL, NULL);
        ok = ok && (n > 0) &&
             (sendto(mfd, buf, (size_t)n, 0,
                     (struct sockaddr *)&grp, sizeof(grp)) == n);
        n = (int)recv(sfd, rbuf, sizeof(rbuf), 0);
        ptp_announce_t ra;
        if ((n <= 0) || (ptp_parse(rbuf, (size_t)n, &h, &ra, NULL,
                                   NULL, NULL) != PTP_MSG_ANNOUNCE)) {
            NO("announce not received/parsed");
            goto out;
        }
        (void)clock_gettime(CLOCK_REALTIME, &now);
        (void)ptp_slave_on_announce(&s, &h, &ra,
                                    (uint64_t)now.tv_sec * 1000ULL +
                                    (uint64_t)(now.tv_nsec / 1000000));
        if (!s.have_master || (s.state != PTP_SLAVE_UNCALIBRATED)) {
            NO("master not adopted over the wire");
            goto out;
        }

        /* 2. Sync (two-step) — t4 is the real receive time. */
        ptp_timestamp_t zero_ts = {0};
        n = ptp_build(buf, sizeof(buf), PTP_MSG_SYNC, 0,
                      PTP_FLAG_TWO_STEP, 0, &msrc, 10, 0, NULL,
                      &zero_ts, NULL, NULL);
        ok = ok && (n > 0) &&
             (sendto(mfd, buf, (size_t)n, 0,
                     (struct sockaddr *)&grp, sizeof(grp)) == n);
        n = (int)recv(sfd, rbuf, sizeof(rbuf), 0);
        ptp_sync_t rs;
        if ((n <= 0) || (ptp_parse(rbuf, (size_t)n, &h, NULL, &rs,
                                   NULL, NULL) != PTP_MSG_SYNC)) {
            NO("sync not received/parsed");
            goto out;
        }
        (void)clock_gettime(CLOCK_REALTIME, &now);
        int64_t t4 = (int64_t)now.tv_sec * 1000000000LL +
                     (int64_t)now.tv_nsec;
        (void)ptp_slave_on_sync(&s, &h, &rs, t4);

        /* 3. Follow_Up — t3 crafted as t4 - 7 ms (5 ms path +
         * 2 ms offset), like a master whose clock runs 2 ms
         * behind ours. */
        int64_t t3 = t4 - 7000000LL;
        ptp_timestamp_t t3ts = {.seconds = (uint64_t)(t3 / 1000000000LL),
                                .nanoseconds = (uint32_t)(t3 % 1000000000LL)};
        n = ptp_build(buf, sizeof(buf), PTP_MSG_FOLLOW_UP, 0, 0, 0,
                      &msrc, 10, 0, NULL, NULL, &t3ts, NULL);
        ok = ok && (n > 0) &&
             (sendto(mfd, buf, (size_t)n, 0,
                     (struct sockaddr *)&grp, sizeof(grp)) == n);
        n = (int)recv(sfd, rbuf, sizeof(rbuf), 0);
        ptp_follow_up_t rf;
        if ((n <= 0) || (ptp_parse(rbuf, (size_t)n, &h, NULL, NULL,
                                   &rf, NULL) != PTP_MSG_FOLLOW_UP)) {
            NO("follow_up not received/parsed");
            goto out;
        }
        (void)ptp_slave_on_follow_up(&s, &h, &rf);
        if (!s.have_t3) {
            NO("t3 not taken from the wire Follow_Up");
            goto out;
        }

        /* 4. Delay_Req from the slave (unicast to the master). */
        uint16_t seq = ptp_slave_next_delay_req_seq(&s);
        ptp_timestamp_t zero2 = {0};
        ptp_port_identity_t sslave = s.local_port_identity;
        n = ptp_build(buf, sizeof(buf), PTP_MSG_DELAY_REQ, 0, 0, 0,
                      &sslave, seq, 0, NULL, &zero2, NULL, NULL);
        (void)clock_gettime(CLOCK_REALTIME, &now);
        int64_t t1 = (int64_t)now.tv_sec * 1000000000LL +
                     (int64_t)now.tv_nsec;
        ok = ok && (n > 0) &&
             (sendto(sfd, buf, (size_t)n, 0,
                     (struct sockaddr *)&maddr, sizeof(maddr)) == n);
        n = (int)recv(mfd, rbuf, sizeof(rbuf), 0);
        if ((n <= 0) || (ptp_parse(rbuf, (size_t)n, &h, NULL, NULL,
                                   NULL, NULL) != PTP_MSG_DELAY_REQ)) {
            NO("delay_req not received/parsed");
            goto out;
        }

        /* 5. Delay_Resp — t2 crafted as t1 + 3 ms (5 ms path -
         * 2 ms offset). */
        int64_t t2 = t1 + 3000000LL;
        ptp_delay_resp_t dr;
        (void)memset(&dr, 0, sizeof(dr));
        dr.receive_timestamp.seconds = (uint64_t)(t2 / 1000000000LL);
        dr.receive_timestamp.nanoseconds = (uint32_t)(t2 % 1000000000LL);
        dr.requesting_port_identity = s.local_port_identity;
        n = ptp_build(buf, sizeof(buf), PTP_MSG_DELAY_RESP, 0, 0, 0,
                      &msrc, seq, 0, NULL, NULL, NULL, &dr);
        ok = ok && (n > 0) &&
             (sendto(mfd, buf, (size_t)n, 0,
                     (struct sockaddr *)&grp, sizeof(grp)) == n);
        n = (int)recv(sfd, rbuf, sizeof(rbuf), 0);
        ptp_delay_resp_t rdr;
        if ((n <= 0) || (ptp_parse(rbuf, (size_t)n, &h, NULL, NULL,
                                   NULL, &rdr) != PTP_MSG_DELAY_RESP)) {
            NO("delay_resp not received/parsed");
            goto out;
        }
        if (ptp_slave_on_delay_resp(&s, &h, &rdr, t1) != 1) {
            NO("delay exchange rejected");
            goto out;
        }

        if ((s.state != PTP_SLAVE_SLAVE) ||
            !CLOSE(s.mean_path_delay_ns, 5000000, 1) ||
            !CLOSE(s.offset_from_master_ns, 2000000, 1)) {
            NO("offset/delay not recovered from the wire exchange");
        } else {
            OK();
        }
        (void)ok;
        goto out;
    }

out:
    if (mfd >= 0) { (void)close(mfd); }
    if (sfd >= 0) { (void)close(sfd); }
}

int main(void)
{
    test_codec();
    test_dataset();
    test_slave();
    test_loopback();

    printf("---\n%d run, %d passed, %d failed\n",
           tests_run, tests_passed, tests_failed);
    return tests_failed ? 1 : 0;
}
