/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * ptp_slave.c — pure PTP slave state machine. See the header for
 * the timing model; everything here is deterministic computation
 * over caller-supplied inputs. No I/O, no allocation.
 */

#include "transport/ptp_slave.h"

#include <string.h>
#include <errno.h>

/* Wire timestamp -> master-clock ns (seconds*1e9 + nanoseconds).
 * The PTP epoch never enters the computation: t3/t2 live in the
 * master's clock domain, t4/t1 in the local one, and the clock
 * offset between them is exactly what the delay measurement
 * computes — the paired differences make any common-mode epoch
 * cancel. */
static int64_t ts_to_ns(const ptp_timestamp_t *ts)
{
    return (int64_t)ts->seconds * 1000000000LL +
           (int64_t)ts->nanoseconds;
}

static int from_master(const ptp_slave_t *s, const ptp_header_t *hdr)
{
    return s->have_master &&
           (memcmp(hdr->source_port_identity.clock_identity,
                   s->master_port.clock_identity,
                   PTP_CLOCK_IDENTITY_LEN) == 0) &&
           (hdr->source_port_identity.port_number ==
            s->master_port.port_number);
}

int ptp_slave_init(ptp_slave_t *s, uint8_t domain_number,
                   const uint8_t clock_identity[PTP_CLOCK_IDENTITY_LEN],
                   uint16_t port_number)
{
    if ((s == NULL) || (clock_identity == NULL)) {
        return -EINVAL;
    }
    memset(s, 0, sizeof(*s));
    s->domain_number = domain_number;
    memcpy(s->local_port_identity.clock_identity, clock_identity,
           PTP_CLOCK_IDENTITY_LEN);
    s->local_port_identity.port_number = port_number;
    s->state = PTP_SLAVE_LISTENING;
    s->have_master = false;
    s->announce_receipt_timeout = 3U;
    s->servo.kp = 0.7;
    s->servo.ki = 0.3;
    s->servo.max_freq_ppb = 500000;
    return 0;
}

int ptp_slave_on_announce(ptp_slave_t *s, const ptp_header_t *hdr,
                          const ptp_announce_t *ann, uint64_t now_ms)
{
    if ((s == NULL) || (hdr == NULL) || (ann == NULL)) {
        return -EINVAL;
    }
    if (hdr->domain_number != s->domain_number) {
        return 0;   /* other domain: ignore silently */
    }

    s->last_announce_ms = now_ms;
    s->announce_timeout_armed = true;

    if (s->have_master) {
        /* BMCA-lite: only a strictly better dataset takes over. */
        int c = ptp_dataset_compare(
            ann->grandmaster_priority1,
            &ann->grandmaster_clock_quality,
            ann->grandmaster_priority2, ann->grandmaster_identity,
            ann->steps_removed,
            s->gm_priority1, &s->gm_quality, s->gm_priority2,
            s->gm_identity, 0U);
        if (c >= 0) {
            return 0;   /* refresh only */
        }
    }

    /* Adopt (first master, or a better one). */
    s->gm_priority1 = ann->grandmaster_priority1;
    s->gm_quality = ann->grandmaster_clock_quality;
    s->gm_priority2 = ann->grandmaster_priority2;
    memcpy(s->gm_identity, ann->grandmaster_identity,
           PTP_CLOCK_IDENTITY_LEN);
    s->master_port = hdr->source_port_identity;
    s->master_announce_seq = hdr->sequence_id;
    ptp_slave_set_announce_interval(s, hdr->log_message_interval);

    /* New master: delay measurement starts over. */
    s->have_delay = false;
    s->have_t4 = false;
    s->have_t3 = false;
    s->state = PTP_SLAVE_UNCALIBRATED;
    s->have_master = true;
    return 1;
}

int ptp_slave_on_sync(ptp_slave_t *s, const ptp_header_t *hdr,
                      const ptp_sync_t *sync, int64_t t4_ns)
{
    if ((s == NULL) || (hdr == NULL) || (sync == NULL)) {
        return -EINVAL;
    }
    if (!from_master(s, hdr)) {
        return 0;
    }

    s->t4_ns = t4_ns;
    s->have_t4 = true;

    if ((hdr->flag_field & PTP_FLAG_TWO_STEP) != 0U) {
        /* t3 arrives with the Follow_Up. */
        s->have_t3 = false;
        return 0;
    }

    /* One-step: the Sync body carries the origin timestamp. */
    s->t3_ns = ts_to_ns(&sync->origin_timestamp) + hdr->correction_ns;
    s->have_t3 = true;
    return 0;
}

int ptp_slave_on_follow_up(ptp_slave_t *s, const ptp_header_t *hdr,
                           const ptp_follow_up_t *fu)
{
    if ((s == NULL) || (hdr == NULL) || (fu == NULL)) {
        return -EINVAL;
    }
    if (!from_master(s, hdr) || !s->have_t4) {
        return 0;
    }

    s->t3_ns = ts_to_ns(&fu->precise_origin_timestamp) +
               hdr->correction_ns;
    s->have_t3 = true;
    return 0;
}

int ptp_slave_on_delay_resp(ptp_slave_t *s, const ptp_header_t *hdr,
                            const ptp_delay_resp_t *dr, int64_t t1_ns)
{
    if ((s == NULL) || (hdr == NULL) || (dr == NULL)) {
        return -EINVAL;
    }
    if (!s->have_master || !s->have_t4 || !s->have_t3) {
        return 0;
    }
    /* The response must match OUR Delay_Req. */
    if ((memcmp(dr->requesting_port_identity.clock_identity,
                s->local_port_identity.clock_identity,
                PTP_CLOCK_IDENTITY_LEN) != 0) ||
        (dr->requesting_port_identity.port_number !=
         s->local_port_identity.port_number)) {
        return 0;
    }
    if (hdr->sequence_id != s->delay_req_seq) {
        return 0;
    }

    int64_t t2_ns = ts_to_ns(&dr->receive_timestamp);

    /* fwd = path + clock offset, rev = path - clock offset. */
    int64_t fwd = s->t4_ns - s->t3_ns;
    int64_t rev = t2_ns - t1_ns;
    s->mean_path_delay_ns = (fwd + rev) / 2;
    s->offset_from_master_ns = (fwd - rev) / 2;

    s->have_delay = true;
    if (s->state == PTP_SLAVE_UNCALIBRATED) {
        s->state = PTP_SLAVE_SLAVE;
    }
    return 1;
}

int32_t ptp_slave_servo_step(ptp_slave_t *s, uint64_t now_ms)
{
    if ((s == NULL) || !s->have_delay) {
        return 0;
    }
    double dt_s = 0.0;   /* first step: proportional only */
    if ((s->last_servo_ms != 0U) && (now_ms > s->last_servo_ms)) {
        dt_s = (double)(now_ms - s->last_servo_ms) / 1000.0;
    }

    double offset = (double)s->offset_from_master_ns;
    s->freq_integral += s->servo.ki * offset * dt_s;

    /* Anti-windup: clamp the integral contribution. */
    double cap = (double)s->servo.max_freq_ppb;
    if (s->freq_integral > cap) {
        s->freq_integral = cap;
    } else if (s->freq_integral < -cap) {
        s->freq_integral = -cap;
    }

    /* Positive offsetFromMaster = local clock AHEAD of the master:
     * the correction is negative frequency (run slower to fall
     * back). The PI output is negated accordingly. */
    double f = -(s->servo.kp * offset + s->freq_integral);
    if (f > cap) {
        f = cap;
    } else if (f < -cap) {
        f = -cap;
    }

    s->freq_ppb = (int32_t)f;
    s->last_servo_ms = now_ms;
    return s->freq_ppb;
}

void ptp_slave_set_announce_interval(ptp_slave_t *s, int8_t log_interval)
{
    if (s == NULL) {
        return;
    }
    int64_t ms = 1000;
    int8_t li = log_interval;
    if (li < -6) { li = -6; }
    if (li > 6) { li = 6; }
    while (li < 0) { ms /= 2; li++; }
    while (li > 0) { ms *= 2; li--; }
    s->announce_interval_ms = (uint64_t)ms;
}

void ptp_slave_tick(ptp_slave_t *s, uint64_t now_ms)
{
    if ((s == NULL) || !s->have_master || !s->announce_timeout_armed ||
        (s->announce_interval_ms == 0U)) {
        return;
    }
    uint64_t window = s->announce_interval_ms *
                      (uint64_t)(s->announce_receipt_timeout + 1U);
    if ((now_ms - s->last_announce_ms) > window) {
        s->state = PTP_SLAVE_LISTENING;
        s->have_master = false;
        s->have_delay = false;
        s->have_t4 = false;
        s->have_t3 = false;
        s->announce_timeout_armed = false;
    }
}

uint16_t ptp_slave_next_delay_req_seq(ptp_slave_t *s)
{
    if (s == NULL) {
        return 0;
    }
    s->delay_req_seq++;
    return s->delay_req_seq;
}
