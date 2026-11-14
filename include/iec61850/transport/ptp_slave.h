/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * ptp_slave.h — PTP slave state machine (IEC 61850-9-3 profile).
 *
 * Pure computation core, no I/O: the caller feeds parsed messages
 * and socket timestamps, the machine produces master-selection
 * decisions, offsetFromMaster / meanPathDelay, and servo frequency
 * adjustments. The I/O shell (socket timestamps, clock_adjtime on
 * the ptp_clock consumer) stays outside so the whole state machine
 * is unit-testable with crafted sequences.
 *
 * Implements end-to-end two-step delay measurement:
 *
 *   t1: slave sends Delay_Req          t3: master sends Sync
 *       (preciseOriginTimestamp in Follow_Up)
 *   t2: master receives (Delay_Resp    t4: slave receives Sync
 *       receiveTimestamp)
 *
 *   meanPathDelay   = ((t4 - t3) + (t2 - t1)) / 2
 *   offsetFromMaster = ((t4 - t3) - (t2 - t1)) / 2
 *
 * Master selection: BMCA-lite — on Announce, the foreign
 * grandmaster dataset is compared against the current one
 * (§9.3.4 dataset comparison); a better master takes over. The
 * announce receipt timeout (3 announce intervals by default)
 * returns the port to LISTENING.
 */

#ifndef IEC61850_PTP_SLAVE_H
#define IEC61850_PTP_SLAVE_H

#include <stdint.h>
#include <stdbool.h>

#include "transport/ptp_message.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PTP_SLAVE_LISTENING = 0,
    PTP_SLAVE_UNCALIBRATED = 1,   /* master selected, no delay yet */
    PTP_SLAVE_SLAVE = 2,          /* calibrated, servo running */
} ptp_slave_state_t;

/* Servo tuning (power profile: kp/ki per LinuxPTP's pi servo
 * defaults scaled for the sub-microsecond offsets the profile
 * targets). */
typedef struct {
    double kp;                    /* proportional gain (ppb/ns) */
    double ki;                    /* integral gain (ppb/ns*s) */
    int32_t max_freq_ppb;         /* clamp */
} ptp_servo_config_t;

typedef struct {
    /* configuration (set once before start) */
    uint8_t domain_number;
    ptp_port_identity_t local_port_identity;
    ptp_servo_config_t servo;
    uint16_t announce_receipt_timeout;  /* in announce intervals */

    /* master state */
    ptp_slave_state_t state;
    bool have_master;
    uint8_t gm_priority1;
    ptp_clock_quality_t gm_quality;
    uint8_t gm_priority2;
    uint8_t gm_identity[PTP_CLOCK_IDENTITY_LEN];
    uint16_t gm_steps_removed;   /* current master's stepsRemoved */
    ptp_port_identity_t master_port;
    uint16_t master_announce_seq;

    /* delay measurement. t3/t2 are MASTER-clock ns (wire
     * timestamps, no epoch conversion: the clock offset cancels in
     * the paired differences), t4/t1 are LOCAL-clock ns (socket
     * timestamps). */
    bool have_t4;
    bool have_t3;
    bool have_delay;
    int64_t t4_ns;                /* Sync ingress (local clock) */
    int64_t t3_ns;                /* preciseOriginTimestamp (master) */
    uint16_t sync_seq;            /* sequenceId of the Sync that
                                   * supplied t4 (a Follow_Up only
                                   * pairs with its own Sync) */
    uint16_t delay_req_seq;       /* sequence for the next Delay_Req */
    int64_t mean_path_delay_ns;
    int64_t offset_from_master_ns;

    /* servo */
    double freq_integral;
    int32_t freq_ppb;
    uint64_t last_servo_ms;

    /* timers (ms) */
    uint64_t last_announce_ms;
    uint64_t announce_interval_ms;
    bool announce_timeout_armed;
} ptp_slave_t;

/**
 * Initialize a slave in LISTENING state. Servo defaults: kp = 0.7,
 * ki = 0.3, max 500000 ppb (LinuxPTP-style starting point).
 */
int ptp_slave_init(ptp_slave_t *s, uint8_t domain_number,
                   const uint8_t clock_identity[PTP_CLOCK_IDENTITY_LEN],
                   uint16_t port_number);

/**
 * Feed an Announce. Returns 1 when the master CHANGED (the I/O
 * shell should reset the delay state), 0 when it merely refreshed
 * the current master, -EINVAL on malformed input.
 *
 * Receipt-timeout fidelity: only announces from the CURRENT master
 * port (or one that just took over) refresh the announce receipt
 * timeout — same-domain traffic from a foreign, not-better master
 * is ignored for timeout purposes, so it cannot keep a dead master
 * alive.
 */
int ptp_slave_on_announce(ptp_slave_t *s, const ptp_header_t *hdr,
                          const ptp_announce_t *ann, uint64_t now_ms);

/**
 * Feed a Sync with its ingress timestamp t4 (LOCAL clock, ns).
 * Two-step masters (the 9-3 profile) supply t3 via the Follow_Up;
 * one-step masters carry it in the Sync body. Returns 1 when a new
 * offset/delay sample became available, 0 otherwise.
 */
int ptp_slave_on_sync(ptp_slave_t *s, const ptp_header_t *hdr,
                      const ptp_sync_t *sync, int64_t t4_ns);

/**
 * Feed a Follow_Up (two-step masters): supplies t3.
 */
int ptp_slave_on_follow_up(ptp_slave_t *s, const ptp_header_t *hdr,
                           const ptp_follow_up_t *fu);

/**
 * Feed a Delay_Resp matching a Delay_Req we sent at t1. The
 * caller obtains t1/t2 from the exchange; t1 is passed in (egress
 * timestamp), t2 comes from the message.
 */
int ptp_slave_on_delay_resp(ptp_slave_t *s, const ptp_header_t *hdr,
                            const ptp_delay_resp_t *dr, int64_t t1_ns);

/**
 * Compute the servo output from the latest offset sample.
 * dt_ms is the time since the previous step. Returns the frequency
 * adjustment in ppb (also stored in freq_ppb).
 */
int32_t ptp_slave_servo_step(ptp_slave_t *s, uint64_t now_ms);

/**
 * Timeout maintenance: announce receipt timeout -> LISTENING and
 * master state cleared. announce_interval_ms should be armed from
 * the master's logMessageInterval (ptp_slave_set_announce_interval).
 */
void ptp_slave_set_announce_interval(ptp_slave_t *s, int8_t log_interval);
void ptp_slave_tick(ptp_slave_t *s, uint64_t now_ms);

/* The sequence ID the I/O shell should use for the next
 * Delay_Req (matching on Delay_Resp is done against it). */
uint16_t ptp_slave_next_delay_req_seq(ptp_slave_t *s);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_PTP_SLAVE_H */
