/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Sampled Values Subscriber for IEC 61850-9-2
 *
 * C11 replacement for C++ SvSubscriber class.
 *
 * License: BSD-2-Clause
 */

#ifndef IEC61850_SV_SUBSCRIBER_H
#define IEC61850_SV_SUBSCRIBER_H

#include "asn1/sv_ber.h"
#include "transport/packet_io.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IEC61850_SV_MAX_PUBLISHERS 16

typedef struct {
    sv_asdu_t asdu;
    uint64_t recv_timestamp_ns;
    bool is_new_sample;
    bool is_duplicate;
    bool has_gap;
    uint32_t gap_count;
    bool simulation;   /* Ed.2 frame-level simulation bit */
} iec61850_sv_message_t;

typedef struct {
    char sv_id[SV_MAX_SVID_LEN];
    uint16_t latest_smp_cnt;
    uint64_t last_recv_time_ns;
    uint64_t last_msg_timestamp;  /* Per-publisher replay detection (seconds) */
    uint32_t message_count;
    uint32_t gap_count;
    bool timeout_detected;
    bool valid;
} iec61850_sv_pub_state_t;

typedef struct {
    char filter_svid[SV_MAX_SVID_LEN];
    uint16_t filter_appid;
    uint16_t smp_rate;       /* samples per cycle (0 = use default 80) */
    uint32_t timeout_ms;
    /* Ed.2: simulated frames must not be processed as real data
     * (IEC 61850-8-1). */
    bool reject_simulation;  /* default: true */
} iec61850_sv_sub_config_t;

typedef void (*iec61850_sv_callback_t)(const iec61850_sv_message_t *msg,
                                        void *user_data);

typedef struct {
    iec61850_sv_sub_config_t config;
    iec61850_sv_callback_t callback;
    void *callback_user_data;

    iec61850_sv_pub_state_t publishers[IEC61850_SV_MAX_PUBLISHERS];
    size_t publisher_count;

    /* Security (optional) */
    bool security_enabled;
    void *cert_manager;  /* iec61850_cert_manager_t *, not owned */

    uint64_t total_messages;
    uint64_t total_duplicates;
    uint64_t total_gaps;
    uint64_t total_timeouts;
    uint64_t total_security_failures;
} iec61850_sv_subscriber_t;

void iec61850_sv_sub_config_init(iec61850_sv_sub_config_t *cfg);

void iec61850_sv_subscriber_init(iec61850_sv_subscriber_t *sub,
                                  const iec61850_sv_sub_config_t *cfg);

void iec61850_sv_subscriber_destroy(iec61850_sv_subscriber_t *sub);

void iec61850_sv_subscriber_set_callback(iec61850_sv_subscriber_t *sub,
                                          iec61850_sv_callback_t cb,
                                          void *user_data);

/**
 * Process a received SV ASDU.
 * @return true if message was accepted
 */
bool iec61850_sv_subscriber_process(iec61850_sv_subscriber_t *sub,
                                     const sv_asdu_t *asdu,
                                     uint64_t recv_time_ns,
                                     bool simulation);

void iec61850_sv_subscriber_check_timeouts(iec61850_sv_subscriber_t *sub,
                                            uint64_t current_time_ns);

const iec61850_sv_pub_state_t *iec61850_sv_subscriber_get_pub_state(
    const iec61850_sv_subscriber_t *sub, const char *sv_id);

/**
 * Enable IEC 62351-6 security verification on SV subscriber.
 */
int iec61850_sv_subscriber_enable_security(iec61850_sv_subscriber_t *sub,
                                             void *cert_manager);

/**
 * Process a raw Ethernet frame containing an SV APDU.
 *
 * Parses Ethernet headers, validates EtherType/MAC/APPID, decodes the BER
 * APDU, verifies security (if enabled), and invokes the state machine.
 * This is the pure-computation core — no I/O. Testable with crafted frames.
 *
 * @param sub          Subscriber
 * @param frame_data   Raw Ethernet frame bytes
 * @param frame_len    Frame length
 * @param recv_time_ns Reception timestamp (nanoseconds)
 * @return 1 if a message was processed, 0 if filtered/invalid
 */
int iec61850_sv_subscriber_process_frame(
    iec61850_sv_subscriber_t *sub,
    const uint8_t *frame_data, size_t frame_len,
    uint64_t recv_time_ns);

/**
 * Poll for an SV frame: recv via packet_io → process_frame.
 *
 * @param sub  Subscriber
 * @param io   Packet I/O backend
 * @return 1 if a message was processed, 0 if no packet, negative on error
 */
int iec61850_sv_subscriber_poll(iec61850_sv_subscriber_t *sub,
                                 struct packet_io *io);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_SV_SUBSCRIBER_H */
