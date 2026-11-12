/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * GOOSE Subscriber for IEC 61850-8-1
 *
 * C11 replacement for C++ GooseSubscriber class.
 * Processes received GOOSE packets, tracks publisher state,
 * detects duplicates and timeouts.
 *
 * License: BSD-2-Clause
 */

#ifndef IEC61850_GOOSE_SUBSCRIBER_H
#define IEC61850_GOOSE_SUBSCRIBER_H

#include "asn1/goose_ber.h"
#include "asn1/goose_ber_decode.h"
#include "transport/packet_io.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IEC61850_GOOSE_MAX_PUBLISHERS 16

typedef struct {
    goose_apdu_t apdu;
    uint64_t recv_timestamp_ns;
    bool is_new_state;
    bool is_duplicate;
    bool is_retransmission;
} iec61850_goose_message_t;

typedef struct {
    char gocb_ref[GOOSE_MAX_GOCBREF_LEN];
    uint32_t latest_st_num;
    uint32_t latest_sq_num;
    uint64_t last_recv_time_ns;
    uint64_t last_msg_timestamp;  /* Per-publisher replay detection (seconds) */
    uint32_t message_count;
    bool timeout_detected;
    bool valid;
} iec61850_goose_pub_state_t;

typedef struct {
    char filter_gocbref[GOOSE_MAX_GOCBREF_LEN];
    uint16_t filter_appid;
    uint16_t filter_vlan;
    uint32_t timeout_ms;
} iec61850_goose_sub_config_t;

typedef void (*iec61850_goose_callback_t)(const iec61850_goose_message_t *msg,
                                           void *user_data);

typedef struct {
    iec61850_goose_sub_config_t config;
    iec61850_goose_callback_t callback;
    void *callback_user_data;

    /* Publisher tracking */
    iec61850_goose_pub_state_t publishers[IEC61850_GOOSE_MAX_PUBLISHERS];
    size_t publisher_count;

    /* Security (optional) */
    bool security_enabled;
    void *cert_manager;  /* iec61850_cert_manager_t *, not owned */

    /* Statistics */
    uint64_t total_messages;
    uint64_t total_duplicates;
    uint64_t total_timeouts;
    uint64_t total_security_failures;
} iec61850_goose_subscriber_t;

void iec61850_goose_sub_config_init(iec61850_goose_sub_config_t *cfg);

void iec61850_goose_subscriber_init(iec61850_goose_subscriber_t *sub,
                                     const iec61850_goose_sub_config_t *cfg);

void iec61850_goose_subscriber_destroy(iec61850_goose_subscriber_t *sub);

void iec61850_goose_subscriber_set_callback(iec61850_goose_subscriber_t *sub,
                                              iec61850_goose_callback_t cb,
                                              void *user_data);

/**
 * Process a received GOOSE APDU (decoded).
 *
 * @param sub   Subscriber
 * @param apdu  Decoded GOOSE APDU
 * @param recv_time_ns Reception timestamp (nanoseconds)
 * @return true if message was accepted (not filtered/duplicate)
 */
bool iec61850_goose_subscriber_process(iec61850_goose_subscriber_t *sub,
                                        const goose_apdu_t *apdu,
                                        uint64_t recv_time_ns);

/**
 * Check for publisher timeouts.
 *
 * @param sub           Subscriber
 * @param current_time_ns Current time (nanoseconds)
 */
void iec61850_goose_subscriber_check_timeouts(
    iec61850_goose_subscriber_t *sub, uint64_t current_time_ns);

const iec61850_goose_pub_state_t *iec61850_goose_subscriber_get_pub_state(
    const iec61850_goose_subscriber_t *sub, const char *gocb_ref);

/**
 * Enable IEC 62351-6 security verification on subscriber.
 * When enabled, poll() verifies signatures and detects replay attacks.
 *
 * @param sub          Subscriber
 * @param cert_manager Loaded cert manager with trusted certificate (not owned)
 * @return 0 on success, negative on error
 */
int iec61850_goose_subscriber_enable_security(iec61850_goose_subscriber_t *sub,
                                                void *cert_manager);

/**
 * Process a raw Ethernet frame containing a GOOSE APDU.
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
int iec61850_goose_subscriber_process_frame(
    iec61850_goose_subscriber_t *sub,
    const uint8_t *frame_data, size_t frame_len,
    uint64_t recv_time_ns);

/**
 * Poll for a GOOSE frame: recv via packet_io → process_frame.
 *
 * @param sub  Subscriber
 * @param io   Packet I/O backend
 * @return 1 if a message was processed, 0 if no packet, negative on error
 */
int iec61850_goose_subscriber_poll(iec61850_goose_subscriber_t *sub,
                                    struct packet_io *io);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_GOOSE_SUBSCRIBER_H */
