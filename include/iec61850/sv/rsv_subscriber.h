/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC TR 61850-90-5 R-SV Subscriber
 *
 * Receives and validates 90-5 R-SV SPDUs over UDP/IP: session
 * decode, per-APPID replay rejection (authoritative userspace
 * re-validation of the BPF dedup: an SPDU whose SPDU Number is <=
 * the last accepted number for its APPID is dropped), optional
 * IEC 62351-6 signature verification, L2-style SV duplicate / gap
 * detection, callbacks and timeout tracking.
 *
 * Transport modes — identical to rgoose_subscriber.h:
 *
 * Plain (unsigned) mode — default:
 *   process_spdu()/poll() expect the bare SPDU.  Attach a UDP
 *   receiver (packet_io_create_udp_receiver): the kernel strips the
 *   IP/UDP headers before delivery.
 *
 * Secure (signed) mode — after enable_security():
 *   The signature covers the IPv4 + UDP headers, which the kernel
 *   UDP path strips — verification would be impossible.  Secure
 *   mode therefore REQUIRES a transport that preserves the headers:
 *   raw AF_PACKET (packet_io_create_raw) or AF_XDP.  poll() then
 *   receives complete [Eth][IPv4][UDP][SPDU] frames; the optional
 *   14-byte Ethernet header is detected structurally (EtherType
 *   0x0800).  Verification: structural IP/UDP parse (checksums not
 *   re-verified — the HMAC subsumes them), session decode,
 *   HMAC-SHA256 recomputation with the signature zeroed,
 *   constant-time compare, key-id check, per-APPID SPDU-number
 *   replay rejection, 90-5 time window on Time-of-Current-Key.
 *
 * Secure mode requires -Denable_security=true; without it
 * enable_security() returns -ENOTSUP.
 *
 * License: BSD-2-Clause
 */

#ifndef IEC61850_RSV_SUBSCRIBER_H
#define IEC61850_RSV_SUBSCRIBER_H

#include "asn1/r_profile.h"
#include "asn1/sv_ber.h"
#include "transport/packet_io.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IEC61850_RSV_MAX_PUBLISHERS 16U
#define IEC61850_RSV_MAX_APPIDS     16U

#define IEC61850_RSV_SEC_KEY_MAX   64U
#define IEC61850_RSV_SEC_HMAC_LEN  32U

/* security_algos bits (mirrors the publisher constants). */
#define IEC61850_RSV_SUB_SEC_ALGO_HMAC_SHA256 0x0100U
#define IEC61850_RSV_SUB_SEC_ALGO_AES_GMAC    0x0200U

typedef struct {
    sv_apdu_t apdu;
    iec61850_r_header_t header;   /* session metadata incl. security */
    uint64_t recv_timestamp_ns;
    bool is_new_sample;
    bool is_duplicate;
    bool has_gap;
    uint32_t gap_count;
} iec61850_rsv_message_t;

/* Per-publisher (svID) ASDU-level state — mirrors the L2 SV
 * subscriber. */
typedef struct {
    char sv_id[SV_MAX_SVID_LEN];
    uint16_t latest_smp_cnt;
    uint64_t last_recv_time_ns;
    uint32_t message_count;
    uint32_t gap_count;
    bool timeout_detected;
    bool valid;
} iec61850_rsv_pub_state_t;

/* Per-APPID session-level state (authoritative replay validation). */
typedef struct {
    uint16_t appid;
    uint32_t last_spdu_number;
    bool has_last_spdu;
    uint32_t last_time_of_key;
    bool has_last_time;
    uint64_t replay_drops;
    bool valid;
} iec61850_rsv_appid_state_t;

typedef struct {
    uint16_t filter_appid;   /* 0 = accept all APPIDs */
    uint16_t filter_port;    /* secure mode only: UDP dst port (0 = any) */
    char filter_svid[SV_MAX_SVID_LEN]; /* "" = accept all */
    uint16_t smp_rate;       /* samples per cycle (0 = default 80) */
    uint32_t timeout_ms;
} iec61850_rsv_sub_config_t;

/* Verification key material (symmetric HMAC profile). */
typedef struct {
    uint16_t algo;         /* IEC61850_RSV_SUB_SEC_ALGO_* */
    uint8_t key[IEC61850_RSV_SEC_KEY_MAX];
    size_t key_len;
    uint32_t expected_key_id; /* 0 = accept any key id */
} iec61850_rsv_sub_security_t;

typedef void (*iec61850_rsv_callback_t)(
    const iec61850_rsv_message_t *msg, void *user_data);

typedef struct {
    iec61850_rsv_sub_config_t config;
    iec61850_rsv_callback_t callback;
    void *callback_user_data;

    /* ASDU-level publisher tracking (svID keyed) */
    iec61850_rsv_pub_state_t publishers[IEC61850_RSV_MAX_PUBLISHERS];
    size_t publisher_count;

    /* Session-level APPID tracking (SPDU-number / time window) */
    iec61850_rsv_appid_state_t appids[IEC61850_RSV_MAX_APPIDS];
    size_t appid_count;

    /* Security (optional) */
    bool security_enabled;
    iec61850_rsv_sub_security_t sec;

    /* Statistics */
    uint64_t total_messages;
    uint64_t total_duplicates;
    uint64_t total_gaps;
    uint64_t total_replays;
    uint64_t total_timeouts;
    uint64_t total_security_failures;
} iec61850_rsv_subscriber_t;

void iec61850_rsv_sub_config_init(iec61850_rsv_sub_config_t *cfg);

void iec61850_rsv_subscriber_init(iec61850_rsv_subscriber_t *sub,
                                  const iec61850_rsv_sub_config_t *cfg);

void iec61850_rsv_subscriber_destroy(iec61850_rsv_subscriber_t *sub);

void iec61850_rsv_subscriber_set_callback(iec61850_rsv_subscriber_t *sub,
                                          iec61850_rsv_callback_t cb,
                                          void *user_data);

/**
 * Enable secure (signed) reception (see the file header for the
 * transport constraint).
 *
 * @return 0 on success, -EINVAL on bad arguments, -ENOTSUP when
 *         built without -Denable_security=true
 */
int iec61850_rsv_subscriber_enable_security(
    iec61850_rsv_subscriber_t *sub,
    const iec61850_rsv_sub_security_t *cfg);

/**
 * Process a bare (plain-mode) SPDU.  Security extension, if present,
 * is decoded but NOT verified (no key).
 * @return 1 if a message was processed, 0 if filtered/invalid
 */
int iec61850_rsv_subscriber_process_spdu(
    iec61850_rsv_subscriber_t *sub,
    const uint8_t *spdu, size_t spdu_len, uint64_t recv_time_ns);

/**
 * Process a received wire message.  Secure mode: [Eth?][IPv4][UDP]
 * [SPDU] — verifies the signature first.  Plain mode: delegates to
 * process_spdu().  Pure computation, no I/O.
 * @return 1 if a message was processed, 0 if filtered/invalid
 */
int iec61850_rsv_subscriber_process_frame(
    iec61850_rsv_subscriber_t *sub,
    const uint8_t *frame_data, size_t frame_len,
    uint64_t recv_time_ns);

/**
 * Poll for a message: recv via packet_io → process_frame.
 * @return 1 if a message was processed, 0 if no packet, negative on
 *         error
 */
int iec61850_rsv_subscriber_poll(iec61850_rsv_subscriber_t *sub,
                                 struct packet_io *io);

void iec61850_rsv_subscriber_check_timeouts(
    iec61850_rsv_subscriber_t *sub, uint64_t current_time_ns);

const iec61850_rsv_pub_state_t *iec61850_rsv_subscriber_get_pub_state(
    const iec61850_rsv_subscriber_t *sub, const char *sv_id);

const iec61850_rsv_appid_state_t *iec61850_rsv_subscriber_get_appid_state(
    const iec61850_rsv_subscriber_t *sub, uint16_t appid);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_RSV_SUBSCRIBER_H */
