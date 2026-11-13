/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * ptp_message.h — IEEE 1588-2008 (PTPv2) message codec.
 *
 * Pure computation: no I/O, no allocation. Parses and builds the
 * wire format used by the IEC 61850-9-3 / IEEE 1588-2008 power
 * profile: common header (34 bytes), Announce, Sync, Follow_Up,
 * Delay_Req and Delay_Resp bodies, 80-bit PTP timestamps, and the
 * dataset comparison used by best-master selection.
 */

#ifndef IEC61850_PTP_MESSAGE_H
#define IEC61850_PTP_MESSAGE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Message types (1588-2008 table 19, low nibble of byte 0). */
#define PTP_MSG_SYNC                 0x00
#define PTP_MSG_DELAY_REQ            0x01
#define PTP_MSG_PDELAY_REQ           0x02
#define PTP_MSG_PDELAY_RESP          0x03
#define PTP_MSG_FOLLOW_UP            0x08
#define PTP_MSG_DELAY_RESP           0x09
#define PTP_MSG_ANNOUNCE             0x0B
#define PTP_MSG_SIGNALING            0x0C
#define PTP_MSG_MANAGEMENT           0x0D

#define PTP_VERSION_PTP              2
#define PTP_HEADER_LEN               34
#define PTP_TIMESTAMP_LEN            10
#define PTP_CLOCK_IDENTITY_LEN       8
#define PTP_MAX_MESSAGE_LEN          128

/* FlagField bits (byte 0 / byte 1). */
#define PTP_FLAG_TWO_STEP            (1u << 1)
#define PTP_FLAG_LEAP61              (1u << 9)
#define PTP_FLAG_LEAP59              (1u << 10)
#define PTP_FLAG_UTC_OFFSET_VALID    (1u << 11)
#define PTP_FLAG_PTP_TIMESCALE       (1u << 12)
#define PTP_FLAG_TIME_TRACEABLE      (1u << 13)
#define PTP_FLAG_FREQ_TRACEABLE      (1u << 14)

/* PTP timestamp: 48-bit seconds + 32-bit nanoseconds. Internally
 * seconds + nanoseconds (differences fit 64-bit ns at the call
 * sites; full range conversion is provided for the wire format). */
typedef struct {
    uint64_t seconds;
    uint32_t nanoseconds;
} ptp_timestamp_t;

/* PortIdentity: clockIdentity (8) + portNumber (2). */
typedef struct {
    uint8_t  clock_identity[PTP_CLOCK_IDENTITY_LEN];
    uint16_t port_number;
} ptp_port_identity_t;

/* ClockQuality (Announce). */
typedef struct {
    uint8_t  clock_class;
    uint8_t  clock_accuracy;
    uint16_t offset_scaled_log_variance;
} ptp_clock_quality_t;

/* Common header (all messages). */
typedef struct {
    uint8_t  message_type;      /* low nibble */
    uint8_t  version_ptp;
    uint16_t message_length;
    uint8_t  domain_number;
    uint16_t flag_field;
    int64_t  correction_ns;     /* correctionField, converted from ns*2^16 */
    ptp_port_identity_t source_port_identity;
    uint16_t sequence_id;
    int8_t   log_message_interval;
} ptp_header_t;

/* Announce body (30 bytes after the header). */
typedef struct {
    ptp_timestamp_t   origin_timestamp;
    uint16_t          current_utc_offset;
    uint8_t           grandmaster_priority1;
    ptp_clock_quality_t grandmaster_clock_quality;
    uint8_t           grandmaster_priority2;
    uint8_t           grandmaster_identity[PTP_CLOCK_IDENTITY_LEN];
    uint16_t          steps_removed;
    uint8_t           time_source;
} ptp_announce_t;

/* Sync / Delay_Req body (10 bytes): originTimestamp. */
typedef struct {
    ptp_timestamp_t origin_timestamp;
} ptp_sync_t;

/* Follow_Up body (10 bytes): preciseOriginTimestamp. */
typedef struct {
    ptp_timestamp_t precise_origin_timestamp;
} ptp_follow_up_t;

/* Delay_Resp body (20 bytes): receiveTimestamp +
 * requestingPortIdentity. */
typedef struct {
    ptp_timestamp_t   receive_timestamp;
    ptp_port_identity_t requesting_port_identity;
} ptp_delay_resp_t;

/* --- codec --------------------------------------------------------- */

/**
 * Parse a PTP message. Fills header and (when non-NULL) the
 * type-specific body. Returns the message type on success,
 * -EINVAL on malformed input (bad version, length, or type).
 */
int ptp_parse(const uint8_t *buf, size_t len,
              ptp_header_t *hdr, ptp_announce_t *announce,
              ptp_sync_t *sync, ptp_follow_up_t *follow_up,
              ptp_delay_resp_t *delay_resp);

/**
 * Build a PTP message. Returns the message length, or -EINVAL.
 * The unused body pointers may be NULL. correction_ns lands in the
 * header for every type.
 */
int ptp_build(uint8_t *buf, size_t cap, uint8_t message_type,
              uint8_t domain, uint16_t flags, int64_t correction_ns,
              const ptp_port_identity_t *source,
              uint16_t sequence_id, int8_t log_message_interval,
              const ptp_announce_t *announce,
              const ptp_timestamp_t *origin_timestamp,
              const ptp_timestamp_t *precise_origin_timestamp,
              const ptp_delay_resp_t *delay_resp);

/**
 * Best-master dataset comparison (1588-2008 §9.3.4, port dataset
 * comparison D0 vs D1). Returns negative when a is better,
 * positive when b is better, 0 when identical (tie broken by
 * portIdentity upstream).
 */
int ptp_dataset_compare(uint8_t a_prio1, const ptp_clock_quality_t *a_q,
                        uint8_t a_prio2,
                        const uint8_t a_identity[PTP_CLOCK_IDENTITY_LEN],
                        uint16_t a_steps_removed,
                        uint8_t b_prio1, const ptp_clock_quality_t *b_q,
                        uint8_t b_prio2,
                        const uint8_t b_identity[PTP_CLOCK_IDENTITY_LEN],
                        uint16_t b_steps_removed);

/* Timestamp helpers. */
int64_t ptp_timestamp_diff_ns(const ptp_timestamp_t *a,
                              const ptp_timestamp_t *b);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_PTP_MESSAGE_H */
