/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC TR 61850-90-5 Routable Profiles: R-GOOSE / R-SV
 *
 * Session/security layer wrapping the existing GOOSE/SV APDUs for
 * UDP/IP transport (unicast or multicast). Security extension per
 * IEC 62351-6 as adapted for routable profiles: the signature is
 * computed over the IP header + UDP header + SPDU (transport-layer
 * concern; this codec places/extracts the fields).
 *
 * FROZEN INTERFACE (WP-S4). The semantic contract is fixed here; the
 * exact wire layout of the 90-5 session header is derived by WP-4a
 * from the owned TR 61850-90-5 and public technical literature, and
 * must be documented in the implementation.
 */

#ifndef IEC61850_R_PROFILE_H
#define IEC61850_R_PROFILE_H

#include "asn1/goose_ber.h"
#include "asn1/sv_ber.h"

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Commonly configured UDP ports (confirm against the owned TR) */
#define IEC61850_RGOOSE_PORT_DEFAULT 102U
#define IEC61850_RSV_PORT_DEFAULT    103U

#define IEC61850_R_MAX_SIGNATURE_LEN 512U /* matches GOOSE_MAX_SIGNATURE_LEN */
#define IEC61850_R_MAX_HEADER_LEN    64U  /* session header + security headroom */

/* 90-5 security extension (62351-6 for routable profiles) */
typedef struct {
    bool present;
    uint16_t key_id;      /* active key identifier */
    uint32_t time_of_day; /* replay-protection timestamp */
    uint8_t signature[IEC61850_R_MAX_SIGNATURE_LEN];
    size_t signature_len;
} iec61850_r_security_t;

/* Decoded 90-5 session-header metadata */
typedef struct {
    size_t spdu_length;   /* total SPDU length (wire) */
    uint16_t session_id;  /* R-session identifier (0 when absent) */
    iec61850_r_security_t security;
} iec61850_r_header_t;

/**
 * Encode a complete R-GOOSE SPDU (session header + optional security
 * extension + GOOSE APDU). sec == NULL omits the security extension.
 * When sec is present, the signature must already be computed by the
 * caller over IP header + UDP header + SPDU.
 * @return total SPDU length, or negative errno.
 */
int iec61850_rgoose_encode(const goose_apdu_t *apdu,
                            const iec61850_r_security_t *sec,
                            uint8_t *buf, size_t buflen);

/**
 * Decode and validate an R-GOOSE SPDU. hdr may be NULL.
 * @return SPDU length consumed, or negative errno on malformed input.
 */
int iec61850_rgoose_decode(const uint8_t *buf, size_t buflen,
                            goose_apdu_t *apdu,
                            iec61850_r_header_t *hdr);

/**
 * Encode a complete R-SV SPDU (session header + optional security
 * extension + SV APDU). Same contract as iec61850_rgoose_encode().
 * @return total SPDU length, or negative errno.
 */
int iec61850_rsv_encode(const sv_apdu_t *apdu,
                         const iec61850_r_security_t *sec,
                         uint8_t *buf, size_t buflen);

/**
 * Decode and validate an R-SV SPDU. hdr may be NULL.
 * @return SPDU length consumed, or negative errno on malformed input.
 */
int iec61850_rsv_decode(const uint8_t *buf, size_t buflen,
                         sv_apdu_t *apdu,
                         iec61850_r_header_t *hdr);

/**
 * 90-5 replay window: true when tod_received is within the acceptance
 * window relative to tod_last (handles time-of-day wraparound).
 * The window size follows the TR; WP-4a implements and documents it.
 */
bool iec61850_r_time_in_window(uint32_t tod_received, uint32_t tod_last);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_R_PROFILE_H */
