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

/* 90-5 security extension (62351-6 for routable profiles).
 * Wire field sizes per the WP-4a clean-room derivation. */
typedef struct {
    bool present;
    uint32_t key_id;               /* KDC-assigned key identifier (4 octets) */
    uint32_t time_of_current_key;  /* epoch seconds of the active key */
    uint16_t time_to_next_key;     /* minutes until the next key activates */
    uint16_t security_algos;       /* security-algorithm bits */
    uint8_t signature[IEC61850_R_MAX_SIGNATURE_LEN];
    size_t signature_len;          /* wire limit 255; encode rejects larger */
} iec61850_r_security_t;

/* Decoded 90-5 session-header metadata */
typedef struct {
    size_t spdu_length;   /* total SPDU bytes (wire Length field = total - 8) */
    uint32_t spdu_number; /* duplicate/out-of-order detection counter */
    uint16_t appid;       /* payload APPID */
    iec61850_r_security_t security;
} iec61850_r_header_t;

/**
 * Encode a complete R-GOOSE SPDU (session header + optional security
 * extension + GOOSE APDU). sec == NULL omits the security extension.
 * appid and spdu_number populate the payload-attribute APPID and the
 * session-header SPDU Number (duplicate detection). When sec is
 * present, the signature must already be computed by the caller over
 * IP header + UDP header + SPDU.
 * @return total SPDU length, or negative errno (-EOVERFLOW when the
 *         signature exceeds the 255-octet wire limit).
 */
int iec61850_rgoose_encode(const goose_apdu_t *apdu, uint16_t appid,
                            uint32_t spdu_number,
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
int iec61850_rsv_encode(const sv_apdu_t *apdu, uint16_t appid,
                         uint32_t spdu_number,
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
 * 90-5 replay window: true when t_received is within the acceptance
 * tolerance of t_last. Wraparound-safe circular comparison (correct
 * for both time-of-day and epoch-second domains). The tolerance
 * follows the TR; the implementation documents its choice.
 */
bool iec61850_r_time_in_window(uint32_t t_received, uint32_t t_last);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_R_PROFILE_H */
