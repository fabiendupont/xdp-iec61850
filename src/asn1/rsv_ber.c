/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC TR 61850-90-5 R-SV Codec + 90-5 replay window
 *
 * Wire-format derivation (CLEAN ROOM, WP-4a)
 * ==========================================
 *
 * The R-SV SPDU uses exactly the same 90-5 session-layer layout as
 * R-GOOSE (documented field-by-field in src/asn1/rgoose_ber.c) with
 * two profile constants differing:
 *
 *   - SI (offset 0)          = 0xA2  (non-tunneled SV APDU)
 *   - Payload Type (H+4)     = 0x82  (non-tunneled SV APDU)
 *
 * Everything else — the SI/LI/PI/LI parameter encoding, the common
 * session header (SPDU Length, SPDU Number, Version), the security
 * extension (Time of Current Key, Time to Next Key, Security
 * Algorithms, Key ID), the session user information (Payload
 * Length, Payload Type, Simulation, APPID, APDU Length) and the
 * 0x85 signature TLV — is identical, per:
 *
 * [S1] Firouzi et al., "Interpreting and implementing IEC 61850-90-5
 *      Routed-Sampled Value and Routed-GOOSE protocols...", Electric
 *      Power Systems Research 144 (2017) 255-267, Section 3.3/Fig. 8
 *      (one common A-profile session specification for R-SV and
 *      R-GOOSE; SI 0xA2 / payload type 0x82 for non-tunneled SV).
 * [S2] Ndzeku, MEng thesis, CPUT 2023 — byte-level constants for the
 *      R-GOOSE/R-SV session layer that confirm [S1] (LI=0x18/0x16,
 *      field sizes, length coverage rules, 0x85 signature tag).
 *
 * Byte-offset table and the mapping onto the frozen r_profile.h
 * contract (flags included): see the header comment of rgoose_ber.c.
 * SPDU Number is sourced from the first ASDU's smpCnt (duplicate/
 * out-of-order detection role); the frozen API has no explicit
 * input for it.
 *
 * 90-5 replay window
 * ==================
 * The frozen contract requires a time-of-day comparison "allowing a
 * tolerance" with midnight wraparound. The public literature ([S1],
 * [S2], PAC World [S3]) describes 90-5 replay protection in terms of
 * the Time of Current Key and SPDU Number but does not state a
 * numeric acceptance window, and the owned TR was not available in
 * this environment. This implementation therefore:
 *
 *   - treats the timestamps as IEC 61850 time-of-day values in
 *     milliseconds since midnight (domain 86,400,000 ms, wrapping
 *     at midnight — matching the frozen u32 field and the
 *     wraparound requirement);
 *   - accepts a received timestamp iff its circular distance from
 *     the last accepted one on the 24-hour circle is at most
 *     IEC61850_R_REPLAY_WINDOW_MS (symmetric tolerance, covering
 *     both replayed-old messages and forward clock skew).
 *
 * The 10-second window default is a WP-4a choice, flagged for
 * conformance review against the owned TR 61850-90-5.
 *
 * Implemented against the frozen interface in
 * include/iec61850/asn1/r_profile.h (WP-S4).
 */

#include "asn1/r_profile.h"
#include "asn1/goose_ber_decode.h"

#include <errno.h>
#include <string.h>

/* --- 90-5 session-protocol constants (sources [S1][S2] above) --- */

#define RSV_SI                   0xA2U /* non-tunneled SV APDU */
#define RSV_PAYLOAD_TYPE         0x82U /* non-tunneled SV APDU */

#define R_PI_COMMON_HEADER       0x80U
#define R_COMMON_LEN_PLAIN       10U
#define R_COMMON_LEN_SECURED     22U
#define R_PARAM_AREA_PLAIN       12U
#define R_PARAM_AREA_SECURED     24U
#define R_HDR_LEN_PLAIN          14U
#define R_HDR_LEN_SECURED        26U

#define R_VERSION                1U
#define R_SPDU_LEN_MAX           65517U
#define R_PAYLOAD_LEN_MAX        65399U

#define R_SIGNATURE_TAG          0x85U
#define R_SIGNATURE_WIRE_MAX     255U

#define R_USERINFO_FIXED         10U
#define R_INNER_BUF_MIN          64U

/* --- replay window (see header comment; TR conformance flag) --- */

#define R_MS_PER_DAY             86400000U /* milliseconds per day */
#define R_REPLAY_WINDOW_MS       10000U    /* 10 s acceptance window */

/* --- big-endian field helpers (bounds pre-validated by callers) --- */

static void rsv_put_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8U);
    p[1] = (uint8_t)v;
}

static void rsv_put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24U);
    p[1] = (uint8_t)(v >> 16U);
    p[2] = (uint8_t)(v >> 8U);
    p[3] = (uint8_t)v;
}

static uint16_t rsv_get_be16(const uint8_t *p)
{
    uint32_t v = (uint32_t)p[0];

    v = (v << 8U) | (uint32_t)p[1];
    return (uint16_t)v;
}

static uint32_t rsv_get_be32(const uint8_t *p)
{
    uint32_t v = (uint32_t)p[0];

    v = (v << 8U) | (uint32_t)p[1];
    v = (v << 8U) | (uint32_t)p[2];
    v = (v << 8U) | (uint32_t)p[3];
    return v;
}

int iec61850_rsv_encode(const sv_apdu_t *apdu,
                         const iec61850_r_security_t *sec,
                         uint8_t *buf, size_t buflen)
{
    size_t hdr_len;
    size_t inner_buflen;
    size_t pdu_len = 0U;
    size_t apdu_len_field;
    size_t pay_len;
    size_t sig_total;
    size_t total;
    size_t spdu_len_field;
    uint32_t spdu_number;
    int ret;
    bool secured;

    if ((apdu == NULL) || (buf == NULL)) {
        return -EINVAL;
    }

    secured = (sec != NULL) && sec->present;

    /* The wire signature length field is a single octet. */
    if (secured && (sec->signature_len > R_SIGNATURE_WIRE_MAX)) {
        return -EOVERFLOW;
    }

    hdr_len = secured ? R_HDR_LEN_SECURED : R_HDR_LEN_PLAIN;
    if (buflen < (hdr_len + R_USERINFO_FIXED)) {
        return -ENOSPC;
    }
    inner_buflen = buflen - hdr_len - R_USERINFO_FIXED;
    if (inner_buflen < R_INNER_BUF_MIN) {
        /* sv_encode_apdu requires buf_size >= 64. */
        return -ENOSPC;
    }

    /* Inner SV APDU at its final position (after the session user
     * information); the session header is filled in afterwards
     * (lengths back-patched from pdu_len). */
    ret = sv_encode_apdu(&buf[hdr_len + R_USERINFO_FIXED], inner_buflen,
                         apdu, &pdu_len);
    if (ret != SV_BER_OK) {
        return (ret == SV_BER_ERR_BUFFER_FULL) ? -ENOSPC : -EINVAL;
    }

    apdu_len_field = pdu_len + 2U; /* includes itself [S1] */
    pay_len = R_USERINFO_FIXED + pdu_len;
    sig_total = secured ? (2U + sec->signature_len) : 0U;
    total = hdr_len + pay_len + sig_total;

    if (total > buflen) {
        return -ENOSPC;
    }
    spdu_len_field = total - 8U; /* SPDU Number .. end of signature */
    if ((spdu_len_field > R_SPDU_LEN_MAX) || (pay_len > R_PAYLOAD_LEN_MAX)) {
        return -EOVERFLOW;
    }

    /* Session header */
    buf[0] = RSV_SI;
    buf[1] = (uint8_t)(secured ? R_PARAM_AREA_SECURED : R_PARAM_AREA_PLAIN);
    buf[2] = R_PI_COMMON_HEADER;
    buf[3] = (uint8_t)(secured ? R_COMMON_LEN_SECURED : R_COMMON_LEN_PLAIN);
    rsv_put_be32(&buf[4], (uint32_t)spdu_len_field);
    /* SPDU Number <- first ASDU's smpCnt (documented mapping) */
    spdu_number = (apdu->noASDU > 0U)
                      ? (uint32_t)apdu->asdu[0].smpCnt
                      : 0U;
    rsv_put_be32(&buf[8], spdu_number);
    rsv_put_be16(&buf[12], (uint16_t)R_VERSION);
    if (secured) {
        rsv_put_be32(&buf[14], sec->time_of_day);
        rsv_put_be16(&buf[18], 0U); /* Time to Next Key (no frozen field) */
        rsv_put_be16(&buf[20], 0U); /* Security Algorithms (no frozen field) */
        rsv_put_be32(&buf[22], (uint32_t)sec->key_id);
    }

    /* Session user information */
    rsv_put_be32(&buf[hdr_len], (uint32_t)pay_len);
    buf[hdr_len + 4U] = RSV_PAYLOAD_TYPE;
    buf[hdr_len + 5U] = 0U; /* Simulation: false */
    rsv_put_be16(&buf[hdr_len + 6U], 0U); /* APPID (no frozen input) */
    rsv_put_be16(&buf[hdr_len + 8U], (uint16_t)apdu_len_field);

    /* Signature (secured only; MACNone => zero length) */
    if (secured) {
        uint8_t *sig = &buf[hdr_len + R_USERINFO_FIXED + pdu_len];

        sig[0] = R_SIGNATURE_TAG;
        sig[1] = (uint8_t)sec->signature_len;
        if (sec->signature_len > 0U) {
            (void)memcpy(&sig[2], sec->signature, sec->signature_len);
        }
    }

    return (int)total;
}

int iec61850_rsv_decode(const uint8_t *buf, size_t buflen,
                         sv_apdu_t *apdu,
                         iec61850_r_header_t *hdr)
{
    size_t param_area;
    size_t hdr_len;
    size_t user_off;
    size_t spdu_end;
    size_t pay_len;
    size_t payload_end;
    size_t apdu_len_field;
    size_t pdu_len;
    size_t pdu_off;
    uint32_t spdu_len;
    uint16_t appid;
    bool secured;
    int ret;

    if ((buf == NULL) || (apdu == NULL)) {
        return -EINVAL;
    }

    /* --- session header: every wire length is validated against
     * buflen before any field is read (hardened-decoder discipline) */

    if (buflen < R_HDR_LEN_PLAIN) {
        return -EBADMSG;
    }
    if (buf[0] != RSV_SI) {
        return -EPROTONOSUPPORT;
    }
    param_area = buf[1];
    if ((param_area != R_PARAM_AREA_PLAIN) &&
        (param_area != R_PARAM_AREA_SECURED)) {
        return -EBADMSG;
    }
    if (buflen < (2U + param_area)) {
        return -EBADMSG;
    }
    if (buf[2] != R_PI_COMMON_HEADER) {
        return -EBADMSG;
    }
    if (((size_t)buf[3] + 2U) != param_area) {
        return -EBADMSG;
    }

    secured = (param_area == R_PARAM_AREA_SECURED);
    hdr_len = 2U + param_area; /* 14 (plain) or 26 (secured) */

    spdu_len = rsv_get_be32(&buf[4]);
    if (spdu_len > R_SPDU_LEN_MAX) {
        return -EBADMSG;
    }
    spdu_end = 8U + (size_t)spdu_len; /* SPDU Number .. end of signature */
    if (spdu_end > buflen) {
        return -EBADMSG; /* overspecified SPDU Length */
    }
    if (rsv_get_be16(&buf[12]) != (uint16_t)R_VERSION) {
        return -EPROTONOSUPPORT;
    }

    /* Security-extension metadata (reads bounded: buflen >= hdr_len) */
    if (hdr != NULL) {
        hdr->spdu_length = 0U;
        hdr->session_id = 0U;
        hdr->security.present = secured;
        hdr->security.key_id = 0U;
        hdr->security.time_of_day = 0U;
        hdr->security.signature_len = 0U;
        if (secured) {
            hdr->security.time_of_day = rsv_get_be32(&buf[14]);
            /* Wire Key ID is 4 bytes; frozen struct is u16 (flagged). */
            hdr->security.key_id =
                (uint16_t)(rsv_get_be32(&buf[22]) & 0xFFFFU);
        }
    }

    /* --- session user information --- */

    user_off = hdr_len;
    if (spdu_end < (user_off + R_USERINFO_FIXED)) {
        return -EBADMSG;
    }
    pay_len = (size_t)rsv_get_be32(&buf[user_off]);
    if (pay_len < R_USERINFO_FIXED) {
        return -EBADMSG;
    }
    if (pay_len > R_PAYLOAD_LEN_MAX) {
        return -EBADMSG;
    }
    if (pay_len > (spdu_end - user_off)) {
        return -EBADMSG; /* payload must fit before the signature */
    }
    payload_end = user_off + pay_len;

    if (buf[user_off + 4U] != RSV_PAYLOAD_TYPE) {
        return -EPROTONOSUPPORT;
    }
    appid = rsv_get_be16(&buf[user_off + 6U]);
    apdu_len_field = (size_t)rsv_get_be16(&buf[user_off + 8U]);
    if (apdu_len_field < 2U) {
        return -EBADMSG;
    }
    /* Payload Length == self(4) + attrs(4) + APDU Length field */
    if (pay_len != (8U + apdu_len_field)) {
        return -EBADMSG;
    }
    pdu_len = apdu_len_field - 2U;
    pdu_off = user_off + R_USERINFO_FIXED;

    /* --- inner SV APDU (tight span; inner decoder re-validates
     * the BER lengths against pdu_len) --- */

    ret = sv_decode_apdu(&buf[pdu_off], pdu_len, apdu);
    if (ret != SV_BER_OK) {
        return -EBADMSG;
    }
    { /* APDU Length must exactly cover the BER TLV (re-parse) */
        size_t off = 0U;
        uint8_t tag;
        size_t ber_len;

        if ((ber_decode_tag(&buf[pdu_off], pdu_len, &off, &tag) !=
             GOOSE_BER_OK) ||
            (ber_decode_length(&buf[pdu_off], pdu_len, &off, &ber_len) !=
             GOOSE_BER_OK)) {
            return -EBADMSG;
        }
        if ((off + ber_len) != pdu_len) {
            return -EBADMSG; /* APDU Length over/under-specifies the PDU */
        }
    }

    /* --- signature (optional; exact remainder of the SPDU) --- */

    if (payload_end < spdu_end) {
        size_t remain = spdu_end - payload_end;
        size_t sig_len;

        if (remain < 2U) {
            return -EBADMSG;
        }
        if (buf[payload_end] != R_SIGNATURE_TAG) {
            return -EBADMSG;
        }
        sig_len = buf[payload_end + 1U];
        if (remain != (2U + sig_len)) {
            return -EBADMSG; /* bad security-extension length */
        }
        if ((sig_len > 0U) && !secured) {
            return -EBADMSG; /* signature without key metadata */
        }
        if (hdr != NULL) {
            if (sig_len > 0U) {
                (void)memcpy(hdr->security.signature,
                             &buf[payload_end + 2U], sig_len);
            }
            hdr->security.signature_len = sig_len;
        }
    }

    if (hdr != NULL) {
        hdr->spdu_length = spdu_end; /* total SPDU byte count */
        hdr->session_id = appid;
    }

    return (int)spdu_end;
}

bool iec61850_r_time_in_window(uint32_t tod_received, uint32_t tod_last)
{
    uint32_t rec = tod_received % R_MS_PER_DAY;
    uint32_t last = tod_last % R_MS_PER_DAY;
    uint32_t fwd;  /* circular forward distance rec - last (mod day) */
    uint32_t dist; /* circular distance */

    if (rec >= last) {
        fwd = rec - last;
    } else {
        fwd = R_MS_PER_DAY - (last - rec);
    }
    dist = (fwd <= (R_MS_PER_DAY / 2U)) ? fwd : (R_MS_PER_DAY - fwd);

    return dist <= R_REPLAY_WINDOW_MS;
}
