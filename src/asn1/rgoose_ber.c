/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC TR 61850-90-5 R-GOOSE Codec
 *
 * Wire-format derivation (CLEAN ROOM, WP-4a)
 * ==========================================
 *
 * The octet layout below was derived without reference to any other
 * protocol implementation's source code, from the following public
 * technical literature:
 *
 * [S1] S.R. Firouzi, L. Vanfretti, A. Ruiz-Alvarez, H. Hooshyar,
 *      F. Mahmood, "Interpreting and implementing IEC 61850-90-5
 *      Routed-Sampled Value and Routed-GOOSE protocols for IEEE
 *      C37.118.2 compliant wide-area synchrophasor data transfer",
 *      Electric Power Systems Research 144 (2017) 255-267,
 *      Section 3.3 and Fig. 8 ("IEC 61850-90-5 R-SV/R-GOOSE message
 *      specification"). Describes the session-protocol parameter
 *      encoding (SI/LI/PI/LI/PV) and every field size.
 * [S2] S.A. Ndzeku, "Development of authentication algorithms for
 *      IEC 61850 GOOSE and Sampled Values", MEng thesis, Cape
 *      Peninsula University of Technology, 2023. Quotes byte-level
 *      constants that independently confirm [S1]: SI=0xA1,
 *      outer LI=0x18 (24), common-header LI=0x16 (22), the field
 *      sizes and the SPDU/Payload length coverage rules.
 * [S3] M. Adamiak, H. Falk, C. DuBose, "Overview and Applications of
 *      Secure Routable GOOSE and Sample Values", PAC World (2022):
 *      enumerates the session-header fields (session number, version
 *      number, time of current key, time until next key, key
 *      identifier) — consistent with [S1]/[S2].
 *
 * The owned IEC TR 61850-90-5 document was NOT available in this
 * environment; every layout decision below is flagged for conformance
 * review against it (see the WP-4a report).
 *
 * R-GOOSE SPDU (90-5 A-profile, non-tunneled) — byte offsets:
 *
 *   off  len  field
 *   ---  ---  -----
 *    0    1   SI  — session identifier; 0xA1 = non-tunneled GOOSE
 *    1    1   LI  — length of the session-header parameter area
 *                  (PI + inner LI + parameter value): 12 (plain)
 *                  or 24 (secured)                       [S1][S2]
 *    2    1   PI  — parameter identifier; 0x80 = common session
 *                  header                                  [S1][S2]
 *    3    1   LI  — length of the common-header parameter value:
 *                  10 (plain) or 22 (secured)             [S1][S2]
 *    4    4   SPDU Length — covers SPDU Number (offset 8)
 *                  through the end of the signature; the TR
 *                  maximum is 65,517                       [S1][S2]
 *    8    4   SPDU Number — duplicate/out-of-order detection [S1]
 *   12    2   Version — 1 in this profile                   [S1]
 *   --- security extension (present iff secured) ---------------
 *   14    4   Time of Current Key — seconds since epoch      [S1]
 *   18    2   Time to Next Key — minutes (signed)            [S1]
 *   20    2   Security Algorithms (encryption | HMAC)        [S1]
 *   22    4   Key ID — assigned by the KDC                   [S1]
 *   --- session user information -------------------------------
 *   H=14  4   Payload Length — covers itself + the payload
 *                  attributes + the APDU, excludes the
 *                  signature; TR maximum 65,399              [S1][S2]
 *   H+4   1   Payload Type — 0x81 = non-tunneled GOOSE APDU  [S1]
 *   H+5   1   Simulation (boolean; true = test payload)      [S1]
 *   H+6   2   APPID — application association identifier     [S1]
 *   H+8   2   APDU Length — GOOSE PDU length + 2 (i.e. it
 *                  includes itself)                          [S1]
 *   H+10  N   GOOSE APDU (BER, IEC 61850-8-1)                [S1]
 *   --- signature (present iff secured) ------------------------
 *   H+10+N 1  Signature tag — 0x85                           [S1]
 *   +1     1  Signature length S (single byte, so S <= 255)  [S1]
 *   +2     S  Signature value                                [S1]
 *
 * H = 14 (plain, LI=12) or 26 (secured, LI=24). Plain total =
 * 24 + N; secured total = 38 + N + S.
 *
 * Mapping onto the frozen r_profile.h contract (revised WP-S4):
 *   - hdr->spdu_length          <- total SPDU byte count (= consumed).
 *     The wire SPDU Length field counts SPDU Number..end-of-
 *     signature, i.e. (total - 8); the decoder cross-validates it.
 *   - hdr->spdu_number          <- SPDU Number (u32), taken from the
 *     explicit encode parameter (duplicate/out-of-order detection).
 *   - hdr->appid                <- APPID (u16), explicit encode
 *     parameter.
 *   - security.key_id           <- full 4-octet wire Key ID.
 *   - security.time_of_current_key <- Time of Current Key (u32,
 *     epoch seconds).
 *   - security.time_to_next_key <- Time to Next Key (u16, minutes).
 *     Caller-zeroed emission: 0 = no scheduled key rotation
 *     indicated (the TR gives no distinguished meaning to zero
 *     beyond "not indicated").
 *   - security.security_algos   <- Security Algorithms (u16
 *     encryption|HMAC bits). Caller-zeroed emission: 0 = MACNone /
 *     no algorithm indicated (the TR's testing option).
 *   - All security fields are passed through verbatim on encode and
 *     extracted fully on decode; the codec assigns no semantics
 *     beyond placement.
 *   - sec == NULL (or !sec->present) omits the security extension
 *     entirely (plain profile, no 0x85 TLV). The TR's MACNone test
 *     mode (security block present, zero-length signature) is
 *     representable with sec->present && signature_len == 0 and is
 *     accepted by the decoder, as is a fully plain SPDU.
 *
 * Implemented against the frozen interface in
 * include/iec61850/asn1/r_profile.h (WP-S4).
 */

#include "asn1/r_profile.h"
#include "asn1/goose_ber_decode.h"

#include <errno.h>
#include <string.h>

/* --- 90-5 session-protocol constants (sources [S1][S2] above) --- */

#define RGOOSE_SI                0xA1U /* non-tunneled GOOSE APDU */
#define RGOOSE_PAYLOAD_TYPE      0x81U /* non-tunneled GOOSE APDU */

#define R_PI_COMMON_HEADER       0x80U /* common session header PI */
#define R_COMMON_LEN_PLAIN       10U   /* common-header PV, plain */
#define R_COMMON_LEN_SECURED     22U   /* common-header PV, secured */
#define R_PARAM_AREA_PLAIN       12U   /* PI + LI + PV, plain */
#define R_PARAM_AREA_SECURED     24U   /* PI + LI + PV, secured */
#define R_HDR_LEN_PLAIN          14U   /* SI + LI + param area, plain */
#define R_HDR_LEN_SECURED        26U   /* SI + LI + param area, secured */

#define R_VERSION                1U    /* session protocol version */
#define R_SPDU_LEN_MAX           65517U /* TR maximum (SPDU Length) */
#define R_PAYLOAD_LEN_MAX        65399U /* TR maximum (Payload Length) */

#define R_SIGNATURE_TAG          0x85U
#define R_SIGNATURE_WIRE_MAX     255U  /* 1-byte wire length field */

/* Payload Length + Payload Type + Simulation + APPID + APDU Length */
#define R_USERINFO_FIXED         10U

/* Inner encoder documented minimum buffer (ACSL contracts) */
#define R_INNER_BUF_MIN          64U

/* --- big-endian field helpers (bounds pre-validated by callers) --- */

static void rgoose_put_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8U);
    p[1] = (uint8_t)v;
}

static void rgoose_put_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24U);
    p[1] = (uint8_t)(v >> 16U);
    p[2] = (uint8_t)(v >> 8U);
    p[3] = (uint8_t)v;
}

static uint16_t rgoose_get_be16(const uint8_t *p)
{
    uint32_t v = (uint32_t)p[0];

    v = (v << 8U) | (uint32_t)p[1];
    return (uint16_t)v;
}

static uint32_t rgoose_get_be32(const uint8_t *p)
{
    uint32_t v = (uint32_t)p[0];

    v = (v << 8U) | (uint32_t)p[1];
    v = (v << 8U) | (uint32_t)p[2];
    v = (v << 8U) | (uint32_t)p[3];
    return v;
}

int iec61850_rgoose_encode(const goose_apdu_t *apdu, uint16_t appid,
                            uint32_t spdu_number,
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
        /* Honour the inner encoder's documented buffer minimum. */
        return -ENOSPC;
    }

    /* Inner GOOSE APDU at its final position (after the session user
     * information); the session header is filled in afterwards
     * (lengths back-patched from pdu_len). */
    ret = goose_encode_apdu(&buf[hdr_len + R_USERINFO_FIXED], inner_buflen,
                            apdu, &pdu_len);
    if (ret != GOOSE_BER_OK) {
        return (ret == GOOSE_BER_ERR_BUFFER_FULL) ? -ENOSPC : -EINVAL;
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
    buf[0] = RGOOSE_SI;
    buf[1] = (uint8_t)(secured ? R_PARAM_AREA_SECURED : R_PARAM_AREA_PLAIN);
    buf[2] = R_PI_COMMON_HEADER;
    buf[3] = (uint8_t)(secured ? R_COMMON_LEN_SECURED : R_COMMON_LEN_PLAIN);
    rgoose_put_be32(&buf[4], (uint32_t)spdu_len_field);
    rgoose_put_be32(&buf[8], spdu_number);
    rgoose_put_be16(&buf[12], (uint16_t)R_VERSION);
    if (secured) {
        rgoose_put_be32(&buf[14], sec->time_of_current_key);
        rgoose_put_be16(&buf[18], sec->time_to_next_key);
        rgoose_put_be16(&buf[20], sec->security_algos);
        rgoose_put_be32(&buf[22], sec->key_id);
    }

    /* Session user information */
    rgoose_put_be32(&buf[hdr_len], (uint32_t)pay_len);
    buf[hdr_len + 4U] = RGOOSE_PAYLOAD_TYPE;
    buf[hdr_len + 5U] = 0U; /* Simulation: false */
    rgoose_put_be16(&buf[hdr_len + 6U], appid);
    rgoose_put_be16(&buf[hdr_len + 8U], (uint16_t)apdu_len_field);

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

int iec61850_rgoose_decode(const uint8_t *buf, size_t buflen,
                            goose_apdu_t *apdu,
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
    size_t consumed = 0U;
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
    if (buf[0] != RGOOSE_SI) {
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

    spdu_len = rgoose_get_be32(&buf[4]);
    if (spdu_len > R_SPDU_LEN_MAX) {
        return -EBADMSG;
    }
    spdu_end = 8U + (size_t)spdu_len; /* SPDU Number .. end of signature */
    if (spdu_end > buflen) {
        return -EBADMSG; /* overspecified SPDU Length */
    }
    if (rgoose_get_be16(&buf[12]) != (uint16_t)R_VERSION) {
        return -EPROTONOSUPPORT;
    }

    /* Security-extension metadata (reads bounded: buflen >= hdr_len) */
    if (hdr != NULL) {
        hdr->spdu_length = 0U;
        hdr->spdu_number = 0U;
        hdr->appid = 0U;
        hdr->security.present = secured;
        hdr->security.key_id = 0U;
        hdr->security.time_of_current_key = 0U;
        hdr->security.time_to_next_key = 0U;
        hdr->security.security_algos = 0U;
        hdr->security.signature_len = 0U;
        if (secured) {
            hdr->security.time_of_current_key = rgoose_get_be32(&buf[14]);
            hdr->security.time_to_next_key = rgoose_get_be16(&buf[18]);
            hdr->security.security_algos = rgoose_get_be16(&buf[20]);
            hdr->security.key_id = rgoose_get_be32(&buf[22]);
        }
    }

    /* --- session user information --- */

    user_off = hdr_len;
    if (spdu_end < (user_off + R_USERINFO_FIXED)) {
        return -EBADMSG;
    }
    pay_len = (size_t)rgoose_get_be32(&buf[user_off]);
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

    if (buf[user_off + 4U] != RGOOSE_PAYLOAD_TYPE) {
        return -EPROTONOSUPPORT;
    }
    appid = rgoose_get_be16(&buf[user_off + 6U]);
    apdu_len_field = (size_t)rgoose_get_be16(&buf[user_off + 8U]);
    if (apdu_len_field < 2U) {
        return -EBADMSG;
    }
    /* Payload Length == self(4) + attrs(4) + APDU Length field */
    if (pay_len != (8U + apdu_len_field)) {
        return -EBADMSG;
    }
    pdu_len = apdu_len_field - 2U;
    pdu_off = user_off + R_USERINFO_FIXED;

    /* --- inner GOOSE APDU (tight span; inner decoder re-validates
     * the BER lengths against pdu_len) --- */

    ret = goose_decode_apdu_ex(&buf[pdu_off], pdu_len, apdu, &consumed);
    if (ret != GOOSE_BER_OK) {
        return -EBADMSG;
    }
    if (consumed != pdu_len) {
        return -EBADMSG; /* APDU Length over/under-specifies the PDU */
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
        hdr->spdu_number = rgoose_get_be32(&buf[8]);
        hdr->appid = appid;
    }

    return (int)spdu_end;
}
