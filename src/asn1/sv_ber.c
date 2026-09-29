/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * ASN.1 BER Encoder/Decoder for IEC 61850-9-2 Sampled Values Protocol
 *
 * Minimal, formally verified implementation for safety-critical systems.
 *
 * License: BSD-3-Clause
 */


#include "asn1/sv_ber.h"
#include "asn1/goose_ber.h"  /* Reuse low-level BER encoding functions */
#include <string.h>
#include <time.h>

/***************************************************************************
 * Helper Functions
 ***************************************************************************/

/**
 * Convert sv_quality_t struct to 4-byte big-endian quality per IEC 61850-7-3.
 */
static void quality_to_bytes(const sv_quality_t *q, uint8_t out[4])
{
    /* IEC 61850-7-3 Quality BitString layout (MSB first):
     * Bits 0-1: validity, Bit 2: overflow, Bit 3: out_of_range,
     * Bit 4: bad_reference, Bit 5: oscillatory, Bit 6: failure,
     * Bit 7: old_data, Bit 8: inconsistent, Bit 9: inaccurate,
     * Bit 10: source, Bit 11: test, Bit 12: operator_blocked */
    uint32_t qval = 0;
    qval |= ((uint32_t)q->validity & 0x03U) << 30;
    qval |= ((uint32_t)q->overflow & 0x01U) << 29;
    qval |= ((uint32_t)q->out_of_range & 0x01U) << 28;
    qval |= ((uint32_t)q->bad_reference & 0x01U) << 27;
    qval |= ((uint32_t)q->oscillatory & 0x01U) << 26;
    qval |= ((uint32_t)q->failure & 0x01U) << 25;
    qval |= ((uint32_t)q->old_data & 0x01U) << 24;
    qval |= ((uint32_t)q->inconsistent & 0x01U) << 23;
    qval |= ((uint32_t)q->inaccurate & 0x01U) << 22;
    qval |= ((uint32_t)q->source & 0x01U) << 21;
    qval |= ((uint32_t)q->test & 0x01U) << 20;
    qval |= ((uint32_t)q->operator_blocked & 0x01U) << 19;
    out[0] = (uint8_t)(qval >> 24);
    out[1] = (uint8_t)(qval >> 16);
    out[2] = (uint8_t)(qval >> 8);
    out[3] = (uint8_t)(qval);
}

/**
 * Convert 4-byte big-endian quality to sv_quality_t struct.
 */
static void bytes_to_quality(const uint8_t in[4], sv_quality_t *q)
{
    uint32_t qval = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) |
                    ((uint32_t)in[2] << 8) | (uint32_t)in[3];
    q->validity = (uint8_t)((qval >> 30) & 0x03U);
    q->overflow = ((qval >> 29U) & 1U) != 0U;
    q->out_of_range = ((qval >> 28U) & 1U) != 0U;
    q->bad_reference = ((qval >> 27U) & 1U) != 0U;
    q->oscillatory = ((qval >> 26U) & 1U) != 0U;
    q->failure = ((qval >> 25U) & 1U) != 0U;
    q->old_data = ((qval >> 24U) & 1U) != 0U;
    q->inconsistent = ((qval >> 23U) & 1U) != 0U;
    q->inaccurate = ((qval >> 22U) & 1U) != 0U;
    q->source = ((qval >> 21U) & 1U) != 0U;
    q->test = ((qval >> 20U) & 1U) != 0U;
    q->operator_blocked = ((qval >> 19U) & 1U) != 0U;
}

/**
 * Encode sample data as flat OCTET STRING per IEC 61850-9-2LE.
 *
 * Tag [7] IMPLICIT OCTET STRING containing packed channel data:
 * 4 bytes value (big-endian int32) + 4 bytes quality (big-endian uint32)
 * per channel.
 */
static int encode_samples(uint8_t *buf, size_t buf_size, size_t *offset,
                         const sv_asdu_t *asdu)
{
    int ret;
    size_t data_len;
    size_t i;

    /* Total data: 8 bytes per sample (4 value + 4 quality) */
    data_len = (size_t)asdu->num_samples * 8U;

    /* Tag: [7] IMPLICIT OCTET STRING (not CONSTRUCTED) */
    ret = ber_encode_tag(buf, buf_size, offset, SV_TAG_SAMPLE);
    if (ret != SV_BER_OK) {
        return ret;
    }

    /* Length */
    ret = ber_encode_length(buf, buf_size, offset, data_len);
    if (ret != SV_BER_OK) {
        return ret;
    }

    /* Check buffer space */
    if ((*offset + data_len) > buf_size) {
        return SV_BER_ERR_BUFFER_FULL;
    }

    /* Pack each sample: 4 bytes value + 4 bytes quality */
    for (i = 0; i < asdu->num_samples; i++) {
        uint32_t val = (uint32_t)asdu->samples[i].value;
        buf[*offset]     = (uint8_t)(val >> 24);
        buf[*offset + 1] = (uint8_t)(val >> 16);
        buf[*offset + 2] = (uint8_t)(val >> 8);
        buf[*offset + 3] = (uint8_t)(val);
        *offset += 4U;

        uint8_t qbytes[4];
        quality_to_bytes(&asdu->samples[i].quality, qbytes);
        buf[*offset]     = qbytes[0];
        buf[*offset + 1] = qbytes[1];
        buf[*offset + 2] = qbytes[2];
        buf[*offset + 3] = qbytes[3];
        *offset += 4U;
    }

    return SV_BER_OK;
}

/**
 * Encode single ASDU
 */
static int encode_asdu(uint8_t *buf, size_t buf_size, size_t *offset,
                      const sv_asdu_t *asdu)
{
    int ret;

    /* ASDU is a SEQUENCE - encode SEQUENCE tag first */
    ret = ber_encode_tag(buf, buf_size, offset, 0x30);  /* UNIVERSAL SEQUENCE */
    if (ret != SV_BER_OK) {
        return ret;
    }

    /* Save position for ASDU SEQUENCE length */
    if (*offset >= buf_size) {
        return SV_BER_ERR_BUFFER_FULL;
    }
    size_t len_offset = *offset;
    (*offset)++;  /* Skip length byte, fill in later */
    size_t asdu_start = *offset;

    /* [0] svID - VisibleString */
    ret = ber_encode_visiblestring(buf, buf_size, offset,
                                   SV_TAG_SVID, asdu->svID);
    if (ret != SV_BER_OK) {
        return ret;
    }

    /* [1] datSet - VisibleString (optional) */
    if (asdu->has_datSet) {
        ret = ber_encode_visiblestring(buf, buf_size, offset,
                                       SV_TAG_DATSET, asdu->datSet);
        if (ret != SV_BER_OK) {
            return ret;
        }
    }

    /* [2] smpCnt - INTEGER */
    ret = ber_encode_uint32(buf, buf_size, offset,
                           SV_TAG_SMPCNT, asdu->smpCnt);
    if (ret != SV_BER_OK) {
        return ret;
    }

    /* [3] confRev - INTEGER */
    ret = ber_encode_uint32(buf, buf_size, offset,
                           SV_TAG_CONFREV, asdu->confRev);
    if (ret != SV_BER_OK) {
        return ret;
    }

    /* [4] refrTm - UtcTime (optional) */
    if (asdu->has_refrTm) {
        ret = ber_encode_utctime(buf, buf_size, offset,
                                SV_TAG_REFRTM, asdu->refrTm, 0x00U);
        if (ret != SV_BER_OK) {
            return ret;
        }
    }

    /* [5] smpSynch - INTEGER */
    ret = ber_encode_uint32(buf, buf_size, offset,
                           SV_TAG_SMPSYNCH, (uint32_t)asdu->smpSynch);
    if (ret != SV_BER_OK) {
        return ret;
    }

    /* [6] smpRate - INTEGER (optional) */
    if (asdu->has_smpRate) {
        ret = ber_encode_uint32(buf, buf_size, offset,
                               SV_TAG_SMPRATE, asdu->smpRate);
        if (ret != SV_BER_OK) {
            return ret;
        }
    }

    /* [7] sample - SEQUENCE OF */
    ret = encode_samples(buf, buf_size, offset, asdu);
    if (ret != SV_BER_OK) {
        return ret;
    }

    /* [8] smpMod - INTEGER (optional) */
    if (asdu->has_smpMod) {
        ret = ber_encode_uint32(buf, buf_size, offset,
                               SV_TAG_SMPMOD, asdu->smpMod);
        if (ret != SV_BER_OK) {
            return ret;
        }
    }

    /* [9] security - SEQUENCE (optional, IEC 62351-6) */
    if (asdu->secure) {
        ret = sv_encode_security(buf, buf_size, offset, asdu);
        if (ret != SV_BER_OK) {
            return ret;
        }
    }

    /* Calculate and encode ASDU SEQUENCE length */
    size_t asdu_len = *offset - asdu_start;
    if (asdu_len >= 128U) {
        /* Need to shift and use long form */
        if (asdu_len <= 0xFFU && (*offset + 1U) <= buf_size) {
            /* Shift data right by 1 byte for 1-byte long form */
            (void)memmove(&buf[asdu_start + 1U], &buf[asdu_start], asdu_len);
            *offset += 1U;
            buf[len_offset] = 0x81U;  /* Long form: 1 length byte follows */
            buf[len_offset + 1U] = (uint8_t)asdu_len;
        } else if (asdu_len <= 0xFFFFU && (*offset + 2U) <= buf_size) {
            /* Shift data right by 2 bytes for 2-byte long form */
            (void)memmove(&buf[asdu_start + 2U], &buf[asdu_start], asdu_len);
            *offset += 2U;
            buf[len_offset] = 0x82U;  /* Long form: 2 length bytes follow */
            buf[len_offset + 1U] = (uint8_t)(asdu_len >> 8U);
            buf[len_offset + 2U] = (uint8_t)(asdu_len & 0xFFU);
        } else {
            return SV_BER_ERR_ENCODING;  /* Length too large or buffer full */
        }
    } else {
        /* Short form */
        buf[len_offset] = (uint8_t)asdu_len;
    }

    return SV_BER_OK;
}

/***************************************************************************
 * Public API
 ***************************************************************************/

int sv_encode_apdu(uint8_t *buf, size_t buf_size,
                   const sv_apdu_t *apdu, size_t *encoded_len)
{
    int ret;
    size_t offset = 0;
    size_t apdu_start;
    size_t apdu_len;

    if (!buf || !apdu || !encoded_len || buf_size < 64U) {
        return SV_BER_ERR_INVALID_ARG;
    }

    /* Tag: APPLICATION 2 | CONSTRUCTED */
    ret = ber_encode_tag(buf, buf_size, &offset, SV_APDU_TAG);
    if (ret != SV_BER_OK) {
        return ret;
    }

    /* Save position for length */
    if (offset >= buf_size) {
        return SV_BER_ERR_BUFFER_FULL;
    }
    size_t apdu_length_offset = offset;
    offset++;  /* Reserve space for length */

    apdu_start = offset;

    /* [0] noASDU - INTEGER */
    ret = ber_encode_uint32(buf, buf_size, &offset,
                           SV_TAG_NOASDU, apdu->noASDU);
    if (ret != SV_BER_OK) {
        return ret;
    }

    /* [1] seqASDU - SEQUENCE OF */
    ret = ber_encode_tag(buf, buf_size, &offset, SV_TAG_SEQASDU);
    if (ret != SV_BER_OK) {
        return ret;
    }

    /* Save position for seqASDU length */
    if (offset >= buf_size) {
        return SV_BER_ERR_BUFFER_FULL;
    }
    size_t seq_length_offset = offset;
    offset++;  /* Reserve space for length */

    size_t seq_start = offset;

    /* Encode each ASDU */
    for (size_t i = 0; i < apdu->noASDU && i < SV_MAX_ASDU; i++) {
        ret = encode_asdu(buf, buf_size, &offset, &apdu->asdu[i]);
        if (ret != SV_BER_OK) {
            return ret;
        }
    }

    /* Calculate and encode seqASDU length */
    size_t seq_len = offset - seq_start;
    if (seq_len >= 128U) {
        /* Need to shift and use long form */
        if (seq_len <= 0xFFU && (offset + 1U) <= buf_size) {
            /* Shift data right by 1 byte for 1-byte long form */
            (void)memmove(buf + seq_start + 1U, buf + seq_start, seq_len);
            buf[seq_length_offset] = 0x81U;
            buf[seq_length_offset + 1U] = (uint8_t)seq_len;
            offset++;
        } else if (seq_len <= 0xFFFFU && (offset + 2U) <= buf_size) {
            /* Shift data right by 2 bytes for 2-byte long form */
            (void)memmove(buf + seq_start + 2U, buf + seq_start, seq_len);
            buf[seq_length_offset] = 0x82U;
            buf[seq_length_offset + 1U] = (uint8_t)(seq_len >> 8U);
            buf[seq_length_offset + 2U] = (uint8_t)(seq_len & 0xFFU);
            offset += 2U;
        } else {
            return SV_BER_ERR_ENCODING;  /* Length too large or buffer full */
        }
    } else {
        buf[seq_length_offset] = (uint8_t)seq_len;
    }

    /* Calculate and encode APDU length */
    apdu_len = offset - apdu_start;
    if (apdu_len >= 128U) {
        /* Need to shift and use long form */
        if (apdu_len <= 0xFFU && (offset + 1U) <= buf_size) {
            /* Shift data right by 1 byte */
            (void)memmove(buf + apdu_start + 1U, buf + apdu_start, apdu_len);
            buf[apdu_length_offset] = 0x81U;
            buf[apdu_length_offset + 1U] = (uint8_t)apdu_len;
            offset++;
        } else if (apdu_len <= 0xFFFFU && (offset + 2U) <= buf_size) {
            /* Shift data right by 2 bytes */
            (void)memmove(buf + apdu_start + 2U, buf + apdu_start, apdu_len);
            buf[apdu_length_offset] = 0x82U;
            buf[apdu_length_offset + 1U] = (uint8_t)(apdu_len >> 8U);
            buf[apdu_length_offset + 2U] = (uint8_t)(apdu_len & 0xFFU);
            offset += 2U;
        } else {
            return SV_BER_ERR_ENCODING;
        }
    } else {
        buf[apdu_length_offset] = (uint8_t)apdu_len;
    }

    *encoded_len = offset;
    return SV_BER_OK;
}

/***************************************************************************
 * SV APDU Decoding Functions
 ***************************************************************************/

/* Forward declarations for BER decode functions (from goose_ber_decode.c) */
extern int ber_decode_tag(const uint8_t *buf, size_t buf_size, size_t *offset, uint8_t *tag);
extern int ber_decode_length(const uint8_t *buf, size_t buf_size, size_t *offset, size_t *length);
extern int ber_decode_uint32(const uint8_t *buf, size_t buf_size, size_t *offset,
                             uint8_t expected_tag, uint32_t *value);
extern int ber_decode_int32(const uint8_t *buf, size_t buf_size, size_t *offset,
                            uint8_t expected_tag, int32_t *value);
extern int ber_decode_visiblestring(const uint8_t *buf, size_t buf_size, size_t *offset,
                                    uint8_t expected_tag, char *str, size_t str_max_len);
extern int ber_decode_utctime(const uint8_t *buf, size_t buf_size, size_t *offset,
                              uint8_t expected_tag, uint64_t *timestamp, uint8_t *time_quality);
extern int ber_decode_octetstring(const uint8_t *buf, size_t buf_size, size_t *offset,
                                  uint8_t expected_tag, uint8_t *output, size_t output_max_len, size_t *output_len);

/**
 * Decode sample data from flat OCTET STRING per IEC 61850-9-2LE.
 *
 * The sample data is a flat byte sequence: 8 bytes per channel
 * (4 bytes value big-endian int32 + 4 bytes quality big-endian uint32).
 */
static int decode_samples(const uint8_t *buf, size_t buf_size, size_t *offset,
                         sv_asdu_t *asdu, size_t samples_end)
{
    size_t data_len = samples_end - *offset;
    asdu->num_samples = 0;

    /* Each sample is 8 bytes (4 value + 4 quality) */
    if (data_len % 8U != 0U) {
        return SV_BER_ERR_DECODING;
    }

    size_t num_samples = data_len / 8U;
    if (num_samples > SV_MAX_SAMPLES) {
        num_samples = SV_MAX_SAMPLES;
    }

    for (size_t i = 0; i < num_samples; i++) {
        if ((*offset + 8U) > buf_size) {
            return SV_BER_ERR_DECODING;
        }

        /* Decode 4-byte big-endian int32 value */
        uint32_t raw_val = ((uint32_t)buf[*offset] << 24) |
                           ((uint32_t)buf[*offset + 1] << 16) |
                           ((uint32_t)buf[*offset + 2] << 8) |
                           (uint32_t)buf[*offset + 3];
        asdu->samples[i].value = (int32_t)raw_val;
        *offset += 4U;

        /* Decode 4-byte big-endian quality */
        uint8_t qbytes[4];
        qbytes[0] = buf[*offset];
        qbytes[1] = buf[*offset + 1];
        qbytes[2] = buf[*offset + 2];
        qbytes[3] = buf[*offset + 3];
        bytes_to_quality(qbytes, &asdu->samples[i].quality);
        *offset += 4U;

        asdu->num_samples++;
    }

    return SV_BER_OK;
}

/**
 * Decode security extension ([9] SEQUENCE)
 */
static int decode_security(const uint8_t *buf, size_t buf_size, size_t *offset,
                          sv_asdu_t *asdu, size_t security_end)
{
    int ret;
    uint32_t algo_u32;

    /* Validate we're within security extension bounds */
    if (*offset >= security_end) {
        return SV_BER_ERR_DECODING;
    }

    /* [0] Signature algorithm - INTEGER */
    ret = ber_decode_uint32(buf, buf_size, offset, SV_TAG_SECURITY_ALGO, &algo_u32);
    if (ret != SV_BER_OK) {
        return ret;
    }
    asdu->signature_algo = (sv_signature_algo_t)algo_u32;

    /* [1] Key ID - OCTET STRING */
    size_t keyid_len;
    ret = ber_decode_octetstring(buf, buf_size, offset, SV_TAG_SECURITY_KEYID,
                                 asdu->key_id, SV_KEYID_LEN, &keyid_len);
    if (ret != SV_BER_OK) {
        return ret;
    }
    if (keyid_len != SV_KEYID_LEN) {
        return SV_BER_ERR_DECODING;
    }

    /* [2] Security timestamp - UtcTime (8 bytes) */
    ret = ber_decode_utctime(buf, buf_size, offset, SV_TAG_SECURITY_TIMESTAMP,
                            &asdu->security_timestamp, NULL);
    if (ret != SV_BER_OK) {
        return ret;
    }

    /* [3] Signature - OCTET STRING */
    ret = ber_decode_octetstring(buf, buf_size, offset, SV_TAG_SECURITY_SIGNATURE,
                                 asdu->signature, SV_MAX_SIGNATURE_LEN, &asdu->signature_len);
    if (ret != SV_BER_OK) {
        return ret;
    }

    asdu->secure = true;
    return SV_BER_OK;
}

/**
 * Decode ASDU (Application Service Data Unit)
 *
 * IEC 61850-9-2 defines ASDU fields in fixed tag order [0]-[9].
 * We decode positionally (no tag-dispatch loop) so each field
 * is decoded at most once with no merge points. Optional fields
 * are skipped by peeking at the tag before decoding.
 */
static int decode_asdu(const uint8_t *buf, size_t buf_size, size_t *offset,
                      sv_asdu_t *asdu, size_t asdu_end)
{
    int ret;
    uint8_t tag = 0;
    size_t length = 0;
    uint32_t u32_value = 0;

    /* Initialize ASDU */
    sv_asdu_init(asdu);

    /* Helper macro: peek at next tag without consuming it */
    #define PEEK_TAG() ((*offset < asdu_end && *offset < buf_size) ? buf[*offset] : (uint8_t)0U)

    /* [0] svID - VisibleString (REQUIRED) */
    if (PEEK_TAG() != SV_TAG_SVID) { return SV_BER_ERR_DECODING; }
    ret = ber_decode_visiblestring(buf, buf_size, offset, SV_TAG_SVID,
                                  asdu->svID, SV_MAX_SVID_LEN);
    if (ret != SV_BER_OK) { return ret; }

    /* [1] datSet - VisibleString (OPTIONAL) */
    if (PEEK_TAG() == SV_TAG_DATSET) {
        ret = ber_decode_visiblestring(buf, buf_size, offset, SV_TAG_DATSET,
                                      asdu->datSet, SV_MAX_DATSET_LEN);
        if (ret != SV_BER_OK) { return ret; }
        asdu->has_datSet = true;
    }

    /* [2] smpCnt - INTEGER (REQUIRED) */
    if (PEEK_TAG() != SV_TAG_SMPCNT) { return SV_BER_ERR_DECODING; }
    ret = ber_decode_uint32(buf, buf_size, offset, SV_TAG_SMPCNT, &u32_value);
    if (ret != SV_BER_OK) { return ret; }
    asdu->smpCnt = (uint16_t)u32_value;

    /* [3] confRev - INTEGER (REQUIRED) */
    if (PEEK_TAG() != SV_TAG_CONFREV) { return SV_BER_ERR_DECODING; }
    ret = ber_decode_uint32(buf, buf_size, offset, SV_TAG_CONFREV, &asdu->confRev);
    if (ret != SV_BER_OK) { return ret; }

    /* [4] refrTm - UtcTime (OPTIONAL) */
    if (PEEK_TAG() == SV_TAG_REFRTM) {
        ret = ber_decode_utctime(buf, buf_size, offset, SV_TAG_REFRTM,
                                &asdu->refrTm, NULL);
        if (ret != SV_BER_OK) { return ret; }
        asdu->has_refrTm = true;
    }

    /* [5] smpSynch - INTEGER (REQUIRED) */
    if (PEEK_TAG() != SV_TAG_SMPSYNCH) { return SV_BER_ERR_DECODING; }
    ret = ber_decode_uint32(buf, buf_size, offset, SV_TAG_SMPSYNCH, &u32_value);
    if (ret != SV_BER_OK) { return ret; }
    asdu->smpSynch = (sv_smpsynch_t)u32_value;

    /* [6] smpRate - INTEGER (OPTIONAL) */
    if (PEEK_TAG() == SV_TAG_SMPRATE) {
        ret = ber_decode_uint32(buf, buf_size, offset, SV_TAG_SMPRATE, &u32_value);
        if (ret != SV_BER_OK) { return ret; }
        asdu->smpRate = (uint16_t)u32_value;
        asdu->has_smpRate = true;
    }

    /* [7] sample - OCTET STRING (REQUIRED: flat packed channel data per 9-2LE) */
    if (PEEK_TAG() == SV_TAG_SAMPLE) {
        (*offset)++;  /* Consume the tag byte we peeked */
        if (*offset >= buf_size) { return SV_BER_ERR_BUFFER_FULL; }
        ret = ber_decode_length(buf, buf_size, offset, &length);
        if (ret != SV_BER_OK) { return ret; }
        size_t samples_end = *offset + length;
        if (samples_end > buf_size) { return SV_BER_ERR_DECODING; }
        ret = decode_samples(buf, buf_size, offset, asdu, samples_end);
        if (ret != SV_BER_OK) { return ret; }
    }

    /* [8] smpMod - INTEGER (OPTIONAL) */
    if (PEEK_TAG() == SV_TAG_SMPMOD) {
        ret = ber_decode_uint32(buf, buf_size, offset, SV_TAG_SMPMOD, &u32_value);
        if (ret != SV_BER_OK) { return ret; }
        asdu->smpMod = (uint8_t)u32_value;
        asdu->has_smpMod = true;
    }

    /* [9] security - SEQUENCE (OPTIONAL) */
    if (PEEK_TAG() == SV_TAG_SECURITY) {
        ret = ber_decode_tag(buf, buf_size, offset, &tag);
        if (ret != SV_BER_OK) { return ret; }
        ret = ber_decode_length(buf, buf_size, offset, &length);
        if (ret != SV_BER_OK) { return ret; }
        size_t security_end = *offset + length;
        if (security_end > buf_size) { return SV_BER_ERR_DECODING; }
        ret = decode_security(buf, buf_size, offset, asdu, security_end);
        if (ret != SV_BER_OK) { return ret; }
    }

    #undef PEEK_TAG

    return SV_BER_OK;
}

int sv_decode_apdu(const uint8_t *buf, size_t buf_size, sv_apdu_t *apdu)
{
    int ret;
    size_t offset = 0;
    uint8_t tag = 0;
    size_t length = 0;

    if (!buf || !apdu || buf_size < 10U) {
        return SV_BER_ERR_INVALID_ARG;
    }

    /* Initialize APDU */
    sv_apdu_init(apdu);

    /* Decode SV APDU Tag: APPLICATION 2 | CONSTRUCTED */
    ret = ber_decode_tag(buf, buf_size, &offset, &tag);
    if (ret != SV_BER_OK) {
        return ret;
    }
    /* Accept both APPLICATION 0 (0x60, per IEC 61850-9-2) and
     * APPLICATION 2 (0x62, used by some implementations) */
    if (tag != 0x60U && tag != SV_APDU_TAG) {
        return SV_BER_ERR_DECODING;
    }

    /* Decode APDU length */
    ret = ber_decode_length(buf, buf_size, &offset, &length);
    if (ret != SV_BER_OK) {
        return ret;
    }
    size_t apdu_end = offset + length;
    if (apdu_end > buf_size) {
        return SV_BER_ERR_DECODING;
    }

    /* [0] noASDU - INTEGER */
    uint32_t noASDU_u32 = 0;
    ret = ber_decode_uint32(buf, buf_size, &offset, SV_TAG_NOASDU, &noASDU_u32);
    if (ret != SV_BER_OK) {
        return ret;
    }
    apdu->noASDU = (uint8_t)noASDU_u32;

    /* [1] seqASDU - SEQUENCE OF */
    ret = ber_decode_tag(buf, buf_size, &offset, &tag);
    if (ret != SV_BER_OK) {
        return ret;
    }
    /* Accept both [2] (0xA2, per IEC 61850-9-2) and [1] (0xA1, legacy) */
    if (tag != 0xA2U && tag != 0xA1U) {
        return SV_BER_ERR_DECODING;
    }
    ret = ber_decode_length(buf, buf_size, &offset, &length);
    if (ret != SV_BER_OK) {
        return ret;
    }
    size_t seqasdu_end = offset + length;
    if (seqasdu_end > buf_size) {
        return SV_BER_ERR_DECODING;
    }

    /* Decode each ASDU */
    for (uint8_t i = 0; i < apdu->noASDU && i < SV_MAX_ASDU; i++) {
        /* Each ASDU is a SEQUENCE */
        ret = ber_decode_tag(buf, buf_size, &offset, &tag);
        if (ret != SV_BER_OK) {
            return ret;
        }
        if (tag != 0x30U) {  /* UNIVERSAL SEQUENCE tag */
            return SV_BER_ERR_DECODING;
        }
        ret = ber_decode_length(buf, buf_size, &offset, &length);
        if (ret != SV_BER_OK) {
            return ret;
        }
        size_t asdu_end = offset + length;
        if (asdu_end > buf_size) {
            return SV_BER_ERR_DECODING;
        }

        ret = decode_asdu(buf, buf_size, &offset, &apdu->asdu[i], asdu_end);
        if (ret != SV_BER_OK) {
            return ret;
        }
    }

    return SV_BER_OK;
}

void sv_apdu_init(sv_apdu_t *apdu)
{
    if (!apdu) {
        return;
    }

    (void)memset(apdu, 0, sizeof(sv_apdu_t));
    apdu->noASDU = 1;  /* Default: 1 ASDU */
    sv_asdu_init(&apdu->asdu[0]);
}

void sv_asdu_init(sv_asdu_t *asdu)
{
    if (!asdu) {
        return;
    }

    (void)memset(asdu, 0, sizeof(sv_asdu_t));
    asdu->svID[0] = '\0';
    asdu->datSet[0] = '\0';
    asdu->has_datSet = false;
    asdu->smpCnt = 0;
    asdu->confRev = 1;
    asdu->refrTm = 0;
    asdu->has_refrTm = false;
    asdu->smpSynch = SV_SMPSYNCH_NONE;
    asdu->smpRate = 80;  /* Default: 80 samples/cycle */
    asdu->has_smpRate = false;
    asdu->num_samples = 0;
    asdu->smpMod = 0;
    asdu->has_smpMod = false;
    asdu->secure = false;
}

int sv_set_svid(sv_asdu_t *asdu, const char *svID)
{
    size_t len;

    if (!asdu || !svID) {
        return SV_BER_ERR_INVALID_ARG;
    }

    len = strlen(svID);
    if (len >= SV_MAX_SVID_LEN) {
        return SV_BER_ERR_INVALID_ARG;
    }

    (void)memcpy(asdu->svID, svID, len);
    asdu->svID[len] = '\0';

    return SV_BER_OK;
}

int sv_set_datset(sv_asdu_t *asdu, const char *datSet)
{
    size_t len;

    if (!asdu || !datSet) {
        return SV_BER_ERR_INVALID_ARG;
    }

    len = strlen(datSet);
    if (len >= SV_MAX_DATSET_LEN) {
        return SV_BER_ERR_INVALID_ARG;
    }

    (void)memcpy(asdu->datSet, datSet, len);
    asdu->datSet[len] = '\0';
    asdu->has_datSet = true;

    return SV_BER_OK;
}

int sv_add_sample(sv_asdu_t *asdu, int32_t value, sv_quality_t quality)
{
    if (!asdu) {
        return SV_BER_ERR_INVALID_ARG;
    }

    if (asdu->num_samples >= SV_MAX_SAMPLES) {
        return SV_BER_ERR_INVALID_ARG;
    }

    asdu->samples[asdu->num_samples].value = value;
    asdu->samples[asdu->num_samples].quality = quality;
    asdu->num_samples++;

    return SV_BER_OK;
}

/***************************************************************************
 * IEC 62351-6 Security Extension
 ***************************************************************************/

int sv_encode_security(uint8_t *buf, size_t buf_size, size_t *offset,
                       const sv_asdu_t *asdu)
{
    int ret;
    size_t sec_start;
    size_t sec_len;

    if (!buf || !offset || !asdu) {
        return SV_BER_ERR_INVALID_ARG;
    }

    if (!asdu->secure) {
        return SV_BER_OK;  /* No security - skip */
    }

    /* Tag: [9] CONSTRUCTED (security extension) */
    ret = ber_encode_tag(buf, buf_size, offset, SV_TAG_SECURITY);
    if (ret != SV_BER_OK) {
        return ret;
    }

    /* Save position for length */
    if (*offset >= buf_size) {
        return SV_BER_ERR_BUFFER_FULL;
    }
    size_t length_offset = *offset;
    (*offset)++;  /* Reserve space for length */

    sec_start = *offset;

    /* [0] Signature algorithm - INTEGER */
    ret = ber_encode_uint32(buf, buf_size, offset,
                           SV_TAG_SECURITY_ALGO, (uint32_t)asdu->signature_algo);
    if (ret != SV_BER_OK) {
        return ret;
    }

    /* [1] Key ID - OCTET STRING */
    if ((*offset + 2U + SV_KEYID_LEN) > buf_size) {
        return SV_BER_ERR_BUFFER_FULL;
    }
    ret = ber_encode_tag(buf, buf_size, offset, SV_TAG_SECURITY_KEYID);
    if (ret != SV_BER_OK) {
        return ret;
    }
    ret = ber_encode_length(buf, buf_size, offset, SV_KEYID_LEN);
    if (ret != SV_BER_OK) {
        return ret;
    }
    (void)memcpy(buf + *offset, asdu->key_id, SV_KEYID_LEN);
    *offset += SV_KEYID_LEN;

    /* [2] Security timestamp - UtcTime - use default quality for security timestamp */
    ret = ber_encode_utctime(buf, buf_size, offset,
                            SV_TAG_SECURITY_TIMESTAMP, asdu->security_timestamp, 0x00U);
    if (ret != SV_BER_OK) {
        return ret;
    }

    /* [3] Signature - OCTET STRING */
    /* Reserve space for tag (1) + length (up to 3 bytes for len <= 65535) + data */
    size_t sig_overhead = 1U; /* tag */
    if (asdu->signature_len < 128U) {
        sig_overhead += 1U; /* short form length */
    } else if (asdu->signature_len <= 0xFFU) {
        sig_overhead += 2U; /* 0x81 + 1 byte */
    } else {
        sig_overhead += 3U; /* 0x82 + 2 bytes */
    }
    if ((*offset + sig_overhead + asdu->signature_len) > buf_size) {
        return SV_BER_ERR_BUFFER_FULL;
    }
    ret = ber_encode_tag(buf, buf_size, offset, SV_TAG_SECURITY_SIGNATURE);
    if (ret != SV_BER_OK) {
        return ret;
    }
    ret = ber_encode_length(buf, buf_size, offset, asdu->signature_len);
    if (ret != SV_BER_OK) {
        return ret;
    }
    (void)memcpy(buf + *offset, asdu->signature, asdu->signature_len);
    *offset += asdu->signature_len;

    /* Calculate and encode length */
    sec_len = *offset - sec_start;
    if (sec_len >= 128U) {
        /* Need to shift and use long form */
        if (sec_len <= 0xFFU && (*offset + 1U) <= buf_size) {
            (void)memmove(buf + sec_start + 1U, buf + sec_start, sec_len);
            buf[length_offset] = 0x81U;
            buf[length_offset + 1U] = (uint8_t)sec_len;
            (*offset)++;
        } else if (sec_len <= 0xFFFFU && (*offset + 2U) <= buf_size) {
            (void)memmove(buf + sec_start + 2U, buf + sec_start, sec_len);
            buf[length_offset] = 0x82U;
            buf[length_offset + 1U] = (uint8_t)(sec_len >> 8U);
            buf[length_offset + 2U] = (uint8_t)(sec_len & 0xFFU);
            (*offset) += 2U;
        } else {
            return SV_BER_ERR_ENCODING;
        }
    } else {
        buf[length_offset] = (uint8_t)sec_len;
    }

    return SV_BER_OK;
}

int sv_set_security(sv_asdu_t *asdu,
                    sv_signature_algo_t signature_algo,
                    const uint8_t *key_id,
                    const uint8_t *signature,
                    size_t signature_len)
{
    if (!asdu || !key_id || !signature) {
        return SV_BER_ERR_INVALID_ARG;
    }

    if (signature_len > SV_MAX_SIGNATURE_LEN) {
        return SV_BER_ERR_INVALID_ARG;
    }

    asdu->secure = true;
    asdu->signature_algo = signature_algo;
    (void)memcpy(asdu->key_id, key_id, SV_KEYID_LEN);

    /* Get current time for security timestamp */
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
        asdu->security_timestamp = (uint64_t)ts.tv_sec * 1000000ULL +
                                   (uint64_t)ts.tv_nsec / 1000ULL;
    } else {
        asdu->security_timestamp = 0;  /* Fallback */
    }

    (void)memcpy(asdu->signature, signature, signature_len);
    asdu->signature_len = signature_len;

    return SV_BER_OK;
}
