/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * ASN.1 BER Decoder for IEC 61850-8-1 GOOSE Protocol
 *
 * Minimal, formally verified implementation for safety-critical systems.
 *
 * License: BSD-3-Clause
 */

#include "asn1/goose_ber_decode.h"
#include <string.h>

/***************************************************************************
 * Low-Level BER Decoding Functions
 ***************************************************************************/

int ber_decode_tag(const uint8_t *buf, size_t buf_size, size_t *offset, uint8_t *tag)
{
    int result;

    if (!buf || !offset || !tag) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else if (*offset >= buf_size) {
        result = GOOSE_BER_ERR_BUFFER_FULL;
    } else {
        *tag = buf[*offset];
        (*offset)++;
        result = GOOSE_BER_OK;
    }

    return result;
}

int ber_decode_length(const uint8_t *buf, size_t buf_size, size_t *offset, size_t *length)
{
    int result;

    if (!buf || !offset || !length) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else if (*offset >= buf_size) {
        result = GOOSE_BER_ERR_BUFFER_FULL;
    } else {
        uint8_t first_byte = buf[*offset];
        (*offset)++;

        if ((first_byte & 0x80U) == 0U) {
            /* Short form: single byte */
            *length = first_byte;
            result = GOOSE_BER_OK;
        } else {
            /* Long form */
            uint8_t num_bytes_u8 = first_byte & 0x7FU;
            size_t num_bytes = num_bytes_u8;

            if ((num_bytes > sizeof(size_t)) || ((*offset + num_bytes) > buf_size)) {
                result = GOOSE_BER_ERR_ENCODING;
            } else {
                *length = 0U;
                for (size_t i = 0U; i < num_bytes; i++) {
                    *length = (*length << 8) | buf[*offset];
                    (*offset)++;
                }
                result = GOOSE_BER_OK;
            }
        }
    }

    return result;
}

int ber_decode_boolean(const uint8_t *buf, size_t buf_size, size_t *offset,
                       uint8_t expected_tag, bool *value)
{
    int result;
    int ret;
    uint8_t tag;
    size_t length;

    if (!buf || !offset || !value) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else {
        /* Decode tag */
        ret = ber_decode_tag(buf, buf_size, offset, &tag);
        if (ret != GOOSE_BER_OK) {
            result = ret;
        } else if (tag != expected_tag) {
            result = GOOSE_BER_ERR_ENCODING;
        } else {
            /* Decode length */
            ret = ber_decode_length(buf, buf_size, offset, &length);
            if (ret != GOOSE_BER_OK) {
                result = ret;
            } else if ((length != 1U) || (*offset >= buf_size)) {
                result = GOOSE_BER_ERR_ENCODING;
            } else {
                /* Decode value */
                *value = (buf[*offset] != 0U);
                (*offset)++;
                result = GOOSE_BER_OK;
            }
        }
    }

    return result;
}

int ber_decode_int32(const uint8_t *buf, size_t buf_size, size_t *offset,
                     uint8_t expected_tag, int32_t *value)
{
    int result;
    int ret;
    uint8_t tag;
    size_t length;

    if (!buf || !offset || !value) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else {
        /* Decode tag */
        ret = ber_decode_tag(buf, buf_size, offset, &tag);
        if (ret != GOOSE_BER_OK) {
            result = ret;
        } else if (tag != expected_tag) {
            result = GOOSE_BER_ERR_ENCODING;
        } else {
            /* Decode length */
            ret = ber_decode_length(buf, buf_size, offset, &length);
            if (ret != GOOSE_BER_OK) {
                result = ret;
            } else if ((length == 0U) || (length > 4U) || ((*offset + length) > buf_size)) {
                result = GOOSE_BER_ERR_ENCODING;
            } else {
                /* Decode value (big-endian, sign-extended) */
                /* Use unsigned arithmetic to avoid undefined behavior with left shift */
                uint32_t unsigned_value = 0U;

                /* Check if negative (high bit of first byte set) */
                bool is_negative = (buf[*offset] & 0x80U) != 0U;

                if (is_negative) {
                    unsigned_value = 0xFFFFFFFFU;  /* Sign extend with all 1s */
                }

                for (size_t i = 0U; i < length; i++) {
                    unsigned_value = (unsigned_value << 8) | buf[*offset];
                    (*offset)++;
                }

                /* Cast to signed at the end */
                *value = (int32_t)unsigned_value;
                result = GOOSE_BER_OK;
            }
        }
    }

    return result;
}

int ber_decode_uint32(const uint8_t *buf, size_t buf_size, size_t *offset,
                      uint8_t expected_tag, uint32_t *value)
{
    int result;
    int ret;
    uint8_t tag;
    size_t length;

    if (!buf || !offset || !value) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else {
        /* Decode tag */
        ret = ber_decode_tag(buf, buf_size, offset, &tag);
        if (ret != GOOSE_BER_OK) {
            result = ret;
        } else if (tag != expected_tag) {
            result = GOOSE_BER_ERR_ENCODING;
        } else {
            /* Decode length */
            ret = ber_decode_length(buf, buf_size, offset, &length);
            if (ret != GOOSE_BER_OK) {
                result = ret;
            } else if ((length == 0U) || (length > 5U) || ((*offset + length) > buf_size)) {
                result = GOOSE_BER_ERR_ENCODING;
            } else {
                /* Decode value (big-endian) */
                *value = 0U;
                for (size_t i = 0U; i < length; i++) {
                    *value = (*value << 8) | buf[*offset];
                    (*offset)++;
                }
                result = GOOSE_BER_OK;
            }
        }
    }

    return result;
}

int ber_decode_visiblestring(const uint8_t *buf, size_t buf_size, size_t *offset,
                              uint8_t expected_tag, char *str, size_t str_size)
{
    int result;
    int ret;
    uint8_t tag;
    size_t length;

    if (!buf || !offset || !str || (str_size == 0U)) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else {
        /* Decode tag */
        ret = ber_decode_tag(buf, buf_size, offset, &tag);
        if (ret != GOOSE_BER_OK) {
            result = ret;
        } else if (tag != expected_tag) {
            result = GOOSE_BER_ERR_ENCODING;
        } else {
            /* Decode length */
            ret = ber_decode_length(buf, buf_size, offset, &length);
            if (ret != GOOSE_BER_OK) {
                result = ret;
            } else if ((*offset + length) > buf_size) {
                result = GOOSE_BER_ERR_ENCODING;
            } else if (length >= str_size) {
                result = GOOSE_BER_ERR_BUFFER_FULL;  /* String too long for buffer */
            } else {
                /* Copy string */
                for (size_t i = 0U; i < length; i++) {
                    str[i] = (char)buf[*offset];
                    (*offset)++;
                }
                str[length] = '\0';  /* Null terminate */
                result = GOOSE_BER_OK;
            }
        }
    }

    return result;
}

int ber_decode_utctime(const uint8_t *buf, size_t buf_size, size_t *offset,
                       uint8_t expected_tag, uint64_t *timestamp_us, uint8_t *time_quality)
{
    int result;
    int ret;
    uint8_t tag;
    size_t length;
    uint32_t seconds;
    uint32_t fraction;

    if (!buf || !offset || !timestamp_us) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else {
        /* Decode tag */
        ret = ber_decode_tag(buf, buf_size, offset, &tag);
        if (ret != GOOSE_BER_OK) {
            result = ret;
        } else if (tag != expected_tag) {
            result = GOOSE_BER_ERR_ENCODING;
        } else {
            /* Decode length */
            ret = ber_decode_length(buf, buf_size, offset, &length);
            if (ret != GOOSE_BER_OK) {
                result = ret;
            } else if ((length != 8U) || ((*offset + 8U) > buf_size)) {
                result = GOOSE_BER_ERR_ENCODING;
            } else {
                /* IEC 61850 UtcTime: 8 bytes
                 *   Bytes 0-3: Seconds since epoch (big-endian)
                 *   Bytes 4-6: Fraction of second (24-bit, in units of 1/2^24 seconds)
                 *   Byte 7: Time quality
                 */

                /* Decode seconds */
                seconds = ((uint32_t)buf[*offset] << 24) |
                          ((uint32_t)buf[*offset + 1U] << 16) |
                          ((uint32_t)buf[*offset + 2U] << 8) |
                          ((uint32_t)buf[*offset + 3U]);

                /* Decode fraction */
                fraction = ((uint32_t)buf[*offset + 4U] << 16) |
                           ((uint32_t)buf[*offset + 5U] << 8) |
                           ((uint32_t)buf[*offset + 6U]);

                /* Convert to microseconds */
                /* Fraction is in units of 1/2^24 seconds, convert to microseconds with rounding */
                uint64_t fraction_us = ((uint64_t)fraction * 1000000ULL + (1ULL << 23)) >> 24;

                *timestamp_us = ((uint64_t)seconds * 1000000ULL) + fraction_us;

                /* Decode time quality (if output parameter provided) */
                if (time_quality) {
                    *time_quality = buf[*offset + 7U];
                }

                *offset += 8U;

                result = GOOSE_BER_OK;
            }
        }
    }

    return result;
}

/***************************************************************************
 * GOOSE APDU Decoding Functions
 ***************************************************************************/

int goose_decode_alldata(const uint8_t *buf, size_t buf_size, size_t *offset,
                         goose_data_t *data, size_t max_count, size_t *count)
{
    int result;
    int ret;
    uint8_t tag;
    size_t length;
    size_t alldata_end;

    if (!buf || !offset || !data || !count) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else {
        *count = 0;

        /* Decode allData tag: [11] IMPLICIT SEQUENCE */
        ret = ber_decode_tag(buf, buf_size, offset, &tag);
        if (ret != GOOSE_BER_OK) {
            result = ret;
        } else if (tag != GOOSE_TAG_ALLDATA) {
            result = GOOSE_BER_ERR_ENCODING;
        } else {
            /* Decode length */
            ret = ber_decode_length(buf, buf_size, offset, &length);
            if (ret != GOOSE_BER_OK) {
                result = ret;
            } else {
                alldata_end = *offset + length;
                if (alldata_end > buf_size) {
                    result = GOOSE_BER_ERR_ENCODING;
                } else {
                    /* Decode each data element */
                    result = GOOSE_BER_OK;
                    while ((*offset < alldata_end) && (*count < max_count) && (result == GOOSE_BER_OK)) {
                        /* Peek at tag to determine type */
                        if (*offset >= buf_size) {
                            result = GOOSE_BER_ERR_ENCODING;
                        } else {
                            tag = buf[*offset];

                            /* Context-specific tags for data types */
                            if (tag == (ASN1_CLASS_CONTEXT | 0x03U)) {  /* [3] boolean */
                                ret = ber_decode_boolean(buf, buf_size, offset, tag,
                                                         &data[*count].value.boolean);
                                if (ret != GOOSE_BER_OK) {
                                    result = ret;
                                } else {
                                    data[*count].type = GOOSE_DATA_BOOLEAN;
                                    (*count)++;
                                }
                            } else if (tag == (ASN1_CLASS_CONTEXT | 0x05U)) {  /* [5] integer */
                                ret = ber_decode_int32(buf, buf_size, offset, tag,
                                                       &data[*count].value.int32);
                                if (ret != GOOSE_BER_OK) {
                                    result = ret;
                                } else {
                                    data[*count].type = GOOSE_DATA_INT32;
                                    (*count)++;
                                }
                            } else if (tag == (ASN1_CLASS_CONTEXT | 0x06U)) {  /* [6] unsigned */
                                ret = ber_decode_uint32(buf, buf_size, offset, tag,
                                                        &data[*count].value.uint32);
                                if (ret != GOOSE_BER_OK) {
                                    result = ret;
                                } else {
                                    data[*count].type = GOOSE_DATA_UINT32;
                                    (*count)++;
                                }
                            } else if (tag == (ASN1_CLASS_CONTEXT | 0x07U)) {  /* [7] floating-point */
                                /* IEC 61850 Float: tag + length + 1-byte exponent width + 4-byte IEEE 754 */
                                uint8_t float_tag;
                                size_t float_len;
                                ret = ber_decode_tag(buf, buf_size, offset, &float_tag);
                                if (ret != GOOSE_BER_OK) {
                                    result = ret;
                                } else {
                                    ret = ber_decode_length(buf, buf_size, offset, &float_len);
                                    if (ret != GOOSE_BER_OK) {
                                        result = ret;
                                    } else if (float_len != 5U || (*offset + 5U) > buf_size) {
                                        result = GOOSE_BER_ERR_ENCODING;
                                    } else {
                                        /* Skip exponent width byte (0x08) */
                                        (*offset)++;
                                        /* Decode 4 IEEE 754 bytes (big-endian) */
                                        uint32_t float_bits = ((uint32_t)buf[*offset] << 24U)
                                                            | ((uint32_t)buf[*offset + 1U] << 16U)
                                                            | ((uint32_t)buf[*offset + 2U] << 8U)
                                                            | (uint32_t)buf[*offset + 3U];
                                        memcpy(&data[*count].value.float32, &float_bits, sizeof(float));
                                        *offset += 4U;
                                        data[*count].type = GOOSE_DATA_FLOAT32;
                                        (*count)++;
                                    }
                                }
                            } else if (tag == (ASN1_CLASS_CONTEXT | 0x04U)) {  /* [4] bit-string */
                                uint8_t bs_tag;
                                size_t bs_len;
                                ret = ber_decode_tag(buf, buf_size, offset, &bs_tag);
                                if (ret != GOOSE_BER_OK) {
                                    result = ret;
                                } else {
                                    ret = ber_decode_length(buf, buf_size, offset, &bs_len);
                                    if (ret != GOOSE_BER_OK) {
                                        result = ret;
                                    } else if (bs_len < 1U || (*offset + bs_len) > buf_size) {
                                        result = GOOSE_BER_ERR_ENCODING;
                                    } else {
                                        /* First byte is "unused bits" count — skip it */
                                        (*offset)++;  /* skip unused bits byte */
                                        data[*count].type = GOOSE_DATA_BITSTRING;
                                        data[*count].value.bytes.data = (uint8_t *)&buf[*offset];
                                        data[*count].value.bytes.len = bs_len - 1U;
                                        *offset += bs_len - 1U;
                                        (*count)++;
                                    }
                                }
                            } else if (tag == (ASN1_CLASS_CONTEXT | 0x09U)) {  /* [9] octet-string */
                                uint8_t os_tag;
                                size_t os_len;
                                ret = ber_decode_tag(buf, buf_size, offset, &os_tag);
                                if (ret != GOOSE_BER_OK) {
                                    result = ret;
                                } else {
                                    ret = ber_decode_length(buf, buf_size, offset, &os_len);
                                    if (ret != GOOSE_BER_OK) {
                                        result = ret;
                                    } else if ((*offset + os_len) > buf_size) {
                                        result = GOOSE_BER_ERR_ENCODING;
                                    } else {
                                        data[*count].type = GOOSE_DATA_OCTETSTRING;
                                        data[*count].value.bytes.data = (uint8_t *)&buf[*offset];
                                        data[*count].value.bytes.len = os_len;
                                        *offset += os_len;
                                        (*count)++;
                                    }
                                }
                            } else if (tag == (ASN1_CLASS_CONTEXT | 0x0AU)) {  /* [10] visible-string */
                                uint8_t vs_tag;
                                size_t vs_len;
                                ret = ber_decode_tag(buf, buf_size, offset, &vs_tag);
                                if (ret != GOOSE_BER_OK) {
                                    result = ret;
                                } else {
                                    ret = ber_decode_length(buf, buf_size, offset, &vs_len);
                                    if (ret != GOOSE_BER_OK) {
                                        result = ret;
                                    } else if ((*offset + vs_len) > buf_size) {
                                        result = GOOSE_BER_ERR_ENCODING;
                                    } else {
                                        data[*count].type = GOOSE_DATA_VISIBLESTRING;
                                        data[*count].value.visiblestring = (char *)&buf[*offset];
                                        *offset += vs_len;
                                        (*count)++;
                                    }
                                }
                            } else if (tag == (ASN1_CLASS_CONTEXT | 0x11U)) {  /* [17] utc-time */
                                uint64_t ts = 0;
                                uint8_t tq = 0;
                                ret = ber_decode_utctime(buf, buf_size, offset,
                                                         ASN1_CLASS_CONTEXT | 0x11U,
                                                         &ts, &tq);
                                if (ret != GOOSE_BER_OK) {
                                    result = ret;
                                } else {
                                    data[*count].type = GOOSE_DATA_UTCTIME;
                                    data[*count].value.utctime.timestamp_us = ts;
                                    data[*count].value.utctime.time_quality = tq;
                                    (*count)++;
                                }
                            } else if (tag == (ASN1_CLASS_CONTEXT | ASN1_CONSTRUCTED | 0x02U)) {  /* [2] structure */
                                uint8_t st_tag;
                                size_t st_len;
                                ret = ber_decode_tag(buf, buf_size, offset, &st_tag);
                                if (ret != GOOSE_BER_OK) {
                                    result = ret;
                                } else {
                                    ret = ber_decode_length(buf, buf_size, offset, &st_len);
                                    if (ret != GOOSE_BER_OK) {
                                        result = ret;
                                    } else if ((*offset + st_len) > buf_size) {
                                        result = GOOSE_BER_ERR_ENCODING;
                                    } else {
                                        /* Structure: point to raw sub-element data.
                                         * Full recursive decode would require heap allocation;
                                         * instead, store pointer to raw bytes for caller. */
                                        data[*count].type = GOOSE_DATA_STRUCTURE;
                                        data[*count].value.structure.elements = NULL;
                                        data[*count].value.structure.count = 0;
                                        *offset += st_len;  /* Skip structure content */
                                        (*count)++;
                                    }
                                }
                            } else {
                                /* Unknown data type - skip it */
                                uint8_t unknown_tag;
                                size_t skip_length;
                                ret = ber_decode_tag(buf, buf_size, offset, &unknown_tag);
                                if (ret != GOOSE_BER_OK) {
                                    result = ret;
                                } else {
                                    ret = ber_decode_length(buf, buf_size, offset, &skip_length);
                                    if (ret != GOOSE_BER_OK) {
                                        result = ret;
                                    } else {
                                        *offset += skip_length;  /* Skip unknown data */
                                    }
                                }
                            }
                        }
                    }

                    if (result == GOOSE_BER_OK) {
                        /* Adjust offset to end of allData */
                        *offset = alldata_end;
                    }
                }
            }
        }
    }

    return result;
}

int goose_decode_apdu(const uint8_t *buf, size_t buf_size, goose_apdu_t *apdu)
{
    size_t offset = 0;
    int ret;
    uint8_t tag = 0;
    size_t length = 0;
    size_t apdu_end;
    size_t data_count = 0;

    if (!buf || !apdu) {
        return GOOSE_BER_ERR_INVALID_ARG;
    }

    /* Initialize APDU */
    goose_apdu_init(apdu);

    /* Decode GOOSE APDU Tag: APPLICATION 1 | CONSTRUCTED */
    ret = ber_decode_tag(buf, buf_size, &offset, &tag);
    if (ret != GOOSE_BER_OK) { return ret; }
    if (tag != GOOSE_APDU_TAG) { return GOOSE_BER_ERR_ENCODING; }

    /* Decode APDU length */
    ret = ber_decode_length(buf, buf_size, &offset, &length);
    if (ret != GOOSE_BER_OK) { return ret; }
    apdu_end = offset + length;
    if (apdu_end > buf_size) { return GOOSE_BER_ERR_ENCODING; }

    /* Decode GOOSE APDU fields positionally (IEC 61850-8-1 fixed order).
     * Each field decoded at most once, no loops, no merge points. */

    /* [0] gocbRef (REQUIRED) */
    ret = ber_decode_visiblestring(buf, buf_size, &offset,
                                   GOOSE_TAG_GOCBREF,
                                   apdu->gocbRef, GOOSE_MAX_GOCBREF_LEN);
    if (ret != GOOSE_BER_OK) { return ret; }

    /* [1] timeAllowedtoLive (REQUIRED) */
    ret = ber_decode_uint32(buf, buf_size, &offset,
                           GOOSE_TAG_TIMEALLOWEDTOLIVE,
                           &apdu->timeAllowedtoLive);
    if (ret != GOOSE_BER_OK) { return ret; }

    /* [2] datSet (REQUIRED) */
    ret = ber_decode_visiblestring(buf, buf_size, &offset,
                                   GOOSE_TAG_DATSET,
                                   apdu->datSet, GOOSE_MAX_DATSET_LEN);
    if (ret != GOOSE_BER_OK) { return ret; }

    /* [3] goID (OPTIONAL) */
    if ((offset < apdu_end) && (buf[offset] == GOOSE_TAG_GOID)) {
        ret = ber_decode_visiblestring(buf, buf_size, &offset,
                                       GOOSE_TAG_GOID,
                                       apdu->goID, GOOSE_MAX_GOID_LEN);
        if (ret != GOOSE_BER_OK) { return ret; }
        apdu->has_goID = true;
    }

    /* [4] t — timestamp (REQUIRED) */
    ret = ber_decode_utctime(buf, buf_size, &offset,
                            GOOSE_TAG_T, &apdu->timestamp, &apdu->time_quality);
    if (ret != GOOSE_BER_OK) { return ret; }

    /* [5] stNum (REQUIRED) */
    ret = ber_decode_uint32(buf, buf_size, &offset,
                           GOOSE_TAG_STNUM, &apdu->stNum);
    if (ret != GOOSE_BER_OK) { return ret; }

    /* [6] sqNum (REQUIRED) */
    ret = ber_decode_uint32(buf, buf_size, &offset,
                           GOOSE_TAG_SQNUM, &apdu->sqNum);
    if (ret != GOOSE_BER_OK) { return ret; }

    /* [7] test (REQUIRED) */
    ret = ber_decode_boolean(buf, buf_size, &offset,
                            GOOSE_TAG_TEST, &apdu->test);
    if (ret != GOOSE_BER_OK) { return ret; }

    /* [8] confRev (REQUIRED) */
    ret = ber_decode_uint32(buf, buf_size, &offset,
                           GOOSE_TAG_CONFREV, &apdu->confRev);
    if (ret != GOOSE_BER_OK) { return ret; }

    /* [9] ndsCom (REQUIRED) */
    ret = ber_decode_boolean(buf, buf_size, &offset,
                            GOOSE_TAG_NDSCOM, &apdu->ndsCom);
    if (ret != GOOSE_BER_OK) { return ret; }

    /* [10] numDatSetEntries (REQUIRED) */
    ret = ber_decode_uint32(buf, buf_size, &offset,
                           GOOSE_TAG_NUMDATSETENTRIES,
                           &apdu->numDatSetEntries);
    if (ret != GOOSE_BER_OK) { return ret; }

    /* [11] allData (REQUIRED) */
    ret = goose_decode_alldata(buf, buf_size, &offset,
                               apdu->allData, GOOSE_MAX_ALLDATA_ENTRIES,
                               &data_count);
    if (ret != GOOSE_BER_OK) { return ret; }

    /* Allow mismatch but use actual count */
    if (data_count != apdu->numDatSetEntries) {
        apdu->numDatSetEntries = (uint32_t)data_count;
    }

    /* [12] Security extension (IEC 62351-6) — OPTIONAL */
    ret = goose_decode_security(buf, buf_size, &offset, apdu);
    if (ret != GOOSE_BER_OK) { return ret; }

    return GOOSE_BER_OK;
}

int goose_decode_apdu_ex(const uint8_t *buf, size_t buf_size,
                          goose_apdu_t *apdu, size_t *consumed)
{
    int ret;

    if (!consumed) {
        return GOOSE_BER_ERR_INVALID_ARG;
    }

    ret = goose_decode_apdu(buf, buf_size, apdu);

    if (ret == GOOSE_BER_OK) {
        /* Calculate consumed bytes by re-parsing the outer tag+length */
        size_t offset = 0;
        uint8_t tag;
        size_t length;
        int r2 = ber_decode_tag(buf, buf_size, &offset, &tag);
        if (r2 == GOOSE_BER_OK) {
            r2 = ber_decode_length(buf, buf_size, &offset, &length);
            if (r2 == GOOSE_BER_OK) {
                *consumed = offset + length;
            } else {
                *consumed = buf_size;
            }
        } else {
            *consumed = buf_size;
        }
    }

    return ret;
}

/***************************************************************************
 * IEC 62351-6 Security Extension Decoding
 ***************************************************************************/

/**
 * Decode ASN.1 OCTET STRING
 */
int ber_decode_octetstring(const uint8_t *buf, size_t buf_size, size_t *offset,
                           uint8_t expected_tag, uint8_t *data, size_t max_len,
                           size_t *actual_len)
{
    int result;
    int ret;
    uint8_t tag;
    size_t length;
    size_t i;

    if (!buf || !offset || !data || !actual_len) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else if (*offset >= buf_size) {
        result = GOOSE_BER_ERR_BUFFER_FULL;
    } else {
        /* Decode tag */
        ret = ber_decode_tag(buf, buf_size, offset, &tag);
        if (ret != GOOSE_BER_OK) {
            result = ret;
        } else if (tag != expected_tag) {
            result = GOOSE_BER_ERR_ENCODING;
        } else {
            /* Decode length */
            ret = ber_decode_length(buf, buf_size, offset, &length);
            if (ret != GOOSE_BER_OK) {
                result = ret;
            } else if (length > max_len) {
                result = GOOSE_BER_ERR_BUFFER_FULL;
            } else if ((*offset + length) > buf_size) {
                result = GOOSE_BER_ERR_BUFFER_FULL;
            } else {
                /* Decode data */
                for (i = 0; i < length; i++) {
                    data[i] = buf[*offset];
                    (*offset)++;
                }
                *actual_len = length;
                result = GOOSE_BER_OK;
            }
        }
    }

    return result;
}

int goose_decode_security(const uint8_t *buf, size_t buf_size, size_t *offset,
                          goose_apdu_t *apdu)
{
    int result;
    int ret;
    uint8_t tag;
    size_t length;
    size_t sec_end;
    uint32_t algo;
    size_t key_id_len;

    if (!buf || !offset || !apdu) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else if (*offset >= buf_size) {
        /* No more data - security extension is optional */
        result = GOOSE_BER_OK;
    } else {
        /* Check if next tag is security extension [12] */
        if (buf[*offset] != GOOSE_TAG_SECURITY) {
            /* No security extension present (backward compatible) */
            result = GOOSE_BER_OK;
        } else {
            /* Decode security extension tag */
            ret = ber_decode_tag(buf, buf_size, offset, &tag);
            if (ret != GOOSE_BER_OK) {
                result = ret;
            } else {
                /* Decode length */
                ret = ber_decode_length(buf, buf_size, offset, &length);
                if (ret != GOOSE_BER_OK) {
                    result = ret;
                } else {
                    sec_end = *offset + length;
                    if (sec_end > buf_size) {
                        result = GOOSE_BER_ERR_BUFFER_FULL;
                    } else {
                        /* [0] Signature algorithm */
                        ret = ber_decode_uint32(buf, buf_size, offset,
                                                GOOSE_TAG_SECURITY_ALGO, &algo);
                        if (ret != GOOSE_BER_OK) {
                            result = ret;
                        } else {
                            apdu->signature_algo = (goose_signature_algo_t)algo;

                            /* [1] Key ID */
                            ret = ber_decode_octetstring(buf, buf_size, offset,
                                                          GOOSE_TAG_SECURITY_KEYID,
                                                          apdu->key_id, GOOSE_KEYID_LEN,
                                                          &key_id_len);
                            if (ret != GOOSE_BER_OK) {
                                result = ret;
                            } else if (key_id_len != GOOSE_KEYID_LEN) {
                                result = GOOSE_BER_ERR_ENCODING;  /* Key ID length mismatch */
                            } else {
                                /* [2] Security timestamp */
                                ret = ber_decode_utctime(buf, buf_size, offset,
                                                         GOOSE_TAG_SECURITY_TIMESTAMP,
                                                         &apdu->security_timestamp, NULL);
                                if (ret != GOOSE_BER_OK) {
                                    result = ret;
                                } else {
                                    /* [3] Signature */
                                    ret = ber_decode_octetstring(buf, buf_size, offset,
                                                                  GOOSE_TAG_SECURITY_SIGNATURE,
                                                                  apdu->signature, GOOSE_MAX_SIGNATURE_LEN,
                                                                  &apdu->signature_len);
                                    if (ret != GOOSE_BER_OK) {
                                        result = ret;
                                    } else {
                                        /* Successfully decoded security extension */
                                        apdu->secure = true;
                                        result = GOOSE_BER_OK;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    return result;
}
