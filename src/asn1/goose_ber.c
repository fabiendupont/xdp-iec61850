/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * ASN.1 BER Encoder for IEC 61850-8-1 GOOSE Protocol
 *
 * Minimal, formally verified implementation for safety-critical systems.
 *
 * License: BSD-3-Clause
 */


#include "asn1/goose_ber.h"
#include <string.h>
#include <time.h>

/***************************************************************************
 * Low-Level BER Encoding Functions
 ***************************************************************************/

int ber_encode_tag(uint8_t *buf, size_t buf_size, size_t *offset, uint8_t tag)
{
    int result;

    if (!buf || !offset) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else if (*offset >= buf_size) {
        result = GOOSE_BER_ERR_BUFFER_FULL;
    } else {
        buf[*offset] = tag;
        (*offset)++;
        result = GOOSE_BER_OK;
    }

    return result;
}

int ber_encode_length(uint8_t *buf, size_t buf_size, size_t *offset, size_t length)
{
    int result;

    if (!buf || !offset) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else if (length < 128U) {
        /* Short form: single byte */
        if (*offset >= buf_size) {
            result = GOOSE_BER_ERR_BUFFER_FULL;
        } else {
            buf[*offset] = (uint8_t)length;
            (*offset)++;
            result = GOOSE_BER_OK;
        }
    } else if (length <= 0xFFU) {
        /* Long form: 1 length byte */
        if ((*offset + 2U) > buf_size) {
            result = GOOSE_BER_ERR_BUFFER_FULL;
        } else {
            buf[*offset] = 0x81U;  /* 1 length byte follows */
            buf[*offset + 1U] = (uint8_t)length;
            *offset += 2U;
            result = GOOSE_BER_OK;
        }
    } else if (length <= 0xFFFFU) {
        /* Long form: 2 length bytes */
        if ((*offset + 3U) > buf_size) {
            result = GOOSE_BER_ERR_BUFFER_FULL;
        } else {
            buf[*offset] = 0x82U;  /* 2 length bytes follow */
            buf[*offset + 1U] = (uint8_t)(length >> 8);
            buf[*offset + 2U] = (uint8_t)(length & 0xFFU);
            *offset += 3U;
            result = GOOSE_BER_OK;
        }
    } else {
        result = GOOSE_BER_ERR_ENCODING;  /* Length too large */
    }

    return result;
}

int ber_encode_boolean(uint8_t *buf, size_t buf_size, size_t *offset,
                       uint8_t tag, bool value)
{
    int result;
    int ret;

    if (!buf || !offset) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else if ((*offset + 3U) > buf_size) {
        result = GOOSE_BER_ERR_BUFFER_FULL;
    } else {
        /* Tag */
        ret = ber_encode_tag(buf, buf_size, offset, tag);
        if (ret != GOOSE_BER_OK) {
            result = ret;
        } else {
            /* Length: always 1 byte for BOOLEAN */
            ret = ber_encode_length(buf, buf_size, offset, 1U);
            if (ret != GOOSE_BER_OK) {
                result = ret;
            } else {
                /* Value: 0x00 = false, 0xFF = true */
                buf[*offset] = value ? 0xFFU : 0x00U;
                (*offset)++;
                result = GOOSE_BER_OK;
            }
        }
    }

    return result;
}

int ber_encode_int32(uint8_t *buf, size_t buf_size, size_t *offset,
                     uint8_t tag, int32_t value)
{
    int result;
    int ret;
    uint8_t int_bytes[4];
    size_t num_bytes;
    size_t i;

    if (!buf || !offset) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else {
        /* Convert to bytes (big-endian) */
        /* Cast to unsigned before shifting to avoid undefined behavior */
        int_bytes[0] = (uint8_t)((uint32_t)value >> 24);
        int_bytes[1] = (uint8_t)((uint32_t)value >> 16);
        int_bytes[2] = (uint8_t)((uint32_t)value >> 8);
        int_bytes[3] = (uint8_t)value;

        /* Determine minimum number of bytes needed */
        /* Skip leading 0xFF (negative) or 0x00 (positive) bytes, keep at least 1 */
        if (value >= 0) {
            /* Positive: skip leading 0x00, unless high bit set */
            num_bytes = 4U;
            for (i = 0U; i < 3U; i++) {
                if ((int_bytes[i] == 0U) && ((int_bytes[i+1U] & 0x80U) == 0U)) {
                    num_bytes--;
                } else {
                    break;
                }
            }
        } else {
            /* Negative: skip leading 0xFF, unless high bit clear */
            num_bytes = 4U;
            for (i = 0U; i < 3U; i++) {
                if ((int_bytes[i] == 0xFFU) && ((int_bytes[i+1U] & 0x80U) != 0U)) {
                    num_bytes--;
                } else {
                    break;
                }
            }
        }

        if ((*offset + 2U + num_bytes) > buf_size) {
            result = GOOSE_BER_ERR_BUFFER_FULL;
        } else {
            /* Tag */
            ret = ber_encode_tag(buf, buf_size, offset, tag);
            if (ret != GOOSE_BER_OK) {
                result = ret;
            } else {
                /* Length */
                ret = ber_encode_length(buf, buf_size, offset, num_bytes);
                if (ret != GOOSE_BER_OK) {
                    result = ret;
                } else {
                    /* Value */
                    for (i = (4U - num_bytes); i < 4U; i++) {
                        buf[*offset] = int_bytes[i];
                        (*offset)++;
                    }
                    result = GOOSE_BER_OK;
                }
            }
        }
    }

    return result;
}

int ber_encode_uint32(uint8_t *buf, size_t buf_size, size_t *offset,
                      uint8_t tag, uint32_t value)
{
    int result;
    int ret;
    uint8_t int_bytes[5];  /* May need extra 0x00 byte if high bit set */
    size_t num_bytes;
    size_t i;

    if (!buf || !offset) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else {
        /* Convert to bytes (big-endian) */
        int_bytes[0] = 0x00;  /* Leading zero for unsigned */
        int_bytes[1] = (uint8_t)(value >> 24);
        int_bytes[2] = (uint8_t)(value >> 16);
        int_bytes[3] = (uint8_t)(value >> 8);
        int_bytes[4] = (uint8_t)(value);

        /* Skip leading 0x00 bytes, but keep one if high bit of next byte is set */
        num_bytes = 5U;
        for (i = 0U; i < 4U; i++) {
            if ((int_bytes[i] == 0U) && ((int_bytes[i+1U] & 0x80U) == 0U)) {
                num_bytes--;
            } else {
                break;
            }
        }

        if ((*offset + 2U + num_bytes) > buf_size) {
            result = GOOSE_BER_ERR_BUFFER_FULL;
        } else {
            /* Tag */
            ret = ber_encode_tag(buf, buf_size, offset, tag);
            if (ret != GOOSE_BER_OK) {
                result = ret;
            } else {
                /* Length */
                ret = ber_encode_length(buf, buf_size, offset, num_bytes);
                if (ret != GOOSE_BER_OK) {
                    result = ret;
                } else {
                    /* Value */
                    for (i = (5U - num_bytes); i < 5U; i++) {
                        buf[*offset] = int_bytes[i];
                        (*offset)++;
                    }
                    result = GOOSE_BER_OK;
                }
            }
        }
    }

    return result;
}

int ber_encode_visiblestring(uint8_t *buf, size_t buf_size, size_t *offset,
                              uint8_t tag, const char *str)
{
    int result;
    int ret;
    size_t len;
    size_t i;

    if (!buf || !offset || !str) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else {
        len = strlen(str);

        if ((*offset + 2U + len) > buf_size) {
            result = GOOSE_BER_ERR_BUFFER_FULL;
        } else {
            /* Tag */
            ret = ber_encode_tag(buf, buf_size, offset, tag);
            if (ret != GOOSE_BER_OK) {
                result = ret;
            } else {
                /* Length */
                ret = ber_encode_length(buf, buf_size, offset, len);
                if (ret != GOOSE_BER_OK) {
                    result = ret;
                } else {
                    /* Value — copy string bytes with explicit bounds guard */
                    result = GOOSE_BER_OK;
                    for (i = 0U; i < len; i++) {
                        if (*offset >= buf_size) {
                            result = GOOSE_BER_ERR_BUFFER_FULL;
                            break;
                        }
                        buf[*offset] = (uint8_t)str[i];
                        (*offset)++;
                    }
                }
            }
        }
    }

    return result;
}

int ber_encode_utctime(uint8_t *buf, size_t buf_size, size_t *offset,
                       uint8_t tag, uint64_t timestamp_us, uint8_t time_quality)
{
    int result;
    int ret;
    uint32_t seconds;
    uint32_t fraction;

    if (!buf || !offset) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else if ((*offset + 10U) > buf_size) {  /* Tag(1) + Len(1) + Value(8) */
        result = GOOSE_BER_ERR_BUFFER_FULL;
    } else {
        /* IEC 61850 UtcTime: 8 bytes
         *   Bytes 0-3: Seconds since epoch (1970-01-01 00:00:00 UTC)
         *   Bytes 4-6: Fraction of second (24-bit, in units of 1/2^24 seconds)
         *   Byte 7: Time quality
         */

        seconds = (uint32_t)(timestamp_us / 1000000ULL);
        /* Fraction: microseconds * (2^24 / 1000000), with rounding */
        uint64_t frac_us = timestamp_us % 1000000ULL;
        fraction = (uint32_t)((frac_us * (1ULL << 24) + 500000ULL) / 1000000ULL);

        /* Tag */
        ret = ber_encode_tag(buf, buf_size, offset, tag);
        if (ret != GOOSE_BER_OK) {
            result = ret;
        } else {
            /* Length: always 8 bytes */
            ret = ber_encode_length(buf, buf_size, offset, 8U);
            if (ret != GOOSE_BER_OK) {
                result = ret;
            } else {
                /* Value: seconds (4 bytes, big-endian) */
                buf[*offset] = (uint8_t)(seconds >> 24);
                buf[*offset + 1U] = (uint8_t)(seconds >> 16);
                buf[*offset + 2U] = (uint8_t)(seconds >> 8);
                buf[*offset + 3U] = (uint8_t)(seconds);

                /* Fraction (3 bytes, big-endian) */
                buf[*offset + 4U] = (uint8_t)(fraction >> 16);
                buf[*offset + 5U] = (uint8_t)(fraction >> 8);
                buf[*offset + 6U] = (uint8_t)(fraction);

                /* Quality (1 byte) */
                buf[*offset + 7U] = time_quality;

                *offset += 8U;

                result = GOOSE_BER_OK;
            }
        }
    }

    return result;
}

/* Forward declaration for ber_encode_octetstring (defined below) */
static int ber_encode_octetstring(uint8_t *buf, size_t buf_size, size_t *offset,
                                   uint8_t tag, const uint8_t *data, size_t data_len);

/***************************************************************************
 * GOOSE APDU Encoding Functions
 ***************************************************************************/


/**
 * Encode a sequence of GOOSE data elements (no wrapping tag).
 * Used by both goose_encode_alldata (with [11] wrapper) and
 * GOOSE_DATA_STRUCTURE (with [2] CONSTRUCTED wrapper).
 */
static int goose_encode_data_elements(uint8_t *buf, size_t buf_size,
                                       size_t *offset,
                                       const goose_data_t *data, size_t count)
{
    int ret = GOOSE_BER_OK;
    size_t i;

    for (i = 0U; i < count && ret == GOOSE_BER_OK; i++) {
        switch (data[i].type) {
            case GOOSE_DATA_BOOLEAN:
                ret = ber_encode_boolean(buf, buf_size, offset,
                                        ASN1_CLASS_CONTEXT | 0x03U,
                                        data[i].value.boolean);
                break;

            case GOOSE_DATA_INT32:
                ret = ber_encode_int32(buf, buf_size, offset,
                                      ASN1_CLASS_CONTEXT | 0x05U,
                                      data[i].value.int32);
                break;

            case GOOSE_DATA_UINT32:
                ret = ber_encode_uint32(buf, buf_size, offset,
                                       ASN1_CLASS_CONTEXT | 0x06U,
                                       data[i].value.uint32);
                break;

            case GOOSE_DATA_FLOAT32:
            {
                uint8_t float_buf[5];
                uint32_t float_bits;
                float_buf[0] = 0x08U;
                (void)memcpy(&float_bits, &data[i].value.float32, sizeof(uint32_t));
                float_buf[1] = (uint8_t)((float_bits >> 24U) & 0xFFU);
                float_buf[2] = (uint8_t)((float_bits >> 16U) & 0xFFU);
                float_buf[3] = (uint8_t)((float_bits >> 8U) & 0xFFU);
                float_buf[4] = (uint8_t)(float_bits & 0xFFU);
                ret = ber_encode_octetstring(buf, buf_size, offset,
                                            ASN1_CLASS_CONTEXT | 0x07U,
                                            float_buf, 5U);
                break;
            }

            case GOOSE_DATA_BITSTRING:
            {
                uint8_t bs_buf[GOOSE_MAX_ALLDATA_ENTRIES + 1U];
                size_t bs_len = data[i].value.bytes.len;
                if (bs_len > sizeof(bs_buf) - 1U) {
                    ret = GOOSE_BER_ERR_BUFFER_FULL;
                } else {
                    bs_buf[0] = 0x00U;  /* unused bits count */
                    (void)memcpy(&bs_buf[1], data[i].value.bytes.data, bs_len);
                    ret = ber_encode_octetstring(buf, buf_size, offset,
                                                ASN1_CLASS_CONTEXT | 0x04U,
                                                bs_buf, bs_len + 1U);
                }
                break;
            }

            case GOOSE_DATA_OCTETSTRING:
                ret = ber_encode_octetstring(buf, buf_size, offset,
                                            ASN1_CLASS_CONTEXT | 0x09U,
                                            data[i].value.bytes.data,
                                            data[i].value.bytes.len);
                break;

            case GOOSE_DATA_VISIBLESTRING:
                ret = ber_encode_visiblestring(buf, buf_size, offset,
                                              ASN1_CLASS_CONTEXT | 0x0AU,
                                              data[i].value.visiblestring != NULL ?
                                                  data[i].value.visiblestring : "");
                break;

            case GOOSE_DATA_UTCTIME:
                ret = ber_encode_utctime(buf, buf_size, offset,
                                        ASN1_CLASS_CONTEXT | 0x11U,
                                        data[i].value.utctime.timestamp_us,
                                        data[i].value.utctime.time_quality);
                break;

            case GOOSE_DATA_STRUCTURE:
            {
                size_t slen_off;
                size_t scontent_start;
                ret = ber_encode_tag(buf, buf_size, offset,
                                    ASN1_CLASS_CONTEXT | ASN1_CONSTRUCTED | 0x02U);
                if (ret != GOOSE_BER_OK) { break; }
                slen_off = *offset;
                *offset += 3U;
                scontent_start = *offset;
                ret = goose_encode_data_elements(buf, buf_size, offset,
                                                data[i].value.structure.elements,
                                                data[i].value.structure.count);
                if (ret == GOOSE_BER_OK) {
                    size_t slen = *offset - scontent_start;
                    size_t tmp = slen_off;
                    ret = ber_encode_length(buf, buf_size, &tmp, slen);
                    if (ret == GOOSE_BER_OK) {
                        size_t lb = tmp - slen_off;
                        if (lb < 3U) {
                            size_t shift = 3U - lb;
                            (void)memmove(&buf[slen_off + lb],
                                          &buf[scontent_start], slen);
                            *offset -= shift;
                        }
                    }
                }
                break;
            }

            default:
                ret = GOOSE_BER_ERR_ENCODING;
                break;
        }
    }

    return ret;
}

int goose_encode_alldata(uint8_t *buf, size_t buf_size, size_t *offset,
                         const goose_data_t *data, size_t count)
{
    int result;
    int ret;
    size_t alldata_len_offset;
    size_t alldata_content_start;
    size_t alldata_len;

    if (!buf || !offset || !data) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else if (count > GOOSE_MAX_ALLDATA_ENTRIES) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else {
        ret = ber_encode_tag(buf, buf_size, offset, GOOSE_TAG_ALLDATA);
        if (ret != GOOSE_BER_OK) {
            result = ret;
        } else {
            alldata_len_offset = *offset;
            *offset += 3U;
            alldata_content_start = *offset;

            result = goose_encode_data_elements(buf, buf_size, offset, data, count);

            if (result == GOOSE_BER_OK) {
                alldata_len = *offset - alldata_content_start;
                size_t temp_offset = alldata_len_offset;
                ret = ber_encode_length(buf, buf_size, &temp_offset, alldata_len);
                if (ret != GOOSE_BER_OK) {
                    result = ret;
                } else {
                    size_t len_bytes_used = temp_offset - alldata_len_offset;
                    if (len_bytes_used < 3U) {
                        size_t shift = 3U - len_bytes_used;
                        (void)memmove(&buf[alldata_len_offset + len_bytes_used],
                                      &buf[alldata_content_start], alldata_len);
                        (*offset) -= shift;
                    }
                    result = GOOSE_BER_OK;
                }
            }
        }
    }

    return result;
}

int goose_encode_apdu(uint8_t *buf, size_t buf_size,
                      const goose_apdu_t *apdu, size_t *encoded_len)
{
    int result;
    size_t offset = 0;
    int ret;
    size_t apdu_len_offset;
    size_t apdu_content_start;
    size_t apdu_len;

    if (!buf || !apdu || !encoded_len) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else {
        /* GOOSE APDU Tag: APPLICATION 1 | CONSTRUCTED */
        ret = ber_encode_tag(buf, buf_size, &offset, GOOSE_APDU_TAG);
        if (ret != GOOSE_BER_OK) {
            result = ret;
        } else {
            /* Reserve space for APDU length */
            apdu_len_offset = offset;
            offset += 3U;  /* Reserve 3 bytes for BER long form (1 byte 0x82 + 2 bytes length) */
            apdu_content_start = offset;

            /* [0] gocbRef */
            ret = ber_encode_visiblestring(buf, buf_size, &offset,
                                           GOOSE_TAG_GOCBREF, apdu->gocbRef);
            if (ret != GOOSE_BER_OK) {
                result = ret;
            } else {
                /* [1] timeAllowedtoLive */
                ret = ber_encode_uint32(buf, buf_size, &offset,
                                       GOOSE_TAG_TIMEALLOWEDTOLIVE,
                                       apdu->timeAllowedtoLive);
                if (ret != GOOSE_BER_OK) {
                    result = ret;
                } else {
                    /* [2] datSet */
                    ret = ber_encode_visiblestring(buf, buf_size, &offset,
                                                   GOOSE_TAG_DATSET, apdu->datSet);
                    if (ret != GOOSE_BER_OK) {
                        result = ret;
                    } else {
                        /* [3] goID (optional) */
                        if (apdu->has_goID) {
                            ret = ber_encode_visiblestring(buf, buf_size, &offset,
                                                           GOOSE_TAG_GOID, apdu->goID);
                            if (ret != GOOSE_BER_OK) {
                                result = ret;
                            } else {
                                result = GOOSE_BER_OK;
                            }
                        } else {
                            result = GOOSE_BER_OK;
                        }

                        if (result == GOOSE_BER_OK) {
                            /* [4] t (timestamp) */
                            ret = ber_encode_utctime(buf, buf_size, &offset,
                                                    GOOSE_TAG_T, apdu->timestamp, apdu->time_quality);
                            if (ret != GOOSE_BER_OK) {
                                result = ret;
                            } else {
                                /* [5] stNum */
                                ret = ber_encode_uint32(buf, buf_size, &offset,
                                                       GOOSE_TAG_STNUM, apdu->stNum);
                                if (ret != GOOSE_BER_OK) {
                                    result = ret;
                                } else {
                                    /* [6] sqNum */
                                    ret = ber_encode_uint32(buf, buf_size, &offset,
                                                           GOOSE_TAG_SQNUM, apdu->sqNum);
                                    if (ret != GOOSE_BER_OK) {
                                        result = ret;
                                    } else {
                                        /* [7] test */
                                        ret = ber_encode_boolean(buf, buf_size, &offset,
                                                                GOOSE_TAG_TEST, apdu->test);
                                        if (ret != GOOSE_BER_OK) {
                                            result = ret;
                                        } else {
                                            /* [8] confRev */
                                            ret = ber_encode_uint32(buf, buf_size, &offset,
                                                                   GOOSE_TAG_CONFREV, apdu->confRev);
                                            if (ret != GOOSE_BER_OK) {
                                                result = ret;
                                            } else {
                                                /* [9] ndsCom */
                                                ret = ber_encode_boolean(buf, buf_size, &offset,
                                                                        GOOSE_TAG_NDSCOM, apdu->ndsCom);
                                                if (ret != GOOSE_BER_OK) {
                                                    result = ret;
                                                } else {
                                                    /* [10] numDatSetEntries */
                                                    ret = ber_encode_uint32(buf, buf_size, &offset,
                                                                           GOOSE_TAG_NUMDATSETENTRIES,
                                                                           apdu->numDatSetEntries);
                                                    if (ret != GOOSE_BER_OK) {
                                                        result = ret;
                                                    } else {
                                                        /* [11] allData */
                                                        ret = goose_encode_alldata(buf, buf_size, &offset,
                                                                                   apdu->allData, apdu->numDatSetEntries);
                                                        if (ret != GOOSE_BER_OK) {
                                                            result = ret;
                                                        } else {
                                                            /* Calculate APDU length and fill in */
                                                            apdu_len = offset - apdu_content_start;
                                                            size_t temp_offset = apdu_len_offset;
                                                            ret = ber_encode_length(buf, buf_size, &temp_offset, apdu_len);
                                                            if (ret != GOOSE_BER_OK) {
                                                                result = ret;
                                                            } else {
                                                                /* Adjust if length encoding was shorter than 3 bytes reserved */
                                                                size_t len_bytes_used = temp_offset - apdu_len_offset;
                                                                if (len_bytes_used < 3U) {
                                                                    size_t shift = 3U - len_bytes_used;
                                                                    (void)memmove(&buf[apdu_len_offset + len_bytes_used], &buf[apdu_content_start], apdu_len);
                                                                    offset -= shift;
                                                                }

                                                                *encoded_len = offset;
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
                        }
                    }
                }
            }
        }
    }

    return result;
}

/***************************************************************************
 * Helper Functions
 ***************************************************************************/

void goose_apdu_init(goose_apdu_t *apdu)
{
    if (apdu != NULL) {
        (void)memset(apdu, 0, sizeof(goose_apdu_t));
        apdu->timeAllowedtoLive = 5000U;  /* Default: 5 seconds */
        apdu->time_quality = 0x00U;  /* Default: time accuracy unspecified */
        apdu->confRev = 1U;
        apdu->test = false;
        apdu->ndsCom = false;
    }
}

int goose_set_gocbref(goose_apdu_t *apdu, const char *gocbRef)
{
    int result;
    size_t len;

    if (!apdu || !gocbRef) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else {
        len = strlen(gocbRef);
        if (len >= GOOSE_MAX_GOCBREF_LEN) {
            result = GOOSE_BER_ERR_INVALID_ARG;
        } else {
            (void)strncpy(apdu->gocbRef, gocbRef, GOOSE_MAX_GOCBREF_LEN - 1U);
            apdu->gocbRef[GOOSE_MAX_GOCBREF_LEN - 1U] = '\0';
            result = GOOSE_BER_OK;
        }
    }

    return result;
}

int goose_set_datset(goose_apdu_t *apdu, const char *datSet)
{
    int result;
    size_t len;

    if (!apdu || !datSet) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else {
        len = strlen(datSet);
        if (len >= GOOSE_MAX_DATSET_LEN) {
            result = GOOSE_BER_ERR_INVALID_ARG;
        } else {
            (void)strncpy(apdu->datSet, datSet, GOOSE_MAX_DATSET_LEN - 1U);
            apdu->datSet[GOOSE_MAX_DATSET_LEN - 1U] = '\0';
            result = GOOSE_BER_OK;
        }
    }

    return result;
}

int goose_set_goid(goose_apdu_t *apdu, const char *goID)
{
    int result;
    size_t len;

    if (!apdu || !goID) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else {
        len = strlen(goID);
        if (len >= GOOSE_MAX_GOID_LEN) {
            result = GOOSE_BER_ERR_INVALID_ARG;
        } else {
            (void)strncpy(apdu->goID, goID, GOOSE_MAX_GOID_LEN - 1U);
            apdu->goID[GOOSE_MAX_GOID_LEN - 1U] = '\0';
            apdu->has_goID = true;
            result = GOOSE_BER_OK;
        }
    }

    return result;
}

int goose_add_boolean(goose_apdu_t *apdu, bool value)
{
    int result;

    if (!apdu) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else if (apdu->numDatSetEntries >= GOOSE_MAX_ALLDATA_ENTRIES) {
        result = GOOSE_BER_ERR_BUFFER_FULL;
    } else {
        apdu->allData[apdu->numDatSetEntries].type = GOOSE_DATA_BOOLEAN;
        apdu->allData[apdu->numDatSetEntries].value.boolean = value;
        apdu->numDatSetEntries++;
        result = GOOSE_BER_OK;
    }

    return result;
}

int goose_add_int32(goose_apdu_t *apdu, int32_t value)
{
    int result;

    if (!apdu) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else if (apdu->numDatSetEntries >= GOOSE_MAX_ALLDATA_ENTRIES) {
        result = GOOSE_BER_ERR_BUFFER_FULL;
    } else {
        apdu->allData[apdu->numDatSetEntries].type = GOOSE_DATA_INT32;
        apdu->allData[apdu->numDatSetEntries].value.int32 = value;
        apdu->numDatSetEntries++;
        result = GOOSE_BER_OK;
    }

    return result;
}

int goose_add_uint32(goose_apdu_t *apdu, uint32_t value)
{
    int result;

    if (!apdu) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else if (apdu->numDatSetEntries >= GOOSE_MAX_ALLDATA_ENTRIES) {
        result = GOOSE_BER_ERR_BUFFER_FULL;
    } else {
        apdu->allData[apdu->numDatSetEntries].type = GOOSE_DATA_UINT32;
        apdu->allData[apdu->numDatSetEntries].value.uint32 = value;
        apdu->numDatSetEntries++;
        result = GOOSE_BER_OK;
    }

    return result;
}

int goose_add_float32(goose_apdu_t *apdu, float value)
{
    int result;

    if (!apdu) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else if (apdu->numDatSetEntries >= GOOSE_MAX_ALLDATA_ENTRIES) {
        result = GOOSE_BER_ERR_BUFFER_FULL;
    } else {
        apdu->allData[apdu->numDatSetEntries].type = GOOSE_DATA_FLOAT32;
        apdu->allData[apdu->numDatSetEntries].value.float32 = value;
        apdu->numDatSetEntries++;
        result = GOOSE_BER_OK;
    }

    return result;
}

int goose_add_bitstring(goose_apdu_t *apdu, const uint8_t *data, size_t len)
{
    int result;

    if (!apdu || !data) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else if (apdu->numDatSetEntries >= GOOSE_MAX_ALLDATA_ENTRIES) {
        result = GOOSE_BER_ERR_BUFFER_FULL;
    } else {
        apdu->allData[apdu->numDatSetEntries].type = GOOSE_DATA_BITSTRING;
        apdu->allData[apdu->numDatSetEntries].value.bytes.data = (uint8_t *)data;
        apdu->allData[apdu->numDatSetEntries].value.bytes.len = len;
        apdu->numDatSetEntries++;
        result = GOOSE_BER_OK;
    }

    return result;
}

int goose_add_octetstring(goose_apdu_t *apdu, const uint8_t *data, size_t len)
{
    int result;

    if (!apdu || !data) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else if (apdu->numDatSetEntries >= GOOSE_MAX_ALLDATA_ENTRIES) {
        result = GOOSE_BER_ERR_BUFFER_FULL;
    } else {
        apdu->allData[apdu->numDatSetEntries].type = GOOSE_DATA_OCTETSTRING;
        apdu->allData[apdu->numDatSetEntries].value.bytes.data = (uint8_t *)data;
        apdu->allData[apdu->numDatSetEntries].value.bytes.len = len;
        apdu->numDatSetEntries++;
        result = GOOSE_BER_OK;
    }

    return result;
}

int goose_add_visiblestring(goose_apdu_t *apdu, const char *str)
{
    int result;

    if (!apdu || !str) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else if (apdu->numDatSetEntries >= GOOSE_MAX_ALLDATA_ENTRIES) {
        result = GOOSE_BER_ERR_BUFFER_FULL;
    } else {
        apdu->allData[apdu->numDatSetEntries].type = GOOSE_DATA_VISIBLESTRING;
        apdu->allData[apdu->numDatSetEntries].value.visiblestring = (char *)str;
        apdu->numDatSetEntries++;
        result = GOOSE_BER_OK;
    }

    return result;
}

int goose_add_utctime(goose_apdu_t *apdu, uint64_t timestamp_us,
                      uint8_t time_quality)
{
    int result;

    if (!apdu) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else if (apdu->numDatSetEntries >= GOOSE_MAX_ALLDATA_ENTRIES) {
        result = GOOSE_BER_ERR_BUFFER_FULL;
    } else {
        apdu->allData[apdu->numDatSetEntries].type = GOOSE_DATA_UTCTIME;
        apdu->allData[apdu->numDatSetEntries].value.utctime.timestamp_us = timestamp_us;
        apdu->allData[apdu->numDatSetEntries].value.utctime.time_quality = time_quality;
        apdu->numDatSetEntries++;
        result = GOOSE_BER_OK;
    }

    return result;
}

int goose_add_structure(goose_apdu_t *apdu, goose_data_t *elements, size_t count)
{
    int result;

    if (!apdu || !elements) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else if (apdu->numDatSetEntries >= GOOSE_MAX_ALLDATA_ENTRIES) {
        result = GOOSE_BER_ERR_BUFFER_FULL;
    } else {
        apdu->allData[apdu->numDatSetEntries].type = GOOSE_DATA_STRUCTURE;
        apdu->allData[apdu->numDatSetEntries].value.structure.elements = elements;
        apdu->allData[apdu->numDatSetEntries].value.structure.count = count;
        apdu->numDatSetEntries++;
        result = GOOSE_BER_OK;
    }

    return result;
}

/***************************************************************************
 * IEC 62351-6 Security Extension Functions
 ***************************************************************************/

/**
 * Encode ASN.1 OCTET STRING
 */
static int ber_encode_octetstring(uint8_t *buf, size_t buf_size, size_t *offset,
                                   uint8_t tag, const uint8_t *data, size_t data_len)
{
    int result;
    int ret;
    size_t i;

    if (!buf || !offset || !data) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else if ((*offset + 2U + data_len) > buf_size) {
        result = GOOSE_BER_ERR_BUFFER_FULL;
    } else {
        /* Tag */
        ret = ber_encode_tag(buf, buf_size, offset, tag);
        if (ret != GOOSE_BER_OK) {
            result = ret;
        } else {
            /* Length */
            ret = ber_encode_length(buf, buf_size, offset, data_len);
            if (ret != GOOSE_BER_OK) {
                result = ret;
            } else {
                /* Data */
                for (i = 0; i < data_len; i++) {
                    if (*offset >= buf_size) {
                        result = GOOSE_BER_ERR_BUFFER_FULL;
                        return result;
                    }
                    buf[*offset] = data[i];
                    (*offset)++;
                }
                result = GOOSE_BER_OK;
            }
        }
    }

    return result;
}

int goose_set_security(goose_apdu_t *apdu,
                       goose_signature_algo_t signature_algo,
                       const uint8_t *key_id,
                       const uint8_t *signature,
                       size_t signature_len)
{
    int result;
    size_t i;
    struct timespec ts;

    if (!apdu || !key_id || !signature) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else if (signature_len > GOOSE_MAX_SIGNATURE_LEN) {
        result = GOOSE_BER_ERR_INVALID_ARG;
    } else {
        /* Enable security */
        apdu->secure = true;
        apdu->signature_algo = signature_algo;

        /* Copy key ID */
        for (i = 0; i < GOOSE_KEYID_LEN; i++) {
            apdu->key_id[i] = key_id[i];
        }

        /* Set security timestamp (current time) */
        if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
            apdu->security_timestamp = (uint64_t)ts.tv_sec * 1000000ULL +
                                      (uint64_t)ts.tv_nsec / 1000ULL;
        } else {
            apdu->security_timestamp = 0;
        }

        /* Copy signature */
        for (i = 0; i < signature_len; i++) {
            apdu->signature[i] = signature[i];
        }
        apdu->signature_len = signature_len;

        result = GOOSE_BER_OK;
    }

    return result;
}
