/* SPDX-License-Identifier: BSD-2-Clause */
// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2024 IEC-61850 DPDK Project

/**
 * @file mms_ber.c
 * @brief MMS ASN.1 BER encoding/decoding implementation
 *
 * Implementation of MMS protocol encoding per ISO 9506-1 and ISO 9506-2.
 */

#include "asn1/mms_ber.h"
#include <string.h>
#include <stdio.h>

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

/**
 * @brief Check if buffer has enough space
 */
static inline bool has_space(size_t current, size_t required, size_t max) {
    return (current + required) <= max;
}

/**
 * @brief Encode BER length field (definite form)
 *
 * BER length encoding:
 * - Short form (0-127): Single byte with length value
 * - Long form (128+): First byte = 0x80 | num_octets, followed by length bytes
 */
int mms_encode_length(size_t length, uint8_t* buffer, size_t buflen) {
    if (buffer == NULL) {
        return MMS_ERROR_INVALID_PARAM;
    }

    if (length < 128) {
        /* Short form: length fits in 7 bits */
        if (buflen < 1) {
            return MMS_ERROR_BUFFER_TOO_SMALL;
        }
        buffer[0] = (uint8_t)length;
        return 1;
    } else {
        /* Long form: determine number of octets needed */
        size_t temp = length;
        int num_octets = 0;
        while (temp > 0) {
            temp >>= 8;
            num_octets++;
        }

        if (buflen < (size_t)(1 + num_octets)) {
            return MMS_ERROR_BUFFER_TOO_SMALL;
        }

        /* First byte: 0x80 | number of length octets */
        buffer[0] = 0x80 | num_octets;

        /* Encode length in big-endian */
        for (int i = num_octets - 1; i >= 0; i--) {
            buffer[1 + i] = (uint8_t)(length & 0xFF);
            length >>= 8;
        }

        return 1 + num_octets;
    }
}

/**
 * @brief Decode BER length field
 */
int mms_decode_length(const uint8_t* buffer, size_t buflen, size_t* length) {
    if (buffer == NULL || length == NULL) {
        return MMS_ERROR_INVALID_PARAM;
    }

    if (buflen < 1) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }

    uint8_t first_byte = buffer[0];

    if ((first_byte & 0x80) == 0) {
        /* Short form */
        *length = first_byte;
        return 1;
    } else {
        /* Long form */
        int num_octets = first_byte & 0x7F;

        if (num_octets == 0) {
            /* Indefinite form not supported */
            return MMS_ERROR_INVALID_ENCODING;
        }

        if (buflen < (size_t)(1 + num_octets)) {
            return MMS_ERROR_BUFFER_TOO_SMALL;
        }

        *length = 0;
        for (int i = 0; i < num_octets; i++) {
            *length = (*length << 8) | buffer[1 + i];
        }

        return 1 + num_octets;
    }
}

/**
 * @brief Encode INTEGER value (signed)
 */
static int encode_integer(int32_t value, uint8_t* buffer, size_t buflen) {
    if (buffer == NULL) {
        return MMS_ERROR_INVALID_PARAM;
    }

    /* Determine minimum number of bytes needed */
    int num_bytes;
    if (value >= -128 && value <= 127) {
        num_bytes = 1;
    } else if (value >= -32768 && value <= 32767) {
        num_bytes = 2;
    } else {
        num_bytes = 4;
    }

    if (buflen < (size_t)num_bytes) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }

    /* Encode in big-endian, two's complement */
    for (int i = num_bytes - 1; i >= 0; i--) {
        buffer[i] = (uint8_t)(value & 0xFF);
        value >>= 8;
    }

    return num_bytes;
}

/**
 * @brief Decode INTEGER value (signed)
 */
static int decode_integer(const uint8_t* buffer, size_t buflen, int32_t* value) {
    if (buffer == NULL || value == NULL || buflen == 0) {
        return MMS_ERROR_INVALID_PARAM;
    }

    /* Use unsigned arithmetic to avoid undefined behavior from shifting negative values */
    uint32_t unsigned_value = 0;
    for (size_t i = 0; i < buflen; i++) {
        unsigned_value = (unsigned_value << 8) | buffer[i];
    }

    /* Convert to signed, handling sign extension for negative values */
    if ((buffer[0] & 0x80) != 0 && buflen < 4) {
        /* Sign extend: set high bits to 1 for negative values */
        uint32_t sign_mask = ~((1u << (buflen * 8)) - 1);
        unsigned_value |= sign_mask;
    }

    *value = (int32_t)unsigned_value;
    return (int)buflen;
}

/**
 * @brief Encode UNSIGNED value
 */
static int encode_unsigned(uint32_t value, uint8_t* buffer, size_t buflen) {
    if (buffer == NULL) {
        return MMS_ERROR_INVALID_PARAM;
    }

    /* Determine minimum number of bytes needed */
    int num_bytes;
    if (value <= 0xFF) {
        num_bytes = 1;
    } else if (value <= 0xFFFF) {
        num_bytes = 2;
    } else {
        num_bytes = 4;
    }

    if (buflen < (size_t)num_bytes) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }

    /* Encode in big-endian */
    for (int i = num_bytes - 1; i >= 0; i--) {
        buffer[i] = (uint8_t)(value & 0xFF);
        value >>= 8;
    }

    return num_bytes;
}

/**
 * @brief Decode UNSIGNED value
 */
static int decode_unsigned(const uint8_t* buffer, size_t buflen, uint32_t* value) {
    if (buffer == NULL || value == NULL || buflen == 0) {
        return MMS_ERROR_INVALID_PARAM;
    }

    *value = 0;
    for (size_t i = 0; i < buflen; i++) {
        *value = (*value << 8) | buffer[i];
    }

    return (int)buflen;
}

/**
 * @brief Encode VISIBLE-STRING
 */
static int encode_visible_string(const char* str, uint8_t* buffer, size_t buflen) {
    if (str == NULL || buffer == NULL) {
        return MMS_ERROR_INVALID_PARAM;
    }

    size_t str_len = strlen(str);
    if (str_len > MMS_MAX_STRING_LENGTH) {
        return MMS_ERROR_INVALID_PARAM;
    }

    if (buflen < str_len) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(buffer, str, str_len);
    return (int)str_len;
}

/**
 * @brief Decode VISIBLE-STRING
 */
static int decode_visible_string(const uint8_t* buffer, size_t buflen, char* str, size_t str_max) {
    if (buffer == NULL || str == NULL) {
        return MMS_ERROR_INVALID_PARAM;
    }

    if (buflen >= str_max) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(str, buffer, buflen);
    str[buflen] = '\0';

    return (int)buflen;
}

/* ============================================================================
 * MMS Value Encoding/Decoding
 * ============================================================================ */

int mms_encode_value(const mms_value_t* value, uint8_t* buffer, size_t buflen) {
    if (value == NULL || buffer == NULL) {
        return MMS_ERROR_INVALID_PARAM;
    }

    size_t offset = 0;
    int ret;

    /* Encode tag based on type */
    uint8_t tag;
    switch (value->type) {
        case MMS_TYPE_BOOLEAN:
            tag = MMS_DATA_BOOLEAN;
            break;
        case MMS_TYPE_INTEGER:
            tag = MMS_DATA_INTEGER;
            break;
        case MMS_TYPE_UNSIGNED:
            tag = MMS_DATA_UNSIGNED;
            break;
        case MMS_TYPE_VISIBLE_STRING:
            tag = MMS_DATA_VISIBLE_STRING;
            break;
        case MMS_TYPE_UTC_TIME:
            tag = MMS_DATA_UTC_TIME;
            break;
        case MMS_TYPE_FLOATING_POINT:
            tag = MMS_DATA_FLOATING_POINT;
            break;
        case MMS_TYPE_OCTET_STRING:
            tag = MMS_DATA_OCTET_STRING;
            break;
        case MMS_TYPE_BIT_STRING:
            tag = MMS_DATA_BIT_STRING;
            break;
        default:
            return MMS_ERROR_NOT_SUPPORTED;
    }

    if (!has_space(offset, 1, buflen)) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }
    buffer[offset++] = tag;

    /* Encode value content to temporary buffer */
    uint8_t value_buf[256];
    int value_len;

    switch (value->type) {
        case MMS_TYPE_BOOLEAN:
            value_buf[0] = value->value.boolean ? 0xFF : 0x00;
            value_len = 1;
            break;

        case MMS_TYPE_INTEGER:
            value_len = encode_integer(value->value.integer, value_buf, sizeof(value_buf));
            if (value_len < 0) {
                return value_len;
            }
            break;

        case MMS_TYPE_UNSIGNED:
            value_len = encode_unsigned(value->value.unsigned_val, value_buf, sizeof(value_buf));
            if (value_len < 0) {
                return value_len;
            }
            break;

        case MMS_TYPE_VISIBLE_STRING:
            value_len = (int)value->value.visible_string.len;
            if (value_len > (int)sizeof(value_buf)) {
                return MMS_ERROR_BUFFER_TOO_SMALL;
            }
            memcpy(value_buf, value->value.visible_string.data, value_len);
            break;

        case MMS_TYPE_UTC_TIME:
            /* UTC time is 8 bytes */
            for (int i = 7; i >= 0; i--) {
                value_buf[7 - i] = (uint8_t)((value->value.utc_time >> (i * 8)) & 0xFF);
            }
            value_len = 8;
            break;

        case MMS_TYPE_FLOATING_POINT: {
            /* IEC 61850 floating point: 1 byte exponent width + 4 bytes IEEE 754 */
            uint32_t ieee;
            memcpy(&ieee, &value->value.floating_point, sizeof(ieee));
            value_buf[0] = 0x08;  /* exponent width = 8 bits (single precision) */
            value_buf[1] = (uint8_t)((ieee >> 24) & 0xFF);
            value_buf[2] = (uint8_t)((ieee >> 16) & 0xFF);
            value_buf[3] = (uint8_t)((ieee >> 8) & 0xFF);
            value_buf[4] = (uint8_t)(ieee & 0xFF);
            value_len = 5;
            break;
        }

        case MMS_TYPE_OCTET_STRING:
            if (value->value.octet_string.len > sizeof(value_buf)) {
                return MMS_ERROR_BUFFER_TOO_SMALL;
            }
            memcpy(value_buf, value->value.octet_string.data, value->value.octet_string.len);
            value_len = (int)value->value.octet_string.len;
            break;

        case MMS_TYPE_BIT_STRING:
            if (value->value.bit_string.bit_count == 0) {
                return MMS_ERROR_INVALID_PARAM;
            }
            /* BIT STRING: first byte is unused-bits count, then data */
            {
                size_t byte_count = (value->value.bit_string.bit_count + 7) / 8;
                uint8_t unused = (uint8_t)((byte_count * 8) - value->value.bit_string.bit_count);
                if (byte_count + 1 > sizeof(value_buf)) {
                    return MMS_ERROR_BUFFER_TOO_SMALL;
                }
                value_buf[0] = unused;
                memcpy(value_buf + 1, value->value.bit_string.data, byte_count);
                value_len = (int)(byte_count + 1);
            }
            break;

        default:
            return MMS_ERROR_NOT_SUPPORTED;
    }

    /* Encode length */
    ret = mms_encode_length(value_len, buffer + offset, buflen - offset);
    if (ret < 0) {
        return ret;
    }
    offset += ret;

    /* Encode value */
    if (!has_space(offset, value_len, buflen)) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(buffer + offset, value_buf, value_len);
    offset += value_len;

    return (int)offset;
}

int mms_decode_value(const uint8_t* buffer, size_t buflen, mms_value_t* value) {
    if (buffer == NULL || value == NULL || buflen < 2) {
        return MMS_ERROR_INVALID_PARAM;
    }

    size_t offset = 0;

    /* Decode tag */
    uint8_t tag = buffer[offset++];

    /* Decode length */
    size_t length;
    int ret = mms_decode_length(buffer + offset, buflen - offset, &length);
    if (ret < 0) {
        return ret;
    }
    offset += ret;

    if (!has_space(offset, length, buflen)) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }

    /* Decode value based on tag */
    switch (tag) {
        case MMS_DATA_BOOLEAN:
            value->type = MMS_TYPE_BOOLEAN;
            value->value.boolean = (buffer[offset] != 0);
            break;

        case MMS_DATA_INTEGER: {
            value->type = MMS_TYPE_INTEGER;
            ret = decode_integer(buffer + offset, length, &value->value.integer);
            if (ret < 0) {
                return ret;
            }
            break;
        }

        case MMS_DATA_UNSIGNED: {
            value->type = MMS_TYPE_UNSIGNED;
            ret = decode_unsigned(buffer + offset, length, &value->value.unsigned_val);
            if (ret < 0) {
                return ret;
            }
            break;
        }

        case MMS_DATA_VISIBLE_STRING:
            value->type = MMS_TYPE_VISIBLE_STRING;
            if (length >= MMS_MAX_STRING_LENGTH) {
                return MMS_ERROR_BUFFER_TOO_SMALL;
            }
            memcpy(value->value.visible_string.data, buffer + offset, length);
            value->value.visible_string.data[length] = '\0';
            value->value.visible_string.len = length;
            break;

        case MMS_DATA_UTC_TIME:
            value->type = MMS_TYPE_UTC_TIME;
            if (length != 8) {
                return MMS_ERROR_INVALID_ENCODING;
            }
            value->value.utc_time = 0;
            for (size_t i = 0; i < 8; i++) {
                value->value.utc_time = (value->value.utc_time << 8) | buffer[offset + i];
            }
            break;

        case MMS_DATA_FLOATING_POINT: {
            value->type = MMS_TYPE_FLOATING_POINT;
            /* IEC 61850: 1 byte exponent width + IEEE 754 bytes */
            if (length < 5) {
                return MMS_ERROR_INVALID_ENCODING;
            }
            /* Skip exponent width byte, read 4-byte IEEE 754 */
            uint32_t ieee = ((uint32_t)buffer[offset + 1] << 24) |
                            ((uint32_t)buffer[offset + 2] << 16) |
                            ((uint32_t)buffer[offset + 3] << 8) |
                            (uint32_t)buffer[offset + 4];
            memcpy(&value->value.floating_point, &ieee, sizeof(float));
            break;
        }

        case MMS_DATA_OCTET_STRING:
            value->type = MMS_TYPE_OCTET_STRING;
            if (length > MMS_MAX_STRING_LENGTH) {
                return MMS_ERROR_BUFFER_TOO_SMALL;
            }
            memcpy(value->value.octet_string.data, buffer + offset, length);
            value->value.octet_string.len = length;
            break;

        case MMS_DATA_BIT_STRING:
            value->type = MMS_TYPE_BIT_STRING;
            if (length < 1) {
                return MMS_ERROR_INVALID_ENCODING;
            }
            {
                uint8_t unused = buffer[offset];
                size_t byte_count = length - 1;
                if (byte_count > 32) {
                    return MMS_ERROR_BUFFER_TOO_SMALL;
                }
                memcpy(value->value.bit_string.data, buffer + offset + 1, byte_count);
                value->value.bit_string.bit_count = (byte_count * 8) - unused;
            }
            break;

        default:
            return MMS_ERROR_NOT_SUPPORTED;
    }

    offset += length;
    return (int)offset;
}

/* ============================================================================
 * Initiate Request/Response
 * ============================================================================ */

int mms_encode_initiate_request(const mms_initiate_request_t* request,
                                uint8_t* buffer, size_t buflen) {
    if (request == NULL || buffer == NULL) {
        return MMS_ERROR_INVALID_PARAM;
    }

    size_t offset = 0;

    /* Initiate-RequestPDU tag [8] IMPLICIT */
    if (!has_space(offset, 1, buflen)) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }
    buffer[offset++] = MMS_TAG_INITIATE_REQUEST;

    /* Build content in temporary buffer */
    uint8_t content[256];
    size_t content_offset = 0;

    /* localDetailCalling [0] IMPLICIT INTEGER (proposed max PDU size) */
    content[content_offset++] = 0x80;  /* [0] IMPLICIT */
    uint8_t temp_buf[16];
    int ret = encode_integer(request->proposed_max_pdu_size, temp_buf, sizeof(temp_buf));
    if (ret < 0) {
        return ret;
    }
    content[content_offset++] = (uint8_t)ret;  /* Length */
    memcpy(content + content_offset, temp_buf, ret);
    content_offset += ret;

    /* proposedMaxServOutstandingCalling [1] IMPLICIT INTEGER */
    content[content_offset++] = 0x81;  /* [1] IMPLICIT */
    content[content_offset++] = 0x01;  /* Length = 1 */
    content[content_offset++] = 0x01;  /* Value = 1 (sequential requests) */

    /* proposedDataStructureNestingLevel [2] IMPLICIT INTEGER */
    content[content_offset++] = 0x82;  /* [2] IMPLICIT */
    ret = encode_integer(request->proposed_data_structure_nesting_level, temp_buf, sizeof(temp_buf));
    if (ret < 0) {
        return ret;
    }
    content[content_offset++] = (uint8_t)ret;
    memcpy(content + content_offset, temp_buf, ret);
    content_offset += ret;

    /* Encode length of Initiate-Request content */
    ret = mms_encode_length(content_offset, buffer + offset, buflen - offset);
    if (ret < 0) {
        return ret;
    }
    offset += ret;

    /* Copy content */
    if (!has_space(offset, content_offset, buflen)) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(buffer + offset, content, content_offset);
    offset += content_offset;

    return (int)offset;
}

int mms_decode_initiate_request(const uint8_t* buffer, size_t buflen,
                                mms_initiate_request_t* request) {
    if (buffer == NULL || request == NULL || buflen < 2) {
        return MMS_ERROR_INVALID_PARAM;
    }

    size_t offset = 0;

    /* Check tag */
    if (buffer[offset++] != MMS_TAG_INITIATE_REQUEST) {
        return MMS_ERROR_INVALID_ENCODING;
    }

    /* Decode length */
    size_t length;
    int ret = mms_decode_length(buffer + offset, buflen - offset, &length);
    if (ret < 0) {
        return ret;
    }
    offset += ret;

    /* Initialize with defaults */
    request->proposed_max_pdu_size = 65000;
    request->proposed_data_structure_nesting_level = 10;
    request->proposed_version_number = 1;

    size_t end = offset + length;
    while (offset < end) {
        uint8_t tag = buffer[offset++];
        size_t field_len;
        ret = mms_decode_length(buffer + offset, buflen - offset, &field_len);
        if (ret < 0) {
            return ret;
        }
        offset += ret;

        switch (tag) {
            case 0x80:  /* localDetailCalling */
                ret = decode_integer(buffer + offset, field_len, (int32_t*)&request->proposed_max_pdu_size);
                if (ret < 0) {
                    return ret;
                }
                break;

            case 0x82:  /* proposedDataStructureNestingLevel */
                ret = decode_integer(buffer + offset, field_len, (int32_t*)&request->proposed_data_structure_nesting_level);
                if (ret < 0) {
                    return ret;
                }
                break;

            default:
                /* Skip unknown fields */
                break;
        }

        offset += field_len;
    }

    return (int)offset;
}

int mms_encode_initiate_response(const mms_initiate_response_t* response,
                                 uint8_t* buffer, size_t buflen) {
    if (response == NULL || buffer == NULL) {
        return MMS_ERROR_INVALID_PARAM;
    }

    size_t offset = 0;

    /* Initiate-ResponsePDU tag [9] IMPLICIT */
    if (!has_space(offset, 1, buflen)) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }
    buffer[offset++] = MMS_TAG_INITIATE_RESPONSE;

    /* Build content */
    uint8_t content[256];
    size_t content_offset = 0;

    /* localDetailCalled [0] IMPLICIT INTEGER */
    content[content_offset++] = 0x80;
    uint8_t temp_buf[16];
    int ret = encode_integer(response->negotiated_max_pdu_size, temp_buf, sizeof(temp_buf));
    if (ret < 0) {
        return ret;
    }
    content[content_offset++] = (uint8_t)ret;
    memcpy(content + content_offset, temp_buf, ret);
    content_offset += ret;

    /* negociatedMaxServOutstandingCalling [1] IMPLICIT INTEGER */
    content[content_offset++] = 0x81;
    content[content_offset++] = 0x01;
    content[content_offset++] = 0x01;

    /* negociatedMaxServOutstandingCalled [2] IMPLICIT INTEGER */
    content[content_offset++] = 0x82;
    content[content_offset++] = 0x01;
    content[content_offset++] = 0x04;

    /* negociatedDataStructureNestingLevel [3] IMPLICIT INTEGER */
    content[content_offset++] = 0x83;
    ret = encode_integer(response->negotiated_data_structure_nesting_level, temp_buf, sizeof(temp_buf));
    if (ret < 0) {
        return ret;
    }
    content[content_offset++] = (uint8_t)ret;
    memcpy(content + content_offset, temp_buf, ret);
    content_offset += ret;

    /* initResponseDetail [4] IMPLICIT SEQUENCE {
     *   [0] negotiatedVersionNumber  INTEGER,
     *   [1] proposedParameterCBB     BIT STRING (11 bits),
     *   [2] servicesSupportedCalled  BIT STRING (85 bits = 11 bytes)
     * }
     * Required by MMS clients (ISO 9506-2) to accept the association. */
    {
        uint8_t detail[64];
        size_t detail_offset = 0;

        /* [0] negotiatedVersionNumber - INTEGER = 1 */
        detail[detail_offset++] = 0x80;  /* [0] tag */
        detail[detail_offset++] = 0x01;  /* length 1 */
        detail[detail_offset++] = 0x01;  /* version 1 */

        /* [1] proposedParameterCBB - BIT STRING (11 bits → 2 bytes + unused) */
        detail[detail_offset++] = 0x81;  /* [1] tag */
        detail[detail_offset++] = 0x03;  /* length: 3 bytes (1 unused + 2 data) */
        detail[detail_offset++] = 0x05;  /* 5 unused bits (16 - 11 = 5) */
        detail[detail_offset++] = 0xF1;  /* CBB: str1+str2+vnam+valt+vadr (bits 0-4 set) */
        detail[detail_offset++] = 0x00;  /* remaining bits */

        /* [2] servicesSupportedCalled - BIT STRING (85 bits → 11 bytes + unused) */
        detail[detail_offset++] = 0x82;  /* [2] tag */
        detail[detail_offset++] = 0x0C;  /* length: 12 bytes (1 unused + 11 data) */
        detail[detail_offset++] = 0x03;  /* 3 unused bits (88 - 85 = 3) */
        /* Services supported bitmap (85 bits, MSB first):
         * Bit 0: status, 1: getNameList, 2: identify, 3: rename,
         * 4: read, 5: write, 6: getVariableAccessAttributes,
         * 7: defineNamedVariable, 8: defineScatteredAccess,
         * 9: getScatteredAccessAttributes, 10: deleteVariableAccess,
         * 11: defineNamedVariableList, 12: getNamedVariableListAttributes,
         * 13: deleteNamedVariableList, 14: defineNamedType,
         * 15: getNamedTypeAttributes, 16: deleteNamedType,
         * ... (see ISO 9506-2 Table 38) */
        /* Set bits for all 27 services we support */
        detail[detail_offset++] = 0xEE;  /* bits 0-7: status,getNameList,identify,X,read,write,getVarAttrs,defNamedVar */
        detail[detail_offset++] = 0x08;  /* bits 8-15: X,X,X,defNamedVarList,getNamedVarListAttrs,delNamedVarList,X,X */
        detail[detail_offset++] = 0x00;  /* bits 16-23 */
        detail[detail_offset++] = 0x00;  /* bits 24-31 */
        detail[detail_offset++] = 0x04;  /* bits 32-39: conclude(bit 37) */
        detail[detail_offset++] = 0x08;  /* bits 40-47: abort(bit 44) */
        detail[detail_offset++] = 0x00;  /* bits 48-55 */
        detail[detail_offset++] = 0x00;  /* bits 56-63 */
        detail[detail_offset++] = 0x00;  /* bits 64-71 */
        detail[detail_offset++] = 0x00;  /* bits 72-79 */
        detail[detail_offset++] = 0x00;  /* bits 80-87 */

        /* Wrap in [4] IMPLICIT SEQUENCE */
        content[content_offset++] = 0xA4;  /* [4] CONSTRUCTED */
        if (detail_offset < 128U) {
            content[content_offset++] = (uint8_t)detail_offset;
        } else {
            content[content_offset++] = 0x81;
            content[content_offset++] = (uint8_t)detail_offset;
        }
        memcpy(content + content_offset, detail, detail_offset);
        content_offset += detail_offset;
    }

    /* Encode length */
    ret = mms_encode_length(content_offset, buffer + offset, buflen - offset);
    if (ret < 0) {
        return ret;
    }
    offset += ret;

    /* Copy content */
    if (!has_space(offset, content_offset, buflen)) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(buffer + offset, content, content_offset);
    offset += content_offset;

    return (int)offset;
}

int mms_decode_initiate_response(const uint8_t* buffer, size_t buflen,
                                 mms_initiate_response_t* response) {
    if (buffer == NULL || response == NULL || buflen < 2) {
        return MMS_ERROR_INVALID_PARAM;
    }

    size_t offset = 0;

    /* Check tag */
    if (buffer[offset++] != MMS_TAG_INITIATE_RESPONSE) {
        return MMS_ERROR_INVALID_ENCODING;
    }

    /* Decode length */
    size_t length;
    int ret = mms_decode_length(buffer + offset, buflen - offset, &length);
    if (ret < 0) {
        return ret;
    }
    offset += ret;

    /* Initialize with defaults */
    response->negotiated_max_pdu_size = 65000;
    response->negotiated_data_structure_nesting_level = 10;
    response->negotiated_version_number = 1;

    size_t end = offset + length;
    while (offset < end) {
        uint8_t tag = buffer[offset++];
        size_t field_len;
        ret = mms_decode_length(buffer + offset, buflen - offset, &field_len);
        if (ret < 0) {
            return ret;
        }
        offset += ret;

        switch (tag) {
            case 0x80:  /* localDetailCalled */
                ret = decode_integer(buffer + offset, field_len, (int32_t*)&response->negotiated_max_pdu_size);
                if (ret < 0) {
                    return ret;
                }
                break;

            case 0x82:  /* negociatedDataStructureNestingLevel */
                ret = decode_integer(buffer + offset, field_len, (int32_t*)&response->negotiated_data_structure_nesting_level);
                if (ret < 0) {
                    return ret;
                }
                break;

            default:
                /* Skip unknown fields */
                break;
        }

        offset += field_len;
    }

    return (int)offset;
}

/* ============================================================================
 * Conclude Request/Response
 * ============================================================================ */

int mms_encode_conclude_request(const mms_conclude_request_t* request,
                                uint8_t* buffer, size_t buflen) {
    if (request == NULL || buffer == NULL) {
        return MMS_ERROR_INVALID_PARAM;
    }

    if (buflen < 2) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }

    /* Conclude-RequestPDU [10] IMPLICIT - empty sequence */
    buffer[0] = MMS_TAG_CONCLUDE_REQUEST;
    buffer[1] = 0x00;  /* Length = 0 */

    return 2;
}

int mms_decode_conclude_request(const uint8_t* buffer, size_t buflen,
                                mms_conclude_request_t* request) {
    if (buffer == NULL || request == NULL || buflen < 2) {
        return MMS_ERROR_INVALID_PARAM;
    }

    if (buffer[0] != MMS_TAG_CONCLUDE_REQUEST || buffer[1] != 0x00) {
        return MMS_ERROR_INVALID_ENCODING;
    }

    return 2;
}

int mms_encode_conclude_response(const mms_conclude_response_t* response,
                                 uint8_t* buffer, size_t buflen) {
    if (response == NULL || buffer == NULL) {
        return MMS_ERROR_INVALID_PARAM;
    }

    if (buflen < 2) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }

    /* Conclude-ResponsePDU [11] IMPLICIT - empty sequence */
    buffer[0] = MMS_TAG_CONCLUDE_RESPONSE;
    buffer[1] = 0x00;  /* Length = 0 */

    return 2;
}

int mms_decode_conclude_response(const uint8_t* buffer, size_t buflen,
                                 mms_conclude_response_t* response) {
    if (buffer == NULL || response == NULL || buflen < 2) {
        return MMS_ERROR_INVALID_PARAM;
    }

    if (buffer[0] != MMS_TAG_CONCLUDE_RESPONSE || buffer[1] != 0x00) {
        return MMS_ERROR_INVALID_ENCODING;
    }

    return 2;
}

/* ============================================================================
 * Error String Helper
 * ============================================================================ */

const char* mms_error_string(int error_code) {
    switch (error_code) {
        case MMS_OK:
            return "Success";
        case MMS_ERROR_BUFFER_TOO_SMALL:
            return "Buffer too small";
        case MMS_ERROR_INVALID_PARAM:
            return "Invalid parameter";
        case MMS_ERROR_INVALID_ENCODING:
            return "Invalid encoding";
        case MMS_ERROR_NOT_SUPPORTED:
            return "Not supported";
        case MMS_ERROR_SERVICE_ERROR:
            return "Service error";
        case MMS_ERROR_OUT_OF_MEMORY:
            return "Out of memory";
        default:
            return "Unknown error";
    }
}

/* ============================================================================
 * Confirmed Request/Response Wrappers
 * ============================================================================ */


/* ============================================================================
 * Extracted request encoders (one per MMS service type)
 * ============================================================================ */

static int encode_read_req_body(const mms_confirmed_request_t *request,
                       uint8_t *buf, size_t buflen) {
    (void)buflen;
    size_t domain_len = strlen(request->params.read.variable_spec.domain);
    size_t item_len = strlen(request->params.read.variable_spec.item_id);

    /*
     * Read-Request ::= SEQUENCE {
     *   specificationWithResult [0] IMPLICIT BOOLEAN DEFAULT FALSE,  -- omitted
     *   variableAccessSpecification [1] CHOICE {
     *     listOfVariable [0] IMPLICIT SEQUENCE OF SEQUENCE {
     *       variableSpecification CHOICE {
     *         name [0] ObjectName CHOICE {
     *           domain-specific [1] IMPLICIT SEQUENCE {
     *             domainId VisibleString,
     *             itemId VisibleString
     * }}}}}}
     *
     * The [1] wrapper avoids tag conflict with specificationWithResult [0].
     */
    size_t ds_content = (2 + domain_len) + (2 + item_len);
    size_t ds_total = 2 + ds_content;   /* A1 + len */
    size_t name_total = 2 + ds_total;   /* A0 + len */
    size_t seq_total = 2 + name_total;  /* 30 + len */
    size_t lov_content = seq_total;
    size_t lov_total = 2 + lov_content; /* A0 + len */

    size_t o = 0;
    /* variableAccessSpecification [1] CONSTRUCTED */
    buf[o++] = 0xA1;
    buf[o++] = (uint8_t)lov_total;

    /* listOfVariable [0] IMPLICIT SEQUENCE OF */
    buf[o++] = 0xA0;
    buf[o++] = (uint8_t)lov_content;

    /* SEQUENCE (one variable) */
    buf[o++] = 0x30;
    buf[o++] = (uint8_t)name_total;

    /* variableSpecification: name [0] */
    buf[o++] = 0xA0;
    buf[o++] = (uint8_t)ds_total;

    /* domain-specific [1] IMPLICIT SEQUENCE */
    buf[o++] = 0xA1;
    buf[o++] = (uint8_t)ds_content;

    /* domainId: VisibleString (0x1A) */
    buf[o++] = 0x1A;
    buf[o++] = (uint8_t)domain_len;
    memcpy(buf + o, request->params.read.variable_spec.domain, domain_len);
    o += domain_len;

    /* itemId: VisibleString (0x1A) */
    buf[o++] = 0x1A;
    buf[o++] = (uint8_t)item_len;
    memcpy(buf + o, request->params.read.variable_spec.item_id, item_len);
    o += item_len;

    return (int)o;
}

static int encode_write_req_body(const mms_confirmed_request_t *request,
                       uint8_t *buf, size_t buflen) {
    int ret;
    size_t domain_len = strlen(request->params.write.variable_spec.domain);
    size_t item_len = strlen(request->params.write.variable_spec.item_id);

    /*
     * Write-Request ::= SEQUENCE {
     *   variableAccessSpecification VariableAccessSpecification,
     *   listOfData [0] IMPLICIT SEQUENCE OF Data
     * }
     *
     * variableAccessSpecification: listOfVariable [0] { 30 { A0 { A1 { 1A dom 1A item }}}}
     * No [1] wrapper needed (unlike Read — Write has no specificationWithResult).
     */
    size_t ds_content = (2 + domain_len) + (2 + item_len);
    size_t ds_total = 2 + ds_content;
    size_t name_total = 2 + ds_total;
    size_t seq_total = 2 + name_total;

    size_t o = 0;

    /* listOfVariable [0] CONSTRUCTED */
    buf[o++] = 0xA0;
    buf[o++] = (uint8_t)seq_total;

    /* SEQUENCE (one variable) */
    buf[o++] = 0x30;
    buf[o++] = (uint8_t)name_total;

    /* variableSpecification: name [0] */
    buf[o++] = 0xA0;
    buf[o++] = (uint8_t)ds_total;

    /* domain-specific [1] IMPLICIT SEQUENCE */
    buf[o++] = 0xA1;
    buf[o++] = (uint8_t)ds_content;

    /* domainId: VisibleString */
    buf[o++] = 0x1A;
    buf[o++] = (uint8_t)domain_len;
    memcpy(buf + o, request->params.write.variable_spec.domain, domain_len);
    o += domain_len;

    /* itemId: VisibleString */
    buf[o++] = 0x1A;
    buf[o++] = (uint8_t)item_len;
    memcpy(buf + o, request->params.write.variable_spec.item_id, item_len);
    o += item_len;

    /* listOfData [0] IMPLICIT SEQUENCE OF Data */
    buf[o++] = 0xA0;
    ret = mms_encode_value(&request->params.write.value, buf + o + 1, buflen - o - 1);
    if (ret < 0) {
        return ret;
    }
    buf[o] = (uint8_t)ret;
    o++;
    o += (size_t)ret;

    return (int)o;
}

static int encode_get_namelist_req_body(const mms_confirmed_request_t *request,
                       uint8_t *buf, size_t buflen) {
    (void)buflen;
    size_t domain_len;
    int slen = 0;
    /* extendedObjectClass [0] CONSTRUCTED { objectClass [0] INTEGER } */
    buf[slen++] = 0xA0;  /* [0] CONSTRUCTED */
    buf[slen++] = 0x03;
    buf[slen++] = 0x80;  /* objectClass [0] IMPLICIT INTEGER */
    buf[slen++] = 0x01;
    buf[slen++] = (uint8_t)request->params.getnamelist.object_class;
    if (strlen(request->params.getnamelist.domain) > 0) {
        domain_len = strlen(request->params.getnamelist.domain);
        buf[slen++] = 0xA1;  /* objectScope [1] CONSTRUCTED */
        buf[slen++] = (uint8_t)(2 + domain_len);
        buf[slen++] = 0x81;  /* domainSpecific [1] IMPLICIT */
        buf[slen++] = (uint8_t)domain_len;
        memcpy(buf + slen, request->params.getnamelist.domain, domain_len);
        slen += (int)domain_len;
    } else {
        buf[slen++] = 0xA1;
        buf[slen++] = 0x02;
        buf[slen++] = 0x80;
        buf[slen++] = 0x00;
    }

    /* continueAfter [2] IMPLICIT VisibleString (optional) */
    if (request->params.getnamelist.continue_after) {
        size_t ca_len = strlen(request->params.getnamelist.continue_after_id);
        if (ca_len > 0) {
            buf[slen++] = 0x82;  /* [2] IMPLICIT */
            buf[slen++] = (uint8_t)ca_len;
            memcpy(buf + slen, request->params.getnamelist.continue_after_id, ca_len);
            slen += (int)ca_len;
        }
    }

    return slen;
}

static int encode_get_variable_attrs_req_body(const mms_confirmed_request_t *request,
                       uint8_t *buf, size_t buflen) {
    uint8_t temp_buf[16];
    int ret;
    (void)temp_buf; (void)ret; (void)buflen;
    size_t domain_len;
    size_t item_len;
    /* GetVariableAccessAttributes-Request ::= CHOICE {
     *   name [0] ObjectName CHOICE {
     *     domain-specific [1] IMPLICIT SEQUENCE {
     *       domainId VisibleString, itemId VisibleString
     * }}}
     */
    domain_len = strlen(request->params.getvariableattrs.variable_spec.domain);
    item_len = strlen(request->params.getvariableattrs.variable_spec.item_id);

    size_t ds_content = (2 + domain_len) + (2 + item_len);
    size_t o = 0;

    /* name [0] CONSTRUCTED */
    buf[o++] = 0xA0;
    buf[o++] = (uint8_t)(2 + ds_content);

    /* domain-specific [1] IMPLICIT SEQUENCE */
    buf[o++] = 0xA1;
    buf[o++] = (uint8_t)ds_content;

    /* domainId: VisibleString */
    buf[o++] = 0x1A;
    buf[o++] = (uint8_t)domain_len;
    memcpy(buf + o, request->params.getvariableattrs.variable_spec.domain, domain_len);
    o += domain_len;

    /* itemId: VisibleString */
    buf[o++] = 0x1A;
    buf[o++] = (uint8_t)item_len;
    memcpy(buf + o, request->params.getvariableattrs.variable_spec.item_id, item_len);
    o += item_len;

    return (int)o;
}

static int encode_define_named_varlist_req_body(const mms_confirmed_request_t *request,
                       uint8_t *buf, size_t buflen) {
    uint8_t temp_buf[16];
    int ret;
    (void)temp_buf; (void)ret; (void)buflen;
    size_t domain_len;
    size_t item_len;
    /* DefineNamedVariableList-Request */
    /* variableListName [0] ObjectName (domain-specific) */
    size_t varlist_offset = 0;
    buf[varlist_offset++] = 0xA0;  /* [0] IMPLICIT */
    domain_len = strlen(request->params.definenamedvarlist.domain);
    size_t list_name_len = strlen(request->params.definenamedvarlist.list_name);
    buf[varlist_offset++] = (uint8_t)(1 + domain_len + 1 + list_name_len);
    buf[varlist_offset++] = (uint8_t)domain_len;
    memcpy(buf + varlist_offset, request->params.definenamedvarlist.domain, domain_len);
    varlist_offset += domain_len;
    buf[varlist_offset++] = (uint8_t)list_name_len;
    memcpy(buf + varlist_offset, request->params.definenamedvarlist.list_name, list_name_len);
    varlist_offset += list_name_len;

    /* listOfVariable [1] SEQUENCE OF VariableSpecification */
    buf[varlist_offset++] = 0xA1;  /* [1] IMPLICIT */
    size_t var_list_start = varlist_offset + 1;  /* Reserve for length */
    varlist_offset++;
    for (uint32_t i = 0; i < request->params.definenamedvarlist.num_variables; i++) {
        buf[varlist_offset++] = 0xA0;  /* domain-specific [0] */
        domain_len = strlen(request->params.definenamedvarlist.variables[i].domain);
        item_len = strlen(request->params.definenamedvarlist.variables[i].item_id);
        buf[varlist_offset++] = (uint8_t)(1 + domain_len + 1 + item_len);
        buf[varlist_offset++] = (uint8_t)domain_len;
        memcpy(buf + varlist_offset, request->params.definenamedvarlist.variables[i].domain, domain_len);
        varlist_offset += domain_len;
        buf[varlist_offset++] = (uint8_t)item_len;
        memcpy(buf + varlist_offset, request->params.definenamedvarlist.variables[i].item_id, item_len);
        varlist_offset += item_len;
    }
    buf[var_list_start - 1] = (uint8_t)(varlist_offset - var_list_start);
    return (int)(varlist_offset);
}

static int encode_delete_named_varlist_req_body(const mms_confirmed_request_t *request,
                       uint8_t *buf, size_t buflen) {
    uint8_t temp_buf[16];
    int ret;
    (void)temp_buf; (void)ret; (void)buflen;
    size_t domain_len;
    size_t list_name_len;
    /* DeleteNamedVariableList-Request */
    /* variableListName [0] ObjectName (domain-specific) */
    buf[0] = 0xA0;  /* [0] IMPLICIT */
    domain_len = strlen(request->params.deletenamedvarlist.domain);
    list_name_len = strlen(request->params.deletenamedvarlist.list_name);
    buf[1] = (uint8_t)(1 + domain_len + 1 + list_name_len);
    buf[2] = (uint8_t)domain_len;
    memcpy(buf + 3, request->params.deletenamedvarlist.domain, domain_len);
    buf[3 + domain_len] = (uint8_t)list_name_len;
    memcpy(buf + 4 + domain_len, request->params.deletenamedvarlist.list_name, list_name_len);
    return (int)(2 + 1 + domain_len + 1 + list_name_len);
}

static int encode_get_named_varlist_attrs_req_body(const mms_confirmed_request_t *request,
                       uint8_t *buf, size_t buflen) {
    uint8_t temp_buf[16];
    int ret;
    (void)temp_buf; (void)ret; (void)buflen;
    size_t domain_len;
    size_t list_name_len;
    /* GetNamedVariableListAttributes-Request */
    /* variableListName [0] ObjectName (domain-specific) */
    buf[0] = 0xA0;  /* [0] IMPLICIT */
    domain_len = strlen(request->params.getnamedvarlistattrs.domain);
    list_name_len = strlen(request->params.getnamedvarlistattrs.list_name);
    buf[1] = (uint8_t)(1 + domain_len + 1 + list_name_len);
    buf[2] = (uint8_t)domain_len;
    memcpy(buf + 3, request->params.getnamedvarlistattrs.domain, domain_len);
    buf[3 + domain_len] = (uint8_t)list_name_len;
    memcpy(buf + 4 + domain_len, request->params.getnamedvarlistattrs.list_name, list_name_len);
    return (int)(2 + 1 + domain_len + 1 + list_name_len);
}

static int encode_read_named_varlist_req_body(const mms_confirmed_request_t *request,
                       uint8_t *buf, size_t buflen) {
    uint8_t temp_buf[16];
    int ret;
    (void)temp_buf; (void)ret; (void)buflen;
    size_t domain_len;
    size_t list_name_len;
    /* Read-Request: variableAccessSpecification [1] variableListName */
    buf[0] = 0xA1;  /* [1] IMPLICIT variableListName */
    domain_len = strlen(request->params.readnamedvarlist.domain);
    list_name_len = strlen(request->params.readnamedvarlist.list_name);
    buf[1] = (uint8_t)(1 + domain_len + 1 + list_name_len);
    buf[2] = (uint8_t)domain_len;
    memcpy(buf + 3, request->params.readnamedvarlist.domain, domain_len);
    buf[3 + domain_len] = (uint8_t)list_name_len;
    memcpy(buf + 4 + domain_len, request->params.readnamedvarlist.list_name, list_name_len);
    return (int)(2 + 1 + domain_len + 1 + list_name_len);
}

static int encode_write_named_varlist_req_body(const mms_confirmed_request_t *request,
                       uint8_t *buf, size_t buflen) {
    uint8_t temp_buf[16];
    int ret;
    (void)temp_buf; (void)ret; (void)buflen;
    size_t domain_len;
    size_t list_name_len;
    /* Write-Request: variableAccessSpecification [1], listOfData [0] */
    size_t write_varlist_offset = 0;
    /* variableAccessSpecification [1] IMPLICIT variableListName */
    buf[write_varlist_offset++] = 0xA1;  /* [1] IMPLICIT */
    domain_len = strlen(request->params.writenamedvarlist.domain);
    list_name_len = strlen(request->params.writenamedvarlist.list_name);
    buf[write_varlist_offset++] = (uint8_t)(1 + domain_len + 1 + list_name_len);
    buf[write_varlist_offset++] = (uint8_t)domain_len;
    memcpy(buf + write_varlist_offset, request->params.writenamedvarlist.domain, domain_len);
    write_varlist_offset += domain_len;
    buf[write_varlist_offset++] = (uint8_t)list_name_len;
    memcpy(buf + write_varlist_offset, request->params.writenamedvarlist.list_name, list_name_len);
    write_varlist_offset += list_name_len;

    /* listOfData [0] IMPLICIT SEQUENCE OF Data */
    buf[write_varlist_offset++] = 0xA0;  /* [0] IMPLICIT */
    size_t data_list_start = write_varlist_offset + 1;  /* Reserve for length */
    size_t data_list_len = 0;
    for (uint32_t i = 0; i < request->params.writenamedvarlist.num_values; i++) {
        ret = mms_encode_value(&request->params.writenamedvarlist.values[i],
                             buf + data_list_start + data_list_len,
                             buflen - data_list_start - data_list_len);
        if (ret < 0) return ret;
        data_list_len += ret;
    }
    buf[write_varlist_offset] = (uint8_t)data_list_len;
    write_varlist_offset = data_list_start + data_list_len;
    return (int)(write_varlist_offset);
}

static int encode_select_req_body(const mms_confirmed_request_t *request,
                       uint8_t *buf, size_t buflen) {
    uint8_t temp_buf[16];
    int ret;
    (void)temp_buf; (void)ret; (void)buflen;
    size_t domain_len;
    size_t item_len;
    /* Select-Request: controlObject [0], checkValue [1], selectTimeout [2] */
    size_t select_offset = 0;
    /* controlObject [0] IMPLICIT VariableAccessSpecification */
    buf[select_offset++] = 0xA0;  /* [0] IMPLICIT domain-specific */
    domain_len = strlen(request->params.select.control_object.domain);
    item_len = strlen(request->params.select.control_object.item_id);
    buf[select_offset++] = (uint8_t)(1 + domain_len + 1 + item_len);
    buf[select_offset++] = (uint8_t)domain_len;
    memcpy(buf + select_offset, request->params.select.control_object.domain, domain_len);
    select_offset += domain_len;
    buf[select_offset++] = (uint8_t)item_len;
    memcpy(buf + select_offset, request->params.select.control_object.item_id, item_len);
    select_offset += item_len;
    /* checkValue [1] IMPLICIT INTEGER */
    buf[select_offset++] = 0x81;  /* [1] IMPLICIT */
    buf[select_offset++] = 0x01;
    buf[select_offset++] = request->params.select.check_value;
    /* selectTimeout [2] IMPLICIT INTEGER (optional, 0 = default) */
    if (request->params.select.select_timeout_ms > 0) {
        buf[select_offset++] = 0x82;  /* [2] IMPLICIT */
        ret = encode_integer(request->params.select.select_timeout_ms, temp_buf, sizeof(temp_buf));
        if (ret < 0) return ret;
        buf[select_offset++] = (uint8_t)ret;
        memcpy(buf + select_offset, temp_buf, ret);
        select_offset += ret;
    }
    return (int)(select_offset);
}

static int encode_select_with_value_req_body(const mms_confirmed_request_t *request,
                       uint8_t *buf, size_t buflen) {
    uint8_t temp_buf[16];
    int ret;
    (void)temp_buf; (void)ret; (void)buflen;
    size_t domain_len;
    size_t item_len;
    /* SelectWithValue-Request: controlObject [0], controlValue [1], checkValue [2], selectTimeout [3] */
    size_t swv_offset = 0;
    /* controlObject [0] IMPLICIT VariableAccessSpecification */
    buf[swv_offset++] = 0xA0;
    domain_len = strlen(request->params.select_with_value.control_object.domain);
    item_len = strlen(request->params.select_with_value.control_object.item_id);
    buf[swv_offset++] = (uint8_t)(1 + domain_len + 1 + item_len);
    buf[swv_offset++] = (uint8_t)domain_len;
    memcpy(buf + swv_offset, request->params.select_with_value.control_object.domain, domain_len);
    swv_offset += domain_len;
    buf[swv_offset++] = (uint8_t)item_len;
    memcpy(buf + swv_offset, request->params.select_with_value.control_object.item_id, item_len);
    swv_offset += item_len;
    /* controlValue [1] IMPLICIT Data */
    buf[swv_offset++] = 0xA1;
    ret = mms_encode_value(&request->params.select_with_value.control_value, buf + swv_offset + 1, buflen - swv_offset - 1);
    if (ret < 0) return ret;
    buf[swv_offset] = (uint8_t)ret;  // Don't increment yet
    swv_offset++;  // Now increment
    // Value already encoded at correct position (swv_offset), no memcpy needed
    swv_offset += ret;
    /* checkValue [2] IMPLICIT INTEGER */
    buf[swv_offset++] = 0x82;
    buf[swv_offset++] = 0x01;
    buf[swv_offset++] = request->params.select_with_value.check_value;
    /* selectTimeout [3] IMPLICIT INTEGER (optional) */
    if (request->params.select_with_value.select_timeout_ms > 0) {
        buf[swv_offset++] = 0x83;
        ret = encode_integer(request->params.select_with_value.select_timeout_ms, temp_buf, sizeof(temp_buf));
        if (ret < 0) return ret;
        buf[swv_offset++] = (uint8_t)ret;
        memcpy(buf + swv_offset, temp_buf, ret);
        swv_offset += ret;
    }
    return (int)(swv_offset);
}

static int encode_operate_req_body(const mms_confirmed_request_t *request,
                       uint8_t *buf, size_t buflen) {
    uint8_t temp_buf[16];
    int ret;
    (void)temp_buf; (void)ret; (void)buflen;
    size_t domain_len;
    size_t item_len;
    /* Operate-Request: controlObject [0], selectionID [1], controlValue [2], operationTime [3] */
    size_t op_offset = 0;
    /* controlObject [0] IMPLICIT VariableAccessSpecification */
    buf[op_offset++] = 0xA0;
    domain_len = strlen(request->params.operate.control_object.domain);
    item_len = strlen(request->params.operate.control_object.item_id);
    buf[op_offset++] = (uint8_t)(1 + domain_len + 1 + item_len);
    buf[op_offset++] = (uint8_t)domain_len;
    memcpy(buf + op_offset, request->params.operate.control_object.domain, domain_len);
    op_offset += domain_len;
    buf[op_offset++] = (uint8_t)item_len;
    memcpy(buf + op_offset, request->params.operate.control_object.item_id, item_len);
    op_offset += item_len;
    /* selectionID [1] IMPLICIT INTEGER */
    buf[op_offset++] = 0x81;
    ret = encode_integer(request->params.operate.selection_id, temp_buf, sizeof(temp_buf));
    if (ret < 0) return ret;
    buf[op_offset++] = (uint8_t)ret;
    memcpy(buf + op_offset, temp_buf, ret);
    op_offset += ret;
    /* controlValue [2] IMPLICIT Data (optional) */
    if (request->params.operate.has_control_value) {
        buf[op_offset++] = 0xA2;
        ret = mms_encode_value(&request->params.operate.control_value, buf + op_offset + 1, buflen - op_offset - 1);
        if (ret < 0) return ret;
        buf[op_offset] = (uint8_t)ret;  // Don't increment yet
        op_offset++;  // Now increment
        // Value already encoded at correct position (op_offset), no memcpy needed
        op_offset += ret;
    }
    /* operationTime [3] IMPLICIT TimeOfDay (optional, 0 = immediate) */
    if (request->params.operate.operation_time > 0) {
        buf[op_offset++] = 0x83;
        buf[op_offset++] = 0x08;  /* Length = 8 */
        for (int i = 7; i >= 0; i--) {
            buf[op_offset++] = (uint8_t)((request->params.operate.operation_time >> (i * 8)) & 0xFF);
        }
    }
    return (int)(op_offset);
}

static int encode_cancel_req_body(const mms_confirmed_request_t *request,
                       uint8_t *buf, size_t buflen) {
    uint8_t temp_buf[16];
    int ret;
    (void)temp_buf; (void)ret; (void)buflen;
    size_t domain_len;
    size_t item_len;
    /* Cancel-Request: controlObject [0], selectionID [1] */
    size_t cancel_offset = 0;
    /* controlObject [0] IMPLICIT VariableAccessSpecification */
    buf[cancel_offset++] = 0xA0;
    domain_len = strlen(request->params.cancel.control_object.domain);
    item_len = strlen(request->params.cancel.control_object.item_id);
    buf[cancel_offset++] = (uint8_t)(1 + domain_len + 1 + item_len);
    buf[cancel_offset++] = (uint8_t)domain_len;
    memcpy(buf + cancel_offset, request->params.cancel.control_object.domain, domain_len);
    cancel_offset += domain_len;
    buf[cancel_offset++] = (uint8_t)item_len;
    memcpy(buf + cancel_offset, request->params.cancel.control_object.item_id, item_len);
    cancel_offset += item_len;
    /* selectionID [1] IMPLICIT INTEGER */
    buf[cancel_offset++] = 0x81;
    ret = encode_integer(request->params.cancel.selection_id, temp_buf, sizeof(temp_buf));
    if (ret < 0) return ret;
    buf[cancel_offset++] = (uint8_t)ret;
    memcpy(buf + cancel_offset, temp_buf, ret);
    cancel_offset += ret;
    return (int)(cancel_offset);
}

static int encode_file_open_req_body(const mms_confirmed_request_t *request,
                       uint8_t *buf, size_t buflen) {
    uint8_t temp_buf[16];
    int ret;
    (void)temp_buf; (void)ret; (void)buflen;
    /* FileOpen-Request: filename [0], accessMode [1] */
    size_t fileopen_offset = 0;
    /* filename [0] IMPLICIT VisibleString */
    buf[fileopen_offset++] = 0xA0;  /* [0] IMPLICIT */
    size_t filename_len = strlen(request->params.fileopen.filename);
    buf[fileopen_offset++] = (uint8_t)filename_len;
    memcpy(buf + fileopen_offset, request->params.fileopen.filename, filename_len);
    fileopen_offset += filename_len;
    /* accessMode [1] IMPLICIT INTEGER */
    buf[fileopen_offset++] = 0x81;  /* [1] IMPLICIT */
    buf[fileopen_offset++] = 0x01;
    buf[fileopen_offset++] = (uint8_t)request->params.fileopen.access_mode;
    return (int)(fileopen_offset);
}

static int encode_file_read_req_body(const mms_confirmed_request_t *request,
                       uint8_t *buf, size_t buflen) {
    uint8_t temp_buf[16];
    int ret;
    (void)temp_buf; (void)ret; (void)buflen;
    /* FileRead-Request: fileHandle [0], maxBytes [1] */
    size_t fileread_offset = 0;
    /* fileHandle [0] IMPLICIT INTEGER */
    buf[fileread_offset++] = 0x80;  /* [0] IMPLICIT */
    ret = encode_integer(request->params.fileread.file_handle, temp_buf, sizeof(temp_buf));
    if (ret < 0) return ret;
    buf[fileread_offset++] = (uint8_t)ret;
    memcpy(buf + fileread_offset, temp_buf, ret);
    fileread_offset += ret;
    /* maxBytes [1] IMPLICIT INTEGER */
    buf[fileread_offset++] = 0x81;  /* [1] IMPLICIT */
    ret = encode_integer(request->params.fileread.max_bytes, temp_buf, sizeof(temp_buf));
    if (ret < 0) return ret;
    buf[fileread_offset++] = (uint8_t)ret;
    memcpy(buf + fileread_offset, temp_buf, ret);
    fileread_offset += ret;
    return (int)(fileread_offset);
}

static int encode_file_close_req_body(const mms_confirmed_request_t *request,
                       uint8_t *buf, size_t buflen) {
    uint8_t temp_buf[16];
    int ret;
    (void)temp_buf; (void)ret; (void)buflen;
    /* FileClose-Request: fileHandle [0] */
    size_t fileclose_offset = 0;
    /* fileHandle [0] IMPLICIT INTEGER */
    buf[fileclose_offset++] = 0x80;  /* [0] IMPLICIT */
    ret = encode_integer(request->params.fileclose.file_handle, temp_buf, sizeof(temp_buf));
    if (ret < 0) return ret;
    buf[fileclose_offset++] = (uint8_t)ret;
    memcpy(buf + fileclose_offset, temp_buf, ret);
    fileclose_offset += ret;
    return (int)(fileclose_offset);
}

static int encode_file_delete_req_body(const mms_confirmed_request_t *request,
                       uint8_t *buf, size_t buflen) {
    uint8_t temp_buf[16];
    int ret;
    (void)temp_buf; (void)ret; (void)buflen;
    size_t filename_len;
    /* FileDelete-Request: filename [0] */
    size_t filedelete_offset = 0;
    /* filename [0] IMPLICIT VisibleString */
    buf[filedelete_offset++] = 0xA0;  /* [0] IMPLICIT */
    filename_len = strlen(request->params.filedelete.filename);
    buf[filedelete_offset++] = (uint8_t)filename_len;
    memcpy(buf + filedelete_offset, request->params.filedelete.filename, filename_len);
    filedelete_offset += filename_len;
    return (int)(filedelete_offset);
}

static int encode_file_directory_req_body(const mms_confirmed_request_t *request,
                       uint8_t *buf, size_t buflen) {
    uint8_t temp_buf[16];
    int ret;
    (void)temp_buf; (void)ret; (void)buflen;
    /* FileDirectory-Request: directory [0], fileSpecification [1] */
    size_t filedir_offset = 0;
    /* directory [0] IMPLICIT VisibleString (optional, empty = root) */
    if (strlen(request->params.filedirectory.directory) > 0) {
        buf[filedir_offset++] = 0xA0;  /* [0] IMPLICIT */
        size_t dir_len = strlen(request->params.filedirectory.directory);
        buf[filedir_offset++] = (uint8_t)dir_len;
        memcpy(buf + filedir_offset, request->params.filedirectory.directory, dir_len);
        filedir_offset += dir_len;
    }
    /* fileSpecification [1] IMPLICIT VisibleString (optional, empty = all) */
    if (strlen(request->params.filedirectory.file_specification) > 0) {
        buf[filedir_offset++] = 0xA1;  /* [1] IMPLICIT */
        size_t spec_len = strlen(request->params.filedirectory.file_specification);
        buf[filedir_offset++] = (uint8_t)spec_len;
        memcpy(buf + filedir_offset, request->params.filedirectory.file_specification, spec_len);
        filedir_offset += spec_len;
    }
    return (int)(filedir_offset);
}

static int encode_read_journal_req_body(const mms_confirmed_request_t *request,
                       uint8_t *buf, size_t buflen) {
    uint8_t temp_buf[16];
    int ret;
    (void)temp_buf; (void)ret; (void)buflen;
    /* ReadJournal-Request: journalName [0], startTime [1], endTime [2], startEntryID [3], maxEntries [4] */
    size_t readjournal_offset = 0;
    /* journalName [0] IMPLICIT VisibleString */
    buf[readjournal_offset++] = 0xA0;  /* [0] IMPLICIT */
    size_t journal_name_len = strlen(request->params.readjournal.journal_name);
    buf[readjournal_offset++] = (uint8_t)journal_name_len;
    memcpy(buf + readjournal_offset, request->params.readjournal.journal_name, journal_name_len);
    readjournal_offset += journal_name_len;
    /* startTime [1] IMPLICIT INTEGER (64-bit, optional if 0) */
    if (request->params.readjournal.start_time > 0) {
        buf[readjournal_offset++] = 0x81;  /* [1] IMPLICIT */
        buf[readjournal_offset++] = 0x08;  /* Length = 8 */
        for (int i = 7; i >= 0; i--) {
            buf[readjournal_offset++] = (uint8_t)((request->params.readjournal.start_time >> (i * 8)) & 0xFF);
        }
    }
    /* endTime [2] IMPLICIT INTEGER (64-bit, optional if 0) */
    if (request->params.readjournal.end_time > 0) {
        buf[readjournal_offset++] = 0x82;  /* [2] IMPLICIT */
        buf[readjournal_offset++] = 0x08;  /* Length = 8 */
        for (int i = 7; i >= 0; i--) {
            buf[readjournal_offset++] = (uint8_t)((request->params.readjournal.end_time >> (i * 8)) & 0xFF);
        }
    }
    /* startEntryID [3] IMPLICIT INTEGER (64-bit, optional if 0) */
    if (request->params.readjournal.start_entry_id > 0) {
        buf[readjournal_offset++] = 0x83;  /* [3] IMPLICIT */
        buf[readjournal_offset++] = 0x08;  /* Length = 8 */
        for (int i = 7; i >= 0; i--) {
            buf[readjournal_offset++] = (uint8_t)((request->params.readjournal.start_entry_id >> (i * 8)) & 0xFF);
        }
    }
    /* maxEntries [4] IMPLICIT INTEGER */
    buf[readjournal_offset++] = 0x84;  /* [4] IMPLICIT */
    ret = encode_integer(request->params.readjournal.max_entries, temp_buf, sizeof(temp_buf));
    if (ret < 0) return ret;
    buf[readjournal_offset++] = (uint8_t)ret;
    memcpy(buf + readjournal_offset, temp_buf, ret);
    readjournal_offset += ret;
    return (int)(readjournal_offset);
}

static int encode_initialize_journal_req_body(const mms_confirmed_request_t *request,
                       uint8_t *buf, size_t buflen) {
    uint8_t temp_buf[16];
    int ret;
    (void)temp_buf; (void)ret; (void)buflen;
    size_t journal_name_len;
    /* InitializeJournal-Request: journalName [0] */
    size_t initjournal_offset = 0;
    /* journalName [0] IMPLICIT VisibleString */
    buf[initjournal_offset++] = 0xA0;  /* [0] IMPLICIT */
    journal_name_len = strlen(request->params.initializejournal.journal_name);
    buf[initjournal_offset++] = (uint8_t)journal_name_len;
    memcpy(buf + initjournal_offset, request->params.initializejournal.journal_name, journal_name_len);
    initjournal_offset += journal_name_len;
    return (int)(initjournal_offset);
}

static int encode_define_named_type_req_body(const mms_confirmed_request_t *request,
                       uint8_t *buf, size_t buflen) {
    uint8_t temp_buf[16];
    int ret;
    (void)temp_buf; (void)ret; (void)buflen;
    /* DefineNamedType-Request: domain [0] (optional), typeName [1], typeSpec [2] */
    size_t definetype_offset = 0;
    /* domain [0] IMPLICIT VisibleString (optional) */
    if (strlen(request->params.definenamedtype.domain) > 0) {
        buf[definetype_offset++] = 0xA0;  /* [0] IMPLICIT */
        size_t domain_len = strlen(request->params.definenamedtype.domain);
        buf[definetype_offset++] = (uint8_t)domain_len;
        memcpy(buf + definetype_offset, request->params.definenamedtype.domain, domain_len);
        definetype_offset += domain_len;
    }
    /* typeName [1] IMPLICIT VisibleString */
    buf[definetype_offset++] = 0xA1;  /* [1] IMPLICIT */
    size_t typename_len = strlen(request->params.definenamedtype.type_name);
    buf[definetype_offset++] = (uint8_t)typename_len;
    memcpy(buf + definetype_offset, request->params.definenamedtype.type_name, typename_len);
    definetype_offset += typename_len;
    /* typeSpec [2] IMPLICIT INTEGER (simplified - just the enum value) */
    buf[definetype_offset++] = 0x82;  /* [2] IMPLICIT */
    buf[definetype_offset++] = 0x01;
    buf[definetype_offset++] = (uint8_t)request->params.definenamedtype.type_spec;
    return (int)(definetype_offset);
}

static int encode_delete_named_type_req_body(const mms_confirmed_request_t *request,
                       uint8_t *buf, size_t buflen) {
    uint8_t temp_buf[16];
    int ret;
    (void)temp_buf; (void)ret; (void)buflen;
    size_t typename_len;
    /* DeleteNamedType-Request: domain [0] (optional), typeName [1] */
    size_t deletetype_offset = 0;
    /* domain [0] IMPLICIT VisibleString (optional) */
    if (strlen(request->params.deletenamedtype.domain) > 0) {
        buf[deletetype_offset++] = 0xA0;  /* [0] IMPLICIT */
        size_t domain_len = strlen(request->params.deletenamedtype.domain);
        buf[deletetype_offset++] = (uint8_t)domain_len;
        memcpy(buf + deletetype_offset, request->params.deletenamedtype.domain, domain_len);
        deletetype_offset += domain_len;
    }
    /* typeName [1] IMPLICIT VisibleString */
    buf[deletetype_offset++] = 0xA1;  /* [1] IMPLICIT */
    typename_len = strlen(request->params.deletenamedtype.type_name);
    buf[deletetype_offset++] = (uint8_t)typename_len;
    memcpy(buf + deletetype_offset, request->params.deletenamedtype.type_name, typename_len);
    deletetype_offset += typename_len;
    return (int)(deletetype_offset);
}

static int encode_get_named_type_attrs_req_body(const mms_confirmed_request_t *request,
                       uint8_t *buf, size_t buflen) {
    uint8_t temp_buf[16];
    int ret;
    (void)temp_buf; (void)ret; (void)buflen;
    size_t typename_len;
    /* GetNamedTypeAttributes-Request: domain [0] (optional), typeName [1] */
    size_t gettypeattrs_offset = 0;
    /* domain [0] IMPLICIT VisibleString (optional) */
    if (strlen(request->params.getnamedtypeattrs.domain) > 0) {
        buf[gettypeattrs_offset++] = 0xA0;  /* [0] IMPLICIT */
        size_t domain_len = strlen(request->params.getnamedtypeattrs.domain);
        buf[gettypeattrs_offset++] = (uint8_t)domain_len;
        memcpy(buf + gettypeattrs_offset, request->params.getnamedtypeattrs.domain, domain_len);
        gettypeattrs_offset += domain_len;
    }
    /* typeName [1] IMPLICIT VisibleString */
    buf[gettypeattrs_offset++] = 0xA1;  /* [1] IMPLICIT */
    typename_len = strlen(request->params.getnamedtypeattrs.type_name);
    buf[gettypeattrs_offset++] = (uint8_t)typename_len;
    memcpy(buf + gettypeattrs_offset, request->params.getnamedtypeattrs.type_name, typename_len);
    gettypeattrs_offset += typename_len;
    return (int)(gettypeattrs_offset);
}
int mms_encode_confirmed_request(const mms_confirmed_request_t* request,
                                 uint8_t* buffer, size_t buflen) {
    if (request == NULL || buffer == NULL) {
        return MMS_ERROR_INVALID_PARAM;
    }

    size_t offset = 0;

    /* Confirmed-RequestPDU [0] IMPLICIT SEQUENCE */
    if (!has_space(offset, 1, buflen)) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }
    buffer[offset++] = MMS_TAG_CONFIRMED_REQUEST;

    /* Build content in temporary buffer */
    uint8_t content[MMS_MAX_PDU_SIZE];
    size_t content_offset = 0;

    /* invokeID — encoded as UNIVERSAL INTEGER (0x02) for interop with libiec61850 */
    content[content_offset++] = 0x02;  /* INTEGER */
    uint8_t temp_buf[16];
    int ret = encode_integer(request->invoke_id, temp_buf, sizeof(temp_buf));
    if (ret < 0) {
        return ret;
    }
    content[content_offset++] = (uint8_t)ret;
    memcpy(content + content_offset, temp_buf, ret);
    content_offset += ret;

    /* Service-specific request (CHOICE) */
    uint8_t service_tag;
    uint8_t service_buf[MMS_MAX_PDU_SIZE];
    int service_len;

    switch (request->service) {
        case MMS_SERVICE_TYPE_IDENTIFY:
            service_tag = MMS_SERVICE_IDENTIFY;
            service_len = 0;  /* Identify-Request is NULL (empty) */
            break;
        case MMS_SERVICE_TYPE_READ:
            service_tag = MMS_SERVICE_READ;
            service_len = encode_read_req_body(request, service_buf, sizeof(service_buf));
            if (service_len < 0) return service_len;
            break;
        case MMS_SERVICE_TYPE_WRITE:
            service_tag = MMS_SERVICE_WRITE;
            service_len = encode_write_req_body(request, service_buf, sizeof(service_buf));
            if (service_len < 0) return service_len;
            break;
        case MMS_SERVICE_TYPE_GET_NAMELIST:
            service_tag = MMS_SERVICE_GET_NAMELIST;
            service_len = encode_get_namelist_req_body(request, service_buf, sizeof(service_buf));
            if (service_len < 0) return service_len;
            break;
        case MMS_SERVICE_TYPE_GET_VARIABLE_ATTRS:
            service_tag = MMS_SERVICE_GET_VARIABLE_ATTRS;
            service_len = encode_get_variable_attrs_req_body(request, service_buf, sizeof(service_buf));
            if (service_len < 0) return service_len;
            break;
        case MMS_SERVICE_TYPE_DEFINE_NAMED_VARLIST:
            service_tag = MMS_SERVICE_DEFINE_NAMED_VARLIST;
            service_len = encode_define_named_varlist_req_body(request, service_buf, sizeof(service_buf));
            if (service_len < 0) return service_len;
            break;
        case MMS_SERVICE_TYPE_DELETE_NAMED_VARLIST:
            service_tag = MMS_SERVICE_DELETE_NAMED_VARLIST;
            service_len = encode_delete_named_varlist_req_body(request, service_buf, sizeof(service_buf));
            if (service_len < 0) return service_len;
            break;
        case MMS_SERVICE_TYPE_GET_NAMED_VARLIST_ATTRS:
            service_tag = MMS_SERVICE_GET_NAMED_VARLIST_ATTRS;
            service_len = encode_get_named_varlist_attrs_req_body(request, service_buf, sizeof(service_buf));
            if (service_len < 0) return service_len;
            break;
        case MMS_SERVICE_TYPE_READ_NAMED_VARLIST:
            service_tag = MMS_SERVICE_READ;
            service_len = encode_read_named_varlist_req_body(request, service_buf, sizeof(service_buf));
            if (service_len < 0) return service_len;
            break;
        case MMS_SERVICE_TYPE_WRITE_NAMED_VARLIST:
            service_tag = MMS_SERVICE_WRITE;
            service_len = encode_write_named_varlist_req_body(request, service_buf, sizeof(service_buf));
            if (service_len < 0) return service_len;
            break;
        case MMS_SERVICE_TYPE_SELECT:
            service_tag = MMS_SERVICE_SELECT;
            service_len = encode_select_req_body(request, service_buf, sizeof(service_buf));
            if (service_len < 0) return service_len;
            break;
        case MMS_SERVICE_TYPE_SELECT_WITH_VALUE:
            service_tag = MMS_SERVICE_SELECT_WITH_VALUE;
            service_len = encode_select_with_value_req_body(request, service_buf, sizeof(service_buf));
            if (service_len < 0) return service_len;
            break;
        case MMS_SERVICE_TYPE_OPERATE:
            service_tag = MMS_SERVICE_OPERATE;
            service_len = encode_operate_req_body(request, service_buf, sizeof(service_buf));
            if (service_len < 0) return service_len;
            break;
        case MMS_SERVICE_TYPE_CANCEL:
            service_tag = MMS_SERVICE_CANCEL;
            service_len = encode_cancel_req_body(request, service_buf, sizeof(service_buf));
            if (service_len < 0) return service_len;
            break;
        case MMS_SERVICE_TYPE_FILE_OPEN:
            service_tag = MMS_SERVICE_FILE_OPEN;
            service_len = encode_file_open_req_body(request, service_buf, sizeof(service_buf));
            if (service_len < 0) return service_len;
            break;
        case MMS_SERVICE_TYPE_FILE_READ:
            service_tag = MMS_SERVICE_FILE_READ;
            service_len = encode_file_read_req_body(request, service_buf, sizeof(service_buf));
            if (service_len < 0) return service_len;
            break;
        case MMS_SERVICE_TYPE_FILE_CLOSE:
            service_tag = MMS_SERVICE_FILE_CLOSE;
            service_len = encode_file_close_req_body(request, service_buf, sizeof(service_buf));
            if (service_len < 0) return service_len;
            break;
        case MMS_SERVICE_TYPE_FILE_DELETE:
            service_tag = MMS_SERVICE_FILE_DELETE;
            service_len = encode_file_delete_req_body(request, service_buf, sizeof(service_buf));
            if (service_len < 0) return service_len;
            break;
        case MMS_SERVICE_TYPE_FILE_DIRECTORY:
            service_tag = MMS_SERVICE_FILE_DIRECTORY;
            service_len = encode_file_directory_req_body(request, service_buf, sizeof(service_buf));
            if (service_len < 0) return service_len;
            break;
        case MMS_SERVICE_TYPE_READ_JOURNAL:
            service_tag = MMS_SERVICE_READ_JOURNAL;
            service_len = encode_read_journal_req_body(request, service_buf, sizeof(service_buf));
            if (service_len < 0) return service_len;
            break;
        case MMS_SERVICE_TYPE_INITIALIZE_JOURNAL:
            service_tag = MMS_SERVICE_INITIALIZE_JOURNAL;
            service_len = encode_initialize_journal_req_body(request, service_buf, sizeof(service_buf));
            if (service_len < 0) return service_len;
            break;
        case MMS_SERVICE_TYPE_DEFINE_NAMED_TYPE:
            service_tag = MMS_SERVICE_DEFINE_NAMED_TYPE;
            service_len = encode_define_named_type_req_body(request, service_buf, sizeof(service_buf));
            if (service_len < 0) return service_len;
            break;
        case MMS_SERVICE_TYPE_DELETE_NAMED_TYPE:
            service_tag = MMS_SERVICE_DELETE_NAMED_TYPE;
            service_len = encode_delete_named_type_req_body(request, service_buf, sizeof(service_buf));
            if (service_len < 0) return service_len;
            break;
        case MMS_SERVICE_TYPE_GET_NAMED_TYPE_ATTRS:
            service_tag = MMS_SERVICE_GET_NAMED_TYPE_ATTRS;
            service_len = encode_get_named_type_attrs_req_body(request, service_buf, sizeof(service_buf));
            if (service_len < 0) return service_len;
            break;

        default:
            return MMS_ERROR_NOT_SUPPORTED;
    }

    /* Add service tag and content to main content buffer */
    content[content_offset++] = service_tag;
    ret = mms_encode_length(service_len, content + content_offset, sizeof(content) - content_offset);
    if (ret < 0) {
        return ret;
    }
    content_offset += ret;
    memcpy(content + content_offset, service_buf, service_len);
    content_offset += service_len;

    /* Encode length of entire Confirmed-Request */
    ret = mms_encode_length(content_offset, buffer + offset, buflen - offset);
    if (ret < 0) {
        return ret;
    }
    offset += ret;

    /* Copy content */
    if (!has_space(offset, content_offset, buflen)) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(buffer + offset, content, content_offset);
    offset += content_offset;

    return (int)offset;
}

int mms_decode_confirmed_request(const uint8_t* buffer, size_t buflen,
                                 mms_confirmed_request_t* request) {
    if (buffer == NULL || request == NULL || buflen < 2) {
        return MMS_ERROR_INVALID_PARAM;
    }

    size_t offset = 0;

    /* Check tag */
    if (buffer[offset++] != MMS_TAG_CONFIRMED_REQUEST) {
        return MMS_ERROR_INVALID_ENCODING;
    }

    /* Decode length */
    size_t length;
    int ret = mms_decode_length(buffer + offset, buflen - offset, &length);
    if (ret < 0) {
        return ret;
    }
    offset += ret;

    size_t end = offset + length;

    /* invokeID — accept both [0] IMPLICIT (0x80) and UNIVERSAL INTEGER (0x02) */
    if (offset >= end) {
        return MMS_ERROR_INVALID_ENCODING;
    }
    if (buffer[offset] != 0x80 && buffer[offset] != 0x02) {
        return MMS_ERROR_INVALID_ENCODING;
    }
    offset++;

    size_t field_len;
    ret = mms_decode_length(buffer + offset, buflen - offset, &field_len);
    if (ret < 0) {
        return ret;
    }
    offset += ret;

    ret = decode_integer(buffer + offset, field_len, (int32_t*)&request->invoke_id);
    if (ret < 0) {
        return ret;
    }
    offset += field_len;

    /* Service CHOICE */
    if (offset >= end) {
        return MMS_ERROR_INVALID_ENCODING;
    }

    uint8_t raw_service_tag = buffer[offset++];
    /* Normalize: set the constructed bit so both 0x8x and 0xAx match.
     * Our defines use 0xA0|n for SEQUENCE services.
     * Exceptions: 0x80 (STATUS), 0x82 (IDENTIFY), 0x90 (FILE_CLOSE). */
    uint8_t tag_num = raw_service_tag & 0x1F;
    uint8_t service_tag = raw_service_tag;
    if (tag_num != 0 && tag_num != 2 && raw_service_tag != 0x90) {
        service_tag = raw_service_tag | 0x20;
    }
    ret = mms_decode_length(buffer + offset, buflen - offset, &field_len);
    if (ret < 0) {
        return ret;
    }
    offset += ret;

    switch (service_tag) {
        case MMS_SERVICE_READ:
            /* Read-Request: [0] specificationWithResult (optional, skipped),
             * then variableAccessSpecification wrapped in [1].
             * Inside [1]: listOfVariable [0] or variableListName [1]. */
            {
                size_t read_end = offset + field_len;

                /* Skip specificationWithResult [0] if present */
                if (buffer[offset] == 0x80) {
                    offset++;
                    size_t swrlen;
                    ret = mms_decode_length(buffer + offset, read_end - offset, &swrlen);
                    if (ret < 0) return ret;
                    offset += ret + swrlen;
                }

                /* variableAccessSpecification [1] CONSTRUCTED */
                if (offset < read_end && buffer[offset] == 0xA1) {
                    offset++;
                    size_t vas_len;
                    ret = mms_decode_length(buffer + offset, read_end - offset, &vas_len);
                    if (ret < 0) return ret;
                    offset += ret;
                    size_t vas_end = offset + vas_len;

                    if (offset < vas_end && buffer[offset] == 0xA0) {
                        /* listOfVariable [0] — Read */
                        request->service = MMS_SERVICE_TYPE_READ;

                        /* Scan for VisibleString (0x1A) tags */
                        size_t scan = offset;
                        while (scan + 2 < vas_end) {
                            uint8_t t = buffer[scan];
                            if (t == 0x1A) break;
                            scan++;
                            size_t skip;
                            ret = mms_decode_length(buffer + scan, vas_end - scan, &skip);
                            if (ret < 0) break;
                            scan += (size_t)ret;
                            if (t & 0x20) continue;
                            scan += skip;
                        }

                        if (scan + 2 < vas_end && buffer[scan] == 0x1A) {
                            scan++;
                            size_t domain_len = buffer[scan++];
                            if (domain_len < MMS_MAX_DOMAIN_NAME) {
                                memcpy(request->params.read.variable_spec.domain,
                                       buffer + scan, domain_len);
                                request->params.read.variable_spec.domain[domain_len] = '\0';
                            }
                            scan += domain_len;

                            if (scan + 2 <= vas_end && buffer[scan] == 0x1A) {
                                scan++;
                                size_t item_len = buffer[scan++];
                                if (item_len < MMS_MAX_VARIABLE_NAME) {
                                    memcpy(request->params.read.variable_spec.item_id,
                                           buffer + scan, item_len);
                                    request->params.read.variable_spec.item_id[item_len] = '\0';
                                }
                            }
                        }
                    } else {
                        /* variableListName — ReadNamedVariableList.
                         * Content is bare domain_len + domain + list_name_len + list_name */
                        request->service = MMS_SERVICE_TYPE_READ_NAMED_VARLIST;
                        if (offset < vas_end) {
                            size_t rnvl_dom_len = buffer[offset++];
                            if (rnvl_dom_len < MMS_MAX_DOMAIN_NAME) {
                                memcpy(request->params.readnamedvarlist.domain,
                                       buffer + offset, rnvl_dom_len);
                                request->params.readnamedvarlist.domain[rnvl_dom_len] = '\0';
                            }
                            offset += rnvl_dom_len;

                            size_t rnvl_name_len = buffer[offset++];
                            if (rnvl_name_len < MMS_MAX_VARIABLE_NAME) {
                                memcpy(request->params.readnamedvarlist.list_name,
                                       buffer + offset, rnvl_name_len);
                                request->params.readnamedvarlist.list_name[rnvl_name_len] = '\0';
                            }
                        }
                    }
                    offset = read_end;
                } else {
                    /* No [1] wrapper — legacy flat format */
                    request->service = MMS_SERVICE_TYPE_READ;
                    offset = read_end;
                }
            }
            break;

        case MMS_SERVICE_WRITE:
            if (buffer[offset] == 0xA1) {
                /* WriteNamedVariableList: variableListName [1] + listOfData [0] */
                request->service = MMS_SERVICE_TYPE_WRITE_NAMED_VARLIST;
                offset++;
                size_t wnvl_spec_len;
                ret = mms_decode_length(buffer + offset, buflen - offset, &wnvl_spec_len);
                if (ret < 0) return ret;
                offset += ret;

                /* domain name */
                size_t wnvl_dom_len = buffer[offset++];
                if (wnvl_dom_len >= MMS_MAX_DOMAIN_NAME) {
                    return MMS_ERROR_BUFFER_TOO_SMALL;
                }
                memcpy(request->params.writenamedvarlist.domain, buffer + offset, wnvl_dom_len);
                request->params.writenamedvarlist.domain[wnvl_dom_len] = '\0';
                offset += wnvl_dom_len;

                /* list name */
                size_t wnvl_name_len = buffer[offset++];
                if (wnvl_name_len >= MMS_MAX_VARIABLE_NAME) {
                    return MMS_ERROR_BUFFER_TOO_SMALL;
                }
                memcpy(request->params.writenamedvarlist.list_name, buffer + offset, wnvl_name_len);
                request->params.writenamedvarlist.list_name[wnvl_name_len] = '\0';
                offset += wnvl_name_len;

                /* listOfData [0] IMPLICIT SEQUENCE OF Data */
                if (offset < end && buffer[offset] == 0xA0) {
                    offset++;
                    size_t wnvl_data_len;
                    ret = mms_decode_length(buffer + offset, buflen - offset, &wnvl_data_len);
                    if (ret < 0) return ret;
                    offset += ret;

                    size_t wnvl_data_end = offset + wnvl_data_len;
                    request->params.writenamedvarlist.num_values = 0;
                    while (offset < wnvl_data_end && request->params.writenamedvarlist.num_values < MMS_MAX_NAMED_VARIABLES) {
                        uint32_t vi = request->params.writenamedvarlist.num_values;
                        ret = mms_decode_value(buffer + offset, wnvl_data_end - offset,
                                             &request->params.writenamedvarlist.values[vi]);
                        if (ret < 0) return ret;
                        offset += ret;
                        request->params.writenamedvarlist.num_values++;
                    }
                }
            } else {
                /* Write-Request: variableAccessSpecification [0] + listOfData [0] */
                request->service = MMS_SERVICE_TYPE_WRITE;
                if (buffer[offset] == 0xA0) {
                    /* First [0]: variableAccessSpecification listOfVariable */
                    offset++;
                    size_t vas_len;
                    ret = mms_decode_length(buffer + offset, buflen - offset, &vas_len);
                    if (ret < 0) return ret;
                    offset += ret;
                    size_t vas_end = offset + vas_len;

                    /* Scan for VisibleString (0x1A) tags */
                    size_t scan = offset;
                    while (scan + 2 < vas_end) {
                        uint8_t t = buffer[scan];
                        if (t == 0x1A) break;
                        scan++;
                        size_t skip;
                        ret = mms_decode_length(buffer + scan, vas_end - scan, &skip);
                        if (ret < 0) break;
                        scan += (size_t)ret;
                        if (t & 0x20) continue;
                        scan += skip;
                    }

                    if (scan + 2 < vas_end && buffer[scan] == 0x1A) {
                        scan++;
                        size_t wr_domain_len = buffer[scan++];
                        if (wr_domain_len < MMS_MAX_DOMAIN_NAME) {
                            memcpy(request->params.write.variable_spec.domain,
                                   buffer + scan, wr_domain_len);
                            request->params.write.variable_spec.domain[wr_domain_len] = '\0';
                        }
                        scan += wr_domain_len;

                        if (scan + 2 <= vas_end && buffer[scan] == 0x1A) {
                            scan++;
                            size_t wr_item_len = buffer[scan++];
                            if (wr_item_len < MMS_MAX_VARIABLE_NAME) {
                                memcpy(request->params.write.variable_spec.item_id,
                                       buffer + scan, wr_item_len);
                                request->params.write.variable_spec.item_id[wr_item_len] = '\0';
                            }
                        }
                    }
                    offset = vas_end;
                }
                /* listOfData [0] IMPLICIT SEQUENCE OF Data */
                if (offset < end && buffer[offset] == 0xA0) {
                    offset++;
                    size_t data_len;
                    ret = mms_decode_length(buffer + offset, buflen - offset, &data_len);
                    if (ret < 0) return ret;
                    offset += ret;

                    ret = mms_decode_value(buffer + offset, data_len, &request->params.write.value);
                    if (ret < 0) return ret;
                    offset += data_len;
                }
            }
            break;

        case MMS_SERVICE_IDENTIFY:
            request->service = MMS_SERVICE_TYPE_IDENTIFY;
            offset += field_len;
            break;

        case MMS_SERVICE_GET_NAMELIST:
            request->service = MMS_SERVICE_TYPE_GET_NAMELIST;
            /* GetNameList-Request: objectClass [0] + objectScope [1] */
            {
                size_t gnl_end = offset + field_len;
                while (offset < gnl_end) {
                    uint8_t gnl_tag = buffer[offset++];
                    size_t gnl_tag_len;
                    ret = mms_decode_length(buffer + offset, buflen - offset, &gnl_tag_len);
                    if (ret < 0) return ret;
                    offset += ret;

                    switch (gnl_tag) {
                        case 0x80:  /* objectClass [0] IMPLICIT INTEGER */
                            if (gnl_tag_len >= 1) {
                                request->params.getnamelist.object_class = (mms_object_class_t)buffer[offset];
                            }
                            break;
                        case 0xA0:  /* extendedObjectClass [0] CONSTRUCTED { objectClass [0] } */
                            if (gnl_tag_len >= 3 && buffer[offset] == 0x80) {
                                size_t oc_len = buffer[offset + 1];
                                if (oc_len >= 1) {
                                    request->params.getnamelist.object_class = (mms_object_class_t)buffer[offset + 2];
                                }
                            }
                            break;
                        case 0xA1:  /* objectScope [1] */
                            /* vmd-specific or domain-specific scope */
                            if (gnl_tag_len > 0 && buffer[offset] == 0x81) {
                                /* domain-specific [1] */
                                offset++;
                                size_t gnl_dom_len;
                                ret = mms_decode_length(buffer + offset, buflen - offset, &gnl_dom_len);
                                if (ret < 0) return ret;
                                offset += ret;
                                if (gnl_dom_len < MMS_MAX_DOMAIN_NAME) {
                                    memcpy(request->params.getnamelist.domain, buffer + offset, gnl_dom_len);
                                    request->params.getnamelist.domain[gnl_dom_len] = '\0';
                                }
                                offset += gnl_dom_len;
                                continue;  /* already advanced */
                            }
                            break;
                        case 0x82:  /* continueAfter [2] IMPLICIT VisibleString */
                            request->params.getnamelist.continue_after = true;
                            if (gnl_tag_len < MMS_MAX_VARIABLE_NAME) {
                                memcpy(request->params.getnamelist.continue_after_id,
                                       buffer + offset, gnl_tag_len);
                                request->params.getnamelist.continue_after_id[gnl_tag_len] = '\0';
                            }
                            break;
                        default:
                            break;
                    }
                    offset += gnl_tag_len;
                }
            }
            break;

        case MMS_SERVICE_GET_VARIABLE_ATTRS:
            request->service = MMS_SERVICE_TYPE_GET_VARIABLE_ATTRS;
            /* GetVariableAccessAttributes-Request: name [0] { A1 { 1A dom 1A item } } */
            if (buffer[offset] == 0xA0) {
                size_t gva_end = offset + field_len;

                /* Scan for VisibleString (0x1A) tags inside nested wrappers */
                size_t scan = offset;
                while (scan + 2 < gva_end) {
                    uint8_t t = buffer[scan];
                    if (t == 0x1A) break;
                    scan++;
                    size_t skip;
                    ret = mms_decode_length(buffer + scan, gva_end - scan, &skip);
                    if (ret < 0) break;
                    scan += (size_t)ret;
                    if (t & 0x20) continue;
                    scan += skip;
                }

                if (scan + 2 < gva_end && buffer[scan] == 0x1A) {
                    scan++;
                    size_t gva_dom_len = buffer[scan++];
                    if (gva_dom_len < MMS_MAX_DOMAIN_NAME) {
                        memcpy(request->params.getvariableattrs.variable_spec.domain,
                               buffer + scan, gva_dom_len);
                        request->params.getvariableattrs.variable_spec.domain[gva_dom_len] = '\0';
                    }
                    scan += gva_dom_len;

                    if (scan + 2 <= gva_end && buffer[scan] == 0x1A) {
                        scan++;
                        size_t gva_item_len = buffer[scan++];
                        if (gva_item_len < MMS_MAX_VARIABLE_NAME) {
                            memcpy(request->params.getvariableattrs.variable_spec.item_id,
                                   buffer + scan, gva_item_len);
                            request->params.getvariableattrs.variable_spec.item_id[gva_item_len] = '\0';
                        }
                    }
                }
                offset = gva_end;
            } else {
                offset += field_len;
            }
            break;

        case MMS_SERVICE_DEFINE_NAMED_VARLIST:
            request->service = MMS_SERVICE_TYPE_DEFINE_NAMED_VARLIST;
            /* DefineNamedVariableList-Request:
               variableListName [0] + listOfVariable [1] */
            {
                size_t dnvl_end = offset + field_len;
                /* [0] variableListName: ObjectName (domain-specific) */
                if (offset < dnvl_end && buffer[offset] == 0xA0) {
                    offset++;
                    size_t name_spec_len;
                    ret = mms_decode_length(buffer + offset, buflen - offset, &name_spec_len);
                    if (ret < 0) return ret;
                    offset += ret;

                    size_t dnvl_dom_len = buffer[offset++];
                    if (dnvl_dom_len >= MMS_MAX_DOMAIN_NAME) return MMS_ERROR_BUFFER_TOO_SMALL;
                    memcpy(request->params.definenamedvarlist.domain, buffer + offset, dnvl_dom_len);
                    request->params.definenamedvarlist.domain[dnvl_dom_len] = '\0';
                    offset += dnvl_dom_len;

                    size_t dnvl_name_len = buffer[offset++];
                    if (dnvl_name_len >= MMS_MAX_VARIABLE_NAME) return MMS_ERROR_BUFFER_TOO_SMALL;
                    memcpy(request->params.definenamedvarlist.list_name, buffer + offset, dnvl_name_len);
                    request->params.definenamedvarlist.list_name[dnvl_name_len] = '\0';
                    offset += dnvl_name_len;
                }
                /* [1] listOfVariable: SEQUENCE OF VariableSpecification */
                if (offset < dnvl_end && buffer[offset] == 0xA1) {
                    offset++;
                    size_t var_list_len;
                    ret = mms_decode_length(buffer + offset, buflen - offset, &var_list_len);
                    if (ret < 0) return ret;
                    offset += ret;

                    size_t var_list_end = offset + var_list_len;
                    request->params.definenamedvarlist.num_variables = 0;
                    while (offset < var_list_end && request->params.definenamedvarlist.num_variables < MMS_MAX_NAMED_VARIABLES) {
                        uint32_t vi = request->params.definenamedvarlist.num_variables;
                        if (buffer[offset] == 0xA0) {  /* domain-specific */
                            offset++;
                            size_t vs_len;
                            ret = mms_decode_length(buffer + offset, buflen - offset, &vs_len);
                            if (ret < 0) return ret;
                            offset += ret;

                            size_t vs_dom_len = buffer[offset++];
                            if (vs_dom_len >= MMS_MAX_DOMAIN_NAME) return MMS_ERROR_BUFFER_TOO_SMALL;
                            memcpy(request->params.definenamedvarlist.variables[vi].domain, buffer + offset, vs_dom_len);
                            request->params.definenamedvarlist.variables[vi].domain[vs_dom_len] = '\0';
                            offset += vs_dom_len;

                            size_t vs_item_len = buffer[offset++];
                            if (vs_item_len >= MMS_MAX_VARIABLE_NAME) return MMS_ERROR_BUFFER_TOO_SMALL;
                            memcpy(request->params.definenamedvarlist.variables[vi].item_id, buffer + offset, vs_item_len);
                            request->params.definenamedvarlist.variables[vi].item_id[vs_item_len] = '\0';
                            offset += vs_item_len;

                            request->params.definenamedvarlist.num_variables++;
                        } else {
                            break;  /* Unknown format */
                        }
                    }
                }
                offset = dnvl_end;
            }
            break;

        case MMS_SERVICE_DELETE_NAMED_VARLIST:
            request->service = MMS_SERVICE_TYPE_DELETE_NAMED_VARLIST;
            /* DeleteNamedVariableList-Request: variableListName [0] */
            if (buffer[offset] == 0xA0) {
                offset++;
                size_t del_spec_len;
                ret = mms_decode_length(buffer + offset, buflen - offset, &del_spec_len);
                if (ret < 0) return ret;
                offset += ret;

                size_t del_dom_len = buffer[offset++];
                if (del_dom_len >= MMS_MAX_DOMAIN_NAME) return MMS_ERROR_BUFFER_TOO_SMALL;
                memcpy(request->params.deletenamedvarlist.domain, buffer + offset, del_dom_len);
                request->params.deletenamedvarlist.domain[del_dom_len] = '\0';
                offset += del_dom_len;

                size_t del_name_len = buffer[offset++];
                if (del_name_len >= MMS_MAX_VARIABLE_NAME) return MMS_ERROR_BUFFER_TOO_SMALL;
                memcpy(request->params.deletenamedvarlist.list_name, buffer + offset, del_name_len);
                request->params.deletenamedvarlist.list_name[del_name_len] = '\0';
                offset += del_name_len;
            } else {
                offset += field_len;
            }
            break;

        case MMS_SERVICE_GET_NAMED_VARLIST_ATTRS:
            request->service = MMS_SERVICE_TYPE_GET_NAMED_VARLIST_ATTRS;
            /* GetNamedVariableListAttributes-Request: variableListName [0] */
            if (buffer[offset] == 0xA0) {
                offset++;
                size_t gattr_spec_len;
                ret = mms_decode_length(buffer + offset, buflen - offset, &gattr_spec_len);
                if (ret < 0) return ret;
                offset += ret;

                size_t gattr_dom_len = buffer[offset++];
                if (gattr_dom_len >= MMS_MAX_DOMAIN_NAME) return MMS_ERROR_BUFFER_TOO_SMALL;
                memcpy(request->params.getnamedvarlistattrs.domain, buffer + offset, gattr_dom_len);
                request->params.getnamedvarlistattrs.domain[gattr_dom_len] = '\0';
                offset += gattr_dom_len;

                size_t gattr_name_len = buffer[offset++];
                if (gattr_name_len >= MMS_MAX_VARIABLE_NAME) return MMS_ERROR_BUFFER_TOO_SMALL;
                memcpy(request->params.getnamedvarlistattrs.list_name, buffer + offset, gattr_name_len);
                request->params.getnamedvarlistattrs.list_name[gattr_name_len] = '\0';
                offset += gattr_name_len;
            } else {
                offset += field_len;
            }
            break;

        /* Phase 7: Control Services Decoding */
        case MMS_SERVICE_SELECT:
            request->service = MMS_SERVICE_TYPE_SELECT;
            /* Parse controlObject [0], checkValue [1], selectTimeout [2] */
            size_t sel_end = offset + field_len;
            while (offset < sel_end) {
                uint8_t tag = buffer[offset++];
                size_t tag_len;
                ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
                if (ret < 0) return ret;
                offset += ret;

                switch (tag) {
                    case 0xA0: { /* controlObject [0] IMPLICIT */
                        /* Decode domain-specific variable spec */
                        size_t domain_len = buffer[offset++];
                        if (domain_len >= MMS_MAX_DOMAIN_NAME) {
                            return MMS_ERROR_BUFFER_TOO_SMALL;
                        }
                        memcpy(request->params.select.control_object.domain, buffer + offset, domain_len);
                        request->params.select.control_object.domain[domain_len] = '\0';
                        offset += domain_len;

                        size_t item_len = buffer[offset++];
                        if (item_len >= MMS_MAX_VARIABLE_NAME) {
                            return MMS_ERROR_BUFFER_TOO_SMALL;
                        }
                        memcpy(request->params.select.control_object.item_id, buffer + offset, item_len);
                        request->params.select.control_object.item_id[item_len] = '\0';
                        offset += item_len;
                        break;
                    }

                    case 0x81:  /* checkValue [1] IMPLICIT */
                        request->params.select.check_value = buffer[offset];
                        offset += tag_len;
                        break;

                    case 0x82:  /* selectTimeout [2] IMPLICIT (optional) */
                        ret = decode_integer(buffer + offset, tag_len, (int32_t*)&request->params.select.select_timeout_ms);
                        if (ret < 0) return ret;
                        offset += tag_len;
                        break;

                    default:
                        /* Skip unknown fields */
                        offset += tag_len;
                        break;
                }
            }
            break;

        case MMS_SERVICE_SELECT_WITH_VALUE:
            request->service = MMS_SERVICE_TYPE_SELECT_WITH_VALUE;
            /* Parse controlObject [0], controlValue [1], checkValue [2], selectTimeout [3] */
            size_t swv_end = offset + field_len;
            while (offset < swv_end) {
                uint8_t tag = buffer[offset++];
                size_t tag_len;
                ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
                if (ret < 0) return ret;
                offset += ret;

                switch (tag) {
                    case 0xA0: { /* controlObject [0] IMPLICIT */
                        /* Decode domain-specific variable spec */
                        size_t domain_len = buffer[offset++];
                        if (domain_len >= MMS_MAX_DOMAIN_NAME) {
                            return MMS_ERROR_BUFFER_TOO_SMALL;
                        }
                        memcpy(request->params.select_with_value.control_object.domain, buffer + offset, domain_len);
                        request->params.select_with_value.control_object.domain[domain_len] = '\0';
                        offset += domain_len;

                        size_t item_len = buffer[offset++];
                        if (item_len >= MMS_MAX_VARIABLE_NAME) {
                            return MMS_ERROR_BUFFER_TOO_SMALL;
                        }
                        memcpy(request->params.select_with_value.control_object.item_id, buffer + offset, item_len);
                        request->params.select_with_value.control_object.item_id[item_len] = '\0';
                        offset += item_len;
                        break;
                    }

                    case 0xA1:  /* controlValue [1] IMPLICIT */
                        ret = mms_decode_value(buffer + offset, tag_len, &request->params.select_with_value.control_value);
                        if (ret < 0) return ret;
                        offset += tag_len;
                        break;

                    case 0x82:  /* checkValue [2] IMPLICIT */
                        request->params.select_with_value.check_value = buffer[offset];
                        offset += tag_len;
                        break;

                    case 0x83:  /* selectTimeout [3] IMPLICIT (optional) */
                        ret = decode_integer(buffer + offset, tag_len, (int32_t*)&request->params.select_with_value.select_timeout_ms);
                        if (ret < 0) return ret;
                        offset += tag_len;
                        break;

                    default:
                        /* Skip unknown fields */
                        offset += tag_len;
                        break;
                }
            }
            break;

        case MMS_SERVICE_OPERATE:
            request->service = MMS_SERVICE_TYPE_OPERATE;
            /* Parse controlObject [0], selectionID [1], controlValue [2], operationTime [3] */
            size_t op_end = offset + field_len;
            request->params.operate.has_control_value = false;
            request->params.operate.operation_time = 0;
            while (offset < op_end) {
                uint8_t tag = buffer[offset++];
                size_t tag_len;
                ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
                if (ret < 0) return ret;
                offset += ret;

                switch (tag) {
                    case 0xA0: { /* controlObject [0] IMPLICIT */
                        /* Decode domain-specific variable spec */
                        size_t domain_len = buffer[offset++];
                        if (domain_len >= MMS_MAX_DOMAIN_NAME) {
                            return MMS_ERROR_BUFFER_TOO_SMALL;
                        }
                        memcpy(request->params.operate.control_object.domain, buffer + offset, domain_len);
                        request->params.operate.control_object.domain[domain_len] = '\0';
                        offset += domain_len;

                        size_t item_len = buffer[offset++];
                        if (item_len >= MMS_MAX_VARIABLE_NAME) {
                            return MMS_ERROR_BUFFER_TOO_SMALL;
                        }
                        memcpy(request->params.operate.control_object.item_id, buffer + offset, item_len);
                        request->params.operate.control_object.item_id[item_len] = '\0';
                        offset += item_len;
                        break;
                    }

                    case 0x81:  /* selectionID [1] IMPLICIT */
                        ret = decode_integer(buffer + offset, tag_len, (int32_t*)&request->params.operate.selection_id);
                        if (ret < 0) return ret;
                        offset += tag_len;
                        break;

                    case 0xA2:  /* controlValue [2] IMPLICIT (optional) */
                        ret = mms_decode_value(buffer + offset, tag_len, &request->params.operate.control_value);
                        if (ret < 0) return ret;
                        request->params.operate.has_control_value = true;
                        offset += tag_len;
                        break;

                    case 0x83:  /* operationTime [3] IMPLICIT (optional, 64-bit) */
                        if (tag_len == 8) {
                            request->params.operate.operation_time = 0;
                            for (size_t i = 0; i < 8; i++) {
                                request->params.operate.operation_time =
                                    (request->params.operate.operation_time << 8) | buffer[offset + i];
                            }
                        } else {
                            int32_t op_time_32 = 0;
                            ret = decode_integer(buffer + offset, tag_len, &op_time_32);
                            if (ret < 0) return ret;
                            request->params.operate.operation_time = (uint64_t)op_time_32;
                        }
                        offset += tag_len;
                        break;

                    default:
                        /* Skip unknown fields */
                        offset += tag_len;
                        break;
                }
            }
            break;

        case MMS_SERVICE_CANCEL:
            request->service = MMS_SERVICE_TYPE_CANCEL;
            /* Parse controlObject [0], selectionID [1] */
            size_t cancel_end = offset + field_len;
            while (offset < cancel_end) {
                uint8_t tag = buffer[offset++];
                size_t tag_len;
                ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
                if (ret < 0) return ret;
                offset += ret;

                switch (tag) {
                    case 0xA0: { /* controlObject [0] IMPLICIT */
                        /* Decode domain-specific variable spec */
                        size_t domain_len = buffer[offset++];
                        if (domain_len >= MMS_MAX_DOMAIN_NAME) {
                            return MMS_ERROR_BUFFER_TOO_SMALL;
                        }
                        memcpy(request->params.cancel.control_object.domain, buffer + offset, domain_len);
                        request->params.cancel.control_object.domain[domain_len] = '\0';
                        offset += domain_len;

                        size_t item_len = buffer[offset++];
                        if (item_len >= MMS_MAX_VARIABLE_NAME) {
                            return MMS_ERROR_BUFFER_TOO_SMALL;
                        }
                        memcpy(request->params.cancel.control_object.item_id, buffer + offset, item_len);
                        request->params.cancel.control_object.item_id[item_len] = '\0';
                        offset += item_len;
                        break;
                    }

                    case 0x81:  /* selectionID [1] IMPLICIT */
                        ret = decode_integer(buffer + offset, tag_len, (int32_t*)&request->params.cancel.selection_id);
                        if (ret < 0) return ret;
                        offset += tag_len;
                        break;

                    default:
                        /* Skip unknown fields */
                        offset += tag_len;
                        break;
                }
            }
            break;

        /* Phase 7 Week 2: File Services Decoding */
        case MMS_SERVICE_FILE_OPEN:
            request->service = MMS_SERVICE_TYPE_FILE_OPEN;
            /* Parse filename [0], accessMode [1] */
            size_t fileopen_end = offset + field_len;
            while (offset < fileopen_end) {
                uint8_t tag = buffer[offset++];
                size_t tag_len;
                ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
                if (ret < 0) return ret;
                offset += ret;

                switch (tag) {
                    case 0xA0: { /* filename [0] IMPLICIT */
                        if (tag_len >= MMS_MAX_VARIABLE_NAME) {
                            return MMS_ERROR_BUFFER_TOO_SMALL;
                        }
                        memcpy(request->params.fileopen.filename, buffer + offset, tag_len);
                        request->params.fileopen.filename[tag_len] = '\0';
                        offset += tag_len;
                        break;
                    }

                    case 0x81:  /* accessMode [1] IMPLICIT */
                        request->params.fileopen.access_mode = (mms_file_access_mode_t)buffer[offset];
                        offset += tag_len;
                        break;

                    default:
                        /* Skip unknown fields */
                        offset += tag_len;
                        break;
                }
            }
            break;

        case MMS_SERVICE_FILE_READ:
            request->service = MMS_SERVICE_TYPE_FILE_READ;
            /* Parse fileHandle [0], maxBytes [1] */
            size_t fileread_end = offset + field_len;
            while (offset < fileread_end) {
                uint8_t tag = buffer[offset++];
                size_t tag_len;
                ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
                if (ret < 0) return ret;
                offset += ret;

                switch (tag) {
                    case 0x80:  /* fileHandle [0] IMPLICIT */
                        ret = decode_integer(buffer + offset, tag_len, (int32_t*)&request->params.fileread.file_handle);
                        if (ret < 0) return ret;
                        offset += tag_len;
                        break;

                    case 0x81:  /* maxBytes [1] IMPLICIT */
                        ret = decode_integer(buffer + offset, tag_len, (int32_t*)&request->params.fileread.max_bytes);
                        if (ret < 0) return ret;
                        offset += tag_len;
                        break;

                    default:
                        /* Skip unknown fields */
                        offset += tag_len;
                        break;
                }
            }
            break;

        case MMS_SERVICE_FILE_CLOSE:
            request->service = MMS_SERVICE_TYPE_FILE_CLOSE;
            /* Parse fileHandle [0] */
            size_t fileclose_end = offset + field_len;
            while (offset < fileclose_end) {
                uint8_t tag = buffer[offset++];
                size_t tag_len;
                ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
                if (ret < 0) return ret;
                offset += ret;

                switch (tag) {
                    case 0x80:  /* fileHandle [0] IMPLICIT */
                        ret = decode_integer(buffer + offset, tag_len, (int32_t*)&request->params.fileclose.file_handle);
                        if (ret < 0) return ret;
                        offset += tag_len;
                        break;

                    default:
                        /* Skip unknown fields */
                        offset += tag_len;
                        break;
                }
            }
            break;

        case MMS_SERVICE_FILE_DELETE:
            request->service = MMS_SERVICE_TYPE_FILE_DELETE;
            /* Parse filename [0] */
            size_t filedelete_end = offset + field_len;
            while (offset < filedelete_end) {
                uint8_t tag = buffer[offset++];
                size_t tag_len;
                ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
                if (ret < 0) return ret;
                offset += ret;

                switch (tag) {
                    case 0xA0: { /* filename [0] IMPLICIT */
                        if (tag_len >= MMS_MAX_VARIABLE_NAME) {
                            return MMS_ERROR_BUFFER_TOO_SMALL;
                        }
                        memcpy(request->params.filedelete.filename, buffer + offset, tag_len);
                        request->params.filedelete.filename[tag_len] = '\0';
                        offset += tag_len;
                        break;
                    }

                    default:
                        /* Skip unknown fields */
                        offset += tag_len;
                        break;
                }
            }
            break;

        case MMS_SERVICE_FILE_DIRECTORY:
            request->service = MMS_SERVICE_TYPE_FILE_DIRECTORY;
            /* Parse directory [0] (optional), fileSpecification [1] (optional) */
            request->params.filedirectory.directory[0] = '\0';
            request->params.filedirectory.file_specification[0] = '\0';
            size_t filedir_end = offset + field_len;
            while (offset < filedir_end) {
                uint8_t tag = buffer[offset++];
                size_t tag_len;
                ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
                if (ret < 0) return ret;
                offset += ret;

                switch (tag) {
                    case 0xA0: { /* directory [0] IMPLICIT (optional) */
                        if (tag_len >= MMS_MAX_VARIABLE_NAME) {
                            return MMS_ERROR_BUFFER_TOO_SMALL;
                        }
                        memcpy(request->params.filedirectory.directory, buffer + offset, tag_len);
                        request->params.filedirectory.directory[tag_len] = '\0';
                        offset += tag_len;
                        break;
                    }

                    case 0xA1: { /* fileSpecification [1] IMPLICIT (optional) */
                        if (tag_len >= MMS_MAX_VARIABLE_NAME) {
                            return MMS_ERROR_BUFFER_TOO_SMALL;
                        }
                        memcpy(request->params.filedirectory.file_specification, buffer + offset, tag_len);
                        request->params.filedirectory.file_specification[tag_len] = '\0';
                        offset += tag_len;
                        break;
                    }

                    default:
                        /* Skip unknown fields */
                        offset += tag_len;
                        break;
                }
            }
            break;

        /* Phase 7 Week 3: Journal Services Request Decoding */
        case MMS_SERVICE_READ_JOURNAL:
            request->service = MMS_SERVICE_TYPE_READ_JOURNAL;
            /* Parse journalName [0], startTime [1], endTime [2], startEntryID [3], maxEntries [4] */
            size_t readjournal_end = offset + field_len;
            request->params.readjournal.start_time = 0;
            request->params.readjournal.end_time = 0;
            request->params.readjournal.start_entry_id = 0;
            request->params.readjournal.max_entries = 50;  /* Default */

            while (offset < readjournal_end) {
                uint8_t tag = buffer[offset++];
                size_t tag_len;
                ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
                if (ret < 0) return ret;
                offset += ret;

                switch (tag) {
                    case 0xA0: { /* journalName [0] IMPLICIT */
                        if (tag_len >= MMS_MAX_VARIABLE_NAME) {
                            return MMS_ERROR_BUFFER_TOO_SMALL;
                        }
                        memcpy(request->params.readjournal.journal_name, buffer + offset, tag_len);
                        request->params.readjournal.journal_name[tag_len] = '\0';
                        offset += tag_len;
                        break;
                    }

                    case 0x81:  /* startTime [1] IMPLICIT INTEGER (64-bit, optional) */
                        if (tag_len == 8) {
                            request->params.readjournal.start_time = 0;
                            for (size_t i = 0; i < 8; i++) {
                                request->params.readjournal.start_time =
                                    (request->params.readjournal.start_time << 8) | buffer[offset + i];
                            }
                        }
                        offset += tag_len;
                        break;

                    case 0x82:  /* endTime [2] IMPLICIT INTEGER (64-bit, optional) */
                        if (tag_len == 8) {
                            request->params.readjournal.end_time = 0;
                            for (size_t i = 0; i < 8; i++) {
                                request->params.readjournal.end_time =
                                    (request->params.readjournal.end_time << 8) | buffer[offset + i];
                            }
                        }
                        offset += tag_len;
                        break;

                    case 0x83:  /* startEntryID [3] IMPLICIT INTEGER (64-bit, optional) */
                        if (tag_len == 8) {
                            request->params.readjournal.start_entry_id = 0;
                            for (size_t i = 0; i < 8; i++) {
                                request->params.readjournal.start_entry_id =
                                    (request->params.readjournal.start_entry_id << 8) | buffer[offset + i];
                            }
                        }
                        offset += tag_len;
                        break;

                    case 0x84:  /* maxEntries [4] IMPLICIT INTEGER */
                        ret = decode_integer(buffer + offset, tag_len, (int32_t*)&request->params.readjournal.max_entries);
                        if (ret < 0) return ret;
                        offset += tag_len;
                        break;

                    default:
                        /* Skip unknown fields */
                        offset += tag_len;
                        break;
                }
            }
            break;

        case MMS_SERVICE_INITIALIZE_JOURNAL:
            request->service = MMS_SERVICE_TYPE_INITIALIZE_JOURNAL;
            /* Parse journalName [0] */
            size_t initjournal_end = offset + field_len;
            while (offset < initjournal_end) {
                uint8_t tag = buffer[offset++];
                size_t tag_len;
                ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
                if (ret < 0) return ret;
                offset += ret;

                switch (tag) {
                    case 0xA0: { /* journalName [0] IMPLICIT */
                        if (tag_len >= MMS_MAX_VARIABLE_NAME) {
                            return MMS_ERROR_BUFFER_TOO_SMALL;
                        }
                        memcpy(request->params.initializejournal.journal_name, buffer + offset, tag_len);
                        request->params.initializejournal.journal_name[tag_len] = '\0';
                        offset += tag_len;
                        break;
                    }

                    default:
                        /* Skip unknown fields */
                        offset += tag_len;
                        break;
                }
            }
            break;

        /* Phase 7 Week 4: Type Services Request Decoding */
        case MMS_SERVICE_DEFINE_NAMED_TYPE:
            request->service = MMS_SERVICE_TYPE_DEFINE_NAMED_TYPE;
            /* Parse domain [0] (optional), typeName [1], typeSpec [2] */
            request->params.definenamedtype.domain[0] = '\0';
            size_t definetype_end = offset + field_len;
            while (offset < definetype_end) {
                uint8_t tag = buffer[offset++];
                size_t tag_len;
                ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
                if (ret < 0) return ret;
                offset += ret;

                switch (tag) {
                    case 0xA0: { /* domain [0] IMPLICIT (optional) */
                        if (tag_len >= MMS_MAX_DOMAIN_NAME) {
                            return MMS_ERROR_BUFFER_TOO_SMALL;
                        }
                        memcpy(request->params.definenamedtype.domain, buffer + offset, tag_len);
                        request->params.definenamedtype.domain[tag_len] = '\0';
                        offset += tag_len;
                        break;
                    }

                    case 0xA1: { /* typeName [1] IMPLICIT */
                        if (tag_len >= MMS_MAX_VARIABLE_NAME) {
                            return MMS_ERROR_BUFFER_TOO_SMALL;
                        }
                        memcpy(request->params.definenamedtype.type_name, buffer + offset, tag_len);
                        request->params.definenamedtype.type_name[tag_len] = '\0';
                        offset += tag_len;
                        break;
                    }

                    case 0x82:  /* typeSpec [2] IMPLICIT INTEGER */
                        request->params.definenamedtype.type_spec = (mms_type_t)buffer[offset];
                        offset += tag_len;
                        break;

                    default:
                        /* Skip unknown fields */
                        offset += tag_len;
                        break;
                }
            }
            break;

        case MMS_SERVICE_DELETE_NAMED_TYPE:
            request->service = MMS_SERVICE_TYPE_DELETE_NAMED_TYPE;
            /* Parse domain [0] (optional), typeName [1] */
            request->params.deletenamedtype.domain[0] = '\0';
            size_t deletetype_end = offset + field_len;
            while (offset < deletetype_end) {
                uint8_t tag = buffer[offset++];
                size_t tag_len;
                ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
                if (ret < 0) return ret;
                offset += ret;

                switch (tag) {
                    case 0xA0: { /* domain [0] IMPLICIT (optional) */
                        if (tag_len >= MMS_MAX_DOMAIN_NAME) {
                            return MMS_ERROR_BUFFER_TOO_SMALL;
                        }
                        memcpy(request->params.deletenamedtype.domain, buffer + offset, tag_len);
                        request->params.deletenamedtype.domain[tag_len] = '\0';
                        offset += tag_len;
                        break;
                    }

                    case 0xA1: { /* typeName [1] IMPLICIT */
                        if (tag_len >= MMS_MAX_VARIABLE_NAME) {
                            return MMS_ERROR_BUFFER_TOO_SMALL;
                        }
                        memcpy(request->params.deletenamedtype.type_name, buffer + offset, tag_len);
                        request->params.deletenamedtype.type_name[tag_len] = '\0';
                        offset += tag_len;
                        break;
                    }

                    default:
                        /* Skip unknown fields */
                        offset += tag_len;
                        break;
                }
            }
            break;

        case MMS_SERVICE_GET_NAMED_TYPE_ATTRS:
            request->service = MMS_SERVICE_TYPE_GET_NAMED_TYPE_ATTRS;
            /* Parse domain [0] (optional), typeName [1] */
            request->params.getnamedtypeattrs.domain[0] = '\0';
            size_t gettypeattrs_end = offset + field_len;
            while (offset < gettypeattrs_end) {
                uint8_t tag = buffer[offset++];
                size_t tag_len;
                ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
                if (ret < 0) return ret;
                offset += ret;

                switch (tag) {
                    case 0xA0: { /* domain [0] IMPLICIT (optional) */
                        if (tag_len >= MMS_MAX_DOMAIN_NAME) {
                            return MMS_ERROR_BUFFER_TOO_SMALL;
                        }
                        memcpy(request->params.getnamedtypeattrs.domain, buffer + offset, tag_len);
                        request->params.getnamedtypeattrs.domain[tag_len] = '\0';
                        offset += tag_len;
                        break;
                    }

                    case 0xA1: { /* typeName [1] IMPLICIT */
                        if (tag_len >= MMS_MAX_VARIABLE_NAME) {
                            return MMS_ERROR_BUFFER_TOO_SMALL;
                        }
                        memcpy(request->params.getnamedtypeattrs.type_name, buffer + offset, tag_len);
                        request->params.getnamedtypeattrs.type_name[tag_len] = '\0';
                        offset += tag_len;
                        break;
                    }

                    default:
                        /* Skip unknown fields */
                        offset += tag_len;
                        break;
                }
            }
            break;

        default:
            return MMS_ERROR_NOT_SUPPORTED;
    }

    return (int)offset;
}

int mms_encode_confirmed_response(const mms_confirmed_response_t* response,
                                  uint8_t* buffer, size_t buflen) {
    if (response == NULL || buffer == NULL) {
        return MMS_ERROR_INVALID_PARAM;
    }

    size_t offset = 0;

    /* Confirmed-ResponsePDU [1] IMPLICIT SEQUENCE */
    if (!has_space(offset, 1, buflen)) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }
    buffer[offset++] = MMS_TAG_CONFIRMED_RESPONSE;

    /* Build content */
    uint8_t content[MMS_MAX_PDU_SIZE];
    size_t content_offset = 0;

    /* invokeID — encoded as UNIVERSAL INTEGER (0x02) for interop */
    content[content_offset++] = 0x02;
    uint8_t temp_buf[16];
    int ret = encode_integer(response->invoke_id, temp_buf, sizeof(temp_buf));
    if (ret < 0) {
        return ret;
    }
    content[content_offset++] = (uint8_t)ret;
    memcpy(content + content_offset, temp_buf, ret);
    content_offset += ret;

    /* Service-specific response */
    uint8_t service_tag;
    uint8_t service_buf[MMS_MAX_PDU_SIZE];
    int service_len;

    switch (response->service) {
        case MMS_SERVICE_TYPE_IDENTIFY:
            service_tag = 0xA2;  /* Identify response is SEQUENCE → CONSTRUCTED */
            /* Identify-Response ::= SEQUENCE {
             *   vendorName [0] IMPLICIT VisibleString,
             *   modelName  [1] IMPLICIT VisibleString,
             *   revision   [2] IMPLICIT VisibleString } */
            {
                size_t o = 0;
                size_t vn_len = strlen(response->params.identify.vendor_name);
                size_t mn_len = strlen(response->params.identify.model_name);
                size_t rv_len = strlen(response->params.identify.revision);

                service_buf[o++] = 0x80;  /* vendorName [0] */
                service_buf[o++] = (uint8_t)vn_len;
                memcpy(service_buf + o, response->params.identify.vendor_name, vn_len);
                o += vn_len;

                service_buf[o++] = 0x81;  /* modelName [1] */
                service_buf[o++] = (uint8_t)mn_len;
                memcpy(service_buf + o, response->params.identify.model_name, mn_len);
                o += mn_len;

                service_buf[o++] = 0x82;  /* revision [2] */
                service_buf[o++] = (uint8_t)rv_len;
                memcpy(service_buf + o, response->params.identify.revision, rv_len);
                o += rv_len;

                service_len = (int)o;
            }
            break;

        case MMS_SERVICE_TYPE_READ_NAMED_VARLIST:
            /* ReadNamedVariableList response — multiple values in listOfAccessResult */
            service_tag = MMS_SERVICE_READ;
            {
                size_t rnvl_o = 0;
                service_buf[rnvl_o++] = 0xA1;  /* listOfAccessResult [1] */
                size_t rnvl_vals_start = rnvl_o + 1;
                rnvl_o++;  /* skip length placeholder */
                for (uint32_t i = 0; i < response->params.readnamedvarlist.num_values; i++) {
                    ret = mms_encode_value(&response->params.readnamedvarlist.values[i],
                                           service_buf + rnvl_o,
                                           sizeof(service_buf) - rnvl_o);
                    if (ret < 0) return ret;
                    rnvl_o += (size_t)ret;
                }
                service_buf[rnvl_vals_start - 1] = (uint8_t)(rnvl_o - rnvl_vals_start);
                service_len = (int)rnvl_o;
            }
            break;

        case MMS_SERVICE_TYPE_READ:
            service_tag = MMS_SERVICE_READ;
            /* Read-Response: listOfAccessResult [1] */
            service_buf[0] = 0xA1;  /* [1] IMPLICIT SEQUENCE OF */
            ret = mms_encode_value(&response->params.read.value, service_buf + 2, sizeof(service_buf) - 2);
            if (ret < 0) {
                return ret;
            }
            service_buf[1] = (uint8_t)ret;
            service_len = 2 + ret;
            break;

        case MMS_SERVICE_TYPE_WRITE:
            service_tag = MMS_SERVICE_WRITE;
            /* Write-Response: success [1] IMPLICIT NULL */
            service_buf[0] = 0x81;  /* success [1] PRIMITIVE */
            service_buf[1] = 0x00;  /* length 0 */
            service_len = 2;
            break;

        case MMS_SERVICE_TYPE_GET_NAMELIST:
            service_tag = MMS_SERVICE_GET_NAMELIST;
            /* GetNameList-Response: listOfIdentifier [0] { VisibleString* }
             *                      moreFollows [1] IMPLICIT BOOLEAN */
            {
                size_t gnl_o = 0;
                service_buf[gnl_o++] = 0xA0;  /* listOfIdentifier [0] */
                size_t gnl_list_start = gnl_o + 1;  /* skip length byte */
                gnl_o++;
                for (uint32_t i = 0; i < response->params.getnamelist.num_identifiers; i++) {
                    size_t name_len = strlen(response->params.getnamelist.identifiers[i]);
                    service_buf[gnl_o++] = 0x1A;  /* VisibleString */
                    service_buf[gnl_o++] = (uint8_t)name_len;
                    memcpy(service_buf + gnl_o, response->params.getnamelist.identifiers[i], name_len);
                    gnl_o += name_len;
                }
                service_buf[gnl_list_start - 1] = (uint8_t)(gnl_o - gnl_list_start);
                /* moreFollows [1] IMPLICIT BOOLEAN = FALSE */
                service_buf[gnl_o++] = 0x81;
                service_buf[gnl_o++] = 0x01;
                service_buf[gnl_o++] = 0x00;
                service_len = (int)gnl_o;
            }
            break;

        case MMS_SERVICE_TYPE_GET_VARIABLE_ATTRS:
            service_tag = MMS_SERVICE_GET_VARIABLE_ATTRS;
            /* GetVariableAccessAttributes-Response */
            size_t gva_resp_offset = 0;
            /* name [0] IMPLICIT VisibleString */
            service_buf[gva_resp_offset++] = 0xA0;  /* [0] IMPLICIT */
            size_t gva_name_len = strlen(response->params.getvariableattrs.attributes.name);
            service_buf[gva_resp_offset++] = (uint8_t)gva_name_len;
            memcpy(service_buf + gva_resp_offset, response->params.getvariableattrs.attributes.name, gva_name_len);
            gva_resp_offset += gva_name_len;
            /* typeDescription [1] IMPLICIT INTEGER */
            service_buf[gva_resp_offset++] = 0x81;  /* [1] IMPLICIT */
            service_buf[gva_resp_offset++] = 0x01;
            service_buf[gva_resp_offset++] = (uint8_t)response->params.getvariableattrs.attributes.type;
            service_len = gva_resp_offset;
            break;

        case MMS_SERVICE_TYPE_DEFINE_NAMED_VARLIST:
            service_tag = MMS_SERVICE_DEFINE_NAMED_VARLIST;
            /* DefineNamedVariableList-Response: NULL (empty) */
            service_len = 0;
            break;

        case MMS_SERVICE_TYPE_DELETE_NAMED_VARLIST:
            service_tag = MMS_SERVICE_DELETE_NAMED_VARLIST;
            /* DeleteNamedVariableList-Response: NULL (empty) */
            service_len = 0;
            break;

        case MMS_SERVICE_TYPE_GET_NAMED_VARLIST_ATTRS:
            service_tag = MMS_SERVICE_GET_NAMED_VARLIST_ATTRS;
            /* GetNamedVariableListAttributes-Response */
            size_t attrs_offset = 0;

            /* listOfVariable [0] SEQUENCE OF VariableSpecification */
            service_buf[attrs_offset++] = 0xA0;  /* [0] IMPLICIT */
            size_t var_list_start = attrs_offset + 1;  /* Reserve for length */
            attrs_offset++;
            for (uint32_t i = 0; i < response->params.getnamedvarlistattrs.num_variables; i++) {
                service_buf[attrs_offset++] = 0xA0;  /* domain-specific [0] */
                size_t domain_len = strlen(response->params.getnamedvarlistattrs.variables[i].domain);
                size_t item_len = strlen(response->params.getnamedvarlistattrs.variables[i].item_id);
                service_buf[attrs_offset++] = (uint8_t)(1 + domain_len + 1 + item_len);
                service_buf[attrs_offset++] = (uint8_t)domain_len;
                memcpy(service_buf + attrs_offset, response->params.getnamedvarlistattrs.variables[i].domain, domain_len);
                attrs_offset += domain_len;
                service_buf[attrs_offset++] = (uint8_t)item_len;
                memcpy(service_buf + attrs_offset, response->params.getnamedvarlistattrs.variables[i].item_id, item_len);
                attrs_offset += item_len;
            }
            service_buf[var_list_start - 1] = (uint8_t)(attrs_offset - var_list_start);

            /* deletable [1] IMPLICIT BOOLEAN */
            service_buf[attrs_offset++] = 0x81;  /* [1] IMPLICIT */
            service_buf[attrs_offset++] = 0x01;
            service_buf[attrs_offset++] = response->params.getnamedvarlistattrs.deletable ? 0xFF : 0x00;

            service_len = attrs_offset;
            break;

        /* Phase 7: Control Services */
        case MMS_SERVICE_TYPE_SELECT:
            service_tag = MMS_SERVICE_SELECT;
            /* Select-Response: state [0], selectionID [1] */
            size_t sel_resp_offset = 0;
            /* state [0] IMPLICIT INTEGER */
            service_buf[sel_resp_offset++] = 0x80;  /* [0] IMPLICIT */
            service_buf[sel_resp_offset++] = 0x01;
            service_buf[sel_resp_offset++] = (uint8_t)response->params.select.state;
            /* selectionID [1] IMPLICIT INTEGER */
            service_buf[sel_resp_offset++] = 0x81;  /* [1] IMPLICIT */
            ret = encode_integer(response->params.select.selection_id, temp_buf, sizeof(temp_buf));
            if (ret < 0) return ret;
            service_buf[sel_resp_offset++] = (uint8_t)ret;
            memcpy(service_buf + sel_resp_offset, temp_buf, ret);
            sel_resp_offset += ret;
            service_len = sel_resp_offset;
            break;

        case MMS_SERVICE_TYPE_SELECT_WITH_VALUE:
            service_tag = MMS_SERVICE_SELECT_WITH_VALUE;
            /* SelectWithValue-Response: state [0], selectionID [1] */
            size_t swv_resp_offset = 0;
            /* state [0] IMPLICIT INTEGER */
            service_buf[swv_resp_offset++] = 0x80;  /* [0] IMPLICIT */
            service_buf[swv_resp_offset++] = 0x01;
            service_buf[swv_resp_offset++] = (uint8_t)response->params.select_with_value.state;
            /* selectionID [1] IMPLICIT INTEGER */
            service_buf[swv_resp_offset++] = 0x81;  /* [1] IMPLICIT */
            ret = encode_integer(response->params.select_with_value.selection_id, temp_buf, sizeof(temp_buf));
            if (ret < 0) return ret;
            service_buf[swv_resp_offset++] = (uint8_t)ret;
            memcpy(service_buf + swv_resp_offset, temp_buf, ret);
            swv_resp_offset += ret;
            service_len = swv_resp_offset;
            break;

        case MMS_SERVICE_TYPE_OPERATE:
            service_tag = MMS_SERVICE_OPERATE;
            /* Operate-Response: state [0], success [1] */
            size_t op_resp_offset = 0;
            /* state [0] IMPLICIT INTEGER */
            service_buf[op_resp_offset++] = 0x80;  /* [0] IMPLICIT */
            service_buf[op_resp_offset++] = 0x01;
            service_buf[op_resp_offset++] = (uint8_t)response->params.operate.state;
            /* success [1] IMPLICIT BOOLEAN */
            service_buf[op_resp_offset++] = 0x81;  /* [1] IMPLICIT */
            service_buf[op_resp_offset++] = 0x01;
            service_buf[op_resp_offset++] = response->params.operate.success ? 0xFF : 0x00;
            service_len = op_resp_offset;
            break;

        case MMS_SERVICE_TYPE_CANCEL:
            service_tag = MMS_SERVICE_CANCEL;
            /* Cancel-Response: empty (success indication) */
            service_len = 0;
            break;

        /* Phase 7 Week 2: File Services */
        case MMS_SERVICE_TYPE_FILE_OPEN:
            service_tag = MMS_SERVICE_FILE_OPEN;
            /* FileOpen-Response: fileHandle [0], fileSize [1] */
            size_t fileopen_resp_offset = 0;
            /* fileHandle [0] IMPLICIT INTEGER */
            service_buf[fileopen_resp_offset++] = 0x80;  /* [0] IMPLICIT */
            ret = encode_integer(response->params.fileopen.file_handle, temp_buf, sizeof(temp_buf));
            if (ret < 0) return ret;
            service_buf[fileopen_resp_offset++] = (uint8_t)ret;
            memcpy(service_buf + fileopen_resp_offset, temp_buf, ret);
            fileopen_resp_offset += ret;
            /* fileSize [1] IMPLICIT INTEGER (64-bit) */
            service_buf[fileopen_resp_offset++] = 0x81;  /* [1] IMPLICIT */
            /* Encode 64-bit file size as 8 bytes big-endian */
            service_buf[fileopen_resp_offset++] = 0x08;  /* Length = 8 */
            for (int i = 7; i >= 0; i--) {
                service_buf[fileopen_resp_offset++] = (uint8_t)((response->params.fileopen.file_size >> (i * 8)) & 0xFF);
            }
            service_len = fileopen_resp_offset;
            break;

        case MMS_SERVICE_TYPE_FILE_READ:
            service_tag = MMS_SERVICE_FILE_READ;
            /* FileRead-Response: data [0], moreFollows [1] */
            size_t fileread_resp_offset = 0;
            /* data [0] IMPLICIT OCTET STRING */
            service_buf[fileread_resp_offset++] = 0xA0;  /* [0] IMPLICIT */
            ret = mms_encode_length(response->params.fileread.bytes_read, service_buf + fileread_resp_offset, sizeof(service_buf) - fileread_resp_offset);
            if (ret < 0) return ret;
            fileread_resp_offset += ret;
            memcpy(service_buf + fileread_resp_offset, response->params.fileread.data, response->params.fileread.bytes_read);
            fileread_resp_offset += response->params.fileread.bytes_read;
            /* moreFollows [1] IMPLICIT BOOLEAN */
            service_buf[fileread_resp_offset++] = 0x81;  /* [1] IMPLICIT */
            service_buf[fileread_resp_offset++] = 0x01;
            service_buf[fileread_resp_offset++] = response->params.fileread.more_follows ? 0xFF : 0x00;
            service_len = fileread_resp_offset;
            break;

        case MMS_SERVICE_TYPE_FILE_CLOSE:
            service_tag = MMS_SERVICE_FILE_CLOSE;
            /* FileClose-Response: empty (success indication) */
            service_len = 0;
            break;

        case MMS_SERVICE_TYPE_FILE_DELETE:
            service_tag = MMS_SERVICE_FILE_DELETE;
            /* FileDelete-Response: empty (success indication) */
            service_len = 0;
            break;

        case MMS_SERVICE_TYPE_FILE_DIRECTORY:
            service_tag = MMS_SERVICE_FILE_DIRECTORY;
            /* FileDirectory-Response: entries [0], moreFollows [1] */
            size_t filedir_resp_offset = 0;
            /* entries [0] IMPLICIT SEQUENCE OF FileEntry */
            service_buf[filedir_resp_offset++] = 0xA0;  /* [0] IMPLICIT */
            size_t entries_start = filedir_resp_offset + 1;  /* Reserve for length */
            filedir_resp_offset++;
            for (uint32_t i = 0; i < response->params.filedirectory.num_entries; i++) {
                /* Each FileEntry: filename, fileSize, lastModified */
                /* filename VISIBLE STRING */
                size_t name_len = strlen(response->params.filedirectory.entries[i].filename);
                service_buf[filedir_resp_offset++] = (uint8_t)name_len;
                memcpy(service_buf + filedir_resp_offset, response->params.filedirectory.entries[i].filename, name_len);
                filedir_resp_offset += name_len;
                /* fileSize INTEGER (64-bit) */
                service_buf[filedir_resp_offset++] = 0x08;  /* Length = 8 */
                for (int j = 7; j >= 0; j--) {
                    service_buf[filedir_resp_offset++] = (uint8_t)((response->params.filedirectory.entries[i].file_size >> (j * 8)) & 0xFF);
                }
                /* lastModified INTEGER (64-bit) */
                service_buf[filedir_resp_offset++] = 0x08;  /* Length = 8 */
                for (int j = 7; j >= 0; j--) {
                    service_buf[filedir_resp_offset++] = (uint8_t)((response->params.filedirectory.entries[i].last_modified >> (j * 8)) & 0xFF);
                }
            }
            service_buf[entries_start - 1] = (uint8_t)(filedir_resp_offset - entries_start);
            /* moreFollows [1] IMPLICIT BOOLEAN */
            service_buf[filedir_resp_offset++] = 0x81;  /* [1] IMPLICIT */
            service_buf[filedir_resp_offset++] = 0x01;
            service_buf[filedir_resp_offset++] = response->params.filedirectory.more_follows ? 0xFF : 0x00;
            service_len = filedir_resp_offset;
            break;

        /* Phase 7 Week 3: Journal Services */
        case MMS_SERVICE_TYPE_READ_JOURNAL:
            service_tag = MMS_SERVICE_READ_JOURNAL;
            /* ReadJournal-Response: entries [0], moreFollows [1] */
            size_t readjournal_resp_offset = 0;

            /* Build entries in temporary buffer first */
            uint8_t entries_buf[MMS_MAX_PDU_SIZE];
            size_t entries_offset = 0;
            for (uint32_t i = 0; i < response->params.readjournal.num_entries; i++) {
                /* Each JournalEntry: entryID, timestamp, variableRef (optional), entryData */
                /* entryID INTEGER (64-bit) */
                entries_buf[entries_offset++] = 0x08;  /* Length = 8 */
                for (int j = 7; j >= 0; j--) {
                    entries_buf[entries_offset++] = (uint8_t)((response->params.readjournal.entries[i].entry_id >> (j * 8)) & 0xFF);
                }
                /* timestamp INTEGER (64-bit) */
                entries_buf[entries_offset++] = 0x08;  /* Length = 8 */
                for (int j = 7; j >= 0; j--) {
                    entries_buf[entries_offset++] = (uint8_t)((response->params.readjournal.entries[i].timestamp >> (j * 8)) & 0xFF);
                }
                /* variableRef [2] IMPLICIT VisibleString (optional) */
                if (strlen(response->params.readjournal.entries[i].variable_ref) > 0) {
                    entries_buf[entries_offset++] = 0xA2;  /* [2] IMPLICIT */
                    size_t varref_len = strlen(response->params.readjournal.entries[i].variable_ref);
                    entries_buf[entries_offset++] = (uint8_t)varref_len;
                    memcpy(entries_buf + entries_offset, response->params.readjournal.entries[i].variable_ref, varref_len);
                    entries_offset += varref_len;
                }
                /* entryData [3] IMPLICIT VisibleString */
                entries_buf[entries_offset++] = 0xA3;  /* [3] IMPLICIT */
                size_t entrydata_len = strlen(response->params.readjournal.entries[i].entry_data);
                entries_buf[entries_offset++] = (uint8_t)entrydata_len;
                memcpy(entries_buf + entries_offset, response->params.readjournal.entries[i].entry_data, entrydata_len);
                entries_offset += entrydata_len;
            }

            /* entries [0] IMPLICIT SEQUENCE OF JournalEntry */
            service_buf[readjournal_resp_offset++] = 0xA0;  /* [0] IMPLICIT */
            ret = mms_encode_length(entries_offset, service_buf + readjournal_resp_offset, sizeof(service_buf) - readjournal_resp_offset);
            if (ret < 0) return ret;
            readjournal_resp_offset += ret;
            memcpy(service_buf + readjournal_resp_offset, entries_buf, entries_offset);
            readjournal_resp_offset += entries_offset;

            /* moreFollows [1] IMPLICIT BOOLEAN */
            service_buf[readjournal_resp_offset++] = 0x81;  /* [1] IMPLICIT */
            service_buf[readjournal_resp_offset++] = 0x01;
            service_buf[readjournal_resp_offset++] = response->params.readjournal.more_follows ? 0xFF : 0x00;
            service_len = readjournal_resp_offset;
            break;

        case MMS_SERVICE_TYPE_INITIALIZE_JOURNAL:
            service_tag = MMS_SERVICE_INITIALIZE_JOURNAL;
            /* InitializeJournal-Response: empty (success indication) */
            service_len = 0;
            break;

        /* Phase 7 Week 4: Type Services */
        case MMS_SERVICE_TYPE_DEFINE_NAMED_TYPE:
            service_tag = MMS_SERVICE_DEFINE_NAMED_TYPE;
            /* DefineNamedType-Response: empty (success indication) */
            service_len = 0;
            break;

        case MMS_SERVICE_TYPE_DELETE_NAMED_TYPE:
            service_tag = MMS_SERVICE_DELETE_NAMED_TYPE;
            /* DeleteNamedType-Response: empty (success indication) */
            service_len = 0;
            break;

        case MMS_SERVICE_TYPE_GET_NAMED_TYPE_ATTRS:
            service_tag = MMS_SERVICE_GET_NAMED_TYPE_ATTRS;
            /* GetNamedTypeAttributes-Response: typeSpec [0] IMPLICIT INTEGER */
            service_buf[0] = 0x80;  /* [0] IMPLICIT */
            service_buf[1] = 0x01;  /* Length = 1 */
            service_buf[2] = (uint8_t)response->params.getnamedtypeattrs.type_spec;
            service_len = 3;
            break;

        default:
            return MMS_ERROR_NOT_SUPPORTED;
    }

    /* Add service to content */
    content[content_offset++] = service_tag;
    ret = mms_encode_length(service_len, content + content_offset, sizeof(content) - content_offset);
    if (ret < 0) {
        return ret;
    }
    content_offset += ret;
    memcpy(content + content_offset, service_buf, service_len);
    content_offset += service_len;

    /* Encode length of entire Confirmed-Response */
    ret = mms_encode_length(content_offset, buffer + offset, buflen - offset);
    if (ret < 0) {
        return ret;
    }
    offset += ret;

    /* Copy content */
    if (!has_space(offset, content_offset, buflen)) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(buffer + offset, content, content_offset);
    offset += content_offset;

    return (int)offset;
}

int mms_decode_confirmed_response(const uint8_t* buffer, size_t buflen,
                                  mms_confirmed_response_t* response) {
    if (buffer == NULL || response == NULL || buflen < 2) {
        return MMS_ERROR_INVALID_PARAM;
    }

    size_t offset = 0;

    /* Check tag */
    if (buffer[offset++] != MMS_TAG_CONFIRMED_RESPONSE) {
        return MMS_ERROR_INVALID_ENCODING;
    }

    /* Decode length */
    size_t length;
    int ret = mms_decode_length(buffer + offset, buflen - offset, &length);
    if (ret < 0) {
        return ret;
    }
    offset += ret;

    size_t end = offset + length;

    /* invokeID — accept both [0] IMPLICIT (0x80) and UNIVERSAL INTEGER (0x02) */
    if (offset >= end) {
        return MMS_ERROR_INVALID_ENCODING;
    }
    if (buffer[offset] != 0x80 && buffer[offset] != 0x02) {
        return MMS_ERROR_INVALID_ENCODING;
    }
    offset++;

    size_t field_len;
    ret = mms_decode_length(buffer + offset, buflen - offset, &field_len);
    if (ret < 0) {
        return ret;
    }
    offset += ret;

    ret = decode_integer(buffer + offset, field_len, (int32_t*)&response->invoke_id);
    if (ret < 0) {
        return ret;
    }
    offset += field_len;

    /* Service CHOICE */
    if (offset >= end) {
        return MMS_ERROR_INVALID_ENCODING;
    }

    uint8_t raw_service_tag = buffer[offset++];
    /* Normalize: set the constructed bit so both 0x8x and 0xAx match.
     * Response Identify uses 0xA2 (constructed SEQUENCE), so no exception for tag 2.
     * Exceptions: 0x80 (STATUS), 0x90 (FILE_CLOSE). */
    uint8_t tag_num = raw_service_tag & 0x1F;
    uint8_t service_tag = raw_service_tag;
    if (tag_num != 0 && raw_service_tag != 0x90) {
        service_tag = raw_service_tag | 0x20;
    }
    ret = mms_decode_length(buffer + offset, buflen - offset, &field_len);
    if (ret < 0) {
        return ret;
    }
    offset += ret;

    switch (service_tag) {
        case 0xA2:  /* Identify response [2] CONSTRUCTED */
            response->service = MMS_SERVICE_TYPE_IDENTIFY;
            {
                size_t id_end = offset + field_len;
                /* Parse [0] vendorName, [1] modelName, [2] revision */
                while (offset < id_end) {
                    uint8_t id_tag = buffer[offset++];
                    size_t id_len;
                    ret = mms_decode_length(buffer + offset, buflen - offset, &id_len);
                    if (ret < 0) return ret;
                    offset += ret;
                    switch (id_tag) {
                        case 0x80:
                            if (id_len < MMS_MAX_VARIABLE_NAME) {
                                memcpy(response->params.identify.vendor_name,
                                       buffer + offset, id_len);
                                response->params.identify.vendor_name[id_len] = '\0';
                            }
                            break;
                        case 0x81:
                            if (id_len < MMS_MAX_VARIABLE_NAME) {
                                memcpy(response->params.identify.model_name,
                                       buffer + offset, id_len);
                                response->params.identify.model_name[id_len] = '\0';
                            }
                            break;
                        case 0x82:
                            if (id_len < MMS_MAX_VARIABLE_NAME) {
                                memcpy(response->params.identify.revision,
                                       buffer + offset, id_len);
                                response->params.identify.revision[id_len] = '\0';
                            }
                            break;
                        default:
                            break;
                    }
                    offset += id_len;
                }
            }
            break;

        case MMS_SERVICE_READ:
            /* Read can be either single value or named variable list */
            /* Decode listOfAccessResult [1] IMPLICIT SEQUENCE */
            if (buffer[offset] == 0xA1) {
                offset++;
                size_t result_len;
                ret = mms_decode_length(buffer + offset, buflen - offset, &result_len);
                if (ret < 0) {
                    return ret;
                }
                offset += ret;
                size_t result_end = offset + result_len;

                /* Check for AccessResult failure [0] */
                if (offset < result_end && buffer[offset] == 0x80) {
                    /* failure [0] IMPLICIT INTEGER — data access error */
                    response->service = MMS_SERVICE_TYPE_READ;
                    offset = result_end;
                    return MMS_ERROR_SERVICE_ERROR;
                }

                /* Try to decode multiple values (ReadNamedVariableList) */
                uint32_t num_values = 0;
                size_t temp_offset = offset;
                while (temp_offset < result_end && num_values < MMS_MAX_NAMED_VARIABLES) {
                    ret = mms_decode_value(buffer + temp_offset, result_end - temp_offset,
                                         &response->params.readnamedvarlist.values[num_values]);
                    if (ret < 0) {
                        break;  /* Not a valid value, might be single value */
                    }
                    temp_offset += ret;
                    num_values++;
                }

                /* Determine if it's a single Read or ReadNamedVariableList */
                if (num_values == 1 && temp_offset == result_end) {
                    /* Single value - regular Read */
                    response->service = MMS_SERVICE_TYPE_READ;
                    response->params.read.value = response->params.readnamedvarlist.values[0];
                    offset = temp_offset;
                } else if (num_values > 0) {
                    /* Multiple values - ReadNamedVariableList */
                    response->service = MMS_SERVICE_TYPE_READ_NAMED_VARLIST;
                    response->params.readnamedvarlist.num_values = num_values;
                    offset = temp_offset;
                } else {
                    /* Failed to decode — unknown content */
                    response->service = MMS_SERVICE_TYPE_READ;
                    offset = result_end;
                    return MMS_ERROR_SERVICE_ERROR;
                }
            } else {
                response->service = MMS_SERVICE_TYPE_READ;
                offset += field_len;
            }
            break;

        case MMS_SERVICE_WRITE:
            /* Write response is empty for both Write and WriteNamedVariableList */
            response->service = MMS_SERVICE_TYPE_WRITE;
            /* Note: Cannot distinguish Write vs WriteNamedVariableList from response alone */
            /* Client must track which type of request was sent */
            offset += field_len;
            break;

        case MMS_SERVICE_GET_NAMELIST:
            response->service = MMS_SERVICE_TYPE_GET_NAMELIST;
            /* GetNameList-Response: listOfIdentifier [0] */
            {
                size_t gnlr_end = offset + field_len;
                if (offset < gnlr_end && buffer[offset] == 0xA0) {
                    offset++;
                    size_t list_len;
                    ret = mms_decode_length(buffer + offset, buflen - offset, &list_len);
                    if (ret < 0) return ret;
                    offset += ret;

                    size_t list_end = offset + list_len;
                    response->params.getnamelist.num_identifiers = 0;
                    while (offset < list_end && response->params.getnamelist.num_identifiers < MMS_MAX_NAMED_VARIABLES) {
                        uint32_t ni = response->params.getnamelist.num_identifiers;
                        /* Skip VisibleString tag (0x1A) if present */
                        if (buffer[offset] == 0x1A) {
                            offset++;
                        }
                        size_t name_len = buffer[offset++];
                        if (name_len >= MMS_MAX_VARIABLE_NAME) {
                            offset += name_len;
                            continue;
                        }
                        memcpy(response->params.getnamelist.identifiers[ni], buffer + offset, name_len);
                        response->params.getnamelist.identifiers[ni][name_len] = '\0';
                        offset += name_len;
                        response->params.getnamelist.num_identifiers++;
                    }
                }
                /* moreFollows [1] IMPLICIT BOOLEAN (optional, default TRUE) */
                response->params.getnamelist.more_follows = true;  /* default */
                if (offset < gnlr_end && buffer[offset] == 0x81) {
                    offset++;
                    size_t mf_len;
                    ret = mms_decode_length(buffer + offset, gnlr_end - offset, &mf_len);
                    if (ret > 0) {
                        offset += ret;
                        if (mf_len >= 1) {
                            response->params.getnamelist.more_follows = (buffer[offset] != 0);
                        }
                    }
                }
                offset = gnlr_end;
            }
            break;

        case MMS_SERVICE_GET_VARIABLE_ATTRS:
            response->service = MMS_SERVICE_TYPE_GET_VARIABLE_ATTRS;
            /* GetVariableAccessAttributes-Response: name [0], typeDescription [1] */
            {
                size_t gvar_end = offset + field_len;
                while (offset < gvar_end) {
                    uint8_t tag = buffer[offset++];
                    size_t tag_len;
                    ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
                    if (ret < 0) return ret;
                    offset += ret;

                    switch (tag) {
                        case 0xA0: { /* name [0] IMPLICIT VisibleString */
                            if (tag_len >= MMS_MAX_VARIABLE_NAME) {
                                return MMS_ERROR_BUFFER_TOO_SMALL;
                            }
                            memcpy(response->params.getvariableattrs.attributes.name, buffer + offset, tag_len);
                            response->params.getvariableattrs.attributes.name[tag_len] = '\0';
                            offset += tag_len;
                            break;
                        }
                        case 0x81:  /* typeDescription [1] IMPLICIT INTEGER */
                            response->params.getvariableattrs.attributes.type = (mms_type_t)buffer[offset];
                            offset += tag_len;
                            break;
                        default:
                            offset += tag_len;
                            break;
                    }
                }
            }
            break;

        case MMS_SERVICE_DEFINE_NAMED_VARLIST:
            response->service = MMS_SERVICE_TYPE_DEFINE_NAMED_VARLIST;
            /* DefineNamedVariableList-Response: empty (success) */
            offset += field_len;
            break;

        case MMS_SERVICE_DELETE_NAMED_VARLIST:
            response->service = MMS_SERVICE_TYPE_DELETE_NAMED_VARLIST;
            /* DeleteNamedVariableList-Response: empty (success) */
            offset += field_len;
            break;

        case MMS_SERVICE_GET_NAMED_VARLIST_ATTRS:
            response->service = MMS_SERVICE_TYPE_GET_NAMED_VARLIST_ATTRS;
            /* GetNamedVariableListAttributes-Response:
               listOfVariable [0] + deletable [1] */
            {
                size_t gva_end = offset + field_len;
                if (offset < gva_end && buffer[offset] == 0xA0) {
                    offset++;
                    size_t gva_list_len;
                    ret = mms_decode_length(buffer + offset, buflen - offset, &gva_list_len);
                    if (ret < 0) return ret;
                    offset += ret;

                    size_t gva_list_end = offset + gva_list_len;
                    response->params.getnamedvarlistattrs.num_variables = 0;
                    while (offset < gva_list_end && response->params.getnamedvarlistattrs.num_variables < MMS_MAX_NAMED_VARIABLES) {
                        uint32_t vi = response->params.getnamedvarlistattrs.num_variables;
                        if (buffer[offset] == 0xA0) {
                            offset++;
                            size_t vs_len;
                            ret = mms_decode_length(buffer + offset, buflen - offset, &vs_len);
                            if (ret < 0) return ret;
                            offset += ret;

                            size_t gva_dom_len = buffer[offset++];
                            if (gva_dom_len < MMS_MAX_DOMAIN_NAME) {
                                memcpy(response->params.getnamedvarlistattrs.variables[vi].domain, buffer + offset, gva_dom_len);
                                response->params.getnamedvarlistattrs.variables[vi].domain[gva_dom_len] = '\0';
                            }
                            offset += gva_dom_len;

                            size_t gva_item_len = buffer[offset++];
                            if (gva_item_len < MMS_MAX_VARIABLE_NAME) {
                                memcpy(response->params.getnamedvarlistattrs.variables[vi].item_id, buffer + offset, gva_item_len);
                                response->params.getnamedvarlistattrs.variables[vi].item_id[gva_item_len] = '\0';
                            }
                            offset += gva_item_len;

                            response->params.getnamedvarlistattrs.num_variables++;
                        } else {
                            break;
                        }
                    }
                }
                /* deletable [1] IMPLICIT BOOLEAN (optional) */
                if (offset < gva_end && buffer[offset] == 0x81) {
                    offset++;
                    size_t del_len;
                    ret = mms_decode_length(buffer + offset, buflen - offset, &del_len);
                    if (ret < 0) return ret;
                    offset += ret;
                    response->params.getnamedvarlistattrs.deletable = (buffer[offset] != 0);
                    offset += del_len;
                }
                offset = gva_end;
            }
            break;

        /* Phase 7: Control Services Response Decoding */
        case MMS_SERVICE_SELECT:
            response->service = MMS_SERVICE_TYPE_SELECT;
            /* Decode state [0], selectionID [1] */
            size_t sel_resp_end = offset + field_len;
            while (offset < sel_resp_end) {
                uint8_t tag = buffer[offset++];
                size_t tag_len;
                ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
                if (ret < 0) return ret;
                offset += ret;

                switch (tag) {
                    case 0x80:  /* state [0] IMPLICIT */
                        response->params.select.state = (mms_control_state_t)buffer[offset];
                        offset += tag_len;
                        break;

                    case 0x81:  /* selectionID [1] IMPLICIT */
                        ret = decode_integer(buffer + offset, tag_len, (int32_t*)&response->params.select.selection_id);
                        if (ret < 0) return ret;
                        offset += tag_len;
                        break;

                    default:
                        /* Skip unknown fields */
                        offset += tag_len;
                        break;
                }
            }
            break;

        case MMS_SERVICE_SELECT_WITH_VALUE:
            response->service = MMS_SERVICE_TYPE_SELECT_WITH_VALUE;
            /* Decode state [0], selectionID [1] */
            size_t swv_resp_end = offset + field_len;
            while (offset < swv_resp_end) {
                uint8_t tag = buffer[offset++];
                size_t tag_len;
                ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
                if (ret < 0) return ret;
                offset += ret;

                switch (tag) {
                    case 0x80:  /* state [0] IMPLICIT */
                        response->params.select_with_value.state = (mms_control_state_t)buffer[offset];
                        offset += tag_len;
                        break;

                    case 0x81:  /* selectionID [1] IMPLICIT */
                        ret = decode_integer(buffer + offset, tag_len, (int32_t*)&response->params.select_with_value.selection_id);
                        if (ret < 0) return ret;
                        offset += tag_len;
                        break;

                    default:
                        /* Skip unknown fields */
                        offset += tag_len;
                        break;
                }
            }
            break;

        case MMS_SERVICE_OPERATE:
            response->service = MMS_SERVICE_TYPE_OPERATE;
            /* Decode state [0], success [1] */
            size_t op_resp_end = offset + field_len;
            while (offset < op_resp_end) {
                uint8_t tag = buffer[offset++];
                size_t tag_len;
                ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
                if (ret < 0) return ret;
                offset += ret;

                switch (tag) {
                    case 0x80:  /* state [0] IMPLICIT */
                        response->params.operate.state = (mms_control_state_t)buffer[offset];
                        offset += tag_len;
                        break;

                    case 0x81:  /* success [1] IMPLICIT */
                        response->params.operate.success = (buffer[offset] != 0);
                        offset += tag_len;
                        break;

                    default:
                        /* Skip unknown fields */
                        offset += tag_len;
                        break;
                }
            }
            break;

        case MMS_SERVICE_CANCEL:
            response->service = MMS_SERVICE_TYPE_CANCEL;
            /* Cancel-Response: empty (success indication) */
            offset += field_len;
            break;

        /* Phase 7 Week 2: File Services Response Decoding */
        case MMS_SERVICE_FILE_OPEN:
            response->service = MMS_SERVICE_TYPE_FILE_OPEN;
            /* Decode fileHandle [0], fileSize [1] */
            size_t fileopen_resp_end = offset + field_len;
            while (offset < fileopen_resp_end) {
                uint8_t tag = buffer[offset++];
                size_t tag_len;
                ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
                if (ret < 0) return ret;
                offset += ret;

                switch (tag) {
                    case 0x80:  /* fileHandle [0] IMPLICIT */
                        ret = decode_integer(buffer + offset, tag_len, (int32_t*)&response->params.fileopen.file_handle);
                        if (ret < 0) return ret;
                        offset += tag_len;
                        break;

                    case 0x81:  /* fileSize [1] IMPLICIT (64-bit) */
                        if (tag_len != 8) {
                            return MMS_ERROR_INVALID_ENCODING;
                        }
                        response->params.fileopen.file_size = 0;
                        for (size_t i = 0; i < 8; i++) {
                            response->params.fileopen.file_size = (response->params.fileopen.file_size << 8) | buffer[offset + i];
                        }
                        offset += tag_len;
                        break;

                    default:
                        /* Skip unknown fields */
                        offset += tag_len;
                        break;
                }
            }
            break;

        case MMS_SERVICE_FILE_READ:
            response->service = MMS_SERVICE_TYPE_FILE_READ;
            /* Decode data [0], moreFollows [1] */
            size_t fileread_resp_end = offset + field_len;
            while (offset < fileread_resp_end) {
                uint8_t tag = buffer[offset++];
                size_t tag_len;
                ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
                if (ret < 0) return ret;
                offset += ret;

                switch (tag) {
                    case 0xA0: { /* data [0] IMPLICIT OCTET STRING */
                        if (tag_len > MMS_MAX_PDU_SIZE) {
                            return MMS_ERROR_BUFFER_TOO_SMALL;
                        }
                        memcpy(response->params.fileread.data, buffer + offset, tag_len);
                        response->params.fileread.bytes_read = (uint32_t)tag_len;
                        offset += tag_len;
                        break;
                    }

                    case 0x81:  /* moreFollows [1] IMPLICIT BOOLEAN */
                        response->params.fileread.more_follows = (buffer[offset] != 0);
                        offset += tag_len;
                        break;

                    default:
                        /* Skip unknown fields */
                        offset += tag_len;
                        break;
                }
            }
            break;

        case MMS_SERVICE_FILE_CLOSE:
            response->service = MMS_SERVICE_TYPE_FILE_CLOSE;
            /* FileClose-Response: empty (success indication) */
            offset += field_len;
            break;

        case MMS_SERVICE_FILE_DELETE:
            response->service = MMS_SERVICE_TYPE_FILE_DELETE;
            /* FileDelete-Response: empty (success indication) */
            offset += field_len;
            break;

        case MMS_SERVICE_FILE_DIRECTORY:
            response->service = MMS_SERVICE_TYPE_FILE_DIRECTORY;
            /* Decode entries [0], moreFollows [1] */
            response->params.filedirectory.num_entries = 0;
            size_t filedir_resp_end = offset + field_len;
            while (offset < filedir_resp_end) {
                uint8_t tag = buffer[offset++];
                size_t tag_len;
                ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
                if (ret < 0) return ret;
                offset += ret;

                switch (tag) {
                    case 0xA0: { /* entries [0] IMPLICIT SEQUENCE OF FileEntry */
                        size_t entries_end = offset + tag_len;
                        while (offset < entries_end && response->params.filedirectory.num_entries < MMS_MAX_NAMELIST_ITEMS) {
                            uint32_t entry_idx = response->params.filedirectory.num_entries;

                            /* filename VISIBLE STRING */
                            size_t name_len = buffer[offset++];
                            if (name_len >= MMS_MAX_VARIABLE_NAME) {
                                return MMS_ERROR_BUFFER_TOO_SMALL;
                            }
                            memcpy(response->params.filedirectory.entries[entry_idx].filename, buffer + offset, name_len);
                            response->params.filedirectory.entries[entry_idx].filename[name_len] = '\0';
                            offset += name_len;

                            /* fileSize INTEGER (64-bit) */
                            size_t size_len = buffer[offset++];
                            if (size_len != 8) {
                                return MMS_ERROR_INVALID_ENCODING;
                            }
                            response->params.filedirectory.entries[entry_idx].file_size = 0;
                            for (size_t i = 0; i < 8; i++) {
                                response->params.filedirectory.entries[entry_idx].file_size =
                                    (response->params.filedirectory.entries[entry_idx].file_size << 8) | buffer[offset + i];
                            }
                            offset += 8;

                            /* lastModified INTEGER (64-bit) */
                            size_t time_len = buffer[offset++];
                            if (time_len != 8) {
                                return MMS_ERROR_INVALID_ENCODING;
                            }
                            response->params.filedirectory.entries[entry_idx].last_modified = 0;
                            for (size_t i = 0; i < 8; i++) {
                                response->params.filedirectory.entries[entry_idx].last_modified =
                                    (response->params.filedirectory.entries[entry_idx].last_modified << 8) | buffer[offset + i];
                            }
                            offset += 8;

                            response->params.filedirectory.num_entries++;
                        }
                        break;
                    }

                    case 0x81:  /* moreFollows [1] IMPLICIT BOOLEAN */
                        response->params.filedirectory.more_follows = (buffer[offset] != 0);
                        offset += tag_len;
                        break;

                    default:
                        /* Skip unknown fields */
                        offset += tag_len;
                        break;
                }
            }
            break;

        /* Phase 7 Week 3: Journal Services Response Decoding */
        case MMS_SERVICE_READ_JOURNAL:
            response->service = MMS_SERVICE_TYPE_READ_JOURNAL;
            /* Decode entries [0], moreFollows [1] */
            response->params.readjournal.num_entries = 0;
            size_t readjournal_resp_end = offset + field_len;
            while (offset < readjournal_resp_end) {
                uint8_t tag = buffer[offset++];
                size_t tag_len;
                ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
                if (ret < 0) return ret;
                offset += ret;

                switch (tag) {
                    case 0xA0: { /* entries [0] IMPLICIT SEQUENCE OF JournalEntry */
                        size_t entries_end = offset + tag_len;
                        while (offset < entries_end && response->params.readjournal.num_entries < MMS_MAX_JOURNAL_ENTRIES) {
                            uint32_t entry_idx = response->params.readjournal.num_entries;

                            /* entryID INTEGER (64-bit) */
                            size_t id_len = buffer[offset++];
                            if (id_len != 8) {
                                return MMS_ERROR_INVALID_ENCODING;
                            }
                            response->params.readjournal.entries[entry_idx].entry_id = 0;
                            for (size_t i = 0; i < 8; i++) {
                                response->params.readjournal.entries[entry_idx].entry_id =
                                    (response->params.readjournal.entries[entry_idx].entry_id << 8) | buffer[offset + i];
                            }
                            offset += 8;

                            /* timestamp INTEGER (64-bit) */
                            size_t time_len = buffer[offset++];
                            if (time_len != 8) {
                                return MMS_ERROR_INVALID_ENCODING;
                            }
                            response->params.readjournal.entries[entry_idx].timestamp = 0;
                            for (size_t i = 0; i < 8; i++) {
                                response->params.readjournal.entries[entry_idx].timestamp =
                                    (response->params.readjournal.entries[entry_idx].timestamp << 8) | buffer[offset + i];
                            }
                            offset += 8;

                            /* variableRef [2] IMPLICIT VisibleString (optional) */
                            response->params.readjournal.entries[entry_idx].variable_ref[0] = '\0';
                            if (offset < entries_end && buffer[offset] == 0xA2) {
                                offset++;  /* Skip tag */
                                size_t varref_len = buffer[offset++];
                                if (varref_len >= MMS_MAX_VARIABLE_NAME) {
                                    return MMS_ERROR_BUFFER_TOO_SMALL;
                                }
                                memcpy(response->params.readjournal.entries[entry_idx].variable_ref, buffer + offset, varref_len);
                                response->params.readjournal.entries[entry_idx].variable_ref[varref_len] = '\0';
                                offset += varref_len;
                            }

                            /* entryData [3] IMPLICIT VisibleString */
                            if (offset >= entries_end || buffer[offset++] != 0xA3) {
                                return MMS_ERROR_INVALID_ENCODING;
                            }
                            size_t data_len = buffer[offset++];
                            if (data_len >= MMS_MAX_STRING_LENGTH) {
                                return MMS_ERROR_BUFFER_TOO_SMALL;
                            }
                            memcpy(response->params.readjournal.entries[entry_idx].entry_data, buffer + offset, data_len);
                            response->params.readjournal.entries[entry_idx].entry_data[data_len] = '\0';
                            offset += data_len;

                            response->params.readjournal.num_entries++;
                        }
                        break;
                    }

                    case 0x81:  /* moreFollows [1] IMPLICIT BOOLEAN */
                        response->params.readjournal.more_follows = (buffer[offset] != 0);
                        offset += tag_len;
                        break;

                    default:
                        /* Skip unknown fields */
                        offset += tag_len;
                        break;
                }
            }
            break;

        case MMS_SERVICE_INITIALIZE_JOURNAL:
            response->service = MMS_SERVICE_TYPE_INITIALIZE_JOURNAL;
            /* InitializeJournal-Response: empty (success indication) */
            offset += field_len;
            break;

        /* Phase 7 Week 4: Type Services Response Decoding */
        case MMS_SERVICE_DEFINE_NAMED_TYPE:
            response->service = MMS_SERVICE_TYPE_DEFINE_NAMED_TYPE;
            /* DefineNamedType-Response: empty (success indication) */
            offset += field_len;
            break;

        case MMS_SERVICE_DELETE_NAMED_TYPE:
            response->service = MMS_SERVICE_TYPE_DELETE_NAMED_TYPE;
            /* DeleteNamedType-Response: empty (success indication) */
            offset += field_len;
            break;

        case MMS_SERVICE_GET_NAMED_TYPE_ATTRS:
            response->service = MMS_SERVICE_TYPE_GET_NAMED_TYPE_ATTRS;
            /* GetNamedTypeAttributes-Response: typeSpec [0] IMPLICIT INTEGER */
            size_t gettypeattrs_resp_end = offset + field_len;
            while (offset < gettypeattrs_resp_end) {
                uint8_t tag = buffer[offset++];
                size_t tag_len;
                ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
                if (ret < 0) return ret;
                offset += ret;

                switch (tag) {
                    case 0x80:  /* typeSpec [0] IMPLICIT */
                        response->params.getnamedtypeattrs.type_spec = (mms_type_t)buffer[offset];
                        offset += tag_len;
                        break;

                    default:
                        /* Skip unknown fields */
                        offset += tag_len;
                        break;
                }
            }
            break;

        default:
            return MMS_ERROR_NOT_SUPPORTED;
    }

    return (int)offset;
}

int mms_encode_confirmed_error(const mms_confirmed_error_t* error,
                               uint8_t* buffer, size_t buflen) {
    if (error == NULL || buffer == NULL) {
        return MMS_ERROR_INVALID_PARAM;
    }

    if (buflen < 10) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }

    size_t offset = 0;

    /* Confirmed-ErrorPDU [2] IMPLICIT */
    buffer[offset++] = MMS_TAG_CONFIRMED_ERROR;

    /* Build content */
    buffer[offset++] = 0x08;  /* Length placeholder */

    /* invokeID [0] IMPLICIT */
    buffer[offset++] = 0x80;
    buffer[offset++] = 0x01;
    buffer[offset++] = (uint8_t)error->invoke_id;

    /* serviceError [1] IMPLICIT ServiceError */
    buffer[offset++] = 0xA1;
    buffer[offset++] = 0x03;

    /* errorClass CHOICE */
    buffer[offset++] = 0x80 | (uint8_t)error->error.error_class;
    buffer[offset++] = 0x01;
    buffer[offset++] = (uint8_t)error->error.error_code;

    /* Update length */
    buffer[1] = (uint8_t)(offset - 2);

    return (int)offset;
}

int mms_decode_confirmed_error(const uint8_t* buffer, size_t buflen,
                               mms_confirmed_error_t* error) {
    if (buffer == NULL || error == NULL || buflen < 2) {
        return MMS_ERROR_INVALID_PARAM;
    }

    size_t offset = 0;

    /* Check tag */
    if (buffer[offset++] != MMS_TAG_CONFIRMED_ERROR) {
        return MMS_ERROR_INVALID_ENCODING;
    }

    /* Decode outer length */
    size_t outer_length;
    int ret = mms_decode_length(buffer + offset, buflen - offset, &outer_length);
    if (ret < 0) {
        return ret;
    }
    offset += ret;
    size_t end = offset + outer_length;

    /* Parse TLV fields */
    while (offset < end && offset < buflen) {
        uint8_t tag = buffer[offset++];
        size_t field_len;
        ret = mms_decode_length(buffer + offset, buflen - offset, &field_len);
        if (ret < 0) return ret;
        offset += ret;

        switch (tag) {
            case 0x80:  /* invokeID [0] IMPLICIT */
                if (field_len <= 4) {
                    error->invoke_id = 0;
                    for (size_t i = 0; i < field_len; i++) {
                        error->invoke_id = (error->invoke_id << 8) | buffer[offset + i];
                    }
                }
                offset += field_len;
                break;

            case 0xA1: {  /* serviceError [1] IMPLICIT */
                size_t se_end = offset + field_len;
                while (offset < se_end) {
                    uint8_t se_tag = buffer[offset++];
                    size_t se_len;
                    ret = mms_decode_length(buffer + offset, buflen - offset, &se_len);
                    if (ret < 0) return ret;
                    offset += ret;

                    /* Error class is encoded as context-specific tag with class value */
                    error->error.error_class = (mms_error_class_t)(se_tag & 0x1F);
                    if (se_len > 0) {
                        error->error.error_code = (int32_t)buffer[offset];
                    }
                    offset += se_len;
                }
                break;
            }

            default:
                /* Skip unknown fields */
                offset += field_len;
                break;
        }
    }

    return (int)offset;
}

/* ============================================================================
 * InformationReport (Unconfirmed Service)
 * ============================================================================ */

int mms_encode_information_report(const mms_information_report_t* report,
                                  uint8_t* buffer, size_t buflen) {
    if (report == NULL || buffer == NULL) {
        return MMS_ERROR_INVALID_PARAM;
    }

    size_t offset = 0;

    /* Unconfirmed-PDU [3] IMPLICIT */
    if (!has_space(offset, 1, buflen)) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }
    buffer[offset++] = MMS_TAG_UNCONFIRMED;

    /* Build content in temporary buffer */
    uint8_t content[MMS_MAX_PDU_SIZE];
    size_t content_offset = 0;

    /* InformationReport service (tag 0x80) */
    content[content_offset++] = 0x80;  /* [0] IMPLICIT */

    /* Build InformationReport content */
    uint8_t report_buf[MMS_MAX_PDU_SIZE];
    size_t report_offset = 0;

    /* variableAccessSpecification [0] VariableAccessSpecification */
    report_buf[report_offset++] = 0xA0;  /* [0] IMPLICIT - listOfVariable */
    size_t varlist_start = report_offset + 1;
    report_offset++;

    /* For simplicity, use variable list name as a single identifier */
    /* In full implementation, this would reference a named variable list */
    size_t list_name_len = strlen(report->variable_list_name);
    report_buf[report_offset++] = (uint8_t)list_name_len;
    memcpy(report_buf + report_offset, report->variable_list_name, list_name_len);
    report_offset += list_name_len;

    report_buf[varlist_start - 1] = (uint8_t)(report_offset - varlist_start);

    /* listOfAccessResult [1] SEQUENCE OF AccessResult */
    report_buf[report_offset++] = 0xA1;  /* [1] IMPLICIT */
    size_t results_start = report_offset + 1;
    report_offset++;

    /* Encode each value */
    for (uint32_t i = 0; i < report->num_values; i++) {
        int ret = mms_encode_value(&report->values[i],
                                  report_buf + report_offset,
                                  sizeof(report_buf) - report_offset);
        if (ret < 0) {
            return ret;
        }
        report_offset += ret;
    }

    report_buf[results_start - 1] = (uint8_t)(report_offset - results_start);

    /* Optional report fields (IEC 61850-8-1 RCB) */
    /* sq_num [2] IMPLICIT UNSIGNED */
    if (report->sq_num_present) {
        report_buf[report_offset++] = 0x82;  /* [2] IMPLICIT */
        uint8_t temp_buf[8];
        int sq_ret = encode_unsigned(report->sq_num, temp_buf, sizeof(temp_buf));
        if (sq_ret < 0) return sq_ret;
        report_buf[report_offset++] = (uint8_t)sq_ret;
        memcpy(report_buf + report_offset, temp_buf, sq_ret);
        report_offset += sq_ret;
    }

    /* report_timestamp [3] IMPLICIT INTEGER (64-bit UTC ms) */
    if (report->report_timestamp_present) {
        report_buf[report_offset++] = 0x83;  /* [3] IMPLICIT */
        report_buf[report_offset++] = 0x08;  /* Length = 8 */
        for (int i = 7; i >= 0; i--) {
            report_buf[report_offset++] = (uint8_t)((report->report_timestamp >> (i * 8)) & 0xFF);
        }
    }

    /* reasons [4] IMPLICIT SEQUENCE OF INTEGER */
    if (report->reasons_present) {
        report_buf[report_offset++] = 0xA4;  /* [4] IMPLICIT CONSTRUCTED */
        size_t reasons_start = report_offset + 1;
        report_offset++;
        for (uint32_t i = 0; i < report->num_values; i++) {
            report_buf[report_offset++] = report->reasons[i];
        }
        report_buf[reasons_start - 1] = (uint8_t)(report_offset - reasons_start);
    }

    /* buffer_overflow [5] IMPLICIT BOOLEAN */
    if (report->buffer_overflow_present) {
        report_buf[report_offset++] = 0x85;  /* [5] IMPLICIT */
        report_buf[report_offset++] = 0x01;
        report_buf[report_offset++] = report->buffer_overflow ? 0xFF : 0x00;
    }

    /* entry_id [6] IMPLICIT INTEGER (64-bit) */
    if (report->entry_id_present) {
        report_buf[report_offset++] = 0x86;  /* [6] IMPLICIT */
        report_buf[report_offset++] = 0x08;  /* Length = 8 */
        for (int i = 7; i >= 0; i--) {
            report_buf[report_offset++] = (uint8_t)((report->entry_id >> (i * 8)) & 0xFF);
        }
    }

    /* config_ref [7] IMPLICIT VisibleString */
    if (report->config_ref_present) {
        report_buf[report_offset++] = 0xA7;  /* [7] IMPLICIT CONSTRUCTED */
        size_t cref_len = strlen(report->config_ref);
        report_buf[report_offset++] = (uint8_t)cref_len;
        memcpy(report_buf + report_offset, report->config_ref, cref_len);
        report_offset += cref_len;
    }

    /* Encode InformationReport length */
    int ret = mms_encode_length(report_offset, content + content_offset,
                                sizeof(content) - content_offset);
    if (ret < 0) {
        return ret;
    }
    content_offset += ret;

    /* Copy report content */
    if (!has_space(content_offset, report_offset, sizeof(content))) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(content + content_offset, report_buf, report_offset);
    content_offset += report_offset;

    /* Encode Unconfirmed-PDU length */
    ret = mms_encode_length(content_offset, buffer + offset, buflen - offset);
    if (ret < 0) {
        return ret;
    }
    offset += ret;

    /* Copy content to output buffer */
    if (!has_space(offset, content_offset, buflen)) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(buffer + offset, content, content_offset);
    offset += content_offset;

    return (int)offset;
}

int mms_decode_information_report(const uint8_t* buffer, size_t buflen,
                                  mms_information_report_t* report) {
    if (buffer == NULL || report == NULL || buflen < 2) {
        return MMS_ERROR_INVALID_PARAM;
    }

    size_t offset = 0;

    /* Check tag */
    if (buffer[offset++] != MMS_TAG_UNCONFIRMED) {
        return MMS_ERROR_INVALID_ENCODING;
    }

    /* Decode Unconfirmed-PDU length */
    size_t length;
    int ret = mms_decode_length(buffer + offset, buflen - offset, &length);
    if (ret < 0) {
        return ret;
    }
    offset += ret;

    size_t end = offset + length;

    /* InformationReport service [0] */
    if (offset >= end || buffer[offset++] != 0x80) {
        return MMS_ERROR_INVALID_ENCODING;
    }

    /* Decode InformationReport length */
    ret = mms_decode_length(buffer + offset, buflen - offset, &length);
    if (ret < 0) {
        return ret;
    }
    offset += ret;

    /* variableAccessSpecification [0] */
    if (offset >= end || buffer[offset++] != 0xA0) {
        return MMS_ERROR_INVALID_ENCODING;
    }

    /* Decode variable list length */
    size_t varlist_len;
    ret = mms_decode_length(buffer + offset, buflen - offset, &varlist_len);
    if (ret < 0) {
        return ret;
    }
    offset += ret;

    /* Decode variable list name (simplified) */
    size_t name_len = buffer[offset++];
    if (name_len >= MMS_MAX_VARIABLE_NAME) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(report->variable_list_name, buffer + offset, name_len);
    report->variable_list_name[name_len] = '\0';
    offset += name_len;

    /* listOfAccessResult [1] */
    if (offset >= end || buffer[offset++] != 0xA1) {
        return MMS_ERROR_INVALID_ENCODING;
    }

    /* Decode results length */
    size_t results_len;
    ret = mms_decode_length(buffer + offset, buflen - offset, &results_len);
    if (ret < 0) {
        return ret;
    }
    offset += ret;

    /* Decode each value */
    report->num_values = 0;
    size_t results_end = offset + results_len;
    while (offset < results_end && report->num_values < MMS_MAX_NAMED_VARIABLES) {
        ret = mms_decode_value(buffer + offset, results_end - offset,
                              &report->values[report->num_values]);
        if (ret < 0) {
            return ret;
        }
        offset += ret;
        report->num_values++;
    }

    /* Initialize optional fields */
    report->sq_num_present = false;
    report->report_timestamp_present = false;
    report->reasons_present = false;
    report->buffer_overflow_present = false;
    report->entry_id_present = false;
    report->config_ref_present = false;

    /* Parse optional report fields */
    while (offset < end) {
        uint8_t opt_tag = buffer[offset++];
        size_t opt_len;
        ret = mms_decode_length(buffer + offset, buflen - offset, &opt_len);
        if (ret < 0) return ret;
        offset += ret;

        switch (opt_tag) {
            case 0x82: { /* sq_num [2] IMPLICIT UNSIGNED */
                uint32_t sq_val = 0;
                ret = decode_unsigned(buffer + offset, opt_len, &sq_val);
                if (ret < 0) return ret;
                report->sq_num = (uint16_t)sq_val;
                report->sq_num_present = true;
                offset += opt_len;
                break;
            }
            case 0x83: { /* report_timestamp [3] IMPLICIT INTEGER (64-bit) */
                if (opt_len == 8) {
                    report->report_timestamp = 0;
                    for (size_t i = 0; i < 8; i++) {
                        report->report_timestamp = (report->report_timestamp << 8) | buffer[offset + i];
                    }
                    report->report_timestamp_present = true;
                }
                offset += opt_len;
                break;
            }
            case 0xA4: { /* reasons [4] IMPLICIT SEQUENCE OF INTEGER */
                for (size_t i = 0; i < opt_len && i < MMS_MAX_NAMED_VARIABLES; i++) {
                    report->reasons[i] = buffer[offset + i];
                }
                report->reasons_present = true;
                offset += opt_len;
                break;
            }
            case 0x85: { /* buffer_overflow [5] IMPLICIT BOOLEAN */
                report->buffer_overflow = (buffer[offset] != 0);
                report->buffer_overflow_present = true;
                offset += opt_len;
                break;
            }
            case 0x86: { /* entry_id [6] IMPLICIT INTEGER (64-bit) */
                if (opt_len == 8) {
                    report->entry_id = 0;
                    for (size_t i = 0; i < 8; i++) {
                        report->entry_id = (report->entry_id << 8) | buffer[offset + i];
                    }
                    report->entry_id_present = true;
                }
                offset += opt_len;
                break;
            }
            case 0xA7: { /* config_ref [7] IMPLICIT VisibleString */
                if (opt_len < MMS_MAX_VARIABLE_NAME) {
                    memcpy(report->config_ref, buffer + offset, opt_len);
                    report->config_ref[opt_len] = '\0';
                    report->config_ref_present = true;
                }
                offset += opt_len;
                break;
            }
            default:
                /* Skip unknown fields */
                offset += opt_len;
                break;
        }
    }

    return (int)offset;
}

/* ============================================================================
 * Phase 7: Standalone Control Service Encode/Decode Functions
 * ============================================================================ */

/**
 * @brief Encode a control object variable spec (domain + item_id)
 *
 * Shared helper for standalone control service encoders.
 * Encodes: tag 0xA0, length, domain_len, domain, item_len, item_id
 */
static int encode_control_object(const mms_variable_spec_t* obj,
                                 uint8_t* buf, size_t buflen) {
    size_t domain_len = strlen(obj->domain);
    size_t item_len = strlen(obj->item_id);
    size_t inner_len = 1 + domain_len + 1 + item_len;
    size_t total = 2 + inner_len;  /* tag + length + inner */

    if (buflen < total) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }

    size_t pos = 0;
    buf[pos++] = 0xA0;  /* [0] IMPLICIT */
    buf[pos++] = (uint8_t)inner_len;
    buf[pos++] = (uint8_t)domain_len;
    memcpy(buf + pos, obj->domain, domain_len);
    pos += domain_len;
    buf[pos++] = (uint8_t)item_len;
    memcpy(buf + pos, obj->item_id, item_len);
    pos += item_len;

    return (int)pos;
}

/**
 * @brief Decode a control object variable spec (domain + item_id)
 *
 * Shared helper for standalone control service decoders.
 * Expects buffer to point at domain_len byte inside the [0] field value.
 */
static int decode_control_object(const uint8_t* buf, size_t buflen,
                                 mms_variable_spec_t* obj) {
    size_t pos = 0;

    if (pos >= buflen) return MMS_ERROR_INVALID_ENCODING;
    size_t domain_len = buf[pos++];
    if (domain_len >= MMS_MAX_DOMAIN_NAME || pos + domain_len > buflen) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(obj->domain, buf + pos, domain_len);
    obj->domain[domain_len] = '\0';
    pos += domain_len;

    if (pos >= buflen) return MMS_ERROR_INVALID_ENCODING;
    size_t item_len = buf[pos++];
    if (item_len >= MMS_MAX_VARIABLE_NAME || pos + item_len > buflen) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(obj->item_id, buf + pos, item_len);
    obj->item_id[item_len] = '\0';
    pos += item_len;

    return (int)pos;
}

/* --------------------------------------------------------------------------
 * Select Request
 * -------------------------------------------------------------------------- */

int mms_encode_select_request(const mms_select_request_t* request,
                              uint8_t* buffer, size_t buflen) {
    if (request == NULL || buffer == NULL) {
        return MMS_ERROR_INVALID_PARAM;
    }

    uint8_t service_buf[MMS_MAX_PDU_SIZE];
    size_t offset = 0;
    uint8_t temp_buf[8];
    int ret;

    /* controlObject [0] IMPLICIT VariableAccessSpecification */
    ret = encode_control_object(&request->control_object, service_buf + offset,
                                sizeof(service_buf) - offset);
    if (ret < 0) return ret;
    offset += ret;

    /* checkValue [1] IMPLICIT INTEGER */
    service_buf[offset++] = 0x81;
    service_buf[offset++] = 0x01;
    service_buf[offset++] = request->check_value;

    /* selectTimeout [2] IMPLICIT INTEGER (optional, 0 = default) */
    if (request->select_timeout_ms > 0) {
        service_buf[offset++] = 0x82;
        ret = encode_integer(request->select_timeout_ms, temp_buf, sizeof(temp_buf));
        if (ret < 0) return ret;
        service_buf[offset++] = (uint8_t)ret;
        memcpy(service_buf + offset, temp_buf, ret);
        offset += ret;
    }

    /* Wrap in service tag */
    size_t total = 0;
    buffer[total++] = MMS_SERVICE_SELECT;
    ret = mms_encode_length(offset, buffer + total, buflen - total);
    if (ret < 0) return ret;
    total += ret;

    if (!has_space(total, offset, buflen)) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(buffer + total, service_buf, offset);
    total += offset;

    return (int)total;
}

int mms_decode_select_request(const uint8_t* buffer, size_t buflen,
                              mms_select_request_t* request) {
    if (buffer == NULL || request == NULL || buflen < 2) {
        return MMS_ERROR_INVALID_PARAM;
    }

    size_t offset = 0;
    int ret;

    /* Check service tag */
    if (buffer[offset++] != MMS_SERVICE_SELECT) {
        return MMS_ERROR_INVALID_ENCODING;
    }

    size_t content_len;
    ret = mms_decode_length(buffer + offset, buflen - offset, &content_len);
    if (ret < 0) return ret;
    offset += ret;

    size_t end = offset + content_len;
    memset(request, 0, sizeof(*request));

    while (offset < end) {
        uint8_t tag = buffer[offset++];
        size_t tag_len;
        ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
        if (ret < 0) return ret;
        offset += ret;

        switch (tag) {
            case 0xA0: { /* controlObject [0] IMPLICIT */
                ret = decode_control_object(buffer + offset, tag_len,
                                            &request->control_object);
                if (ret < 0) return ret;
                offset += tag_len;
                break;
            }
            case 0x81:  /* checkValue [1] IMPLICIT */
                request->check_value = buffer[offset];
                offset += tag_len;
                break;
            case 0x82:  /* selectTimeout [2] IMPLICIT */
                ret = decode_integer(buffer + offset, tag_len,
                                     (int32_t*)&request->select_timeout_ms);
                if (ret < 0) return ret;
                offset += tag_len;
                break;
            default:
                offset += tag_len;
                break;
        }
    }

    return (int)offset;
}

/* --------------------------------------------------------------------------
 * Select Response
 * -------------------------------------------------------------------------- */

int mms_encode_select_response(const mms_select_response_t* response,
                               uint8_t* buffer, size_t buflen) {
    if (response == NULL || buffer == NULL) {
        return MMS_ERROR_INVALID_PARAM;
    }

    uint8_t service_buf[64];
    size_t offset = 0;
    uint8_t temp_buf[8];
    int ret;

    /* state [0] IMPLICIT INTEGER */
    service_buf[offset++] = 0x80;
    service_buf[offset++] = 0x01;
    service_buf[offset++] = (uint8_t)response->state;

    /* selectionID [1] IMPLICIT INTEGER */
    service_buf[offset++] = 0x81;
    ret = encode_integer(response->selection_id, temp_buf, sizeof(temp_buf));
    if (ret < 0) return ret;
    service_buf[offset++] = (uint8_t)ret;
    memcpy(service_buf + offset, temp_buf, ret);
    offset += ret;

    /* Wrap in service tag */
    size_t total = 0;
    buffer[total++] = MMS_SERVICE_SELECT;
    ret = mms_encode_length(offset, buffer + total, buflen - total);
    if (ret < 0) return ret;
    total += ret;

    if (!has_space(total, offset, buflen)) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(buffer + total, service_buf, offset);
    total += offset;

    return (int)total;
}

int mms_decode_select_response(const uint8_t* buffer, size_t buflen,
                               mms_select_response_t* response) {
    if (buffer == NULL || response == NULL || buflen < 2) {
        return MMS_ERROR_INVALID_PARAM;
    }

    size_t offset = 0;
    int ret;

    if (buffer[offset++] != MMS_SERVICE_SELECT) {
        return MMS_ERROR_INVALID_ENCODING;
    }

    size_t content_len;
    ret = mms_decode_length(buffer + offset, buflen - offset, &content_len);
    if (ret < 0) return ret;
    offset += ret;

    size_t end = offset + content_len;
    memset(response, 0, sizeof(*response));

    while (offset < end) {
        uint8_t tag = buffer[offset++];
        size_t tag_len;
        ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
        if (ret < 0) return ret;
        offset += ret;

        switch (tag) {
            case 0x80:  /* state [0] IMPLICIT */
                response->state = (mms_control_state_t)buffer[offset];
                offset += tag_len;
                break;
            case 0x81:  /* selectionID [1] IMPLICIT */
                ret = decode_integer(buffer + offset, tag_len,
                                     (int32_t*)&response->selection_id);
                if (ret < 0) return ret;
                offset += tag_len;
                break;
            default:
                offset += tag_len;
                break;
        }
    }

    return (int)offset;
}

/* --------------------------------------------------------------------------
 * SelectWithValue Request
 * -------------------------------------------------------------------------- */

int mms_encode_select_with_value_request(const mms_select_with_value_request_t* request,
                                         uint8_t* buffer, size_t buflen) {
    if (request == NULL || buffer == NULL) {
        return MMS_ERROR_INVALID_PARAM;
    }

    uint8_t service_buf[MMS_MAX_PDU_SIZE];
    size_t offset = 0;
    uint8_t temp_buf[8];
    int ret;

    /* controlObject [0] IMPLICIT VariableAccessSpecification */
    ret = encode_control_object(&request->control_object, service_buf + offset,
                                sizeof(service_buf) - offset);
    if (ret < 0) return ret;
    offset += ret;

    /* controlValue [1] IMPLICIT Data */
    service_buf[offset++] = 0xA1;
    ret = mms_encode_value(&request->control_value,
                           service_buf + offset + 1,
                           sizeof(service_buf) - offset - 1);
    if (ret < 0) return ret;
    service_buf[offset] = (uint8_t)ret;
    offset++;
    offset += ret;

    /* checkValue [2] IMPLICIT INTEGER */
    service_buf[offset++] = 0x82;
    service_buf[offset++] = 0x01;
    service_buf[offset++] = request->check_value;

    /* selectTimeout [3] IMPLICIT INTEGER (optional) */
    if (request->select_timeout_ms > 0) {
        service_buf[offset++] = 0x83;
        ret = encode_integer(request->select_timeout_ms, temp_buf, sizeof(temp_buf));
        if (ret < 0) return ret;
        service_buf[offset++] = (uint8_t)ret;
        memcpy(service_buf + offset, temp_buf, ret);
        offset += ret;
    }

    /* Wrap in service tag */
    size_t total = 0;
    buffer[total++] = MMS_SERVICE_SELECT_WITH_VALUE;
    ret = mms_encode_length(offset, buffer + total, buflen - total);
    if (ret < 0) return ret;
    total += ret;

    if (!has_space(total, offset, buflen)) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(buffer + total, service_buf, offset);
    total += offset;

    return (int)total;
}

int mms_decode_select_with_value_request(const uint8_t* buffer, size_t buflen,
                                         mms_select_with_value_request_t* request) {
    if (buffer == NULL || request == NULL || buflen < 2) {
        return MMS_ERROR_INVALID_PARAM;
    }

    size_t offset = 0;
    int ret;

    if (buffer[offset++] != MMS_SERVICE_SELECT_WITH_VALUE) {
        return MMS_ERROR_INVALID_ENCODING;
    }

    size_t content_len;
    ret = mms_decode_length(buffer + offset, buflen - offset, &content_len);
    if (ret < 0) return ret;
    offset += ret;

    size_t end = offset + content_len;
    memset(request, 0, sizeof(*request));

    while (offset < end) {
        uint8_t tag = buffer[offset++];
        size_t tag_len;
        ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
        if (ret < 0) return ret;
        offset += ret;

        switch (tag) {
            case 0xA0: { /* controlObject [0] IMPLICIT */
                ret = decode_control_object(buffer + offset, tag_len,
                                            &request->control_object);
                if (ret < 0) return ret;
                offset += tag_len;
                break;
            }
            case 0xA1:  /* controlValue [1] IMPLICIT */
                ret = mms_decode_value(buffer + offset, tag_len,
                                       &request->control_value);
                if (ret < 0) return ret;
                offset += tag_len;
                break;
            case 0x82:  /* checkValue [2] IMPLICIT */
                request->check_value = buffer[offset];
                offset += tag_len;
                break;
            case 0x83:  /* selectTimeout [3] IMPLICIT */
                ret = decode_integer(buffer + offset, tag_len,
                                     (int32_t*)&request->select_timeout_ms);
                if (ret < 0) return ret;
                offset += tag_len;
                break;
            default:
                offset += tag_len;
                break;
        }
    }

    return (int)offset;
}

/* --------------------------------------------------------------------------
 * SelectWithValue Response
 * -------------------------------------------------------------------------- */

int mms_encode_select_with_value_response(const mms_select_with_value_response_t* response,
                                          uint8_t* buffer, size_t buflen) {
    if (response == NULL || buffer == NULL) {
        return MMS_ERROR_INVALID_PARAM;
    }

    uint8_t service_buf[64];
    size_t offset = 0;
    uint8_t temp_buf[8];
    int ret;

    /* state [0] IMPLICIT INTEGER */
    service_buf[offset++] = 0x80;
    service_buf[offset++] = 0x01;
    service_buf[offset++] = (uint8_t)response->state;

    /* selectionID [1] IMPLICIT INTEGER */
    service_buf[offset++] = 0x81;
    ret = encode_integer(response->selection_id, temp_buf, sizeof(temp_buf));
    if (ret < 0) return ret;
    service_buf[offset++] = (uint8_t)ret;
    memcpy(service_buf + offset, temp_buf, ret);
    offset += ret;

    /* Wrap in service tag */
    size_t total = 0;
    buffer[total++] = MMS_SERVICE_SELECT_WITH_VALUE;
    ret = mms_encode_length(offset, buffer + total, buflen - total);
    if (ret < 0) return ret;
    total += ret;

    if (!has_space(total, offset, buflen)) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(buffer + total, service_buf, offset);
    total += offset;

    return (int)total;
}

int mms_decode_select_with_value_response(const uint8_t* buffer, size_t buflen,
                                          mms_select_with_value_response_t* response) {
    if (buffer == NULL || response == NULL || buflen < 2) {
        return MMS_ERROR_INVALID_PARAM;
    }

    size_t offset = 0;
    int ret;

    if (buffer[offset++] != MMS_SERVICE_SELECT_WITH_VALUE) {
        return MMS_ERROR_INVALID_ENCODING;
    }

    size_t content_len;
    ret = mms_decode_length(buffer + offset, buflen - offset, &content_len);
    if (ret < 0) return ret;
    offset += ret;

    size_t end = offset + content_len;
    memset(response, 0, sizeof(*response));

    while (offset < end) {
        uint8_t tag = buffer[offset++];
        size_t tag_len;
        ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
        if (ret < 0) return ret;
        offset += ret;

        switch (tag) {
            case 0x80:  /* state [0] IMPLICIT */
                response->state = (mms_control_state_t)buffer[offset];
                offset += tag_len;
                break;
            case 0x81:  /* selectionID [1] IMPLICIT */
                ret = decode_integer(buffer + offset, tag_len,
                                     (int32_t*)&response->selection_id);
                if (ret < 0) return ret;
                offset += tag_len;
                break;
            default:
                offset += tag_len;
                break;
        }
    }

    return (int)offset;
}

/* --------------------------------------------------------------------------
 * Operate Request
 * -------------------------------------------------------------------------- */

int mms_encode_operate_request(const mms_operate_request_t* request,
                               uint8_t* buffer, size_t buflen) {
    if (request == NULL || buffer == NULL) {
        return MMS_ERROR_INVALID_PARAM;
    }

    uint8_t service_buf[MMS_MAX_PDU_SIZE];
    size_t offset = 0;
    uint8_t temp_buf[8];
    int ret;

    /* controlObject [0] IMPLICIT VariableAccessSpecification */
    ret = encode_control_object(&request->control_object, service_buf + offset,
                                sizeof(service_buf) - offset);
    if (ret < 0) return ret;
    offset += ret;

    /* selectionID [1] IMPLICIT INTEGER */
    service_buf[offset++] = 0x81;
    ret = encode_integer(request->selection_id, temp_buf, sizeof(temp_buf));
    if (ret < 0) return ret;
    service_buf[offset++] = (uint8_t)ret;
    memcpy(service_buf + offset, temp_buf, ret);
    offset += ret;

    /* controlValue [2] IMPLICIT Data (optional) */
    if (request->has_control_value) {
        service_buf[offset++] = 0xA2;
        ret = mms_encode_value(&request->control_value,
                               service_buf + offset + 1,
                               sizeof(service_buf) - offset - 1);
        if (ret < 0) return ret;
        service_buf[offset] = (uint8_t)ret;
        offset++;
        offset += ret;
    }

    /* operationTime [3] IMPLICIT TimeOfDay (optional, 0 = immediate) */
    if (request->operation_time > 0) {
        service_buf[offset++] = 0x83;
        service_buf[offset++] = 0x08;  /* Length = 8 */
        for (int i = 7; i >= 0; i--) {
            service_buf[offset++] = (uint8_t)((request->operation_time >> (i * 8)) & 0xFF);
        }
    }

    /* Wrap in service tag */
    size_t total = 0;
    buffer[total++] = MMS_SERVICE_OPERATE;
    ret = mms_encode_length(offset, buffer + total, buflen - total);
    if (ret < 0) return ret;
    total += ret;

    if (!has_space(total, offset, buflen)) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(buffer + total, service_buf, offset);
    total += offset;

    return (int)total;
}

int mms_decode_operate_request(const uint8_t* buffer, size_t buflen,
                               mms_operate_request_t* request) {
    if (buffer == NULL || request == NULL || buflen < 2) {
        return MMS_ERROR_INVALID_PARAM;
    }

    size_t offset = 0;
    int ret;

    if (buffer[offset++] != MMS_SERVICE_OPERATE) {
        return MMS_ERROR_INVALID_ENCODING;
    }

    size_t content_len;
    ret = mms_decode_length(buffer + offset, buflen - offset, &content_len);
    if (ret < 0) return ret;
    offset += ret;

    size_t end = offset + content_len;
    memset(request, 0, sizeof(*request));

    while (offset < end) {
        uint8_t tag = buffer[offset++];
        size_t tag_len;
        ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
        if (ret < 0) return ret;
        offset += ret;

        switch (tag) {
            case 0xA0: { /* controlObject [0] IMPLICIT */
                ret = decode_control_object(buffer + offset, tag_len,
                                            &request->control_object);
                if (ret < 0) return ret;
                offset += tag_len;
                break;
            }
            case 0x81:  /* selectionID [1] IMPLICIT */
                ret = decode_integer(buffer + offset, tag_len,
                                     (int32_t*)&request->selection_id);
                if (ret < 0) return ret;
                offset += tag_len;
                break;
            case 0xA2:  /* controlValue [2] IMPLICIT (optional) */
                ret = mms_decode_value(buffer + offset, tag_len,
                                       &request->control_value);
                if (ret < 0) return ret;
                request->has_control_value = true;
                offset += tag_len;
                break;
            case 0x83:  /* operationTime [3] IMPLICIT (optional, 64-bit) */
                if (tag_len == 8) {
                    request->operation_time = 0;
                    for (size_t i = 0; i < 8; i++) {
                        request->operation_time = (request->operation_time << 8) | buffer[offset + i];
                    }
                } else {
                    /* Fallback for shorter encodings */
                    int32_t op_time_32 = 0;
                    ret = decode_integer(buffer + offset, tag_len, &op_time_32);
                    if (ret < 0) return ret;
                    request->operation_time = (uint64_t)op_time_32;
                }
                offset += tag_len;
                break;
            default:
                offset += tag_len;
                break;
        }
    }

    return (int)offset;
}

/* --------------------------------------------------------------------------
 * Operate Response
 * -------------------------------------------------------------------------- */

int mms_encode_operate_response(const mms_operate_response_t* response,
                                uint8_t* buffer, size_t buflen) {
    if (response == NULL || buffer == NULL) {
        return MMS_ERROR_INVALID_PARAM;
    }

    uint8_t service_buf[64];
    size_t offset = 0;

    /* state [0] IMPLICIT INTEGER */
    service_buf[offset++] = 0x80;
    service_buf[offset++] = 0x01;
    service_buf[offset++] = (uint8_t)response->state;

    /* success [1] IMPLICIT BOOLEAN */
    service_buf[offset++] = 0x81;
    service_buf[offset++] = 0x01;
    service_buf[offset++] = response->success ? 0xFF : 0x00;

    /* Wrap in service tag */
    size_t total = 0;
    buffer[total++] = MMS_SERVICE_OPERATE;
    int ret = mms_encode_length(offset, buffer + total, buflen - total);
    if (ret < 0) return ret;
    total += ret;

    if (!has_space(total, offset, buflen)) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(buffer + total, service_buf, offset);
    total += offset;

    return (int)total;
}

int mms_decode_operate_response(const uint8_t* buffer, size_t buflen,
                                mms_operate_response_t* response) {
    if (buffer == NULL || response == NULL || buflen < 2) {
        return MMS_ERROR_INVALID_PARAM;
    }

    size_t offset = 0;
    int ret;

    if (buffer[offset++] != MMS_SERVICE_OPERATE) {
        return MMS_ERROR_INVALID_ENCODING;
    }

    size_t content_len;
    ret = mms_decode_length(buffer + offset, buflen - offset, &content_len);
    if (ret < 0) return ret;
    offset += ret;

    size_t end = offset + content_len;
    memset(response, 0, sizeof(*response));

    while (offset < end) {
        uint8_t tag = buffer[offset++];
        size_t tag_len;
        ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
        if (ret < 0) return ret;
        offset += ret;

        switch (tag) {
            case 0x80:  /* state [0] IMPLICIT */
                response->state = (mms_control_state_t)buffer[offset];
                offset += tag_len;
                break;
            case 0x81:  /* success [1] IMPLICIT */
                response->success = (buffer[offset] != 0);
                offset += tag_len;
                break;
            default:
                offset += tag_len;
                break;
        }
    }

    return (int)offset;
}

/* --------------------------------------------------------------------------
 * Cancel Request
 * -------------------------------------------------------------------------- */

int mms_encode_cancel_request(const mms_cancel_request_t* request,
                              uint8_t* buffer, size_t buflen) {
    if (request == NULL || buffer == NULL) {
        return MMS_ERROR_INVALID_PARAM;
    }

    uint8_t service_buf[MMS_MAX_PDU_SIZE];
    size_t offset = 0;
    uint8_t temp_buf[8];
    int ret;

    /* controlObject [0] IMPLICIT VariableAccessSpecification */
    ret = encode_control_object(&request->control_object, service_buf + offset,
                                sizeof(service_buf) - offset);
    if (ret < 0) return ret;
    offset += ret;

    /* selectionID [1] IMPLICIT INTEGER */
    service_buf[offset++] = 0x81;
    ret = encode_integer(request->selection_id, temp_buf, sizeof(temp_buf));
    if (ret < 0) return ret;
    service_buf[offset++] = (uint8_t)ret;
    memcpy(service_buf + offset, temp_buf, ret);
    offset += ret;

    /* Wrap in service tag */
    size_t total = 0;
    buffer[total++] = MMS_SERVICE_CANCEL;
    ret = mms_encode_length(offset, buffer + total, buflen - total);
    if (ret < 0) return ret;
    total += ret;

    if (!has_space(total, offset, buflen)) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(buffer + total, service_buf, offset);
    total += offset;

    return (int)total;
}

int mms_decode_cancel_request(const uint8_t* buffer, size_t buflen,
                              mms_cancel_request_t* request) {
    if (buffer == NULL || request == NULL || buflen < 2) {
        return MMS_ERROR_INVALID_PARAM;
    }

    size_t offset = 0;
    int ret;

    if (buffer[offset++] != MMS_SERVICE_CANCEL) {
        return MMS_ERROR_INVALID_ENCODING;
    }

    size_t content_len;
    ret = mms_decode_length(buffer + offset, buflen - offset, &content_len);
    if (ret < 0) return ret;
    offset += ret;

    size_t end = offset + content_len;
    memset(request, 0, sizeof(*request));

    while (offset < end) {
        uint8_t tag = buffer[offset++];
        size_t tag_len;
        ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
        if (ret < 0) return ret;
        offset += ret;

        switch (tag) {
            case 0xA0: { /* controlObject [0] IMPLICIT */
                ret = decode_control_object(buffer + offset, tag_len,
                                            &request->control_object);
                if (ret < 0) return ret;
                offset += tag_len;
                break;
            }
            case 0x81:  /* selectionID [1] IMPLICIT */
                ret = decode_integer(buffer + offset, tag_len,
                                     (int32_t*)&request->selection_id);
                if (ret < 0) return ret;
                offset += tag_len;
                break;
            default:
                offset += tag_len;
                break;
        }
    }

    return (int)offset;
}

/* --------------------------------------------------------------------------
 * Cancel Response
 * -------------------------------------------------------------------------- */

int mms_encode_cancel_response(const mms_cancel_response_t* response,
                               uint8_t* buffer, size_t buflen) {
    if (response == NULL || buffer == NULL) {
        return MMS_ERROR_INVALID_PARAM;
    }

    (void)response;  /* Empty response */

    /* Wrap empty content in service tag */
    size_t total = 0;

    if (buflen < 3) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }

    buffer[total++] = MMS_SERVICE_CANCEL;
    buffer[total++] = 0x01;  /* Length = 1 */
    buffer[total++] = 0x00;  /* Empty content */

    return (int)total;
}

int mms_decode_cancel_response(const uint8_t* buffer, size_t buflen,
                               mms_cancel_response_t* response) {
    if (buffer == NULL || response == NULL || buflen < 2) {
        return MMS_ERROR_INVALID_PARAM;
    }

    size_t offset = 0;
    int ret;

    if (buffer[offset++] != MMS_SERVICE_CANCEL) {
        return MMS_ERROR_INVALID_ENCODING;
    }

    size_t content_len;
    ret = mms_decode_length(buffer + offset, buflen - offset, &content_len);
    if (ret < 0) return ret;
    offset += ret;

    /* Skip empty content */
    offset += content_len;

    memset(response, 0, sizeof(*response));

    return (int)offset;
}

/* --------------------------------------------------------------------------
 * CommandTermination (Unconfirmed)
 * -------------------------------------------------------------------------- */

int mms_encode_command_termination(const mms_command_termination_t* termination,
                                   uint8_t* buffer, size_t buflen) {
    if (termination == NULL || buffer == NULL) {
        return MMS_ERROR_INVALID_PARAM;
    }

    uint8_t service_buf[MMS_MAX_PDU_SIZE];
    size_t offset = 0;
    uint8_t temp_buf[8];
    int ret;

    /* controlObject [0] IMPLICIT VariableAccessSpecification */
    ret = encode_control_object(&termination->control_object, service_buf + offset,
                                sizeof(service_buf) - offset);
    if (ret < 0) return ret;
    offset += ret;

    /* selectionID [1] IMPLICIT INTEGER */
    service_buf[offset++] = 0x81;
    ret = encode_integer(termination->selection_id, temp_buf, sizeof(temp_buf));
    if (ret < 0) return ret;
    service_buf[offset++] = (uint8_t)ret;
    memcpy(service_buf + offset, temp_buf, ret);
    offset += ret;

    /* success [2] IMPLICIT BOOLEAN */
    service_buf[offset++] = 0x82;
    service_buf[offset++] = 0x01;
    service_buf[offset++] = termination->success ? 0xFF : 0x00;

    /* terminationReason [3] IMPLICIT INTEGER */
    service_buf[offset++] = 0x83;
    service_buf[offset++] = 0x01;
    service_buf[offset++] = termination->termination_reason;

    /* Wrap in service tag */
    size_t total = 0;
    buffer[total++] = MMS_SERVICE_COMMAND_TERMINATION;
    ret = mms_encode_length(offset, buffer + total, buflen - total);
    if (ret < 0) return ret;
    total += ret;

    if (!has_space(total, offset, buflen)) {
        return MMS_ERROR_BUFFER_TOO_SMALL;
    }
    memcpy(buffer + total, service_buf, offset);
    total += offset;

    return (int)total;
}

int mms_decode_command_termination(const uint8_t* buffer, size_t buflen,
                                   mms_command_termination_t* termination) {
    if (buffer == NULL || termination == NULL || buflen < 2) {
        return MMS_ERROR_INVALID_PARAM;
    }

    size_t offset = 0;
    int ret;

    if (buffer[offset++] != MMS_SERVICE_COMMAND_TERMINATION) {
        return MMS_ERROR_INVALID_ENCODING;
    }

    size_t content_len;
    ret = mms_decode_length(buffer + offset, buflen - offset, &content_len);
    if (ret < 0) return ret;
    offset += ret;

    size_t end = offset + content_len;
    memset(termination, 0, sizeof(*termination));

    while (offset < end) {
        uint8_t tag = buffer[offset++];
        size_t tag_len;
        ret = mms_decode_length(buffer + offset, buflen - offset, &tag_len);
        if (ret < 0) return ret;
        offset += ret;

        switch (tag) {
            case 0xA0: { /* controlObject [0] IMPLICIT */
                ret = decode_control_object(buffer + offset, tag_len,
                                            &termination->control_object);
                if (ret < 0) return ret;
                offset += tag_len;
                break;
            }
            case 0x81:  /* selectionID [1] IMPLICIT */
                ret = decode_integer(buffer + offset, tag_len,
                                     (int32_t*)&termination->selection_id);
                if (ret < 0) return ret;
                offset += tag_len;
                break;
            case 0x82:  /* success [2] IMPLICIT */
                termination->success = (buffer[offset] != 0);
                offset += tag_len;
                break;
            case 0x83:  /* terminationReason [3] IMPLICIT */
                termination->termination_reason = buffer[offset];
                offset += tag_len;
                break;
            default:
                offset += tag_len;
                break;
        }
    }

    return (int)offset;
}
