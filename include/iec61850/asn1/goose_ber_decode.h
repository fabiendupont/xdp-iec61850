/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * ASN.1 BER Decoder for IEC 61850-8-1 GOOSE Protocol
 *
 * This is a minimal, formally verified implementation of BER decoding
 * for GOOSE APDUs. Written in C (not C++) for Frama-C verification.
 *
 * License: BSD-3-Clause
 */

#ifndef GOOSE_BER_DECODE_H
#define GOOSE_BER_DECODE_H

#include "asn1/goose_ber.h"
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/***************************************************************************
 * Low-Level BER Decoding Functions
 ***************************************************************************/

/**
 * Decode ASN.1 tag
 *
 * @param buf       Input buffer
 * @param buf_size  Size of input buffer
 * @param offset    Current offset in buffer (updated)
 * @param tag       Output: decoded tag value
 * @return 0 on success, negative error code on failure
 */
/*@ behavior valid:
  @   assumes buf != \null && offset != \null && tag != \null;
  @   assumes \valid_read(buf + (0..buf_size-1));
  @   assumes 0 <= *offset < buf_size;
  @   assigns *offset, *tag;
  @   ensures \result == 0 ==> *offset <= buf_size;
  @   ensures \result != 0 ==> *offset == \old(*offset);
  @ behavior null_args:
  @   assumes buf == \null || offset == \null || tag == \null;
  @   assigns \nothing;
  @   ensures \result < 0;
  @*/
int ber_decode_tag(const uint8_t *buf, size_t buf_size, size_t *offset, uint8_t *tag);

/**
 * Decode ASN.1 length (definite form)
 */
/*@ behavior valid:
  @   assumes buf != \null && offset != \null && length != \null;
  @   assumes \valid_read(buf + (0..buf_size-1));
  @   assumes 0 <= *offset < buf_size;
  @   assigns *offset, *length;
  @   ensures \result == 0 ==> *offset <= buf_size;
  @   ensures \result != 0 ==> *offset == \old(*offset);
  @ behavior null_args:
  @   assumes buf == \null || offset == \null || length == \null;
  @   assigns \nothing;
  @   ensures \result < 0;
  @*/
int ber_decode_length(const uint8_t *buf, size_t buf_size, size_t *offset, size_t *length);

/**
 * Decode ASN.1 BOOLEAN
 */
/*@ behavior valid:
  @   assumes buf != \null && offset != \null && value != \null;
  @   assumes \valid_read(buf + (0..buf_size-1));
  @   assumes 0 <= *offset < buf_size;
  @   assigns *offset, *value;
  @   ensures \result == 0 ==> *offset <= buf_size;
  @ behavior null_args:
  @   assumes buf == \null || offset == \null || value == \null;
  @   assigns \nothing;
  @   ensures \result < 0;
  @*/
int ber_decode_boolean(const uint8_t *buf, size_t buf_size, size_t *offset,
                       uint8_t expected_tag, bool *value);

/**
 * Decode ASN.1 INTEGER (32-bit signed)
 */
/*@ behavior valid:
  @   assumes buf != \null && offset != \null && value != \null;
  @   assumes \valid_read(buf + (0..buf_size-1));
  @   assumes 0 <= *offset < buf_size;
  @   assigns *offset, *value;
  @   ensures \result == 0 ==> *offset <= buf_size;
  @ behavior null_args:
  @   assumes buf == \null || offset == \null || value == \null;
  @   assigns \nothing;
  @   ensures \result < 0;
  @*/
int ber_decode_int32(const uint8_t *buf, size_t buf_size, size_t *offset,
                     uint8_t expected_tag, int32_t *value);

/**
 * Decode ASN.1 INTEGER (32-bit unsigned)
 */
/*@ behavior valid:
  @   assumes buf != \null && offset != \null && value != \null;
  @   assumes \valid_read(buf + (0..buf_size-1));
  @   assumes 0 <= *offset < buf_size;
  @   assigns *offset, *value;
  @   ensures \result == 0 ==> *offset <= buf_size;
  @ behavior null_args:
  @   assumes buf == \null || offset == \null || value == \null;
  @   assigns \nothing;
  @   ensures \result < 0;
  @*/
int ber_decode_uint32(const uint8_t *buf, size_t buf_size, size_t *offset,
                      uint8_t expected_tag, uint32_t *value);

/**
 * Decode ASN.1 VisibleString
 */
/*@ behavior valid:
  @   assumes buf != \null && offset != \null && str != \null;
  @   assumes \valid_read(buf + (0..buf_size-1));
  @   assumes 0 <= *offset < buf_size;
  @   assumes str_size > 0;
  @   assigns *offset, str[0..str_size-1];
  @   ensures \result == 0 ==> *offset <= buf_size;
  @ behavior null_args:
  @   assumes buf == \null || offset == \null || str == \null;
  @   assigns \nothing;
  @   ensures \result < 0;
  @*/
int ber_decode_visiblestring(const uint8_t *buf, size_t buf_size, size_t *offset,
                              uint8_t expected_tag, char *str, size_t str_size);

/**
 * Decode ASN.1 UtcTime (8 bytes: seconds + fraction + quality)
 */
/*@ behavior valid:
  @   assumes buf != \null && offset != \null && timestamp_us != \null;
  @   assumes \valid_read(buf + (0..buf_size-1));
  @   assumes 0 <= *offset < buf_size;
  @   assigns *offset, *timestamp_us;
  @   ensures \result == 0 ==> *offset <= buf_size;
  @ behavior null_args:
  @   assumes buf == \null || offset == \null || timestamp_us == \null;
  @   assigns \nothing;
  @   ensures \result < 0;
  @*/
int ber_decode_utctime(const uint8_t *buf, size_t buf_size, size_t *offset,
                       uint8_t expected_tag, uint64_t *timestamp_us, uint8_t *time_quality);

/**
 * Decode ASN.1 OCTET STRING
 *
 * @param buf          Input buffer
 * @param buf_size     Size of input buffer
 * @param offset       Current offset (updated)
 * @param expected_tag Expected tag value
 * @param output       Output buffer for octets
 * @param output_max_len Maximum size of output buffer
 * @param output_len   Output: actual length of decoded octets
 * @return 0 on success, negative error code on failure
 */
/*@ requires \valid_read(buf + (0..buf_size-1));
  @ requires \valid(offset);
  @ requires \valid(output + (0..output_max_len-1));
  @ requires \valid(output_len);
  @ requires 0 <= *offset < buf_size;
  @ requires output_max_len > 0;
  @ assigns *offset, output[0..output_max_len-1], *output_len;
  @*/
int ber_decode_octetstring(const uint8_t *buf, size_t buf_size, size_t *offset,
                           uint8_t expected_tag, uint8_t *output,
                           size_t output_max_len, size_t *output_len);

/***************************************************************************
 * GOOSE APDU Decoding Functions
 ***************************************************************************/

/**
 * Decode complete GOOSE APDU
 *
 * @param buf       Input buffer (starting at GOOSE APDU, after Ethernet headers)
 * @param buf_size  Size of input buffer
 * @param apdu      Output: decoded GOOSE APDU structure
 * @return 0 on success, negative error code on failure
 */
/*@ behavior valid:
  @   assumes buf != \null && apdu != \null && buf_size > 0;
  @   assumes \valid_read(buf + (0..buf_size-1));
  @   assigns *apdu;
  @ behavior null_args:
  @   assumes buf == \null || apdu == \null;
  @   assigns \nothing;
  @   ensures \result < 0;
  @*/
int goose_decode_apdu(const uint8_t *buf, size_t buf_size, goose_apdu_t *apdu);

/**
 * Decode GOOSE APDU with consumed byte count
 *
 * Same as goose_decode_apdu() but also returns the number of bytes consumed.
 * This allows the caller to find the security extension that follows the APDU.
 *
 * @param buf       Input buffer
 * @param buf_size  Size of input buffer
 * @param apdu      Output: decoded APDU structure
 * @param consumed  Output: number of bytes consumed by the APDU
 * @return GOOSE_BER_OK on success, error code otherwise
 */
int goose_decode_apdu_ex(const uint8_t *buf, size_t buf_size,
                          goose_apdu_t *apdu, size_t *consumed);

/**
 * Decode GOOSE allData field (SEQUENCE OF Data)
 *
 * @param buf       Input buffer
 * @param buf_size  Size of input buffer
 * @param offset    Current offset (updated)
 * @param data      Output: array of decoded data values
 * @param max_count Maximum number of data entries
 * @param count     Output: actual number of entries decoded
 * @return 0 on success, negative error code on failure
 */
/*@ requires \valid_read(buf + (0..buf_size-1));
  @ requires \valid(offset);
  @ requires \valid(data + (0..max_count-1));
  @ requires \valid(count);
  @ requires 0 <= *offset < buf_size;
  @ assigns *offset, data[0..max_count-1], *count;
  @*/
int goose_decode_alldata(const uint8_t *buf, size_t buf_size, size_t *offset,
                         goose_data_t *data, size_t max_count, size_t *count);

/***************************************************************************
 * IEC 62351-6 Security Extension Decoding
 ***************************************************************************/

/**
 * Decode security extension (IEC 62351-6)
 *
 * Decodes the security field ([12] SEQUENCE) containing:
 * - [0] Signature algorithm (INTEGER)
 * - [1] Key ID (OCTET STRING, 4 bytes per IEC 62351-6)
 * - [2] Security timestamp (UtcTime, 8 bytes)
 * - [3] Signature (OCTET STRING, variable length)
 *
 * @param buf       Input buffer
 * @param buf_size  Size of input buffer
 * @param offset    Current offset in buffer (updated)
 * @param apdu      GOOSE APDU to populate with security fields
 * @return 0 on success, negative error code on failure
 */
/*@ requires \valid_read(buf + (0..buf_size-1));
  @ requires \valid(offset);
  @ requires \valid(apdu);
  @ requires 0 <= *offset <= buf_size;
  @ assigns *offset, apdu->secure, apdu->signature_algo, apdu->key_id[0..3],
  @         apdu->security_timestamp, apdu->signature[0..511], apdu->signature_len;
  @*/
int goose_decode_security(const uint8_t *buf, size_t buf_size, size_t *offset,
                          goose_apdu_t *apdu);

#ifdef __cplusplus
}
#endif

#endif /* GOOSE_BER_DECODE_H */
