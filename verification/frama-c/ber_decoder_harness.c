/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Frama-C Verification Harness for BER Decoder
 *
 * This file provides entry points for formal verification of the BER decoder
 * using Frama-C EVA (Evolved Value Analysis).
 *
 * Verification Goals:
 * 1. Memory safety (no buffer overruns)
 * 2. Absence of undefined behavior
 * 3. Proper input validation
 */

#include "asn1/goose_ber_decode.h"
#include <stdint.h>
#include <stdbool.h>

/*@
  @ requires \valid_read(buf + (0..buf_size-1));
  @ requires \valid(offset);
  @ requires \valid(tag);
  @ requires buf_size > 0;
  @ requires *offset < buf_size;
  @ assigns *offset, *tag;
  @ ensures \result == GOOSE_BER_OK || \result == GOOSE_BER_ERR_INVALID_ARG ||
  @         \result == GOOSE_BER_ERR_ENCODING;
  @*/
int verify_ber_decode_tag(const uint8_t *buf, size_t buf_size, size_t *offset, uint8_t *tag)
{
    return ber_decode_tag(buf, buf_size, offset, tag);
}

/*@
  @ requires \valid_read(buf + (0..buf_size-1));
  @ requires \valid(offset);
  @ requires \valid(length);
  @ requires buf_size > 0;
  @ requires *offset < buf_size;
  @ assigns *offset, *length;
  @ ensures \result == GOOSE_BER_OK || \result == GOOSE_BER_ERR_INVALID_ARG ||
  @         \result == GOOSE_BER_ERR_ENCODING;
  @*/
int verify_ber_decode_length(const uint8_t *buf, size_t buf_size, size_t *offset, size_t *length)
{
    return ber_decode_length(buf, buf_size, offset, length);
}

/*@
  @ requires \valid_read(buf + (0..buf_size-1));
  @ requires \valid(offset);
  @ requires \valid(value);
  @ requires buf_size >= 3;
  @ requires *offset < buf_size - 2;
  @ assigns *offset, *value;
  @ ensures \result == GOOSE_BER_OK || \result == GOOSE_BER_ERR_INVALID_ARG ||
  @         \result == GOOSE_BER_ERR_ENCODING;
  @*/
int verify_ber_decode_boolean(const uint8_t *buf, size_t buf_size, size_t *offset,
                               uint8_t expected_tag, bool *value)
{
    return ber_decode_boolean(buf, buf_size, offset, expected_tag, value);
}

/*@
  @ requires \valid_read(buf + (0..buf_size-1));
  @ requires \valid(offset);
  @ requires \valid(value);
  @ requires buf_size >= 7;
  @ requires *offset < buf_size - 6;
  @ assigns *offset, *value;
  @ ensures \result == GOOSE_BER_OK || \result == GOOSE_BER_ERR_INVALID_ARG ||
  @         \result == GOOSE_BER_ERR_ENCODING;
  @*/
int verify_ber_decode_int32(const uint8_t *buf, size_t buf_size, size_t *offset,
                             uint8_t expected_tag, int32_t *value)
{
    return ber_decode_int32(buf, buf_size, offset, expected_tag, value);
}

/*@
  @ requires \valid_read(buf + (0..buf_size-1));
  @ requires \valid(offset);
  @ requires \valid(value);
  @ requires buf_size >= 7;
  @ requires *offset < buf_size - 6;
  @ assigns *offset, *value;
  @ ensures \result == GOOSE_BER_OK || \result == GOOSE_BER_ERR_INVALID_ARG ||
  @         \result == GOOSE_BER_ERR_ENCODING;
  @*/
int verify_ber_decode_uint32(const uint8_t *buf, size_t buf_size, size_t *offset,
                              uint8_t expected_tag, uint32_t *value)
{
    return ber_decode_uint32(buf, buf_size, offset, expected_tag, value);
}

/*
 * Main verification entry point
 *
 * Tests all low-level BER decoding functions with various encoded inputs.
 */
void main(void)
{
    uint8_t buffer[256];
    size_t offset;
    uint8_t tag_result;
    size_t length_result;
    bool bool_result;
    int32_t int32_result;
    uint32_t uint32_result;
    int ret;

    /* Initialize buffer to zero */
    /*@ loop assigns i, buffer[0..255];
      @ loop invariant 0 <= i <= 256;
      @ loop variant 256 - i;
      @*/
    for (size_t i = 0; i < 256; i++) {
        buffer[i] = 0;
    }

    /* Test 1: Decode tag */
    buffer[0] = 0x80;
    offset = 0;
    ret = verify_ber_decode_tag(buffer, 256, &offset, &tag_result);
    /*@ assert ret == GOOSE_BER_OK; */
    /*@ assert offset == 1; */
    /*@ assert tag_result == 0x80; */

    /* Test 2: Decode short length (< 128) */
    buffer[0] = 42;
    offset = 0;
    ret = verify_ber_decode_length(buffer, 256, &offset, &length_result);
    /*@ assert ret == GOOSE_BER_OK; */
    /*@ assert offset == 1; */
    /*@ assert length_result == 42; */

    /* Test 3: Decode long length (128-255) - long form with 1 byte */
    buffer[0] = 0x81;  /* 1 length byte follows */
    buffer[1] = 200;
    offset = 0;
    ret = verify_ber_decode_length(buffer, 256, &offset, &length_result);
    /*@ assert ret == GOOSE_BER_OK; */
    /*@ assert offset == 2; */
    /*@ assert length_result == 200; */

    /* Test 4: Decode long length - 2 bytes */
    buffer[0] = 0x82;  /* 2 length bytes follow */
    buffer[1] = 0x01;
    buffer[2] = 0x00;
    offset = 0;
    ret = verify_ber_decode_length(buffer, 256, &offset, &length_result);
    /*@ assert ret == GOOSE_BER_OK; */
    /*@ assert offset == 3; */
    /*@ assert length_result == 256; */

    /* Test 5: Decode boolean TRUE */
    buffer[0] = 0x87;  /* Tag */
    buffer[1] = 0x01;  /* Length */
    buffer[2] = 0xFF;  /* Value: TRUE */
    offset = 0;
    ret = verify_ber_decode_boolean(buffer, 256, &offset, 0x87, &bool_result);
    /*@ assert ret == GOOSE_BER_OK; */
    /*@ assert offset == 3; */
    /*@ assert bool_result == true; */

    /* Test 6: Decode boolean FALSE */
    buffer[2] = 0x00;  /* Value: FALSE */
    offset = 0;
    ret = verify_ber_decode_boolean(buffer, 256, &offset, 0x87, &bool_result);
    /*@ assert ret == GOOSE_BER_OK; */
    /*@ assert bool_result == false; */

    /* Test 7: Decode positive int32 (12345 = 0x3039) */
    buffer[0] = 0x85;  /* Tag */
    buffer[1] = 0x02;  /* Length: 2 bytes */
    buffer[2] = 0x30;  /* MSB */
    buffer[3] = 0x39;  /* LSB */
    offset = 0;
    ret = verify_ber_decode_int32(buffer, 256, &offset, 0x85, &int32_result);
    /*@ assert ret == GOOSE_BER_OK; */
    /*@ assert int32_result == 12345; */

    /* Test 8: Decode negative int32 (-12345 = 0xFFFFCFC7) */
    buffer[1] = 0x02;  /* Length: 2 bytes */
    buffer[2] = 0xCF;
    buffer[3] = 0xC7;
    offset = 0;
    ret = verify_ber_decode_int32(buffer, 256, &offset, 0x85, &int32_result);
    /*@ assert ret == GOOSE_BER_OK; */
    /*@ assert int32_result == -12345; */

    /* Test 9: Decode zero */
    buffer[1] = 0x01;  /* Length: 1 byte */
    buffer[2] = 0x00;
    offset = 0;
    ret = verify_ber_decode_int32(buffer, 256, &offset, 0x85, &int32_result);
    /*@ assert ret == GOOSE_BER_OK; */
    /*@ assert int32_result == 0; */

    /* Test 10: Decode uint32 (0x12345678) */
    buffer[0] = 0x86;  /* Tag */
    buffer[1] = 0x04;  /* Length: 4 bytes */
    buffer[2] = 0x12;
    buffer[3] = 0x34;
    buffer[4] = 0x56;
    buffer[5] = 0x78;
    offset = 0;
    ret = verify_ber_decode_uint32(buffer, 256, &offset, 0x86, &uint32_result);
    /*@ assert ret == GOOSE_BER_OK; */
    /*@ assert uint32_result == 0x12345678U; */

    /* Test 11: Wrong tag error */
    buffer[0] = 0x88;  /* Wrong tag */
    buffer[1] = 0x01;
    buffer[2] = 0xFF;
    offset = 0;
    ret = verify_ber_decode_boolean(buffer, 256, &offset, 0x87, &bool_result);
    /*@ assert ret == GOOSE_BER_ERR_ENCODING; */

    /* Test 12: NULL pointer protection */
    ret = ber_decode_tag(NULL, 256, &offset, &tag_result);
    /*@ assert ret == GOOSE_BER_ERR_INVALID_ARG; */
    ret = ber_decode_tag(buffer, 256, NULL, &tag_result);
    /*@ assert ret == GOOSE_BER_ERR_INVALID_ARG; */
    ret = ber_decode_tag(buffer, 256, &offset, NULL);
    /*@ assert ret == GOOSE_BER_ERR_INVALID_ARG; */
}
