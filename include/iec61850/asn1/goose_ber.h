/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * ASN.1 BER Encoder for IEC 61850-8-1 GOOSE Protocol
 *
 * This is a minimal, formally verified implementation of BER encoding
 * for GOOSE APDUs. Written in C (not C++) for Frama-C verification.
 *
 * IEC 61850-8-1 GOOSE APDU Structure (Table 16):
 *   [APPLICATION 1] SEQUENCE {
 *     gocbRef         [0] VisibleString,
 *     timeAllowedtoLive [1] INTEGER,
 *     datSet          [2] VisibleString,
 *     goID            [3] VisibleString OPTIONAL,
 *     t               [4] UtcTime,
 *     stNum           [5] INTEGER,
 *     sqNum           [6] INTEGER,
 *     test            [7] BOOLEAN,
 *     confRev         [8] INTEGER,
 *     ndsCom          [9] BOOLEAN,
 *     numDatSetEntries [10] INTEGER,
 *     allData         [11] SEQUENCE OF Data
 *   }
 */

#ifndef GOOSE_BER_H
#define GOOSE_BER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ASN.1 Tag Classes */
#define ASN1_CLASS_UNIVERSAL        0x00U
#define ASN1_CLASS_APPLICATION      0x40U
#define ASN1_CLASS_CONTEXT          0x80U
#define ASN1_CLASS_PRIVATE          0xC0U

/* ASN.1 Constructed Flag */
#define ASN1_CONSTRUCTED            0x20U

/* ASN.1 Universal Tags */
#define ASN1_TAG_BOOLEAN            0x01U
#define ASN1_TAG_INTEGER            0x02U
#define ASN1_TAG_BITSTRING          0x03U
#define ASN1_TAG_OCTETSTRING        0x04U
#define ASN1_TAG_SEQUENCE           0x10U
#define ASN1_TAG_VISIBLESTRING      0x1AU
#define ASN1_TAG_UTCTIME            0x17U

/* GOOSE Application Tag */
#define GOOSE_APDU_TAG              0x61U  /* APPLICATION 1 | CONSTRUCTED */

/* GOOSE APDU Field Tags (Context-Specific) */
#define GOOSE_TAG_GOCBREF           0x80U  /* [0] */
#define GOOSE_TAG_TIMEALLOWEDTOLIVE 0x81U  /* [1] */
#define GOOSE_TAG_DATSET            0x82U  /* [2] */
#define GOOSE_TAG_GOID              0x83U  /* [3] */
#define GOOSE_TAG_T                 0x84U  /* [4] */
#define GOOSE_TAG_STNUM             0x85U  /* [5] */
#define GOOSE_TAG_SQNUM             0x86U  /* [6] */
#define GOOSE_TAG_TEST              0x87U  /* [7] */
#define GOOSE_TAG_CONFREV           0x88U  /* [8] */
#define GOOSE_TAG_NDSCOM            0x89U  /* [9] */
#define GOOSE_TAG_NUMDATSETENTRIES  0x8AU  /* [10] */
#define GOOSE_TAG_ALLDATA           0xABU  /* [11] | CONSTRUCTED */

/* IEC 62351-6 Security Extension Tags (Context-Specific) */
#define GOOSE_TAG_SECURITY          0xACU  /* [12] | CONSTRUCTED - Security extension */
#define GOOSE_TAG_SECURITY_ALGO     0x80U  /* [0] - Signature algorithm */
#define GOOSE_TAG_SECURITY_KEYID    0x81U  /* [1] - Key identifier */
#define GOOSE_TAG_SECURITY_TIMESTAMP 0x82U /* [2] - Security timestamp */
#define GOOSE_TAG_SECURITY_SIGNATURE 0x83U /* [3] - Digital signature */

/* Maximum sizes */
#define GOOSE_MAX_GOCBREF_LEN       129U
#define GOOSE_MAX_DATSET_LEN        129U
#define GOOSE_MAX_GOID_LEN          129U
#define GOOSE_MAX_ALLDATA_ENTRIES   64U
#define GOOSE_MAX_APDU_SIZE         1518U  /* Max Ethernet payload */
#define GOOSE_MAX_SIGNATURE_LEN     512U   /* Max signature size (RSA-4096 = 512 bytes) */
#define GOOSE_KEYID_LEN             4U     /* Key ID per IEC 62351-6 (4 bytes) */

/* Error codes */
#define GOOSE_BER_OK                0
#define GOOSE_BER_ERR_BUFFER_FULL   -1
#define GOOSE_BER_ERR_INVALID_ARG   -2
#define GOOSE_BER_ERR_ENCODING      -3

/**
 * IEC 62351-6 Signature Algorithms
 */
typedef enum {
    GOOSE_SIGNATURE_NONE        = 0x00,  /* No signature (non-secure mode) */
    GOOSE_SIGNATURE_RSA_PSS     = 0x01,  /* RSA-PSS-SHA256 */
    GOOSE_SIGNATURE_ECDSA       = 0x02   /* ECDSA-SHA256 */
} goose_signature_algo_t;

/**
 * GOOSE Data Types for allData
 */
typedef enum {
    GOOSE_DATA_BOOLEAN,
    GOOSE_DATA_INT32,
    GOOSE_DATA_UINT32,
    GOOSE_DATA_FLOAT32,
    GOOSE_DATA_BITSTRING,
    GOOSE_DATA_OCTETSTRING,
    GOOSE_DATA_VISIBLESTRING,
    GOOSE_DATA_UTCTIME,
    GOOSE_DATA_STRUCTURE
} goose_data_type_t;

/**
 * GOOSE Data Value
 */
/* Forward declaration for recursive structure type */
struct goose_data;

typedef struct goose_data {
    goose_data_type_t type;
    union {
        bool boolean;
        int32_t int32;
        uint32_t uint32;
        float float32;
        struct {
            uint8_t *data;
            size_t len;
        } bytes;
        char *visiblestring;           /* GOOSE_DATA_VISIBLESTRING */
        struct {
            uint64_t timestamp_us;     /* UTC microseconds since epoch */
            uint8_t time_quality;      /* Time quality flags */
        } utctime;                     /* GOOSE_DATA_UTCTIME */
        struct {
            struct goose_data *elements;
            size_t count;
        } structure;                   /* GOOSE_DATA_STRUCTURE */
    } value;
} goose_data_t;

/**
 * GOOSE APDU Structure
 */
typedef struct {
    /* Standard IEC 61850-8-1 fields */
    char gocbRef[GOOSE_MAX_GOCBREF_LEN];
    uint32_t timeAllowedtoLive;
    char datSet[GOOSE_MAX_DATSET_LEN];
    char goID[GOOSE_MAX_GOID_LEN];
    bool has_goID;
    uint64_t timestamp;  /* UTC time in microseconds since epoch */
    uint8_t time_quality;  /* Time quality flags (0x00 = time accuracy unspecified) */
    uint32_t stNum;
    uint32_t sqNum;
    bool test;
    uint32_t confRev;
    bool ndsCom;
    uint32_t numDatSetEntries;
    goose_data_t allData[GOOSE_MAX_ALLDATA_ENTRIES];

    /* IEC 62351-6 Security Extension */
    bool secure;                                 /* Security enabled? */
    goose_signature_algo_t signature_algo;       /* Signature algorithm */
    uint8_t key_id[GOOSE_KEYID_LEN];            /* Key ID per IEC 62351-6 */
    uint64_t security_timestamp;                 /* Timestamp for replay protection (microseconds) */
    uint8_t signature[GOOSE_MAX_SIGNATURE_LEN];  /* Digital signature */
    size_t signature_len;                        /* Actual signature length */
} goose_apdu_t;

/***************************************************************************
 * Low-Level BER Encoding Functions
 ***************************************************************************/

/*@ behavior valid:
  @   assumes buf != \null && offset != \null;
  @   assumes \valid(buf + (0..buf_size-1));
  @   assumes 0 <= *offset < buf_size;
  @   assigns buf[*offset] \from tag;
  @   assigns *offset \from *offset;
  @   ensures \result == 0 ==> *offset == \old(*offset) + 1;
  @   ensures \result == 0 ==> *offset <= buf_size;
  @   ensures \result == 0 ==> buf[\old(*offset)] == tag;
  @   ensures \result != 0 ==> *offset == \old(*offset);
  @ behavior null_args:
  @   assumes buf == \null || offset == \null;
  @   assigns \nothing;
  @   ensures \result < 0;
  @*/
int ber_encode_tag(uint8_t *buf, size_t buf_size, size_t *offset, uint8_t tag);

/*@ behavior valid:
  @   assumes buf != \null && offset != \null;
  @   assumes \valid(buf + (0..buf_size-1));
  @   assumes 0 <= *offset < buf_size;
  @   assigns buf[*offset .. buf_size-1] \from length, *offset;
  @   assigns *offset \from *offset, length;
  @   ensures \result == 0 ==> *offset > \old(*offset);
  @   ensures \result == 0 ==> *offset <= buf_size;
  @   ensures \result != 0 ==> *offset == \old(*offset);
  @ behavior null_args:
  @   assumes buf == \null || offset == \null;
  @   assigns \nothing;
  @   ensures \result < 0;
  @*/
int ber_encode_length(uint8_t *buf, size_t buf_size, size_t *offset, size_t length);

/*@ behavior valid:
  @   assumes buf != \null && offset != \null;
  @   assumes \valid(buf + (0..buf_size-1));
  @   assumes 0 <= *offset < buf_size;
  @   assigns buf[*offset .. buf_size-1] \from tag, value, *offset;
  @   assigns *offset \from *offset;
  @   ensures \result == 0 ==> *offset <= buf_size;
  @   ensures \result != 0 ==> *offset == \old(*offset);
  @ behavior null_args:
  @   assumes buf == \null || offset == \null;
  @   assigns \nothing;
  @   ensures \result < 0;
  @*/
int ber_encode_boolean(uint8_t *buf, size_t buf_size, size_t *offset,
                       uint8_t tag, bool value);

/*@ behavior valid:
  @   assumes buf != \null && offset != \null;
  @   assumes \valid(buf + (0..buf_size-1));
  @   assumes 0 <= *offset < buf_size;
  @   assigns buf[*offset .. buf_size-1] \from tag, value, *offset;
  @   assigns *offset \from *offset;
  @   ensures \result == 0 ==> *offset <= buf_size;
  @   ensures \result != 0 ==> *offset == \old(*offset);
  @ behavior null_args:
  @   assumes buf == \null || offset == \null;
  @   assigns \nothing;
  @   ensures \result < 0;
  @*/
int ber_encode_int32(uint8_t *buf, size_t buf_size, size_t *offset,
                     uint8_t tag, int32_t value);

/*@ behavior valid:
  @   assumes buf != \null && offset != \null;
  @   assumes \valid(buf + (0..buf_size-1));
  @   assumes 0 <= *offset < buf_size;
  @   assigns buf[*offset .. buf_size-1] \from tag, value, *offset;
  @   assigns *offset \from *offset;
  @   ensures \result == 0 ==> *offset <= buf_size;
  @   ensures \result != 0 ==> *offset == \old(*offset);
  @ behavior null_args:
  @   assumes buf == \null || offset == \null;
  @   assigns \nothing;
  @   ensures \result < 0;
  @*/
int ber_encode_uint32(uint8_t *buf, size_t buf_size, size_t *offset,
                      uint8_t tag, uint32_t value);

/*@ behavior valid:
  @   assumes buf != \null && offset != \null && str != \null;
  @   assumes \valid(buf + (0..buf_size-1));
  @   assumes \valid_read(str);
  @   assumes 0 <= *offset < buf_size;
  @   assigns buf[*offset .. buf_size-1] \from tag, str[0..], *offset;
  @   assigns *offset \from *offset;
  @   ensures \result == 0 ==> *offset <= buf_size;
  @   ensures \result != 0 ==> *offset == \old(*offset);
  @ behavior null_args:
  @   assumes buf == \null || offset == \null || str == \null;
  @   assigns \nothing;
  @   ensures \result < 0;
  @*/
int ber_encode_visiblestring(uint8_t *buf, size_t buf_size, size_t *offset,
                              uint8_t tag, const char *str);

/*@ behavior valid:
  @   assumes buf != \null && offset != \null;
  @   assumes \valid(buf + (0..buf_size-1));
  @   assumes 0 <= *offset < buf_size;
  @   assigns buf[*offset .. buf_size-1] \from tag, timestamp_us, time_quality, *offset;
  @   assigns *offset \from *offset;
  @   ensures \result == 0 ==> *offset <= buf_size;
  @   ensures \result != 0 ==> *offset == \old(*offset);
  @ behavior null_args:
  @   assumes buf == \null || offset == \null;
  @   assigns \nothing;
  @   ensures \result < 0;
  @*/
int ber_encode_utctime(uint8_t *buf, size_t buf_size, size_t *offset,
                       uint8_t tag, uint64_t timestamp_us, uint8_t time_quality);

/***************************************************************************
 * GOOSE APDU Encoding Functions
 ***************************************************************************/

/*@ requires \valid(buf + (0..buf_size-1));
  @ requires \valid_read(apdu);
  @ requires \valid(encoded_len);
  @ requires buf_size >= 64;
  @ assigns buf[0..buf_size-1] \from *apdu;
  @ assigns *encoded_len \from *apdu, buf_size;
  @ ensures \result == 0 ==> *encoded_len > 0 && *encoded_len <= buf_size;
  @*/
int goose_encode_apdu(uint8_t *buf, size_t buf_size,
                      const goose_apdu_t *apdu, size_t *encoded_len);

/*@ requires \valid(buf + (0..buf_size-1));
  @ requires \valid_read(data + (0..count-1));
  @ requires \valid(offset);
  @ requires count <= 64;
  @ assigns buf[*offset .. buf_size-1] \from data[0..count-1], *offset;
  @ assigns *offset \from *offset, count;
  @*/
int goose_encode_alldata(uint8_t *buf, size_t buf_size, size_t *offset,
                         const goose_data_t *data, size_t count);

/*@ requires \valid(apdu);
  @ assigns *apdu \from \nothing;
  @*/
void goose_apdu_init(goose_apdu_t *apdu);

int goose_set_gocbref(goose_apdu_t *apdu, const char *gocbRef);
int goose_set_datset(goose_apdu_t *apdu, const char *datSet);
int goose_set_goid(goose_apdu_t *apdu, const char *goID);
int goose_add_boolean(goose_apdu_t *apdu, bool value);
int goose_add_int32(goose_apdu_t *apdu, int32_t value);
int goose_add_uint32(goose_apdu_t *apdu, uint32_t value);
int goose_add_float32(goose_apdu_t *apdu, float value);
int goose_add_bitstring(goose_apdu_t *apdu, const uint8_t *data, size_t len);
int goose_add_octetstring(goose_apdu_t *apdu, const uint8_t *data, size_t len);
int goose_add_visiblestring(goose_apdu_t *apdu, const char *str);
int goose_add_utctime(goose_apdu_t *apdu, uint64_t timestamp_us, uint8_t time_quality);
int goose_add_structure(goose_apdu_t *apdu, goose_data_t *elements, size_t count);

int goose_set_security(goose_apdu_t *apdu,
                       goose_signature_algo_t signature_algo,
                       const uint8_t *key_id,
                       const uint8_t *signature,
                       size_t signature_len);

#ifdef __cplusplus
}
#endif

#endif /* GOOSE_BER_H */
