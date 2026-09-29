/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * ASN.1 BER Encoder/Decoder for IEC 61850-9-2 Sampled Values Protocol
 *
 * This is a minimal, formally verified implementation of BER encoding
 * for SV APDUs. Written in C (not C++) for Frama-C verification.
 *
 * IEC 61850-9-2 Sampled Values APDU Structure:
 *   [APPLICATION 2] SEQUENCE {
 *     noASDU         [0] INTEGER,
 *     seqASDU        [1] SEQUENCE OF {
 *       svID         [0] VisibleString,
 *       datSet       [1] VisibleString OPTIONAL,
 *       smpCnt       [2] INTEGER,
 *       confRev      [3] INTEGER,
 *       refrTm       [4] UtcTime OPTIONAL,
 *       smpSynch     [5] INTEGER,
 *       smpRate      [6] INTEGER OPTIONAL,
 *       sample       [7] SEQUENCE OF Data,
 *       smpMod       [8] INTEGER OPTIONAL,
 *       security     [9] SEQUENCE {...} OPTIONAL  // IEC 62351-6
 *     }
 *   }
 *
 * License: BSD-3-Clause
 */

#ifndef SV_BER_H
#define SV_BER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* SV Application Tag */
#define SV_APDU_TAG                 0x62U  /* APPLICATION 2 | CONSTRUCTED */

/* SV APDU Field Tags (Context-Specific) */
#define SV_TAG_NOASDU               0x80U  /* [0] */
#define SV_TAG_SEQASDU              0xA2U  /* [2] | CONSTRUCTED (per IEC 61850-9-2) */

/* ASDU Field Tags (Context-Specific) */
#define SV_TAG_SVID                 0x80U  /* [0] */
#define SV_TAG_DATSET               0x81U  /* [1] */
#define SV_TAG_SMPCNT               0x82U  /* [2] */
#define SV_TAG_CONFREV              0x83U  /* [3] */
#define SV_TAG_REFRTM               0x84U  /* [4] */
#define SV_TAG_SMPSYNCH             0x85U  /* [5] */
#define SV_TAG_SMPRATE              0x86U  /* [6] */
#define SV_TAG_SAMPLE               0x87U  /* [7] | CONSTRUCTED */
#define SV_TAG_SMPMOD               0x88U  /* [8] */
#define SV_TAG_SECURITY             0xA9U  /* [9] | CONSTRUCTED - Security extension */

/* IEC 62351-6 Security Extension Tags (Context-Specific) */
#define SV_TAG_SECURITY_ALGO        0x80U  /* [0] - Signature algorithm */
#define SV_TAG_SECURITY_KEYID       0x81U  /* [1] - Key identifier */
#define SV_TAG_SECURITY_TIMESTAMP   0x82U  /* [2] - Security timestamp */
#define SV_TAG_SECURITY_SIGNATURE   0x83U  /* [3] - Digital signature */

/* Maximum sizes */
#define SV_MAX_SVID_LEN             129U
#define SV_MAX_DATSET_LEN           129U
#define SV_MAX_SAMPLES              64U    /* Maximum samples per ASDU */
#define SV_MAX_ASDU                 8U     /* Maximum ASDUs per APDU (IEC 61850-9-2) */
#define SV_MAX_APDU_SIZE            1518U  /* Max Ethernet payload */
#define SV_MAX_SIGNATURE_LEN        512U   /* Max signature size (RSA-4096 = 512 bytes) */
#define SV_KEYID_LEN                4U     /* Key ID per IEC 62351-6 (4 bytes) */

/* Error codes */
#define SV_BER_OK                   0
#define SV_BER_ERR_BUFFER_FULL      (-1)
#define SV_BER_ERR_INVALID_ARG      (-2)
#define SV_BER_ERR_ENCODING         (-3)
#define SV_BER_ERR_DECODING         (-4)

/**
 * IEC 62351-6 Signature Algorithms
 */
typedef enum {
    SV_SIGNATURE_NONE           = 0x00,  /* No signature (non-secure mode) */
    SV_SIGNATURE_RSA_PSS        = 0x01,  /* RSA-PSS-SHA256 */
    SV_SIGNATURE_ECDSA          = 0x02   /* ECDSA-SHA256 */
} sv_signature_algo_t;

/**
 * Sample synchronization modes (IEC 61850-9-2)
 */
typedef enum {
    SV_SMPSYNCH_NONE            = 0,     /* No synchronization */
    SV_SMPSYNCH_LOCAL           = 1,     /* Local time synchronization */
    SV_SMPSYNCH_GLOBAL          = 2      /* Global time synchronization (e.g., IEEE 1588 PTP) */
} sv_smpsynch_t;

/**
 * Sample quality flags (IEC 61850-7-3 Quality, 32-bit)
 *
 * Wire format (IEC 61850-9-2LE): 4 bytes, big-endian.
 * Bits 0-1: validity (00=good, 01=invalid, 10=reserved, 11=questionable)
 * Bit 2: overflow
 * Bit 3: out_of_range
 * Bit 4: bad_reference
 * Bit 5: oscillatory
 * Bit 6: failure
 * Bit 7: old_data
 * Bit 8: inconsistent
 * Bit 9: inaccurate
 * Bit 10: source (0=process, 1=substituted)
 * Bit 11: test
 * Bit 12: operator_blocked
 * Bits 13-31: reserved (zero)
 */
typedef struct {
    uint8_t validity : 2;          /* 00=good, 01=invalid, 10=rsvd, 11=questionable */
    uint8_t overflow : 1;          /* Sample overflow detected */
    uint8_t out_of_range : 1;      /* Sample out of range */
    uint8_t bad_reference : 1;     /* Bad reference (e.g., time sync lost) */
    uint8_t oscillatory : 1;       /* Oscillatory condition */
    uint8_t failure : 1;           /* General failure */
    uint8_t old_data : 1;          /* Old data */
    uint8_t inconsistent : 1;      /* Inconsistent */
    uint8_t inaccurate : 1;        /* Inaccurate */
    uint8_t source : 1;            /* 0=process, 1=substituted */
    uint8_t test : 1;              /* Test mode */
    uint8_t operator_blocked : 1;  /* Operator blocked */
} sv_quality_t;

/**
 * Sample data (value + quality)
 */
typedef struct {
    int32_t value;                 /* Sample value */
    sv_quality_t quality;          /* Quality flags */
} sv_sample_t;

/**
 * SV ASDU Structure (Application Service Data Unit)
 */
typedef struct {
    /* Standard IEC 61850-9-2 fields */
    char svID[SV_MAX_SVID_LEN];           /* SV identifier */
    char datSet[SV_MAX_DATSET_LEN];       /* Dataset reference (optional) */
    bool has_datSet;                      /* Dataset present? */
    uint16_t smpCnt;                      /* Sample counter */
    uint32_t confRev;                     /* Configuration revision */
    uint64_t refrTm;                      /* Reference time (UTC microseconds, optional) */
    bool has_refrTm;                      /* Reference time present? */
    sv_smpsynch_t smpSynch;               /* Sample synchronization mode */
    uint16_t smpRate;                     /* Sample rate (optional) */
    bool has_smpRate;                     /* Sample rate present? */
    sv_sample_t samples[SV_MAX_SAMPLES];  /* Sample data array */
    uint8_t num_samples;                  /* Number of samples */
    uint8_t smpMod;                       /* Samples per nominal period (optional) */
    bool has_smpMod;                      /* smpMod present? */

    /* IEC 62351-6 Security Extension */
    bool secure;                                  /* Security enabled? */
    sv_signature_algo_t signature_algo;           /* Signature algorithm */
    uint8_t key_id[SV_KEYID_LEN];                /* Key ID per IEC 62351-6 (4 bytes) */
    uint64_t security_timestamp;                  /* Timestamp for replay protection (microseconds) */
    uint8_t signature[SV_MAX_SIGNATURE_LEN];     /* Digital signature */
    size_t signature_len;                         /* Actual signature length */
} sv_asdu_t;

/**
 * SV APDU Structure (Application Protocol Data Unit)
 */
typedef struct {
    uint8_t noASDU;                /* Number of ASDUs (1..SV_MAX_ASDU) */
    sv_asdu_t asdu[SV_MAX_ASDU];   /* ASDU array */
} sv_apdu_t;

/***************************************************************************
 * SV APDU Encoding Functions
 ***************************************************************************/

/**
 * Encode complete SV APDU
 *
 * @param buf       Output buffer (typically after Ethernet + VLAN headers)
 * @param buf_size  Size of output buffer
 * @param apdu      SV APDU structure to encode
 * @param encoded_len Output: length of encoded APDU
 * @return 0 on success, negative error code on failure
 */
/*@ requires \valid(buf + (0..buf_size-1));
  @ requires \valid_read(apdu);
  @ requires \valid(encoded_len);
  @ requires buf_size >= 64;
  @ assigns buf[0..buf_size-1], *encoded_len;
  @ ensures \result == 0 ==> *encoded_len > 0 && *encoded_len <= buf_size;
  @*/
int sv_encode_apdu(uint8_t *buf, size_t buf_size,
                   const sv_apdu_t *apdu, size_t *encoded_len);

/**
 * Decode SV APDU
 *
 * @param buf       Input buffer containing encoded APDU
 * @param buf_size  Size of input buffer
 * @param apdu      Output: decoded SV APDU
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
int sv_decode_apdu(const uint8_t *buf, size_t buf_size, sv_apdu_t *apdu);

/**
 * Initialize SV APDU with default values
 */
/*@ requires \valid(apdu);
  @ assigns *apdu;
  @*/
void sv_apdu_init(sv_apdu_t *apdu);

/**
 * Initialize SV ASDU with default values
 */
/*@ requires \valid(asdu);
  @ assigns *asdu;
  @*/
void sv_asdu_init(sv_asdu_t *asdu);

/**
 * Helper: Set svID (null-terminated string)
 */
/*@ requires \valid(asdu);
  @ requires \valid_read(svID);
  @ assigns asdu->svID[0..128];
  @*/
int sv_set_svid(sv_asdu_t *asdu, const char *svID);

/**
 * Helper: Set datSet (null-terminated string, optional)
 */
/*@ requires \valid(asdu);
  @ requires \valid_read(datSet);
  @ assigns asdu->datSet[0..128], asdu->has_datSet;
  @*/
int sv_set_datset(sv_asdu_t *asdu, const char *datSet);

/**
 * Helper: Add sample data
 */
/*@ requires \valid(asdu);
  @ requires asdu->num_samples < 64;
  @ assigns asdu->samples[asdu->num_samples], asdu->num_samples;
  @*/
int sv_add_sample(sv_asdu_t *asdu, int32_t value, sv_quality_t quality);

/***************************************************************************
 * IEC 62351-6 Security Extension Functions
 ***************************************************************************/

/**
 * Encode security extension (IEC 62351-6)
 *
 * Encodes the security field ([9] SEQUENCE) containing:
 * - [0] Signature algorithm (INTEGER)
 * - [1] Key ID (OCTET STRING, 4 bytes per IEC 62351-6)
 * - [2] Security timestamp (UtcTime, 8 bytes)
 * - [3] Signature (OCTET STRING, variable length)
 *
 * @param buf       Output buffer
 * @param buf_size  Size of output buffer
 * @param offset    Current offset in buffer (updated)
 * @param asdu      SV ASDU with security fields populated
 * @return 0 on success, negative error code on failure
 */
/*@ requires \valid(buf + (0..buf_size-1));
  @ requires \valid_read(asdu);
  @ requires \valid(offset);
  @ requires 0 <= *offset < buf_size;
  @ assigns buf[*offset .. buf_size-1], *offset;
  @*/
int sv_encode_security(uint8_t *buf, size_t buf_size, size_t *offset,
                       const sv_asdu_t *asdu);

/**
 * Helper: Set security parameters
 *
 * @param asdu           SV ASDU to configure
 * @param signature_algo Signature algorithm
 * @param key_id         Key identifier (4 bytes per IEC 62351-6)
 * @param signature      Signature data
 * @param signature_len  Length of signature
 * @return 0 on success, negative error code on failure
 */
/*@ requires \valid(asdu);
  @ requires \valid_read(key_id + (0..3));
  @ requires \valid_read(signature + (0..signature_len-1));
  @ requires signature_len <= 512;
  @ assigns asdu->secure, asdu->signature_algo, asdu->key_id[0..3],
  @         asdu->security_timestamp, asdu->signature[0..signature_len-1],
  @         asdu->signature_len;
  @*/
int sv_set_security(sv_asdu_t *asdu,
                    sv_signature_algo_t signature_algo,
                    const uint8_t *key_id,
                    const uint8_t *signature,
                    size_t signature_len);

#ifdef __cplusplus
}
#endif

#endif /* SV_BER_H */
