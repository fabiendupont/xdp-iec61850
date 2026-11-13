/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC TR 61850-90-5 R-SV Publisher
 *
 * Publishes SV APDUs wrapped in the 90-5 routable session profile
 * (see asn1/r_profile.h and src/asn1/rsv_ber.c for the wire layout)
 * over UDP/IP.
 *
 * Transport modes — identical to rgoose_publisher.h:
 *
 * Plain (unsigned) mode — default:
 *   The publisher emits only the SPDU; the kernel builds the IP/UDP
 *   headers.  Attach a packet_io created with
 *   packet_io_create_udp_sender(config.dst_ip, config.dst_port, mcast).
 *
 * Secure (signed) mode — after enable_security():
 *   The IEC 62351-6 routable adaptation signs the IPv4 header + UDP
 *   header + SPDU, so the publisher builds the complete datagram:
 *   publish()/build_frame() emit [Eth(14)][IPv4(20)][UDP(8)][SPDU].
 *   Attach a raw (packet_io_create_raw) or XSK backend.  The UDP
 *   checksum is transmitted as zero ("not used" per RFC 768 — a
 *   non-zero checksum over the signature bytes would be circular
 *   with the signature covering the UDP header); the IPv4 header
 *   checksum is always computed.  The signature is HMAC-SHA256 (32
 *   octets, default) or AES-GMAC (16-octet tag) over IP header ..
 *   end of SPDU with the signature value bytes zeroed; the
 *   signature TLV offset is derived arithmetically from the encoded
 *   length, never scanned for.  The AES-GMAC IV is derived per
 *   packet from the session fields — spdu_number(4) | appid(2) |
 *   key_id(4) | reserved(2), big-endian — mirroring the
 *   subscriber's verification path.
 *
 * Retransmission is OFF by default for R-SV (sampled values are not
 * retransmitted); enable_retransmit() opts in.
 *
 * Secure mode requires -Denable_security=true; without it
 * enable_security() returns -ENOTSUP.
 *
 * License: BSD-2-Clause
 */

#ifndef IEC61850_RSV_PUBLISHER_H
#define IEC61850_RSV_PUBLISHER_H

#include "asn1/r_profile.h"
#include "asn1/sv_ber.h"
#include "goose/goose_retransmission.h"
#include "transport/packet_io.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dotted-quad IPv4 string capacity ("255.255.255.255" + NUL). */
#define IEC61850_RSV_IP_ADDR_LEN   16U

/* SPDU capacity: 26 + 10 + SV_MAX_APDU_SIZE + 2 + 32, rounded. */
#define IEC61850_RSV_MAX_SPDU_LEN  1600U

/* Wire frame capacity: Ethernet(14) + IPv4(20) + UDP(8) + SPDU. */
#define IEC61850_RSV_MAX_FRAME_LEN 1664U

/* Security configuration capacities. */
#define IEC61850_RSV_SEC_KEY_MAX   64U
#define IEC61850_RSV_SEC_HMAC_LEN  32U  /* HMAC-SHA256 output */
#define IEC61850_RSV_SEC_GMAC_LEN  16U  /* AES-GMAC tag */

/* security_algos wire bits (emitted verbatim; publication supports
 * HMAC-SHA256 (default) and AES-GMAC (128/256-bit keys)). */
#define IEC61850_RSV_PUB_SEC_ALGO_HMAC_SHA256 0x0100U
#define IEC61850_RSV_PUB_SEC_ALGO_AES_GMAC    0x0200U

typedef struct {
    uint16_t appid;        /* payload + session APPID */
    char src_ip[IEC61850_RSV_IP_ADDR_LEN];  /* secure mode: IP source */
    char dst_ip[IEC61850_RSV_IP_ADDR_LEN];  /* plain: UDP dest; secure: IP dest */
    uint16_t src_port;     /* secure mode: UDP source port */
    uint16_t dst_port;     /* UDP destination port */
    uint8_t dst_mac[6];    /* secure mode: Ethernet destination */
    uint8_t src_mac[6];    /* secure mode: Ethernet source */
    char sv_id[SV_MAX_SVID_LEN];
    char dataset[SV_MAX_DATSET_LEN];
    uint32_t conf_rev;
    uint8_t smp_synch;     /* 0=none, 1=local, 2=global */
    uint16_t smp_rate;     /* samples per cycle */
    uint8_t num_channels;
} iec61850_rsv_pub_config_t;

/* Security material for the publisher (copied at enable time). */
typedef struct {
    uint16_t algo;         /* IEC61850_RSV_PUB_SEC_ALGO_* */
    uint8_t key[IEC61850_RSV_SEC_KEY_MAX];
    size_t key_len;
    uint32_t key_id;       /* KDC-assigned key identifier */
    uint16_t time_to_next_key; /* minutes; emitted verbatim */
} iec61850_rsv_pub_security_t;

typedef struct {
    iec61850_rsv_pub_config_t config;
    uint16_t smp_cnt;
    uint32_t spdu_number;  /* session-level counter, never resets */

    /* Sample data (fixed capacity) */
    int32_t samples[SV_MAX_SAMPLES];
    sv_quality_t quality[SV_MAX_SAMPLES];
    uint8_t sample_count;

    /* Retransmission (default OFF for R-SV) */
    bool has_retransmit;
    iec61850_retransmit_t retransmit;

    /* Security (optional) */
    bool security_enabled;
    iec61850_rsv_pub_security_t sec;

    /* Packet I/O (optional, not owned) */
    struct packet_io *io;
} iec61850_rsv_publisher_t;

void iec61850_rsv_pub_config_init(iec61850_rsv_pub_config_t *cfg);

void iec61850_rsv_publisher_init(iec61850_rsv_publisher_t *pub,
                                 const iec61850_rsv_pub_config_t *cfg);

void iec61850_rsv_publisher_destroy(iec61850_rsv_publisher_t *pub);

int iec61850_rsv_publisher_set_sample(iec61850_rsv_publisher_t *pub,
                                      size_t channel, int32_t value);
int iec61850_rsv_publisher_set_quality(iec61850_rsv_publisher_t *pub,
                                       size_t channel, sv_quality_t quality);
int iec61850_rsv_publisher_set_samples(iec61850_rsv_publisher_t *pub,
                                       const int32_t *values, size_t count);

/**
 * Reset the sample counter (smpCnt).
 */
void iec61850_rsv_publisher_reset_counter(iec61850_rsv_publisher_t *pub);

uint16_t iec61850_rsv_publisher_get_smp_cnt(const iec61850_rsv_publisher_t *pub);
uint32_t iec61850_rsv_publisher_get_spdu_number(
    const iec61850_rsv_publisher_t *pub);

/**
 * Set packet I/O backend.  Plain mode: UDP sender whose remote
 * address/port match the config.  Secure mode: raw or XSK backend.
 */
void iec61850_rsv_publisher_set_io(iec61850_rsv_publisher_t *pub,
                                   struct packet_io *io);

/**
 * Enable secure (signed) publication.
 *
 * @return 0 on success, -EINVAL on bad arguments (NULL, missing key,
 *         unsupported algorithm, AES-GMAC key not 128/256 bits),
 *         -ENOTSUP when built without -Denable_security=true
 */
int iec61850_rsv_publisher_enable_security(
    iec61850_rsv_publisher_t *pub,
    const iec61850_rsv_pub_security_t *cfg);

/**
 * Build the plain (unsigned) SPDU (no security extension).  No I/O.
 * @return 0 on success, negative errno on error
 */
int iec61850_rsv_publisher_build_spdu(iec61850_rsv_publisher_t *pub,
                                      uint8_t *buf, size_t buf_size,
                                      size_t *spdu_len);

/**
 * Build the complete wire message.  Plain mode: identical to
 * build_spdu().  Secure mode: [Eth][IPv4][UDP][SPDU + signature],
 * signed per the header comment.  No I/O.
 * @return 0 on success, negative errno on error
 */
int iec61850_rsv_publisher_build_frame(iec61850_rsv_publisher_t *pub,
                                       uint8_t *frame_buf, size_t frame_size,
                                       size_t *frame_len);

/**
 * Publish: build_frame() → packet_io_send().  Increments smpCnt
 * (wraparound at smp_rate * 50) and spdu_number.
 * @return 0 on success, negative errno on error
 */
int iec61850_rsv_publisher_publish(iec61850_rsv_publisher_t *pub);

/**
 * Retransmission service call (default OFF for R-SV).  When the
 * scheduler is due and enabled, re-publishes and returns 1.
 * @return 1 if sent, 0 if not due/disabled, negative errno on error
 */
int iec61850_rsv_publisher_retransmit(iec61850_rsv_publisher_t *pub);

/**
 * Enable retransmission scheduling (GOOSE backoff semantics).
 */
void iec61850_rsv_publisher_enable_retransmit(
    iec61850_rsv_publisher_t *pub,
    const iec61850_retransmit_config_t *cfg);

void iec61850_rsv_publisher_disable_retransmit(
    iec61850_rsv_publisher_t *pub);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_RSV_PUBLISHER_H */
