/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC TR 61850-90-5 R-GOOSE Publisher
 *
 * Publishes GOOSE APDUs wrapped in the 90-5 routable session profile
 * (see asn1/r_profile.h and src/asn1/rgoose_ber.c for the wire
 * layout) over UDP/IP.
 *
 * Transport modes
 * ===============
 *
 * Plain (unsigned) mode — default:
 *   The publisher emits only the SPDU; the kernel builds the IP/UDP
 *   headers.  Attach a packet_io created with
 *   packet_io_create_udp_sender(config.dst_ip, config.dst_port, mcast)
 *   (the UDP sender's remote must match the publisher config).
 *   build_spdu() emits the bare SPDU; publish() sends it via the io.
 *
 * Secure (signed) mode — after enable_security():
 *   The IEC 62351-6 routable adaptation signs the IPv4 header + UDP
 *   header + SPDU, so the publisher must build the headers itself:
 *   publish()/build_frame() emit [Eth(14)][IPv4(20)][UDP(8)][SPDU].
 *   Attach a raw (packet_io_create_raw) or XSK backend — the frame
 *   includes the link-layer header those backends expect.
 *
 *   Secure-mode UDP checksum: transmitted as zero ("checksum not
 *   used" per RFC 768).  A non-zero UDP checksum would cover the
 *   signature bytes while the signature covers the UDP header — a
 *   circular dependency.  The HMAC provides the integrity guarantee.
 *   The IPv4 header checksum is always computed and carried.
 *
 *   The signature is HMAC-SHA256 (32 octets, default) or AES-GMAC
 *   (16-octet tag) over the complete datagram from the IP header
 *   through the end of the SPDU, with the signature value bytes
 *   zeroed during the computation.  The signature TLV offset inside
 *   the SPDU is derived arithmetically from the encoded length (the
 *   signature is the final SPDU element) — never scanned for.  The
 *   AES-GMAC IV is derived per packet from the session fields —
 *   spdu_number(4) | appid(2) | key_id(4) | reserved(2),
 *   big-endian — mirroring the subscriber's verification path.
 *
 * Secure mode requires -Denable_security=true; without it
 * enable_security() returns -ENOTSUP.
 *
 * License: BSD-2-Clause
 */

#ifndef IEC61850_RGOOSE_PUBLISHER_H
#define IEC61850_RGOOSE_PUBLISHER_H

#include "asn1/goose_ber.h"
#include "asn1/r_profile.h"
#include "goose/goose_retransmission.h"
#include "transport/packet_io.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Dotted-quad IPv4 string capacity ("255.255.255.255" + NUL). */
#define IEC61850_RGOOSE_IP_ADDR_LEN   16U

/* Dataset byte-entry capacity (bitstring/octetstring storage). */
#define IEC61850_RGOOSE_MAX_BYTE_ENTRY_LEN 256U

/* SPDU capacity: 26 (secured session hdr) + 10 (user info) +
 * GOOSE_MAX_APDU_SIZE + 2 + 32 (signature TLV), rounded. */
#define IEC61850_RGOOSE_MAX_SPDU_LEN  1600U

/* Wire frame capacity: Ethernet(14) + IPv4(20) + UDP(8) +
 * IEC61850_RGOOSE_MAX_SPDU_LEN, rounded. */
#define IEC61850_RGOOSE_MAX_FRAME_LEN 1664U

/* Security configuration capacities. */
#define IEC61850_RGOOSE_SEC_KEY_MAX   64U
#define IEC61850_RGOOSE_SEC_HMAC_LEN  32U  /* HMAC-SHA256 output */
#define IEC61850_RGOOSE_SEC_GMAC_LEN  16U  /* AES-GMAC tag */

/* security_algos wire bits (emitted verbatim into the session
 * header; the codec assigns no semantics).  Publication supports
 * HMAC-SHA256 (default) and AES-GMAC (128/256-bit keys). */
#define IEC61850_RGOOSE_PUB_SEC_ALGO_HMAC_SHA256 0x0100U
#define IEC61850_RGOOSE_PUB_SEC_ALGO_AES_GMAC    0x0200U

typedef struct {
    uint8_t data[IEC61850_RGOOSE_MAX_BYTE_ENTRY_LEN];
    size_t len;
} iec61850_rgoose_byte_entry_t;

typedef struct {
    uint16_t appid;        /* payload + session APPID */
    char src_ip[IEC61850_RGOOSE_IP_ADDR_LEN];  /* secure mode: IP source */
    char dst_ip[IEC61850_RGOOSE_IP_ADDR_LEN];  /* plain: UDP dest; secure: IP dest */
    uint16_t src_port;     /* secure mode: UDP source port */
    uint16_t dst_port;     /* UDP destination port */
    uint8_t dst_mac[6];    /* secure mode: Ethernet destination */
    uint8_t src_mac[6];    /* secure mode: Ethernet source */
    char goose_id[GOOSE_MAX_GOID_LEN];
    char gocb_ref[GOOSE_MAX_GOCBREF_LEN];
    char dataset[GOOSE_MAX_DATSET_LEN];
    uint32_t time_allowed_to_live;
    uint32_t conf_rev;
} iec61850_rgoose_pub_config_t;

/* Security material for the publisher (IEC 62351-6 routable
 * adaptation, symmetric HMAC profile).  Copied into the publisher at
 * enable_security() time; the caller may reuse/free its copy. */
typedef struct {
    uint16_t algo;         /* IEC61850_RGOOSE_PUB_SEC_ALGO_* */
    uint8_t key[IEC61850_RGOOSE_SEC_KEY_MAX];
    size_t key_len;
    uint32_t key_id;       /* KDC-assigned key identifier */
    uint16_t time_to_next_key; /* minutes; emitted verbatim */
} iec61850_rgoose_pub_security_t;

typedef struct {
    iec61850_rgoose_pub_config_t config;
    uint32_t st_num;
    uint32_t sq_num;
    uint32_t spdu_number;  /* session-level counter, never resets */

    /* Dataset: fixed-capacity arrays */
    goose_data_t data[GOOSE_MAX_ALLDATA_ENTRIES];
    iec61850_rgoose_byte_entry_t byte_storage[GOOSE_MAX_ALLDATA_ENTRIES];
    uint32_t data_count;

    /* Retransmission (default ON for R-GOOSE, GOOSE backoff) */
    bool has_retransmit;
    iec61850_retransmit_t retransmit;

    /* Security (optional) */
    bool security_enabled;
    iec61850_rgoose_pub_security_t sec;

    /* Packet I/O (optional, not owned) */
    struct packet_io *io;
} iec61850_rgoose_publisher_t;

void iec61850_rgoose_pub_config_init(iec61850_rgoose_pub_config_t *cfg);

void iec61850_rgoose_publisher_init(iec61850_rgoose_publisher_t *pub,
                                    const iec61850_rgoose_pub_config_t *cfg);

void iec61850_rgoose_publisher_destroy(iec61850_rgoose_publisher_t *pub);

/* Data setters (indexed access into the dataset) */
int iec61850_rgoose_publisher_set_boolean(iec61850_rgoose_publisher_t *pub,
                                          size_t index, bool value);
int iec61850_rgoose_publisher_set_int32(iec61850_rgoose_publisher_t *pub,
                                        size_t index, int32_t value);
int iec61850_rgoose_publisher_set_uint32(iec61850_rgoose_publisher_t *pub,
                                         size_t index, uint32_t value);
int iec61850_rgoose_publisher_set_float32(iec61850_rgoose_publisher_t *pub,
                                          size_t index, float value);
int iec61850_rgoose_publisher_set_bitstring(iec61850_rgoose_publisher_t *pub,
                                            size_t index,
                                            const uint8_t *data, size_t len);
int iec61850_rgoose_publisher_set_octetstring(iec61850_rgoose_publisher_t *pub,
                                              size_t index,
                                              const uint8_t *data, size_t len);
int iec61850_rgoose_publisher_set_utctime(iec61850_rgoose_publisher_t *pub,
                                          size_t index,
                                          uint64_t timestamp_us,
                                          uint8_t time_quality);
int iec61850_rgoose_publisher_set_btime6(iec61850_rgoose_publisher_t *pub,
                                         size_t index,
                                         uint32_t ms_since_midnight,
                                         uint16_t days);

/**
 * Notify state change (increments stNum, resets sqNum, restarts the
 * retransmission backoff).
 */
void iec61850_rgoose_publisher_state_change(iec61850_rgoose_publisher_t *pub);

/**
 * Enable retransmission scheduling (GOOSE backoff semantics).
 * Enabled by default at init(); disable_retransmit() turns it off.
 */
void iec61850_rgoose_publisher_enable_retransmit(
    iec61850_rgoose_publisher_t *pub,
    const iec61850_retransmit_config_t *cfg);

void iec61850_rgoose_publisher_disable_retransmit(
    iec61850_rgoose_publisher_t *pub);

uint32_t iec61850_rgoose_publisher_get_st_num(
    const iec61850_rgoose_publisher_t *pub);
uint32_t iec61850_rgoose_publisher_get_sq_num(
    const iec61850_rgoose_publisher_t *pub);
uint32_t iec61850_rgoose_publisher_get_spdu_number(
    const iec61850_rgoose_publisher_t *pub);

/**
 * Set packet I/O backend.  Plain mode: UDP sender whose remote
 * address/port match the config.  Secure mode: raw or XSK backend.
 */
void iec61850_rgoose_publisher_set_io(iec61850_rgoose_publisher_t *pub,
                                      struct packet_io *io);

/**
 * Enable secure (signed) publication.
 *
 * @param pub  Publisher
 * @param cfg  Key material, key_id and rotation fields (copied).
 *             algo selects HMAC-SHA256 (default) or AES-GMAC;
 *             AES-GMAC requires a 128- or 256-bit key.
 * @return 0 on success, -EINVAL on bad arguments (NULL, missing key,
 *         unsupported algorithm, AES-GMAC key not 128/256 bits),
 *         -ENOTSUP when built without -Denable_security=true
 */
int iec61850_rgoose_publisher_enable_security(
    iec61850_rgoose_publisher_t *pub,
    const iec61850_rgoose_pub_security_t *cfg);

/**
 * Build the plain (unsigned) SPDU.  Ignores the security
 * configuration — the output carries no security extension.  No I/O.
 *
 * @return 0 on success, negative errno on error
 */
int iec61850_rgoose_publisher_build_spdu(iec61850_rgoose_publisher_t *pub,
                                         uint8_t *buf, size_t buf_size,
                                         size_t *spdu_len);

/**
 * Build the complete wire message.  Plain mode: identical to
 * build_spdu().  Secure mode: [Eth][IPv4][UDP][SPDU + signature],
 * signed per the header comment.  No I/O — testable without network.
 *
 * @return 0 on success, negative errno on error
 */
int iec61850_rgoose_publisher_build_frame(iec61850_rgoose_publisher_t *pub,
                                          uint8_t *frame_buf, size_t frame_size,
                                          size_t *frame_len);

/**
 * Publish: build_frame() → packet_io_send().  Increments sqNum and
 * spdu_number (also on failure — a partially consumed counter is
 * harmless, cf. the L2 publisher).
 *
 * @return 0 on success, negative errno on error
 */
int iec61850_rgoose_publisher_publish(iec61850_rgoose_publisher_t *pub);

/**
 * Retransmission service call (GOOSE backoff).  When the scheduler
 * is due, re-publishes the current dataset (same stNum, incremented
 * sqNum/spdu_number — GOOSE retransmission semantics) and returns 1.
 *
 * @return 1 if a retransmission was sent, 0 if not due (or
 *         retransmission disabled), negative errno on error
 */
int iec61850_rgoose_publisher_retransmit(iec61850_rgoose_publisher_t *pub);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_RGOOSE_PUBLISHER_H */
