/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * GOOSE Publisher for IEC 61850-8-1
 *
 * C11 replacement for C++ GoosePublisher class.
 * Uses embedded fixed-capacity arrays (no heap allocation on hot path).
 *
 * License: BSD-2-Clause
 */

#ifndef IEC61850_GOOSE_PUBLISHER_H
#define IEC61850_GOOSE_PUBLISHER_H

#include "asn1/goose_ber.h"
#include "goose/goose_retransmission.h"
#include "transport/packet_io.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IEC61850_GOOSE_MAX_BYTE_ENTRY_LEN 256

typedef struct {
    uint8_t data[IEC61850_GOOSE_MAX_BYTE_ENTRY_LEN];
    size_t len;
} iec61850_goose_byte_entry_t;

typedef struct {
    uint16_t app_id;
    char goose_id[GOOSE_MAX_GOID_LEN];
    char gocb_ref[GOOSE_MAX_GOCBREF_LEN];
    char dataset[GOOSE_MAX_DATSET_LEN];
    uint32_t time_allowed_to_live;
    uint16_t vlan_id;
    uint8_t vlan_priority;
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
} iec61850_goose_config_t;

typedef struct {
    iec61850_goose_config_t config;
    uint32_t st_num;
    uint32_t sq_num;
    uint32_t conf_rev;

    /* Dataset: fixed-capacity arrays */
    goose_data_t data[GOOSE_MAX_ALLDATA_ENTRIES];
    iec61850_goose_byte_entry_t byte_storage[GOOSE_MAX_ALLDATA_ENTRIES];
    uint32_t data_count;

    /* Retransmission (optional) */
    bool has_retransmit;
    iec61850_retransmit_t retransmit;

    /* Security (optional) */
    bool security_enabled;
    void *key_manager;   /* iec61850_key_manager_t *, not owned */
    void *cert_manager;  /* iec61850_cert_manager_t *, not owned */

    /* Packet I/O (optional, not owned) */
    struct packet_io *io;
} iec61850_goose_publisher_t;

void iec61850_goose_config_init(iec61850_goose_config_t *cfg);

void iec61850_goose_publisher_init(iec61850_goose_publisher_t *pub,
                                    const iec61850_goose_config_t *cfg);

void iec61850_goose_publisher_destroy(iec61850_goose_publisher_t *pub);

/* Data setters (indexed access into dataset) */
int iec61850_goose_publisher_set_boolean(iec61850_goose_publisher_t *pub,
                                          size_t index, bool value);
int iec61850_goose_publisher_set_int32(iec61850_goose_publisher_t *pub,
                                        size_t index, int32_t value);
int iec61850_goose_publisher_set_uint32(iec61850_goose_publisher_t *pub,
                                         size_t index, uint32_t value);
int iec61850_goose_publisher_set_float32(iec61850_goose_publisher_t *pub,
                                          size_t index, float value);
int iec61850_goose_publisher_set_bitstring(iec61850_goose_publisher_t *pub,
                                            size_t index,
                                            const uint8_t *data, size_t len);
int iec61850_goose_publisher_set_octetstring(iec61850_goose_publisher_t *pub,
                                              size_t index,
                                              const uint8_t *data, size_t len);
int iec61850_goose_publisher_set_utctime(iec61850_goose_publisher_t *pub,
                                          size_t index,
                                          uint64_t timestamp_us,
                                          uint8_t time_quality);
int iec61850_goose_publisher_set_btime6(iec61850_goose_publisher_t *pub,
                                         size_t index,
                                         uint32_t ms_since_midnight,
                                         uint16_t days);

/**
 * Prepare a GOOSE APDU into a buffer (encode only, no networking).
 *
 * @param pub       Publisher
 * @param buf       Output buffer
 * @param buf_size  Buffer size
 * @param encoded   Output: encoded length
 * @return 0 on success
 */
int iec61850_goose_publisher_prepare(iec61850_goose_publisher_t *pub,
                                      uint8_t *buf, size_t buf_size,
                                      size_t *encoded);

/**
 * Notify state change (increments stNum, resets sqNum).
 */
void iec61850_goose_publisher_state_change(iec61850_goose_publisher_t *pub);

/**
 * Enable retransmission scheduling.
 */
void iec61850_goose_publisher_enable_retransmit(
    iec61850_goose_publisher_t *pub,
    const iec61850_retransmit_config_t *cfg);

uint32_t iec61850_goose_publisher_get_st_num(
    const iec61850_goose_publisher_t *pub);
uint32_t iec61850_goose_publisher_get_sq_num(
    const iec61850_goose_publisher_t *pub);

/**
 * Set packet I/O backend for publishing.
 */
void iec61850_goose_publisher_set_io(iec61850_goose_publisher_t *pub,
                                      struct packet_io *io);

/**
 * Enable IEC 62351-6 security on publisher.
 * When enabled, publish() signs the APDU and appends a security extension.
 *
 * @param pub          Publisher
 * @param key_manager  Loaded key manager (not owned, must outlive publisher)
 * @param cert_manager Loaded cert manager (not owned, must outlive publisher)
 * @return 0 on success, negative on error
 */
int iec61850_goose_publisher_enable_security(iec61850_goose_publisher_t *pub,
                                               void *key_manager,
                                               void *cert_manager);

/**
 * Build a complete GOOSE Ethernet frame (encode APDU + frame headers +
 * optional security extension). No I/O — testable without network.
 *
 * @param pub        Publisher
 * @param frame_buf  Output frame buffer
 * @param frame_size Buffer capacity
 * @param frame_len  Output: actual frame length
 * @return 0 on success, negative errno on error
 */
int iec61850_goose_publisher_build_frame(iec61850_goose_publisher_t *pub,
                                           uint8_t *frame_buf, size_t frame_size,
                                           size_t *frame_len);

/**
 * Publish a GOOSE frame: build_frame → send via packet_io.
 *
 * @param pub  Publisher (must have packet_io set)
 * @return 0 on success, negative errno on error
 */
int iec61850_goose_publisher_publish(iec61850_goose_publisher_t *pub);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_GOOSE_PUBLISHER_H */
