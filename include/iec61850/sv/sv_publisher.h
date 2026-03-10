/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Sampled Values Publisher for IEC 61850-9-2
 *
 * C11 replacement for C++ SvPublisher class.
 *
 * License: BSD-3-Clause
 */

#ifndef IEC61850_SV_PUBLISHER_H
#define IEC61850_SV_PUBLISHER_H

#include "asn1/sv_ber.h"
#include "transport/packet_io.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint16_t app_id;
    char sv_id[SV_MAX_SVID_LEN];
    char dataset[SV_MAX_DATSET_LEN];
    uint32_t conf_rev;
    uint8_t smp_synch;     /* 0=none, 1=local, 2=global */
    uint16_t smp_rate;     /* samples per cycle */
    uint8_t num_channels;
    uint16_t vlan_id;
    uint8_t vlan_priority;
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
} iec61850_sv_config_t;

typedef struct {
    iec61850_sv_config_t config;
    uint16_t smp_cnt;

    /* Sample data (fixed capacity) */
    int32_t samples[SV_MAX_SAMPLES];
    sv_quality_t quality[SV_MAX_SAMPLES];
    uint8_t sample_count;

    /* Security (optional) */
    bool security_enabled;
    void *key_manager;   /* iec61850_key_manager_t *, not owned */
    void *cert_manager;  /* iec61850_cert_manager_t *, not owned */

    /* Packet I/O (optional, not owned) */
    struct packet_io *io;
} iec61850_sv_publisher_t;

void iec61850_sv_config_init(iec61850_sv_config_t *cfg);

void iec61850_sv_publisher_init(iec61850_sv_publisher_t *pub,
                                 const iec61850_sv_config_t *cfg);

void iec61850_sv_publisher_destroy(iec61850_sv_publisher_t *pub);

int iec61850_sv_publisher_set_sample(iec61850_sv_publisher_t *pub,
                                      size_t channel, int32_t value);

int iec61850_sv_publisher_set_quality(iec61850_sv_publisher_t *pub,
                                       size_t channel, sv_quality_t quality);

int iec61850_sv_publisher_set_samples(iec61850_sv_publisher_t *pub,
                                       const int32_t *values, size_t count);

/**
 * Prepare SV APDU into buffer (encode only, no networking).
 *
 * @param pub       Publisher
 * @param buf       Output buffer
 * @param buf_size  Buffer size
 * @param encoded   Output: encoded length
 * @return 0 on success
 */
int iec61850_sv_publisher_prepare(iec61850_sv_publisher_t *pub,
                                   uint8_t *buf, size_t buf_size,
                                   size_t *encoded);

void iec61850_sv_publisher_reset_counter(iec61850_sv_publisher_t *pub);

uint16_t iec61850_sv_publisher_get_smp_cnt(
    const iec61850_sv_publisher_t *pub);

/**
 * Set packet I/O backend for publishing.
 */
void iec61850_sv_publisher_set_io(iec61850_sv_publisher_t *pub,
                                    struct packet_io *io);

/**
 * Enable IEC 62351-6 security on SV publisher.
 */
int iec61850_sv_publisher_enable_security(iec61850_sv_publisher_t *pub,
                                            void *key_manager,
                                            void *cert_manager);

/**
 * Build a complete SV Ethernet frame (encode APDU + frame headers +
 * optional security extension). No I/O — testable without network.
 *
 * @param pub        Publisher
 * @param frame_buf  Output frame buffer
 * @param frame_size Buffer capacity
 * @param frame_len  Output: actual frame length
 * @return 0 on success, negative errno on error
 */
int iec61850_sv_publisher_build_frame(iec61850_sv_publisher_t *pub,
                                        uint8_t *frame_buf, size_t frame_size,
                                        size_t *frame_len);

/**
 * Publish an SV frame: build_frame → send via packet_io.
 *
 * @param pub  Publisher (must have packet_io set)
 * @return 0 on success, negative errno on error
 */
int iec61850_sv_publisher_publish(iec61850_sv_publisher_t *pub);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_SV_PUBLISHER_H */
