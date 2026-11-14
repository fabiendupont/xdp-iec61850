/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Ethernet Frame Builder for IEC 61850 GOOSE/SV
 *
 * Builds complete Ethernet frames:
 *   [Dst MAC (6)] [Src MAC (6)] [QinQ (4, optional)] [VLAN (4, optional)]
 *   [EtherType (2)] [PDU Header (8)] [APDU (variable)]
 *
 * The tag stack matches the XDP filter nodes (WP-5b): untagged,
 * one 802.1Q tag, or 802.1ad QinQ (service tag + customer tag).
 *
 * PDU Header (IEC 61850-8-1 / IEC 61850-9-2):
 *   [APPID (2)] [Length (2)] [Reserved1 (2)] [Reserved2 (2)]
 */

#ifndef IEC61850_ETH_FRAME_H
#define IEC61850_ETH_FRAME_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* EtherType constants */
#define IEC61850_ETHERTYPE_GOOSE  0x88B8U
#define IEC61850_ETHERTYPE_SV     0x88BAU
#define IEC61850_ETHERTYPE_VLAN   0x8100U
#define IEC61850_ETHERTYPE_QINQ   0x88A8U  /* 802.1ad service VLAN */

/* Frame size limits */
#define IEC61850_ETH_HEADER_LEN    14U   /* dst(6) + src(6) + ethertype(2) */
#define IEC61850_VLAN_TAG_LEN       4U   /* TPID(2) + TCI(2) */
#define IEC61850_MAX_VLAN_TAGS      2U   /* 802.1ad QinQ: service + customer */
#define IEC61850_PDU_HEADER_LEN     8U   /* APPID(2) + Length(2) + Res1(2) + Res2(2) */
#define IEC61850_MAX_FRAME_SIZE  1544U   /* 14 + 4 + 8 + 1518 */

/**
 * Ethernet frame configuration.
 */
typedef struct {
    uint8_t dst_mac[6];      /* Destination MAC (multicast for GOOSE/SV) */
    uint8_t src_mac[6];      /* Source MAC */
    uint16_t ethertype;      /* 0x88B8 (GOOSE) or 0x88BA (SV) */
    uint16_t app_id;         /* APPID */
    uint16_t vlan_id;        /* 802.1Q VLAN ID (0 = no VLAN) */
    uint8_t vlan_priority;   /* 802.1Q priority (0-7) */
    uint16_t qinq_svlan_id;      /* 802.1ad outer service VLAN ID
                                  * (0 = no QinQ; requires vlan_id > 0) */
    uint8_t qinq_svlan_priority; /* 802.1ad outer priority (0-7) */
    bool simulation;          /* Ed.2 frame-level simulation bit
                               * (reserved1 LSB, IEC 61850-8-1) */
} iec61850_eth_frame_config_t;

/**
 * Build a complete Ethernet frame around an APDU.
 *
 * Frame layout:
 *   [Dst MAC][Src MAC][QinQ?][VLAN?][EtherType][APPID][Length][Res1][Res2][APDU]
 *
 * When cfg->qinq_svlan_id > 0 an 802.1ad service tag (0x88A8) is
 * emitted before the 802.1Q customer tag (cfg->vlan_id must be > 0;
 * a service tag without a customer tag is rejected, matching the
 * XDP filter tag stack).
 *
 * @param frame_buf    Output buffer for the complete frame
 * @param frame_size   Size of the output buffer
 * @param cfg          Frame configuration (MACs, VLAN, EtherType, APPID)
 * @param apdu         BER-encoded APDU data
 * @param apdu_len     Length of the APDU data
 * @param frame_len    Output: total frame length
 * @return 0 on success, negative errno on error
 */
int iec61850_eth_frame_build(uint8_t *frame_buf, size_t frame_size,
                              const iec61850_eth_frame_config_t *cfg,
                              const uint8_t *apdu, size_t apdu_len,
                              size_t *frame_len);

/**
 * Parse an Ethernet frame and extract the APDU.
 *
 * Validates EtherType, extracts VLAN info and APPID,
 * returns pointer into frame_buf where APDU starts.
 *
 * Accepts the same tag stack as the XDP filter nodes: untagged,
 * one 802.1Q tag, or 802.1ad QinQ (service tag + exactly one
 * customer tag).  *vlan_id reports the innermost (customer) VLAN.
 *
 * @param frame_buf    Received Ethernet frame
 * @param frame_len    Length of the received frame
 * @param ethertype    Output: EtherType (0x88B8 or 0x88BA)
 * @param app_id       Output: APPID from PDU header
 * @param vlan_id      Output: VLAN ID (0 if no VLAN tag)
 * @param apdu         Output: pointer to APDU data within frame_buf
 * @param apdu_len     Output: length of APDU data
 * @param apdu_offset_out  Output: byte offset of APDU within frame_buf (may be NULL)
 * @return 0 on success, negative errno on error
 */
int iec61850_eth_frame_parse(const uint8_t *frame_buf, size_t frame_len,
                              uint16_t *ethertype, uint16_t *app_id,
                              uint16_t *vlan_id,
                              const uint8_t **apdu, size_t *apdu_len,
                              size_t *apdu_offset_out,
                              bool *simulation_out);

/**
 * Parse an Ethernet frame, additionally reporting the 802.1ad
 * service VLAN.
 *
 * Same tag stack and outputs as iec61850_eth_frame_parse(), plus:
 *
 * @param svlan_id     Output: 802.1ad outer service VLAN ID
 *                     (0 if the frame is not QinQ-tagged; may be NULL)
 */
int iec61850_eth_frame_parse_qinq(const uint8_t *frame_buf, size_t frame_len,
                                   uint16_t *ethertype, uint16_t *app_id,
                                   uint16_t *vlan_id, uint16_t *svlan_id,
                                   const uint8_t **apdu, size_t *apdu_len,
                                   size_t *apdu_offset_out,
                                   bool *simulation_out);

/**
 * Update the PDU Length field in an already-built frame.
 *
 * Called after appending data (e.g., security extension) to update
 * the PDU Length to include the additional bytes.
 *
 * @param frame_buf  Frame buffer
 * @param frame_len  Current total frame length (including appended data)
 * @param vlan       true if frame has VLAN tag
 * @return 0 on success, negative errno on error
 */
int iec61850_eth_frame_update_pdu_length(uint8_t *frame_buf, size_t frame_len,
                                           bool vlan);

/**
 * Update the PDU Length field in an already-built frame, for any
 * tag depth.
 *
 * Same as iec61850_eth_frame_update_pdu_length(), extended for
 * 802.1ad QinQ frames:
 *
 * @param qinq  true if the frame carries an 802.1ad service tag in
 *              front of the (mandatory) 802.1Q customer tag
 * @return 0 on success, negative errno on error
 */
int iec61850_eth_frame_update_pdu_length_tags(uint8_t *frame_buf,
                                               size_t frame_len,
                                               bool vlan, bool qinq);

/**
 * Validate destination MAC is a valid GOOSE multicast address.
 * GOOSE: 01:0C:CD:01:xx:xx
 */
bool iec61850_eth_is_goose_multicast(const uint8_t *mac);

/**
 * Validate destination MAC is a valid SV multicast address.
 * SV: 01:0C:CD:04:xx:xx
 */
bool iec61850_eth_is_sv_multicast(const uint8_t *mac);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_ETH_FRAME_H */
