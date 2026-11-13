/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Ethernet Frame Builder for IEC 61850 GOOSE/SV
 *
 * Builds complete Ethernet frames:
 *   [Dst MAC (6)] [Src MAC (6)] [VLAN (4, optional)]
 *   [EtherType (2)] [PDU Header (8)] [APDU (variable)]
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

/* Frame size limits */
#define IEC61850_ETH_HEADER_LEN    14U   /* dst(6) + src(6) + ethertype(2) */
#define IEC61850_VLAN_TAG_LEN       4U   /* TPID(2) + TCI(2) */
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
    bool simulation;          /* Ed.2 frame-level simulation bit
                               * (reserved1 LSB, IEC 61850-8-1) */
} iec61850_eth_frame_config_t;

/**
 * Build a complete Ethernet frame around an APDU.
 *
 * Frame layout:
 *   [Dst MAC][Src MAC][VLAN?][EtherType][APPID][Length][Res1][Res2][APDU]
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
