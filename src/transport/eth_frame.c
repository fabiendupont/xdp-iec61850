/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Ethernet Frame Builder for IEC 61850 GOOSE/SV
 *
 * Builds and parses Ethernet frames for GOOSE (0x88B8) and SV (0x88BA).
 */

#include "transport/eth_frame.h"
#include <string.h>
#include <errno.h>

int iec61850_eth_frame_build(uint8_t *frame_buf, size_t frame_size,
                              const iec61850_eth_frame_config_t *cfg,
                              const uint8_t *apdu, size_t apdu_len,
                              size_t *frame_len)
{
    size_t offset = 0;
    size_t needed;
    size_t length_offset;
    uint16_t pdu_length;
    uint16_t tci;

    if (frame_buf == NULL || cfg == NULL || apdu == NULL || frame_len == NULL) {
        return -EINVAL;
    }

    /* Calculate needed size */
    needed = 12U + 2U + IEC61850_PDU_HEADER_LEN + apdu_len;
    if (cfg->vlan_id > 0U) {
        needed += IEC61850_VLAN_TAG_LEN;
    }

    if (needed > frame_size) {
        return -ENOSPC;
    }

    /* Destination MAC */
    (void)memcpy(frame_buf + offset, cfg->dst_mac, 6U);
    offset += 6U;

    /* Source MAC */
    (void)memcpy(frame_buf + offset, cfg->src_mac, 6U);
    offset += 6U;

    /* VLAN tag (802.1Q) if configured */
    if (cfg->vlan_id > 0U) {
        frame_buf[offset] = (uint8_t)(IEC61850_ETHERTYPE_VLAN >> 8);
        offset++;
        frame_buf[offset] = (uint8_t)(IEC61850_ETHERTYPE_VLAN & 0xFFU);
        offset++;

        tci = (uint16_t)((uint16_t)(cfg->vlan_priority & 0x07U) << 13) |
              (cfg->vlan_id & 0x0FFFU);
        frame_buf[offset] = (uint8_t)(tci >> 8);
        offset++;
        frame_buf[offset] = (uint8_t)(tci & 0xFFU);
        offset++;
    }

    /* EtherType */
    frame_buf[offset] = (uint8_t)(cfg->ethertype >> 8);
    offset++;
    frame_buf[offset] = (uint8_t)(cfg->ethertype & 0xFFU);
    offset++;

    /* PDU Header: APPID */
    frame_buf[offset] = (uint8_t)(cfg->app_id >> 8);
    offset++;
    frame_buf[offset] = (uint8_t)(cfg->app_id & 0xFFU);
    offset++;

    /* PDU Header: Length (placeholder) */
    length_offset = offset;
    frame_buf[offset] = 0;
    offset++;
    frame_buf[offset] = 0;
    offset++;

    /* PDU Header: Reserved1 + Reserved2 */
    frame_buf[offset] = 0; offset++;
    frame_buf[offset] = 0; offset++;
    frame_buf[offset] = 0; offset++;
    frame_buf[offset] = 0; offset++;

    /* APDU data */
    (void)memcpy(frame_buf + offset, apdu, apdu_len);
    offset += apdu_len;

    /* Update PDU length: from APPID to end (includes APPID + Length + Reserved + APDU) */
    pdu_length = (uint16_t)(IEC61850_PDU_HEADER_LEN + apdu_len);
    frame_buf[length_offset] = (uint8_t)(pdu_length >> 8U);
    frame_buf[length_offset + 1U] = (uint8_t)(pdu_length & 0xFFU);

    *frame_len = offset;
    return 0;
}

int iec61850_eth_frame_parse(const uint8_t *frame_buf, size_t frame_len,
                              uint16_t *ethertype, uint16_t *app_id,
                              uint16_t *vlan_id,
                              const uint8_t **apdu, size_t *apdu_len)
{
    size_t offset = 0;
    uint16_t et;
    uint16_t pdu_length;

    if (frame_buf == NULL || ethertype == NULL || app_id == NULL ||
        vlan_id == NULL || apdu == NULL || apdu_len == NULL) {
        return -EINVAL;
    }

    /* Need at least dst(6) + src(6) + ethertype(2) = 14 */
    if (frame_len < 14U) {
        return -EBADMSG;
    }

    /* Skip dst MAC + src MAC */
    offset = 12U;

    /* Read EtherType / check for VLAN */
    et = (uint16_t)((uint16_t)frame_buf[offset] << 8U) |
         (uint16_t)frame_buf[offset + 1U];
    offset += 2U;

    *vlan_id = 0;
    if (et == IEC61850_ETHERTYPE_VLAN) {
        /* VLAN tagged frame */
        if (frame_len < offset + 4U) {
            return -EBADMSG;
        }
        uint16_t tci = (uint16_t)((uint16_t)frame_buf[offset] << 8U) |
                       (uint16_t)frame_buf[offset + 1U];
        *vlan_id = tci & 0x0FFFU;
        offset += 2U;

        /* Read actual EtherType */
        et = (uint16_t)((uint16_t)frame_buf[offset] << 8U) |
             (uint16_t)frame_buf[offset + 1U];
        offset += 2U;
    }

    *ethertype = et;

    /* Validate EtherType */
    if (et != IEC61850_ETHERTYPE_GOOSE && et != IEC61850_ETHERTYPE_SV) {
        return -EPROTONOSUPPORT;
    }

    /* Need PDU header (8 bytes minimum) */
    if (frame_len < offset + IEC61850_PDU_HEADER_LEN) {
        return -EBADMSG;
    }

    /* APPID */
    *app_id = (uint16_t)((uint16_t)frame_buf[offset] << 8U) |
              (uint16_t)frame_buf[offset + 1U];
    offset += 2U;

    /* PDU Length */
    pdu_length = (uint16_t)((uint16_t)frame_buf[offset] << 8U) |
                 (uint16_t)frame_buf[offset + 1U];
    offset += 2U;

    /* Skip Reserved1 + Reserved2 */
    offset += 4U;

    /* APDU starts here */
    if (pdu_length < IEC61850_PDU_HEADER_LEN) {
        return -EBADMSG;
    }

    size_t apdu_data_len = (size_t)(pdu_length - IEC61850_PDU_HEADER_LEN);
    if (offset + apdu_data_len > frame_len) {
        return -EBADMSG;
    }

    *apdu = frame_buf + offset;
    *apdu_len = apdu_data_len;

    return 0;
}

int iec61850_eth_frame_update_pdu_length(uint8_t *frame_buf, size_t frame_len,
                                           bool vlan)
{
    if (frame_buf == NULL) {
        return -EINVAL;
    }

    /* PDU Length field offset:
     * dst(6) + src(6) + [VLAN(4)] + EtherType(2) + APPID(2) = offset to Length
     */
    size_t pdu_start_offset = 12U + (vlan ? IEC61850_VLAN_TAG_LEN : 0U) + 2U;
    size_t length_offset = pdu_start_offset + 2U;  /* skip APPID */

    if (length_offset + 2U > frame_len) {
        return -EBADMSG;
    }

    /* PDU length = from APPID to end of frame (includes APPID + Len + Res + APDU + ext) */
    uint16_t pdu_length = (uint16_t)(frame_len - pdu_start_offset);
    frame_buf[length_offset] = (uint8_t)(pdu_length >> 8U);
    frame_buf[length_offset + 1U] = (uint8_t)(pdu_length & 0xFFU);

    return 0;
}

bool iec61850_eth_is_goose_multicast(const uint8_t *mac)
{
    if (mac == NULL) { return false; }
    return mac[0] == 0x01U && mac[1] == 0x0CU && mac[2] == 0xCDU && mac[3] == 0x01U;
}

bool iec61850_eth_is_sv_multicast(const uint8_t *mac)
{
    if (mac == NULL) { return false; }
    return mac[0] == 0x01U && mac[1] == 0x0CU && mac[2] == 0xCDU && mac[3] == 0x04U;
}
