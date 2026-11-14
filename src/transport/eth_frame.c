/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Ethernet Frame Builder for IEC 61850 GOOSE/SV
 *
 * Builds and parses Ethernet frames for GOOSE (0x88B8) and SV (0x88BA).
 * The tag stack matches the XDP filter nodes (WP-5b): untagged, one
 * 802.1Q tag, or 802.1ad QinQ (service tag + customer tag).
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

    if ((frame_buf == NULL) || (cfg == NULL) || (apdu == NULL) || (frame_len == NULL)) {
        return -EINVAL;
    }

    /* Calculate needed size */
    needed = 12U + 2U + IEC61850_PDU_HEADER_LEN + apdu_len;
    if (cfg->vlan_id > 0U) {
        needed += IEC61850_VLAN_TAG_LEN;
    }
    if (cfg->qinq_svlan_id > 0U) {
        /* 802.1ad service tag — only meaningful in front of a
         * customer tag, matching the XDP filter tag stack. */
        if (cfg->vlan_id == 0U) {
            return -EINVAL;
        }
        needed += IEC61850_VLAN_TAG_LEN;
    }

    if (needed > frame_size) {
        return -ENOSPC;
    }

    /* Destination MAC */
    (void)memcpy(&frame_buf[offset], cfg->dst_mac, 6U);
    offset += 6U;

    /* Source MAC */
    (void)memcpy(&frame_buf[offset], cfg->src_mac, 6U);
    offset += 6U;

    /* QinQ outer service tag (802.1ad, 0x88A8) if configured */
    if (cfg->qinq_svlan_id > 0U) {
        frame_buf[offset] = (uint8_t)(IEC61850_ETHERTYPE_QINQ >> 8);
        offset++;
        frame_buf[offset] = (uint8_t)(IEC61850_ETHERTYPE_QINQ & 0xFFU);
        offset++;

        tci = (uint16_t)((uint16_t)(cfg->qinq_svlan_priority & 0x07U) << 13) |
              (cfg->qinq_svlan_id & 0x0FFFU);
        frame_buf[offset] = (uint8_t)(tci >> 8);
        offset++;
        frame_buf[offset] = (uint8_t)(tci & 0xFFU);
        offset++;
    }

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

    /* PDU Header: Reserved1 (Ed.2 simulation bit in the LSB) +
     * Reserved2. */
    frame_buf[offset] = cfg->simulation ? 1U : 0U; offset++;
    frame_buf[offset] = 0; offset++;
    frame_buf[offset] = 0; offset++;
    frame_buf[offset] = 0; offset++;

    /* APDU data */
    (void)memcpy(&frame_buf[offset], apdu, apdu_len);
    offset += apdu_len;

    /* Update PDU length: from APPID to end (includes APPID + Length + Reserved + APDU) */
    pdu_length = (uint16_t)(IEC61850_PDU_HEADER_LEN + apdu_len);
    frame_buf[length_offset] = (uint8_t)(pdu_length >> 8U);
    frame_buf[length_offset + 1U] = (uint8_t)(pdu_length & 0xFFU);

    *frame_len = offset;
    return 0;
}

int iec61850_eth_frame_parse_qinq(const uint8_t *frame_buf, size_t frame_len,
                                   uint16_t *ethertype, uint16_t *app_id,
                                   uint16_t *vlan_id, uint16_t *svlan_id,
                                   const uint8_t **apdu, size_t *apdu_len, /* NOLINT(bugprone-easily-swappable-parameters) */
                                   size_t *apdu_offset_out,
                                   bool *simulation_out)
{
    size_t offset = 0;
    uint16_t et;
    uint16_t pdu_length;

    if ((frame_buf == NULL) || (ethertype == NULL) || (app_id == NULL) ||
        (vlan_id == NULL) || (apdu == NULL) || (apdu_len == NULL)) {
        return -EINVAL;
    }

    /* Need at least dst(6) + src(6) + ethertype(2) = 14 */
    if (frame_len < 14U) {
        return -EBADMSG;
    }

    /* Skip dst MAC + src MAC */
    offset = 12U;

    /* Read EtherType / walk the tag stack.
     *
     * Same stack as the XDP filter nodes (WP-5b): untagged, one
     * 802.1Q tag, or 802.1ad QinQ (service tag + exactly one
     * customer tag — 0x8100 or another 0x88A8).  Bounded to two
     * tags; anything else is rejected. */
    et = (uint16_t)((uint16_t)frame_buf[offset] << 8U) |
         (uint16_t)frame_buf[offset + 1U];
    offset += 2U;

    *vlan_id = 0;
    if (svlan_id != NULL) {
        *svlan_id = 0;
    }
    if (et == IEC61850_ETHERTYPE_QINQ) {
        /* 802.1ad QinQ: outer service tag */
        if (frame_len < (offset + 4U)) {
            return -EBADMSG;
        }
        uint16_t stci = (uint16_t)((uint16_t)frame_buf[offset] << 8U) |
                        (uint16_t)frame_buf[offset + 1U];
        if (svlan_id != NULL) {
            *svlan_id = stci & 0x0FFFU;
        }
        offset += 2U;

        /* The service tag must be followed by exactly one customer
         * tag (0x8100 or another 0x88A8) */
        et = (uint16_t)((uint16_t)frame_buf[offset] << 8U) |
             (uint16_t)frame_buf[offset + 1U];
        offset += 2U;
        if ((et != IEC61850_ETHERTYPE_VLAN) &&
            (et != IEC61850_ETHERTYPE_QINQ)) {
            return -EBADMSG;
        }
    }

    if ((et == IEC61850_ETHERTYPE_VLAN) ||
        (et == IEC61850_ETHERTYPE_QINQ)) {
        /* Customer (or single) 802.1Q/802.1ad tag */
        if (frame_len < (offset + 4U)) {
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
    if ((et != IEC61850_ETHERTYPE_GOOSE) && (et != IEC61850_ETHERTYPE_SV)) {
        return -EPROTONOSUPPORT;
    }

    /* Need PDU header (8 bytes minimum) */
    if (frame_len < (offset + IEC61850_PDU_HEADER_LEN)) {
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

    /* Reserved1: Ed.2 simulation bit (LSB of the first octet);
     * Reserved2 is skipped. */
    if (simulation_out != NULL) {
        *simulation_out = (frame_buf[offset] & 0x01U) != 0U;
    }
    offset += 4U;

    /* APDU starts here */
    if (pdu_length < IEC61850_PDU_HEADER_LEN) {
        return -EBADMSG;
    }

    size_t apdu_data_len = (size_t)(pdu_length - IEC61850_PDU_HEADER_LEN);
    if ((offset + apdu_data_len) > frame_len) {
        return -EBADMSG;
    }

    *apdu = &frame_buf[offset];
    *apdu_len = apdu_data_len;
    if (apdu_offset_out != NULL) {
        *apdu_offset_out = offset;
    }

    return 0;
}

int iec61850_eth_frame_parse(const uint8_t *frame_buf, size_t frame_len,
                              uint16_t *ethertype, uint16_t *app_id,
                              uint16_t *vlan_id,
                              const uint8_t **apdu, size_t *apdu_len,
                              size_t *apdu_offset_out,
                              bool *simulation_out)
{
    return iec61850_eth_frame_parse_qinq(frame_buf, frame_len, ethertype,
                                          app_id, vlan_id, NULL, apdu,
                                          apdu_len, apdu_offset_out,
                                          simulation_out);
}

int iec61850_eth_frame_update_pdu_length_tags(uint8_t *frame_buf,
                                               size_t frame_len,
                                               bool vlan, bool qinq)
{
    if (frame_buf == NULL) {
        return -EINVAL;
    }

    /* PDU Length field offset:
     * dst(6) + src(6) + [QinQ(4)] + [VLAN(4)] + EtherType(2) + APPID(2)
     * = offset to Length
     */
    size_t tags = (vlan ? IEC61850_VLAN_TAG_LEN : 0U) +
                  (qinq ? IEC61850_VLAN_TAG_LEN : 0U);
    size_t pdu_start_offset = 12U + tags + 2U;
    size_t length_offset = pdu_start_offset + 2U;  /* skip APPID */

    if ((length_offset + 2U) > frame_len) {
        return -EBADMSG;
    }

    /* PDU length = from APPID to end of frame (includes APPID + Len + Res + APDU + ext) */
    uint16_t pdu_length = (uint16_t)(frame_len - pdu_start_offset);
    frame_buf[length_offset] = (uint8_t)(pdu_length >> 8U);
    frame_buf[length_offset + 1U] = (uint8_t)(pdu_length & 0xFFU);

    return 0;
}

int iec61850_eth_frame_update_pdu_length(uint8_t *frame_buf, size_t frame_len,
                                           bool vlan)
{
    return iec61850_eth_frame_update_pdu_length_tags(frame_buf, frame_len,
                                                      vlan, false);
}

bool iec61850_eth_is_goose_multicast(const uint8_t *mac)
{
    if (mac == NULL) { return false; }
    return (mac[0] == 0x01U) && (mac[1] == 0x0CU) && (mac[2] == 0xCDU) && (mac[3] == 0x01U);
}

bool iec61850_eth_is_sv_multicast(const uint8_t *mac)
{
    if (mac == NULL) { return false; }
    return (mac[0] == 0x01U) && (mac[1] == 0x0CU) && (mac[2] == 0xCDU) && (mac[3] == 0x04U);
}
