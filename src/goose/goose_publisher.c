/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * GOOSE Publisher Implementation
 *
 * License: BSD-3-Clause
 */


#include "goose/goose_publisher.h"
#include "transport/eth_frame.h"
#include <string.h>
#include <time.h>
#include <errno.h>

#ifdef IEC61850_SECURITY_ENABLED
#include "security/key_manager.h"
#include "security/cert_manager.h"
#endif

void iec61850_goose_config_init(iec61850_goose_config_t *cfg)
{
    if (cfg == NULL) { return; }

    (void)memset(cfg, 0, sizeof(*cfg));
    cfg->app_id = 0x0001;
    (void)strncpy(cfg->goose_id, "GOOSE_PUB_1", (size_t)GOOSE_MAX_GOID_LEN - 1U);
    (void)strncpy(cfg->gocb_ref, "IED1LD0/LLN0$GO$gcb01", (size_t)GOOSE_MAX_GOCBREF_LEN - 1U);
    (void)strncpy(cfg->dataset, "IED1LD0/LLN0$DS1", (size_t)GOOSE_MAX_DATSET_LEN - 1U);
    cfg->time_allowed_to_live = 2000;
    cfg->vlan_id = 100;
    cfg->vlan_priority = 4;

    /* GOOSE multicast MAC */
    cfg->dst_mac[0] = 0x01; cfg->dst_mac[1] = 0x0C; cfg->dst_mac[2] = 0xCD;
    cfg->dst_mac[3] = 0x01; cfg->dst_mac[4] = 0x00; cfg->dst_mac[5] = 0x01;
}

void iec61850_goose_publisher_init(iec61850_goose_publisher_t *pub,
                                    const iec61850_goose_config_t *cfg)
{
    if (pub == NULL) { return; }

    (void)memset(pub, 0, sizeof(*pub));

    if (cfg != NULL) {
        pub->config = *cfg;
    } else {
        iec61850_goose_config_init(&pub->config);
    }

    pub->conf_rev = 1;
}

void iec61850_goose_publisher_destroy(iec61850_goose_publisher_t *pub)
{
    (void)pub;
}

/* Ensure data array has at least index+1 entries */
static int ensure_data_index(iec61850_goose_publisher_t *pub, size_t index)
{
    if (index >= GOOSE_MAX_ALLDATA_ENTRIES) {
        return -1;
    }
    if (index >= pub->data_count) {
        /* Zero-fill any gaps */
        for (size_t i = pub->data_count; i <= index; i++) {
            (void)memset(&pub->data[i], 0, sizeof(pub->data[i]));
            pub->byte_storage[i].len = 0;
        }
        pub->data_count = (uint32_t)(index + 1U);
    }
    return 0;
}

int iec61850_goose_publisher_set_boolean(iec61850_goose_publisher_t *pub,
                                          size_t index, bool value)
{
    if (pub == NULL || ensure_data_index(pub, index) != 0) { return -1; }
    pub->data[index].type = GOOSE_DATA_BOOLEAN;
    pub->data[index].value.boolean = value;
    return 0;
}

int iec61850_goose_publisher_set_int32(iec61850_goose_publisher_t *pub,
                                        size_t index, int32_t value)
{
    if (pub == NULL || ensure_data_index(pub, index) != 0) { return -1; }
    pub->data[index].type = GOOSE_DATA_INT32;
    pub->data[index].value.int32 = value;
    return 0;
}

int iec61850_goose_publisher_set_uint32(iec61850_goose_publisher_t *pub,
                                         size_t index, uint32_t value)
{
    if (pub == NULL || ensure_data_index(pub, index) != 0) { return -1; }
    pub->data[index].type = GOOSE_DATA_UINT32;
    pub->data[index].value.uint32 = value;
    return 0;
}

int iec61850_goose_publisher_set_float32(iec61850_goose_publisher_t *pub,
                                          size_t index, float value)
{
    if (pub == NULL || ensure_data_index(pub, index) != 0) { return -1; }
    pub->data[index].type = GOOSE_DATA_FLOAT32;
    pub->data[index].value.float32 = value;
    return 0;
}

int iec61850_goose_publisher_set_bitstring(iec61850_goose_publisher_t *pub,
                                            size_t index,
                                            const uint8_t *data, size_t len)
{
    if (pub == NULL || data == NULL || ensure_data_index(pub, index) != 0) {
        return -1;
    }
    if (len > (size_t)IEC61850_GOOSE_MAX_BYTE_ENTRY_LEN) { return -1; }

    /* Copy to owned storage */
    (void)memcpy(pub->byte_storage[index].data, data, len);
    pub->byte_storage[index].len = len;

    pub->data[index].type = GOOSE_DATA_BITSTRING;
    pub->data[index].value.bytes.data = pub->byte_storage[index].data;
    pub->data[index].value.bytes.len = len;
    return 0;
}

int iec61850_goose_publisher_set_octetstring(iec61850_goose_publisher_t *pub,
                                              size_t index,
                                              const uint8_t *data, size_t len)
{
    if (pub == NULL || data == NULL || ensure_data_index(pub, index) != 0) {
        return -1;
    }
    if (len > (size_t)IEC61850_GOOSE_MAX_BYTE_ENTRY_LEN) { return -1; }

    (void)memcpy(pub->byte_storage[index].data, data, len);
    pub->byte_storage[index].len = len;

    pub->data[index].type = GOOSE_DATA_OCTETSTRING;
    pub->data[index].value.bytes.data = pub->byte_storage[index].data;
    pub->data[index].value.bytes.len = len;
    return 0;
}

/*
 * WARNING: prepare() encodes the APDU only — it does NOT apply IEC 62351-6
 * security (signing). The output is unsigned. For signed frames, use
 * iec61850_goose_publisher_publish() which calls prepare() internally
 * and then appends the security extension.
 */
int iec61850_goose_publisher_prepare(iec61850_goose_publisher_t *pub,
                                      uint8_t *buf, size_t buf_size,
                                      size_t *encoded)
{
    int result;
    goose_apdu_t apdu;
    struct timespec ts;

    if (pub == NULL || buf == NULL || encoded == NULL) {
        return -1;
    }

    goose_apdu_init(&apdu);

    (void)goose_set_gocbref(&apdu, pub->config.gocb_ref);
    (void)goose_set_datset(&apdu, pub->config.dataset);
    (void)goose_set_goid(&apdu, pub->config.goose_id);

    apdu.timeAllowedtoLive = pub->config.time_allowed_to_live;
    apdu.confRev = pub->conf_rev;
    apdu.stNum = pub->st_num;
    apdu.sqNum = pub->sq_num;
    apdu.test = false;
    apdu.ndsCom = false;
    apdu.numDatSetEntries = pub->data_count;

    /* Timestamp */
    (void)clock_gettime(CLOCK_REALTIME, &ts);
    apdu.timestamp = (uint64_t)ts.tv_sec * 1000000ULL +
                     (uint64_t)ts.tv_nsec / 1000ULL;

    /* Copy data entries */
    for (uint32_t i = 0; i < pub->data_count; i++) {
        apdu.allData[i] = pub->data[i];
    }

    /* Encode APDU */
    result = goose_encode_apdu(buf, buf_size, &apdu, encoded);
    if (result != GOOSE_BER_OK) {
        return result;
    }

    /* Increment sqNum for next packet */
    pub->sq_num++;

    return 0;
}

void iec61850_goose_publisher_state_change(iec61850_goose_publisher_t *pub)
{
    if (pub == NULL) { return; }

    pub->st_num++;
    pub->sq_num = 0;

    if (pub->has_retransmit) {
        iec61850_retransmit_on_state_change(&pub->retransmit);
    }
}

void iec61850_goose_publisher_enable_retransmit(
    iec61850_goose_publisher_t *pub,
    const iec61850_retransmit_config_t *cfg)
{
    if (pub == NULL) { return; }

    iec61850_retransmit_init(&pub->retransmit, cfg);
    pub->has_retransmit = true;
}

uint32_t iec61850_goose_publisher_get_st_num(
    const iec61850_goose_publisher_t *pub)
{
    if (pub == NULL) { return 0; }
    return pub->st_num;
}

uint32_t iec61850_goose_publisher_get_sq_num(
    const iec61850_goose_publisher_t *pub)
{
    if (pub == NULL) { return 0; }
    return pub->sq_num;
}

void iec61850_goose_publisher_set_io(iec61850_goose_publisher_t *pub,
                                      struct packet_io *io)
{
    if (pub != NULL) {
        pub->io = io;
    }
}

int iec61850_goose_publisher_enable_security(iec61850_goose_publisher_t *pub,
                                               void *key_manager,
                                               void *cert_manager)
{
    if (pub == NULL || key_manager == NULL || cert_manager == NULL) {
        return -EINVAL;
    }

#ifdef IEC61850_SECURITY_ENABLED
    /* MISRA 11.5: opaque key_manager/cert_manager handles, deviation Cat. 3 */
    iec61850_key_manager_t *km = (iec61850_key_manager_t *)key_manager;
    iec61850_cert_manager_t *cm = (iec61850_cert_manager_t *)cert_manager;

    if (!iec61850_key_manager_is_loaded(km)) {
        return -EINVAL;
    }
    if (!iec61850_cert_manager_is_loaded(cm)) {
        return -EINVAL;
    }

    pub->key_manager = key_manager;
    pub->cert_manager = cert_manager;
    pub->security_enabled = true;
    return 0;
#else
    (void)key_manager;
    (void)cert_manager;
    return -ENOTSUP;
#endif
}

/*
 * Append IEC 62351-6 security extension to frame.
 * GOOSE security extension: tag [12] CONSTRUCTED
 *   timeOfCurrentKey  [0] UtcTime (8 bytes)
 *   keyID             [1] INTEGER (4 bytes)
 *   signature         [2] OCTET STRING
 */
#ifdef IEC61850_SECURITY_ENABLED
static int append_security_extension(uint8_t *frame_buf, size_t frame_capacity,
                                       size_t *frame_len,
                                       const uint8_t *apdu, size_t apdu_len,
                                       iec61850_key_manager_t *km,
                                       iec61850_cert_manager_t *cm)
{
    uint8_t sig_buf[IEC61850_MAX_SIGNATURE_LEN];
    size_t sig_len = 0;
    uint8_t ext_buf[600];  /* security extension TLV */
    size_t ext_pos = 0;
    const uint8_t *key_id;
    int ret;

    /* Sign the APDU */
    ret = iec61850_key_manager_sign(km, apdu, apdu_len,
                                     sig_buf, sizeof(sig_buf), &sig_len);
    if (ret != IEC61850_SEC_OK) {
        return -1;
    }

    key_id = iec61850_cert_manager_get_key_id(cm);
    if (key_id == NULL) {
        return -1;
    }

    /* Build security extension TLV:
     * [0] timeOfCurrentKey: 8 bytes UtcTime (current time)
     * [1] keyID: 4 bytes (first 4 of SHA-1 key ID)
     * [2] signature: variable length
     */

    /* [0] IMPLICIT UtcTime — tag 0x80, len 8 */
    ext_buf[ext_pos++] = 0x80;
    ext_buf[ext_pos++] = 8;
    {
        struct timespec ts;
        (void)clock_gettime(CLOCK_REALTIME, &ts);
        uint32_t secs = (uint32_t)ts.tv_sec;
        /* UtcTime: 4 bytes seconds, 3 bytes fraction, 1 byte quality */
        ext_buf[ext_pos++] = (uint8_t)(secs >> 24);
        ext_buf[ext_pos++] = (uint8_t)(secs >> 16);
        ext_buf[ext_pos++] = (uint8_t)(secs >> 8);
        ext_buf[ext_pos++] = (uint8_t)(secs);
        uint32_t frac = (uint32_t)((uint64_t)ts.tv_nsec * 16777216ULL / 1000000000ULL);
        ext_buf[ext_pos++] = (uint8_t)(frac >> 16);
        ext_buf[ext_pos++] = (uint8_t)(frac >> 8);
        ext_buf[ext_pos++] = (uint8_t)(frac);
        ext_buf[ext_pos++] = 0x18;  /* quality: clockNotSynchronized=false, leapSecond=1, timeAccuracy=8 */
    }

    /* [1] IMPLICIT OCTET STRING keyID — tag 0x81, 4 bytes per IEC 62351-6 */
    ext_buf[ext_pos++] = 0x81;
    ext_buf[ext_pos++] = (uint8_t)IEC61850_CERT_KEYID_LEN;
    (void)memcpy(&ext_buf[ext_pos], key_id, (size_t)IEC61850_CERT_KEYID_LEN);
    ext_pos += (size_t)IEC61850_CERT_KEYID_LEN;

    /* [2] IMPLICIT OCTET STRING signature — tag 0x82 */
    ext_buf[ext_pos++] = 0x82;
    if (sig_len < 128U) {
        ext_buf[ext_pos++] = (uint8_t)sig_len;
    } else if (sig_len < 256U) {
        ext_buf[ext_pos++] = 0x81;
        ext_buf[ext_pos++] = (uint8_t)sig_len;
    } else {
        ext_buf[ext_pos++] = 0x82;
        ext_buf[ext_pos++] = (uint8_t)(sig_len >> 8U);
        ext_buf[ext_pos++] = (uint8_t)(sig_len);
    }
    if (ext_pos + sig_len > sizeof(ext_buf)) {
        return -1;
    }
    (void)memcpy(&ext_buf[ext_pos], sig_buf, sig_len);
    ext_pos += sig_len;

    /* Wrap in CONSTRUCTED [12] for GOOSE (tag 0xAC) */
    uint8_t outer[604];
    size_t outer_pos = 0;
    outer[outer_pos++] = 0xAC;  /* [12] CONSTRUCTED */
    if (ext_pos < 128U) {
        outer[outer_pos++] = (uint8_t)ext_pos;
    } else if (ext_pos < 256U) {
        outer[outer_pos++] = 0x81;
        outer[outer_pos++] = (uint8_t)ext_pos;
    } else {
        outer[outer_pos++] = 0x82;
        outer[outer_pos++] = (uint8_t)(ext_pos >> 8U);
        outer[outer_pos++] = (uint8_t)(ext_pos);
    }
    if (outer_pos + ext_pos > sizeof(outer)) {
        return -1;
    }
    (void)memcpy(&outer[outer_pos], ext_buf, ext_pos);
    outer_pos += ext_pos;

    /* Append to frame */
    if (*frame_len + outer_pos > frame_capacity) {
        return -1;
    }
    (void)memcpy(&frame_buf[*frame_len], outer, outer_pos);
    *frame_len += outer_pos;

    return 0;
}
#endif /* IEC61850_SECURITY_ENABLED */

int iec61850_goose_publisher_build_frame(iec61850_goose_publisher_t *pub,
                                           uint8_t *frame_buf, size_t frame_size,
                                           size_t *frame_len)
{
    uint8_t apdu_buf[GOOSE_MAX_APDU_SIZE];
    size_t apdu_len = 0;
    iec61850_eth_frame_config_t fcfg;
    int ret;

    if (pub == NULL || frame_buf == NULL || frame_len == NULL) {
        return -EINVAL;
    }

    ret = iec61850_goose_publisher_prepare(pub, apdu_buf, sizeof(apdu_buf),
                                            &apdu_len);
    if (ret != 0) {
        return ret;
    }

    (void)memset(&fcfg, 0, sizeof(fcfg));
    (void)memcpy(fcfg.dst_mac, pub->config.dst_mac, 6);
    (void)memcpy(fcfg.src_mac, pub->config.src_mac, 6);
    fcfg.ethertype = IEC61850_ETHERTYPE_GOOSE;
    fcfg.app_id = pub->config.app_id;
    fcfg.vlan_id = pub->config.vlan_id;
    fcfg.vlan_priority = pub->config.vlan_priority;

    ret = iec61850_eth_frame_build(frame_buf, frame_size, &fcfg,
                                    apdu_buf, apdu_len, frame_len);
    if (ret != 0) {
        return ret;
    }

#ifdef IEC61850_SECURITY_ENABLED
    if (pub->security_enabled) {
        /* MISRA 11.5: opaque key_manager/cert_manager handles, deviation Cat. 3 */
        ret = append_security_extension(frame_buf, frame_size,
                                          frame_len, apdu_buf, apdu_len,
                                          (iec61850_key_manager_t *)pub->key_manager,
                                          (iec61850_cert_manager_t *)pub->cert_manager);
        if (ret != 0) {
            return -EIO;
        }
        ret = iec61850_eth_frame_update_pdu_length(frame_buf, *frame_len,
                                                     pub->config.vlan_id > 0U);
        if (ret != 0) {
            return ret;
        }
    }
#endif

    return 0;
}

int iec61850_goose_publisher_publish(iec61850_goose_publisher_t *pub)
{
    uint8_t frame_buf[IEC61850_MAX_FRAME_SIZE];
    size_t frame_len = 0;
    int ret;

    if (pub == NULL || pub->io == NULL) {
        return -EINVAL;
    }

    ret = iec61850_goose_publisher_build_frame(pub, frame_buf,
                                                 sizeof(frame_buf), &frame_len);
    if (ret != 0) {
        return ret;
    }

    return packet_io_send(pub->io, frame_buf, (uint32_t)frame_len);
}
