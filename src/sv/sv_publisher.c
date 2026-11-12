/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * SV Publisher Implementation
 *
 * License: BSD-2-Clause
 */


#include "sv/sv_publisher.h"
#include "transport/eth_frame.h"
#include <string.h>
#include <time.h>
#include <errno.h>

#ifdef IEC61850_SECURITY_ENABLED
#include "security/key_manager.h"
#include "security/cert_manager.h"
#endif

void iec61850_sv_config_init(iec61850_sv_config_t *cfg)
{
    if (cfg == NULL) { return; }

    (void)memset(cfg, 0, sizeof(*cfg));
    cfg->app_id = 0x4000;
    (void)strncpy(cfg->sv_id, "SV_PUB_1", (size_t)SV_MAX_SVID_LEN - 1U);
    (void)strncpy(cfg->dataset, "IED1LD0/MSVCB01", (size_t)SV_MAX_DATSET_LEN - 1U);
    cfg->conf_rev = 1;
    cfg->smp_synch = 1;  /* LOCAL */
    cfg->smp_rate = 80;
    cfg->num_channels = 4;
    cfg->vlan_id = 100;
    cfg->vlan_priority = 4;

    /* SV multicast MAC */
    cfg->dst_mac[0] = 0x01; cfg->dst_mac[1] = 0x0C; cfg->dst_mac[2] = 0xCD;
    cfg->dst_mac[3] = 0x04; cfg->dst_mac[4] = 0x00; cfg->dst_mac[5] = 0x01;
}

void iec61850_sv_publisher_init(iec61850_sv_publisher_t *pub,
                                 const iec61850_sv_config_t *cfg)
{
    if (pub == NULL) { return; }

    (void)memset(pub, 0, sizeof(*pub));

    if (cfg != NULL) {
        pub->config = *cfg;
    } else {
        iec61850_sv_config_init(&pub->config);
    }

    pub->sample_count = pub->config.num_channels;
}

void iec61850_sv_publisher_destroy(iec61850_sv_publisher_t *pub)
{
    (void)pub;
}

int iec61850_sv_publisher_set_sample(iec61850_sv_publisher_t *pub,
                                      size_t channel, int32_t value)
{
    if ((pub == NULL) || (channel >= SV_MAX_SAMPLES)) { return -1; }

    if (channel >= pub->sample_count) {
        pub->sample_count = (uint8_t)(channel + 1U);
    }

    pub->samples[channel] = value;
    return 0;
}

int iec61850_sv_publisher_set_quality(iec61850_sv_publisher_t *pub,
                                       size_t channel, sv_quality_t quality)
{
    if ((pub == NULL) || (channel >= SV_MAX_SAMPLES)) { return -1; }

    pub->quality[channel] = quality;
    return 0;
}

int iec61850_sv_publisher_set_samples(iec61850_sv_publisher_t *pub,
                                       const int32_t *values, size_t count)
{
    if ((pub == NULL) || (values == NULL) || (count > SV_MAX_SAMPLES)) { return -1; }

    (void)memcpy(pub->samples, values, count * sizeof(int32_t));
    pub->sample_count = (uint8_t)count;
    return 0;
}

/*
 * WARNING: prepare() encodes the APDU only — it does NOT apply IEC 62351-6
 * security (signing). The output is unsigned. For signed frames, use
 * iec61850_sv_publisher_publish() which calls prepare() internally
 * and then appends the security extension.
 */
int iec61850_sv_publisher_prepare(iec61850_sv_publisher_t *pub,
                                   uint8_t *buf, size_t buf_size,
                                   size_t *encoded)
{
    int result;
    sv_apdu_t apdu;

    if ((pub == NULL) || (buf == NULL) || (encoded == NULL)) {
        return -1;
    }

    sv_apdu_init(&apdu);
    sv_asdu_init(&apdu.asdu[0]);

    (void)sv_set_svid(&apdu.asdu[0], pub->config.sv_id);

    if (pub->config.dataset[0] != '\0') {
        (void)sv_set_datset(&apdu.asdu[0], pub->config.dataset);
    }

    apdu.asdu[0].smpCnt  = pub->smp_cnt;
    apdu.asdu[0].confRev = pub->config.conf_rev;
    apdu.asdu[0].smpSynch = pub->config.smp_synch;
    apdu.asdu[0].smpRate = pub->config.smp_rate;
    apdu.asdu[0].has_smpRate = (pub->config.smp_rate > 0U);

    /* refrTm: include current UTC timestamp (normalizer strips it for comparison) */
    {
        struct timespec ts;
        if (clock_gettime(CLOCK_REALTIME, &ts) == 0) {
            apdu.asdu[0].has_refrTm = true;
            apdu.asdu[0].refrTm = (uint64_t)ts.tv_sec * 1000000ULL
                                  + (uint64_t)ts.tv_nsec / 1000ULL;
        }
    }

    /* Add samples */
    for (uint8_t i = 0; i < pub->sample_count; i++) {
        (void)sv_add_sample(&apdu.asdu[0], pub->samples[i], pub->quality[i]);
    }

    result = sv_encode_apdu(buf, buf_size, &apdu, encoded);
    if (result != 0) {
        return result;
    }

    /* smpCnt wraparound at smp_rate * 50 (match C++ behavior) */
    pub->smp_cnt++;
    if (pub->config.smp_rate > 0U) {
        uint16_t wrap = (uint16_t)(pub->config.smp_rate * 50U);
        if ((wrap > 0U) && (pub->smp_cnt >= wrap)) {
            pub->smp_cnt = 0;
        }
    }

    return 0;
}

void iec61850_sv_publisher_reset_counter(iec61850_sv_publisher_t *pub)
{
    if (pub != NULL) {
        pub->smp_cnt = 0;
    }
}

uint16_t iec61850_sv_publisher_get_smp_cnt(
    const iec61850_sv_publisher_t *pub)
{
    if (pub == NULL) { return 0; }
    return pub->smp_cnt;
}

void iec61850_sv_publisher_set_io(iec61850_sv_publisher_t *pub,
                                    struct packet_io *io)
{
    if (pub != NULL) {
        pub->io = io;
    }
}

int iec61850_sv_publisher_enable_security(iec61850_sv_publisher_t *pub,
                                            void *key_manager,
                                            void *cert_manager)
{
    if ((pub == NULL) || (key_manager == NULL) || (cert_manager == NULL)) {
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
 * Append IEC 62351-6 SV security extension.
 * SV uses tag [9] CONSTRUCTED (0xA9).
 */
#ifdef IEC61850_SECURITY_ENABLED
static int sv_append_security_extension(uint8_t *frame_buf, size_t frame_capacity,
                                          size_t *frame_len,
                                          const uint8_t *apdu, size_t apdu_len,
                                          iec61850_key_manager_t *km,
                                          iec61850_cert_manager_t *cm)
{
    uint8_t sig_buf[IEC61850_MAX_SIGNATURE_LEN];
    size_t sig_len = 0;
    uint8_t ext_buf[600];
    size_t ext_pos = 0;
    const uint8_t *key_id;
    int ret;

    ret = iec61850_key_manager_sign(km, apdu, apdu_len,
                                     sig_buf, sizeof(sig_buf), &sig_len);
    if (ret != IEC61850_SEC_OK) {
        return -1;
    }

    key_id = iec61850_cert_manager_get_key_id(cm);
    if (key_id == NULL) {
        return -1;
    }

    /* [0] timeOfCurrentKey */
    ext_buf[ext_pos] = 0x80; ext_pos++;
    ext_buf[ext_pos] = 8; ext_pos++;
    {
        struct timespec ts;
        (void)clock_gettime(CLOCK_REALTIME, &ts);
        uint32_t secs = (uint32_t)ts.tv_sec;
        ext_buf[ext_pos] = (uint8_t)(secs >> 24); ext_pos++;
        ext_buf[ext_pos] = (uint8_t)(secs >> 16); ext_pos++;
        ext_buf[ext_pos] = (uint8_t)(secs >> 8); ext_pos++;
        ext_buf[ext_pos] = (uint8_t)(secs); ext_pos++;
        uint32_t frac = (uint32_t)((uint64_t)ts.tv_nsec * 16777216ULL / 1000000000ULL);
        ext_buf[ext_pos] = (uint8_t)(frac >> 16); ext_pos++;
        ext_buf[ext_pos] = (uint8_t)(frac >> 8); ext_pos++;
        ext_buf[ext_pos] = (uint8_t)(frac); ext_pos++;
        ext_buf[ext_pos] = 0x18; ext_pos++;
    }

    /* [1] keyID — 4 bytes per IEC 62351-6 */
    ext_buf[ext_pos] = 0x81; ext_pos++;
    ext_buf[ext_pos] = (uint8_t)IEC61850_CERT_KEYID_LEN; ext_pos++;
    (void)memcpy(&ext_buf[ext_pos], key_id, (size_t)IEC61850_CERT_KEYID_LEN);
    ext_pos += (size_t)IEC61850_CERT_KEYID_LEN;

    /* [2] signature */
    ext_buf[ext_pos] = 0x82; ext_pos++;
    if (sig_len < 128U) {
        ext_buf[ext_pos] = (uint8_t)sig_len; ext_pos++;
    } else if (sig_len < 256U) {
        ext_buf[ext_pos] = 0x81; ext_pos++;
        ext_buf[ext_pos] = (uint8_t)sig_len; ext_pos++;
    } else {
        ext_buf[ext_pos] = 0x82; ext_pos++;
        ext_buf[ext_pos] = (uint8_t)(sig_len >> 8U); ext_pos++;
        ext_buf[ext_pos] = (uint8_t)(sig_len); ext_pos++;
    }
    if ((ext_pos + sig_len) > sizeof(ext_buf)) {
        return -1;
    }
    (void)memcpy(&ext_buf[ext_pos], sig_buf, sig_len);
    ext_pos += sig_len;

    /* Wrap in CONSTRUCTED [9] for SV (tag 0xA9) */
    uint8_t outer[604];
    size_t outer_pos = 0;
    outer[outer_pos] = 0xA9; outer_pos++;
    if (ext_pos < 128U) {
        outer[outer_pos] = (uint8_t)ext_pos; outer_pos++;
    } else if (ext_pos < 256U) {
        outer[outer_pos] = 0x81; outer_pos++;
        outer[outer_pos] = (uint8_t)ext_pos; outer_pos++;
    } else {
        outer[outer_pos] = 0x82; outer_pos++;
        outer[outer_pos] = (uint8_t)(ext_pos >> 8U); outer_pos++;
        outer[outer_pos] = (uint8_t)(ext_pos); outer_pos++;
    }
    if ((outer_pos + ext_pos) > sizeof(outer)) {
        return -1;
    }
    (void)memcpy(&outer[outer_pos], ext_buf, ext_pos);
    outer_pos += ext_pos;

    if ((*frame_len + outer_pos) > frame_capacity) {
        return -1;
    }
    (void)memcpy(&frame_buf[*frame_len], outer, outer_pos);
    *frame_len += outer_pos;

    return 0;
}
#endif /* IEC61850_SECURITY_ENABLED */

int iec61850_sv_publisher_build_frame(iec61850_sv_publisher_t *pub,
                                        uint8_t *frame_buf, size_t frame_size,
                                        size_t *frame_len)
{
    uint8_t apdu_buf[1500];
    size_t apdu_len = 0;
    iec61850_eth_frame_config_t fcfg;
    int ret;

    if ((pub == NULL) || (frame_buf == NULL) || (frame_len == NULL)) {
        return -EINVAL;
    }

    ret = iec61850_sv_publisher_prepare(pub, apdu_buf, sizeof(apdu_buf),
                                         &apdu_len);
    if (ret != 0) {
        return ret;
    }

    (void)memset(&fcfg, 0, sizeof(fcfg));
    (void)memcpy(fcfg.dst_mac, pub->config.dst_mac, 6);
    (void)memcpy(fcfg.src_mac, pub->config.src_mac, 6);
    fcfg.ethertype = IEC61850_ETHERTYPE_SV;
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
        ret = sv_append_security_extension(frame_buf, frame_size,
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

int iec61850_sv_publisher_publish(iec61850_sv_publisher_t *pub)
{
    uint8_t frame_buf[IEC61850_MAX_FRAME_SIZE];
    size_t frame_len = 0;
    int ret;

    if ((pub == NULL) || (pub->io == NULL)) {
        return -EINVAL;
    }

    ret = iec61850_sv_publisher_build_frame(pub, frame_buf,
                                              sizeof(frame_buf), &frame_len);
    if (ret != 0) {
        return ret;
    }

    return packet_io_send(pub->io, frame_buf, (uint32_t)frame_len);
}
