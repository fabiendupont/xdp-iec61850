/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC TR 61850-90-5 R-SV Publisher Implementation
 *
 * Transport modes and the secure-mode signing flow are documented in
 * include/iec61850/sv/rsv_publisher.h.  Wire layout of the SPDU:
 * src/asn1/rsv_ber.c (WP-4a derivation).
 *
 * Secure-mode signature patch offset derivation: the 0x85 signature
 * TLV is the FINAL element of the SPDU and its length is fixed per
 * algorithm (HMAC-SHA256 = IEC61850_RSV_SEC_HMAC_LEN, AES-GMAC =
 * IEC61850_RSV_SEC_GMAC_LEN), so given the encoded SPDU length the
 * signature VALUE starts at
 *
 *     sig_value_off = spdu_len - sig_len
 *
 * (TLV header at sig_value_off - 2, defensively asserted to carry
 * tag 0x85).  The offset is computed arithmetically — the frame is
 * never scanned for the tag.
 *
 * License: BSD-2-Clause
 */

#include "sv/rsv_publisher.h"
#include "transport/ip_udp_frame.h"

#include <errno.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>

#ifdef IEC61850_SECURITY_ENABLED
#include "security/hmac_verify.h"
#endif

/* Signature tag of the 90-5 security extension (see
 * src/asn1/rsv_ber.c; not exported by the frozen codec header). */
#define RSV_SIG_TAG 0x85U

/* EtherType for IPv4 (Ethernet header of secure-mode frames). */
#define RSV_ETH_P_IPV4 0x0800U

/* Ethernet header length of secure-mode frames. */
#define RSV_ETH_HDR_LEN 14U

#ifdef IEC61850_SECURITY_ENABLED
static uint32_t rsv_now_epoch_s(void)
{
    struct timespec ts;

    (void)clock_gettime(CLOCK_REALTIME, &ts);
    return (uint32_t)ts.tv_sec;
}
#endif

void iec61850_rsv_pub_config_init(iec61850_rsv_pub_config_t *cfg)
{
    if (cfg == NULL) {
        return;
    }

    (void)memset(cfg, 0, sizeof(*cfg));
    cfg->appid = 0x4000U;
    (void)strncpy(cfg->src_ip, "127.0.0.1", (size_t)IEC61850_RSV_IP_ADDR_LEN - 1U);
    (void)strncpy(cfg->dst_ip, "127.0.0.1", (size_t)IEC61850_RSV_IP_ADDR_LEN - 1U);
    cfg->src_port = IEC61850_RSV_PORT_DEFAULT;
    cfg->dst_port = IEC61850_RSV_PORT_DEFAULT;
    (void)strncpy(cfg->sv_id, "RSV_PUB_1", (size_t)SV_MAX_SVID_LEN - 1U);
    (void)strncpy(cfg->dataset, "IED1LD0/MSVCB01", (size_t)SV_MAX_DATSET_LEN - 1U);
    cfg->conf_rev = 1U;
    cfg->smp_synch = 1U;  /* LOCAL */
    cfg->smp_rate = 80U;
    cfg->num_channels = 4U;
}

void iec61850_rsv_publisher_init(iec61850_rsv_publisher_t *pub,
                                 const iec61850_rsv_pub_config_t *cfg)
{
    if (pub == NULL) {
        return;
    }

    (void)memset(pub, 0, sizeof(*pub));

    if (cfg != NULL) {
        pub->config = *cfg;
    } else {
        iec61850_rsv_pub_config_init(&pub->config);
    }

    pub->sample_count = pub->config.num_channels;

    /* R-SV does not retransmit sampled values by default. */
    pub->has_retransmit = false;
    iec61850_retransmit_init(&pub->retransmit, NULL);
}

void iec61850_rsv_publisher_destroy(iec61850_rsv_publisher_t *pub)
{
    (void)pub;
}

int iec61850_rsv_publisher_set_sample(iec61850_rsv_publisher_t *pub,
                                      size_t channel, int32_t value)
{
    if ((pub == NULL) || (channel >= (size_t)SV_MAX_SAMPLES)) {
        return -EINVAL;
    }

    if (channel >= (size_t)pub->sample_count) {
        pub->sample_count = (uint8_t)(channel + 1U);
    }

    pub->samples[channel] = value;
    return 0;
}

int iec61850_rsv_publisher_set_quality(iec61850_rsv_publisher_t *pub,
                                       size_t channel, sv_quality_t quality)
{
    if ((pub == NULL) || (channel >= (size_t)SV_MAX_SAMPLES)) {
        return -EINVAL;
    }

    pub->quality[channel] = quality;
    return 0;
}

int iec61850_rsv_publisher_set_samples(iec61850_rsv_publisher_t *pub,
                                       const int32_t *values, size_t count)
{
    if ((pub == NULL) || (values == NULL) ||
        (count > (size_t)SV_MAX_SAMPLES)) {
        return -EINVAL;
    }

    (void)memcpy(pub->samples, values, count * sizeof(int32_t));
    pub->sample_count = (uint8_t)count;
    return 0;
}

void iec61850_rsv_publisher_reset_counter(iec61850_rsv_publisher_t *pub)
{
    if (pub != NULL) {
        pub->smp_cnt = 0U;
    }
}

uint16_t iec61850_rsv_publisher_get_smp_cnt(const iec61850_rsv_publisher_t *pub)
{
    if (pub == NULL) {
        return 0U;
    }
    return pub->smp_cnt;
}

uint32_t iec61850_rsv_publisher_get_spdu_number(
    const iec61850_rsv_publisher_t *pub)
{
    if (pub == NULL) {
        return 0U;
    }
    return pub->spdu_number;
}

void iec61850_rsv_publisher_set_io(iec61850_rsv_publisher_t *pub,
                                   struct packet_io *io)
{
    if (pub != NULL) {
        pub->io = io;
    }
}

int iec61850_rsv_publisher_enable_security(
    iec61850_rsv_publisher_t *pub,
    const iec61850_rsv_pub_security_t *cfg)
{
    if ((pub == NULL) || (cfg == NULL)) {
        return -EINVAL;
    }
    if ((cfg->key_len == 0U) ||
        (cfg->key_len > (size_t)IEC61850_RSV_SEC_KEY_MAX)) {
        return -EINVAL;
    }
    if ((cfg->algo != (uint16_t)IEC61850_RSV_PUB_SEC_ALGO_HMAC_SHA256) &&
        (cfg->algo != (uint16_t)IEC61850_RSV_PUB_SEC_ALGO_AES_GMAC)) {
        return -EINVAL;
    }

#ifdef IEC61850_SECURITY_ENABLED
    if ((cfg->algo == (uint16_t)IEC61850_RSV_PUB_SEC_ALGO_AES_GMAC) &&
        (cfg->key_len != 16U) && (cfg->key_len != 32U)) {
        /* AES-GMAC supports 128/256-bit keys only (aes_gmac_sign). */
        return -EINVAL;
    }
    pub->sec = *cfg;
    pub->security_enabled = true;
    return 0;
#else
    return -ENOTSUP;
#endif
}

/* Fill an SV APDU from the publisher state (mirrors the L2 SV
 * publisher's prepare()). */
static void rsv_fill_apdu(const iec61850_rsv_publisher_t *pub,
                          sv_apdu_t *apdu)
{
    sv_apdu_init(apdu);
    sv_asdu_init(&apdu->asdu[0]);

    (void)sv_set_svid(&apdu->asdu[0], pub->config.sv_id);

    if (pub->config.dataset[0] != '\0') {
        (void)sv_set_datset(&apdu->asdu[0], pub->config.dataset);
    }

    apdu->asdu[0].smpCnt = pub->smp_cnt;
    apdu->asdu[0].confRev = pub->config.conf_rev;
    apdu->asdu[0].smpSynch = (sv_smpsynch_t)pub->config.smp_synch;
    apdu->asdu[0].smpRate = pub->config.smp_rate;
    apdu->asdu[0].has_smpRate = (pub->config.smp_rate > 0U);

    for (uint8_t i = 0U; i < pub->sample_count; i++) {
        (void)sv_add_sample(&apdu->asdu[0], pub->samples[i],
                            pub->quality[i]);
    }
}

/* Encode the current state as a plain SPDU; on success smpCnt and
 * spdu_number have been consumed (L2 prepare() semantics). */
static int rsv_encode_plain(iec61850_rsv_publisher_t *pub,
                            uint8_t *buf, size_t buf_size,
                            size_t *spdu_len)
{
    sv_apdu_t apdu;
    int ret;

    rsv_fill_apdu(pub, &apdu);

    ret = iec61850_rsv_encode(&apdu, pub->config.appid,
                              pub->spdu_number, NULL, buf, buf_size);
    if (ret < 0) {
        return ret;
    }
    *spdu_len = (size_t)ret;

    /* smpCnt wraparound at smp_rate * 50 (L2 semantics). */
    pub->smp_cnt++;
    if (pub->config.smp_rate > 0U) {
        uint16_t wrap = (uint16_t)(pub->config.smp_rate * 50U);

        if ((wrap > 0U) && (pub->smp_cnt >= wrap)) {
            pub->smp_cnt = 0U;
        }
    }
    pub->spdu_number++;

    return 0;
}

int iec61850_rsv_publisher_build_spdu(iec61850_rsv_publisher_t *pub,
                                      uint8_t *buf, size_t buf_size,
                                      size_t *spdu_len)
{
    if ((pub == NULL) || (buf == NULL) || (spdu_len == NULL)) {
        return -EINVAL;
    }

    return rsv_encode_plain(pub, buf, buf_size, spdu_len);
}

#ifdef IEC61850_SECURITY_ENABLED
/* Build the 14-byte Ethernet header (IPv4) for raw/XSK backends. */
static void rsv_build_eth_header(uint8_t *eth,
                                 const iec61850_rsv_pub_config_t *cfg)
{
    (void)memcpy(&eth[0], cfg->dst_mac, 6U);
    (void)memcpy(&eth[6], cfg->src_mac, 6U);
    eth[12] = (uint8_t)(RSV_ETH_P_IPV4 >> 8);
    eth[13] = (uint8_t)RSV_ETH_P_IPV4;
}
#endif /* IEC61850_SECURITY_ENABLED */

#ifdef IEC61850_SECURITY_ENABLED
/*
 * Secure-mode frame construction (same flow as rgoose_publisher.c):
 * SPDU with zeroed fixed-length signature placeholder →
 * [Eth][IPv4][UDP] wrap (IP header checksum computed, UDP checksum
 * zeroed = "not used") → HMAC-SHA256 or AES-GMAC over IP+UDP+SPDU →
 * patch.
 *
 * AES-GMAC mirrors the subscriber's verify path byte-for-byte
 * (src/sv/rsv_subscriber.c): 12-byte IV derived per packet from the
 * session fields — spdu_number(4) | appid(2) | key_id(4) |
 * reserved(2), big-endian concatenation — with AAD = the signed
 * span and a 16-byte tag.
 */
static int rsv_build_secure_frame(iec61850_rsv_publisher_t *pub,
                                  uint8_t *frame_buf, size_t frame_size,
                                  size_t *frame_len)
{
    uint8_t spdu[IEC61850_RSV_MAX_SPDU_LEN];
    uint8_t sig[IEC61850_RSV_SEC_HMAC_LEN];
    iec61850_r_security_t sec;
    sv_apdu_t apdu;
    size_t sig_len;
    size_t spdu_len;
    size_t sig_value_off;
    size_t span_len;
    uint8_t *ip;
    bool gmac;
    int ret;

    if (frame_size < (size_t)IEC61850_RSV_MAX_FRAME_LEN) {
        return -ENOSPC;
    }

    /* Fixed signature length per algorithm (max capacity: HMAC 32). */
    gmac = (pub->sec.algo ==
            (uint16_t)IEC61850_RSV_PUB_SEC_ALGO_AES_GMAC);
    sig_len = gmac ? (size_t)IEC61850_RSV_SEC_GMAC_LEN
                   : (size_t)IEC61850_RSV_SEC_HMAC_LEN;

    rsv_fill_apdu(pub, &apdu);

    (void)memset(&sec, 0, sizeof(sec));
    sec.present = true;
    sec.key_id = pub->sec.key_id;
    sec.time_of_current_key = rsv_now_epoch_s();
    sec.time_to_next_key = pub->sec.time_to_next_key;
    sec.security_algos = pub->sec.algo;
    sec.signature_len = sig_len;
    /* sec.signature stays zeroed: the placeholder. */

    ret = iec61850_rsv_encode(&apdu, pub->config.appid,
                              pub->spdu_number, &sec, spdu, sizeof(spdu));
    if (ret < 0) {
        return ret;
    }
    spdu_len = (size_t)ret;

    /* Deterministic signature-value offset (see file header). */
    sig_value_off = spdu_len - sig_len;
    if ((sig_value_off < 2U) ||
        (spdu[sig_value_off - 2U] != (uint8_t)RSV_SIG_TAG)) {
        /* Defensive: the codec's layout contract drifted. */
        return -EPROTO;
    }

    rsv_build_eth_header(frame_buf, &pub->config);
    ip = &frame_buf[RSV_ETH_HDR_LEN];

    ret = iec61850_ip_udp_build(ip, frame_size - (size_t)RSV_ETH_HDR_LEN,
                                pub->config.src_ip, pub->config.dst_ip,
                                pub->config.src_port, pub->config.dst_port,
                                spdu, spdu_len, (uint8_t)IPPROTO_UDP);
    if (ret != 0) {
        return ret;
    }

    /* UDP checksum "not used" in secure mode (circularity argument:
     * see rsv_publisher.h). */
    ip[26] = 0U;
    ip[27] = 0U;

    /* Sign IP header + UDP header + SPDU (signature zeroed). */
    span_len = (size_t)IEC61850_IP_UDP_HEADER_LEN + spdu_len;
    if (gmac) {
        /* AES-GMAC: per-packet IV from the session fields encoded in
         * THIS SPDU (spdu_number not yet consumed) — mirrors the
         * subscriber's derivation. */
        uint8_t iv[12];

        iv[0] = (uint8_t)(pub->spdu_number >> 24);
        iv[1] = (uint8_t)(pub->spdu_number >> 16);
        iv[2] = (uint8_t)(pub->spdu_number >> 8);
        iv[3] = (uint8_t)pub->spdu_number;
        iv[4] = (uint8_t)(pub->config.appid >> 8);
        iv[5] = (uint8_t)pub->config.appid;
        iv[6] = (uint8_t)(pub->sec.key_id >> 24);
        iv[7] = (uint8_t)(pub->sec.key_id >> 16);
        iv[8] = (uint8_t)(pub->sec.key_id >> 8);
        iv[9] = (uint8_t)pub->sec.key_id;
        iv[10] = 0U;
        iv[11] = 0U;

        ret = aes_gmac_sign(pub->sec.key, pub->sec.key_len, iv, sizeof(iv),
                            ip, span_len, sig, sig_len);
    } else {
        /* HMAC-SHA256 (default). */
        ret = hmac_sha256_sign(pub->sec.key, pub->sec.key_len, ip, span_len,
                               sig, sig_len);
    }
    if (ret != 0) {
        return -EIO;
    }

    /* Patch the signature value in (length fields already final). */
    (void)memcpy(&ip[IEC61850_IP_UDP_HEADER_LEN + sig_value_off], sig,
                 sig_len);

    *frame_len = (size_t)RSV_ETH_HDR_LEN + span_len;

    /* Consume the sequence counters only on success. */
    pub->smp_cnt++;
    if (pub->config.smp_rate > 0U) {
        uint16_t wrap = (uint16_t)(pub->config.smp_rate * 50U);

        if ((wrap > 0U) && (pub->smp_cnt >= wrap)) {
            pub->smp_cnt = 0U;
        }
    }
    pub->spdu_number++;

    return 0;
}
#endif /* IEC61850_SECURITY_ENABLED */

int iec61850_rsv_publisher_build_frame(iec61850_rsv_publisher_t *pub,
                                       uint8_t *frame_buf, size_t frame_size,
                                       size_t *frame_len)
{
    if ((pub == NULL) || (frame_buf == NULL) || (frame_len == NULL)) {
        return -EINVAL;
    }

#ifdef IEC61850_SECURITY_ENABLED
    if (pub->security_enabled) {
        return rsv_build_secure_frame(pub, frame_buf, frame_size, frame_len);
    }
#endif

    return rsv_encode_plain(pub, frame_buf, frame_size, frame_len);
}

int iec61850_rsv_publisher_publish(iec61850_rsv_publisher_t *pub)
{
    uint8_t frame_buf[IEC61850_RSV_MAX_FRAME_LEN];
    size_t frame_len = 0U;
    int ret;

    if ((pub == NULL) || (pub->io == NULL)) {
        return -EINVAL;
    }

    ret = iec61850_rsv_publisher_build_frame(pub, frame_buf,
                                             sizeof(frame_buf), &frame_len);
    if (ret != 0) {
        return ret;
    }

    return packet_io_send(pub->io, frame_buf, (uint32_t)frame_len);
}

int iec61850_rsv_publisher_retransmit(iec61850_rsv_publisher_t *pub)
{
    int ret;

    if (pub == NULL) {
        return -EINVAL;
    }
    if (!pub->has_retransmit) {
        return 0;
    }
    if (!iec61850_retransmit_is_due(&pub->retransmit)) {
        return 0;
    }

    ret = iec61850_rsv_publisher_publish(pub);
    if (ret != 0) {
        return ret;
    }
    return 1;
}

void iec61850_rsv_publisher_enable_retransmit(
    iec61850_rsv_publisher_t *pub,
    const iec61850_retransmit_config_t *cfg)
{
    if (pub == NULL) {
        return;
    }

    iec61850_retransmit_init(&pub->retransmit, cfg);
    pub->has_retransmit = true;
}

void iec61850_rsv_publisher_disable_retransmit(
    iec61850_rsv_publisher_t *pub)
{
    if (pub != NULL) {
        pub->has_retransmit = false;
    }
}
