/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC TR 61850-90-5 R-GOOSE Publisher Implementation
 *
 * Transport modes and the secure-mode signing flow are documented in
 * include/iec61850/goose/rgoose_publisher.h.  Wire layout of the
 * SPDU: src/asn1/rgoose_ber.c (WP-4a derivation).
 *
 * Secure-mode signature patch offset derivation: the 0x85 signature
 * TLV is the FINAL element of the SPDU and its length is fixed
 * (HMAC-SHA256 = IEC61850_RGOOSE_SEC_HMAC_LEN), so given the encoded
 * SPDU length the signature VALUE starts at
 *
 *     sig_value_off = spdu_len - IEC61850_RGOOSE_SEC_HMAC_LEN
 *
 * (TLV header at sig_value_off - 2, defensively asserted to carry
 * tag 0x85).  The offset is computed arithmetically — the frame is
 * never scanned for the tag.
 *
 * License: BSD-2-Clause
 */

#include "goose/rgoose_publisher.h"
#include "transport/ip_udp_frame.h"

#include <errno.h>
#include <string.h>
#include <time.h>
#include <netinet/in.h>

#ifdef IEC61850_SECURITY_ENABLED
#include "security/hmac_verify.h"
#endif

/* Signature tag of the 90-5 security extension (see
 * src/asn1/rgoose_ber.c; not exported by the frozen codec header). */
#define RGOOSE_SIG_TAG 0x85U

/* EtherType for IPv4 (Ethernet header of secure-mode frames). */
#define RGOOSE_ETH_P_IPV4 0x0800U

/* Ethernet header length of secure-mode frames (dst+src+ethertype). */
#define RGOOSE_ETH_HDR_LEN 14U

static uint64_t rgoose_now_ns(void)
{
    struct timespec ts;

    (void)clock_gettime(CLOCK_REALTIME, &ts);
    return ((uint64_t)ts.tv_sec * 1000000000ULL) + (uint64_t)ts.tv_nsec;
}

#ifdef IEC61850_SECURITY_ENABLED
static uint32_t rgoose_now_epoch_s(void)
{
    struct timespec ts;

    (void)clock_gettime(CLOCK_REALTIME, &ts);
    return (uint32_t)ts.tv_sec;
}
#endif

void iec61850_rgoose_pub_config_init(iec61850_rgoose_pub_config_t *cfg)
{
    if (cfg == NULL) {
        return;
    }

    (void)memset(cfg, 0, sizeof(*cfg));
    cfg->appid = 0x0001U;
    (void)strncpy(cfg->src_ip, "127.0.0.1", (size_t)IEC61850_RGOOSE_IP_ADDR_LEN - 1U);
    (void)strncpy(cfg->dst_ip, "127.0.0.1", (size_t)IEC61850_RGOOSE_IP_ADDR_LEN - 1U);
    cfg->src_port = IEC61850_RGOOSE_PORT_DEFAULT;
    cfg->dst_port = IEC61850_RGOOSE_PORT_DEFAULT;
    (void)strncpy(cfg->goose_id, "RGOOSE_PUB_1", (size_t)GOOSE_MAX_GOID_LEN - 1U);
    (void)strncpy(cfg->gocb_ref, "IED1LD0/LLN0$GO$gcb01",
                  (size_t)GOOSE_MAX_GOCBREF_LEN - 1U);
    (void)strncpy(cfg->dataset, "IED1LD0/LLN0$DS1",
                  (size_t)GOOSE_MAX_DATSET_LEN - 1U);
    cfg->time_allowed_to_live = 2000U;
    cfg->conf_rev = 1U;
}

void iec61850_rgoose_publisher_init(iec61850_rgoose_publisher_t *pub,
                                    const iec61850_rgoose_pub_config_t *cfg)
{
    if (pub == NULL) {
        return;
    }

    (void)memset(pub, 0, sizeof(*pub));

    if (cfg != NULL) {
        pub->config = *cfg;
    } else {
        iec61850_rgoose_pub_config_init(&pub->config);
    }

    /* R-GOOSE retransmits with GOOSE backoff semantics by default. */
    iec61850_retransmit_init(&pub->retransmit, NULL);
    pub->has_retransmit = true;
}

void iec61850_rgoose_publisher_destroy(iec61850_rgoose_publisher_t *pub)
{
    (void)pub;
}

/* Ensure the data array has at least index+1 entries. */
static int rgoose_ensure_data_index(iec61850_rgoose_publisher_t *pub,
                                    size_t index)
{
    if (index >= (size_t)GOOSE_MAX_ALLDATA_ENTRIES) {
        return -EINVAL;
    }
    if (index >= (size_t)pub->data_count) {
        /* Zero-fill any gaps */
        for (size_t i = (size_t)pub->data_count; i <= index; i++) {
            (void)memset(&pub->data[i], 0, sizeof(pub->data[i]));
            pub->byte_storage[i].len = 0;
        }
        pub->data_count = (uint32_t)(index + 1U);
    }
    return 0;
}

int iec61850_rgoose_publisher_set_boolean(iec61850_rgoose_publisher_t *pub,
                                          size_t index, bool value)
{
    if ((pub == NULL) || (rgoose_ensure_data_index(pub, index) != 0)) {
        return -EINVAL;
    }
    pub->data[index].type = GOOSE_DATA_BOOLEAN;
    pub->data[index].value.boolean = value;
    return 0;
}

int iec61850_rgoose_publisher_set_int32(iec61850_rgoose_publisher_t *pub,
                                        size_t index, int32_t value)
{
    if ((pub == NULL) || (rgoose_ensure_data_index(pub, index) != 0)) {
        return -EINVAL;
    }
    pub->data[index].type = GOOSE_DATA_INT32;
    pub->data[index].value.int32 = value;
    return 0;
}

int iec61850_rgoose_publisher_set_uint32(iec61850_rgoose_publisher_t *pub,
                                         size_t index, uint32_t value)
{
    if ((pub == NULL) || (rgoose_ensure_data_index(pub, index) != 0)) {
        return -EINVAL;
    }
    pub->data[index].type = GOOSE_DATA_UINT32;
    pub->data[index].value.uint32 = value;
    return 0;
}

int iec61850_rgoose_publisher_set_float32(iec61850_rgoose_publisher_t *pub,
                                          size_t index, float value)
{
    if ((pub == NULL) || (rgoose_ensure_data_index(pub, index) != 0)) {
        return -EINVAL;
    }
    pub->data[index].type = GOOSE_DATA_FLOAT32;
    pub->data[index].value.float32 = value;
    return 0;
}

int iec61850_rgoose_publisher_set_bitstring(iec61850_rgoose_publisher_t *pub,
                                            size_t index,
                                            const uint8_t *data, size_t len)
{
    if ((pub == NULL) || (data == NULL) ||
        (rgoose_ensure_data_index(pub, index) != 0)) {
        return -EINVAL;
    }
    if (len > (size_t)IEC61850_RGOOSE_MAX_BYTE_ENTRY_LEN) {
        return -EMSGSIZE;
    }

    (void)memcpy(pub->byte_storage[index].data, data, len);
    pub->byte_storage[index].len = len;

    pub->data[index].type = GOOSE_DATA_BITSTRING;
    pub->data[index].value.bytes.data = pub->byte_storage[index].data;
    pub->data[index].value.bytes.len = len;
    return 0;
}

int iec61850_rgoose_publisher_set_octetstring(iec61850_rgoose_publisher_t *pub,
                                              size_t index,
                                              const uint8_t *data, size_t len)
{
    if ((pub == NULL) || (data == NULL) ||
        (rgoose_ensure_data_index(pub, index) != 0)) {
        return -EINVAL;
    }
    if (len > (size_t)IEC61850_RGOOSE_MAX_BYTE_ENTRY_LEN) {
        return -EMSGSIZE;
    }

    (void)memcpy(pub->byte_storage[index].data, data, len);
    pub->byte_storage[index].len = len;

    pub->data[index].type = GOOSE_DATA_OCTETSTRING;
    pub->data[index].value.bytes.data = pub->byte_storage[index].data;
    pub->data[index].value.bytes.len = len;
    return 0;
}

int iec61850_rgoose_publisher_set_utctime(iec61850_rgoose_publisher_t *pub,
                                          size_t index,
                                          uint64_t timestamp_us,
                                          uint8_t time_quality)
{
    if ((pub == NULL) || (rgoose_ensure_data_index(pub, index) != 0)) {
        return -EINVAL;
    }
    pub->data[index].type = GOOSE_DATA_UTCTIME;
    pub->data[index].value.utctime.timestamp_us = timestamp_us;
    pub->data[index].value.utctime.time_quality = time_quality;
    return 0;
}

int iec61850_rgoose_publisher_set_btime6(iec61850_rgoose_publisher_t *pub,
                                         size_t index,
                                         uint32_t ms_since_midnight,
                                         uint16_t days)
{
    if ((pub == NULL) || (rgoose_ensure_data_index(pub, index) != 0)) {
        return -EINVAL;
    }
    pub->data[index].type = GOOSE_DATA_BTIME6;
    pub->data[index].value.btime6.ms_since_midnight = ms_since_midnight;
    pub->data[index].value.btime6.days = days;
    return 0;
}

void iec61850_rgoose_publisher_state_change(iec61850_rgoose_publisher_t *pub)
{
    if (pub == NULL) {
        return;
    }

    pub->st_num++;
    pub->sq_num = 0;

    if (pub->has_retransmit) {
        iec61850_retransmit_on_state_change(&pub->retransmit);
    }
}

void iec61850_rgoose_publisher_enable_retransmit(
    iec61850_rgoose_publisher_t *pub,
    const iec61850_retransmit_config_t *cfg)
{
    if (pub == NULL) {
        return;
    }

    iec61850_retransmit_init(&pub->retransmit, cfg);
    pub->has_retransmit = true;
}

void iec61850_rgoose_publisher_disable_retransmit(
    iec61850_rgoose_publisher_t *pub)
{
    if (pub != NULL) {
        pub->has_retransmit = false;
    }
}

uint32_t iec61850_rgoose_publisher_get_st_num(
    const iec61850_rgoose_publisher_t *pub)
{
    if (pub == NULL) {
        return 0U;
    }
    return pub->st_num;
}

uint32_t iec61850_rgoose_publisher_get_sq_num(
    const iec61850_rgoose_publisher_t *pub)
{
    if (pub == NULL) {
        return 0U;
    }
    return pub->sq_num;
}

uint32_t iec61850_rgoose_publisher_get_spdu_number(
    const iec61850_rgoose_publisher_t *pub)
{
    if (pub == NULL) {
        return 0U;
    }
    return pub->spdu_number;
}

void iec61850_rgoose_publisher_set_io(iec61850_rgoose_publisher_t *pub,
                                      struct packet_io *io)
{
    if (pub != NULL) {
        pub->io = io;
    }
}

int iec61850_rgoose_publisher_enable_security(
    iec61850_rgoose_publisher_t *pub,
    const iec61850_rgoose_pub_security_t *cfg)
{
    if ((pub == NULL) || (cfg == NULL)) {
        return -EINVAL;
    }
    if ((cfg->key_len == 0U) ||
        (cfg->key_len > (size_t)IEC61850_RGOOSE_SEC_KEY_MAX)) {
        return -EINVAL;
    }
    if (cfg->algo != (uint16_t)IEC61850_RGOOSE_PUB_SEC_ALGO_HMAC_SHA256) {
        /* No AES-GMAC signing primitive exists in src/security. */
        return -ENOTSUP;
    }

#ifdef IEC61850_SECURITY_ENABLED
    pub->sec = *cfg;
    pub->security_enabled = true;
    return 0;
#else
    return -ENOTSUP;
#endif
}

/* Fill a GOOSE APDU from the publisher state (mirrors the L2
 * publisher's prepare()). */
static void rgoose_fill_apdu(const iec61850_rgoose_publisher_t *pub,
                             goose_apdu_t *apdu)
{
    goose_apdu_init(apdu);

    (void)goose_set_gocbref(apdu, pub->config.gocb_ref);
    (void)goose_set_datset(apdu, pub->config.dataset);
    (void)goose_set_goid(apdu, pub->config.goose_id);

    apdu->timeAllowedtoLive = pub->config.time_allowed_to_live;
    apdu->confRev = pub->config.conf_rev;
    apdu->stNum = pub->st_num;
    apdu->sqNum = pub->sq_num;
    apdu->test = false;
    apdu->ndsCom = false;
    apdu->numDatSetEntries = pub->data_count;
    apdu->timestamp = rgoose_now_ns() / 1000ULL;

    for (uint32_t i = 0U; i < pub->data_count; i++) {
        apdu->allData[i] = pub->data[i];
    }
}

/* Encode the current state as a plain SPDU into buf; on success
 * sq_num has been consumed (mirrors the L2 prepare() contract). */
static int rgoose_encode_plain(iec61850_rgoose_publisher_t *pub,
                               uint8_t *buf, size_t buf_size,
                               size_t *spdu_len)
{
    goose_apdu_t apdu;
    int ret;

    rgoose_fill_apdu(pub, &apdu);

    ret = iec61850_rgoose_encode(&apdu, pub->config.appid,
                                 pub->spdu_number, NULL, buf, buf_size);
    if (ret < 0) {
        return ret;
    }
    *spdu_len = (size_t)ret;

    /* Consume the sequence counters (L2 prepare() semantics). */
    pub->sq_num++;
    pub->spdu_number++;

    return 0;
}

int iec61850_rgoose_publisher_build_spdu(iec61850_rgoose_publisher_t *pub,
                                         uint8_t *buf, size_t buf_size,
                                         size_t *spdu_len)
{
    if ((pub == NULL) || (buf == NULL) || (spdu_len == NULL)) {
        return -EINVAL;
    }

    return rgoose_encode_plain(pub, buf, buf_size, spdu_len);
}

#ifdef IEC61850_SECURITY_ENABLED
/* Build the 14-byte Ethernet header (IPv4) for raw/XSK backends. */
static void rgoose_build_eth_header(uint8_t *eth,
                                    const iec61850_rgoose_pub_config_t *cfg)
{
    (void)memcpy(&eth[0], cfg->dst_mac, 6U);
    (void)memcpy(&eth[6], cfg->src_mac, 6U);
    eth[12] = (uint8_t)(RGOOSE_ETH_P_IPV4 >> 8);
    eth[13] = (uint8_t)RGOOSE_ETH_P_IPV4;
}
#endif /* IEC61850_SECURITY_ENABLED */

#ifdef IEC61850_SECURITY_ENABLED
/*
 * Secure-mode frame construction:
 *   1. encode the SPDU with a fixed-length zeroed signature
 *      placeholder (all SPDU length fields cover the final size);
 *   2. wrap it in [Eth][IPv4][UDP] via iec61850_ip_udp_build (IPv4
 *      header checksum computed);
 *   3. zero the UDP checksum field ("not used", RFC 768 — see the
 *      header comment for the circularity argument);
 *   4. HMAC-SHA256 over the complete IP+UDP+SPDU span (signature
 *      bytes still zeroed);
 *   5. patch the signature value in (arithmetically derived offset).
 */
static int rgoose_build_secure_frame(iec61850_rgoose_publisher_t *pub,
                                     uint8_t *frame_buf, size_t frame_size,
                                     size_t *frame_len)
{
    uint8_t spdu[IEC61850_RGOOSE_MAX_SPDU_LEN];
    uint8_t sig[IEC61850_RGOOSE_SEC_HMAC_LEN];
    iec61850_r_security_t sec;
    goose_apdu_t apdu;
    size_t spdu_len;
    size_t sig_value_off;
    size_t span_len;
    uint8_t *ip;
    int ret;

    if (frame_size < (size_t)IEC61850_RGOOSE_MAX_FRAME_LEN) {
        return -ENOSPC;
    }

    rgoose_fill_apdu(pub, &apdu);

    (void)memset(&sec, 0, sizeof(sec));
    sec.present = true;
    sec.key_id = pub->sec.key_id;
    sec.time_of_current_key = rgoose_now_epoch_s();
    sec.time_to_next_key = pub->sec.time_to_next_key;
    sec.security_algos = pub->sec.algo;
    sec.signature_len = (size_t)IEC61850_RGOOSE_SEC_HMAC_LEN;
    /* sec.signature stays zeroed: the placeholder. */

    ret = iec61850_rgoose_encode(&apdu, pub->config.appid,
                                 pub->spdu_number, &sec,
                                 spdu, sizeof(spdu));
    if (ret < 0) {
        return ret;
    }
    spdu_len = (size_t)ret;

    /* Deterministic signature-value offset (see file header). */
    sig_value_off = spdu_len - (size_t)IEC61850_RGOOSE_SEC_HMAC_LEN;
    if ((sig_value_off < 2U) ||
        (spdu[sig_value_off - 2U] != (uint8_t)RGOOSE_SIG_TAG)) {
        /* Defensive: the codec's layout contract drifted. */
        return -EPROTO;
    }

    rgoose_build_eth_header(frame_buf, &pub->config);
    ip = &frame_buf[RGOOSE_ETH_HDR_LEN];

    ret = iec61850_ip_udp_build(ip, frame_size - (size_t)RGOOSE_ETH_HDR_LEN,
                                pub->config.src_ip, pub->config.dst_ip,
                                pub->config.src_port, pub->config.dst_port,
                                spdu, spdu_len, (uint8_t)IPPROTO_UDP);
    if (ret != 0) {
        return ret;
    }

    /* UDP checksum "not used" in secure mode (see header comment):
     * bytes 26-27 of the UDP header, i.e. offset 20+6 within ip. */
    ip[26] = 0U;
    ip[27] = 0U;

    /* Sign IP header + UDP header + SPDU (signature zeroed). */
    span_len = (size_t)IEC61850_IP_UDP_HEADER_LEN + spdu_len;
    ret = hmac_sha256_sign(pub->sec.key, pub->sec.key_len, ip, span_len,
                           sig, sizeof(sig));
    if (ret != 0) {
        return -EIO;
    }

    /* Patch the signature value in (length fields already final). */
    (void)memcpy(&ip[IEC61850_IP_UDP_HEADER_LEN + sig_value_off], sig,
                 sizeof(sig));

    *frame_len = (size_t)RGOOSE_ETH_HDR_LEN + span_len;

    /* Consume the sequence counters only on success. */
    pub->sq_num++;
    pub->spdu_number++;

    return 0;
}
#endif /* IEC61850_SECURITY_ENABLED */

int iec61850_rgoose_publisher_build_frame(iec61850_rgoose_publisher_t *pub,
                                          uint8_t *frame_buf, size_t frame_size,
                                          size_t *frame_len)
{
    if ((pub == NULL) || (frame_buf == NULL) || (frame_len == NULL)) {
        return -EINVAL;
    }

#ifdef IEC61850_SECURITY_ENABLED
    if (pub->security_enabled) {
        return rgoose_build_secure_frame(pub, frame_buf, frame_size,
                                         frame_len);
    }
#endif

    return rgoose_encode_plain(pub, frame_buf, frame_size, frame_len);
}

int iec61850_rgoose_publisher_publish(iec61850_rgoose_publisher_t *pub)
{
    uint8_t frame_buf[IEC61850_RGOOSE_MAX_FRAME_LEN];
    size_t frame_len = 0U;
    int ret;

    if ((pub == NULL) || (pub->io == NULL)) {
        return -EINVAL;
    }

    ret = iec61850_rgoose_publisher_build_frame(pub, frame_buf,
                                                sizeof(frame_buf),
                                                &frame_len);
    if (ret != 0) {
        return ret;
    }

    return packet_io_send(pub->io, frame_buf, (uint32_t)frame_len);
}

int iec61850_rgoose_publisher_retransmit(iec61850_rgoose_publisher_t *pub)
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

    ret = iec61850_rgoose_publisher_publish(pub);
    if (ret != 0) {
        return ret;
    }
    return 1;
}
