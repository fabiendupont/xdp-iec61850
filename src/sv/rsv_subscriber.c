/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC TR 61850-90-5 R-SV Subscriber Implementation
 *
 * Transport modes, the secure-mode verification steps and the
 * kernel-UDP-headers constraint are documented in
 * include/iec61850/sv/rsv_subscriber.h.
 *
 * Replay validation is authoritative in userspace (the BPF 90-5
 * parse nodes are an optimization): per-APPID tracking of the last
 * accepted SPDU Number with drop-<= semantics, plus the 90-5 time
 * window (iec61850_r_time_in_window) over the Time-of-Current-Key
 * field when the security extension is present.
 *
 * License: BSD-2-Clause
 */

#include "sv/rsv_subscriber.h"
#include "transport/ip_udp_frame.h"

#include <errno.h>
#include <string.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#ifdef IEC61850_SECURITY_ENABLED
#include "security/hmac_verify.h"
#endif

/* Ethernet header length (secure-mode frames may carry one). */
#define RSV_ETH_HDR_LEN 14U

/* EtherType IPv4. */
#define RSV_ETH_P_IPV4 0x0800U

/* Scratch capacity for the signed-span copy used by verification. */
#define RSV_VERIFY_SPAN_MAX 2048U

void iec61850_rsv_sub_config_init(iec61850_rsv_sub_config_t *cfg)
{
    if (cfg == NULL) {
        return;
    }
    (void)memset(cfg, 0, sizeof(*cfg));
    cfg->timeout_ms = 1000U;
}

void iec61850_rsv_subscriber_init(iec61850_rsv_subscriber_t *sub,
                                  const iec61850_rsv_sub_config_t *cfg)
{
    if (sub == NULL) {
        return;
    }
    (void)memset(sub, 0, sizeof(*sub));

    if (cfg != NULL) {
        sub->config = *cfg;
    } else {
        iec61850_rsv_sub_config_init(&sub->config);
    }
}

void iec61850_rsv_subscriber_destroy(iec61850_rsv_subscriber_t *sub)
{
    (void)sub;
}

void iec61850_rsv_subscriber_set_callback(iec61850_rsv_subscriber_t *sub,
                                          iec61850_rsv_callback_t cb,
                                          void *user_data)
{
    if (sub == NULL) {
        return;
    }
    sub->callback = cb;
    sub->callback_user_data = user_data;
}

int iec61850_rsv_subscriber_enable_security(
    iec61850_rsv_subscriber_t *sub,
    const iec61850_rsv_sub_security_t *cfg)
{
    if ((sub == NULL) || (cfg == NULL)) {
        return -EINVAL;
    }
    if ((cfg->key_len == 0U) ||
        (cfg->key_len > (size_t)IEC61850_RSV_SEC_KEY_MAX)) {
        return -EINVAL;
    }
    if ((cfg->algo != (uint16_t)IEC61850_RSV_SUB_SEC_ALGO_HMAC_SHA256) &&
        (cfg->algo != (uint16_t)IEC61850_RSV_SUB_SEC_ALGO_AES_GMAC)) {
        return -EINVAL;
    }

#ifdef IEC61850_SECURITY_ENABLED
    sub->sec = *cfg;
    sub->security_enabled = true;
    return 0;
#else
    return -ENOTSUP;
#endif
}

/* --- state tables --------------------------------------------------- */

static iec61850_rsv_pub_state_t *rsv_find_or_create_pub(
    iec61850_rsv_subscriber_t *sub, const char *sv_id)
{
    for (size_t i = 0U; i < sub->publisher_count; i++) {
        if (sub->publishers[i].valid &&
            (strcmp(sub->publishers[i].sv_id, sv_id) == 0)) {
            return &sub->publishers[i];
        }
    }

    if (sub->publisher_count >= (size_t)IEC61850_RSV_MAX_PUBLISHERS) {
        return NULL;
    }

    {
        iec61850_rsv_pub_state_t *ps = &sub->publishers[sub->publisher_count];

        (void)memset(ps, 0, sizeof(*ps));
        (void)strncpy(ps->sv_id, sv_id, (size_t)SV_MAX_SVID_LEN - 1U);
        ps->sv_id[SV_MAX_SVID_LEN - 1U] = '\0';
        ps->valid = true;
        sub->publisher_count++;
        return ps;
    }
}

static iec61850_rsv_appid_state_t *rsv_find_or_create_appid(
    iec61850_rsv_subscriber_t *sub, uint16_t appid)
{
    for (size_t i = 0U; i < sub->appid_count; i++) {
        if (sub->appids[i].valid && (sub->appids[i].appid == appid)) {
            return &sub->appids[i];
        }
    }

    if (sub->appid_count >= (size_t)IEC61850_RSV_MAX_APPIDS) {
        return NULL;
    }

    {
        iec61850_rsv_appid_state_t *as = &sub->appids[sub->appid_count];

        (void)memset(as, 0, sizeof(*as));
        as->appid = appid;
        as->valid = true;
        sub->appid_count++;
        return as;
    }
}

/* --- L2-style ASDU state machine (mirrors the L2 SV subscriber) ------ */

static int rsv_process_apdu(iec61850_rsv_subscriber_t *sub,
                            const sv_apdu_t *apdu,
                            const iec61850_r_header_t *hdr,
                            uint64_t recv_time_ns)
{
    iec61850_rsv_message_t msg;
    iec61850_rsv_pub_state_t *ps;

    if (apdu->noASDU == 0U) {
        return 0;
    }

    /* svID filter */
    if (sub->config.filter_svid[0] != '\0') {
        if (strcmp(apdu->asdu[0].svID, sub->config.filter_svid) != 0) {
            return 0;
        }
    }

    ps = rsv_find_or_create_pub(sub, apdu->asdu[0].svID);
    if (ps == NULL) {
        return 0;
    }

    msg.apdu = *apdu;
    msg.header = *hdr;
    msg.recv_timestamp_ns = recv_time_ns;
    msg.is_new_sample = false;
    msg.is_duplicate = false;
    msg.has_gap = false;
    msg.gap_count = 0U;

    if (ps->message_count == 0U) {
        msg.is_new_sample = true;
    } else if (apdu->asdu[0].smpCnt == ps->latest_smp_cnt) {
        msg.is_duplicate = true;
        sub->total_duplicates++;
    } else {
        msg.is_new_sample = true;

        /* Gap detection with modular arithmetic for wraparound */
        uint16_t smp_rate = sub->config.smp_rate;
        uint16_t wrap = (smp_rate > 0U)
            ? (uint16_t)(smp_rate * 50U) : (uint16_t)4000U;
        uint16_t expected = (uint16_t)((ps->latest_smp_cnt + 1U) % wrap);

        if (apdu->asdu[0].smpCnt != expected) {
            msg.has_gap = true;
            if (apdu->asdu[0].smpCnt >= expected) {
                msg.gap_count = (uint32_t)(apdu->asdu[0].smpCnt - expected);
            } else {
                msg.gap_count = (uint32_t)(wrap - expected + apdu->asdu[0].smpCnt);
            }
            ps->gap_count += msg.gap_count;
            sub->total_gaps += msg.gap_count;
        }
    }

    ps->latest_smp_cnt = apdu->asdu[0].smpCnt;
    ps->last_recv_time_ns = recv_time_ns;
    ps->message_count++;
    ps->timeout_detected = false;

    sub->total_messages++;

    if ((sub->callback != NULL) && (!msg.is_duplicate)) {
        sub->callback(&msg, sub->callback_user_data);
    }

    return msg.is_duplicate ? 0 : 1;
}

/* --- session-level replay / time-window validation ------------------- */

/*
 * Authoritative replay validation: per-APPID SPDU Number (drop <=)
 * and the 90-5 time window over Time-of-Current-Key when present.
 * @return 1 accepted, 0 rejected.
 */
static int rsv_accept_session(iec61850_rsv_subscriber_t *sub,
                              const iec61850_r_header_t *hdr)
{
    iec61850_rsv_appid_state_t *as;

    as = rsv_find_or_create_appid(sub, hdr->appid);
    if (as == NULL) {
        return 0;
    }

    if (as->has_last_spdu && (hdr->spdu_number <= as->last_spdu_number)) {
        as->replay_drops++;
        sub->total_replays++;
        return 0;
    }

    if (hdr->security.present && (hdr->security.time_of_current_key != 0U)) {
        if (as->has_last_time &&
            !iec61850_r_time_in_window(hdr->security.time_of_current_key,
                                       as->last_time_of_key)) {
            sub->total_security_failures++;
            return 0;
        }
    }

    as->last_spdu_number = hdr->spdu_number;
    as->has_last_spdu = true;
    if (hdr->security.present && (hdr->security.time_of_current_key != 0U)) {
        as->last_time_of_key = hdr->security.time_of_current_key;
        as->has_last_time = true;
    }

    return 1;
}

/* --- plain-mode SPDU processing -------------------------------------- */

int iec61850_rsv_subscriber_process_spdu(
    iec61850_rsv_subscriber_t *sub,
    const uint8_t *spdu, size_t spdu_len, uint64_t recv_time_ns)
{
    sv_apdu_t apdu;
    iec61850_r_header_t hdr;
    int ret;

    if ((sub == NULL) || (spdu == NULL) || (spdu_len == 0U)) {
        return 0;
    }

#ifdef IEC61850_SECURITY_ENABLED
    /* A secure-mode subscriber must not bypass verification by being
     * fed bare SPDUs — secure reception goes through
     * process_frame(), which enforces the signature check. */
    if (sub->security_enabled) {
        sub->total_security_failures++;
        return 0;
    }
#endif

    ret = iec61850_rsv_decode(spdu, spdu_len, &apdu, &hdr);
    if (ret < 0) {
        return 0;
    }

    if ((sub->config.filter_appid != 0U) &&
        (hdr.appid != sub->config.filter_appid)) {
        return 0;
    }

    if (rsv_accept_session(sub, &hdr) == 0) {
        return 0;
    }

    return rsv_process_apdu(sub, &apdu, &hdr, recv_time_ns);
}

/* --- secure-mode verification ---------------------------------------- */

#ifdef IEC61850_SECURITY_ENABLED

/* Constant-time comparison (0 == equal). */
static int rsv_ct_memcmp(const uint8_t *a, const uint8_t *b, size_t len)
{
    volatile uint8_t diff = 0U;

    for (size_t i = 0U; i < len; i++) {
        diff = (uint8_t)(diff | (uint8_t)(a[i] ^ b[i]));
    }
    return (int)diff;
}

/*
 * Verify the signature of a received [Eth?][IPv4][UDP][SPDU] frame.
 * On success the decoded APDU and header are written to the apdu and
 * hdr out-parameters and 1 is returned; 0 on any rejection.  Same
 * steps as rgoose_subscriber.c (see that file's verify comment).
 */
static int rsv_verify_secure(iec61850_rsv_subscriber_t *sub,
                             const uint8_t *frame, size_t frame_len,
                             sv_apdu_t *apdu, iec61850_r_header_t *hdr)
{
    uint8_t span[RSV_VERIFY_SPAN_MAX];
    uint8_t computed[IEC61850_RSV_SEC_HMAC_LEN];
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    const uint8_t *payload = NULL;
    size_t payload_len = 0U;
    size_t ip_off;
    size_t ip_len;
    size_t payload_rel;
    size_t span_len;
    size_t sig_rel;
    uint16_t src_port;
    uint16_t dst_port;
    int ret;

    /* Normalize: strip an optional Ethernet header (EtherType
     * 0x0800), else require a bare IPv4 datagram. */
    if ((frame_len >= (RSV_ETH_HDR_LEN + 1U)) &&
        ((((uint16_t)frame[12] << 8) | (uint16_t)frame[13]) ==
         (uint16_t)RSV_ETH_P_IPV4)) {
        ip_off = RSV_ETH_HDR_LEN;
    } else if ((frame_len > 0U) && ((frame[0] >> 4) == 4)) {
        ip_off = 0U;
    } else {
        return 0;
    }
    ip_len = frame_len - ip_off;
    if (ip_len < (size_t)IEC61850_IP_UDP_HEADER_LEN) {
        return 0;
    }

    ret = iec61850_ip_udp_parse(&frame[ip_off], ip_len, src_ip,
                                sizeof(src_ip), dst_ip, sizeof(dst_ip),
                                &src_port, &dst_port, &payload, &payload_len);
    if (ret != 0) {
        return 0;
    }

    /* Secure-mode port filter (the kernel does not demux here). */
    if ((sub->config.filter_port != 0U) &&
        (dst_port != sub->config.filter_port)) {
        return 0;
    }

    ret = iec61850_rsv_decode(payload, payload_len, apdu, hdr);
    if (ret < 0) {
        sub->total_security_failures++;
        return 0;
    }

    if (!hdr->security.present || (hdr->security.signature_len == 0U)) {
        sub->total_security_failures++;
        return 0;
    }

    if ((sub->sec.expected_key_id != 0U) &&
        (hdr->security.key_id != sub->sec.expected_key_id)) {
        sub->total_security_failures++;
        return 0;
    }

    /* Signed span: IP header .. end of SPDU. */
    payload_rel = (size_t)(payload - &frame[ip_off]);
    span_len = payload_rel + hdr->spdu_length;
    if ((span_len > ip_len) || (span_len > sizeof(span))) {
        sub->total_security_failures++;
        return 0;
    }

    /* Copy the span with the signature bytes zeroed (the received
     * frame itself is never mutated — it may be UMEM-backed). */
    (void)memcpy(span, &frame[ip_off], span_len);
    sig_rel = payload_rel + hdr->spdu_length - hdr->security.signature_len;
    (void)memset(&span[sig_rel], 0, hdr->security.signature_len);

    if (sub->sec.algo == (uint16_t)IEC61850_RSV_SUB_SEC_ALGO_AES_GMAC) {
        /* AES-GMAC (optional): 12-byte IV derived per packet from
         * the session fields — spdu_number(4) | appid(2) | key_id(4)
         * | reserved(2).  AAD = the signed span. */
        uint8_t iv[12];

        iv[0] = (uint8_t)(hdr->spdu_number >> 24);
        iv[1] = (uint8_t)(hdr->spdu_number >> 16);
        iv[2] = (uint8_t)(hdr->spdu_number >> 8);
        iv[3] = (uint8_t)hdr->spdu_number;
        iv[4] = (uint8_t)(hdr->appid >> 8);
        iv[5] = (uint8_t)hdr->appid;
        iv[6] = (uint8_t)(hdr->security.key_id >> 24);
        iv[7] = (uint8_t)(hdr->security.key_id >> 16);
        iv[8] = (uint8_t)(hdr->security.key_id >> 8);
        iv[9] = (uint8_t)hdr->security.key_id;
        iv[10] = 0U;
        iv[11] = 0U;

        ret = aes_gmac_verify(sub->sec.key, sub->sec.key_len, iv, sizeof(iv),
                              span, span_len, hdr->security.signature,
                              hdr->security.signature_len);
        if (ret != 0) {
            sub->total_security_failures++;
            return 0;
        }
    } else {
        /* HMAC-SHA256 (default). */
        if (hdr->security.signature_len != (size_t)IEC61850_RSV_SEC_HMAC_LEN) {
            sub->total_security_failures++;
            return 0;
        }
        ret = hmac_sha256_sign(sub->sec.key, sub->sec.key_len, span, span_len,
                               computed, sizeof(computed));
        if (ret != 0) {
            sub->total_security_failures++;
            return 0;
        }
        if (rsv_ct_memcmp(computed, hdr->security.signature,
                          hdr->security.signature_len) != 0) {
            sub->total_security_failures++;
            return 0;
        }
    }

    return 1;
}
#endif /* IEC61850_SECURITY_ENABLED */

/* --- frame processing / dispatch -------------------------------------- */

int iec61850_rsv_subscriber_process_frame(
    iec61850_rsv_subscriber_t *sub,
    const uint8_t *frame_data, size_t frame_len,
    uint64_t recv_time_ns)
{
    if ((sub == NULL) || (frame_data == NULL) || (frame_len == 0U)) {
        return 0;
    }

#ifdef IEC61850_SECURITY_ENABLED
    if (sub->security_enabled) {
        sv_apdu_t apdu;
        iec61850_r_header_t hdr;
        int ret;

        ret = rsv_verify_secure(sub, frame_data, frame_len, &apdu, &hdr);
        if (ret != 1) {
            return 0;
        }

        if ((sub->config.filter_appid != 0U) &&
            (hdr.appid != sub->config.filter_appid)) {
            return 0;
        }

        if (rsv_accept_session(sub, &hdr) == 0) {
            return 0;
        }

        return rsv_process_apdu(sub, &apdu, &hdr, recv_time_ns);
    }
#endif

    return iec61850_rsv_subscriber_process_spdu(sub, frame_data,
                                                frame_len, recv_time_ns);
}

int iec61850_rsv_subscriber_poll(iec61850_rsv_subscriber_t *sub,
                                 struct packet_io *io)
{
    void *pkt_data = NULL;
    uint32_t pkt_len = 0;
    struct timespec ts;
    uint64_t recv_time_ns;
    int ret;

    if ((sub == NULL) || (io == NULL)) {
        return -EINVAL;
    }

    ret = packet_io_recv(io, &pkt_data, &pkt_len);
    if (ret <= 0) {
        return 0;
    }

    (void)clock_gettime(CLOCK_REALTIME, &ts);
    recv_time_ns = ((uint64_t)ts.tv_sec * 1000000000ULL) +
                   (uint64_t)ts.tv_nsec;

    ret = iec61850_rsv_subscriber_process_frame(
        sub, (const uint8_t *)pkt_data, (size_t)pkt_len, recv_time_ns);

    packet_io_release(io);
    return ret;
}

void iec61850_rsv_subscriber_check_timeouts(
    iec61850_rsv_subscriber_t *sub, uint64_t current_time_ns)
{
    uint64_t timeout_ns;

    if (sub == NULL) {
        return;
    }

    timeout_ns = (uint64_t)sub->config.timeout_ms * 1000000ULL;

    for (size_t i = 0U; i < sub->publisher_count; i++) {
        if ((!sub->publishers[i].valid) || (sub->publishers[i].timeout_detected)) {
            continue;
        }
        if ((sub->publishers[i].last_recv_time_ns > 0ULL) &&
            (current_time_ns > sub->publishers[i].last_recv_time_ns) &&
            ((current_time_ns - sub->publishers[i].last_recv_time_ns) >
             timeout_ns)) {
            sub->publishers[i].timeout_detected = true;
            sub->total_timeouts++;
        }
    }
}

const iec61850_rsv_pub_state_t *iec61850_rsv_subscriber_get_pub_state(
    const iec61850_rsv_subscriber_t *sub, const char *sv_id)
{
    if ((sub == NULL) || (sv_id == NULL)) {
        return NULL;
    }

    for (size_t i = 0U; i < sub->publisher_count; i++) {
        if (sub->publishers[i].valid &&
            (strcmp(sub->publishers[i].sv_id, sv_id) == 0)) {
            return &sub->publishers[i];
        }
    }
    return NULL;
}

const iec61850_rsv_appid_state_t *iec61850_rsv_subscriber_get_appid_state(
    const iec61850_rsv_subscriber_t *sub, uint16_t appid)
{
    if (sub == NULL) {
        return NULL;
    }

    for (size_t i = 0U; i < sub->appid_count; i++) {
        if (sub->appids[i].valid && (sub->appids[i].appid == appid)) {
            return &sub->appids[i];
        }
    }
    return NULL;
}
