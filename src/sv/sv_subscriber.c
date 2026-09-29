/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * SV Subscriber Implementation
 *
 * License: BSD-3-Clause
 */


#include "sv/sv_subscriber.h"
#include "transport/eth_frame.h"
#include <string.h>
#include <time.h>
#include <errno.h>

#ifdef IEC61850_SECURITY_ENABLED
#include "security/key_manager.h"
#include "security/cert_manager.h"
#endif

void iec61850_sv_sub_config_init(iec61850_sv_sub_config_t *cfg)
{
    if (cfg == NULL) { return; }
    (void)memset(cfg, 0, sizeof(*cfg));
    cfg->timeout_ms = 1000;
}

void iec61850_sv_subscriber_init(iec61850_sv_subscriber_t *sub,
                                  const iec61850_sv_sub_config_t *cfg)
{
    if (sub == NULL) { return; }
    (void)memset(sub, 0, sizeof(*sub));

    if (cfg != NULL) {
        sub->config = *cfg;
    } else {
        iec61850_sv_sub_config_init(&sub->config);
    }
}

void iec61850_sv_subscriber_destroy(iec61850_sv_subscriber_t *sub)
{
    (void)sub;
}

void iec61850_sv_subscriber_set_callback(iec61850_sv_subscriber_t *sub,
                                          iec61850_sv_callback_t cb,
                                          void *user_data)
{
    if (sub == NULL) { return; }
    sub->callback = cb;
    sub->callback_user_data = user_data;
}

static iec61850_sv_pub_state_t *find_or_create_pub(
    iec61850_sv_subscriber_t *sub, const char *sv_id)
{
    for (size_t i = 0; i < sub->publisher_count; i++) {
        if (sub->publishers[i].valid &&
            strcmp(sub->publishers[i].sv_id, sv_id) == 0) {
            return &sub->publishers[i];
        }
    }

    if (sub->publisher_count >= (size_t)IEC61850_SV_MAX_PUBLISHERS) {
        return NULL;
    }

    iec61850_sv_pub_state_t *ps = &sub->publishers[sub->publisher_count];
    (void)memset(ps, 0, sizeof(*ps));
    (void)strncpy(ps->sv_id, sv_id, (size_t)SV_MAX_SVID_LEN - 1U);
    ps->sv_id[SV_MAX_SVID_LEN - 1U] = '\0';
    ps->valid = true;
    sub->publisher_count++;

    return ps;
}

bool iec61850_sv_subscriber_process(iec61850_sv_subscriber_t *sub,
                                     const sv_asdu_t *asdu,
                                     uint64_t recv_time_ns)
{
    iec61850_sv_pub_state_t *ps;
    iec61850_sv_message_t msg;

    if ((sub == NULL) || (asdu == NULL)) {
        return false;
    }

    /* Apply svID filter */
    if (sub->config.filter_svid[0] != '\0') {
        if (strcmp(asdu->svID, sub->config.filter_svid) != 0) {
            return false;
        }
    }

    ps = find_or_create_pub(sub, asdu->svID);
    if (ps == NULL) {
        return false;
    }

    /* Build message */
    msg.asdu = *asdu;
    msg.recv_timestamp_ns = recv_time_ns;
    msg.is_new_sample = false;
    msg.is_duplicate = false;
    msg.has_gap = false;
    msg.gap_count = 0;

    if (ps->message_count == 0U) {
        msg.is_new_sample = true;
    } else if (asdu->smpCnt == ps->latest_smp_cnt) {
        msg.is_duplicate = true;
        sub->total_duplicates++;
    } else {
        msg.is_new_sample = true;

        /* Gap detection with modular arithmetic for wraparound */
        uint16_t smp_rate = sub->config.smp_rate;
        uint16_t wrap = (smp_rate > 0U)
            ? (uint16_t)(smp_rate * 50U) : (uint16_t)4000U;
        uint16_t expected = (uint16_t)((ps->latest_smp_cnt + 1U) % wrap);
        if (asdu->smpCnt != expected) {
            msg.has_gap = true;
            /* Calculate gap count with wraparound */
            if (asdu->smpCnt >= expected) {
                msg.gap_count = (uint32_t)(asdu->smpCnt - expected);
            } else {
                msg.gap_count = (uint32_t)(wrap - expected + asdu->smpCnt);
            }
            ps->gap_count += msg.gap_count;
            sub->total_gaps += msg.gap_count;
        }
    }

    ps->latest_smp_cnt = asdu->smpCnt;
    ps->last_recv_time_ns = recv_time_ns;
    ps->message_count++;
    ps->timeout_detected = false;

    sub->total_messages++;

    if ((sub->callback != NULL) && (!msg.is_duplicate)) {
        sub->callback(&msg, sub->callback_user_data);
    }

    return !msg.is_duplicate;
}

void iec61850_sv_subscriber_check_timeouts(iec61850_sv_subscriber_t *sub,
                                            uint64_t current_time_ns)
{
    uint64_t timeout_ns;

    if (sub == NULL) { return; }

    timeout_ns = (uint64_t)sub->config.timeout_ms * 1000000ULL;

    for (size_t i = 0; i < sub->publisher_count; i++) {
        if ((!sub->publishers[i].valid) || (sub->publishers[i].timeout_detected)) {
            continue;
        }
        if ((sub->publishers[i].last_recv_time_ns > 0ULL) &&
            (current_time_ns > sub->publishers[i].last_recv_time_ns) &&
            ((current_time_ns - sub->publishers[i].last_recv_time_ns) > timeout_ns)) {
            sub->publishers[i].timeout_detected = true;
            sub->total_timeouts++;
        }
    }
}

const iec61850_sv_pub_state_t *iec61850_sv_subscriber_get_pub_state(
    const iec61850_sv_subscriber_t *sub, const char *sv_id)
{
    if ((sub == NULL) || (sv_id == NULL)) { return NULL; }

    for (size_t i = 0; i < sub->publisher_count; i++) {
        if (sub->publishers[i].valid &&
            strcmp(sub->publishers[i].sv_id, sv_id) == 0) {
            return &sub->publishers[i];
        }
    }
    return NULL;
}

int iec61850_sv_subscriber_enable_security(iec61850_sv_subscriber_t *sub,
                                             void *cert_manager)
{
    if ((sub == NULL) || (cert_manager == NULL)) {
        return -EINVAL;
    }

#ifdef IEC61850_SECURITY_ENABLED
    /* MISRA 11.5: opaque cert_manager handle, deviation Cat. 3 */
    iec61850_cert_manager_t *cm = (iec61850_cert_manager_t *)cert_manager;
    if (!iec61850_cert_manager_is_loaded(cm)) {
        return -EINVAL;
    }
    sub->cert_manager = cert_manager;
    sub->security_enabled = true;
    return 0;
#else
    (void)cert_manager;
    return -ENOTSUP;
#endif
}

#ifdef IEC61850_SECURITY_ENABLED

/* Maximum forward-drift tolerance: reject timestamps > 60s in the future */
#define SV_SEC_MAX_FORWARD_DRIFT_S   60U
/* Maximum backward-drift tolerance: reject timestamps > 5s in the past */
#define SV_SEC_MAX_BACKWARD_DRIFT_S  5U

/*
 * Phase 1: Verify signature and forward-drift only.
 * Called before APDU decode (publisher identity unknown).
 * Stores parsed msg_timestamp in *timestamp_out for Phase 2 replay check.
 */
static int sv_verify_security_signature(iec61850_sv_subscriber_t *sub,
                                          const uint8_t *frame_data, size_t frame_len, // NOLINT(bugprone-easily-swappable-parameters)
                                          size_t apdu_offset, size_t apdu_len,
                                          uint32_t *timestamp_out)
{
    /* MISRA 11.5: opaque cert_manager handle, deviation Cat. 3 */
    iec61850_cert_manager_t *cm = (iec61850_cert_manager_t *)sub->cert_manager;
    const uint8_t *apdu_data = &frame_data[apdu_offset];
    EVP_PKEY *pubkey;
    size_t after_apdu = apdu_offset + apdu_len;
    int ret;

    if (timestamp_out != NULL) { *timestamp_out = 0; }

    /* Runtime certificate expiry check */
    if (!iec61850_cert_manager_is_valid_time(cm)) {
        sub->total_security_failures++;
        return -EKEYEXPIRED;
    }

    if (after_apdu >= frame_len) {
        sub->total_security_failures++;
        return -1;
    }

    /* Look for CONSTRUCTED [9] (tag 0xA9) */
    const uint8_t *ext_data = &frame_data[after_apdu];
    size_t ext_remain = frame_len - after_apdu;

    if ((ext_remain < 4U) || (ext_data[0] != 0xA9U)) {
        sub->total_security_failures++;
        return -1;
    }

    /* Parse the security extension (same TLV format as GOOSE) */
    const uint8_t *sig = NULL;
    size_t sig_len = 0;
    uint32_t msg_timestamp = 0;
    size_t pos = 1;
    size_t inner_len;

    if (ext_data[pos] < 0x80U) {
        inner_len = ext_data[pos]; pos++;
    } else if (ext_data[pos] == 0x81U) {
        pos++;
        inner_len = ext_data[pos]; pos++;
    } else if (ext_data[pos] == 0x82U) {
        pos++;
        inner_len = ((size_t)ext_data[pos] << 8U) | ext_data[pos + 1U];
        pos += 2U;
    } else {
        sub->total_security_failures++;
        return -1;
    }

    size_t end = pos + inner_len;
    if (end > ext_remain) {
        sub->total_security_failures++;
        return -1;
    }

    while (pos < end) {
        uint8_t tag = ext_data[pos]; pos++;
        if (pos >= end) { break; }
        size_t len;
        if (ext_data[pos] < 0x80U) {
            len = ext_data[pos]; pos++;
        } else if (ext_data[pos] == 0x81U) {
            pos++;
            len = ext_data[pos]; pos++;
        } else if (ext_data[pos] == 0x82U) {
            pos++;
            len = ((size_t)ext_data[pos] << 8U) | ext_data[pos + 1U];
            pos += 2U;
        } else {
            break;
        }
        if ((pos + len) > end) { break; }

        if ((tag == 0x80U) && (len == 8U)) {
            msg_timestamp = ((uint32_t)ext_data[pos] << 24U) |
                            ((uint32_t)ext_data[pos + 1U] << 16U) |
                            ((uint32_t)ext_data[pos + 2U] << 8U) |
                            (uint32_t)ext_data[pos + 3U];
        } else if (tag == 0x82U) {
            sig = &ext_data[pos];
            sig_len = len;
        }
        pos += len;
    }

    if (sig == NULL) {
        sub->total_security_failures++;
        return -1;
    }

    pubkey = iec61850_cert_manager_get_public_key(cm);
    if (pubkey == NULL) {
        sub->total_security_failures++;
        return -1;
    }

    ret = iec61850_key_manager_verify(apdu_data, apdu_len, sig, sig_len, pubkey);
    if (ret != IEC61850_SEC_OK) {
        sub->total_security_failures++;
        return -1;
    }

    /* Forward-drift check: reject future timestamps */
    if (msg_timestamp > 0U) {
        uint64_t ts64 = (uint64_t)msg_timestamp;
        struct timespec now_ts;
        (void)clock_gettime(CLOCK_REALTIME, &now_ts);
        uint64_t now_secs = (uint64_t)now_ts.tv_sec;
        if (ts64 > (now_secs + SV_SEC_MAX_FORWARD_DRIFT_S)) {
            sub->total_security_failures++;
            return -1;
        }
    }

    if (timestamp_out != NULL) { *timestamp_out = msg_timestamp; }
    return 0;
}

/*
 * Phase 2: Per-publisher backward-drift / replay check.
 * Called after APDU decode when pub_state is known.
 */
static int sv_verify_security_replay(iec61850_sv_subscriber_t *sub,
                                       iec61850_sv_pub_state_t *pub_state,
                                       uint32_t msg_timestamp)
{
    if ((pub_state == NULL) || (msg_timestamp == 0U)) { return 0; }

    uint64_t ts64 = (uint64_t)msg_timestamp;

    if (pub_state->last_msg_timestamp > 0ULL) {
        uint64_t last64 = pub_state->last_msg_timestamp;
        if ((ts64 < last64) &&
            ((last64 - ts64) > SV_SEC_MAX_BACKWARD_DRIFT_S)) {
            sub->total_security_failures++;
            return -1;
        }
    }
    pub_state->last_msg_timestamp = ts64;

    return 0;
}
#endif /* IEC61850_SECURITY_ENABLED */

int iec61850_sv_subscriber_process_frame(
    iec61850_sv_subscriber_t *sub,
    const uint8_t *frame_data, size_t frame_len, // NOLINT(bugprone-easily-swappable-parameters)
    uint64_t recv_time_ns)
{
    uint16_t ethertype = 0;
    uint16_t app_id = 0;
    uint16_t vlan_id = 0;
    const uint8_t *apdu_data = NULL;
    size_t apdu_len = 0;
    size_t apdu_offset = 0;
    sv_apdu_t apdu;
    int ret;
#ifdef IEC61850_SECURITY_ENABLED
    uint32_t sec_timestamp = 0;
#endif

    if ((sub == NULL) || (frame_data == NULL) || (frame_len == 0U)) {
        return 0;
    }

    /* Parse Ethernet frame */
    ret = iec61850_eth_frame_parse(frame_data, frame_len,
                                    &ethertype, &app_id, &vlan_id,
                                    &apdu_data, &apdu_len, &apdu_offset);
    if (ret != 0) {
        return 0;
    }

    /* Validate SV EtherType */
    if (ethertype != IEC61850_ETHERTYPE_SV) {
        return 0;
    }

    /* Validate multicast MAC — accept both SV (01:0C:CD:04) and
     * GOOSE (01:0C:CD:01) prefixes for interop with implementations
     * that use the GOOSE range for SV traffic */
    if (!iec61850_eth_is_sv_multicast(frame_data) &&
        !iec61850_eth_is_goose_multicast(frame_data)) {
        return 0;
    }

    /* APPID filter */
    if ((sub->config.filter_appid != 0U) && (app_id != sub->config.filter_appid)) {
        return 0;
    }

#ifdef IEC61850_SECURITY_ENABLED
    /* Phase 1: Verify signature + forward-drift (no pub_state needed) */
    if (sub->security_enabled) {
        ret = sv_verify_security_signature(sub, frame_data, frame_len,
                                             apdu_offset, apdu_len,
                                             &sec_timestamp);
        if (ret != 0) {
            return 0;
        }
    }
#endif

    /* Decode SV APDU */
    sv_apdu_init(&apdu);
    ret = sv_decode_apdu(apdu_data, apdu_len, &apdu);
    if (ret != 0) {
        return 0;
    }

#ifdef IEC61850_SECURITY_ENABLED
    /* Phase 2: Per-publisher replay check after decode */
    if ((sub->security_enabled) && (sec_timestamp > 0U) && (apdu.noASDU > 0U)) {
        iec61850_sv_pub_state_t *ps = find_or_create_pub(sub, apdu.asdu[0].svID);
        if (ps != NULL) {
            ret = sv_verify_security_replay(sub, ps, sec_timestamp);
            if (ret != 0) {
                return 0;
            }
        }
    }
#endif

    /* Process ALL ASDUs */
    for (uint8_t i = 0; i < apdu.noASDU; i++) {
        (void)iec61850_sv_subscriber_process(sub, &apdu.asdu[i], recv_time_ns);
    }

    return (apdu.noASDU > 0U) ? 1 : 0;
}

int iec61850_sv_subscriber_poll(iec61850_sv_subscriber_t *sub,
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

    ret = iec61850_sv_subscriber_process_frame(
        sub, (const uint8_t *)pkt_data, (size_t)pkt_len, recv_time_ns);

    packet_io_release(io);
    return ret;
}
