/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * GOOSE Subscriber Implementation
 *
 * License: BSD-3-Clause
 */

#include "goose/goose_subscriber.h"
#include "transport/eth_frame.h"
#include <string.h>
#include <time.h>
#include <errno.h>

#ifdef IEC61850_SECURITY_ENABLED
#include "security/key_manager.h"
#include "security/cert_manager.h"
#endif

void iec61850_goose_sub_config_init(iec61850_goose_sub_config_t *cfg)
{
    if (cfg == NULL) { return; }
    (void)memset(cfg, 0, sizeof(*cfg));
    cfg->timeout_ms = 10000;
}

void iec61850_goose_subscriber_init(iec61850_goose_subscriber_t *sub,
                                     const iec61850_goose_sub_config_t *cfg)
{
    if (sub == NULL) { return; }
    (void)memset(sub, 0, sizeof(*sub));

    if (cfg != NULL) {
        sub->config = *cfg;
    } else {
        iec61850_goose_sub_config_init(&sub->config);
    }
}

void iec61850_goose_subscriber_destroy(iec61850_goose_subscriber_t *sub)
{
    (void)sub;
}

void iec61850_goose_subscriber_set_callback(iec61850_goose_subscriber_t *sub,
                                              iec61850_goose_callback_t cb,
                                              void *user_data)
{
    if (sub == NULL) { return; }
    sub->callback = cb;
    sub->callback_user_data = user_data;
}

/* Find or create publisher state entry */
static iec61850_goose_pub_state_t *find_or_create_pub(
    iec61850_goose_subscriber_t *sub, const char *gocb_ref)
{
    /* Search existing */
    for (size_t i = 0; i < sub->publisher_count; i++) {
        if (sub->publishers[i].valid &&
            strcmp(sub->publishers[i].gocb_ref, gocb_ref) == 0) {
            return &sub->publishers[i];
        }
    }

    /* Create new if room */
    if (sub->publisher_count >= (size_t)IEC61850_GOOSE_MAX_PUBLISHERS) {
        return NULL;
    }

    iec61850_goose_pub_state_t *ps = &sub->publishers[sub->publisher_count];
    (void)memset(ps, 0, sizeof(*ps));
    (void)strncpy(ps->gocb_ref, gocb_ref, (size_t)GOOSE_MAX_GOCBREF_LEN - 1U);
    ps->gocb_ref[GOOSE_MAX_GOCBREF_LEN - 1U] = '\0';
    ps->valid = true;
    sub->publisher_count++;

    return ps;
}

bool iec61850_goose_subscriber_process(iec61850_goose_subscriber_t *sub,
                                        const goose_apdu_t *apdu,
                                        uint64_t recv_time_ns)
{
    iec61850_goose_pub_state_t *ps;
    iec61850_goose_message_t msg;

    if (sub == NULL || apdu == NULL) {
        return false;
    }

    /* Apply gocbRef filter */
    if (sub->config.filter_gocbref[0] != '\0') {
        if (strcmp(apdu->gocbRef, sub->config.filter_gocbref) != 0) {
            return false;
        }
    }

    /* Find or create publisher state */
    ps = find_or_create_pub(sub, apdu->gocbRef);
    if (ps == NULL) {
        return false;
    }

    /* Build message */
    msg.apdu = *apdu;
    msg.recv_timestamp_ns = recv_time_ns;
    msg.is_new_state = false;
    msg.is_duplicate = false;
    msg.is_retransmission = false;

    /* Detect state changes, duplicates, retransmissions */
    if (ps->message_count == 0U) {
        /* First message from this publisher */
        msg.is_new_state = true;
    } else if (apdu->stNum > ps->latest_st_num) {
        /* New state */
        msg.is_new_state = true;
    } else if (apdu->stNum == ps->latest_st_num) {
        if (apdu->sqNum <= ps->latest_sq_num) {
            /* Duplicate or out-of-order retransmission — discard */
            msg.is_duplicate = true;
            sub->total_duplicates++;
        } else {
            /* Retransmission (same state, higher sequence) */
            msg.is_retransmission = true;
        }
    } else {
        /* stNum < latest_st_num — old state, silently discard */
        sub->total_messages++;
        return false;
    }

    /* Update publisher state only for new/retransmission messages */
    if (!msg.is_duplicate) {
        ps->latest_st_num = apdu->stNum;
        ps->latest_sq_num = apdu->sqNum;
    }
    ps->last_recv_time_ns = recv_time_ns;
    ps->message_count++;
    ps->timeout_detected = false;

    sub->total_messages++;

    /* Invoke callback only for non-duplicate messages */
    if (sub->callback != NULL && !msg.is_duplicate) {
        sub->callback(&msg, sub->callback_user_data);
    }

    return !msg.is_duplicate;
}

void iec61850_goose_subscriber_check_timeouts(
    iec61850_goose_subscriber_t *sub, uint64_t current_time_ns)
{
    uint64_t timeout_ns;

    if (sub == NULL) { return; }

    timeout_ns = (uint64_t)sub->config.timeout_ms * 1000000ULL;

    for (size_t i = 0; i < sub->publisher_count; i++) {
        if (!sub->publishers[i].valid || sub->publishers[i].timeout_detected) {
            continue;
        }
        if (sub->publishers[i].last_recv_time_ns > 0ULL &&
            current_time_ns > sub->publishers[i].last_recv_time_ns &&
            (current_time_ns - sub->publishers[i].last_recv_time_ns) > timeout_ns) {
            sub->publishers[i].timeout_detected = true;
            sub->total_timeouts++;
        }
    }
}

const iec61850_goose_pub_state_t *iec61850_goose_subscriber_get_pub_state(
    const iec61850_goose_subscriber_t *sub, const char *gocb_ref)
{
    if (sub == NULL || gocb_ref == NULL) { return NULL; }

    for (size_t i = 0; i < sub->publisher_count; i++) {
        if (sub->publishers[i].valid &&
            strcmp(sub->publishers[i].gocb_ref, gocb_ref) == 0) {
            return &sub->publishers[i];
        }
    }
    return NULL;
}

int iec61850_goose_subscriber_enable_security(iec61850_goose_subscriber_t *sub,
                                                void *cert_manager)
{
    if (sub == NULL || cert_manager == NULL) {
        return -EINVAL;
    }

#ifdef IEC61850_SECURITY_ENABLED
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

/*
 * Parse IEC 62351-6 security extension from frame data after APDU.
 * Extracts signature from CONSTRUCTED [12] (tag 0xAC).
 * Returns: 0 on success, negative on failure
 */
#ifdef IEC61850_SECURITY_ENABLED
static int parse_security_extension(const uint8_t *data, size_t data_len,
                                      const uint8_t **sig_out, size_t *sig_len_out,
                                      uint32_t *timestamp_secs_out)
{
    size_t pos = 0;

    if (data_len < 4U) { return -1; }

    /* Look for tag 0xAC (CONSTRUCTED [12]) */
    if (data[pos] != 0xACU) { return -1; }
    pos++;

    /* Parse length */
    size_t ext_len;
    if (data[pos] < 0x80U) {
        ext_len = data[pos++];
    } else if (data[pos] == 0x81U) {
        pos++;
        if (pos >= data_len) { return -1; }
        ext_len = data[pos++];
    } else if (data[pos] == 0x82U) {
        pos++;
        if (pos + 1U >= data_len) { return -1; }
        ext_len = ((size_t)data[pos] << 8U) | data[pos + 1U];
        pos += 2U;
    } else {
        return -1;
    }

    if (pos + ext_len > data_len) { return -1; }

    size_t end = pos + ext_len;

    /* Parse sub-elements */
    while (pos < end) {
        uint8_t tag = data[pos++];
        if (pos >= end) { return -1; }

        size_t len;
        if (data[pos] < 0x80U) {
            len = data[pos++];
        } else if (data[pos] == 0x81U) {
            pos++;
            if (pos >= end) { return -1; }
            len = data[pos++];
        } else if (data[pos] == 0x82U) {
            pos++;
            if (pos + 1U >= end) { return -1; }
            len = ((size_t)data[pos] << 8U) | data[pos + 1U];
            pos += 2U;
        } else {
            return -1;
        }

        if (pos + len > end) { return -1; }

        if (tag == 0x80U && len == 8U && timestamp_secs_out != NULL) {
            /* timeOfCurrentKey: first 4 bytes are seconds */
            *timestamp_secs_out = ((uint32_t)data[pos] << 24U) |
                                  ((uint32_t)data[pos + 1U] << 16U) |
                                  ((uint32_t)data[pos + 2U] << 8U) |
                                  (uint32_t)data[pos + 3U];
        } else if (tag == 0x82U) {
            /* signature */
            *sig_out = &data[pos];
            *sig_len_out = len;
        }

        pos += len;
    }

    return (*sig_out != NULL) ? 0 : -1;
}

/* Maximum forward-drift tolerance: reject timestamps > 60s in the future */
#define GOOSE_SEC_MAX_FORWARD_DRIFT_S  60U
/* Maximum backward-drift tolerance: reject timestamps > 5s in the past */
#define GOOSE_SEC_MAX_BACKWARD_DRIFT_S  5U

/*
 * Phase 1: Verify signature and forward-drift only.
 * Called before APDU decode (publisher identity unknown).
 * Stores parsed msg_timestamp in *timestamp_out for Phase 2 replay check.
 */
static int verify_security_signature(iec61850_goose_subscriber_t *sub,
                                       const uint8_t *frame_data, size_t frame_len,
                                       const uint8_t *apdu_data, size_t apdu_len,
                                       uint32_t *timestamp_out)
{
    iec61850_cert_manager_t *cm = (iec61850_cert_manager_t *)sub->cert_manager;
    EVP_PKEY *pubkey;
    const uint8_t *sig = NULL;
    size_t sig_len = 0;
    uint32_t msg_timestamp = 0;
    int ret;

    if (timestamp_out != NULL) { *timestamp_out = 0; }

    /* Runtime certificate expiry check */
    if (!iec61850_cert_manager_is_valid_time(cm)) {
        sub->total_security_failures++;
        return -EKEYEXPIRED;
    }

    /* Security extension follows the APDU in the frame */
    size_t apdu_offset = (size_t)(apdu_data - frame_data);
    size_t after_apdu = apdu_offset + apdu_len;
    if (after_apdu >= frame_len) {
        sub->total_security_failures++;
        return -1;
    }

    ret = parse_security_extension(&frame_data[after_apdu],
                                     frame_len - after_apdu,
                                     &sig, &sig_len, &msg_timestamp);
    if (ret != 0 || sig == NULL) {
        sub->total_security_failures++;
        return -1;
    }

    /* Verify signature */
    pubkey = iec61850_cert_manager_get_public_key(cm);
    if (pubkey == NULL) {
        sub->total_security_failures++;
        return -1;
    }

    ret = iec61850_key_manager_verify(apdu_data, apdu_len,
                                        sig, sig_len, pubkey);
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
        if (ts64 > now_secs + GOOSE_SEC_MAX_FORWARD_DRIFT_S) {
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
static int verify_security_replay(iec61850_goose_subscriber_t *sub,
                                    iec61850_goose_pub_state_t *pub_state,
                                    uint32_t msg_timestamp)
{
    if (pub_state == NULL || msg_timestamp == 0U) { return 0; }

    uint64_t ts64 = (uint64_t)msg_timestamp;

    if (pub_state->last_msg_timestamp > 0ULL) {
        uint64_t last64 = pub_state->last_msg_timestamp;
        if (ts64 < last64 &&
            (last64 - ts64) > GOOSE_SEC_MAX_BACKWARD_DRIFT_S) {
            sub->total_security_failures++;
            return -1;
        }
    }
    pub_state->last_msg_timestamp = ts64;

    return 0;
}
#endif /* IEC61850_SECURITY_ENABLED */

int iec61850_goose_subscriber_process_frame(
    iec61850_goose_subscriber_t *sub,
    const uint8_t *frame_data, size_t frame_len,
    uint64_t recv_time_ns)
{
    uint16_t ethertype = 0;
    uint16_t app_id = 0;
    uint16_t vlan_id = 0;
    const uint8_t *apdu_data = NULL;
    size_t apdu_len = 0;
    goose_apdu_t apdu;
    int ret;
#ifdef IEC61850_SECURITY_ENABLED
    uint32_t sec_timestamp = 0;
#endif

    if (sub == NULL || frame_data == NULL || frame_len == 0U) {
        return 0;
    }

    /* Parse Ethernet frame */
    ret = iec61850_eth_frame_parse(frame_data, frame_len,
                                    &ethertype, &app_id, &vlan_id,
                                    &apdu_data, &apdu_len);
    if (ret != 0) {
        return 0;
    }

    /* Validate GOOSE EtherType */
    if (ethertype != IEC61850_ETHERTYPE_GOOSE) {
        return 0;
    }

    /* Validate multicast MAC */
    if (!iec61850_eth_is_goose_multicast(frame_data)) {
        return 0;
    }

    /* APPID filter */
    if (sub->config.filter_appid != 0U && app_id != sub->config.filter_appid) {
        return 0;
    }

    /* VLAN filter */
    if (sub->config.filter_vlan != 0U && vlan_id != sub->config.filter_vlan) {
        return 0;
    }

#ifdef IEC61850_SECURITY_ENABLED
    /* Phase 1: Verify signature + forward-drift (no pub_state needed) */
    if (sub->security_enabled) {
        ret = verify_security_signature(sub, frame_data, frame_len,
                                          apdu_data, apdu_len, &sec_timestamp);
        if (ret != 0) {
            return 0;
        }
    }
#endif

    /* Decode BER APDU */
    goose_apdu_init(&apdu);
    ret = goose_decode_apdu(apdu_data, apdu_len, &apdu);
    if (ret != GOOSE_BER_OK) {
        return 0;
    }

#ifdef IEC61850_SECURITY_ENABLED
    /* Phase 2: Per-publisher replay check (pub_state now available) */
    if (sub->security_enabled && sec_timestamp > 0U) {
        iec61850_goose_pub_state_t *ps = find_or_create_pub(sub, apdu.gocbRef);
        if (ps != NULL) {
            ret = verify_security_replay(sub, ps, sec_timestamp);
            if (ret != 0) {
                return 0;
            }
        }
    }
#endif

    /* Process decoded APDU through state machine */
    if (iec61850_goose_subscriber_process(sub, &apdu, recv_time_ns)) {
        return 1;
    }

    return 0;
}

int iec61850_goose_subscriber_poll(iec61850_goose_subscriber_t *sub,
                                    struct packet_io *io)
{
    void *pkt_data = NULL;
    uint32_t pkt_len = 0;
    struct timespec ts;
    uint64_t recv_time_ns;
    int ret;

    if (sub == NULL || io == NULL) {
        return -EINVAL;
    }

    ret = packet_io_recv(io, &pkt_data, &pkt_len);
    if (ret <= 0) {
        return 0;
    }

    (void)clock_gettime(CLOCK_REALTIME, &ts);
    recv_time_ns = (uint64_t)ts.tv_sec * 1000000000ULL +
                   (uint64_t)ts.tv_nsec;

    ret = iec61850_goose_subscriber_process_frame(
        sub, (const uint8_t *)pkt_data, (size_t)pkt_len, recv_time_ns);

    packet_io_release(io);
    return ret;
}
