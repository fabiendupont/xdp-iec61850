/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * ptp_message.c — IEEE 1588-2008 wire codec. Big-endian on the
 * wire; bounds-checked, allocation-free, fully deterministic
 * (CBMC-analyzable, matching the repo's pure-core discipline).
 */

#include "transport/ptp_message.h"

#include <string.h>
#include <errno.h>

/* --- little endianness helpers (network order = big endian) ------ */

static uint16_t rd16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t rd32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | p[3];
}

static uint64_t rd48(const uint8_t *p)
{
    return ((uint64_t)p[0] << 40) | ((uint64_t)p[1] << 32) |
           ((uint64_t)p[2] << 24) | ((uint64_t)p[3] << 16) |
           ((uint64_t)p[4] << 8) | p[5];
}

static uint64_t rd64(const uint8_t *p)
{
    return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) |
           ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) |
           ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) |
           ((uint64_t)p[6] << 8) | p[7];
}

/* correctionField (ns scaled by 2^16, possibly negative): shift in
 * the UNSIGNED domain, then sign-extend bit 47 explicitly — a right
 * shift of a negative signed value is implementation-defined
 * (MISRA-C:2012 Rule 10.1 preference), and a plain logical shift
 * alone would lose the sign. Both operations are well-defined and
 * the result always fits int64_t (48-bit signed ns count). */
static int64_t rd_correction_ns(const uint8_t *p)
{
    uint64_t v = rd64(p) >> 16U;

    if ((v & 0x800000000000ULL) != 0U) {
        return (int64_t)(v - 0x1000000000000ULL);
    }
    return (int64_t)v;
}

static void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void wr48(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 6; i++) {
        p[i] = (uint8_t)(v >> (8 * (5 - i)));
    }
}

static void wr64(uint8_t *p, uint64_t v)
{
    for (int i = 0; i < 8; i++) {
        p[i] = (uint8_t)(v >> (8 * (7 - i)));
    }
}

static void rd_timestamp(const uint8_t *p, ptp_timestamp_t *ts)
{
    ts->seconds = rd48(p);
    ts->nanoseconds = rd32(p + 6);
}

static void wr_timestamp(uint8_t *p, const ptp_timestamp_t *ts)
{
    wr48(p, ts->seconds);
    wr32(p + 6, ts->nanoseconds);
}

static void rd_identity(const uint8_t *p,
                        uint8_t id[PTP_CLOCK_IDENTITY_LEN])
{
    memcpy(id, p, PTP_CLOCK_IDENTITY_LEN);
}

static void rd_port_identity(const uint8_t *p, ptp_port_identity_t *pi)
{
    rd_identity(p, pi->clock_identity);
    pi->port_number = rd16(p + 8);
}

static void wr_port_identity(uint8_t *p, const ptp_port_identity_t *pi)
{
    memcpy(p, pi->clock_identity, PTP_CLOCK_IDENTITY_LEN);
    wr16(p + 8, pi->port_number);
}

/* --- parse --------------------------------------------------------- */

int ptp_parse(const uint8_t *buf, size_t len,
              ptp_header_t *hdr, ptp_announce_t *announce,
              ptp_sync_t *sync, ptp_follow_up_t *follow_up,
              ptp_delay_resp_t *delay_resp)
{
    if ((buf == NULL) || (hdr == NULL) || (len < PTP_HEADER_LEN)) {
        return -EINVAL;
    }

    uint8_t type = buf[0] & 0x0Fu;
    if ((type != PTP_MSG_SYNC) && (type != PTP_MSG_DELAY_REQ) &&
        (type != PTP_MSG_FOLLOW_UP) && (type != PTP_MSG_DELAY_RESP) &&
        (type != PTP_MSG_ANNOUNCE)) {
        return -EINVAL;
    }

    hdr->message_type = type;
    hdr->version_ptp = buf[1];
    if (hdr->version_ptp != PTP_VERSION_PTP) {
        return -EINVAL;
    }

    hdr->message_length = rd16(buf + 2);
    if ((hdr->message_length < PTP_HEADER_LEN) ||
        ((size_t)hdr->message_length > len)) {
        return -EINVAL;
    }

    hdr->domain_number = buf[4];
    hdr->flag_field = rd16(buf + 6);
    /* correctionField: nanoseconds scaled by 2^16. */
    hdr->correction_ns = rd_correction_ns(buf + 8);
    rd_port_identity(buf + 16, &hdr->source_port_identity);
    hdr->sequence_id = rd16(buf + 28);
    hdr->log_message_interval = (int8_t)buf[33];

    const uint8_t *body = buf + PTP_HEADER_LEN;

    switch (type) {
    case PTP_MSG_ANNOUNCE:
        if (hdr->message_length < PTP_HEADER_LEN + 30) {
            return -EINVAL;
        }
        if (announce != NULL) {
            rd_timestamp(body, &announce->origin_timestamp);
            announce->current_utc_offset = rd16(body + 10);
            announce->grandmaster_priority1 = body[12];
            announce->grandmaster_clock_quality.clock_class =
                body[13];
            announce->grandmaster_clock_quality.clock_accuracy =
                body[14];
            announce->grandmaster_clock_quality
                .offset_scaled_log_variance = rd16(body + 15);
            announce->grandmaster_priority2 = body[17];
            rd_identity(body + 18, announce->grandmaster_identity);
            announce->steps_removed = rd16(body + 26);
            announce->time_source = body[28];
        }
        break;

    case PTP_MSG_SYNC:
    case PTP_MSG_DELAY_REQ:
        if (hdr->message_length < PTP_HEADER_LEN + 10) {
            return -EINVAL;
        }
        if (sync != NULL) {
            rd_timestamp(body, &sync->origin_timestamp);
        }
        break;

    case PTP_MSG_FOLLOW_UP:
        if (hdr->message_length < PTP_HEADER_LEN + 10) {
            return -EINVAL;
        }
        if (follow_up != NULL) {
            rd_timestamp(body, &follow_up->precise_origin_timestamp);
        }
        break;

    case PTP_MSG_DELAY_RESP:
        if (hdr->message_length < PTP_HEADER_LEN + 20) {
            return -EINVAL;
        }
        if (delay_resp != NULL) {
            rd_timestamp(body, &delay_resp->receive_timestamp);
            rd_port_identity(body + 10,
                             &delay_resp->requesting_port_identity);
        }
        break;

    default:
        return -EINVAL;
    }

    return (int)type;
}

/* --- build --------------------------------------------------------- */

int ptp_build(uint8_t *buf, size_t cap, uint8_t message_type,
              uint8_t domain, uint16_t flags, int64_t correction_ns,
              const ptp_port_identity_t *source,
              uint16_t sequence_id, int8_t log_message_interval,
              const ptp_announce_t *announce,
              const ptp_timestamp_t *origin_timestamp,
              const ptp_timestamp_t *precise_origin_timestamp,
              const ptp_delay_resp_t *delay_resp)
{
    if ((buf == NULL) || (source == NULL)) {
        return -EINVAL;
    }

    uint16_t body_len;
    switch (message_type) {
    case PTP_MSG_ANNOUNCE:
        if (announce == NULL) { return -EINVAL; }
        body_len = 30;
        break;
    case PTP_MSG_SYNC:
    case PTP_MSG_DELAY_REQ:
        if (origin_timestamp == NULL) { return -EINVAL; }
        body_len = 10;
        break;
    case PTP_MSG_FOLLOW_UP:
        if (precise_origin_timestamp == NULL) { return -EINVAL; }
        body_len = 10;
        break;
    case PTP_MSG_DELAY_RESP:
        if (delay_resp == NULL) { return -EINVAL; }
        body_len = 20;
        break;
    default:
        return -EINVAL;
    }

    uint16_t total = (uint16_t)(PTP_HEADER_LEN + body_len);
    if (cap < (size_t)total) {
        return -EINVAL;
    }

    memset(buf, 0, total);
    buf[0] = message_type;
    buf[1] = PTP_VERSION_PTP;
    wr16(buf + 2, total);
    buf[4] = domain;
    wr16(buf + 6, flags);
    wr64(buf + 8, (uint64_t)correction_ns << 16);
    wr_port_identity(buf + 16, source);
    wr16(buf + 28, sequence_id);
    buf[32] = 0; /* controlField (legacy) */
    buf[33] = (uint8_t)log_message_interval;

    uint8_t *body = buf + PTP_HEADER_LEN;
    switch (message_type) {
    case PTP_MSG_ANNOUNCE:
        wr_timestamp(body, &announce->origin_timestamp);
        wr16(body + 10, announce->current_utc_offset);
        body[12] = announce->grandmaster_priority1;
        body[13] = announce->grandmaster_clock_quality.clock_class;
        body[14] =
            announce->grandmaster_clock_quality.clock_accuracy;
        wr16(body + 15, announce->grandmaster_clock_quality
                            .offset_scaled_log_variance);
        body[17] = announce->grandmaster_priority2;
        memcpy(body + 18, announce->grandmaster_identity,
               PTP_CLOCK_IDENTITY_LEN);
        wr16(body + 26, announce->steps_removed);
        body[28] = announce->time_source;
        break;
    case PTP_MSG_SYNC:
    case PTP_MSG_DELAY_REQ:
        wr_timestamp(body, origin_timestamp);
        break;
    case PTP_MSG_FOLLOW_UP:
        wr_timestamp(body, precise_origin_timestamp);
        break;
    case PTP_MSG_DELAY_RESP:
        wr_timestamp(body, &delay_resp->receive_timestamp);
        wr_port_identity(body + 10,
                         &delay_resp->requesting_port_identity);
        break;
    default:
        return -EINVAL;
    }

    return (int)total;
}

/* --- dataset comparison -------------------------------------------- */

int ptp_dataset_compare(uint8_t a_prio1, const ptp_clock_quality_t *a_q,
                        uint8_t a_prio2,
                        const uint8_t a_identity[PTP_CLOCK_IDENTITY_LEN],
                        uint16_t a_steps_removed,
                        uint8_t b_prio1, const ptp_clock_quality_t *b_q,
                        uint8_t b_prio2,
                        const uint8_t b_identity[PTP_CLOCK_IDENTITY_LEN],
                        uint16_t b_steps_removed)
{
    if ((a_q == NULL) || (b_q == NULL) || (a_identity == NULL) ||
        (b_identity == NULL)) {
        return 0;
    }
    if (a_prio1 != b_prio1) {
        return (a_prio1 < b_prio1) ? -1 : 1;
    }
    if (a_q->clock_class != b_q->clock_class) {
        return (a_q->clock_class < b_q->clock_class) ? -1 : 1;
    }
    if (a_q->clock_accuracy != b_q->clock_accuracy) {
        return (a_q->clock_accuracy < b_q->clock_accuracy) ? -1 : 1;
    }
    if (a_q->offset_scaled_log_variance !=
        b_q->offset_scaled_log_variance) {
        return (a_q->offset_scaled_log_variance <
                b_q->offset_scaled_log_variance) ? -1 : 1;
    }
    if (a_prio2 != b_prio2) {
        return (a_prio2 < b_prio2) ? -1 : 1;
    }
    int idc = memcmp(a_identity, b_identity, PTP_CLOCK_IDENTITY_LEN);
    if (idc != 0) {
        return (idc < 0) ? -1 : 1;
    }
    if (a_steps_removed != b_steps_removed) {
        return (a_steps_removed < b_steps_removed) ? -1 : 1;
    }
    return 0;
}

/* --- timestamps ---------------------------------------------------- */

int64_t ptp_timestamp_diff_ns(const ptp_timestamp_t *a,
                              const ptp_timestamp_t *b)
{
    if ((a == NULL) || (b == NULL)) {
        return 0;
    }
    /* Seconds delta bounded by callers (power-profile epochs);
     * int64 ns carries ±292 years. */
    int64_t ds = (int64_t)(a->seconds - b->seconds);
    return ds * 1000000000LL +
           (int64_t)a->nanoseconds - (int64_t)b->nanoseconds;
}
