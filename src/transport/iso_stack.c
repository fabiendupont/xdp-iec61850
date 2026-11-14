/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * ISO Transport Stack Implementation
 *
 * TPKT (RFC 1006) + ISO Session (ISO 8327) + ISO Presentation (ISO 8823)
 * + ACSE (ISO 8650) composite stack for MMS transport.
 */


#include "transport/iso_stack.h"
#include <string.h>
#include <errno.h>

/* Well-known OIDs */
const uint8_t IEC61850_OID_ACSE[4] = {0x52, 0x01, 0x00, 0x01};  /* 2.2.1.0.1 */
const uint8_t IEC61850_OID_BER[2]  = {0x51, 0x01};               /* 2.1.1 */
const uint8_t IEC61850_OID_MMS[5]  = {0x28, 0xCA, 0x22, 0x02, 0x01}; /* 1.0.9506.2.1 */

/* MMS Application Context OID (IEC 61850-8-1) */
static const uint8_t MMS_APP_CONTEXT_OID[] = {
    0x28, 0xCA, 0x22, 0x02, 0x03  /* 1.0.9506.2.3 */
};

/* ========================================================================
 * WP-3b (IEC 62351-4): transport dispatch.
 *
 * A connection runs either over plain TCP (conn->tcp) or over TLS
 * (conn->tls, set via iec61850_iso_connect_tls() or a TLS listener
 * accept). The dispatch helpers below are the only I/O entry points
 * the composite stack uses; the plain path is byte-for-byte the
 * previous behavior when use_tls is false. TLS branches compile
 * only in security-enabled builds.
 * ======================================================================== */

static int iso_conn_send(iec61850_iso_conn_t *conn,
                           const uint8_t *data, size_t len)
{
#ifdef IEC61850_SECURITY_ENABLED
    if (conn->use_tls) {
        return iec61850_tls_send(&conn->tls, data, len);
    }
#endif
    return iec61850_tcp_send(&conn->tcp, data, len);
}

static int iso_conn_recv_tpkt(iec61850_iso_conn_t *conn,
                                uint8_t *buffer, size_t buflen,
                                int timeout_ms)
{
#ifdef IEC61850_SECURITY_ENABLED
    if (conn->use_tls) {
        return iec61850_tls_recv_tpkt(&conn->tls, buffer, buflen,
                                        timeout_ms);
    }
#endif
    return iec61850_tcp_recv_tpkt(&conn->tcp, buffer, buflen,
                                    timeout_ms);
}

static void iso_conn_transport_disconnect(iec61850_iso_conn_t *conn)
{
#ifdef IEC61850_SECURITY_ENABLED
    if (conn->use_tls) {
        (void)iec61850_tls_disconnect(&conn->tls);
        conn->use_tls = false;
        return;
    }
#endif
    (void)iec61850_tcp_disconnect(&conn->tcp);
}

/* ========================================================================
 * BER Length Helpers (used by all layers)
 * ======================================================================== */

static int ber_write_length(uint8_t *buf, size_t buf_size, size_t *offset,
                              size_t length)
{
    if (length < 128U) {
        if (*offset >= buf_size) { return -ENOSPC; }
        buf[*offset] = (uint8_t)length;
        (*offset)++;
    } else if (length < 256U) {
        if ((*offset + 2U) > buf_size) { return -ENOSPC; }
        buf[*offset] = 0x81;
        buf[*offset + 1U] = (uint8_t)length;
        *offset += 2U;
    } else {
        if ((*offset + 3U) > buf_size) { return -ENOSPC; }
        buf[*offset] = 0x82;
        buf[*offset + 1U] = (uint8_t)(length >> 8U);
        buf[*offset + 2U] = (uint8_t)(length & 0xFFU);
        *offset += 3U;
    }
    return 0;
}

static int ber_read_length(const uint8_t *buf, size_t buf_len, size_t *offset,
                             size_t *length)
{
    if (*offset >= buf_len) { return -EBADMSG; }

    uint8_t first = buf[*offset];
    (*offset)++;

    if ((first & 0x80U) == 0U) {
        *length = first;
    } else {
        uint8_t num_bytes = first & 0x7FU;
        if ((num_bytes == 0U) || (num_bytes > 2U)) { return -EBADMSG; }
        if (*offset + (size_t)num_bytes > buf_len) { return -EBADMSG; }

        *length = 0;
        for (uint8_t i = 0U; i < num_bytes; i++) {
            *length = (*length << 8U) | buf[*offset];
            (*offset)++;
        }
    }
    return 0;
}

/* ========================================================================
 * TPKT (RFC 1006)
 * ======================================================================== */

/* COTP (ISO 8073 Class 0 Transport) */
#define COTP_DT_TYPE    0xF0U  /* Data TPDU */
#define COTP_CR_TYPE    0xE0U  /* Connection Request */
#define COTP_CC_TYPE    0xD0U  /* Connection Confirm */
#define COTP_DT_EOT     0x80U
#define COTP_DT_HEADER  3U     /* LI(1) + type(1) + EOT(1) */

/* ========================================================================
 * COTP Negotiation (ISO 8073 Class 0)
 * ======================================================================== */

/*
 * Send COTP Connection Request (CR) and receive Connection Confirm (CC).
 * CR TPDU: LI=6, type=0xE0, DST-REF=0x0000, SRC-REF=0x0001, Class=0x00
 * Wrapped in TPKT header.
 */
static int cotp_negotiate(iec61850_iso_conn_t *conn, int timeout_ms)
{
    uint8_t cr_buf[22];
    uint8_t cc_buf[64];
    int ret;

    /* Build TPKT + CR TPDU with TPDU-size + TSAP parameters */
    /* TPKT: version=3, reserved=0, length=22 */
    cr_buf[0] = 0x03;  /* TPKT version */
    cr_buf[1] = 0x00;
    cr_buf[2] = 0x00;
    cr_buf[3] = 0x16;  /* total length = 22 */
    /* COTP CR: LI=17, type=0xE0, DST-REF=0, SRC-REF=1, Class=0 */
    cr_buf[4] = 0x11;  /* LI = 17 */
    cr_buf[5] = COTP_CR_TYPE;
    cr_buf[6] = 0x00; cr_buf[7] = 0x00;  /* DST-REF */
    cr_buf[8] = 0x00; cr_buf[9] = 0x01;  /* SRC-REF */
    cr_buf[10] = 0x00;  /* Class 0 */
    /* TPDU size parameter: C0 01 0D (8192 bytes) */
    cr_buf[11] = 0xC0; cr_buf[12] = 0x01; cr_buf[13] = 0x0D;
    /* Calling TSAP: C2 02 00 01 */
    cr_buf[14] = 0xC2; cr_buf[15] = 0x02; cr_buf[16] = 0x00; cr_buf[17] = 0x01;
    /* Called TSAP: C1 02 00 01 */
    cr_buf[18] = 0xC1; cr_buf[19] = 0x02; cr_buf[20] = 0x00; cr_buf[21] = 0x01;

    ret = iso_conn_send(conn, cr_buf, sizeof(cr_buf));
    if (ret < 0) { return ret; }

    /* Receive CC */
    ret = iso_conn_recv_tpkt(conn, cc_buf, sizeof(cc_buf), timeout_ms);
    if (ret < 0) { return ret; }

    /* Validate: TPKT header + COTP CC (type 0xD0) */
    if (ret < 7) { return -EPROTO; }
    /* cc_buf[4] is LI, cc_buf[5] is type */
    if ((cc_buf[5] & 0xF0U) != COTP_CC_TYPE) { return -EPROTO; }

    return 0;
}

/*
 * Receive COTP CR from client and send CC back.
 */
static int cotp_accept(iec61850_iso_conn_t *conn, int timeout_ms)
{
    uint8_t cr_buf[64];
    uint8_t cc_buf[22];
    int ret;

    /* Receive CR */
    ret = iso_conn_recv_tpkt(conn, cr_buf, sizeof(cr_buf), timeout_ms);
    if (ret < 0) { return ret; }

    if (ret < 7) { return -EPROTO; }
    if ((cr_buf[5] & 0xF0U) != COTP_CR_TYPE) { return -EPROTO; }

    /* Extract client's SRC-REF (bytes 8-9 in the TPKT frame) */
    uint16_t client_src_ref = 0;
    if (ret >= 10) {
        client_src_ref = (uint16_t)((uint16_t)cr_buf[8] << 8U) | cr_buf[9U];
    }

    /* Build TPKT + CC TPDU with parameters */
    cc_buf[0] = 0x03;  /* TPKT version */
    cc_buf[1] = 0x00;
    cc_buf[2] = 0x00;
    cc_buf[3] = 0x16;  /* total length = 22 */
    cc_buf[4] = 0x11;  /* LI = 17 */
    cc_buf[5] = COTP_CC_TYPE;
    /* DST-REF = client's SRC-REF */
    cc_buf[6] = (uint8_t)(client_src_ref >> 8U);
    cc_buf[7] = (uint8_t)(client_src_ref & 0xFFU);
    /* SRC-REF = our reference */
    cc_buf[8] = 0x00; cc_buf[9] = 0x01;
    cc_buf[10] = 0x00;  /* Class 0 */
    /* TPDU size: C0 01 0D (8192) */
    cc_buf[11] = 0xC0; cc_buf[12] = 0x01; cc_buf[13] = 0x0D;
    /* Calling TSAP: C2 02 00 01 */
    cc_buf[14] = 0xC2; cc_buf[15] = 0x02; cc_buf[16] = 0x00; cc_buf[17] = 0x01;
    /* Called TSAP: C1 02 00 01 */
    cc_buf[18] = 0xC1; cc_buf[19] = 0x02; cc_buf[20] = 0x00; cc_buf[21] = 0x01;

    ret = iso_conn_send(conn, cc_buf, sizeof(cc_buf));
    if (ret < 0) { return ret; }

    return 0;
}

int iec61850_tpkt_encode(uint8_t *buf, size_t buf_size,
                           const uint8_t *data, size_t data_len)
{
    size_t total;

    if ((buf == NULL) || (data == NULL)) { return -EINVAL; }

    /* TPKT header (4) + COTP DT header (3) + data */
    total = (size_t)IEC61850_TPKT_HEADER_LEN + COTP_DT_HEADER + data_len;
    if ((total > buf_size) || (total > 65535U)) { return -ENOSPC; }

    /* TPKT header */
    buf[0] = IEC61850_TPKT_VERSION;
    buf[1] = 0;
    buf[2] = (uint8_t)(total >> 8U);
    buf[3] = (uint8_t)(total & 0xFFU);

    /* COTP DT header */
    buf[4] = 0x02;           /* Length indicator = 2 */
    buf[5] = COTP_DT_TYPE;   /* Data TPDU */
    buf[6] = COTP_DT_EOT;    /* EOT + TPDU-NR=0 */

    (void)memcpy(&buf[7], data, data_len);

    return (int)total;
}

int iec61850_tpkt_decode(const uint8_t *buf, size_t buf_len,
                           const uint8_t **payload, size_t *payload_len)
{
    uint16_t total_len;
    size_t cotp_li;
    size_t header_len;

    if ((buf == NULL) || (payload == NULL) || (payload_len == NULL)) {
        return -EINVAL;
    }
    if (buf_len < (size_t)IEC61850_TPKT_HEADER_LEN + 1U) { return -EBADMSG; }
    if (buf[0] != (uint8_t)IEC61850_TPKT_VERSION) { return -EPROTONOSUPPORT; }

    total_len = (uint16_t)((uint16_t)buf[2] << 8U) | (uint16_t)buf[3];
    if ((total_len < (size_t)IEC61850_TPKT_HEADER_LEN + 1U) || (total_len > buf_len)) {
        return -EBADMSG;
    }

    /* Skip COTP header: LI byte tells us how long COTP header is */
    cotp_li = buf[IEC61850_TPKT_HEADER_LEN];
    header_len = (size_t)IEC61850_TPKT_HEADER_LEN + 1U + cotp_li;
    if (header_len > total_len) { return -EBADMSG; }

    *payload = &buf[header_len];
    *payload_len = (size_t)(total_len - header_len);
    return 0;
}

/* ========================================================================
 * ISO Session (ISO 8327)
 * ======================================================================== */

void iec61850_session_params_init(iec61850_session_params_t *params)
{
    if (params != NULL) {
        (void)memset(params, 0, sizeof(*params));
        params->version = 2;
        params->user_requirements = 0x0002;  /* Duplex functional unit */
        /* Default session selectors (IEC 61850-8-1) */
        params->calling_ssel[0] = 0x00;
        params->calling_ssel[1] = 0x01;
        params->calling_ssel_len = 2;
        params->called_ssel[0] = 0x00;
        params->called_ssel[1] = 0x01;
        params->called_ssel_len = 2;
    }
}

/* Encode a session parameter item: PI(1) + LI(1) + value */
static int session_encode_param(uint8_t *buf, size_t buf_size, size_t *offset,
                                  uint8_t pi, const uint8_t *value, size_t val_len)
{
    if ((*offset + 2U + val_len) > buf_size) { return -ENOSPC; }
    buf[*offset] = pi;
    buf[*offset + 1U] = (uint8_t)val_len;
    if (val_len > 0U) {
        (void)memcpy(&buf[*offset + 2U], value, val_len);
    }
    *offset += 2U + val_len;
    return 0;
}

/*
 * Write ISO 8327 Session Layer length encoding:
 *   ≤ 254: single byte (the value itself)
 *   > 254: 0xFF prefix + 2-byte big-endian length
 */
static int write_session_length(uint8_t *buf, size_t buf_size, size_t *offset,
                                  size_t length)
{
    if (length <= 254U) {
        if (*offset >= buf_size) { return -ENOSPC; }
        buf[*offset] = (uint8_t)length;
        (*offset)++;
    } else {
        if ((*offset + 3U) > buf_size) { return -ENOSPC; }
        buf[*offset] = 0xFF;
        buf[*offset + 1U] = (uint8_t)(length >> 8U);
        buf[*offset + 2U] = (uint8_t)(length & 0xFFU);
        *offset += 3U;
    }
    return 0;
}

/* Number of bytes a session length occupies */
static size_t session_length_size(size_t length)
{
    return (length <= 254U) ? 1U : 3U;
}

/* Encode CONNECT or ACCEPT SPDU */
static int session_encode_cn_ac(uint8_t *buf, size_t buf_size, uint8_t si, /* NOLINT(bugprone-easily-swappable-parameters) */
                                  const iec61850_session_params_t *params,
                                  const uint8_t *user_data, size_t user_data_len)
{
    size_t offset = 0;
    uint8_t ver_buf[1];
    uint8_t req_buf[2];
    int ret;

    if ((buf == NULL) || (params == NULL)) { return -EINVAL; }

    /*
     * Compute total SPDU content length first, so we can write the
     * correct length prefix (1 or 3 bytes depending on size).
     *
     * Content: Connect/Accept Item PGI 0x05 (contains Protocol Options 0x13
     *          + Version Number 0x16) + requirements PI (4)
     *          + optional SSELs + optional user data PI
     *
     * PGI 0x05 layout: 0x05 LI { 0x13 0x01 0x00 0x16 0x01 0x02 } = 8 bytes
     */
    size_t ca_inner = 3U + 3U;  /* protocol_options(3) + version(3) */
    size_t content_len = 2U + ca_inner;  /* PGI 0x05 tag(1) + LI(1) + inner */
    content_len += 4U;  /* requirements (PI=1,LI=1,val=2) */
    /* CONNECT includes both SSELs; ACCEPT only includes Called SSEL */
    if ((si == IEC61850_SI_CONNECT) && (params->calling_ssel_len > 0U)) {
        content_len += 2U + params->calling_ssel_len;
    }
    if (params->called_ssel_len > 0U) {
        content_len += 2U + params->called_ssel_len;
    }
    if ((user_data != NULL) && (user_data_len > 0U)) {
        /* User data PI: PI(1) + session_length_size(user_data_len) + data */
        content_len += 1U + session_length_size(user_data_len) + user_data_len;
    }

    /* SI byte */
    if (offset >= buf_size) { return -ENOSPC; }
    buf[offset] = si;
    offset++;

    /* SPDU total length */
    ret = write_session_length(buf, buf_size, &offset, content_len);
    if (ret != 0) { return ret; }

    /* Connect/Accept Item PGI (0x05) containing Protocol Options + Version */
    if ((offset + 2U + ca_inner) > buf_size) { return -ENOSPC; }
    buf[offset] = 0x05; offset++;  /* PGI Connect/Accept Item */
    buf[offset] = (uint8_t)ca_inner; offset++;

    /* Protocol Options PI (0x13): value 0x00 */
    buf[offset] = 0x13; offset++;
    buf[offset] = 0x01; offset++;
    buf[offset] = 0x00; offset++;

    /* Protocol Version PI (0x16) inside PGI 0x05 */
    ver_buf[0] = params->version;
    ret = session_encode_param(buf, buf_size, &offset,
                                 IEC61850_SPI_VERSION, ver_buf, 1);
    if (ret != 0) { return ret; }

    /* User Requirements (functional units) */
    req_buf[0] = (uint8_t)(params->user_requirements >> 8U);
    req_buf[1] = (uint8_t)(params->user_requirements & 0xFFU);
    ret = session_encode_param(buf, buf_size, &offset,
                                 IEC61850_SPI_REQUIREMENTS, req_buf, 2);
    if (ret != 0) { return ret; }

    /* Calling Session Selector (CONNECT only) */
    if ((si == IEC61850_SI_CONNECT) && (params->calling_ssel_len > 0U)) {
        ret = session_encode_param(buf, buf_size, &offset,
                                     IEC61850_SPI_CALLING_SSEL,
                                     params->calling_ssel,
                                     params->calling_ssel_len);
        if (ret != 0) { return ret; }
    }

    /* Called Session Selector */
    if (params->called_ssel_len > 0U) {
        ret = session_encode_param(buf, buf_size, &offset,
                                     IEC61850_SPI_CALLED_SSEL,
                                     params->called_ssel,
                                     params->called_ssel_len);
        if (ret != 0) { return ret; }
    }

    /* User Data */
    if ((user_data != NULL) && (user_data_len > 0U)) {
        if (offset >= buf_size) { return -ENOSPC; }
        buf[offset] = IEC61850_SPI_USER_DATA;
        offset++;
        /* User data PI length uses ISO 8327 session length encoding */
        ret = write_session_length(buf, buf_size, &offset, user_data_len);
        if (ret != 0) { return ret; }
        if ((offset + user_data_len) > buf_size) { return -ENOSPC; }
        (void)memcpy(&buf[offset],user_data, user_data_len);
        offset += user_data_len;
    }

    return (int)offset;
}

int iec61850_session_encode_connect(uint8_t *buf, size_t buf_size,
                                      const iec61850_session_params_t *params,
                                      const uint8_t *user_data,
                                      size_t user_data_len)
{
    return session_encode_cn_ac(buf, buf_size, IEC61850_SI_CONNECT,
                                 params, user_data, user_data_len);
}

int iec61850_session_encode_accept(uint8_t *buf, size_t buf_size,
                                     const iec61850_session_params_t *params,
                                     const uint8_t *user_data,
                                     size_t user_data_len)
{
    return session_encode_cn_ac(buf, buf_size, IEC61850_SI_ACCEPT,
                                 params, user_data, user_data_len);
}

int iec61850_session_encode_data(uint8_t *buf, size_t buf_size,
                                   const uint8_t *user_data,
                                   size_t user_data_len)
{
    size_t offset = 0;

    if ((buf == NULL) || (user_data == NULL)) { return -EINVAL; }

    /* GIVE_TOKENS SPDU (SI=0x01, LI=0x00) + DATA SPDU (SI=0x01, LI=0x00) */
    if ((4U + user_data_len) > buf_size) { return -ENOSPC; }

    /* GIVE_TOKENS */
    buf[offset] = IEC61850_SI_DATA; offset++;  /* SI=0x01 */
    buf[offset] = 0x00; offset++;

    /* DATA */
    buf[offset] = IEC61850_SI_DATA; offset++;  /* SI=0x01 */
    buf[offset] = 0x00; offset++;

    (void)memcpy(&buf[offset],user_data, user_data_len);
    offset += user_data_len;

    return (int)offset;
}

int iec61850_session_encode_finish(uint8_t *buf, size_t buf_size,
                                     const uint8_t *user_data,
                                     size_t user_data_len)
{
    size_t offset = 0;
    int ret;

    if (buf == NULL) { return -EINVAL; }

    size_t content_len = 0;
    if ((user_data != NULL) && (user_data_len > 0U)) {
        content_len = 1U + session_length_size(user_data_len) + user_data_len;
    }

    if (offset >= buf_size) { return -ENOSPC; }
    buf[offset] = IEC61850_SI_FINISH;
    offset++;

    ret = write_session_length(buf, buf_size, &offset, content_len);
    if (ret != 0) { return ret; }

    if ((user_data != NULL) && (user_data_len > 0U)) {
        if (offset >= buf_size) { return -ENOSPC; }
        buf[offset] = IEC61850_SPI_USER_DATA;
        offset++;
        ret = write_session_length(buf, buf_size, &offset, user_data_len);
        if (ret != 0) { return ret; }
        if ((offset + user_data_len) > buf_size) { return -ENOSPC; }
        (void)memcpy(&buf[offset],user_data, user_data_len);
        offset += user_data_len;
    }

    return (int)offset;
}

int iec61850_session_decode(const uint8_t *buf, size_t buf_len,
                              uint8_t *si_type,
                              iec61850_session_params_t *params,
                              const uint8_t **user_data,
                              size_t *user_data_len)
{
    size_t offset = 0;
    uint8_t si;
    uint8_t li;
    size_t params_end;

    if ((buf == NULL) || (si_type == NULL) || (user_data == NULL) ||
        (user_data_len == NULL)) {
        return -EINVAL;
    }

    if (buf_len < 2U) { return -EBADMSG; }

    si = buf[offset]; offset++;

    /* Read SPDU length using ISO 8327 encoding */
    {
        uint8_t first_li = buf[offset]; offset++;
        if (first_li == 0xFFU) {
            /* 3-byte form: 0xFF + 2-byte big-endian */
            if ((offset + 2U) > buf_len) { return -EBADMSG; }
            li = (uint8_t)0;  /* unused — use spdu_len below */
            size_t spdu_len = (size_t)((size_t)buf[offset] << 8U) |
                              (size_t)buf[offset + 1U];
            offset += 2U;
            params_end = offset + spdu_len;
        } else {
            li = first_li;
            params_end = offset + li;
        }
    }

    *si_type = si;
    *user_data = NULL;
    *user_data_len = 0;

    if (params != NULL) {
        iec61850_session_params_init(params);
    }

    if (si == IEC61850_SI_DATA) {
        /* Handle GIVE_TOKENS + DATA format (01 00 01 00 <data>)
         * or plain DATA format (01 00 <data>) */
        if ((li == 0U) && ((offset + 2U) <= buf_len) &&
            (buf[offset] == IEC61850_SI_DATA) && (buf[offset + 1U] == 0x00U)) {
            /* GIVE_TOKENS prefix present — skip it */
            offset += 2U;
        }
        *user_data = &buf[offset];
        *user_data_len = buf_len - offset;
        return 0;
    }

    /* Parse parameter items */
    if (params_end > buf_len) { return -EBADMSG; }

    while (offset < params_end) {
        if ((offset + 1U) >= params_end) { break; }

        uint8_t pi = buf[offset]; offset++;
        size_t plen;

        if (pi == IEC61850_SPI_USER_DATA) {
            /* User data uses ISO 8327 session length encoding */
            if (offset >= params_end) { break; }
            if (buf[offset] == 0xFFU) {
                /* 3-byte form */
                offset++;
                if ((offset + 2U) > buf_len) { break; }
                plen = (size_t)((size_t)buf[offset] << 8U) |
                       (size_t)buf[offset + 1U];
                offset += 2U;
            } else {
                plen = buf[offset];
                offset++;
            }
            /* Wire-declared user-data length must stay inside the
             * input buffer; reject instead of returning a range that
             * extends past it. */
            if ((offset + plen) > buf_len) { break; }
            *user_data = &buf[offset];
            *user_data_len = plen;
            break;  /* User data is always last */
        }

        plen = buf[offset]; offset++;

        if ((offset + plen) > params_end) { break; }

        if (params != NULL) {
            switch (pi) {
                case IEC61850_SPI_VERSION:
                    if (plen >= 1U) { params->version = buf[offset]; }
                    break;
                case IEC61850_SPI_REQUIREMENTS:
                    if (plen >= 2U) {
                        params->user_requirements =
                            (uint16_t)((uint16_t)buf[offset] << 8U) |
                            (uint16_t)buf[offset + 1U];
                    }
                    break;
                case IEC61850_SPI_CALLING_SSEL:
                    if (plen <= (size_t)IEC61850_ISO_MAX_SSEL) {
                        (void)memcpy(params->calling_ssel, &buf[offset], plen);
                        params->calling_ssel_len = plen;
                    }
                    break;
                case IEC61850_SPI_CALLED_SSEL:
                    if (plen <= (size_t)IEC61850_ISO_MAX_SSEL) {
                        (void)memcpy(params->called_ssel, &buf[offset], plen);
                        params->called_ssel_len = plen;
                    }
                    break;
                default:
                    break;
            }
        }

        offset += plen;
    }

    return 0;
}

/* ========================================================================
 * ISO Presentation (ISO 8823)
 * ======================================================================== */

/* BER tags for presentation PDU construction */
#define PRES_TAG_CP         0x31U  /* SET */
#define PRES_TAG_CPA        0x31U  /* SET */

int iec61850_pres_encode_cp(uint8_t *buf, size_t buf_size,
                              const uint8_t *acse_pdu, size_t acse_len)
{
    size_t offset = 0;

    if ((buf == NULL) || (acse_pdu == NULL)) { return -EINVAL; }

    /* Build bottom-up: we know the content sizes */
    /* For simplicity, encode directly (this is init-time, not hot path) */

    /* CP [SET] tag */
    if (offset >= buf_size) { return -ENOSPC; }
    buf[offset] = PRES_TAG_CP;
    offset++;

    /* Reserve length (will fill later) */
    size_t cp_len_offset = offset;
    offset += 3U;  /* Reserve 3 bytes for BER length */

    /* Mode selector [0] IMPLICIT SET { [0] INTEGER = 1 (normal mode) } */
    if ((offset + 8U) > buf_size) { return -ENOSPC; }
    buf[offset] = 0xA0; offset++;  /* [0] CONSTRUCTED */
    buf[offset] = 0x03; offset++;  /* length 3 */
    buf[offset] = 0x80; offset++;  /* [0] IMPLICIT */
    buf[offset] = 0x01; offset++;  /* length 1 */
    buf[offset] = 0x01; offset++;  /* normal-mode = 1 */

    /* Normal-mode-parameters [2] IMPLICIT SEQUENCE */
    if ((offset + 3U) > buf_size) { return -ENOSPC; }
    buf[offset] = 0xA2; offset++;  /* [2] CONSTRUCTED */
    size_t nmp_len_offset = offset;
    offset += 2U;  /* length placeholder (0x81 NN) */
    size_t nmp_start = offset;

    /* Calling presentation selector [1] IMPLICIT OCTET STRING */
    if ((offset + 6U) > buf_size) { return -ENOSPC; }
    buf[offset] = 0x81; offset++;  /* [1] IMPLICIT */
    buf[offset] = 0x04; offset++;  /* length 4 */
    buf[offset] = 0x00; offset++; buf[offset] = 0x00; offset++;
    buf[offset] = 0x00; offset++; buf[offset] = 0x01; offset++;  /* P-selector = 1 */

    /* Called presentation selector [2] IMPLICIT OCTET STRING */
    if ((offset + 6U) > buf_size) { return -ENOSPC; }
    buf[offset] = 0x82; offset++;  /* [2] IMPLICIT */
    buf[offset] = 0x04; offset++;  /* length 4 */
    buf[offset] = 0x00; offset++; buf[offset] = 0x00; offset++;
    buf[offset] = 0x00; offset++; buf[offset] = 0x01; offset++;  /* P-selector = 1 */

    /* Definition Context List [4] IMPLICIT SEQUENCE OF */
    if ((offset + 4U) > buf_size) { return -ENOSPC; }
    buf[offset] = 0xA4; offset++;  /* [4] CONSTRUCTED */
    size_t dcl_len_offset = offset;
    offset += 2U;  /* length placeholder */

    size_t dcl_start = offset;

    /* Context entry 1: ACSE (pcid=1) */
    if ((offset + 20U) > buf_size) { return -ENOSPC; }
    buf[offset] = 0x30; offset++;  /* SEQUENCE */
    buf[offset] = (uint8_t)(3U + 2U + (size_t)IEC61850_OID_ACSE_LEN +
                               2U + 2U + (size_t)IEC61850_OID_BER_LEN); offset++;
    buf[offset] = 0x02; offset++; buf[offset] = 0x01; offset++;
    buf[offset] = IEC61850_PCID_ACSE; offset++;  /* pcid = 1 */
    buf[offset] = 0x06; offset++;
    buf[offset] = (uint8_t)IEC61850_OID_ACSE_LEN; offset++;
    (void)memcpy(&buf[offset],IEC61850_OID_ACSE, (size_t)IEC61850_OID_ACSE_LEN);
    offset += (size_t)IEC61850_OID_ACSE_LEN;
    buf[offset] = 0x30; offset++;
    buf[offset] = (uint8_t)(2U + (size_t)IEC61850_OID_BER_LEN); offset++;
    buf[offset] = 0x06; offset++;
    buf[offset] = (uint8_t)IEC61850_OID_BER_LEN; offset++;
    (void)memcpy(&buf[offset],IEC61850_OID_BER, (size_t)IEC61850_OID_BER_LEN);
    offset += (size_t)IEC61850_OID_BER_LEN;

    /* Context entry 2: MMS (pcid=3) */
    if ((offset + 20U) > buf_size) { return -ENOSPC; }
    buf[offset] = 0x30; offset++;
    buf[offset] = (uint8_t)(3U + 2U + (size_t)IEC61850_OID_MMS_LEN +
                               2U + 2U + (size_t)IEC61850_OID_BER_LEN); offset++;
    buf[offset] = 0x02; offset++; buf[offset] = 0x01; offset++;
    buf[offset] = IEC61850_PCID_MMS; offset++;  /* pcid = 3 */
    buf[offset] = 0x06; offset++;
    buf[offset] = (uint8_t)IEC61850_OID_MMS_LEN; offset++;
    (void)memcpy(&buf[offset],IEC61850_OID_MMS, (size_t)IEC61850_OID_MMS_LEN);
    offset += (size_t)IEC61850_OID_MMS_LEN;
    buf[offset] = 0x30; offset++;
    buf[offset] = (uint8_t)(2U + (size_t)IEC61850_OID_BER_LEN); offset++;
    buf[offset] = 0x06; offset++;
    buf[offset] = (uint8_t)IEC61850_OID_BER_LEN; offset++;
    (void)memcpy(&buf[offset],IEC61850_OID_BER, (size_t)IEC61850_OID_BER_LEN);
    offset += (size_t)IEC61850_OID_BER_LEN;

    /* Update DCL length */
    size_t dcl_content_len = offset - dcl_start;
    buf[dcl_len_offset] = 0x81;
    buf[dcl_len_offset + 1U] = (uint8_t)dcl_content_len;

    /* User data: fully-encoded-data [APPLICATION 1] */
    /* Content: PDV-list SEQUENCE { pcid, [0] CONSTRUCTED { acse_pdu } } */
    size_t a0_len_sz = (acse_len < 128U) ? (size_t)1U
                       : ((acse_len < 256U) ? (size_t)2U : (size_t)3U);
    size_t a0_total = 1U + a0_len_sz + acse_len;
    size_t pdv_inner = 3U + a0_total;  /* pcid(3) + A0-wrapped data */
    size_t pdv_len_sz = (pdv_inner < 128U) ? (size_t)1U
                        : ((pdv_inner < 256U) ? (size_t)2U : (size_t)3U);
    size_t pdv_total = 1U + pdv_len_sz + pdv_inner;
    size_t fed_inner = pdv_total;

    if ((offset + 10U + acse_len) > buf_size) { return -ENOSPC; }
    buf[offset] = 0x61; offset++;  /* [APPLICATION 1] fully-encoded-data */
    int lret = ber_write_length(buf, buf_size, &offset, fed_inner);
    if (lret != 0) { return lret; }

    /* PDV-list: SEQUENCE */
    buf[offset] = 0x30; offset++;
    lret = ber_write_length(buf, buf_size, &offset, pdv_inner);
    if (lret != 0) { return lret; }
    buf[offset] = 0x02; offset++; buf[offset] = 0x01; offset++;
    buf[offset] = IEC61850_PCID_ACSE; offset++;

    /* Single-ASN1-type [0] CONSTRUCTED wrapper */
    buf[offset] = 0xA0; offset++;
    lret = ber_write_length(buf, buf_size, &offset, acse_len);
    if (lret != 0) { return lret; }
    (void)memcpy(&buf[offset],acse_pdu, acse_len);
    offset += acse_len;

    /* Update normal-mode-parameters [2] length */
    size_t nmp_content_len = offset - nmp_start;
    buf[nmp_len_offset] = 0x81;
    buf[nmp_len_offset + 1U] = (uint8_t)nmp_content_len;

    /* Update CP length */
    size_t cp_content_len = offset - cp_len_offset - 3U;
    buf[cp_len_offset] = 0x82;
    buf[cp_len_offset + 1U] = (uint8_t)(cp_content_len >> 8U);
    buf[cp_len_offset + 2U] = (uint8_t)(cp_content_len & 0xFFU);

    return (int)offset;
}

int iec61850_pres_encode_cpa(uint8_t *buf, size_t buf_size,
                               const uint8_t *acse_pdu, size_t acse_len)
{
    /*
     * CPA-PPDU ::= SET {
     *   mode-selector [0] IMPLICIT SET { [0] INTEGER = 1 },
     *   normal-mode-parameters [2] IMPLICIT SEQUENCE {
     *     responding-presentation-selector [3] IMPLICIT OCTET STRING,
     *     presentation-context-definition-result-list [5] IMPLICIT SEQUENCE OF {
     *       SEQUENCE { result [0] INTEGER = 0 (acceptance),
     *                  transfer-syntax-name [1] OID } },
     *     user-data [APPLICATION 1] fully-encoded-data
     *   }
     * }
     */
    size_t offset = 0;
    int lret;

    if ((buf == NULL) || (acse_pdu == NULL)) { return -EINVAL; }

    /* CPA SET tag (same as CP: 0x31) */
    if (offset >= buf_size) { return -ENOSPC; }
    buf[offset] = PRES_TAG_CPA; offset++;

    /* Reserve length (3 bytes for BER long form) */
    size_t cp_len_offset = offset;
    offset += 3U;

    /* Mode selector [0] IMPLICIT SET { [0] INTEGER = 1 (normal mode) } */
    if ((offset + 8U) > buf_size) { return -ENOSPC; }
    buf[offset] = 0xA0; offset++; buf[offset] = 0x03; offset++;
    buf[offset] = 0x80; offset++; buf[offset] = 0x01; offset++; buf[offset] = 0x01; offset++;

    /* Normal-mode-parameters [2] IMPLICIT SEQUENCE */
    if ((offset + 3U) > buf_size) { return -ENOSPC; }
    buf[offset] = 0xA2; offset++;
    size_t nmp_len_offset = offset;
    offset += 2U;  /* 0x81 NN placeholder */
    size_t nmp_start = offset;

    /* Responding presentation selector [3] IMPLICIT OCTET STRING */
    if ((offset + 6U) > buf_size) { return -ENOSPC; }
    buf[offset] = 0x83; offset++; buf[offset] = 0x04; offset++;
    buf[offset] = 0x00; offset++; buf[offset] = 0x00; offset++;
    buf[offset] = 0x00; offset++; buf[offset] = 0x01; offset++;

    /* Presentation context definition result list [5] IMPLICIT SEQUENCE OF */
    if ((offset + 4U) > buf_size) { return -ENOSPC; }
    buf[offset] = 0xA5; offset++;
    size_t rl_len_offset = offset;
    offset++;  /* length placeholder (short form) */
    size_t rl_start = offset;

    /* Result entry 1: ACSE context accepted */
    if ((offset + 12U) > buf_size) { return -ENOSPC; }
    buf[offset] = 0x30; offset++;  /* SEQUENCE */
    buf[offset] = (uint8_t)(3U + 2U + (size_t)IEC61850_OID_BER_LEN); offset++;
    buf[offset] = 0x80; offset++; buf[offset] = 0x01; offset++; buf[offset] = 0x00; offset++;  /* result = acceptance */
    buf[offset] = 0x81; offset++; buf[offset] = (uint8_t)IEC61850_OID_BER_LEN; offset++;
    (void)memcpy(&buf[offset],IEC61850_OID_BER, IEC61850_OID_BER_LEN);
    offset += (size_t)IEC61850_OID_BER_LEN;

    /* Result entry 2: MMS context accepted */
    if ((offset + 12U) > buf_size) { return -ENOSPC; }
    buf[offset] = 0x30; offset++;
    buf[offset] = (uint8_t)(3U + 2U + (size_t)IEC61850_OID_BER_LEN); offset++;
    buf[offset] = 0x80; offset++; buf[offset] = 0x01; offset++; buf[offset] = 0x00; offset++;
    buf[offset] = 0x81; offset++; buf[offset] = (uint8_t)IEC61850_OID_BER_LEN; offset++;
    (void)memcpy(&buf[offset],IEC61850_OID_BER, IEC61850_OID_BER_LEN);
    offset += (size_t)IEC61850_OID_BER_LEN;

    /* Update result list length */
    buf[rl_len_offset] = (uint8_t)(offset - rl_start);

    /* User data: fully-encoded-data [APPLICATION 1] */
    size_t a0_len_sz = (acse_len < 128U) ? (size_t)1U
                       : ((acse_len < 256U) ? (size_t)2U : (size_t)3U);
    size_t a0_total = 1U + a0_len_sz + acse_len;
    size_t pdv_inner = 3U + a0_total;
    size_t pdv_len_sz = (pdv_inner < 128U) ? (size_t)1U
                        : ((pdv_inner < 256U) ? (size_t)2U : (size_t)3U);
    size_t pdv_total = 1U + pdv_len_sz + pdv_inner;

    if ((offset + 10U + acse_len) > buf_size) { return -ENOSPC; }
    buf[offset] = 0x61; offset++;  /* [APPLICATION 1] */
    lret = ber_write_length(buf, buf_size, &offset, pdv_total);
    if (lret != 0) { return lret; }

    buf[offset] = 0x30; offset++;  /* PDV-list SEQUENCE */
    lret = ber_write_length(buf, buf_size, &offset, pdv_inner);
    if (lret != 0) { return lret; }
    buf[offset] = 0x02; offset++; buf[offset] = 0x01; offset++;
    buf[offset] = IEC61850_PCID_ACSE; offset++;

    buf[offset] = 0xA0; offset++;  /* single-ASN1-type [0] */
    lret = ber_write_length(buf, buf_size, &offset, acse_len);
    if (lret != 0) { return lret; }
    (void)memcpy(&buf[offset],acse_pdu, acse_len);
    offset += acse_len;

    /* Update normal-mode-parameters length */
    size_t nmp_content_len = offset - nmp_start;
    buf[nmp_len_offset] = 0x81;
    buf[nmp_len_offset + 1U] = (uint8_t)nmp_content_len;

    /* Update CPA outer length */
    size_t cp_content_len = offset - cp_len_offset - 3U;
    buf[cp_len_offset] = 0x82;
    buf[cp_len_offset + 1U] = (uint8_t)(cp_content_len >> 8U);
    buf[cp_len_offset + 2U] = (uint8_t)(cp_content_len & 0xFFU);

    return (int)offset;
}

int iec61850_pres_encode_pdata(uint8_t *buf, size_t buf_size, /* NOLINT(bugprone-easily-swappable-parameters) */
                                 uint8_t pcid,
                                 const uint8_t *app_pdu, size_t app_len)
{
    size_t offset = 0;
    int ret;

    if ((buf == NULL) || (app_pdu == NULL)) { return -EINVAL; }

    /* Calculate sizes with A0 wrapper */
    size_t a0_len_size = (app_len < 128U) ? 1U : ((app_len < 256U) ? 2U : 3U);
    size_t a0_total = 1U + a0_len_size + app_len;  /* 0xA0 + len + data */
    size_t pdv_inner = 3U + a0_total;  /* pcid(3) + A0-wrapped data */

    /* Fully-encoded-data [APPLICATION 1] */
    if (offset >= buf_size) { return -ENOSPC; }
    buf[offset] = 0x61; offset++;

    /* Length of PDV-list SEQUENCE */
    size_t seq_len_size = (pdv_inner < 128U) ? 1U : ((pdv_inner < 256U) ? 2U : 3U);
    size_t fed_inner = 1U + seq_len_size + pdv_inner;
    ret = ber_write_length(buf, buf_size, &offset, fed_inner);
    if (ret != 0) { return ret; }

    /* PDV-list: SEQUENCE */
    buf[offset] = 0x30; offset++;
    ret = ber_write_length(buf, buf_size, &offset, pdv_inner);
    if (ret != 0) { return ret; }

    /* Context ID */
    buf[offset] = 0x02; offset++;
    buf[offset] = 0x01; offset++;
    buf[offset] = pcid; offset++;

    /* Single-ASN1-type [0] CONSTRUCTED wrapper */
    buf[offset] = 0xA0; offset++;
    ret = ber_write_length(buf, buf_size, &offset, app_len);
    if (ret != 0) { return ret; }
    (void)memcpy(&buf[offset],app_pdu, app_len);
    offset += app_len;

    return (int)offset;
}

int iec61850_pres_decode(const uint8_t *buf, size_t buf_len,
                           uint8_t *pcid,
                           const uint8_t **app_pdu, size_t *app_len)
{
    size_t offset = 0;
    size_t outer_len;
    size_t seq_len;
    int ret;

    if ((buf == NULL) || (pcid == NULL) || (app_pdu == NULL) || (app_len == NULL)) {
        return -EINVAL;
    }

    *pcid = 0;
    *app_pdu = NULL;
    *app_len = 0;

    if (buf_len < 4U) { return -EBADMSG; }

    /* Skip outer tag (CP/CPA or fully-encoded-data) */
    uint8_t outer_tag = buf[offset]; offset++;
    (void)outer_tag;

    ret = ber_read_length(buf, buf_len, &offset, &outer_len);
    if (ret != 0) { return ret; }

    /* Find the PDV-list SEQUENCE containing pcid + application data.
     *
     * The PDV-list is inside the user-data field, which may be:
     * - Direct: outer tag is 0x61 (fully-encoded-data / P-DATA)
     * - Nested: outer tag is 0x31 (CP/CPA SET), PDV-list is inside
     *   a fully-encoded-data [APPLICATION 1] (0x61) element.
     *
     * Strategy: scan top-level elements. If we find 0x61 (fully-
     * encoded-data), descend into it. If we find 0x30 (SEQUENCE
     * with pcid), extract the data directly. Skip everything else
     * (mode-selector 0xA0, context-list 0xA4, etc.). */
    size_t scan_end = offset + outer_len;
    if (scan_end > buf_len) { scan_end = buf_len; }

    while (offset < scan_end) {
        uint8_t tag = buf[offset];

        if (tag == 0xA2U) {
            /* normal-mode-parameters [2] — descend into it */
            offset++;
            size_t nmp_len;
            ret = ber_read_length(buf, buf_len, &offset, &nmp_len);
            if (ret != 0) { return ret; }
            scan_end = offset + nmp_len;
            if (scan_end > buf_len) { scan_end = buf_len; }
            continue;
        }

        if (tag == 0x61U) {
            /* fully-encoded-data [APPLICATION 1] — descend into it */
            offset++;
            size_t fed_len;
            ret = ber_read_length(buf, buf_len, &offset, &fed_len);
            if (ret != 0) { return ret; }
            /* Continue scanning inside the fully-encoded-data */
            scan_end = offset + fed_len;
            if (scan_end > buf_len) { scan_end = buf_len; }
            continue;
        }

        if (tag == 0x30U) {
            /* SEQUENCE — check if it's a PDV-list with pcid */
            size_t seq_start = offset;
            offset++;
            ret = ber_read_length(buf, buf_len, &offset, &seq_len);
            if (ret != 0) { return ret; }
            (void)seq_start;

            size_t seq_end = offset + seq_len;
            if (seq_end > buf_len) { return -EBADMSG; }

            /* Read pcid: INTEGER */
            if (((offset + 3U) <= seq_end) && (buf[offset] == 0x02U) &&
                (buf[offset + 1U] == 0x01U)) {
                *pcid = buf[offset + 2U];
                offset += 3U;

                /* Strip [0] CONSTRUCTED wrapper (0xA0) if present */
                if ((offset < seq_end) && (buf[offset] == 0xA0U)) {
                    offset++;
                    size_t a0_len;
                    ret = ber_read_length(buf, buf_len, &offset, &a0_len);
                    if (ret != 0) { return ret; }
                    /* Wire-declared length must stay inside the PDV-list
                     * (and therefore inside the input buffer) */
                    if ((offset + a0_len) > seq_end) { return -EBADMSG; }
                    *app_pdu = &buf[offset];
                    *app_len = a0_len;
                } else {
                    *app_pdu = &buf[offset];
                    *app_len = seq_end - offset;
                }
                return 0;
            }
            /* Not a PDV-list — skip past it */
            offset = seq_end;
            continue;
        }

        /* Skip any other element (mode-selector A0, context-list A4, etc.) */
        offset++;
        if (offset < scan_end) {
            size_t skip_len;
            ret = ber_read_length(buf, buf_len, &offset, &skip_len);
            if (ret != 0) { return ret; }
            offset += skip_len;
        }
    }

    return -EBADMSG;
}

/* ========================================================================
 * ACSE (ISO 8650)
 * ======================================================================== */

/* IEC 61850 AP-title OID: 1.1.9506.1 = {29 01 87 67 01} */
static const uint8_t IEC61850_AP_TITLE_OID[] = {0x29, 0x01, 0x87, 0x67, 0x01};
/* AE-qualifier for MMS: 12 */
#define IEC61850_AE_QUALIFIER 12

void iec61850_acse_params_init(iec61850_acse_params_t *params)
{
    if (params != NULL) {
        (void)memset(params, 0, sizeof(*params));

        /* Default MMS application context */
        (void)memcpy(params->app_context_oid, MMS_APP_CONTEXT_OID,
                     sizeof(MMS_APP_CONTEXT_OID));
        params->app_context_oid_len = sizeof(MMS_APP_CONTEXT_OID);

        /* Default AP-titles and AE-qualifiers per IEC 61850-8-1 */
        (void)memcpy(params->called_ap_title, IEC61850_AP_TITLE_OID,
                     sizeof(IEC61850_AP_TITLE_OID));
        params->called_ap_title_len = sizeof(IEC61850_AP_TITLE_OID);
        (void)memcpy(params->calling_ap_title, IEC61850_AP_TITLE_OID,
                     sizeof(IEC61850_AP_TITLE_OID));
        params->calling_ap_title_len = sizeof(IEC61850_AP_TITLE_OID);
        params->called_ae_qualifier = IEC61850_AE_QUALIFIER;
        params->calling_ae_qualifier = IEC61850_AE_QUALIFIER;
    }
}

int iec61850_acse_encode_aarq(uint8_t *buf, size_t buf_size,
                                const iec61850_acse_params_t *params,
                                const uint8_t *app_pdu, size_t app_len)
{
    size_t offset = 0;
    int ret;

    if ((buf == NULL) || (params == NULL)) { return -EINVAL; }

    /* AARQ tag [APPLICATION 0] CONSTRUCTED */
    buf[offset] = IEC61850_ACSE_TAG_AARQ; offset++;

    /* Length placeholder */
    size_t len_offset = offset;
    offset += 3U;

    /* Application Context Name [1] */
    if (params->app_context_oid_len > 0U) {
        buf[offset] = 0xA1; offset++;  /* [1] CONSTRUCTED */
        buf[offset] = (uint8_t)(2U + params->app_context_oid_len); offset++;
        buf[offset] = 0x06; offset++;  /* OBJECT IDENTIFIER */
        buf[offset] = (uint8_t)params->app_context_oid_len; offset++;
        (void)memcpy(&buf[offset],params->app_context_oid,
                     params->app_context_oid_len);
        offset += params->app_context_oid_len;
    }

    /* Called AP Title [2] — wraps an OID */
    if (params->called_ap_title_len > 0U) {
        buf[offset] = 0xA2; offset++;
        buf[offset] = (uint8_t)(2U + params->called_ap_title_len); offset++;
        buf[offset] = 0x06; offset++;  /* OID tag */
        buf[offset] = (uint8_t)(params->called_ap_title_len); offset++;
        (void)memcpy(&buf[offset],params->called_ap_title,
                     params->called_ap_title_len);
        offset += params->called_ap_title_len;
    }

    /* Called AE Qualifier [3] — wraps an INTEGER */
    if (params->called_ae_qualifier >= 0) {
        buf[offset] = 0xA3; offset++;
        buf[offset] = 0x03; offset++;
        buf[offset] = 0x02; offset++;  /* INTEGER tag */
        buf[offset] = 0x01; offset++;
        buf[offset] = (uint8_t)params->called_ae_qualifier; offset++;
    }

    /* Calling AP Title [6] — wraps an OID */
    if (params->calling_ap_title_len > 0U) {
        buf[offset] = 0xA6; offset++;
        buf[offset] = (uint8_t)(2U + params->calling_ap_title_len); offset++;
        buf[offset] = 0x06; offset++;  /* OID tag */
        buf[offset] = (uint8_t)(params->calling_ap_title_len); offset++;
        (void)memcpy(&buf[offset],params->calling_ap_title,
                     params->calling_ap_title_len);
        offset += params->calling_ap_title_len;
    }

    /* Calling AE Qualifier [7] — wraps an INTEGER */
    if (params->calling_ae_qualifier >= 0) {
        buf[offset] = 0xA7; offset++;
        buf[offset] = 0x03; offset++;
        buf[offset] = 0x02; offset++;  /* INTEGER tag */
        buf[offset] = 0x01; offset++;
        buf[offset] = (uint8_t)params->calling_ae_qualifier; offset++;
    }

    /* User Information [30] — contains the MMS InitiateRequest
     * Wrapped in EXTERNAL { direct-reference INTEGER, encoding [0] } */
    if ((app_pdu != NULL) && (app_len > 0U)) {
        /* EXTERNAL inner: direct-ref(3) + encoding [0](2+app_len) */
        /* Adjust for BER length encoding of app_len */
        size_t app_len_sz = (app_len < 128U) ? (size_t)1U
                            : ((app_len < 256U) ? (size_t)2U : (size_t)3U);
        size_t a0_total = 1U + app_len_sz + app_len;
        size_t ext_inner = 3U + a0_total;

        size_t ext_len_sz = (ext_inner < 128U) ? (size_t)1U
                            : ((ext_inner < 256U) ? (size_t)2U : (size_t)3U);
        size_t be_inner = 1U + ext_len_sz + ext_inner;

        buf[offset] = 0xBE; offset++;  /* [30] CONSTRUCTED */
        ret = ber_write_length(buf, buf_size, &offset, be_inner);
        if (ret != 0) { return ret; }

        /* EXTERNAL [8] IMPLICIT SEQUENCE */
        buf[offset] = 0x28; offset++;  /* [8] CONSTRUCTED */
        ret = ber_write_length(buf, buf_size, &offset, ext_inner);
        if (ret != 0) { return ret; }

        /* direct-reference: INTEGER pcid=3 (MMS context) */
        buf[offset] = 0x02; offset++;
        buf[offset] = 0x01; offset++;
        buf[offset] = IEC61850_PCID_MMS; offset++;

        /* encoding [0] single-ASN1-type */
        buf[offset] = 0xA0; offset++;
        ret = ber_write_length(buf, buf_size, &offset, app_len);
        if (ret != 0) { return ret; }

        (void)memcpy(&buf[offset],app_pdu, app_len);
        offset += app_len;
    }

    /* Update AARQ length */
    size_t content_len = offset - len_offset - 3U;
    buf[len_offset] = 0x82;
    buf[len_offset + 1U] = (uint8_t)(content_len >> 8U);
    buf[len_offset + 2U] = (uint8_t)(content_len & 0xFFU);

    return (int)offset;
}

int iec61850_acse_encode_aare(uint8_t *buf, size_t buf_size,
                                const iec61850_acse_params_t *params,
                                iec61850_aare_result_t result,
                                const uint8_t *app_pdu, size_t app_len)
{
    size_t offset = 0;
    int ret;

    if ((buf == NULL) || (params == NULL)) { return -EINVAL; }

    buf[offset] = IEC61850_ACSE_TAG_AARE; offset++;
    size_t len_offset = offset;
    offset += 3U;

    /* Application Context Name [1] */
    if (params->app_context_oid_len > 0U) {
        buf[offset] = 0xA1; offset++;
        buf[offset] = (uint8_t)(2U + params->app_context_oid_len); offset++;
        buf[offset] = 0x06; offset++;
        buf[offset] = (uint8_t)params->app_context_oid_len; offset++;
        (void)memcpy(&buf[offset],params->app_context_oid,
                     params->app_context_oid_len);
        offset += params->app_context_oid_len;
    }

    /* Result [2] */
    buf[offset] = 0xA2; offset++;
    buf[offset] = 0x03; offset++;
    buf[offset] = 0x02; offset++;  /* INTEGER */
    buf[offset] = 0x01; offset++;
    buf[offset] = (uint8_t)result; offset++;

    /* Result Source Diagnostic [3] */
    buf[offset] = 0xA3; offset++;
    buf[offset] = 0x05; offset++;
    buf[offset] = 0xA1; offset++;  /* [1] acse-service-user */
    buf[offset] = 0x03; offset++;
    buf[offset] = 0x02; offset++;
    buf[offset] = 0x01; offset++;
    buf[offset] = 0x00; offset++;  /* null (no diagnostic) */

    /* User Information [30] IMPLICIT SEQUENCE OF EXTERNAL */
    if ((app_pdu != NULL) && (app_len > 0U)) {
        /* EXTERNAL { indirect-reference INTEGER, encoding [0] } */
        size_t ext_content = 3U + 2U + app_len;  /* indirect-ref(3) + A0+len + data */
        size_t ext_len_sz = (ext_content < 128U) ? (size_t)1U : (size_t)2U;
        size_t be_content = 1U + ext_len_sz + ext_content;  /* 0x28 + len + content */

        buf[offset] = 0xBE; offset++;
        ret = ber_write_length(buf, buf_size, &offset, be_content);
        if (ret != 0) { return ret; }

        buf[offset] = 0x28; offset++;  /* EXTERNAL (UNIVERSAL 8 CONSTRUCTED) */
        ret = ber_write_length(buf, buf_size, &offset, ext_content);
        if (ret != 0) { return ret; }

        /* indirect-reference INTEGER = 3 (MMS context) */
        buf[offset] = 0x02; offset++;
        buf[offset] = 0x01; offset++;
        buf[offset] = IEC61850_PCID_MMS; offset++;

        /* encoding: single-ASN1-type [0] */
        buf[offset] = 0xA0; offset++;
        ret = ber_write_length(buf, buf_size, &offset, app_len);
        if (ret != 0) { return ret; }

        (void)memcpy(&buf[offset],app_pdu, app_len);
        offset += app_len;
    }

    size_t content_len = offset - len_offset - 3U;
    buf[len_offset] = 0x82;
    buf[len_offset + 1U] = (uint8_t)(content_len >> 8U);
    buf[len_offset + 2U] = (uint8_t)(content_len & 0xFFU);

    return (int)offset;
}

int iec61850_acse_encode_rlrq(uint8_t *buf, size_t buf_size)
{
    if ((buf == NULL) || (buf_size < 4U)) { return -EINVAL; }

    buf[0] = IEC61850_ACSE_TAG_RLRQ;
    buf[1] = 0x02;
    /* Reason [0] = normal (0) */
    buf[2] = 0x80;
    buf[3] = 0x00;
    return 4;
}

int iec61850_acse_encode_rlre(uint8_t *buf, size_t buf_size)
{
    if ((buf == NULL) || (buf_size < 2U)) { return -EINVAL; }

    buf[0] = IEC61850_ACSE_TAG_RLRE;
    buf[1] = 0x00;
    return 2;
}

int iec61850_acse_decode(const uint8_t *buf, size_t buf_len,
                           uint8_t *tag,
                           iec61850_acse_params_t *params,
                           iec61850_aare_result_t *result,
                           const uint8_t **app_pdu, size_t *app_len)
{
    size_t offset = 0;
    size_t total_len;
    size_t end;
    int ret;

    if ((buf == NULL) || (tag == NULL)) { return -EINVAL; }
    if (buf_len < 2U) { return -EBADMSG; }

    *tag = buf[offset]; offset++;
    ret = ber_read_length(buf, buf_len, &offset, &total_len);
    if (ret != 0) { return ret; }

    end = offset + total_len;
    if (end > buf_len) { return -EBADMSG; }

    if (params != NULL) {
        iec61850_acse_params_init(params);
    }
    if (result != NULL) {
        *result = IEC61850_AARE_ACCEPTED;
    }
    if (app_pdu != NULL) { *app_pdu = NULL; }
    if (app_len != NULL) { *app_len = 0; }

    /* Parse ACSE elements */
    while (offset < end) {
        uint8_t elem_tag = buf[offset]; offset++;
        size_t elem_len;
        ret = ber_read_length(buf, buf_len, &offset, &elem_len);
        if (ret != 0) { return ret; }

        size_t elem_end = offset + elem_len;
        if (elem_end > end) { return -EBADMSG; }

        switch (elem_tag) {
            case 0xA1:  /* Application Context Name [1] */
                if ((params != NULL) && (elem_len > 2U) && (buf[offset] == 0x06U)) {
                    size_t oid_len = buf[offset + 1U];
                    if ((oid_len <= (size_t)IEC61850_ISO_MAX_OID) && ((offset + 2U + oid_len) <= elem_end)) {
                        (void)memcpy(params->app_context_oid, &buf[offset + 2U], oid_len);
                        params->app_context_oid_len = oid_len;
                    }
                }
                break;

            case 0xA2:  /* Result [2] (AARE only) */
                if ((result != NULL) && (elem_len >= 3U) && (buf[offset] == 0x02U) &&
                    (buf[offset + 1U] == 0x01U)) {
                    *result = (iec61850_aare_result_t)buf[offset + 2U];
                }
                break;

            case 0xBE:  /* User Information [30] */
                if ((app_pdu != NULL) && (app_len != NULL)) {
                    /* Dig into EXTERNAL { direct-reference, encoding [0] } */
                    size_t inner = offset;
                    if ((inner < elem_end) && (buf[inner] == 0x28U)) {
                        inner++;
                        size_t ext_len;
                        ret = ber_read_length(buf, buf_len, &inner, &ext_len);
                        if (ret != 0) break;
                        size_t ext_end = inner + ext_len;
                        if (ext_end > elem_end) break;

                        /* Skip optional direct-reference (INTEGER) */
                        if ((inner < ext_end) && (buf[inner] == 0x02U)) {
                            inner++;
                            size_t dr_len;
                            ret = ber_read_length(buf, buf_len, &inner, &dr_len);
                            if (ret != 0) break;
                            inner += dr_len;
                        }

                        /* encoding [0] single-ASN1-type */
                        if ((inner < ext_end) && (buf[inner] == 0xA0U)) {
                            inner++;
                            size_t enc_len;
                            ret = ber_read_length(buf, buf_len, &inner, &enc_len);
                            if ((ret == 0) && ((inner + enc_len) <= ext_end)) {
                                *app_pdu = &buf[inner];
                                *app_len = enc_len;
                            }
                        }
                    }
                }
                break;

            default:
                break;
        }

        offset = elem_end;
    }

    return 0;
}

/* ========================================================================
 * ISO Connection — Composite Stack
 * ======================================================================== */

void iec61850_iso_conn_init(iec61850_iso_conn_t *conn)
{
    if (conn == NULL) { return; }

    iec61850_tcp_conn_init(&conn->tcp);
#ifdef IEC61850_SECURITY_ENABLED
    iec61850_tls_conn_init(&conn->tls);
#else
    /* No TLS implementation is linked; keep the embedded member in
     * a defined (unconnected) state without referencing it. */
    (void)memset(&conn->tls, 0, sizeof(conn->tls));
    conn->tls.tcp.sockfd = -1;
#endif
    conn->use_tls = false;
    iec61850_session_params_init(&conn->session_params);
    iec61850_acse_params_init(&conn->acse_params);
    conn->state = IEC61850_ISO_STATE_IDLE;
    conn->max_pdu_size = IEC61850_ISO_MAX_PDU;
}

/*
 * Client-side ISO negotiation after the transport is established
 * (plain TCP or TLS): COTP CR/CC, then Session CONNECT +
 * Presentation CP + ACSE AARQ carrying the MMS InitiateRequest,
 * and the AARE acceptance check.
 */
static int iso_connect_negotiate(iec61850_iso_conn_t *conn,
                                   const uint8_t *mms_init,
                                   size_t mms_init_len, int timeout_ms)
{
    uint8_t acse_buf[4096];
    uint8_t pres_buf[4096];
    uint8_t sess_buf[4096];
    uint8_t tpkt_buf[4096];
    uint8_t recv_buf[4096];
    int ret;

    /* COTP CR/CC handshake */
    ret = cotp_negotiate(conn, timeout_ms);
    if (ret != 0) { goto fail; }

    /* Build AARQ with MMS InitiateRequest */
    ret = iec61850_acse_encode_aarq(acse_buf, sizeof(acse_buf),
                                      &conn->acse_params,
                                      mms_init, mms_init_len);
    if (ret < 0) { goto fail; }
    size_t acse_len = (size_t)ret;

    /* Wrap in Presentation CP */
    ret = iec61850_pres_encode_cp(pres_buf, sizeof(pres_buf),
                                    acse_buf, acse_len);
    if (ret < 0) { goto fail; }
    size_t pres_len = (size_t)ret;

    /* Wrap in Session CONNECT */
    ret = iec61850_session_encode_connect(sess_buf, sizeof(sess_buf),
                                            &conn->session_params,
                                            pres_buf, pres_len);
    if (ret < 0) { goto fail; }
    size_t sess_len = (size_t)ret;

    /* Wrap in TPKT */
    ret = iec61850_tpkt_encode(tpkt_buf, sizeof(tpkt_buf),
                                 sess_buf, sess_len);
    if (ret < 0) { goto fail; }
    size_t tpkt_len = (size_t)ret;

    /* Send */
    ret = iso_conn_send(conn, tpkt_buf, tpkt_len);
    if (ret < 0) { goto fail; }

    /* Receive complete TPKT response (handles fragmented reads) */
    ret = iso_conn_recv_tpkt(conn, recv_buf, sizeof(recv_buf),
                               timeout_ms);
    if (ret < 0) { goto fail; }
    size_t recv_len = (size_t)ret;

    /* Decode TPKT */
    const uint8_t *tpkt_payload;
    size_t tpkt_payload_len;
    ret = iec61850_tpkt_decode(recv_buf, recv_len,
                                 &tpkt_payload, &tpkt_payload_len);
    if (ret != 0) { goto fail; }

    /* Decode Session */
    uint8_t si_type;
    const uint8_t *sess_user_data;
    size_t sess_user_data_len;
    ret = iec61850_session_decode(tpkt_payload, tpkt_payload_len,
                                    &si_type, &conn->session_params,
                                    &sess_user_data, &sess_user_data_len);
    if ((ret != 0) || (si_type != IEC61850_SI_ACCEPT)) { goto fail; }

    /* Decode Presentation */
    uint8_t pres_pcid;
    const uint8_t *pres_app;
    size_t pres_app_len;
    ret = iec61850_pres_decode(sess_user_data, sess_user_data_len,
                                 &pres_pcid, &pres_app, &pres_app_len);
    if (ret != 0) { goto fail; }

    /* Decode ACSE AARE */
    uint8_t acse_tag;
    iec61850_aare_result_t aare_result;
    const uint8_t *aare_app;
    size_t aare_app_len;
    ret = iec61850_acse_decode(pres_app, pres_app_len, &acse_tag,
                                 &conn->acse_params, &aare_result,
                                 &aare_app, &aare_app_len);
    if ((ret != 0) || (acse_tag != IEC61850_ACSE_TAG_AARE) ||
        (aare_result != IEC61850_AARE_ACCEPTED)) {
        goto fail;
    }

    conn->state = IEC61850_ISO_STATE_CONNECTED;
    return 0;

fail:
    iso_conn_transport_disconnect(conn);
    conn->state = IEC61850_ISO_STATE_CLOSED;
    return -ECONNREFUSED;
}

int iec61850_iso_connect(iec61850_iso_conn_t *conn, const char *host,
                           uint16_t port, const uint8_t *mms_init,
                           size_t mms_init_len, int timeout_ms) /* NOLINT(bugprone-easily-swappable-parameters) */
{
    int ret;

    if ((conn == NULL) || (host == NULL)) { return -EINVAL; }

    conn->state = IEC61850_ISO_STATE_CONNECTING;

    /* TCP connect */
    ret = iec61850_tcp_connect(&conn->tcp, host, port, timeout_ms);
    if (ret != 0) {
        conn->state = IEC61850_ISO_STATE_CLOSED;
        return ret;
    }

    return iso_connect_negotiate(conn, mms_init, mms_init_len,
                                  timeout_ms);
}

int iec61850_iso_connect_tls(iec61850_iso_conn_t *conn, const char *host,
                               uint16_t port, const uint8_t *mms_init,
                               size_t mms_init_len, int timeout_ms,
                               const iec61850_cert_provider_t *provider,
                               iec61850_tls_mode_t mode)
{
#ifdef IEC61850_SECURITY_ENABLED
    int ret;

    if ((conn == NULL) || (host == NULL)) { return -EINVAL; }

    conn->state = IEC61850_ISO_STATE_CONNECTING;

    /* TLS connect + handshake (IEC 62351-4). Credentials are read
     * here; a later provider refresh() applies to new associations
     * only. */
    ret = iec61850_tls_connect(&conn->tls, host, port, timeout_ms,
                                 provider, mode);
    if (ret != 0) {
        conn->state = IEC61850_ISO_STATE_CLOSED;
        return ret;
    }
    conn->use_tls = true;

    return iso_connect_negotiate(conn, mms_init, mms_init_len,
                                  timeout_ms);
#else
    (void)conn;
    (void)host;
    (void)port;
    (void)mms_init;
    (void)mms_init_len;
    (void)timeout_ms;
    (void)provider;
    (void)mode;
    return -ENOTSUP;
#endif
}

int iec61850_iso_accept(iec61850_iso_conn_t *conn,
                          const uint8_t *mms_resp, size_t mms_resp_len,
                          uint8_t *mms_req, size_t *mms_req_len,
                          int timeout_ms)
{
    uint8_t recv_buf[4096];
    uint8_t acse_buf[4096];
    uint8_t pres_buf[4096];
    uint8_t sess_buf[4096];
    uint8_t tpkt_buf[4096];
    int ret;

    if (conn == NULL) { return -EINVAL; }

    /* COTP CR/CC handshake (server side) */
    ret = cotp_accept(conn, timeout_ms);
    if (ret != 0) { return ret; }

    /* Read incoming Session CONNECT (complete TPKT frame) */
    ret = iso_conn_recv_tpkt(conn, recv_buf, sizeof(recv_buf),
                               timeout_ms);
    if (ret < 0) { return ret; }
    size_t recv_len = (size_t)ret;

    /* Decode TPKT → Session → Presentation → ACSE */
    const uint8_t *tpkt_payload;
    size_t tpkt_payload_len;
    ret = iec61850_tpkt_decode(recv_buf, recv_len,
                                 &tpkt_payload, &tpkt_payload_len);
    if (ret != 0) { return ret; }

    uint8_t si_type;
    const uint8_t *sess_data;
    size_t sess_data_len;
    ret = iec61850_session_decode(tpkt_payload, tpkt_payload_len,
                                    &si_type, &conn->session_params,
                                    &sess_data, &sess_data_len);
    if ((ret != 0) || (si_type != IEC61850_SI_CONNECT)) { return -EPROTO; }

    uint8_t pres_pcid;
    const uint8_t *pres_data;
    size_t pres_data_len;
    ret = iec61850_pres_decode(sess_data, sess_data_len,
                                 &pres_pcid, &pres_data, &pres_data_len);
    if (ret != 0) { return ret; }

    uint8_t acse_tag;
    iec61850_aare_result_t aare_result;
    const uint8_t *app_data;
    size_t app_data_len;
    ret = iec61850_acse_decode(pres_data, pres_data_len, &acse_tag,
                                 &conn->acse_params, &aare_result,
                                 &app_data, &app_data_len);
    if ((ret != 0) || (acse_tag != IEC61850_ACSE_TAG_AARQ)) { return -EPROTO; }

    /* Copy MMS InitiateRequest to caller */
    if ((mms_req != NULL) && (mms_req_len != NULL) && (app_data != NULL)) {
        if (app_data_len > *mms_req_len) { return -ENOSPC; }
        (void)memcpy(mms_req, app_data, app_data_len);
        *mms_req_len = app_data_len;
    }

    /* Build AARE with MMS InitiateResponse */
    ret = iec61850_acse_encode_aare(acse_buf, sizeof(acse_buf),
                                      &conn->acse_params,
                                      IEC61850_AARE_ACCEPTED,
                                      mms_resp, mms_resp_len);
    if (ret < 0) { return ret; }
    size_t acse_len = (size_t)ret;

    ret = iec61850_pres_encode_cpa(pres_buf, sizeof(pres_buf),
                                     acse_buf, acse_len);
    if (ret < 0) { return ret; }
    size_t pres_len = (size_t)ret;

    /* ACCEPT only includes called SSEL, not calling */
    iec61850_session_params_t accept_params = conn->session_params;
    accept_params.calling_ssel_len = 0;
    ret = iec61850_session_encode_accept(sess_buf, sizeof(sess_buf),
                                           &accept_params,
                                           pres_buf, pres_len);
    if (ret < 0) { return ret; }
    size_t sess_len = (size_t)ret;

    ret = iec61850_tpkt_encode(tpkt_buf, sizeof(tpkt_buf),
                                 sess_buf, sess_len);
    if (ret < 0) { return ret; }

    ret = iso_conn_send(conn, tpkt_buf, (size_t)ret);
    if (ret < 0) { return ret; }

    conn->state = IEC61850_ISO_STATE_CONNECTED;
    return 0;
}

int iec61850_iso_send(iec61850_iso_conn_t *conn,
                        const uint8_t *data, size_t data_len)
{
    uint8_t pres_buf[IEC61850_ISO_MAX_PDU];
    uint8_t sess_buf[IEC61850_ISO_MAX_PDU];
    uint8_t tpkt_buf[IEC61850_ISO_MAX_PDU];
    int ret;

    if ((conn == NULL) || (data == NULL)) { return -EINVAL; }
    if (conn->state != IEC61850_ISO_STATE_CONNECTED) { return -ENOTCONN; }

    /* Wrap in Presentation P-DATA (MMS context = pcid 3) */
    ret = iec61850_pres_encode_pdata(pres_buf, sizeof(pres_buf),
                                       IEC61850_PCID_MMS, data, data_len);
    if (ret < 0) { return ret; }
    size_t pres_len = (size_t)ret;

    /* Wrap in Session DATA */
    ret = iec61850_session_encode_data(sess_buf, sizeof(sess_buf),
                                         pres_buf, pres_len);
    if (ret < 0) { return ret; }
    size_t sess_len = (size_t)ret;

    /* Wrap in TPKT */
    ret = iec61850_tpkt_encode(tpkt_buf, sizeof(tpkt_buf),
                                 sess_buf, sess_len);
    if (ret < 0) { return ret; }

    return iso_conn_send(conn, tpkt_buf, (size_t)ret);
}

int iec61850_iso_recv(iec61850_iso_conn_t *conn,
                        uint8_t *buf, size_t buf_size,
                        size_t *recv_len, int timeout_ms)
{
    uint8_t recv_buf[IEC61850_ISO_MAX_PDU];
    int ret;

    if ((conn == NULL) || (buf == NULL) || (recv_len == NULL)) { return -EINVAL; }
    if (conn->state != IEC61850_ISO_STATE_CONNECTED) { return -ENOTCONN; }

    *recv_len = 0;

    /* Read complete TPKT frame (handles fragmented reads) */
    ret = iso_conn_recv_tpkt(conn, recv_buf, sizeof(recv_buf),
                               timeout_ms);
    if (ret < 0) { return ret; }
    size_t raw_len = (size_t)ret;

    /* Decode TPKT */
    const uint8_t *tpkt_payload;
    size_t tpkt_payload_len;
    ret = iec61850_tpkt_decode(recv_buf, raw_len,
                                 &tpkt_payload, &tpkt_payload_len);
    if (ret != 0) { return ret; }

    /* Decode Session */
    uint8_t si_type;
    const uint8_t *sess_data;
    size_t sess_data_len;
    ret = iec61850_session_decode(tpkt_payload, tpkt_payload_len,
                                    &si_type, NULL,
                                    &sess_data, &sess_data_len);
    if (ret != 0) { return ret; }

    /* Handle FINISH (disconnect) */
    if (si_type == IEC61850_SI_FINISH) {
        conn->state = IEC61850_ISO_STATE_CLOSED;
        return IEC61850_TRANSPORT_ERR_CLOSED;
    }

    if (si_type != IEC61850_SI_DATA) { return -EPROTO; }

    /* Decode Presentation */
    uint8_t pcid;
    const uint8_t *app_data;
    size_t app_data_len;
    ret = iec61850_pres_decode(sess_data, sess_data_len,
                                 &pcid, &app_data, &app_data_len);
    if (ret != 0) { return ret; }

    /* Copy MMS PDU to caller */
    if (app_data_len > buf_size) { return -ENOSPC; }
    (void)memcpy(buf, app_data, app_data_len);
    *recv_len = app_data_len;

    return 0;
}

int iec61850_iso_disconnect(iec61850_iso_conn_t *conn)
{
    uint8_t acse_buf[64];
    uint8_t pres_buf[128];
    uint8_t sess_buf[256];
    uint8_t tpkt_buf[512];
    int ret;

    if (conn == NULL) { return -EINVAL; }

    if (conn->state == IEC61850_ISO_STATE_CONNECTED) {
        /* Encode RLRQ */
        ret = iec61850_acse_encode_rlrq(acse_buf, sizeof(acse_buf));
        if (ret > 0) {
            size_t acse_len = (size_t)ret;

            ret = iec61850_pres_encode_pdata(pres_buf, sizeof(pres_buf),
                                               IEC61850_PCID_ACSE,
                                               acse_buf, acse_len);
            if (ret > 0) {
                size_t pres_len = (size_t)ret;

                ret = iec61850_session_encode_finish(sess_buf, sizeof(sess_buf),
                                                       pres_buf, pres_len);
                if (ret > 0) {
                    size_t sess_len = (size_t)ret;

                    ret = iec61850_tpkt_encode(tpkt_buf, sizeof(tpkt_buf),
                                                 sess_buf, sess_len);
                    if (ret > 0) {
                        (void)iso_conn_send(conn, tpkt_buf,
                                             (size_t)ret);
                    }
                }
            }
        }

        conn->state = IEC61850_ISO_STATE_RELEASING;
    }

    iso_conn_transport_disconnect(conn);
    conn->state = IEC61850_ISO_STATE_CLOSED;
    return 0;
}
