/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * ISO Transport Stack Implementation
 *
 * TPKT (RFC 1006) + ISO Session (ISO 8327) + ISO Presentation (ISO 8823)
 * + ACSE (ISO 8650) composite stack for MMS transport.
 */

#define _POSIX_C_SOURCE 200809L

#include "transport/iso_stack.h"
#include <string.h>
#include <errno.h>

/* Well-known OIDs */
const uint8_t IEC61850_OID_ACSE[4] = {0x52, 0x01, 0x00, 0x01};  /* 2.2.1.0.1 */
const uint8_t IEC61850_OID_BER[3]  = {0x51, 0x01, 0x01};         /* 2.1.1 */
const uint8_t IEC61850_OID_MMS[5]  = {0x28, 0xCA, 0x22, 0x02, 0x01}; /* 1.0.9506.2.1 */

/* MMS Application Context OID (IEC 61850-8-1) */
static const uint8_t MMS_APP_CONTEXT_OID[] = {
    0x28, 0xCA, 0x22, 0x02, 0x03  /* 1.0.9506.2.3 */
};

/* ========================================================================
 * BER Length Helpers (used by all layers)
 * ======================================================================== */

static int ber_write_length(uint8_t *buf, size_t buf_size, size_t *offset,
                              size_t length)
{
    if (length < 128) {
        if (*offset >= buf_size) { return -ENOSPC; }
        buf[*offset] = (uint8_t)length;
        (*offset)++;
    } else if (length < 256) {
        if (*offset + 2 > buf_size) { return -ENOSPC; }
        buf[*offset] = 0x81;
        buf[*offset + 1] = (uint8_t)length;
        *offset += 2;
    } else {
        if (*offset + 3 > buf_size) { return -ENOSPC; }
        buf[*offset] = 0x82;
        buf[*offset + 1] = (uint8_t)(length >> 8);
        buf[*offset + 2] = (uint8_t)(length & 0xFF);
        *offset += 3;
    }
    return 0;
}

static int ber_read_length(const uint8_t *buf, size_t buf_len, size_t *offset,
                             size_t *length)
{
    if (*offset >= buf_len) { return -EBADMSG; }

    uint8_t first = buf[*offset];
    (*offset)++;

    if ((first & 0x80) == 0) {
        *length = first;
    } else {
        uint8_t num_bytes = first & 0x7F;
        if (num_bytes == 0 || num_bytes > 2) { return -EBADMSG; }
        if (*offset + num_bytes > buf_len) { return -EBADMSG; }

        *length = 0;
        for (uint8_t i = 0; i < num_bytes; i++) {
            *length = (*length << 8) | buf[*offset];
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
static int cotp_negotiate(iec61850_tcp_conn_t *tcp, int timeout_ms)
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

    ret = iec61850_tcp_send(tcp, cr_buf, sizeof(cr_buf));
    if (ret < 0) { return ret; }

    /* Receive CC */
    ret = iec61850_tcp_recv_tpkt(tcp, cc_buf, sizeof(cc_buf), timeout_ms);
    if (ret < 0) { return ret; }

    /* Validate: TPKT header + COTP CC (type 0xD0) */
    if (ret < 7) { return -EPROTO; }
    /* cc_buf[4] is LI, cc_buf[5] is type */
    if ((cc_buf[5] & 0xF0) != COTP_CC_TYPE) { return -EPROTO; }

    return 0;
}

/*
 * Receive COTP CR from client and send CC back.
 */
static int cotp_accept(iec61850_tcp_conn_t *tcp, int timeout_ms)
{
    uint8_t cr_buf[64];
    uint8_t cc_buf[22];
    int ret;

    /* Receive CR */
    ret = iec61850_tcp_recv_tpkt(tcp, cr_buf, sizeof(cr_buf), timeout_ms);
    if (ret < 0) { return ret; }

    if (ret < 7) { return -EPROTO; }
    if ((cr_buf[5] & 0xF0) != COTP_CR_TYPE) { return -EPROTO; }

    /* Extract client's SRC-REF (bytes 8-9 in the TPKT frame) */
    uint16_t client_src_ref = 0;
    if (ret >= 10) {
        client_src_ref = (uint16_t)((uint16_t)cr_buf[8] << 8) | cr_buf[9];
    }

    /* Build TPKT + CC TPDU with parameters */
    cc_buf[0] = 0x03;  /* TPKT version */
    cc_buf[1] = 0x00;
    cc_buf[2] = 0x00;
    cc_buf[3] = 0x16;  /* total length = 22 */
    cc_buf[4] = 0x11;  /* LI = 17 */
    cc_buf[5] = COTP_CC_TYPE;
    /* DST-REF = client's SRC-REF */
    cc_buf[6] = (uint8_t)(client_src_ref >> 8);
    cc_buf[7] = (uint8_t)(client_src_ref & 0xFF);
    /* SRC-REF = our reference */
    cc_buf[8] = 0x00; cc_buf[9] = 0x01;
    cc_buf[10] = 0x00;  /* Class 0 */
    /* TPDU size: C0 01 0D (8192) */
    cc_buf[11] = 0xC0; cc_buf[12] = 0x01; cc_buf[13] = 0x0D;
    /* Calling TSAP: C2 02 00 01 */
    cc_buf[14] = 0xC2; cc_buf[15] = 0x02; cc_buf[16] = 0x00; cc_buf[17] = 0x01;
    /* Called TSAP: C1 02 00 01 */
    cc_buf[18] = 0xC1; cc_buf[19] = 0x02; cc_buf[20] = 0x00; cc_buf[21] = 0x01;

    ret = iec61850_tcp_send(tcp, cc_buf, sizeof(cc_buf));
    if (ret < 0) { return ret; }

    return 0;
}

int iec61850_tpkt_encode(uint8_t *buf, size_t buf_size,
                           const uint8_t *data, size_t data_len)
{
    size_t total;

    if (buf == NULL || data == NULL) { return -EINVAL; }

    /* TPKT header (4) + COTP DT header (3) + data */
    total = IEC61850_TPKT_HEADER_LEN + COTP_DT_HEADER + data_len;
    if (total > buf_size || total > 65535) { return -ENOSPC; }

    /* TPKT header */
    buf[0] = IEC61850_TPKT_VERSION;
    buf[1] = 0;
    buf[2] = (uint8_t)(total >> 8);
    buf[3] = (uint8_t)(total & 0xFF);

    /* COTP DT header */
    buf[4] = 0x02;           /* Length indicator = 2 */
    buf[5] = COTP_DT_TYPE;   /* Data TPDU */
    buf[6] = COTP_DT_EOT;    /* EOT + TPDU-NR=0 */

    (void)memcpy(buf + 7, data, data_len);

    return (int)total;
}

int iec61850_tpkt_decode(const uint8_t *buf, size_t buf_len,
                           const uint8_t **payload, size_t *payload_len)
{
    uint16_t total_len;
    size_t cotp_li;
    size_t header_len;

    if (buf == NULL || payload == NULL || payload_len == NULL) {
        return -EINVAL;
    }
    if (buf_len < IEC61850_TPKT_HEADER_LEN + 1) { return -EBADMSG; }
    if (buf[0] != IEC61850_TPKT_VERSION) { return -EPROTONOSUPPORT; }

    total_len = (uint16_t)((uint16_t)buf[2] << 8) | (uint16_t)buf[3];
    if (total_len < IEC61850_TPKT_HEADER_LEN + 1 || total_len > buf_len) {
        return -EBADMSG;
    }

    /* Skip COTP header: LI byte tells us how long COTP header is */
    cotp_li = buf[IEC61850_TPKT_HEADER_LEN];
    header_len = IEC61850_TPKT_HEADER_LEN + 1 + cotp_li;
    if (header_len > total_len) { return -EBADMSG; }

    *payload = buf + header_len;
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
    if (*offset + 2 + val_len > buf_size) { return -ENOSPC; }
    buf[*offset] = pi;
    buf[*offset + 1] = (uint8_t)val_len;
    if (val_len > 0) {
        (void)memcpy(buf + *offset + 2, value, val_len);
    }
    *offset += 2 + val_len;
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
    if (length <= 254) {
        if (*offset >= buf_size) { return -ENOSPC; }
        buf[*offset] = (uint8_t)length;
        (*offset)++;
    } else {
        if (*offset + 3 > buf_size) { return -ENOSPC; }
        buf[*offset] = 0xFF;
        buf[*offset + 1] = (uint8_t)(length >> 8);
        buf[*offset + 2] = (uint8_t)(length & 0xFF);
        *offset += 3;
    }
    return 0;
}

/* Number of bytes a session length occupies */
static size_t session_length_size(size_t length)
{
    return (length <= 254) ? 1 : 3;
}

/* Encode CONNECT or ACCEPT SPDU */
static int session_encode_cn_ac(uint8_t *buf, size_t buf_size, uint8_t si,
                                  const iec61850_session_params_t *params,
                                  const uint8_t *user_data, size_t user_data_len)
{
    size_t offset = 0;
    uint8_t ver_buf[1];
    uint8_t req_buf[2];
    int ret;

    if (buf == NULL || params == NULL) { return -EINVAL; }

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
    size_t ca_inner = 3 + 3;  /* protocol_options(3) + version(3) */
    size_t content_len = 2 + ca_inner;  /* PGI 0x05 tag(1) + LI(1) + inner */
    content_len += 4;  /* requirements (PI=1,LI=1,val=2) */
    if (params->calling_ssel_len > 0) {
        content_len += 2 + params->calling_ssel_len;
    }
    if (params->called_ssel_len > 0) {
        content_len += 2 + params->called_ssel_len;
    }
    if (user_data != NULL && user_data_len > 0) {
        /* User data PI: PI(1) + session_length_size(user_data_len) + data */
        content_len += 1 + session_length_size(user_data_len) + user_data_len;
    }

    /* SI byte */
    if (offset >= buf_size) { return -ENOSPC; }
    buf[offset] = si;
    offset++;

    /* SPDU total length */
    ret = write_session_length(buf, buf_size, &offset, content_len);
    if (ret != 0) { return ret; }

    /* Connect/Accept Item PGI (0x05) containing Protocol Options + Version */
    if (offset + 2 + ca_inner > buf_size) { return -ENOSPC; }
    buf[offset++] = 0x05;  /* PGI Connect/Accept Item */
    buf[offset++] = (uint8_t)ca_inner;

    /* Protocol Options PI (0x13): value 0x00 */
    buf[offset++] = 0x13;
    buf[offset++] = 0x01;
    buf[offset++] = 0x00;

    /* Protocol Version PI (0x16) inside PGI 0x05 */
    ver_buf[0] = params->version;
    ret = session_encode_param(buf, buf_size, &offset,
                                 IEC61850_SPI_VERSION, ver_buf, 1);
    if (ret != 0) { return ret; }

    /* User Requirements (functional units) */
    req_buf[0] = (uint8_t)(params->user_requirements >> 8);
    req_buf[1] = (uint8_t)(params->user_requirements & 0xFF);
    ret = session_encode_param(buf, buf_size, &offset,
                                 IEC61850_SPI_REQUIREMENTS, req_buf, 2);
    if (ret != 0) { return ret; }

    /* Calling Session Selector */
    if (params->calling_ssel_len > 0) {
        ret = session_encode_param(buf, buf_size, &offset,
                                     IEC61850_SPI_CALLING_SSEL,
                                     params->calling_ssel,
                                     params->calling_ssel_len);
        if (ret != 0) { return ret; }
    }

    /* Called Session Selector */
    if (params->called_ssel_len > 0) {
        ret = session_encode_param(buf, buf_size, &offset,
                                     IEC61850_SPI_CALLED_SSEL,
                                     params->called_ssel,
                                     params->called_ssel_len);
        if (ret != 0) { return ret; }
    }

    /* User Data */
    if (user_data != NULL && user_data_len > 0) {
        if (offset >= buf_size) { return -ENOSPC; }
        buf[offset] = IEC61850_SPI_USER_DATA;
        offset++;
        /* User data PI length uses ISO 8327 session length encoding */
        ret = write_session_length(buf, buf_size, &offset, user_data_len);
        if (ret != 0) { return ret; }
        if (offset + user_data_len > buf_size) { return -ENOSPC; }
        (void)memcpy(buf + offset, user_data, user_data_len);
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

    if (buf == NULL || user_data == NULL) { return -EINVAL; }

    /* GIVE_TOKENS SPDU (SI=0x01, LI=0x00) + DATA SPDU (SI=0x01, LI=0x00) */
    if (4 + user_data_len > buf_size) { return -ENOSPC; }

    /* GIVE_TOKENS */
    buf[offset++] = IEC61850_SI_DATA;  /* SI=0x01 */
    buf[offset++] = 0x00;

    /* DATA */
    buf[offset++] = IEC61850_SI_DATA;  /* SI=0x01 */
    buf[offset++] = 0x00;

    (void)memcpy(buf + offset, user_data, user_data_len);
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
    if (user_data != NULL && user_data_len > 0) {
        content_len = 1 + session_length_size(user_data_len) + user_data_len;
    }

    if (offset >= buf_size) { return -ENOSPC; }
    buf[offset] = IEC61850_SI_FINISH;
    offset++;

    ret = write_session_length(buf, buf_size, &offset, content_len);
    if (ret != 0) { return ret; }

    if (user_data != NULL && user_data_len > 0) {
        if (offset >= buf_size) { return -ENOSPC; }
        buf[offset] = IEC61850_SPI_USER_DATA;
        offset++;
        ret = write_session_length(buf, buf_size, &offset, user_data_len);
        if (ret != 0) { return ret; }
        if (offset + user_data_len > buf_size) { return -ENOSPC; }
        (void)memcpy(buf + offset, user_data, user_data_len);
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

    if (buf == NULL || si_type == NULL || user_data == NULL ||
        user_data_len == NULL) {
        return -EINVAL;
    }

    if (buf_len < 2) { return -EBADMSG; }

    si = buf[offset]; offset++;

    /* Read SPDU length using ISO 8327 encoding */
    {
        uint8_t first_li = buf[offset]; offset++;
        if (first_li == 0xFF) {
            /* 3-byte form: 0xFF + 2-byte big-endian */
            if (offset + 2 > buf_len) { return -EBADMSG; }
            li = (uint8_t)0;  /* unused — use spdu_len below */
            size_t spdu_len = (size_t)((size_t)buf[offset] << 8) |
                              (size_t)buf[offset + 1];
            offset += 2;
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
        if (li == 0 && offset + 2 <= buf_len &&
            buf[offset] == IEC61850_SI_DATA && buf[offset + 1] == 0x00) {
            /* GIVE_TOKENS prefix present — skip it */
            offset += 2;
        }
        *user_data = buf + offset;
        *user_data_len = buf_len - offset;
        return 0;
    }

    /* Parse parameter items */
    if (params_end > buf_len) { return -EBADMSG; }

    while (offset < params_end) {
        if (offset + 1 >= params_end) { break; }

        uint8_t pi = buf[offset]; offset++;
        size_t plen;

        if (pi == IEC61850_SPI_USER_DATA) {
            /* User data uses ISO 8327 session length encoding */
            if (offset >= params_end) { break; }
            if (buf[offset] == 0xFF) {
                /* 3-byte form */
                offset++;
                if (offset + 2 > buf_len) { break; }
                plen = (size_t)((size_t)buf[offset] << 8) |
                       (size_t)buf[offset + 1];
                offset += 2;
            } else {
                plen = buf[offset];
                offset++;
            }
            *user_data = buf + offset;
            *user_data_len = plen;
            break;  /* User data is always last */
        }

        plen = buf[offset]; offset++;

        if (offset + plen > params_end) { break; }

        if (params != NULL) {
            switch (pi) {
                case IEC61850_SPI_VERSION:
                    if (plen >= 1) { params->version = buf[offset]; }
                    break;
                case IEC61850_SPI_REQUIREMENTS:
                    if (plen >= 2) {
                        params->user_requirements =
                            (uint16_t)((uint16_t)buf[offset] << 8) |
                            (uint16_t)buf[offset + 1];
                    }
                    break;
                case IEC61850_SPI_CALLING_SSEL:
                    if (plen <= IEC61850_ISO_MAX_SSEL) {
                        (void)memcpy(params->calling_ssel, buf + offset, plen);
                        params->calling_ssel_len = plen;
                    }
                    break;
                case IEC61850_SPI_CALLED_SSEL:
                    if (plen <= IEC61850_ISO_MAX_SSEL) {
                        (void)memcpy(params->called_ssel, buf + offset, plen);
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
#define PRES_TAG_MODE       0xA0U  /* [0] */
#define PRES_TAG_NORMAL_MODE 0xA0U /* [0] */
#define PRES_TAG_DCS_LIST   0xA4U  /* [4] - Definition Context List */
#define PRES_TAG_DCS_ENTRY  0x30U  /* SEQUENCE */
#define PRES_TAG_PCID       0x02U  /* INTEGER */
#define PRES_TAG_ABS_SYNTAX 0x06U  /* OBJECT IDENTIFIER */
#define PRES_TAG_TRF_SYNTAX 0x30U  /* SEQUENCE */
#define PRES_TAG_USER_DATA  0x61U  /* [APPLICATION 1] */
#define PRES_TAG_PDATA      0x61U  /* fully-encoded-data [APPLICATION 1] */
#define PRES_TAG_PDV_LIST   0x30U  /* SEQUENCE */

int iec61850_pres_encode_cp(uint8_t *buf, size_t buf_size,
                              const uint8_t *acse_pdu, size_t acse_len)
{
    size_t offset = 0;

    if (buf == NULL || acse_pdu == NULL) { return -EINVAL; }

    /* Build bottom-up: we know the content sizes */
    /* For simplicity, encode directly (this is init-time, not hot path) */

    /* CP [SET] tag */
    if (offset >= buf_size) { return -ENOSPC; }
    buf[offset] = PRES_TAG_CP;
    offset++;

    /* Reserve length (will fill later) */
    size_t cp_len_offset = offset;
    offset += 3;  /* Reserve 3 bytes for BER length */

    /* Mode selector [0] IMPLICIT SET { [0] INTEGER = 1 (normal mode) } */
    if (offset + 8 > buf_size) { return -ENOSPC; }
    buf[offset++] = 0xA0;  /* [0] CONSTRUCTED */
    buf[offset++] = 0x03;  /* length 3 */
    buf[offset++] = 0x80;  /* [0] IMPLICIT */
    buf[offset++] = 0x01;  /* length 1 */
    buf[offset++] = 0x01;  /* normal-mode = 1 */

    /* Normal-mode-parameters [2] IMPLICIT SEQUENCE */
    if (offset + 3 > buf_size) { return -ENOSPC; }
    buf[offset++] = 0xA2;  /* [2] CONSTRUCTED */
    size_t nmp_len_offset = offset;
    offset += 2;  /* length placeholder (0x81 NN) */
    size_t nmp_start = offset;

    /* Calling presentation selector [1] IMPLICIT OCTET STRING */
    if (offset + 6 > buf_size) { return -ENOSPC; }
    buf[offset++] = 0x81;  /* [1] IMPLICIT */
    buf[offset++] = 0x04;  /* length 4 */
    buf[offset++] = 0x00; buf[offset++] = 0x00;
    buf[offset++] = 0x00; buf[offset++] = 0x01;  /* P-selector = 1 */

    /* Called presentation selector [2] IMPLICIT OCTET STRING */
    if (offset + 6 > buf_size) { return -ENOSPC; }
    buf[offset++] = 0x82;  /* [2] IMPLICIT */
    buf[offset++] = 0x04;  /* length 4 */
    buf[offset++] = 0x00; buf[offset++] = 0x00;
    buf[offset++] = 0x00; buf[offset++] = 0x01;  /* P-selector = 1 */

    /* Definition Context List [4] IMPLICIT SEQUENCE OF */
    if (offset + 4 > buf_size) { return -ENOSPC; }
    buf[offset++] = 0xA4;  /* [4] CONSTRUCTED */
    size_t dcl_len_offset = offset;
    offset += 2;  /* length placeholder */

    size_t dcl_start = offset;

    /* Context entry 1: ACSE (pcid=1) */
    if (offset + 20 > buf_size) { return -ENOSPC; }
    buf[offset++] = 0x30;  /* SEQUENCE */
    buf[offset++] = (uint8_t)(3 + 2 + IEC61850_OID_ACSE_LEN +
                               2 + 2 + IEC61850_OID_BER_LEN);
    buf[offset++] = 0x02; buf[offset++] = 0x01;
    buf[offset++] = IEC61850_PCID_ACSE;  /* pcid = 1 */
    buf[offset++] = 0x06;
    buf[offset++] = (uint8_t)IEC61850_OID_ACSE_LEN;
    (void)memcpy(buf + offset, IEC61850_OID_ACSE, IEC61850_OID_ACSE_LEN);
    offset += IEC61850_OID_ACSE_LEN;
    buf[offset++] = 0x30;
    buf[offset++] = (uint8_t)(2 + IEC61850_OID_BER_LEN);
    buf[offset++] = 0x06;
    buf[offset++] = (uint8_t)IEC61850_OID_BER_LEN;
    (void)memcpy(buf + offset, IEC61850_OID_BER, IEC61850_OID_BER_LEN);
    offset += IEC61850_OID_BER_LEN;

    /* Context entry 2: MMS (pcid=3) */
    if (offset + 20 > buf_size) { return -ENOSPC; }
    buf[offset++] = 0x30;
    buf[offset++] = (uint8_t)(3 + 2 + IEC61850_OID_MMS_LEN +
                               2 + 2 + IEC61850_OID_BER_LEN);
    buf[offset++] = 0x02; buf[offset++] = 0x01;
    buf[offset++] = IEC61850_PCID_MMS;  /* pcid = 3 */
    buf[offset++] = 0x06;
    buf[offset++] = (uint8_t)IEC61850_OID_MMS_LEN;
    (void)memcpy(buf + offset, IEC61850_OID_MMS, IEC61850_OID_MMS_LEN);
    offset += IEC61850_OID_MMS_LEN;
    buf[offset++] = 0x30;
    buf[offset++] = (uint8_t)(2 + IEC61850_OID_BER_LEN);
    buf[offset++] = 0x06;
    buf[offset++] = (uint8_t)IEC61850_OID_BER_LEN;
    (void)memcpy(buf + offset, IEC61850_OID_BER, IEC61850_OID_BER_LEN);
    offset += IEC61850_OID_BER_LEN;

    /* Update DCL length */
    size_t dcl_content_len = offset - dcl_start;
    buf[dcl_len_offset] = 0x81;
    buf[dcl_len_offset + 1] = (uint8_t)dcl_content_len;

    /* User data: fully-encoded-data [APPLICATION 1] */
    /* Content: PDV-list SEQUENCE { pcid, [0] CONSTRUCTED { acse_pdu } } */
    size_t a0_len_sz = (acse_len < 128) ? (size_t)1
                       : (acse_len < 256 ? (size_t)2 : (size_t)3);
    size_t a0_total = 1 + a0_len_sz + acse_len;
    size_t pdv_inner = 3 + a0_total;  /* pcid(3) + A0-wrapped data */
    size_t pdv_len_sz = (pdv_inner < 128) ? (size_t)1
                        : (pdv_inner < 256 ? (size_t)2 : (size_t)3);
    size_t pdv_total = 1 + pdv_len_sz + pdv_inner;
    size_t fed_inner = pdv_total;

    if (offset + 10 + acse_len > buf_size) { return -ENOSPC; }
    buf[offset++] = 0x61;  /* [APPLICATION 1] fully-encoded-data */
    int lret = ber_write_length(buf, buf_size, &offset, fed_inner);
    if (lret != 0) { return lret; }

    /* PDV-list: SEQUENCE */
    buf[offset++] = 0x30;
    lret = ber_write_length(buf, buf_size, &offset, pdv_inner);
    if (lret != 0) { return lret; }
    buf[offset++] = 0x02; buf[offset++] = 0x01;
    buf[offset++] = IEC61850_PCID_ACSE;

    /* Single-ASN1-type [0] CONSTRUCTED wrapper */
    buf[offset++] = 0xA0;
    lret = ber_write_length(buf, buf_size, &offset, acse_len);
    if (lret != 0) { return lret; }
    (void)memcpy(buf + offset, acse_pdu, acse_len);
    offset += acse_len;

    /* Update normal-mode-parameters [2] length */
    size_t nmp_content_len = offset - nmp_start;
    buf[nmp_len_offset] = 0x81;
    buf[nmp_len_offset + 1] = (uint8_t)nmp_content_len;

    /* Update CP length */
    size_t cp_content_len = offset - cp_len_offset - 3;
    buf[cp_len_offset] = 0x82;
    buf[cp_len_offset + 1] = (uint8_t)(cp_content_len >> 8);
    buf[cp_len_offset + 2] = (uint8_t)(cp_content_len & 0xFF);

    return (int)offset;
}

int iec61850_pres_encode_cpa(uint8_t *buf, size_t buf_size,
                               const uint8_t *acse_pdu, size_t acse_len)
{
    size_t offset = 0;

    if (buf == NULL || acse_pdu == NULL) { return -EINVAL; }

    /* CPA PPDU [SET] tag */
    buf[offset++] = PRES_TAG_CP;  /* Same tag as CP (0x31) */
    size_t cp_len_offset = offset;
    offset += 3;  /* Reserve for BER length */

    /* Mode selector [0] { [0] INTEGER = 1 (normal mode) } */
    buf[offset++] = 0xA0;
    buf[offset++] = 0x03;
    buf[offset++] = 0x80;
    buf[offset++] = 0x01;
    buf[offset++] = 0x01;

    /* Normal-mode-parameters [2] IMPLICIT SEQUENCE */
    buf[offset++] = 0xA2;
    size_t nmp_len_offset = offset;
    offset += 2;  /* placeholder */
    size_t nmp_start = offset;

    /* Responding presentation selector [3] IMPLICIT OCTET STRING */
    buf[offset++] = 0x83;
    buf[offset++] = 0x04;
    buf[offset++] = 0x00; buf[offset++] = 0x00;
    buf[offset++] = 0x00; buf[offset++] = 0x01;

    /* Context definition result list [5] IMPLICIT SEQUENCE OF */
    buf[offset++] = 0xA5;
    /* Two results: ACSE (accepted) + MMS (accepted) */
    size_t crl_start = offset;
    offset++;  /* placeholder for length */

    /* Result for ACSE context: acceptance (0), transfer syntax = BER */
    buf[offset++] = 0x30;
    buf[offset++] = 0x07;
    buf[offset++] = 0x80; buf[offset++] = 0x01; buf[offset++] = 0x00;  /* result: acceptance */
    buf[offset++] = 0x81; buf[offset++] = 0x02;
    buf[offset++] = 0x51; buf[offset++] = 0x01;  /* transfer syntax OID (BER) */

    /* Result for MMS context: acceptance (0), transfer syntax = BER */
    buf[offset++] = 0x30;
    buf[offset++] = 0x07;
    buf[offset++] = 0x80; buf[offset++] = 0x01; buf[offset++] = 0x00;
    buf[offset++] = 0x81; buf[offset++] = 0x02;
    buf[offset++] = 0x51; buf[offset++] = 0x01;

    /* Update context result list length */
    buf[crl_start] = (uint8_t)(offset - crl_start - 1);

    /* User data: fully-encoded-data [APPLICATION 1] with ACSE AARE */
    size_t a0_len_sz = (acse_len < 128) ? (size_t)1
                       : (acse_len < 256 ? (size_t)2 : (size_t)3);
    size_t a0_total = 1 + a0_len_sz + acse_len;
    size_t pdv_inner = 3 + a0_total;
    size_t pdv_len_sz = (pdv_inner < 128) ? (size_t)1
                        : (pdv_inner < 256 ? (size_t)2 : (size_t)3);
    size_t pdv_total = 1 + pdv_len_sz + pdv_inner;
    size_t fed_inner = pdv_total;
    int lret;

    buf[offset++] = 0x61;
    lret = ber_write_length(buf, buf_size, &offset, fed_inner);
    if (lret != 0) { return lret; }

    buf[offset++] = 0x30;
    lret = ber_write_length(buf, buf_size, &offset, pdv_inner);
    if (lret != 0) { return lret; }
    buf[offset++] = 0x02; buf[offset++] = 0x01;
    buf[offset++] = IEC61850_PCID_ACSE;

    buf[offset++] = 0xA0;
    lret = ber_write_length(buf, buf_size, &offset, acse_len);
    if (lret != 0) { return lret; }
    (void)memcpy(buf + offset, acse_pdu, acse_len);
    offset += acse_len;

    /* Update normal-mode-parameters [2] length */
    size_t nmp_content_len = offset - nmp_start;
    buf[nmp_len_offset] = 0x81;
    buf[nmp_len_offset + 1] = (uint8_t)nmp_content_len;

    /* Update CPA length */
    size_t cp_content_len = offset - cp_len_offset - 3;
    buf[cp_len_offset] = 0x82;
    buf[cp_len_offset + 1] = (uint8_t)(cp_content_len >> 8);
    buf[cp_len_offset + 2] = (uint8_t)(cp_content_len & 0xFF);

    return (int)offset;
}

int iec61850_pres_encode_pdata(uint8_t *buf, size_t buf_size,
                                 uint8_t pcid,
                                 const uint8_t *app_pdu, size_t app_len)
{
    size_t offset = 0;
    int ret;

    if (buf == NULL || app_pdu == NULL) { return -EINVAL; }

    /* Calculate sizes with A0 wrapper */
    size_t a0_len_size = (app_len < 128) ? 1 : (app_len < 256 ? 2 : 3);
    size_t a0_total = 1 + a0_len_size + app_len;  /* 0xA0 + len + data */
    size_t pdv_inner = 3 + a0_total;  /* pcid(3) + A0-wrapped data */

    /* Fully-encoded-data [APPLICATION 1] */
    if (offset >= buf_size) { return -ENOSPC; }
    buf[offset++] = 0x61;

    /* Length of PDV-list SEQUENCE */
    size_t seq_len_size = (pdv_inner < 128) ? 1 : (pdv_inner < 256 ? 2 : 3);
    size_t fed_inner = 1 + seq_len_size + pdv_inner;
    ret = ber_write_length(buf, buf_size, &offset, fed_inner);
    if (ret != 0) { return ret; }

    /* PDV-list: SEQUENCE */
    buf[offset++] = 0x30;
    ret = ber_write_length(buf, buf_size, &offset, pdv_inner);
    if (ret != 0) { return ret; }

    /* Context ID */
    buf[offset++] = 0x02;
    buf[offset++] = 0x01;
    buf[offset++] = pcid;

    /* Single-ASN1-type [0] CONSTRUCTED wrapper */
    buf[offset++] = 0xA0;
    ret = ber_write_length(buf, buf_size, &offset, app_len);
    if (ret != 0) { return ret; }
    (void)memcpy(buf + offset, app_pdu, app_len);
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

    if (buf == NULL || pcid == NULL || app_pdu == NULL || app_len == NULL) {
        return -EINVAL;
    }

    *pcid = 0;
    *app_pdu = NULL;
    *app_len = 0;

    if (buf_len < 4) { return -EBADMSG; }

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

        if (tag == 0xA2) {
            /* normal-mode-parameters [2] — descend into it */
            offset++;
            size_t nmp_len;
            ret = ber_read_length(buf, buf_len, &offset, &nmp_len);
            if (ret != 0) { return ret; }
            scan_end = offset + nmp_len;
            if (scan_end > buf_len) { scan_end = buf_len; }
            continue;
        }

        if (tag == 0x61) {
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

        if (tag == 0x30) {
            /* SEQUENCE — check if it's a PDV-list with pcid */
            size_t seq_start = offset;
            offset++;
            ret = ber_read_length(buf, buf_len, &offset, &seq_len);
            if (ret != 0) { return ret; }
            (void)seq_start;

            size_t seq_end = offset + seq_len;
            if (seq_end > buf_len) { return -EBADMSG; }

            /* Read pcid: INTEGER */
            if (offset + 3 <= seq_end && buf[offset] == 0x02 &&
                buf[offset + 1] == 0x01) {
                *pcid = buf[offset + 2];
                offset += 3;

                /* Strip [0] CONSTRUCTED wrapper (0xA0) if present */
                if (offset < seq_end && buf[offset] == 0xA0) {
                    offset++;
                    size_t a0_len;
                    ret = ber_read_length(buf, buf_len, &offset, &a0_len);
                    if (ret != 0) { return ret; }
                    *app_pdu = buf + offset;
                    *app_len = a0_len;
                } else {
                    *app_pdu = buf + offset;
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

    if (buf == NULL || params == NULL) { return -EINVAL; }

    /* AARQ tag [APPLICATION 0] CONSTRUCTED */
    buf[offset++] = IEC61850_ACSE_TAG_AARQ;

    /* Length placeholder */
    size_t len_offset = offset;
    offset += 3;

    /* Application Context Name [1] */
    if (params->app_context_oid_len > 0) {
        buf[offset++] = 0xA1;  /* [1] CONSTRUCTED */
        buf[offset++] = (uint8_t)(2 + params->app_context_oid_len);
        buf[offset++] = 0x06;  /* OBJECT IDENTIFIER */
        buf[offset++] = (uint8_t)params->app_context_oid_len;
        (void)memcpy(buf + offset, params->app_context_oid,
                     params->app_context_oid_len);
        offset += params->app_context_oid_len;
    }

    /* Called AP Title [2] — wraps an OID */
    if (params->called_ap_title_len > 0) {
        buf[offset++] = 0xA2;
        buf[offset++] = (uint8_t)(2 + params->called_ap_title_len);
        buf[offset++] = 0x06;  /* OID tag */
        buf[offset++] = (uint8_t)(params->called_ap_title_len);
        (void)memcpy(buf + offset, params->called_ap_title,
                     params->called_ap_title_len);
        offset += params->called_ap_title_len;
    }

    /* Called AE Qualifier [3] — wraps an INTEGER */
    if (params->called_ae_qualifier >= 0) {
        buf[offset++] = 0xA3;
        buf[offset++] = 0x03;
        buf[offset++] = 0x02;  /* INTEGER tag */
        buf[offset++] = 0x01;
        buf[offset++] = (uint8_t)params->called_ae_qualifier;
    }

    /* Calling AP Title [6] — wraps an OID */
    if (params->calling_ap_title_len > 0) {
        buf[offset++] = 0xA6;
        buf[offset++] = (uint8_t)(2 + params->calling_ap_title_len);
        buf[offset++] = 0x06;  /* OID tag */
        buf[offset++] = (uint8_t)(params->calling_ap_title_len);
        (void)memcpy(buf + offset, params->calling_ap_title,
                     params->calling_ap_title_len);
        offset += params->calling_ap_title_len;
    }

    /* Calling AE Qualifier [7] — wraps an INTEGER */
    if (params->calling_ae_qualifier >= 0) {
        buf[offset++] = 0xA7;
        buf[offset++] = 0x03;
        buf[offset++] = 0x02;  /* INTEGER tag */
        buf[offset++] = 0x01;
        buf[offset++] = (uint8_t)params->calling_ae_qualifier;
    }

    /* User Information [30] — contains the MMS InitiateRequest
     * Wrapped in EXTERNAL { direct-reference INTEGER, encoding [0] } */
    if (app_pdu != NULL && app_len > 0) {
        /* EXTERNAL inner: direct-ref(3) + encoding [0](2+app_len) */
        size_t ext_inner = 3 + 2 + app_len;
        /* Adjust for BER length encoding of app_len */
        size_t app_len_sz = (app_len < 128) ? (size_t)1
                            : (app_len < 256 ? (size_t)2 : (size_t)3);
        size_t a0_total = 1 + app_len_sz + app_len;
        ext_inner = 3 + a0_total;

        size_t ext_len_sz = (ext_inner < 128) ? (size_t)1
                            : (ext_inner < 256 ? (size_t)2 : (size_t)3);
        size_t be_inner = 1 + ext_len_sz + ext_inner;

        buf[offset++] = 0xBE;  /* [30] CONSTRUCTED */
        ret = ber_write_length(buf, buf_size, &offset, be_inner);
        if (ret != 0) { return ret; }

        /* EXTERNAL [8] IMPLICIT SEQUENCE */
        buf[offset++] = 0x28;  /* [8] CONSTRUCTED */
        ret = ber_write_length(buf, buf_size, &offset, ext_inner);
        if (ret != 0) { return ret; }

        /* direct-reference: INTEGER pcid=3 (MMS context) */
        buf[offset++] = 0x02;
        buf[offset++] = 0x01;
        buf[offset++] = IEC61850_PCID_MMS;

        /* encoding [0] single-ASN1-type */
        buf[offset++] = 0xA0;
        ret = ber_write_length(buf, buf_size, &offset, app_len);
        if (ret != 0) { return ret; }

        (void)memcpy(buf + offset, app_pdu, app_len);
        offset += app_len;
    }

    /* Update AARQ length */
    size_t content_len = offset - len_offset - 3;
    buf[len_offset] = 0x82;
    buf[len_offset + 1] = (uint8_t)(content_len >> 8);
    buf[len_offset + 2] = (uint8_t)(content_len & 0xFF);

    return (int)offset;
}

int iec61850_acse_encode_aare(uint8_t *buf, size_t buf_size,
                                const iec61850_acse_params_t *params,
                                iec61850_aare_result_t result,
                                const uint8_t *app_pdu, size_t app_len)
{
    size_t offset = 0;
    int ret;

    if (buf == NULL || params == NULL) { return -EINVAL; }

    buf[offset++] = IEC61850_ACSE_TAG_AARE;
    size_t len_offset = offset;
    offset += 3;

    /* Application Context Name [1] */
    if (params->app_context_oid_len > 0) {
        buf[offset++] = 0xA1;
        buf[offset++] = (uint8_t)(2 + params->app_context_oid_len);
        buf[offset++] = 0x06;
        buf[offset++] = (uint8_t)params->app_context_oid_len;
        (void)memcpy(buf + offset, params->app_context_oid,
                     params->app_context_oid_len);
        offset += params->app_context_oid_len;
    }

    /* Result [2] */
    buf[offset++] = 0xA2;
    buf[offset++] = 0x03;
    buf[offset++] = 0x02;  /* INTEGER */
    buf[offset++] = 0x01;
    buf[offset++] = (uint8_t)result;

    /* Result Source Diagnostic [3] */
    buf[offset++] = 0xA3;
    buf[offset++] = 0x05;
    buf[offset++] = 0xA1;  /* [1] acse-service-user */
    buf[offset++] = 0x03;
    buf[offset++] = 0x02;
    buf[offset++] = 0x01;
    buf[offset++] = 0x00;  /* null (no diagnostic) */

    /* User Information [30] with EXTERNAL { direct-reference, encoding [0] } */
    if (app_pdu != NULL && app_len > 0) {
        size_t app_len_sz = (app_len < 128) ? (size_t)1
                            : (app_len < 256 ? (size_t)2 : (size_t)3);
        size_t a0_total = 1 + app_len_sz + app_len;
        size_t ext_inner = 3 + a0_total;  /* direct-ref(3) + encoding */
        size_t ext_len_sz = (ext_inner < 128) ? (size_t)1
                            : (ext_inner < 256 ? (size_t)2 : (size_t)3);
        size_t be_inner = 1 + ext_len_sz + ext_inner;

        buf[offset++] = 0xBE;
        ret = ber_write_length(buf, buf_size, &offset, be_inner);
        if (ret != 0) { return ret; }

        buf[offset++] = 0x28;
        ret = ber_write_length(buf, buf_size, &offset, ext_inner);
        if (ret != 0) { return ret; }

        /* direct-reference: INTEGER pcid=3 (MMS context) */
        buf[offset++] = 0x02;
        buf[offset++] = 0x01;
        buf[offset++] = IEC61850_PCID_MMS;

        buf[offset++] = 0xA0;
        ret = ber_write_length(buf, buf_size, &offset, app_len);
        if (ret != 0) { return ret; }

        (void)memcpy(buf + offset, app_pdu, app_len);
        offset += app_len;
    }

    size_t content_len = offset - len_offset - 3;
    buf[len_offset] = 0x82;
    buf[len_offset + 1] = (uint8_t)(content_len >> 8);
    buf[len_offset + 2] = (uint8_t)(content_len & 0xFF);

    return (int)offset;
}

int iec61850_acse_encode_rlrq(uint8_t *buf, size_t buf_size)
{
    if (buf == NULL || buf_size < 4) { return -EINVAL; }

    buf[0] = IEC61850_ACSE_TAG_RLRQ;
    buf[1] = 0x02;
    /* Reason [0] = normal (0) */
    buf[2] = 0x80;
    buf[3] = 0x00;
    return 4;
}

int iec61850_acse_encode_rlre(uint8_t *buf, size_t buf_size)
{
    if (buf == NULL || buf_size < 2) { return -EINVAL; }

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

    if (buf == NULL || tag == NULL) { return -EINVAL; }
    if (buf_len < 2) { return -EBADMSG; }

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
                if (params != NULL && elem_len > 2 && buf[offset] == 0x06) {
                    size_t oid_len = buf[offset + 1];
                    if (oid_len <= IEC61850_ISO_MAX_OID && offset + 2 + oid_len <= elem_end) {
                        (void)memcpy(params->app_context_oid, buf + offset + 2, oid_len);
                        params->app_context_oid_len = oid_len;
                    }
                }
                break;

            case 0xA2:  /* Result [2] (AARE only) */
                if (result != NULL && elem_len >= 3 && buf[offset] == 0x02 &&
                    buf[offset + 1] == 0x01) {
                    *result = (iec61850_aare_result_t)buf[offset + 2];
                }
                break;

            case 0xBE:  /* User Information [30] */
                if (app_pdu != NULL && app_len != NULL) {
                    /* Dig into EXTERNAL { direct-reference, encoding [0] } */
                    size_t inner = offset;
                    if (inner < elem_end && buf[inner] == 0x28) {
                        inner++;
                        size_t ext_len;
                        ret = ber_read_length(buf, buf_len, &inner, &ext_len);
                        if (ret != 0) break;
                        size_t ext_end = inner + ext_len;
                        if (ext_end > elem_end) break;

                        /* Skip optional direct-reference (INTEGER) */
                        if (inner < ext_end && buf[inner] == 0x02) {
                            inner++;
                            size_t dr_len;
                            ret = ber_read_length(buf, buf_len, &inner, &dr_len);
                            if (ret != 0) break;
                            inner += dr_len;
                        }

                        /* encoding [0] single-ASN1-type */
                        if (inner < ext_end && buf[inner] == 0xA0) {
                            inner++;
                            size_t enc_len;
                            ret = ber_read_length(buf, buf_len, &inner, &enc_len);
                            if (ret == 0 && inner + enc_len <= ext_end) {
                                *app_pdu = buf + inner;
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
    iec61850_session_params_init(&conn->session_params);
    iec61850_acse_params_init(&conn->acse_params);
    conn->state = IEC61850_ISO_STATE_IDLE;
    conn->max_pdu_size = IEC61850_ISO_MAX_PDU;
}

int iec61850_iso_connect(iec61850_iso_conn_t *conn, const char *host,
                           uint16_t port, const uint8_t *mms_init,
                           size_t mms_init_len, int timeout_ms)
{
    uint8_t acse_buf[4096];
    uint8_t pres_buf[4096];
    uint8_t sess_buf[4096];
    uint8_t tpkt_buf[4096];
    uint8_t recv_buf[4096];
    int ret;

    if (conn == NULL || host == NULL) { return -EINVAL; }

    conn->state = IEC61850_ISO_STATE_CONNECTING;

    /* TCP connect */
    ret = iec61850_tcp_connect(&conn->tcp, host, port, timeout_ms);
    if (ret != 0) {
        conn->state = IEC61850_ISO_STATE_CLOSED;
        return ret;
    }

    /* COTP CR/CC handshake */
    ret = cotp_negotiate(&conn->tcp, timeout_ms);
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
    ret = iec61850_tcp_send(&conn->tcp, tpkt_buf, tpkt_len);
    if (ret < 0) { goto fail; }

    /* Receive complete TPKT response (handles fragmented TCP reads) */
    ret = iec61850_tcp_recv_tpkt(&conn->tcp, recv_buf, sizeof(recv_buf),
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
    if (ret != 0 || si_type != IEC61850_SI_ACCEPT) { goto fail; }

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
    if (ret != 0 || acse_tag != IEC61850_ACSE_TAG_AARE ||
        aare_result != IEC61850_AARE_ACCEPTED) {
        goto fail;
    }

    conn->state = IEC61850_ISO_STATE_CONNECTED;
    return 0;

fail:
    iec61850_tcp_disconnect(&conn->tcp);
    conn->state = IEC61850_ISO_STATE_CLOSED;
    return -ECONNREFUSED;
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
    ret = cotp_accept(&conn->tcp, timeout_ms);
    if (ret != 0) { return ret; }

    /* Read incoming Session CONNECT (complete TPKT frame) */
    ret = iec61850_tcp_recv_tpkt(&conn->tcp, recv_buf, sizeof(recv_buf),
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
    if (ret != 0 || si_type != IEC61850_SI_CONNECT) { return -EPROTO; }

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
    if (ret != 0 || acse_tag != IEC61850_ACSE_TAG_AARQ) { return -EPROTO; }

    /* Copy MMS InitiateRequest to caller */
    if (mms_req != NULL && mms_req_len != NULL && app_data != NULL) {
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

    ret = iec61850_tcp_send(&conn->tcp, tpkt_buf, (size_t)ret);
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

    if (conn == NULL || data == NULL) { return -EINVAL; }
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

    return iec61850_tcp_send(&conn->tcp, tpkt_buf, (size_t)ret);
}

int iec61850_iso_recv(iec61850_iso_conn_t *conn,
                        uint8_t *buf, size_t buf_size,
                        size_t *recv_len, int timeout_ms)
{
    uint8_t recv_buf[IEC61850_ISO_MAX_PDU];
    int ret;

    if (conn == NULL || buf == NULL || recv_len == NULL) { return -EINVAL; }
    if (conn->state != IEC61850_ISO_STATE_CONNECTED) { return -ENOTCONN; }

    *recv_len = 0;

    /* Read complete TPKT frame (handles fragmented TCP reads) */
    ret = iec61850_tcp_recv_tpkt(&conn->tcp, recv_buf, sizeof(recv_buf),
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
                        (void)iec61850_tcp_send(&conn->tcp, tpkt_buf,
                                                (size_t)ret);
                    }
                }
            }
        }

        conn->state = IEC61850_ISO_STATE_RELEASING;
    }

    iec61850_tcp_disconnect(&conn->tcp);
    conn->state = IEC61850_ISO_STATE_CLOSED;
    return 0;
}
