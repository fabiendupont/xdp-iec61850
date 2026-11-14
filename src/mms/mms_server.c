/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Server Implementation
 *
 * Thread-per-connection server with ISO stack transport.
 * Handles GetNameList, Read, Write, GetVariableAccessAttributes.
 *
 * WP-2x: optional RCB-manager wiring (iec61850_mms_server_set_rcb_
 * manager) — pre-commit Ed.2 validation of RCB component writes,
 * per-request bridge reconcile, periodic bridge sync on the session
 * loop's recv-timeout tick and association release at session
 * teardown. Inert unless a manager is registered.
 *
 * WP-2w: IEC 61850-8-1 Ed.2 control-object wire mapping
 * (iec61850_mms_server_set_control_manager). Control objects are
 * exposed as ordinary data-store named variables ("<LN>$CO$<DO>$SBO"
 * / "$SBOw" / "$Oper" / "$Cancel" plus the readable ctlModel /
 * sboTimeout / OperTm attributes and their "$CF$" spellings) and
 * dispatched pre-commit to the control manager — Select/Operate/
 * Cancel are MMS Reads/Writes on those objects, and command
 * termination is an unsolicited InformationReport on the "$Oper"
 * object pushed to the owning association. Inert unless a control
 * manager is wired through the bridge API.
 */


#include "mms/mms_server.h"
#include "mms/mms_file_service.h"
#include "mms/mms_journal.h"
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

/* ISO 9506-2 DataAccessError codes for the in-band Write-Response
 * failure CHOICE live in asn1/mms_ber.h (MMS_DATAACCESS_*, hoisted
 * from locals in WP-C3 — the IEC 61850-8-1 mapping this repo's
 * WP-1c/1f client decodes for rejected RCB/SGCB/control writes). */

void iec61850_mms_server_config_init(iec61850_mms_server_config_t *cfg)
{
    if (cfg == NULL) { return; }
    cfg->port = 102;
    cfg->max_pdu_size = IEC61850_MMS_MAX_PDU_SIZE;
    cfg->max_sessions = IEC61850_MMS_MAX_SESSIONS;
    cfg->accept_timeout_ms = 1000;
    cfg->after_response = NULL;
    cfg->after_response_user_data = NULL;
    /* WP-3b: TLS off by default; port per IEC 62351-4 (3782) */
    cfg->tls_enabled = false;
    cfg->tls_provider = NULL;
    cfg->tls_mode = IEC61850_TLS_MODE_COMPATIBLE;
    cfg->tls_port = (uint16_t)IEC61850_TLS_MMS_PORT_DEFAULT;
    cfg->tls_only = false;
}

void iec61850_mms_server_init(iec61850_mms_server_t *server,
                                const iec61850_mms_server_config_t *cfg,
                                iec61850_mms_data_store_t *data_store)
{
    if (server == NULL) { return; }

    (void)memset(server, 0, sizeof(*server));

    if (cfg != NULL) {
        server->config = *cfg;
    } else {
        iec61850_mms_server_config_init(&server->config);
    }

    server->data_store = data_store;
    iec61850_tcp_listener_init(&server->listener);
#ifdef IEC61850_SECURITY_ENABLED
    iec61850_tls_listener_init(&server->tls_listener);
#else
    /* No TLS implementation is linked; keep the embedded member in
     * a defined (unbound) state without referencing it. */
    (void)memset(&server->tls_listener, 0, sizeof(server->tls_listener));
    server->tls_listener.tcp.sockfd = -1;
#endif
    atomic_store(&server->running, false);
    atomic_store(&server->stop_requested, false);
    atomic_store(&server->active_session_count, 0);
    /* WP-2w: control-bridge state lock (see mms_server.h; the struct
     * has no destroy API — the mutex holds no allocation). */
    (void)pthread_mutex_init(&server->control_bridge_mutex, NULL);
}

/* Map data store error to MMS error class + code */
static void map_ds_error(int ds_ret, mms_service_error_t *err)
{
    switch (ds_ret) {
        case IEC61850_MMS_DS_ERR_NOT_FOUND:
            err->error_class = MMS_ERROR_CLASS_ACCESS;
            err->error_code = MMS_ACCESS_ERROR_OBJECT_NON_EXISTENT;
            break;
        case IEC61850_MMS_DS_ERR_EXISTS:
            err->error_class = MMS_ERROR_CLASS_ACCESS;
            err->error_code = MMS_ACCESS_ERROR_OBJECT_EXISTS;
            break;
        case IEC61850_MMS_DS_ERR_TYPE:
            err->error_class = MMS_ERROR_CLASS_ACCESS;
            err->error_code = MMS_ACCESS_ERROR_TYPE_INCONSISTENT;
            break;
        default:
            err->error_class = MMS_ERROR_CLASS_SERVICE;
            err->error_code = MMS_SERVICE_ERROR_OTHER;
            break;
    }
}

/*
 * WP-2x: route one Write to the RCB manager registered for the target
 * domain (pre-commit; the session pointer is the bridge's owner
 * identity). Returns the iec61850_rcb_bridge_write() result of the
 * matching registration, or -ENOENT when no registration matches the
 * domain (ordinary variable: the caller writes the store normally).
 */
static int session_rcb_write(iec61850_mms_session_t *session,
                              const char *domain, const char *item,
                              const mms_value_t *value)
{
    uint32_t i;

    for (i = 0U; i < session->rcb_reg_count; i++) {
        iec61850_mms_server_rcb_reg_t *reg = &session->rcb_regs[i];

        if (strcmp(reg->domain, domain) != 0) {
            continue;
        }
        return iec61850_rcb_bridge_write(reg->manager, domain, item,
                                         value, (void *)session);
    }
    return -ENOENT;
}

/*
 * WP-2x: server-owned post-response reconcile. Every serviced request
 * is pushed through the bridge with the requesting session — the same
 * point the interim (application-level) after_response hook used — so
 * monitored data-point writes dispatch dchg/qchg, RCB components stay
 * reconciled and closed BufTm windows flush, with no hook installed.
 */
static void session_rcb_reconcile(iec61850_mms_session_t *session,
                                   const char *domain, const char *item)
{
    uint32_t i;

    if ((session->rcb_reg_count == 0U) || (domain == NULL) ||
        (item == NULL) || (domain[0] == '\0')) {
        return;
    }
    for (i = 0U; i < session->rcb_reg_count; i++) {
        iec61850_rcb_bridge_on_write(session->rcb_regs[i].manager,
                                     domain, item, (void *)session);
    }
}

/* ========================================================================
 * WP-2w: IEC 61850-8-1 Ed.2 control-object bridge
 * ========================================================================
 *
 * Select/SelectWithValue/Operate/Cancel are ordinary MMS Reads and
 * Writes on the control object's component data attributes, and the
 * command-termination notification is an unsolicited InformationReport
 * echoing the operated structure on the "$Oper" object (the 8-1
 * mapping, wire-observed from conformant client/server pairs):
 *
 *   Write  <LN>$CO$<DO>$SBO   boolean TRUE  -> select (plain)
 *   Write  <LN>$CO$<DO>$SBOw  Oper struct   -> select with value
 *   Read   <LN>$CO$<DO>$SBO                 -> select (sbo-with-normal-
 *                                              security form); answers
 *                                              "<domain>/<LN>$CO$<DO>"
 *                                              as VisibleString
 *   Write  <LN>$CO$<DO>$Oper  Oper struct   -> operate (operTm honored
 *                                              when present, 7-element
 *                                              time-activated form)
 *   Write  <LN>$CO$<DO>$Cancel Oper struct  -> cancel
 *
 * The Oper structure (IEC 61850-8-1 originator-controlled parameters):
 *   SEQUENCE {
 *     ctlVal  BOOLEAN (or BIT STRING for "Spc" step controls),
 *     operTm  UTC_TIME (only in the time-activated form),
 *     origin  SEQUENCE { orCat INTEGER, orIdent OCTET STRING },
 *     ctlNum  UNSIGNED,
 *     T       UTC_TIME,
 *     Test    BOOLEAN,
 *     Check   BIT STRING (synchrocheck, interlock-check)
 *   }
 */

/* CO object suffixes */
#define CW_CO_SUFFIX_SBO    "$SBO"
#define CW_CO_SUFFIX_SBOW   "$SBOw"
#define CW_CO_SUFFIX_OPER   "$Oper"
#define CW_CO_SUFFIX_CANCEL "$Cancel"

/* BER helpers (bounded TLV building for the CommandTermination PDU) */
static size_t cw_ber_len_size(size_t len)
{
    if (len < 128U) { return 1U; }
    if (len < 256U) { return 2U; }
    return 3U;
}

/* Bounded "base + suffix" item-name builder (no truncation: returns
 * -EINVAL when the composed name does not fit). */
static int cw_item_suffix(char *out, size_t out_size, const char *base,
                           const char *suffix)
{
    size_t bl = strlen(base);
    size_t sl = strlen(suffix);

    if ((bl + sl + 1U) > out_size) { return -EINVAL; }
    (void)memcpy(out, base, bl);
    (void)memcpy(out + bl, suffix, sl + 1U);
    return 0;
}

static size_t cw_put_tlv(uint8_t *buf, size_t cap, size_t pos,
                          uint8_t tag, const uint8_t *content, size_t len)
{
    size_t need = 1U + cw_ber_len_size(len) + len;

    if ((pos + need) > cap) { return 0U; }
    buf[pos++] = tag;
    if (len < 128U) {
        buf[pos++] = (uint8_t)len;
    } else if (len < 256U) {
        buf[pos++] = 0x81U;
        buf[pos++] = (uint8_t)len;
    } else {
        buf[pos++] = 0x82U;
        buf[pos++] = (uint8_t)(len >> 8);
        buf[pos++] = (uint8_t)(len & 0xFFU);
    }
    if (len > 0U) {
        (void)memcpy(buf + pos, content, len);
        pos += len;
    }
    return pos;
}

/* Parsed Oper structure (IEC 61850-8-1 originator parameters) */
typedef struct {
    bool has_ctl_val;
    bool ctl_val;
    bool has_oper_tm;
    uint64_t oper_tm_utc_ms;
    int32_t or_cat;
    uint8_t or_ident[64];
    size_t or_ident_len;
    uint32_t ctl_num;
    bool has_t;
    uint64_t t_utc_ms;
    bool test;
} cw_oper_t;

/* Read one BER TLV header; returns 0 and advances *pos past it. */
static int cw_read_tlv(const uint8_t *buf, size_t len, size_t *pos,
                        uint8_t *tag, const uint8_t **content,
                        size_t *content_len)
{
    size_t p = *pos;
    size_t vlen = 0U;
    uint8_t b;
    uint32_t i;

    if ((p + 2U) > len) { return -EINVAL; }
    *tag = buf[p++];
    b = buf[p++];
    if ((b & 0x80U) == 0U) {
        vlen = b;
    } else {
        uint32_t n = (uint32_t)(b & 0x7FU);

        if ((n == 0U) || (n > 4U) || ((p + n) > len)) { return -EINVAL; }
        for (i = 0U; i < n; i++) {
            vlen = (vlen << 8) | (uint32_t)buf[p++];
        }
    }
    if ((p + vlen) > len) { return -EINVAL; }
    *content = &buf[p];
    *content_len = vlen;
    *pos = p + vlen;
    return 0;
}

/* Decode a little-endian-safe unsigned integer from big-endian bytes */
static uint64_t cw_be_uint(const uint8_t *b, size_t len)
{
    uint64_t v = 0U;
    size_t i;

    for (i = 0U; i < len; i++) {
        v = (v << 8) | (uint64_t)b[i];
    }
    return v;
}

/* IEC 61850-8-1 UTC-Time (4-byte seconds + 3-byte binary fraction +
 * 1-byte time quality) to UTC milliseconds. */
static uint64_t cw_utc_time_ms(const uint8_t *b)
{
    uint64_t sec = cw_be_uint(b, 4U);
    uint32_t frac = (uint32_t)cw_be_uint(b + 4, 3U);

    return (sec * 1000ULL) + (((uint64_t)frac * 1000ULL) / 16777216ULL);
}

/*
 * Parse the Oper structure. `tlv` points at the raw STRUCTURE TLV
 * (MMS_DATA_STRUCTURE tag + length + content) as stashed by
 * mms_decode_value(). Elements are consumed positionally per 8-1
 * (ctlVal, [operTm], origin, ctlNum, T, Test, [Check]); an element
 * with an unexpected type aborts the parse conservatively.
 */
static int cw_parse_oper(const uint8_t *tlv, size_t tlv_len, cw_oper_t *out)
{
    const uint8_t *content;
    size_t content_len;
    size_t pos = 0U;
    uint8_t tag;

    (void)memset(out, 0, sizeof(*out));

    if (cw_read_tlv(tlv, tlv_len, &pos, &tag, &content, &content_len) != 0) {
        return -EINVAL;
    }
    if (tag != (uint8_t)MMS_DATA_STRUCTURE) { return -EINVAL; }

    /* Work inside the structure content */
    const uint8_t *body = content;
    size_t body_len = content_len;
    size_t bpos = 0U;

    /* Element 0: ctlVal — BOOLEAN (or BIT STRING for step controls) */
    if (cw_read_tlv(body, body_len, &bpos, &tag, &content, &content_len) != 0) {
        return -EINVAL;
    }
    if (tag == (uint8_t)MMS_DATA_BOOLEAN) {
        out->has_ctl_val = true;
        out->ctl_val = (content_len > 0U) && (content[0] != 0U);
    } else if (tag == (uint8_t)MMS_DATA_BIT_STRING) {
        /* OperSpc-style step position: non-zero position = "on" */
        out->has_ctl_val = true;
        out->ctl_val = (content_len > 1U) && (content[1] != 0U);
    } else {
        return -EINVAL;
    }

    /* Element 1: operTm (UTC time) in the time-activated form, else
     * the origin structure. */
    if (cw_read_tlv(body, body_len, &bpos, &tag, &content, &content_len) != 0) {
        return -EINVAL;
    }
    if (tag == (uint8_t)MMS_DATA_UTC_TIME) {
        if (content_len != 8U) { return -EINVAL; }
        out->has_oper_tm = true;
        out->oper_tm_utc_ms = cw_utc_time_ms(content);
        if (cw_read_tlv(body, body_len, &bpos, &tag, &content,
                        &content_len) != 0) {
            return -EINVAL;
        }
    }
    if (tag != (uint8_t)MMS_DATA_STRUCTURE) { return -EINVAL; }

    /* origin: SEQUENCE { orCat INTEGER, orIdent OCTET STRING } */
    {
        const uint8_t *org = content;
        size_t org_len = content_len;
        size_t opos = 0U;

        if (cw_read_tlv(org, org_len, &opos, &tag, &content,
                        &content_len) != 0) {
            return -EINVAL;
        }
        if (tag != (uint8_t)MMS_DATA_INTEGER) { return -EINVAL; }
        out->or_cat = (content_len > 0U) ? (int32_t)content[content_len - 1U] : 0;
        if (cw_read_tlv(org, org_len, &opos, &tag, &content,
                        &content_len) != 0) {
            return -EINVAL;
        }
        if (tag != (uint8_t)MMS_DATA_OCTET_STRING) { return -EINVAL; }
        if (content_len > sizeof(out->or_ident)) {
            content_len = sizeof(out->or_ident);
        }
        if (content_len > 0U) {
            (void)memcpy(out->or_ident, content, content_len);
        }
        out->or_ident_len = content_len;
    }

    /* ctlNum: UNSIGNED */
    if (cw_read_tlv(body, body_len, &bpos, &tag, &content, &content_len) != 0) {
        return -EINVAL;
    }
    if (tag != (uint8_t)MMS_DATA_UNSIGNED) { return -EINVAL; }
    out->ctl_num = (uint32_t)cw_be_uint(content, content_len);

    /* T: UTC_TIME */
    if (cw_read_tlv(body, body_len, &bpos, &tag, &content, &content_len) != 0) {
        return -EINVAL;
    }
    if (tag == (uint8_t)MMS_DATA_UTC_TIME) {
        if (content_len != 8U) { return -EINVAL; }
        out->has_t = true;
        out->t_utc_ms = cw_be_uint(content, 8U);
    } else {
        return -EINVAL;
    }

    /* Test: BOOLEAN (optional trailing elements are tolerated) */
    if (bpos < body_len) {
        if (cw_read_tlv(body, body_len, &bpos, &tag, &content,
                        &content_len) != 0) {
            return -EINVAL;
        }
        if (tag == (uint8_t)MMS_DATA_BOOLEAN) {
            out->test = (content_len > 0U) && (content[0] != 0U);
        }
    }
    return 0;
}

/* Control-object component this item refers to (for one reg). */
typedef enum {
    CW_CO_NONE = 0,
    CW_CO_SBO,
    CW_CO_SBOW,
    CW_CO_OPER,
    CW_CO_CANCEL
} cw_co_component_t;

static cw_co_component_t cw_classify_item(const char *reg_item,
                                           const char *item)
{
    size_t base = strlen(reg_item);

    if (strncmp(item, reg_item, base) != 0) { return CW_CO_NONE; }
    if (strcmp(&item[base], CW_CO_SUFFIX_SBO) == 0) { return CW_CO_SBO; }
    if (strcmp(&item[base], CW_CO_SUFFIX_SBOW) == 0) { return CW_CO_SBOW; }
    if (strcmp(&item[base], CW_CO_SUFFIX_OPER) == 0) { return CW_CO_OPER; }
    if (strcmp(&item[base], CW_CO_SUFFIX_CANCEL) == 0) { return CW_CO_CANCEL; }
    return CW_CO_NONE;
}

static iec61850_mms_control_reg_t *cw_find_reg(
    iec61850_mms_session_t *session, const char *domain, const char *item,
    cw_co_component_t *component)
{
    uint32_t i;

    for (i = 0U; i < session->control_reg_count; i++) {
        iec61850_mms_control_reg_t *reg = &session->control_regs[i];

        if (strcmp(reg->domain, domain) != 0) { continue; }
        *component = cw_classify_item(reg->item_id, item);
        if (*component != CW_CO_NONE) { return reg; }
    }
    *component = CW_CO_NONE;
    return NULL;
}

/* Build the CommandTermination PDU (unconfirmed InformationReport on
 * the "$Oper" object, echoing the operated structure — the 8-1
 * mapping wire-observed from conformant servers). Returns the PDU
 * length or 0 on overflow. */
static size_t cw_build_command_termination(const char *domain,
                                            const char *base_item,
                                            const uint8_t *echo,
                                            size_t echo_len,
                                            uint8_t *buf, size_t cap)
{
    char oper_item[MMS_MAX_VARIABLE_NAME];
    size_t dom_len = strlen(domain);
    size_t pos = 0U;
    size_t rpos = 0U;
    size_t rpt = 0U;

    if (dom_len >= MMS_MAX_DOMAIN_NAME) { return 0U; }
    if (cw_item_suffix(oper_item, sizeof(oper_item), base_item,
                       CW_CO_SUFFIX_OPER) != 0) {
        return 0U;
    }

    /* informationReport content = variableAccessSpecification
     * (listOfVariable [0] { SEQUENCE { name [0] { domain-specific [1]
     * { domainId, itemId } } } }) + listOfAccessResult [0] { echo },
     * assembled in a scratch buffer then wrapped by the [0]
     * informationReport and [3] unconfirmed-PDU tags. */
    {
        uint8_t ds_buf[MMS_MAX_VARIABLE_NAME + MMS_MAX_DOMAIN_NAME + 16];
        uint8_t name_buf[MMS_MAX_VARIABLE_NAME + MMS_MAX_DOMAIN_NAME + 20];
        uint8_t seq_buf[MMS_MAX_VARIABLE_NAME + MMS_MAX_DOMAIN_NAME + 24];
        uint8_t lov_buf[MMS_MAX_VARIABLE_NAME + MMS_MAX_DOMAIN_NAME + 28];
        uint8_t res_buf[MMS_MAX_STRING_LENGTH + 8];
        uint8_t rpt_body[MMS_MAX_STRING_LENGTH + MMS_MAX_VARIABLE_NAME +
                         MMS_MAX_DOMAIN_NAME + 44];
        uint8_t rpt_buf[MMS_MAX_STRING_LENGTH + MMS_MAX_VARIABLE_NAME +
                        MMS_MAX_DOMAIN_NAME + 48];
        size_t ds_len = 0U;
        size_t name_len = 0U;
        size_t seq_len = 0U;
        size_t lov_len = 0U;
        size_t rpt_body_len = 0U;

        /* domainId / itemId VisibleStrings wrapped in the
         * domain-specific [1] ObjectName CHOICE */
        ds_len = cw_put_tlv(ds_buf, sizeof(ds_buf), ds_len, 0x1AU,
                            (const uint8_t *)domain, dom_len);
        if (ds_len == 0U) { return 0U; }
        ds_len = cw_put_tlv(ds_buf, sizeof(ds_buf), ds_len, 0x1AU,
                            (const uint8_t *)oper_item,
                            strlen(oper_item));
        if (ds_len == 0U) { return 0U; }
        {
            uint8_t ds_wrap[MMS_MAX_VARIABLE_NAME + MMS_MAX_DOMAIN_NAME + 20];
            size_t ds_wrap_len = cw_put_tlv(ds_wrap, sizeof(ds_wrap), 0U,
                                             0xA1U, ds_buf, ds_len);

            if (ds_wrap_len == 0U) { return 0U; }
            /* name [0] { domain-specific } */
            name_len = cw_put_tlv(name_buf, sizeof(name_buf), name_len,
                                  0xA0U, ds_wrap, ds_wrap_len);
        }
        if (name_len == 0U) { return 0U; }
        /* per-item SEQUENCE { variableSpecification } */
        seq_len = cw_put_tlv(seq_buf, sizeof(seq_buf), seq_len, 0x30U,
                             name_buf, name_len);
        if (seq_len == 0U) { return 0U; }
        /* listOfVariable [0] */
        lov_len = cw_put_tlv(lov_buf, sizeof(lov_buf), lov_len, 0xA0U,
                             seq_buf, seq_len);
        if (lov_len == 0U) { return 0U; }

        /* listOfAccessResult [0] { echo } */
        rpos = cw_put_tlv(res_buf, sizeof(res_buf), rpos, 0xA0U,
                          echo, echo_len);
        if (rpos == 0U) { return 0U; }

        /* informationReport [0] { VAS, listOfAccessResult } — one
         * constructed TLV over the concatenated fields. */
        if ((lov_len + rpos) > sizeof(rpt_body)) { return 0U; }
        (void)memcpy(rpt_body, lov_buf, lov_len);
        rpt_body_len = lov_len;
        (void)memcpy(rpt_body + rpt_body_len, res_buf, rpos);
        rpt_body_len += rpos;
        rpt = cw_put_tlv(rpt_buf, sizeof(rpt_buf), rpt, 0xA0U,
                         rpt_body, rpt_body_len);
        if (rpt == 0U) { return 0U; }

        /* unconfirmed-PDU [3] { informationReport } */
        pos = cw_put_tlv(buf, cap, pos, 0xA3U, rpt_buf, rpt);
    }
    return pos;
}

/*
 * Bridge command-termination callback (installed per bridged control
 * object; chains the application callback captured at wiring time).
 * WP-C3: records the termination as pending on the object's
 * registration instead of sending immediately — the termination
 * fires synchronously inside iec61850_control_operate_ed2() /
 * _cancel() / _process(), i.e. BEFORE the Write-Response the client
 * is waiting for, while 8-1 servers send the CommandTermination
 * after it. The post-response hook (or the recv-timeout tick for
 * operTm commands fired by control_process) flushes it:
 * cw_flush_pending_ct() sends the InformationReport to the
 * association that owns the command's selection and then chains the
 * application callback.
 */
static void cw_termination_cb(const char *domain, const char *item_id,
                               uint32_t selection_id, bool success,
                               iec61850_control_addcause_t addcause,
                               uint64_t timestamp_ms, void *user_data)
{
    /* MISRA 11.5: callback context is the server, deviation Cat. 3 */
    iec61850_mms_server_t *server = (iec61850_mms_server_t *)user_data;
    uint32_t i;

    if (server == NULL) { return; }

    (void)pthread_mutex_lock(&server->control_bridge_mutex);
    for (i = 0U; i < server->control_reg_count; i++) {
        iec61850_mms_control_reg_t *reg = &server->control_regs[i];

        if ((strcmp(reg->domain, domain) == 0) &&
            (strcmp(reg->item_id, item_id) == 0)) {
            reg->pending_termination = true;
            reg->pending_selection_id = selection_id;
            reg->pending_success = success;
            reg->pending_addcause = addcause;
            reg->pending_timestamp_ms = timestamp_ms;
            break;
        }
    }
    (void)pthread_mutex_unlock(&server->control_bridge_mutex);
}

/*
 * WP-C3: flush deferred CommandTerminations. Sends the
 * InformationReport PDU for every pending termination (to the
 * association that owns the command's selection) and chains the
 * application termination callback after the send — the 8-1
 * ordering: Write-Response first, CommandTermination after. The
 * pending flag is claimed under the mutex, so exactly one session
 * thread flushes a given termination even when the post-response
 * hooks of concurrent sessions race.
 */
static void cw_flush_pending_ct(iec61850_mms_server_t *server)
{
    uint32_t i;

    if (server == NULL) { return; }

    for (i = 0U; i < server->control_reg_count; i++) {
        iec61850_mms_control_reg_t *reg = &server->control_regs[i];
        iec61850_mms_session_t *owner = NULL;
        iec61850_control_termination_cb_t app_cb = NULL;
        void *app_data = NULL;
        uint8_t echo[MMS_MAX_STRING_LENGTH];
        size_t echo_len = 0U;
        bool pending = false;
        bool success = false;
        iec61850_control_addcause_t addcause = IEC61850_ADDCAUSE_UNKNOWN;
        uint32_t selection_id = 0U;
        uint64_t timestamp_ms = 0ULL;

        (void)memset(echo, 0, sizeof(echo));

        (void)pthread_mutex_lock(&server->control_bridge_mutex);
        if (reg->pending_termination) {
            pending = true;
            reg->pending_termination = false;
            owner = (iec61850_mms_session_t *)reg->owner_session;
            echo_len = reg->oper_echo_len;
            if (echo_len > sizeof(echo)) { echo_len = 0U; }
            if (echo_len > 0U) {
                (void)memcpy(echo, reg->oper_echo, echo_len);
            }
            app_cb = reg->app_termination_cb;
            app_data = reg->app_termination_user_data;
            selection_id = reg->pending_selection_id;
            success = reg->pending_success;
            addcause = reg->pending_addcause;
            timestamp_ms = reg->pending_timestamp_ms;
        }
        (void)pthread_mutex_unlock(&server->control_bridge_mutex);

        if (!pending) { continue; }

        if ((owner != NULL) && (echo_len > 0U) &&
            atomic_load(&owner->active)) {
            uint8_t pdu[MMS_MAX_STRING_LENGTH + MMS_MAX_VARIABLE_NAME +
                        MMS_MAX_DOMAIN_NAME + 32];
            size_t len = cw_build_command_termination(
                reg->domain, reg->item_id, echo, echo_len, pdu,
                sizeof(pdu));

            if (len > 0U) {
                (void)iec61850_iso_send(&owner->iso, pdu, len);
            }
        }

        if (app_cb != NULL) {
            app_cb(reg->domain, reg->item_id, selection_id, success,
                   addcause, timestamp_ms, app_data);
        }
    }
}

/* Select via the bridge: plain (boolean TRUE) or with value (the
 * parsed ctlVal from the Oper structure). */
static int cw_bridge_select(iec61850_mms_session_t *session,
                             iec61850_mms_control_reg_t *reg,
                             const mms_value_t *value, bool with_value)
{
    iec61850_mms_server_t *server = session->server;
    mms_select_response_t resp;
    cw_oper_t oper;
    int ret;

    if (with_value && (value->type == MMS_TYPE_STRUCTURE)) {
        if (cw_parse_oper(value->value.octet_string.data,
                          value->value.octet_string.len, &oper) != 0) {
            return -EINVAL;
        }
        mms_value_t ctl_val;

        (void)memset(&ctl_val, 0, sizeof(ctl_val));
        ctl_val.type = MMS_TYPE_BOOLEAN;
        ctl_val.value.boolean = oper.ctl_val;
        mms_select_with_value_response_t swv_resp;

        (void)memset(&swv_resp, 0, sizeof(swv_resp));
        ret = iec61850_control_select_with_value(
            session->control_manager, reg->domain, reg->item_id,
            session->session_id, &ctl_val, &swv_resp);
        resp.state = swv_resp.state;
        resp.selection_id = swv_resp.selection_id;
    } else if ((!with_value) && (value->type == MMS_TYPE_BOOLEAN) &&
               value->value.boolean) {
        ret = iec61850_control_select(session->control_manager,
                                       reg->domain, reg->item_id,
                                       session->session_id, &resp);
    } else {
        return -EINVAL;
    }

    if (ret != 0) { return -EPERM; }

    (void)pthread_mutex_lock(&server->control_bridge_mutex);
    reg->selection_id = resp.selection_id;
    reg->owner_session = (void *)session;
    (void)pthread_mutex_unlock(&server->control_bridge_mutex);
    return 0;
}

/* Read-select on "$SBO" (sbo-with-normal-security, 8-1). */
static int cw_bridge_read_select(iec61850_mms_session_t *session,
                                  iec61850_mms_control_reg_t *reg,
                                  mms_read_response_t *out)
{
    iec61850_mms_server_t *server = session->server;
    mms_select_response_t resp;
    int ret;

    ret = iec61850_control_select(session->control_manager, reg->domain,
                                   reg->item_id, session->session_id,
                                   &resp);
    if (ret != 0) {
        out->failure = true;
        out->access_error = MMS_DATAACCESS_TEMPORARILY_UNAVAILABLE;
        return 0;
    }

    (void)pthread_mutex_lock(&server->control_bridge_mutex);
    reg->selection_id = resp.selection_id;
    reg->owner_session = (void *)session;
    (void)pthread_mutex_unlock(&server->control_bridge_mutex);

    (void)memset(out, 0, sizeof(*out));
    out->value.type = MMS_TYPE_VISIBLE_STRING;
    {
        /* "<domain>/<LN>$CO$<DO>" — the selected object reference
         * (8-1 SBO read answer), assembled in a buffer that always
         * fits then copied bounded into the VisibleString. */
        char ref[MMS_MAX_DOMAIN_NAME + MMS_MAX_VARIABLE_NAME + 2];
        size_t copy;

        (void)memcpy(ref, reg->domain, strlen(reg->domain));
        ref[strlen(reg->domain)] = '/';
        (void)memcpy(ref + strlen(reg->domain) + 1U, reg->item_id,
                     strlen(reg->item_id) + 1U);
        copy = strlen(ref);
        if (copy >= MMS_MAX_STRING_LENGTH) {
            copy = MMS_MAX_STRING_LENGTH - 1U;
        }
        (void)memcpy(out->value.value.visible_string.data, ref, copy);
        out->value.value.visible_string.data[copy] = '\0';
        out->value.value.visible_string.len = copy;
    }
    return 0;
}

/* Operate via the bridge: parse the Oper structure, route through
 * iec61850_control_operate_ed2 (operTm honored) and record the echo
 * for the CommandTermination. */
static int cw_bridge_operate(iec61850_mms_session_t *session,
                              iec61850_mms_control_reg_t *reg,
                              const mms_value_t *value)
{
    iec61850_mms_server_t *server = session->server;
    iec61850_control_ids_t ids;
    mms_operate_response_t resp;
    iec61850_control_addcause_t addcause = IEC61850_ADDCAUSE_UNKNOWN;
    cw_oper_t oper;
    uint32_t selection_id = 0U;
    int ret;

    if (value->type != MMS_TYPE_STRUCTURE) { return -EINVAL; }
    if (cw_parse_oper(value->value.octet_string.data,
                      value->value.octet_string.len, &oper) != 0) {
        return -EINVAL;
    }

    (void)pthread_mutex_lock(&server->control_bridge_mutex);
    if (reg->owner_session == (void *)session) {
        selection_id = reg->selection_id;
    }
    /* Record the echo BEFORE the operate: the termination callback
     * (WP-C3: deferred — see cw_termination_cb / cw_flush_pending_ct)
     * fires synchronously inside iec61850_control_operate_ed2() and
     * must find the echo in place for the post-response flush. */
    if ((value->value.octet_string.len > 0U) &&
        (value->value.octet_string.len <= sizeof(reg->oper_echo))) {
        reg->oper_echo_len = value->value.octet_string.len;
        (void)memcpy(reg->oper_echo, value->value.octet_string.data,
                     reg->oper_echo_len);
    }
    (void)pthread_mutex_unlock(&server->control_bridge_mutex);

    ids.session_id = session->session_id;
    ids.selection_id = selection_id;
    ret = iec61850_control_operate_ed2(session->control_manager,
                                        reg->domain, reg->item_id, ids,
                                        oper.has_oper_tm ?
                                            oper.oper_tm_utc_ms : 0ULL,
                                        &resp, &addcause);
    if (ret != 0) { return -EPERM; }

    /* Publish the accepted echo and the operTm state as plain store
     * values so reads of "$Oper" / "$OperTm" serve them. */
    if (oper.has_oper_tm) {
        mms_value_t v;
        char item[MMS_MAX_VARIABLE_NAME];

        (void)memset(&v, 0, sizeof(v));
        v.type = MMS_TYPE_BOOLEAN;
        v.value.boolean = true;
        if (cw_item_suffix(item, sizeof(item), reg->item_id, "$OperTm") == 0) {
            (void)iec61850_mms_ds_write_variable(session->data_store,
                                                  reg->domain, item, &v);
        }
    }
    {
        char item[MMS_MAX_VARIABLE_NAME];

        if (cw_item_suffix(item, sizeof(item), reg->item_id,
                           CW_CO_SUFFIX_OPER) == 0) {
            (void)iec61850_mms_ds_write_variable(session->data_store,
                                                  reg->domain, item, value);
        }
    }
    return 0;
}

/* Cancel via the bridge (outstanding selection or armed operTm). */
static int cw_bridge_cancel(iec61850_mms_session_t *session,
                             iec61850_mms_control_reg_t *reg)
{
    iec61850_mms_server_t *server = session->server;
    iec61850_control_ids_t ids;
    uint32_t selection_id = 0U;
    int ret;

    (void)pthread_mutex_lock(&server->control_bridge_mutex);
    if (reg->owner_session == (void *)session) {
        selection_id = reg->selection_id;
    }
    (void)pthread_mutex_unlock(&server->control_bridge_mutex);

    ids.session_id = session->session_id;
    ids.selection_id = selection_id;
    ret = iec61850_control_cancel(session->control_manager, reg->domain,
                                   reg->item_id, ids);
    if (ret != 0) { return -EPERM; }

    (void)pthread_mutex_lock(&server->control_bridge_mutex);
    if (reg->owner_session == (void *)session) {
        reg->selection_id = 0U;
        reg->owner_session = NULL;
    }
    (void)pthread_mutex_unlock(&server->control_bridge_mutex);
    return 0;
}

/*
 * WP-2w: pre-commit control-object Write dispatch. Returns 0 when the
 * bridge applied the write (the store write is skipped), -ENOENT when
 * the item is not a bridged control-object component (ordinary
 * variable), -EINVAL for a malformed control value and -EPERM for an
 * Ed.2 rejection (both surface as Write-Response failures).
 */
static int session_control_write(iec61850_mms_session_t *session,
                                  const char *domain, const char *item,
                                  const mms_value_t *value)
{
    cw_co_component_t component;
    iec61850_mms_control_reg_t *reg;

    if ((session->control_regs == NULL) || (domain == NULL) ||
        (item == NULL) || (value == NULL)) {
        return -ENOENT;
    }

    reg = cw_find_reg(session, domain, item, &component);
    if (reg == NULL) { return -ENOENT; }

    switch (component) {
        case CW_CO_SBO:
            if (value->type == MMS_TYPE_STRUCTURE) {
                return cw_bridge_select(session, reg, value, true);
            }
            return cw_bridge_select(session, reg, value, false);
        case CW_CO_SBOW:
            return cw_bridge_select(session, reg, value, true);
        case CW_CO_OPER:
            return cw_bridge_operate(session, reg, value);
        case CW_CO_CANCEL:
            return cw_bridge_cancel(session, reg);
        default:
            return -ENOENT;
    }
}

/*
 * WP-2w: control-object Read dispatch (the "$SBO" read-select form of
 * 8-1 sbo-with-normal-security). Returns 0 when the read was answered
 * by the bridge, -ENOENT for an ordinary variable read.
 */
static int session_control_read(iec61850_mms_session_t *session,
                                 const char *domain, const char *item,
                                 mms_read_response_t *out)
{
    cw_co_component_t component;
    iec61850_mms_control_reg_t *reg;

    if ((session->control_regs == NULL) || (domain == NULL) ||
        (item == NULL)) {
        return -ENOENT;
    }

    reg = cw_find_reg(session, domain, item, &component);
    if ((reg == NULL) || (component != CW_CO_SBO)) { return -ENOENT; }

    return cw_bridge_read_select(session, reg, out);
}

/*
 * WP-2w: GetVariableAccessAttributes on a bridged control object
 * ("<LN>$CO$<DO>") answers a structure type — the 8-1 component
 * layout is exposed by the object's component variables. Returns 0
 * when answered, -ENOENT otherwise.
 */
static int session_control_attrs(iec61850_mms_session_t *session,
                                  const char *domain, const char *item,
                                  mms_variable_access_attrs_t *attrs)
{
    uint32_t i;

    if ((session->control_regs == NULL) || (domain == NULL) ||
        (item == NULL)) {
        return -ENOENT;
    }
    for (i = 0U; i < session->control_reg_count; i++) {
        iec61850_mms_control_reg_t *reg = &session->control_regs[i];

        if ((strcmp(reg->domain, domain) == 0) &&
            (strcmp(reg->item_id, item) == 0)) {
            (void)memset(attrs, 0, sizeof(*attrs));
            (void)strncpy(attrs->name, item,
                          (size_t)MMS_MAX_VARIABLE_NAME - 1U);
            attrs->type = MMS_TYPE_STRUCTURE;
            return 0;
        }
    }
    return -ENOENT;
}

/* Exposed-store helper: create (or re-seed) one component variable. */
static void cw_expose_var(iec61850_mms_data_store_t *store,
                           const char *domain, const char *item,
                           const mms_value_t *initial)
{
    int ret = iec61850_mms_ds_create_variable(store, domain, item,
                                               initial->type, initial);

    if (ret == (int)IEC61850_MMS_DS_ERR_EXISTS) {
        (void)iec61850_mms_ds_write_variable(store, domain, item, initial);
    }
}

/*
 * WP-2w: expose one bridged control object's component variables and
 * install the bridge termination callback (chaining any application
 * callback already registered on the manager).
 */
static void control_bridge_expose_object(iec61850_mms_server_t *server,
                                          iec61850_mms_control_reg_t *reg)
{
    iec61850_mms_data_store_t *store = server->data_store;
    char item[MMS_MAX_VARIABLE_NAME];
    char cf_item[MMS_MAX_VARIABLE_NAME];
    mms_value_t v;
    iec61850_control_object_t *obj = NULL;
    uint32_t i;
    const char *co_pos;
    int32_t ctl_model;
    uint32_t sbo_timeout;
    bool have_cf = false;

    /* Look the object up in the manager (public struct) for its
     * current Ed.2 configuration — read under the manager's locks,
     * mirroring the manager's own accessor pattern. */
    (void)pthread_mutex_lock(&server->control_manager->mutex);
    for (i = 0U; i < server->control_manager->count; i++) {
        iec61850_control_object_t *cand =
            &server->control_manager->objects[i];

        if ((cand->valid) &&
            (strcmp(cand->domain, reg->domain) == 0) &&
            (strcmp(cand->item_id, reg->item_id) == 0)) {
            obj = cand;
            (void)pthread_mutex_lock(&obj->mutex);
            break;
        }
    }
    (void)pthread_mutex_unlock(&server->control_manager->mutex);
    if (obj == NULL) { return; }

    /* Snapshot the Ed.2 configuration and chain the application
     * termination callback (captured under the object lock). */
    reg->app_termination_cb = obj->termination_cb;
    reg->app_termination_user_data = obj->termination_cb_user_data;
    /* ctlModel mapping (conservative): the manager's strict sboClass
     * is sbo-with-normal-security (2), dynamic is direct-with-normal-
     * security (1). sboTimeout serves the effective timeout (the
     * manager's 0 means the default). */
    ctl_model = (obj->sbo_class == IEC61850_CONTROL_SBO_CLASS_DYNAMIC) ?
                    1 : 2;
    sbo_timeout = (obj->sbo_timeout_ms != 0U) ?
                      obj->sbo_timeout_ms :
                      (uint32_t)IEC61850_CONTROL_DEFAULT_TIMEOUT_MS;
    (void)pthread_mutex_unlock(&obj->mutex);

    (void)iec61850_control_set_termination_callback(
        server->control_manager, reg->domain, reg->item_id,
        cw_termination_cb, (void *)server);

    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_INTEGER;
    v.value.integer = ctl_model;
    if (cw_item_suffix(item, sizeof(item), reg->item_id, "$ctlModel") == 0) {
        cw_expose_var(store, reg->domain, item, &v);
    }

    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_UNSIGNED;
    v.value.unsigned_val = sbo_timeout;
    if (cw_item_suffix(item, sizeof(item), reg->item_id,
                       "$sboTimeout") == 0) {
        cw_expose_var(store, reg->domain, item, &v);
    }

    /* 7-2 configuration-attribute spellings ("<LN>$CF$<DO>$...") for
     * conformant clients that read ctlModel from CF. */
    co_pos = strstr(reg->item_id, "$CO$");
    if (co_pos != NULL) {
        size_t head = (size_t)(co_pos - reg->item_id);
        size_t tail_len = strlen(co_pos + 4);

        if ((head + 4U + tail_len + 1U) <= sizeof(cf_item)) {
            (void)memcpy(cf_item, reg->item_id, head);
            (void)memcpy(cf_item + head, "$CF$", 4U);
            (void)memcpy(cf_item + head + 4U, co_pos + 4, tail_len + 1U);
            have_cf = true;
        }
    }
    if (have_cf) {
        (void)memset(&v, 0, sizeof(v));
        v.type = MMS_TYPE_INTEGER;
        v.value.integer = ctl_model;
        if (cw_item_suffix(item, sizeof(item), cf_item, "$ctlModel") == 0) {
            cw_expose_var(store, reg->domain, item, &v);
        }

        (void)memset(&v, 0, sizeof(v));
        v.type = MMS_TYPE_UNSIGNED;
        v.value.unsigned_val = sbo_timeout;
        if (cw_item_suffix(item, sizeof(item), cf_item, "$sboTimeout") == 0) {
            cw_expose_var(store, reg->domain, item, &v);
        }
    }

    /* Oper / SBOw / Cancel: STRUCTURE variables (empty echo) */
    {
        (void)memset(&v, 0, sizeof(v));
        v.type = MMS_TYPE_STRUCTURE;
        v.value.octet_string.data[0] = (uint8_t)MMS_DATA_STRUCTURE;
        v.value.octet_string.data[1] = 0x00U;
        v.value.octet_string.len = 2U;

        if (cw_item_suffix(item, sizeof(item), reg->item_id,
                           CW_CO_SUFFIX_OPER) == 0) {
            cw_expose_var(store, reg->domain, item, &v);
        }
        if (cw_item_suffix(item, sizeof(item), reg->item_id,
                           CW_CO_SUFFIX_SBOW) == 0) {
            cw_expose_var(store, reg->domain, item, &v);
        }
        if (cw_item_suffix(item, sizeof(item), reg->item_id,
                           CW_CO_SUFFIX_CANCEL) == 0) {
            cw_expose_var(store, reg->domain, item, &v);
        }
    }

    /* SBO: VisibleString (empty until selected) */
    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_VISIBLE_STRING;
    v.value.visible_string.len = 0U;
    if (cw_item_suffix(item, sizeof(item), reg->item_id,
                       CW_CO_SUFFIX_SBO) == 0) {
        cw_expose_var(store, reg->domain, item, &v);
    }

    /* OperTm: BOOLEAN (false until a time-activated operate arms) */
    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_BOOLEAN;
    v.value.boolean = false;
    if (cw_item_suffix(item, sizeof(item), reg->item_id, "$OperTm") == 0) {
        cw_expose_var(store, reg->domain, item, &v);
    }
}


/*
 * Process a confirmed request. Returns:
 *   0  = success, resp is populated
 *   1  = error, err is populated (send ConfirmedError)
 *  -1  = conclude (terminate session)
 */
static int process_request(iec61850_mms_session_t *session,
                             const mms_confirmed_request_t *req,
                             mms_confirmed_response_t *resp,
                             mms_confirmed_error_t *err)
{
    int ds_ret;

    (void)memset(resp, 0, sizeof(*resp));
    (void)memset(err, 0, sizeof(*err));
    resp->invoke_id = req->invoke_id;
    resp->service = req->service;
    err->invoke_id = req->invoke_id;

    switch (req->service) {
        case MMS_SERVICE_TYPE_STATUS: {
            resp->params.status.vmd_logical_status = 0;   /* state-changes-allowed */
            resp->params.status.vmd_physical_status = 0;   /* operational */
            return 0;
        }

        case MMS_SERVICE_TYPE_IDENTIFY: {
            (void)strncpy(resp->params.identify.vendor_name, "xdp-iec61850",
                          (size_t)MMS_MAX_VARIABLE_NAME - 1U);
            (void)strncpy(resp->params.identify.model_name, "IEC 61850 XDP Stack",
                          (size_t)MMS_MAX_VARIABLE_NAME - 1U);
            (void)strncpy(resp->params.identify.revision, "1.0.0",
                          (size_t)MMS_MAX_VARIABLE_NAME - 1U);
            return 0;
        }

        case MMS_SERVICE_TYPE_READ: {
            /* SGCB bridge: SGCB attributes and SE (setting-group)
             * values are served from the manager, not the store. */
            if (session->sg_manager != NULL) {
                int sg_ret = iec61850_sg_bridge_read(
                    session->sg_manager,
                    req->params.read.variable_spec.domain,
                    req->params.read.variable_spec.item_id,
                    &resp->params.read.value);
                if (sg_ret == 0) {
                    return 0;
                }
            }

            /* WP-2w: control-object read dispatch — the "$SBO"
             * read-select of 8-1 sbo-with-normal-security. */
            if (session->control_reg_count > 0U) {
                int ctl_ret = session_control_read(
                    session, req->params.read.variable_spec.domain,
                    req->params.read.variable_spec.item_id,
                    &resp->params.read);
                if (ctl_ret == 0) { return 0; }
                /* -ENOENT: ordinary variable read */
            }
            ds_ret = iec61850_mms_ds_read_variable(session->data_store,
                                                      req->params.read.variable_spec.domain,
                                                      req->params.read.variable_spec.item_id,
                                                      &resp->params.read.value);
            if (ds_ret == (int)IEC61850_MMS_DS_OK) {
                return 0;
            }

            /* IEC 61850-8-1 §8.8: reading a named variable list by item_id returns
             * a STRUCTURE containing the list member values as AccessResults.
             * This is how RCB objects (e.g. LLN0$RP$EventsRCB01) are read whole. */
            {
                mms_variable_spec_t list_vars[MMS_MAX_NAMED_VARIABLES];
                uint32_t list_count = 0;
                int list_ret = iec61850_mms_ds_get_list_attrs(
                    session->data_store,
                    req->params.read.variable_spec.domain,
                    req->params.read.variable_spec.item_id,
                    list_vars, &list_count, MMS_MAX_NAMED_VARIABLES);
                if (list_ret == (int)IEC61850_MMS_DS_OK && list_count > 0U) {
                    /* Encode each member value directly into the response buffer as a
                     * structure [2] IMPLICIT SEQUENCE OF AccessResult. The caller's
                     * mms_encode_response() for MMS_SERVICE_TYPE_READ wraps it in
                     * listOfAccessResult [1]; we return the inner structure value. */
                    resp->service = MMS_SERVICE_TYPE_READ_NAMED_VARLIST;
                    resp->params.readnamedvarlist.num_values = 0;
                    for (uint32_t vi = 0; vi < list_count && vi < MMS_MAX_NAMED_VARIABLES; vi++) {
                        int vr = iec61850_mms_ds_read_variable(
                            session->data_store,
                            list_vars[vi].domain,
                            list_vars[vi].item_id,
                            &resp->params.readnamedvarlist.values[vi]);
                        if (vr != (int)IEC61850_MMS_DS_OK) {
                            map_ds_error(vr, &err->error);
                            return 1;
                        }
                        resp->params.readnamedvarlist.num_values++;
                    }
                    return 0;
                }
            }

            map_ds_error(ds_ret, &err->error);
            return 1;
        }

        case MMS_SERVICE_TYPE_WRITE: {
            /* WP-2x: pre-commit RCB bridge dispatch. The bridge
             * validates and applies Ed.2 RCB component writes itself;
             * on success it committed the variable (the store write is
             * skipped), on -ENOENT the item is an ordinary variable,
             * and any other negative is an Ed.2 rejection surfaced as
             * a real MMS Write failure (in-band DataAccessError, the
             * code the WP-1c/1f client maps to ERR_MMS/ERR_RCB_OWNER). */
            if (session->rcb_reg_count > 0U) {
                int rcb_ret = session_rcb_write(
                    session,
                    req->params.write.variable_spec.domain,
                    req->params.write.variable_spec.item_id,
                    &req->params.write.value);
                if (rcb_ret == 0) {
                    return 0;   /* bridge committed the component */
                }
                if (rcb_ret != -ENOENT) {
                    resp->params.write.failure = true;
                    resp->params.write.access_error =
                        (rcb_ret == -EINVAL) ?
                            (int32_t)MMS_DATAACCESS_TYPE_INCONSISTENT :
                            (int32_t)MMS_DATAACCESS_TEMPORARILY_UNAVAILABLE;
                    return 0;   /* Write-Response failure */
                }
            }

            /* SGCB bridge: ActSG/EditSG selection and SE
             * (setting-group) value writes are validated and
             * committed by the manager; the live model is only
             * touched on activation. */
            if (session->sg_manager != NULL) {
                int sg_ret = iec61850_sg_bridge_write(
                    session->sg_manager,
                    req->params.write.variable_spec.domain,
                    req->params.write.variable_spec.item_id,
                    &req->params.write.value,
                    (void *)session);
                if (sg_ret == 0) {
                    return 0;   /* bridge committed the variable */
                }
                if (sg_ret != -ENOENT) {
                    resp->params.write.failure = true;
                    resp->params.write.access_error =
                        (sg_ret == -EINVAL) ?
                            (int32_t)MMS_DATAACCESS_TYPE_INCONSISTENT :
                            (int32_t)MMS_DATAACCESS_TEMPORARILY_UNAVAILABLE;
                    return 0;   /* Write-Response failure */
                }
            }

            /* WP-2w: control-object bridge dispatch (after the RCB
             * bridge, before the store). Select/SelectWithValue/
             * Operate/Cancel writes are applied by the control
             * manager; Ed.2 rejections (e.g. an operate without a
             * prior select on a strict object) surface as in-band
             * Write-Response failures, malformed control structures
             * as type-inconsistent failures. */
            if (session->control_reg_count > 0U) {
                int ctl_ret = session_control_write(
                    session,
                    req->params.write.variable_spec.domain,
                    req->params.write.variable_spec.item_id,
                    &req->params.write.value);
                if (ctl_ret == 0) {
                    return 0;   /* bridge applied the control write */
                }
                if (ctl_ret != -ENOENT) {
                    resp->params.write.failure = true;
                    resp->params.write.access_error =
                        (ctl_ret == -EINVAL) ?
                            (int32_t)MMS_DATAACCESS_TYPE_INCONSISTENT :
                            (int32_t)MMS_DATAACCESS_TEMPORARILY_UNAVAILABLE;
                    return 0;   /* Write-Response failure */
                }
            }
            ds_ret = iec61850_mms_ds_write_variable(session->data_store,
                                                       req->params.write.variable_spec.domain,
                                                       req->params.write.variable_spec.item_id,
                                                       &req->params.write.value);
            if (ds_ret != (int)IEC61850_MMS_DS_OK) {
                map_ds_error(ds_ret, &err->error);
                return 1;
            }
            return 0;
        }

        case MMS_SERVICE_TYPE_GET_NAMELIST: {
            /* Get all names into a temp buffer, then apply continueAfter filter */
            char all_names[MMS_MAX_NAMELIST_ITEMS][MMS_MAX_VARIABLE_NAME];
            uint32_t total = 0;

            if (req->params.getnamelist.object_class == MMS_OBJECT_CLASS_DOMAIN) {
                (void)iec61850_mms_ds_get_domain_names(session->data_store,
                                                        all_names, &total,
                                                        MMS_MAX_NAMELIST_ITEMS);
            } else if (req->params.getnamelist.object_class == MMS_OBJECT_CLASS_NAMED_VARIABLE) {
                (void)iec61850_mms_ds_get_var_names(session->data_store,
                                                      req->params.getnamelist.domain,
                                                      all_names, &total,
                                                      MMS_MAX_NAMELIST_ITEMS);
            }

            /* Apply continueAfter: skip until we find the token, then start from next */
            uint32_t start = 0;
            if (req->params.getnamelist.continue_after) {
                for (uint32_t i = 0; i < total; i++) {
                    if (strcmp(all_names[i], req->params.getnamelist.continue_after_id) == 0) {
                        start = i + 1U;
                        break;
                    }
                }
            }

            /* Copy up to MMS_MAX_NAMELIST_ITEMS from the start position */
            uint32_t remaining = (start < total) ? (total - start) : 0U;
            uint32_t to_copy = remaining;
            if (to_copy > (uint32_t)MMS_MAX_NAMELIST_ITEMS) {
                to_copy = (uint32_t)MMS_MAX_NAMELIST_ITEMS;
            }

            resp->params.getnamelist.num_identifiers = to_copy;
            for (uint32_t i = 0; i < to_copy; i++) {
                (void)memcpy(resp->params.getnamelist.identifiers[i],
                             all_names[start + i], MMS_MAX_VARIABLE_NAME);
            }
            resp->params.getnamelist.more_follows = ((start + to_copy) < total);
            return 0;
        }

        case MMS_SERVICE_TYPE_GET_VARIABLE_ATTRS: {
            mms_variable_access_attrs_t attrs;
            (void)memset(&attrs, 0, sizeof(attrs));
            /* WP-2w: a bridged control object ("<LN>$CO$<DO>") is a
             * structure of its component objects. */
            if (session->control_reg_count > 0U) {
                if (session_control_attrs(
                        session,
                        req->params.getvariableattrs.variable_spec.domain,
                        req->params.getvariableattrs.variable_spec.item_id,
                        &attrs) == 0) {
                    resp->params.getvariableattrs.attributes = attrs;
                    return 0;
                }
            }
            ds_ret = iec61850_mms_ds_get_variable_attrs(
                session->data_store,
                req->params.getvariableattrs.variable_spec.domain,
                req->params.getvariableattrs.variable_spec.item_id,
                &attrs);
            if (ds_ret == (int)IEC61850_MMS_DS_OK) {
                resp->params.getvariableattrs.attributes = attrs;
            } else {
                map_ds_error(ds_ret, &err->error);
                return 1;
            }
            return 0;
        }

        case MMS_SERVICE_TYPE_DEFINE_NAMED_VARLIST: {
            ds_ret = iec61850_mms_ds_define_list(
                session->data_store,
                req->params.definenamedvarlist.domain,
                req->params.definenamedvarlist.list_name,
                req->params.definenamedvarlist.variables,
                req->params.definenamedvarlist.num_variables);
            if (ds_ret != (int)IEC61850_MMS_DS_OK) {
                map_ds_error(ds_ret, &err->error);
                return 1;
            }
            return 0;
        }

        case MMS_SERVICE_TYPE_DELETE_NAMED_VARLIST: {
            ds_ret = iec61850_mms_ds_delete_list(
                session->data_store,
                req->params.deletenamedvarlist.domain,
                req->params.deletenamedvarlist.list_name);
            if (ds_ret != (int)IEC61850_MMS_DS_OK) {
                map_ds_error(ds_ret, &err->error);
                return 1;
            }
            return 0;
        }

        case MMS_SERVICE_TYPE_GET_NAMED_VARLIST_ATTRS: {
            uint32_t count = 0;
            ds_ret = iec61850_mms_ds_get_list_attrs(
                session->data_store,
                req->params.getnamedvarlistattrs.domain,
                req->params.getnamedvarlistattrs.list_name,
                resp->params.getnamedvarlistattrs.variables,
                &count, MMS_MAX_NAMED_VARIABLES);
            if (ds_ret != (int)IEC61850_MMS_DS_OK) {
                map_ds_error(ds_ret, &err->error);
                return 1;
            }
            resp->params.getnamedvarlistattrs.num_variables = count;
            return 0;
        }

        case MMS_SERVICE_TYPE_SELECT: {
            if (session->control_manager == NULL) {
                err->error.error_class = MMS_ERROR_CLASS_SERVICE;
                err->error.error_code = MMS_SERVICE_ERROR_OTHER;
                return 1;
            }
            ds_ret = iec61850_control_select(
                session->control_manager,
                req->params.select.control_object.domain,
                req->params.select.control_object.item_id,
                session->session_id,
                &resp->params.select);
            if (ds_ret != 0) {
                err->error.error_class = MMS_ERROR_CLASS_ACCESS;
                err->error.error_code = MMS_ACCESS_ERROR_OBJECT_NON_EXISTENT;
                return 1;
            }
            return 0;
        }

        case MMS_SERVICE_TYPE_SELECT_WITH_VALUE: {
            if (session->control_manager == NULL) {
                err->error.error_class = MMS_ERROR_CLASS_SERVICE;
                err->error.error_code = MMS_SERVICE_ERROR_OTHER;
                return 1;
            }
            ds_ret = iec61850_control_select_with_value(
                session->control_manager,
                req->params.select_with_value.control_object.domain,
                req->params.select_with_value.control_object.item_id,
                session->session_id,
                &req->params.select_with_value.control_value,
                &resp->params.select_with_value);
            if (ds_ret != 0) {
                err->error.error_class = MMS_ERROR_CLASS_ACCESS;
                err->error.error_code = MMS_ACCESS_ERROR_OBJECT_NON_EXISTENT;
                return 1;
            }
            return 0;
        }

        case MMS_SERVICE_TYPE_OPERATE: {
            if (session->control_manager == NULL) {
                err->error.error_class = MMS_ERROR_CLASS_SERVICE;
                err->error.error_code = MMS_SERVICE_ERROR_OTHER;
                return 1;
            }
            ds_ret = iec61850_control_operate(
                session->control_manager,
                req->params.operate.control_object.domain,
                req->params.operate.control_object.item_id,
                (iec61850_control_ids_t){
                    .session_id   = session->session_id,
                    .selection_id = req->params.operate.selection_id,
                },
                &resp->params.operate);
            if (ds_ret != 0) {
                err->error.error_class = MMS_ERROR_CLASS_ACCESS;
                err->error.error_code = MMS_ACCESS_ERROR_OBJECT_NON_EXISTENT;
                return 1;
            }
            return 0;
        }

        case MMS_SERVICE_TYPE_CANCEL: {
            if (session->control_manager == NULL) {
                err->error.error_class = MMS_ERROR_CLASS_SERVICE;
                err->error.error_code = MMS_SERVICE_ERROR_OTHER;
                return 1;
            }
            ds_ret = iec61850_control_cancel(
                session->control_manager,
                req->params.cancel.control_object.domain,
                req->params.cancel.control_object.item_id,
                (iec61850_control_ids_t){
                    .session_id   = session->session_id,
                    .selection_id = req->params.cancel.selection_id,
                });
            if (ds_ret != 0) {
                err->error.error_class = MMS_ERROR_CLASS_ACCESS;
                err->error.error_code = MMS_ACCESS_ERROR_OBJECT_NON_EXISTENT;
                return 1;
            }
            return 0;
        }

        case MMS_SERVICE_TYPE_FILE_OPEN: {
            if (session->file_service == NULL) {
                err->error.error_class = MMS_ERROR_CLASS_SERVICE;
                err->error.error_code = MMS_SERVICE_ERROR_OTHER;
                return 1;
            }
            uint32_t fsize = 0;
            int fh = iec61850_mms_file_open(session->file_service,
                                              req->params.fileopen.filename,
                                              &fsize);
            if (fh < 0) {
                err->error.error_class = MMS_ERROR_CLASS_ACCESS;
                err->error.error_code = MMS_ACCESS_ERROR_OBJECT_NON_EXISTENT;
                return 1;
            }
            resp->params.fileopen.file_handle = (uint32_t)fh;
            resp->params.fileopen.file_size = fsize;
            return 0;
        }

        case MMS_SERVICE_TYPE_FILE_READ: {
            if (session->file_service == NULL) {
                err->error.error_class = MMS_ERROR_CLASS_SERVICE;
                err->error.error_code = MMS_SERVICE_ERROR_OTHER;
                return 1;
            }
            size_t read_len = 0;
            bool more = false;
            ds_ret = iec61850_mms_file_read(
                session->file_service,
                (int)req->params.fileread.file_handle,
                resp->params.fileread.data,
                sizeof(resp->params.fileread.data),
                &read_len, &more);
            if (ds_ret != (int)IEC61850_MMS_FILE_OK) {
                err->error.error_class = MMS_ERROR_CLASS_ACCESS;
                err->error.error_code = MMS_ACCESS_ERROR_OBJECT_NON_EXISTENT;
                return 1;
            }
            resp->params.fileread.bytes_read = (uint32_t)read_len;
            resp->params.fileread.more_follows = more;
            return 0;
        }

        case MMS_SERVICE_TYPE_FILE_CLOSE: {
            if (session->file_service == NULL) {
                err->error.error_class = MMS_ERROR_CLASS_SERVICE;
                err->error.error_code = MMS_SERVICE_ERROR_OTHER;
                return 1;
            }
            ds_ret = iec61850_mms_file_close(
                session->file_service,
                (int)req->params.fileclose.file_handle);
            if (ds_ret != (int)IEC61850_MMS_FILE_OK) {
                err->error.error_class = MMS_ERROR_CLASS_ACCESS;
                err->error.error_code = MMS_ACCESS_ERROR_OBJECT_NON_EXISTENT;
                return 1;
            }
            return 0;
        }

        case MMS_SERVICE_TYPE_FILE_DELETE: {
            if (session->file_service == NULL) {
                err->error.error_class = MMS_ERROR_CLASS_SERVICE;
                err->error.error_code = MMS_SERVICE_ERROR_OTHER;
                return 1;
            }
            ds_ret = iec61850_mms_file_delete(
                session->file_service,
                req->params.filedelete.filename);
            if (ds_ret != (int)IEC61850_MMS_FILE_OK) {
                err->error.error_class = MMS_ERROR_CLASS_ACCESS;
                err->error.error_code = MMS_ACCESS_ERROR_OBJECT_NON_EXISTENT;
                return 1;
            }
            return 0;
        }

        case MMS_SERVICE_TYPE_FILE_DIRECTORY: {
            if (session->file_service == NULL) {
                err->error.error_class = MMS_ERROR_CLASS_SERVICE;
                err->error.error_code = MMS_SERVICE_ERROR_OTHER;
                return 1;
            }
            uint32_t count = 0;
            ds_ret = iec61850_mms_file_get_directory(
                session->file_service,
                req->params.filedirectory.file_specification,
                (iec61850_mms_file_entry_t *)resp->params.filedirectory.entries,
                &count, MMS_MAX_NAMELIST_ITEMS);
            if (ds_ret != (int)IEC61850_MMS_FILE_OK) {
                err->error.error_class = MMS_ERROR_CLASS_SERVICE;
                err->error.error_code = MMS_SERVICE_ERROR_OTHER;
                return 1;
            }
            resp->params.filedirectory.num_entries = count;
            resp->params.filedirectory.more_follows = false;
            return 0;
        }

        case MMS_SERVICE_TYPE_READ_JOURNAL: {
            if (session->journal == NULL) {
                err->error.error_class = MMS_ERROR_CLASS_SERVICE;
                err->error.error_code = MMS_SERVICE_ERROR_OTHER;
                return 1;
            }
            uint32_t j_count = 0;
            iec61850_journal_entry_t j_entries[MMS_MAX_JOURNAL_ENTRIES];
            if (req->params.readjournal.start_entry_id > 0ULL) {
                (void)iec61850_journal_read_by_id(
                    session->journal,
                    req->params.readjournal.start_entry_id,
                    j_entries, &j_count,
                    (req->params.readjournal.max_entries > 0U) ?
                        req->params.readjournal.max_entries :
                        (uint32_t)MMS_MAX_JOURNAL_ENTRIES);
            } else {
                (void)iec61850_journal_read_by_time(
                    session->journal,
                    req->params.readjournal.start_time,
                    req->params.readjournal.end_time,
                    j_entries, &j_count,
                    (req->params.readjournal.max_entries > 0U) ?
                        req->params.readjournal.max_entries :
                        (uint32_t)MMS_MAX_JOURNAL_ENTRIES);
            }
            for (uint32_t ji = 0;
                 (ji < j_count) && (ji < (uint32_t)MMS_MAX_JOURNAL_ENTRIES); ji++) {
                resp->params.readjournal.entries[ji].entry_id =
                    j_entries[ji].entry_id;
                resp->params.readjournal.entries[ji].timestamp =
                    j_entries[ji].timestamp_ms;
                (void)strncpy(
                    resp->params.readjournal.entries[ji].variable_ref,
                    j_entries[ji].variable_ref,
                    (size_t)MMS_MAX_VARIABLE_NAME - 1U);
            }
            resp->params.readjournal.num_entries = j_count;
            resp->params.readjournal.more_follows = false;
            return 0;
        }

        case MMS_SERVICE_TYPE_INITIALIZE_JOURNAL: {
            if (session->journal == NULL) {
                err->error.error_class = MMS_ERROR_CLASS_SERVICE;
                err->error.error_code = MMS_SERVICE_ERROR_OTHER;
                return 1;
            }
            iec61850_journal_init(session->journal,
                                   req->params.initializejournal.journal_name);
            return 0;
        }

        case MMS_SERVICE_TYPE_READ_NAMED_VARLIST: {
            /* Read all variables in a named variable list */
            mms_variable_spec_t list_vars[MMS_MAX_NAMED_VARIABLES];
            uint32_t list_count = 0;
            ds_ret = iec61850_mms_ds_get_list_attrs(
                session->data_store,
                req->params.readnamedvarlist.domain,
                req->params.readnamedvarlist.list_name,
                list_vars, &list_count, MMS_MAX_NAMED_VARIABLES);
            if (ds_ret != (int)IEC61850_MMS_DS_OK) {
                map_ds_error(ds_ret, &err->error);
                return 1;
            }
            resp->params.readnamedvarlist.num_values = 0;
            for (uint32_t vi = 0; vi < list_count; vi++) {
                ds_ret = iec61850_mms_ds_read_variable(
                    session->data_store,
                    list_vars[vi].domain,
                    list_vars[vi].item_id,
                    &resp->params.readnamedvarlist.values[vi]);
                if (ds_ret != (int)IEC61850_MMS_DS_OK) {
                    map_ds_error(ds_ret, &err->error);
                    return 1;
                }
                resp->params.readnamedvarlist.num_values++;
            }
            return 0;
        }

        case MMS_SERVICE_TYPE_WRITE_NAMED_VARLIST: {
            /* Write all variables in a named variable list */
            mms_variable_spec_t wl_vars[MMS_MAX_NAMED_VARIABLES];
            uint32_t wl_count = 0;
            ds_ret = iec61850_mms_ds_get_list_attrs(
                session->data_store,
                req->params.writenamedvarlist.domain,
                req->params.writenamedvarlist.list_name,
                wl_vars, &wl_count, MMS_MAX_NAMED_VARIABLES);
            if (ds_ret != (int)IEC61850_MMS_DS_OK) {
                map_ds_error(ds_ret, &err->error);
                return 1;
            }
            if (req->params.writenamedvarlist.num_values != wl_count) {
                err->error.error_class = MMS_ERROR_CLASS_ACCESS;
                err->error.error_code = MMS_ACCESS_ERROR_TYPE_INCONSISTENT;
                return 1;
            }
            for (uint32_t vi = 0; vi < wl_count; vi++) {
                ds_ret = iec61850_mms_ds_write_variable(
                    session->data_store,
                    wl_vars[vi].domain,
                    wl_vars[vi].item_id,
                    &req->params.writenamedvarlist.values[vi]);
                if (ds_ret != (int)IEC61850_MMS_DS_OK) {
                    map_ds_error(ds_ret, &err->error);
                    return 1;
                }
            }
            return 0;
        }

        case MMS_SERVICE_TYPE_DEFINE_NAMED_TYPE:
        case MMS_SERVICE_TYPE_DELETE_NAMED_TYPE:
        case MMS_SERVICE_TYPE_GET_NAMED_TYPE_ATTRS:
        case MMS_SERVICE_TYPE_COMMAND_TERMINATION: {
            /* Named type services are not used by IEC 61850 (types are
             * inferred from the data model). CommandTermination is an
             * unconfirmed service (server→client); receiving it as a
             * request is invalid. Return service error per ISO 9506-2. */
            err->error.error_class = MMS_ERROR_CLASS_SERVICE;
            err->error.error_code = MMS_SERVICE_ERROR_OTHER;
            return 1;
        }

        default:
            /* Unsupported service — send ConfirmedError */
            err->error.error_class = MMS_ERROR_CLASS_SERVICE;
            err->error.error_code = MMS_SERVICE_ERROR_OTHER;
            return 1;
    }
}

/* Session thread */
static void *session_thread(void *arg)
{
    /* MISRA 11.5: pthread arg is opaque void*, deviation Cat. 3 */
    iec61850_mms_session_t *session = (iec61850_mms_session_t *)arg;
    uint8_t recv_buf[IEC61850_MMS_MAX_PDU_SIZE];
    uint8_t resp_buf[IEC61850_MMS_MAX_PDU_SIZE];
    size_t recv_len;
    int ret;

    /* Accept ISO association */
    uint8_t mms_init_resp[256];
    mms_initiate_response_t init_resp;
    (void)memset(&init_resp, 0, sizeof(init_resp));
    init_resp.negotiated_max_pdu_size = session->max_pdu_size;
    init_resp.negotiated_data_structure_nesting_level = 4;
    init_resp.negotiated_version_number = 1;

    ret = mms_encode_initiate_response(&init_resp, mms_init_resp,
                                         sizeof(mms_init_resp));
    if (ret <= 0) { goto done; }

    uint8_t mms_init_req[4096];
    size_t mms_init_req_len = sizeof(mms_init_req);
    ret = iec61850_iso_accept(&session->iso, mms_init_resp, (size_t)ret,
                                mms_init_req, &mms_init_req_len, 30000);
    if (ret != 0) { goto done; }

    /* Main request loop */
    while (!atomic_load(&session->stop_requested)) {
        ret = iec61850_iso_recv(&session->iso, recv_buf, sizeof(recv_buf),
                                  &recv_len, 5000);
        if (ret == IEC61850_TRANSPORT_ERR_TIMEOUT) {
            /* WP-2x: periodic RCB bridge processing. The loop blocks
             * in recv with a 5 s timeout, so the timeout tick is the
             * natural (thread-free) place for the full two-way sweep:
             * closed BufTm windows flush and buffered reports deliver
             * with no incoming client request. */
            for (uint32_t ri = 0U; ri < session->rcb_reg_count; ri++) {
                iec61850_rcb_bridge_sync(session->rcb_regs[ri].manager);
            }
            /* WP-2w: periodic control processing (selection-timeout
             * cleanup, time-activated operate firing) — the same
             * tick, thread-free. WP-C3: the flush sends the
             * CommandTermination of any operTm command that just
             * fired (no response is in flight on this path). */
            if (session->control_reg_count > 0U) {
                iec61850_control_process(session->control_manager);
                cw_flush_pending_ct(session->server);
            }
            continue;
        }
        if (ret != 0) {
            break;
        }

        /* Check for Conclude request */
        if ((recv_len >= 1U) && (recv_buf[0] == (uint8_t)MMS_TAG_CONCLUDE_REQUEST)) {
            /* Send Conclude response and exit */
            uint8_t conclude_resp[2] = { MMS_TAG_CONCLUDE_RESPONSE, 0x00 };
            (void)iec61850_iso_send(&session->iso, conclude_resp, 2);
            break;
        }

        /* Decode confirmed request (returns consumed bytes > 0 on success).
         * Zero-init so optional bool fields (e.g. continue_after) are false
         * when absent from the BER encoding, preventing UBSan false values. */
        mms_confirmed_request_t req = {0};
        ret = mms_decode_confirmed_request(recv_buf, recv_len, &req);
        if (ret < 0) {
            break;
        }

        /* Process and build response */
        mms_confirmed_response_t resp;
        mms_confirmed_error_t err;
        int proc_ret = process_request(session, &req, &resp, &err);

        if (proc_ret == 0) {
            /* Success — send confirmed response */
            ret = mms_encode_confirmed_response(&resp, resp_buf,
                                                  sizeof(resp_buf));
            if (ret <= 0) { break; }
            ret = iec61850_iso_send(&session->iso, resp_buf, (size_t)ret);
            if (ret < 0) { break; }
            /* Post-response processing while the session is still
             * active. The domain/item of the just-served request feed
             * both the server-owned RCB bridge reconcile (WP-2x: no
             * application hook needed) and the application-level
             * after_response callback, which may send unsolicited PDUs
             * (e.g. InformationReport) without sleeping or polling. */
            {
                const char *cb_domain = "";
                const char *cb_item   = "";
                switch (req.service) {
                    case MMS_SERVICE_TYPE_READ:
                    case MMS_SERVICE_TYPE_READ_NAMED_VARLIST:
                        cb_domain = req.params.read.variable_spec.domain;
                        cb_item   = req.params.read.variable_spec.item_id;
                        break;
                    case MMS_SERVICE_TYPE_WRITE:
                        cb_domain = req.params.write.variable_spec.domain;
                        cb_item   = req.params.write.variable_spec.item_id;
                        break;
                    default:
                        break;
                }
                session_rcb_reconcile(session, cb_domain, cb_item);
                /* WP-2w: post-response control processing — an armed
                 * time-activated operate (operTm) that came due fires
                 * here while the association is hot, without waiting
                 * for the recv-timeout tick. WP-C3: the deferred
                 * CommandTermination flush runs here too — the
                 * response is on the wire, so the 8-1 ordering
                 * (Write-Response first, CT after) holds for both the
                 * operate just serviced and any operTm command that
                 * fired above. */
                if (session->control_reg_count > 0U) {
                    iec61850_control_process(session->control_manager);
                    cw_flush_pending_ct(session->server);
                }
                if (session->after_response != NULL) {
                    session->after_response(session, cb_domain, cb_item,
                                            session->after_response_user_data);
                }
            }
        } else if (proc_ret == 1) {
            /* Error — send confirmed error */
            ret = mms_encode_confirmed_error(&err, resp_buf,
                                               sizeof(resp_buf));
            if (ret <= 0) { break; }
            ret = iec61850_iso_send(&session->iso, resp_buf, (size_t)ret);
            if (ret < 0) { break; }
        } else {
            /* Conclude or fatal — exit */
            break;
        }
    }

done:
    /* WP-2x: session teardown releases the RCB bridge association when
     * this session owns it. The check-then-clear cannot race with
     * another session adopting ownership: while this session is still
     * marked active, the bridge sees a live association and refuses
     * every foreign adoption (bridge_adopt_association / Ed.2 owner
     * checks). URCBs are disabled and their reservation/Owner
     * released; BRCBs stay enabled and keep buffering for resume. */
    for (uint32_t ri = 0U; ri < session->rcb_reg_count; ri++) {
        iec61850_rcb_manager_t *mgr = session->rcb_regs[ri].manager;

        if (mgr->bridge.association == (void *)session) {
            iec61850_rcb_bridge_clear_association(mgr);
        }
    }
    /* WP-6x follow-up: session teardown releases the SGCB edit
     * reservation when this session holds it (8-1 association-loss
     * semantics — the same contract the RCB and control bridges
     * implement above; ResvTms expiry is the fallback for hosts
     * wiring the manager without the server). */
    if (session->sg_manager != NULL) {
        iec61850_sg_release_owner(session->sg_manager, (void *)session);
    }

    /* WP-2w: session teardown releases control-object selections (and
     * aborts time-activated operates) this session owns — the 8-1
     * association-loss semantics; sboTimeout is the fallback for
     * hosts wiring the manager without the bridge. The cancel uses
     * the bridge-recorded selection ID, so it passes the manager's
     * owner/selection checks; results are ignored (the association is
     * going away). */
    if (session->control_reg_count > 0U) {
        for (uint32_t ci = 0U; ci < session->control_reg_count; ci++) {
            iec61850_mms_control_reg_t *reg = &session->control_regs[ci];
            uint32_t selection_id = 0U;
            bool owned = false;

            (void)pthread_mutex_lock(
                &session->server->control_bridge_mutex);
            if (reg->owner_session == (void *)session) {
                selection_id = reg->selection_id;
                reg->selection_id = 0U;
                reg->owner_session = NULL;
                /* WP-C3: the association is going away — drop any
                 * deferred CommandTermination with the ownership so
                 * a later flush cannot fire it at a new owner. */
                reg->pending_termination = false;
                owned = true;
            }
            (void)pthread_mutex_unlock(
                &session->server->control_bridge_mutex);

            if (owned) {
                (void)iec61850_control_cancel(
                    session->control_manager, reg->domain, reg->item_id,
                    (iec61850_control_ids_t){
                        .session_id = session->session_id,
                        .selection_id = selection_id,
                    });
            }
        }
    }
    iec61850_iso_disconnect(&session->iso);
    atomic_store(&session->active, false);
    return NULL;
}

/*
 * Spawn a session thread for an accepted transport (plain TCP or
 * TLS-handshaked). pending carries the accepted connection: either
 * a plain tcp member (use_tls false) or a completed TLS connection
 * (use_tls true). Consumes pending on success (the session owns the
 * association); disconnects it when no slot or thread is available.
 */
static void accept_spawn_session(iec61850_mms_server_t *server,
                                   iec61850_iso_conn_t *pending)
{
    uint32_t i;
    bool assigned = false;

    /* Find a free session slot */
    for (i = 0U; (i < server->config.max_sessions) &&
         (i < (uint32_t)IEC61850_MMS_MAX_SESSIONS); i++) {
        if (!atomic_load(&server->sessions[i].active)) {
            iec61850_mms_session_t *sess = &server->sessions[i];
            iec61850_iso_conn_init(&sess->iso);
            if (pending->use_tls) {
                /* WP-3b: TLS association (IEC 62351-4) — the socket
                 * and SSL state live in the embedded TLS conn. */
                sess->iso.tls = pending->tls;
                sess->iso.use_tls = true;
            } else {
                sess->iso.tcp = pending->tcp;
                sess->iso.tcp.connected = true;
            }
            sess->data_store = server->data_store;
            sess->server = server;   /* WP-2w: bridge context */
            sess->control_manager = server->control_manager;
            sess->file_service = server->file_service;
            sess->journal = server->journal;
            sess->rcb_regs = server->rcb_regs;   /* WP-2x (fixed before start) */
            sess->rcb_reg_count = server->rcb_reg_count;
            sess->sg_manager = server->sg_manager;
            sess->control_regs = server->control_regs;  /* WP-2w (fixed before start) */
            sess->control_reg_count = server->control_reg_count;
            sess->max_pdu_size = server->config.max_pdu_size;
            sess->invoke_id = 0;
            sess->session_id = server->next_session_id; server->next_session_id++;
            sess->after_response = server->config.after_response;
            sess->after_response_user_data = server->config.after_response_user_data;
            atomic_store(&sess->active, true);
            atomic_store(&sess->stop_requested, false);
            atomic_fetch_add(&server->active_session_count, 1);

            if (pthread_create(&sess->thread, NULL, session_thread, sess) != 0) {
                atomic_store(&sess->active, false);
                atomic_fetch_sub(&server->active_session_count, 1);
                (void)iec61850_iso_disconnect(pending);
            }
            /* Thread is joinable — joined during server stop */
            assigned = true;
            break;
        }
    }

    if (!assigned) {
        (void)iec61850_iso_disconnect(pending);
    }
}

/* Accept thread */
static void *accept_thread(void *arg)
{
    /* MISRA 11.5: pthread arg is opaque void*, deviation Cat. 3 */
    iec61850_mms_server_t *server = (iec61850_mms_server_t *)arg;

    while (!atomic_load(&server->stop_requested)) {
#ifdef IEC61850_SECURITY_ENABLED
        /*
         * WP-3b: TLS-enabled servers poll the plain listener (when
         * bound) and the TLS listener together; one ready listener
         * is served per iteration. The single accept thread of the
         * existing thread model covers both.
         */
        if (server->config.tls_enabled) {
            struct pollfd pfds[2];
            int n = 0;
            int plain_idx = -1;
            int tls_idx = -1;
            int poll_ret;

            if (!server->config.tls_only) {
                pfds[n].fd = server->listener.sockfd;
                pfds[n].events = POLLIN;
                pfds[n].revents = 0;
                plain_idx = n;
                n++;
            }
            pfds[n].fd = server->tls_listener.tcp.sockfd;
            pfds[n].events = POLLIN;
            pfds[n].revents = 0;
            tls_idx = n;
            n++;

            poll_ret = poll(pfds, (nfds_t)n, server->config.accept_timeout_ms);
            if (poll_ret == 0) { continue; }
            if (poll_ret < 0) { break; }

            if ((tls_idx >= 0) &&
                ((pfds[tls_idx].revents & POLLIN) != 0)) {
                iec61850_iso_conn_t pending;

                iec61850_iso_conn_init(&pending);
                /* TLS accept: TCP accept + server-side handshake
                 * (bounded like the ISO session accept timeout) */
                if (iec61850_tls_listener_accept(&server->tls_listener,
                                                   &pending.tls,
                                                   30000) == 0) {
                    pending.use_tls = true;
                    accept_spawn_session(server, &pending);
                }
                continue;
            }

            if ((plain_idx >= 0) &&
                ((pfds[plain_idx].revents & POLLIN) != 0)) {
                iec61850_iso_conn_t pending;

                iec61850_iso_conn_init(&pending);
                if (iec61850_tcp_listener_accept(&server->listener,
                                                   &pending.tcp,
                                                   0) == 0) {
                    pending.tcp.connected = true;
                    accept_spawn_session(server, &pending);
                }
                continue;
            }

            continue;
        }
#endif /* IEC61850_SECURITY_ENABLED */

        {
            iec61850_iso_conn_t pending;
            int ret;

            iec61850_iso_conn_init(&pending);
            ret = iec61850_tcp_listener_accept(&server->listener,
                                                &pending.tcp,
                                                server->config.accept_timeout_ms);
            if (ret == IEC61850_TRANSPORT_ERR_TIMEOUT) {
                continue;
            }
            if (ret != 0) {
                break;
            }
            pending.tcp.connected = true;
            accept_spawn_session(server, &pending);
        }
    }

    atomic_store(&server->running, false);
    return NULL;
}

int iec61850_mms_server_set_rcb_manager_domain(
    iec61850_mms_server_t *server, iec61850_rcb_manager_t *mgr,
    const char *domain)
{
    size_t len;
    uint32_t i;

    if ((server == NULL) || (mgr == NULL) || (domain == NULL)) {
        return -EINVAL;
    }
    /* Registrations are copied into sessions at accept time; refuse
     * while running so no session can miss a registration. */
    if (atomic_load(&server->running)) { return -EBUSY; }

    len = strlen(domain);
    if ((len == 0U) || (len >= (size_t)MMS_MAX_DOMAIN_NAME)) {
        return -EINVAL;
    }
    for (i = 0U; i < server->rcb_reg_count; i++) {
        if (server->rcb_regs[i].manager == mgr) { return -EEXIST; }
        if (strcmp(server->rcb_regs[i].domain, domain) == 0) {
            return -EEXIST;
        }
    }
    if (server->rcb_reg_count >=
        (uint32_t)IEC61850_MMS_SERVER_MAX_RCB_MANAGERS) {
        return -ENOSPC;
    }

    server->rcb_regs[server->rcb_reg_count].manager = mgr;
    (void)memcpy(server->rcb_regs[server->rcb_reg_count].domain, domain,
                 len + 1U);
    server->rcb_reg_count++;
    return 0;
}

int iec61850_mms_server_set_rcb_manager(iec61850_mms_server_t *server,
                                         iec61850_rcb_manager_t *mgr)
{
    if ((server == NULL) || (mgr == NULL)) { return -EINVAL; }

    /* LD-name derivation: an RCB manager is constructed for exactly
     * one logical device (iec61850_rcb_manager_init(mgr, ld_name))
     * and the bridge keys its component objects by that LD name, so
     * the manager itself carries the domain to expose. Hosts that
     * need a different domain use the _domain() variant. */
    return iec61850_mms_server_set_rcb_manager_domain(server, mgr,
                                                      mgr->ld_name);
}

int iec61850_mms_server_set_control_manager(
    iec61850_mms_server_t *server, iec61850_control_manager_t *mgr)
{
    uint32_t count;
    uint32_t i;

    if ((server == NULL) || (mgr == NULL)) { return -EINVAL; }
    /* Registrations are snapshotted into sessions at accept time;
     * refuse while running so no session can miss a registration. */
    if (atomic_load(&server->running)) { return -EBUSY; }

    if (server->control_reg_count > 0U) {
        if (server->control_manager == mgr) { return 0; }
        return -EEXIST;
    }

    /* Snapshot the manager's registered control objects (public
     * manager struct, read under its lock — the manager's own
     * accessor pattern). */
    (void)pthread_mutex_lock(&mgr->mutex);
    count = mgr->count;
    if (count > (uint32_t)IEC61850_MMS_SERVER_MAX_CONTROL_REGS) {
        count = (uint32_t)IEC61850_MMS_SERVER_MAX_CONTROL_REGS;
    }
    for (i = 0U; i < count; i++) {
        (void)strncpy(server->control_regs[i].domain,
                      mgr->objects[i].domain,
                      (size_t)MMS_MAX_DOMAIN_NAME - 1U);
        server->control_regs[i].domain[MMS_MAX_DOMAIN_NAME - 1U] = '\0';
        (void)strncpy(server->control_regs[i].item_id,
                      mgr->objects[i].item_id,
                      (size_t)MMS_MAX_VARIABLE_NAME - 1U);
        server->control_regs[i].item_id[MMS_MAX_VARIABLE_NAME - 1U] = '\0';
        server->control_regs[i].selection_id = 0U;
        server->control_regs[i].owner_session = NULL;
        server->control_regs[i].oper_echo_len = 0U;
        server->control_regs[i].app_termination_cb = NULL;
        server->control_regs[i].app_termination_user_data = NULL;
        /* WP-C3: no deferred CommandTermination outstanding. */
        server->control_regs[i].pending_termination = false;
        server->control_regs[i].pending_success = false;
        server->control_regs[i].pending_addcause =
            IEC61850_ADDCAUSE_UNKNOWN;
        server->control_regs[i].pending_selection_id = 0U;
        server->control_regs[i].pending_timestamp_ms = 0ULL;
    }
    (void)pthread_mutex_unlock(&mgr->mutex);

    server->control_manager = mgr;
    server->control_reg_count = count;
    return 0;
}

int iec61850_mms_server_start(iec61850_mms_server_t *server)
{
    int ret;
    uint32_t i;

    if (server == NULL) { return IEC61850_MMS_SERVER_ERR_ARGS; }
    if (atomic_load(&server->running)) { return IEC61850_MMS_SERVER_ERR_RUNNING; }

#ifdef IEC61850_SECURITY_ENABLED
    /* WP-3b (IEC 62351-4): TLS listener. The provider's server
     * certificate is snapshotted here; a later provider refresh()
     * applies to newly started servers only. */
    if (server->config.tls_enabled) {
        if (server->config.tls_provider == NULL) {
            return IEC61850_MMS_SERVER_ERR_ARGS;
        }
    }
#else
    if (server->config.tls_enabled) {
        /* TLS requires a security-enabled build. */
        return -ENOTSUP;
    }
#endif

    if (!server->config.tls_enabled || !server->config.tls_only) {
        ret = iec61850_tcp_listener_bind(&server->listener, server->config.port);
        if (ret != 0) { return IEC61850_MMS_SERVER_ERR_BIND; }

        ret = iec61850_tcp_listener_listen(&server->listener, 10);
        if (ret != 0) { return IEC61850_MMS_SERVER_ERR_LISTEN; }
    }

#ifdef IEC61850_SECURITY_ENABLED
    if (server->config.tls_enabled) {
        ret = iec61850_tls_listener_bind(&server->tls_listener,
                                          server->config.tls_port,
                                          server->config.tls_provider,
                                          server->config.tls_mode);
        if (ret != 0) {
            if (!server->config.tls_only) {
                (void)iec61850_tcp_listener_close(&server->listener);
            }
            return IEC61850_MMS_SERVER_ERR_BIND;
        }
    }
#endif

    /* WP-2x: expose every registered RCB manager's component objects
     * in the server's data store. A manager already exposed (server
     * restart, or a host that exposed it manually) is accepted as-is
     * as long as store and domain match; exposure is otherwise the
     * bridge's one-time setup. */
    for (i = 0U; i < server->rcb_reg_count; i++) {
        iec61850_rcb_manager_t *mgr = server->rcb_regs[i].manager;
        const char *dom = server->rcb_regs[i].domain;

        if (mgr->bridge.active) {
            if ((mgr->bridge.store != server->data_store) ||
                (strcmp(mgr->bridge.domain, dom) != 0)) {
                iec61850_tcp_listener_close(&server->listener);
                return IEC61850_MMS_SERVER_ERR_ARGS;
            }
            continue;
        }
        if (iec61850_rcb_manager_expose(mgr, server->data_store, dom) != 0) {
            iec61850_tcp_listener_close(&server->listener);
            return IEC61850_MMS_SERVER_ERR_ARGS;
        }
    }

    /* WP-2w: expose every bridged control object's component objects
     * in the server's data store (idempotent) and install the bridge
     * termination callbacks. Objects registered in the manager after
     * iec61850_mms_server_set_control_manager() are not bridged
     * (registrations are fixed before start, RCB precedent). */
    for (i = 0U; i < server->control_reg_count; i++) {
        (void)iec61850_mms_ds_create_domain(server->data_store,
                                             server->control_regs[i].domain);
        control_bridge_expose_object(server, &server->control_regs[i]);
    }

    atomic_store(&server->stop_requested, false);
    atomic_store(&server->running, true);

    ret = pthread_create(&server->accept_thread, NULL, accept_thread, server);
    if (ret != 0) {
        iec61850_tcp_listener_close(&server->listener);
#ifdef IEC61850_SECURITY_ENABLED
        if (server->config.tls_enabled) {
            (void)iec61850_tls_listener_close(&server->tls_listener);
        }
#endif
        atomic_store(&server->running, false);
        return IEC61850_MMS_SERVER_ERR_THREAD;
    }

    return IEC61850_MMS_SERVER_OK;
}

int iec61850_mms_server_stop(iec61850_mms_server_t *server)
{
    if (server == NULL) { return IEC61850_MMS_SERVER_ERR_ARGS; }

    atomic_store(&server->stop_requested, true);

    for (uint32_t i = 0; i < (uint32_t)IEC61850_MMS_MAX_SESSIONS; i++) {
        if (atomic_load(&server->sessions[i].active)) {
            atomic_store(&server->sessions[i].stop_requested, true);
        }
    }

    if (atomic_load(&server->running)) {
        (void)pthread_join(server->accept_thread, NULL);
    }

    /* Join all session threads to ensure clean shutdown */
    for (uint32_t i = 0; i < (uint32_t)IEC61850_MMS_MAX_SESSIONS; i++) {
        if (atomic_load(&server->sessions[i].active)) {
            (void)pthread_join(server->sessions[i].thread, NULL);
        }
    }

    iec61850_tcp_listener_close(&server->listener);
#ifdef IEC61850_SECURITY_ENABLED
    if (server->config.tls_enabled) {
        (void)iec61850_tls_listener_close(&server->tls_listener);
    }
#endif
    atomic_store(&server->running, false);

    return IEC61850_MMS_SERVER_OK;
}

bool iec61850_mms_server_is_running(const iec61850_mms_server_t *server)
{
    if (server == NULL) { return false; }
    return atomic_load(&server->running);
}

uint32_t iec61850_mms_server_get_session_count(
    const iec61850_mms_server_t *server)
{
    if (server == NULL) { return 0; }
    return atomic_load(&server->active_session_count);
}

int iec61850_mms_server_set_sg_manager(iec61850_mms_server_t *server,
                                       iec61850_sg_manager_t *mgr)
{
    if ((server == NULL) || (mgr == NULL)) {
        return -EINVAL;
    }
    /* Sessions copy the pointer at accept time; refuse while
     * running so no session can miss the manager. */
    if (atomic_load(&server->running)) {
        return -EBUSY;
    }
    server->sg_manager = mgr;
    return 0;
}
