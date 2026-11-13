/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Client RCB Enrollment for IEC 61850 (Ed.2) — WP-1c
 *
 * Client-side reporting against the frozen interface in
 * include/iec61850/mms/mms_client_rcb.h.
 *
 * Object model (matches this repo's mms_server + data store):
 *   The server exposes RCB components as ordinary named variables in
 *   the logical-device domain, using the IEC 61850-8-1 Ed.2
 *   component-object naming: RCB <name> has one named variable per
 *   component, named "<name><Suffix>" (e.g. RCB "urcb01" exposes
 *   "urcb01RptEna", "urcb01Resv", "urcb01DatSet", ...). rcb_list()
 *   therefore filters a GetNameList(NAMED_VARIABLE) result on the
 *   "...RptEna" component pattern; every other operation reads or
 *   writes the component objects directly.
 *
 * Value encoding (IEC 61850-8-1 component types, as carried by this
 * repo's BER codec / data store):
 *   RptEna, Resv, GI, PurgeBuf ................ BOOLEAN
 *   RptID, DatSet, Owner ...................... VISIBLE-STRING
 *   ConfRev, BufTm, IntgPd, SqNum ............. UNSIGNED
 *   OptFlds ................................... BIT-STRING (10 bits)
 *   TrgOps .................................... BIT-STRING (6 bits)
 *   EntryID ................................... OCTET-STRING (8 bytes)
 *
 * OptFlds bit layout (IEC 61850-7-2 s8.3.2, identical to this repo's
 * mms_encode_iec61850_report()): first value octet bit1=sequence-
 * number, bit2=report-timestamp, bit3=reason-for-inclusion, bit4=
 * data-set-name, bit5=data-reference, bit6=buffer-overflow, bit7=
 * entry-id; second octet bit0=config-ref.
 *
 * TrgOps bit layout (first value octet): bit1=dchg, bit2=qchg,
 * bit3=dupd, bit4=period(integrity), bit5=general-interrogation.
 *
 * Enrollment write order (IEC 61850-8-1 Ed.2 client procedure, see
 * set_values): PurgeBuf, Resv (URCB reservation first), RptID,
 * DatSet, ConfRev, OptFlds, TrgOps, BufTm, IntgPd, GI, EntryID
 * (before RptEna for BRCB resume), RptEna last.
 *
 * Report reception: the handler installed via set_report_handler is
 * routed through the async core's unsolicited-report dispatch
 * (mms_client_core_set_report_handler); it fires from within any
 * subsequent blocking transaction or iec61850_mms_client_poll()
 * call. The core decodes InformationReports with
 * mms_decode_information_report() — the wire format produced by this
 * repo's RCB engine (mms_report.c) via mms_encode_information_report().
 */

#include "mms/mms_client_rcb.h"

#include <errno.h>
#include <string.h>

/* ========================================================================
 * Component-object naming
 * ======================================================================== */

#define RCB_SUFFIX_RPT_ID    "RptID"
#define RCB_SUFFIX_RPT_ENA   "RptEna"
#define RCB_SUFFIX_RESV      "Resv"
#define RCB_SUFFIX_DAT_SET   "DatSet"
#define RCB_SUFFIX_CONF_REV  "ConfRev"
#define RCB_SUFFIX_OPT_FLDS  "OptFlds"
#define RCB_SUFFIX_BUF_TM    "BufTm"
#define RCB_SUFFIX_SQ_NUM    "SqNum"
#define RCB_SUFFIX_TRG_OPS   "TrgOps"
#define RCB_SUFFIX_INTG_PD   "IntgPd"
#define RCB_SUFFIX_GI        "GI"
#define RCB_SUFFIX_PURGE_BUF "PurgeBuf"
#define RCB_SUFFIX_ENTRY_ID  "EntryID"
#define RCB_SUFFIX_OWNER     "Owner"

/* rcb_list() scan granularity: named variables fetched per GetNameList
 * sweep. Domains with more variables than this are truncated (the
 * frozen API is capacity-bound by max_count anyway). */
#define RCB_LIST_SCAN_MAX 128

/* OptFlds value-octet bits (first octet). */
#define RCB_OPTFLDS_SEQ_NUM     0x40u
#define RCB_OPTFLDS_TIMESTAMP   0x20u
#define RCB_OPTFLDS_REASON      0x10u
#define RCB_OPTFLDS_DATA_SET    0x08u
#define RCB_OPTFLDS_DATA_REF    0x04u
#define RCB_OPTFLDS_BUF_OVFL    0x02u
#define RCB_OPTFLDS_ENTRY_ID    0x01u
/* Second value octet. */
#define RCB_OPTFLDS_CONF_REV    0x80u

/* TrgOps value-octet bits. */
#define RCB_TRGOPS_DCHG         0x40u
#define RCB_TRGOPS_QCHG         0x20u
#define RCB_TRGOPS_DUPD         0x10u
#define RCB_TRGOPS_PERIOD       0x08u
#define RCB_TRGOPS_GI           0x04u

/* EntryID wire size (octet string, big-endian). */
#define RCB_ENTRY_ID_LEN        8u

/* Build "<rcb-name><suffix>" into out. Returns 0, or -EINVAL when the
 * arguments are bad or the concatenation does not fit. */
static int rcb_component_name(char *out, size_t out_size,
                               const char *rcb_name, const char *suffix)
{
    size_t name_len;
    size_t suffix_len;

    if ((out == NULL) || (rcb_name == NULL) || (suffix == NULL)) {
        return -EINVAL;
    }

    name_len = strlen(rcb_name);
    suffix_len = strlen(suffix);

    if ((name_len == 0U) || (suffix_len == 0U) ||
        (name_len >= out_size) || (suffix_len >= out_size) ||
        ((name_len + suffix_len) >= out_size)) {
        return -EINVAL;
    }

    (void)memcpy(out, rcb_name, name_len);
    (void)memcpy(&out[name_len], suffix, suffix_len);
    out[name_len + suffix_len] = '\0';
    return 0;
}

/* Read one RCB component object. */
static int rcb_read_component(iec61850_mms_client_t *client,
                               const char *domain, const char *rcb_name,
                               const char *suffix, mms_value_t *value)
{
    char item[MMS_MAX_VARIABLE_NAME];
    int ret;

    ret = rcb_component_name(item, (size_t)MMS_MAX_VARIABLE_NAME,
                              rcb_name, suffix);
    if (ret != 0) {
        return IEC61850_MMS_CLIENT_ERR_ARGS;
    }

    return iec61850_mms_client_read(client, domain, item, value);
}

/* Write one RCB component object. */
static int rcb_write_component(iec61850_mms_client_t *client,
                                const char *domain, const char *rcb_name,
                                const char *suffix, const mms_value_t *value)
{
    char item[MMS_MAX_VARIABLE_NAME];
    int ret;

    ret = rcb_component_name(item, (size_t)MMS_MAX_VARIABLE_NAME,
                              rcb_name, suffix);
    if (ret != 0) {
        return IEC61850_MMS_CLIENT_ERR_ARGS;
    }

    return iec61850_mms_client_write(client, domain, item, value);
}

/* ========================================================================
 * Value construction / parsing
 * ======================================================================== */

static void rcb_set_bool_value(mms_value_t *value, bool b)
{
    (void)memset(value, 0, sizeof(*value));
    value->type = MMS_TYPE_BOOLEAN;
    value->value.boolean = b;
}

static int rcb_set_string_value(mms_value_t *value, const char *s)
{
    size_t len;

    if ((value == NULL) || (s == NULL)) {
        return -EINVAL;
    }

    len = strlen(s);
    if (len >= (size_t)MMS_MAX_STRING_LENGTH) {
        return -EINVAL;
    }

    (void)memset(value, 0, sizeof(*value));
    value->type = MMS_TYPE_VISIBLE_STRING;
    (void)memcpy(value->value.visible_string.data, s, len);
    value->value.visible_string.data[len] = '\0';
    value->value.visible_string.len = len;
    return 0;
}

static void rcb_set_unsigned_value(mms_value_t *value, uint32_t u)
{
    (void)memset(value, 0, sizeof(*value));
    value->type = MMS_TYPE_UNSIGNED;
    value->value.unsigned_val = u;
}

static void rcb_set_opt_flds_value(mms_value_t *value,
                                    const iec61850_opt_flds_t *f)
{
    uint8_t b0 = 0u;
    uint8_t b1 = 0u;

    if (f->sequence_number)      { b0 |= RCB_OPTFLDS_SEQ_NUM; }
    if (f->report_timestamp)     { b0 |= RCB_OPTFLDS_TIMESTAMP; }
    if (f->reason_for_inclusion) { b0 |= RCB_OPTFLDS_REASON; }
    if (f->data_set_name)        { b0 |= RCB_OPTFLDS_DATA_SET; }
    if (f->data_reference)       { b0 |= RCB_OPTFLDS_DATA_REF; }
    if (f->buffer_overflow)      { b0 |= RCB_OPTFLDS_BUF_OVFL; }
    if (f->entry_id)             { b0 |= RCB_OPTFLDS_ENTRY_ID; }
    if (f->config_ref)           { b1 |= RCB_OPTFLDS_CONF_REV; }

    (void)memset(value, 0, sizeof(*value));
    value->type = MMS_TYPE_BIT_STRING;
    value->value.bit_string.data[0] = b0;
    value->value.bit_string.data[1] = b1;
    value->value.bit_string.bit_count = 10u; /* 8 + confRev bit */
}

static void rcb_set_trg_ops_value(mms_value_t *value,
                                   const iec61850_trg_ops_t *t)
{
    uint8_t b0 = 0u;

    if (t->data_change)              { b0 |= RCB_TRGOPS_DCHG; }
    if (t->quality_change)           { b0 |= RCB_TRGOPS_QCHG; }
    if (t->data_update)              { b0 |= RCB_TRGOPS_DUPD; }
    if (t->integrity)                { b0 |= RCB_TRGOPS_PERIOD; }
    if (t->general_interrogation)    { b0 |= RCB_TRGOPS_GI; }

    (void)memset(value, 0, sizeof(*value));
    value->type = MMS_TYPE_BIT_STRING;
    value->value.bit_string.data[0] = b0;
    value->value.bit_string.bit_count = 6u;
}

static void rcb_set_entry_id_value(mms_value_t *value, uint64_t entry_id)
{
    uint32_t i;

    (void)memset(value, 0, sizeof(*value));
    value->type = MMS_TYPE_OCTET_STRING;
    for (i = 0u; i < RCB_ENTRY_ID_LEN; i++) {
        size_t idx = (size_t)i;
        value->value.octet_string.data[idx] =
            (uint8_t)((entry_id >> ((RCB_ENTRY_ID_LEN - 1u - (uint64_t)i) * 8u)) & 0xFFu);
    }
    value->value.octet_string.len = RCB_ENTRY_ID_LEN;
}

static int rcb_parse_bool(const mms_value_t *value, bool *out)
{
    if ((value == NULL) || (value->type != MMS_TYPE_BOOLEAN)) {
        return -EINVAL;
    }
    *out = value->value.boolean;
    return 0;
}

static int rcb_parse_string(const mms_value_t *value, char *out, size_t out_size)
{
    size_t len;

    if ((value == NULL) || (value->type != MMS_TYPE_VISIBLE_STRING) ||
        (out == NULL) || (out_size == 0U)) {
        return -EINVAL;
    }

    len = value->value.visible_string.len;
    if (len >= (size_t)MMS_MAX_STRING_LENGTH) {
        len = strlen(value->value.visible_string.data);
    }
    if (len >= out_size) {
        len = out_size - 1u;
    }

    (void)memcpy(out, value->value.visible_string.data, len);
    out[len] = '\0';
    return 0;
}

static int rcb_parse_u32(const mms_value_t *value, uint32_t *out)
{
    if (value == NULL) {
        return -EINVAL;
    }
    if (value->type == MMS_TYPE_UNSIGNED) {
        *out = value->value.unsigned_val;
        return 0;
    }
    if (value->type == MMS_TYPE_INTEGER) {
        if (value->value.integer < 0) {
            return -EINVAL;
        }
        *out = (uint32_t)value->value.integer;
        return 0;
    }
    return -EINVAL;
}

static int rcb_parse_opt_flds(const mms_value_t *value,
                               iec61850_opt_flds_t *out)
{
    uint8_t b0;
    uint8_t b1;
    size_t byte_count;

    if ((value == NULL) || (value->type != MMS_TYPE_BIT_STRING) ||
        (out == NULL)) {
        return -EINVAL;
    }

    byte_count = ((value->value.bit_string.bit_count + 7u) / 8u);
    if (byte_count == 0u) {
        return -EINVAL;
    }

    b0 = value->value.bit_string.data[0];
    b1 = (byte_count > 1u) ? value->value.bit_string.data[1] : 0u;

    (void)memset(out, 0, sizeof(*out));
    out->sequence_number      = ((b0 & RCB_OPTFLDS_SEQ_NUM) != 0u);
    out->report_timestamp     = ((b0 & RCB_OPTFLDS_TIMESTAMP) != 0u);
    out->reason_for_inclusion = ((b0 & RCB_OPTFLDS_REASON) != 0u);
    out->data_set_name        = ((b0 & RCB_OPTFLDS_DATA_SET) != 0u);
    out->data_reference       = ((b0 & RCB_OPTFLDS_DATA_REF) != 0u);
    out->buffer_overflow      = ((b0 & RCB_OPTFLDS_BUF_OVFL) != 0u);
    out->entry_id             = ((b0 & RCB_OPTFLDS_ENTRY_ID) != 0u);
    out->config_ref           = ((b1 & RCB_OPTFLDS_CONF_REV) != 0u);
    return 0;
}

static int rcb_parse_trg_ops(const mms_value_t *value,
                              iec61850_trg_ops_t *out)
{
    uint8_t b0;

    if ((value == NULL) || (value->type != MMS_TYPE_BIT_STRING) ||
        (out == NULL) || (value->value.bit_string.bit_count < 6u)) {
        return -EINVAL;
    }

    b0 = value->value.bit_string.data[0];

    (void)memset(out, 0, sizeof(*out));
    out->data_change           = ((b0 & RCB_TRGOPS_DCHG) != 0u);
    out->quality_change        = ((b0 & RCB_TRGOPS_QCHG) != 0u);
    out->data_update           = ((b0 & RCB_TRGOPS_DUPD) != 0u);
    out->integrity             = ((b0 & RCB_TRGOPS_PERIOD) != 0u);
    out->general_interrogation = ((b0 & RCB_TRGOPS_GI) != 0u);
    return 0;
}

static int rcb_parse_entry_id(const mms_value_t *value, uint64_t *out)
{
    uint32_t i;

    if (value == NULL) {
        return -EINVAL;
    }

    if ((value->type == MMS_TYPE_OCTET_STRING) &&
        (value->value.octet_string.len == RCB_ENTRY_ID_LEN)) {
        uint64_t id = 0u;
        for (i = 0u; i < RCB_ENTRY_ID_LEN; i++) {
            size_t idx = (size_t)i;
            id = (id << 8) | (uint64_t)value->value.octet_string.data[idx];
        }
        *out = id;
        return 0;
    }

    /* Leniency: servers exposing EntryID as UNSIGNED. */
    if (value->type == MMS_TYPE_UNSIGNED) {
        *out = (uint64_t)value->value.unsigned_val;
        return 0;
    }

    return -EINVAL;
}

/*
 * Read a component that may legitimately be absent (Resv on a BRCB,
 * Owner, EntryID, PurgeBuf, SqNum). A server rejection of the Read
 * (IEC61850_MMS_CLIENT_ERR_MMS: object-non-existent) maps to "not
 * present"; transport/timeout failures propagate.
 */
static int rcb_read_optional(iec61850_mms_client_t *client,
                              const char *domain, const char *rcb_name,
                              const char *suffix, mms_value_t *value,
                              bool *present)
{
    int ret;

    *present = false;
    ret = rcb_read_component(client, domain, rcb_name, suffix, value);
    if (ret == (int)IEC61850_MMS_CLIENT_OK) {
        *present = true;
        return 0;
    }
    if (ret == (int)IEC61850_MMS_CLIENT_ERR_MMS) {
        return 0; /* component object does not exist */
    }
    return ret;
}

/* ========================================================================
 * Frozen interface (WP-S1)
 * ========================================================================
 */

int iec61850_mms_client_rcb_list(iec61850_mms_client_t *client,
                                   const char *domain,
                                   char names[][IEC61850_RCB_MAX_NAME],
                                   uint32_t *count, uint32_t max_count)
{
    /* 128 * 256 B = 32 KiB scan buffer (the server side uses the same
     * class of stack buffer for GetNameList). */
    char scan[RCB_LIST_SCAN_MAX][MMS_MAX_VARIABLE_NAME];
    uint32_t total = 0u;
    uint32_t i;
    int ret;

    if ((client == NULL) || (!client->connected) || (domain == NULL) ||
        (names == NULL) || (count == NULL)) {
        return IEC61850_MMS_CLIENT_ERR_ARGS;
    }

    *count = 0u;

    ret = iec61850_mms_client_get_name_list(client,
                                             MMS_OBJECT_CLASS_NAMED_VARIABLE,
                                             domain, scan, &total,
                                             (uint32_t)RCB_LIST_SCAN_MAX);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) {
        return ret;
    }

    /* An RCB is any object whose name ends in the "RptEna" component
     * suffix; the RCB name is the remainder. */
    for (i = 0u; (i < total) && (*count < max_count); i++) {
        size_t len = strlen(scan[i]);

        if ((len > 6u) &&
            (strcmp(&scan[i][len - 6u], RCB_SUFFIX_RPT_ENA) == 0)) {
            size_t base_len = len - 6u;

            if (base_len >= (size_t)IEC61850_RCB_MAX_NAME) {
                base_len = (size_t)IEC61850_RCB_MAX_NAME - 1u;
            }
            (void)memcpy(names[*count], scan[i], base_len);
            names[*count][base_len] = '\0';
            (*count)++;
        }
    }

    return IEC61850_MMS_CLIENT_OK;
}

int iec61850_mms_client_rcb_get_values(iec61850_mms_client_t *client,
                                        const char *domain,
                                        const char *rcb_name,
                                        iec61850_mms_client_rcb_values_t *out)
{
    mms_value_t value;
    bool present;
    int ret;

    if ((client == NULL) || (!client->connected) || (domain == NULL) ||
        (rcb_name == NULL) || (out == NULL)) {
        return IEC61850_MMS_CLIENT_ERR_ARGS;
    }

    (void)memset(out, 0, sizeof(*out));

    /* Mandatory components (IEC 61850-8-1): strict reads. */
    ret = rcb_read_component(client, domain, rcb_name,
                              RCB_SUFFIX_RPT_ENA, &value);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    if (rcb_parse_bool(&value, &out->attrs.rpt_ena) != 0) {
        return IEC61850_MMS_CLIENT_ERR_DECODE;
    }

    ret = rcb_read_component(client, domain, rcb_name,
                              RCB_SUFFIX_RPT_ID, &value);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    if (rcb_parse_string(&value, out->attrs.rpt_id,
                          (size_t)IEC61850_RCB_MAX_NAME) != 0) {
        return IEC61850_MMS_CLIENT_ERR_DECODE;
    }

    ret = rcb_read_component(client, domain, rcb_name,
                              RCB_SUFFIX_DAT_SET, &value);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    if (rcb_parse_string(&value, out->attrs.dat_set,
                          (size_t)IEC61850_RCB_MAX_NAME) != 0) {
        return IEC61850_MMS_CLIENT_ERR_DECODE;
    }

    ret = rcb_read_component(client, domain, rcb_name,
                              RCB_SUFFIX_CONF_REV, &value);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    if (rcb_parse_u32(&value, &out->attrs.conf_rev) != 0) {
        return IEC61850_MMS_CLIENT_ERR_DECODE;
    }

    ret = rcb_read_component(client, domain, rcb_name,
                              RCB_SUFFIX_OPT_FLDS, &value);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    if (rcb_parse_opt_flds(&value, &out->attrs.opt_flds) != 0) {
        return IEC61850_MMS_CLIENT_ERR_DECODE;
    }

    ret = rcb_read_component(client, domain, rcb_name,
                              RCB_SUFFIX_BUF_TM, &value);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    if (rcb_parse_u32(&value, &out->attrs.buf_tm) != 0) {
        return IEC61850_MMS_CLIENT_ERR_DECODE;
    }

    ret = rcb_read_component(client, domain, rcb_name,
                              RCB_SUFFIX_TRG_OPS, &value);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    if (rcb_parse_trg_ops(&value, &out->attrs.trg_ops) != 0) {
        return IEC61850_MMS_CLIENT_ERR_DECODE;
    }

    ret = rcb_read_component(client, domain, rcb_name,
                              RCB_SUFFIX_INTG_PD, &value);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    if (rcb_parse_u32(&value, &out->attrs.intg_pd) != 0) {
        return IEC61850_MMS_CLIENT_ERR_DECODE;
    }

    ret = rcb_read_component(client, domain, rcb_name,
                              RCB_SUFFIX_GI, &value);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    if (rcb_parse_bool(&value, &out->attrs.gi) != 0) {
        return IEC61850_MMS_CLIENT_ERR_DECODE;
    }

    /* Optional / type-dependent components: tolerant reads. */
    ret = rcb_read_optional(client, domain, rcb_name,
                             RCB_SUFFIX_RESV, &value, &present);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    if (present && (rcb_parse_bool(&value, &out->resv) != 0)) {
        return IEC61850_MMS_CLIENT_ERR_DECODE;
    }

    ret = rcb_read_optional(client, domain, rcb_name,
                             RCB_SUFFIX_SQ_NUM, &value, &present);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    if (present) {
        uint32_t sq = 0u;
        if (rcb_parse_u32(&value, &sq) != 0) {
            return IEC61850_MMS_CLIENT_ERR_DECODE;
        }
        out->attrs.sq_num = (uint16_t)(sq & 0xFFFFu);
    }

    ret = rcb_read_optional(client, domain, rcb_name,
                             RCB_SUFFIX_OWNER, &value, &present);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    if (present) {
        out->owner_present = true;
        if (rcb_parse_string(&value, out->owner,
                              (size_t)IEC61850_RCB_MAX_NAME) != 0) {
            return IEC61850_MMS_CLIENT_ERR_DECODE;
        }
    }

    ret = rcb_read_optional(client, domain, rcb_name,
                             RCB_SUFFIX_ENTRY_ID, &value, &present);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    if (present) {
        out->buffered = true;
        if (rcb_parse_entry_id(&value, &out->attrs.entry_id) != 0) {
            return IEC61850_MMS_CLIENT_ERR_DECODE;
        }
    }

    if (!out->buffered) {
        ret = rcb_read_optional(client, domain, rcb_name,
                                 RCB_SUFFIX_PURGE_BUF, &value, &present);
        if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
        out->buffered = present;
    }

    return IEC61850_MMS_CLIENT_OK;
}

/*
 * Ed.2 ownership-conflict probe: after a failed Resv write, a
 * readable non-empty Owner means another client holds the
 * reservation (our own reservation would not have failed).
 */
static int rcb_owner_held_by_other(iec61850_mms_client_t *client,
                                    const char *domain, const char *rcb_name)
{
    mms_value_t value;
    int ret;

    (void)memset(&value, 0, sizeof(value));
    ret = rcb_read_component(client, domain, rcb_name,
                              RCB_SUFFIX_OWNER, &value);
    if (ret != (int)IEC61850_MMS_CLIENT_OK) {
        return 0; /* no Owner information available */
    }
    if (value.type != MMS_TYPE_VISIBLE_STRING) {
        return 0;
    }
    if (value.value.visible_string.len == 0u) {
        return 0;
    }
    return 1;
}

int iec61850_mms_client_rcb_set_values(iec61850_mms_client_t *client,
                                        const char *domain,
                                        const char *rcb_name,
                                        const iec61850_mms_client_rcb_values_t *in,
                                        uint32_t field_mask)
{
    mms_value_t value;
    int ret;

    if ((client == NULL) || (!client->connected) || (domain == NULL) ||
        (rcb_name == NULL) || (in == NULL) || (field_mask == 0u)) {
        return IEC61850_MMS_CLIENT_ERR_ARGS;
    }

    /*
     * IEC 61850-8-1 Ed.2 client procedure order. Each masked field is
     * written individually; a failure stops the sequence (the client
     * never auto-retries).
     */

    /* 1. PurgeBuf (BRCB buffer purge, always written TRUE). */
    if ((field_mask & (uint32_t)IEC61850_RCB_FIELD_PURGE_BUF) != 0u) {
        rcb_set_bool_value(&value, true);
        ret = rcb_write_component(client, domain, rcb_name,
                                   RCB_SUFFIX_PURGE_BUF, &value);
        if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    }

    /* 2. Resv — URCB reservation first. */
    if ((field_mask & (uint32_t)IEC61850_RCB_FIELD_RESV) != 0u) {
        rcb_set_bool_value(&value, in->resv);
        ret = rcb_write_component(client, domain, rcb_name,
                                   RCB_SUFFIX_RESV, &value);
        if (ret != (int)IEC61850_MMS_CLIENT_OK) {
            if (rcb_owner_held_by_other(client, domain, rcb_name) != 0) {
                return IEC61850_MMS_CLIENT_ERR_RCB_OWNER;
            }
            return ret;
        }
    }

    /* 3. RptID. */
    if ((field_mask & (uint32_t)IEC61850_RCB_FIELD_RPT_ID) != 0u) {
        if (rcb_set_string_value(&value, in->attrs.rpt_id) != 0) {
            return IEC61850_MMS_CLIENT_ERR_ARGS;
        }
        ret = rcb_write_component(client, domain, rcb_name,
                                   RCB_SUFFIX_RPT_ID, &value);
        if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    }

    /* 4. DatSet. */
    if ((field_mask & (uint32_t)IEC61850_RCB_FIELD_DAT_SET) != 0u) {
        if (rcb_set_string_value(&value, in->attrs.dat_set) != 0) {
            return IEC61850_MMS_CLIENT_ERR_ARGS;
        }
        ret = rcb_write_component(client, domain, rcb_name,
                                   RCB_SUFFIX_DAT_SET, &value);
        if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    }

    /* 5. ConfRev. */
    if ((field_mask & (uint32_t)IEC61850_RCB_FIELD_CONF_REV) != 0u) {
        rcb_set_unsigned_value(&value, in->attrs.conf_rev);
        ret = rcb_write_component(client, domain, rcb_name,
                                   RCB_SUFFIX_CONF_REV, &value);
        if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    }

    /* 6. OptFlds. */
    if ((field_mask & (uint32_t)IEC61850_RCB_FIELD_OPT_FLDS) != 0u) {
        rcb_set_opt_flds_value(&value, &in->attrs.opt_flds);
        ret = rcb_write_component(client, domain, rcb_name,
                                   RCB_SUFFIX_OPT_FLDS, &value);
        if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    }

    /* 7. TrgOps. */
    if ((field_mask & (uint32_t)IEC61850_RCB_FIELD_TRG_OPS) != 0u) {
        rcb_set_trg_ops_value(&value, &in->attrs.trg_ops);
        ret = rcb_write_component(client, domain, rcb_name,
                                   RCB_SUFFIX_TRG_OPS, &value);
        if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    }

    /* 8. BufTm. */
    if ((field_mask & (uint32_t)IEC61850_RCB_FIELD_BUF_TM) != 0u) {
        rcb_set_unsigned_value(&value, in->attrs.buf_tm);
        ret = rcb_write_component(client, domain, rcb_name,
                                   RCB_SUFFIX_BUF_TM, &value);
        if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    }

    /* 9. IntgPd. */
    if ((field_mask & (uint32_t)IEC61850_RCB_FIELD_INTG_PD) != 0u) {
        rcb_set_unsigned_value(&value, in->attrs.intg_pd);
        ret = rcb_write_component(client, domain, rcb_name,
                                   RCB_SUFFIX_INTG_PD, &value);
        if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    }

    /* 10. GI. */
    if ((field_mask & (uint32_t)IEC61850_RCB_FIELD_GI) != 0u) {
        rcb_set_bool_value(&value, in->attrs.gi);
        ret = rcb_write_component(client, domain, rcb_name,
                                   RCB_SUFFIX_GI, &value);
        if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    }

    /* 11. EntryID — before RptEna for BRCB resume. */
    if ((field_mask & (uint32_t)IEC61850_RCB_FIELD_ENTRY_ID) != 0u) {
        rcb_set_entry_id_value(&value, in->attrs.entry_id);
        ret = rcb_write_component(client, domain, rcb_name,
                                   RCB_SUFFIX_ENTRY_ID, &value);
        if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    }

    /* 12. RptEna — always last. */
    if ((field_mask & (uint32_t)IEC61850_RCB_FIELD_RPT_ENA) != 0u) {
        rcb_set_bool_value(&value, in->attrs.rpt_ena);
        ret = rcb_write_component(client, domain, rcb_name,
                                   RCB_SUFFIX_RPT_ENA, &value);
        if (ret != (int)IEC61850_MMS_CLIENT_OK) { return ret; }
    }

    return IEC61850_MMS_CLIENT_OK;
}

int iec61850_mms_client_rcb_enable(iec61850_mms_client_t *client,
                                     const char *domain,
                                     const char *rcb_name)
{
    iec61850_mms_client_rcb_values_t values;

    if ((client == NULL) || (domain == NULL) || (rcb_name == NULL)) {
        return IEC61850_MMS_CLIENT_ERR_ARGS;
    }

    (void)memset(&values, 0, sizeof(values));
    values.attrs.rpt_ena = true;
    return iec61850_mms_client_rcb_set_values(client, domain, rcb_name,
                                               &values,
                                               (uint32_t)IEC61850_RCB_FIELD_RPT_ENA);
}

int iec61850_mms_client_rcb_disable(iec61850_mms_client_t *client,
                                      const char *domain,
                                      const char *rcb_name)
{
    iec61850_mms_client_rcb_values_t values;

    if ((client == NULL) || (domain == NULL) || (rcb_name == NULL)) {
        return IEC61850_MMS_CLIENT_ERR_ARGS;
    }

    (void)memset(&values, 0, sizeof(values));
    values.attrs.rpt_ena = false; /* releases the URCB reservation */
    return iec61850_mms_client_rcb_set_values(client, domain, rcb_name,
                                               &values,
                                               (uint32_t)IEC61850_RCB_FIELD_RPT_ENA);
}

int iec61850_mms_client_rcb_purge_buffer(iec61850_mms_client_t *client,
                                           const char *domain,
                                           const char *rcb_name)
{
    iec61850_mms_client_rcb_values_t values;

    if ((client == NULL) || (domain == NULL) || (rcb_name == NULL)) {
        return IEC61850_MMS_CLIENT_ERR_ARGS;
    }

    (void)memset(&values, 0, sizeof(values));
    return iec61850_mms_client_rcb_set_values(client, domain, rcb_name,
                                               &values,
                                               (uint32_t)IEC61850_RCB_FIELD_PURGE_BUF);
}

int iec61850_mms_client_rcb_set_entry_id(iec61850_mms_client_t *client,
                                           const char *domain,
                                           const char *rcb_name,
                                           uint64_t entry_id)
{
    iec61850_mms_client_rcb_values_t values;

    if ((client == NULL) || (domain == NULL) || (rcb_name == NULL)) {
        return IEC61850_MMS_CLIENT_ERR_ARGS;
    }

    (void)memset(&values, 0, sizeof(values));
    values.attrs.entry_id = entry_id;
    return iec61850_mms_client_rcb_set_values(client, domain, rcb_name,
                                               &values,
                                               (uint32_t)IEC61850_RCB_FIELD_ENTRY_ID);
}

int iec61850_mms_client_set_report_handler(iec61850_mms_client_t *client,
                                             iec61850_mms_client_report_cb cb,
                                             void *user_data)
{
    if (client == NULL) {
        return IEC61850_MMS_CLIENT_ERR_ARGS;
    }

    /* iec61850_mms_client_report_cb and the core's
     * iec61850_mms_core_report_cb are the same type: the handler fires
     * from the core's poll context (blocking transactions and
     * iec61850_mms_client_poll). NULL clears the handler. */
    iec61850_mms_client_core_set_report_handler(&client->core, cb, user_data);
    return IEC61850_MMS_CLIENT_OK;
}
