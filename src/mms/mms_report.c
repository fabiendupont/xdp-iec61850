/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Report Control Block Implementation
 *
 * BRCB/URCB trigger evaluation, integrity scanning, and report generation.
 */


#include "mms/mms_report.h"
#include "mms/mms_data_store.h"
#include "mms/mms_server.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

static uint64_t now_ms(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_REALTIME, &ts);
    return ((uint64_t)ts.tv_sec * 1000ULL) +
           ((uint64_t)ts.tv_nsec / 1000000ULL);
}

/* Fill the WP-S1 report-metadata extension fields (rpt_id, dat_set,
 * conf_rev) of an assembled report from the RCB's authoritative state
 * (WP-2z). The conformant 7-2 bridge sender maps these onto the
 * InformationReport metadata fields; dat_set/conf_rev are only
 * carried when the corresponding OptFlds bits are armed so the wire
 * stays consistent with the optFlds bit string. */
static void report_fill_metadata(mms_information_report_t *report,
                                 const iec61850_rcb_t *rcb)
{
    (void)strncpy(report->rpt_id, rcb->attrs.rpt_id,
                  (size_t)MMS_MAX_STRING_LENGTH - 1U);
    report->rpt_id[MMS_MAX_STRING_LENGTH - 1U] = '\0';
    if (rcb->attrs.opt_flds.data_set_name) {
        (void)strncpy(report->dat_set, rcb->attrs.dat_set,
                      (size_t)MMS_MAX_STRING_LENGTH - 1U);
        report->dat_set[MMS_MAX_STRING_LENGTH - 1U] = '\0';
    }
    if (rcb->attrs.opt_flds.config_ref) {
        report->conf_rev = rcb->attrs.conf_rev;
        report->conf_rev_present = true;
    }
}

/* Forward declaration (defined after the RCB entry points). */
static void generate_report(iec61850_rcb_t *rcb, const char *var_ref,
                              const mms_value_t *value,
                              iec61850_reason_code_t reason);

/* Forward declarations for the Ed.2 data-store bridge (WP-2a). */
static int bridge_expose_rcb(iec61850_rcb_manager_t *mgr, uint32_t idx);
static bool bridge_can_deliver(const iec61850_rcb_manager_t *mgr);
static void brcb_flush(iec61850_rcb_manager_t *mgr, uint32_t idx,
                       uint64_t now_ms_val, bool force);
static void bridge_publish_rcb(iec61850_rcb_manager_t *mgr, uint32_t idx);


/* Integrity scan thread */
static void *integrity_thread_func(void *arg)
{
    /* MISRA 11.5: pthread arg is opaque void*, deviation Cat. 3 */
    iec61850_rcb_t *rcb = (iec61850_rcb_t *)arg;

    while (atomic_load(&rcb->running)) {
        if (rcb->attrs.intg_pd == 0U) {
            /* No integrity period configured, sleep and check */
            struct timespec ts = {1, 0};
            (void)nanosleep(&ts, NULL);
            continue;
        }

        /* Sleep for integrity period */
        struct timespec ts;
        ts.tv_sec = (long)(rcb->attrs.intg_pd / 1000U);
        ts.tv_nsec = (long)((rcb->attrs.intg_pd % 1000U) * 1000000UL);
        (void)nanosleep(&ts, NULL);

        if ((!atomic_load(&rcb->running)) || (!rcb->attrs.rpt_ena)) {
            continue;
        }

        /* Generate integrity report */
        pthread_mutex_lock(&rcb->mutex);

        if (rcb->report_sender != NULL) {
            mms_information_report_t report;
            (void)memset(&report, 0, sizeof(report));
            (void)strncpy(report.variable_list_name, rcb->attrs.rpt_id,
                           (size_t)MMS_MAX_VARIABLE_NAME - 1U);
            report_fill_metadata(&report, rcb);
            report.num_values = 0;  /* Integrity: snapshot of all data */

            rcb->attrs.sq_num++;
            rcb->report_sender(&report, rcb->report_sender_data);
        }

        pthread_mutex_unlock(&rcb->mutex);
    }

    return NULL;
}

void iec61850_rcb_init(iec61850_rcb_t *rcb, const char *rpt_id,
                         iec61850_rcb_type_t type)
{
    if (rcb == NULL) { return; }

    (void)memset(rcb, 0, sizeof(*rcb));
    rcb->type = type;
    if (rpt_id != NULL) {
        (void)strncpy(rcb->attrs.rpt_id, rpt_id, (size_t)IEC61850_RCB_MAX_NAME - 1U);
    }
    rcb->attrs.rpt_ena = false;
    rcb->attrs.conf_rev = 1;
    rcb->attrs.sq_num = 0;
    rcb->attrs.entry_id = 0;

    /* Default trigger: dchg + gi */
    rcb->attrs.trg_ops.data_change = true;
    rcb->attrs.trg_ops.general_interrogation = true;

    /* Default opt fields: seqNum + timestamp */
    rcb->attrs.opt_flds.sequence_number = true;
    rcb->attrs.opt_flds.report_timestamp = true;

    pthread_mutex_init(&rcb->mutex, NULL);
    atomic_store(&rcb->running, false);
    rcb->initialized = true;
}

void iec61850_rcb_destroy(iec61850_rcb_t *rcb)
{
    if ((rcb == NULL) || (!rcb->initialized)) { return; }

    if (atomic_load(&rcb->running)) {
        (void)iec61850_rcb_disable(rcb);
    }

    pthread_mutex_destroy(&rcb->mutex);
    rcb->initialized = false;
}

int iec61850_rcb_enable(iec61850_rcb_t *rcb)
{
    int ret;

    if ((rcb == NULL) || (!rcb->initialized)) { return -EINVAL; }

    pthread_mutex_lock(&rcb->mutex);

    if (rcb->attrs.rpt_ena) {
        pthread_mutex_unlock(&rcb->mutex);
        return 0;  /* Already enabled */
    }

    rcb->attrs.rpt_ena = true;
    atomic_store(&rcb->running, true);

    /* Start integrity scanner if intgPd > 0 */
    rcb->has_integrity_thread = false;
    if ((rcb->attrs.intg_pd > 0U) || (rcb->attrs.trg_ops.integrity)) {
        ret = pthread_create(&rcb->integrity_thread, NULL,
                               integrity_thread_func, rcb);
        if (ret != 0) {
            rcb->attrs.rpt_ena = false;
            atomic_store(&rcb->running, false);
            pthread_mutex_unlock(&rcb->mutex);
            return -ret;
        }
        rcb->has_integrity_thread = true;
    }

    pthread_mutex_unlock(&rcb->mutex);
    return 0;
}

int iec61850_rcb_disable(iec61850_rcb_t *rcb)
{
    if ((rcb == NULL) || (!rcb->initialized)) { return -EINVAL; }

    pthread_mutex_lock(&rcb->mutex);
    rcb->attrs.rpt_ena = false;
    pthread_mutex_unlock(&rcb->mutex);

    if (atomic_load(&rcb->running)) {
        atomic_store(&rcb->running, false);
        if (rcb->has_integrity_thread) {
            (void)pthread_join(rcb->integrity_thread, NULL);
            rcb->has_integrity_thread = false;
        }
    }

    return 0;
}

void iec61850_rcb_set_report_sender(iec61850_rcb_t *rcb,
                                      void (*sender)(const mms_information_report_t *,
                                                      void *),
                                      void *user_data)
{
    if (rcb == NULL) { return; }

    pthread_mutex_lock(&rcb->mutex);
    rcb->report_sender = sender;
    rcb->report_sender_data = user_data;
    pthread_mutex_unlock(&rcb->mutex);
}

void iec61850_rcb_on_data_change(iec61850_rcb_t *rcb,
                                   const char *var_ref,
                                   const mms_value_t *old_val, /* NOLINT(bugprone-easily-swappable-parameters) */
                                   const mms_value_t *new_val)
{
    if ((rcb == NULL) || (!rcb->attrs.rpt_ena)) { return; }
    if (!rcb->attrs.trg_ops.data_change) { return; }

    (void)old_val;  /* Used for change detection, not included in report */

    pthread_mutex_lock(&rcb->mutex);
    generate_report(rcb, var_ref, new_val, IEC61850_REASON_DCHG);
    pthread_mutex_unlock(&rcb->mutex);
}

/* Generate a report for a given trigger reason */
static void generate_report(iec61850_rcb_t *rcb,
                              const char *var_ref,
                              const mms_value_t *value,
                              iec61850_reason_code_t reason)
{
    if (rcb->report_sender == NULL) { return; }

    mms_information_report_t report;
    uint16_t next_sq;
    (void)memset(&report, 0, sizeof(report));
    (void)strncpy(report.variable_list_name, rcb->attrs.rpt_id,
                   (size_t)MMS_MAX_VARIABLE_NAME - 1U);
    report_fill_metadata(&report, rcb);

    /* Ed.2: SqNum of a report is its 1-based position in the stream
     * (incremented per transmitted report). */
    next_sq = (uint16_t)(rcb->attrs.sq_num + 1U);

    /* Optional fields */
    if (rcb->attrs.opt_flds.sequence_number) {
        report.sq_num_present = true;
        report.sq_num = next_sq;
    }
    if (rcb->attrs.opt_flds.report_timestamp) {
        struct timespec ts;
        (void)clock_gettime(CLOCK_REALTIME, &ts);
        report.report_timestamp_present = true;
        report.report_timestamp = ((uint64_t)ts.tv_sec * 1000ULL) +
                                  ((uint64_t)ts.tv_nsec / 1000000ULL);
    }
    if (rcb->attrs.opt_flds.reason_for_inclusion) {
        report.reasons_present = true;
        report.reasons[0] = (uint8_t)reason;
    }
    if ((rcb->attrs.opt_flds.data_reference) && (var_ref != NULL)) {
        report.data_references_present = true;
        (void)strncpy(report.data_references[0], var_ref,
                       (size_t)MMS_MAX_VARIABLE_NAME - 1U);
    }
    if ((rcb->attrs.opt_flds.buffer_overflow) &&
        (rcb->type == IEC61850_RCB_BUFFERED)) {
        report.buffer_overflow_present = true;
        report.buffer_overflow = false;
    }
    if ((rcb->attrs.opt_flds.entry_id) &&
        (rcb->type == IEC61850_RCB_BUFFERED)) {
        report.entry_id_present = true;
        report.entry_id = rcb->attrs.entry_id;
    }
    if (rcb->attrs.opt_flds.config_ref) {
        report.config_ref_present = true;
        (void)snprintf(report.config_ref, MMS_MAX_VARIABLE_NAME,
                        "%u", rcb->attrs.conf_rev);
    }

    if ((value != NULL) && (report.num_values < (uint32_t)MMS_MAX_NAMED_VARIABLES)) {
        report.values[report.num_values] = *value;
        report.num_values++;
    }

    rcb->attrs.sq_num = next_sq;
    if (rcb->type == IEC61850_RCB_BUFFERED) {
        rcb->attrs.entry_id++;
    }

    rcb->report_sender(&report, rcb->report_sender_data);
}

void iec61850_rcb_on_quality_change(iec61850_rcb_t *rcb,
                                       const char *var_ref,
                                       const mms_value_t *value)
{
    if ((rcb == NULL) || (!rcb->attrs.rpt_ena)) { return; }
    if (!rcb->attrs.trg_ops.quality_change) { return; }

    pthread_mutex_lock(&rcb->mutex);
    generate_report(rcb, var_ref, value, IEC61850_REASON_QCHG);
    pthread_mutex_unlock(&rcb->mutex);
}

void iec61850_rcb_on_data_update(iec61850_rcb_t *rcb,
                                    const char *var_ref,
                                    const mms_value_t *value)
{
    if ((rcb == NULL) || (!rcb->attrs.rpt_ena)) { return; }
    if (!rcb->attrs.trg_ops.data_update) { return; }

    pthread_mutex_lock(&rcb->mutex);
    generate_report(rcb, var_ref, value, IEC61850_REASON_DUPD);
    pthread_mutex_unlock(&rcb->mutex);
}

void iec61850_rcb_trigger_gi(iec61850_rcb_t *rcb)
{
    if ((rcb == NULL) || (!rcb->attrs.rpt_ena)) { return; }
    if (!rcb->attrs.trg_ops.general_interrogation) { return; }

    pthread_mutex_lock(&rcb->mutex);

    rcb->attrs.gi = true;

    if (rcb->report_sender != NULL) {
        mms_information_report_t report;
        (void)memset(&report, 0, sizeof(report));
        (void)strncpy(report.variable_list_name, rcb->attrs.rpt_id,
                       (size_t)MMS_MAX_VARIABLE_NAME - 1U);
        report_fill_metadata(&report, rcb);

        /* Snapshot all data values from data store if available */
        if (rcb->data_store != NULL) {
            /* MISRA 11.5: opaque data_store handle, deviation Cat. 3 */
            iec61850_mms_data_store_t *ds =
                (iec61850_mms_data_store_t *)rcb->data_store;
            /* Parse domain from dat_set (format: "domain/list") */
            char domain[IEC61850_RCB_MAX_NAME] = {0};
            (void)strncpy(domain, rcb->attrs.dat_set, (size_t)IEC61850_RCB_MAX_NAME - 1U);
            char *slash = strchr(domain, '/');
            const char *list_name = NULL;
            if (slash != NULL) {
                *slash = '\0';
                list_name = slash + 1;
            }

            /* Prefer the exact dataset membership when the DatSet
             * reference resolves to a named variable list (WP-2a);
             * fall back to a domain-wide snapshot otherwise. */
            mms_variable_spec_t members[MMS_MAX_NAMED_VARIABLES];
            uint32_t member_count = 0;
            bool use_list = false;

            if ((list_name != NULL) && (list_name[0] != '\0') &&
                (iec61850_mms_ds_get_list_attrs(ds, domain, list_name,
                                                 members, &member_count,
                                                 MMS_MAX_NAMED_VARIABLES) ==
                 (int)IEC61850_MMS_DS_OK)) {
                use_list = true;
            }

            if (use_list) {
                for (uint32_t i = 0U; (i < member_count) &&
                     (report.num_values < (uint32_t)MMS_MAX_NAMED_VARIABLES); i++) {
                    mms_value_t val;
                    (void)memset(&val, 0, sizeof(val));
                    if (iec61850_mms_ds_read_variable(ds, members[i].domain,
                                                       members[i].item_id,
                                                       &val) == (int)IEC61850_MMS_DS_OK) {
                        report.values[report.num_values] = val;
                        if (rcb->attrs.opt_flds.reason_for_inclusion) {
                            report.reasons[report.num_values] =
                                (uint8_t)IEC61850_REASON_GI;
                        }
                        report.num_values++;
                    }
                }
            } else {
                /* Read all variable names from domain */
                char var_names[MMS_MAX_NAMED_VARIABLES][MMS_MAX_VARIABLE_NAME];
                uint32_t name_count = 0;
                (void)iec61850_mms_ds_get_var_names(ds, domain,
                                                      var_names, &name_count,
                                                      MMS_MAX_NAMED_VARIABLES);
                /* Read each variable value */
                for (uint32_t i = 0U; (i < name_count) &&
                     (report.num_values < (uint32_t)MMS_MAX_NAMED_VARIABLES); i++) {
                    mms_value_t val;
                    (void)memset(&val, 0, sizeof(val));
                    if (iec61850_mms_ds_read_variable(ds, domain, var_names[i],
                                                        &val) == (int)IEC61850_MMS_DS_OK) {
                        report.values[report.num_values] = val;
                        if (rcb->attrs.opt_flds.reason_for_inclusion) {
                            report.reasons[report.num_values] =
                                (uint8_t)IEC61850_REASON_GI;
                        }
                        report.num_values++;
                    }
                }
            }
        }

        /* Optional fields */
        if (rcb->attrs.opt_flds.sequence_number) {
            report.sq_num_present = true;
            report.sq_num = (uint16_t)(rcb->attrs.sq_num + 1U);
        }
        if (rcb->attrs.opt_flds.report_timestamp) {
            struct timespec ts;
            (void)clock_gettime(CLOCK_REALTIME, &ts);
            report.report_timestamp_present = true;
            report.report_timestamp = ((uint64_t)ts.tv_sec * 1000ULL) +
                                      ((uint64_t)ts.tv_nsec / 1000000ULL);
        }
        if (rcb->attrs.opt_flds.reason_for_inclusion) {
            report.reasons_present = true;
        }

        rcb->attrs.sq_num++;
        if (rcb->type == IEC61850_RCB_BUFFERED) {
            rcb->attrs.entry_id++;
        }

        rcb->report_sender(&report, rcb->report_sender_data);
    }

    rcb->attrs.gi = false;
    pthread_mutex_unlock(&rcb->mutex);
}

/* ========================================================================
 * Report Buffer Implementation
 * ======================================================================== */

void iec61850_report_buffer_init(iec61850_report_buffer_t *buf,
                                   uint32_t capacity)
{
    if (buf == NULL) { return; }
    (void)memset(buf, 0, sizeof(*buf));
    if (capacity > (uint32_t)IEC61850_RCB_MAX_BUFFER) {
        capacity = (uint32_t)IEC61850_RCB_MAX_BUFFER;
    }
    buf->capacity = capacity;
    buf->next_entry_id = 1;
}

uint64_t iec61850_report_buffer_add(iec61850_report_buffer_t *buf,
                                      iec61850_reason_code_t reason,
                                      const char *var_ref,
                                      const mms_value_t *value,
                                      uint64_t timestamp_ms)
{
    iec61850_report_entry_t *entry;

    if ((buf == NULL) || (buf->capacity == 0U)) { return 0; }

    /* Purge oldest if full */
    if (buf->count >= buf->capacity) {
        buf->overflow = true;
    }

    entry = &buf->entries[buf->head];
    entry->entry_id = buf->next_entry_id; buf->next_entry_id++;
    entry->sq_num = 0;
    entry->timestamp_ms = timestamp_ms;
    entry->reason = reason;
    entry->valid = true;

    if (var_ref != NULL) {
        (void)strncpy(entry->var_ref, var_ref, (size_t)IEC61850_RCB_MAX_NAME - 1U);
        entry->var_ref[(size_t)IEC61850_RCB_MAX_NAME - 1U] = '\0';
    } else {
        entry->var_ref[0] = '\0';
    }

    if (value != NULL) {
        entry->value = *value;
    } else {
        (void)memset(&entry->value, 0, sizeof(entry->value));
    }

    buf->head = (buf->head + 1U) % buf->capacity;
    if (buf->count < buf->capacity) {
        buf->count++;
    }

    return entry->entry_id;
}

int iec61850_report_buffer_get_entries(const iec61850_report_buffer_t *buf,
                                         uint64_t after_id,
                                         iec61850_report_entry_t *out,
                                         uint32_t *count, uint32_t max_count)
{
    uint32_t found = 0;
    uint32_t start;

    if ((buf == NULL) || (out == NULL) || (count == NULL)) {
        return -EINVAL;
    }

    *count = 0;

    if (buf->count == 0U) {
        return 0;
    }

    /* Start from oldest entry */
    if (buf->count < buf->capacity) {
        start = 0;
    } else {
        start = buf->head;  /* head points past newest, so it's the oldest */
    }

    for (uint32_t i = 0; (i < buf->count) && (found < max_count); i++) {
        uint32_t idx = (start + i) % buf->capacity;
        const iec61850_report_entry_t *e = &buf->entries[idx];

        if (!e->valid) { continue; }
        if (e->entry_id <= after_id) { continue; }

        out[found] = *e; found++;
    }

    *count = found;
    return 0;
}

bool iec61850_report_buffer_had_overflow(iec61850_report_buffer_t *buf)
{
    if (buf == NULL) { return false; }
    bool was = buf->overflow;
    buf->overflow = false;
    return was;
}

void iec61850_report_buffer_purge(iec61850_report_buffer_t *buf)
{
    if (buf == NULL) { return; }
    buf->head = 0;
    buf->count = 0;
    buf->overflow = false;
    /* next_entry_id intentionally kept: EntryIDs stay unique and
     * monotonic for the whole RCB lifetime (Ed.2, conservative). */
}

/* ========================================================================
 * RCB Manager Implementation
 * ======================================================================== */

void iec61850_rcb_manager_init(iec61850_rcb_manager_t *mgr,
                                 const char *ld_name)
{
    if (mgr == NULL) { return; }
    (void)memset(mgr, 0, sizeof(*mgr));
    if (ld_name != NULL) {
        (void)strncpy(mgr->ld_name, ld_name, (size_t)IEC61850_RCB_MAX_NAME - 1U);
    }
}

void iec61850_rcb_manager_destroy(iec61850_rcb_manager_t *mgr)
{
    if (mgr == NULL) { return; }

    for (uint32_t i = 0; i < mgr->rcb_count; i++) {
        iec61850_rcb_destroy(&mgr->rcbs[i]);
    }
    mgr->rcb_count = 0;
}

int iec61850_rcb_manager_add_rcb(iec61850_rcb_manager_t *mgr,
                                   const char *rpt_id,
                                   iec61850_rcb_type_t type,
                                   uint32_t buf_size)
{
    if ((mgr == NULL) || (rpt_id == NULL)) {
        return -EINVAL;
    }

    if (mgr->rcb_count >= (uint32_t)IEC61850_RCB_MANAGER_MAX_RCBS) {
        return -ENOMEM;
    }

    uint32_t idx = mgr->rcb_count;
    iec61850_rcb_init(&mgr->rcbs[idx], rpt_id, type);

    /* Initialize report buffer for buffered RCBs */
    if ((type == IEC61850_RCB_BUFFERED) && (buf_size > 0U)) {
        iec61850_report_buffer_init(&mgr->buffers[idx], buf_size);
    }

    mgr->rcb_count++;

    /* Bridge already active: expose the new RCB immediately. */
    if (mgr->bridge.active) {
        (void)bridge_expose_rcb(mgr, idx);
    }
    return (int)idx;
}

iec61850_rcb_t *iec61850_rcb_manager_find_rcb(iec61850_rcb_manager_t *mgr,
                                                 const char *rpt_id)
{
    if ((mgr == NULL) || (rpt_id == NULL)) { return NULL; }

    for (uint32_t i = 0; i < mgr->rcb_count; i++) {
        if (strcmp(mgr->rcbs[i].attrs.rpt_id, rpt_id) == 0) {
            return &mgr->rcbs[i];
        }
    }
    return NULL;
}

void iec61850_rcb_manager_on_data_change(iec61850_rcb_manager_t *mgr,
                                            const char *var_ref,
                                            const mms_value_t *old_val,
                                            const mms_value_t *new_val)
{
    uint64_t timestamp_ms;

    if (mgr == NULL) { return; }

    timestamp_ms = now_ms();

    for (uint32_t i = 0; i < mgr->rcb_count; i++) {
        iec61850_rcb_t *rcb = &mgr->rcbs[i];

        if ((!rcb->attrs.rpt_ena) || (!rcb->attrs.trg_ops.data_change)) {
            continue;
        }

        /* For buffered RCBs, add to buffer and deliver through the
         * BufTm pipeline (buf_tm == 0: one report per entry, sent
         * immediately when an association can receive it; buf_tm > 0:
         * entries aggregate into one report per closed window). */
        if ((rcb->type == IEC61850_RCB_BUFFERED) &&
            (mgr->buffers[i].capacity > 0U)) {
            (void)iec61850_report_buffer_add(&mgr->buffers[i],
                                              IEC61850_REASON_DCHG,
                                              var_ref, new_val,
                                              timestamp_ms);
            if (bridge_can_deliver(mgr)) {
                brcb_flush(mgr, i, timestamp_ms, false);
            }
            continue;
        }

        /* Trigger the report sender (URCB path) */
        iec61850_rcb_on_data_change(rcb, var_ref, old_val, new_val);
    }
}

void iec61850_rcb_manager_trigger_gi(iec61850_rcb_manager_t *mgr)
{
    if (mgr == NULL) { return; }

    for (uint32_t i = 0; i < mgr->rcb_count; i++) {
        iec61850_rcb_trigger_gi(&mgr->rcbs[i]);
    }
}

iec61850_report_buffer_t *iec61850_rcb_manager_get_buffer(
    iec61850_rcb_manager_t *mgr, uint32_t rcb_index)
{
    if ((mgr == NULL) || (rcb_index >= mgr->rcb_count)) {
        return NULL;
    }
    return &mgr->buffers[rcb_index];
}

/* ========================================================================
 * RCB <-> data-store bridge — IEC 61850-8-1 Ed.2 semantics (WP-2a)
 *
 * Component-object model (WP-1f DIV-1, standard "$"-separated
 * naming): every managed RCB is exposed under the LN0 reference
 * "LLN0$RP$<name>" (URCB) / "LLN0$BR$<name>" (BRCB) — RCBs live in
 * LN0 per IEC 61850-7-2 — with one named variable per component,
 * named "<reference>$<Component>" (e.g. "LLN0$RP$urcb01$RptEna"),
 * matching the naming of reference IEC 61850 servers and of this
 * repo's WP-1c client. Value encodings (matching the client):
 *   RptEna, Resv, GI, PurgeBuf ... BOOLEAN
 *   RptID, DatSet, Owner ........ VISIBLE-STRING
 *   ConfRev, BufTm, IntgPd, SqNum  UNSIGNED
 *   OptFlds ..................... BIT-STRING (10 bits)
 *   TrgOps ...................... BIT-STRING (6 bits)
 *   EntryID ..................... OCTET-STRING (8 bytes, big-endian)
 * ======================================================================== */

#define RCB_BRIDGE_ENTRY_ID_LEN 8u

/* OptFlds value-octet bits (first octet, then second). */
#define RCB_OF_SEQ_NUM    0x40u
#define RCB_OF_TIMESTAMP  0x20u
#define RCB_OF_REASON     0x10u
#define RCB_OF_DATA_SET   0x08u
#define RCB_OF_DATA_REF   0x04u
#define RCB_OF_BUF_OVFL   0x02u
#define RCB_OF_ENTRY_ID   0x01u
#define RCB_OF_CONF_REV   0x80u

/* TrgOps value-octet bits (first octet). */
#define RCB_TO_DCHG   0x40u
#define RCB_TO_QCHG   0x20u
#define RCB_TO_DUPD   0x10u
#define RCB_TO_PERIOD 0x08u
#define RCB_TO_GI     0x04u

typedef enum {
    RCB_COMP_NONE = 0,
    RCB_COMP_RPT_ID,
    RCB_COMP_RPT_ENA,
    RCB_COMP_RESV,
    RCB_COMP_DAT_SET,
    RCB_COMP_CONF_REV,
    RCB_COMP_OPT_FLDS,
    RCB_COMP_BUF_TM,
    RCB_COMP_TRG_OPS,
    RCB_COMP_INTG_PD,
    RCB_COMP_GI,
    RCB_COMP_SQ_NUM,
    RCB_COMP_PURGE_BUF,
    RCB_COMP_ENTRY_ID,
    RCB_COMP_OWNER
} rcb_comp_t;

static rcb_comp_t bridge_suffix_comp(const char *suffix,
                                     iec61850_rcb_type_t type)
{
    rcb_comp_t comp = RCB_COMP_NONE;

    if (strcmp(suffix, "RptID") == 0) {
        comp = RCB_COMP_RPT_ID;
    } else if (strcmp(suffix, "RptEna") == 0) {
        comp = RCB_COMP_RPT_ENA;
    } else if (strcmp(suffix, "DatSet") == 0) {
        comp = RCB_COMP_DAT_SET;
    } else if (strcmp(suffix, "ConfRev") == 0) {
        comp = RCB_COMP_CONF_REV;
    } else if (strcmp(suffix, "OptFlds") == 0) {
        comp = RCB_COMP_OPT_FLDS;
    } else if (strcmp(suffix, "BufTm") == 0) {
        comp = RCB_COMP_BUF_TM;
    } else if (strcmp(suffix, "TrgOps") == 0) {
        comp = RCB_COMP_TRG_OPS;
    } else if (strcmp(suffix, "IntgPd") == 0) {
        comp = RCB_COMP_INTG_PD;
    } else if (strcmp(suffix, "GI") == 0) {
        comp = RCB_COMP_GI;
    } else if (strcmp(suffix, "SqNum") == 0) {
        comp = RCB_COMP_SQ_NUM;
    } else if (strcmp(suffix, "Owner") == 0) {
        comp = RCB_COMP_OWNER;
    } else if (strcmp(suffix, "Resv") == 0) {
        /* Resv is a URCB-only component (Ed.2 BRCBs use ResvTms,
         * not implemented — conservative deviation, flagged). */
        comp = (type == IEC61850_RCB_UNBUFFERED) ? RCB_COMP_RESV
                                                 : RCB_COMP_NONE;
    } else if (strcmp(suffix, "PurgeBuf") == 0) {
        comp = (type == IEC61850_RCB_BUFFERED) ? RCB_COMP_PURGE_BUF
                                               : RCB_COMP_NONE;
    } else if (strcmp(suffix, "EntryID") == 0) {
        comp = (type == IEC61850_RCB_BUFFERED) ? RCB_COMP_ENTRY_ID
                                               : RCB_COMP_NONE;
    }

    return comp;
}

static const char *bridge_comp_suffix(rcb_comp_t comp)
{
    switch (comp) {
        case RCB_COMP_RPT_ID:    return "RptID";
        case RCB_COMP_RPT_ENA:   return "RptEna";
        case RCB_COMP_RESV:      return "Resv";
        case RCB_COMP_DAT_SET:   return "DatSet";
        case RCB_COMP_CONF_REV:  return "ConfRev";
        case RCB_COMP_OPT_FLDS:  return "OptFlds";
        case RCB_COMP_BUF_TM:    return "BufTm";
        case RCB_COMP_TRG_OPS:   return "TrgOps";
        case RCB_COMP_INTG_PD:   return "IntgPd";
        case RCB_COMP_GI:        return "GI";
        case RCB_COMP_SQ_NUM:    return "SqNum";
        case RCB_COMP_PURGE_BUF: return "PurgeBuf";
        case RCB_COMP_ENTRY_ID:  return "EntryID";
        case RCB_COMP_OWNER:     return "Owner";
        default:                 break;
    }
    return NULL;
}

/* ---- value marshaling (bridge component types) ---- */

static mms_value_t bridge_mk_bool(bool b)
{
    mms_value_t v;
    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_BOOLEAN;
    v.value.boolean = b;
    return v;
}

static mms_value_t bridge_mk_str(const char *s)
{
    mms_value_t v;
    size_t len = strlen(s);
    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_VISIBLE_STRING;
    if (len >= (size_t)MMS_MAX_STRING_LENGTH) {
        len = (size_t)MMS_MAX_STRING_LENGTH - 1u;
    }
    (void)memcpy(v.value.visible_string.data, s, len);
    v.value.visible_string.data[len] = '\0';
    v.value.visible_string.len = len;
    return v;
}

static mms_value_t bridge_mk_u32(uint32_t u)
{
    mms_value_t v;
    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_UNSIGNED;
    v.value.unsigned_val = u;
    return v;
}

static mms_value_t bridge_mk_opt_flds(const iec61850_opt_flds_t *f)
{
    mms_value_t v;
    uint8_t b0 = 0u;
    uint8_t b1 = 0u;

    if (f->sequence_number)      { b0 |= RCB_OF_SEQ_NUM; }
    if (f->report_timestamp)     { b0 |= RCB_OF_TIMESTAMP; }
    if (f->reason_for_inclusion) { b0 |= RCB_OF_REASON; }
    if (f->data_set_name)        { b0 |= RCB_OF_DATA_SET; }
    if (f->data_reference)       { b0 |= RCB_OF_DATA_REF; }
    if (f->buffer_overflow)      { b0 |= RCB_OF_BUF_OVFL; }
    if (f->entry_id)             { b0 |= RCB_OF_ENTRY_ID; }
    if (f->config_ref)           { b1 |= RCB_OF_CONF_REV; }

    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_BIT_STRING;
    v.value.bit_string.data[0] = b0;
    v.value.bit_string.data[1] = b1;
    v.value.bit_string.bit_count = 10u;
    return v;
}

static mms_value_t bridge_mk_trg_ops(const iec61850_trg_ops_t *t)
{
    mms_value_t v;
    uint8_t b0 = 0u;

    if (t->data_change)           { b0 |= RCB_TO_DCHG; }
    if (t->quality_change)        { b0 |= RCB_TO_QCHG; }
    if (t->data_update)           { b0 |= RCB_TO_DUPD; }
    if (t->integrity)             { b0 |= RCB_TO_PERIOD; }
    if (t->general_interrogation) { b0 |= RCB_TO_GI; }

    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_BIT_STRING;
    v.value.bit_string.data[0] = b0;
    v.value.bit_string.bit_count = 6u;
    return v;
}

static mms_value_t bridge_mk_entry_id(uint64_t id)
{
    mms_value_t v;
    uint32_t i;
    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_OCTET_STRING;
    for (i = 0u; i < RCB_BRIDGE_ENTRY_ID_LEN; i++) {
        size_t idx = (size_t)i;
        v.value.octet_string.data[idx] =
            (uint8_t)((id >> (((uint64_t)RCB_BRIDGE_ENTRY_ID_LEN - 1u -
                               (uint64_t)i) * 8u)) & 0xFFu);
    }
    v.value.octet_string.len = RCB_BRIDGE_ENTRY_ID_LEN;
    return v;
}

/* ---- value parsing (mirror of the WP-1c client decoders) ---- */

static int bridge_parse_bool(const mms_value_t *v, bool *out)
{
    if ((v == NULL) || (v->type != MMS_TYPE_BOOLEAN)) { return -EINVAL; }
    *out = v->value.boolean;
    return 0;
}

static int bridge_parse_str(const mms_value_t *v, char *out, size_t out_size)
{
    size_t len;
    if ((v == NULL) || (v->type != MMS_TYPE_VISIBLE_STRING) ||
        (out == NULL) || (out_size == 0U)) {
        return -EINVAL;
    }
    len = v->value.visible_string.len;
    if (len >= (size_t)MMS_MAX_STRING_LENGTH) {
        len = strlen(v->value.visible_string.data);
    }
    if (len >= out_size) { len = out_size - 1u; }
    (void)memcpy(out, v->value.visible_string.data, len);
    out[len] = '\0';
    return 0;
}

static int bridge_parse_u32(const mms_value_t *v, uint32_t *out)
{
    if (v == NULL) { return -EINVAL; }
    if (v->type == MMS_TYPE_UNSIGNED) {
        *out = v->value.unsigned_val;
        return 0;
    }
    if ((v->type == MMS_TYPE_INTEGER) && (v->value.integer >= 0)) {
        *out = (uint32_t)v->value.integer;
        return 0;
    }
    return -EINVAL;
}

static int bridge_parse_opt_flds(const mms_value_t *v,
                                 iec61850_opt_flds_t *out)
{
    uint8_t b0;
    uint8_t b1;
    size_t byte_count;

    if ((v == NULL) || (v->type != MMS_TYPE_BIT_STRING) || (out == NULL)) {
        return -EINVAL;
    }
    byte_count = ((v->value.bit_string.bit_count + 7u) / 8u);
    if (byte_count == 0u) { return -EINVAL; }
    b0 = v->value.bit_string.data[0];
    b1 = (byte_count > 1u) ? v->value.bit_string.data[1] : 0u;

    (void)memset(out, 0, sizeof(*out));
    out->sequence_number      = ((b0 & RCB_OF_SEQ_NUM) != 0u);
    out->report_timestamp     = ((b0 & RCB_OF_TIMESTAMP) != 0u);
    out->reason_for_inclusion = ((b0 & RCB_OF_REASON) != 0u);
    out->data_set_name        = ((b0 & RCB_OF_DATA_SET) != 0u);
    out->data_reference       = ((b0 & RCB_OF_DATA_REF) != 0u);
    out->buffer_overflow      = ((b0 & RCB_OF_BUF_OVFL) != 0u);
    out->entry_id             = ((b0 & RCB_OF_ENTRY_ID) != 0u);
    out->config_ref           = ((b1 & RCB_OF_CONF_REV) != 0u);
    return 0;
}

static int bridge_parse_trg_ops(const mms_value_t *v,
                                iec61850_trg_ops_t *out)
{
    uint8_t b0;

    if ((v == NULL) || (v->type != MMS_TYPE_BIT_STRING) ||
        (out == NULL) || (v->value.bit_string.bit_count < 6u)) {
        return -EINVAL;
    }
    b0 = v->value.bit_string.data[0];

    (void)memset(out, 0, sizeof(*out));
    out->data_change           = ((b0 & RCB_TO_DCHG) != 0u);
    out->quality_change        = ((b0 & RCB_TO_QCHG) != 0u);
    out->data_update           = ((b0 & RCB_TO_DUPD) != 0u);
    out->integrity             = ((b0 & RCB_TO_PERIOD) != 0u);
    out->general_interrogation = ((b0 & RCB_TO_GI) != 0u);
    return 0;
}

static int bridge_parse_entry_id(const mms_value_t *v, uint64_t *out)
{
    uint32_t i;

    if (v == NULL) { return -EINVAL; }

    if ((v->type == MMS_TYPE_OCTET_STRING) &&
        (v->value.octet_string.len == RCB_BRIDGE_ENTRY_ID_LEN)) {
        uint64_t id = 0u;
        for (i = 0u; i < RCB_BRIDGE_ENTRY_ID_LEN; i++) {
            size_t idx = (size_t)i;
            id = (id << 8) | (uint64_t)v->value.octet_string.data[idx];
        }
        *out = id;
        return 0;
    }

    /* Leniency: UNSIGNED EntryID. */
    if (v->type == MMS_TYPE_UNSIGNED) {
        *out = (uint64_t)v->value.unsigned_val;
        return 0;
    }
    return -EINVAL;
}

static bool bridge_value_equal(const mms_value_t *a, const mms_value_t *b)
{
    if ((a == NULL) || (b == NULL) || (a->type != b->type)) {
        return false;
    }

    switch (a->type) {
        case MMS_TYPE_BOOLEAN:
            return a->value.boolean == b->value.boolean;
        case MMS_TYPE_INTEGER:
            return a->value.integer == b->value.integer;
        case MMS_TYPE_UNSIGNED:
            return a->value.unsigned_val == b->value.unsigned_val;
        case MMS_TYPE_FLOATING_POINT:
            return a->value.floating_point == b->value.floating_point;
        case MMS_TYPE_UTC_TIME:
            return a->value.utc_time == b->value.utc_time;
        case MMS_TYPE_VISIBLE_STRING:
            return (a->value.visible_string.len ==
                    b->value.visible_string.len) &&
                   ((a->value.visible_string.len == 0u) ||
                    (memcmp(a->value.visible_string.data,
                            b->value.visible_string.data,
                            a->value.visible_string.len) == 0));
        case MMS_TYPE_OCTET_STRING:
            return (a->value.octet_string.len ==
                    b->value.octet_string.len) &&
                   ((a->value.octet_string.len == 0u) ||
                    (memcmp(a->value.octet_string.data,
                            b->value.octet_string.data,
                            a->value.octet_string.len) == 0));
        case MMS_TYPE_BIT_STRING:
            return (a->value.bit_string.bit_count ==
                    b->value.bit_string.bit_count) &&
                   (memcmp(a->value.bit_string.data,
                           b->value.bit_string.data,
                           sizeof(a->value.bit_string.data)) == 0);
        default:
            break;
    }
    return false;
}

/* ---- association / ownership ---- */

static void bridge_identity_from_association(void *association,
                                              char *out, size_t out_size)
{
    out[0] = '\0';
    if (association == NULL) { return; }
    /* MISRA 11.5: opaque session handle, deviation Cat. 3 */
    const iec61850_mms_session_t *sess =
        (const iec61850_mms_session_t *)association;
    /* Synthetic per-association owner identity: stable for the
     * lifetime of the association, unique across associations. */
    (void)snprintf(out, out_size, "sess-%u", (unsigned)sess->session_id);
}

static bool bridge_association_alive(const iec61850_rcb_manager_t *mgr)
{
    const iec61850_mms_session_t *sess;

    if (mgr->bridge.association == NULL) { return false; }
    /* MISRA 11.5: opaque session handle, deviation Cat. 3 */
    sess = (const iec61850_mms_session_t *)mgr->bridge.association;
    if (!atomic_load(&sess->active)) { return false; }
    /* Session-slot reuse guard: the recorded id must match. */
    return sess->session_id == mgr->bridge.association_id;
}

static bool bridge_can_deliver(const iec61850_rcb_manager_t *mgr)
{
    if (!mgr->bridge.active) { return true; }  /* host-managed sender */
    return bridge_association_alive(mgr);
}

static void bridge_adopt_association(iec61850_rcb_manager_t *mgr,
                                     void *association)
{
    const iec61850_mms_session_t *sess;

    if (association == NULL) { return; }
    if ((mgr->bridge.association != NULL) &&
        bridge_association_alive(mgr) &&
        (mgr->bridge.association != association)) {
        /* A live owner from another session keeps control. */
        return;
    }
    /* MISRA 11.5: opaque session handle, deviation Cat. 3 */
    sess = (const iec61850_mms_session_t *)association;
    mgr->bridge.association = association;
    mgr->bridge.association_id = sess->session_id;
    bridge_identity_from_association(association, mgr->bridge.owner_id,
                                     sizeof(mgr->bridge.owner_id));
}

static bool bridge_client_is_owner(iec61850_rcb_manager_t *mgr,
                                   void *association)
{
    if (mgr->bridge.association == NULL) { return true; }
    if (!bridge_association_alive(mgr)) { return true; }  /* stale owner */
    /* A live owner keeps control; NULL-association callers are
     * host-internal accesses and are only trusted when no live owner
     * exists (checked above). */
    return (association != NULL) &&
           (mgr->bridge.association == association);
}

/* IEC 61850 BINARY-TIME epoch: 1984-01-01T00:00:00 UTC in Unix
 * milliseconds. timeOfEntry carries milliseconds since this epoch. */
#define BRIDGE_BINARY_TIME_EPOCH_MS 441763200000ULL

/* Bridge report sender: maps the assembled report plus its WP-S1
 * metadata (rpt_id/dat_set/conf_rev, filled by the report-assembly
 * helpers) onto the conformant IEC 61850-7-2 URCB/BRCB report
 * (mms_encode_iec61850_report, WP-2z) and pushes it onto the owning
 * client's association.
 *
 * Mapping notes:
 *  - optFlds bits mirror the report's presence flags, so the wire
 *    carries exactly the fields the RCB's OptFlds armed.
 *  - dataRef (optFlds b5) is never set: mms_iec61850_report_t carries
 *    no per-member data-reference fields (frozen struct).
 *  - timeOfEntry is converted from the report's UTC-millisecond
 *    timestamp to BINARY-TIME (ms since 1984-01-01).
 *  - The inclusion bitstring marks the first num_values members: the
 *    generic report struct carries no dataset member positions.
 *  - The single frozen reason_code field carries the report's first
 *    reason code (BufTm groups normally share one trigger reason). */
static void bridge_report_sender(const mms_information_report_t *report,
                                  void *user_data)
{
    /* MISRA 11.5: callback context is the manager, deviation Cat. 3 */
    iec61850_rcb_manager_t *mgr = (iec61850_rcb_manager_t *)user_data;
    mms_iec61850_report_t rpt;
    uint8_t buf[4096];
    int len;
    uint32_t i;

    if ((mgr == NULL) || (report == NULL) ||
        (!bridge_association_alive(mgr))) {
        return;
    }
    /* MISRA 11.5: opaque session handle, deviation Cat. 3 */
    iec61850_mms_session_t *sess =
        (iec61850_mms_session_t *)mgr->bridge.association;

    (void)memset(&rpt, 0, sizeof(rpt));

    /* rptID: WP-S1 metadata field, falling back to the legacy
     * variable_list_name (RptID) used by host-managed assemblies. */
    if (report->rpt_id[0] != '\0') {
        (void)strncpy(rpt.rpt_id, report->rpt_id,
                      (size_t)MMS_MAX_STRING_LENGTH - 1U);
    } else {
        (void)strncpy(rpt.rpt_id, report->variable_list_name,
                      (size_t)MMS_MAX_STRING_LENGTH - 1U);
    }
    rpt.rpt_id[MMS_MAX_STRING_LENGTH - 1U] = '\0';

    /* datSet: carried only when the assembly filled it (RCB
     * OptFlds data-set-name armed). */
    if (report->dat_set[0] != '\0') {
        (void)strncpy(rpt.dat_set, report->dat_set,
                      (size_t)MMS_MAX_STRING_LENGTH - 1U);
        rpt.dat_set[MMS_MAX_STRING_LENGTH - 1U] = '\0';
        rpt.opt_flds_byte |= 0x08u;  /* b4: data-set-name */
    }

    if (report->sq_num_present) {
        rpt.sq_num = report->sq_num;
        rpt.sq_num_present = true;
        rpt.opt_flds_byte |= 0x40u;  /* b1: sequence-number */
    }
    if (report->report_timestamp_present) {
        uint64_t bt = report->report_timestamp;

        if (bt < BRIDGE_BINARY_TIME_EPOCH_MS) {
            bt = 0U;  /* pre-1984 clock: saturate at the epoch */
        } else {
            bt -= BRIDGE_BINARY_TIME_EPOCH_MS;
        }
        for (i = 0u; i < 6u; i++) {
            rpt.time_of_entry[i] =
                (uint8_t)((bt >> ((5u - i) * 8u)) & 0xFFu);
        }
        rpt.time_of_entry_present = true;
        rpt.opt_flds_byte |= 0x20u;  /* b2: time-of-entry */
    }
    if (report->reasons_present) {
        rpt.reason_code = report->reasons[0];
        rpt.opt_flds_byte |= 0x10u;  /* b3: reason-for-inclusion */
    }
    if (report->buffer_overflow_present) {
        rpt.buffer_overflow = report->buffer_overflow;
        rpt.opt_flds_byte |= 0x02u;  /* b6: buffer-overflow */
    }
    if (report->entry_id_present) {
        rpt.entry_id = report->entry_id;
        rpt.opt_flds_byte |= 0x01u;  /* b7: entryID */
    }
    if (report->conf_rev_present) {
        rpt.conf_rev = report->conf_rev;
        rpt.conf_rev_present = true; /* b8 (2nd octet): confRev */
    }

    rpt.num_members = report->num_values;
    rpt.num_values = report->num_values;
    for (i = 0u; i < report->num_values; i++) {
        rpt.values[i] = report->values[i];
    }

    len = mms_encode_iec61850_report(&rpt, buf, sizeof(buf));
    if (len > 0) {
        (void)iec61850_iso_send(&sess->iso, buf, (size_t)len);
    }
}

/* ---- BRCB BufTm pipeline ---- */

/* Emit one aggregated report for a group of buffered entries
 * (deduplicated by dataset member — last value wins). */
static void brcb_emit_group(iec61850_rcb_manager_t *mgr, uint32_t idx,
                            const iec61850_report_entry_t *const *group,
                            uint32_t group_len)
{
    iec61850_rcb_t *rcb = &mgr->rcbs[idx];
    iec61850_report_buffer_t *rbuf = &mgr->buffers[idx];
    mms_information_report_t report;
    const char *refs[MMS_MAX_NAMED_VARIABLES];
    uint32_t n_members = 0u;
    uint32_t i;
    uint32_t j;

    if ((rcb->report_sender == NULL) || (group_len == 0U)) { return; }

    (void)memset(&report, 0, sizeof(report));
    (void)strncpy(report.variable_list_name, rcb->attrs.rpt_id,
                  (size_t)MMS_MAX_VARIABLE_NAME - 1U);
    report_fill_metadata(&report, rcb);

    for (i = 0u; (i < group_len) && (n_members < MMS_MAX_NAMED_VARIABLES); i++) {
        const iec61850_report_entry_t *e = group[i];
        bool found = false;

        for (j = 0u; j < n_members; j++) {
            if (strcmp(refs[j], e->var_ref) == 0) {
                found = true;
                break;
            }
        }
        if (found) {
            report.values[j] = e->value;
            report.reasons[j] = (uint8_t)e->reason;
        } else {
            refs[n_members] = e->var_ref;
            report.values[n_members] = e->value;
            report.reasons[n_members] = (uint8_t)e->reason;
            n_members++;
        }
    }
    report.num_values = n_members;

    if (rcb->attrs.opt_flds.sequence_number) {
        report.sq_num_present = true;
        report.sq_num = (uint16_t)(rcb->attrs.sq_num + 1U);
    }
    if (rcb->attrs.opt_flds.report_timestamp) {
        report.report_timestamp_present = true;
        report.report_timestamp = group[group_len - 1u]->timestamp_ms;
    }
    if (rcb->attrs.opt_flds.reason_for_inclusion) {
        report.reasons_present = true;
    }
    if (rcb->attrs.opt_flds.data_reference) {
        report.data_references_present = true;
        for (j = 0u; j < n_members; j++) {
            (void)strncpy(report.data_references[j], refs[j],
                          (size_t)MMS_MAX_VARIABLE_NAME - 1U);
        }
    }
    if (rcb->attrs.opt_flds.entry_id) {
        report.entry_id_present = true;
        report.entry_id = group[group_len - 1u]->entry_id;
    }
    if (rcb->attrs.opt_flds.buffer_overflow) {
        report.buffer_overflow_present = true;
        report.buffer_overflow = rbuf->overflow;
        rbuf->overflow = false;   /* consumed by this report */
    }
    if (rcb->attrs.opt_flds.config_ref) {
        report.config_ref_present = true;
        (void)snprintf(report.config_ref, MMS_MAX_VARIABLE_NAME,
                       "%u", rcb->attrs.conf_rev);
    }

    pthread_mutex_lock(&rcb->mutex);
    /* Commit the stream state BEFORE sending: once a client can have
     * observed the report, the SqNum/EntryID markers must already
     * reflect it (the markers are the client-visible resume point). */
    rcb->attrs.sq_num++;
    rcb->attrs.entry_id = group[group_len - 1u]->entry_id;
    rcb->report_sender(&report, rcb->report_sender_data);
    pthread_mutex_unlock(&rcb->mutex);

    if (mgr->bridge.active) {
        bridge_publish_rcb(mgr, idx);
    }
}

/*
 * Flush buffered entries of one BRCB. Entries are grouped into BufTm
 * windows: a window closes when the next entry's timestamp is at
 * least buf_tm after the window's first entry (buf_tm == 0 therefore
 * produces one report per entry), or when buf_tm has elapsed
 * (checked against now_ms_val). force flushes the trailing open
 * window too (BRCB resume). Only entries after the RCB's EntryID
 * marker are emitted. No-op while no association can receive.
 */
static void brcb_flush(iec61850_rcb_manager_t *mgr, uint32_t idx,
                       uint64_t now_ms_val, bool force)
{
    iec61850_rcb_t *rcb = &mgr->rcbs[idx];
    iec61850_report_buffer_t *rbuf = &mgr->buffers[idx];
    const iec61850_report_entry_t *group[IEC61850_RCB_MAX_BUFFER];
    uint32_t group_len = 0u;
    uint32_t start;
    uint64_t window_first = 0u;
    uint32_t buf_tm;
    uint32_t i;

    if ((rcb->type != IEC61850_RCB_BUFFERED) || (rbuf->capacity == 0u) ||
        (rcb->report_sender == NULL)) {
        return;
    }
    if (!bridge_can_deliver(mgr)) { return; }

    buf_tm = rcb->attrs.buf_tm;
    if (rbuf->count < rbuf->capacity) {
        start = 0u;
    } else {
        start = rbuf->head;   /* oldest entry when full */
    }

    for (i = 0u; i < rbuf->count; i++) {
        const iec61850_report_entry_t *e =
            &rbuf->entries[(start + i) % rbuf->capacity];

        if ((!e->valid) || (e->entry_id <= rcb->attrs.entry_id)) {
            continue;
        }

        if ((group_len > 0u) &&
            ((e->timestamp_ms - window_first) >= (uint64_t)buf_tm)) {
            brcb_emit_group(mgr, idx, group, group_len);
            group_len = 0u;
        }
        if (group_len == 0u) {
            window_first = e->timestamp_ms;
        }
        if (group_len < (uint32_t)IEC61850_RCB_MAX_BUFFER) {
            group[group_len] = e;
            group_len++;
        }
    }

    if (group_len > 0u) {
        if (force || ((now_ms_val - window_first) >= (uint64_t)buf_tm)) {
            brcb_emit_group(mgr, idx, group, group_len);
        }
    }
}

void iec61850_rcb_manager_flush_reports(iec61850_rcb_manager_t *mgr)
{
    uint64_t ts;

    if (mgr == NULL) { return; }
    ts = now_ms();
    for (uint32_t i = 0u; i < mgr->rcb_count; i++) {
        brcb_flush(mgr, i, ts, false);
    }
}

/* ---- component variable plumbing ---- */

/* Build the IEC 61850-8-1 component item name: "<reference>$<suffix>"
 * where the reference is the exposed name of RCB idx (built at
 * expose() time from the RCB's name/type, see bridge_expose_rcb). */
static int bridge_component_item(const iec61850_rcb_manager_t *mgr,
                                 uint32_t idx, rcb_comp_t comp,
                                 char *out, size_t out_size)
{
    const char *suffix;

    if ((out == NULL) || (out_size == 0U)) { return -EINVAL; }
    if (mgr->bridge.names[idx][0] == '\0') { return -ENOENT; }
    suffix = bridge_comp_suffix(comp);
    if (suffix == NULL) { return -EINVAL; }

    return (snprintf(out, out_size, "%s$%s", mgr->bridge.names[idx],
                     suffix) < (int)out_size) ? 0 : -EINVAL;
}

static void bridge_shadow_update(iec61850_rcb_manager_t *mgr, uint32_t idx,
                                 rcb_comp_t comp, const mms_value_t *v)
{
    iec61850_rcb_bridge_shadow_t *sh = &mgr->bridge.shadow[idx];
    bool b = false;
    uint32_t u = 0u;
    uint64_t e = 0u;
    char s[IEC61850_RCB_MAX_NAME];
    iec61850_opt_flds_t of;
    iec61850_trg_ops_t to;

    switch (comp) {
        case RCB_COMP_RPT_ID:
            if (bridge_parse_str(v, s, sizeof(s)) == 0) {
                (void)strncpy(sh->rpt_id, s, (size_t)IEC61850_RCB_MAX_NAME - 1U);
                sh->rpt_id[IEC61850_RCB_MAX_NAME - 1U] = '\0';
            }
            break;
        case RCB_COMP_RPT_ENA:
            if (bridge_parse_bool(v, &b) == 0) { sh->rpt_ena = b; }
            break;
        case RCB_COMP_RESV:
            if (bridge_parse_bool(v, &b) == 0) { sh->resv = b; }
            break;
        case RCB_COMP_DAT_SET:
            if (bridge_parse_str(v, s, sizeof(s)) == 0) {
                (void)strncpy(sh->dat_set, s, (size_t)IEC61850_RCB_MAX_NAME - 1U);
                sh->dat_set[IEC61850_RCB_MAX_NAME - 1U] = '\0';
            }
            break;
        case RCB_COMP_CONF_REV:
            if (bridge_parse_u32(v, &u) == 0) { sh->conf_rev = u; }
            break;
        case RCB_COMP_OPT_FLDS:
            if (bridge_parse_opt_flds(v, &of) == 0) { sh->opt_flds = of; }
            break;
        case RCB_COMP_BUF_TM:
            if (bridge_parse_u32(v, &u) == 0) { sh->buf_tm = u; }
            break;
        case RCB_COMP_TRG_OPS:
            if (bridge_parse_trg_ops(v, &to) == 0) { sh->trg_ops = to; }
            break;
        case RCB_COMP_INTG_PD:
            if (bridge_parse_u32(v, &u) == 0) { sh->intg_pd = u; }
            break;
        case RCB_COMP_GI:
            if (bridge_parse_bool(v, &b) == 0) { sh->gi = b; }
            break;
        case RCB_COMP_SQ_NUM:
            if (bridge_parse_u32(v, &u) == 0) { sh->sq_num = (uint16_t)(u & 0xFFFFu); }
            break;
        case RCB_COMP_ENTRY_ID:
            if (bridge_parse_entry_id(v, &e) == 0) { sh->entry_id = e; }
            break;
        case RCB_COMP_OWNER:
            if (bridge_parse_str(v, s, sizeof(s)) == 0) {
                (void)strncpy(sh->owner, s, (size_t)IEC61850_RCB_MAX_NAME - 1U);
                sh->owner[IEC61850_RCB_MAX_NAME - 1U] = '\0';
            }
            break;
        case RCB_COMP_PURGE_BUF:
            /* trigger component: always published FALSE */
            break;
        default:
            break;
    }
}

/* Write one component variable to the store and refresh the shadow. */
static void bridge_publish_comp(iec61850_rcb_manager_t *mgr, uint32_t idx,
                                rcb_comp_t comp, const mms_value_t *v)
{
    char item[MMS_MAX_VARIABLE_NAME];

    if (bridge_component_item(mgr, idx, comp, item, sizeof(item)) == 0) {
        (void)iec61850_mms_ds_write_variable(mgr->bridge.store,
                                              mgr->bridge.domain, item, v);
    }
    bridge_shadow_update(mgr, idx, comp, v);
}

/* Republish every component of one RCB from its authoritative state. */
static void bridge_publish_rcb(iec61850_rcb_manager_t *mgr, uint32_t idx)
{
    iec61850_rcb_t *rcb = &mgr->rcbs[idx];
    mms_value_t v;

    if (!mgr->bridge.active) { return; }
    if (mgr->bridge.names[idx][0] == '\0') { return; }

    v = bridge_mk_str(rcb->attrs.rpt_id);
    bridge_publish_comp(mgr, idx, RCB_COMP_RPT_ID, &v);

    v = bridge_mk_bool(rcb->attrs.rpt_ena);
    bridge_publish_comp(mgr, idx, RCB_COMP_RPT_ENA, &v);

    if (rcb->type == IEC61850_RCB_UNBUFFERED) {
        v = bridge_mk_bool(rcb->resv);
        bridge_publish_comp(mgr, idx, RCB_COMP_RESV, &v);
    }

    v = bridge_mk_str(rcb->attrs.dat_set);
    bridge_publish_comp(mgr, idx, RCB_COMP_DAT_SET, &v);

    v = bridge_mk_u32(rcb->attrs.conf_rev);
    bridge_publish_comp(mgr, idx, RCB_COMP_CONF_REV, &v);

    v = bridge_mk_opt_flds(&rcb->attrs.opt_flds);
    bridge_publish_comp(mgr, idx, RCB_COMP_OPT_FLDS, &v);

    v = bridge_mk_u32(rcb->attrs.buf_tm);
    bridge_publish_comp(mgr, idx, RCB_COMP_BUF_TM, &v);

    v = bridge_mk_trg_ops(&rcb->attrs.trg_ops);
    bridge_publish_comp(mgr, idx, RCB_COMP_TRG_OPS, &v);

    v = bridge_mk_u32(rcb->attrs.intg_pd);
    bridge_publish_comp(mgr, idx, RCB_COMP_INTG_PD, &v);

    v = bridge_mk_bool(rcb->attrs.gi);
    bridge_publish_comp(mgr, idx, RCB_COMP_GI, &v);

    v = bridge_mk_u32(rcb->attrs.sq_num);
    bridge_publish_comp(mgr, idx, RCB_COMP_SQ_NUM, &v);

    v = bridge_mk_str(rcb->owner);
    bridge_publish_comp(mgr, idx, RCB_COMP_OWNER, &v);

    if (rcb->type == IEC61850_RCB_BUFFERED) {
        v = bridge_mk_entry_id(rcb->attrs.entry_id);
        bridge_publish_comp(mgr, idx, RCB_COMP_ENTRY_ID, &v);

        v = bridge_mk_bool(false);
        bridge_publish_comp(mgr, idx, RCB_COMP_PURGE_BUF, &v);
    }

    mgr->bridge.shadow[idx].valid = true;
}

/* Create one component variable (idempotent). */
static void bridge_create_comp(iec61850_rcb_manager_t *mgr, uint32_t idx,
                               rcb_comp_t comp, const mms_value_t *initial)
{
    char item[MMS_MAX_VARIABLE_NAME];
    int ret;

    if (bridge_component_item(mgr, idx, comp, item, sizeof(item)) != 0) {
        return;
    }
    ret = iec61850_mms_ds_create_variable(mgr->bridge.store,
                                           mgr->bridge.domain, item,
                                           initial->type, initial);
    if (ret == (int)IEC61850_MMS_DS_ERR_EXISTS) {
        (void)iec61850_mms_ds_write_variable(mgr->bridge.store,
                                              mgr->bridge.domain, item,
                                              initial);
    }
}

/* Expose one RCB's component objects and take over its report path. */
static int bridge_expose_rcb(iec61850_rcb_manager_t *mgr, uint32_t idx)
{
    iec61850_rcb_t *rcb = &mgr->rcbs[idx];
    mms_value_t v;
    const char *name = rcb->attrs.rpt_id;

    if (!mgr->bridge.active) { return -EINVAL; }
    if ((name == NULL) || (name[0] == '\0')) { return -EINVAL; }

    /* Exposed reference, IEC 61850-8-1 (WP-1f DIV-1): RCBs live in
     * LN0 ("LLN0"), $-separated with the RP (URCB) / BR (BRCB)
     * segment, e.g. "LLN0$RP$urcb01". Truncation beyond the
     * IEC61850_RCB_MAX_NAME budget keeps the reference usable (the
     * same truncated form is used consistently for publish and
     * lookup). */
    {
        const char *seg =
            (rcb->type == IEC61850_RCB_BUFFERED) ? "BR" : "RP";
        int n = snprintf(mgr->bridge.names[idx],
                         (size_t)IEC61850_RCB_MAX_NAME,
                         "LLN0$%s$%s", seg, name);
        if (n < 0) {
            return -EINVAL;
        }
    }
    mgr->bridge.shadow[idx].valid = false;

    /* GI snapshots read from the bridged store. */
    rcb->data_store = mgr->bridge.store;

    /* The bridge owns the report path (overwrites any sender set
     * before expose; hosts may override again afterwards). */
    iec61850_rcb_set_report_sender(rcb, bridge_report_sender, mgr);

    v = bridge_mk_str(rcb->attrs.rpt_id);
    bridge_create_comp(mgr, idx, RCB_COMP_RPT_ID, &v);
    v = bridge_mk_bool(rcb->attrs.rpt_ena);
    bridge_create_comp(mgr, idx, RCB_COMP_RPT_ENA, &v);
    if (rcb->type == IEC61850_RCB_UNBUFFERED) {
        v = bridge_mk_bool(rcb->resv);
        bridge_create_comp(mgr, idx, RCB_COMP_RESV, &v);
    }
    v = bridge_mk_str(rcb->attrs.dat_set);
    bridge_create_comp(mgr, idx, RCB_COMP_DAT_SET, &v);
    v = bridge_mk_u32(rcb->attrs.conf_rev);
    bridge_create_comp(mgr, idx, RCB_COMP_CONF_REV, &v);
    v = bridge_mk_opt_flds(&rcb->attrs.opt_flds);
    bridge_create_comp(mgr, idx, RCB_COMP_OPT_FLDS, &v);
    v = bridge_mk_u32(rcb->attrs.buf_tm);
    bridge_create_comp(mgr, idx, RCB_COMP_BUF_TM, &v);
    v = bridge_mk_trg_ops(&rcb->attrs.trg_ops);
    bridge_create_comp(mgr, idx, RCB_COMP_TRG_OPS, &v);
    v = bridge_mk_u32(rcb->attrs.intg_pd);
    bridge_create_comp(mgr, idx, RCB_COMP_INTG_PD, &v);
    v = bridge_mk_bool(rcb->attrs.gi);
    bridge_create_comp(mgr, idx, RCB_COMP_GI, &v);
    v = bridge_mk_u32(rcb->attrs.sq_num);
    bridge_create_comp(mgr, idx, RCB_COMP_SQ_NUM, &v);
    v = bridge_mk_str(rcb->owner);
    bridge_create_comp(mgr, idx, RCB_COMP_OWNER, &v);
    if (rcb->type == IEC61850_RCB_BUFFERED) {
        v = bridge_mk_entry_id(rcb->attrs.entry_id);
        bridge_create_comp(mgr, idx, RCB_COMP_ENTRY_ID, &v);
        v = bridge_mk_bool(false);
        bridge_create_comp(mgr, idx, RCB_COMP_PURGE_BUF, &v);
    }

    bridge_publish_rcb(mgr, idx);
    return 0;
}

int iec61850_rcb_manager_expose(iec61850_rcb_manager_t *mgr,
                                iec61850_mms_data_store_t *store,
                                const char *domain)
{
    uint32_t i;

    if ((mgr == NULL) || (store == NULL) || (domain == NULL) ||
        (domain[0] == '\0')) {
        return -EINVAL;
    }
    if (mgr->bridge.active) { return -EBUSY; }

    (void)iec61850_mms_ds_create_domain(store, domain);  /* idempotent */
    mgr->bridge.store = store;
    (void)strncpy(mgr->bridge.domain, domain,
                  (size_t)MMS_MAX_DOMAIN_NAME - 1U);
    mgr->bridge.domain[MMS_MAX_DOMAIN_NAME - 1U] = '\0';
    mgr->bridge.active = true;

    for (i = 0u; i < mgr->rcb_count; i++) {
        (void)bridge_expose_rcb(mgr, i);
    }
    return 0;
}

/* ---- monitored data points (dchg / qchg dispatch) ---- */

static iec61850_rcb_bridge_data_shadow_t *bridge_data_shadow_find(
    iec61850_rcb_manager_t *mgr, const char *ref)
{
    uint32_t i;

    for (i = 0u; i < (uint32_t)IEC61850_RCB_BRIDGE_DATA_SHADOWS; i++) {
        iec61850_rcb_bridge_data_shadow_t *s = &mgr->bridge.data_shadow[i];
        if ((s->valid) && (strcmp(s->ref, ref) == 0)) {
            return s;
        }
    }
    return NULL;
}

static void bridge_data_shadow_put(iec61850_rcb_manager_t *mgr,
                                   const char *ref, const mms_value_t *v)
{
    iec61850_rcb_bridge_data_shadow_t *s = bridge_data_shadow_find(mgr, ref);

    if (s == NULL) {
        /* Bounded round-robin allocation. */
        s = &mgr->bridge.data_shadow[mgr->bridge.data_shadow_next %
                                     (uint32_t)IEC61850_RCB_BRIDGE_DATA_SHADOWS];
        mgr->bridge.data_shadow_next++;
    }
    s->valid = true;
    (void)strncpy(s->ref, ref, (size_t)IEC61850_RCB_BRIDGE_REF_MAX - 1U);
    s->ref[IEC61850_RCB_BRIDGE_REF_MAX - 1U] = '\0';
    s->value = *v;
}

/* Resolve the dat_set reference of one RCB: "domain/list" names a
 * named variable list; if that list exists, membership is exact,
 * otherwise every variable of the domain is monitored (conservative
 * fallback mirroring the GI snapshot approximation). */
static bool bridge_rcb_monitors(iec61850_rcb_manager_t *mgr, uint32_t idx,
                                const char *domain, const char *item)
{
    const iec61850_rcb_t *rcb = &mgr->rcbs[idx];
    const char *ds = rcb->attrs.dat_set;
    const char *slash;
    char ds_domain[MMS_MAX_DOMAIN_NAME];
    char ds_list[MMS_MAX_VARIABLE_NAME];
    size_t dom_len;
    size_t list_len;
    mms_variable_spec_t members[MMS_MAX_NAMED_VARIABLES];
    uint32_t n = 0u;
    bool monitored = false;
    uint32_t i;

    if (ds[0] == '\0') { return false; }

    slash = strchr(ds, '/');
    if (slash == NULL) {
        /* No domain part: look for a list in the bridge domain. */
        (void)strncpy(ds_domain, mgr->bridge.domain,
                      (size_t)MMS_MAX_DOMAIN_NAME - 1U);
        ds_domain[MMS_MAX_DOMAIN_NAME - 1U] = '\0';
        (void)strncpy(ds_list, ds, (size_t)MMS_MAX_VARIABLE_NAME - 1U);
        ds_list[MMS_MAX_VARIABLE_NAME - 1U] = '\0';
    } else {
        dom_len = (size_t)(slash - ds);
        list_len = strlen(slash + 1);
        if ((dom_len >= sizeof(ds_domain)) ||
            (list_len >= sizeof(ds_list))) {
            return false;
        }
        (void)memcpy(ds_domain, ds, dom_len);
        ds_domain[dom_len] = '\0';
        (void)memcpy(ds_list, slash + 1, list_len);
        ds_list[list_len] = '\0';
    }

    if (iec61850_mms_ds_get_list_attrs(mgr->bridge.store, ds_domain,
                                        ds_list, members, &n,
                                        MMS_MAX_NAMED_VARIABLES) ==
        (int)IEC61850_MMS_DS_OK) {
        for (i = 0u; i < n; i++) {
            if ((strcmp(members[i].domain, domain) == 0) &&
                (strcmp(members[i].item_id, item) == 0)) {
                monitored = true;
                break;
            }
        }
        return monitored;
    }

    /* List not found: domain-wide monitoring. */
    return strcmp(ds_domain, domain) == 0;
}

/* Snapshot current values of every monitored member so reads (and
 * idempotent rewrites) never trigger reports. */
static void bridge_seed_data_shadows(iec61850_rcb_manager_t *mgr)
{
    uint32_t i;

    if (!mgr->bridge.active) { return; }

    for (i = 0u; i < mgr->rcb_count; i++) {
        const iec61850_rcb_t *rcb = &mgr->rcbs[i];
        const char *ds = rcb->attrs.dat_set;
        const char *slash;
        char ds_domain[MMS_MAX_DOMAIN_NAME];
        char ds_list[MMS_MAX_VARIABLE_NAME];
        char names[MMS_MAX_NAMED_VARIABLES][MMS_MAX_VARIABLE_NAME];
        uint32_t n = 0u;
        uint32_t k;

        if (ds[0] == '\0') { continue; }

        slash = strchr(ds, '/');
        if (slash != NULL) {
            size_t dom_len = (size_t)(slash - ds);
            size_t list_len = strlen(slash + 1);
            if ((dom_len >= sizeof(ds_domain)) ||
                (list_len >= sizeof(ds_list))) {
                continue;
            }
            (void)memcpy(ds_domain, ds, dom_len);
            ds_domain[dom_len] = '\0';
            (void)memcpy(ds_list, slash + 1, list_len);
            ds_list[list_len] = '\0';
        } else {
            (void)strncpy(ds_domain, mgr->bridge.domain,
                          (size_t)MMS_MAX_DOMAIN_NAME - 1U);
            ds_domain[MMS_MAX_DOMAIN_NAME - 1U] = '\0';
            (void)strncpy(ds_list, ds,
                          (size_t)MMS_MAX_VARIABLE_NAME - 1U);
            ds_list[MMS_MAX_VARIABLE_NAME - 1U] = '\0';
        }

        if (iec61850_mms_ds_domain_exists(mgr->bridge.store, ds_domain)) {
            mms_variable_spec_t members[MMS_MAX_NAMED_VARIABLES];
            uint32_t mn = 0u;

            if (iec61850_mms_ds_get_list_attrs(mgr->bridge.store, ds_domain,
                                                ds_list, members, &mn,
                                                MMS_MAX_NAMED_VARIABLES) ==
                (int)IEC61850_MMS_DS_OK) {
                for (k = 0u; k < mn; k++) {
                    mms_value_t v;
                    char ref[IEC61850_RCB_BRIDGE_REF_MAX];
                    if (iec61850_mms_ds_read_variable(mgr->bridge.store,
                                                       members[k].domain,
                                                       members[k].item_id,
                                                       &v) ==
                        (int)IEC61850_MMS_DS_OK) {
                        (void)snprintf(ref, sizeof(ref), "%s/%s",
                                       members[k].domain, members[k].item_id);
                        bridge_data_shadow_put(mgr, ref, &v);
                    }
                }
                continue;
            }

            /* No list: domain-wide (mirrors bridge_rcb_monitors). */
            (void)iec61850_mms_ds_get_var_names(mgr->bridge.store, ds_domain,
                                                  names, &n,
                                                  MMS_MAX_NAMED_VARIABLES);
            for (k = 0u; k < n; k++) {
                mms_value_t v;
                char ref[IEC61850_RCB_BRIDGE_REF_MAX];
                if (iec61850_mms_ds_read_variable(mgr->bridge.store, ds_domain,
                                                   names[k], &v) ==
                    (int)IEC61850_MMS_DS_OK) {
                    (void)snprintf(ref, sizeof(ref), "%s/%s", ds_domain,
                                   names[k]);
                    bridge_data_shadow_put(mgr, ref, &v);
                }
            }
        }
    }
}

/* Dispatch a monitored data-point access (dchg, or qchg for "$q"
 * items — the repo's quality-variable convention). */
static void bridge_dispatch_data(iec61850_rcb_manager_t *mgr,
                                 const char *domain, const char *item)
{
    char ref[IEC61850_RCB_BRIDGE_REF_MAX];
    mms_value_t value;
    iec61850_rcb_bridge_data_shadow_t *shadow;
    size_t item_len;
    bool is_q;
    uint64_t ts;
    uint32_t i;

    item_len = strlen(item);
    if (item_len >= (size_t)IEC61850_RCB_BRIDGE_REF_MAX) { return; }
    if (snprintf(ref, sizeof(ref), "%s/%s", domain, item) >=
        (int)sizeof(ref)) {
        return;
    }

    if (iec61850_mms_ds_read_variable(mgr->bridge.store, domain, item,
                                       &value) != (int)IEC61850_MMS_DS_OK) {
        return;
    }

    /* Reads and idempotent writes never trigger (Ed.2 dchg/qchg
     * require an actual value change). */
    shadow = bridge_data_shadow_find(mgr, ref);
    if ((shadow != NULL) && bridge_value_equal(&shadow->value, &value)) {
        return;
    }
    bridge_data_shadow_put(mgr, ref, &value);

    is_q = ((item_len > 2u) &&
            (strcmp(&item[item_len - 2u], "$q") == 0));
    ts = now_ms();

    for (i = 0u; i < mgr->rcb_count; i++) {
        iec61850_rcb_t *rcb = &mgr->rcbs[i];

        if (!rcb->attrs.rpt_ena) { continue; }
        if (!bridge_rcb_monitors(mgr, i, domain, item)) { continue; }

        if (is_q) {
            if (!rcb->attrs.trg_ops.quality_change) { continue; }
            if ((rcb->type == IEC61850_RCB_BUFFERED) &&
                (mgr->buffers[i].capacity > 0u)) {
                (void)iec61850_report_buffer_add(&mgr->buffers[i],
                                                  IEC61850_REASON_QCHG,
                                                  ref, &value, ts);
                if (bridge_can_deliver(mgr)) {
                    brcb_flush(mgr, i, ts, false);
                }
            } else {
                iec61850_rcb_on_quality_change(rcb, ref, &value);
            }
        } else {
            if (!rcb->attrs.trg_ops.data_change) { continue; }
            if ((rcb->type == IEC61850_RCB_BUFFERED) &&
                (mgr->buffers[i].capacity > 0u)) {
                (void)iec61850_report_buffer_add(&mgr->buffers[i],
                                                  IEC61850_REASON_DCHG,
                                                  ref, &value, ts);
                if (bridge_can_deliver(mgr)) {
                    brcb_flush(mgr, i, ts, false);
                }
            } else {
                iec61850_rcb_on_data_change(rcb, ref, &value, &value);
            }
        }
    }
}

/* ---- Ed.2 component-write validation and application ---- */

static int bridge_apply_component(iec61850_rcb_manager_t *mgr, uint32_t idx,
                                  rcb_comp_t comp, const mms_value_t *val,
                                  void *association)
{
    iec61850_rcb_t *rcb = &mgr->rcbs[idx];
    bool b;
    uint32_t u;
    uint64_t eid;
    char s[IEC61850_RCB_MAX_NAME];
    iec61850_opt_flds_t of;
    iec61850_trg_ops_t to;
    int ret;

    switch (comp) {
        case RCB_COMP_RPT_ENA:
            if (bridge_parse_bool(val, &b) != 0) { return -EINVAL; }
            if (b) {
                /* Ed.2: URCB enable requires a prior reservation. */
                if ((rcb->type == IEC61850_RCB_UNBUFFERED) &&
                    (!rcb->resv)) {
                    return -EACCES;
                }
                if ((rcb->owner[0] != '\0') &&
                    (!bridge_client_is_owner(mgr, association))) {
                    return -EACCES;
                }
                bridge_adopt_association(mgr, association);
                if (association != NULL) {
                    pthread_mutex_lock(&rcb->mutex);
                    (void)strncpy(rcb->owner, mgr->bridge.owner_id,
                                  (size_t)IEC61850_RCB_MAX_NAME - 1U);
                    rcb->owner[IEC61850_RCB_MAX_NAME - 1U] = '\0';
                    pthread_mutex_unlock(&rcb->mutex);
                }
                ret = iec61850_rcb_enable(rcb);
                if (ret != 0) { return ret; }
                if (mgr->bridge.active) {
                    bridge_seed_data_shadows(mgr);
                }
                if (rcb->type == IEC61850_RCB_BUFFERED) {
                    /* Resume: flush everything after the EntryID
                     * marker the client armed (force open windows). */
                    brcb_flush(mgr, idx, now_ms(), true);
                }
            } else {
                if ((rcb->owner[0] != '\0') && (association != NULL) &&
                    (!bridge_client_is_owner(mgr, association))) {
                    return -EACCES;
                }
                (void)iec61850_rcb_disable(rcb);
                pthread_mutex_lock(&rcb->mutex);
                rcb->resv = false;
                rcb->owner[0] = '\0';
                pthread_mutex_unlock(&rcb->mutex);
            }
            return 0;

        case RCB_COMP_RESV:
            if (rcb->type != IEC61850_RCB_UNBUFFERED) { return -EINVAL; }
            if (bridge_parse_bool(val, &b) != 0) { return -EINVAL; }
            if (b) {
                if ((rcb->owner[0] != '\0') &&
                    (!bridge_client_is_owner(mgr, association))) {
                    return -EACCES;
                }
                bridge_adopt_association(mgr, association);
                pthread_mutex_lock(&rcb->mutex);
                rcb->resv = true;
                if (association != NULL) {
                    (void)strncpy(rcb->owner, mgr->bridge.owner_id,
                                  (size_t)IEC61850_RCB_MAX_NAME - 1U);
                    rcb->owner[IEC61850_RCB_MAX_NAME - 1U] = '\0';
                }
                pthread_mutex_unlock(&rcb->mutex);
            } else {
                if ((rcb->owner[0] != '\0') && (association != NULL) &&
                    (!bridge_client_is_owner(mgr, association))) {
                    return -EACCES;
                }
                pthread_mutex_lock(&rcb->mutex);
                rcb->resv = false;
                rcb->owner[0] = '\0';
                pthread_mutex_unlock(&rcb->mutex);
            }
            return 0;

        case RCB_COMP_RPT_ID:
        case RCB_COMP_DAT_SET:
        case RCB_COMP_CONF_REV:
        case RCB_COMP_OPT_FLDS:
        case RCB_COMP_BUF_TM:
        case RCB_COMP_TRG_OPS:
        case RCB_COMP_INTG_PD:
            /* Ed.2: configuration attributes are read-only while the
             * RCB is enabled (conservative interpretation). */
            if (rcb->attrs.rpt_ena) { return -EACCES; }

            switch (comp) {
                case RCB_COMP_RPT_ID:
                    if (bridge_parse_str(val, s, sizeof(s)) != 0) {
                        return -EINVAL;
                    }
                    pthread_mutex_lock(&rcb->mutex);
                    (void)strncpy(rcb->attrs.rpt_id, s,
                                  (size_t)IEC61850_RCB_MAX_NAME - 1U);
                    rcb->attrs.rpt_id[IEC61850_RCB_MAX_NAME - 1U] = '\0';
                    pthread_mutex_unlock(&rcb->mutex);
                    break;
                case RCB_COMP_DAT_SET:
                    if (bridge_parse_str(val, s, sizeof(s)) != 0) {
                        return -EINVAL;
                    }
                    pthread_mutex_lock(&rcb->mutex);
                    (void)strncpy(rcb->attrs.dat_set, s,
                                  (size_t)IEC61850_RCB_MAX_NAME - 1U);
                    rcb->attrs.dat_set[IEC61850_RCB_MAX_NAME - 1U] = '\0';
                    pthread_mutex_unlock(&rcb->mutex);
                    if (mgr->bridge.active) {
                        bridge_seed_data_shadows(mgr);
                    }
                    break;
                case RCB_COMP_CONF_REV:
                    if (bridge_parse_u32(val, &u) != 0) { return -EINVAL; }
                    pthread_mutex_lock(&rcb->mutex);
                    rcb->attrs.conf_rev = u;
                    pthread_mutex_unlock(&rcb->mutex);
                    break;
                case RCB_COMP_OPT_FLDS:
                    if (bridge_parse_opt_flds(val, &of) != 0) {
                        return -EINVAL;
                    }
                    pthread_mutex_lock(&rcb->mutex);
                    rcb->attrs.opt_flds = of;
                    pthread_mutex_unlock(&rcb->mutex);
                    break;
                case RCB_COMP_BUF_TM:
                    if (bridge_parse_u32(val, &u) != 0) { return -EINVAL; }
                    pthread_mutex_lock(&rcb->mutex);
                    rcb->attrs.buf_tm = u;
                    pthread_mutex_unlock(&rcb->mutex);
                    break;
                case RCB_COMP_TRG_OPS:
                    if (bridge_parse_trg_ops(val, &to) != 0) {
                        return -EINVAL;
                    }
                    pthread_mutex_lock(&rcb->mutex);
                    rcb->attrs.trg_ops = to;
                    pthread_mutex_unlock(&rcb->mutex);
                    break;
                case RCB_COMP_INTG_PD:
                    if (bridge_parse_u32(val, &u) != 0) { return -EINVAL; }
                    pthread_mutex_lock(&rcb->mutex);
                    rcb->attrs.intg_pd = u;
                    pthread_mutex_unlock(&rcb->mutex);
                    break;
                default:
                    return -EINVAL;
            }
            return 0;

        case RCB_COMP_GI:
            if (bridge_parse_bool(val, &b) != 0) { return -EINVAL; }
            if (!b) { return 0; }
            if (!rcb->attrs.rpt_ena) { return -EACCES; }
            if (!bridge_client_is_owner(mgr, association)) {
                return -EACCES;
            }
            iec61850_rcb_trigger_gi(rcb);
            /* trigger_gi resets attrs.gi; publish writes GI=FALSE. */
            return 0;

        case RCB_COMP_PURGE_BUF:
            if (rcb->type != IEC61850_RCB_BUFFERED) { return -EINVAL; }
            if (bridge_parse_bool(val, &b) != 0) { return -EINVAL; }
            if (!b) { return 0; }
            if (!bridge_client_is_owner(mgr, association)) {
                return -EACCES;
            }
            iec61850_report_buffer_purge(&mgr->buffers[idx]);
            pthread_mutex_lock(&rcb->mutex);
            /* Reset the visible EntryID marker (resume from scratch);
             * the entry-ID counter itself stays monotonic. */
            rcb->attrs.entry_id = 0u;
            pthread_mutex_unlock(&rcb->mutex);
            return 0;

        case RCB_COMP_ENTRY_ID:
            if (rcb->type != IEC61850_RCB_BUFFERED) { return -EINVAL; }
            if (bridge_parse_entry_id(val, &eid) != 0) { return -EINVAL; }
            /* Ed.2 deviation (flagged): a BRCB stays enabled across
             * client loss, so the resume procedure must be able to
             * arm the EntryID marker while RptEna is still TRUE. The
             * write is owner-gated (a live foreign owner rejects). */
            if (!bridge_client_is_owner(mgr, association)) {
                return -EACCES;
            }
            pthread_mutex_lock(&rcb->mutex);
            rcb->attrs.entry_id = eid;
            pthread_mutex_unlock(&rcb->mutex);
            return 0;

        case RCB_COMP_SQ_NUM:
        case RCB_COMP_OWNER:
            /* Server-published, read-only. */
            return -EACCES;

        default:
            break;
    }
    return -EINVAL;
}

/* Detect a client write to a component (store value differs from the
 * published shadow). */
static bool bridge_component_differs(iec61850_rcb_manager_t *mgr,
                                     uint32_t idx, rcb_comp_t comp,
                                     const mms_value_t *val)
{
    const iec61850_rcb_bridge_shadow_t *sh = &mgr->bridge.shadow[idx];
    bool b = false;
    uint32_t u = 0u;
    uint64_t e = 0u;
    char s[IEC61850_RCB_MAX_NAME];
    iec61850_opt_flds_t of;
    iec61850_trg_ops_t to;

    if (!sh->valid) { return true; }

    switch (comp) {
        case RCB_COMP_RPT_ENA:
            return (bridge_parse_bool(val, &b) != 0) || (b != sh->rpt_ena);
        case RCB_COMP_RESV:
            return (bridge_parse_bool(val, &b) != 0) || (b != sh->resv);
        case RCB_COMP_GI:
            return (bridge_parse_bool(val, &b) != 0) || (b != sh->gi);
        case RCB_COMP_PURGE_BUF:
            return (bridge_parse_bool(val, &b) != 0) || b;
        case RCB_COMP_RPT_ID:
            return (bridge_parse_str(val, s, sizeof(s)) != 0) ||
                   (strcmp(s, sh->rpt_id) != 0);
        case RCB_COMP_DAT_SET:
            return (bridge_parse_str(val, s, sizeof(s)) != 0) ||
                   (strcmp(s, sh->dat_set) != 0);
        case RCB_COMP_OWNER:
            return (bridge_parse_str(val, s, sizeof(s)) != 0) ||
                   (strcmp(s, sh->owner) != 0);
        case RCB_COMP_CONF_REV:
            return (bridge_parse_u32(val, &u) != 0) || (u != sh->conf_rev);
        case RCB_COMP_BUF_TM:
            return (bridge_parse_u32(val, &u) != 0) || (u != sh->buf_tm);
        case RCB_COMP_INTG_PD:
            return (bridge_parse_u32(val, &u) != 0) || (u != sh->intg_pd);
        case RCB_COMP_SQ_NUM:
            return (bridge_parse_u32(val, &u) != 0) ||
                   ((uint16_t)(u & 0xFFFFu) != sh->sq_num);
        case RCB_COMP_ENTRY_ID:
            return (bridge_parse_entry_id(val, &e) != 0) ||
                   (e != sh->entry_id);
        case RCB_COMP_OPT_FLDS:
            return (bridge_parse_opt_flds(val, &of) != 0) ||
                   (memcmp(&of, &sh->opt_flds, sizeof(of)) != 0);
        case RCB_COMP_TRG_OPS:
            return (bridge_parse_trg_ops(val, &to) != 0) ||
                   (memcmp(&to, &sh->trg_ops, sizeof(to)) != 0);
        default:
            break;
    }
    return true;
}

/* Post-commit reconcile of one component: apply client-written value
 * with Ed.2 validation; on rejection restore the authoritative value. */
static void bridge_reconcile_component(iec61850_rcb_manager_t *mgr,
                                       uint32_t idx, rcb_comp_t comp,
                                       void *association)
{
    char item[MMS_MAX_VARIABLE_NAME];
    mms_value_t val;

    if (bridge_component_item(mgr, idx, comp, item, sizeof(item)) != 0) {
        return;
    }
    if (iec61850_mms_ds_read_variable(mgr->bridge.store, mgr->bridge.domain,
                                       item, &val) != (int)IEC61850_MMS_DS_OK) {
        return;
    }
    {
        /* RptEna/Resv writes of TRUE are always significant: a BRCB
         * resume writes RptEna=TRUE while the stored value is already
         * TRUE (the RCB stays enabled across client loss), and the
         * write must (re)arm delivery and ownership. Reads of TRUE
         * re-apply idempotently (validation + no-op enable). */
        bool significant = false;
        bool b = false;

        if ((comp == RCB_COMP_RPT_ENA) || (comp == RCB_COMP_RESV)) {
            significant = (bridge_parse_bool(&val, &b) == 0) && b;
        }

        if (!bridge_component_differs(mgr, idx, comp, &val) &&
            (!significant)) {
            return;   /* our own published value (e.g. after a Read) */
        }
    }
    /* Rejected or accepted, republishing the authoritative state both
     * propagates side effects and reverts invalid writes. */
    (void)bridge_apply_component(mgr, idx, comp, &val, association);
    bridge_publish_rcb(mgr, idx);
}

/* Find the RCB and component an item refers to in the bridge domain. */
static bool bridge_lookup_item(iec61850_rcb_manager_t *mgr,
                               const char *domain, const char *item,
                               uint32_t *idx_out, rcb_comp_t *comp_out)
{
    uint32_t i;

    if ((domain == NULL) || (item == NULL) ||
        (strcmp(domain, mgr->bridge.domain) != 0)) {
        return false;
    }

    for (i = 0u; i < mgr->rcb_count; i++) {
        const char *name = mgr->bridge.names[i];
        size_t n = strlen(name);

        if ((n > 0u) && (strncmp(item, name, n) == 0) &&
            (item[n] == '$') && (item[n + 1u] != '\0')) {
            rcb_comp_t comp = bridge_suffix_comp(&item[n + 1u],
                                                 mgr->rcbs[i].type);
            if (comp != RCB_COMP_NONE) {
                *idx_out = i;
                *comp_out = comp;
                return true;
            }
        }
    }
    return false;
}

void iec61850_rcb_bridge_on_write(iec61850_rcb_manager_t *mgr,
                                  const char *domain, const char *item,
                                  void *association)
{
    uint32_t idx = 0u;
    rcb_comp_t comp = RCB_COMP_NONE;
    uint64_t ts;
    uint32_t i;

    if ((mgr == NULL) || (domain == NULL) || (item == NULL) ||
        (!mgr->bridge.active)) {
        return;
    }

    /* Liveness: flush BufTm windows that closed since the last call. */
    ts = now_ms();
    for (i = 0u; i < mgr->rcb_count; i++) {
        brcb_flush(mgr, i, ts, false);
    }

    if (bridge_lookup_item(mgr, domain, item, &idx, &comp)) {
        bridge_reconcile_component(mgr, idx, comp, association);
        return;
    }

    bridge_dispatch_data(mgr, domain, item);
}

int iec61850_rcb_bridge_write(iec61850_rcb_manager_t *mgr,
                              const char *domain, const char *item,
                              const mms_value_t *value,
                              void *association)
{
    uint32_t idx = 0u;
    rcb_comp_t comp = RCB_COMP_NONE;
    int ret;

    if ((mgr == NULL) || (domain == NULL) || (item == NULL) ||
        (value == NULL) || (!mgr->bridge.active)) {
        return -EINVAL;
    }

    if (!bridge_lookup_item(mgr, domain, item, &idx, &comp)) {
        return -ENOENT;   /* not an RCB component: server handles it */
    }

    ret = bridge_apply_component(mgr, idx, comp, value, association);
    if (ret == 0) {
        bridge_publish_rcb(mgr, idx);
    }
    return ret;
}

void iec61850_rcb_bridge_sync(iec61850_rcb_manager_t *mgr)
{
    static const rcb_comp_t comps_all[] = {
        RCB_COMP_RPT_ID, RCB_COMP_RPT_ENA, RCB_COMP_RESV,
        RCB_COMP_DAT_SET, RCB_COMP_CONF_REV, RCB_COMP_OPT_FLDS,
        RCB_COMP_BUF_TM, RCB_COMP_TRG_OPS, RCB_COMP_INTG_PD,
        RCB_COMP_GI, RCB_COMP_SQ_NUM, RCB_COMP_PURGE_BUF,
        RCB_COMP_ENTRY_ID, RCB_COMP_OWNER
    };
    uint64_t ts;
    uint32_t i;
    uint32_t c;

    if ((mgr == NULL) || (!mgr->bridge.active)) { return; }

    ts = now_ms();
    for (i = 0u; i < mgr->rcb_count; i++) {
        for (c = 0u;
             c < (uint32_t)(sizeof(comps_all) / sizeof(comps_all[0]));
             c++) {
            bridge_reconcile_component(mgr, i, comps_all[c], NULL);
        }
        brcb_flush(mgr, i, ts, false);
        bridge_publish_rcb(mgr, i);
    }
}

void iec61850_rcb_bridge_clear_association(iec61850_rcb_manager_t *mgr)
{
    uint32_t i;

    if ((mgr == NULL) || (!mgr->bridge.active)) { return; }

    for (i = 0u; i < mgr->rcb_count; i++) {
        iec61850_rcb_t *rcb = &mgr->rcbs[i];

        if (rcb->type == IEC61850_RCB_UNBUFFERED) {
            /* URCB: client loss disables reporting and releases the
             * reservation and Owner (Ed.2). */
            if (rcb->attrs.rpt_ena) {
                (void)iec61850_rcb_disable(rcb);
            }
            pthread_mutex_lock(&rcb->mutex);
            rcb->resv = false;
            rcb->owner[0] = '\0';
            pthread_mutex_unlock(&rcb->mutex);
        }
        /* BRCB: stays enabled, keeps buffering for resume; Owner is
         * retained (conservative Ed.2 interpretation). */
        bridge_publish_rcb(mgr, i);
    }

    mgr->bridge.association = NULL;
    mgr->bridge.association_id = 0u;
    mgr->bridge.owner_id[0] = '\0';
}
