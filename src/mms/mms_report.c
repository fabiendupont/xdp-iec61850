/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Report Control Block Implementation
 *
 * BRCB/URCB trigger evaluation, integrity scanning, and report generation.
 */

#define _POSIX_C_SOURCE 200809L

#include "mms/mms_report.h"
#include "mms/mms_data_store.h"
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

/* Integrity scan thread */
static void *integrity_thread_func(void *arg)
{
    iec61850_rcb_t *rcb = (iec61850_rcb_t *)arg;

    while (atomic_load(&rcb->running)) {
        if (rcb->attrs.intg_pd == 0) {
            /* No integrity period configured, sleep and check */
            struct timespec ts = {1, 0};
            (void)nanosleep(&ts, NULL);
            continue;
        }

        /* Sleep for integrity period */
        struct timespec ts;
        ts.tv_sec = (long)(rcb->attrs.intg_pd / 1000U);
        ts.tv_nsec = (long)((rcb->attrs.intg_pd % 1000U) * 1000000L);
        (void)nanosleep(&ts, NULL);

        if (!atomic_load(&rcb->running) || !rcb->attrs.rpt_ena) {
            continue;
        }

        /* Generate integrity report */
        pthread_mutex_lock(&rcb->mutex);

        if (rcb->report_sender != NULL) {
            mms_information_report_t report;
            (void)memset(&report, 0, sizeof(report));
            (void)strncpy(report.variable_list_name, rcb->attrs.rpt_id,
                           MMS_MAX_VARIABLE_NAME - 1);
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
        (void)strncpy(rcb->attrs.rpt_id, rpt_id, IEC61850_RCB_MAX_NAME - 1);
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
    if (rcb == NULL || !rcb->initialized) { return; }

    if (atomic_load(&rcb->running)) {
        (void)iec61850_rcb_disable(rcb);
    }

    pthread_mutex_destroy(&rcb->mutex);
    rcb->initialized = false;
}

int iec61850_rcb_enable(iec61850_rcb_t *rcb)
{
    int ret;

    if (rcb == NULL || !rcb->initialized) { return -EINVAL; }

    pthread_mutex_lock(&rcb->mutex);

    if (rcb->attrs.rpt_ena) {
        pthread_mutex_unlock(&rcb->mutex);
        return 0;  /* Already enabled */
    }

    rcb->attrs.rpt_ena = true;
    atomic_store(&rcb->running, true);

    /* Start integrity scanner if intgPd > 0 */
    rcb->has_integrity_thread = false;
    if (rcb->attrs.intg_pd > 0 || rcb->attrs.trg_ops.integrity) {
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
    if (rcb == NULL || !rcb->initialized) { return -EINVAL; }

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
                                   const mms_value_t *old_val,
                                   const mms_value_t *new_val)
{
    if (rcb == NULL || !rcb->attrs.rpt_ena) { return; }
    if (!rcb->attrs.trg_ops.data_change) { return; }

    pthread_mutex_lock(&rcb->mutex);

    if (rcb->report_sender != NULL) {
        mms_information_report_t report;
        (void)memset(&report, 0, sizeof(report));
        (void)strncpy(report.variable_list_name, rcb->attrs.rpt_id,
                       MMS_MAX_VARIABLE_NAME - 1);

        if (var_ref != NULL) {
            (void)strncpy(report.config_ref, var_ref,
                           MMS_MAX_DOMAIN_NAME - 1);
        }

        if (new_val != NULL && report.num_values < MMS_MAX_NAMED_VARIABLES) {
            report.values[report.num_values] = *new_val;
            report.num_values++;
        }

        (void)old_val;  /* Used for change detection, not included in report */

        rcb->attrs.sq_num++;
        if (rcb->type == IEC61850_RCB_BUFFERED) {
            rcb->attrs.entry_id++;
        }

        rcb->report_sender(&report, rcb->report_sender_data);
    }

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
    (void)memset(&report, 0, sizeof(report));
    (void)strncpy(report.variable_list_name, rcb->attrs.rpt_id,
                   MMS_MAX_VARIABLE_NAME - 1);

    /* Optional fields */
    if (rcb->attrs.opt_flds.sequence_number) {
        report.sq_num_present = true;
        report.sq_num = rcb->attrs.sq_num;
    }
    if (rcb->attrs.opt_flds.report_timestamp) {
        struct timespec ts;
        (void)clock_gettime(CLOCK_REALTIME, &ts);
        report.report_timestamp_present = true;
        report.report_timestamp = (uint64_t)ts.tv_sec * 1000ULL +
                                  (uint64_t)ts.tv_nsec / 1000000ULL;
    }
    if (rcb->attrs.opt_flds.reason_for_inclusion) {
        report.reasons_present = true;
        report.reasons[0] = (uint8_t)reason;
    }
    if (rcb->attrs.opt_flds.data_reference && var_ref != NULL) {
        report.data_references_present = true;
        (void)strncpy(report.data_references[0], var_ref,
                       MMS_MAX_VARIABLE_NAME - 1);
    }
    if (rcb->attrs.opt_flds.buffer_overflow &&
        rcb->type == IEC61850_RCB_BUFFERED) {
        report.buffer_overflow_present = true;
        report.buffer_overflow = false;
    }
    if (rcb->attrs.opt_flds.entry_id &&
        rcb->type == IEC61850_RCB_BUFFERED) {
        report.entry_id_present = true;
        report.entry_id = rcb->attrs.entry_id;
    }
    if (rcb->attrs.opt_flds.config_ref) {
        report.config_ref_present = true;
        (void)snprintf(report.config_ref, MMS_MAX_VARIABLE_NAME,
                        "%u", rcb->attrs.conf_rev);
    }

    if (value != NULL && report.num_values < MMS_MAX_NAMED_VARIABLES) {
        report.values[report.num_values] = *value;
        report.num_values++;
    }

    rcb->attrs.sq_num++;
    if (rcb->type == IEC61850_RCB_BUFFERED) {
        rcb->attrs.entry_id++;
    }

    rcb->report_sender(&report, rcb->report_sender_data);
}

void iec61850_rcb_on_quality_change(iec61850_rcb_t *rcb,
                                       const char *var_ref,
                                       const mms_value_t *value)
{
    if (rcb == NULL || !rcb->attrs.rpt_ena) { return; }
    if (!rcb->attrs.trg_ops.quality_change) { return; }

    pthread_mutex_lock(&rcb->mutex);
    generate_report(rcb, var_ref, value, IEC61850_REASON_QCHG);
    pthread_mutex_unlock(&rcb->mutex);
}

void iec61850_rcb_on_data_update(iec61850_rcb_t *rcb,
                                    const char *var_ref,
                                    const mms_value_t *value)
{
    if (rcb == NULL || !rcb->attrs.rpt_ena) { return; }
    if (!rcb->attrs.trg_ops.data_update) { return; }

    pthread_mutex_lock(&rcb->mutex);
    generate_report(rcb, var_ref, value, IEC61850_REASON_DUPD);
    pthread_mutex_unlock(&rcb->mutex);
}

void iec61850_rcb_trigger_gi(iec61850_rcb_t *rcb)
{
    if (rcb == NULL || !rcb->attrs.rpt_ena) { return; }
    if (!rcb->attrs.trg_ops.general_interrogation) { return; }

    pthread_mutex_lock(&rcb->mutex);

    rcb->attrs.gi = true;

    if (rcb->report_sender != NULL) {
        mms_information_report_t report;
        (void)memset(&report, 0, sizeof(report));
        (void)strncpy(report.variable_list_name, rcb->attrs.rpt_id,
                       MMS_MAX_VARIABLE_NAME - 1);

        /* Snapshot all data values from data store if available */
        if (rcb->data_store != NULL) {
            iec61850_mms_data_store_t *ds =
                (iec61850_mms_data_store_t *)rcb->data_store;
            /* Parse domain from dat_set (format: "domain/item") */
            char domain[IEC61850_RCB_MAX_NAME] = {0};
            (void)strncpy(domain, rcb->attrs.dat_set, IEC61850_RCB_MAX_NAME - 1);
            char *slash = strchr(domain, '/');
            if (slash != NULL) {
                *slash = '\0';
            }
            /* Read all variable names from domain */
            char var_names[MMS_MAX_NAMED_VARIABLES][MMS_MAX_VARIABLE_NAME];
            uint32_t name_count = 0;
            (void)iec61850_mms_ds_get_var_names(ds, domain,
                                                  var_names, &name_count,
                                                  MMS_MAX_NAMED_VARIABLES);
            /* Read each variable value */
            for (uint32_t i = 0; i < name_count &&
                 report.num_values < MMS_MAX_NAMED_VARIABLES; i++) {
                mms_value_t val;
                (void)memset(&val, 0, sizeof(val));
                if (iec61850_mms_ds_read_variable(ds, domain, var_names[i],
                                                    &val) == IEC61850_MMS_DS_OK) {
                    report.values[report.num_values] = val;
                    if (rcb->attrs.opt_flds.reason_for_inclusion) {
                        report.reasons[report.num_values] =
                            (uint8_t)IEC61850_REASON_GI;
                    }
                    report.num_values++;
                }
            }
        }

        /* Optional fields */
        if (rcb->attrs.opt_flds.sequence_number) {
            report.sq_num_present = true;
            report.sq_num = rcb->attrs.sq_num;
        }
        if (rcb->attrs.opt_flds.report_timestamp) {
            struct timespec ts;
            (void)clock_gettime(CLOCK_REALTIME, &ts);
            report.report_timestamp_present = true;
            report.report_timestamp = (uint64_t)ts.tv_sec * 1000ULL +
                                      (uint64_t)ts.tv_nsec / 1000000ULL;
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
    if (capacity > IEC61850_RCB_MAX_BUFFER) {
        capacity = IEC61850_RCB_MAX_BUFFER;
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

    if (buf == NULL || buf->capacity == 0) { return 0; }

    /* Purge oldest if full */
    if (buf->count >= buf->capacity) {
        buf->overflow = true;
    }

    entry = &buf->entries[buf->head];
    entry->entry_id = buf->next_entry_id++;
    entry->sq_num = 0;
    entry->timestamp_ms = timestamp_ms;
    entry->reason = reason;
    entry->valid = true;

    if (var_ref != NULL) {
        (void)strncpy(entry->var_ref, var_ref, IEC61850_RCB_MAX_NAME - 1);
        entry->var_ref[IEC61850_RCB_MAX_NAME - 1] = '\0';
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

    if (buf == NULL || out == NULL || count == NULL) {
        return -EINVAL;
    }

    *count = 0;

    if (buf->count == 0) {
        return 0;
    }

    /* Start from oldest entry */
    if (buf->count < buf->capacity) {
        start = 0;
    } else {
        start = buf->head;  /* head points past newest, so it's the oldest */
    }

    for (uint32_t i = 0; i < buf->count && found < max_count; i++) {
        uint32_t idx = (start + i) % buf->capacity;
        const iec61850_report_entry_t *e = &buf->entries[idx];

        if (!e->valid) { continue; }
        if (e->entry_id <= after_id) { continue; }

        out[found++] = *e;
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

/* ========================================================================
 * RCB Manager Implementation
 * ======================================================================== */

void iec61850_rcb_manager_init(iec61850_rcb_manager_t *mgr,
                                 const char *ld_name)
{
    if (mgr == NULL) { return; }
    (void)memset(mgr, 0, sizeof(*mgr));
    if (ld_name != NULL) {
        (void)strncpy(mgr->ld_name, ld_name, IEC61850_RCB_MAX_NAME - 1);
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
    if (mgr == NULL || rpt_id == NULL) {
        return -EINVAL;
    }

    if (mgr->rcb_count >= IEC61850_RCB_MANAGER_MAX_RCBS) {
        return -ENOMEM;
    }

    uint32_t idx = mgr->rcb_count;
    iec61850_rcb_init(&mgr->rcbs[idx], rpt_id, type);

    /* Initialize report buffer for buffered RCBs */
    if (type == IEC61850_RCB_BUFFERED && buf_size > 0) {
        iec61850_report_buffer_init(&mgr->buffers[idx], buf_size);
    }

    mgr->rcb_count++;
    return (int)idx;
}

iec61850_rcb_t *iec61850_rcb_manager_find_rcb(iec61850_rcb_manager_t *mgr,
                                                 const char *rpt_id)
{
    if (mgr == NULL || rpt_id == NULL) { return NULL; }

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
    struct timespec ts;
    uint64_t timestamp_ms;

    if (mgr == NULL) { return; }

    (void)clock_gettime(CLOCK_REALTIME, &ts);
    timestamp_ms = (uint64_t)ts.tv_sec * 1000ULL +
                   (uint64_t)ts.tv_nsec / 1000000ULL;

    for (uint32_t i = 0; i < mgr->rcb_count; i++) {
        iec61850_rcb_t *rcb = &mgr->rcbs[i];

        if (!rcb->attrs.rpt_ena || !rcb->attrs.trg_ops.data_change) {
            continue;
        }

        /* For buffered RCBs, add to buffer */
        if (rcb->type == IEC61850_RCB_BUFFERED) {
            iec61850_report_buffer_add(&mgr->buffers[i],
                                         IEC61850_REASON_DCHG,
                                         var_ref, new_val, timestamp_ms);
        }

        /* Trigger the report sender */
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
    if (mgr == NULL || rcb_index >= mgr->rcb_count) {
        return NULL;
    }
    return &mgr->buffers[rcb_index];
}
