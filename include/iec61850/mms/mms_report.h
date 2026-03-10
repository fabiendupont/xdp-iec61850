/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Report Control Block (RCB) for IEC 61850
 *
 * Implements BRCB (Buffered) and URCB (Unbuffered) report control blocks.
 * Trigger evaluation (dchg, qchg, dupd, period, gi), report generation,
 * entry ID management, and buffer management.
 */

#ifndef IEC61850_MMS_REPORT_H
#define IEC61850_MMS_REPORT_H

#include "asn1/mms_ber.h"

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdatomic.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Limits */
#define IEC61850_RCB_MAX_NAME   64
#define IEC61850_RCB_MAX_REFS   64
#define IEC61850_RCB_MAX_BUFFER 256

/* Trigger reason codes */
typedef enum {
    IEC61850_REASON_DCHG      = 0x01,
    IEC61850_REASON_QCHG      = 0x02,
    IEC61850_REASON_DUPD      = 0x04,
    IEC61850_REASON_INTEGRITY = 0x08,
    IEC61850_REASON_GI        = 0x10
} iec61850_reason_code_t;

/* RCB type */
typedef enum {
    IEC61850_RCB_UNBUFFERED = 0,
    IEC61850_RCB_BUFFERED   = 1
} iec61850_rcb_type_t;

/* Trigger options */
typedef struct {
    bool data_change;
    bool quality_change;
    bool data_update;
    bool integrity;
    bool general_interrogation;
} iec61850_trg_ops_t;

/* Optional fields */
typedef struct {
    bool sequence_number;
    bool report_timestamp;
    bool reason_for_inclusion;
    bool data_set_name;
    bool data_reference;
    bool buffer_overflow;    /* BRCB only */
    bool entry_id;           /* BRCB only */
    bool config_ref;
} iec61850_opt_flds_t;

/* Report Control Block attributes */
typedef struct {
    char rpt_id[IEC61850_RCB_MAX_NAME];
    bool rpt_ena;
    char dat_set[IEC61850_RCB_MAX_NAME];
    uint32_t conf_rev;
    iec61850_opt_flds_t opt_flds;
    iec61850_trg_ops_t trg_ops;
    uint32_t buf_tm;         /* Buffer time ms */
    uint32_t intg_pd;        /* Integrity period ms (0 = disabled) */
    uint16_t sq_num;
    bool gi;                 /* GI in progress */
    uint64_t entry_id;       /* BRCB: last entry ID */
} iec61850_rcb_attrs_t;

/* Report Control Block */
typedef struct {
    iec61850_rcb_attrs_t attrs;
    iec61850_rcb_type_t type;

    /* Report callback: called when a report is generated */
    void (*report_sender)(const mms_information_report_t *report,
                           void *user_data);
    void *report_sender_data;

    /* Data store for GI snapshot (not owned, cast to iec61850_mms_data_store_t *) */
    void *data_store;

    /* Integrity scanner thread */
    pthread_t integrity_thread;
    atomic_bool running;
    bool has_integrity_thread;
    pthread_mutex_t mutex;

    bool initialized;
} iec61850_rcb_t;

/**
 * Initialize a Report Control Block.
 */
void iec61850_rcb_init(iec61850_rcb_t *rcb, const char *rpt_id,
                         iec61850_rcb_type_t type);

/**
 * Destroy RCB.
 */
void iec61850_rcb_destroy(iec61850_rcb_t *rcb);

/**
 * Enable reporting.
 */
int iec61850_rcb_enable(iec61850_rcb_t *rcb);

/**
 * Disable reporting.
 */
int iec61850_rcb_disable(iec61850_rcb_t *rcb);

/**
 * Set the report sender callback.
 */
void iec61850_rcb_set_report_sender(iec61850_rcb_t *rcb,
                                      void (*sender)(const mms_information_report_t *,
                                                      void *),
                                      void *user_data);

/**
 * Notify data change (triggers report if dchg enabled).
 */
void iec61850_rcb_on_data_change(iec61850_rcb_t *rcb,
                                   const char *var_ref,
                                   const mms_value_t *old_val,
                                   const mms_value_t *new_val);

/**
 * Handle quality change event (qchg trigger).
 */
void iec61850_rcb_on_quality_change(iec61850_rcb_t *rcb,
                                       const char *var_ref,
                                       const mms_value_t *value);

/**
 * Handle data update event (dupd trigger).
 */
void iec61850_rcb_on_data_update(iec61850_rcb_t *rcb,
                                    const char *var_ref,
                                    const mms_value_t *value);

/**
 * Trigger General Interrogation.
 */
void iec61850_rcb_trigger_gi(iec61850_rcb_t *rcb);

/* ========================================================================
 * Report Buffer (for buffered RCBs)
 * ======================================================================== */

/* Buffered report entry */
typedef struct {
    uint64_t entry_id;
    uint16_t sq_num;
    uint64_t timestamp_ms;
    iec61850_reason_code_t reason;
    char var_ref[IEC61850_RCB_MAX_NAME];
    mms_value_t value;
    bool valid;
} iec61850_report_entry_t;

/* Circular report buffer */
typedef struct {
    iec61850_report_entry_t entries[IEC61850_RCB_MAX_BUFFER];
    uint32_t head;       /* Next write position */
    uint32_t count;      /* Number of valid entries */
    uint32_t capacity;   /* Configured capacity (<= IEC61850_RCB_MAX_BUFFER) */
    uint64_t next_entry_id;
    bool overflow;       /* Buffer overflow occurred */
} iec61850_report_buffer_t;

/**
 * Initialize report buffer with given capacity.
 */
void iec61850_report_buffer_init(iec61850_report_buffer_t *buf,
                                   uint32_t capacity);

/**
 * Add an entry to the report buffer. Purges oldest if full.
 *
 * @return entry_id of the new entry
 */
uint64_t iec61850_report_buffer_add(iec61850_report_buffer_t *buf,
                                      iec61850_reason_code_t reason,
                                      const char *var_ref,
                                      const mms_value_t *value,
                                      uint64_t timestamp_ms);

/**
 * Get entries from buffer starting after given entry_id.
 *
 * @param buf        Report buffer
 * @param after_id   Return entries after this ID (0 = all)
 * @param out        Output array
 * @param count      Output: number of entries returned
 * @param max_count  Maximum entries to return
 * @return 0 on success
 */
int iec61850_report_buffer_get_entries(const iec61850_report_buffer_t *buf,
                                         uint64_t after_id,
                                         iec61850_report_entry_t *out,
                                         uint32_t *count, uint32_t max_count);

/**
 * Check if buffer overflow occurred (and clear the flag).
 */
bool iec61850_report_buffer_had_overflow(iec61850_report_buffer_t *buf);

/* ========================================================================
 * RCB Manager — manage multiple RCBs per logical device
 * ======================================================================== */

#define IEC61850_RCB_MANAGER_MAX_RCBS 32

typedef struct {
    iec61850_rcb_t rcbs[IEC61850_RCB_MANAGER_MAX_RCBS];
    iec61850_report_buffer_t buffers[IEC61850_RCB_MANAGER_MAX_RCBS];
    uint32_t rcb_count;
    char ld_name[IEC61850_RCB_MAX_NAME];
} iec61850_rcb_manager_t;

/**
 * Initialize RCB manager for a logical device.
 */
void iec61850_rcb_manager_init(iec61850_rcb_manager_t *mgr,
                                 const char *ld_name);

/**
 * Destroy RCB manager and all RCBs.
 */
void iec61850_rcb_manager_destroy(iec61850_rcb_manager_t *mgr);

/**
 * Add an RCB to the manager.
 *
 * @param mgr       RCB manager
 * @param rpt_id    Report ID
 * @param type      BRCB or URCB
 * @param buf_size  Report buffer capacity (BRCB only, 0 for URCB)
 * @return Index of the RCB (>= 0) on success, negative on error
 */
int iec61850_rcb_manager_add_rcb(iec61850_rcb_manager_t *mgr,
                                   const char *rpt_id,
                                   iec61850_rcb_type_t type,
                                   uint32_t buf_size);

/**
 * Get an RCB by report ID.
 */
iec61850_rcb_t *iec61850_rcb_manager_find_rcb(iec61850_rcb_manager_t *mgr,
                                                 const char *rpt_id);

/**
 * Notify data change across all enabled RCBs in this manager.
 * Generates reports for each RCB with matching trigger conditions.
 */
void iec61850_rcb_manager_on_data_change(iec61850_rcb_manager_t *mgr,
                                            const char *var_ref,
                                            const mms_value_t *old_val,
                                            const mms_value_t *new_val);

/**
 * Trigger GI on all enabled RCBs that have GI trigger enabled.
 */
void iec61850_rcb_manager_trigger_gi(iec61850_rcb_manager_t *mgr);

/**
 * Get the report buffer for a specific RCB (by index).
 */
iec61850_report_buffer_t *iec61850_rcb_manager_get_buffer(
    iec61850_rcb_manager_t *mgr, uint32_t rcb_index);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_MMS_REPORT_H */
