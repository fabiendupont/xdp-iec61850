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
#include "mms/mms_data_store.h"

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <stdatomic.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Limits */
#define IEC61850_RCB_MAX_NAME   64
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
    uint64_t entry_id;       /* BRCB: last entry ID / client resume marker */
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

    /* Ed.2 reservation / ownership state (WP-2a, managed by the bridge) */
    bool resv;                          /* URCB reservation flag */
    char owner[IEC61850_RCB_MAX_NAME];  /* owning client identity ("" = none) */

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

/**
 * Purge the report buffer (BRCB PurgeBuf, Ed.2).
 *
 * Clears all buffered entries and the overflow flag. The EntryID
 * counter (next_entry_id) is intentionally NOT reset: entry IDs stay
 * unique and monotonically increasing for the whole RCB lifetime
 * (conservative Ed.2 reading — a client resuming with an old EntryID
 * never misses post-purge entries). Callers reset the RCB's visible
 * entry-id marker separately.
 */
void iec61850_report_buffer_purge(iec61850_report_buffer_t *buf);

/* ========================================================================
 * RCB Manager — manage multiple RCBs per logical device
 * ======================================================================== */

#define IEC61850_RCB_MANAGER_MAX_RCBS 32

/* Bounded shadow table for monitored data points (see bridge below). */
#define IEC61850_RCB_BRIDGE_DATA_SHADOWS 64
#define IEC61850_RCB_BRIDGE_REF_MAX      512

/* Per-RCB shadow of the component values the bridge itself published.
 * A store value that differs from the shadow is a client write. */
typedef struct {
    bool valid;
    bool rpt_ena;
    bool resv;
    bool gi;
    char rpt_id[IEC61850_RCB_MAX_NAME];
    char dat_set[IEC61850_RCB_MAX_NAME];
    char owner[IEC61850_RCB_MAX_NAME];
    uint32_t conf_rev;
    uint32_t buf_tm;
    uint32_t intg_pd;
    uint64_t entry_id;
    uint16_t sq_num;
    iec61850_opt_flds_t opt_flds;
    iec61850_trg_ops_t trg_ops;
} iec61850_rcb_bridge_shadow_t;

/* Shadow of a monitored data point (read-trigger suppression and
 * value-change detection for dchg/qchg dispatch). */
typedef struct {
    bool valid;
    char ref[IEC61850_RCB_BRIDGE_REF_MAX];
    mms_value_t value;
} iec61850_rcb_bridge_data_shadow_t;

/*
 * RCB <-> data-store bridge (IEC 61850-8-1 Ed.2, WP-2a).
 *
 * Exposes every managed RCB's component objects (RptEna, Resv, DatSet,
 * ConfRev, OptFlds, BufTm, TrgOps, IntgPd, GI, SqNum, Owner and, for
 * BRCBs, EntryID and PurgeBuf) as ordinary named variables named
 * "<rcb-name><Suffix>" in one logical-device domain of the data store,
 * and keeps them synchronized in both directions:
 *
 *   - client writes to a component variable (committed to the store by
 *     the MMS server) are detected against the published shadow and
 *     applied to the RCB state with Ed.2 validation
 *     (iec61850_rcb_bridge_on_write / iec61850_rcb_bridge_sync);
 *   - RCB state changes (enable, reservation, purge, buffered entries,
 *     Owner) are reflected back into the component variables.
 *
 * The bridge has no threads: the host calls on_write()/sync() from its
 * I/O context (e.g. the MMS server's post-response hook), and reports
 * are delivered through the report sender installed by expose().
 */
typedef struct {
    bool active;
    iec61850_mms_data_store_t *store;   /* not owned */
    char domain[MMS_MAX_DOMAIN_NAME];

    /* Owning client association: opaque iec61850_mms_session_t pointer
     * plus the session-id snapshot used to detect slot reuse. NULL
     * means detached (buffered RCBs keep buffering). */
    void *association;
    uint32_t association_id;
    char owner_id[IEC61850_RCB_MAX_NAME];

    /* Exposed object names (fixed at expose() time — client RptID
     * writes change report content, not object names). */
    char names[IEC61850_RCB_MANAGER_MAX_RCBS][IEC61850_RCB_MAX_NAME];
    iec61850_rcb_bridge_shadow_t shadow[IEC61850_RCB_MANAGER_MAX_RCBS];
    iec61850_rcb_bridge_data_shadow_t
        data_shadow[IEC61850_RCB_BRIDGE_DATA_SHADOWS];
    uint32_t data_shadow_next;
} iec61850_rcb_bridge_t;

typedef struct {
    iec61850_rcb_t rcbs[IEC61850_RCB_MANAGER_MAX_RCBS];
    iec61850_report_buffer_t buffers[IEC61850_RCB_MANAGER_MAX_RCBS];
    uint32_t rcb_count;
    char ld_name[IEC61850_RCB_MAX_NAME];
    iec61850_rcb_bridge_t bridge;   /* Ed.2 data-store bridge (WP-2a) */
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

/**
 * Flush pending BufTm aggregation windows of every buffered RCB.
 *
 * Emits one aggregated report per closed window (entries whose
 * timestamps are within buf_tm of the window's first entry are
 * merged into a single report, deduplicated by dataset member —
 * the last value of each member wins). Windows still open are kept.
 * Also available to hosts that do not use the data-store bridge.
 */
void iec61850_rcb_manager_flush_reports(iec61850_rcb_manager_t *mgr);

/* ========================================================================
 * RCB <-> data-store bridge (Ed.2, WP-2a)
 * ======================================================================== */

/**
 * Expose every managed RCB of the manager as MMS named variables in
 * @p domain of @p store (IEC 61850-8-1 Ed.2 component-object naming:
 * "<rcb-name>RptEna", "<rcb-name>Resv", ...; EntryID and PurgeBuf only
 * for BRCBs, Resv only for URCBs). Seeds the variables from the RCB
 * state, installs the bridge report sender on every RCB (overriding
 * any previously set sender) and attaches the store for GI snapshots.
 * RCBs added later via iec61850_rcb_manager_add_rcb() are exposed too.
 *
 * @return 0 on success, -EINVAL on bad arguments.
 */
int iec61850_rcb_manager_expose(iec61850_rcb_manager_t *mgr,
                                iec61850_mms_data_store_t *store,
                                const char *domain);

/**
 * Reconcile one client access after the server committed it to the
 * data store (post-commit hook — e.g. the MMS server's after_response
 * callback). If @p item is an RCB component object, the written value
 * is compared against the published shadow and applied to the RCB
 * state with Ed.2 validation; writes that fail validation are reverted
 * in the store. Otherwise, if the item is a monitored data point of an
 * enabled RCB, a dchg (or qchg for "$q"-suffixed items) report trigger
 * is dispatched — but only when the stored value actually changed
 * (reads and idempotent writes never trigger). BufTm windows that
 * closed since the last call are flushed.
 *
 * @param association  Opaque iec61850_mms_session_t pointer of the
 *                     requesting client (NULL for host-internal
 *                     accesses: state is reconciled, routing is not
 *                     changed, data changes are still dispatched).
 */
void iec61850_rcb_bridge_on_write(iec61850_rcb_manager_t *mgr,
                                  const char *domain, const char *item,
                                  void *association);

/**
 * Pre-validation variant of on_write for servers that can intercept
 * RCB component writes BEFORE committing them to the data store
 * (the recommended wiring): validates and applies the component value
 * and publishes it to the store itself. On success the server must
 * NOT write the variable again.
 *
 * @param association  Opaque iec61850_mms_session_t pointer of the
 *                     requesting client (used for Ed.2 ownership
 *                     validation).
 * @return 0 on success, -ENOENT when the item is not an RCB component
 *         (the server handles it normally), -EINVAL for a bad value,
 *         -EACCES when Ed.2 validation rejects the write.
 */
int iec61850_rcb_bridge_write(iec61850_rcb_manager_t *mgr,
                              const char *domain, const char *item,
                              const mms_value_t *value,
                              void *association);

/**
 * Full two-way sweep: pull client-written component values from the
 * store (same validation/revert semantics as on_write, keeping the
 * current owner identity), flush closed BufTm windows and re-publish
 * every component. Intended as a periodic poll / test entry point.
 */
void iec61850_rcb_bridge_sync(iec61850_rcb_manager_t *mgr);

/**
 * Drop the owning client association (call on client disconnect).
 * URCBs are disabled and their reservation/Owner released; buffered
 * RCBs stay enabled and keep buffering entries for later resume
 * (their Owner is retained). Report delivery stops until a new
 * association takes ownership.
 */
void iec61850_rcb_bridge_clear_association(iec61850_rcb_manager_t *mgr);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_MMS_REPORT_H */
