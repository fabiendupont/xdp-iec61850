/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Control Services (Select/Operate/Cancel)
 *
 * Session-scoped control object ownership with selection IDs,
 * timeouts, and state machine enforcement.
 */

#ifndef IEC61850_MMS_CONTROL_H
#define IEC61850_MMS_CONTROL_H

#include "asn1/mms_ber.h"
#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IEC61850_CONTROL_MAX_OBJECTS    64
#define IEC61850_CONTROL_DEFAULT_TIMEOUT_MS  30000

/*
 * Manager-level control error code (IEC 61850 Ed.2). Value chosen beyond
 * the ISO 9506-2 MMS_ERROR_CLASS_CONTROL codes 0-5 defined in mms_ber.h.
 */
#define IEC61850_CONTROL_ERROR_OPER_TM_INVALID  10

/**
 * Select-Before-Operate class (IEC 61850-7-2 Ed.2, sboClass).
 *
 * STRICT: an operate without a prior, still-valid select is rejected
 *         (classic Ed.1 SBO behavior; the default).
 * DYNAMIC: the operate request carries its own select check; it is
 *          accepted on a READY (unselected) control object.
 */
typedef enum {
    IEC61850_CONTROL_SBO_CLASS_STRICT = 0,
    IEC61850_CONTROL_SBO_CLASS_DYNAMIC = 1
} iec61850_control_sbo_class_t;

/**
 * AddCause (IEC 61850-8-1 Ed.2, ControlNumValueReason enumeration).
 * Reported on control rejection paths and command-termination
 * notifications; UNKNOWN (0) is used when no more specific cause applies.
 */
typedef enum {
    IEC61850_ADDCAUSE_UNKNOWN = 0,
    IEC61850_ADDCAUSE_NOT_IN_ALLOWED_VALUE_RANGE = 1,
    IEC61850_ADDCAUSE_BLOCKED_BY_SWITCHING_HIERARCHY = 2,
    IEC61850_ADDCAUSE_SELECT_FAILED = 3,
    IEC61850_ADDCAUSE_INVALID_POSITION = 4,
    IEC61850_ADDCAUSE_POSITION_REACHED = 5,
    IEC61850_ADDCAUSE_PARAMETER_CHANGE_IN_EXECUTION = 6,
    IEC61850_ADDCAUSE_STEP_LIMIT = 7,
    IEC61850_ADDCAUSE_BLOCKED_BY_MODE = 8,
    IEC61850_ADDCAUSE_BLOCKED_BY_PROCESS = 9,
    IEC61850_ADDCAUSE_BLOCKED_BY_INTERLOCKING = 10,
    IEC61850_ADDCAUSE_BLOCKED_BY_SYNCHROCHECK = 11,
    IEC61850_ADDCAUSE_COMMAND_ALREADY_IN_EXECUTION = 12,
    IEC61850_ADDCAUSE_BLOCKED_BY_HEALTH = 13,
    IEC61850_ADDCAUSE_ONE_OF_N_CONTROL = 14,
    IEC61850_ADDCAUSE_ABORTION_BY_CANCEL = 15,
    IEC61850_ADDCAUSE_TIME_LIMIT_OVERRUN = 16,
    IEC61850_ADDCAUSE_ABORTION_BY_TRIP = 17,
    IEC61850_ADDCAUSE_OBJECT_NOT_SELECTED = 18
} iec61850_control_addcause_t;

/**
 * Per-control-object Ed.2 configuration (IEC 61850 Ed.2 control model).
 */
typedef struct {
    uint32_t sbo_timeout_ms;    /**< sboTimeout: select timeout in ms, 0 = default (30 s) */
    iec61850_control_sbo_class_t sbo_class;  /**< sboClass: select-before-operate class */
} iec61850_control_config_t;

/**
 * Command-termination notification callback (IEC 61850 Ed.2
 * CommandTermination- with timestamp). Invoked when a command completes:
 * after an immediate operate finishes, when a time-activated operate fires,
 * or when a pending time-activated operate is aborted by cancel.
 *
 * @param domain        Control object domain name
 * @param item_id       Control object item ID
 * @param selection_id  Selection ID of the terminated command
 * @param success       True when the command executed successfully
 * @param addcause      Most specific AddCause for the outcome
 * @param timestamp_ms  UTC timestamp of the termination (ms since Unix epoch)
 * @param user_data     User-provided context
 */
typedef void (*iec61850_control_termination_cb_t)(const char *domain,
                                                   const char *item_id,
                                                   uint32_t selection_id,
                                                   bool success,
                                                   iec61850_control_addcause_t addcause,
                                                   uint64_t timestamp_ms,
                                                   void *user_data);

/**
 * Operate action callback. Called during iec61850_control_operate()
 * after validation, before state reset.
 *
 * @param domain    Control object domain name
 * @param item_id   Control object item ID
 * @param value     Preloaded value (NULL if no SelectWithValue was used)
 * @param user_data User-provided context
 * @return 0 on success, negative errno on failure (aborts operate)
 */
typedef int (*iec61850_control_action_cb_t)(const char *domain,
                                              const char *item_id,
                                              const mms_value_t *value,
                                              void *user_data);

typedef struct {
    char domain[MMS_MAX_DOMAIN_NAME];
    char item_id[MMS_MAX_VARIABLE_NAME];
    mms_control_state_t state;
    uint32_t selection_id;
    uint32_t owner_session_id;
    uint64_t selection_expires_at_ms;
    mms_value_t preloaded_value;
    bool has_preloaded_value;
    bool valid;
    iec61850_control_action_cb_t action_cb;
    void *action_cb_user_data;
    /* IEC 61850 Ed.2 control-model extensions */
    uint32_t sbo_timeout_ms;                        /**< sboClass timeout (0 = default) */
    iec61850_control_sbo_class_t sbo_class;         /**< sboClass (strict by default) */
    bool oper_tm_pending;                           /**< time-activated operate armed */
    uint64_t oper_tm_due_ms;                        /**< monotonic due time of operTm */
    iec61850_control_addcause_t last_addcause;      /**< most recent rejection cause */
    iec61850_control_termination_cb_t termination_cb;
    void *termination_cb_user_data;
    pthread_mutex_t mutex;
} iec61850_control_object_t;

typedef struct {
    iec61850_control_object_t objects[IEC61850_CONTROL_MAX_OBJECTS];
    uint32_t count;
    uint32_t next_selection_id;
    pthread_mutex_t mutex;
} iec61850_control_manager_t;

void iec61850_control_manager_init(iec61850_control_manager_t *mgr);
void iec61850_control_manager_destroy(iec61850_control_manager_t *mgr);

int iec61850_control_register(iec61850_control_manager_t *mgr,
                                const char *domain, const char *item_id);

/**
 * Set action callback for a registered control object.
 * Called during operate to perform the actual switching action.
 */
int iec61850_control_set_action_callback(iec61850_control_manager_t *mgr,
                                           const char *domain,
                                           const char *item_id,
                                           iec61850_control_action_cb_t cb,
                                           void *user_data);

int iec61850_control_select(iec61850_control_manager_t *mgr,
                              const char *domain, const char *item_id,
                              uint32_t session_id,
                              mms_select_response_t *resp);

int iec61850_control_select_with_value(iec61850_control_manager_t *mgr,
                                         const char *domain,
                                         const char *item_id,
                                         uint32_t session_id,
                                         const mms_value_t *value,
                                         mms_select_with_value_response_t *resp);

/** Session and selection identifiers for control operations. */
typedef struct {
    uint32_t session_id;
    uint32_t selection_id;
} iec61850_control_ids_t;

int iec61850_control_operate(iec61850_control_manager_t *mgr,
                               const char *domain, const char *item_id,
                               iec61850_control_ids_t ids,
                               mms_operate_response_t *resp);

/**
 * Ed.2 operate with time-activated operate (operTm) and AddCause detail.
 *
 * Same validation and execution semantics as iec61850_control_operate(),
 * extended with:
 *
 * @param oper_tm_utc_ms  Time-activated operate time (operTm), in ms since
 *                        the Unix epoch (UTC). 0 = execute immediately.
 *                        A non-zero value not in the future is rejected
 *                        with IEC61850_CONTROL_ERROR_OPER_TM_INVALID and
 *                        AddCause NOT_IN_ALLOWED_VALUE_RANGE. A future
 *                        value arms the command: the operate is accepted,
 *                        the object enters the OPERATE state, and the
 *                        action callback fires when due during
 *                        iec61850_control_process().
 * @param addcause        Optional output (may be NULL): the most specific
 *                        Ed.2 AddCause for a rejection.
 *
 * @return 0 on success (immediate execution done, or operTm armed),
 *         MMS_CONTROL_ERROR_* / IEC61850_CONTROL_ERROR_OPER_TM_INVALID on
 *         rejection, -EINVAL on NULL arguments.
 */
int iec61850_control_operate_ed2(iec61850_control_manager_t *mgr,
                                   const char *domain, const char *item_id,
                                   iec61850_control_ids_t ids,
                                   uint64_t oper_tm_utc_ms,
                                   mms_operate_response_t *resp,
                                   iec61850_control_addcause_t *addcause);

int iec61850_control_cancel(iec61850_control_manager_t *mgr,
                              const char *domain, const char *item_id,
                              iec61850_control_ids_t ids);

void iec61850_control_cleanup_expired(iec61850_control_manager_t *mgr);

/**
 * Periodic control processing. The server calls this from its main/poll
 * loop (no internal thread). Performs selection-timeout cleanup (same as
 * iec61850_control_cleanup_expired()) and fires time-activated operates
 * (operTm) whose due time has been reached.
 */
void iec61850_control_process(iec61850_control_manager_t *mgr);

/**
 * Configure the Ed.2 control-model attributes (sboTimeout, sboClass) of a
 * registered control object. The configuration applies to future selects
 * and operates; an in-flight selection keeps the timeout armed at select
 * time.
 *
 * @return 0 on success, -ENOENT if the object is not registered,
 *         -EINVAL on NULL arguments or an invalid sboClass value.
 */
int iec61850_control_configure(iec61850_control_manager_t *mgr,
                                 const char *domain, const char *item_id,
                                 const iec61850_control_config_t *config);

/**
 * Set the command-termination notification callback for a registered
 * control object. Invoked when a command on that object terminates
 * (immediate operate completion, time-activated operate execution, or
 * abortion of a pending time-activated operate by cancel).
 *
 * @return 0 on success, -ENOENT if the object is not registered,
 *         -EINVAL on NULL arguments.
 */
int iec61850_control_set_termination_callback(iec61850_control_manager_t *mgr,
                                                const char *domain,
                                                const char *item_id,
                                                iec61850_control_termination_cb_t cb,
                                                void *user_data);

/**
 * Read the most specific AddCause recorded for the latest rejection on a
 * control object (select/operate/cancel paths). Reset to UNKNOWN after a
 * subsequent successful operation on the same object.
 *
 * @return 0 on success, -ENOENT if the object is not registered,
 *         -EINVAL on NULL arguments.
 */
int iec61850_control_get_last_addcause(iec61850_control_manager_t *mgr,
                                         const char *domain,
                                         const char *item_id,
                                         iec61850_control_addcause_t *out);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_MMS_CONTROL_H */
