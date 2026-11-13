/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Control Services Implementation
 *
 * IEC 61850 Ed.2 control-model enhancements:
 * - sboTimeout: per-control-object select timeout
 * - sboClass: strict vs. dynamic select-before-operate
 * - operTm: time-activated operate (executed in iec61850_control_process)
 * - AddCause enrichment on every rejection path
 * - CommandTermination notification with timestamp
 */


#include "mms/mms_control.h"
#include <string.h>
#include <time.h>
#include <errno.h>

static uint64_t now_ms(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
}

/* UTC time base used for operTm and command-termination timestamps */
static uint64_t now_utc_ms(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_REALTIME, &ts);
    return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
}

void iec61850_control_manager_init(iec61850_control_manager_t *mgr)
{
    if (mgr == NULL) { return; }
    (void)memset(mgr, 0, sizeof(*mgr));
    (void)pthread_mutex_init(&mgr->mutex, NULL);
    mgr->next_selection_id = 1;
}

void iec61850_control_manager_destroy(iec61850_control_manager_t *mgr)
{
    if (mgr == NULL) { return; }
    for (uint32_t i = 0; i < mgr->count; i++) {
        if (mgr->objects[i].valid) {
            (void)pthread_mutex_destroy(&mgr->objects[i].mutex);
        }
    }
    (void)pthread_mutex_destroy(&mgr->mutex);
}

static iec61850_control_object_t *find_object(iec61850_control_manager_t *mgr,
                                                const char *domain,
                                                const char *item_id)
{
    for (uint32_t i = 0; i < mgr->count; i++) {
        if (mgr->objects[i].valid &&
            strcmp(mgr->objects[i].domain, domain) == 0 &&
            strcmp(mgr->objects[i].item_id, item_id) == 0) {
            return &mgr->objects[i];
        }
    }
    return NULL;
}

/* Reset a control object to the READY state (selection and operTm
 * pending-operate state cleared). Called with obj->mutex held. */
static void reset_object_state(iec61850_control_object_t *obj)
{
    obj->state = MMS_CONTROL_STATE_READY;
    obj->selection_id = 0;
    obj->owner_session_id = 0;
    obj->has_preloaded_value = false;
    obj->selection_expires_at_ms = 0ULL;
    obj->oper_tm_pending = false;
    obj->oper_tm_due_ms = 0ULL;
}

/* Record the AddCause, fill the response, unlock the object mutex and
 * return the control error code. Called with obj->mutex held. */
static int reject_operate_locked(iec61850_control_object_t *obj,
                                   mms_operate_response_t *resp,
                                   iec61850_control_addcause_t *addcause,
                                   iec61850_control_addcause_t cause,
                                   int ret)
{
    obj->last_addcause = cause;
    if (addcause != NULL) { *addcause = cause; }
    resp->state = obj->state;
    resp->success = false;
    (void)pthread_mutex_unlock(&obj->mutex);
    return ret;
}

/* Execute the operate action callback and terminate the command.
 * Resets the object to READY and notifies the command-termination
 * callback (if configured) with a UTC timestamp.
 * Called with obj->mutex held. Returns the action callback result. */
static int run_operate_action(iec61850_control_object_t *obj)
{
    int cb_ret = 0;

    if (obj->action_cb != NULL) {
        const mms_value_t *val = obj->has_preloaded_value ? &obj->preloaded_value : NULL;
        cb_ret = obj->action_cb(obj->domain, obj->item_id, val,
                                  obj->action_cb_user_data);
    }

    bool success = (cb_ret == 0);
    iec61850_control_addcause_t cause = success ? IEC61850_ADDCAUSE_UNKNOWN
                                                  : IEC61850_ADDCAUSE_BLOCKED_BY_PROCESS;
    obj->last_addcause = cause;

    if (obj->termination_cb != NULL) {
        obj->termination_cb(obj->domain, obj->item_id, obj->selection_id,
                            success, cause, now_utc_ms(),
                            obj->termination_cb_user_data);
    }

    reset_object_state(obj);
    return cb_ret;
}

int iec61850_control_register(iec61850_control_manager_t *mgr,
                                const char *domain, const char *item_id)
{
    if ((mgr == NULL) || (domain == NULL) || (item_id == NULL)) {
        return -EINVAL;
    }

    (void)pthread_mutex_lock(&mgr->mutex);

    if (find_object(mgr, domain, item_id) != NULL) {
        (void)pthread_mutex_unlock(&mgr->mutex);
        return -EEXIST;
    }

    if (mgr->count >= (uint32_t)IEC61850_CONTROL_MAX_OBJECTS) {
        (void)pthread_mutex_unlock(&mgr->mutex);
        return -ENOSPC;
    }

    iec61850_control_object_t *obj = &mgr->objects[mgr->count];
    (void)memset(obj, 0, sizeof(*obj));
    (void)strncpy(obj->domain, domain, MMS_MAX_DOMAIN_NAME - 1);
    (void)strncpy(obj->item_id, item_id, MMS_MAX_VARIABLE_NAME - 1);
    obj->state = MMS_CONTROL_STATE_READY;
    obj->valid = true;
    obj->sbo_class = IEC61850_CONTROL_SBO_CLASS_STRICT;
    (void)pthread_mutex_init(&obj->mutex, NULL);
    mgr->count++;

    (void)pthread_mutex_unlock(&mgr->mutex);
    return 0;
}

int iec61850_control_set_action_callback(iec61850_control_manager_t *mgr,
                                           const char *domain,
                                           const char *item_id,
                                           iec61850_control_action_cb_t cb,
                                           void *user_data)
{
    if ((mgr == NULL) || (domain == NULL) || (item_id == NULL)) {
        return -EINVAL;
    }

    (void)pthread_mutex_lock(&mgr->mutex);
    iec61850_control_object_t *obj = find_object(mgr, domain, item_id);
    if (obj == NULL) {
        (void)pthread_mutex_unlock(&mgr->mutex);
        return -ENOENT;
    }

    (void)pthread_mutex_lock(&obj->mutex);
    (void)pthread_mutex_unlock(&mgr->mutex);

    obj->action_cb = cb;
    obj->action_cb_user_data = user_data;

    (void)pthread_mutex_unlock(&obj->mutex);
    return 0;
}

int iec61850_control_configure(iec61850_control_manager_t *mgr,
                                 const char *domain, const char *item_id,
                                 const iec61850_control_config_t *config)
{
    if ((mgr == NULL) || (domain == NULL) || (item_id == NULL) ||
        (config == NULL)) {
        return -EINVAL;
    }

    if ((config->sbo_class != IEC61850_CONTROL_SBO_CLASS_STRICT) &&
        (config->sbo_class != IEC61850_CONTROL_SBO_CLASS_DYNAMIC)) {
        return -EINVAL;
    }

    (void)pthread_mutex_lock(&mgr->mutex);
    iec61850_control_object_t *obj = find_object(mgr, domain, item_id);
    if (obj == NULL) {
        (void)pthread_mutex_unlock(&mgr->mutex);
        return -ENOENT;
    }

    (void)pthread_mutex_lock(&obj->mutex);
    (void)pthread_mutex_unlock(&mgr->mutex);

    obj->sbo_timeout_ms = config->sbo_timeout_ms;
    obj->sbo_class = config->sbo_class;

    (void)pthread_mutex_unlock(&obj->mutex);
    return 0;
}

int iec61850_control_set_termination_callback(iec61850_control_manager_t *mgr,
                                                const char *domain,
                                                const char *item_id,
                                                iec61850_control_termination_cb_t cb,
                                                void *user_data)
{
    if ((mgr == NULL) || (domain == NULL) || (item_id == NULL)) {
        return -EINVAL;
    }

    (void)pthread_mutex_lock(&mgr->mutex);
    iec61850_control_object_t *obj = find_object(mgr, domain, item_id);
    if (obj == NULL) {
        (void)pthread_mutex_unlock(&mgr->mutex);
        return -ENOENT;
    }

    (void)pthread_mutex_lock(&obj->mutex);
    (void)pthread_mutex_unlock(&mgr->mutex);

    obj->termination_cb = cb;
    obj->termination_cb_user_data = user_data;

    (void)pthread_mutex_unlock(&obj->mutex);
    return 0;
}

int iec61850_control_get_last_addcause(iec61850_control_manager_t *mgr,
                                         const char *domain,
                                         const char *item_id,
                                         iec61850_control_addcause_t *out)
{
    if ((mgr == NULL) || (domain == NULL) || (item_id == NULL) || (out == NULL)) {
        return -EINVAL;
    }

    (void)pthread_mutex_lock(&mgr->mutex);
    iec61850_control_object_t *obj = find_object(mgr, domain, item_id);
    if (obj == NULL) {
        (void)pthread_mutex_unlock(&mgr->mutex);
        return -ENOENT;
    }

    (void)pthread_mutex_lock(&obj->mutex);
    (void)pthread_mutex_unlock(&mgr->mutex);

    *out = obj->last_addcause;

    (void)pthread_mutex_unlock(&obj->mutex);
    return 0;
}

int iec61850_control_select(iec61850_control_manager_t *mgr,
                              const char *domain, const char *item_id,
                              uint32_t session_id,
                              mms_select_response_t *resp)
{
    if ((mgr == NULL) || (resp == NULL)) { return -EINVAL; }

    (void)pthread_mutex_lock(&mgr->mutex);
    iec61850_control_object_t *obj = find_object(mgr, domain, item_id);
    /* Allocate the selection ID under the manager lock (unique across
     * concurrent selects on different objects). */
    uint32_t next_id = 0;
    if (obj != NULL) {
        next_id = mgr->next_selection_id;
        mgr->next_selection_id++;
    }
    if (obj == NULL) {
        (void)pthread_mutex_unlock(&mgr->mutex);
        return MMS_CONTROL_ERROR_ALREADY_SELECTED;  /* not found */
    }

    (void)pthread_mutex_lock(&obj->mutex);
    (void)pthread_mutex_unlock(&mgr->mutex);

    if (obj->state == MMS_CONTROL_STATE_BLOCKED) {
        obj->last_addcause = IEC61850_ADDCAUSE_BLOCKED_BY_MODE;
        resp->state = obj->state;
        resp->selection_id = 0;
        (void)pthread_mutex_unlock(&obj->mutex);
        return MMS_CONTROL_ERROR_CONTROL_BLOCKED;
    }

    if (obj->state == MMS_CONTROL_STATE_OPERATE) {
        /* A time-activated operate is pending on this object (the OPERATE
         * state is otherwise transient and held under the object mutex). */
        obj->last_addcause = IEC61850_ADDCAUSE_COMMAND_ALREADY_IN_EXECUTION;
        resp->state = obj->state;
        resp->selection_id = 0;
        (void)pthread_mutex_unlock(&obj->mutex);
        return MMS_CONTROL_ERROR_CONTROL_IN_PROGRESS;
    }

    if (obj->state != MMS_CONTROL_STATE_READY) {
        /* Check if prior selection expired */
        uint64_t now = now_ms();
        if ((obj->selection_expires_at_ms > 0ULL) &&
            (now > obj->selection_expires_at_ms)) {
            reset_object_state(obj);
        } else {
            obj->last_addcause = IEC61850_ADDCAUSE_SELECT_FAILED;
            resp->state = obj->state;
            resp->selection_id = 0;
            (void)pthread_mutex_unlock(&obj->mutex);
            return MMS_CONTROL_ERROR_ALREADY_SELECTED;
        }
    }

    obj->state = MMS_CONTROL_STATE_SELECTED;
    obj->selection_id = next_id;
    obj->owner_session_id = session_id;
    /* Ed.2 sboTimeout: per-object select timeout, 0 = default */
    uint32_t timeout_ms = (obj->sbo_timeout_ms != 0U) ? obj->sbo_timeout_ms
                                                        : (uint32_t)IEC61850_CONTROL_DEFAULT_TIMEOUT_MS;
    obj->selection_expires_at_ms = now_ms() + (uint64_t)timeout_ms;
    obj->has_preloaded_value = false;
    obj->last_addcause = IEC61850_ADDCAUSE_UNKNOWN;

    resp->state = obj->state;
    resp->selection_id = obj->selection_id;
    (void)pthread_mutex_unlock(&obj->mutex);
    return 0;
}

int iec61850_control_select_with_value(iec61850_control_manager_t *mgr,
                                         const char *domain,
                                         const char *item_id,
                                         uint32_t session_id,
                                         const mms_value_t *value,
                                         mms_select_with_value_response_t *resp)
{
    mms_select_response_t sel_resp = {0};
    int ret = iec61850_control_select(mgr, domain, item_id, session_id,
                                        &sel_resp);

    resp->state = sel_resp.state;
    resp->selection_id = sel_resp.selection_id;

    if (ret != 0) { return ret; }

    /* Store preloaded value */
    (void)pthread_mutex_lock(&mgr->mutex);
    iec61850_control_object_t *obj = find_object(mgr, domain, item_id);
    if (obj != NULL) {
        (void)pthread_mutex_lock(&obj->mutex);
        (void)pthread_mutex_unlock(&mgr->mutex);
        if (value != NULL) {
            obj->preloaded_value = *value;
            obj->has_preloaded_value = true;
        }
        (void)pthread_mutex_unlock(&obj->mutex);
    } else {
        (void)pthread_mutex_unlock(&mgr->mutex);
    }

    return 0;
}

int iec61850_control_operate(iec61850_control_manager_t *mgr,
                               const char *domain, const char *item_id,
                               iec61850_control_ids_t ids,
                               mms_operate_response_t *resp)
{
    return iec61850_control_operate_ed2(mgr, domain, item_id, ids, 0ULL,
                                          resp, NULL);
}

int iec61850_control_operate_ed2(iec61850_control_manager_t *mgr,
                                   const char *domain, const char *item_id,
                                   iec61850_control_ids_t ids,
                                   uint64_t oper_tm_utc_ms,
                                   mms_operate_response_t *resp,
                                   iec61850_control_addcause_t *addcause)
{
    if ((mgr == NULL) || (domain == NULL) || (item_id == NULL) ||
        (resp == NULL)) {
        return -EINVAL;
    }

    if (addcause != NULL) { *addcause = IEC61850_ADDCAUSE_UNKNOWN; }

    (void)pthread_mutex_lock(&mgr->mutex);
    iec61850_control_object_t *obj = find_object(mgr, domain, item_id);
    if (obj == NULL) {
        (void)pthread_mutex_unlock(&mgr->mutex);
        resp->state = MMS_CONTROL_STATE_READY;
        resp->success = false;
        return MMS_CONTROL_ERROR_NOT_SELECTED;
    }

    (void)pthread_mutex_lock(&obj->mutex);
    (void)pthread_mutex_unlock(&mgr->mutex);

    if (obj->state == MMS_CONTROL_STATE_BLOCKED) {
        return reject_operate_locked(obj, resp, addcause,
                                       IEC61850_ADDCAUSE_BLOCKED_BY_MODE,
                                       MMS_CONTROL_ERROR_CONTROL_BLOCKED);
    }

    if (obj->state == MMS_CONTROL_STATE_OPERATE) {
        /* A time-activated operate is already armed on this object. */
        return reject_operate_locked(obj, resp, addcause,
                                       IEC61850_ADDCAUSE_COMMAND_ALREADY_IN_EXECUTION,
                                       MMS_CONTROL_ERROR_CONTROL_IN_PROGRESS);
    }

    bool have_valid_selection = false;
    if (obj->state == MMS_CONTROL_STATE_SELECTED) {
        if (obj->selection_id != ids.selection_id) {
            return reject_operate_locked(obj, resp, addcause,
                                           IEC61850_ADDCAUSE_SELECT_FAILED,
                                           MMS_CONTROL_ERROR_INVALID_SELECTION_ID);
        }

        if (obj->owner_session_id != ids.session_id) {
            return reject_operate_locked(obj, resp, addcause,
                                           IEC61850_ADDCAUSE_SELECT_FAILED,
                                           MMS_CONTROL_ERROR_INVALID_SELECTION_ID);
        }

        /* Check selection timeout (Ed.2 sboTimeout) */
        if ((obj->selection_expires_at_ms > 0ULL) &&
            (now_ms() > obj->selection_expires_at_ms)) {
            reset_object_state(obj);
            return reject_operate_locked(obj, resp, addcause,
                                           IEC61850_ADDCAUSE_TIME_LIMIT_OVERRUN,
                                           MMS_CONTROL_ERROR_SELECTION_TIMEOUT);
        }

        have_valid_selection = true;
    }

    if (!have_valid_selection) {
        /* Ed.2 sboClass enforcement:
         * - strict: an operate without a prior, still-valid select is
         *   rejected (object-not-selected).
         * - dynamic: the operate carries its own select check and is
         *   accepted on a READY object; a SELECTED object still requires
         *   the matching selection (conservative interpretation). */
        if ((obj->sbo_class != IEC61850_CONTROL_SBO_CLASS_DYNAMIC) ||
            (obj->state != MMS_CONTROL_STATE_READY)) {
            return reject_operate_locked(obj, resp, addcause,
                                           IEC61850_ADDCAUSE_OBJECT_NOT_SELECTED,
                                           MMS_CONTROL_ERROR_NOT_SELECTED);
        }
    }

    /* Ed.2 operTm: time-activated operate */
    if (oper_tm_utc_ms != 0ULL) {
        uint64_t now_utc = now_utc_ms();
        if (oper_tm_utc_ms <= now_utc) {
            /* operTm in the past (or now): reject, selection preserved */
            return reject_operate_locked(obj, resp, addcause,
                                           IEC61850_ADDCAUSE_NOT_IN_ALLOWED_VALUE_RANGE,
                                           IEC61850_CONTROL_ERROR_OPER_TM_INVALID);
        }

        /* Arm the time-activated operate. The sboTimeout no longer
         * applies once the operate has been accepted; the command stays
         * armed until operTm is reached (fired by control_process). */
        obj->state = MMS_CONTROL_STATE_OPERATE;
        obj->oper_tm_pending = true;
        obj->oper_tm_due_ms = now_ms() + (oper_tm_utc_ms - now_utc);
        obj->selection_expires_at_ms = 0ULL;
        obj->last_addcause = IEC61850_ADDCAUSE_UNKNOWN;

        resp->state = obj->state;
        resp->success = true;
        (void)pthread_mutex_unlock(&obj->mutex);
        return 0;
    }

    /* Immediate execution: transition to OPERATE, call the action
     * callback, terminate the command, then back to READY */
    obj->state = MMS_CONTROL_STATE_OPERATE;
    obj->oper_tm_pending = false;

    int cb_ret = run_operate_action(obj);

    resp->state = obj->state;
    resp->success = (cb_ret == 0);
    if (cb_ret != 0) {
        if (addcause != NULL) { *addcause = obj->last_addcause; }
    }
    (void)pthread_mutex_unlock(&obj->mutex);
    return (cb_ret == 0) ? 0 : MMS_CONTROL_ERROR_CONTROL_BLOCKED;
}

int iec61850_control_cancel(iec61850_control_manager_t *mgr,
                              const char *domain, const char *item_id,
                              iec61850_control_ids_t ids)
{
    if (mgr == NULL) { return -EINVAL; }

    (void)pthread_mutex_lock(&mgr->mutex);
    iec61850_control_object_t *obj = find_object(mgr, domain, item_id);
    if (obj == NULL) {
        (void)pthread_mutex_unlock(&mgr->mutex);
        return MMS_CONTROL_ERROR_NOT_SELECTED;
    }

    (void)pthread_mutex_lock(&obj->mutex);
    (void)pthread_mutex_unlock(&mgr->mutex);

    /* Ed.2: abort a pending time-activated operate */
    if ((obj->state == MMS_CONTROL_STATE_OPERATE) && obj->oper_tm_pending) {
        if ((obj->selection_id != ids.selection_id) ||
            (obj->owner_session_id != ids.session_id)) {
            obj->last_addcause = IEC61850_ADDCAUSE_SELECT_FAILED;
            (void)pthread_mutex_unlock(&obj->mutex);
            return MMS_CONTROL_ERROR_INVALID_SELECTION_ID;
        }

        obj->last_addcause = IEC61850_ADDCAUSE_ABORTION_BY_CANCEL;
        if (obj->termination_cb != NULL) {
            obj->termination_cb(obj->domain, obj->item_id, obj->selection_id,
                                false, IEC61850_ADDCAUSE_ABORTION_BY_CANCEL,
                                now_utc_ms(), obj->termination_cb_user_data);
        }
        reset_object_state(obj);
        (void)pthread_mutex_unlock(&obj->mutex);
        return 0;
    }

    if ((obj->selection_id != ids.selection_id) ||
        (obj->owner_session_id != ids.session_id)) {
        obj->last_addcause = IEC61850_ADDCAUSE_SELECT_FAILED;
        (void)pthread_mutex_unlock(&obj->mutex);
        return MMS_CONTROL_ERROR_INVALID_SELECTION_ID;
    }

    reset_object_state(obj);

    (void)pthread_mutex_unlock(&obj->mutex);
    return 0;
}

void iec61850_control_cleanup_expired(iec61850_control_manager_t *mgr)
{
    if (mgr == NULL) { return; }

    uint64_t now = now_ms();

    (void)pthread_mutex_lock(&mgr->mutex);
    for (uint32_t i = 0; i < mgr->count; i++) {
        iec61850_control_object_t *obj = &mgr->objects[i];
        if (!obj->valid) { continue; }

        (void)pthread_mutex_lock(&obj->mutex);
        if ((obj->state == MMS_CONTROL_STATE_SELECTED) &&
            (obj->selection_expires_at_ms > 0ULL) &&
            (now > obj->selection_expires_at_ms)) {
            reset_object_state(obj);
        }
        (void)pthread_mutex_unlock(&obj->mutex);
    }
    (void)pthread_mutex_unlock(&mgr->mutex);
}

void iec61850_control_process(iec61850_control_manager_t *mgr)
{
    if (mgr == NULL) { return; }

    /* Phase 1: selection-timeout cleanup (existing behavior) */
    iec61850_control_cleanup_expired(mgr);

    /* Phase 2: fire time-activated operates (operTm) that are due.
     * The manager mutex is not held while the action and termination
     * callbacks run; object slots are never removed, so a slot address
     * stays valid across the loop. */
    uint64_t now = now_ms();

    uint32_t count;
    (void)pthread_mutex_lock(&mgr->mutex);
    count = mgr->count;
    (void)pthread_mutex_unlock(&mgr->mutex);

    for (uint32_t i = 0; i < count; i++) {
        (void)pthread_mutex_lock(&mgr->mutex);
        if (i >= mgr->count) {
            (void)pthread_mutex_unlock(&mgr->mutex);
            break;
        }
        iec61850_control_object_t *obj = &mgr->objects[i];
        bool valid = obj->valid;
        if (valid) {
            (void)pthread_mutex_lock(&obj->mutex);
        }
        (void)pthread_mutex_unlock(&mgr->mutex);

        if (!valid) { continue; }

        if ((obj->state == MMS_CONTROL_STATE_OPERATE) && obj->oper_tm_pending &&
            (now >= obj->oper_tm_due_ms)) {
            (void)run_operate_action(obj);
        }
        (void)pthread_mutex_unlock(&obj->mutex);
    }
}
