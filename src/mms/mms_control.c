/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Control Services Implementation
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

int iec61850_control_select(iec61850_control_manager_t *mgr,
                              const char *domain, const char *item_id,
                              uint32_t session_id,
                              mms_select_response_t *resp)
{
    if ((mgr == NULL) || (resp == NULL)) { return -EINVAL; }

    (void)pthread_mutex_lock(&mgr->mutex);
    iec61850_control_object_t *obj = find_object(mgr, domain, item_id);
    if (obj == NULL) {
        (void)pthread_mutex_unlock(&mgr->mutex);
        return MMS_CONTROL_ERROR_ALREADY_SELECTED;  /* not found */
    }

    (void)pthread_mutex_lock(&obj->mutex);
    (void)pthread_mutex_unlock(&mgr->mutex);

    if (obj->state == MMS_CONTROL_STATE_BLOCKED) {
        resp->state = obj->state;
        resp->selection_id = 0;
        (void)pthread_mutex_unlock(&obj->mutex);
        return MMS_CONTROL_ERROR_CONTROL_BLOCKED;
    }

    if (obj->state != MMS_CONTROL_STATE_READY) {
        /* Check if prior selection expired */
        uint64_t now = now_ms();
        if ((obj->selection_expires_at_ms > 0ULL) &&
            (now > obj->selection_expires_at_ms)) {
            obj->state = MMS_CONTROL_STATE_READY;
            obj->selection_id = 0;
            obj->owner_session_id = 0;
        } else {
            resp->state = obj->state;
            resp->selection_id = 0;
            (void)pthread_mutex_unlock(&obj->mutex);
            return MMS_CONTROL_ERROR_ALREADY_SELECTED;
        }
    }

    obj->state = MMS_CONTROL_STATE_SELECTED;
    obj->selection_id = mgr->next_selection_id++;
    obj->owner_session_id = session_id;
    obj->selection_expires_at_ms = now_ms() + (uint64_t)IEC61850_CONTROL_DEFAULT_TIMEOUT_MS;
    obj->has_preloaded_value = false;

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
    mms_select_response_t sel_resp;
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
    if ((mgr == NULL) || (resp == NULL)) { return -EINVAL; }

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

    if (obj->state != MMS_CONTROL_STATE_SELECTED) {
        resp->state = obj->state;
        resp->success = false;
        (void)pthread_mutex_unlock(&obj->mutex);
        return MMS_CONTROL_ERROR_NOT_SELECTED;
    }

    if (obj->selection_id != ids.selection_id) {
        resp->state = obj->state;
        resp->success = false;
        (void)pthread_mutex_unlock(&obj->mutex);
        return MMS_CONTROL_ERROR_INVALID_SELECTION_ID;
    }

    if (obj->owner_session_id != ids.session_id) {
        resp->state = obj->state;
        resp->success = false;
        (void)pthread_mutex_unlock(&obj->mutex);
        return MMS_CONTROL_ERROR_INVALID_SELECTION_ID;
    }

    /* Check selection timeout */
    if ((obj->selection_expires_at_ms > 0ULL) &&
        (now_ms() > obj->selection_expires_at_ms)) {
        obj->state = MMS_CONTROL_STATE_READY;
        obj->selection_id = 0;
        obj->owner_session_id = 0;
        resp->state = MMS_CONTROL_STATE_READY;
        resp->success = false;
        (void)pthread_mutex_unlock(&obj->mutex);
        return MMS_CONTROL_ERROR_SELECTION_TIMEOUT;
    }

    /* Execute: transition to OPERATE, call action callback, then back to READY */
    obj->state = MMS_CONTROL_STATE_OPERATE;

    if (obj->action_cb != NULL) {
        const mms_value_t *val = obj->has_preloaded_value ? &obj->preloaded_value : NULL;
        int cb_ret = obj->action_cb(obj->domain, obj->item_id, val,
                                      obj->action_cb_user_data);
        if (cb_ret != 0) {
            obj->state = MMS_CONTROL_STATE_READY;
            obj->selection_id = 0;
            obj->owner_session_id = 0;
            obj->has_preloaded_value = false;
            obj->selection_expires_at_ms = 0;
            resp->state = MMS_CONTROL_STATE_READY;
            resp->success = false;
            (void)pthread_mutex_unlock(&obj->mutex);
            return MMS_CONTROL_ERROR_CONTROL_BLOCKED;
        }
    }

    obj->state = MMS_CONTROL_STATE_READY;
    obj->selection_id = 0;
    obj->owner_session_id = 0;
    obj->has_preloaded_value = false;
    obj->selection_expires_at_ms = 0;

    resp->state = MMS_CONTROL_STATE_READY;
    resp->success = true;
    (void)pthread_mutex_unlock(&obj->mutex);
    return 0;
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

    if ((obj->selection_id != ids.selection_id) ||
        (obj->owner_session_id != ids.session_id)) {
        (void)pthread_mutex_unlock(&obj->mutex);
        return MMS_CONTROL_ERROR_INVALID_SELECTION_ID;
    }

    obj->state = MMS_CONTROL_STATE_READY;
    obj->selection_id = 0;
    obj->owner_session_id = 0;
    obj->has_preloaded_value = false;
    obj->selection_expires_at_ms = 0;

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
            obj->state = MMS_CONTROL_STATE_READY;
            obj->selection_id = 0;
            obj->owner_session_id = 0;
            obj->has_preloaded_value = false;
            obj->selection_expires_at_ms = 0;
        }
        (void)pthread_mutex_unlock(&obj->mutex);
    }
    (void)pthread_mutex_unlock(&mgr->mutex);
}
