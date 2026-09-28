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

int iec61850_control_cancel(iec61850_control_manager_t *mgr,
                              const char *domain, const char *item_id,
                              iec61850_control_ids_t ids);

void iec61850_control_cleanup_expired(iec61850_control_manager_t *mgr);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_MMS_CONTROL_H */
