/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Variable Binding Manager — Implementation
 *
 * Linear-search binding table (up to 512 entries).
 * Thread-safe via pthread_mutex.  The on_mms_write path releases
 * the binding mutex before calling into the DataAttribute (which
 * has its own mutex) to avoid ABBA deadlocks.
 *
 * License: BSD-3-Clause
 */


#include "mms/mms_variable_binding.h"

#include <string.h>

/* --------------------------------------------------------------------
 * Internal helpers
 * -------------------------------------------------------------------- */

/**
 * Match a binding entry against domain+variable.
 * Returns true if both fields match.
 */
static bool binding_matches(const iec61850_mms_binding_t *b,
                            const char *domain, const char *variable)
{
    return (strcmp(b->domain, domain) == 0) &&
           (strcmp(b->variable, variable) == 0);
}

/**
 * Find index of binding.  Caller must hold the mutex.
 * Returns index in [0, mgr->count) or -1 if not found.
 */
static int find_index(const iec61850_mms_binding_manager_t *mgr,
                      const char *domain, const char *variable)
{
    for (uint32_t i = 0; i < mgr->count; i++) {
        if (binding_matches(&mgr->bindings[i], domain, variable)) {
            return (int)i;
        }
    }
    return -1;
}

/* --------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------- */

int iec61850_binding_init(iec61850_mms_binding_manager_t *mgr)
{
    if (mgr == NULL) { return -1; }

    (void)memset(mgr, 0, sizeof(*mgr));
    return pthread_mutex_init(&mgr->mutex, NULL);
}

void iec61850_binding_destroy(iec61850_mms_binding_manager_t *mgr)
{
    if (mgr == NULL) { return; }

    (void)pthread_mutex_destroy(&mgr->mutex);
    mgr->count = 0;
}

iec61850_binding_result_t iec61850_binding_bind_variable(
    iec61850_mms_binding_manager_t *mgr,
    const char *domain, const char *variable,
    iec61850_data_attribute_t *attribute)
{
    if (mgr == NULL || domain == NULL || variable == NULL ||
        attribute == NULL) {
        return IEC61850_BINDING_ERR_ARGS;
    }

    (void)pthread_mutex_lock(&mgr->mutex);

    /* Reject duplicates */
    if (find_index(mgr, domain, variable) >= 0) {
        (void)pthread_mutex_unlock(&mgr->mutex);
        return IEC61850_BINDING_ERR_EXISTS;
    }

    /* Check capacity */
    if (mgr->count >= MMS_MAX_BINDINGS) {
        (void)pthread_mutex_unlock(&mgr->mutex);
        return IEC61850_BINDING_ERR_FULL;
    }

    /* Insert at end */
    iec61850_mms_binding_t *b = &mgr->bindings[mgr->count];
    (void)strncpy(b->domain, domain, MMS_MAX_DOMAIN_NAME - 1);
    b->domain[MMS_MAX_DOMAIN_NAME - 1] = '\0';
    (void)strncpy(b->variable, variable, MMS_MAX_VARIABLE_NAME - 1);
    b->variable[MMS_MAX_VARIABLE_NAME - 1] = '\0';
    b->attribute = attribute;
    mgr->count++;

    (void)pthread_mutex_unlock(&mgr->mutex);
    return IEC61850_BINDING_OK;
}

iec61850_binding_result_t iec61850_binding_unbind_variable(
    iec61850_mms_binding_manager_t *mgr,
    const char *domain, const char *variable)
{
    if (mgr == NULL || domain == NULL || variable == NULL) {
        return IEC61850_BINDING_ERR_ARGS;
    }

    (void)pthread_mutex_lock(&mgr->mutex);

    int idx = find_index(mgr, domain, variable);
    if (idx < 0) {
        (void)pthread_mutex_unlock(&mgr->mutex);
        return IEC61850_BINDING_ERR_NOT_FOUND;
    }

    /* Swap with last element */
    mgr->count--;
    if ((uint32_t)idx < mgr->count) {
        mgr->bindings[idx] = mgr->bindings[mgr->count];
    }
    (void)memset(&mgr->bindings[mgr->count], 0, sizeof(iec61850_mms_binding_t));

    (void)pthread_mutex_unlock(&mgr->mutex);
    return IEC61850_BINDING_OK;
}

iec61850_binding_result_t iec61850_binding_unbind_domain(
    iec61850_mms_binding_manager_t *mgr,
    const char *domain)
{
    if (mgr == NULL || domain == NULL) {
        return IEC61850_BINDING_ERR_ARGS;
    }

    (void)pthread_mutex_lock(&mgr->mutex);

    uint32_t i = 0;
    while (i < mgr->count) {
        if (strcmp(mgr->bindings[i].domain, domain) == 0) {
            /* Swap with last */
            mgr->count--;
            if (i < mgr->count) {
                mgr->bindings[i] = mgr->bindings[mgr->count];
            }
            (void)memset(&mgr->bindings[mgr->count], 0,
                         sizeof(iec61850_mms_binding_t));
            /* Don't increment i — re-check swapped-in element */
        } else {
            i++;
        }
    }

    (void)pthread_mutex_unlock(&mgr->mutex);
    return IEC61850_BINDING_OK;
}

iec61850_binding_result_t iec61850_binding_unbind_all(
    iec61850_mms_binding_manager_t *mgr)
{
    if (mgr == NULL) { return IEC61850_BINDING_ERR_ARGS; }

    (void)pthread_mutex_lock(&mgr->mutex);
    (void)memset(mgr->bindings, 0, sizeof(mgr->bindings));
    mgr->count = 0;
    (void)pthread_mutex_unlock(&mgr->mutex);

    return IEC61850_BINDING_OK;
}

iec61850_data_attribute_t *iec61850_binding_get_bound_attribute(
    iec61850_mms_binding_manager_t *mgr,
    const char *domain, const char *variable)
{
    iec61850_data_attribute_t *attr = NULL;

    if (mgr == NULL || domain == NULL || variable == NULL) {
        return NULL;
    }

    (void)pthread_mutex_lock(&mgr->mutex);

    int idx = find_index(mgr, domain, variable);
    if (idx >= 0) {
        attr = mgr->bindings[idx].attribute;
    }

    (void)pthread_mutex_unlock(&mgr->mutex);
    return attr;
}

bool iec61850_binding_is_bound(
    iec61850_mms_binding_manager_t *mgr,
    const char *domain, const char *variable)
{
    return iec61850_binding_get_bound_attribute(mgr, domain, variable) != NULL;
}

uint32_t iec61850_binding_get_count(
    iec61850_mms_binding_manager_t *mgr)
{
    uint32_t count = 0;

    if (mgr == NULL) { return 0; }

    (void)pthread_mutex_lock(&mgr->mutex);
    count = mgr->count;
    (void)pthread_mutex_unlock(&mgr->mutex);

    return count;
}

iec61850_binding_result_t iec61850_binding_on_mms_write(
    iec61850_mms_binding_manager_t *mgr,
    const char *domain, const char *variable,
    const mms_value_t *value)
{
    if (mgr == NULL || domain == NULL || variable == NULL || value == NULL) {
        return IEC61850_BINDING_ERR_ARGS;
    }

    (void)pthread_mutex_lock(&mgr->mutex);

    int idx = find_index(mgr, domain, variable);
    iec61850_data_attribute_t *attr = NULL;
    if (idx >= 0) {
        attr = mgr->bindings[idx].attribute;
    }

    (void)pthread_mutex_unlock(&mgr->mutex);

    if (attr == NULL) {
        return IEC61850_BINDING_ERR_NOT_FOUND;
    }

    /* Propagate write outside the binding mutex to avoid ABBA deadlock */
    iec61850_da_set_value(attr, value);

    return IEC61850_BINDING_OK;
}
