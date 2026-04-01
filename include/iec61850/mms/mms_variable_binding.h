/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Variable Binding Manager
 *
 * Maps MMS domain+variable names to IED DataAttribute pointers.
 * When MMS Write occurs, the manager propagates the value to the
 * bound DataAttribute.  When a DataAttribute changes (via its
 * change callback), the application can be notified.
 *
 * Thread-safe: all operations acquire the manager mutex.
 *
 * License: BSD-3-Clause
 */

#ifndef IEC61850_MMS_VARIABLE_BINDING_H
#define IEC61850_MMS_VARIABLE_BINDING_H

#include "asn1/mms_ber.h"
#include "ied/ied_data_model.h"

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Limits */
#define MMS_MAX_BINDINGS    512
#define MMS_BINDING_KEY_LEN 512

/* Result codes */
typedef enum {
    IEC61850_BINDING_OK         =  0,
    IEC61850_BINDING_ERR_ARGS   = -1,
    IEC61850_BINDING_ERR_NOT_FOUND = -2,
    IEC61850_BINDING_ERR_EXISTS = -3,
    IEC61850_BINDING_ERR_FULL   = -4,
    IEC61850_BINDING_ERR_WRITE  = -5
} iec61850_binding_result_t;

/* Single binding: domain + variable -> DataAttribute */
typedef struct {
    char domain[MMS_MAX_DOMAIN_NAME];
    char variable[MMS_MAX_VARIABLE_NAME];
    iec61850_data_attribute_t *attribute;  /* non-owning */
} iec61850_mms_binding_t;

/* Binding manager */
typedef struct {
    iec61850_mms_binding_t bindings[MMS_MAX_BINDINGS];
    uint32_t count;
    pthread_mutex_t mutex;
} iec61850_mms_binding_manager_t;

/**
 * Initialise a binding manager.  Must be called before any other
 * binding operation.
 */
int iec61850_binding_init(iec61850_mms_binding_manager_t *mgr);

/**
 * Destroy the binding manager and release its mutex.
 */
void iec61850_binding_destroy(iec61850_mms_binding_manager_t *mgr);

/**
 * Bind an MMS domain+variable to a DataAttribute.
 * Returns IEC61850_BINDING_OK on success, or a negative error code.
 */
iec61850_binding_result_t iec61850_binding_bind_variable(
    iec61850_mms_binding_manager_t *mgr,
    const char *domain, const char *variable,
    iec61850_data_attribute_t *attribute);

/**
 * Unbind a single domain+variable.
 * Returns IEC61850_BINDING_OK or IEC61850_BINDING_ERR_NOT_FOUND.
 */
iec61850_binding_result_t iec61850_binding_unbind_variable(
    iec61850_mms_binding_manager_t *mgr,
    const char *domain, const char *variable);

/**
 * Unbind all variables in a given domain.
 * Returns IEC61850_BINDING_OK (0 removals is OK).
 */
iec61850_binding_result_t iec61850_binding_unbind_domain(
    iec61850_mms_binding_manager_t *mgr,
    const char *domain);

/**
 * Unbind all variables.
 */
iec61850_binding_result_t iec61850_binding_unbind_all(
    iec61850_mms_binding_manager_t *mgr);

/**
 * Look up the DataAttribute bound to domain+variable.
 * Returns the attribute pointer, or NULL if not found.
 */
iec61850_data_attribute_t *iec61850_binding_get_bound_attribute(
    iec61850_mms_binding_manager_t *mgr,
    const char *domain, const char *variable);

/**
 * Check whether domain+variable is bound.
 */
bool iec61850_binding_is_bound(
    iec61850_mms_binding_manager_t *mgr,
    const char *domain, const char *variable);

/**
 * Return current number of bindings.
 */
uint32_t iec61850_binding_get_count(
    iec61850_mms_binding_manager_t *mgr);

/**
 * Propagate an MMS Write to the bound DataAttribute.
 *
 * Looks up the binding under the mutex, then releases the mutex
 * before calling iec61850_da_set_value (which acquires the DA mutex).
 * This avoids ABBA deadlocks between the binding and DA mutexes.
 *
 * Returns IEC61850_BINDING_OK on success, or a negative error code.
 */
iec61850_binding_result_t iec61850_binding_on_mms_write(
    iec61850_mms_binding_manager_t *mgr,
    const char *domain, const char *variable,
    const mms_value_t *value);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_MMS_VARIABLE_BINDING_H */
