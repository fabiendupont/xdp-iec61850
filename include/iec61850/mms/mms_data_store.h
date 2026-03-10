/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Data Store for IEC 61850
 *
 * Thread-safe storage for MMS domains, variables, and named variable lists.
 * Uses dynamic allocation (malloc/realloc) for all collections — MMS scales
 * with the number of IEDs, logical devices, and variables, which are
 * determined by SCL configuration and are not bounded by protocol constants.
 *
 * Allocation happens at init/config time (SCL load), not on hot paths.
 * Read/write operations use linear scan within a domain; for typical IED
 * sizes (< 2000 variables) this is acceptable. If needed, a hash map
 * can be substituted later without changing the API.
 *
 * License: BSD-3-Clause
 */

#ifndef IEC61850_MMS_DATA_STORE_H
#define IEC61850_MMS_DATA_STORE_H

#include "asn1/mms_ber.h"
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Initial capacities (grow by doubling) */
#define IEC61850_MMS_INIT_DOMAINS    4
#define IEC61850_MMS_INIT_VARS      32
#define IEC61850_MMS_INIT_LISTS      4
#define IEC61850_MMS_INIT_LIST_VARS  8

/* Result codes */
typedef enum {
    IEC61850_MMS_DS_OK = 0,
    IEC61850_MMS_DS_ERR_NOT_FOUND = -1,
    IEC61850_MMS_DS_ERR_EXISTS = -2,
    IEC61850_MMS_DS_ERR_ALLOC = -3,
    IEC61850_MMS_DS_ERR_ARGS = -4,
    IEC61850_MMS_DS_ERR_TYPE = -5
} iec61850_mms_ds_result_t;

/* Variable entry */
typedef struct {
    char item_id[MMS_MAX_VARIABLE_NAME];
    mms_type_t type;
    mms_value_t value;
    bool deletable;
} iec61850_mms_variable_t;

/* Named variable list entry */
typedef struct {
    char list_name[MMS_MAX_VARIABLE_NAME];
    mms_variable_spec_t *variables;   /* heap-allocated */
    uint32_t num_variables;
    uint32_t var_capacity;
    bool deletable;
} iec61850_mms_named_list_t;

/* Domain (heap-allocated collections of variables and lists) */
typedef struct {
    char name[MMS_MAX_DOMAIN_NAME];

    iec61850_mms_variable_t *vars;    /* heap-allocated */
    size_t var_count;
    size_t var_capacity;

    iec61850_mms_named_list_t *lists;  /* heap-allocated */
    size_t list_count;
    size_t list_capacity;
} iec61850_mms_domain_t;

/* Data store (heap-allocated collection of domains) */
typedef struct {
    iec61850_mms_domain_t *domains;   /* heap-allocated */
    size_t domain_count;
    size_t domain_capacity;
    pthread_mutex_t mutex;
} iec61850_mms_data_store_t;

/* ======================================================================== */

/**
 * Initialize data store. Allocates initial capacity.
 * The data store struct itself may live on the stack or heap — it's small.
 */
void iec61850_mms_ds_init(iec61850_mms_data_store_t *ds);

/**
 * Destroy data store and free all memory.
 */
void iec61850_mms_ds_destroy(iec61850_mms_data_store_t *ds);

/* Domain management */
int iec61850_mms_ds_create_domain(iec61850_mms_data_store_t *ds,
                                   const char *domain);
bool iec61850_mms_ds_domain_exists(const iec61850_mms_data_store_t *ds,
                                    const char *domain);

/* Variable CRUD */
int iec61850_mms_ds_create_variable(iec61850_mms_data_store_t *ds,
                                     const char *domain, const char *item_id,
                                     mms_type_t type,
                                     const mms_value_t *initial_value);

int iec61850_mms_ds_read_variable(iec61850_mms_data_store_t *ds,
                                   const char *domain, const char *item_id,
                                   mms_value_t *value);

int iec61850_mms_ds_write_variable(iec61850_mms_data_store_t *ds,
                                    const char *domain, const char *item_id,
                                    const mms_value_t *value);

int iec61850_mms_ds_get_variable_attrs(const iec61850_mms_data_store_t *ds,
                                        const char *domain, const char *item_id,
                                        mms_variable_access_attrs_t *attrs);

bool iec61850_mms_ds_variable_exists(const iec61850_mms_data_store_t *ds,
                                      const char *domain, const char *item_id);

/* Get variable names in a domain */
int iec61850_mms_ds_get_var_names(const iec61850_mms_data_store_t *ds,
                                   const char *domain,
                                   char names[][MMS_MAX_VARIABLE_NAME],
                                   uint32_t *count, uint32_t max_count);

/* Named variable lists */
int iec61850_mms_ds_define_list(iec61850_mms_data_store_t *ds,
                                 const char *domain, const char *list_name,
                                 const mms_variable_spec_t *variables,
                                 uint32_t num_variables);

int iec61850_mms_ds_delete_list(iec61850_mms_data_store_t *ds,
                                 const char *domain, const char *list_name);

int iec61850_mms_ds_get_list_attrs(const iec61850_mms_data_store_t *ds,
                                    const char *domain, const char *list_name,
                                    mms_variable_spec_t *variables,
                                    uint32_t *num_variables,
                                    uint32_t max_variables);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_MMS_DATA_STORE_H */
