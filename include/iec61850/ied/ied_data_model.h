/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850 IED Data Model (ACSI)
 *
 * C11 replacement for C++ IED model hierarchy:
 *   IedDataModel -> LogicalDevice -> LogicalNode -> DataObject -> DataAttribute
 *
 * Uses malloc/free for tree construction (init-time, not hot path).
 * DataAttribute value access is thread-safe via pthread_mutex_t.
 *
 * License: BSD-2-Clause
 */

#ifndef IEC61850_IED_DATA_MODEL_H
#define IEC61850_IED_DATA_MODEL_H

#include "ied/ied_types.h"
#include "asn1/mms_ber.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Limits */
#define IEC61850_MAX_DA_PER_DO      32
#define IEC61850_MAX_SUBDO_PER_DO   8
#define IEC61850_MAX_DO_PER_LN      32
#define IEC61850_MAX_LN_PER_LD      32
#define IEC61850_MAX_LD_PER_IED     8
#define IEC61850_MAX_NAME_LEN       64

/* ========================================================================
 * DataAttribute - leaf value node
 * ======================================================================== */

typedef void (*iec61850_da_change_cb_t)(const mms_value_t *old_val,
                                         const mms_value_t *new_val,
                                         void *user_data);

typedef struct {
    char name[IEC61850_MAX_NAME_LEN];
    iec61850_fc_t fc;
    iec61850_btype_t btype;
    mms_value_t value;
    uint8_t trigger_conditions;
    iec61850_da_change_cb_t change_cb;
    void *change_cb_user_data;
    pthread_mutex_t mutex;
    bool valid;
} iec61850_data_attribute_t;

int iec61850_da_init(iec61850_data_attribute_t *da, const char *name,
                      iec61850_fc_t fc, iec61850_btype_t btype);
void iec61850_da_destroy(iec61850_data_attribute_t *da);

mms_value_t iec61850_da_get_value(iec61850_data_attribute_t *da);
void iec61850_da_set_value(iec61850_data_attribute_t *da,
                            const mms_value_t *value);

/**
 * Set the change callback for a DataAttribute.
 *
 * NOTE: Callbacks MUST be set at initialization time only, before any
 * concurrent access to the attribute. Setting callbacks after the data
 * model is live is not thread-safe. The callback pointer is read without
 * locking in the set_value path for performance.
 */
void iec61850_da_set_change_callback(iec61850_data_attribute_t *da,
                                      iec61850_da_change_cb_t cb,
                                      void *user_data);

/* ========================================================================
 * DataObject - contains DataAttributes and sub-DataObjects
 * ======================================================================== */

typedef struct iec61850_data_object {
    char name[IEC61850_MAX_NAME_LEN];
    iec61850_cdc_t cdc;
    iec61850_data_attribute_t attributes[IEC61850_MAX_DA_PER_DO];
    size_t attr_count;
    struct iec61850_data_object *sub_objects[IEC61850_MAX_SUBDO_PER_DO];
    size_t sub_count;
    bool valid;
} iec61850_data_object_t;

iec61850_data_object_t *iec61850_do_create(const char *name, iec61850_cdc_t cdc);
void iec61850_do_destroy(iec61850_data_object_t *dobj);

int iec61850_do_add_attribute(iec61850_data_object_t *dobj,
                               const char *name, iec61850_fc_t fc,
                               iec61850_btype_t btype);

int iec61850_do_add_sub_object(iec61850_data_object_t *dobj,
                                iec61850_data_object_t *sub);

iec61850_data_attribute_t *iec61850_do_find_attribute(
    iec61850_data_object_t *dobj, const char *name, iec61850_fc_t fc);

iec61850_data_object_t *iec61850_do_find_sub_object(
    iec61850_data_object_t *dobj, const char *name);

/* ========================================================================
 * LogicalNode - contains DataObjects
 * ======================================================================== */

typedef struct {
    char ln_class[IEC61850_MAX_NAME_LEN];
    char ln_inst[IEC61850_MAX_NAME_LEN];
    iec61850_data_object_t *data_objects[IEC61850_MAX_DO_PER_LN];
    size_t do_count;
    bool valid;
} iec61850_logical_node_t;

iec61850_logical_node_t *iec61850_ln_create(const char *ln_class,
                                             const char *ln_inst);
void iec61850_ln_destroy(iec61850_logical_node_t *ln);

int iec61850_ln_add_data_object(iec61850_logical_node_t *ln,
                                 iec61850_data_object_t *dobj);

iec61850_data_object_t *iec61850_ln_find_do(
    const iec61850_logical_node_t *ln, const char *do_name);

/**
 * Find attribute by dotted path (e.g., "Pos.stVal").
 */
iec61850_data_attribute_t *iec61850_ln_find_attribute(
    const iec61850_logical_node_t *ln, const char *path, iec61850_fc_t fc);

/* ========================================================================
 * LogicalDevice - contains LogicalNodes
 * ======================================================================== */

typedef struct {
    char ld_inst[IEC61850_MAX_NAME_LEN];
    iec61850_logical_node_t *logical_nodes[IEC61850_MAX_LN_PER_LD];
    size_t ln_count;
    bool valid;
} iec61850_logical_device_t;

iec61850_logical_device_t *iec61850_ld_create(const char *ld_inst);
void iec61850_ld_destroy(iec61850_logical_device_t *ld);

int iec61850_ld_add_logical_node(iec61850_logical_device_t *ld,
                                  iec61850_logical_node_t *ln);

iec61850_logical_node_t *iec61850_ld_find_ln(
    const iec61850_logical_device_t *ld, const char *ln_name);

/* ========================================================================
 * IedDataModel - top-level container
 * ======================================================================== */

typedef struct {
    char ied_name[IEC61850_MAX_NAME_LEN];
    iec61850_logical_device_t *logical_devices[IEC61850_MAX_LD_PER_IED];
    size_t ld_count;
} iec61850_ied_model_t;

void iec61850_ied_model_init(iec61850_ied_model_t *model, const char *ied_name);
void iec61850_ied_model_destroy(iec61850_ied_model_t *model);

int iec61850_ied_model_add_ld(iec61850_ied_model_t *model,
                               iec61850_logical_device_t *ld);

iec61850_logical_device_t *iec61850_ied_model_find_ld(
    const iec61850_ied_model_t *model, const char *ld_inst);

/**
 * Find attribute by full path (e.g., "LD0/XCBR1.Pos.stVal").
 */
iec61850_data_attribute_t *iec61850_ied_model_find_attribute(
    const iec61850_ied_model_t *model, const char *path, iec61850_fc_t fc);

/* Statistics */
size_t iec61850_ied_model_count_ld(const iec61850_ied_model_t *model);
size_t iec61850_ied_model_count_ln(const iec61850_ied_model_t *model);
size_t iec61850_ied_model_count_do(const iec61850_ied_model_t *model);
size_t iec61850_ied_model_count_da(const iec61850_ied_model_t *model);

/* ========================================================================
 * CDC Factory - creates standard CDC structures
 * ======================================================================== */

/**
 * Create a DataObject with CDC-specific attributes.
 * Allocates and populates standard attributes per IEC 61850-7-3.
 */
/* Status CDCs */
iec61850_data_object_t *iec61850_cdc_create_sps(const char *name);
iec61850_data_object_t *iec61850_cdc_create_dps(const char *name);
iec61850_data_object_t *iec61850_cdc_create_ins(const char *name);
iec61850_data_object_t *iec61850_cdc_create_ens(const char *name);
iec61850_data_object_t *iec61850_cdc_create_act(const char *name);
iec61850_data_object_t *iec61850_cdc_create_acd(const char *name);
iec61850_data_object_t *iec61850_cdc_create_sec(const char *name);

/* Control CDCs */
iec61850_data_object_t *iec61850_cdc_create_spc(const char *name);
iec61850_data_object_t *iec61850_cdc_create_dpc(const char *name);
iec61850_data_object_t *iec61850_cdc_create_inc(const char *name);
iec61850_data_object_t *iec61850_cdc_create_bsc(const char *name);

/* Measurement CDCs */
iec61850_data_object_t *iec61850_cdc_create_mv(const char *name);
iec61850_data_object_t *iec61850_cdc_create_cmv(const char *name);
iec61850_data_object_t *iec61850_cdc_create_sav(const char *name);
iec61850_data_object_t *iec61850_cdc_create_wye(const char *name);
iec61850_data_object_t *iec61850_cdc_create_del(const char *name);

/* Setting CDCs */
iec61850_data_object_t *iec61850_cdc_create_spg(const char *name);
iec61850_data_object_t *iec61850_cdc_create_asg(const char *name);

/* General CDCs */
iec61850_data_object_t *iec61850_cdc_create_lpl(const char *name);
iec61850_data_object_t *iec61850_cdc_create_dpl(const char *name);
iec61850_data_object_t *iec61850_cdc_create_bcr(const char *name);
iec61850_data_object_t *iec61850_cdc_create_vss(const char *name);

/* Three-phase measurement CDCs */
iec61850_data_object_t *iec61850_cdc_create_mx3(const char *name);
iec61850_data_object_t *iec61850_cdc_create_del3(const char *name);

/* WP-S6 extension CDCs (implemented in src/ied/cdc/, WP-6a) */
iec61850_data_object_t *iec61850_cdc_create_apc(const char *name);
iec61850_data_object_t *iec61850_cdc_create_enc(const char *name);
iec61850_data_object_t *iec61850_cdc_create_isc(const char *name);
iec61850_data_object_t *iec61850_cdc_create_curs(const char *name);
iec61850_data_object_t *iec61850_cdc_create_csd(const char *name);
iec61850_data_object_t *iec61850_cdc_create_seq(const char *name);
iec61850_data_object_t *iec61850_cdc_create_hmv(const char *name);
iec61850_data_object_t *iec61850_cdc_create_hwye(const char *name);
iec61850_data_object_t *iec61850_cdc_create_hdel(const char *name);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_IED_DATA_MODEL_H */
