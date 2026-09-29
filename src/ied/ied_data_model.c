/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IED Data Model Implementation
 *
 * Uses malloc for tree construction (init-time, not hot path).
 * DataAttribute value access is thread-safe via pthread_mutex_t.
 *
 * License: BSD-3-Clause
 */


#include "ied/ied_data_model.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ========================================================================
 * DataAttribute
 * ======================================================================== */

int iec61850_da_init(iec61850_data_attribute_t *da, const char *name,
                      iec61850_fc_t fc, iec61850_btype_t btype)
{
    if (da == NULL || name == NULL) { return -1; }

    (void)memset(da, 0, sizeof(*da));
    (void)strncpy(da->name, name, IEC61850_MAX_NAME_LEN - 1);
    da->fc = fc;
    da->btype = btype;
    da->valid = true;
    (void)pthread_mutex_init(&da->mutex, NULL);

    return 0;
}

void iec61850_da_destroy(iec61850_data_attribute_t *da)
{
    if (da != NULL && da->valid) {
        (void)pthread_mutex_destroy(&da->mutex);
        da->valid = false;
    }
}

mms_value_t iec61850_da_get_value(iec61850_data_attribute_t *da)
{
    mms_value_t val;
    (void)memset(&val, 0, sizeof(val));

    if (da != NULL && da->valid) {
        (void)pthread_mutex_lock(&da->mutex);
        val = da->value;
        (void)pthread_mutex_unlock(&da->mutex);
    }
    return val;
}

void iec61850_da_set_value(iec61850_data_attribute_t *da,
                            const mms_value_t *value)
{
    mms_value_t old_val;

    if (da == NULL || value == NULL || !da->valid) { return; }

    (void)pthread_mutex_lock(&da->mutex);
    old_val = da->value;
    da->value = *value;
    (void)pthread_mutex_unlock(&da->mutex);

    if (da->change_cb != NULL) {
        da->change_cb(&old_val, value, da->change_cb_user_data);
    }
}

void iec61850_da_set_change_callback(iec61850_data_attribute_t *da,
                                      iec61850_da_change_cb_t cb,
                                      void *user_data)
{
    if (da != NULL) {
        da->change_cb = cb;
        da->change_cb_user_data = user_data;
    }
}

/* ========================================================================
 * DataObject
 * ======================================================================== */

iec61850_data_object_t *iec61850_do_create(const char *name, iec61850_cdc_t cdc)
{
    iec61850_data_object_t *dobj;

    if (name == NULL) { return NULL; }

    dobj = calloc(1, sizeof(*dobj));
    if (dobj == NULL) { return NULL; }

    (void)strncpy(dobj->name, name, IEC61850_MAX_NAME_LEN - 1);
    dobj->cdc = cdc;
    dobj->valid = true;

    return dobj;
}

void iec61850_do_destroy(iec61850_data_object_t *dobj)
{
    if (dobj == NULL) { return; }

    for (size_t i = 0; i < dobj->attr_count; i++) {
        iec61850_da_destroy(&dobj->attributes[i]);
    }
    for (size_t i = 0; i < dobj->sub_count; i++) {
        iec61850_do_destroy(dobj->sub_objects[i]);
    }

    free(dobj);
}

int iec61850_do_add_attribute(iec61850_data_object_t *dobj,
                               const char *name, iec61850_fc_t fc,
                               iec61850_btype_t btype)
{
    if (dobj == NULL || dobj->attr_count >= (size_t)IEC61850_MAX_DA_PER_DO) {
        return -1;
    }

    return iec61850_da_init(&dobj->attributes[dobj->attr_count++],
                             name, fc, btype);
}

int iec61850_do_add_sub_object(iec61850_data_object_t *dobj,
                                iec61850_data_object_t *sub)
{
    if (dobj == NULL || sub == NULL ||
        dobj->sub_count >= (size_t)IEC61850_MAX_SUBDO_PER_DO) {
        return -1;
    }

    dobj->sub_objects[dobj->sub_count++] = sub;
    return 0;
}

iec61850_data_attribute_t *iec61850_do_find_attribute(
    iec61850_data_object_t *dobj, const char *name, iec61850_fc_t fc)
{
    if (dobj == NULL || name == NULL) { return NULL; }

    for (size_t i = 0; i < dobj->attr_count; i++) {
        if (dobj->attributes[i].valid &&
            strcmp(dobj->attributes[i].name, name) == 0 &&
            dobj->attributes[i].fc == fc) {
            return &dobj->attributes[i];
        }
    }
    return NULL;
}

iec61850_data_object_t *iec61850_do_find_sub_object(
    iec61850_data_object_t *dobj, const char *name)
{
    if (dobj == NULL || name == NULL) { return NULL; }

    for (size_t i = 0; i < dobj->sub_count; i++) {
        if (dobj->sub_objects[i] != NULL &&
            strcmp(dobj->sub_objects[i]->name, name) == 0) {
            return dobj->sub_objects[i];
        }
    }
    return NULL;
}

/* ========================================================================
 * LogicalNode
 * ======================================================================== */

iec61850_logical_node_t *iec61850_ln_create(const char *ln_class,
                                             const char *ln_inst)
{
    iec61850_logical_node_t *ln;

    if (ln_class == NULL) { return NULL; }

    ln = calloc(1, sizeof(*ln));
    if (ln == NULL) { return NULL; }

    (void)strncpy(ln->ln_class, ln_class, IEC61850_MAX_NAME_LEN - 1);
    if (ln_inst != NULL) {
        (void)strncpy(ln->ln_inst, ln_inst, IEC61850_MAX_NAME_LEN - 1);
    }
    ln->valid = true;

    return ln;
}

void iec61850_ln_destroy(iec61850_logical_node_t *ln)
{
    if (ln == NULL) { return; }

    for (size_t i = 0; i < ln->do_count; i++) {
        iec61850_do_destroy(ln->data_objects[i]);
    }

    free(ln);
}

int iec61850_ln_add_data_object(iec61850_logical_node_t *ln,
                                 iec61850_data_object_t *dobj)
{
    if (ln == NULL || dobj == NULL ||
        ln->do_count >= (size_t)IEC61850_MAX_DO_PER_LN) {
        return -1;
    }

    ln->data_objects[ln->do_count++] = dobj;
    return 0;
}

iec61850_data_object_t *iec61850_ln_find_do(
    const iec61850_logical_node_t *ln, const char *do_name)
{
    if (ln == NULL || do_name == NULL) { return NULL; }

    for (size_t i = 0; i < ln->do_count; i++) {
        if (ln->data_objects[i] != NULL &&
            strcmp(ln->data_objects[i]->name, do_name) == 0) {
            return ln->data_objects[i];
        }
    }
    return NULL;
}

iec61850_data_attribute_t *iec61850_ln_find_attribute(
    const iec61850_logical_node_t *ln, const char *path, iec61850_fc_t fc)
{
    char buf[256];
    char *dot;
    iec61850_data_object_t *dobj;

    if (ln == NULL || path == NULL) { return NULL; }

    (void)strncpy(buf, path, sizeof(buf) - 1U);
    buf[sizeof(buf) - 1U] = '\0';

    /* Split on first dot: "Pos.stVal" -> DO="Pos", rest="stVal" */
    dot = strchr(buf, '.');
    if (dot == NULL) {
        /* No dot: path is just a DO name, can't find attribute */
        return NULL;
    }

    *dot = '\0';
    char *rest = dot + 1;

    dobj = iec61850_ln_find_do(ln, buf);
    if (dobj == NULL) { return NULL; }

    /* Check if rest contains more dots (sub-objects) */
    dot = strchr(rest, '.');
    while (dot != NULL) {
        *dot = '\0';
        iec61850_data_object_t *sub = iec61850_do_find_sub_object(dobj, rest);
        if (sub == NULL) {
            /* Try as attribute name */
            break;
        }
        dobj = sub;
        rest = dot + 1;
        dot = strchr(rest, '.');
    }

    return iec61850_do_find_attribute(dobj, rest, fc);
}

/* ========================================================================
 * LogicalDevice
 * ======================================================================== */

iec61850_logical_device_t *iec61850_ld_create(const char *ld_inst)
{
    iec61850_logical_device_t *ld;

    if (ld_inst == NULL) { return NULL; }

    ld = calloc(1, sizeof(*ld));
    if (ld == NULL) { return NULL; }

    (void)strncpy(ld->ld_inst, ld_inst, IEC61850_MAX_NAME_LEN - 1);
    ld->valid = true;

    return ld;
}

void iec61850_ld_destroy(iec61850_logical_device_t *ld)
{
    if (ld == NULL) { return; }

    for (size_t i = 0; i < ld->ln_count; i++) {
        iec61850_ln_destroy(ld->logical_nodes[i]);
    }

    free(ld);
}

int iec61850_ld_add_logical_node(iec61850_logical_device_t *ld,
                                  iec61850_logical_node_t *ln)
{
    if (ld == NULL || ln == NULL ||
        ld->ln_count >= (size_t)IEC61850_MAX_LN_PER_LD) {
        return -1;
    }

    ld->logical_nodes[ld->ln_count++] = ln;
    return 0;
}

iec61850_logical_node_t *iec61850_ld_find_ln(
    const iec61850_logical_device_t *ld, const char *ln_name)
{
    char combined[IEC61850_MAX_NAME_LEN * 2];

    if (ld == NULL || ln_name == NULL) { return NULL; }

    for (size_t i = 0; i < ld->ln_count; i++) {
        iec61850_logical_node_t *ln = ld->logical_nodes[i];
        if (ln == NULL) { continue; }

        /* Build combined name: class + inst */
        (void)snprintf(combined, sizeof(combined), "%s%s",
                       ln->ln_class, ln->ln_inst);

        if (strcmp(combined, ln_name) == 0 ||
            strcmp(ln->ln_class, ln_name) == 0) {
            return ln;
        }
    }
    return NULL;
}

/* ========================================================================
 * IedDataModel
 * ======================================================================== */

void iec61850_ied_model_init(iec61850_ied_model_t *model, const char *ied_name)
{
    if (model == NULL) { return; }

    (void)memset(model, 0, sizeof(*model));
    if (ied_name != NULL) {
        (void)strncpy(model->ied_name, ied_name, IEC61850_MAX_NAME_LEN - 1);
    }
}

void iec61850_ied_model_destroy(iec61850_ied_model_t *model)
{
    if (model == NULL) { return; }

    for (size_t i = 0; i < model->ld_count; i++) {
        iec61850_ld_destroy(model->logical_devices[i]);
    }
    model->ld_count = 0;
}

int iec61850_ied_model_add_ld(iec61850_ied_model_t *model,
                               iec61850_logical_device_t *ld)
{
    if (model == NULL || ld == NULL ||
        model->ld_count >= (size_t)IEC61850_MAX_LD_PER_IED) {
        return -1;
    }

    model->logical_devices[model->ld_count++] = ld;
    return 0;
}

iec61850_logical_device_t *iec61850_ied_model_find_ld(
    const iec61850_ied_model_t *model, const char *ld_inst)
{
    if (model == NULL || ld_inst == NULL) { return NULL; }

    for (size_t i = 0; i < model->ld_count; i++) {
        if (model->logical_devices[i] != NULL &&
            strcmp(model->logical_devices[i]->ld_inst, ld_inst) == 0) {
            return model->logical_devices[i];
        }
    }
    return NULL;
}

iec61850_data_attribute_t *iec61850_ied_model_find_attribute(
    const iec61850_ied_model_t *model, const char *path, iec61850_fc_t fc)
{
    char buf[256];
    char *slash;
    const iec61850_logical_device_t *ld;
    const iec61850_logical_node_t *ln;
    char *dot;

    if (model == NULL || path == NULL) { return NULL; }

    (void)strncpy(buf, path, sizeof(buf) - 1U);
    buf[sizeof(buf) - 1U] = '\0';

    /* Split on '/': "LD0/XCBR1.Pos.stVal" */
    slash = strchr(buf, '/');
    if (slash == NULL) { return NULL; }
    *slash = '\0';

    ld = iec61850_ied_model_find_ld(model, buf);
    if (ld == NULL) { return NULL; }

    /* Rest: "XCBR1.Pos.stVal" - split on first dot for LN name */
    char *ln_and_rest = slash + 1;
    dot = strchr(ln_and_rest, '.');
    if (dot == NULL) { return NULL; }
    *dot = '\0';

    ln = iec61850_ld_find_ln(ld, ln_and_rest);
    if (ln == NULL) { return NULL; }

    /* Rest: "Pos.stVal" */
    return iec61850_ln_find_attribute(ln, dot + 1, fc);
}

size_t iec61850_ied_model_count_ld(const iec61850_ied_model_t *model)
{
    return (model != NULL) ? model->ld_count : 0U;
}

size_t iec61850_ied_model_count_ln(const iec61850_ied_model_t *model)
{
    size_t count = 0;
    if (model == NULL) { return 0; }
    for (size_t i = 0; i < model->ld_count; i++) {
        if (model->logical_devices[i] != NULL) {
            count += model->logical_devices[i]->ln_count;
        }
    }
    return count;
}

size_t iec61850_ied_model_count_do(const iec61850_ied_model_t *model)
{
    size_t count = 0;
    if (model == NULL) { return 0; }
    for (size_t i = 0; i < model->ld_count; i++) {
        iec61850_logical_device_t *ld = model->logical_devices[i];
        if (ld == NULL) { continue; }
        for (size_t j = 0; j < ld->ln_count; j++) {
            if (ld->logical_nodes[j] != NULL) {
                count += ld->logical_nodes[j]->do_count;
            }
        }
    }
    return count;
}

size_t iec61850_ied_model_count_da(const iec61850_ied_model_t *model)
{
    size_t count = 0;
    if (model == NULL) { return 0; }
    for (size_t i = 0; i < model->ld_count; i++) {
        iec61850_logical_device_t *ld = model->logical_devices[i];
        if (ld == NULL) { continue; }
        for (size_t j = 0; j < ld->ln_count; j++) {
            iec61850_logical_node_t *ln = ld->logical_nodes[j];
            if (ln == NULL) { continue; }
            for (size_t k = 0; k < ln->do_count; k++) {
                if (ln->data_objects[k] != NULL) {
                    count += ln->data_objects[k]->attr_count;
                }
            }
        }
    }
    return count;
}

/* ========================================================================
 * CDC Factory
 * ======================================================================== */

iec61850_data_object_t *iec61850_cdc_create_spc(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_SPC);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "stVal", IEC61850_FC_ST, IEC61850_BTYPE_BOOLEAN);
    (void)iec61850_do_add_attribute(dobj, "q", IEC61850_FC_ST, IEC61850_BTYPE_QUALITY);
    (void)iec61850_do_add_attribute(dobj, "t", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP);
    (void)iec61850_do_add_attribute(dobj, "ctlVal", IEC61850_FC_CO, IEC61850_BTYPE_BOOLEAN);
    (void)iec61850_do_add_attribute(dobj, "ctlModel", IEC61850_FC_CF, IEC61850_BTYPE_ENUMERATED);

    return dobj;
}

iec61850_data_object_t *iec61850_cdc_create_dpc(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_DPC);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "stVal", IEC61850_FC_ST, IEC61850_BTYPE_DBPOS);
    (void)iec61850_do_add_attribute(dobj, "q", IEC61850_FC_ST, IEC61850_BTYPE_QUALITY);
    (void)iec61850_do_add_attribute(dobj, "t", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP);
    (void)iec61850_do_add_attribute(dobj, "ctlVal", IEC61850_FC_CO, IEC61850_BTYPE_DBPOS);
    (void)iec61850_do_add_attribute(dobj, "ctlModel", IEC61850_FC_CF, IEC61850_BTYPE_ENUMERATED);

    return dobj;
}

iec61850_data_object_t *iec61850_cdc_create_ins(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_INS);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "stVal", IEC61850_FC_ST, IEC61850_BTYPE_INT32);
    (void)iec61850_do_add_attribute(dobj, "q", IEC61850_FC_ST, IEC61850_BTYPE_QUALITY);
    (void)iec61850_do_add_attribute(dobj, "t", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP);

    return dobj;
}

iec61850_data_object_t *iec61850_cdc_create_mv(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_MV);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "mag", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32);
    (void)iec61850_do_add_attribute(dobj, "q", IEC61850_FC_MX, IEC61850_BTYPE_QUALITY);
    (void)iec61850_do_add_attribute(dobj, "t", IEC61850_FC_MX, IEC61850_BTYPE_TIMESTAMP);

    return dobj;
}

iec61850_data_object_t *iec61850_cdc_create_sps(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_SPS);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "stVal", IEC61850_FC_ST, IEC61850_BTYPE_BOOLEAN);
    (void)iec61850_do_add_attribute(dobj, "q", IEC61850_FC_ST, IEC61850_BTYPE_QUALITY);
    (void)iec61850_do_add_attribute(dobj, "t", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP);

    return dobj;
}

iec61850_data_object_t *iec61850_cdc_create_dps(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_DPS);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "stVal", IEC61850_FC_ST, IEC61850_BTYPE_DBPOS);
    (void)iec61850_do_add_attribute(dobj, "q", IEC61850_FC_ST, IEC61850_BTYPE_QUALITY);
    (void)iec61850_do_add_attribute(dobj, "t", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP);

    return dobj;
}

iec61850_data_object_t *iec61850_cdc_create_ens(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_ENS);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "stVal", IEC61850_FC_ST, IEC61850_BTYPE_ENUMERATED);
    (void)iec61850_do_add_attribute(dobj, "q", IEC61850_FC_ST, IEC61850_BTYPE_QUALITY);
    (void)iec61850_do_add_attribute(dobj, "t", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP);

    return dobj;
}

iec61850_data_object_t *iec61850_cdc_create_act(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_ACT);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "general", IEC61850_FC_ST, IEC61850_BTYPE_BOOLEAN);
    (void)iec61850_do_add_attribute(dobj, "phsA", IEC61850_FC_ST, IEC61850_BTYPE_BOOLEAN);
    (void)iec61850_do_add_attribute(dobj, "phsB", IEC61850_FC_ST, IEC61850_BTYPE_BOOLEAN);
    (void)iec61850_do_add_attribute(dobj, "phsC", IEC61850_FC_ST, IEC61850_BTYPE_BOOLEAN);
    (void)iec61850_do_add_attribute(dobj, "q", IEC61850_FC_ST, IEC61850_BTYPE_QUALITY);
    (void)iec61850_do_add_attribute(dobj, "t", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP);

    return dobj;
}

iec61850_data_object_t *iec61850_cdc_create_acd(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_ACD);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "general", IEC61850_FC_ST, IEC61850_BTYPE_BOOLEAN);
    (void)iec61850_do_add_attribute(dobj, "dirGeneral", IEC61850_FC_ST, IEC61850_BTYPE_ENUMERATED);
    (void)iec61850_do_add_attribute(dobj, "phsA", IEC61850_FC_ST, IEC61850_BTYPE_BOOLEAN);
    (void)iec61850_do_add_attribute(dobj, "phsB", IEC61850_FC_ST, IEC61850_BTYPE_BOOLEAN);
    (void)iec61850_do_add_attribute(dobj, "phsC", IEC61850_FC_ST, IEC61850_BTYPE_BOOLEAN);
    (void)iec61850_do_add_attribute(dobj, "q", IEC61850_FC_ST, IEC61850_BTYPE_QUALITY);
    (void)iec61850_do_add_attribute(dobj, "t", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP);

    return dobj;
}

iec61850_data_object_t *iec61850_cdc_create_sec(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_SEC);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "cnt", IEC61850_FC_ST, IEC61850_BTYPE_INT32U);
    (void)iec61850_do_add_attribute(dobj, "sev", IEC61850_FC_ST, IEC61850_BTYPE_ENUMERATED);
    (void)iec61850_do_add_attribute(dobj, "t", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP);

    return dobj;
}

iec61850_data_object_t *iec61850_cdc_create_inc(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_INC);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "stVal", IEC61850_FC_ST, IEC61850_BTYPE_INT32);
    (void)iec61850_do_add_attribute(dobj, "q", IEC61850_FC_ST, IEC61850_BTYPE_QUALITY);
    (void)iec61850_do_add_attribute(dobj, "t", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP);
    (void)iec61850_do_add_attribute(dobj, "ctlVal", IEC61850_FC_CO, IEC61850_BTYPE_INT32);
    (void)iec61850_do_add_attribute(dobj, "ctlModel", IEC61850_FC_CF, IEC61850_BTYPE_ENUMERATED);

    return dobj;
}

iec61850_data_object_t *iec61850_cdc_create_bsc(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_BSC);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "valWTr", IEC61850_FC_ST, IEC61850_BTYPE_STRUCT);
    (void)iec61850_do_add_attribute(dobj, "q", IEC61850_FC_ST, IEC61850_BTYPE_QUALITY);
    (void)iec61850_do_add_attribute(dobj, "t", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP);
    (void)iec61850_do_add_attribute(dobj, "ctlVal", IEC61850_FC_CO, IEC61850_BTYPE_STRUCT);
    (void)iec61850_do_add_attribute(dobj, "ctlModel", IEC61850_FC_CF, IEC61850_BTYPE_ENUMERATED);

    return dobj;
}

iec61850_data_object_t *iec61850_cdc_create_cmv(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_CMV);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "cVal.mag.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32);
    (void)iec61850_do_add_attribute(dobj, "cVal.ang.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32);
    (void)iec61850_do_add_attribute(dobj, "q", IEC61850_FC_MX, IEC61850_BTYPE_QUALITY);
    (void)iec61850_do_add_attribute(dobj, "t", IEC61850_FC_MX, IEC61850_BTYPE_TIMESTAMP);

    return dobj;
}

iec61850_data_object_t *iec61850_cdc_create_sav(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_SAV);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "instMag.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32);
    (void)iec61850_do_add_attribute(dobj, "q", IEC61850_FC_MX, IEC61850_BTYPE_QUALITY);
    (void)iec61850_do_add_attribute(dobj, "t", IEC61850_FC_MX, IEC61850_BTYPE_TIMESTAMP);

    return dobj;
}

iec61850_data_object_t *iec61850_cdc_create_wye(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_WYE);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "phsA.cVal.mag.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32);
    (void)iec61850_do_add_attribute(dobj, "phsA.cVal.ang.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32);
    (void)iec61850_do_add_attribute(dobj, "phsB.cVal.mag.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32);
    (void)iec61850_do_add_attribute(dobj, "phsB.cVal.ang.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32);
    (void)iec61850_do_add_attribute(dobj, "phsC.cVal.mag.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32);
    (void)iec61850_do_add_attribute(dobj, "phsC.cVal.ang.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32);
    (void)iec61850_do_add_attribute(dobj, "q", IEC61850_FC_MX, IEC61850_BTYPE_QUALITY);
    (void)iec61850_do_add_attribute(dobj, "t", IEC61850_FC_MX, IEC61850_BTYPE_TIMESTAMP);

    return dobj;
}

iec61850_data_object_t *iec61850_cdc_create_del(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_DEL);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "phsAB.cVal.mag.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32);
    (void)iec61850_do_add_attribute(dobj, "phsAB.cVal.ang.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32);
    (void)iec61850_do_add_attribute(dobj, "phsBC.cVal.mag.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32);
    (void)iec61850_do_add_attribute(dobj, "phsBC.cVal.ang.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32);
    (void)iec61850_do_add_attribute(dobj, "phsCA.cVal.mag.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32);
    (void)iec61850_do_add_attribute(dobj, "phsCA.cVal.ang.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32);
    (void)iec61850_do_add_attribute(dobj, "q", IEC61850_FC_MX, IEC61850_BTYPE_QUALITY);
    (void)iec61850_do_add_attribute(dobj, "t", IEC61850_FC_MX, IEC61850_BTYPE_TIMESTAMP);

    return dobj;
}

iec61850_data_object_t *iec61850_cdc_create_spg(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_SPG);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "setVal", IEC61850_FC_SP, IEC61850_BTYPE_BOOLEAN);

    return dobj;
}

iec61850_data_object_t *iec61850_cdc_create_asg(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_ASG);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "setMag.f", IEC61850_FC_SP, IEC61850_BTYPE_FLOAT32);

    return dobj;
}

iec61850_data_object_t *iec61850_cdc_create_lpl(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_LPL);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "vendor", IEC61850_FC_DC, IEC61850_BTYPE_VISIBLE_STRING);
    (void)iec61850_do_add_attribute(dobj, "swRev", IEC61850_FC_DC, IEC61850_BTYPE_VISIBLE_STRING);
    (void)iec61850_do_add_attribute(dobj, "d", IEC61850_FC_DC, IEC61850_BTYPE_VISIBLE_STRING);
    (void)iec61850_do_add_attribute(dobj, "configRev", IEC61850_FC_DC, IEC61850_BTYPE_VISIBLE_STRING);
    (void)iec61850_do_add_attribute(dobj, "ldNs", IEC61850_FC_EX, IEC61850_BTYPE_VISIBLE_STRING);

    return dobj;
}

iec61850_data_object_t *iec61850_cdc_create_dpl(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_DPL);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "vendor", IEC61850_FC_DC, IEC61850_BTYPE_VISIBLE_STRING);
    (void)iec61850_do_add_attribute(dobj, "hwRev", IEC61850_FC_DC, IEC61850_BTYPE_VISIBLE_STRING);
    (void)iec61850_do_add_attribute(dobj, "swRev", IEC61850_FC_DC, IEC61850_BTYPE_VISIBLE_STRING);
    (void)iec61850_do_add_attribute(dobj, "serNum", IEC61850_FC_DC, IEC61850_BTYPE_VISIBLE_STRING);
    (void)iec61850_do_add_attribute(dobj, "model", IEC61850_FC_DC, IEC61850_BTYPE_VISIBLE_STRING);

    return dobj;
}

iec61850_data_object_t *iec61850_cdc_create_bcr(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_BCR);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "actVal", IEC61850_FC_ST, IEC61850_BTYPE_INT64);
    (void)iec61850_do_add_attribute(dobj, "frVal", IEC61850_FC_ST, IEC61850_BTYPE_INT64);
    (void)iec61850_do_add_attribute(dobj, "frTm", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP);
    (void)iec61850_do_add_attribute(dobj, "q", IEC61850_FC_ST, IEC61850_BTYPE_QUALITY);
    (void)iec61850_do_add_attribute(dobj, "t", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP);

    return dobj;
}

iec61850_data_object_t *iec61850_cdc_create_vss(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_VSS);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "stVal", IEC61850_FC_ST, IEC61850_BTYPE_VISIBLE_STRING);
    (void)iec61850_do_add_attribute(dobj, "q", IEC61850_FC_ST, IEC61850_BTYPE_QUALITY);
    (void)iec61850_do_add_attribute(dobj, "t", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP);

    return dobj;
}

iec61850_data_object_t *iec61850_cdc_create_mx3(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_MX3);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "phsA.mag.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32);
    (void)iec61850_do_add_attribute(dobj, "phsB.mag.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32);
    (void)iec61850_do_add_attribute(dobj, "phsC.mag.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32);
    (void)iec61850_do_add_attribute(dobj, "q", IEC61850_FC_MX, IEC61850_BTYPE_QUALITY);
    (void)iec61850_do_add_attribute(dobj, "t", IEC61850_FC_MX, IEC61850_BTYPE_TIMESTAMP);

    return dobj;
}

iec61850_data_object_t *iec61850_cdc_create_del3(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_DEL3);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "phsAB.mag.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32);
    (void)iec61850_do_add_attribute(dobj, "phsBC.mag.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32);
    (void)iec61850_do_add_attribute(dobj, "phsCA.mag.f", IEC61850_FC_MX, IEC61850_BTYPE_FLOAT32);
    (void)iec61850_do_add_attribute(dobj, "q", IEC61850_FC_MX, IEC61850_BTYPE_QUALITY);
    (void)iec61850_do_add_attribute(dobj, "t", IEC61850_FC_MX, IEC61850_BTYPE_TIMESTAMP);

    return dobj;
}
