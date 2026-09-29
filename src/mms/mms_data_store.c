/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Data Store Implementation
 *
 * All collections use malloc/realloc with doubling growth.
 * Thread-safe via pthread_mutex_t.
 *
 * License: BSD-3-Clause
 */


#include "mms/mms_data_store.h"
#include <stdlib.h>
#include <string.h>

/* ========================================================================
 * Internal helpers (caller must hold mutex)
 * ======================================================================== */

static iec61850_mms_domain_t *find_domain(iec61850_mms_data_store_t *ds,
                                            const char *name)
{
    for (size_t i = 0; i < ds->domain_count; i++) {
        if (strcmp(ds->domains[i].name, name) == 0) {
            return &ds->domains[i];
        }
    }
    return NULL;
}

static const iec61850_mms_domain_t *find_domain_const(
    const iec61850_mms_data_store_t *ds, const char *name)
{
    for (size_t i = 0; i < ds->domain_count; i++) {
        if (strcmp(ds->domains[i].name, name) == 0) {
            return &ds->domains[i];
        }
    }
    return NULL;
}

static iec61850_mms_variable_t *find_var(iec61850_mms_domain_t *dom,
                                           const char *item_id)
{
    for (size_t i = 0; i < dom->var_count; i++) {
        if (strcmp(dom->vars[i].item_id, item_id) == 0) {
            return &dom->vars[i];
        }
    }
    return NULL;
}

static const iec61850_mms_variable_t *find_var_const(
    const iec61850_mms_domain_t *dom, const char *item_id)
{
    for (size_t i = 0; i < dom->var_count; i++) {
        if (strcmp(dom->vars[i].item_id, item_id) == 0) {
            return &dom->vars[i];
        }
    }
    return NULL;
}

/* Grow an array by doubling. Returns 0 on success, -1 on alloc failure. */
static int grow_array(void **ptr, size_t *capacity, size_t elem_size,
                       size_t init_cap)
{
    size_t new_cap = (*capacity == 0) ? init_cap : (*capacity * 2);
    void *new_ptr = realloc(*ptr, new_cap * elem_size);
    if (new_ptr == NULL) {
        return -1;
    }
    /* Zero the new portion */
    /* MISRA 11.5: void*→char* cast required for byte arithmetic on opaque buffer */
    (void)memset(&((char *)new_ptr)[*capacity * elem_size], 0,
                  (new_cap - *capacity) * elem_size);
    *ptr = new_ptr;
    *capacity = new_cap;
    return 0;
}

static void domain_init(iec61850_mms_domain_t *dom)
{
    dom->vars = NULL;
    dom->var_count = 0;
    dom->var_capacity = 0;
    dom->lists = NULL;
    dom->list_count = 0;
    dom->list_capacity = 0;
}

static void domain_free(iec61850_mms_domain_t *dom)
{
    /* Free each named list's variable array */
    for (size_t i = 0; i < dom->list_count; i++) {
        free(dom->lists[i].variables);
    }
    free(dom->lists);
    free(dom->vars);
    dom->vars = NULL;
    dom->lists = NULL;
    dom->var_count = 0;
    dom->list_count = 0;
    dom->var_capacity = 0;
    dom->list_capacity = 0;
}

/* ========================================================================
 * Public API
 * ======================================================================== */

void iec61850_mms_ds_init(iec61850_mms_data_store_t *ds)
{
    if (ds == NULL) { return; }
    ds->domains = NULL;
    ds->domain_count = 0;
    ds->domain_capacity = 0;
    (void)pthread_mutex_init(&ds->mutex, NULL);
}

void iec61850_mms_ds_destroy(iec61850_mms_data_store_t *ds)
{
    if (ds == NULL) { return; }

    for (size_t i = 0; i < ds->domain_count; i++) {
        domain_free(&ds->domains[i]);
    }
    free(ds->domains);
    ds->domains = NULL;
    ds->domain_count = 0;
    ds->domain_capacity = 0;

    (void)pthread_mutex_destroy(&ds->mutex);
}

int iec61850_mms_ds_create_domain(iec61850_mms_data_store_t *ds,
                                   const char *domain)
{
    int result;

    if (ds == NULL || domain == NULL) { return IEC61850_MMS_DS_ERR_ARGS; }

    (void)pthread_mutex_lock(&ds->mutex);

    if (find_domain(ds, domain) != NULL) {
        result = IEC61850_MMS_DS_ERR_EXISTS;
        goto done;
    }

    /* Grow domains array if needed */
    if (ds->domain_count >= ds->domain_capacity) {
        if (grow_array((void **)&ds->domains, &ds->domain_capacity,
                        sizeof(iec61850_mms_domain_t),
                        IEC61850_MMS_INIT_DOMAINS) != 0) {
            result = IEC61850_MMS_DS_ERR_ALLOC;
            goto done;
        }
    }

    iec61850_mms_domain_t *dom = &ds->domains[ds->domain_count];
    (void)memset(dom, 0, sizeof(*dom));
    (void)strncpy(dom->name, domain, MMS_MAX_DOMAIN_NAME - 1);
    domain_init(dom);
    ds->domain_count++;
    result = IEC61850_MMS_DS_OK;

done:
    (void)pthread_mutex_unlock(&ds->mutex);
    return result;
}

bool iec61850_mms_ds_domain_exists(const iec61850_mms_data_store_t *ds,
                                    const char *domain)
{
    if (ds == NULL || domain == NULL) { return false; }
    return find_domain_const(ds, domain) != NULL;
}

int iec61850_mms_ds_create_variable(iec61850_mms_data_store_t *ds,
                                     const char *domain, const char *item_id,
                                     mms_type_t type,
                                     const mms_value_t *initial_value)
{
    int result;
    iec61850_mms_domain_t *dom;

    if (ds == NULL || domain == NULL || item_id == NULL) {
        return IEC61850_MMS_DS_ERR_ARGS;
    }

    (void)pthread_mutex_lock(&ds->mutex);

    dom = find_domain(ds, domain);
    if (dom == NULL) {
        result = IEC61850_MMS_DS_ERR_NOT_FOUND;
        goto done;
    }

    if (find_var(dom, item_id) != NULL) {
        result = IEC61850_MMS_DS_ERR_EXISTS;
        goto done;
    }

    /* Grow variable array if needed */
    if (dom->var_count >= dom->var_capacity) {
        if (grow_array((void **)&dom->vars, &dom->var_capacity,
                        sizeof(iec61850_mms_variable_t),
                        IEC61850_MMS_INIT_VARS) != 0) {
            result = IEC61850_MMS_DS_ERR_ALLOC;
            goto done;
        }
    }

    iec61850_mms_variable_t *v = &dom->vars[dom->var_count];
    (void)memset(v, 0, sizeof(*v));
    (void)strncpy(v->item_id, item_id, MMS_MAX_VARIABLE_NAME - 1);
    v->type = type;
    if (initial_value != NULL) {
        v->value = *initial_value;
    }
    v->value.type = type;
    v->deletable = true;
    dom->var_count++;
    result = IEC61850_MMS_DS_OK;

done:
    (void)pthread_mutex_unlock(&ds->mutex);
    return result;
}

int iec61850_mms_ds_read_variable(iec61850_mms_data_store_t *ds,
                                   const char *domain, const char *item_id,
                                   mms_value_t *value)
{
    int result;

    if (ds == NULL || domain == NULL || item_id == NULL || value == NULL) {
        return IEC61850_MMS_DS_ERR_ARGS;
    }

    (void)pthread_mutex_lock(&ds->mutex);

    const iec61850_mms_domain_t *dom = find_domain_const(ds, domain);
    if (dom == NULL) {
        result = IEC61850_MMS_DS_ERR_NOT_FOUND;
    } else {
        const iec61850_mms_variable_t *v = find_var_const(dom, item_id);
        if (v == NULL) {
            result = IEC61850_MMS_DS_ERR_NOT_FOUND;
        } else {
            *value = v->value;
            result = IEC61850_MMS_DS_OK;
        }
    }

    (void)pthread_mutex_unlock(&ds->mutex);
    return result;
}

int iec61850_mms_ds_write_variable(iec61850_mms_data_store_t *ds,
                                    const char *domain, const char *item_id,
                                    const mms_value_t *value)
{
    int result;

    if (ds == NULL || domain == NULL || item_id == NULL || value == NULL) {
        return IEC61850_MMS_DS_ERR_ARGS;
    }

    (void)pthread_mutex_lock(&ds->mutex);

    iec61850_mms_domain_t *dom = find_domain(ds, domain);
    if (dom == NULL) {
        result = IEC61850_MMS_DS_ERR_NOT_FOUND;
    } else {
        iec61850_mms_variable_t *v = find_var(dom, item_id);
        if (v == NULL) {
            result = IEC61850_MMS_DS_ERR_NOT_FOUND;
        } else {
            v->value = *value;
            result = IEC61850_MMS_DS_OK;
        }
    }

    (void)pthread_mutex_unlock(&ds->mutex);
    return result;
}

int iec61850_mms_ds_get_variable_attrs(const iec61850_mms_data_store_t *ds,
                                        const char *domain, const char *item_id,
                                        mms_variable_access_attrs_t *attrs)
{
    if (ds == NULL || domain == NULL || item_id == NULL || attrs == NULL) {
        return IEC61850_MMS_DS_ERR_ARGS;
    }

    const iec61850_mms_domain_t *dom = find_domain_const(ds, domain);
    if (dom == NULL) { return IEC61850_MMS_DS_ERR_NOT_FOUND; }

    const iec61850_mms_variable_t *v = find_var_const(dom, item_id);
    if (v == NULL) { return IEC61850_MMS_DS_ERR_NOT_FOUND; }

    (void)memset(attrs, 0, sizeof(*attrs));
    (void)strncpy(attrs->name, item_id, MMS_MAX_VARIABLE_NAME - 1);
    attrs->type = v->type;

    return IEC61850_MMS_DS_OK;
}

bool iec61850_mms_ds_variable_exists(const iec61850_mms_data_store_t *ds,
                                      const char *domain, const char *item_id)
{
    if (ds == NULL || domain == NULL || item_id == NULL) { return false; }

    const iec61850_mms_domain_t *dom = find_domain_const(ds, domain);
    if (dom == NULL) { return false; }

    return find_var_const(dom, item_id) != NULL;
}

int iec61850_mms_ds_get_domain_names(const iec61850_mms_data_store_t *ds,
                                      char names[][MMS_MAX_DOMAIN_NAME],
                                      uint32_t *count, uint32_t max_count)
{
    if (ds == NULL || names == NULL || count == NULL) {
        return IEC61850_MMS_DS_ERR_ARGS;
    }
    *count = 0;
    for (size_t i = 0; i < ds->domain_count && *count < max_count; i++) {
        (void)strncpy(names[*count], ds->domains[i].name, MMS_MAX_DOMAIN_NAME - 1);
        names[*count][MMS_MAX_DOMAIN_NAME - 1] = '\0';
        (*count)++;
    }
    return IEC61850_MMS_DS_OK;
}

int iec61850_mms_ds_get_var_names(const iec61850_mms_data_store_t *ds,
                                   const char *domain,
                                   char names[][MMS_MAX_VARIABLE_NAME],
                                   uint32_t *count, uint32_t max_count)
{
    if (ds == NULL || domain == NULL || names == NULL || count == NULL) {
        return IEC61850_MMS_DS_ERR_ARGS;
    }

    const iec61850_mms_domain_t *dom = find_domain_const(ds, domain);
    if (dom == NULL) { return IEC61850_MMS_DS_ERR_NOT_FOUND; }

    *count = 0;
    for (size_t i = 0; i < dom->var_count && *count < max_count; i++) {
        (void)strncpy(names[*count], dom->vars[i].item_id,
                      MMS_MAX_VARIABLE_NAME - 1);
        names[*count][MMS_MAX_VARIABLE_NAME - 1] = '\0';
        (*count)++;
    }

    return IEC61850_MMS_DS_OK;
}

/* ========================================================================
 * Named Variable Lists
 * ======================================================================== */

int iec61850_mms_ds_define_list(iec61850_mms_data_store_t *ds,
                                 const char *domain, const char *list_name,
                                 const mms_variable_spec_t *variables,
                                 uint32_t num_variables)
{
    int result;
    iec61850_mms_domain_t *dom;

    if (ds == NULL || domain == NULL || list_name == NULL) {
        return IEC61850_MMS_DS_ERR_ARGS;
    }

    (void)pthread_mutex_lock(&ds->mutex);

    dom = find_domain(ds, domain);
    if (dom == NULL) {
        result = IEC61850_MMS_DS_ERR_NOT_FOUND;
        goto done;
    }

    /* Check for existing list with same name */
    for (size_t i = 0; i < dom->list_count; i++) {
        if (strcmp(dom->lists[i].list_name, list_name) == 0) {
            result = IEC61850_MMS_DS_ERR_EXISTS;
            goto done;
        }
    }

    /* Grow lists array if needed */
    if (dom->list_count >= dom->list_capacity) {
        if (grow_array((void **)&dom->lists, &dom->list_capacity,
                        sizeof(iec61850_mms_named_list_t),
                        IEC61850_MMS_INIT_LISTS) != 0) {
            result = IEC61850_MMS_DS_ERR_ALLOC;
            goto done;
        }
    }

    iec61850_mms_named_list_t *list = &dom->lists[dom->list_count];
    (void)memset(list, 0, sizeof(*list));
    (void)strncpy(list->list_name, list_name, MMS_MAX_VARIABLE_NAME - 1);
    list->deletable = true;

    /* Copy variables into heap-allocated array */
    if (variables != NULL && num_variables > 0U) {
        /* MISRA 11.5: malloc returns void*, deviation Cat. 3 */
        list->variables = malloc(num_variables * sizeof(mms_variable_spec_t));
        if (list->variables == NULL) {
            result = IEC61850_MMS_DS_ERR_ALLOC;
            goto done;
        }
        (void)memcpy(list->variables, variables,
                      num_variables * sizeof(mms_variable_spec_t));
        list->num_variables = num_variables;
        list->var_capacity = num_variables;
    }

    dom->list_count++;
    result = IEC61850_MMS_DS_OK;

done:
    (void)pthread_mutex_unlock(&ds->mutex);
    return result;
}

int iec61850_mms_ds_delete_list(iec61850_mms_data_store_t *ds,
                                 const char *domain, const char *list_name)
{
    int result = IEC61850_MMS_DS_ERR_NOT_FOUND;

    if (ds == NULL || domain == NULL || list_name == NULL) {
        return IEC61850_MMS_DS_ERR_ARGS;
    }

    (void)pthread_mutex_lock(&ds->mutex);

    iec61850_mms_domain_t *dom = find_domain(ds, domain);
    if (dom != NULL) {
        for (size_t i = 0; i < dom->list_count; i++) {
            if (strcmp(dom->lists[i].list_name, list_name) == 0) {
                /* Free the list's variable array */
                free(dom->lists[i].variables);

                /* Shift remaining lists down */
                for (size_t j = i; j + 1U < dom->list_count; j++) {
                    dom->lists[j] = dom->lists[j + 1U];
                }
                dom->list_count--;

                /* Zero the now-unused last slot */
                (void)memset(&dom->lists[dom->list_count], 0,
                              sizeof(iec61850_mms_named_list_t));

                result = IEC61850_MMS_DS_OK;
                break;
            }
        }
    }

    (void)pthread_mutex_unlock(&ds->mutex);
    return result;
}

int iec61850_mms_ds_get_list_attrs(const iec61850_mms_data_store_t *ds,
                                    const char *domain, const char *list_name,
                                    mms_variable_spec_t *variables,
                                    uint32_t *num_variables,
                                    uint32_t max_variables)
{
    if (ds == NULL || domain == NULL || list_name == NULL ||
        variables == NULL || num_variables == NULL) {
        return IEC61850_MMS_DS_ERR_ARGS;
    }

    const iec61850_mms_domain_t *dom = find_domain_const(ds, domain);
    if (dom == NULL) { return IEC61850_MMS_DS_ERR_NOT_FOUND; }

    for (size_t i = 0; i < dom->list_count; i++) {
        if (strcmp(dom->lists[i].list_name, list_name) == 0) {
            uint32_t copy = dom->lists[i].num_variables;
            if (copy > max_variables) { copy = max_variables; }
            if (dom->lists[i].variables != NULL && copy > 0U) {
                (void)memcpy(variables, dom->lists[i].variables,
                              copy * sizeof(mms_variable_spec_t));
            }
            *num_variables = copy;
            return IEC61850_MMS_DS_OK;
        }
    }

    return IEC61850_MMS_DS_ERR_NOT_FOUND;
}
