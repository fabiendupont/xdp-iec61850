/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * mms_setting_groups.c — SGCB implementation. See the header for
 * the variable layout and semantics; the code below follows the
 * pre-commit bridge pattern established by the RCB bridge
 * (mms_report.c).
 */

#include "mms/mms_setting_groups.h"

#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* Only the manager owns allocation (init-time); the bridge paths
 * are lock-free by the same convention as the rest of the server:
 * the manager is configured before the server starts. */

/* Bounds discipline (house style): a name that does not fit is a
 * configuration error, never a silent truncation — a truncated
 * "$SE$" item could collide with another entry and divert writes
 * to the wrong group copy. */
static int join_into(char *out, size_t outsz, const char *a,
                     const char *b)
{
    int n = snprintf(out, outsz, "%s$%s", a, b);
    return ((n < 0) || ((size_t)n >= outsz)) ? -ENAMETOOLONG : 0;
}

static int build_item(char *out, size_t outsz,
                      const iec61850_logical_node_t *ln,
                      const char *path)
{
    int n = snprintf(out, outsz, "%s%s$SE$%s", ln->ln_class, ln->ln_inst,
                     path);
    return ((n < 0) || ((size_t)n >= outsz)) ? -ENAMETOOLONG : 0;
}

/* Recursive model walk: register every FC=SE attribute, building
 * the "<DO>$<sub-DO>...$<DA>" path. */
static int register_do(iec61850_sg_manager_t *mgr,
                       const char *ld_inst,
                       const iec61850_logical_node_t *ln,
                       const iec61850_data_object_t *dobj,
                       char *path)
{
    for (size_t a = 0; a < dobj->attr_count; a++) {
        const iec61850_data_attribute_t *da = &dobj->attributes[a];
        if (da->fc != IEC61850_FC_SE) {
            continue;
        }
        if (mgr->entry_count >= IEC61850_SG_MAX_SE_ENTRIES) {
            return -ENOMEM;
        }
        char item[IEC61850_SG_MAX_ITEM_LEN];
        char full_path[IEC61850_SG_MAX_ITEM_LEN];
        int ret = join_into(full_path, sizeof(full_path), path,
                            da->name);
        if (ret != 0) {
            return ret;
        }
        ret = build_item(item, sizeof(item), ln, full_path);
        if (ret != 0) {
            return ret;
        }

        size_t e = mgr->entry_count;
        (void)snprintf(mgr->entries[e].ld, sizeof(mgr->entries[e].ld),
                       "%s", ld_inst);
        (void)snprintf(mgr->entries[e].item,
                       sizeof(mgr->entries[e].item), "%s", item);
        mgr->entries[e].live = (iec61850_data_attribute_t *)da;
        /* Every group starts as a copy of the initial value. */
        for (int g = 0; g < IEC61850_SG_MAX_GROUPS; g++) {
            mgr->entries[e].groups[g] = da->value;
        }
        mgr->entry_count++;
    }

    for (size_t s = 0; s < dobj->sub_count; s++) {
        char sub[IEC61850_SG_MAX_ITEM_LEN];
        int ret = join_into(sub, sizeof(sub), path,
                            dobj->sub_objects[s]->name);
        if (ret != 0) {
            return ret;
        }
        ret = register_do(mgr, ld_inst, ln, dobj->sub_objects[s],
                          sub);
        if (ret != 0) {
            return ret;
        }
    }
    return 0;
}

int iec61850_sg_manager_init(iec61850_sg_manager_t **mgr,
                             iec61850_ied_model_t *model,
                             uint8_t num_of_sg, uint8_t act_sg,
                             uint32_t resv_tms_s)
{
    if ((mgr == NULL) || (model == NULL) ||
        (num_of_sg < 1U) || (num_of_sg > IEC61850_SG_MAX_GROUPS) ||
        (act_sg < 1U) || (act_sg > num_of_sg)) {
        return -EINVAL;
    }

    iec61850_sg_manager_t *m = calloc(1, sizeof(*m));
    if (m == NULL) {
        return -ENOMEM;
    }
    m->model = model;
    m->num_of_sg = num_of_sg;
    m->act_sg = act_sg;
    m->edit_sg = 0;
    m->resv_tms_s = resv_tms_s;

    for (size_t l = 0; l < model->ld_count; l++) {
        const iec61850_logical_device_t *ld = model->logical_devices[l];
        for (size_t n = 0; n < ld->ln_count; n++) {
            const iec61850_logical_node_t *ln = ld->logical_nodes[n];
            for (size_t d = 0; d < ln->do_count; d++) {
                char path[IEC61850_SG_MAX_ITEM_LEN];
                (void)snprintf(path, sizeof(path), "%s",
                               ln->data_objects[d]->name);
                int ret = register_do(m, ld->ld_inst, ln,
                                      ln->data_objects[d], path);
                if (ret != 0) {
                    free(m);
                    return ret;
                }
            }
        }
    }

    *mgr = m;
    return 0;
}

void iec61850_sg_manager_destroy(iec61850_sg_manager_t *mgr)
{
    free(mgr);
}

void iec61850_sg_set_activation_callback(iec61850_sg_manager_t *mgr,
                                         iec61850_sg_activated_cb_t cb,
                                         void *user_data)
{
    if (mgr != NULL) {
        mgr->activated_cb = cb;
        mgr->activated_user = user_data;
    }
}

int iec61850_sg_activate(iec61850_sg_manager_t *mgr, uint8_t sg)
{
    if ((mgr == NULL) || (sg < 1U) || (sg > mgr->num_of_sg)) {
        return -EINVAL;
    }

    uint8_t prev = mgr->act_sg;
    for (size_t e = 0; e < mgr->entry_count; e++) {
        iec61850_da_set_value(mgr->entries[e].live,
                              &mgr->entries[e].groups[sg - 1U]);
    }
    mgr->act_sg = sg;

    if ((mgr->activated_cb != NULL) && (sg != prev)) {
        mgr->activated_cb(mgr->activated_user, sg, prev);
    }
    return 0;
}

/* --- bridge helpers ------------------------------------------------ */

/* SGCB attributes follow the IEC 61850-8-1 MMS mapping observed on
 * the reference stack (libiec61850 server_example_setting_groups,
 * black-box wire probe): the SGCB is a component object of LLN0
 * under FC SP, i.e. "LLN0$SP$SGCB$<attr>". The pre-review code
 * used the non-conformant "LLN0$SG$<attr>" — a real client could
 * not discover the SGCB. */
#define SGCB_PREFIX "LLN0$SP$SGCB$"

static int is_sgcb_attr(const char *item, const char *attr)
{
    return (strncmp(item, SGCB_PREFIX, sizeof(SGCB_PREFIX) - 1U) == 0) &&
           (strcmp(item + sizeof(SGCB_PREFIX) - 1U, attr) == 0);
}

/* Translate a "$SG$" read view ("<LN>$SG$<path>", the read-only
 * active-group values per 7-2) into the registered "$SE$" item
 * name. Only the FIRST separator is replaced — it follows the LN
 * name, which cannot contain '$'. */
static int sg_to_se_item(const char *item, char *out, size_t outsz)
{
    const char *sep = strstr(item, "$SG$");
    if ((sep == NULL) || (sep == item)) {
        return -1;
    }
    int n = snprintf(out, outsz, "%.*s$SE$%s", (int)(sep - item), item,
                     sep + 4U);
    return ((n < 0) || ((size_t)n >= outsz)) ? -1 : 0;
}

static int find_entry(const iec61850_sg_manager_t *mgr,
                      const char *domain, const char *item)
{
    for (size_t e = 0; e < mgr->entry_count; e++) {
        if ((strcmp(mgr->entries[e].ld, domain) == 0) &&
            (strcmp(mgr->entries[e].item, item) == 0)) {
            return (int)e;
        }
    }
    return -1;
}

static int value_is_unsigned(const mms_value_t *v)
{
    return (v != NULL) && (v->type == MMS_TYPE_UNSIGNED);
}

int iec61850_sg_bridge_write(iec61850_sg_manager_t *mgr,
                             const char *domain, const char *item,
                             const mms_value_t *value,
                             void *association)
{
    if ((mgr == NULL) || (domain == NULL) || (item == NULL) ||
        (value == NULL)) {
        return -ENOENT;
    }

    /* SGCB attributes. */
    if (is_sgcb_attr(item, "ActSG")) {
        if (!value_is_unsigned(value)) {
            return -EINVAL;
        }
        uint32_t sg = value->value.unsigned_val;
        if ((sg < 1U) || (sg > mgr->num_of_sg)) {
            return -EINVAL;
        }
        return iec61850_sg_activate(mgr, (uint8_t)sg);
    }

    if (is_sgcb_attr(item, "EditSG")) {
        if (!value_is_unsigned(value)) {
            return -EINVAL;
        }
        uint32_t sg = value->value.unsigned_val;
        if (sg == 0U) {
            /* Release: only the owner may release. */
            if ((mgr->edit_sg != 0U) && (mgr->edit_owner != NULL) &&
                (mgr->edit_owner != association)) {
                return -EPERM;
            }
            mgr->edit_sg = 0;
            mgr->resv_deadline_ms = 0;
            mgr->edit_owner = NULL;
            return 0;
        }
        if (sg > mgr->num_of_sg) {
            return -EINVAL;
        }
        if ((mgr->edit_sg != 0U) && (mgr->edit_owner != NULL) &&
            (mgr->edit_owner != association)) {
            return -EPERM;
        }
        mgr->edit_sg = (uint8_t)sg;
        mgr->edit_owner = association;
        /* Reservation clock starts now; the tick releases it. */
        mgr->resv_deadline_ms = 1U; /* set by first tick after start */
        return 0;
    }

    /* Setting-group values ($SE$). */
    int e = find_entry(mgr, domain, item);
    if (e < 0) {
        return -ENOENT;
    }

    if (mgr->edit_sg == 0U) {
        return -EAGAIN;
    }
    if ((mgr->edit_owner != NULL) && (association != NULL) &&
        (mgr->edit_owner != association)) {
        return -EPERM;
    }
    /* Type must match the live attribute's btype. */
    if (value->type != mgr->entries[e].live->value.type) {
        return -EINVAL;
    }
    mgr->entries[e].groups[mgr->edit_sg - 1U] = *value;
    return 0;
}

int iec61850_sg_bridge_read(iec61850_sg_manager_t *mgr,
                            const char *domain, const char *item,
                            mms_value_t *value)
{
    if ((mgr == NULL) || (domain == NULL) || (item == NULL) ||
        (value == NULL)) {
        return -ENOENT;
    }

    mms_value_t v;
    (void)memset(&v, 0, sizeof(v));
    v.type = MMS_TYPE_UNSIGNED;

    if (is_sgcb_attr(item, "NumOfSG")) {
        v.value.unsigned_val = mgr->num_of_sg;
        *value = v;
        return 0;
    }
    if (is_sgcb_attr(item, "ActSG")) {
        v.value.unsigned_val = mgr->act_sg;
        *value = v;
        return 0;
    }
    if (is_sgcb_attr(item, "EditSG")) {
        v.value.unsigned_val = mgr->edit_sg;
        *value = v;
        return 0;
    }
    if (is_sgcb_attr(item, "ResvTms")) {
        v.value.unsigned_val =
            (mgr->edit_sg != 0U) ? mgr->resv_tms_s : 0U;
        *value = v;
        return 0;
    }

    /* "$SG$" view: read-only values of the ACTIVE group (7-2). */
    char translated[IEC61850_SG_MAX_ITEM_LEN];
    if (sg_to_se_item(item, translated, sizeof(translated)) == 0) {
        int e = find_entry(mgr, domain, translated);
        if (e < 0) {
            return -ENOENT;
        }
        *value = mgr->entries[e].groups[mgr->act_sg - 1U];
        return 0;
    }

    int e = find_entry(mgr, domain, item);
    if (e < 0) {
        return -ENOENT;
    }
    /* SE values are the EDIT-session view: without a selected edit
     * group they are not visible (matches the reference stack — SE
     * reads outside an edit session come back as object errors).
     * Fall through so the store produces the error. */
    if (mgr->edit_sg == 0U) {
        return -ENOENT;
    }
    *value = mgr->entries[e].groups[mgr->edit_sg - 1U];
    return 0;
}

void iec61850_sg_tick(iec61850_sg_manager_t *mgr, uint64_t now_ms)
{
    if (mgr == NULL) {
        return;
    }
    if (mgr->resv_deadline_ms == 1U) {
        /* First tick after selection: start the countdown. */
        uint64_t tms_ms = (uint64_t)mgr->resv_tms_s * 1000ULL;
        mgr->resv_deadline_ms = now_ms + tms_ms;
        return;
    }
    if ((mgr->edit_sg != 0U) && (mgr->resv_deadline_ms != 0U) &&
        (now_ms >= mgr->resv_deadline_ms)) {
        mgr->edit_sg = 0;
        mgr->resv_deadline_ms = 0;
        mgr->edit_owner = NULL;
    }
}

void iec61850_sg_release_owner(iec61850_sg_manager_t *mgr,
                               void *association)
{
    if ((mgr != NULL) && (mgr->edit_owner == association)) {
        mgr->edit_sg = 0;
        mgr->resv_deadline_ms = 0;
        mgr->edit_owner = NULL;
    }
}

uint8_t iec61850_sg_get_num_of_sg(const iec61850_sg_manager_t *mgr)
{
    return (mgr != NULL) ? mgr->num_of_sg : 0U;
}

uint8_t iec61850_sg_get_active(const iec61850_sg_manager_t *mgr)
{
    return (mgr != NULL) ? mgr->act_sg : 0U;
}

uint8_t iec61850_sg_get_edit(const iec61850_sg_manager_t *mgr)
{
    return (mgr != NULL) ? mgr->edit_sg : 0U;
}
