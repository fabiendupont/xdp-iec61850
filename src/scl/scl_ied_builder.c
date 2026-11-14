/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * SCL-to-IED Model Builder
 *
 * Builds complete IED data model from parsed SCL document.
 *
 * WP-6e: when the SCL document carries DataTypeTemplates, Logical
 * Nodes are constructed from their LNodeType/DOType/DAType chains
 * (including SDO sub-data-objects and Struct DA expansion). The
 * class-name based standard population below remains as fallback
 * for documents without templates.
 *
 * WP-6f: SCL-driven auto-configuration of model-bound GOOSE/SV
 * publishers (iec61850_scl_configure_publishers) — dataset FCDAs
 * feed the model binding, mirroring the RCB auto-configuration.
 *
 * License: BSD-2-Clause
 */

#include "scl/scl_ied_builder.h"
#include "mms/mms_report.h"
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <strings.h>

/* ======================================================================
 * Template-driven construction (WP-6e)
 *
 * Nested template structures are flattened into dotted leaf
 * attribute names ("phsA.cVal.mag.f"), matching the convention of
 * the CDC factories in ied_data_model.c and the path walker in
 * iec61850_ln_find_attribute().
 * ====================================================================== */

/* Sentinel CDC value for template cdc strings outside the compiled
 * iec61850_cdc_t enum (iec61850_cdc_to_string reports "UNKNOWN"). */
#define SCL_CDC_UNMAPPED ((iec61850_cdc_t)0xFF)

/* Maximum SDO/Struct nesting depth: cycle guard for malformed
 * templates (a DAType whose BDA chain loops back on itself). */
#define SCL_TEMPLATE_MAX_DEPTH 8U

static iec61850_cdc_t scl_cdc_from_string(const char *cdc)
{
    if (cdc == NULL) { return SCL_CDC_UNMAPPED; }
    if (strcasecmp(cdc, "SPS") == 0)  { return IEC61850_CDC_SPS; }
    if (strcasecmp(cdc, "DPS") == 0)  { return IEC61850_CDC_DPS; }
    if (strcasecmp(cdc, "INS") == 0)  { return IEC61850_CDC_INS; }
    if (strcasecmp(cdc, "ENS") == 0)  { return IEC61850_CDC_ENS; }
    if (strcasecmp(cdc, "ACT") == 0)  { return IEC61850_CDC_ACT; }
    if (strcasecmp(cdc, "ACD") == 0)  { return IEC61850_CDC_ACD; }
    if (strcasecmp(cdc, "SEC") == 0)  { return IEC61850_CDC_SEC; }
    if (strcasecmp(cdc, "BSC") == 0)  { return IEC61850_CDC_BSC; }
    if (strcasecmp(cdc, "SPC") == 0)  { return IEC61850_CDC_SPC; }
    if (strcasecmp(cdc, "DPC") == 0)  { return IEC61850_CDC_DPC; }
    if (strcasecmp(cdc, "INC") == 0)  { return IEC61850_CDC_INC; }
    if (strcasecmp(cdc, "MV") == 0)   { return IEC61850_CDC_MV; }
    if (strcasecmp(cdc, "CMV") == 0)  { return IEC61850_CDC_CMV; }
    if (strcasecmp(cdc, "SAV") == 0)  { return IEC61850_CDC_SAV; }
    if (strcasecmp(cdc, "WYE") == 0)  { return IEC61850_CDC_WYE; }
    if (strcasecmp(cdc, "DEL") == 0)  { return IEC61850_CDC_DEL; }
    if (strcasecmp(cdc, "SPG") == 0)  { return IEC61850_CDC_SPG; }
    if (strcasecmp(cdc, "ASG") == 0)  { return IEC61850_CDC_ASG; }
    if (strcasecmp(cdc, "VSS") == 0)  { return IEC61850_CDC_VSS; }
    if (strcasecmp(cdc, "LPL") == 0)  { return IEC61850_CDC_LPL; }
    if (strcasecmp(cdc, "DPL") == 0)  { return IEC61850_CDC_DPL; }
    if (strcasecmp(cdc, "BCR") == 0)  { return IEC61850_CDC_BCR; }
    if (strcasecmp(cdc, "MX3") == 0)  { return IEC61850_CDC_MX3; }
    if (strcasecmp(cdc, "DEL3") == 0) { return IEC61850_CDC_DEL3; }
    if (strcasecmp(cdc, "APC") == 0)  { return IEC61850_CDC_APC; }
    if (strcasecmp(cdc, "ENC") == 0)  { return IEC61850_CDC_ENC; }
    if (strcasecmp(cdc, "ISC") == 0)  { return IEC61850_CDC_ISC; }
    if (strcasecmp(cdc, "CURS") == 0) { return IEC61850_CDC_CURS; }
    if (strcasecmp(cdc, "CSD") == 0)  { return IEC61850_CDC_CSD; }
    if (strcasecmp(cdc, "SEQ") == 0)  { return IEC61850_CDC_SEQ; }
    if (strcasecmp(cdc, "HMV") == 0)  { return IEC61850_CDC_HMV; }
    if (strcasecmp(cdc, "HWYE") == 0) { return IEC61850_CDC_HWYE; }
    if (strcasecmp(cdc, "HDEL") == 0) { return IEC61850_CDC_HDEL; }
    return SCL_CDC_UNMAPPED;
}

static iec61850_btype_t scl_btype_from_string(const char *btype)
{
    if (btype == NULL) { return IEC61850_BTYPE_VISIBLE_STRING; }
    if (strcasecmp(btype, "BOOLEAN") == 0)     { return IEC61850_BTYPE_BOOLEAN; }
    if (strcasecmp(btype, "INT8") == 0)        { return IEC61850_BTYPE_INT8; }
    if (strcasecmp(btype, "INT16") == 0)       { return IEC61850_BTYPE_INT16; }
    if (strcasecmp(btype, "INT32") == 0)       { return IEC61850_BTYPE_INT32; }
    if (strcasecmp(btype, "INT64") == 0)       { return IEC61850_BTYPE_INT64; }
    if (strcasecmp(btype, "INT128") == 0)      { return IEC61850_BTYPE_INT128; }
    if (strcasecmp(btype, "INT8U") == 0)       { return IEC61850_BTYPE_INT8U; }
    if (strcasecmp(btype, "INT16U") == 0)      { return IEC61850_BTYPE_INT16U; }
    if (strcasecmp(btype, "INT32U") == 0)      { return IEC61850_BTYPE_INT32U; }
    if (strcasecmp(btype, "FLOAT32") == 0)     { return IEC61850_BTYPE_FLOAT32; }
    if (strcasecmp(btype, "FLOAT64") == 0)     { return IEC61850_BTYPE_FLOAT64; }
    if (strcasecmp(btype, "Enum") == 0)        { return IEC61850_BTYPE_ENUMERATED; }
    if (strcasecmp(btype, "Dbpos") == 0)       { return IEC61850_BTYPE_DBPOS; }
    if (strcasecmp(btype, "Quality") == 0)     { return IEC61850_BTYPE_QUALITY; }
    if (strcasecmp(btype, "Timestamp") == 0)   { return IEC61850_BTYPE_TIMESTAMP; }
    if (strcasecmp(btype, "Check") == 0)       { return IEC61850_BTYPE_CHECK; }
    if (strcasecmp(btype, "EntryTime") == 0)   { return IEC61850_BTYPE_ENTRY_TIME; }
    if (strcasecmp(btype, "PhyComAddr") == 0)  { return IEC61850_BTYPE_PHYS_COMM_ADDR; }
    if (strcasecmp(btype, "Currency") == 0)    { return IEC61850_BTYPE_CURRENCY; }
    if (strcasecmp(btype, "Struct") == 0)      { return IEC61850_BTYPE_STRUCT; }
    if (strncasecmp(btype, "VisString", 9) == 0) {
        return IEC61850_BTYPE_VISIBLE_STRING;
    }
    if (strncasecmp(btype, "Unicode", 7) == 0) {
        return IEC61850_BTYPE_UNICODE_STRING;
    }
    if (strncasecmp(btype, "Octet", 5) == 0) {
        return IEC61850_BTYPE_OCTET_STRING;
    }
    return IEC61850_BTYPE_VISIBLE_STRING;
}

/*
 * Add the leaf attributes of one DA/BDA descriptor. Struct entries
 * are expanded through their DAType (BDAs inherit the functional
 * constraint of the enclosing DA). Unresolvable or oversized
 * subtree entries are skipped gracefully.
 */
static void add_da_leaves(iec61850_data_object_t *dobj,
                           const iec61850_scl_doc_t *doc,
                           const char *prefix,
                           const iec61850_scl_da_t *da,
                           const char *inherited_fc,
                           unsigned depth)
{
    char name[IEC61850_MAX_NAME_LEN * 2];

    if (depth > SCL_TEMPLATE_MAX_DEPTH) { return; }

    int n = snprintf(name, sizeof(name), "%s%s", prefix, da->name);
    if ((n < 0) || ((size_t)n >= sizeof(name))) {
        return;  /* flattened path does not fit: skip leaf */
    }

    if (strcasecmp(da->btype, "Struct") == 0) {
        const iec61850_scl_da_type_t *dat =
            iec61850_scl_find_da_type(doc, da->type);
        if (dat == NULL) { return; }

        char sub_prefix[IEC61850_MAX_NAME_LEN * 2];
        int m = snprintf(sub_prefix, sizeof(sub_prefix), "%s.", name);
        if ((m < 0) || ((size_t)m >= sizeof(sub_prefix))) { return; }

        const char *fc = (da->fc[0] != '\0') ? da->fc : inherited_fc;
        for (size_t i = 0; i < dat->bda_count; i++) {
            add_da_leaves(dobj, doc, sub_prefix, &dat->bdas[i], fc,
                           depth + 1U);
        }
        return;
    }

    const char *fc = (da->fc[0] != '\0') ? da->fc : inherited_fc;
    (void)iec61850_do_add_attribute(dobj, name,
                                     iec61850_string_to_fc(fc),
                                     scl_btype_from_string(da->btype));
}

/*
 * Add all leaf attributes of a DOType into dobj, prefixing nested
 * SDO names (flattened dotted paths).
 */
static void add_do_type_attrs(iec61850_data_object_t *dobj,
                               const iec61850_scl_doc_t *doc,
                               const char *prefix,
                               const iec61850_scl_do_type_t *dt,
                               unsigned depth)
{
    if (depth > SCL_TEMPLATE_MAX_DEPTH) { return; }

    for (size_t i = 0; i < dt->da_count; i++) {
        const iec61850_scl_da_t *entry = &dt->das[i];

        char child_prefix[IEC61850_MAX_NAME_LEN * 2];
        int n = snprintf(child_prefix, sizeof(child_prefix), "%s%s.",
                          prefix, entry->name);
        if ((n < 0) || ((size_t)n >= sizeof(child_prefix))) {
            continue;  /* flattened path does not fit: skip subtree */
        }

        if (entry->is_sdo) {
            const iec61850_scl_do_type_t *sub_dt =
                iec61850_scl_find_do_type(doc, entry->type);
            if (sub_dt == NULL) { continue; }
            add_do_type_attrs(dobj, doc, child_prefix, sub_dt, depth + 1U);
        } else {
            add_da_leaves(dobj, doc, prefix, entry, NULL, depth + 1U);
        }
    }
}

/*
 * Build a DataObject from a DOType template. Returns NULL when no
 * leaf attribute could be derived (caller falls back).
 */
static iec61850_data_object_t *build_do_from_type(
    const iec61850_scl_doc_t *doc,
    const char *do_name,
    const iec61850_scl_do_type_t *dt)
{
    iec61850_data_object_t *dobj =
        iec61850_do_create(do_name, scl_cdc_from_string(dt->cdc));
    if (dobj == NULL) { return NULL; }

    add_do_type_attrs(dobj, doc, "", dt, 0U);

    if (dobj->attr_count == 0) {
        iec61850_do_destroy(dobj);
        return NULL;
    }
    return dobj;
}

/* Create standard data objects for known LN classes (IEC 61850-7-4).
 * Fallback for LNs whose lnType has no resolvable LNodeType. */
static void populate_ln_with_standard_dos(iec61850_logical_node_t *ln,
                                             const char *ln_class)
{
    iec61850_data_object_t *dobj;

    if (strcmp(ln_class, "LLN0") == 0) {
        /* Logical Node Zero: Health, Beh, Mod, NamPlt */
        dobj = iec61850_cdc_create_ins("Beh");
        if (dobj != NULL) { (void)iec61850_ln_add_data_object(ln, dobj); }
        dobj = iec61850_cdc_create_ins("Health");
        if (dobj != NULL) { (void)iec61850_ln_add_data_object(ln, dobj); }
        dobj = iec61850_cdc_create_ins("Mod");
        if (dobj != NULL) { (void)iec61850_ln_add_data_object(ln, dobj); }
    } else if (strcmp(ln_class, "LPHD") == 0) {
        /* Physical Device: PhyHealth, PhyNam, Proxy */
        dobj = iec61850_cdc_create_ins("PhyHealth");
        if (dobj != NULL) { (void)iec61850_ln_add_data_object(ln, dobj); }
        dobj = iec61850_cdc_create_sps("Proxy");
        if (dobj != NULL) { (void)iec61850_ln_add_data_object(ln, dobj); }
    } else if (strcmp(ln_class, "XCBR") == 0) {
        /* Circuit Breaker */
        dobj = iec61850_cdc_create_dpc("Pos");
        if (dobj != NULL) { (void)iec61850_ln_add_data_object(ln, dobj); }
        dobj = iec61850_cdc_create_sps("BlkOpn");
        if (dobj != NULL) { (void)iec61850_ln_add_data_object(ln, dobj); }
        dobj = iec61850_cdc_create_sps("BlkCls");
        if (dobj != NULL) { (void)iec61850_ln_add_data_object(ln, dobj); }
        dobj = iec61850_cdc_create_ins("Beh");
        if (dobj != NULL) { (void)iec61850_ln_add_data_object(ln, dobj); }
    } else if ((strcmp(ln_class, "XSWI") == 0) || (strcmp(ln_class, "CSWI") == 0)) {
        /* Disconnector / Switch Controller */
        dobj = iec61850_cdc_create_dpc("Pos");
        if (dobj != NULL) { (void)iec61850_ln_add_data_object(ln, dobj); }
        dobj = iec61850_cdc_create_ins("Beh");
        if (dobj != NULL) { (void)iec61850_ln_add_data_object(ln, dobj); }
    } else if (strcmp(ln_class, "MMXU") == 0) {
        /* Measurement */
        dobj = iec61850_cdc_create_mv("TotW");
        if (dobj != NULL) { (void)iec61850_ln_add_data_object(ln, dobj); }
        dobj = iec61850_cdc_create_mv("TotVAr");
        if (dobj != NULL) { (void)iec61850_ln_add_data_object(ln, dobj); }
        dobj = iec61850_cdc_create_mv("TotVA");
        if (dobj != NULL) { (void)iec61850_ln_add_data_object(ln, dobj); }
        dobj = iec61850_cdc_create_mv("Hz");
        if (dobj != NULL) { (void)iec61850_ln_add_data_object(ln, dobj); }
    } else if (strcmp(ln_class, "PTOC") == 0) {
        /* Overcurrent Protection */
        dobj = iec61850_cdc_create_spc("Op");
        if (dobj != NULL) { (void)iec61850_ln_add_data_object(ln, dobj); }
        dobj = iec61850_cdc_create_sps("Str");
        if (dobj != NULL) { (void)iec61850_ln_add_data_object(ln, dobj); }
        dobj = iec61850_cdc_create_ins("Beh");
        if (dobj != NULL) { (void)iec61850_ln_add_data_object(ln, dobj); }
    } else if (strcmp(ln_class, "GGIO") == 0) {
        /* Generic I/O */
        dobj = iec61850_cdc_create_sps("Ind1");
        if (dobj != NULL) { (void)iec61850_ln_add_data_object(ln, dobj); }
        dobj = iec61850_cdc_create_sps("Ind2");
        if (dobj != NULL) { (void)iec61850_ln_add_data_object(ln, dobj); }
        dobj = iec61850_cdc_create_spc("SPCSO1");
        if (dobj != NULL) { (void)iec61850_ln_add_data_object(ln, dobj); }
    }
    /* Unknown LN classes get no pre-populated DOs */
}

int iec61850_scl_build_ied_model(const iec61850_scl_doc_t *doc,
                                   iec61850_ied_model_t *model)
{
    if ((doc == NULL) || (model == NULL)) {
        return -EINVAL;
    }

    iec61850_ied_model_init(model, doc->ied_name);

    /* Create LogicalDevices and LogicalNodes from SCL */
    for (size_t i = 0; i < doc->ld_count; i++) {
        const iec61850_scl_ld_t *scl_ld = &doc->lds[i];

        iec61850_logical_device_t *ld = iec61850_ld_create(scl_ld->inst);
        if (ld == NULL) {
            continue;
        }

        for (size_t j = 0; j < scl_ld->ln_count; j++) {
            const iec61850_scl_ln_ref_t *scl_ln = &scl_ld->lns[j];

            /* Build LN name: prefix + lnClass + inst */
            char ln_name[IEC61850_MAX_NAME_LEN];
            ln_name[0] = '\0';
            (void)strncat(ln_name, scl_ln->ln_prefix, sizeof(ln_name) - strlen(ln_name) - 1U);
            (void)strncat(ln_name, scl_ln->ln_class,
                          sizeof(ln_name) - strlen(ln_name) - 1U);
            (void)strncat(ln_name, scl_ln->ln_inst,
                          sizeof(ln_name) - strlen(ln_name) - 1U);

            iec61850_logical_node_t *ln = iec61850_ln_create(scl_ln->ln_class,
                                                                ln_name);
            if (ln == NULL) {
                continue;
            }

            /* Template-driven population: walk the LNodeType ->
             * DOType chains when the templates resolve. */
            const iec61850_scl_lnode_type_t *lt =
                iec61850_scl_find_lnode_type(doc, scl_ln->ln_type);
            bool built_from_templates = false;

            if ((lt != NULL) && (lt->do_count > 0)) {
                for (size_t k = 0; k < lt->do_count; k++) {
                    const iec61850_scl_do_type_t *dt =
                        iec61850_scl_find_do_type(doc, lt->dos[k].type);
                    if (dt == NULL) { continue; }

                    iec61850_data_object_t *dobj =
                        build_do_from_type(doc, lt->dos[k].name, dt);
                    if (dobj == NULL) { continue; }

                    if (iec61850_ln_add_data_object(ln, dobj) == 0) {
                        built_from_templates = true;
                    } else {
                        iec61850_do_destroy(dobj);
                    }
                }
            }

            if (!built_from_templates) {
                /* Fallback: standard CDC data objects for known
                 * LN classes */
                populate_ln_with_standard_dos(ln, scl_ln->ln_class);
            }

            (void)iec61850_ld_add_logical_node(ld, ln);
        }

        (void)iec61850_ied_model_add_ld(model, ld);
    }

    return 0;
}

/* Map IEC 61850 BasicType to MMS type */
static mms_type_t btype_to_mms_type(iec61850_btype_t btype)
{
    switch (btype) {
        case IEC61850_BTYPE_BOOLEAN:        return MMS_TYPE_BOOLEAN;
        case IEC61850_BTYPE_INT8:
        case IEC61850_BTYPE_INT16:
        case IEC61850_BTYPE_INT32:
        case IEC61850_BTYPE_INT64:
        case IEC61850_BTYPE_INT128:         return MMS_TYPE_INTEGER;
        case IEC61850_BTYPE_INT8U:
        case IEC61850_BTYPE_INT16U:
        case IEC61850_BTYPE_INT32U:         return MMS_TYPE_UNSIGNED;
        case IEC61850_BTYPE_FLOAT32:
        case IEC61850_BTYPE_FLOAT64:        return MMS_TYPE_FLOATING_POINT;
        case IEC61850_BTYPE_ENUMERATED:
        case IEC61850_BTYPE_CODED_ENUM:     return MMS_TYPE_INTEGER;
        case IEC61850_BTYPE_OCTET_STRING:   return MMS_TYPE_OCTET_STRING;
        case IEC61850_BTYPE_VISIBLE_STRING:
        case IEC61850_BTYPE_UNICODE_STRING: return MMS_TYPE_VISIBLE_STRING;
        case IEC61850_BTYPE_TIMESTAMP:      return MMS_TYPE_UTC_TIME;
        case IEC61850_BTYPE_QUALITY:
        case IEC61850_BTYPE_CHECK:          return MMS_TYPE_BIT_STRING;
        case IEC61850_BTYPE_ENTRY_TIME:     return MMS_TYPE_BINARY_TIME;
        case IEC61850_BTYPE_DBPOS:          return MMS_TYPE_BIT_STRING;
        case IEC61850_BTYPE_STRUCT:         return MMS_TYPE_STRUCTURE;
        case IEC61850_BTYPE_PHYS_COMM_ADDR: return MMS_TYPE_OCTET_STRING;
        default:                            return MMS_TYPE_VISIBLE_STRING;
    }
}

/* Append one name component to a '$'-separated MMS variable name,
 * translating '.' separators (flattened template paths) to '$'.
 * Returns 0, or -1 when the buffer is exhausted. */
static int append_component(char *buf, size_t buf_size, size_t *pos,
                              const char *comp)
{
    for (const char *p = comp; *p != '\0'; p++) {
        if (*pos >= (buf_size - 1U)) { return -1; }
        buf[*pos] = (*p == '.') ? '$' : *p;
        (*pos)++;
    }
    return 0;
}

static int append_sep(char *buf, size_t buf_size, size_t *pos)
{
    if (*pos >= (buf_size - 1U)) { return -1; }
    buf[*pos] = '$';
    (*pos)++;
    return 0;
}

/* Register all DAs of a DO as MMS variables.
 * var_prefix is the dotted DO path ("Pos" or "Pos.sub"): components
 * are emitted with the IEC 61850-8-1 '$' separator. */
static int register_do_variables(const iec61850_data_object_t *dobj,
                                   const char *ln_name, /* NOLINT(bugprone-easily-swappable-parameters) */
                                   const char *domain,
                                   iec61850_mms_data_store_t *data_store)
{
    int registered = 0;

    for (size_t i = 0; i < dobj->attr_count; i++) {
        const iec61850_data_attribute_t *da = &dobj->attributes[i];
        if (!da->valid) { continue; }

        const char *fc_str = iec61850_fc_to_string(da->fc);

        /* Build MMS variable name: LN$FC$DO[$SDO]*$DA[$BDA]* */
        char var_name[MMS_MAX_VARIABLE_NAME];
        size_t pos = 0;
        if ((append_component(var_name, sizeof(var_name), &pos, ln_name) == 0) &&
            (append_sep(var_name, sizeof(var_name), &pos) == 0) &&
            (append_component(var_name, sizeof(var_name), &pos, fc_str) == 0) &&
            (append_sep(var_name, sizeof(var_name), &pos) == 0) &&
            (append_component(var_name, sizeof(var_name), &pos, dobj->name) == 0) &&
            (append_sep(var_name, sizeof(var_name), &pos) == 0) &&
            (append_component(var_name, sizeof(var_name), &pos, da->name) == 0)) {
            var_name[pos] = '\0';

            mms_type_t mms_type = btype_to_mms_type(da->btype);
            int ret = iec61850_mms_ds_create_variable(
                data_store, domain, var_name, mms_type, &da->value);
            if (ret == (int)IEC61850_MMS_DS_OK) {
                registered++;
            }
        }
    }

    /* Recurse into sub-data-objects */
    for (size_t i = 0; i < dobj->sub_count; i++) {
        const iec61850_data_object_t *sub = dobj->sub_objects[i];
        if ((sub == NULL) || (!sub->valid)) { continue; }

        char sub_path[IEC61850_MAX_NAME_LEN * 2];
        int n = snprintf(sub_path, sizeof(sub_path), "%s.%s",
                          dobj->name, sub->name);
        if ((n < 0) || ((size_t)n >= sizeof(sub_path))) { continue; }

        /* Present the sub-object under its full dotted path by
         * registering its attributes directly. */
        for (size_t j = 0; j < sub->attr_count; j++) {
            const iec61850_data_attribute_t *da = &sub->attributes[j];
            if (!da->valid) { continue; }

            const char *fc_str = iec61850_fc_to_string(da->fc);

            char var_name[MMS_MAX_VARIABLE_NAME];
            size_t pos = 0;
            if ((append_component(var_name, sizeof(var_name), &pos, ln_name) == 0) &&
                (append_sep(var_name, sizeof(var_name), &pos) == 0) &&
                (append_component(var_name, sizeof(var_name), &pos, fc_str) == 0) &&
                (append_sep(var_name, sizeof(var_name), &pos) == 0) &&
                (append_component(var_name, sizeof(var_name), &pos, sub_path) == 0) &&
                (append_sep(var_name, sizeof(var_name), &pos) == 0) &&
                (append_component(var_name, sizeof(var_name), &pos, da->name) == 0)) {
                var_name[pos] = '\0';

                mms_type_t mms_type = btype_to_mms_type(da->btype);
                int ret = iec61850_mms_ds_create_variable(
                    data_store, domain, var_name, mms_type, &da->value);
                if (ret == (int)IEC61850_MMS_DS_OK) {
                    registered++;
                }
            }
        }
    }

    return registered;
}

int iec61850_ied_model_register_mms(const iec61850_ied_model_t *model,
                                      iec61850_mms_data_store_t *data_store)
{
    int total = 0;

    if ((model == NULL) || (data_store == NULL)) {
        return -EINVAL;
    }

    for (size_t i = 0; i < model->ld_count; i++) {
        const iec61850_logical_device_t *ld = model->logical_devices[i];
        if ((ld == NULL) || (!ld->valid)) { continue; }

        /* Domain name: IEDName + LDInst */
        char domain[MMS_MAX_DOMAIN_NAME];
        (void)snprintf(domain, sizeof(domain), "%s%s",
                        model->ied_name, ld->ld_inst);

        int ret = iec61850_mms_ds_create_domain(data_store, domain);
        if ((ret != (int)IEC61850_MMS_DS_OK) && (ret != (int)IEC61850_MMS_DS_ERR_EXISTS)) {
            continue;
        }

        for (size_t j = 0; j < ld->ln_count; j++) {
            const iec61850_logical_node_t *ln = ld->logical_nodes[j];
            if ((ln == NULL) || (!ln->valid)) { continue; }

            /* LN name: lnClass + inst (already combined in ln_inst) */
            const char *ln_name = ln->ln_inst;

            for (size_t k = 0; k < ln->do_count; k++) {
                const iec61850_data_object_t *dobj = ln->data_objects[k];
                if ((dobj == NULL) || (!dobj->valid)) { continue; }

                int reg = register_do_variables(dobj, ln_name, domain,
                                                 data_store);
                if (reg > 0) {
                    total += reg;
                }
            }
        }
    }

    return total;
}

int iec61850_scl_auto_configure_rcbs(const iec61850_scl_doc_t *doc,
                                       void *mgr_ptr)
{
    /* MISRA 11.5: opaque mgr_ptr handle, deviation Cat. 3 */
    iec61850_rcb_manager_t *mgr = (iec61850_rcb_manager_t *)mgr_ptr;
    int configured = 0;

    if ((doc == NULL) || (mgr == NULL)) {
        return -EINVAL;
    }

    for (size_t i = 0; i < doc->rcb_count; i++) {
        const iec61850_scl_rcb_t *scl_rcb = &doc->rcbs[i];

        iec61850_rcb_type_t type = scl_rcb->buffered ?
            IEC61850_RCB_BUFFERED : IEC61850_RCB_UNBUFFERED;

        uint32_t buf_size = 0;
        if (type == IEC61850_RCB_BUFFERED) {
            buf_size = IEC61850_RCB_MAX_BUFFER;
        }

        int idx = iec61850_rcb_manager_add_rcb(mgr, scl_rcb->rpt_id,
                                                 type, buf_size);
        if (idx < 0) {
            continue;
        }

        iec61850_rcb_t *rcb = &mgr->rcbs[idx];

        /* Set trigger options from SCL */
        rcb->attrs.trg_ops.data_change = scl_rcb->trg_dchg;
        rcb->attrs.trg_ops.quality_change = scl_rcb->trg_qchg;
        rcb->attrs.trg_ops.data_update = scl_rcb->trg_dupd;
        rcb->attrs.trg_ops.integrity = scl_rcb->trg_period;
        rcb->attrs.trg_ops.general_interrogation = scl_rcb->trg_gi;

        /* Set optional fields from SCL */
        rcb->attrs.opt_flds.sequence_number = scl_rcb->opt_seq_num;
        rcb->attrs.opt_flds.report_timestamp = scl_rcb->opt_timestamp;
        rcb->attrs.opt_flds.reason_for_inclusion = scl_rcb->opt_reason;
        rcb->attrs.opt_flds.data_reference = scl_rcb->opt_dataref;
        rcb->attrs.opt_flds.entry_id = scl_rcb->opt_entryid;
        rcb->attrs.opt_flds.buffer_overflow = scl_rcb->opt_bufovfl;
        rcb->attrs.opt_flds.config_ref = scl_rcb->opt_configref;

        /* Set timing from SCL */
        rcb->attrs.buf_tm = scl_rcb->buf_time;
        rcb->attrs.intg_pd = scl_rcb->intg_pd;

        /* Set dataset name */
        (void)strncpy(rcb->attrs.dat_set, scl_rcb->dataset,
                       IEC61850_RCB_MAX_NAME - 1);

        configured++;
    }

    return configured;
}

/* ======================================================================
 * SCL-driven publisher auto-configuration (WP-6f)
 *
 * For every GSEControl/SampledValueControl of the parsed IED:
 * resolve the dataset FCDAs into iec61850_da_ref_t lists (expanding
 * whole-DO/SDO FCDAs against the built model's flattened leaf
 * attributes), prepare the publisher configuration from the SCL
 * Communication address, create the publisher through the caller's
 * callback, and bind it into the model binding. Mirrors the RCB
 * auto-config's skip tolerance: one bad control block never fails
 * the call; the result summary counts configured and skipped.
 * ====================================================================== */

/* Accumulator for the dataset-to-reference expansion of one control
 * block. ld/ln/do_name come from the resolved FCDA identity; prefix
 * restricts whole-SDO expansion to one sub-data-object path. */
typedef struct {
    char ld[IEC61850_MAX_NAME_LEN];
    char ln[IEC61850_MAX_NAME_LEN];
    char do_name[IEC61850_MAX_NAME_LEN];
    char prefix[IEC61850_MAX_NAME_LEN];
    size_t prefix_len;
    iec61850_fc_t fc;
    bool is_sv;   /* SV: filter leaves without a sample/quality map */
    iec61850_da_ref_t *refs;
    uint32_t count;
    uint32_t capacity;
} scl_ref_builder_t;

/* Whether a leaf DA of this basic type can occupy an SV channel
 * (sample or quality), mirroring the binding's SV type rules. */
static bool scl_sv_leaf_mappable(iec61850_btype_t btype)
{
    switch (btype) {
        case IEC61850_BTYPE_BOOLEAN:
        case IEC61850_BTYPE_INT8:
        case IEC61850_BTYPE_INT8U:
        case IEC61850_BTYPE_INT16:
        case IEC61850_BTYPE_INT16U:
        case IEC61850_BTYPE_INT32:
        case IEC61850_BTYPE_INT32U:
        case IEC61850_BTYPE_INT64:
        case IEC61850_BTYPE_INT128:
        case IEC61850_BTYPE_FLOAT32:
        case IEC61850_BTYPE_FLOAT64:
        case IEC61850_BTYPE_ENUMERATED:
        case IEC61850_BTYPE_CODED_ENUM:
        case IEC61850_BTYPE_QUALITY:
            return true;
        default:
            return false;
    }
}

/* Bounded copy into a fixed-size name field. Returns 0, or
 * -ENAMETOOLONG when src does not fit. */
static int scl_copy_name(char *dst, size_t dst_size, const char *src)
{
    size_t len = strlen(src);

    if (len >= dst_size) {
        return -ENAMETOOLONG;
    }
    (void)memcpy(dst, src, len + 1U);
    return 0;
}

/* Append one DA reference (leaf-DA FCDA or whole-DO expansion
 * member) to the builder. Returns 0, or -ENOSPC when the publisher
 * dataset capacity is exhausted. */
static int scl_append_ref(scl_ref_builder_t *rb, const char *da_name,
                           iec61850_btype_t btype)
{
    iec61850_da_ref_t *ref;
    int ret;

    if (rb->count >= rb->capacity) {
        return -ENOSPC;
    }

    if (rb->is_sv && (!scl_sv_leaf_mappable(btype))) {
        return 0;  /* no SV sample/quality mapping: excluded */
    }

    ref = &rb->refs[rb->count];
    (void)memset(ref, 0, sizeof(*ref));

    ret = scl_copy_name(ref->ld, sizeof(ref->ld), rb->ld);
    if (ret == 0) {
        ret = scl_copy_name(ref->ln, sizeof(ref->ln), rb->ln);
    }
    if (ret == 0) {
        ret = scl_copy_name(ref->do_name, sizeof(ref->do_name), rb->do_name);
    }
    if (ret == 0) {
        ret = scl_copy_name(ref->da_name, sizeof(ref->da_name), da_name);
    }
    if (ret != 0) {
        return ret;
    }
    ref->fc = rb->fc;

    rb->count++;
    return 0;
}

/*
 * Recursively enumerate the leaf DataAttributes of one DataObject,
 * appending the ones matching the builder's FC (and, for whole-SDO
 * references, the sub-object path prefix). Only leaves the frozen
 * binding can watch are appended (see the bindability note below);
 * every appended ref therefore re-resolves in the binding.
 */
static int scl_enum_do_leaves(const iec61850_data_object_t *dobj,
                               const char *path_prefix,
                               scl_ref_builder_t *rb)
{
    int ret = 0;

    if ((dobj == NULL) || (!dobj->valid)) {
        return 0;
    }

    for (size_t i = 0; i < dobj->attr_count; i++) {
        const iec61850_data_attribute_t *da = &dobj->attributes[i];
        char leaf[IEC61850_MAX_NAME_LEN];
        int n;

        if (!da->valid) { continue; }
        if (da->fc != rb->fc) { continue; }

        n = snprintf(leaf, sizeof(leaf), "%s%s", path_prefix, da->name);
        if ((n < 0) || ((size_t)n >= sizeof(leaf))) {
            continue;  /* does not fit a reference: skip leaf */
        }

        /* Bindability (WP-C2): the binding resolves {do_name,
         * da_name} through iec61850_ln_find_attribute(), which now
         * falls back to matching the full dotted reference path
         * against the DataObject's flat attribute table when the
         * sub-data-object walk misses — so template-flattened
         * attribute names (dotted names inside one DataObject's
         * table, e.g. "phsA.cVal.mag.f") are watchable and are no
         * longer excluded from the expansion. Whole-SDO references
         * (e.g. a whole SDO under a WYE) expand to their flattened
         * leaves like any other whole-DO reference. */

        /* Whole-SDO reference: keep only leaves under the prefix. */
        if ((rb->prefix_len > 0U) &&
            ((strncmp(leaf, rb->prefix, rb->prefix_len) != 0) ||
             (leaf[rb->prefix_len] != '.'))) {
            continue;
        }

        ret = scl_append_ref(rb, leaf, da->btype);
        if (ret != 0) { return ret; }
    }

    /* Sub-data-objects (class-library models): recurse with the
     * accumulated dotted path. */
    for (size_t i = 0; i < dobj->sub_count; i++) {
        char sub_prefix[IEC61850_MAX_NAME_LEN];
        const iec61850_data_object_t *sub = dobj->sub_objects[i];
        int n;

        if (sub == NULL) { continue; }

        n = snprintf(sub_prefix, sizeof(sub_prefix), "%s%s.",
                     path_prefix, sub->name);
        if ((n < 0) || ((size_t)n >= sizeof(sub_prefix))) {
            continue;
        }

        ret = scl_enum_do_leaves(sub, sub_prefix, rb);
        if (ret != 0) { return ret; }
    }

    return ret;
}

/*
 * Find an LN in the model by reference name, accepting the naming
 * conventions the tree builders produce (full name in ln_inst,
 * plain inst with class+inst combined, bare class). Mirrors the
 * binding's matcher.
 */
static iec61850_logical_node_t *scl_find_model_ln(
    const iec61850_ied_model_t *model, const char *ld_inst,
    const char *ln_name)
{
    const iec61850_logical_device_t *ld = iec61850_ied_model_find_ld(model,
                                                                      ld_inst);
    if (ld == NULL) {
        return NULL;
    }

    for (size_t i = 0; i < ld->ln_count; i++) {
        iec61850_logical_node_t *ln = ld->logical_nodes[i];
        char combined[(IEC61850_MAX_NAME_LEN * 2U) + 1U];

        if (ln == NULL) {
            continue;
        }
        if (strcmp(ln->ln_inst, ln_name) == 0) {
            return ln;
        }
        (void)snprintf(combined, sizeof(combined), "%s%s",
                       ln->ln_class, ln->ln_inst);
        if (strcmp(combined, ln_name) == 0) {
            return ln;
        }
        if (strcmp(ln->ln_class, ln_name) == 0) {
            return ln;
        }
    }
    return NULL;
}

/*
 * Expand one whole-DO/SDO FCDA against the model into the builder:
 * enumerate the referenced DO's flattened leaf attributes filtered
 * by the FCDA's functional constraint (and, for SV, by mappable
 * leaf type). Appends after the references already collected for
 * earlier FCDAs of the same dataset. Returns 0, or negative errno
 * (-ENOENT when the DO is not in the model or nothing expands).
 */
static int scl_expand_whole_do(const iec61850_ied_model_t *model,
                                const iec61850_scl_da_path_t *path,
                                scl_ref_builder_t *rb)
{
    const char *dot = strchr(path->path, '.');
    char do_name[IEC61850_MAX_NAME_LEN];
    size_t do_len = (dot != NULL)
        ? (size_t)(dot - path->path) : strlen(path->path);
    iec61850_logical_node_t *ln;
    iec61850_data_object_t *dobj;
    uint32_t before;
    int ret;

    if ((do_len == 0U) || (do_len >= sizeof(do_name))) {
        return -ENAMETOOLONG;
    }
    (void)memcpy(do_name, path->path, do_len);
    do_name[do_len] = '\0';

    ln = scl_find_model_ln(model, path->ld_inst, path->ln_name);
    if (ln == NULL) {
        return -ENOENT;
    }
    dobj = iec61850_ln_find_do(ln, do_name);
    if (dobj == NULL) {
        return -ENOENT;
    }

    ret = scl_copy_name(rb->ld, sizeof(rb->ld), path->ld_inst);
    if (ret == 0) {
        ret = scl_copy_name(rb->ln, sizeof(rb->ln), path->ln_name);
    }
    if (ret == 0) {
        ret = scl_copy_name(rb->do_name, sizeof(rb->do_name), do_name);
    }
    if (ret != 0) {
        return ret;
    }

    rb->prefix_len = 0U;
    rb->prefix[0] = '\0';
    if (dot != NULL) {
        /* Whole-SDO reference: restrict to leaves under the SDO. */
        ret = scl_copy_name(rb->prefix, sizeof(rb->prefix), &dot[1]);
        if (ret != 0) {
            return ret;
        }
        rb->prefix_len = strlen(rb->prefix);
    }
    rb->fc = iec61850_string_to_fc(path->fc);

    before = rb->count;
    ret = scl_enum_do_leaves(dobj, "", rb);
    if (ret != 0) {
        return ret;
    }

    /* Zero leaves under this FCDA: the reference selects nothing
     * (wrong functional constraint, or every leaf excluded for SV);
     * the control block cannot publish it. */
    if (rb->count == before) {
        return -ENOENT;
    }

    return 0;
}

/*
 * Resolve all FCDAs of a dataset into binding references. Leaf-DA
 * FCDAs map 1:1; whole-DO/SDO FCDAs expand to their leaf DAs. All
 * FCDAs must resolve (all-or-nothing, matching the binding's add
 * contract). Returns 0, or negative errno.
 */
static int scl_build_dataset_refs(const iec61850_scl_doc_t *doc,
                                   const iec61850_ied_model_t *model,
                                   const char *dataset_name, bool is_sv,
                                   iec61850_da_ref_t *refs,
                                   uint32_t *ref_count)
{
    const iec61850_scl_dataset_t *ds =
        iec61850_scl_find_dataset(doc, dataset_name);
    scl_ref_builder_t rb;

    if (ds == NULL) {
        return -ENOENT;
    }

    (void)memset(&rb, 0, sizeof(rb));
    rb.is_sv = is_sv;
    rb.refs = refs;
    rb.capacity = (uint32_t)IEC61850_BINDING_MAX_REFS;
    rb.count = 0U;

    for (size_t i = 0; i < ds->member_count; i++) {
        iec61850_scl_da_path_t path;
        const char *dot;
        const char *da_name;
        char do_name[IEC61850_MAX_NAME_LEN];
        size_t do_len;
        int ret;

        ret = iec61850_scl_resolve_fcda(doc, ds, i, &path);
        if (ret != 0) {
            return ret;
        }

        if (path.whole_do) {
            ret = scl_expand_whole_do(model, &path, &rb);
            if (ret != 0) {
                return ret;
            }
            continue;
        }

        /* Leaf-DA FCDA: split the resolved dotted path at the first
         * separator — the model flattens everything after the DO. */
        dot = strchr(path.path, '.');
        if (dot == NULL) {
            return -ENOENT;
        }
        do_len = (size_t)(dot - path.path);
        da_name = &dot[1];
        if ((do_len == 0U) || (do_len >= sizeof(do_name)) ||
            (da_name[0] == '\0')) {
            return -ENAMETOOLONG;
        }
        (void)memcpy(do_name, path.path, do_len);
        do_name[do_len] = '\0';

        ret = scl_copy_name(rb.ld, sizeof(rb.ld), path.ld_inst);
        if (ret == 0) {
            ret = scl_copy_name(rb.ln, sizeof(rb.ln), path.ln_name);
        }
        if (ret == 0) {
            ret = scl_copy_name(rb.do_name, sizeof(rb.do_name), do_name);
        }
        if (ret != 0) {
            return ret;
        }
        rb.fc = iec61850_string_to_fc(path.fc);

        ret = scl_append_ref(&rb, da_name, scl_btype_from_string(path.btype));
        if (ret != 0) {
            return ret;
        }
    }

    if (rb.count == 0U) {
        return -ENOENT;  /* empty dataset: nothing to publish */
    }

    *ref_count = rb.count;
    return 0;
}

/* Parse an SCL MAC-Address ("01-0C-CD-01-00-01"; '-', ':' and '.'
 * separators accepted) into 6 bytes. Returns 0, or -EINVAL on a
 * malformed string. */
static int scl_parse_mac(const char *str, uint8_t out[6])
{
    size_t pos = 0U;

    for (size_t b = 0U; b < 6U; b++) {
        unsigned value = 0U;
        unsigned digits = 0U;

        while ((digits < 2U) && (str[pos] != '\0')) {
            char c = str[pos];
            unsigned nibble;

            if ((c >= '0') && (c <= '9')) {
                nibble = (unsigned)(c - '0');
            } else if ((c >= 'A') && (c <= 'F')) {
                nibble = (unsigned)(c - 'A') + 10U;
            } else if ((c >= 'a') && (c <= 'f')) {
                nibble = (unsigned)(c - 'a') + 10U;
            } else {
                break;
            }
            value = (value * 16U) + nibble;
            digits++;
            pos++;
        }

        if ((digits == 0U) || (value > 0xFFU)) {
            return -EINVAL;
        }
        out[b] = (uint8_t)value;

        /* One separator between byte groups; trailing separator or
         * end-of-string after the sixth group both terminate. */
        if (str[pos] != '\0') {
            if ((str[pos] != '-') && (str[pos] != ':') && (str[pos] != '.')) {
                return -EINVAL;
            }
            pos++;
        }
    }

    return (str[pos] == '\0') ? 0 : -EINVAL;
}

/* Build the IEC 61850-8-1 LD/LN dataset reference
 * ("IED1LD0/LLN0$DS1"). Returns 0, or -ENAMETOOLONG. */
static int scl_build_ds_ref(char *dst, size_t dst_size,
                             const char *ied_name, const char *ld_inst,
                             const char *ds_name)
{
    int n = snprintf(dst, dst_size, "%s%s/LLN0$%s", ied_name, ld_inst,
                     ds_name);
    if ((n < 0) || ((size_t)n >= dst_size)) {
        return -ENAMETOOLONG;
    }
    return 0;
}

/*
 * Prepare a GOOSE publisher configuration from an SCL control
 * block and its Communication address. Fields absent from the SCL
 * keep the iec61850_goose_config_init() defaults. Returns 0, or
 * -ENOENT when no address is configured (no Communication section),
 * -ENAMETOOLONG when a derived name does not fit.
 */
static int scl_build_goose_config(const iec61850_scl_doc_t *doc,
                                   const iec61850_scl_goose_cb_t *cb,
                                   iec61850_goose_config_t *cfg)
{
    int ret;

    iec61850_goose_config_init(cfg);

    if (cb->mac_address[0] == '\0') {
        return -ENOENT;  /* no Communication address for this block */
    }
    ret = scl_parse_mac(cb->mac_address, cfg->dst_mac);
    if (ret != 0) {
        return ret;
    }

    if (cb->app_id != 0U) {
        cfg->app_id = cb->app_id;
    }
    if (cb->vlan_id != 0U) {
        cfg->vlan_id = cb->vlan_id;
    }
    if (cb->vlan_priority != 0U) {
        cfg->vlan_priority = cb->vlan_priority;
    }
    if (cb->max_time != 0U) {
        cfg->time_allowed_to_live = cb->max_time;
    }
    if (cb->go_id[0] != '\0') {
        ret = scl_copy_name(cfg->goose_id, sizeof(cfg->goose_id), cb->go_id);
        if (ret != 0) { return ret; }
    }

    {
        char ref[GOOSE_MAX_GOCBREF_LEN];
        int n = snprintf(ref, sizeof(ref), "%s%s/LLN0$GO$%s",
                         doc->ied_name, cb->ld_inst, cb->cb_name);
        if ((n < 0) || ((size_t)n >= sizeof(ref))) {
            return -ENAMETOOLONG;
        }
        ret = scl_copy_name(cfg->gocb_ref, sizeof(cfg->gocb_ref), ref);
        if (ret != 0) { return ret; }
    }

    return scl_build_ds_ref(cfg->dataset, sizeof(cfg->dataset),
                            doc->ied_name, cb->ld_inst, cb->dataset);
}

/*
 * Prepare an SV publisher configuration. num_channels is set by the
 * caller once the expanded dataset size is known. Same conventions
 * as scl_build_goose_config().
 */
static int scl_build_sv_config(const iec61850_scl_doc_t *doc,
                                const iec61850_scl_sv_cb_t *cb,
                                iec61850_sv_config_t *cfg)
{
    int ret;

    iec61850_sv_config_init(cfg);

    if (cb->mac_address[0] == '\0') {
        return -ENOENT;
    }
    ret = scl_parse_mac(cb->mac_address, cfg->dst_mac);
    if (ret != 0) {
        return ret;
    }

    if (cb->app_id != 0U) {
        cfg->app_id = cb->app_id;
    }
    if (cb->vlan_id != 0U) {
        cfg->vlan_id = cb->vlan_id;
    }
    if (cb->vlan_priority != 0U) {
        cfg->vlan_priority = cb->vlan_priority;
    }
    if (cb->smp_rate != 0U) {
        cfg->smp_rate = cb->smp_rate;
    }
    if (cb->sv_id[0] != '\0') {
        ret = scl_copy_name(cfg->sv_id, sizeof(cfg->sv_id), cb->sv_id);
        if (ret != 0) { return ret; }
    }
    cfg->conf_rev = cb->conf_rev;

    return scl_build_ds_ref(cfg->dataset, sizeof(cfg->dataset),
                            doc->ied_name, cb->ld_inst, cb->dataset);
}

/* Configure one GSE control block. Returns 0 when bound, negative
 * errno when skipped. */
static int scl_configure_goose_cb(const iec61850_scl_doc_t *doc,
                                   const iec61850_scl_goose_cb_t *cb,
                                   iec61850_model_binding_t *binding,
                                   const iec61850_scl_publisher_ops_t *ops)
{
    iec61850_goose_config_t cfg;
    iec61850_da_ref_t refs[IEC61850_BINDING_MAX_REFS];
    iec61850_goose_publisher_t *pub = NULL;
    uint32_t ref_count = 0U;
    int ret;

    ret = scl_build_goose_config(doc, cb, &cfg);
    if (ret != 0) {
        return ret;
    }

    ret = scl_build_dataset_refs(doc, binding->model, cb->dataset, false,
                                 refs, &ref_count);
    if (ret != 0) {
        return ret;
    }

    ret = ops->create_goose(cb, &cfg, &pub, ops->user_data);
    if ((ret != 0) || (pub == NULL)) {
        return -ENOENT;
    }

    /* confRev is a publisher field (not part of the config struct). */
    pub->conf_rev = cb->conf_rev;

    /* SCL MinTime/MaxTime drive the retransmission backoff; TAL
     * advertises the steady-state (max) interval. */
    if ((cb->min_time != 0U) || (cb->max_time != 0U)) {
        iec61850_retransmit_config_t rc;
        (void)memset(&rc, 0, sizeof(rc));
        rc.t0_ms = (cb->min_time != 0U) ? cb->min_time : 2U;
        rc.t_max_ms = (cb->max_time != 0U) ? cb->max_time : 1000U;
        iec61850_goose_publisher_enable_retransmit(pub, &rc);
    }

    return iec61850_model_binding_add_goose(binding, pub, refs, ref_count);
}

/* Configure one SampledValue control block. Same contract. */
static int scl_configure_sv_cb(const iec61850_scl_doc_t *doc,
                                const iec61850_scl_sv_cb_t *cb,
                                iec61850_model_binding_t *binding,
                                const iec61850_scl_publisher_ops_t *ops)
{
    iec61850_sv_config_t cfg;
    iec61850_da_ref_t refs[IEC61850_BINDING_MAX_REFS];
    iec61850_sv_publisher_t *pub = NULL;
    uint32_t ref_count = 0U;
    int ret;

    ret = scl_build_sv_config(doc, cb, &cfg);
    if (ret != 0) {
        return ret;
    }

    ret = scl_build_dataset_refs(doc, binding->model, cb->dataset, true,
                                 refs, &ref_count);
    if (ret != 0) {
        return ret;
    }

    /* One channel per expanded dataset member (slot-for-slot
     * mapping of the binding). */
    cfg.num_channels = (uint8_t)ref_count;

    ret = ops->create_sv(cb, &cfg, &pub, ops->user_data);
    if ((ret != 0) || (pub == NULL)) {
        return -ENOENT;
    }

    return iec61850_model_binding_add_sv(binding, pub, refs, ref_count);
}

int iec61850_scl_configure_publishers(
    const iec61850_scl_doc_t *doc,
    iec61850_model_binding_t *binding,
    const iec61850_scl_publisher_ops_t *ops,
    iec61850_scl_publisher_result_t *result)
{
    uint32_t goose_configured = 0U;
    uint32_t sv_configured = 0U;
    uint32_t skipped = 0U;

    if ((doc == NULL) || (binding == NULL) || (ops == NULL) ||
        (!binding->initialized)) {
        return -EINVAL;
    }

    if (result != NULL) {
        (void)memset(result, 0, sizeof(*result));
    }

    for (size_t i = 0; i < doc->goose_cb_count; i++) {
        int ret;

        if (ops->create_goose == NULL) {
            skipped++;  /* caller declined GOOSE publishers */
            continue;
        }

        ret = scl_configure_goose_cb(doc, &doc->goose_cbs[i], binding, ops);
        /* The bind returns the publisher slot (0..MAX-1); every
         * non-negative result is a configured block. */
        if (ret >= 0) {
            goose_configured++;
        } else {
            skipped++;
        }
    }

    for (size_t i = 0; i < doc->sv_cb_count; i++) {
        int ret;

        if (ops->create_sv == NULL) {
            skipped++;  /* caller declined SV publishers */
            continue;
        }

        ret = scl_configure_sv_cb(doc, &doc->sv_cbs[i], binding, ops);
        /* Same contract: the bind returns the publisher slot. */
        if (ret >= 0) {
            sv_configured++;
        } else {
            skipped++;
        }
    }

    if (result != NULL) {
        result->goose_configured = goose_configured;
        result->sv_configured = sv_configured;
        result->skipped = skipped;
    }

    return (int)(goose_configured + sv_configured);
}

