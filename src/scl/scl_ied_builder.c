/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * SCL-to-IED Model Builder
 *
 * Builds complete IED data model from parsed SCL document.
 */

#include "scl/scl_ied_builder.h"
#include "mms/mms_report.h"
#include <string.h>
#include <stdio.h>
#include <errno.h>

/* Create standard data objects for known LN classes (IEC 61850-7-4) */
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
    } else if (strcmp(ln_class, "XSWI") == 0) {
        /* Disconnector */
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
    } else if (strcmp(ln_class, "CSWI") == 0) {
        /* Switch Controller */
        dobj = iec61850_cdc_create_dpc("Pos");
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
    if (doc == NULL || model == NULL) {
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
            (void)strncat(ln_name, scl_ln->ln_prefix, sizeof(ln_name) - 1U);
            (void)strncat(ln_name, scl_ln->ln_class,
                          sizeof(ln_name) - strlen(ln_name) - 1U);
            (void)strncat(ln_name, scl_ln->ln_inst,
                          sizeof(ln_name) - strlen(ln_name) - 1U);

            iec61850_logical_node_t *ln = iec61850_ln_create(scl_ln->ln_class,
                                                               ln_name);
            if (ln == NULL) {
                continue;
            }

            /* Populate with standard data objects for known LN classes */
            populate_ln_with_standard_dos(ln, scl_ln->ln_class);

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
        case IEC61850_BTYPE_VISIBLE_STRING: return MMS_TYPE_VISIBLE_STRING;
        case IEC61850_BTYPE_UNICODE_STRING: return MMS_TYPE_VISIBLE_STRING;
        case IEC61850_BTYPE_TIMESTAMP:      return MMS_TYPE_UTC_TIME;
        case IEC61850_BTYPE_QUALITY:        return MMS_TYPE_BIT_STRING;
        case IEC61850_BTYPE_CHECK:          return MMS_TYPE_BIT_STRING;
        case IEC61850_BTYPE_ENTRY_TIME:     return MMS_TYPE_BINARY_TIME;
        case IEC61850_BTYPE_DBPOS:          return MMS_TYPE_BIT_STRING;
        case IEC61850_BTYPE_STRUCT:         return MMS_TYPE_STRUCTURE;
        case IEC61850_BTYPE_PHYS_COMM_ADDR: return MMS_TYPE_OCTET_STRING;
        case IEC61850_BTYPE_CURRENCY:       return MMS_TYPE_VISIBLE_STRING;
        default:                            return MMS_TYPE_VISIBLE_STRING;
    }
}

/* Register all DAs of a DO as MMS variables.
 * var_prefix is "LN$FC$DO" or "LN$FC$DO$SubDO" for nested objects. */
static int register_do_variables(const iec61850_data_object_t *dobj,
                                   const char *ln_name,
                                   const char *domain,
                                   iec61850_mms_data_store_t *data_store)
{
    int registered = 0;

    for (size_t i = 0; i < dobj->attr_count; i++) {
        const iec61850_data_attribute_t *da = &dobj->attributes[i];
        if (!da->valid) { continue; }

        const char *fc_str = iec61850_fc_to_string(da->fc);

        /* Build MMS variable name: LN$FC$DO$DA */
        char var_name[MMS_MAX_VARIABLE_NAME];
        (void)snprintf(var_name, sizeof(var_name), "%s$%s$%s$%s",
                       ln_name, fc_str, dobj->name, da->name);

        mms_type_t mms_type = btype_to_mms_type(da->btype);
        int ret = iec61850_mms_ds_create_variable(
            data_store, domain, var_name, mms_type, &da->value);
        if (ret == (int)IEC61850_MMS_DS_OK) {
            registered++;
        }
    }

    /* Recurse into sub-data-objects */
    for (size_t i = 0; i < dobj->sub_count; i++) {
        const iec61850_data_object_t *sub = dobj->sub_objects[i];
        if (sub == NULL || !sub->valid) { continue; }

        /* For sub-objects, DAs are named: LN$FC$ParentDO$SubDO$DA
         * We need to iterate sub-object DAs and build the compound name */
        for (size_t j = 0; j < sub->attr_count; j++) {
            const iec61850_data_attribute_t *da = &sub->attributes[j];
            if (!da->valid) { continue; }

            const char *fc_str = iec61850_fc_to_string(da->fc);

            char var_name[MMS_MAX_VARIABLE_NAME];
            (void)snprintf(var_name, sizeof(var_name), "%s$%s$%s$%s$%s",
                           ln_name, fc_str, dobj->name, sub->name, da->name);

            mms_type_t mms_type = btype_to_mms_type(da->btype);
            int ret = iec61850_mms_ds_create_variable(
                data_store, domain, var_name, mms_type, &da->value);
            if (ret == (int)IEC61850_MMS_DS_OK) {
                registered++;
            }
        }
    }

    return registered;
}

int iec61850_ied_model_register_mms(const iec61850_ied_model_t *model,
                                      iec61850_mms_data_store_t *data_store)
{
    int total = 0;

    if (model == NULL || data_store == NULL) {
        return -EINVAL;
    }

    for (size_t i = 0; i < model->ld_count; i++) {
        const iec61850_logical_device_t *ld = model->logical_devices[i];
        if (ld == NULL || !ld->valid) { continue; }

        /* Domain name: IEDName + LDInst */
        char domain[MMS_MAX_DOMAIN_NAME];
        (void)snprintf(domain, sizeof(domain), "%s%s",
                       model->ied_name, ld->ld_inst);

        int ret = iec61850_mms_ds_create_domain(data_store, domain);
        if (ret != (int)IEC61850_MMS_DS_OK && ret != (int)IEC61850_MMS_DS_ERR_EXISTS) {
            continue;
        }

        for (size_t j = 0; j < ld->ln_count; j++) {
            const iec61850_logical_node_t *ln = ld->logical_nodes[j];
            if (ln == NULL || !ln->valid) { continue; }

            /* LN name: lnClass + inst (already combined in ln_inst) */
            const char *ln_name = ln->ln_inst;

            for (size_t k = 0; k < ln->do_count; k++) {
                const iec61850_data_object_t *dobj = ln->data_objects[k];
                if (dobj == NULL || !dobj->valid) { continue; }

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
    iec61850_rcb_manager_t *mgr = (iec61850_rcb_manager_t *)mgr_ptr;
    int configured = 0;

    if (doc == NULL || mgr == NULL) {
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
