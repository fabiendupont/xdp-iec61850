/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * SCL Parser Implementation using libxml2
 *
 * Accepts the four IEC 61850-6 exchange variants (SCD, ICD, IID,
 * CID) of the common SCL schema and reports the sniffed variant in
 * the document (WP-6e).
 *
 * License: BSD-2-Clause
 */

#include "scl/scl_parser.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void iec61850_scl_doc_init(iec61850_scl_doc_t *doc)
{
    if (doc != NULL) {
        (void)memset(doc, 0, sizeof(*doc));
    }
}

/* ======================================================================
 * Bounds-disciplined string copies (WP-6e hardening)
 *
 * Every string extracted from the (attacker-controllable) document
 * must fit its fixed-size destination. Oversized values fail the
 * parse with -ENAMETOOLONG instead of being silently truncated.
 * ====================================================================== */

/* Checked copy of a bounded source string (already validated) */
static int copy_bounded(char *dst, size_t dst_size, const char *src)
{
    if (src == NULL) {
        dst[0] = '\0';
        return 0;
    }
    if (strlen(src) >= dst_size) {
        return -ENAMETOOLONG;
    }
    (void)memset(dst, 0, dst_size);
    (void)memcpy(dst, src, strlen(src) + 1U);
    return 0;
}

/* Safe attribute copy: 0 on success (missing attribute -> empty),
 * -ENAMETOOLONG when the value does not fit. */
static int copy_attr(char *dst, size_t dst_size, xmlNode *node,
                      const char *attr_name)
{
    xmlChar *val = xmlGetProp(node, (const xmlChar *)attr_name);
    if (val == NULL) {
        dst[0] = '\0';
        return 0;
    }
    int ret = copy_bounded(dst, dst_size, (const char *)val);
    xmlFree(val);
    return ret;
}

/* Safe element-content copy (same contract as copy_attr) */
static int copy_text(char *dst, size_t dst_size, xmlNode *node)
{
    xmlChar *val = xmlNodeGetContent(node);
    if (val == NULL) {
        dst[0] = '\0';
        return 0;
    }
    int ret = copy_bounded(dst, dst_size, (const char *)val);
    xmlFree(val);
    return ret;
}

/* ======================================================================
 * Control-block / dataset parsing
 * ====================================================================== */

/* Parse GSEControl inside LN0 */
static int parse_gse_control(xmlNode *gse_node, const char *ied_name,
                              const char *ld_inst, iec61850_scl_doc_t *doc)
{
    if (doc->goose_cb_count >= (size_t)IEC61850_SCL_MAX_CBS) { return 0; }

    iec61850_scl_goose_cb_t *cb = &doc->goose_cbs[doc->goose_cb_count];
    (void)memset(cb, 0, sizeof(*cb));

    int ret = copy_bounded(cb->ied_name, sizeof(cb->ied_name), ied_name);
    if (ret == 0) {
        ret = copy_bounded(cb->ld_inst, sizeof(cb->ld_inst), ld_inst);
    }
    if (ret == 0) {
        ret = copy_attr(cb->cb_name, sizeof(cb->cb_name), gse_node, "name");
    }
    if (ret == 0) {
        ret = copy_attr(cb->dataset, sizeof(cb->dataset), gse_node, "datSet");
    }
    if (ret != 0) { return ret; }

    /* appID attribute */
    xmlChar *app_id_str = xmlGetProp(gse_node, (const xmlChar *)"appID");
    if (app_id_str != NULL) {
        cb->app_id = (uint16_t)strtoul((const char *)app_id_str, NULL, 0);
        xmlFree(app_id_str);
    }

    /* confRev attribute */
    xmlChar *conf_rev_str = xmlGetProp(gse_node, (const xmlChar *)"confRev");
    if (conf_rev_str != NULL) {
        cb->conf_rev = (uint32_t)strtoul((const char *)conf_rev_str, NULL, 10);
        xmlFree(conf_rev_str);
    } else {
        cb->conf_rev = 1;
    }

    /* goID from attribute (IEC 61850-6 §9.3.7) */
    ret = copy_attr(cb->go_id, sizeof(cb->go_id), gse_node, "goID");
    if (ret != 0) { return ret; }

    doc->goose_cb_count++;
    return 0;
}

/* Parse SampledValueControl inside LN0 */
static int parse_sv_control(xmlNode *sv_node, const char *ied_name,
                             const char *ld_inst, iec61850_scl_doc_t *doc)
{
    if (doc->sv_cb_count >= (size_t)IEC61850_SCL_MAX_CBS) { return 0; }

    iec61850_scl_sv_cb_t *cb = &doc->sv_cbs[doc->sv_cb_count];
    (void)memset(cb, 0, sizeof(*cb));

    int ret = copy_bounded(cb->ied_name, sizeof(cb->ied_name), ied_name);
    if (ret == 0) {
        ret = copy_bounded(cb->ld_inst, sizeof(cb->ld_inst), ld_inst);
    }
    if (ret == 0) {
        ret = copy_attr(cb->cb_name, sizeof(cb->cb_name), sv_node, "name");
    }
    if (ret == 0) {
        ret = copy_attr(cb->dataset, sizeof(cb->dataset), sv_node, "datSet");
    }
    if (ret == 0) {
        ret = copy_attr(cb->sv_id, sizeof(cb->sv_id), sv_node, "smvID");
    }
    if (ret != 0) { return ret; }

    xmlChar *conf_rev_str = xmlGetProp(sv_node, (const xmlChar *)"confRev");
    if (conf_rev_str != NULL) {
        cb->conf_rev = (uint32_t)strtoul((const char *)conf_rev_str, NULL, 10);
        xmlFree(conf_rev_str);
    } else {
        cb->conf_rev = 1;
    }

    xmlChar *smp_rate_str = xmlGetProp(sv_node, (const xmlChar *)"smpRate");
    if (smp_rate_str != NULL) {
        cb->smp_rate = (uint16_t)strtoul((const char *)smp_rate_str, NULL, 10);
        xmlFree(smp_rate_str);
    }

    doc->sv_cb_count++;
    return 0;
}

/* Parse boolean attribute (returns false if missing) */
static bool parse_bool_attr(xmlNode *node, const char *attr)
{
    xmlChar *val = xmlGetProp(node, (const xmlChar *)attr);
    if (val == NULL) { return false; }
    bool result = ((strcmp((const char *)val, "true") == 0) ||
                   (strcmp((const char *)val, "1") == 0));
    xmlFree(val);
    return result;
}

/* Parse ReportControl inside LN0 */
static int parse_report_control(xmlNode *rcb_node, const char *ied_name,
                                 const char *ld_inst, iec61850_scl_doc_t *doc)
{
    if (doc->rcb_count >= (size_t)IEC61850_SCL_MAX_RCBS) { return 0; }

    iec61850_scl_rcb_t *rcb = &doc->rcbs[doc->rcb_count];
    (void)memset(rcb, 0, sizeof(*rcb));

    int ret = copy_bounded(rcb->ied_name, sizeof(rcb->ied_name), ied_name);
    if (ret == 0) {
        ret = copy_bounded(rcb->ld_inst, sizeof(rcb->ld_inst), ld_inst);
    }
    if (ret == 0) {
        ret = copy_attr(rcb->rpt_id, sizeof(rcb->rpt_id), rcb_node, "rptID");
    }
    if (ret == 0) {
        ret = copy_attr(rcb->dataset, sizeof(rcb->dataset), rcb_node, "datSet");
    }
    if (ret != 0) { return ret; }

    rcb->buffered = parse_bool_attr(rcb_node, "buffered");

    xmlChar *conf_rev_str = xmlGetProp(rcb_node, (const xmlChar *)"confRev");
    if (conf_rev_str != NULL) {
        rcb->conf_rev = (uint32_t)strtoul((const char *)conf_rev_str, NULL, 10);
        xmlFree(conf_rev_str);
    }

    xmlChar *buf_time_str = xmlGetProp(rcb_node, (const xmlChar *)"bufTime");
    if (buf_time_str != NULL) {
        rcb->buf_time = (uint32_t)strtoul((const char *)buf_time_str, NULL, 10);
        xmlFree(buf_time_str);
    }

    xmlChar *intg_pd_str = xmlGetProp(rcb_node, (const xmlChar *)"intgPd");
    if (intg_pd_str != NULL) {
        rcb->intg_pd = (uint32_t)strtoul((const char *)intg_pd_str, NULL, 10);
        xmlFree(intg_pd_str);
    }

    /* Parse child elements: TrgOps, OptFields, RptEnabled */
    for (xmlNode *child = rcb_node->children; child != NULL; child = child->next) {
        if (child->type != XML_ELEMENT_NODE) { continue; }
        const char *cname = (const char *)child->name;

        if (strcmp(cname, "TrgOps") == 0) {
            rcb->trg_dchg = parse_bool_attr(child, "dchg");
            rcb->trg_qchg = parse_bool_attr(child, "qchg");
            rcb->trg_dupd = parse_bool_attr(child, "dupd");
            rcb->trg_period = parse_bool_attr(child, "period");
            rcb->trg_gi = parse_bool_attr(child, "gi");
        } else if (strcmp(cname, "OptFields") == 0) {
            rcb->opt_seq_num = parse_bool_attr(child, "seqNum");
            rcb->opt_timestamp = parse_bool_attr(child, "timeStamp");
            rcb->opt_reason = parse_bool_attr(child, "reasonCode");
            rcb->opt_dataref = parse_bool_attr(child, "dataRef");
            rcb->opt_entryid = parse_bool_attr(child, "entryID");
            rcb->opt_bufovfl = parse_bool_attr(child, "bufOvfl");
            rcb->opt_configref = parse_bool_attr(child, "configRef");
        } else if (strcmp(cname, "RptEnabled") == 0) {
            xmlChar *max_str = xmlGetProp(child, (const xmlChar *)"max");
            if (max_str != NULL) {
                rcb->rpt_enabled_max = (uint8_t)strtoul((const char *)max_str, NULL, 10);
                xmlFree(max_str);
            } else {
                rcb->rpt_enabled_max = 1;
            }
        }
    }

    doc->rcb_count++;
    return 0;
}

/* Parse DataSet inside LN0 or LN */
static int parse_dataset(xmlNode *ds_node, iec61850_scl_doc_t *doc)
{
    if (doc->dataset_count >= (size_t)IEC61850_SCL_MAX_DATASETS) { return 0; }

    iec61850_scl_dataset_t *ds = &doc->datasets[doc->dataset_count];
    (void)memset(ds, 0, sizeof(*ds));

    int ret = copy_attr(ds->name, sizeof(ds->name), ds_node, "name");
    if (ret != 0) { return ret; }

    /* Parse FCDA members */
    for (xmlNode *fcda = ds_node->children; fcda != NULL; fcda = fcda->next) {
        if (fcda->type != XML_ELEMENT_NODE) { continue; }
        if (strcmp((const char *)fcda->name, "FCDA") != 0) { continue; }
        if (ds->member_count >= (size_t)IEC61850_SCL_MAX_DS_MEMBERS) { break; }

        iec61850_scl_fcda_t *m = &ds->members[ds->member_count];
        (void)memset(m, 0, sizeof(*m));

        ret = copy_attr(m->ld_inst, sizeof(m->ld_inst), fcda, "ldInst");
        if (ret == 0) {
            ret = copy_attr(m->ln_prefix, sizeof(m->ln_prefix), fcda, "prefix");
        }
        if (ret == 0) {
            ret = copy_attr(m->ln_class, sizeof(m->ln_class), fcda, "lnClass");
        }
        if (ret == 0) {
            ret = copy_attr(m->ln_inst, sizeof(m->ln_inst), fcda, "lnInst");
        }
        if (ret == 0) {
            ret = copy_attr(m->do_name, sizeof(m->do_name), fcda, "doName");
        }
        if (ret == 0) {
            ret = copy_attr(m->da_name, sizeof(m->da_name), fcda, "daName");
        }
        if (ret == 0) {
            ret = copy_attr(m->fc, sizeof(m->fc), fcda, "fc");
        }
        if (ret != 0) { return ret; }

        ds->member_count++;
    }

    doc->dataset_count++;
    return 0;
}

/* Parse LN0 children for control blocks and datasets */
static int parse_ln0(xmlNode *ln0_node, const char *ied_name,
                      const char *ld_inst, iec61850_scl_doc_t *doc)
{
    for (xmlNode *child = ln0_node->children; child != NULL; child = child->next) {
        if (child->type != XML_ELEMENT_NODE) { continue; }
        const char *name = (const char *)child->name;
        int ret = 0;

        if (strcmp(name, "GSEControl") == 0) {
            ret = parse_gse_control(child, ied_name, ld_inst, doc);
        } else if (strcmp(name, "SampledValueControl") == 0) {
            ret = parse_sv_control(child, ied_name, ld_inst, doc);
        } else if (strcmp(name, "ReportControl") == 0) {
            ret = parse_report_control(child, ied_name, ld_inst, doc);
        } else if (strcmp(name, "DataSet") == 0) {
            ret = parse_dataset(child, doc);
        }
        if (ret != 0) { return ret; }
    }
    return 0;
}

/* Parse LN reference attributes */
static int parse_ln_ref(iec61850_scl_ln_ref_t *ln, xmlNode *ln_node)
{
    int ret = copy_attr(ln->ln_class, sizeof(ln->ln_class), ln_node, "lnClass");
    if (ret == 0) {
        ret = copy_attr(ln->ln_inst, sizeof(ln->ln_inst), ln_node, "inst");
    }
    if (ret == 0) {
        ret = copy_attr(ln->ln_type, sizeof(ln->ln_type), ln_node, "lnType");
    }
    if (ret == 0) {
        ret = copy_attr(ln->ln_prefix, sizeof(ln->ln_prefix), ln_node, "prefix");
    }
    return ret;
}

/* Parse LDevice children for LN definitions and control blocks */
static int parse_ldevice(xmlNode *ld_node, const char *ied_name,
                          iec61850_scl_doc_t *doc)
{
    if (doc->ld_count >= (size_t)IEC61850_SCL_MAX_LDS) {
        return 0;
    }

    iec61850_scl_ld_t *ld = &doc->lds[doc->ld_count];
    (void)memset(ld, 0, sizeof(*ld));
    int ret = copy_attr(ld->inst, sizeof(ld->inst), ld_node, "inst");
    if (ret != 0) { return ret; }

    for (xmlNode *child = ld_node->children; child != NULL; child = child->next) {
        if (child->type != XML_ELEMENT_NODE) { continue; }
        if (ld->ln_count >= (size_t)IEC61850_SCL_MAX_LNS) { break; }

        const char *name = (const char *)child->name;

        if (strcmp(name, "LN0") == 0) {
            iec61850_scl_ln_ref_t *ln = &ld->lns[ld->ln_count];
            (void)memset(ln, 0, sizeof(*ln));
            ret = parse_ln_ref(ln, child);
            if (ret != 0) { return ret; }
            ld->ln_count++;

            /* Parse control blocks inside LN0 */
            ret = parse_ln0(child, ied_name, ld->inst, doc);
            if (ret != 0) { return ret; }
        } else if (strcmp(name, "LN") == 0) {
            iec61850_scl_ln_ref_t *ln = &ld->lns[ld->ln_count];
            (void)memset(ln, 0, sizeof(*ln));
            ret = parse_ln_ref(ln, child);
            if (ret != 0) { return ret; }
            ld->ln_count++;

            /* Parse DataSets inside LN */
            for (xmlNode *lnchild = child->children; lnchild != NULL;
                 lnchild = lnchild->next) {
                if (lnchild->type != XML_ELEMENT_NODE) { continue; }
                if (strcmp((const char *)lnchild->name, "DataSet") == 0) {
                    ret = parse_dataset(lnchild, doc);
                    if (ret != 0) { return ret; }
                }
            }
        }
    }

    doc->ld_count++;
    return 0;
}

/* Parse DataTypeTemplates section */
static int parse_data_type_templates(xmlNode *dtt_node, iec61850_scl_doc_t *doc)
{
    for (xmlNode *child = dtt_node->children; child != NULL; child = child->next) {
        if (child->type != XML_ELEMENT_NODE) { continue; }
        const char *name = (const char *)child->name;
        int ret = 0;

        if (strcmp(name, "LNodeType") == 0) {
            if (doc->lnode_type_count >= (size_t)IEC61850_SCL_MAX_LNODE_TYPES) { continue; }
            iec61850_scl_lnode_type_t *lt = &doc->lnode_types[doc->lnode_type_count];
            (void)memset(lt, 0, sizeof(*lt));
            ret = copy_attr(lt->id, sizeof(lt->id), child, "id");
            if (ret == 0) {
                ret = copy_attr(lt->ln_class, sizeof(lt->ln_class), child, "lnClass");
            }
            if (ret != 0) { return ret; }

            for (xmlNode *do_child = child->children; do_child != NULL;
                 do_child = do_child->next) {
                if (do_child->type != XML_ELEMENT_NODE) { continue; }
                if (strcmp((const char *)do_child->name, "DO") != 0) { continue; }
                if (lt->do_count >= (size_t)IEC61850_SCL_MAX_TYPE_DOS) { break; }

                iec61850_scl_do_ref_t *doref = &lt->dos[lt->do_count];
                (void)memset(doref, 0, sizeof(*doref));
                ret = copy_attr(doref->name, sizeof(doref->name), do_child, "name");
                if (ret == 0) {
                    ret = copy_attr(doref->type, sizeof(doref->type), do_child, "type");
                }
                if (ret != 0) { return ret; }
                lt->do_count++;
            }
            doc->lnode_type_count++;

        } else if (strcmp(name, "DOType") == 0) {
            if (doc->do_type_count >= (size_t)IEC61850_SCL_MAX_DO_TYPES) { continue; }
            iec61850_scl_do_type_t *dt = &doc->do_types[doc->do_type_count];
            (void)memset(dt, 0, sizeof(*dt));
            ret = copy_attr(dt->id, sizeof(dt->id), child, "id");
            if (ret == 0) {
                ret = copy_attr(dt->cdc, sizeof(dt->cdc), child, "cdc");
            }
            if (ret != 0) { return ret; }

            for (xmlNode *da_child = child->children; da_child != NULL;
                 da_child = da_child->next) {
                if (da_child->type != XML_ELEMENT_NODE) { continue; }
                const char *da_name = (const char *)da_child->name;
                bool is_sdo = (strcmp(da_name, "SDO") == 0);
                if ((strcmp(da_name, "DA") != 0) && (!is_sdo)) {
                    continue;
                }
                if (dt->da_count >= (size_t)IEC61850_SCL_MAX_TYPE_DAS) { break; }

                iec61850_scl_da_t *da = &dt->das[dt->da_count];
                (void)memset(da, 0, sizeof(*da));
                da->is_sdo = is_sdo;
                ret = copy_attr(da->name, sizeof(da->name), da_child, "name");
                if (ret == 0) {
                    ret = copy_attr(da->fc, sizeof(da->fc), da_child, "fc");
                }
                if (ret == 0) {
                    ret = copy_attr(da->btype, sizeof(da->btype), da_child, "bType");
                }
                if (ret == 0) {
                    ret = copy_attr(da->type, sizeof(da->type), da_child, "type");
                }
                if (ret != 0) { return ret; }

                xmlChar *count_str = xmlGetProp(da_child, (const xmlChar *)"count");
                if (count_str != NULL) {
                    da->count = (uint32_t)strtoul((const char *)count_str, NULL, 10);
                    xmlFree(count_str);
                }
                dt->da_count++;
            }
            doc->do_type_count++;

        } else if (strcmp(name, "DAType") == 0) {
            if (doc->da_type_count >= (size_t)IEC61850_SCL_MAX_DA_TYPES) { continue; }
            iec61850_scl_da_type_t *dat = &doc->da_types[doc->da_type_count];
            (void)memset(dat, 0, sizeof(*dat));
            ret = copy_attr(dat->id, sizeof(dat->id), child, "id");
            if (ret != 0) { return ret; }

            for (xmlNode *bda = child->children; bda != NULL; bda = bda->next) {
                if (bda->type != XML_ELEMENT_NODE) { continue; }
                if (strcmp((const char *)bda->name, "BDA") != 0) { continue; }
                if (dat->bda_count >= (size_t)IEC61850_SCL_MAX_TYPE_DAS) { break; }

                iec61850_scl_da_t *b = &dat->bdas[dat->bda_count];
                (void)memset(b, 0, sizeof(*b));
                ret = copy_attr(b->name, sizeof(b->name), bda, "name");
                if (ret == 0) {
                    ret = copy_attr(b->btype, sizeof(b->btype), bda, "bType");
                }
                if (ret == 0) {
                    ret = copy_attr(b->type, sizeof(b->type), bda, "type");
                }
                if (ret != 0) { return ret; }
                dat->bda_count++;
            }
            doc->da_type_count++;

        } else if (strcmp(name, "EnumType") == 0) {
            if (doc->enum_type_count >= (size_t)IEC61850_SCL_MAX_ENUM_TYPES) { continue; }
            iec61850_scl_enum_type_t *et = &doc->enum_types[doc->enum_type_count];
            (void)memset(et, 0, sizeof(*et));
            ret = copy_attr(et->id, sizeof(et->id), child, "id");
            if (ret != 0) { return ret; }

            for (xmlNode *ev = child->children; ev != NULL; ev = ev->next) {
                if (ev->type != XML_ELEMENT_NODE) { continue; }
                if (strcmp((const char *)ev->name, "EnumVal") != 0) { continue; }
                if (et->val_count >= (size_t)IEC61850_SCL_MAX_ENUM_VALS) { break; }

                iec61850_scl_enum_val_t *v = &et->vals[et->val_count];
                (void)memset(v, 0, sizeof(*v));
                xmlChar *ord_str = xmlGetProp(ev, (const xmlChar *)"ord");
                if (ord_str != NULL) {
                    v->ord = (int32_t)strtol((const char *)ord_str, NULL, 10);
                    xmlFree(ord_str);
                }
                ret = copy_text(v->val, sizeof(v->val), ev);
                if (ret != 0) { return ret; }
                et->val_count++;
            }
            doc->enum_type_count++;
        }
    }
    return 0;
}

/* Parse IED node */
static int parse_ied(xmlNode *ied_node, iec61850_scl_doc_t *doc)
{
    int ret = copy_attr(doc->ied_name, sizeof(doc->ied_name), ied_node, "name");
    if (ret != 0) { return ret; }

    /* Find AccessPoint -> Server -> LDevice */
    for (const xmlNode *ap = ied_node->children; ap != NULL; ap = ap->next) {
        if (ap->type != XML_ELEMENT_NODE) { continue; }
        if (strcmp((const char *)ap->name, "AccessPoint") != 0) { continue; }

        for (const xmlNode *srv = ap->children; srv != NULL; srv = srv->next) {
            if (srv->type != XML_ELEMENT_NODE) { continue; }
            if (strcmp((const char *)srv->name, "Server") != 0) { continue; }

            for (xmlNode *ld = srv->children; ld != NULL; ld = ld->next) {
                if (ld->type != XML_ELEMENT_NODE) { continue; }
                if (strcmp((const char *)ld->name, "LDevice") != 0) { continue; }

                ret = parse_ldevice(ld, doc->ied_name, doc);
                if (ret != 0) { return ret; }
            }
        }
    }
    return 0;
}

/* ======================================================================
 * Input-variant (profile) sniffing — WP-6e
 *
 * All four IEC 61850-6 exchange variants share the SCL schema. The
 * distinctions implemented here:
 *
 *   - SCD:  station-wide file, more than one IED (+ Communication)
 *   - CID:  single IED with a configured Communication section
 *   - IID:  single IED, no Communication, Header carries history
 *           (Ed.2 instance-independent device description)
 *   - ICD:  single IED, no Communication (capability description)
 *
 * A single-IED SCD is content-indistinguishable from a CID and is
 * reported as CID.
 * ====================================================================== */

static bool scl_version_known(const char *version)
{
    return ((strcmp(version, "2003") == 0) ||
            (strcmp(version, "2007") == 0) ||
            (strcmp(version, "2007B") == 0) ||
            (strcmp(version, "2007B2") == 0));
}

static iec61850_scl_profile_t sniff_profile(size_t ied_count,
                                             bool has_communication,
                                             bool has_history)
{
    if (ied_count > 1U) {
        return IEC61850_SCL_PROFILE_SCD;
    }
    if (has_communication) {
        return IEC61850_SCL_PROFILE_CID;
    }
    if (has_history) {
        return IEC61850_SCL_PROFILE_IID;
    }
    return IEC61850_SCL_PROFILE_ICD;
}

const char *iec61850_scl_profile_name(iec61850_scl_profile_t profile)
{
    switch (profile) {
        case IEC61850_SCL_PROFILE_SCD: return "SCD";
        case IEC61850_SCL_PROFILE_ICD: return "ICD";
        case IEC61850_SCL_PROFILE_IID: return "IID";
        case IEC61850_SCL_PROFILE_CID: return "CID";
        default:                        return "UNKNOWN";
    }
}

/* Parse Communication section: GSE/SMV address parameters
 * (VLAN, APPID, MAC) for the selected IED's control blocks. */
static int parse_communication(xmlNode *comm_node, iec61850_scl_doc_t *doc)
{
    for (xmlNode *sn = comm_node->children; sn != NULL; sn = sn->next) {
        if (sn->type != XML_ELEMENT_NODE) { continue; }
        if (strcmp((const char *)sn->name, "SubNetwork") != 0) { continue; }

        for (xmlNode *cap = sn->children; cap != NULL; cap = cap->next) {
            if (cap->type != XML_ELEMENT_NODE) { continue; }
            if (strcmp((const char *)cap->name, "ConnectedAP") != 0) { continue; }

            /* Check iedName matches */
            xmlChar *cap_ied = xmlGetProp(cap, (const xmlChar *)"iedName");
            if (cap_ied == NULL) { continue; }
            bool ied_match = (strcmp((const char *)cap_ied, doc->ied_name) == 0);
            xmlFree(cap_ied);
            if (!ied_match) { continue; }

            for (xmlNode *gse = cap->children; gse != NULL; gse = gse->next) {
                if (gse->type != XML_ELEMENT_NODE) { continue; }
                const char *gse_name = (const char *)gse->name;
                bool is_gse = (strcmp(gse_name, "GSE") == 0);
                bool is_smv = (strcmp(gse_name, "SMV") == 0);
                if ((!is_gse) && (!is_smv)) { continue; }

                char ld_inst[IEC61850_SCL_MAX_NAME] = {0};
                char cb_name[IEC61850_SCL_MAX_NAME] = {0};
                int ret = copy_attr(ld_inst, sizeof(ld_inst), gse, "ldInst");
                if (ret == 0) {
                    ret = copy_attr(cb_name, sizeof(cb_name), gse, "cbName");
                }
                if (ret != 0) { return ret; }

                /* Parse Address/P elements */
                uint16_t vlan_id = 0;
                uint8_t vlan_priority = 0;
                uint16_t app_id = 0;
                uint32_t min_time = 0;
                uint32_t max_time = 0;
                char mac_address[IEC61850_SCL_MAX_MAC] = {0};

                for (xmlNode *addr = gse->children; addr != NULL; addr = addr->next) {
                    if (addr->type != XML_ELEMENT_NODE) { continue; }
                    if (strcmp((const char *)addr->name, "Address") == 0) {
                        for (xmlNode *p = addr->children; p != NULL; p = p->next) {
                            if (p->type != XML_ELEMENT_NODE) { continue; }
                            if (strcmp((const char *)p->name, "P") != 0) { continue; }
                            xmlChar *ptype = xmlGetProp(p, (const xmlChar *)"type");
                            xmlChar *pval = xmlNodeGetContent(p);
                            if ((ptype != NULL) && (pval != NULL)) {
                                if (strcmp((const char *)ptype, "VLAN-ID") == 0) {
                                    vlan_id = (uint16_t)strtoul((const char *)pval, NULL, 0);
                                } else if (strcmp((const char *)ptype, "VLAN-PRIORITY") == 0) {
                                    vlan_priority = (uint8_t)strtoul((const char *)pval, NULL, 10);
                                } else if (strcmp((const char *)ptype, "APPID") == 0) {
                                    app_id = (uint16_t)strtoul((const char *)pval, NULL, 0);
                                } else if (strcmp((const char *)ptype, "MAC-Address") == 0) {
                                    ret = copy_bounded(mac_address, sizeof(mac_address),
                                                        (const char *)pval);
                                    if (ret != 0) {
                                        if (ptype != NULL) { xmlFree(ptype); }
                                        if (pval != NULL) { xmlFree(pval); }
                                        return ret;
                                    }
                                }
                            }
                            if (ptype != NULL) { xmlFree(ptype); }
                            if (pval != NULL) { xmlFree(pval); }
                        }
                    } else if (strcmp((const char *)addr->name, "MinTime") == 0) {
                        xmlChar *val = xmlNodeGetContent(addr);
                        if (val != NULL) { min_time = (uint32_t)strtoul((const char *)val, NULL, 10); xmlFree(val); }
                    } else if (strcmp((const char *)addr->name, "MaxTime") == 0) {
                        xmlChar *val = xmlNodeGetContent(addr);
                        if (val != NULL) { max_time = (uint32_t)strtoul((const char *)val, NULL, 10); xmlFree(val); }
                    }
                }

                /* Match to parsed control blocks and populate. Both the
                 * control-block name and its LDevice must match. */
                if (is_gse) {
                    for (size_t i = 0; i < doc->goose_cb_count; i++) {
                        if ((strcmp(doc->goose_cbs[i].cb_name, cb_name) == 0) &&
                            (strcmp(doc->goose_cbs[i].ld_inst, ld_inst) == 0)) {
                            doc->goose_cbs[i].vlan_id = vlan_id;
                            doc->goose_cbs[i].vlan_priority = vlan_priority;
                            if (app_id != 0U) { doc->goose_cbs[i].app_id = app_id; }
                            if (min_time != 0U) { doc->goose_cbs[i].min_time = min_time; }
                            if (max_time != 0U) { doc->goose_cbs[i].max_time = max_time; }
                            if (mac_address[0] != '\0') {
                                (void)memcpy(doc->goose_cbs[i].mac_address, mac_address,
                                             sizeof(mac_address));
                            }
                        }
                    }
                } else if (is_smv) {
                    for (size_t i = 0; i < doc->sv_cb_count; i++) {
                        if ((strcmp(doc->sv_cbs[i].cb_name, cb_name) == 0) &&
                            (strcmp(doc->sv_cbs[i].ld_inst, ld_inst) == 0)) {
                            doc->sv_cbs[i].vlan_id = vlan_id;
                            doc->sv_cbs[i].vlan_priority = vlan_priority;
                            if (app_id != 0U) { doc->sv_cbs[i].app_id = app_id; }
                            if (mac_address[0] != '\0') {
                                (void)memcpy(doc->sv_cbs[i].mac_address, mac_address,
                                             sizeof(mac_address));
                            }
                        }
                    }
                }
            }
        }
    }
    return 0;
}

int iec61850_scl_parse_file(const char *filename, const char *ied_name, /* NOLINT(bugprone-easily-swappable-parameters) */
                             iec61850_scl_doc_t *doc)
{
    xmlDoc *xml_doc = NULL;
    const xmlNode *root = NULL;
    xmlNode *target_ied = NULL;
    xmlNode *dtt_node = NULL;
    xmlNode *comm_node = NULL;
    size_t ied_count = 0;
    bool has_history = false;
    int result = -ENOENT;

    if ((filename == NULL) || (doc == NULL)) {
        return -EINVAL;
    }

    iec61850_scl_doc_init(doc);

    /* Distinguish "file not readable" from "file is not valid XML" */
    FILE *probe = fopen(filename, "r");
    if (probe == NULL) {
        return -ENOENT;
    }
    (void)fclose(probe);

    xml_doc = xmlReadFile(filename, NULL, XML_PARSE_NONET | XML_PARSE_NOERROR);
    if (xml_doc == NULL) {
        return -EINVAL;
    }

    root = xmlDocGetRootElement(xml_doc);
    if (root == NULL) {
        result = -EINVAL;
        goto cleanup;
    }

    /* Root must be the SCL element (all four exchange variants
     * share it). Namespace prefixes, when present, are tolerated by
     * comparing the local name. */
    if ((root->name == NULL) ||
        (strcmp((const char *)root->name, "SCL") != 0)) {
        result = -EINVAL;
        goto cleanup;
    }

    /* Version attribute: when present it must be a known SCL
     * edition (2003 / 2007 / 2007B / 2007B2). Absence is tolerated
     * (tools omit it), unknown values are rejected. */
    xmlChar *version = xmlGetProp((xmlNode *)root, (const xmlChar *)"version");
    if (version != NULL) {
        bool known = scl_version_known((const char *)version);
        if (known) {
            result = copy_bounded(doc->version, sizeof(doc->version),
                                   (const char *)version);
        } else {
            result = -EINVAL;
        }
        xmlFree(version);
        if (result != 0) {
            goto cleanup;
        }
    }

    /* Single pass over the root children: locate the target IED,
     * the DataTypeTemplates and Communication sections, count the
     * IEDs and detect Header history for profile sniffing. */
    for (xmlNode *child = root->children; child != NULL; child = child->next) {
        if (child->type != XML_ELEMENT_NODE) { continue; }
        const char *name = (const char *)child->name;

        if (strcmp(name, "IED") == 0) {
            ied_count++;

            xmlChar *ied_attr = xmlGetProp(child, (const xmlChar *)"name");
            if (ied_attr == NULL) { continue; }

            bool match;
            if (ied_name == NULL) {
                match = (target_ied == NULL);  /* Take first IED */
            } else {
                match = (strcmp((const char *)ied_attr, ied_name) == 0);
            }
            xmlFree(ied_attr);

            if (match && (target_ied == NULL)) {
                target_ied = child;
            }
        } else if (strcmp(name, "DataTypeTemplates") == 0) {
            if (dtt_node == NULL) { dtt_node = child; }
        } else if (strcmp(name, "Communication") == 0) {
            if (comm_node == NULL) { comm_node = child; }
        } else if (strcmp(name, "Header") == 0) {
            for (xmlNode *h = child->children; h != NULL; h = h->next) {
                if (h->type != XML_ELEMENT_NODE) { continue; }
                if (strcmp((const char *)h->name, "History") == 0) {
                    has_history = true;
                }
            }
        }
    }

    if (target_ied == NULL) {
        result = -ENOENT;
        goto cleanup;
    }

    result = parse_ied(target_ied, doc);
    if (result != 0) { goto cleanup; }

    if (dtt_node != NULL) {
        result = parse_data_type_templates(dtt_node, doc);
        if (result != 0) { goto cleanup; }
    }

    if (comm_node != NULL) {
        result = parse_communication(comm_node, doc);
        if (result != 0) { goto cleanup; }
    }

    doc->profile = sniff_profile(ied_count, comm_node != NULL, has_history);
    result = 0;

cleanup:
    xmlFreeDoc(xml_doc);
    return result;
}

/* ======================================================================
 * Lookup helpers
 * ====================================================================== */

const iec61850_scl_goose_cb_t *iec61850_scl_find_goose_cb(
    const iec61850_scl_doc_t *doc, const char *cb_name)
{
    if ((doc == NULL) || (cb_name == NULL)) { return NULL; }

    for (size_t i = 0; i < doc->goose_cb_count; i++) {
        if (strcmp(doc->goose_cbs[i].cb_name, cb_name) == 0) {
            return &doc->goose_cbs[i];
        }
    }
    return NULL;
}

const iec61850_scl_sv_cb_t *iec61850_scl_find_sv_cb(
    const iec61850_scl_doc_t *doc, const char *cb_name)
{
    if ((doc == NULL) || (cb_name == NULL)) { return NULL; }

    for (size_t i = 0; i < doc->sv_cb_count; i++) {
        if (strcmp(doc->sv_cbs[i].cb_name, cb_name) == 0) {
            return &doc->sv_cbs[i];
        }
    }
    return NULL;
}

const iec61850_scl_rcb_t *iec61850_scl_find_rcb(
    const iec61850_scl_doc_t *doc, const char *rpt_id)
{
    if ((doc == NULL) || (rpt_id == NULL)) { return NULL; }

    for (size_t i = 0; i < doc->rcb_count; i++) {
        if (strcmp(doc->rcbs[i].rpt_id, rpt_id) == 0) {
            return &doc->rcbs[i];
        }
    }
    return NULL;
}

const iec61850_scl_dataset_t *iec61850_scl_find_dataset(
    const iec61850_scl_doc_t *doc, const char *name)
{
    if ((doc == NULL) || (name == NULL)) { return NULL; }

    for (size_t i = 0; i < doc->dataset_count; i++) {
        if (strcmp(doc->datasets[i].name, name) == 0) {
            return &doc->datasets[i];
        }
    }
    return NULL;
}

const iec61850_scl_lnode_type_t *iec61850_scl_find_lnode_type(
    const iec61850_scl_doc_t *doc, const char *id)
{
    if ((doc == NULL) || (id == NULL)) { return NULL; }
    for (size_t i = 0; i < doc->lnode_type_count; i++) {
        if (strcmp(doc->lnode_types[i].id, id) == 0) {
            return &doc->lnode_types[i];
        }
    }
    return NULL;
}

const iec61850_scl_do_type_t *iec61850_scl_find_do_type(
    const iec61850_scl_doc_t *doc, const char *id)
{
    if ((doc == NULL) || (id == NULL)) { return NULL; }
    for (size_t i = 0; i < doc->do_type_count; i++) {
        if (strcmp(doc->do_types[i].id, id) == 0) {
            return &doc->do_types[i];
        }
    }
    return NULL;
}

const iec61850_scl_da_type_t *iec61850_scl_find_da_type(
    const iec61850_scl_doc_t *doc, const char *id)
{
    if ((doc == NULL) || (id == NULL)) { return NULL; }
    for (size_t i = 0; i < doc->da_type_count; i++) {
        if (strcmp(doc->da_types[i].id, id) == 0) {
            return &doc->da_types[i];
        }
    }
    return NULL;
}

const iec61850_scl_enum_type_t *iec61850_scl_find_enum_type(
    const iec61850_scl_doc_t *doc, const char *id)
{
    if ((doc == NULL) || (id == NULL)) { return NULL; }
    for (size_t i = 0; i < doc->enum_type_count; i++) {
        if (strcmp(doc->enum_types[i].id, id) == 0) {
            return &doc->enum_types[i];
        }
    }
    return NULL;
}

const char *iec61850_scl_enum_label(const iec61850_scl_enum_type_t *et,
                                     int32_t ord)
{
    if (et == NULL) { return NULL; }

    for (size_t i = 0; i < et->val_count; i++) {
        if (et->vals[i].ord == ord) {
            return et->vals[i].val;
        }
    }
    return NULL;
}

/* ======================================================================
 * FCDA → DA reference resolution (WP-6e)
 * ====================================================================== */

/* Find an SDO entry by name inside a DOType */
static const iec61850_scl_da_t *find_sdo(const iec61850_scl_do_type_t *dt,
                                          const char *name)
{
    for (size_t i = 0; i < dt->da_count; i++) {
        if ((dt->das[i].is_sdo) && (strcmp(dt->das[i].name, name) == 0)) {
            return &dt->das[i];
        }
    }
    return NULL;
}

/* Find a DA entry by name (and functional constraint, when the FCDA
 * carries one) inside a DOType */
static const iec61850_scl_da_t *find_da(const iec61850_scl_do_type_t *dt,
                                         const char *name, const char *fc)
{
    for (size_t i = 0; i < dt->da_count; i++) {
        if (dt->das[i].is_sdo) { continue; }
        if (strcmp(dt->das[i].name, name) != 0) { continue; }
        if ((fc != NULL) && (fc[0] != '\0') &&
            (strcmp(dt->das[i].fc, fc) != 0)) {
            continue;
        }
        return &dt->das[i];
    }
    return NULL;
}

/* Find a BDA entry by name inside a DAType */
static const iec61850_scl_da_t *find_bda(const iec61850_scl_da_type_t *dat,
                                          const char *name)
{
    for (size_t i = 0; i < dat->bda_count; i++) {
        if (strcmp(dat->bdas[i].name, name) == 0) {
            return &dat->bdas[i];
        }
    }
    return NULL;
}

/* Iterate dot-separated segments of a (bounded, non-NULL) string.
 * Returns the next segment start or NULL when exhausted; *seg_len
 * receives the segment length. */
static const char *next_segment(const char *cursor, size_t *seg_len)
{
    *seg_len = 0U;
    if ((cursor == NULL) || (cursor[0] == '\0')) { return NULL; }

    const char *dot = strchr(cursor, '.');
    if (dot == NULL) {
        *seg_len = strlen(cursor);
        return NULL;  /* last segment */
    }
    *seg_len = (size_t)(dot - cursor);
    return dot + 1;
}

int iec61850_scl_resolve_fcda(const iec61850_scl_doc_t *doc,
                               const iec61850_scl_dataset_t *dataset,
                               size_t index,
                               iec61850_scl_da_path_t *out)
{
    const iec61850_scl_ld_t *ld = NULL;
    const iec61850_scl_ln_ref_t *ln = NULL;
    const iec61850_scl_lnode_type_t *lt = NULL;
    const iec61850_scl_do_type_t *dt = NULL;
    const iec61850_scl_da_type_t *dat = NULL;
    const iec61850_scl_da_t *leaf = NULL;
    char seg[IEC61850_SCL_MAX_NAME];
    const char *cursor;
    size_t seg_len;

    if ((doc == NULL) || (dataset == NULL) || (out == NULL) ||
        (index >= dataset->member_count)) {
        return -EINVAL;
    }

    const iec61850_scl_fcda_t *fcda = &dataset->members[index];

    (void)memset(out, 0, sizeof(*out));

    if (fcda->do_name[0] == '\0') {
        return -ENOENT;  /* whole-LN references are not valid FCDAs */
    }

    /* Locate the referenced Logical Device and Logical Node */
    for (size_t i = 0; i < doc->ld_count; i++) {
        if (strcmp(doc->lds[i].inst, fcda->ld_inst) == 0) {
            ld = &doc->lds[i];
            break;
        }
    }
    if (ld == NULL) { return -ENOENT; }

    for (size_t i = 0; i < ld->ln_count; i++) {
        const iec61850_scl_ln_ref_t *cand = &ld->lns[i];
        if ((strcmp(cand->ln_class, fcda->ln_class) == 0) &&
            (strcmp(cand->ln_prefix, fcda->ln_prefix) == 0) &&
            (strcmp(cand->ln_inst, fcda->ln_inst) == 0)) {
            ln = cand;
            break;
        }
    }
    if (ln == NULL) { return -ENOENT; }

    lt = iec61850_scl_find_lnode_type(doc, ln->ln_type);
    if (lt == NULL) { return -ENOENT; }

    /* Walk the doName segments: first through the LNodeType DOs,
     * then through SDOs of the resolved DOType. */
    cursor = fcda->do_name;
    bool more = true;
    bool first = true;
    while (more) {
        const char *next = next_segment(cursor, &seg_len);
        more = (next != NULL);
        if (seg_len == 0U) { return -ENOENT; }
        if (seg_len >= sizeof(seg)) { return -ENAMETOOLONG; }
        (void)memcpy(seg, cursor, seg_len);
        seg[seg_len] = '\0';

        if (first) {
            const iec61850_scl_do_ref_t *doref = NULL;
            for (size_t i = 0; i < lt->do_count; i++) {
                if (strcmp(lt->dos[i].name, seg) == 0) {
                    doref = &lt->dos[i];
                    break;
                }
            }
            if (doref == NULL) { return -ENOENT; }
            dt = iec61850_scl_find_do_type(doc, doref->type);
            first = false;
        } else {
            const iec61850_scl_da_t *sdo = find_sdo(dt, seg);
            if (sdo == NULL) { return -ENOENT; }
            dt = iec61850_scl_find_do_type(doc, sdo->type);
        }
        if (dt == NULL) { return -ENOENT; }
        cursor = next;
    }

    /* Whole-DO (or whole-SDO) reference: daName absent */
    if (fcda->da_name[0] == '\0') {
        out->whole_do = true;
        out->do_type = dt;
    } else {
        /* Walk the daName segments: through SDOs and DAs of the
         * DOType, then through BDAs of DATypes when descending into
         * Struct leaves. */
        cursor = fcda->da_name;
        bool da_more = true;
        while (da_more) {
            const char *next = next_segment(cursor, &seg_len);
            da_more = (next != NULL);
            if (seg_len == 0U) { return -ENOENT; }
            if (seg_len >= sizeof(seg)) { return -ENAMETOOLONG; }
            (void)memcpy(seg, cursor, seg_len);
            seg[seg_len] = '\0';

            if (dat == NULL) {
                /* DOType context: SDO first, then DA */
                const iec61850_scl_da_t *sdo = find_sdo(dt, seg);
                if (sdo != NULL) {
                    if (!da_more) {
                        /* Reference to a whole SDO */
                        dt = iec61850_scl_find_do_type(doc, sdo->type);
                        if (dt == NULL) { return -ENOENT; }
                        out->whole_do = true;
                        out->do_type = dt;
                        break;
                    }
                    dt = iec61850_scl_find_do_type(doc, sdo->type);
                    if (dt == NULL) { return -ENOENT; }
                    cursor = next;
                    continue;
                }

                const iec61850_scl_da_t *da = find_da(dt, seg, fcda->fc);
                if (da == NULL) { return -ENOENT; }
                leaf = da;
                if (!da_more) { break; }
                if (strcmp(da->btype, "Struct") != 0) { return -ENOENT; }
                dat = iec61850_scl_find_da_type(doc, da->type);
                if (dat == NULL) { return -ENOENT; }
            } else {
                /* DAType context: BDAs */
                const iec61850_scl_da_t *bda = find_bda(dat, seg);
                if (bda == NULL) { return -ENOENT; }
                leaf = bda;
                if (!da_more) { break; }
                if (strcmp(bda->btype, "Struct") != 0) { return -ENOENT; }
                dat = iec61850_scl_find_da_type(doc, bda->type);
                if (dat == NULL) { return -ENOENT; }
            }
            cursor = next;
        }

        if (!out->whole_do) {
            if (leaf == NULL) { return -ENOENT; }
            int ret = copy_bounded(out->btype, sizeof(out->btype), leaf->btype);
            if (ret == 0) {
                ret = copy_bounded(out->type, sizeof(out->type), leaf->type);
            }
            if (ret != 0) { return ret; }

            if (strcmp(leaf->btype, "Enum") == 0) {
                out->enum_type = iec61850_scl_find_enum_type(doc, leaf->type);
            } else if (strcmp(leaf->btype, "Struct") == 0) {
                out->leaf_struct = true;
                out->struct_type = iec61850_scl_find_da_type(doc, leaf->type);
            }
            out->do_type = dt;
        }
    }

    /* Fill identity fields */
    int ret = copy_bounded(out->ld_inst, sizeof(out->ld_inst), fcda->ld_inst);
    if (ret != 0) { return ret; }

    int n = snprintf(out->ln_name, sizeof(out->ln_name), "%s%s%s",
                      fcda->ln_prefix, fcda->ln_class, fcda->ln_inst);
    if ((n < 0) || ((size_t)n >= sizeof(out->ln_name))) {
        return -ENAMETOOLONG;
    }

    if (fcda->da_name[0] == '\0') {
        n = snprintf(out->path, sizeof(out->path), "%s", fcda->do_name);
    } else {
        n = snprintf(out->path, sizeof(out->path), "%s.%s",
                      fcda->do_name, fcda->da_name);
    }
    if ((n < 0) || ((size_t)n >= sizeof(out->path))) {
        return -ENAMETOOLONG;
    }

    ret = copy_bounded(out->fc, sizeof(out->fc), fcda->fc);
    if (ret != 0) { return ret; }

    return 0;
}
