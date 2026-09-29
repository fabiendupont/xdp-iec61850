/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * SCL Parser Implementation using libxml2
 *
 * License: BSD-3-Clause
 */

#include "scl/scl_parser.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <stdlib.h>
#include <string.h>

void iec61850_scl_doc_init(iec61850_scl_doc_t *doc)
{
    if (doc != NULL) {
        (void)memset(doc, 0, sizeof(*doc));
    }
}

/* Safe string copy into fixed buffer, free xmlChar */
static void copy_attr(char *dst, size_t dst_size, xmlNode *node,
                        const char *attr_name)
{
    xmlChar *val = xmlGetProp(node, (const xmlChar *)attr_name);
    if (val != NULL) {
        (void)strncpy(dst, (const char *)val, dst_size - 1U);
        dst[dst_size - 1U] = '\0';
        xmlFree(val);
    } else {
        dst[0] = '\0';
    }
}

/* Parse GSEControl inside LN0 */
static void parse_gse_control(xmlNode *gse_node, const char *ied_name,
                                const char *ld_inst, iec61850_scl_doc_t *doc)
{
    if (doc->goose_cb_count >= (size_t)IEC61850_SCL_MAX_CBS) { return; }

    iec61850_scl_goose_cb_t *cb = &doc->goose_cbs[doc->goose_cb_count];
    (void)memset(cb, 0, sizeof(*cb));

    (void)strncpy(cb->ied_name, ied_name, (size_t)IEC61850_SCL_MAX_NAME - 1U);
    (void)strncpy(cb->ld_inst, ld_inst, (size_t)IEC61850_SCL_MAX_NAME - 1U);
    copy_attr(cb->cb_name, sizeof(cb->cb_name), gse_node, "name");
    copy_attr(cb->dataset, sizeof(cb->dataset), gse_node, "datSet");

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
    copy_attr(cb->go_id, sizeof(cb->go_id), gse_node, "goID");

    doc->goose_cb_count++;
}

/* Parse SampledValueControl inside LN0 */
static void parse_sv_control(xmlNode *sv_node, const char *ied_name,
                               const char *ld_inst, iec61850_scl_doc_t *doc)
{
    if (doc->sv_cb_count >= (size_t)IEC61850_SCL_MAX_CBS) { return; }

    iec61850_scl_sv_cb_t *cb = &doc->sv_cbs[doc->sv_cb_count];
    (void)memset(cb, 0, sizeof(*cb));

    (void)strncpy(cb->ied_name, ied_name, (size_t)IEC61850_SCL_MAX_NAME - 1U);
    (void)strncpy(cb->ld_inst, ld_inst, (size_t)IEC61850_SCL_MAX_NAME - 1U);
    copy_attr(cb->cb_name, sizeof(cb->cb_name), sv_node, "name");
    copy_attr(cb->dataset, sizeof(cb->dataset), sv_node, "datSet");
    copy_attr(cb->sv_id, sizeof(cb->sv_id), sv_node, "smvID");

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
static void parse_report_control(xmlNode *rcb_node, const char *ied_name,
                                   const char *ld_inst, iec61850_scl_doc_t *doc)
{
    if (doc->rcb_count >= (size_t)IEC61850_SCL_MAX_RCBS) { return; }

    iec61850_scl_rcb_t *rcb = &doc->rcbs[doc->rcb_count];
    (void)memset(rcb, 0, sizeof(*rcb));

    (void)strncpy(rcb->ied_name, ied_name, (size_t)IEC61850_SCL_MAX_NAME - 1U);
    (void)strncpy(rcb->ld_inst, ld_inst, (size_t)IEC61850_SCL_MAX_NAME - 1U);
    copy_attr(rcb->rpt_id, sizeof(rcb->rpt_id), rcb_node, "rptID");
    copy_attr(rcb->dataset, sizeof(rcb->dataset), rcb_node, "datSet");
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
}

/* Parse DataSet inside LN0 */
static void parse_dataset(xmlNode *ds_node, iec61850_scl_doc_t *doc)
{
    if (doc->dataset_count >= (size_t)IEC61850_SCL_MAX_DATASETS) { return; }

    iec61850_scl_dataset_t *ds = &doc->datasets[doc->dataset_count];
    (void)memset(ds, 0, sizeof(*ds));

    copy_attr(ds->name, sizeof(ds->name), ds_node, "name");

    /* Parse FCDA members */
    for (xmlNode *fcda = ds_node->children; fcda != NULL; fcda = fcda->next) {
        if (fcda->type != XML_ELEMENT_NODE) { continue; }
        if (strcmp((const char *)fcda->name, "FCDA") != 0) { continue; }
        if (ds->member_count >= (size_t)IEC61850_SCL_MAX_DS_MEMBERS) { break; }

        iec61850_scl_fcda_t *m = &ds->members[ds->member_count];
        (void)memset(m, 0, sizeof(*m));

        copy_attr(m->ld_inst, sizeof(m->ld_inst), fcda, "ldInst");
        copy_attr(m->ln_prefix, sizeof(m->ln_prefix), fcda, "prefix");
        copy_attr(m->ln_class, sizeof(m->ln_class), fcda, "lnClass");
        copy_attr(m->ln_inst, sizeof(m->ln_inst), fcda, "lnInst");
        copy_attr(m->do_name, sizeof(m->do_name), fcda, "doName");
        copy_attr(m->da_name, sizeof(m->da_name), fcda, "daName");
        copy_attr(m->fc, sizeof(m->fc), fcda, "fc");

        ds->member_count++;
    }

    doc->dataset_count++;
}

/* Parse LN0 children for control blocks and datasets */
static void parse_ln0(const xmlNode *ln0_node, const char *ied_name,
                        const char *ld_inst, iec61850_scl_doc_t *doc)
{
    for (xmlNode *child = ln0_node->children; child != NULL; child = child->next) {
        if (child->type != XML_ELEMENT_NODE) { continue; }
        const char *name = (const char *)child->name;

        if (strcmp(name, "GSEControl") == 0) {
            parse_gse_control(child, ied_name, ld_inst, doc);
        } else if (strcmp(name, "SampledValueControl") == 0) {
            parse_sv_control(child, ied_name, ld_inst, doc);
        } else if (strcmp(name, "ReportControl") == 0) {
            parse_report_control(child, ied_name, ld_inst, doc);
        } else if (strcmp(name, "DataSet") == 0) {
            parse_dataset(child, doc);
        }
    }
}

/* Parse LDevice children for LN definitions and control blocks */
static void parse_ldevice(xmlNode *ld_node, const char *ied_name,
                            iec61850_scl_doc_t *doc)
{
    if (doc->ld_count >= (size_t)IEC61850_SCL_MAX_LDS) {
        return;
    }

    iec61850_scl_ld_t *ld = &doc->lds[doc->ld_count];
    (void)memset(ld, 0, sizeof(*ld));
    copy_attr(ld->inst, sizeof(ld->inst), ld_node, "inst");

    for (xmlNode *child = ld_node->children; child != NULL; child = child->next) {
        if (child->type != XML_ELEMENT_NODE) { continue; }
        if (ld->ln_count >= (size_t)IEC61850_SCL_MAX_LNS) { break; }

        const char *name = (const char *)child->name;

        if (strcmp(name, "LN0") == 0) {
            iec61850_scl_ln_ref_t *ln = &ld->lns[ld->ln_count];
            (void)memset(ln, 0, sizeof(*ln));
            copy_attr(ln->ln_class, sizeof(ln->ln_class), child, "lnClass");
            copy_attr(ln->ln_inst, sizeof(ln->ln_inst), child, "inst");
            copy_attr(ln->ln_type, sizeof(ln->ln_type), child, "lnType");
            copy_attr(ln->ln_prefix, sizeof(ln->ln_prefix), child, "prefix");
            ld->ln_count++;

            /* Parse control blocks inside LN0 */
            parse_ln0(child, ied_name, ld->inst, doc);
        } else if (strcmp(name, "LN") == 0) {
            iec61850_scl_ln_ref_t *ln = &ld->lns[ld->ln_count];
            (void)memset(ln, 0, sizeof(*ln));
            copy_attr(ln->ln_class, sizeof(ln->ln_class), child, "lnClass");
            copy_attr(ln->ln_inst, sizeof(ln->ln_inst), child, "inst");
            copy_attr(ln->ln_type, sizeof(ln->ln_type), child, "lnType");
            copy_attr(ln->ln_prefix, sizeof(ln->ln_prefix), child, "prefix");
            ld->ln_count++;

            /* Parse DataSets inside LN */
            for (xmlNode *lnchild = child->children; lnchild != NULL;
                 lnchild = lnchild->next) {
                if (lnchild->type != XML_ELEMENT_NODE) { continue; }
                if (strcmp((const char *)lnchild->name, "DataSet") == 0) {
                    parse_dataset(lnchild, doc);
                }
            }
        }
    }

    doc->ld_count++;
}

/* Parse DataTypeTemplates section */
static void parse_data_type_templates(xmlNode *dtt_node, iec61850_scl_doc_t *doc)
{
    for (xmlNode *child = dtt_node->children; child != NULL; child = child->next) {
        if (child->type != XML_ELEMENT_NODE) { continue; }
        const char *name = (const char *)child->name;

        if (strcmp(name, "LNodeType") == 0) {
            if (doc->lnode_type_count >= (size_t)IEC61850_SCL_MAX_LNODE_TYPES) { continue; }
            iec61850_scl_lnode_type_t *lt = &doc->lnode_types[doc->lnode_type_count];
            (void)memset(lt, 0, sizeof(*lt));
            copy_attr(lt->id, sizeof(lt->id), child, "id");
            copy_attr(lt->ln_class, sizeof(lt->ln_class), child, "lnClass");

            for (xmlNode *do_child = child->children; do_child != NULL;
                 do_child = do_child->next) {
                if (do_child->type != XML_ELEMENT_NODE) { continue; }
                if (strcmp((const char *)do_child->name, "DO") != 0) { continue; }
                if (lt->do_count >= (size_t)IEC61850_SCL_MAX_TYPE_DOS) { break; }

                iec61850_scl_do_ref_t *doref = &lt->dos[lt->do_count];
                copy_attr(doref->name, sizeof(doref->name), do_child, "name");
                copy_attr(doref->type, sizeof(doref->type), do_child, "type");
                lt->do_count++;
            }
            doc->lnode_type_count++;

        } else if (strcmp(name, "DOType") == 0) {
            if (doc->do_type_count >= (size_t)IEC61850_SCL_MAX_DO_TYPES) { continue; }
            iec61850_scl_do_type_t *dt = &doc->do_types[doc->do_type_count];
            (void)memset(dt, 0, sizeof(*dt));
            copy_attr(dt->id, sizeof(dt->id), child, "id");
            copy_attr(dt->cdc, sizeof(dt->cdc), child, "cdc");

            for (xmlNode *da_child = child->children; da_child != NULL;
                 da_child = da_child->next) {
                if (da_child->type != XML_ELEMENT_NODE) { continue; }
                const char *da_name = (const char *)da_child->name;
                if ((strcmp(da_name, "DA") != 0) && (strcmp(da_name, "SDO") != 0)) {
                    continue;
                }
                if (dt->da_count >= (size_t)IEC61850_SCL_MAX_TYPE_DAS) { break; }

                iec61850_scl_da_t *da = &dt->das[dt->da_count];
                (void)memset(da, 0, sizeof(*da));
                copy_attr(da->name, sizeof(da->name), da_child, "name");
                copy_attr(da->fc, sizeof(da->fc), da_child, "fc");
                copy_attr(da->btype, sizeof(da->btype), da_child, "bType");
                copy_attr(da->type, sizeof(da->type), da_child, "type");

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
            copy_attr(dat->id, sizeof(dat->id), child, "id");

            for (xmlNode *bda = child->children; bda != NULL; bda = bda->next) {
                if (bda->type != XML_ELEMENT_NODE) { continue; }
                if (strcmp((const char *)bda->name, "BDA") != 0) { continue; }
                if (dat->bda_count >= (size_t)IEC61850_SCL_MAX_TYPE_DAS) { break; }

                iec61850_scl_da_t *b = &dat->bdas[dat->bda_count];
                (void)memset(b, 0, sizeof(*b));
                copy_attr(b->name, sizeof(b->name), bda, "name");
                copy_attr(b->btype, sizeof(b->btype), bda, "bType");
                copy_attr(b->type, sizeof(b->type), bda, "type");
                dat->bda_count++;
            }
            doc->da_type_count++;

        } else if (strcmp(name, "EnumType") == 0) {
            if (doc->enum_type_count >= (size_t)IEC61850_SCL_MAX_ENUM_TYPES) { continue; }
            iec61850_scl_enum_type_t *et = &doc->enum_types[doc->enum_type_count];
            (void)memset(et, 0, sizeof(*et));
            copy_attr(et->id, sizeof(et->id), child, "id");

            for (xmlNode *ev = child->children; ev != NULL; ev = ev->next) {
                if (ev->type != XML_ELEMENT_NODE) { continue; }
                if (strcmp((const char *)ev->name, "EnumVal") != 0) { continue; }
                if (et->val_count >= (size_t)IEC61850_SCL_MAX_ENUM_VALS) { break; }

                iec61850_scl_enum_val_t *v = &et->vals[et->val_count];
                xmlChar *ord_str = xmlGetProp(ev, (const xmlChar *)"ord");
                if (ord_str != NULL) {
                    v->ord = (int32_t)strtol((const char *)ord_str, NULL, 10);
                    xmlFree(ord_str);
                }
                xmlChar *val_content = xmlNodeGetContent(ev);
                if (val_content != NULL) {
                    (void)strncpy(v->val, (const char *)val_content,
                                  (size_t)IEC61850_SCL_MAX_NAME - 1U);
                    xmlFree(val_content);
                }
                et->val_count++;
            }
            doc->enum_type_count++;
        }
    }
}

/* Parse IED node */
static void parse_ied(xmlNode *ied_node, iec61850_scl_doc_t *doc)
{
    copy_attr(doc->ied_name, sizeof(doc->ied_name), ied_node, "name");

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

                parse_ldevice(ld, doc->ied_name, doc);
            }
        }
    }
}

int iec61850_scl_parse_file(const char *filename, const char *ied_name,
                             iec61850_scl_doc_t *doc)
{
    xmlDoc *xml_doc = NULL;
    const xmlNode *root = NULL;
    int result = -1;

    if ((filename == NULL) || (doc == NULL)) {
        return -1;
    }

    iec61850_scl_doc_init(doc);

    xml_doc = xmlReadFile(filename, NULL, XML_PARSE_NONET | XML_PARSE_NOERROR);
    if (xml_doc == NULL) {
        goto done;
    }

    root = xmlDocGetRootElement(xml_doc);
    if (root == NULL) {
        goto cleanup;
    }

    /* Find the target IED */
    for (xmlNode *child = root->children; child != NULL; child = child->next) {
        if (child->type != XML_ELEMENT_NODE) { continue; }
        if (strcmp((const char *)child->name, "IED") != 0) { continue; }

        xmlChar *name = xmlGetProp(child, (const xmlChar *)"name");
        if (name == NULL) { continue; }

        bool match;
        if (ied_name == NULL) {
            match = true;  /* Take first IED */
        } else {
            match = (strcmp((const char *)name, ied_name) == 0);
        }
        xmlFree(name);

        if (match) {
            parse_ied(child, doc);
            result = 0;
            break;
        }
    }

    /* Parse DataTypeTemplates section */
    for (xmlNode *child = root->children; child != NULL; child = child->next) {
        if (child->type != XML_ELEMENT_NODE) { continue; }
        if (strcmp((const char *)child->name, "DataTypeTemplates") == 0) {
            parse_data_type_templates(child, doc);
            break;
        }
    }

    /* Parse Communication section for GSE/SMV address parameters (VLAN, APPID, MAC) */
    if (result == 0) {
        for (xmlNode *child = root->children; child != NULL; child = child->next) {
            if (child->type != XML_ELEMENT_NODE) { continue; }
            if (strcmp((const char *)child->name, "Communication") != 0) { continue; }

            for (xmlNode *sn = child->children; sn != NULL; sn = sn->next) {
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
                        copy_attr(ld_inst, sizeof(ld_inst), gse, "ldInst");
                        copy_attr(cb_name, sizeof(cb_name), gse, "cbName");

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
                                            (void)strncpy(mac_address, (const char *)pval,
                                                          (size_t)IEC61850_SCL_MAX_MAC - 1U);
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

                        /* Match to parsed control blocks and populate */
                        if (is_gse) {
                            for (size_t i = 0; i < doc->goose_cb_count; i++) {
                                if (strcmp(doc->goose_cbs[i].cb_name, cb_name) == 0) {
                                    doc->goose_cbs[i].vlan_id = vlan_id;
                                    doc->goose_cbs[i].vlan_priority = vlan_priority;
                                    if (app_id != 0U) { doc->goose_cbs[i].app_id = app_id; }
                                    if (min_time != 0U) { doc->goose_cbs[i].min_time = min_time; }
                                    if (max_time != 0U) { doc->goose_cbs[i].max_time = max_time; }
                                    if (mac_address[0] != '\0') {
                                        (void)strncpy(doc->goose_cbs[i].mac_address, mac_address,
                                                      (size_t)IEC61850_SCL_MAX_MAC - 1U);
                                    }
                                }
                            }
                        } else if (is_smv) {
                            for (size_t i = 0; i < doc->sv_cb_count; i++) {
                                if (strcmp(doc->sv_cbs[i].cb_name, cb_name) == 0) {
                                    doc->sv_cbs[i].vlan_id = vlan_id;
                                    doc->sv_cbs[i].vlan_priority = vlan_priority;
                                    if (app_id != 0U) { doc->sv_cbs[i].app_id = app_id; }
                                    if (mac_address[0] != '\0') {
                                        (void)strncpy(doc->sv_cbs[i].mac_address, mac_address,
                                                      (size_t)IEC61850_SCL_MAX_MAC - 1U);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

cleanup:
    xmlFreeDoc(xml_doc);
done:
    return result;
}

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
