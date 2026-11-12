/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * SCL Report Control Block Auto-Configuration
 *
 * Extracts ReportControl configurations from parsed SCL documents
 * and creates RCBs in an RCB manager with proper trigger options,
 * optional fields, timing, and data set references.
 *
 * License: BSD-2-Clause
 */

#include "scl/scl_rcb_config.h"

#include <errno.h>
#include <string.h>

/*
 * Convert a parsed SCL RCB entry to an scl_rcb_config_t.
 */
static void scl_rcb_to_config(const iec61850_scl_rcb_t *scl_rcb,
                               iec61850_scl_rcb_config_t *cfg)
{
    (void)memset(cfg, 0, sizeof(*cfg));

    (void)strncpy(cfg->rpt_id, scl_rcb->rpt_id,
                   IEC61850_SCL_MAX_NAME - 1);
    (void)strncpy(cfg->dat_set, scl_rcb->dataset,
                   IEC61850_SCL_MAX_NAME - 1);
    (void)strncpy(cfg->ied_name, scl_rcb->ied_name,
                   IEC61850_SCL_MAX_NAME - 1);
    (void)strncpy(cfg->ld_inst, scl_rcb->ld_inst,
                   IEC61850_SCL_MAX_NAME - 1);

    cfg->conf_rev         = scl_rcb->conf_rev;
    cfg->buffered         = scl_rcb->buffered;
    cfg->buf_time         = scl_rcb->buf_time;
    cfg->intg_pd          = scl_rcb->intg_pd;
    cfg->rpt_enabled_max  = scl_rcb->rpt_enabled_max;

    cfg->trg_ops.data_change           = scl_rcb->trg_dchg;
    cfg->trg_ops.quality_change        = scl_rcb->trg_qchg;
    cfg->trg_ops.data_update           = scl_rcb->trg_dupd;
    cfg->trg_ops.integrity             = scl_rcb->trg_period;
    cfg->trg_ops.general_interrogation = scl_rcb->trg_gi;

    cfg->opt_flds.sequence_number      = scl_rcb->opt_seq_num;
    cfg->opt_flds.report_timestamp     = scl_rcb->opt_timestamp;
    cfg->opt_flds.reason_for_inclusion = scl_rcb->opt_reason;
    cfg->opt_flds.data_reference       = scl_rcb->opt_dataref;
    cfg->opt_flds.entry_id             = scl_rcb->opt_entryid;
    cfg->opt_flds.buffer_overflow      = scl_rcb->opt_bufovfl;
    cfg->opt_flds.config_ref           = scl_rcb->opt_configref;
}

/*
 * Apply a config to an RCB that was just added to the manager.
 */
static void apply_config_to_rcb(iec61850_rcb_t *rcb,
                                 const iec61850_scl_rcb_config_t *cfg)
{
    rcb->attrs.trg_ops   = cfg->trg_ops;
    rcb->attrs.opt_flds  = cfg->opt_flds;
    rcb->attrs.conf_rev  = cfg->conf_rev;
    rcb->attrs.buf_tm    = cfg->buf_time;
    rcb->attrs.intg_pd   = cfg->intg_pd;

    (void)strncpy(rcb->attrs.dat_set, cfg->dat_set,
                   IEC61850_RCB_MAX_NAME - 1);
}

int iec61850_scl_get_rcb_configs(const iec61850_scl_doc_t *doc,
                                  iec61850_scl_rcb_config_t *configs,
                                  size_t max_count, size_t *count)
{
    if ((doc == NULL) || (configs == NULL) || (count == NULL)) {
        return -EINVAL;
    }

    *count = 0;

    for (size_t i = 0; (i < doc->rcb_count) && (*count < max_count); i++) {
        scl_rcb_to_config(&doc->rcbs[i], &configs[*count]);
        (*count)++;
    }

    return 0;
}

int iec61850_scl_auto_create_rcbs(const iec61850_scl_doc_t *doc,
                                   iec61850_rcb_manager_t *mgr,
                                   iec61850_mms_data_store_t *data_store)
{
    if ((doc == NULL) || (mgr == NULL)) {
        return -EINVAL;
    }

    int created = 0;

    for (size_t i = 0; i < doc->rcb_count; i++) {
        iec61850_scl_rcb_config_t cfg;
        scl_rcb_to_config(&doc->rcbs[i], &cfg);

        /* Skip duplicates: if an RCB with this rptID already exists */
        if (iec61850_rcb_manager_find_rcb(mgr, cfg.rpt_id) != NULL) {
            continue;
        }

        iec61850_rcb_type_t type = cfg.buffered ?
            IEC61850_RCB_BUFFERED : IEC61850_RCB_UNBUFFERED;

        uint32_t buf_size = 0;
        if (type == IEC61850_RCB_BUFFERED) {
            buf_size = IEC61850_RCB_MAX_BUFFER;
        }

        int idx = iec61850_rcb_manager_add_rcb(mgr, cfg.rpt_id,
                                                type, buf_size);
        if (idx < 0) {
            continue;
        }

        apply_config_to_rcb(&mgr->rcbs[idx], &cfg);

        /*
         * If a data store is provided, attach it to the RCB so that
         * GI snapshots can read current values.  The data set name
         * is already recorded in dat_set for runtime resolution.
         */
        if (data_store != NULL) {
            mgr->rcbs[idx].data_store = data_store;
        }

        created++;
    }

    return created;
}
