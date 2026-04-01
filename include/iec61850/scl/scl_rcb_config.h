/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * SCL Report Control Block Auto-Configuration
 *
 * Extracts ReportControl configurations from parsed SCL documents
 * and auto-creates RCBs in an RCB manager, using the binding manager
 * to connect RCBs to data sets.
 *
 * License: BSD-3-Clause
 */

#ifndef IEC61850_SCL_RCB_CONFIG_H
#define IEC61850_SCL_RCB_CONFIG_H

#include "scl/scl_parser.h"
#include "mms/mms_report.h"
#include "mms/mms_data_store.h"

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * RCB configuration extracted from SCL ReportControl element.
 *
 * This is a self-contained snapshot of one ReportControl block,
 * suitable for creating an RCB without the original SCL document.
 */
typedef struct {
    char rpt_id[IEC61850_SCL_MAX_NAME];
    char dat_set[IEC61850_SCL_MAX_NAME];
    char ied_name[IEC61850_SCL_MAX_NAME];
    char ld_inst[IEC61850_SCL_MAX_NAME];
    uint32_t conf_rev;
    bool buffered;
    uint32_t buf_time;    /* Buffer time ms (BRCB only) */
    uint32_t intg_pd;     /* Integrity period ms */
    iec61850_trg_ops_t trg_ops;
    iec61850_opt_flds_t opt_flds;
    uint8_t rpt_enabled_max;
} iec61850_scl_rcb_config_t;

/**
 * Extract RCB configurations from a parsed SCL document.
 *
 * Iterates all ReportControl elements in the SCL document and
 * populates the output array with self-contained config structs.
 *
 * @param doc       Parsed SCL document
 * @param configs   Output array of RCB configs
 * @param max_count Maximum entries in configs array
 * @param count     Output: number of configs extracted
 * @return 0 on success, negative errno on error
 */
int iec61850_scl_get_rcb_configs(const iec61850_scl_doc_t *doc,
                                  iec61850_scl_rcb_config_t *configs,
                                  size_t max_count, size_t *count);

/**
 * Auto-create RCBs from SCL into an RCB manager.
 *
 * Parses the SCL document for ReportControl elements and creates
 * corresponding RCBs (BRCB or URCB) in the RCB manager with
 * matching trigger options, optional fields, timing, and data set
 * references.  Optionally binds data sets to MMS data store
 * variables when a data store is provided.
 *
 * Duplicate RCBs (matching rptID already in the manager) are
 * silently skipped.
 *
 * @param doc        Parsed SCL document
 * @param mgr        RCB manager (must be initialized)
 * @param data_store MMS data store for data set binding (may be NULL)
 * @return Number of RCBs created (>= 0), negative errno on error
 */
int iec61850_scl_auto_create_rcbs(const iec61850_scl_doc_t *doc,
                                   iec61850_rcb_manager_t *mgr,
                                   iec61850_mms_data_store_t *data_store);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_SCL_RCB_CONFIG_H */
