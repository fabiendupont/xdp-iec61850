/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * SCL-to-IED Model Builder
 *
 * Builds a complete iec61850_ied_model_t from parsed SCL data.
 * Creates LD/LN/DO/DA hierarchy and auto-configures RCBs.
 */

#ifndef IEC61850_SCL_IED_BUILDER_H
#define IEC61850_SCL_IED_BUILDER_H

#include "scl/scl_parser.h"
#include "ied/ied_data_model.h"
#include "mms/mms_data_store.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Build an IED model from parsed SCL document.
 *
 * Creates LogicalDevice/LogicalNode hierarchy from the SCL parse result.
 * For known LN classes (LLN0, LPHD, XCBR, XSWI, MMXU, PTOC, CSWI, GGIO),
 * creates standard CDC data objects.
 *
 * @param doc    Parsed SCL document
 * @param model  Output IED model (must be initialized)
 * @return 0 on success, negative on error
 */
int iec61850_scl_build_ied_model(const iec61850_scl_doc_t *doc,
                                   iec61850_ied_model_t *model);

/**
 * Auto-configure RCBs from parsed SCL document into an RCB manager.
 *
 * For each ReportControl block in the SCL, creates a BRCB or URCB
 * with matching trigger options, optional fields, and buffer size.
 *
 * @param doc   Parsed SCL document
 * @param mgr   RCB manager (must be initialized)
 * @return Number of RCBs configured (>= 0), negative on error
 */
/**
 * Register IED model variables into an MMS data store.
 *
 * Creates MMS domains from logical devices (IEDName + LDInst)
 * and registers all data attributes as MMS named variables
 * using IEC 61850-8-1 naming: LN$FC$DO$DA.
 *
 * @param model       IED data model (built via iec61850_scl_build_ied_model)
 * @param data_store  MMS data store (must be initialized)
 * @return Number of variables registered (>= 0), negative on error
 */
int iec61850_ied_model_register_mms(const iec61850_ied_model_t *model,
                                      iec61850_mms_data_store_t *data_store);

struct iec61850_rcb_manager_t;  /* forward declaration */
int iec61850_scl_auto_configure_rcbs(const iec61850_scl_doc_t *doc,
                                       void *mgr);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_SCL_IED_BUILDER_H */
