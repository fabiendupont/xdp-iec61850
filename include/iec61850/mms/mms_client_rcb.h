/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Client Report Control Block Enrollment for IEC 61850 (Ed.2)
 *
 * Client-side reporting: discover RCBs on a server, read/write their
 * components, enable/disable reporting, and receive reports through
 * the client's report handler. BRCB (buffered) resume after
 * reconnect via EntryID.
 *
 * FROZEN INTERFACE (WP-S1). Implementations change; signatures do not.
 * Change requests go to the orchestrator, not the implementing WP.
 */

#ifndef IEC61850_MMS_CLIENT_RCB_H
#define IEC61850_MMS_CLIENT_RCB_H

#include "mms/mms_client.h"
#include "mms/mms_report.h"

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* RCB component values as read from / written to the server.
 * iec61850_rcb_attrs_t carries rpt_id, rpt_ena, dat_set, conf_rev,
 * opt_flds, trg_ops, buf_tm, intg_pd, sq_num, gi, entry_id. */
typedef struct {
    iec61850_rcb_attrs_t attrs;

    bool resv;                                /* reservation flag (URCB) */
    bool owner_present;                       /* Owner was readable */
    char owner[IEC61850_RCB_MAX_NAME];        /* owning client identity */
    bool buffered;                            /* BRCB (true) vs URCB */
} iec61850_mms_client_rcb_values_t;

/* Component selection mask for set_values (bitwise OR). */
typedef enum {
    IEC61850_RCB_FIELD_RPT_ID    = 1U << 0,
    IEC61850_RCB_FIELD_RPT_ENA   = 1U << 1,
    IEC61850_RCB_FIELD_RESV      = 1U << 2,
    IEC61850_RCB_FIELD_DAT_SET   = 1U << 3,
    IEC61850_RCB_FIELD_CONF_REV  = 1U << 4,
    IEC61850_RCB_FIELD_OPT_FLDS  = 1U << 5,
    IEC61850_RCB_FIELD_TRG_OPS   = 1U << 6,
    IEC61850_RCB_FIELD_BUF_TM    = 1U << 7,
    IEC61850_RCB_FIELD_INTG_PD   = 1U << 8,
    IEC61850_RCB_FIELD_GI        = 1U << 9,
    IEC61850_RCB_FIELD_ENTRY_ID  = 1U << 10,
    IEC61850_RCB_FIELD_PURGE_BUF = 1U << 11
} iec61850_mms_rcb_field_t;

/*
 * Report handler: invoked for every InformationReport received on the
 * client's association (decoded 61850 report metadata included).
 */
typedef void (*iec61850_mms_client_report_cb)(
    const mms_information_report_t *report, void *user_data);

/**
 * List the RCBs in a domain (GetNameList on the RCB objects).
 *
 * @param names     Output: RCB names.
 * @param count     Output: number of names written.
 * @param max_count Capacity of names.
 * @return 0, or negative IEC61850_MMS_CLIENT_ERR_*.
 */
int iec61850_mms_client_rcb_list(iec61850_mms_client_t *client,
                                  const char *domain,
                                  char names[][IEC61850_RCB_MAX_NAME],
                                  uint32_t *count, uint32_t max_count);

/**
 * Read all components of one RCB (Read on each RCB component object).
 * @return 0, or negative IEC61850_MMS_CLIENT_ERR_*.
 */
int iec61850_mms_client_rcb_get_values(iec61850_mms_client_t *client,
                                        const char *domain,
                                        const char *rcb_name,
                                        iec61850_mms_client_rcb_values_t *out);

/**
 * Write the selected RCB components (Write on RCB component objects,
 * in the order mandated by IEC 61850-8-1 Ed.2 client procedures).
 * Components are applied field by field; a mid-sequence failure
 * stops and returns the error.
 *
 * @param field_mask Bitwise OR of iec61850_mms_rcb_field_t values.
 * @return 0, or negative IEC61850_MMS_CLIENT_ERR_*.
 */
int iec61850_mms_client_rcb_set_values(iec61850_mms_client_t *client,
                                        const char *domain,
                                        const char *rcb_name,
                                        const iec61850_mms_client_rcb_values_t *in,
                                        uint32_t field_mask);

/**
 * Enable reporting (RptEna = TRUE). For URCBs the reservation
 * (Resv) must already be set; use set_values with
 * IEC61850_RCB_FIELD_RESV first.
 * @return 0, or negative IEC61850_MMS_CLIENT_ERR_*.
 */
int iec61850_mms_client_rcb_enable(iec61850_mms_client_t *client,
                                    const char *domain,
                                    const char *rcb_name);

/**
 * Disable reporting (RptEna = FALSE; releases URCB reservation).
 * @return 0, or negative IEC61850_MMS_CLIENT_ERR_*.
 */
int iec61850_mms_client_rcb_disable(iec61850_mms_client_t *client,
                                     const char *domain,
                                     const char *rcb_name);

/**
 * Purge a BRCB's buffer (PurgeBuf = TRUE).
 * @return 0, or negative IEC61850_MMS_CLIENT_ERR_*.
 */
int iec61850_mms_client_rcb_purge_buffer(iec61850_mms_client_t *client,
                                          const char *domain,
                                          const char *rcb_name);

/**
 * Set the BRCB EntryID for resume-after-reconnect.
 * @return 0, or negative IEC61850_MMS_CLIENT_ERR_*.
 */
int iec61850_mms_client_rcb_set_entry_id(iec61850_mms_client_t *client,
                                          const char *domain,
                                          const char *rcb_name,
                                          uint64_t entry_id);

/**
 * Install the report handler on the client's association.
 * @return 0, or negative IEC61850_MMS_CLIENT_ERR_*.
 */
int iec61850_mms_client_set_report_handler(iec61850_mms_client_t *client,
                                            iec61850_mms_client_report_cb cb,
                                            void *user_data);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_MMS_CLIENT_RCB_H */
