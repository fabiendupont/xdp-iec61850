/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Client RCB Enrollment for IEC 61850 (Ed.2)
 *
 * WP-S1 scaffold: all operations return -ENOSYS until WP-1c
 * (client-rcb) implements them against the frozen interface in
 * include/iec61850/mms/mms_client_rcb.h.
 */

#include "mms/mms_client_rcb.h"

#include <errno.h>

int iec61850_mms_client_rcb_list(iec61850_mms_client_t *client,
                                  const char *domain,
                                  char names[][IEC61850_RCB_MAX_NAME],
                                  uint32_t *count, uint32_t max_count)
{
    (void)client;
    (void)domain;
    (void)names;
    (void)count;
    (void)max_count;
    return -ENOSYS; /* implemented by WP-1c */
}

int iec61850_mms_client_rcb_get_values(iec61850_mms_client_t *client,
                                        const char *domain,
                                        const char *rcb_name,
                                        iec61850_mms_client_rcb_values_t *out)
{
    (void)client;
    (void)domain;
    (void)rcb_name;
    (void)out;
    return -ENOSYS; /* implemented by WP-1c */
}

int iec61850_mms_client_rcb_set_values(iec61850_mms_client_t *client,
                                        const char *domain,
                                        const char *rcb_name,
                                        const iec61850_mms_client_rcb_values_t *in,
                                        uint32_t field_mask)
{
    (void)client;
    (void)domain;
    (void)rcb_name;
    (void)in;
    (void)field_mask;
    return -ENOSYS; /* implemented by WP-1c */
}

int iec61850_mms_client_rcb_enable(iec61850_mms_client_t *client,
                                    const char *domain,
                                    const char *rcb_name)
{
    (void)client;
    (void)domain;
    (void)rcb_name;
    return -ENOSYS; /* implemented by WP-1c */
}

int iec61850_mms_client_rcb_disable(iec61850_mms_client_t *client,
                                     const char *domain,
                                     const char *rcb_name)
{
    (void)client;
    (void)domain;
    (void)rcb_name;
    return -ENOSYS; /* implemented by WP-1c */
}

int iec61850_mms_client_rcb_purge_buffer(iec61850_mms_client_t *client,
                                          const char *domain,
                                          const char *rcb_name)
{
    (void)client;
    (void)domain;
    (void)rcb_name;
    return -ENOSYS; /* implemented by WP-1c */
}

int iec61850_mms_client_rcb_set_entry_id(iec61850_mms_client_t *client,
                                          const char *domain,
                                          const char *rcb_name,
                                          uint64_t entry_id)
{
    (void)client;
    (void)domain;
    (void)rcb_name;
    (void)entry_id;
    return -ENOSYS; /* implemented by WP-1c */
}

int iec61850_mms_client_set_report_handler(iec61850_mms_client_t *client,
                                            iec61850_mms_client_report_cb cb,
                                            void *user_data)
{
    (void)client;
    (void)cb;
    (void)user_data;
    return -ENOSYS; /* implemented by WP-1c */
}
