/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Example: MMS Client Report Enrollment
 *
 * Connect to an MMS server, discover its Report Control Blocks,
 * enroll for reporting, and print incoming reports.
 *
 * WP-S1b scaffold — completed by WP-1d.
 *
 * Usage: example_mms_client_report [host] [port]
 */

#include "mms/mms_client.h"
#include "mms/mms_client_rcb.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define REPORT_DURATION_SEC 10

static void on_report(const mms_information_report_t *report,
                       void *user_data)
{
    (void)user_data;
    printf("report: rptID=%s datSet=%s sqNum=%u values=%u\n",
           report->rpt_id, report->dat_set,
           (unsigned)report->sq_num, (unsigned)report->num_values);
    for (uint32_t i = 0; i < report->num_values; i++) {
        if (report->values[i].type == MMS_TYPE_INTEGER) {
            printf("  [%u] = %d\n", (unsigned)i,
                   (int)report->values[i].value.integer);
        }
    }
}

int main(int argc, char **argv)
{
    const char *host = (argc > 1) ? argv[1] : "127.0.0.1";
    int port = (argc > 2) ? atoi(argv[2]) : 10102;

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);

    if (iec61850_mms_client_connect(&client, host, (uint16_t)port,
                                     5000) != 0) {
        printf("connect to %s:%d failed - is an MMS server running?\n",
               host, port);
        return 1;
    }
    printf("connected to %s:%d\n", host, port);

    /* Discover RCBs */
    char names[8][IEC61850_RCB_MAX_NAME];
    uint32_t count = 0;
    if (iec61850_mms_client_rcb_list(&client, "simpleIO", names,
                                       &count, 8) == 0) {
        printf("found %u RCB(s):\n", (unsigned)count);
        for (uint32_t i = 0; i < count; i++) {
            printf("  %s\n", names[i]);
        }
    } else {
        printf("rcb_list failed\n");
    }

    /* Enroll the first RCB and receive reports */
    if (count > 0) {
        iec61850_mms_client_rcb_values_t values;
        memset(&values, 0, sizeof(values));
        if (iec61850_mms_client_set_report_handler(&client, on_report,
                                                      NULL) == 0 &&
            iec61850_mms_client_rcb_get_values(&client, "simpleIO",
                                                 names[0],
                                                 &values) == 0) {
            values.attrs.rpt_ena = true;
            (void)iec61850_mms_client_rcb_set_values(&client, "simpleIO",
                                                       names[0], &values,
                                                       IEC61850_RCB_FIELD_RPT_ENA);
            printf("enrolled %s - receiving reports for %d s\n",
                   names[0], REPORT_DURATION_SEC);
            for (int i = 0; i < REPORT_DURATION_SEC; i++) {
                (void)iec61850_mms_client_poll(&client, 1000);
            }
            (void)iec61850_mms_client_rcb_disable(&client, "simpleIO",
                                                    names[0]);
        }
    }

    (void)iec61850_mms_client_disconnect(&client);
    printf("done\n");
    return 0;
}
