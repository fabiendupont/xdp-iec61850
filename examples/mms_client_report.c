/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Example: MMS Client Report Enrollment
 *
 * Connect to an MMS server, discover its domains and Report Control
 * Blocks, read an RCB's values, enroll for reporting (URCB or
 * BRCB), and print incoming reports.
 *
 * Cross-validated (WP-1d) against a libiec61850 server used as a
 * black-box oracle. Two oracle conventions are handled explicitly:
 *
 *   - RCB components are addressed as "<RCB path>$<Component>"
 *     ("LLN0$RP$EventsRCB01$RptEna"). The client API builds
 *     component names by appending the suffix to the RCB name, so
 *     the names discovered from the server's name list are passed
 *     verbatim with their trailing "$".
 *   - The oracle's BRCBs default to report options that include the
 *     buffer-overflow field, which this client's report decoder
 *     does not parse (see WP-1d, BUG-R4). Enrollment therefore
 *     configures OptFlds explicitly (without buffer-overflow)
 *     before enabling — a standard Ed.2 client procedure.
 *
 * Usage:
 *   example_mms_client_report [host] [port] [options]
 * Options:
 *   -d         discover only: list domains, variables, RCBs; exit
 *   -b         enroll a buffered RCB (BRCB) instead of a URCB
 *   -t SECS    receive reports for SECS seconds (default 10)
 *
 * Example (against libiec61850's server_example_basic_io):
 *   server_example_basic_io 10102 &
 *   example_mms_client_report 127.0.0.1 10102 -b -t 5
 */

#include "mms/mms_client.h"
#include "mms/mms_client_rcb.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define REPORT_DURATION_SEC 10
#define DISCOVER_MAX_VARS   600
#define DISCOVER_MAX_RCBS   8

static void print_value(const mms_value_t *v)
{
    switch (v->type) {
        case MMS_TYPE_BOOLEAN:
            printf("%s", v->value.boolean ? "true" : "false");
            break;
        case MMS_TYPE_INTEGER:
            printf("%d", (int)v->value.integer);
            break;
        case MMS_TYPE_UNSIGNED:
            printf("%u", (unsigned)v->value.unsigned_val);
            break;
        case MMS_TYPE_FLOATING_POINT:
            printf("%f", (double)v->value.floating_point);
            break;
        case MMS_TYPE_VISIBLE_STRING:
            printf("'%s'", v->value.visible_string.data);
            break;
        case MMS_TYPE_OCTET_STRING:
            printf("0x");
            for (size_t i = 0; i < v->value.octet_string.len; i++) {
                printf("%02x", v->value.octet_string.data[i]);
            }
            break;
        case MMS_TYPE_BIT_STRING:
            printf("0x");
            for (size_t i = 0;
                 i < (v->value.bit_string.bit_count + 7U) / 8U; i++) {
                printf("%02x", v->value.bit_string.data[i]);
            }
            break;
        default:
            printf("<type %d>", (int)v->type);
            break;
    }
}

static void on_report(const mms_information_report_t *report,
                       void *user_data)
{
    (void)user_data;
    printf("report: rptID=%s datSet=%s sqNum=%u values=%u\n",
           report->rpt_id, report->dat_set,
           (unsigned)report->sq_num, (unsigned)report->num_values);
    if (report->report_timestamp_present) {
        printf("  timeOfEntry = 0x%llx\n",
               (unsigned long long)report->report_timestamp);
    }
    if (report->buffer_overflow_present) {
        printf("  bufferOverflow = %s\n",
               report->buffer_overflow ? "true" : "false");
    }
    if (report->entry_id_present) {
        printf("  EntryID = 0x%016llx\n",
               (unsigned long long)report->entry_id);
    }
    for (uint32_t i = 0; i < report->num_values; i++) {
        printf("  [%u] = ", (unsigned)i);
        print_value(&report->values[i]);
        if (report->reasons_present) {
            printf("  (reason 0x%02x)", report->reasons[i]);
        }
        printf("\n");
    }
}

static void discover_domains(iec61850_mms_client_t *client)
{
    char domains[32][MMS_MAX_DOMAIN_NAME];
    uint32_t count = 0;

    if (iec61850_mms_client_get_name_list(client,
                                          MMS_OBJECT_CLASS_DOMAIN,
                                          NULL, domains, &count, 32) != 0) {
        printf("domain list failed\n");
        return;
    }
    printf("found %u domain(s):\n", (unsigned)count);
    for (uint32_t i = 0; i < count; i++) {
        printf("  %s\n", domains[i]);
    }
}

/*
 * Discover the RCBs in the server's first domain. Tries the client's
 * rcb_list first; when the server's model is too large for its
 * internal scan window, falls back to a full GetNameList sweep
 * filtered on the RptEna component pattern. Discovered names keep
 * their trailing "$" (see the file header).
 */
static uint32_t discover_rcbs(iec61850_mms_client_t *client,
                               char domain[], size_t domain_size,
                               char names[][IEC61850_RCB_MAX_NAME],
                               uint32_t max_names)
{
    char domains[32][MMS_MAX_DOMAIN_NAME];
    uint32_t dcount = 0;
    uint32_t count = 0;

    if (iec61850_mms_client_get_name_list(client,
                                          MMS_OBJECT_CLASS_DOMAIN,
                                          NULL, domains, &dcount,
                                          32) != 0 || dcount == 0) {
        printf("domain discovery failed\n");
        return 0;
    }
    (void)snprintf(domain, domain_size, "%s", domains[0]);

    if ((iec61850_mms_client_rcb_list(client, domain, names,
                                       &count, max_names) == 0) &&
        (count > 0U)) {
        return count;
    }

    /* Fallback: full named-variable sweep. */
    static char vars[DISCOVER_MAX_VARS][MMS_MAX_VARIABLE_NAME];
    uint32_t vcount = 0;
    if (iec61850_mms_client_get_name_list(client,
                                          MMS_OBJECT_CLASS_NAMED_VARIABLE,
                                          domain, vars, &vcount,
                                          DISCOVER_MAX_VARS) != 0) {
        return 0;
    }
    count = 0;
    for (uint32_t i = 0; i < vcount && count < max_names; i++) {
        size_t len = strlen(vars[i]);
        if ((len > 6U) && (strcmp(&vars[i][len - 6U], "RptEna") == 0)) {
            size_t base = len - 6U;
            if (base >= IEC61850_RCB_MAX_NAME) {
                base = IEC61850_RCB_MAX_NAME - 1U;
            }
            (void)memcpy(names[count], vars[i], base);
            names[count][base] = '\0';
            count++;
        }
    }
    return count;
}

/* Read and print one RCB component (best effort). */
static void show_component(iec61850_mms_client_t *client,
                            const char *domain, const char *rcb_ref,
                            const char *suffix)
{
    char item[MMS_MAX_VARIABLE_NAME];
    mms_value_t v;

    (void)snprintf(item, sizeof(item), "%s%s", rcb_ref, suffix);
    (void)memset(&v, 0, sizeof(v));
    if (iec61850_mms_client_read(client, domain, item, &v) == 0) {
        printf("  %-8s = ", suffix);
        print_value(&v);
        printf("\n");
    }
}

int main(int argc, char **argv)
{
    const char *host = (argc > 1) ? argv[1] : "127.0.0.1";
    int port = (argc > 2) ? atoi(argv[2]) : 10102;
    int duration = REPORT_DURATION_SEC;
    bool discover_only = false;
    bool use_brcb = false;

    int argi = 3;
    while (argi < argc) {
        if (strcmp(argv[argi], "-d") == 0) {
            discover_only = true;
        } else if (strcmp(argv[argi], "-b") == 0) {
            use_brcb = true;
        } else if ((strcmp(argv[argi], "-t") == 0) &&
                   ((argi + 1) < argc)) {
            duration = atoi(argv[++argi]);
        } else {
            fprintf(stderr,
                    "usage: %s [host] [port] [-d] [-b] [-t SECS]\n",
                    argv[0]);
            return 2;
        }
        argi++;
    }

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    /* Keep absent-component reads (some servers reject them in-band)
     * from stalling the demo for the full default timeout. */
    client.request_timeout_ms = 3000;

    if (iec61850_mms_client_connect(&client, host, (uint16_t)port,
                                     5000) != 0) {
        printf("connect to %s:%d failed - is an MMS server running?\n",
               host, port);
        return 1;
    }
    printf("connected to %s:%d\n", host, port);

    if (discover_only) {
        char domains[32][MMS_MAX_DOMAIN_NAME];
        uint32_t dcount = 0;
        discover_domains(&client);
        if (iec61850_mms_client_get_name_list(&client,
                                               MMS_OBJECT_CLASS_DOMAIN,
                                               NULL, domains, &dcount,
                                               32) == 0) {
            for (uint32_t d = 0; d < dcount; d++) {
                static char vars[DISCOVER_MAX_VARS][MMS_MAX_VARIABLE_NAME];
                uint32_t vcount = 0;
                if (iec61850_mms_client_get_name_list(
                        &client, MMS_OBJECT_CLASS_NAMED_VARIABLE,
                        domains[d], vars, &vcount,
                        DISCOVER_MAX_VARS) == 0) {
                    printf("variables in %s (%u):\n", domains[d],
                           (unsigned)vcount);
                    for (uint32_t i = 0; i < vcount; i++) {
                        printf("  %s\n", vars[i]);
                    }
                }
            }
        }
        (void)iec61850_mms_client_disconnect(&client);
        printf("done\n");
        return 0;
    }

    /* Discover the domain and its RCBs. */
    char domain[MMS_MAX_DOMAIN_NAME];
    char names[DISCOVER_MAX_RCBS][IEC61850_RCB_MAX_NAME];
    uint32_t count = discover_rcbs(&client, domain, sizeof(domain),
                                    names, DISCOVER_MAX_RCBS);
    printf("found %u RCB(s) in %s:\n", (unsigned)count, domain);
    for (uint32_t i = 0; i < count; i++) {
        printf("  %s\n", names[i]);
    }

    /* Pick an RCB: buffered (-b) or the first unbuffered one. */
    int selected = -1;
    for (uint32_t i = 0; i < count; i++) {
        bool is_brcb = strstr(names[i], "$BR$") != NULL;
        if (is_brcb == use_brcb) {
            selected = (int)i;
            break;
        }
    }
    if (selected < 0) {
        printf("no %s RCB found in the server model\n",
               use_brcb ? "buffered" : "unbuffered");
        (void)iec61850_mms_client_disconnect(&client);
        return 1;
    }
    const char *rcb_ref = names[selected];

    /* Show the RCB's current component values (best effort: servers
     * may not implement every optional component). */
    printf("RCB %s:\n", rcb_ref);
    show_component(&client, domain, rcb_ref, "RptID");
    show_component(&client, domain, rcb_ref, "DatSet");
    show_component(&client, domain, rcb_ref, "ConfRev");
    show_component(&client, domain, rcb_ref, "OptFlds");
    show_component(&client, domain, rcb_ref, "TrgOps");
    show_component(&client, domain, rcb_ref, "BufTm");
    show_component(&client, domain, rcb_ref, "IntgPd");
    show_component(&client, domain, rcb_ref, "SqNum");
    if (use_brcb) {
        show_component(&client, domain, rcb_ref, "EntryID");
    }

    /* Enroll and receive reports. */
    if (iec61850_mms_client_set_report_handler(&client, on_report,
                                                NULL) != 0) {
        printf("installing the report handler failed\n");
        (void)iec61850_mms_client_disconnect(&client);
        return 1;
    }

    iec61850_mms_client_rcb_values_t values;
    (void)memset(&values, 0, sizeof(values));
    values.attrs.rpt_ena = true;
    if (!use_brcb) {
        /* URCB: reserve first, then enable. */
        values.resv = true;
    } else {
        /* BRCB: configure the report options explicitly (see file
         * header) before enabling; no reservation needed. */
        values.attrs.opt_flds.sequence_number = true;
        values.attrs.opt_flds.report_timestamp = true;
        values.attrs.opt_flds.reason_for_inclusion = true;
        values.attrs.opt_flds.data_set_name = true;
        values.attrs.opt_flds.config_ref = true;
    }
    uint32_t mask = IEC61850_RCB_FIELD_RPT_ENA |
                    (use_brcb ? IEC61850_RCB_FIELD_OPT_FLDS
                              : IEC61850_RCB_FIELD_RESV);
    int rc = iec61850_mms_client_rcb_set_values(&client, domain, rcb_ref,
                                                 &values, mask);
    printf("enrolled %s (rc=%d) - receiving reports for %d s\n",
           rcb_ref, rc, duration);

    for (int i = 0; i < duration; i++) {
        (void)iec61850_mms_client_poll(&client, 1000);
    }

    (void)iec61850_mms_client_rcb_disable(&client, domain, rcb_ref);
    (void)iec61850_mms_client_disconnect(&client);
    printf("disconnected\ndone\n");
    return 0;
}
