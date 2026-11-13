/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * DIAGNOSTIC ARTIFACT ONLY — WP-ms10-investigation
 *
 * Clean-room wire probe against the libiec61850 oracle server
 * (server_example_basic_io), run through diagnostics/logproxy so both
 * directions are captured. No oracle source is read.
 *
 * Steps:
 *   1. connect (through proxy)
 *   2. GetNameList domains
 *   3. GetNameList named-variable-lists in the domain
 *   4. read_named_varlist() with OUR client's flat wire format
 *   5. hand-crafted STANDARD MMS Read (variableListName, domain-specific
 *      ObjectName with 0x1A string tags) submitted via the core API
 *
 *   ./ms10_oracle_probe <port>
 */

#include "mms/mms_client.h"
#include "mms/mms_client_core.h"
#include "asn1/mms_ber.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

static void dump(const char *label, const uint8_t *b, size_t n)
{
    printf("--- %s (%zu bytes) ---\n", label, n);
    for (size_t i = 0; i < n; i++) {
        printf("%02X ", b[i]);
        if ((i % 16) == 15) printf("\n");
    }
    printf("\n");
    fflush(stdout);
}

static void probe_cb(int status, const mms_confirmed_response_t *resp,
                     const mms_confirmed_error_t *err, void *ud)
{
    int *done = ud;
    *done = 1;
    printf("probe: delivery status=%d\n", status);
    if (err != NULL) {
        printf("probe: ConfirmedError class=%d code=%d\n",
               err->error.error_class, err->error.error_code);
    } else if (resp != NULL) {
        printf("probe: ConfirmedResponse service=%d (READ_NVL=%d)\n",
               resp->service, MMS_SERVICE_TYPE_READ_NAMED_VARLIST);
        if (resp->service == MMS_SERVICE_TYPE_READ_NAMED_VARLIST) {
            printf("probe:   num_values=%u\n",
                   resp->params.readnamedvarlist.num_values);
        }
    } else {
        printf("probe: delivered with neither resp nor err\n");
    }
}

int main(int argc, char **argv)
{
    if (argc != 2) { fprintf(stderr, "usage: %s <port>\n", argv[0]); return 1; }
    uint16_t port = (uint16_t)atoi(argv[1]);

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", port, 5000);
    printf("connect = %d\n", ret);
    if (ret != IEC61850_MMS_CLIENT_OK) return 1;

    char domains[8][MMS_MAX_VARIABLE_NAME];
    uint32_t ndom = 0;
    ret = iec61850_mms_client_get_name_list(&client, MMS_OBJECT_CLASS_DOMAIN,
                                             NULL, domains, &ndom, 8);
    printf("get_name_list(domains) = %d, ndom=%u\n", ret, ndom);
    for (uint32_t i = 0; i < ndom; i++) printf("  domain[%u] = %s\n", i, domains[i]);
    if (ndom == 0) return 1;
    const char *dom = domains[0];

    char lists[16][MMS_MAX_VARIABLE_NAME];
    uint32_t nlist = 0;
    ret = iec61850_mms_client_get_name_list(
        &client, MMS_OBJECT_CLASS_NAMED_VARIABLE_LIST, dom, lists, &nlist, 16);
    printf("get_name_list(nvl in %s) = %d, nlist=%u\n", dom, ret, nlist);
    for (uint32_t i = 0; i < nlist; i++) printf("  list[%u] = %s\n", i, lists[i]);

    if (nlist > 0) {
        /* 4. our flat format */
        mms_value_t values[8];
        uint32_t nv = 0;
        ret = iec61850_mms_client_read_named_varlist(&client, dom, lists[0],
                                                      values, &nv, 8);
        printf("read_named_varlist(\"%s\",\"%s\") [OUR FLAT FORMAT] = %d nv=%u\n",
               dom, lists[0], ret, nv);

        /* 5. hand-crafted standard format, same invoke-id space */
        uint8_t pdu[512];
        size_t o = 0;
        size_t dom_len = strlen(dom);
        size_t ls_len = strlen(lists[0]);
        size_t inner = 2 + 2 + dom_len + 2 + ls_len; /* A1 L 1A dl dom 1A nl name */
        size_t vas  = 2 + inner;                     /* A1 L <inner>          */
        size_t rd   = 2 + vas;                       /* A4 L <vas>            */
        size_t body = 3 + rd;                        /* 80 01 <id> <read>     */

        pdu[o++] = 0xA0;                     /* confirmedRequest */
        pdu[o++] = (uint8_t)(body + 1);      /* total length     */
        pdu[o++] = 0x80; pdu[o++] = 0x01; pdu[o++] = 0x55;  /* invokeID 85 */
        pdu[o++] = 0xA4; pdu[o++] = (uint8_t)rd;
        pdu[o++] = 0xA1; pdu[o++] = (uint8_t)vas;
        pdu[o++] = 0xA1; pdu[o++] = (uint8_t)inner;
        pdu[o++] = 0x1A; pdu[o++] = (uint8_t)dom_len;
        memcpy(pdu + o, dom, dom_len); o += dom_len;
        pdu[o++] = 0x1A; pdu[o++] = (uint8_t)ls_len;
        memcpy(pdu + o, lists[0], ls_len); o += ls_len;

        dump("hand-crafted STANDARD Read PDU", pdu, o);

        int done = 0;
        ret = iec61850_mms_client_core_submit(&client.core, pdu, o, 85,
                                               probe_cb, &done);
        printf("core_submit = %d\n", ret);
        if (ret == 0) {
            ret = iec61850_mms_client_core_wait(&client.core, 85, 3000);
            printf("core_wait = %d done=%d\n", ret, done);
        }
    }

    iec61850_mms_client_disconnect(&client);
    return 0;
}
