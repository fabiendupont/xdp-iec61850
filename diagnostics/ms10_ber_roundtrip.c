/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * DIAGNOSTIC ARTIFACT ONLY — WP-ms10-investigation
 *
 * BER round-trip reproducer (no sockets, no oracle): encodes the exact
 * Read-named-variable-list request that iec61850_mms_client_read_named_varlist()
 * puts on the wire, then feeds it to our own server-side decoder and prints
 * what the server would see. Demonstrates the MS-10 root cause.
 */

#include "asn1/mms_ber.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    mms_confirmed_request_t req;
    mms_confirmed_request_t decoded;
    uint8_t buf[4096];
    int ret;

    memset(&req, 0, sizeof(req));
    req.invoke_id = 3;
    req.service = MMS_SERVICE_TYPE_READ_NAMED_VARLIST;
    strncpy(req.params.readnamedvarlist.domain, "IED1LD0",
            MMS_MAX_DOMAIN_NAME - 1);
    strncpy(req.params.readnamedvarlist.list_name, "TestList",
            (size_t)MMS_MAX_VARIABLE_NAME - 1U);

    ret = mms_encode_confirmed_request(&req, buf, sizeof(buf));
    if (ret <= 0) { printf("encode failed: %d\n", ret); return 1; }

    printf("encoded %d bytes:\n", ret);
    for (int i = 0; i < ret; i++) {
        printf("%02X ", buf[i]);
        if ((i % 16) == 15) printf("\n");
    }
    printf("\n\n");

    memset(&decoded, 0, sizeof(decoded));
    ret = mms_decode_confirmed_request(buf, (size_t)ret, &decoded);
    printf("decode ret = %d\n", ret);
    printf("decoded.service     = %d (READ_NAMED_VARLIST=%d READ=%d)\n",
           decoded.service, MMS_SERVICE_TYPE_READ_NAMED_VARLIST,
           MMS_SERVICE_TYPE_READ);
    if (decoded.service == MMS_SERVICE_TYPE_READ_NAMED_VARLIST) {
        printf("decoded.domain     = \"%s\"\n", decoded.params.readnamedvarlist.domain);
        printf("decoded.list_name  = \"%s\"\n", decoded.params.readnamedvarlist.list_name);
    } else if (decoded.service == MMS_SERVICE_TYPE_READ) {
        printf("decoded.domain     = \"%s\"\n", decoded.params.read.variable_spec.domain);
        printf("decoded.item_id    = \"%s\"\n", decoded.params.read.variable_spec.item_id);
    }

    return 0;
}
