/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * DIAGNOSTIC ARTIFACT ONLY — WP-ms10-investigation
 *
 * Minimal reproducer for the MS-10 (named-variable-list lifecycle)
 * pre-existing failure. Mirrors test_ms10_named_varlist() from
 * tests/interop/mms/test_mms_interop_server.c but prints the return
 * code of every step so the failing exchange can be pinpointed.
 *
 * Not part of the test suite; do not wire into meson.
 */

#include "mms/mms_server.h"
#include "mms/mms_client.h"
#include "mms/mms_data_store.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
    static iec61850_mms_data_store_t ds;
    static iec61850_mms_server_t server;
    const uint16_t port = 10777;
    int ret;

    iec61850_mms_ds_init(&ds);
    iec61850_mms_ds_create_domain(&ds, "IED1LD0");

    mms_value_t val;
    memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;
    val.value.integer = 1;
    iec61850_mms_ds_create_variable(&ds, "IED1LD0", "LLN0$ST$Beh$stVal",
                                     MMS_TYPE_INTEGER, &val);
    val.type = MMS_TYPE_BOOLEAN;
    val.value.boolean = false;
    iec61850_mms_ds_create_variable(&ds, "IED1LD0", "GGIO1$ST$SPCSO1$stVal",
                                     MMS_TYPE_BOOLEAN, &val);

    iec61850_mms_server_config_t cfg;
    iec61850_mms_server_config_init(&cfg);
    cfg.port = port;
    iec61850_mms_server_init(&server, &cfg, &ds);
    ret = iec61850_mms_server_start(&server);
    printf("server_start           = %d\n", ret);
    if (ret != IEC61850_MMS_SERVER_OK) return 1;
    usleep(200000);

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    ret = iec61850_mms_client_connect(&client, "127.0.0.1", port, 5000);
    printf("client_connect         = %d\n", ret);
    if (ret != IEC61850_MMS_CLIENT_OK) return 1;

    mms_variable_spec_t vars[2];
    memset(vars, 0, sizeof(vars));
    strncpy(vars[0].domain, "IED1LD0", MMS_MAX_DOMAIN_NAME - 1);
    strncpy(vars[0].item_id, "LLN0$ST$Beh$stVal", MMS_MAX_VARIABLE_NAME - 1);
    strncpy(vars[1].domain, "IED1LD0", MMS_MAX_DOMAIN_NAME - 1);
    strncpy(vars[1].item_id, "GGIO1$ST$SPCSO1$stVal", MMS_MAX_VARIABLE_NAME - 1);

    ret = iec61850_mms_client_define_named_varlist(&client, "IED1LD0",
                                                    "TestList", vars, 2);
    printf("define_named_varlist   = %d\n", ret);

    if (ret == IEC61850_MMS_CLIENT_OK) {
        mms_value_t values[8];
        uint32_t num_values = 0;
        ret = iec61850_mms_client_read_named_varlist(&client, "IED1LD0",
                                                      "TestList", values,
                                                      &num_values, 8);
        printf("read_named_varlist     = %d (num_values=%u)\n", ret, num_values);

        if (ret == IEC61850_MMS_CLIENT_OK) {
            ret = iec61850_mms_client_delete_named_varlist(&client, "IED1LD0",
                                                            "TestList");
            printf("delete_named_varlist   = %d\n", ret);
        }
    }

    iec61850_mms_client_disconnect(&client);
    iec61850_mms_server_stop(&server);
    iec61850_mms_ds_destroy(&ds);
    return 0;
}
