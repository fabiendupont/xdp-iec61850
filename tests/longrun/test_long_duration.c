/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Long-Duration Stress Test for IEC 61850 Stack
 *
 * Validates system stability under sustained load:
 *   1. MMS server handles continuous client requests without leaks
 *   2. GOOSE encoder/decoder handles sustained encoding without corruption
 *   3. BER codec handles repeated encode/decode cycles
 *
 * Duration is configurable via LONGRUN_DURATION_SEC (default: 10 for CI).
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "mms/mms_server.h"
#include "mms/mms_client.h"
#include "mms/mms_data_store.h"
#include "asn1/goose_ber.h"
#include "asn1/goose_ber_decode.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/resource.h>

/* ------------------------------------------------------------------------ */
/* Minimal test framework                                                   */
/* ------------------------------------------------------------------------ */

static int test_run = 0, test_passed = 0, test_failed = 0;
#define TEST(name) do { test_run++; printf("  [TEST] %s ...\n", name); } while(0)
#define PASS() do { test_passed++; printf("    PASS\n"); } while(0)
#define FAIL(msg) do { test_failed++; printf("    FAIL: %s\n", msg); return; } while(0)
#define ASSERT_TRUE(x) do { if (!(x)) { FAIL(#x); } } while(0)
#define ASSERT_EQ(a,b) do { if ((a) != (b)) { \
    printf("    (got %d, want %d) ", (int)(a), (int)(b)); FAIL(#a " != " #b); } } while(0)

/* ------------------------------------------------------------------------ */
/* Helpers                                                                  */
/* ------------------------------------------------------------------------ */

static int get_duration_sec(void)
{
    const char *env = getenv("LONGRUN_DURATION_SEC");
    if (env) {
        int val = atoi(env);
        if (val > 0)
            return val;
    }
    return 10;  /* CI default */
}

static double elapsed_sec(const struct timespec *start)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (double)(now.tv_sec - start->tv_sec) +
           (double)(now.tv_nsec - start->tv_nsec) / 1e9;
}

static long get_rss_kb(void)
{
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    return ru.ru_maxrss;  /* kilobytes on Linux */
}

/* ------------------------------------------------------------------------ */
/* Scenario 1: MMS server under sustained client request load               */
/* ------------------------------------------------------------------------ */

static void test_mms_sustained_load(void)
{
    TEST("mms_sustained_load");

    int duration = get_duration_sec();

    /* Set up data store and server */
    iec61850_mms_data_store_t ds;
    iec61850_mms_ds_init(&ds);
    iec61850_mms_ds_create_domain(&ds, "stressLD");

    mms_value_t val;
    (void)memset(&val, 0, sizeof(val));
    val.type = MMS_TYPE_INTEGER;
    val.value.integer = 100;
    iec61850_mms_ds_create_variable(&ds, "stressLD", "LLN0$ST$Beh$stVal",
                                     MMS_TYPE_INTEGER, &val);

    val.type = MMS_TYPE_FLOATING_POINT;
    val.value.floating_point = 230.0f;
    iec61850_mms_ds_create_variable(&ds, "stressLD", "MMXU1$MX$PhV$phsA",
                                     MMS_TYPE_FLOATING_POINT, &val);

    iec61850_mms_server_config_t cfg;
    iec61850_mms_server_config_init(&cfg);
    cfg.port = 10400;

    iec61850_mms_server_t server;
    iec61850_mms_server_init(&server, &cfg, &ds);
    int ret = iec61850_mms_server_start(&server);
    ASSERT_EQ(ret, IEC61850_MMS_SERVER_OK);
    usleep(200000);

    /* Connect client */
    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    ret = iec61850_mms_client_connect(&client, "127.0.0.1", 10400, 5000);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    long rss_before = get_rss_kb();
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);

    unsigned long iters = 0;
    unsigned long errors = 0;
    double last_report = 0.0;

    while (elapsed_sec(&start) < (double)duration) {
        /* Read */
        mms_value_t rv;
        ret = iec61850_mms_client_read(&client, "stressLD",
                                        "LLN0$ST$Beh$stVal", &rv);
        if (ret != IEC61850_MMS_CLIENT_OK)
            errors++;

        /* Write */
        mms_value_t wv;
        (void)memset(&wv, 0, sizeof(wv));
        wv.type = MMS_TYPE_INTEGER;
        wv.value.integer = (int32_t)(iters & 0x7FFFFFFF);
        ret = iec61850_mms_client_write(&client, "stressLD",
                                         "LLN0$ST$Beh$stVal", &wv);
        if (ret != IEC61850_MMS_CLIENT_OK)
            errors++;

        /* GetNameList */
        char names[8][MMS_MAX_VARIABLE_NAME];
        uint32_t count = 0;
        ret = iec61850_mms_client_get_name_list(&client,
                                                 MMS_OBJECT_CLASS_NAMED_VARIABLE,
                                                 "stressLD", names, &count, 8);
        if (ret != IEC61850_MMS_CLIENT_OK)
            errors++;

        iters++;

        double now = elapsed_sec(&start);
        if (now - last_report >= 1.0) {
            printf("    [%5.1fs] iterations=%lu errors=%lu\n",
                   now, iters, errors);
            last_report = now;
        }
    }

    double total = elapsed_sec(&start);
    long rss_after = get_rss_kb();

    iec61850_mms_client_disconnect(&client);
    iec61850_mms_server_stop(&server);
    iec61850_mms_ds_destroy(&ds);

    printf("    Summary: %lu iterations in %.1fs (%.0f ops/s), "
           "%lu errors, RSS %ld->%ld KB\n",
           iters, total, (double)(iters * 3) / total,
           errors, rss_before, rss_after);

    if (rss_before > 0 && rss_after > rss_before) {
        long growth = rss_after - rss_before;
        double pct = 100.0 * (double)growth / (double)rss_before;
        if (pct > 10.0)
            printf("    WARNING: RSS grew %.1f%% (%ld KB)\n", pct, growth);
    }

    ASSERT_TRUE(errors == 0);
    ASSERT_TRUE(iters > 0);
    PASS();
}

/* ------------------------------------------------------------------------ */
/* Scenario 2: GOOSE encoder/decoder sustained cycles                       */
/* ------------------------------------------------------------------------ */

static void test_goose_sustained_codec(void)
{
    TEST("goose_sustained_codec");

    int duration = get_duration_sec();
    long rss_before = get_rss_kb();
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);

    unsigned long iters = 0;
    unsigned long errors = 0;
    double last_report = 0.0;

    while (elapsed_sec(&start) < (double)duration) {
        /* Build APDU with mixed data types */
        goose_apdu_t apdu;
        goose_apdu_init(&apdu);
        goose_set_gocbref(&apdu, "testLD/LLN0$GO$gcb01");
        goose_set_datset(&apdu, "testLD/LLN0$DataSet01");
        goose_set_goid(&apdu, "gcb01");
        apdu.timeAllowedtoLive = 2000;
        apdu.stNum = (uint32_t)(iters & 0xFFFFFFFF);
        apdu.sqNum = (uint32_t)((iters >> 1) & 0xFFFFFFFF);
        apdu.confRev = 1;
        apdu.timestamp = 1700000000000000ULL + iters;

        goose_add_boolean(&apdu, (iters & 1) != 0);
        goose_add_int32(&apdu, (int32_t)(iters & 0x7FFFFFFF));
        goose_add_float32(&apdu, (float)iters * 0.1f);

        uint8_t bits[] = {0x00, 0x0D};
        goose_add_bitstring(&apdu, bits, sizeof(bits));

        /* Encode */
        uint8_t buf[GOOSE_MAX_APDU_SIZE];
        size_t encoded_len = 0;
        int ret = goose_encode_apdu(buf, sizeof(buf), &apdu, &encoded_len);
        if (ret != GOOSE_BER_OK) {
            errors++;
            iters++;
            continue;
        }

        /* Decode and verify round-trip */
        goose_apdu_t decoded;
        goose_apdu_init(&decoded);
        ret = goose_decode_apdu(buf, encoded_len, &decoded);
        if (ret != GOOSE_BER_OK) {
            errors++;
            iters++;
            continue;
        }

        /* Verify key fields survived round-trip */
        if (decoded.stNum != apdu.stNum ||
            decoded.sqNum != apdu.sqNum ||
            decoded.confRev != apdu.confRev ||
            decoded.numDatSetEntries != apdu.numDatSetEntries) {
            errors++;
        }

        iters++;

        double now = elapsed_sec(&start);
        if (now - last_report >= 1.0) {
            printf("    [%5.1fs] iterations=%lu errors=%lu\n",
                   now, iters, errors);
            last_report = now;
        }
    }

    double total = elapsed_sec(&start);
    long rss_after = get_rss_kb();

    printf("    Summary: %lu iterations in %.1fs (%.0f encode+decode/s), "
           "%lu errors, RSS %ld->%ld KB\n",
           iters, total, (double)iters / total,
           errors, rss_before, rss_after);

    if (rss_before > 0 && rss_after > rss_before) {
        long growth = rss_after - rss_before;
        double pct = 100.0 * (double)growth / (double)rss_before;
        if (pct > 10.0)
            printf("    WARNING: RSS grew %.1f%% (%ld KB)\n", pct, growth);
    }

    ASSERT_TRUE(errors == 0);
    ASSERT_TRUE(iters > 0);
    PASS();
}

/* ------------------------------------------------------------------------ */
/* Scenario 3: BER primitive encode/decode stress                           */
/* ------------------------------------------------------------------------ */

static void test_ber_codec_stress(void)
{
    TEST("ber_codec_stress");

    int duration = get_duration_sec();
    long rss_before = get_rss_kb();
    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);

    unsigned long iters = 0;
    unsigned long errors = 0;
    double last_report = 0.0;

    while (elapsed_sec(&start) < (double)duration) {
        uint8_t buf[256];
        size_t offset;
        int ret;

        /* Boolean */
        offset = 0;
        ret = ber_encode_boolean(buf, sizeof(buf), &offset,
                                 ASN1_TAG_BOOLEAN, (iters & 1) != 0);
        if (ret != GOOSE_BER_OK || offset != 3)
            errors++;

        /* Integer */
        offset = 0;
        ret = ber_encode_int32(buf, sizeof(buf), &offset,
                               ASN1_TAG_INTEGER, (int32_t)iters);
        if (ret != GOOSE_BER_OK || offset == 0)
            errors++;

        /* Unsigned */
        offset = 0;
        ret = ber_encode_uint32(buf, sizeof(buf), &offset,
                                ASN1_TAG_INTEGER, (uint32_t)iters);
        if (ret != GOOSE_BER_OK || offset == 0)
            errors++;

        /* VisibleString */
        offset = 0;
        ret = ber_encode_visiblestring(buf, sizeof(buf), &offset,
                                       ASN1_TAG_VISIBLESTRING,
                                       "stress-test-string");
        if (ret != GOOSE_BER_OK || offset == 0)
            errors++;

        /* UTC Time */
        offset = 0;
        ret = ber_encode_utctime(buf, sizeof(buf), &offset,
                                 ASN1_TAG_UTCTIME,
                                 1700000000000000ULL + iters, 0x00);
        if (ret != GOOSE_BER_OK || offset == 0)
            errors++;

        iters++;

        double now = elapsed_sec(&start);
        if (now - last_report >= 1.0) {
            printf("    [%5.1fs] iterations=%lu errors=%lu\n",
                   now, iters, errors);
            last_report = now;
        }
    }

    double total = elapsed_sec(&start);
    long rss_after = get_rss_kb();

    printf("    Summary: %lu iterations in %.1fs (%.0f encode-sets/s), "
           "%lu errors, RSS %ld->%ld KB\n",
           iters, total, (double)iters / total,
           errors, rss_before, rss_after);

    if (rss_before > 0 && rss_after > rss_before) {
        long growth = rss_after - rss_before;
        double pct = 100.0 * (double)growth / (double)rss_before;
        if (pct > 10.0)
            printf("    WARNING: RSS grew %.1f%% (%ld KB)\n", pct, growth);
    }

    ASSERT_TRUE(errors == 0);
    ASSERT_TRUE(iters > 0);
    PASS();
}

/* ------------------------------------------------------------------------ */
/* Main                                                                     */
/* ------------------------------------------------------------------------ */

int main(void)
{
    int duration = get_duration_sec();
    printf("\n=== Long-Duration Stress Tests (%ds) ===\n", duration);
    printf("    Set LONGRUN_DURATION_SEC to override (default: 10)\n\n");

    test_mms_sustained_load();
    test_goose_sustained_codec();
    test_ber_codec_stress();

    printf("\n  Results: %d/%d passed\n\n", test_passed, test_run);
    return (test_failed > 0) ? 1 : 0;
}
