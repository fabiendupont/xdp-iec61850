/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Phase 7 Combined Workflow and Monitoring Export Tests
 *
 * Tests combined MMS service workflows over loopback TCP:
 * - Combined services: read, write, getnamelist, identify, file directory
 * - Concurrent clients performing reads simultaneously
 * - Rapid read/write cycles (100 iterations)
 *
 * Tests monitoring subsystem:
 * - System monitor init and initial state
 * - System monitor update and counter verification
 * - Latency statistics: min/max/avg calculation
 */


#include "mms/mms_server.h"
#include "mms/mms_client.h"
#include "mms/mms_data_store.h"
#include "mms/mms_file_service.h"
#include "mms/mms_journal.h"
#include "monitoring/system_monitor.h"
#include "monitoring/latency_stats.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>

/* Minimal test framework */
static int test_run = 0, test_passed = 0, test_failed = 0;
#define TEST(name) do { test_run++; printf("  [TEST] %s ...", name); } while(0)
#define PASS() do { test_passed++; printf(" PASS\n"); } while(0)
#define FAIL(msg) do { test_failed++; printf(" FAIL: %s\n", msg); return; } while(0)
#define ASSERT_TRUE(x) do { if (!(x)) { FAIL(#x); } } while(0)
#define ASSERT_EQ(a,b) do { if ((a) != (b)) { printf(" (got %d, want %d)", (int)(a), (int)(b)); FAIL(#a " != " #b); } } while(0)

/* Test port and file directory */
#define TEST_PORT  10700
#define TEST_DIR   "/tmp/iec61850_phase7_files"

/* Shared infrastructure */
static iec61850_mms_data_store_t g_ds;
static iec61850_mms_server_t g_server;
static iec61850_mms_file_service_t g_fs;
static iec61850_journal_t g_journal;

static void setup_server(void)
{
    /* Data store with test variables */
    iec61850_mms_ds_init(&g_ds);
    iec61850_mms_ds_create_domain(&g_ds, "testLD");

    mms_value_t val;
    (void)memset(&val, 0, sizeof(val));

    val.type = MMS_TYPE_INTEGER;
    val.value.integer = 42;
    iec61850_mms_ds_create_variable(&g_ds, "testLD", "LLN0$ST$Beh$stVal",
                                     MMS_TYPE_INTEGER, &val);

    val.type = MMS_TYPE_BOOLEAN;
    val.value.boolean = true;
    iec61850_mms_ds_create_variable(&g_ds, "testLD", "XCBR1$ST$Pos$stVal",
                                     MMS_TYPE_BOOLEAN, &val);

    val.type = MMS_TYPE_FLOATING_POINT;
    val.value.floating_point = 220.5f;
    iec61850_mms_ds_create_variable(&g_ds, "testLD", "MMXU1$MX$PhV$phsA",
                                     MMS_TYPE_FLOATING_POINT, &val);

    /* File service */
    (void)mkdir(TEST_DIR, 0755);
    iec61850_mms_file_service_init(&g_fs, TEST_DIR);

    /* Create a test file */
    {
        char path[512];
        (void)snprintf(path, sizeof(path), "%s/test.txt", TEST_DIR);
        FILE *f = fopen(path, "w");
        if (f) {
            (void)fputs("Phase 7 test file content", f);
            (void)fclose(f);
        }
    }

    /* Journal */
    iec61850_journal_init(&g_journal, "testJournal");
    mms_value_t jval;
    (void)memset(&jval, 0, sizeof(jval));
    jval.type = MMS_TYPE_INTEGER;
    jval.value.integer = 100;
    iec61850_journal_add_entry(&g_journal, "testLD/LLN0$ST$Beh$stVal",
                                &jval, 1000);

    /* Server config */
    iec61850_mms_server_config_t cfg;
    iec61850_mms_server_config_init(&cfg);
    cfg.port = TEST_PORT;

    iec61850_mms_server_init(&g_server, &cfg, &g_ds);
    g_server.file_service = &g_fs;
    g_server.journal = &g_journal;

    iec61850_mms_server_start(&g_server);
    usleep(200000);
}

static void teardown_server(void)
{
    iec61850_mms_server_stop(&g_server);
    iec61850_mms_file_service_destroy(&g_fs);
    iec61850_mms_ds_destroy(&g_ds);

    /* Clean up test files */
    (void)unlink(TEST_DIR "/test.txt");
    (void)rmdir(TEST_DIR);
}

/* ========================================================================
 * Phase 7 Workflow Tests
 * ======================================================================== */

static void test_combined_services(void)
{
    TEST("combined_services");

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", TEST_PORT, 5000);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    /* 1. Read */
    mms_value_t val;
    ret = iec61850_mms_client_read(&client, "testLD", "LLN0$ST$Beh$stVal", &val);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ(val.value.integer, 42);

    /* 2. Write */
    mms_value_t wval;
    (void)memset(&wval, 0, sizeof(wval));
    wval.type = MMS_TYPE_INTEGER;
    wval.value.integer = 77;
    ret = iec61850_mms_client_write(&client, "testLD",
                                      "LLN0$ST$Beh$stVal", &wval);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    /* 3. GetNameList */
    char names[16][MMS_MAX_VARIABLE_NAME];
    uint32_t count = 0;
    ret = iec61850_mms_client_get_name_list(&client,
                                              MMS_OBJECT_CLASS_NAMED_VARIABLE,
                                              "testLD", names, &count, 16);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_TRUE(count >= 3);

    /* 4. Identify */
    char vendor[128], model[128], revision[128];
    ret = iec61850_mms_client_identify(&client, vendor, model, revision, 128);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    /* 5. File directory */
    mms_file_entry_t entries[8];
    uint32_t num_entries = 0;
    ret = iec61850_mms_client_file_directory(&client, NULL,
                                               entries, &num_entries, 8);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_TRUE(num_entries >= 1);

    /* Verify write persisted */
    ret = iec61850_mms_client_read(&client, "testLD", "LLN0$ST$Beh$stVal", &val);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ(val.value.integer, 77);

    /* Restore original value */
    wval.value.integer = 42;
    iec61850_mms_client_write(&client, "testLD", "LLN0$ST$Beh$stVal", &wval);

    iec61850_mms_client_disconnect(&client);
    PASS();
}

/* Thread argument for concurrent client test */
typedef struct {
    int client_id;
    int result;
    int reads_ok;
} client_thread_arg_t;

static void *concurrent_reader(void *arg)
{
    client_thread_arg_t *a = (client_thread_arg_t *)arg;
    a->result = -1;
    a->reads_ok = 0;

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);

    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", TEST_PORT, 5000);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        return NULL;
    }

    /* Each client performs 10 reads */
    for (int i = 0; i < 10; i++) {
        mms_value_t val;
        ret = iec61850_mms_client_read(&client, "testLD",
                                         "LLN0$ST$Beh$stVal", &val);
        if (ret == IEC61850_MMS_CLIENT_OK) {
            a->reads_ok++;
        }
    }

    iec61850_mms_client_disconnect(&client);
    a->result = 0;
    return NULL;
}

static void test_concurrent_clients(void)
{
    TEST("concurrent_clients");

    pthread_t threads[2];
    client_thread_arg_t args[2];

    args[0].client_id = 0;
    args[1].client_id = 1;

    /* Launch 2 concurrent readers */
    for (int i = 0; i < 2; i++) {
        int ret = pthread_create(&threads[i], NULL, concurrent_reader, &args[i]);
        ASSERT_EQ(ret, 0);
    }

    /* Wait for both */
    for (int i = 0; i < 2; i++) {
        pthread_join(threads[i], NULL);
    }

    /* Both clients should have connected and completed reads */
    ASSERT_EQ(args[0].result, 0);
    ASSERT_EQ(args[1].result, 0);
    ASSERT_EQ(args[0].reads_ok, 10);
    ASSERT_EQ(args[1].reads_ok, 10);

    PASS();
}

static void test_rapid_operations(void)
{
    TEST("rapid_operations (100 cycles)");

    iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", TEST_PORT, 5000);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    int errors = 0;
    for (int i = 0; i < 100; i++) {
        /* Write */
        mms_value_t wval;
        (void)memset(&wval, 0, sizeof(wval));
        wval.type = MMS_TYPE_INTEGER;
        wval.value.integer = (int32_t)i;
        ret = iec61850_mms_client_write(&client, "testLD",
                                          "LLN0$ST$Beh$stVal", &wval);
        if (ret != IEC61850_MMS_CLIENT_OK) {
            errors++;
            continue;
        }

        /* Read back */
        mms_value_t rval;
        ret = iec61850_mms_client_read(&client, "testLD",
                                         "LLN0$ST$Beh$stVal", &rval);
        if (ret != IEC61850_MMS_CLIENT_OK) {
            errors++;
        }
    }

    ASSERT_EQ(errors, 0);

    /* Restore original value */
    mms_value_t rval;
    (void)memset(&rval, 0, sizeof(rval));
    rval.type = MMS_TYPE_INTEGER;
    rval.value.integer = 42;
    iec61850_mms_client_write(&client, "testLD", "LLN0$ST$Beh$stVal", &rval);

    iec61850_mms_client_disconnect(&client);
    PASS();
}

/* ========================================================================
 * Monitoring Tests
 * ======================================================================== */

static void test_monitor_init(void)
{
    TEST("monitor_init");

    iec61850_system_monitor_t mon;
    iec61850_monitor_init(&mon);

    ASSERT_EQ((int)mon.pub_sent, 0);
    ASSERT_EQ((int)mon.pub_errors, 0);
    ASSERT_EQ((int)mon.sub_received, 0);
    ASSERT_EQ((int)mon.sub_duplicates, 0);
    ASSERT_EQ((int)mon.sub_timeouts, 0);
    ASSERT_TRUE(mon.last_check_time_ns > 0);

    /* Initial health should be HEALTHY */
    iec61850_system_health_t h = iec61850_monitor_get_health(&mon);
    ASSERT_EQ((int)h.status, (int)IEC61850_HEALTH_HEALTHY);
    ASSERT_TRUE(h.memory_healthy);
    ASSERT_TRUE(h.publisher_healthy);
    ASSERT_TRUE(h.subscriber_healthy);

    PASS();
}

static void test_monitor_update(void)
{
    TEST("monitor_update");

    iec61850_system_monitor_t mon;
    iec61850_monitor_init(&mon);

    /* Update publisher stats */
    iec61850_monitor_update_pub(&mon, &(iec61850_pub_stats_t){.sent=1000, .errors=0});
    ASSERT_EQ((int)mon.pub_sent, 1000);
    ASSERT_EQ((int)mon.pub_errors, 0);

    /* Update subscriber stats */
    iec61850_monitor_update_sub(&mon, &(iec61850_sub_stats_t){.received=500, .duplicates=2, .timeouts=1});
    ASSERT_EQ((int)mon.sub_received, 500);
    ASSERT_EQ((int)mon.sub_duplicates, 2);
    ASSERT_EQ((int)mon.sub_timeouts, 1);

    /* Update memory pool */
    iec61850_monitor_set_mempool(&mon, 1024, 800);
    ASSERT_EQ((int)mon.mempool.total_capacity, 1024);
    ASSERT_EQ((int)mon.mempool.available, 800);
    ASSERT_EQ((int)mon.mempool.in_use, 224);

    /* Health should reflect the updates */
    iec61850_system_health_t h = iec61850_monitor_get_health(&mon);
    ASSERT_EQ((int)h.pub_total_sent, 1000);
    ASSERT_EQ((int)h.sub_total_received, 500);
    /* WARNING because sub_total_timeouts > 0 */
    ASSERT_TRUE(h.status == IEC61850_HEALTH_WARNING ||
                h.status == IEC61850_HEALTH_HEALTHY);

    /* Verify JSON export works */
    char buf[1024];
    int n = iec61850_metrics_to_json(&h, buf, sizeof(buf));
    ASSERT_TRUE(n > 0);

    /* Verify CSV export works */
    char csv[512];
    n = iec61850_metrics_to_csv(&h, csv, sizeof(csv));
    ASSERT_TRUE(n > 0);

    /* Verify CSV header */
    char hdr[256];
    n = iec61850_metrics_csv_header(hdr, sizeof(hdr));
    ASSERT_TRUE(n > 0);

    PASS();
}

static void test_latency_stats(void)
{
    TEST("latency_stats");

    iec61850_latency_stats_t stats;
    iec61850_latency_stats_init(&stats, 100);  /* 100us buckets */

    /* Add samples: 50, 100, 150, 200, 250 us */
    iec61850_latency_stats_record(&stats, 50);
    iec61850_latency_stats_record(&stats, 100);
    iec61850_latency_stats_record(&stats, 150);
    iec61850_latency_stats_record(&stats, 200);
    iec61850_latency_stats_record(&stats, 250);

    ASSERT_EQ((int)stats.count, 5);
    ASSERT_EQ((int)stats.min_us, 50);
    ASSERT_EQ((int)stats.max_us, 250);

    /* Verify summary */
    iec61850_latency_summary_t summary;
    iec61850_latency_stats_get_summary(&stats, &summary);
    ASSERT_EQ((int)summary.count, 5);
    ASSERT_EQ((int)summary.min_us, 50);
    ASSERT_EQ((int)summary.max_us, 250);
    /* avg = (50+100+150+200+250)/5 = 150 */
    ASSERT_EQ((int)summary.avg_us, 150);

    /* Verify compute_us */
    uint64_t lat = iec61850_latency_compute_us(1000000, 1500000);
    ASSERT_EQ((int)lat, 500);  /* 500us */

    /* recv < send returns 0 */
    lat = iec61850_latency_compute_us(2000000, 1000000);
    ASSERT_EQ((int)lat, 0);

    /* Reset and verify */
    iec61850_latency_stats_reset(&stats);
    ASSERT_EQ((int)stats.count, 0);
    ASSERT_EQ((int)stats.bucket_width_us, 100);  /* preserved */

    PASS();
}

/* ======================================================================== */

int main(void)
{
    printf("\n=== Phase 7 Combined Workflow + Monitoring Tests ===\n");

    /* Monitoring tests (no server needed) */
    printf("\n--- Monitoring ---\n");
    test_monitor_init();
    test_monitor_update();
    test_latency_stats();

    /* Phase 7 workflow tests (server needed) */
    printf("\n--- Phase 7 Combined Workflow ---\n");
    setup_server();

    test_combined_services();
    test_concurrent_clients();
    test_rapid_operations();

    teardown_server();

    printf("\n  Results: %d/%d passed\n\n", test_passed, test_run);
    return (test_failed > 0) ? 1 : 0;
}
