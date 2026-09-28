/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS File Service End-to-End Test
 *
 * Tests MMS file operations over loopback TCP:
 * - File download (open, read, close)
 * - Chunked file download with more_follows
 * - File delete via file service API
 * - File directory listing
 * - Path traversal rejection
 * - Complete workflow (directory → open → read → close → delete → directory)
 */


#include "mms/mms_server.h"
#include "mms/mms_client.h"
#include "mms/mms_data_store.h"
#include "mms/mms_file_service.h"
#include "asn1/mms_ber.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

/* Minimal test framework */
static int test_run = 0, test_passed = 0, test_failed = 0;
#define TEST(name) do { test_run++; printf("  [TEST] %s ...", name); } while(0)
#define PASS() do { test_passed++; printf(" PASS\n"); } while(0)
#define FAIL(msg) do { test_failed++; printf(" FAIL: %s\n", msg); return; } while(0)
#define ASSERT_TRUE(x) do { if (!(x)) { FAIL(#x); } } while(0)
#define ASSERT_EQ(a,b) do { if ((a) != (b)) { printf(" (got %d, want %d)", (int)(a), (int)(b)); FAIL(#a " != " #b); } } while(0)

/* Test directory and port */
#define TEST_DIR      "/tmp/iec61850_file_e2e"
#define TEST_PORT     10620
#define SMALL_FILE    "small.txt"
#define LARGE_FILE    "large.dat"
#define DELETE_FILE   "todelete.txt"
#define SMALL_CONTENT "Hello, IEC 61850 file service!"
#define LARGE_SIZE    12000  /* larger than IEC61850_MMS_FILE_MAX_CHUNK (4096) */

/* Shared infrastructure */
static iec61850_mms_data_store_t g_ds;
static iec61850_mms_server_t g_server;
static iec61850_mms_file_service_t g_fs;

static void write_test_file(const char *name, const void *data, size_t len)
{
    char path[512];
    (void)snprintf(path, sizeof(path), "%s/%s", TEST_DIR, name);
    FILE *f = fopen(path, "wb");
    if (f) {
        (void)fwrite(data, 1, len, f);
        (void)fclose(f);
    }
}

static bool file_exists(const char *name)
{
    char path[512];
    (void)snprintf(path, sizeof(path), "%s/%s", TEST_DIR, name);
    return access(path, F_OK) == 0;
}

static void create_test_files(void)
{
    (void)mkdir(TEST_DIR, 0755);

    /* Small file */
    write_test_file(SMALL_FILE, SMALL_CONTENT, strlen(SMALL_CONTENT));

    /* Large file — fill with repeating pattern */
    uint8_t *buf = malloc(LARGE_SIZE);
    if (buf) {
        for (int i = 0; i < LARGE_SIZE; i++) {
            buf[i] = (uint8_t)(i & 0xFF);
        }
        write_test_file(LARGE_FILE, buf, LARGE_SIZE);
        free(buf);
    }

    /* File to be deleted */
    write_test_file(DELETE_FILE, "delete me", 9);
}

static void remove_test_files(void)
{
    char path[512];
    const char *files[] = { SMALL_FILE, LARGE_FILE, DELETE_FILE, NULL };
    for (int i = 0; files[i]; i++) {
        (void)snprintf(path, sizeof(path), "%s/%s", TEST_DIR, files[i]);
        (void)unlink(path);
    }
    (void)rmdir(TEST_DIR);
}

static void setup_server(void)
{
    create_test_files();

    iec61850_mms_ds_init(&g_ds);
    iec61850_mms_ds_create_domain(&g_ds, "fileLD");

    iec61850_mms_file_service_init(&g_fs, TEST_DIR);

    iec61850_mms_server_config_t cfg;
    iec61850_mms_server_config_init(&cfg);
    cfg.port = TEST_PORT;

    iec61850_mms_server_init(&g_server, &cfg, &g_ds);
    g_server.file_service = &g_fs;

    iec61850_mms_server_start(&g_server);
    usleep(200000);
}

static void teardown_server(void)
{
    iec61850_mms_server_stop(&g_server);
    iec61850_mms_file_service_destroy(&g_fs);
    iec61850_mms_ds_destroy(&g_ds);
    remove_test_files();
}

static iec61850_mms_client_t *connect_client(void)
{
    static iec61850_mms_client_t client;
    iec61850_mms_client_init(&client);
    int ret = iec61850_mms_client_connect(&client, "127.0.0.1", TEST_PORT, 5000);
    if (ret != IEC61850_MMS_CLIENT_OK) {
        return NULL;
    }
    return &client;
}

/* ======================================================================== */
/* Test: File download — open, read, close a small test file                */
/* ======================================================================== */
static void test_file_download(void)
{
    TEST("file_download");

    iec61850_mms_client_t *client = connect_client();
    ASSERT_TRUE(client != NULL);

    uint32_t handle = 0;
    uint32_t file_size = 0;
    int ret = iec61850_mms_client_file_open(client, SMALL_FILE,
                                              &handle, &file_size);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ((int)file_size, (int)strlen(SMALL_CONTENT));

    uint8_t buf[256];
    uint32_t data_len = 0;
    bool more = false;
    ret = iec61850_mms_client_file_read(client, handle, buf, &data_len,
                                          sizeof(buf), &more);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ((int)data_len, (int)strlen(SMALL_CONTENT));
    ASSERT_TRUE(!more);
    ASSERT_TRUE(memcmp(buf, SMALL_CONTENT, data_len) == 0);

    ret = iec61850_mms_client_file_close(client, handle);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    iec61850_mms_client_disconnect(client);
    PASS();
}

/* ======================================================================== */
/* Test: Chunked download — read large file in chunks with more_follows     */
/* ======================================================================== */
static void test_file_download_chunked(void)
{
    TEST("file_download_chunked");

    iec61850_mms_client_t *client = connect_client();
    ASSERT_TRUE(client != NULL);

    uint32_t handle = 0;
    uint32_t file_size = 0;
    int ret = iec61850_mms_client_file_open(client, LARGE_FILE,
                                              &handle, &file_size);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ((int)file_size, LARGE_SIZE);

    /* Read in chunks until done */
    uint32_t total_read = 0;
    int chunk_count = 0;
    bool more = true;

    while (more) {
        uint8_t buf[IEC61850_MMS_FILE_MAX_CHUNK];
        uint32_t data_len = 0;
        ret = iec61850_mms_client_file_read(client, handle, buf, &data_len,
                                              sizeof(buf), &more);
        ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
        ASSERT_TRUE(data_len > 0);

        /* Verify chunk content matches pattern */
        for (uint32_t i = 0; i < data_len; i++) {
            uint8_t expected = (uint8_t)((total_read + i) & 0xFF);
            if (buf[i] != expected) {
                FAIL("chunk data mismatch");
            }
        }

        total_read += data_len;
        chunk_count++;

        /* Safety: don't loop forever */
        if (chunk_count > 100) {
            FAIL("too many chunks");
        }
    }

    ASSERT_EQ((int)total_read, LARGE_SIZE);
    ASSERT_TRUE(chunk_count > 1);  /* Must have required multiple reads */

    ret = iec61850_mms_client_file_close(client, handle);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    iec61850_mms_client_disconnect(client);
    PASS();
}

/* ======================================================================== */
/* Test: File delete — create file, delete via file service, verify removed  */
/* ======================================================================== */
static void test_file_delete(void)
{
    TEST("file_delete");

    ASSERT_TRUE(file_exists(DELETE_FILE));

    int ret = iec61850_mms_file_delete(&g_fs, DELETE_FILE);
    ASSERT_EQ(ret, IEC61850_MMS_FILE_OK);
    ASSERT_TRUE(!file_exists(DELETE_FILE));

    /* Deleting again should fail */
    ret = iec61850_mms_file_delete(&g_fs, DELETE_FILE);
    ASSERT_TRUE(ret != IEC61850_MMS_FILE_OK);

    PASS();
}

/* ======================================================================== */
/* Test: File directory — list files in test directory                       */
/* ======================================================================== */
static void test_file_directory(void)
{
    TEST("file_directory");

    iec61850_mms_client_t *client = connect_client();
    ASSERT_TRUE(client != NULL);

    mms_file_entry_t entries[16];
    uint32_t num_entries = 0;
    int ret = iec61850_mms_client_file_directory(client, NULL,
                                                   entries, &num_entries, 16);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    /* At least small.txt and large.dat should be present */
    ASSERT_TRUE(num_entries >= 2);

    /* Verify we can find the small file in the listing */
    bool found_small = false;
    for (uint32_t i = 0; i < num_entries; i++) {
        if (strcmp(entries[i].filename, SMALL_FILE) == 0) {
            found_small = true;
            ASSERT_EQ((int)entries[i].file_size, (int)strlen(SMALL_CONTENT));
        }
    }
    ASSERT_TRUE(found_small);

    iec61850_mms_client_disconnect(client);
    PASS();
}

/* ======================================================================== */
/* Test: Path traversal rejection — attempt ../ paths, verify rejection     */
/* ======================================================================== */
static void test_path_traversal_rejection(void)
{
    TEST("path_traversal_rejection");

    /* Attempt various path traversal attacks via file service */
    uint32_t file_size = 0;
    int ret;

    ret = iec61850_mms_file_open(&g_fs, "../etc/passwd", &file_size);
    ASSERT_TRUE(ret < 0);

    ret = iec61850_mms_file_open(&g_fs, "../../etc/shadow", &file_size);
    ASSERT_TRUE(ret < 0);

    ret = iec61850_mms_file_open(&g_fs, "subdir/../../../etc/passwd", &file_size);
    ASSERT_TRUE(ret < 0);

    /* Delete with traversal should also fail */
    ret = iec61850_mms_file_delete(&g_fs, "../etc/passwd");
    ASSERT_TRUE(ret != IEC61850_MMS_FILE_OK);

    PASS();
}

/* ======================================================================== */
/* Test: Complete workflow — directory → open → read → close → delete →     */
/*       directory, verifying file disappears from listing                   */
/* ======================================================================== */
static void test_complete_workflow(void)
{
    TEST("complete_workflow");

    /* Re-create the delete file for this test */
    write_test_file(DELETE_FILE, "workflow test", 13);

    iec61850_mms_client_t *client = connect_client();
    ASSERT_TRUE(client != NULL);

    /* Step 1: Directory listing — should include all test files */
    mms_file_entry_t entries[16];
    uint32_t num_entries = 0;
    int ret = iec61850_mms_client_file_directory(client, NULL,
                                                   entries, &num_entries, 16);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    bool found = false;
    for (uint32_t i = 0; i < num_entries; i++) {
        if (strcmp(entries[i].filename, DELETE_FILE) == 0) {
            found = true;
        }
    }
    ASSERT_TRUE(found);

    /* Step 2: Open the file */
    uint32_t handle = 0;
    uint32_t file_size = 0;
    ret = iec61850_mms_client_file_open(client, DELETE_FILE,
                                          &handle, &file_size);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ((int)file_size, 13);

    /* Step 3: Read the file */
    uint8_t buf[64];
    uint32_t data_len = 0;
    bool more = false;
    ret = iec61850_mms_client_file_read(client, handle, buf, &data_len,
                                          sizeof(buf), &more);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);
    ASSERT_EQ((int)data_len, 13);
    ASSERT_TRUE(memcmp(buf, "workflow test", 13) == 0);

    /* Step 4: Close the file */
    ret = iec61850_mms_client_file_close(client, handle);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    /* Step 5: Delete the file via file service */
    ret = iec61850_mms_file_delete(&g_fs, DELETE_FILE);
    ASSERT_EQ(ret, IEC61850_MMS_FILE_OK);

    /* Step 6: Directory listing — file should be gone */
    num_entries = 0;
    ret = iec61850_mms_client_file_directory(client, NULL,
                                               entries, &num_entries, 16);
    ASSERT_EQ(ret, IEC61850_MMS_CLIENT_OK);

    found = false;
    for (uint32_t i = 0; i < num_entries; i++) {
        if (strcmp(entries[i].filename, DELETE_FILE) == 0) {
            found = true;
        }
    }
    ASSERT_TRUE(!found);

    iec61850_mms_client_disconnect(client);
    PASS();
}

/* ======================================================================== */
/* Main                                                                      */
/* ======================================================================== */

int main(void)
{
    printf("\n=== MMS File Service E2E Tests ===\n");

    setup_server();

    printf("\n--- File Operations ---\n");
    test_file_download();
    test_file_download_chunked();
    test_file_directory();
    test_path_traversal_rejection();
    test_file_delete();
    test_complete_workflow();

    teardown_server();

    printf("\n  Results: %d/%d passed\n\n", test_passed, test_run);
    return (test_failed > 0) ? 1 : 0;
}
