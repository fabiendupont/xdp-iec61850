/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Tests for MMS File Service
 */


#include "mms/mms_file_service.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>
#include <sys/stat.h>

static char test_dir[256];

static void setup_test_dir(void)
{
    (void)snprintf(test_dir, sizeof(test_dir), "/tmp/iec61850_test_%d",
                    (int)getpid());
    (void)mkdir(test_dir, 0755);
}

static void create_test_file(const char *name, const char *content)
{
    char path[512];
    (void)snprintf(path, sizeof(path), "%s/%s", test_dir, name);
    FILE *f = fopen(path, "w");
    assert(f != NULL);
    (void)fputs(content, f);
    (void)fclose(f);
}

static void cleanup_test_dir(void)
{
    char cmd[512];
    (void)snprintf(cmd, sizeof(cmd), "rm -rf %s", test_dir);
    (void)system(cmd);
}

static void test_init_destroy(void)
{
    iec61850_mms_file_service_t fs;
    iec61850_mms_file_service_init(&fs, test_dir);
    assert(strcmp(fs.base_directory, test_dir) == 0);
    iec61850_mms_file_service_destroy(&fs);
    printf("  PASS: init/destroy\n");
}

static void test_get_directory(void)
{
    iec61850_mms_file_service_t fs;
    iec61850_mms_file_entry_t entries[16];
    uint32_t count = 0;

    create_test_file("alpha.txt", "hello");
    create_test_file("beta.dat", "world");
    create_test_file("gamma.txt", "test data 123");

    iec61850_mms_file_service_init(&fs, test_dir);

    /* Get all files */
    int ret = iec61850_mms_file_get_directory(&fs, NULL, entries, &count, 16);
    assert(ret == IEC61850_MMS_FILE_OK);
    assert(count == 3);

    /* Get with pattern */
    count = 0;
    ret = iec61850_mms_file_get_directory(&fs, "*.txt", entries, &count, 16);
    assert(ret == IEC61850_MMS_FILE_OK);
    assert(count == 2);

    iec61850_mms_file_service_destroy(&fs);
    printf("  PASS: get_directory\n");
}

static void test_file_open_read_close(void)
{
    iec61850_mms_file_service_t fs;
    uint32_t file_size = 0;
    uint8_t buf[256];
    size_t read_len = 0;
    bool more = false;

    create_test_file("readable.txt", "Hello, IEC 61850!");

    iec61850_mms_file_service_init(&fs, test_dir);

    int handle = iec61850_mms_file_open(&fs, "readable.txt", &file_size);
    assert(handle >= 0);
    assert(file_size == 17);

    int ret = iec61850_mms_file_read(&fs, handle, buf, sizeof(buf),
                                       &read_len, &more);
    assert(ret == IEC61850_MMS_FILE_OK);
    assert(read_len == 17);
    assert(more == false);
    assert(memcmp(buf, "Hello, IEC 61850!", 17) == 0);

    ret = iec61850_mms_file_close(&fs, handle);
    assert(ret == IEC61850_MMS_FILE_OK);

    /* Close again should fail */
    ret = iec61850_mms_file_close(&fs, handle);
    assert(ret == IEC61850_MMS_FILE_ERR_INVALID_HANDLE);

    iec61850_mms_file_service_destroy(&fs);
    printf("  PASS: open/read/close\n");
}

static void test_file_not_found(void)
{
    iec61850_mms_file_service_t fs;
    uint32_t file_size = 0;

    iec61850_mms_file_service_init(&fs, test_dir);

    int handle = iec61850_mms_file_open(&fs, "nonexistent.txt", &file_size);
    assert(handle == IEC61850_MMS_FILE_ERR_NOT_FOUND);

    iec61850_mms_file_service_destroy(&fs);
    printf("  PASS: file not found\n");
}

static void test_file_delete(void)
{
    iec61850_mms_file_service_t fs;

    create_test_file("deleteme.txt", "delete this");

    iec61850_mms_file_service_init(&fs, test_dir);

    int ret = iec61850_mms_file_delete(&fs, "deleteme.txt");
    assert(ret == IEC61850_MMS_FILE_OK);

    /* Delete again should fail */
    ret = iec61850_mms_file_delete(&fs, "deleteme.txt");
    assert(ret == IEC61850_MMS_FILE_ERR_NOT_FOUND);

    iec61850_mms_file_service_destroy(&fs);
    printf("  PASS: delete\n");
}

static void test_file_rename(void)
{
    iec61850_mms_file_service_t fs;
    uint32_t file_size = 0;

    create_test_file("original.txt", "rename me");

    iec61850_mms_file_service_init(&fs, test_dir);

    int ret = iec61850_mms_file_rename(&fs, "original.txt", "renamed.txt");
    assert(ret == IEC61850_MMS_FILE_OK);

    /* Original should not exist */
    int handle = iec61850_mms_file_open(&fs, "original.txt", &file_size);
    assert(handle == IEC61850_MMS_FILE_ERR_NOT_FOUND);

    /* Renamed should exist */
    handle = iec61850_mms_file_open(&fs, "renamed.txt", &file_size);
    assert(handle >= 0);
    assert(file_size == 9);

    (void)iec61850_mms_file_close(&fs, handle);
    iec61850_mms_file_service_destroy(&fs);
    printf("  PASS: rename\n");
}

static void test_path_traversal_rejected(void)
{
    iec61850_mms_file_service_t fs;
    uint32_t file_size = 0;

    iec61850_mms_file_service_init(&fs, test_dir);

    /* Path traversal should be rejected */
    int handle = iec61850_mms_file_open(&fs, "../etc/passwd", &file_size);
    assert(handle == IEC61850_MMS_FILE_ERR_ARGS);

    handle = iec61850_mms_file_open(&fs, "/etc/passwd", &file_size);
    assert(handle == IEC61850_MMS_FILE_ERR_ARGS);

    int ret = iec61850_mms_file_delete(&fs, "../../etc/passwd");
    assert(ret == IEC61850_MMS_FILE_ERR_ARGS);

    iec61850_mms_file_service_destroy(&fs);
    printf("  PASS: path traversal rejected\n");
}

static void test_null_args(void)
{
    iec61850_mms_file_service_t fs;
    iec61850_mms_file_entry_t entries[1];
    uint32_t count = 0;
    uint32_t file_size = 0;
    uint8_t buf[16];
    size_t read_len = 0;
    bool more = false;

    /* init/destroy NULL */
    iec61850_mms_file_service_init(NULL, "/tmp");
    iec61850_mms_file_service_destroy(NULL);

    /* init with NULL base_dir → defaults to /tmp */
    iec61850_mms_file_service_init(&fs, NULL);
    assert(strcmp(fs.base_directory, "/tmp") == 0);
    iec61850_mms_file_service_destroy(&fs);

    /* get_directory NULL args */
    assert(iec61850_mms_file_get_directory(NULL, NULL, entries, &count, 1)
           == IEC61850_MMS_FILE_ERR_ARGS);
    iec61850_mms_file_service_init(&fs, test_dir);
    assert(iec61850_mms_file_get_directory(&fs, NULL, NULL, &count, 1)
           == IEC61850_MMS_FILE_ERR_ARGS);
    assert(iec61850_mms_file_get_directory(&fs, NULL, entries, NULL, 1)
           == IEC61850_MMS_FILE_ERR_ARGS);

    /* open NULL args */
    assert(iec61850_mms_file_open(NULL, "f", &file_size) == IEC61850_MMS_FILE_ERR_ARGS);
    assert(iec61850_mms_file_open(&fs, NULL, &file_size) == IEC61850_MMS_FILE_ERR_ARGS);
    assert(iec61850_mms_file_open(&fs, "f", NULL) == IEC61850_MMS_FILE_ERR_ARGS);

    /* open with empty filename */
    assert(iec61850_mms_file_open(&fs, "", &file_size) == IEC61850_MMS_FILE_ERR_ARGS);

    /* read NULL args */
    assert(iec61850_mms_file_read(NULL, 0, buf, sizeof(buf), &read_len, &more)
           == IEC61850_MMS_FILE_ERR_ARGS);
    assert(iec61850_mms_file_read(&fs, 0, NULL, sizeof(buf), &read_len, &more)
           == IEC61850_MMS_FILE_ERR_ARGS);
    assert(iec61850_mms_file_read(&fs, 0, buf, sizeof(buf), NULL, &more)
           == IEC61850_MMS_FILE_ERR_ARGS);
    assert(iec61850_mms_file_read(&fs, 0, buf, sizeof(buf), &read_len, NULL)
           == IEC61850_MMS_FILE_ERR_ARGS);

    /* read invalid handle */
    assert(iec61850_mms_file_read(&fs, -1, buf, sizeof(buf), &read_len, &more)
           == IEC61850_MMS_FILE_ERR_INVALID_HANDLE);
    assert(iec61850_mms_file_read(&fs, IEC61850_MMS_FILE_MAX_OPEN, buf, sizeof(buf),
           &read_len, &more) == IEC61850_MMS_FILE_ERR_INVALID_HANDLE);
    assert(iec61850_mms_file_read(&fs, 0, buf, sizeof(buf), &read_len, &more)
           == IEC61850_MMS_FILE_ERR_INVALID_HANDLE);

    /* close NULL */
    assert(iec61850_mms_file_close(NULL, 0) == IEC61850_MMS_FILE_ERR_ARGS);

    /* close invalid handle */
    assert(iec61850_mms_file_close(&fs, -1) == IEC61850_MMS_FILE_ERR_INVALID_HANDLE);
    assert(iec61850_mms_file_close(&fs, IEC61850_MMS_FILE_MAX_OPEN)
           == IEC61850_MMS_FILE_ERR_INVALID_HANDLE);

    /* delete NULL args */
    assert(iec61850_mms_file_delete(NULL, "f") == IEC61850_MMS_FILE_ERR_ARGS);
    assert(iec61850_mms_file_delete(&fs, NULL) == IEC61850_MMS_FILE_ERR_ARGS);

    /* rename NULL args */
    assert(iec61850_mms_file_rename(NULL, "a", "b") == IEC61850_MMS_FILE_ERR_ARGS);
    assert(iec61850_mms_file_rename(&fs, NULL, "b") == IEC61850_MMS_FILE_ERR_ARGS);
    assert(iec61850_mms_file_rename(&fs, "a", NULL) == IEC61850_MMS_FILE_ERR_ARGS);

    /* rename path traversal */
    assert(iec61850_mms_file_rename(&fs, "../etc/passwd", "b")
           == IEC61850_MMS_FILE_ERR_ARGS);
    assert(iec61850_mms_file_rename(&fs, "a", "../etc/shadow")
           == IEC61850_MMS_FILE_ERR_ARGS);

    /* rename non-existent file */
    assert(iec61850_mms_file_rename(&fs, "no_such_file.txt", "dest.txt")
           == IEC61850_MMS_FILE_ERR_NOT_FOUND);

    iec61850_mms_file_service_destroy(&fs);
    printf("  PASS: null_args\n");
}

static void test_max_open_handles(void)
{
    iec61850_mms_file_service_t fs;
    uint32_t file_size = 0;
    int handles[IEC61850_MMS_FILE_MAX_OPEN];

    create_test_file("maxtest.txt", "data");

    iec61850_mms_file_service_init(&fs, test_dir);

    /* Open max handles */
    for (int i = 0; i < IEC61850_MMS_FILE_MAX_OPEN; i++) {
        handles[i] = iec61850_mms_file_open(&fs, "maxtest.txt", &file_size);
        assert(handles[i] >= 0);
    }

    /* Next open should fail with ERR_FULL */
    int overflow = iec61850_mms_file_open(&fs, "maxtest.txt", &file_size);
    assert(overflow == IEC61850_MMS_FILE_ERR_FULL);

    /* Close all */
    for (int i = 0; i < IEC61850_MMS_FILE_MAX_OPEN; i++) {
        assert(iec61850_mms_file_close(&fs, handles[i]) == IEC61850_MMS_FILE_OK);
    }

    /* Now open should work again */
    int reopened = iec61850_mms_file_open(&fs, "maxtest.txt", &file_size);
    assert(reopened >= 0);
    (void)iec61850_mms_file_close(&fs, reopened);

    iec61850_mms_file_service_destroy(&fs);
    printf("  PASS: max_open_handles\n");
}

static void test_get_directory_empty_pattern(void)
{
    iec61850_mms_file_service_t fs;
    iec61850_mms_file_entry_t entries[16];
    uint32_t count = 0;

    create_test_file("pat1.txt", "a");
    create_test_file("pat2.dat", "b");

    iec61850_mms_file_service_init(&fs, test_dir);

    /* Empty string pattern = all files */
    int ret = iec61850_mms_file_get_directory(&fs, "", entries, &count, 16);
    assert(ret == IEC61850_MMS_FILE_OK);
    assert(count >= 2);

    iec61850_mms_file_service_destroy(&fs);
    printf("  PASS: get_directory_empty_pattern\n");
}

static void test_destroy_closes_handles(void)
{
    iec61850_mms_file_service_t fs;
    uint32_t file_size = 0;

    create_test_file("destroytest.txt", "content");

    iec61850_mms_file_service_init(&fs, test_dir);

    int h = iec61850_mms_file_open(&fs, "destroytest.txt", &file_size);
    assert(h >= 0);

    /* Destroy should close all open handles without crash */
    iec61850_mms_file_service_destroy(&fs);
    printf("  PASS: destroy_closes_handles\n");
}

int main(void)
{
    printf("=== MMS File Service Tests ===\n");

    setup_test_dir();

    test_init_destroy();
    test_get_directory();
    test_file_open_read_close();
    test_file_not_found();
    test_file_delete();
    test_file_rename();
    test_path_traversal_rejected();

    printf("\n--- NULL / Error Branches ---\n");
    test_null_args();
    test_max_open_handles();
    test_get_directory_empty_pattern();
    test_destroy_closes_handles();

    cleanup_test_dir();

    printf("All MMS file service tests passed.\n");
    return 0;
}
