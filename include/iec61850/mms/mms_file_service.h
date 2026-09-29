/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS File Service for IEC 61850
 *
 * Implements GetFileDirectory, FileOpen, FileRead, FileClose,
 * FileDelete, and FileRename per MMS (ISO 9506-2).
 */

#ifndef IEC61850_MMS_FILE_SERVICE_H
#define IEC61850_MMS_FILE_SERVICE_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Limits */
#define IEC61850_MMS_FILE_MAX_NAME     256
#define IEC61850_MMS_FILE_MAX_CHUNK   4096
#define IEC61850_MMS_FILE_MAX_OPEN       8

/* Result codes */
typedef enum {
    IEC61850_MMS_FILE_OK = 0,
    IEC61850_MMS_FILE_ERR_ARGS = -1,
    IEC61850_MMS_FILE_ERR_NOT_FOUND = -2,
    IEC61850_MMS_FILE_ERR_ACCESS = -3,
    IEC61850_MMS_FILE_ERR_IO = -4,
    IEC61850_MMS_FILE_ERR_EXISTS = -5,
    IEC61850_MMS_FILE_ERR_FULL = -6,
    IEC61850_MMS_FILE_ERR_INVALID_HANDLE = -7
} iec61850_mms_file_result_t;

/* File directory entry */
typedef struct {
    char filename[IEC61850_MMS_FILE_MAX_NAME];
    uint32_t file_size;
    uint64_t last_modified;  /* Unix timestamp */
} iec61850_mms_file_entry_t;

/* Open file handle */
typedef struct {
    int fd;
    char filename[IEC61850_MMS_FILE_MAX_NAME];
    uint32_t file_size;
    uint32_t position;
    bool in_use;
} iec61850_mms_file_handle_t;

/* File service context */
typedef struct {
    char base_directory[IEC61850_MMS_FILE_MAX_NAME];
    iec61850_mms_file_handle_t handles[IEC61850_MMS_FILE_MAX_OPEN];
} iec61850_mms_file_service_t;

/**
 * Initialize file service with a base directory.
 */
void iec61850_mms_file_service_init(iec61850_mms_file_service_t *fs,
                                      const char *base_dir);

/**
 * Destroy file service, closing all open handles.
 */
void iec61850_mms_file_service_destroy(iec61850_mms_file_service_t *fs);

/**
 * Get directory listing.
 *
 * @param fs        File service
 * @param pattern   Filename pattern (NULL or "" = all files)
 * @param entries   Output array of directory entries
 * @param count     Output: number of entries found
 * @param max_count Maximum entries to return
 * @return 0 on success
 */
int iec61850_mms_file_get_directory(iec61850_mms_file_service_t *fs,
                                      const char *pattern,
                                      iec61850_mms_file_entry_t *entries,
                                      uint32_t *count, uint32_t max_count);

/**
 * Open a file for reading.
 *
 * @param fs        File service
 * @param filename  File name (relative to base directory)
 * @param file_size Output: file size in bytes
 * @return File handle ID (>= 0) on success, negative error code on failure
 */
int iec61850_mms_file_open(iec61850_mms_file_service_t *fs,
                             const char *filename, uint32_t *file_size);

/**
 * Read a chunk from an open file.
 *
 * @param fs       File service
 * @param handle   File handle from file_open
 * @param buf      Output buffer
 * @param buf_size Buffer size
 * @param read_len Output: bytes actually read
 * @param more     Output: true if more data follows
 * @return 0 on success
 */
int iec61850_mms_file_read(iec61850_mms_file_service_t *fs,
                             int handle, uint8_t *buf, size_t buf_size,
                             size_t *read_len, bool *more);

/**
 * Close an open file handle.
 */
int iec61850_mms_file_close(iec61850_mms_file_service_t *fs, int handle);

/**
 * Delete a file.
 */
int iec61850_mms_file_delete(iec61850_mms_file_service_t *fs,
                               const char *filename);

/**
 * Rename a file.
 */
int iec61850_mms_file_rename(iec61850_mms_file_service_t *fs,
                               const char *old_name, const char *new_name);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_MMS_FILE_SERVICE_H */
