/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS File Service Implementation
 *
 * GetFileDirectory, FileOpen, FileRead, FileClose, FileDelete, FileRename.
 * All file operations are relative to a configured base directory.
 * Path traversal attacks are prevented by rejecting ".." components.
 */


#include "mms/mms_file_service.h"

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <fnmatch.h>

/* Validate filename: reject path traversal */
static bool validate_filename(const char *name)
{
    if (name == NULL || name[0] == '\0') {
        return false;
    }
    /* Reject absolute paths */
    if (name[0] == '/') {
        return false;
    }
    /* Reject ".." components */
    if (strstr(name, "..") != NULL) {
        return false;
    }
    return true;
}

/* Build full path: base_dir/filename */
static int build_path(const iec61850_mms_file_service_t *fs,
                        const char *filename, char *out, size_t out_size)
{
    int n = snprintf(out, out_size, "%s/%s", fs->base_directory, filename);
    if (n < 0 || (size_t)n >= out_size) {
        return IEC61850_MMS_FILE_ERR_ARGS;
    }
    return IEC61850_MMS_FILE_OK;
}

void iec61850_mms_file_service_init(iec61850_mms_file_service_t *fs,
                                      const char *base_dir)
{
    if (fs == NULL) { return; }
    (void)memset(fs, 0, sizeof(*fs));

    if (base_dir != NULL) {
        (void)strncpy(fs->base_directory, base_dir,
                       IEC61850_MMS_FILE_MAX_NAME - 1);
    } else {
        (void)strncpy(fs->base_directory, "/tmp",
                       IEC61850_MMS_FILE_MAX_NAME - 1);
    }

    for (int i = 0; i < IEC61850_MMS_FILE_MAX_OPEN; i++) {
        fs->handles[i].fd = -1;
        fs->handles[i].in_use = false;
    }
}

void iec61850_mms_file_service_destroy(iec61850_mms_file_service_t *fs)
{
    if (fs == NULL) { return; }

    for (int i = 0; i < IEC61850_MMS_FILE_MAX_OPEN; i++) {
        if (fs->handles[i].in_use && fs->handles[i].fd >= 0) {
            (void)close(fs->handles[i].fd);
            fs->handles[i].fd = -1;
            fs->handles[i].in_use = false;
        }
    }
}

int iec61850_mms_file_get_directory(iec61850_mms_file_service_t *fs,
                                      const char *pattern,
                                      iec61850_mms_file_entry_t *entries,
                                      uint32_t *count, uint32_t max_count)
{
    DIR *dir;
    struct dirent *de;
    struct stat st;
    char fullpath[IEC61850_MMS_FILE_MAX_NAME * 2];

    if (fs == NULL || entries == NULL || count == NULL) {
        return IEC61850_MMS_FILE_ERR_ARGS;
    }

    *count = 0;

    dir = opendir(fs->base_directory);
    if (dir == NULL) {
        return IEC61850_MMS_FILE_ERR_IO;
    }

    while ((de = readdir(dir)) != NULL && *count < max_count) {
        /* Skip . and .. */
        if (de->d_name[0] == '.' &&
            (de->d_name[1] == '\0' ||
             (de->d_name[1] == '.' && de->d_name[2] == '\0'))) {
            continue;
        }

        /* Apply pattern filter */
        if (pattern != NULL && pattern[0] != '\0') {
            if (fnmatch(pattern, de->d_name, 0) != 0) {
                continue;
            }
        }

        /* Get file info */
        int n = snprintf(fullpath, sizeof(fullpath), "%s/%s",
                          fs->base_directory, de->d_name);
        if (n < 0 || (size_t)n >= sizeof(fullpath)) {
            continue;
        }

        if (stat(fullpath, &st) != 0) {
            continue;
        }

        /* Only regular files */
        if (!S_ISREG(st.st_mode)) {
            continue;
        }

        iec61850_mms_file_entry_t *e = &entries[*count];
        (void)strncpy(e->filename, de->d_name, IEC61850_MMS_FILE_MAX_NAME - 1);
        e->filename[IEC61850_MMS_FILE_MAX_NAME - 1] = '\0';
        e->file_size = (uint32_t)st.st_size;
        e->last_modified = (uint64_t)st.st_mtime;
        (*count)++;
    }

    (void)closedir(dir);
    return IEC61850_MMS_FILE_OK;
}

int iec61850_mms_file_open(iec61850_mms_file_service_t *fs,
                             const char *filename, uint32_t *file_size)
{
    char fullpath[IEC61850_MMS_FILE_MAX_NAME * 2];
    struct stat st;
    int handle_id = -1;
    int fd;
    int ret;

    if (fs == NULL || filename == NULL || file_size == NULL) {
        return IEC61850_MMS_FILE_ERR_ARGS;
    }

    if (!validate_filename(filename)) {
        return IEC61850_MMS_FILE_ERR_ARGS;
    }

    ret = build_path(fs, filename, fullpath, sizeof(fullpath));
    if (ret != IEC61850_MMS_FILE_OK) {
        return ret;
    }

    /* Find free handle slot */
    for (int i = 0; i < IEC61850_MMS_FILE_MAX_OPEN; i++) {
        if (!fs->handles[i].in_use) {
            handle_id = i;
            break;
        }
    }
    if (handle_id < 0) {
        return IEC61850_MMS_FILE_ERR_FULL;
    }

    fd = open(fullpath, O_RDONLY);
    if (fd < 0) {
        if (errno == ENOENT) {
            return IEC61850_MMS_FILE_ERR_NOT_FOUND;
        }
        return IEC61850_MMS_FILE_ERR_ACCESS;
    }

    if (fstat(fd, &st) != 0) {
        (void)close(fd);
        return IEC61850_MMS_FILE_ERR_IO;
    }

    iec61850_mms_file_handle_t *h = &fs->handles[handle_id];
    h->fd = fd;
    h->file_size = (uint32_t)st.st_size;
    h->position = 0;
    h->in_use = true;
    (void)strncpy(h->filename, filename, IEC61850_MMS_FILE_MAX_NAME - 1);
    h->filename[IEC61850_MMS_FILE_MAX_NAME - 1] = '\0';

    *file_size = h->file_size;
    return handle_id;
}

int iec61850_mms_file_read(iec61850_mms_file_service_t *fs,
                             int handle, uint8_t *buf, size_t buf_size,
                             size_t *read_len, bool *more)
{
    ssize_t n;

    if (fs == NULL || buf == NULL || read_len == NULL || more == NULL) {
        return IEC61850_MMS_FILE_ERR_ARGS;
    }

    if (handle < 0 || handle >= IEC61850_MMS_FILE_MAX_OPEN ||
        !fs->handles[handle].in_use) {
        return IEC61850_MMS_FILE_ERR_INVALID_HANDLE;
    }

    iec61850_mms_file_handle_t *h = &fs->handles[handle];

    /* Limit chunk size */
    size_t to_read = buf_size;
    if (to_read > IEC61850_MMS_FILE_MAX_CHUNK) {
        to_read = IEC61850_MMS_FILE_MAX_CHUNK;
    }

    n = read(h->fd, buf, to_read);
    if (n < 0) {
        *read_len = 0;
        *more = false;
        return IEC61850_MMS_FILE_ERR_IO;
    }

    *read_len = (size_t)n;
    h->position += (uint32_t)n;
    *more = (h->position < h->file_size);

    return IEC61850_MMS_FILE_OK;
}

int iec61850_mms_file_close(iec61850_mms_file_service_t *fs, int handle)
{
    if (fs == NULL) {
        return IEC61850_MMS_FILE_ERR_ARGS;
    }

    if (handle < 0 || handle >= IEC61850_MMS_FILE_MAX_OPEN ||
        !fs->handles[handle].in_use) {
        return IEC61850_MMS_FILE_ERR_INVALID_HANDLE;
    }

    iec61850_mms_file_handle_t *h = &fs->handles[handle];
    if (h->fd >= 0) {
        (void)close(h->fd);
        h->fd = -1;
    }
    h->in_use = false;
    return IEC61850_MMS_FILE_OK;
}

int iec61850_mms_file_delete(iec61850_mms_file_service_t *fs,
                               const char *filename)
{
    char fullpath[IEC61850_MMS_FILE_MAX_NAME * 2];
    int ret;

    if (fs == NULL || filename == NULL) {
        return IEC61850_MMS_FILE_ERR_ARGS;
    }

    if (!validate_filename(filename)) {
        return IEC61850_MMS_FILE_ERR_ARGS;
    }

    ret = build_path(fs, filename, fullpath, sizeof(fullpath));
    if (ret != IEC61850_MMS_FILE_OK) {
        return ret;
    }

    if (unlink(fullpath) != 0) {
        if (errno == ENOENT) {
            return IEC61850_MMS_FILE_ERR_NOT_FOUND;
        }
        return IEC61850_MMS_FILE_ERR_ACCESS;
    }

    return IEC61850_MMS_FILE_OK;
}

int iec61850_mms_file_rename(iec61850_mms_file_service_t *fs,
                               const char *old_name, const char *new_name)
{
    char old_path[IEC61850_MMS_FILE_MAX_NAME * 2];
    char new_path[IEC61850_MMS_FILE_MAX_NAME * 2];
    int ret;

    if (fs == NULL || old_name == NULL || new_name == NULL) {
        return IEC61850_MMS_FILE_ERR_ARGS;
    }

    if (!validate_filename(old_name) || !validate_filename(new_name)) {
        return IEC61850_MMS_FILE_ERR_ARGS;
    }

    ret = build_path(fs, old_name, old_path, sizeof(old_path));
    if (ret != IEC61850_MMS_FILE_OK) { return ret; }

    ret = build_path(fs, new_name, new_path, sizeof(new_path));
    if (ret != IEC61850_MMS_FILE_OK) { return ret; }

    if (rename(old_path, new_path) != 0) {
        if (errno == ENOENT) {
            return IEC61850_MMS_FILE_ERR_NOT_FOUND;
        }
        return IEC61850_MMS_FILE_ERR_ACCESS;
    }

    return IEC61850_MMS_FILE_OK;
}
