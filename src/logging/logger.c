/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Thread-Safe Logger Implementation
 *
 * Module-level static state with pthread_mutex_t for thread safety.
 * Replaces C++ singleton Logger class.
 */


#include "logging/logger.h"

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <pthread.h>

/* Module-level static state */
static pthread_mutex_t g_logger_mutex = PTHREAD_MUTEX_INITIALIZER;
static iec61850_log_level_t g_min_level = IEC61850_LOG_INFO;
static FILE *g_log_file = NULL;

void iec61850_logger_set_level(iec61850_log_level_t level)
{
    (void)pthread_mutex_lock(&g_logger_mutex);
    g_min_level = level;
    (void)pthread_mutex_unlock(&g_logger_mutex);
}

iec61850_log_level_t iec61850_logger_get_level(void)
{
    iec61850_log_level_t level;

    (void)pthread_mutex_lock(&g_logger_mutex);
    level = g_min_level;
    (void)pthread_mutex_unlock(&g_logger_mutex);

    return level;
}

bool iec61850_logger_is_enabled(iec61850_log_level_t level)
{
    /* Lock-free read: g_min_level is a small enum, reads are atomic on
     * all supported platforms. For strict C11 atomics, this could use
     * _Atomic, but the mutex path is also acceptable. */
    return level >= g_min_level;
}

int iec61850_logger_open_file(const char *path)
{
    int result;

    if (path == NULL) {
        result = -1;
    } else {
        (void)pthread_mutex_lock(&g_logger_mutex);

        /* Close existing file if open */
        if (g_log_file != NULL) {
            (void)fclose(g_log_file);
            g_log_file = NULL;
        }

        g_log_file = fopen(path, "a");
        if (g_log_file == NULL) {
            result = -1;
        } else {
            result = 0;
        }

        (void)pthread_mutex_unlock(&g_logger_mutex);
    }

    return result;
}

void iec61850_logger_log(iec61850_log_level_t level, const char *component,
                          const char *message)
{
    char timestamp[32];
    char line[1024];
    struct timespec ts;
    struct tm tm_buf;
    time_t sec;

    /* Fast path: filter before locking */
    if (level < g_min_level) {
        return;
    }

    if (component == NULL) {
        component = "UNKNOWN";
    }
    if (message == NULL) {
        message = "";
    }

    /* Format timestamp */
    (void)clock_gettime(CLOCK_REALTIME, &ts);
    sec = ts.tv_sec;
    (void)localtime_r(&sec, &tm_buf);
    (void)strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", &tm_buf);

    /* Format the log line */
    (void)snprintf(line, sizeof(line), "%s [%-8s] [%10s] %s",
                   timestamp,
                   iec61850_log_level_to_string(level),
                   component,
                   message);

    (void)pthread_mutex_lock(&g_logger_mutex);

    /* Write to file if configured */
    if (g_log_file != NULL) {
        (void)fprintf(g_log_file, "%s\n", line);
        (void)fflush(g_log_file);
    }

    /* Also write to console (stderr for WARNING+, stdout otherwise) */
    if (level >= IEC61850_LOG_WARNING) {
        (void)fprintf(stderr, "%s\n", line);
    } else {
        (void)fprintf(stdout, "%s\n", line);
    }

    (void)pthread_mutex_unlock(&g_logger_mutex);
}

void iec61850_logger_close(void)
{
    (void)pthread_mutex_lock(&g_logger_mutex);

    if (g_log_file != NULL) {
        (void)fclose(g_log_file);
        g_log_file = NULL;
    }

    g_min_level = IEC61850_LOG_INFO;

    (void)pthread_mutex_unlock(&g_logger_mutex);
}

const char *iec61850_log_level_to_string(iec61850_log_level_t level)
{
    const char *result;

    switch (level) {
        case IEC61850_LOG_TRACE:    result = "TRACE";    break;
        case IEC61850_LOG_DEBUG:    result = "DEBUG";    break;
        case IEC61850_LOG_INFO:     result = "INFO";     break;
        case IEC61850_LOG_WARNING:  result = "WARNING";  break;
        case IEC61850_LOG_ERROR:    result = "ERROR";    break;
        case IEC61850_LOG_CRITICAL: result = "CRITICAL"; break;
        default:                    result = "UNKNOWN";  break;
    }

    return result;
}

iec61850_log_level_t iec61850_log_level_from_string(const char *str)
{
    iec61850_log_level_t result = IEC61850_LOG_INFO; /* default for NULL or unknown */

    if (str == NULL) {
        return result;
    } else if (strcasecmp(str, "trace") == 0) {
        result = IEC61850_LOG_TRACE;
    } else if (strcasecmp(str, "debug") == 0) {
        result = IEC61850_LOG_DEBUG;
    } else if (strcasecmp(str, "info") == 0) {
        result = IEC61850_LOG_INFO;
    } else if (strcasecmp(str, "warning") == 0) {
        result = IEC61850_LOG_WARNING;
    } else if (strcasecmp(str, "error") == 0) {
        result = IEC61850_LOG_ERROR;
    } else if (strcasecmp(str, "critical") == 0) {
        result = IEC61850_LOG_CRITICAL;
    } else {
        result = IEC61850_LOG_INFO;
    }

    return result;
}
