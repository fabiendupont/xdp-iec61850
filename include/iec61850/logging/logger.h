/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Thread-Safe Logging for IEC 61850
 *
 * C11 replacement for the C++ Logger singleton. Uses module-level static
 * state with pthread_mutex_t for thread safety. FILE* for output,
 * snprintf() for formatting.
 *
 * API:
 *   iec61850_logger_set_level()     - Set minimum log level
 *   iec61850_logger_get_level()     - Get current log level
 *   iec61850_logger_is_enabled()    - Check if level would be logged
 *   iec61850_logger_open_file()     - Direct output to a file (append)
 *   iec61850_logger_log()           - Log a message
 *   iec61850_logger_close()         - Close file, reset state
 */

#ifndef IEC61850_LOGGER_H
#define IEC61850_LOGGER_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Log levels (ordered: TRACE < DEBUG < INFO < WARNING < ERROR < CRITICAL) */
typedef enum {
    IEC61850_LOG_TRACE    = 0,
    IEC61850_LOG_DEBUG    = 1,
    IEC61850_LOG_INFO     = 2,
    IEC61850_LOG_WARNING  = 3,
    IEC61850_LOG_ERROR    = 4,
    IEC61850_LOG_CRITICAL = 5
} iec61850_log_level_t;

/**
 * Set the minimum log level. Messages below this level are discarded.
 */
void iec61850_logger_set_level(iec61850_log_level_t level);

/**
 * Get the current minimum log level.
 */
iec61850_log_level_t iec61850_logger_get_level(void);

/**
 * Check if a given log level would be logged.
 */
bool iec61850_logger_is_enabled(iec61850_log_level_t level);

/**
 * Open a log file for output (append mode).
 * If a file is already open, it is closed first.
 *
 * @param path  File path to open
 * @return 0 on success, -1 on failure
 */
int iec61850_logger_open_file(const char *path);

/**
 * Log a formatted message.
 *
 * @param level     Log level
 * @param component Component name (e.g., "GOOSE", "SV", "MMS")
 * @param message   Message text
 */
void iec61850_logger_log(iec61850_log_level_t level, const char *component,
                          const char *message);

/**
 * Close the logger: flush and close file, reset to defaults.
 * After close(), the logger is in default state (INFO level, no file).
 */
void iec61850_logger_close(void);

/**
 * Convert log level enum to string.
 */
const char *iec61850_log_level_to_string(iec61850_log_level_t level);

/**
 * Parse log level from string (case-insensitive).
 * Returns IEC61850_LOG_INFO for unknown strings.
 */
iec61850_log_level_t iec61850_log_level_from_string(const char *str);

/* Convenience macros */
#define IEC61850_LOG_TRACE_MSG(component, msg) \
    do { \
        if (iec61850_logger_is_enabled(IEC61850_LOG_TRACE)) { \
            iec61850_logger_log(IEC61850_LOG_TRACE, component, msg); \
        } \
    } while (0)

#define IEC61850_LOG_DEBUG_MSG(component, msg) \
    do { \
        if (iec61850_logger_is_enabled(IEC61850_LOG_DEBUG)) { \
            iec61850_logger_log(IEC61850_LOG_DEBUG, component, msg); \
        } \
    } while (0)

#define IEC61850_LOG_INFO_MSG(component, msg) \
    do { \
        if (iec61850_logger_is_enabled(IEC61850_LOG_INFO)) { \
            iec61850_logger_log(IEC61850_LOG_INFO, component, msg); \
        } \
    } while (0)

#define IEC61850_LOG_WARNING_MSG(component, msg) \
    do { \
        if (iec61850_logger_is_enabled(IEC61850_LOG_WARNING)) { \
            iec61850_logger_log(IEC61850_LOG_WARNING, component, msg); \
        } \
    } while (0)

#define IEC61850_LOG_ERROR_MSG(component, msg) \
    do { \
        if (iec61850_logger_is_enabled(IEC61850_LOG_ERROR)) { \
            iec61850_logger_log(IEC61850_LOG_ERROR, component, msg); \
        } \
    } while (0)

#define IEC61850_LOG_CRITICAL_MSG(component, msg) \
    do { \
        if (iec61850_logger_is_enabled(IEC61850_LOG_CRITICAL)) { \
            iec61850_logger_log(IEC61850_LOG_CRITICAL, component, msg); \
        } \
    } while (0)

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_LOGGER_H */
