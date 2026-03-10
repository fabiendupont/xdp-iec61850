/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Minimal YAML Parser for IEC 61850 Configuration
 *
 * Supports the YAML subset needed for project config files:
 * - Flat maps (key: value)
 * - 2-level nested maps (section.key: value)
 * - String lists (- item), including nested (section.key: [items])
 * - Scalar types: strings, integers, booleans
 * - Comments (# ...)
 * - Quoted strings (double and single)
 *
 * License: BSD-3-Clause
 */

#ifndef IEC61850_YAML_PARSER_H
#define IEC61850_YAML_PARSER_H

#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Limits */
#define IEC61850_YAML_MAX_ENTRIES   128
#define IEC61850_YAML_MAX_KEY_LEN   128
#define IEC61850_YAML_MAX_VALUE_LEN 512
#define IEC61850_YAML_MAX_LIST_ITEMS 32

/* Entry types */
typedef enum {
    IEC61850_YAML_STRING,
    IEC61850_YAML_LIST
} iec61850_yaml_type_t;

/* A single key-value entry */
typedef struct {
    char key[IEC61850_YAML_MAX_KEY_LEN];
    iec61850_yaml_type_t type;

    /* String value (for YAML_STRING) */
    char value[IEC61850_YAML_MAX_VALUE_LEN];

    /* List values (for YAML_LIST) */
    char list[IEC61850_YAML_MAX_LIST_ITEMS][IEC61850_YAML_MAX_VALUE_LEN];
    size_t list_count;
} iec61850_yaml_entry_t;

/* Parsed YAML document */
typedef struct {
    iec61850_yaml_entry_t entries[IEC61850_YAML_MAX_ENTRIES];
    size_t count;
} iec61850_yaml_doc_t;

/**
 * Initialize a YAML document structure.
 */
void iec61850_yaml_doc_init(iec61850_yaml_doc_t *doc);

/**
 * Free any resources held by a YAML document.
 */
void iec61850_yaml_doc_free(iec61850_yaml_doc_t *doc);

/**
 * Parse a YAML file into a document.
 *
 * @param path  File path
 * @param doc   Output document (must be initialized)
 * @return 0 on success, -1 on failure
 */
int iec61850_yaml_parse_file(const char *path, iec61850_yaml_doc_t *doc);

/**
 * Get a string value by dotted key (e.g., "logging.level").
 * Returns default_val if key not found.
 */
const char *iec61850_yaml_get_string(const iec61850_yaml_doc_t *doc,
                                      const char *key,
                                      const char *default_val);

/**
 * Get an integer value by dotted key.
 * Returns default_val if key not found or not parseable.
 */
int iec61850_yaml_get_int(const iec61850_yaml_doc_t *doc,
                           const char *key,
                           int default_val);

/**
 * Get a boolean value by dotted key.
 * Recognizes: true/false, yes/no (case-insensitive).
 * Returns default_val if key not found.
 */
bool iec61850_yaml_get_bool(const iec61850_yaml_doc_t *doc,
                             const char *key,
                             bool default_val);

/**
 * Get a list of strings by dotted key.
 *
 * @param doc       Document
 * @param key       Dotted key
 * @param count     Output: number of items
 * @return Array of string pointers (internal to doc, do not free),
 *         or NULL if key not found
 */
const char **iec61850_yaml_get_list(const iec61850_yaml_doc_t *doc,
                                     const char *key,
                                     size_t *count);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_YAML_PARSER_H */
