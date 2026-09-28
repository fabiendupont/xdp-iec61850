/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Minimal YAML Parser Implementation
 *
 * Hand-written parser for the YAML subset used in IEC 61850 config files.
 * No external dependencies (no libyaml, no yaml-cpp).
 *
 * License: BSD-3-Clause
 */


#include "config/yaml_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <strings.h>

void iec61850_yaml_doc_init(iec61850_yaml_doc_t *doc)
{
    if (doc != NULL) {
        doc->count = 0;
    }
}

void iec61850_yaml_doc_free(iec61850_yaml_doc_t *doc)
{
    if (doc != NULL) {
        doc->count = 0;
    }
}

/* Strip leading whitespace, return indent level */
static size_t count_indent(const char *line)
{
    size_t indent = 0;
    while (line[indent] == ' ') {
        indent++;
    }
    return indent;
}

/* Strip trailing whitespace and newline */
static void strip_trailing(char *s)
{
    size_t len = strlen(s);
    while (len > 0 && (s[len - 1] == '\n' || s[len - 1] == '\r' ||
                        s[len - 1] == ' ' || s[len - 1] == '\t')) {
        s[len - 1] = '\0';
        len--;
    }
}

/* Strip inline comments (# not inside quotes) */
static void strip_comment(char *s)
{
    bool in_single = false;
    bool in_double = false;

    for (size_t i = 0; s[i] != '\0'; i++) {
        if (s[i] == '\'' && !in_double) {
            in_single = !in_single;
        } else if (s[i] == '"' && !in_single) {
            in_double = !in_double;
        } else if (s[i] == '#' && !in_single && !in_double) {
            /* Check that there's a space before # (YAML rule) */
            if (i == 0 || s[i - 1] == ' ') {
                s[i] = '\0';
                strip_trailing(s);
                return;
            }
        }
    }
}

/* Strip surrounding quotes from a value */
static void strip_quotes(char *s)
{
    size_t len = strlen(s);
    if (len >= 2) {
        if ((s[0] == '"' && s[len - 1] == '"') ||
            (s[0] == '\'' && s[len - 1] == '\'')) {
            (void)memmove(s, s + 1, len - 2);
            s[len - 2] = '\0';
        }
    }
}

/* Find or create an entry by key */
static iec61850_yaml_entry_t *find_or_create(iec61850_yaml_doc_t *doc,
                                              const char *key)
{
    /* Search existing */
    for (size_t i = 0; i < doc->count; i++) {
        if (strcmp(doc->entries[i].key, key) == 0) {
            return &doc->entries[i];
        }
    }

    /* Create new */
    if (doc->count >= IEC61850_YAML_MAX_ENTRIES) {
        return NULL;
    }

    iec61850_yaml_entry_t *entry = &doc->entries[doc->count];
    (void)strncpy(entry->key, key, IEC61850_YAML_MAX_KEY_LEN - 1);
    entry->key[IEC61850_YAML_MAX_KEY_LEN - 1] = '\0';
    entry->type = IEC61850_YAML_STRING;
    entry->value[0] = '\0';
    entry->list_count = 0;
    doc->count++;

    return entry;
}

int iec61850_yaml_parse_file(const char *path, iec61850_yaml_doc_t *doc)
{
    FILE *f;
    char line[1024];
    char section[IEC61850_YAML_MAX_KEY_LEN];
    char full_key[IEC61850_YAML_MAX_KEY_LEN * 2];
    char *colon;
    char *value_start;
    size_t indent;
    size_t key_len;
    iec61850_yaml_entry_t *list_entry;

    if (path == NULL || doc == NULL) {
        return -1;
    }

    f = fopen(path, "r");
    if (f == NULL) {
        return -1;
    }

    section[0] = '\0';
    list_entry = NULL;

    while (fgets(line, (int)sizeof(line), f) != NULL) {
        strip_trailing(line);
        strip_comment(line);

        /* Skip empty lines */
        if (line[0] == '\0') {
            continue;
        }

        indent = count_indent(line);

        /* Skip pure comment lines */
        if (line[indent] == '#') {
            continue;
        }

        /* List item: "  - value" */
        if (line[indent] == '-' && line[indent + 1] == ' ') {
            if (list_entry != NULL &&
                list_entry->list_count < IEC61850_YAML_MAX_LIST_ITEMS) {
                value_start = &line[indent + 2];
                /* Skip leading whitespace */
                while (*value_start == ' ') { value_start++; }
                strip_quotes(value_start);
                (void)strncpy(
                    list_entry->list[list_entry->list_count],
                    value_start,
                    IEC61850_YAML_MAX_VALUE_LEN - 1);
                list_entry->list[list_entry->list_count][IEC61850_YAML_MAX_VALUE_LEN - 1] = '\0';
                list_entry->list_count++;
                list_entry->type = IEC61850_YAML_LIST;
            }
            continue;
        }

        /* Not a list item, clear list context if indent changed */
        list_entry = NULL;

        /* Find colon */
        colon = strchr(&line[indent], ':');
        if (colon == NULL) {
            continue;
        }

        /* Extract key */
        key_len = (size_t)(colon - &line[indent]);
        if (key_len == 0 || key_len >= IEC61850_YAML_MAX_KEY_LEN) {
            continue;
        }

        /* Build key string */
        char raw_key[IEC61850_YAML_MAX_KEY_LEN];
        (void)memcpy(raw_key, &line[indent], key_len);
        raw_key[key_len] = '\0';
        strip_trailing(raw_key);

        /* Value part (after colon) */
        value_start = colon + 1;
        while (*value_start == ' ') { value_start++; }

        if (indent == 0) {
            /* Top-level key */
            if (*value_start == '\0') {
                /* Section header (no value = next lines are nested or list) */
                (void)strncpy(section, raw_key, IEC61850_YAML_MAX_KEY_LEN - 1);
                section[IEC61850_YAML_MAX_KEY_LEN - 1] = '\0';
                /* Pre-create entry for direct lists under top-level key */
                list_entry = find_or_create(doc, raw_key);
            } else {
                /* Flat key-value */
                section[0] = '\0';
                strip_quotes(value_start);

                iec61850_yaml_entry_t *entry = find_or_create(doc, raw_key);
                if (entry != NULL) {
                    (void)strncpy(entry->value, value_start,
                                  IEC61850_YAML_MAX_VALUE_LEN - 1);
                    entry->value[IEC61850_YAML_MAX_VALUE_LEN - 1] = '\0';
                }
            }
        } else {
            /* Nested key: section.key */
            if (section[0] != '\0') {
                (void)snprintf(full_key, sizeof(full_key), "%s.%s",
                               section, raw_key);
            } else {
                (void)strncpy(full_key, raw_key, sizeof(full_key) - 1);
                full_key[sizeof(full_key) - 1] = '\0';
            }

            if (*value_start == '\0') {
                /* This is a list header or sub-section */
                iec61850_yaml_entry_t *entry = find_or_create(doc, full_key);
                list_entry = entry;
            } else {
                strip_quotes(value_start);
                iec61850_yaml_entry_t *entry = find_or_create(doc, full_key);
                if (entry != NULL) {
                    (void)strncpy(entry->value, value_start,
                                  IEC61850_YAML_MAX_VALUE_LEN - 1);
                    entry->value[IEC61850_YAML_MAX_VALUE_LEN - 1] = '\0';
                }
            }
        }
    }

    (void)fclose(f);
    return 0;
}

/* Find entry by key */
static const iec61850_yaml_entry_t *find_entry(const iec61850_yaml_doc_t *doc,
                                                const char *key)
{
    for (size_t i = 0; i < doc->count; i++) {
        if (strcmp(doc->entries[i].key, key) == 0) {
            return &doc->entries[i];
        }
    }
    return NULL;
}

const char *iec61850_yaml_get_string(const iec61850_yaml_doc_t *doc,
                                      const char *key)
{
    const iec61850_yaml_entry_t *entry = find_entry(doc, key);
    if (entry == NULL || entry->type != IEC61850_YAML_STRING) {
        return NULL;
    }
    return entry->value;
}

int iec61850_yaml_get_int(const iec61850_yaml_doc_t *doc,
                           const char *key,
                           int default_val)
{
    const iec61850_yaml_entry_t *entry = find_entry(doc, key);
    if (entry == NULL || entry->type != IEC61850_YAML_STRING) {
        return default_val;
    }
    if (entry->value[0] == '\0') {
        return default_val;
    }

    char *endptr;
    long val = strtol(entry->value, &endptr, 10);
    if (*endptr != '\0') {
        return default_val;
    }
    return (int)val;
}

bool iec61850_yaml_get_bool(const iec61850_yaml_doc_t *doc,
                             const char *key,
                             bool default_val)
{
    const iec61850_yaml_entry_t *entry = find_entry(doc, key);
    if (entry == NULL || entry->type != IEC61850_YAML_STRING) {
        return default_val;
    }
    if (entry->value[0] == '\0') {
        return default_val;
    }

    if (strcasecmp(entry->value, "true") == 0 ||
        strcasecmp(entry->value, "yes") == 0) {
        return true;
    }
    if (strcasecmp(entry->value, "false") == 0 ||
        strcasecmp(entry->value, "no") == 0) {
        return false;
    }

    return default_val;
}

/* Static storage for list pointers returned by get_list */
static const char *s_list_ptrs[IEC61850_YAML_MAX_LIST_ITEMS];

const char **iec61850_yaml_get_list(const iec61850_yaml_doc_t *doc,
                                     const char *key,
                                     size_t *count)
{
    const iec61850_yaml_entry_t *entry = find_entry(doc, key);
    if (entry == NULL || entry->type != IEC61850_YAML_LIST ||
        entry->list_count == 0) {
        if (count != NULL) { *count = 0; }
        return NULL;
    }

    for (size_t i = 0; i < entry->list_count; i++) {
        s_list_ptrs[i] = entry->list[i];
    }

    if (count != NULL) {
        *count = entry->list_count;
    }
    return s_list_ptrs;
}
