/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Journal Service Implementation
 *
 * Circular buffer of timestamped journal entries with time-range
 * and entry-ID queries.
 */

#include "mms/mms_journal.h"
#include <string.h>
#include <errno.h>

void iec61850_journal_init(iec61850_journal_t *journal,
                             const char *name)
{
    if (journal == NULL) { return; }
    (void)memset(journal, 0, sizeof(*journal));
    journal->next_entry_id = 1;
    if (name != NULL) {
        (void)strncpy(journal->journal_name, name,
                       IEC61850_JOURNAL_MAX_VAR_NAME - 1);
    }
}

uint64_t iec61850_journal_add_entry(iec61850_journal_t *journal,
                                      const char *variable_ref,
                                      const mms_value_t *value,
                                      uint64_t timestamp_ms)
{
    iec61850_journal_entry_t *entry;

    if (journal == NULL) { return 0; }

    entry = &journal->entries[journal->head];
    entry->entry_id = journal->next_entry_id++;
    entry->timestamp_ms = timestamp_ms;
    entry->valid = true;

    if (variable_ref != NULL) {
        (void)strncpy(entry->variable_ref, variable_ref,
                       IEC61850_JOURNAL_MAX_VAR_NAME - 1);
        entry->variable_ref[IEC61850_JOURNAL_MAX_VAR_NAME - 1] = '\0';
    } else {
        entry->variable_ref[0] = '\0';
    }

    if (value != NULL) {
        entry->value = *value;
    } else {
        (void)memset(&entry->value, 0, sizeof(entry->value));
    }

    journal->head = (journal->head + 1U) % (uint32_t)IEC61850_JOURNAL_MAX_ENTRIES;
    if (journal->count < (uint32_t)IEC61850_JOURNAL_MAX_ENTRIES) {
        journal->count++;
    }

    return entry->entry_id;
}

int iec61850_journal_read_by_time(const iec61850_journal_t *journal,
                                    uint64_t start_ms, uint64_t end_ms,
                                    iec61850_journal_entry_t *out,
                                    uint32_t *count, uint32_t max_count)
{
    uint32_t found = 0;
    uint32_t start;

    if (journal == NULL || out == NULL || count == NULL) {
        return -EINVAL;
    }

    *count = 0;

    if (journal->count == 0U) {
        return 0;
    }

    /* Start from oldest entry */
    if (journal->count < (uint32_t)IEC61850_JOURNAL_MAX_ENTRIES) {
        start = 0U;
    } else {
        start = journal->head;
    }

    for (uint32_t i = 0U; i < journal->count && found < max_count; i++) {
        uint32_t idx = (start + i) % (uint32_t)IEC61850_JOURNAL_MAX_ENTRIES;
        const iec61850_journal_entry_t *e = &journal->entries[idx];

        if (!e->valid) { continue; }

        /* Time range filter */
        if (start_ms > 0ULL && e->timestamp_ms < start_ms) { continue; }
        if (end_ms > 0ULL && e->timestamp_ms > end_ms) { continue; }

        out[found++] = *e;
    }

    *count = found;
    return 0;
}

int iec61850_journal_read_by_id(const iec61850_journal_t *journal,
                                  uint64_t after_id,
                                  iec61850_journal_entry_t *out,
                                  uint32_t *count, uint32_t max_count)
{
    uint32_t found = 0;
    uint32_t start;

    if (journal == NULL || out == NULL || count == NULL) {
        return -EINVAL;
    }

    *count = 0;

    if (journal->count == 0U) {
        return 0;
    }

    if (journal->count < (uint32_t)IEC61850_JOURNAL_MAX_ENTRIES) {
        start = 0U;
    } else {
        start = journal->head;
    }

    for (uint32_t i = 0U; i < journal->count && found < max_count; i++) {
        uint32_t idx = (start + i) % (uint32_t)IEC61850_JOURNAL_MAX_ENTRIES;
        const iec61850_journal_entry_t *e = &journal->entries[idx];

        if (!e->valid) { continue; }
        if (e->entry_id <= after_id) { continue; }

        out[found++] = *e;
    }

    *count = found;
    return 0;
}

uint32_t iec61850_journal_get_count(const iec61850_journal_t *journal)
{
    if (journal == NULL) { return 0; }
    return journal->count;
}
