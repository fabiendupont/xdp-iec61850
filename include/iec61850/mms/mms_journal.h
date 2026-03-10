/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * MMS Journal Service for IEC 61850
 *
 * Historical data access via journal entries.
 * Stores timestamped data values and allows time-range queries.
 */

#ifndef IEC61850_MMS_JOURNAL_H
#define IEC61850_MMS_JOURNAL_H

#include "asn1/mms_ber.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Limits */
#define IEC61850_JOURNAL_MAX_ENTRIES   1024
#define IEC61850_JOURNAL_MAX_VAR_NAME  128

/* Result codes */
typedef enum {
    IEC61850_JOURNAL_OK = 0,
    IEC61850_JOURNAL_ERR_ARGS = -1,
    IEC61850_JOURNAL_ERR_FULL = -2,
    IEC61850_JOURNAL_ERR_NOT_FOUND = -3
} iec61850_journal_result_t;

/* Journal entry */
typedef struct {
    uint64_t entry_id;
    uint64_t timestamp_ms;      /* Unix timestamp in milliseconds */
    char variable_ref[IEC61850_JOURNAL_MAX_VAR_NAME];
    mms_value_t value;
    bool valid;
} iec61850_journal_entry_t;

/* Journal manager (circular buffer of entries) */
typedef struct {
    iec61850_journal_entry_t entries[IEC61850_JOURNAL_MAX_ENTRIES];
    uint32_t head;
    uint32_t count;
    uint64_t next_entry_id;
    char journal_name[IEC61850_JOURNAL_MAX_VAR_NAME];
} iec61850_journal_t;

/**
 * Initialize journal.
 */
void iec61850_journal_init(iec61850_journal_t *journal,
                             const char *name);

/**
 * Add an entry to the journal.
 *
 * @return entry_id on success, 0 on error
 */
uint64_t iec61850_journal_add_entry(iec61850_journal_t *journal,
                                      const char *variable_ref,
                                      const mms_value_t *value,
                                      uint64_t timestamp_ms);

/**
 * Read journal entries by time range.
 *
 * @param journal     Journal
 * @param start_ms    Start time (inclusive), 0 = from beginning
 * @param end_ms      End time (inclusive), 0 = to end
 * @param out         Output array
 * @param count       Output: number of entries returned
 * @param max_count   Maximum entries to return
 * @return 0 on success
 */
int iec61850_journal_read_by_time(const iec61850_journal_t *journal,
                                    uint64_t start_ms, uint64_t end_ms,
                                    iec61850_journal_entry_t *out,
                                    uint32_t *count, uint32_t max_count);

/**
 * Read journal entries by entry ID range.
 *
 * @param journal     Journal
 * @param after_id    Return entries after this ID (0 = all)
 * @param out         Output array
 * @param count       Output: number of entries returned
 * @param max_count   Maximum entries to return
 * @return 0 on success
 */
int iec61850_journal_read_by_id(const iec61850_journal_t *journal,
                                  uint64_t after_id,
                                  iec61850_journal_entry_t *out,
                                  uint32_t *count, uint32_t max_count);

/**
 * Get total number of entries in journal.
 */
uint32_t iec61850_journal_get_count(const iec61850_journal_t *journal);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_MMS_JOURNAL_H */
