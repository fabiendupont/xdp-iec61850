/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850 Model-Driven Publishing Binding — Implementation (WP-6d)
 *
 * Implements the frozen interface in
 * include/iec61850/ied/model_binding.h: one DataAttribute change
 * fans out to GOOSE and SV publishers from a single IED data model.
 *
 * Watch mechanism (coexistence): the data model supports exactly
 * ONE change callback per DataAttribute
 * (iec61850_da_set_change_callback). To coexist with a listener
 * registered before the binding (e.g. an MMS-side observer on the
 * DA-change path, as used by the MMS variable binding tests), each
 * watched DA gets a watch node allocated at BIND time only
 * (init-time allocation, mirroring ied_data_model.c's tree
 * construction; never on the change path). The node chains the
 * previously-registered callback; the installed trampoline invokes
 * the chained listener first, then updates every mapped publisher
 * slot from the DA's current value and marks the owning publishers
 * dirty. No publication happens inside the callback —
 * iec61850_model_binding_process() publishes for dirty publishers
 * (single-threaded contract).
 *
 * resolved[i] of each publisher slot caches the watch node of
 * ref i; the node embeds the resolved DataAttribute pointer.
 * Multiple refs to the same DA (within or across publishers)
 * share one node, so a single change fans out to every mapped
 * slot by pointer comparison. iec61850_model_binding_destroy()
 * restores the chained callbacks, frees the nodes, and zeroes
 * the struct (idempotent).
 *
 * Limitation (documented): with two binding instances watching
 * the same DA, the second instance chains on top of the first's
 * trampoline. Destroy bindings in reverse order of creation;
 * destroying the first-chained binding first would clobber the
 * second's trampoline (a single callback slot per DA).
 *
 * License: BSD-2-Clause
 */

#include "ied/model_binding.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ========================================================================
 * Internal types
 * ======================================================================== */

/*
 * One per-DA watch: the collection node that chains the listener
 * registered before the binding (if any) below the binding's
 * trampoline. Allocated at bind time, freed at destroy time.
 */
typedef struct {
    iec61850_data_attribute_t *da;   /* watched DataAttribute */
    iec61850_da_change_cb_t prev_cb; /* chained listener (may be NULL) */
    void *prev_user_data;            /* its user_data */
    iec61850_model_binding_t *owner; /* binding that installed this */
} iec61850_binding_watch_t;

/* ========================================================================
 * Reference resolution
 * ======================================================================== */

/*
 * Match an LN name against a reference's ln component. Accepts the
 * two conventions present in the tree:
 *   - full name in ln_inst (iec61850_ied_model_add_ln_class():
 *     prefix + class + inst, e.g. "XCBR1" — the register_mms
 *     convention),
 *   - plain inst in ln_inst with class + inst combined on the fly
 *     (iec61850_ln_create(), e.g. class "XCBR" + inst "1"),
 * plus the bare class name (first LN of that class, matching
 * iec61850_ld_find_ln()).
 */
static bool binding_ln_matches(const iec61850_logical_node_t *ln,
                                const char *name)
{
    char combined[(IEC61850_MAX_NAME_LEN * 2U) + 1U];

    if (strcmp(ln->ln_inst, name) == 0) {
        return true;
    }

    (void)snprintf(combined, sizeof(combined), "%s%s",
                    ln->ln_class, ln->ln_inst);
    if (strcmp(combined, name) == 0) {
        return true;
    }

    return (strcmp(ln->ln_class, name) == 0);
}

/*
 * Resolve one DA reference against the model: LD by instance,
 * LN by name (both conventions), then the dotted DO.DA path with
 * an exact FC match. Returns the DA, or NULL on any miss.
 */
static iec61850_data_attribute_t *binding_resolve_ref(
    const iec61850_ied_model_t *model,
    const iec61850_da_ref_t *ref)
{
    const iec61850_logical_device_t *ld;
    const iec61850_logical_node_t *ln = NULL;
    char path[(IEC61850_MAX_NAME_LEN * 2U) + 2U];
    int n;

    ld = iec61850_ied_model_find_ld(model, ref->ld);
    if (ld == NULL) {
        return NULL;
    }

    for (size_t j = 0; j < ld->ln_count; j++) {
        if ((ld->logical_nodes[j] != NULL) &&
            (binding_ln_matches(ld->logical_nodes[j], ref->ln))) {
            ln = ld->logical_nodes[j];
            break;
        }
    }
    if (ln == NULL) {
        return NULL;
    }

    n = snprintf(path, sizeof(path), "%s.%s", ref->do_name, ref->da_name);
    if ((n < 0) || ((size_t)n >= sizeof(path))) {
        return NULL;
    }

    return iec61850_ln_find_attribute(ln, path, ref->fc);
}

/* ========================================================================
 * Value conversion (BTYPE -> publisher setter)
 * ======================================================================== */

/*
 * Whether a DA of this basic type can be pushed into the given
 * publisher kind. GOOSE datasets carry every scalar the publisher
 * can encode; SV slots carry int32 samples plus per-channel
 * quality, so only numeric types and Quality are accepted.
 * STRUCT never maps (it has no scalar encoding).
 */
static bool binding_type_mappable(bool is_sv, iec61850_btype_t btype)
{
    switch (btype) {
        case IEC61850_BTYPE_STRUCT:
            return false;
        case IEC61850_BTYPE_BOOLEAN:
        case IEC61850_BTYPE_INT8:
        case IEC61850_BTYPE_INT8U:
        case IEC61850_BTYPE_INT16:
        case IEC61850_BTYPE_INT16U:
        case IEC61850_BTYPE_INT32:
        case IEC61850_BTYPE_INT32U:
        case IEC61850_BTYPE_INT64:
        case IEC61850_BTYPE_INT128:
        case IEC61850_BTYPE_FLOAT32:
        case IEC61850_BTYPE_FLOAT64:
        case IEC61850_BTYPE_ENUMERATED:
        case IEC61850_BTYPE_CODED_ENUM:
        case IEC61850_BTYPE_QUALITY:
            return true;
        default:
            return !is_sv;
    }
}

/*
 * Bit k (0-based, BER order: MSB-first within each byte) of a
 * Quality-typed DA's bit string.
 */
static bool binding_quality_bit(const mms_value_t *val, uint32_t bit_idx)
{
    size_t byte_idx = (size_t)(bit_idx / 8U);

    if ((byte_idx >= sizeof(val->value.bit_string.data)) ||
        ((size_t)bit_idx >= val->value.bit_string.bit_count)) {
        return false;
    }
    return ((val->value.bit_string.data[byte_idx] >>
             (7U - (bit_idx % 8U))) & 0x01U) != 0U;
}

/*
 * Push one mapped GOOSE dataset slot from the DA's current value.
 * The mapping is mechanical, following btype_to_mms_type()'s value
 * storage in mms_value_t (src/scl/scl_ied_builder.c):
 *   BOOLEAN -> bool; signed INT and ENUMERATED -> int32;
 *   unsigned INT -> uint32; FLOAT -> float32;
 *   OCTET_STRING and strings -> octetstring;
 *   TIMESTAMP -> utctime; QUALITY/CHECK/DBPOS -> bitstring;
 *   ENTRY_TIME -> btime6 (derived from the UTC microseconds).
 */
static int binding_update_goose_slot(iec61850_binding_pub_t *bp,
                                      uint32_t idx,
                                      const mms_value_t *val)
{
    /* MISRA 11.5: pub is the bound GOOSE publisher, deviation Cat. 3 */
    iec61850_goose_publisher_t *pub = (iec61850_goose_publisher_t *)bp->pub;
    const iec61850_binding_watch_t *w = bp->resolved[idx];

    switch (w->da->btype) {
        case IEC61850_BTYPE_BOOLEAN:
            return iec61850_goose_publisher_set_boolean(pub, idx,
                                                          val->value.boolean);
        case IEC61850_BTYPE_INT8:
        case IEC61850_BTYPE_INT16:
        case IEC61850_BTYPE_INT32:
        case IEC61850_BTYPE_INT64:
        case IEC61850_BTYPE_INT128:
        case IEC61850_BTYPE_ENUMERATED:
        case IEC61850_BTYPE_CODED_ENUM:
            return iec61850_goose_publisher_set_int32(pub, idx,
                                                        val->value.integer);
        case IEC61850_BTYPE_INT8U:
        case IEC61850_BTYPE_INT16U:
        case IEC61850_BTYPE_INT32U:
            return iec61850_goose_publisher_set_uint32(pub, idx,
                                                         val->value.unsigned_val);
        case IEC61850_BTYPE_FLOAT32:
        case IEC61850_BTYPE_FLOAT64:
            return iec61850_goose_publisher_set_float32(pub, idx,
                                                          val->value.floating_point);
        case IEC61850_BTYPE_OCTET_STRING:
        case IEC61850_BTYPE_PHYS_COMM_ADDR:
            return iec61850_goose_publisher_set_octetstring(
                pub, idx, val->value.octet_string.data,
                val->value.octet_string.len);
        case IEC61850_BTYPE_VISIBLE_STRING:
        case IEC61850_BTYPE_UNICODE_STRING:
        case IEC61850_BTYPE_CURRENCY:
            return iec61850_goose_publisher_set_octetstring(
                pub, idx, (const uint8_t *)val->value.visible_string.data,
                val->value.visible_string.len);
        case IEC61850_BTYPE_TIMESTAMP:
            return iec61850_goose_publisher_set_utctime(pub, idx,
                                                          val->value.utc_time,
                                                          0U);
        case IEC61850_BTYPE_QUALITY:
        case IEC61850_BTYPE_CHECK:
        case IEC61850_BTYPE_DBPOS: {
            size_t len = (val->value.bit_string.bit_count + 7U) / 8U;
            if (len > sizeof(val->value.bit_string.data)) {
                len = sizeof(val->value.bit_string.data);
            }
            return iec61850_goose_publisher_set_bitstring(
                pub, idx, val->value.bit_string.data, len);
        }
        case IEC61850_BTYPE_ENTRY_TIME: {
            /* Btime6: ms since midnight (4) + days since epoch (2),
             * derived from the stored UTC microseconds. */
            uint64_t us = val->value.utc_time;
            uint32_t ms = (uint32_t)((us / 1000ULL) % 86400000ULL);
            uint16_t days = (uint16_t)(us / 86400000000ULL);
            return iec61850_goose_publisher_set_btime6(pub, idx, ms, days);
        }
        default:
            return -ENOTSUP;
    }
}

/*
 * Push one mapped SV slot from the DA's current value. Refs map
 * slot-for-slot to channels: a Quality-typed DA sets that
 * channel's quality; numeric DAs set the channel's int32 sample
 * (floats truncate toward zero — 9-2 samples are integer counts).
 * Note: the publisher only grows sample_count through
 * set_sample(), so channels covered solely by Quality refs must be
 * within the publisher's configured num_channels.
 */
static int binding_update_sv_slot(iec61850_binding_pub_t *bp,
                                   uint32_t idx,
                                   const mms_value_t *val)
{
    /* MISRA 11.5: pub is the bound SV publisher, deviation Cat. 3 */
    iec61850_sv_publisher_t *pub = (iec61850_sv_publisher_t *)bp->pub;
    const iec61850_binding_watch_t *w = bp->resolved[idx];

    switch (w->da->btype) {
        case IEC61850_BTYPE_QUALITY: {
            sv_quality_t q;
            (void)memset(&q, 0, sizeof(q));
            /* Bit k of the DA bit string -> quality field k
             * (declaration order, IEC 61850-7-3 Quality). The
             * ternary forms keep the value ranges provably within
             * the bitfield widths (-Wconversion). */
            q.validity = (uint8_t)((binding_quality_bit(val, 0U) ? 2U : 0U) |
                                   (binding_quality_bit(val, 1U) ? 1U : 0U));
            q.overflow = binding_quality_bit(val, 2U);
            q.out_of_range = binding_quality_bit(val, 3U);
            q.bad_reference = binding_quality_bit(val, 4U);
            q.oscillatory = binding_quality_bit(val, 5U);
            q.failure = binding_quality_bit(val, 6U);
            q.old_data = binding_quality_bit(val, 7U);
            q.inconsistent = binding_quality_bit(val, 8U);
            q.inaccurate = binding_quality_bit(val, 9U);
            q.source = binding_quality_bit(val, 10U);
            q.test = binding_quality_bit(val, 11U);
            q.operator_blocked = binding_quality_bit(val, 12U);
            return iec61850_sv_publisher_set_quality(pub, idx, q);
        }
        case IEC61850_BTYPE_BOOLEAN:
            return iec61850_sv_publisher_set_sample(
                pub, idx, val->value.boolean ? 1 : 0);
        case IEC61850_BTYPE_INT8:
        case IEC61850_BTYPE_INT16:
        case IEC61850_BTYPE_INT32:
        case IEC61850_BTYPE_INT64:
        case IEC61850_BTYPE_INT128:
        case IEC61850_BTYPE_ENUMERATED:
        case IEC61850_BTYPE_CODED_ENUM:
            return iec61850_sv_publisher_set_sample(pub, idx,
                                                     val->value.integer);
        case IEC61850_BTYPE_INT8U:
        case IEC61850_BTYPE_INT16U:
        case IEC61850_BTYPE_INT32U:
            return iec61850_sv_publisher_set_sample(
                pub, idx, (int32_t)val->value.unsigned_val);
        case IEC61850_BTYPE_FLOAT32:
        case IEC61850_BTYPE_FLOAT64:
            return iec61850_sv_publisher_set_sample(
                pub, idx, (int32_t)val->value.floating_point);
        default:
            return -ENOTSUP;
    }
}

/* Push one mapped slot (either publisher kind) from the DA's
 * current value. Returns 0, or negative errno. */
static int binding_update_slot(iec61850_binding_pub_t *bp, uint32_t idx)
{
    iec61850_binding_watch_t *w = bp->resolved[idx];
    mms_value_t val;

    if (w == NULL) {
        return -EINVAL;
    }

    val = iec61850_da_get_value(w->da);

    if (bp->is_sv) {
        return binding_update_sv_slot(bp, idx, &val);
    }
    return binding_update_goose_slot(bp, idx, &val);
}

/* ========================================================================
 * DA-change collection (chained trampoline)
 * ======================================================================== */

/*
 * Trampoline installed on every watched DA. Chains the previously
 * registered listener (coexistence), then updates the mapped
 * publisher slots and marks their publishers dirty. Never
 * publishes — iec61850_model_binding_process() does that.
 */
static void binding_da_changed(const mms_value_t *old_val,
                                const mms_value_t *new_val,
                                void *user_data)
{
    iec61850_binding_watch_t *w = user_data;

    if (w == NULL) {
        return;
    }

    /* Chained listener first (e.g. an MMS-side observer). */
    if (w->prev_cb != NULL) {
        w->prev_cb(old_val, new_val, w->prev_user_data);
    }

    /* Fan out: every mapped slot, every publisher. Slot pushes
     * cannot fail for validated slots (idx < capacity). */
    for (uint32_t p = 0U; p < w->owner->publisher_count; p++) {
        iec61850_binding_pub_t *bp = &w->owner->publishers[p];
        for (uint32_t i = 0U; i < bp->ref_count; i++) {
            if (bp->resolved[i] == w) {
                (void)binding_update_slot(bp, i);
                bp->dirty = true;
            }
        }
    }
}

/* ========================================================================
 * Watch lifecycle
 * ======================================================================== */

/*
 * Find an existing watch of this binding for da: first among the
 * watches of the add in progress (watches[0..in_count)), then the
 * committed publisher slots.
 */
static iec61850_binding_watch_t *binding_find_watch(
    const iec61850_model_binding_t *b,
    iec61850_binding_watch_t *const *watches, uint32_t in_count,
    const iec61850_data_attribute_t *da)
{
    for (uint32_t i = 0U; i < in_count; i++) {
        if (watches[i]->da == da) {
            return watches[i];
        }
    }
    for (uint32_t p = 0U; p < b->publisher_count; p++) {
        const iec61850_binding_pub_t *bp = &b->publishers[p];
        for (uint32_t i = 0U; i < bp->ref_count; i++) {
            iec61850_binding_watch_t *w = bp->resolved[i];
            if ((w != NULL) && (w->da == da)) {
                return w;
            }
        }
    }
    return NULL;
}

/*
 * Undo the watches created by a failed add: restore the chained
 * callbacks, free the nodes.
 */
static void binding_rollback_watches(iec61850_model_binding_t *b,
                                      iec61850_binding_watch_t *const *watches,
                                      const bool *created, uint32_t count)
{
    for (uint32_t i = 0U; i < count; i++) {
        if (created[i]) {
            iec61850_da_set_change_callback(watches[i]->da,
                                             watches[i]->prev_cb,
                                             watches[i]->prev_user_data);
            free(watches[i]);
            if (b->watch_count > 0U) {
                b->watch_count--;
            }
        }
    }
}

/* ========================================================================
 * Public API
 * ======================================================================== */

int iec61850_model_binding_init(iec61850_model_binding_t *b,
                                  iec61850_ied_model_t *model)
{
    if ((b == NULL) || (model == NULL)) {
        return -EINVAL;
    }
    if (b->initialized) {
        /* Double init would leak the registered watches. */
        return -EALREADY;
    }

    (void)memset(b, 0, sizeof(*b));
    b->model = model;
    b->initialized = true;
    return 0;
}

/*
 * Common add path for add_goose/add_sv: resolve every ref
 * (all-or-nothing), find-or-create a watch per unique DA, then
 * commit the publisher slot.
 */
static int binding_add(iec61850_model_binding_t *b, void *pub, bool is_sv,
                        const iec61850_da_ref_t *refs, uint32_t ref_count)
{
    iec61850_data_attribute_t *das[IEC61850_BINDING_MAX_REFS];
    iec61850_binding_watch_t *watches[IEC61850_BINDING_MAX_REFS];
    bool created[IEC61850_BINDING_MAX_REFS];
    iec61850_binding_pub_t *slot;
    int slot_idx;

    if ((b == NULL) || (!b->initialized)) {
        return -EINVAL;
    }
    if ((pub == NULL) || (refs == NULL) || (ref_count == 0U)) {
        return -EINVAL;
    }
    if (ref_count > (uint32_t)IEC61850_BINDING_MAX_REFS) {
        return -ENOSPC;
    }
    if (b->publisher_count >= (uint32_t)IEC61850_BINDING_MAX_PUBLISHERS) {
        return -ENOSPC;
    }

    /* Phase 1: resolve and type-check every ref. Any miss leaves
     * nothing bound. */
    for (uint32_t i = 0U; i < ref_count; i++) {
        das[i] = binding_resolve_ref(b->model, &refs[i]);
        if (das[i] == NULL) {
            return -ENOENT;
        }
        if (!binding_type_mappable(is_sv, das[i]->btype)) {
            return -ENOTSUP;
        }
    }

    /* Phase 2: find or create a watch per unique DA (bind-time
     * allocation only — never on the change path). */
    for (uint32_t i = 0U; i < ref_count; i++) {
        iec61850_binding_watch_t *w =
            binding_find_watch(b, watches, i, das[i]);

        created[i] = false;
        if (w == NULL) {
            w = calloc(1U, sizeof(*w));
            if (w == NULL) {
                binding_rollback_watches(b, watches, created, i);
                return -ENOMEM;
            }
            w->da = das[i];
            w->owner = b;
            w->prev_cb = das[i]->change_cb;
            w->prev_user_data = das[i]->change_cb_user_data;
            iec61850_da_set_change_callback(das[i], binding_da_changed, w);
            created[i] = true;
            b->watch_count++;
        }
        watches[i] = w;
    }

    /* Phase 3: commit the slot. */
    slot_idx = (int)b->publisher_count;
    slot = &b->publishers[b->publisher_count];
    (void)memset(slot, 0, sizeof(*slot));
    slot->pub = pub;
    slot->is_sv = is_sv;
    slot->ref_count = ref_count;
    for (uint32_t i = 0U; i < ref_count; i++) {
        slot->refs[i] = refs[i];
        slot->resolved[i] = watches[i];
    }
    b->publisher_count++;

    return slot_idx;
}

int iec61850_model_binding_add_goose(iec61850_model_binding_t *b,
                                       iec61850_goose_publisher_t *pub,
                                       const iec61850_da_ref_t *refs,
                                       uint32_t ref_count)
{
    return binding_add(b, pub, false, refs, ref_count);
}

int iec61850_model_binding_add_sv(iec61850_model_binding_t *b,
                                    iec61850_sv_publisher_t *pub,
                                    const iec61850_da_ref_t *refs,
                                    uint32_t ref_count)
{
    return binding_add(b, pub, true, refs, ref_count);
}

int iec61850_model_binding_process(iec61850_model_binding_t *b)
{
    int published = 0;

    if ((b == NULL) || (!b->initialized)) {
        return -EINVAL;
    }

    for (uint32_t p = 0U; p < b->publisher_count; p++) {
        iec61850_binding_pub_t *bp = &b->publishers[p];
        int ret;

        if (!bp->dirty) {
            continue;
        }
        bp->dirty = false;

        /* The dataset is a snapshot: push ALL mapped slots from
         * the current DA values, not just the changed one. */
        for (uint32_t i = 0U; i < bp->ref_count; i++) {
            ret = binding_update_slot(bp, i);
            if (ret != 0) {
                return ret;
            }
        }

        if (bp->is_sv) {
            /* MISRA 11.5: pub is the bound SV publisher, deviation Cat. 3 */
            ret = iec61850_sv_publisher_publish(
                (iec61850_sv_publisher_t *)bp->pub);
        } else {
            /* GOOSE state-change semantics: stNum++/sqNum=0, then
             * publish (which retransmits with sqNum++). */
            /* MISRA 11.5: pub is the bound GOOSE publisher, deviation Cat. 3 */
            iec61850_goose_publisher_state_change(
                (iec61850_goose_publisher_t *)bp->pub);
            ret = iec61850_goose_publisher_publish(
                (iec61850_goose_publisher_t *)bp->pub);
        }

        if (ret != 0) {
            return ret;
        }
        published++;
    }

    return published;
}

void iec61850_model_binding_destroy(iec61850_model_binding_t *b)
{
    /* Unique watch nodes across all slots (refs share nodes). */
    iec61850_binding_watch_t *unique[IEC61850_BINDING_MAX_PUBLISHERS *
                                      IEC61850_BINDING_MAX_REFS];
    uint32_t unique_count = 0U;

    if (b == NULL) {
        return;
    }

    if (b->initialized) {
        for (uint32_t p = 0U; p < b->publisher_count; p++) {
            const iec61850_binding_pub_t *bp = &b->publishers[p];
            for (uint32_t i = 0U; i < bp->ref_count; i++) {
                iec61850_binding_watch_t *w = bp->resolved[i];
                bool seen = false;

                if (w == NULL) {
                    continue;
                }
                for (uint32_t u = 0U; u < unique_count; u++) {
                    if (unique[u] == w) {
                        seen = true;
                        break;
                    }
                }
                if (!seen) {
                    unique[unique_count] = w;
                    unique_count++;
                }
            }
        }

        /* Restore the chained listeners, free the nodes. */
        for (uint32_t u = 0U; u < unique_count; u++) {
            iec61850_binding_watch_t *w = unique[u];
            iec61850_da_set_change_callback(w->da, w->prev_cb,
                                             w->prev_user_data);
            free(w);
        }
    }

    (void)memset(b, 0, sizeof(*b));
}
