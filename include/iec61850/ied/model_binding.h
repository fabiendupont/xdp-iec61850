/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850 Model-Driven Publishing Binding
 *
 * Binds IED data-model DataAttributes to protocol publishers so a
 * single DA change fans out to MMS reports (via the existing RCB
 * bridge), GOOSE, and SV from one model. The binding is
 * FC/trigger-aware: the caller's reference list defines the fan-out
 * set (ST/MX for status/measurement datasets); only listed DAs feed
 * the publishers.
 *
 * Single-threaded contract: DA writes update the mapped publisher
 * slot and mark the publisher dirty; iec61850_model_binding_process()
 * publishes (GOOSE state-change semantics) for dirty publishers.
 * No threads.
 *
 * FROZEN INTERFACE (WP-S6d). Implementations change; signatures
 * do not.
 */

#ifndef IEC61850_MODEL_BINDING_H
#define IEC61850_MODEL_BINDING_H

#include "ied/ied_data_model.h"
#include "goose/goose_publisher.h"
#include "sv/sv_publisher.h"

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum publishers per binding */
#define IEC61850_BINDING_MAX_PUBLISHERS 8

/* Maximum DA references per bound publisher (the publishers'
 * dataset capacity bound). */
#define IEC61850_BINDING_MAX_REFS 64

/* One dataset-member reference: a DataAttribute in the model. */
typedef struct {
    char ld[IEC61850_MAX_NAME_LEN];
    char ln[IEC61850_MAX_NAME_LEN];
    char do_name[IEC61850_MAX_NAME_LEN];
    char da_name[IEC61850_MAX_NAME_LEN];
    iec61850_fc_t fc;
} iec61850_da_ref_t;

/* One bound publisher slot. */
typedef struct {
    void *pub;                     /* goose or sv publisher; not owned */
    bool is_sv;
    iec61850_da_ref_t refs[IEC61850_BINDING_MAX_REFS];
    uint32_t ref_count;
    bool dirty;
    /* Implementation resolution state (model DA pointers, cached) */
    void *resolved[IEC61850_BINDING_MAX_REFS];
} iec61850_binding_pub_t;

typedef struct {
    iec61850_ied_model_t *model;   /* not owned */
    bool initialized;
    iec61850_binding_pub_t publishers[IEC61850_BINDING_MAX_PUBLISHERS];
    uint32_t publisher_count;
    /* Model DA-change registration state */
    uint32_t watch_count;
} iec61850_model_binding_t;

/**
 * Initialize the binding against a data model. Registers the
 * model-level DA-change collection (coexists with the MMS variable
 * binding's listeners — both observe the same changes).
 * @return 0, or negative errno.
 */
int iec61850_model_binding_init(iec61850_model_binding_t *b,
                                 iec61850_ied_model_t *model);

/**
 * Bind a GOOSE publisher's dataset slots to an ordered list of DA
 * references. The refs map slot-for-slot: refs[i] is dataset member
 * i. Every ref must resolve in the model (else -ENOENT and nothing
 * is bound). The publisher is not owned; keep it alive until
 * iec61850_model_binding_destroy().
 * @return the publisher slot (0..MAX-1), or negative errno
 *         (-ENOSPC when full).
 */
int iec61850_model_binding_add_goose(iec61850_model_binding_t *b,
                                      iec61850_goose_publisher_t *pub,
                                      const iec61850_da_ref_t *refs,
                                      uint32_t ref_count);

/**
 * Bind an SV publisher identically (refs map to sample slots).
 * @return the publisher slot, or negative errno.
 */
int iec61850_model_binding_add_sv(iec61850_model_binding_t *b,
                                   iec61850_sv_publisher_t *pub,
                                   const iec61850_da_ref_t *refs,
                                   uint32_t ref_count);

/**
 * Fan out pending changes: for every dirty publisher, update the
 * mapped dataset slots from the current DA values and publish
 * (GOOSE: state-change semantics — stNum++/sqNum=0; SV: publish the
 * current sample). Idempotent when nothing changed.
 * @return The number of publishers that published, or negative
 *         errno.
 */
int iec61850_model_binding_process(iec61850_model_binding_t *b);

/**
 * Release all model callbacks and binding state. Publishers and the
 * model are not owned (not destroyed).
 */
void iec61850_model_binding_destroy(iec61850_model_binding_t *b);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_MODEL_BINDING_H */
