/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * SCL-to-IED Model Builder
 *
 * Builds a complete iec61850_ied_model_t from parsed SCL data.
 * Creates LD/LN/DO/DA hierarchy and auto-configures RCBs.
 */

#ifndef IEC61850_SCL_IED_BUILDER_H
#define IEC61850_SCL_IED_BUILDER_H

#include "scl/scl_parser.h"
#include "ied/ied_data_model.h"
#include "ied/model_binding.h"
#include "mms/mms_data_store.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Build an IED model from parsed SCL document.
 *
 * Creates LogicalDevice/LogicalNode hierarchy from the SCL parse result.
 * For known LN classes (LLN0, LPHD, XCBR, XSWI, MMXU, PTOC, CSWI, GGIO),
 * creates standard CDC data objects.
 *
 * @param doc    Parsed SCL document
 * @param model  Output IED model (must be initialized)
 * @return 0 on success, negative on error
 */
int iec61850_scl_build_ied_model(const iec61850_scl_doc_t *doc,
                                   iec61850_ied_model_t *model);

/**
 * Auto-configure RCBs from parsed SCL document into an RCB manager.
 *
 * For each ReportControl block in the SCL, creates a BRCB or URCB
 * with matching trigger options, optional fields, and buffer size.
 *
 * @param doc   Parsed SCL document
 * @param mgr   RCB manager (must be initialized)
 * @return Number of RCBs configured (>= 0), negative on error
 */
/**
 * Register IED model variables into an MMS data store.
 *
 * Creates MMS domains from logical devices (IEDName + LDInst)
 * and registers all data attributes as MMS named variables
 * using IEC 61850-8-1 naming: LN$FC$DO$DA.
 *
 * @param model       IED data model (built via iec61850_scl_build_ied_model)
 * @param data_store  MMS data store (must be initialized)
 * @return Number of variables registered (>= 0), negative on error
 */
int iec61850_ied_model_register_mms(const iec61850_ied_model_t *model,
                                      iec61850_mms_data_store_t *data_store);

struct iec61850_rcb_manager_t;  /* forward declaration */
int iec61850_scl_auto_configure_rcbs(const iec61850_scl_doc_t *doc,
                                       void *mgr);

/* ========================================================================
 * SCL-Driven Publisher Auto-Configuration (WP-6f)
 *
 * Mirrors iec61850_scl_auto_configure_rcbs() for model-bound GOOSE and
 * SV publishers: every GSEControl / SampledValueControl of the parsed
 * IED is resolved through its dataset's FCDAs and bound into an
 * iec61850_model_binding_t, so one DA change fans out to publishing
 * through iec61850_model_binding_process().
 *
 * Usage sequence (see tests/unit/test_scl_ied_builder.c):
 *
 *   iec61850_scl_parse_file("station.scd", "IED1", &doc);
 *   iec61850_scl_build_ied_model(&doc, &model);
 *   iec61850_model_binding_init(&binding, &model);
 *   iec61850_scl_configure_publishers(&doc, &binding, &ops, &result);
 *   for (;;) {
 *       ... application writes DataAttributes ...
 *       iec61850_model_binding_process(&binding);
 *   }
 *
 * Publisher creation contract (design choice, RCB-precedent): the
 * library derives the COMPLETE publisher configuration from the SCL
 * control block plus its Communication-section address (MAC, APPID,
 * VLAN, TAL/retransmission timing for GOOSE; svID, smpRate, confRev
 * and a channel count equal to the expanded dataset size for SV).
 * The caller-provided creation callback only supplies storage and
 * lifetime: it receives the prepared config, constructs the
 * publisher (typically iec61850_goose_publisher_init() /
 * iec61850_sv_publisher_init() plus set_io()) and returns it. The
 * publisher is NOT owned by the binding or the library; it must
 * outlive iec61850_model_binding_destroy().
 *
 * A NULL create callback declines that publisher kind: the matching
 * control blocks are counted as skipped.
 *
 * Whole-DO/SDO FCDAs (no daName, or an SDO-named daName) are
 * expanded to their leaf DataAttributes: iec61850_ln_find_attribute()
 * and the DA-change callback are leaf-only, so DO-level watching is
 * not possible. The expansion enumerates the built model's
 * DataObject attribute table (the same leaves
 * iec61850_scl_build_ied_model() creates, recursing sub-data-objects
 * when present), filtered by the FCDA functional constraint and
 * bounded by IEC61850_BINDING_MAX_REFS. Two further filters apply:
 *  - SV: leaves without a sample/quality mapping (timestamps,
 *    strings, structs) are excluded;
 *  - bindability: leaves whose attribute name is a flattened dotted
 *    path (SDO/struct-nested, e.g. "phsA.cVal.mag.f") are excluded —
 *    the binding resolves {do, da} through
 *    iec61850_ln_find_attribute(), which walks reference segments
 *    as sub-data-objects, and no model builder in this codebase
 *    creates sub-data-objects, so such leaves cannot be watched. A
 *    whole-SDO FCDA under a composite CDC (e.g. WYE) therefore has
 *    no bindable leaves and skips its control block; a leaf-DA FCDA
 *    naming a dotted path is likewise rejected by the binding.
 *
 * Skip tolerance (mirrors the RCB auto-config): one bad control
 * block never fails the call. A control block is SKIPPED — leaving
 * nothing bound — when (1) its create callback is NULL, (2) the
 * Communication section carries no address for it (empty
 * MAC-Address: ICD/IID documents have no Communication section),
 * (3) its datSet does not exist, (4) any FCDA fails
 * iec61850_scl_resolve_fcda(), (5) the expanded dataset is empty or
 * exceeds IEC61850_BINDING_MAX_REFS members, (6) the creation
 * callback fails or returns NULL, or (7) iec61850_model_binding_add_goose/add_sv()
 * rejects it (-ENOENT unresolvable in the model, -ENOTSUP
 * unmappable leaf type, -ENOSPC binding full). The result summary
 * always satisfies: goose_configured + sv_configured + skipped ==
 * total GSE/SV control blocks in the document.
 * ======================================================================== */

/* Per-call summary of the auto-configuration. */
typedef struct {
    uint32_t goose_configured;  /* GSE control blocks bound */
    uint32_t sv_configured;     /* SampledValue control blocks bound */
    uint32_t skipped;           /* control blocks not bound (see above) */
} iec61850_scl_publisher_result_t;

/*
 * GOOSE publisher creation callback. cfg is the fully prepared
 * publisher configuration derived from the SCL control block and
 * its Communication address; cb carries the originating SCL
 * context. Construct a publisher from cfg and return it through
 * *out. Return 0 on success, negative errno to skip the block.
 */
typedef int (*iec61850_scl_goose_create_fn_t)(
    const iec61850_scl_goose_cb_t *cb,
    const iec61850_goose_config_t *cfg,
    iec61850_goose_publisher_t **out,
    void *user_data);

/*
 * SV publisher creation callback, identical contract. cfg includes
 * num_channels set to the control block's expanded dataset size.
 */
typedef int (*iec61850_scl_sv_create_fn_t)(
    const iec61850_scl_sv_cb_t *cb,
    const iec61850_sv_config_t *cfg,
    iec61850_sv_publisher_t **out,
    void *user_data);

/* Creation callbacks + user data. Either callback may be NULL. */
typedef struct {
    iec61850_scl_goose_create_fn_t create_goose;
    iec61850_scl_sv_create_fn_t create_sv;
    void *user_data;
} iec61850_scl_publisher_ops_t;

/**
 * Auto-configure model-bound GOOSE/SV publishers from an SCL
 * document (WP-6f).
 *
 * For every GSEControl/SampledValueControl of the IED the document
 * was parsed for: resolve the dataset FCDAs to DA references
 * (whole-DO FCDAs expanded to leaf DAs), prepare the publisher
 * configuration from the Communication address, invoke the creation
 * callback, and bind the publisher into the binding. The model the
 * binding was initialized with must be the one built from doc
 * (iec61850_scl_build_ied_model).
 *
 * @param doc     Parsed SCL document (per-IED, from parse_file)
 * @param binding Model binding (initialized against the model
 *                built from doc)
 * @param ops     Publisher creation callbacks (non-NULL; members
 *                may be NULL to decline a kind)
 * @param result  Optional summary (may be NULL)
 * @return Total number of publishers configured (>= 0), or
 *         -EINVAL on bad arguments (NULL doc/binding/ops or an
 *         uninitialized binding)
 */
int iec61850_scl_configure_publishers(
    const iec61850_scl_doc_t *doc,
    iec61850_model_binding_t *binding,
    const iec61850_scl_publisher_ops_t *ops,
    iec61850_scl_publisher_result_t *result);


#ifdef __cplusplus
}
#endif

#endif /* IEC61850_SCL_IED_BUILDER_H */
