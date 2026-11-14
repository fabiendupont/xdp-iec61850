/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850-7-3 CDC factories — harmonics batch (WP-6a)
 *
 * HMV, HWYE, HDEL, SEQ: harmonic measurement CDCs plus the sequence
 * status form, following the house factory pattern (MV/WYE/DEL for the
 * harmonic set).
 *
 * 7-3 provenance and TR-review flags (conservative common subset):
 *  - HMV (harmonic value, non-phase): mirrors MV. The per-harmonic
 *    value array is modelled as a single BTYPE_STRUCT (hVal) because
 *    the house model has no array btype; numHrv declares the number
 *    of harmonics carried. FLAG(TR): numHrv FC (CF here; the 7-3
 *    functional constraint should be confirmed) and the hVal
 *    struct-vs-array shape.
 *  - HWYE (harmonic WYE): mirrors WYE with a per-phase harmonic
 *    value (phsA/phsB/phsC .hVal). FLAG(TR): same as HMV; the
 *    cVal/ang decomposition of WYE does not apply to harmonic
 *    arrays, so hVal is a STRUCT.
 *  - HDEL (harmonic DELTA): mirrors DEL with the pair-wise
 *    harmonics (phsAB/phsBC/phsCA .hVal). FLAG(TR): same as HMV.
 *  - SEQ (sequence): status-shaped conservative subset (structured
 *    sequence value plus q/t). FLAG(TR): seqVal name/shape; the
 *    full 7-3 sequence attribute set is deferred.
 */

#include "ied/ied_data_model.h"

#include <stddef.h>

iec61850_data_object_t *iec61850_cdc_create_hmv(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_HMV);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "numHrv", IEC61850_FC_CF, IEC61850_BTYPE_INT32U);
    (void)iec61850_do_add_attribute(dobj, "hVal", IEC61850_FC_MX, IEC61850_BTYPE_STRUCT);
    (void)iec61850_do_add_attribute(dobj, "q", IEC61850_FC_MX, IEC61850_BTYPE_QUALITY);
    (void)iec61850_do_add_attribute(dobj, "t", IEC61850_FC_MX, IEC61850_BTYPE_TIMESTAMP);

    return dobj;
}

iec61850_data_object_t *iec61850_cdc_create_hwye(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_HWYE);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "numHrv", IEC61850_FC_CF, IEC61850_BTYPE_INT32U);
    (void)iec61850_do_add_attribute(dobj, "phsA.hVal", IEC61850_FC_MX, IEC61850_BTYPE_STRUCT);
    (void)iec61850_do_add_attribute(dobj, "phsB.hVal", IEC61850_FC_MX, IEC61850_BTYPE_STRUCT);
    (void)iec61850_do_add_attribute(dobj, "phsC.hVal", IEC61850_FC_MX, IEC61850_BTYPE_STRUCT);
    (void)iec61850_do_add_attribute(dobj, "q", IEC61850_FC_MX, IEC61850_BTYPE_QUALITY);
    (void)iec61850_do_add_attribute(dobj, "t", IEC61850_FC_MX, IEC61850_BTYPE_TIMESTAMP);

    return dobj;
}

iec61850_data_object_t *iec61850_cdc_create_hdel(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_HDEL);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "numHrv", IEC61850_FC_CF, IEC61850_BTYPE_INT32U);
    (void)iec61850_do_add_attribute(dobj, "phsAB.hVal", IEC61850_FC_MX, IEC61850_BTYPE_STRUCT);
    (void)iec61850_do_add_attribute(dobj, "phsBC.hVal", IEC61850_FC_MX, IEC61850_BTYPE_STRUCT);
    (void)iec61850_do_add_attribute(dobj, "phsCA.hVal", IEC61850_FC_MX, IEC61850_BTYPE_STRUCT);
    (void)iec61850_do_add_attribute(dobj, "q", IEC61850_FC_MX, IEC61850_BTYPE_QUALITY);
    (void)iec61850_do_add_attribute(dobj, "t", IEC61850_FC_MX, IEC61850_BTYPE_TIMESTAMP);

    return dobj;
}

iec61850_data_object_t *iec61850_cdc_create_seq(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_SEQ);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "seqVal", IEC61850_FC_ST, IEC61850_BTYPE_STRUCT);
    (void)iec61850_do_add_attribute(dobj, "q", IEC61850_FC_ST, IEC61850_BTYPE_QUALITY);
    (void)iec61850_do_add_attribute(dobj, "t", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP);

    return dobj;
}
