/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850-7-3 CDC factories — analog batch (WP-6a)
 *
 * CURS, CSD: the composite curve/custom setting forms.
 *
 * 7-3 provenance and TR-review flags (conservative common subset):
 *  - CURS (curves): the curve point list is modelled as a single
 *    BTYPE_STRUCT (crvPts, SG) because the house model has no array
 *    btype. Axis units are declared as VISIBLE_STRING under CF
 *    because the house model has no Unit (SIUnit + multiplier)
 *    component. FLAG(TR): crvPts/xUnits/yUnits names, FCs, and the
 *    struct-vs-array shape; full 7-3 curve description attributes
 *    (crvDim, xVal/yVal arrays, yRefVal, ...) deferred.
 *  - CSD (custom setting): a custom structured setting. Only the
 *    value attribute is instantiated; the 7-3 attribute set for
 *    custom settings is implementation-defined by design.
 *    FLAG(TR): setVal name/shape; consider SE mirror for editable
 *    setting groups.
 */

#include "ied/ied_data_model.h"

#include <stddef.h>

iec61850_data_object_t *iec61850_cdc_create_curs(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_CURS);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "crvPts", IEC61850_FC_SG, IEC61850_BTYPE_STRUCT);
    (void)iec61850_do_add_attribute(dobj, "xUnits", IEC61850_FC_CF, IEC61850_BTYPE_VISIBLE_STRING);
    (void)iec61850_do_add_attribute(dobj, "yUnits", IEC61850_FC_CF, IEC61850_BTYPE_VISIBLE_STRING);

    return dobj;
}

iec61850_data_object_t *iec61850_cdc_create_csd(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_CSD);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "setVal", IEC61850_FC_SG, IEC61850_BTYPE_STRUCT);

    return dobj;
}
