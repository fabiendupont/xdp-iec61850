/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850-7-3 CDC factories — control batch (WP-6a)
 *
 * APC, ENC, ISC: controllable CDCs, following the house factory pattern
 * from src/ied/ied_data_model.c (do_create + per-CDC DOA tree with the
 * 7-3 attribute names/FCs).
 *
 * 7-3 provenance and TR-review flags:
 *  - APC (analogue point control): mxVal/ctlVal are the AnalogueValue
 *    component (float/int union). The house model has no union btype,
 *    so they are declared BTYPE_STRUCT (same convention as BSC valWTr).
 *    The Oper PDU sub-structure (ctlVal/Test/Check) is flattened to
 *    ctlVal at DO level, matching the existing SPC/DPC/INC factories.
 *    sboClass (CF) is included per the select-before-operate model.
 *    FLAG(TR): Oper flattening and the AnalogueValue struct shape.
 *  - ENC (enumerated control): mirrors INC exactly, with ctlVal
 *    enumerated. FLAG(TR): sboClass omitted to match the INC house
 *    pattern (conservative common subset).
 *  - ISC (integer status control): mirrors INC with INT32 values.
 *    FLAG(TR): sboClass omitted (same as ENC).
 */

#include "ied/ied_data_model.h"

#include <stddef.h>

iec61850_data_object_t *iec61850_cdc_create_apc(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_APC);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "mxVal", IEC61850_FC_MX, IEC61850_BTYPE_STRUCT);
    (void)iec61850_do_add_attribute(dobj, "q", IEC61850_FC_MX, IEC61850_BTYPE_QUALITY);
    (void)iec61850_do_add_attribute(dobj, "t", IEC61850_FC_MX, IEC61850_BTYPE_TIMESTAMP);
    (void)iec61850_do_add_attribute(dobj, "ctlVal", IEC61850_FC_CO, IEC61850_BTYPE_STRUCT);
    (void)iec61850_do_add_attribute(dobj, "ctlModel", IEC61850_FC_CF, IEC61850_BTYPE_ENUMERATED);
    (void)iec61850_do_add_attribute(dobj, "sboClass", IEC61850_FC_CF, IEC61850_BTYPE_ENUMERATED);

    return dobj;
}

iec61850_data_object_t *iec61850_cdc_create_enc(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_ENC);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "stVal", IEC61850_FC_ST, IEC61850_BTYPE_ENUMERATED);
    (void)iec61850_do_add_attribute(dobj, "q", IEC61850_FC_ST, IEC61850_BTYPE_QUALITY);
    (void)iec61850_do_add_attribute(dobj, "t", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP);
    (void)iec61850_do_add_attribute(dobj, "ctlVal", IEC61850_FC_CO, IEC61850_BTYPE_ENUMERATED);
    (void)iec61850_do_add_attribute(dobj, "ctlModel", IEC61850_FC_CF, IEC61850_BTYPE_ENUMERATED);

    return dobj;
}

iec61850_data_object_t *iec61850_cdc_create_isc(const char *name)
{
    iec61850_data_object_t *dobj = iec61850_do_create(name, IEC61850_CDC_ISC);
    if (dobj == NULL) { return NULL; }

    (void)iec61850_do_add_attribute(dobj, "stVal", IEC61850_FC_ST, IEC61850_BTYPE_INT32);
    (void)iec61850_do_add_attribute(dobj, "q", IEC61850_FC_ST, IEC61850_BTYPE_QUALITY);
    (void)iec61850_do_add_attribute(dobj, "t", IEC61850_FC_ST, IEC61850_BTYPE_TIMESTAMP);
    (void)iec61850_do_add_attribute(dobj, "ctlVal", IEC61850_FC_CO, IEC61850_BTYPE_INT32);
    (void)iec61850_do_add_attribute(dobj, "ctlModel", IEC61850_FC_CF, IEC61850_BTYPE_ENUMERATED);

    return dobj;
}
