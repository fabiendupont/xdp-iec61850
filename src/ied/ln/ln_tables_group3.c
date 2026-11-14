/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850-7-4 LN class tables — group 3: measurement / metering
 *
 * Pilot classes (WP-6b): MMXU, MMTR. WP-6c appends the remaining
 * group-3 classes.
 *
 * Same conventions as ln_tables_group1.c: conservative common
 * subset across 7-4 editions, CDCs restricted to the implemented
 * factories in src/ied/ied_data_model.c.
 */

#include "ln_schema_tables.h"

/* ------------------------------------------------------------------
 * MMXU — Measurement (7-4 group 3)
 *
 * Judgment call: in 7-4 the measurement DOs are O/C (the deployed
 * subset is configuration-dependent; profiles require at least one
 * MX DO), so only the LN-common DOs are M and every measurement is
 * an optional DO added via iec61850_ln_add_ln_class_do(). Flagged.
 * Omitted due to WP-S6 stub CDCs (all Ed.2 optionals): HA (HMV),
 * HPhV (HWYE), HPPV (HDEL). Flagged; WP-6c adds them back.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t mmxu_dos[] = {
    { "A",      IEC61850_CDC_WYE, false },
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Hz",     IEC61850_CDC_MV,  false },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "PPV",    IEC61850_CDC_DEL, false },
    { "PhV",    IEC61850_CDC_WYE, false },
    { "TotVA",   IEC61850_CDC_MV,  false },
    { "TotVAr",  IEC61850_CDC_MV,  false },
    { "TotVArh", IEC61850_CDC_BCR, false },
    { "TotW",    IEC61850_CDC_MV,  false },
    { "TotWh",   IEC61850_CDC_BCR, false },
    { "VA",      IEC61850_CDC_WYE, false },
    { "VAr",     IEC61850_CDC_WYE, false },
    { "W",       IEC61850_CDC_WYE, false },
};

/* ------------------------------------------------------------------
 * MMTR — Metering (7-4 group 3)
 *
 * Judgment call: whether the energy counters TotWh/TotVArh are M or
 * C/O in MMTR is edition/profile-dependent; conservative choice is
 * O. Flagged.
 * Omitted due to WP-S6 stub CDCs (Ed.2 optionals): HA (HMV) and
 * the other harmonic DOs. Flagged; WP-6c adds them back.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t mmtr_dos[] = {
    { "A",       IEC61850_CDC_WYE, false },
    { "Beh",     IEC61850_CDC_INS, true  },
    { "Health",  IEC61850_CDC_INS, true  },
    { "Hz",      IEC61850_CDC_MV,  false },
    { "Mod",     IEC61850_CDC_INC, true  },
    { "NamPlt",  IEC61850_CDC_LPL, true  },
    { "PPV",     IEC61850_CDC_DEL, false },
    { "PhV",     IEC61850_CDC_WYE, false },
    { "TotVA",   IEC61850_CDC_MV,  false },
    { "TotVAr",  IEC61850_CDC_MV,  false },
    { "TotW",    IEC61850_CDC_MV,  false },
    { "TotVArh", IEC61850_CDC_BCR, false },
    { "TotWh",   IEC61850_CDC_BCR, false },
    { "VA",      IEC61850_CDC_WYE, false },
    { "VAr",     IEC61850_CDC_WYE, false },
    { "W",       IEC61850_CDC_WYE, false },
};

const iec61850_ln_class_def_t ln_group3_classes[LN_GROUP3_CLASS_COUNT] = {
    { "MMTR", mmtr_dos, 16U },
    { "MMXU", mmxu_dos, 16U },
};

