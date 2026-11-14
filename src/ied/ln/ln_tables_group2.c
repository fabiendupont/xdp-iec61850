/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850-7-4 LN class tables — group 2: protection
 *
 * Pilot classes (WP-6b): PTOC, PDIS. WP-6c appends the remaining
 * group-2 classes.
 *
 * Same conventions as ln_tables_group1.c: conservative common
 * subset across 7-4 editions, CDCs restricted to the implemented
 * factories in src/ied/ied_data_model.c.
 */

#include "ln_schema_tables.h"

/* ------------------------------------------------------------------
 * PTOC — Time overcurrent protection (7-4 group 2)
 *
 * Str (ACD) and Op (ACT) are the protection start/trip statuses.
 * Judgment call: the repo's scl_ied_builder models PTOC.Op as SPC;
 * 7-4 types it ACT. The table follows 7-4. Flagged.
 * StrVal (ASG, pickup current) is listed O; Ed.2 timing settings
 * (ING family) are omitted — CDC not implemented. Flagged.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t ptoc_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Op",     IEC61850_CDC_ACT, true  },
    { "Str",    IEC61850_CDC_ACD, true  },
    { "StrVal", IEC61850_CDC_ASG, false },
};

/* ------------------------------------------------------------------
 * PDIS — Distance protection (7-4 group 2)
 *
 * Conservative: Str/Op plus the LN-common DOs. Zone/reach settings
 * (ASG/ING families) are configuration-specific and not listed —
 * flagged; nothing mandatory needs a stub CDC.
 * ------------------------------------------------------------------ */
static const iec61850_ln_do_def_t pdis_dos[] = {
    { "Beh",    IEC61850_CDC_INS, true  },
    { "Health", IEC61850_CDC_INS, true  },
    { "Mod",    IEC61850_CDC_INC, true  },
    { "NamPlt", IEC61850_CDC_LPL, true  },
    { "Op",     IEC61850_CDC_ACT, true  },
    { "Str",    IEC61850_CDC_ACD, true  },
};

const iec61850_ln_class_def_t ln_group2_classes[LN_GROUP2_CLASS_COUNT] = {
    { "PDIS", pdis_dos, 6U },
    { "PTOC", ptoc_dos, 7U },
};

