/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850 SCL (System Configuration Language) Parser
 *
 * Parses SCD/SCL files using libxml2 to extract GOOSE, SV, and RCB
 * control block configurations plus IED structure.
 *
 * License: BSD-3-Clause
 */

#ifndef IEC61850_SCL_PARSER_H
#define IEC61850_SCL_PARSER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IEC61850_SCL_MAX_NAME     64
#define IEC61850_SCL_MAX_MAC      18  /* "01-0C-CD-01-00-01" + nul */
#define IEC61850_SCL_MAX_CBS      64
#define IEC61850_SCL_MAX_DS_MEMBERS 64
#define IEC61850_SCL_MAX_LDS      16
#define IEC61850_SCL_MAX_LNS      64

/* GOOSE control block extracted from SCD */
typedef struct {
    char ied_name[IEC61850_SCL_MAX_NAME];
    char ld_inst[IEC61850_SCL_MAX_NAME];
    char cb_name[IEC61850_SCL_MAX_NAME];
    char go_id[IEC61850_SCL_MAX_NAME];
    char dataset[IEC61850_SCL_MAX_NAME];
    uint32_t conf_rev;
    uint16_t app_id;
    char mac_address[IEC61850_SCL_MAX_MAC];
    uint16_t vlan_id;
    uint8_t vlan_priority;
    uint32_t min_time;
    uint32_t max_time;
} iec61850_scl_goose_cb_t;

/* SV control block extracted from SCD */
typedef struct {
    char ied_name[IEC61850_SCL_MAX_NAME];
    char ld_inst[IEC61850_SCL_MAX_NAME];
    char cb_name[IEC61850_SCL_MAX_NAME];
    char sv_id[IEC61850_SCL_MAX_NAME];
    char dataset[IEC61850_SCL_MAX_NAME];
    uint32_t conf_rev;
    uint16_t app_id;
    char mac_address[IEC61850_SCL_MAX_MAC];
    uint16_t vlan_id;
    uint8_t vlan_priority;
    uint16_t smp_rate;
    uint8_t num_channels;
    uint8_t smp_synch;
} iec61850_scl_sv_cb_t;

/* FCDA (Functional Constraint Data Attribute) member of a DataSet */
typedef struct {
    char ld_inst[IEC61850_SCL_MAX_NAME];
    char ln_prefix[IEC61850_SCL_MAX_NAME];
    char ln_class[IEC61850_SCL_MAX_NAME];
    char ln_inst[IEC61850_SCL_MAX_NAME];
    char do_name[IEC61850_SCL_MAX_NAME];
    char da_name[IEC61850_SCL_MAX_NAME];
    char fc[8];  /* Functional constraint: ST, MX, CO, CF, etc. */
} iec61850_scl_fcda_t;

/* DataSet extracted from SCD */
typedef struct {
    char name[IEC61850_SCL_MAX_NAME];
    iec61850_scl_fcda_t members[IEC61850_SCL_MAX_DS_MEMBERS];
    size_t member_count;
} iec61850_scl_dataset_t;

/* Report Control Block extracted from SCD */
typedef struct {
    char ied_name[IEC61850_SCL_MAX_NAME];
    char ld_inst[IEC61850_SCL_MAX_NAME];
    char rpt_id[IEC61850_SCL_MAX_NAME];
    char dataset[IEC61850_SCL_MAX_NAME];
    uint32_t conf_rev;
    bool buffered;       /* true=BRCB, false=URCB */
    uint32_t buf_time;   /* Buffer time ms (BRCB only) */
    uint32_t intg_pd;    /* Integrity period ms */

    /* Trigger options (TrgOps) */
    bool trg_dchg;
    bool trg_qchg;
    bool trg_dupd;
    bool trg_period;
    bool trg_gi;

    /* Optional fields (OptFlds) */
    bool opt_seq_num;
    bool opt_timestamp;
    bool opt_reason;
    bool opt_dataref;
    bool opt_entryid;
    bool opt_bufovfl;
    bool opt_configref;

    uint8_t rpt_enabled_max;  /* Max enabled clients */
} iec61850_scl_rcb_t;

#define IEC61850_SCL_MAX_RCBS    32
#define IEC61850_SCL_MAX_DATASETS 32

/* DataTypeTemplates limits */
#define IEC61850_SCL_MAX_LNODE_TYPES 64
#define IEC61850_SCL_MAX_DO_TYPES    128
#define IEC61850_SCL_MAX_DA_TYPES    64
#define IEC61850_SCL_MAX_ENUM_TYPES  32
#define IEC61850_SCL_MAX_TYPE_DOS    32  /* DOs per LNodeType */
#define IEC61850_SCL_MAX_TYPE_DAS    32  /* DAs per DOType or DAType */
#define IEC61850_SCL_MAX_ENUM_VALS   32  /* Values per EnumType */

/* Data Attribute in DOType or DAType */
typedef struct {
    char name[IEC61850_SCL_MAX_NAME];
    char fc[8];                            /* Functional constraint: ST, MX, CO, etc. */
    char btype[IEC61850_SCL_MAX_NAME];     /* BasicType: BOOLEAN, INT32, Struct, Enum, etc. */
    char type[IEC61850_SCL_MAX_NAME];      /* Referenced DAType/EnumType id (if btype=Struct/Enum) */
    uint32_t count;                        /* Array count (0 or 1 = scalar) */
} iec61850_scl_da_t;

/* DO reference in LNodeType */
typedef struct {
    char name[IEC61850_SCL_MAX_NAME];      /* DO instance name (e.g., "Pos") */
    char type[IEC61850_SCL_MAX_NAME];      /* Referenced DOType id */
} iec61850_scl_do_ref_t;

/* LNodeType (defines a logical node type) */
typedef struct {
    char id[IEC61850_SCL_MAX_NAME];        /* Type id (e.g., "XCBR001") */
    char ln_class[IEC61850_SCL_MAX_NAME];  /* LN class (e.g., "XCBR") */
    iec61850_scl_do_ref_t dos[IEC61850_SCL_MAX_TYPE_DOS];
    size_t do_count;
} iec61850_scl_lnode_type_t;

/* DOType (defines a data object type) */
typedef struct {
    char id[IEC61850_SCL_MAX_NAME];        /* Type id (e.g., "DPC_1") */
    char cdc[IEC61850_SCL_MAX_NAME];       /* CDC name (e.g., "DPC", "SPS", "MV") */
    iec61850_scl_da_t das[IEC61850_SCL_MAX_TYPE_DAS];
    size_t da_count;
} iec61850_scl_do_type_t;

/* DAType (defines a structured data attribute type) */
typedef struct {
    char id[IEC61850_SCL_MAX_NAME];
    iec61850_scl_da_t bdas[IEC61850_SCL_MAX_TYPE_DAS];  /* BDA children */
    size_t bda_count;
} iec61850_scl_da_type_t;

/* EnumVal (single enumeration value) */
typedef struct {
    int32_t ord;                           /* Ordinal value */
    char val[IEC61850_SCL_MAX_NAME];       /* String description */
} iec61850_scl_enum_val_t;

/* EnumType (defines an enumeration type) */
typedef struct {
    char id[IEC61850_SCL_MAX_NAME];
    iec61850_scl_enum_val_t vals[IEC61850_SCL_MAX_ENUM_VALS];
    size_t val_count;
} iec61850_scl_enum_type_t;

/* Logical node reference extracted from SCD */
typedef struct {
    char ln_class[IEC61850_SCL_MAX_NAME];
    char ln_inst[IEC61850_SCL_MAX_NAME];
    char ln_type[IEC61850_SCL_MAX_NAME];
    char ln_prefix[IEC61850_SCL_MAX_NAME];
} iec61850_scl_ln_ref_t;

/* Logical device extracted from SCD */
typedef struct {
    char inst[IEC61850_SCL_MAX_NAME];
    iec61850_scl_ln_ref_t lns[IEC61850_SCL_MAX_LNS];
    size_t ln_count;
} iec61850_scl_ld_t;

/* Parsed SCL document */
typedef struct {
    iec61850_scl_goose_cb_t goose_cbs[IEC61850_SCL_MAX_CBS];
    size_t goose_cb_count;

    iec61850_scl_sv_cb_t sv_cbs[IEC61850_SCL_MAX_CBS];
    size_t sv_cb_count;

    iec61850_scl_rcb_t rcbs[IEC61850_SCL_MAX_RCBS];
    size_t rcb_count;

    iec61850_scl_dataset_t datasets[IEC61850_SCL_MAX_DATASETS];
    size_t dataset_count;

    iec61850_scl_ld_t lds[IEC61850_SCL_MAX_LDS];
    size_t ld_count;

    /* DataTypeTemplates */
    iec61850_scl_lnode_type_t lnode_types[IEC61850_SCL_MAX_LNODE_TYPES];
    size_t lnode_type_count;

    iec61850_scl_do_type_t do_types[IEC61850_SCL_MAX_DO_TYPES];
    size_t do_type_count;

    iec61850_scl_da_type_t da_types[IEC61850_SCL_MAX_DA_TYPES];
    size_t da_type_count;

    iec61850_scl_enum_type_t enum_types[IEC61850_SCL_MAX_ENUM_TYPES];
    size_t enum_type_count;

    char ied_name[IEC61850_SCL_MAX_NAME];
} iec61850_scl_doc_t;

/**
 * Initialize SCL document.
 */
void iec61850_scl_doc_init(iec61850_scl_doc_t *doc);

/**
 * Parse an SCD file and extract configuration for a given IED.
 *
 * @param filename Path to SCD file
 * @param ied_name IED name to extract (NULL = first IED)
 * @param doc      Output document
 * @return 0 on success, -1 on error
 */
int iec61850_scl_parse_file(const char *filename, const char *ied_name,
                             iec61850_scl_doc_t *doc);

/**
 * Find a GOOSE control block by name.
 */
const iec61850_scl_goose_cb_t *iec61850_scl_find_goose_cb(
    const iec61850_scl_doc_t *doc, const char *cb_name);

/**
 * Find a SV control block by name.
 */
const iec61850_scl_sv_cb_t *iec61850_scl_find_sv_cb(
    const iec61850_scl_doc_t *doc, const char *cb_name);

/**
 * Find a Report Control Block by RptID.
 */
const iec61850_scl_rcb_t *iec61850_scl_find_rcb(
    const iec61850_scl_doc_t *doc, const char *rpt_id);

/**
 * Find a DataSet by name.
 */
const iec61850_scl_dataset_t *iec61850_scl_find_dataset(
    const iec61850_scl_doc_t *doc, const char *name);

/**
 * Find an LNodeType by id.
 */
const iec61850_scl_lnode_type_t *iec61850_scl_find_lnode_type(
    const iec61850_scl_doc_t *doc, const char *id);

/**
 * Find a DOType by id.
 */
const iec61850_scl_do_type_t *iec61850_scl_find_do_type(
    const iec61850_scl_doc_t *doc, const char *id);

/**
 * Find a DAType by id.
 */
const iec61850_scl_da_type_t *iec61850_scl_find_da_type(
    const iec61850_scl_doc_t *doc, const char *id);

/**
 * Find an EnumType by id.
 */
const iec61850_scl_enum_type_t *iec61850_scl_find_enum_type(
    const iec61850_scl_doc_t *doc, const char *id);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_SCL_PARSER_H */
