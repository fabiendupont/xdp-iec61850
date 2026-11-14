/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850 SCL (System Configuration Language) Parser
 *
 * Parses SCD/SCL files using libxml2 to extract GOOSE, SV, and RCB
 * control block configurations plus IED structure.
 *
 * License: BSD-2-Clause
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
#define IEC61850_SCL_MAX_VERSION  16  /* "2007B2" + nul */
#define IEC61850_SCL_MAX_DA_PATH  256 /* dotted DO[.SDO]*[.DA[.BDA]*] path */

/*
 * SCL exchange-file variant (IEC 61850-6). All four share the SCL
 * schema and are accepted by iec61850_scl_parse_file(); the profile
 * is sniffed from document structure and reported in the doc:
 *
 *   SCD  system configuration description: multiple IEDs plus a
 *        Communication section (station-engineering exchange file)
 *   ICD  IED capability description: single IED, no Communication
 *        section (project-independent device capabilities)
 *   IID  instance-independent IED description: single IED, no
 *        Communication section, carries Header history (Ed.2
 *        device-exchange format with pre-engineered content)
 *   CID  configured IED description: single IED with a configured
 *        Communication section (project-configured device)
 *
 * Note: an SCD that happens to contain a single IED is content-
 * indistinguishable from a CID; such documents are reported as CID.
 */
typedef enum {
    IEC61850_SCL_PROFILE_UNKNOWN = 0,
    IEC61850_SCL_PROFILE_SCD,
    IEC61850_SCL_PROFILE_ICD,
    IEC61850_SCL_PROFILE_IID,
    IEC61850_SCL_PROFILE_CID
} iec61850_scl_profile_t;

/* Human-readable profile name ("SCD", "ICD", "IID", "CID"). */
const char *iec61850_scl_profile_name(iec61850_scl_profile_t profile);

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
    bool is_sdo;                           /* true when entry is an SDO (type -> DOType) */
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

    /* Input variant sniffed from the document structure (WP-6e) */
    iec61850_scl_profile_t profile;
    char version[IEC61850_SCL_MAX_VERSION];  /* SCL version attribute */
} iec61850_scl_doc_t;

/**
 * Initialize SCL document.
 */
void iec61850_scl_doc_init(iec61850_scl_doc_t *doc);

/**
 * Parse an SCL exchange file (SCD, ICD, IID or CID — the four
 * IEC 61850-6 variants of the same schema) and extract the
 * configuration for a given IED.
 *
 * The root element must be <SCL>; the version attribute, when
 * present, must be one of 2003/2007/2007B/2007B2. The
 * Communication section is optional (absent in ICD/IID). The
 * sniffed variant is reported in doc->profile.
 *
 * Bounds discipline: every string extracted from the document must
 * fit its fixed-size destination; oversized names fail the parse
 * instead of being silently truncated.
 *
 * @param filename Path to SCL file
 * @param ied_name IED name to extract (NULL = first IED)
 * @param doc      Output document
 * @return 0 on success, -EINVAL on bad arguments / unreadable XML /
 *         non-SCL root / unsupported version, -ENOENT when the file
 *         is not readable or no matching IED exists,
 *         -ENAMETOOLONG when a name exceeds its fixed buffer
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

/**
 * Resolve the label of an EnumType ordinal value.
 *
 * @param et  EnumType to search
 * @param ord Ordinal value
 * @return Label string, or NULL if the ordinal is not defined
 */
const char *iec61850_scl_enum_label(const iec61850_scl_enum_type_t *et,
                                     int32_t ord);

/*
 * FCDA → DA reference resolution (WP-6e).
 *
 * An FCDA names a data point as ldInst / (prefix, lnClass, lnInst) /
 * doName [ / daName ] / fc. Resolution walks the DataTypeTemplates
 * (LNodeType → DOType → DAType) to the concrete leaf DA, yielding a
 * dotted object path and the leaf's type metadata. Both leaf-DA
 * references (daName present, possibly a dotted path through struct
 * BDAs) and whole-DO/SDO references (daName absent) resolve.
 */

/* Result of iec61850_scl_resolve_fcda() */
typedef struct {
    char ld_inst[IEC61850_SCL_MAX_NAME];
    char ln_name[IEC61850_SCL_MAX_NAME * 3];  /* prefix + lnClass + inst */
    char path[IEC61850_SCL_MAX_DA_PATH];      /* "Pos.stVal", "PhV.phsA.cVal.mag.f" */
    char fc[8];

    bool whole_do;    /* true: reference to a whole DO or SDO (no daName) */
    bool leaf_struct; /* true: leaf is a Struct (struct_type set) */

    /* Leaf type metadata (copies from the defining template entry;
     * empty when whole_do is true). */
    char btype[IEC61850_SCL_MAX_NAME];
    char type[IEC61850_SCL_MAX_NAME];

    /* Template back-pointers into doc (NULL when not applicable) */
    const iec61850_scl_do_type_t *do_type;     /* DO(SDO) type of the reference */
    const iec61850_scl_da_type_t *struct_type; /* DAType when leaf is Struct */
    const iec61850_scl_enum_type_t *enum_type; /* EnumType when leaf is Enum */
} iec61850_scl_da_path_t;

/**
 * Resolve one FCDA of a dataset through the DataTypeTemplates.
 *
 * @param doc     Parsed SCL document (with DataTypeTemplates)
 * @param dataset Dataset containing the FCDA
 * @param index   FCDA index within the dataset
 * @param out     Resolved DA path
 * @return 0 on success, -EINVAL on bad arguments or index,
 *         -ENOENT when the reference does not resolve against the
 *         templates (unknown LD/LN/LNodeType/DO/SDO/DA/BDA, or an
 *         FCDA functional constraint that does not match the leaf DA),
 *         -ENAMETOOLONG when the dotted path exceeds out->path
 */
int iec61850_scl_resolve_fcda(const iec61850_scl_doc_t *doc,
                               const iec61850_scl_dataset_t *dataset,
                               size_t index,
                               iec61850_scl_da_path_t *out);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_SCL_PARSER_H */
