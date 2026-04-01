/* SPDX-License-Identifier: BSD-2-Clause */
// SPDX-License-Identifier: BSD-2-Clause
// Copyright (c) 2024 IEC-61850 DPDK Project

/**
 * @file mms_ber.h
 * @brief MMS (Manufacturing Message Specification) ASN.1 BER encoding/decoding
 *
 * Implementation of MMS protocol encoding per ISO 9506-1 and ISO 9506-2.
 * This is a C implementation to enable Frama-C formal verification.
 *
 * References:
 * - ISO 9506-1:2003 - MMS Service Definition
 * - ISO 9506-2:2003 - MMS Protocol Specification
 * - IEC 61850-8-1:2011 - SCSM Mappings to MMS
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ============================================================================
 * Constants and Limits
 * ============================================================================ */

/** Maximum MMS PDU size (negotiated, typically 65000) */
#define MMS_MAX_PDU_SIZE 65535

/** Maximum MMS domain name length */
#define MMS_MAX_DOMAIN_NAME 256

/** Maximum MMS variable name length */
#define MMS_MAX_VARIABLE_NAME 256

/** Maximum visible string length */
#define MMS_MAX_STRING_LENGTH 256

/** Maximum number of variables in a named variable list */
#define MMS_MAX_NAMED_VARIABLES 256

/** Maximum number of items in GetNameList response */
#define MMS_MAX_NAMELIST_ITEMS 1024

/** Standard MMS port */
#define MMS_STANDARD_PORT 102

/* ============================================================================
 * Return Codes
 * ============================================================================ */

/** Success */
#define MMS_OK 0

/** Buffer too small */
#define MMS_ERROR_BUFFER_TOO_SMALL -1

/** Invalid parameter */
#define MMS_ERROR_INVALID_PARAM -2

/** Invalid encoding */
#define MMS_ERROR_INVALID_ENCODING -3

/** Service not supported */
#define MMS_ERROR_NOT_SUPPORTED -4

/** Service error response */
#define MMS_ERROR_SERVICE_ERROR -5

/** Out of memory */
#define MMS_ERROR_OUT_OF_MEMORY -6

/* ============================================================================
 * ASN.1 Tags (ISO 9506-2)
 * ============================================================================ */

/** MMS PDU Tags (context-specific) */
#define MMS_TAG_CONFIRMED_REQUEST     0xA0  /* [0] IMPLICIT */
#define MMS_TAG_CONFIRMED_RESPONSE    0xA1  /* [1] IMPLICIT */
#define MMS_TAG_CONFIRMED_ERROR       0xA2  /* [2] IMPLICIT */
#define MMS_TAG_UNCONFIRMED           0xA3  /* [3] IMPLICIT */
#define MMS_TAG_REJECT                0xA4  /* [4] IMPLICIT */
#define MMS_TAG_INITIATE_REQUEST      0xA8  /* [8] IMPLICIT */
#define MMS_TAG_INITIATE_RESPONSE     0xA9  /* [9] IMPLICIT */
#define MMS_TAG_CONCLUDE_REQUEST      0x8A  /* [10] IMPLICIT */
#define MMS_TAG_CONCLUDE_RESPONSE     0x8B  /* [11] IMPLICIT */

/*
 * MMS Confirmed Service tags (context-specific [n], constructed form).
 * Per ASN.1 BER, IMPLICIT on a SEQUENCE preserves the constructed bit.
 * Decoders normalize both 0x80|n and 0xA0|n for interoperability.
 */
#define MMS_SERVICE_STATUS                  0x80  /* [0] IMPLICIT INTEGER */
#define MMS_SERVICE_GET_NAMELIST            0xA1  /* [1] IMPLICIT SEQUENCE */
#define MMS_SERVICE_IDENTIFY                0x82  /* [2] IMPLICIT NULL */
#define MMS_SERVICE_RENAME                  0xA3  /* [3] IMPLICIT SEQUENCE */
#define MMS_SERVICE_READ                    0xA4  /* [4] IMPLICIT SEQUENCE */
#define MMS_SERVICE_WRITE                   0xA5  /* [5] IMPLICIT SEQUENCE */
#define MMS_SERVICE_GET_VARIABLE_ATTRS      0xA6  /* [6] IMPLICIT SEQUENCE */
#define MMS_SERVICE_SELECT                  0xA7  /* [7] IMPLICIT SEQUENCE */
#define MMS_SERVICE_SELECT_WITH_VALUE       0xA8  /* [8] IMPLICIT SEQUENCE */
#define MMS_SERVICE_OPERATE                 0xA9  /* [9] IMPLICIT SEQUENCE */
#define MMS_SERVICE_CANCEL                  0xAA  /* [10] IMPLICIT SEQUENCE */
#define MMS_SERVICE_DEFINE_NAMED_VARLIST    0xAB  /* [11] IMPLICIT SEQUENCE */
#define MMS_SERVICE_GET_NAMED_VARLIST_ATTRS 0xAC  /* [12] IMPLICIT SEQUENCE */
#define MMS_SERVICE_DELETE_NAMED_VARLIST    0xAD  /* [13] IMPLICIT SEQUENCE */
#define MMS_SERVICE_FILE_OPEN               0xAE  /* [14] IMPLICIT SEQUENCE */
#define MMS_SERVICE_FILE_READ               0xAF  /* [15] IMPLICIT SEQUENCE */
#define MMS_SERVICE_FILE_CLOSE              0x90  /* [16] IMPLICIT INTEGER */
#define MMS_SERVICE_FILE_DELETE             0xB1  /* [17] IMPLICIT SEQUENCE */
#define MMS_SERVICE_FILE_DIRECTORY          0xB2  /* [18] IMPLICIT SEQUENCE */
#define MMS_SERVICE_READ_JOURNAL            0xB3  /* [19] IMPLICIT SEQUENCE */
#define MMS_SERVICE_INITIALIZE_JOURNAL      0xB4  /* [20] IMPLICIT SEQUENCE */
#define MMS_SERVICE_DEFINE_NAMED_TYPE       0xB5  /* [21] IMPLICIT SEQUENCE */
#define MMS_SERVICE_DELETE_NAMED_TYPE       0xB6  /* [22] IMPLICIT SEQUENCE */
#define MMS_SERVICE_GET_NAMED_TYPE_ATTRS    0xB7  /* [23] IMPLICIT SEQUENCE */
#define MMS_SERVICE_COMMAND_TERMINATION     0xA0  /* Unconfirmed [0] */

/** MMS Data Type Tags */
#define MMS_DATA_ARRAY          0xA1  /* [1] IMPLICIT */
#define MMS_DATA_STRUCTURE      0xA2  /* [2] IMPLICIT */
#define MMS_DATA_BOOLEAN        0x83  /* [3] IMPLICIT */
#define MMS_DATA_BIT_STRING     0x84  /* [4] IMPLICIT */
#define MMS_DATA_INTEGER        0x85  /* [5] IMPLICIT */
#define MMS_DATA_UNSIGNED       0x86  /* [6] IMPLICIT */
#define MMS_DATA_FLOATING_POINT 0x87  /* [7] IMPLICIT */
#define MMS_DATA_OCTET_STRING   0x89  /* [9] IMPLICIT */
#define MMS_DATA_VISIBLE_STRING 0x8A  /* [10] IMPLICIT */
#define MMS_DATA_BINARY_TIME    0x8C  /* [12] IMPLICIT */
#define MMS_DATA_BCD            0x8D  /* [13] IMPLICIT */
#define MMS_DATA_BOOLEANARRAY   0x8E  /* [14] IMPLICIT */
#define MMS_DATA_UTC_TIME       0x91  /* [17] IMPLICIT */

/* ============================================================================
 * Enumerations
 * ============================================================================ */

/**
 * @brief MMS object class for GetNameList
 */
typedef enum {
    MMS_OBJECT_CLASS_NAMED_VARIABLE = 0,
    MMS_OBJECT_CLASS_NAMED_VARIABLE_LIST = 2,
    MMS_OBJECT_CLASS_NAMED_TYPE = 1,
    MMS_OBJECT_CLASS_DATA_SET = 2,
    MMS_OBJECT_CLASS_DOMAIN = 9
} mms_object_class_t;

/**
 * @brief MMS service types
 */
typedef enum {
    MMS_SERVICE_TYPE_STATUS = 0,
    MMS_SERVICE_TYPE_GET_NAMELIST = 1,
    MMS_SERVICE_TYPE_IDENTIFY = 2,
    MMS_SERVICE_TYPE_READ = 4,
    MMS_SERVICE_TYPE_WRITE = 5,
    MMS_SERVICE_TYPE_GET_VARIABLE_ATTRS = 6,
    MMS_SERVICE_TYPE_SELECT = 7,                    /* Phase 7 - Control */
    MMS_SERVICE_TYPE_SELECT_WITH_VALUE = 8,         /* Phase 7 - Control */
    MMS_SERVICE_TYPE_OPERATE = 9,                   /* Phase 7 - Control */
    MMS_SERVICE_TYPE_CANCEL = 10,                   /* Phase 7 - Control */
    MMS_SERVICE_TYPE_DEFINE_NAMED_VARLIST = 11,
    MMS_SERVICE_TYPE_GET_NAMED_VARLIST_ATTRS = 12,
    MMS_SERVICE_TYPE_DELETE_NAMED_VARLIST = 13,
    MMS_SERVICE_TYPE_READ_NAMED_VARLIST = 14,       /* ReadNamedVariableList (data sets) */
    MMS_SERVICE_TYPE_WRITE_NAMED_VARLIST = 15,      /* WriteNamedVariableList (data sets) */
    MMS_SERVICE_TYPE_FILE_OPEN = 16,                /* Phase 7 - File */
    MMS_SERVICE_TYPE_FILE_READ = 17,                /* Phase 7 - File */
    MMS_SERVICE_TYPE_FILE_CLOSE = 18,               /* Phase 7 - File */
    MMS_SERVICE_TYPE_FILE_DELETE = 19,              /* Phase 7 - File */
    MMS_SERVICE_TYPE_FILE_DIRECTORY = 20,           /* Phase 7 - File */
    MMS_SERVICE_TYPE_READ_JOURNAL = 21,             /* Phase 7 - Journal */
    MMS_SERVICE_TYPE_INITIALIZE_JOURNAL = 22,       /* Phase 7 - Journal */
    MMS_SERVICE_TYPE_DEFINE_NAMED_TYPE = 23,        /* Phase 7 - Type */
    MMS_SERVICE_TYPE_DELETE_NAMED_TYPE = 24,        /* Phase 7 - Type */
    MMS_SERVICE_TYPE_GET_NAMED_TYPE_ATTRS = 25,     /* Phase 7 - Type */
    MMS_SERVICE_TYPE_COMMAND_TERMINATION = 26       /* Phase 7 - Control (Unconfirmed) */
} mms_service_type_t;

/**
 * @brief MMS data type
 */
typedef enum {
    MMS_TYPE_ARRAY = 1,
    MMS_TYPE_STRUCTURE = 2,
    MMS_TYPE_BOOLEAN = 3,
    MMS_TYPE_BIT_STRING = 4,
    MMS_TYPE_INTEGER = 5,
    MMS_TYPE_UNSIGNED = 6,
    MMS_TYPE_FLOATING_POINT = 7,
    MMS_TYPE_OCTET_STRING = 9,
    MMS_TYPE_VISIBLE_STRING = 10,
    MMS_TYPE_BINARY_TIME = 12,
    MMS_TYPE_BCD = 13,
    MMS_TYPE_BOOLEANARRAY = 14,
    MMS_TYPE_UTC_TIME = 17
} mms_type_t;

/**
 * @brief MMS error class
 */
typedef enum {
    MMS_ERROR_CLASS_VMD_STATE = 0,
    MMS_ERROR_CLASS_APPLICATION_REFERENCE = 1,
    MMS_ERROR_CLASS_DEFINITION = 2,
    MMS_ERROR_CLASS_RESOURCE = 3,
    MMS_ERROR_CLASS_SERVICE = 4,
    MMS_ERROR_CLASS_SERVICE_PREEMPT = 5,
    MMS_ERROR_CLASS_TIME_RESOLUTION = 6,
    MMS_ERROR_CLASS_ACCESS = 7,
    MMS_ERROR_CLASS_INITIATE = 8,
    MMS_ERROR_CLASS_CONCLUDE = 9,
    MMS_ERROR_CLASS_CANCEL = 10,
    MMS_ERROR_CLASS_FILE = 11,
    MMS_ERROR_CLASS_OTHERS = 12,
    MMS_ERROR_CLASS_CONTROL = 13  /* Phase 7 - Control service errors */
} mms_error_class_t;

/**
 * @brief MMS error codes for MMS_ERROR_CLASS_ACCESS
 * Per ISO 9506-2 Table 22 - Access error codes
 */
#define MMS_ACCESS_ERROR_OBJECT_NON_EXISTENT 0
#define MMS_ACCESS_ERROR_OBJECT_ACCESS_UNSUPPORTED 1
#define MMS_ACCESS_ERROR_OBJECT_EXISTS 2
#define MMS_ACCESS_ERROR_OBJECT_UNDEFINED 3
#define MMS_ACCESS_ERROR_TYPE_INCONSISTENT 5

/**
 * @brief MMS error codes for MMS_ERROR_CLASS_SERVICE
 * Per ISO 9506-2 Table 25 - Service error codes
 */
#define MMS_SERVICE_ERROR_OTHER 0
#define MMS_SERVICE_ERROR_PARAMETER_VALUE_INAPPROPRIATE 1

/**
 * @brief MMS error codes for MMS_ERROR_CLASS_CONTROL
 * Phase 7 - Control service errors
 */
#define MMS_CONTROL_ERROR_ALREADY_SELECTED 0
#define MMS_CONTROL_ERROR_NOT_SELECTED 1
#define MMS_CONTROL_ERROR_INVALID_SELECTION_ID 2
#define MMS_CONTROL_ERROR_SELECTION_TIMEOUT 3
#define MMS_CONTROL_ERROR_CONTROL_BLOCKED 4
#define MMS_CONTROL_ERROR_CONTROL_IN_PROGRESS 5

/**
 * @brief MMS error codes for MMS_ERROR_CLASS_FILE
 * Phase 7 - File service errors
 */
#define MMS_FILE_ERROR_FILE_NOT_FOUND 0
#define MMS_FILE_ERROR_ACCESS_DENIED 1
#define MMS_FILE_ERROR_FILE_BUSY 2
#define MMS_FILE_ERROR_INVALID_HANDLE 3
#define MMS_FILE_ERROR_PATH_TRAVERSAL 4
#define MMS_FILE_ERROR_FILE_TOO_LARGE 5

/* ============================================================================
 * Data Structures
 * ============================================================================ */

/**
 * @brief MMS value union
 */
typedef struct {
    mms_type_t type;
    union {
        bool boolean;
        int32_t integer;
        uint32_t unsigned_val;
        float floating_point;
        struct {
            uint8_t data[MMS_MAX_STRING_LENGTH];
            size_t len;
        } octet_string;
        struct {
            char data[MMS_MAX_STRING_LENGTH];
            size_t len;
        } visible_string;
        uint64_t utc_time;
        struct {
            uint8_t data[32];  /* Max bit string size */
            size_t bit_count;
        } bit_string;
    } value;
} mms_value_t;

/**
 * @brief MMS variable specification
 */
typedef struct {
    char domain[MMS_MAX_DOMAIN_NAME];
    char item_id[MMS_MAX_VARIABLE_NAME];
} mms_variable_spec_t;

/**
 * @brief MMS variable access specification (for type info)
 */
typedef struct {
    char name[MMS_MAX_VARIABLE_NAME];
    mms_type_t type;
    /* Additional type-specific info can be added */
} mms_variable_access_attrs_t;

/* ============================================================================
 * Service Request/Response Structures
 * ============================================================================ */

/**
 * @brief MMS Initiate Request
 */
typedef struct {
    uint32_t proposed_max_pdu_size;
    uint32_t proposed_data_structure_nesting_level;
    int32_t proposed_version_number;
    /* Additional parameters can be added */
} mms_initiate_request_t;

/**
 * @brief MMS Initiate Response
 */
typedef struct {
    uint32_t negotiated_max_pdu_size;
    uint32_t negotiated_data_structure_nesting_level;
    int32_t negotiated_version_number;
    /* Additional parameters can be added */
} mms_initiate_response_t;

/**
 * @brief MMS Conclude Request (empty)
 */
typedef struct {
    uint8_t reserved;  /* Empty structure, placeholder */
} mms_conclude_request_t;

/**
 * @brief MMS Conclude Response (empty)
 */
typedef struct {
    uint8_t reserved;  /* Empty structure, placeholder */
} mms_conclude_response_t;

/**
 * @brief MMS Status Response
 * Per ISO 9506-2: VMD logical status + physical status
 */
typedef struct {
    uint8_t vmd_logical_status;    /* 0=state-changes-allowed, 1=no-state-changes, 2=limited */
    uint8_t vmd_physical_status;   /* 0=operational, 1=partially-operational, 2=inoperable, 3=needs-commissioning */
} mms_status_response_t;

/**
 * @brief MMS Identify Response
 * Per ISO 9506-2: vendor, model, revision strings
 */
typedef struct {
    char vendor_name[MMS_MAX_VARIABLE_NAME];
    char model_name[MMS_MAX_VARIABLE_NAME];
    char revision[MMS_MAX_VARIABLE_NAME];
} mms_identify_response_t;

/**
 * @brief MMS Read Request
 */
typedef struct {
    mms_variable_spec_t variable_spec;
} mms_read_request_t;

/**
 * @brief MMS Read Response
 */
typedef struct {
    mms_value_t value;
} mms_read_response_t;

/**
 * @brief MMS Write Request
 */
typedef struct {
    mms_variable_spec_t variable_spec;
    mms_value_t value;
} mms_write_request_t;

/**
 * @brief MMS Write Response (empty - success indication)
 */
typedef struct {
    uint8_t reserved;  /* Empty structure, placeholder */
} mms_write_response_t;

/**
 * @brief MMS ReadNamedVariableList Request
 *
 * Reads all variables in a named variable list atomically.
 * Uses variableListName [1] variant of VariableAccessSpecification.
 */
typedef struct {
    char domain[MMS_MAX_DOMAIN_NAME];
    char list_name[MMS_MAX_VARIABLE_NAME];
} mms_readnamedvarlist_request_t;

/**
 * @brief MMS ReadNamedVariableList Response
 *
 * Returns array of values corresponding to variables in the list.
 */
typedef struct {
    mms_value_t values[MMS_MAX_NAMED_VARIABLES];
    uint32_t num_values;
} mms_readnamedvarlist_response_t;

/**
 * @brief MMS WriteNamedVariableList Request
 *
 * Writes all variables in a named variable list atomically.
 * Number of values must match the list definition.
 */
typedef struct {
    char domain[MMS_MAX_DOMAIN_NAME];
    char list_name[MMS_MAX_VARIABLE_NAME];
    mms_value_t values[MMS_MAX_NAMED_VARIABLES];
    uint32_t num_values;
} mms_writenamedvarlist_request_t;

/**
 * @brief MMS WriteNamedVariableList Response (empty - success indication)
 */
typedef struct {
    uint8_t reserved;  /* Empty structure, placeholder */
} mms_writenamedvarlist_response_t;

/**
 * @brief MMS GetNameList Request
 */
typedef struct {
    mms_object_class_t object_class;
    char domain[MMS_MAX_DOMAIN_NAME];
    bool continue_after;  /* True if continueAfter token is set */
    char continue_after_id[MMS_MAX_VARIABLE_NAME];  /* Last identifier from previous response */
} mms_getnamelist_request_t;

/**
 * @brief MMS GetNameList Response
 */
typedef struct {
    char identifiers[MMS_MAX_NAMELIST_ITEMS][MMS_MAX_VARIABLE_NAME];
    uint32_t num_identifiers;
    bool more_follows;  /* True if more results available */
} mms_getnamelist_response_t;

/**
 * @brief MMS GetVariableAccessAttributes Request
 */
typedef struct {
    mms_variable_spec_t variable_spec;
} mms_getvariableattrs_request_t;

/**
 * @brief MMS GetVariableAccessAttributes Response
 */
typedef struct {
    mms_variable_access_attrs_t attributes;
} mms_getvariableattrs_response_t;

/**
 * @brief MMS DefineNamedVariableList Request
 */
typedef struct {
    char domain[MMS_MAX_DOMAIN_NAME];
    char list_name[MMS_MAX_VARIABLE_NAME];
    mms_variable_spec_t variables[MMS_MAX_NAMED_VARIABLES];
    uint32_t num_variables;
} mms_definenamedvarlist_request_t;

/**
 * @brief MMS DefineNamedVariableList Response (empty - success indication)
 */
typedef struct {
    uint8_t reserved;  /* Empty structure, placeholder */
} mms_definenamedvarlist_response_t;

/**
 * @brief MMS DeleteNamedVariableList Request
 */
typedef struct {
    char domain[MMS_MAX_DOMAIN_NAME];
    char list_name[MMS_MAX_VARIABLE_NAME];
} mms_deletenamedvarlist_request_t;

/**
 * @brief MMS DeleteNamedVariableList Response (empty - success indication)
 */
typedef struct {
    uint8_t reserved;  /* Empty structure, placeholder */
} mms_deletenamedvarlist_response_t;

/**
 * @brief MMS GetNamedVariableListAttributes Request
 */
typedef struct {
    char domain[MMS_MAX_DOMAIN_NAME];
    char list_name[MMS_MAX_VARIABLE_NAME];
} mms_getnamedvarlistattrs_request_t;

/**
 * @brief MMS GetNamedVariableListAttributes Response
 */
typedef struct {
    mms_variable_spec_t variables[MMS_MAX_NAMED_VARIABLES];
    uint32_t num_variables;
    bool deletable;
} mms_getnamedvarlistattrs_response_t;

/**
 * @brief MMS InformationReport (unsolicited notification)
 *
 * InformationReport is an unconfirmed service that allows the server
 * to send asynchronous notifications to the client. Used for reports
 * and event notifications in IEC 61850.
 *
 * Optional Fields (Phase 6 Week 3):
 * Each optional field has a corresponding *_present flag. When the flag
 * is false, the field is not encoded in BER. This maintains backward
 * compatibility with Week 2 URCB implementation.
 */
typedef struct {
    // Core fields (Week 2)
    char variable_list_name[MMS_MAX_VARIABLE_NAME];
    mms_value_t values[MMS_MAX_NAMED_VARIABLES];
    uint32_t num_values;

    // Optional fields (Week 3 - IEC 61850-7-2 RCB)
    uint16_t sq_num;                        ///< Sequence number
    bool sq_num_present;                    ///< Include sequence number in report

    uint64_t report_timestamp;              ///< Report timestamp (UTC milliseconds)
    bool report_timestamp_present;          ///< Include timestamp in report

    uint8_t reasons[MMS_MAX_NAMED_VARIABLES]; ///< Reason-for-inclusion per value
    bool reasons_present;                   ///< Include reason codes in report

    char data_references[MMS_MAX_NAMED_VARIABLES][MMS_MAX_VARIABLE_NAME]; ///< Data references
    bool data_references_present;           ///< Include data references in report

    bool buffer_overflow;                   ///< Buffer overflow occurred
    bool buffer_overflow_present;           ///< Include buffer overflow flag

    uint64_t entry_id;                      ///< Entry ID (BRCB only)
    bool entry_id_present;                  ///< Include entry ID in report

    char config_ref[MMS_MAX_VARIABLE_NAME]; ///< Configuration reference
    bool config_ref_present;                ///< Include config ref in report
} mms_information_report_t;

/* ============================================================================
 * Phase 7: Control Service Structures
 * ============================================================================ */

/**
 * @brief Control object state (IEC 61850 control model)
 */
typedef enum {
    MMS_CONTROL_STATE_READY = 0,      /**< Available for selection */
    MMS_CONTROL_STATE_SELECTED = 1,   /**< Reserved by client */
    MMS_CONTROL_STATE_OPERATE = 2,    /**< Command executing */
    MMS_CONTROL_STATE_BLOCKED = 3,    /**< Control disabled */
    MMS_CONTROL_STATE_TEST = 4        /**< Test mode */
} mms_control_state_t;

/**
 * @brief MMS Select Request (IEC 61850 Select-Before-Operate)
 * Per ISO 9506-2 §9.1.2
 */
typedef struct {
    mms_variable_spec_t control_object;  /**< Control object reference */
    uint8_t check_value;                 /**< Check conditions (synchro, interlocking) */
    uint32_t select_timeout_ms;          /**< Selection timeout (0 = default 30s) */
} mms_select_request_t;

/**
 * @brief MMS Select Response
 */
typedef struct {
    mms_control_state_t state;           /**< Control state after selection */
    uint32_t selection_id;               /**< Unique selection identifier */
} mms_select_response_t;

/**
 * @brief MMS SelectWithValue Request
 */
typedef struct {
    mms_variable_spec_t control_object;  /**< Control object reference */
    mms_value_t control_value;           /**< Preloaded control value */
    uint8_t check_value;                 /**< Check conditions */
    uint32_t select_timeout_ms;          /**< Selection timeout */
} mms_select_with_value_request_t;

/**
 * @brief MMS SelectWithValue Response
 */
typedef struct {
    mms_control_state_t state;           /**< Control state after selection */
    uint32_t selection_id;               /**< Unique selection identifier */
} mms_select_with_value_response_t;

/**
 * @brief MMS Operate Request
 */
typedef struct {
    mms_variable_spec_t control_object;  /**< Control object reference */
    uint32_t selection_id;               /**< Selection ID from Select */
    mms_value_t control_value;           /**< Control value (if not preloaded) */
    bool has_control_value;              /**< True if control_value is provided */
    uint64_t operation_time;             /**< Scheduled operation time (0 = immediate) */
} mms_operate_request_t;

/**
 * @brief MMS Operate Response
 */
typedef struct {
    mms_control_state_t state;           /**< Control state after operate */
    bool success;                        /**< Operation initiated successfully */
} mms_operate_response_t;

/**
 * @brief MMS Cancel Request
 */
typedef struct {
    mms_variable_spec_t control_object;  /**< Control object reference */
    uint32_t selection_id;               /**< Selection ID to cancel */
} mms_cancel_request_t;

/**
 * @brief MMS Cancel Response (empty - success indication)
 */
typedef struct {
    uint8_t reserved;
} mms_cancel_response_t;

/**
 * @brief MMS CommandTermination (unconfirmed service)
 * Sent by server to notify client of command completion
 */
typedef struct {
    mms_variable_spec_t control_object;  /**< Control object reference */
    uint32_t selection_id;               /**< Selection ID */
    bool success;                        /**< Command completed successfully */
    uint8_t termination_reason;          /**< Reason code */
} mms_command_termination_t;

/* ============================================================================
 * Phase 7 Week 2: File Services
 * ============================================================================ */

/**
 * @brief File access mode
 */
typedef enum {
    MMS_FILE_ACCESS_READ = 0,
    MMS_FILE_ACCESS_WRITE = 1,
    MMS_FILE_ACCESS_APPEND = 2
} mms_file_access_mode_t;

/**
 * @brief File entry (for directory listing)
 */
typedef struct {
    char filename[MMS_MAX_VARIABLE_NAME];
    uint64_t file_size;
    uint64_t last_modified;  /**< UTC timestamp in milliseconds */
} mms_file_entry_t;

/**
 * @brief MMS FileOpen Request
 */
typedef struct {
    char filename[MMS_MAX_VARIABLE_NAME];
    mms_file_access_mode_t access_mode;
} mms_fileopen_request_t;

/**
 * @brief MMS FileOpen Response
 */
typedef struct {
    uint32_t file_handle;
    uint64_t file_size;
} mms_fileopen_response_t;

/**
 * @brief MMS FileRead Request
 */
typedef struct {
    uint32_t file_handle;
    uint32_t max_bytes;  /**< Maximum bytes to read (respecting max PDU size) */
} mms_fileread_request_t;

/**
 * @brief MMS FileRead Response
 */
typedef struct {
    uint8_t data[MMS_MAX_PDU_SIZE];
    uint32_t bytes_read;
    bool more_follows;  /**< True if file has more data */
} mms_fileread_response_t;

/**
 * @brief MMS FileClose Request
 */
typedef struct {
    uint32_t file_handle;
} mms_fileclose_request_t;

/**
 * @brief MMS FileClose Response (empty - success indication)
 */
typedef struct {
    uint8_t reserved;
} mms_fileclose_response_t;

/**
 * @brief MMS FileDelete Request
 */
typedef struct {
    char filename[MMS_MAX_VARIABLE_NAME];
} mms_filedelete_request_t;

/**
 * @brief MMS FileDelete Response (empty - success indication)
 */
typedef struct {
    uint8_t reserved;
} mms_filedelete_response_t;

/**
 * @brief MMS FileDirectory Request
 */
typedef struct {
    char directory[MMS_MAX_VARIABLE_NAME];  /**< Directory path (empty = root) */
    char file_specification[MMS_MAX_VARIABLE_NAME];  /**< Wildcard pattern (e.g., "*.scd") */
} mms_filedirectory_request_t;

/**
 * @brief MMS FileDirectory Response
 */
typedef struct {
    mms_file_entry_t entries[MMS_MAX_NAMELIST_ITEMS];
    uint32_t num_entries;
    bool more_follows;  /**< True if directory has more entries */
} mms_filedirectory_response_t;

/* ============================================================================
 * Journal Service Structures (Phase 7 Week 3)
 * ============================================================================ */

#define MMS_MAX_JOURNAL_ENTRIES 50  /**< Max journal entries per response */

/**
 * @brief Journal Entry
 */
typedef struct {
    uint64_t entry_id;                           /**< Unique entry identifier */
    uint64_t timestamp;                          /**< UTC timestamp in milliseconds */
    char variable_ref[MMS_MAX_VARIABLE_NAME];    /**< Associated variable (optional) */
    char entry_data[MMS_MAX_STRING_LENGTH];      /**< Journal entry data */
} mms_journal_entry_t;

/**
 * @brief MMS ReadJournal Request
 */
typedef struct {
    char journal_name[MMS_MAX_VARIABLE_NAME];    /**< Journal name */
    uint64_t start_time;                         /**< Start time filter (0 = no filter) */
    uint64_t end_time;                           /**< End time filter (0 = no filter) */
    uint64_t start_entry_id;                     /**< Start entry ID (0 = from beginning) */
    uint32_t max_entries;                        /**< Maximum entries to return */
} mms_readjournal_request_t;

/**
 * @brief MMS ReadJournal Response
 */
typedef struct {
    mms_journal_entry_t entries[MMS_MAX_JOURNAL_ENTRIES];
    uint32_t num_entries;
    bool more_follows;                           /**< True if more entries available */
} mms_readjournal_response_t;

/**
 * @brief MMS InitializeJournal Request
 */
typedef struct {
    char journal_name[MMS_MAX_VARIABLE_NAME];    /**< Journal name to initialize/clear */
} mms_initializejournal_request_t;

/**
 * @brief MMS InitializeJournal Response
 */
typedef struct {
    uint8_t reserved; /* Empty response - success indicated by no error */
} mms_initializejournal_response_t;

/* ============================================================================
 * Type Services (Phase 7 Week 4)
 * ============================================================================ */

/**
 * @brief MMS DefineNamedType Request
 */
typedef struct {
    char domain[MMS_MAX_DOMAIN_NAME];           /**< Domain name (VMD-specific if empty) */
    char type_name[MMS_MAX_VARIABLE_NAME];      /**< Named type identifier */
    mms_type_t type_spec;                       /**< Type specification (simplified) */
} mms_definenamedtype_request_t;

/**
 * @brief MMS DefineNamedType Response
 */
typedef struct {
    uint8_t reserved; /* Empty response - success indicated by no error */
} mms_definenamedtype_response_t;

/**
 * @brief MMS DeleteNamedType Request
 */
typedef struct {
    char domain[MMS_MAX_DOMAIN_NAME];           /**< Domain name (VMD-specific if empty) */
    char type_name[MMS_MAX_VARIABLE_NAME];      /**< Named type identifier to delete */
} mms_deletenamedtype_request_t;

/**
 * @brief MMS DeleteNamedType Response
 */
typedef struct {
    uint8_t reserved; /* Empty response - success indicated by no error */
} mms_deletenamedtype_response_t;

/**
 * @brief MMS GetNamedTypeAttributes Request
 */
typedef struct {
    char domain[MMS_MAX_DOMAIN_NAME];           /**< Domain name (VMD-specific if empty) */
    char type_name[MMS_MAX_VARIABLE_NAME];      /**< Named type identifier */
} mms_getnamedtypeattrs_request_t;

/**
 * @brief MMS GetNamedTypeAttributes Response
 */
typedef struct {
    mms_type_t type_spec;                       /**< Type specification */
} mms_getnamedtypeattrs_response_t;

/**
 * @brief MMS Service Error
 */
typedef struct {
    mms_error_class_t error_class;
    int32_t error_code;
    char additional_description[MMS_MAX_STRING_LENGTH];
} mms_service_error_t;

/**
 * @brief Generic MMS Confirmed Request PDU
 */
typedef struct {
    uint32_t invoke_id;
    mms_service_type_t service;
    union {
        mms_read_request_t read;
        mms_write_request_t write;
        mms_getnamelist_request_t getnamelist;
        mms_getvariableattrs_request_t getvariableattrs;
        mms_definenamedvarlist_request_t definenamedvarlist;
        mms_deletenamedvarlist_request_t deletenamedvarlist;
        mms_getnamedvarlistattrs_request_t getnamedvarlistattrs;
        mms_readnamedvarlist_request_t readnamedvarlist;     /* ReadNamedVariableList */
        mms_writenamedvarlist_request_t writenamedvarlist;   /* WriteNamedVariableList */
        mms_select_request_t select;                         /* Phase 7 */
        mms_select_with_value_request_t select_with_value;   /* Phase 7 */
        mms_operate_request_t operate;                       /* Phase 7 */
        mms_cancel_request_t cancel;                         /* Phase 7 */
        mms_fileopen_request_t fileopen;                     /* Phase 7 Week 2 */
        mms_fileread_request_t fileread;                     /* Phase 7 Week 2 */
        mms_fileclose_request_t fileclose;                   /* Phase 7 Week 2 */
        mms_filedelete_request_t filedelete;                 /* Phase 7 Week 2 */
        mms_filedirectory_request_t filedirectory;           /* Phase 7 Week 2 */
        mms_readjournal_request_t readjournal;               /* Phase 7 Week 3 */
        mms_initializejournal_request_t initializejournal;   /* Phase 7 Week 3 */
        mms_definenamedtype_request_t definenamedtype;       /* Phase 7 Week 4 */
        mms_deletenamedtype_request_t deletenamedtype;       /* Phase 7 Week 4 */
        mms_getnamedtypeattrs_request_t getnamedtypeattrs;   /* Phase 7 Week 4 */
    } params;
} mms_confirmed_request_t;

/**
 * @brief Generic MMS Confirmed Response PDU
 */
typedef struct {
    uint32_t invoke_id;
    mms_service_type_t service;
    union {
        mms_status_response_t status;
        mms_identify_response_t identify;
        mms_read_response_t read;
        mms_write_response_t write;
        mms_getnamelist_response_t getnamelist;
        mms_getvariableattrs_response_t getvariableattrs;
        mms_definenamedvarlist_response_t definenamedvarlist;
        mms_deletenamedvarlist_response_t deletenamedvarlist;
        mms_getnamedvarlistattrs_response_t getnamedvarlistattrs;
        mms_readnamedvarlist_response_t readnamedvarlist;    /* ReadNamedVariableList */
        mms_writenamedvarlist_response_t writenamedvarlist;  /* WriteNamedVariableList */
        mms_select_response_t select;                        /* Phase 7 */
        mms_select_with_value_response_t select_with_value;  /* Phase 7 */
        mms_operate_response_t operate;                      /* Phase 7 */
        mms_cancel_response_t cancel;                        /* Phase 7 */
        mms_fileopen_response_t fileopen;                    /* Phase 7 Week 2 */
        mms_fileread_response_t fileread;                    /* Phase 7 Week 2 */
        mms_fileclose_response_t fileclose;                  /* Phase 7 Week 2 */
        mms_filedelete_response_t filedelete;                /* Phase 7 Week 2 */
        mms_filedirectory_response_t filedirectory;          /* Phase 7 Week 2 */
        mms_readjournal_response_t readjournal;              /* Phase 7 Week 3 */
        mms_initializejournal_response_t initializejournal;  /* Phase 7 Week 3 */
        mms_definenamedtype_response_t definenamedtype;      /* Phase 7 Week 4 */
        mms_deletenamedtype_response_t deletenamedtype;      /* Phase 7 Week 4 */
        mms_getnamedtypeattrs_response_t getnamedtypeattrs;  /* Phase 7 Week 4 */
    } params;
} mms_confirmed_response_t;

/**
 * @brief MMS Confirmed Error PDU
 */
typedef struct {
    uint32_t invoke_id;
    mms_service_error_t error;
} mms_confirmed_error_t;

/* ============================================================================
 * Encoding Functions
 * ============================================================================ */

/**
 * @brief Encode MMS Initiate Request
 *
 * @param request Initiate request structure
 * @param buffer Output buffer
 * @param buflen Buffer length
 * @return Number of bytes encoded, or negative error code
 */
int mms_encode_initiate_request(const mms_initiate_request_t* request,
                                uint8_t* buffer, size_t buflen);

/**
 * @brief Encode MMS Initiate Response
 *
 * @param response Initiate response structure
 * @param buffer Output buffer
 * @param buflen Buffer length
 * @return Number of bytes encoded, or negative error code
 */
int mms_encode_initiate_response(const mms_initiate_response_t* response,
                                 uint8_t* buffer, size_t buflen);

/**
 * @brief Encode MMS Conclude Request
 *
 * @param request Conclude request structure
 * @param buffer Output buffer
 * @param buflen Buffer length
 * @return Number of bytes encoded, or negative error code
 */
int mms_encode_conclude_request(const mms_conclude_request_t* request,
                                uint8_t* buffer, size_t buflen);

/**
 * @brief Encode MMS Conclude Response
 *
 * @param response Conclude response structure
 * @param buffer Output buffer
 * @param buflen Buffer length
 * @return Number of bytes encoded, or negative error code
 */
int mms_encode_conclude_response(const mms_conclude_response_t* response,
                                 uint8_t* buffer, size_t buflen);

/**
 * @brief Encode MMS Confirmed Request
 *
 * @param request Confirmed request structure
 * @param buffer Output buffer
 * @param buflen Buffer length
 * @return Number of bytes encoded, or negative error code
 */
int mms_encode_confirmed_request(const mms_confirmed_request_t* request,
                                 uint8_t* buffer, size_t buflen);

/**
 * @brief Encode MMS Confirmed Response
 *
 * @param response Confirmed response structure
 * @param buffer Output buffer
 * @param buflen Buffer length
 * @return Number of bytes encoded, or negative error code
 */
int mms_encode_confirmed_response(const mms_confirmed_response_t* response,
                                  uint8_t* buffer, size_t buflen);

/**
 * @brief Encode MMS Confirmed Error
 *
 * @param error Confirmed error structure
 * @param buffer Output buffer
 * @param buflen Buffer length
 * @return Number of bytes encoded, or negative error code
 */
int mms_encode_confirmed_error(const mms_confirmed_error_t* error,
                               uint8_t* buffer, size_t buflen);

/* ============================================================================
 * Decoding Functions
 * ============================================================================ */

/**
 * @brief Decode MMS Initiate Request
 *
 * @param buffer Input buffer
 * @param buflen Buffer length
 * @param request Output initiate request structure
 * @return Number of bytes consumed, or negative error code
 */
int mms_decode_initiate_request(const uint8_t* buffer, size_t buflen,
                                mms_initiate_request_t* request);

/**
 * @brief Decode MMS Initiate Response
 *
 * @param buffer Input buffer
 * @param buflen Buffer length
 * @param response Output initiate response structure
 * @return Number of bytes consumed, or negative error code
 */
int mms_decode_initiate_response(const uint8_t* buffer, size_t buflen,
                                 mms_initiate_response_t* response);

/**
 * @brief Decode MMS Conclude Request
 *
 * @param buffer Input buffer
 * @param buflen Buffer length
 * @param request Output conclude request structure
 * @return Number of bytes consumed, or negative error code
 */
int mms_decode_conclude_request(const uint8_t* buffer, size_t buflen,
                                mms_conclude_request_t* request);

/**
 * @brief Decode MMS Conclude Response
 *
 * @param buffer Input buffer
 * @param buflen Buffer length
 * @param response Output conclude response structure
 * @return Number of bytes consumed, or negative error code
 */
int mms_decode_conclude_response(const uint8_t* buffer, size_t buflen,
                                 mms_conclude_response_t* response);

/**
 * @brief Decode MMS Confirmed Request
 *
 * @param buffer Input buffer
 * @param buflen Buffer length
 * @param request Output confirmed request structure
 * @return Number of bytes consumed, or negative error code
 */
int mms_decode_confirmed_request(const uint8_t* buffer, size_t buflen,
                                 mms_confirmed_request_t* request);

/**
 * @brief Decode MMS Confirmed Response
 *
 * @param buffer Input buffer
 * @param buflen Buffer length
 * @param response Output confirmed response structure
 * @return Number of bytes consumed, or negative error code
 */
int mms_decode_confirmed_response(const uint8_t* buffer, size_t buflen,
                                  mms_confirmed_response_t* response);

/**
 * @brief Decode MMS Confirmed Error
 *
 * @param buffer Input buffer
 * @param buflen Buffer length
 * @param error Output confirmed error structure
 * @return Number of bytes consumed, or negative error code
 */
int mms_decode_confirmed_error(const uint8_t* buffer, size_t buflen,
                               mms_confirmed_error_t* error);

/**
 * @brief Encode MMS InformationReport (unconfirmed service)
 *
 * @param report Information report structure
 * @param buffer Output buffer
 * @param buflen Buffer length
 * @return Number of bytes encoded, or negative error code
 */
int mms_encode_information_report(const mms_information_report_t* report,
                                  uint8_t* buffer, size_t buflen);

/**
 * @brief Decode MMS InformationReport
 *
 * @param buffer Input buffer
 * @param buflen Buffer length
 * @param report Output information report structure
 * @return Number of bytes consumed, or negative error code
 */
int mms_decode_information_report(const uint8_t* buffer, size_t buflen,
                                  mms_information_report_t* report);

/* ============================================================================
 * Phase 7: Control Service Encoding/Decoding Functions
 * ============================================================================ */

/**
 * @brief Encode MMS Select Request
 */
int mms_encode_select_request(const mms_select_request_t* request,
                              uint8_t* buffer, size_t buflen);

/**
 * @brief Decode MMS Select Request
 */
int mms_decode_select_request(const uint8_t* buffer, size_t buflen,
                              mms_select_request_t* request);

/**
 * @brief Encode MMS Select Response
 */
int mms_encode_select_response(const mms_select_response_t* response,
                               uint8_t* buffer, size_t buflen);

/**
 * @brief Decode MMS Select Response
 */
int mms_decode_select_response(const uint8_t* buffer, size_t buflen,
                               mms_select_response_t* response);

/**
 * @brief Encode MMS SelectWithValue Request
 */
int mms_encode_select_with_value_request(const mms_select_with_value_request_t* request,
                                         uint8_t* buffer, size_t buflen);

/**
 * @brief Decode MMS SelectWithValue Request
 */
int mms_decode_select_with_value_request(const uint8_t* buffer, size_t buflen,
                                         mms_select_with_value_request_t* request);

/**
 * @brief Encode MMS SelectWithValue Response
 */
int mms_encode_select_with_value_response(const mms_select_with_value_response_t* response,
                                          uint8_t* buffer, size_t buflen);

/**
 * @brief Decode MMS SelectWithValue Response
 */
int mms_decode_select_with_value_response(const uint8_t* buffer, size_t buflen,
                                          mms_select_with_value_response_t* response);

/**
 * @brief Encode MMS Operate Request
 */
int mms_encode_operate_request(const mms_operate_request_t* request,
                               uint8_t* buffer, size_t buflen);

/**
 * @brief Decode MMS Operate Request
 */
int mms_decode_operate_request(const uint8_t* buffer, size_t buflen,
                               mms_operate_request_t* request);

/**
 * @brief Encode MMS Operate Response
 */
int mms_encode_operate_response(const mms_operate_response_t* response,
                                uint8_t* buffer, size_t buflen);

/**
 * @brief Decode MMS Operate Response
 */
int mms_decode_operate_response(const uint8_t* buffer, size_t buflen,
                                mms_operate_response_t* response);

/**
 * @brief Encode MMS Cancel Request
 */
int mms_encode_cancel_request(const mms_cancel_request_t* request,
                              uint8_t* buffer, size_t buflen);

/**
 * @brief Decode MMS Cancel Request
 */
int mms_decode_cancel_request(const uint8_t* buffer, size_t buflen,
                              mms_cancel_request_t* request);

/**
 * @brief Encode MMS Cancel Response
 */
int mms_encode_cancel_response(const mms_cancel_response_t* response,
                               uint8_t* buffer, size_t buflen);

/**
 * @brief Decode MMS Cancel Response
 */
int mms_decode_cancel_response(const uint8_t* buffer, size_t buflen,
                               mms_cancel_response_t* response);

/**
 * @brief Encode MMS CommandTermination
 */
int mms_encode_command_termination(const mms_command_termination_t* termination,
                                   uint8_t* buffer, size_t buflen);

/**
 * @brief Decode MMS CommandTermination
 */
int mms_decode_command_termination(const uint8_t* buffer, size_t buflen,
                                   mms_command_termination_t* termination);

/* ============================================================================
 * Helper Functions
 * ============================================================================ */

/**
 * @brief Encode BER length field
 *
 * @param length Length value to encode
 * @param buffer Output buffer
 * @param buflen Buffer length
 * @return Number of bytes written, or negative error code
 */
int mms_encode_length(size_t length, uint8_t* buffer, size_t buflen);

/**
 * @brief Decode BER length field
 *
 * @param buffer Input buffer
 * @param buflen Buffer length
 * @param length Output length value
 * @return Number of bytes consumed, or negative error code
 */
int mms_decode_length(const uint8_t* buffer, size_t buflen, size_t* length);

/**
 * @brief Encode MMS value
 *
 * @param value MMS value to encode
 * @param buffer Output buffer
 * @param buflen Buffer length
 * @return Number of bytes written, or negative error code
 */
int mms_encode_value(const mms_value_t* value, uint8_t* buffer, size_t buflen);

/**
 * @brief Decode MMS value
 *
 * @param buffer Input buffer
 * @param buflen Buffer length
 * @param value Output MMS value
 * @return Number of bytes consumed, or negative error code
 */
int mms_decode_value(const uint8_t* buffer, size_t buflen, mms_value_t* value);

/**
 * @brief Get string description of error code
 *
 * @param error_code Error code
 * @return Human-readable error string
 */
const char* mms_error_string(int error_code);

#ifdef __cplusplus
}
#endif
