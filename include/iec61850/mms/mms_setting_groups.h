/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * mms_setting_groups.h — Setting Group Control Block (SGCB).
 *
 * Implements IEC 61850-7-2 §14 (setting groups) over the MMS
 * mapping of 61850-8-1 §7.4: SGCB attributes and setting-group
 * values are exposed as MMS named variables with functional
 * constraints SG and SE, intercepted by a read/write bridge before
 * the ordinary data store (the same pre-commit pattern as the RCB
 * bridge in mms_report.c).
 *
 * MMS variable layout (per LD) — the IEC 61850-8-1 mapping
 * (wire-verified against the libiec61850 reference server):
 *
 *   LD/LLN0$SP$SGCB$NumOfSG  (r)   number of setting groups
 *   LD/LLN0$SP$SGCB$ActSG    (rw)  SelectActiveSG: 1..NumOfSG
 *   LD/LLN0$SP$SGCB$EditSG   (rw)  SelectEditSG: 0 (release) or 1..NumOfSG
 *   LD/LLN0$SP$SGCB$ResvTms  (r)   reservation time in seconds (0 = free)
 *   LD/<LN>$SE$<path>        (rw)  setting-group values: writes go to
 *                                 the SELECTED EDIT group's copy; reads
 *                                 serve the edit group while an edit
 *                                 session is selected and are invisible
 *                                 otherwise (SE is the edit-session view)
 *   LD/<LN>$SG$<path>        (r)   read-only view of the ACTIVE group
 *
 * Semantics:
 *   - SelectActiveSG copies the selected group's values into the
 *     live data model (via iec61850_da_set_value, so change
 *     callbacks and report dchg evaluation fire) and invokes the
 *     activation callback.
 *   - SelectEditSG takes a single-owner reservation (ResvTms
 *     seconds, tracked by the owner association pointer); a
 *     different client's write is rejected. Release by writing 0,
 *     by client disconnect, or by ResvTms expiry
 *     (iec61850_sg_tick).
 *   - Writes to $SE$ variables are diverted to the edit group's
 *     copy — the live model is only touched on activation.
 *
 * All groups are initialized from the model's initial values
 * (SCL SettingControl per-group initial values are a follow-up).
 */

#ifndef IEC61850_MMS_SETTING_GROUPS_H
#define IEC61850_MMS_SETTING_GROUPS_H

#include <stdint.h>
#include <stddef.h>

#include "asn1/mms_ber.h"
#include "ied/ied_data_model.h"

#define IEC61850_SG_MAX_GROUPS 8
#define IEC61850_SG_MAX_SE_ENTRIES 128
#define IEC61850_SG_MAX_ITEM_LEN 128

typedef struct iec61850_sg_manager iec61850_sg_manager_t;

typedef void (*iec61850_sg_activated_cb_t)(void *user_data,
                                           uint8_t act_sg,
                                           uint8_t prev_sg);

struct iec61850_sg_manager {
    iec61850_ied_model_t *model;      /* shared, not owned */
    uint8_t num_of_sg;                /* 1..IEC61850_SG_MAX_GROUPS */
    uint8_t act_sg;                   /* 1-based active group */
    uint8_t edit_sg;                  /* 0 = none selected */
    uint32_t resv_tms_s;              /* reservation timeout (s) */
    uint64_t resv_deadline_ms;        /* 0 = no reservation running */
    void *edit_owner;                 /* owning association */

    struct {
        char ld[IEC61850_MAX_NAME_LEN];
        char item[IEC61850_SG_MAX_ITEM_LEN];   /* "<LN>$SE$<path>" */
        iec61850_data_attribute_t *live;       /* model attr (FC=SE) */
        mms_value_t groups[IEC61850_SG_MAX_GROUPS];
    } entries[IEC61850_SG_MAX_SE_ENTRIES];
    size_t entry_count;

    iec61850_sg_activated_cb_t activated_cb;
    void *activated_user;
};

/**
 * Create and initialize a setting-group manager for the model.
 * Walks the model, registering every DataAttribute with FC=SE and
 * cloning its initial value into every group.
 *
 * @param num_of_sg  number of setting groups (1..MAX)
 * @param act_sg     initial active group (1-based)
 * @param resv_tms_s EditSG reservation timeout in seconds
 */
int iec61850_sg_manager_init(iec61850_sg_manager_t **mgr,
                             iec61850_ied_model_t *model,
                             uint8_t num_of_sg, uint8_t act_sg,
                             uint32_t resv_tms_s);

void iec61850_sg_manager_destroy(iec61850_sg_manager_t *mgr);

void iec61850_sg_set_activation_callback(iec61850_sg_manager_t *mgr,
                                         iec61850_sg_activated_cb_t cb,
                                         void *user_data);

/**
 * MMS write bridge (pre-commit, before the data store).
 *
 * Returns:
 *    0        the variable was an SG/SE variable, committed by the
 *             bridge (store write must be skipped)
 *   -ENOENT   not an SG/SE variable (ordinary write proceeds)
 *   -EINVAL   malformed value or out-of-range group number
 *   -EPERM    edit reservation held by another association
 *   -EAGAIN   edit reservation expired / not selected
 */
int iec61850_sg_bridge_write(iec61850_sg_manager_t *mgr,
                             const char *domain, const char *item,
                             const mms_value_t *value,
                             void *association);

/**
 * MMS read bridge (before the data store).
 *
 * Returns 0 with *value filled when the variable is served by the
 * SGCB (SGCB attributes, SE values), -ENOENT for ordinary
 * variables.
 */
int iec61850_sg_bridge_read(iec61850_sg_manager_t *mgr,
                            const char *domain, const char *item,
                            mms_value_t *value);

/**
 * Copy group @sg's values into the live data model. Called by the
 * bridge on SelectActiveSG; also usable directly (e.g. startup).
 */
int iec61850_sg_activate(iec61850_sg_manager_t *mgr, uint8_t sg);

/**
 * Reservation maintenance: releases the edit reservation when
 * ResvTms has expired. Call periodically (seconds cadence).
 */
void iec61850_sg_tick(iec61850_sg_manager_t *mgr, uint64_t now_ms);

/** Release the edit reservation if held by @association (call on
 * client disconnect). */
void iec61850_sg_release_owner(iec61850_sg_manager_t *mgr,
                               void *association);

/* Introspection for tests and diagnostics. */
uint8_t iec61850_sg_get_num_of_sg(const iec61850_sg_manager_t *mgr);
uint8_t iec61850_sg_get_active(const iec61850_sg_manager_t *mgr);
uint8_t iec61850_sg_get_edit(const iec61850_sg_manager_t *mgr);

#endif /* IEC61850_MMS_SETTING_GROUPS_H */
