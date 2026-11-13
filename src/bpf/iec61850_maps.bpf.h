/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850 BPF Maps
 *
 * Application-specific map definitions for GOOSE/SV XDP filter nodes
 * and routable-profile (IEC TR 61850-90-5) UDP nodes.
 * Graph infrastructure maps (egl_prog_array, egl_node_stats, xgl_xsk_map,
 * xgl_tx_ports) are provided by xgl_common.bpf.h.
 */

#ifndef IEC61850_MAPS_BPF_H
#define IEC61850_MAPS_BPF_H

#include <xgl/bpf/xgl_common.bpf.h>

/* GOOSE state tracking for change detection */
struct goose_state {
    __u32 st_num;
    __u32 sq_num;
};

/* GOOSE subscription filter: APPID -> action
 * value: 0 = drop, 1 = pass to AF_XDP */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);       /* APPID (network byte order) */
    __type(value, __u8);      /* action: 0=drop, 1=accept */
} goose_filter SEC(".maps");

/* SV subscription filter: APPID -> action */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);
    __type(value, __u8);
} sv_filter SEC(".maps");

/* Routable-profile (90-5) UDP subscription filter: UDP destination
 * port -> action
 * key:   UDP destination port (network byte order)
 * value: 0 = drop, 1 = pass to AF_XDP */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);       /* UDP dport (network byte order) */
    __type(value, __u32);     /* action: 0=drop, 1=accept */
} r_filter SEC(".maps");

/* GOOSE state tracking: APPID -> {stNum, sqNum} for change detection */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);
    __type(value, struct goose_state);
} goose_state_map SEC(".maps");

/* R-GOOSE replay state: session identifier -> last-accepted 90-5
 * security TimeOfDay for anti-replay checks.
 * key:   90-5 session identifier (network byte order)
 * value: last-accepted security TimeOfDay (host byte order) */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);       /* session identifier (network byte order) */
    __type(value, __u32);     /* last-accepted time-of-day */
} rgoose_state_map SEC(".maps");

/* R-SV replay state: same shape as rgoose_state_map */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);       /* session identifier (network byte order) */
    __type(value, __u32);     /* last-accepted time-of-day */
} rsv_state_map SEC(".maps");

/* =====================================================================
 * WP-4A-RECONCILE: IEC TR 61850-90-5 session-header wire offsets
 * =====================================================================
 *
 * ALL 90-5 session-header wire-format constants live in this single
 * block.  They describe the SPDU carried in the UDP payload and are
 * derived from the publicly documented 90-5 R-session header layout:
 *
 *   octet 0..1   SPDU length          (uint16, network byte order)
 *   octet 2..3   Session identifier   (uint16, network byte order)
 *   octet 4      SPDU type            (uint8)
 *   octet 5..8   Security TimeOfDay   (uint32, network byte order)
 *
 * WP-4a is deriving the exact wire layout on a parallel branch; its
 * offsets are NOT yet reconciled with the values below.  At merge
 * time the orchestrator must reconcile this block (and only this
 * block) against WP-4a's report — every offset assumption used by
 * node_rgoose_parse / node_rsv_parse is expressed here.
 *
 * Assumptions pending reconciliation:
 *   - offsets are relative to the start of the UDP payload (SPDU)
 *   - TimeOfDay is a 32-bit value in units of milliseconds
 *   - SPDU length counts from octet 0 of the SPDU (includes itself)
 */
#define IEC61850_905_SPDU_LEN_OFFSET    0  /* uint16: SPDU total length */
#define IEC61850_905_SESSION_ID_OFFSET  2  /* uint16: session identifier */
#define IEC61850_905_SPDU_TYPE_OFFSET   4  /* uint8:  SPDU type */
#define IEC61850_905_TOD_OFFSET         5  /* uint32: security TimeOfDay */
#define IEC61850_905_SESSION_HDR_LEN    9  /* min SPDU bytes for replay check */

/* 90-5 anti-replay acceptance window, in TimeOfDay units.
 * SPDUs whose TimeOfDay is older than (last accepted - window) are
 * rejected as replays; newer or in-window SPDUs are accepted and the
 * window slides forward.  Conservative 200 ms pending WP-4a
 * reconciliation of the documented window. */
#define IEC61850_905_REPLAY_WINDOW_TOD  200

/* Logical roles (not PROG_ARRAY indices — indices are dynamic) */
#define IEC61850_ROLE_GOOSE_FILTER   0
#define IEC61850_ROLE_GOOSE_PARSE    1
#define IEC61850_ROLE_SV_FILTER      2
#define IEC61850_ROLE_SV_PARSE       3
#define IEC61850_ROLE_UDP_FILTER     4  /* WP-S4: 90-5 IPv4/UDP dispatch */
#define IEC61850_ROLE_RGOOSE_PARSE   5  /* WP-S4: 90-5 R-GOOSE parse */
#define IEC61850_ROLE_RSV_PARSE      6  /* WP-S4: 90-5 R-SV parse */
#define IEC61850_ROLE_COUNT          7

/* Config map: role → PROG_ARRAY index (populated by userspace) */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, __u32);
} iec61850_node_config SEC(".maps");

/* EtherType constants */
#define ETH_P_GOOSE         0x88B8
#define ETH_P_SV            0x88BA
#define ETH_P_8021Q         0x8100

/* GOOSE PDU header (after EtherType) */
struct goose_pdu_header {
    __u16 appid;
    __u16 length;
    __u16 reserved1;
    __u16 reserved2;
} __attribute__((packed));

/* SV PDU header (after EtherType) */
struct sv_pdu_header {
    __u16 appid;
    __u16 length;
    __u16 reserved1;
    __u16 reserved2;
} __attribute__((packed));

#endif /* IEC61850_MAPS_BPF_H */
