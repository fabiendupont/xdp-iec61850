/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850 BPF Maps
 *
 * Application-specific map definitions for GOOSE/SV XDP filter nodes.
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

/* GOOSE state tracking: APPID -> {stNum, sqNum} for change detection */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u16);
    __type(value, struct goose_state);
} goose_state_map SEC(".maps");

/* Logical roles (not PROG_ARRAY indices — indices are dynamic) */
#define IEC61850_ROLE_GOOSE_FILTER   0
#define IEC61850_ROLE_GOOSE_PARSE    1
#define IEC61850_ROLE_SV_FILTER      2
#define IEC61850_ROLE_SV_PARSE       3
#define IEC61850_ROLE_COUNT          4

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
