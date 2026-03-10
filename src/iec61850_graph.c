/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850 XDP Graph Registration
 */

#include "iec61850_graph.h"
#include <xgl/xgl_graph.h>
#include <bpf/bpf.h>

#include <string.h>
#include <stdio.h>
#include <errno.h>

/* EtherType constants */
#define ETHERTYPE_GOOSE  0x88B8U
#define ETHERTYPE_SV     0x88BAU

int iec61850_graph_register(struct xgl_graph *g, const char *bpf_dir)
{
    char path[512];
    int ret;

    if (g == NULL || bpf_dir == NULL) {
        return -EINVAL;
    }

    (void)snprintf(path, sizeof(path), "%s/node_goose_filter.bpf.o", bpf_dir);
    ret = xgl_graph_add_node(g, IEC61850_NODE_GOOSE_FILTER, path,
                              "node_goose_filter");
    if (ret != 0) { return ret; }

    (void)snprintf(path, sizeof(path), "%s/node_goose_parse.bpf.o", bpf_dir);
    ret = xgl_graph_add_node(g, IEC61850_NODE_GOOSE_PARSE, path,
                              "node_goose_parse");
    if (ret != 0) { return ret; }

    (void)snprintf(path, sizeof(path), "%s/node_sv_filter.bpf.o", bpf_dir);
    ret = xgl_graph_add_node(g, IEC61850_NODE_SV_FILTER, path,
                              "node_sv_filter");
    if (ret != 0) { return ret; }

    (void)snprintf(path, sizeof(path), "%s/node_sv_parse.bpf.o", bpf_dir);
    ret = xgl_graph_add_node(g, IEC61850_NODE_SV_PARSE, path,
                              "node_sv_parse");
    if (ret != 0) { return ret; }

    return 0;
}

int iec61850_graph_setup_dispatch(int dispatch_map_fd)
{
    int ret;

    if (dispatch_map_fd < 0) {
        return -EINVAL;
    }

    /* Map EtherType 0x88B8 → GOOSE filter node */
    uint16_t goose_et = (uint16_t)ETHERTYPE_GOOSE;
    uint32_t goose_idx = IEC61850_NODE_GOOSE_FILTER;
    ret = bpf_map_update_elem(dispatch_map_fd, &goose_et, &goose_idx, BPF_ANY);
    if (ret != 0) {
        return -errno;
    }

    /* Map EtherType 0x88BA → SV filter node */
    uint16_t sv_et = (uint16_t)ETHERTYPE_SV;
    uint32_t sv_idx = IEC61850_NODE_SV_FILTER;
    ret = bpf_map_update_elem(dispatch_map_fd, &sv_et, &sv_idx, BPF_ANY);
    if (ret != 0) {
        return -errno;
    }

    return 0;
}
