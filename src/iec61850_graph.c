/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850 XDP Graph Registration
 *
 * Dynamically allocates PROG_ARRAY indices for IEC 61850 BPF nodes
 * and populates the iec61850_node_config map so BPF programs can
 * look up their own index at runtime.
 */

#include "iec61850_graph.h"
#include <xgl/xgl_graph.h>
#include <bpf/bpf.h>

#include <string.h>
#include <stdio.h>
#include <errno.h>

/*
 * Local index allocator — xdp-graph-lib does not yet expose
 * xgl_graph_alloc_index().  Start at 20 to stay above groutx
 * reserved range (conntrack=13, snat=14, ndp=15) and xdp-hsr-prp.
 */
static int next_alloc_index = 20;

static int xgl_graph_alloc_index(struct xgl_graph *g)
{
    (void)g;
    return next_alloc_index++;
}

/* EtherType constants */
#define ETHERTYPE_GOOSE  0x88B8U
#define ETHERTYPE_SV     0x88BAU

struct node_def {
    const char *obj_file;
    const char *prog_name;
    int role;
};

static const struct node_def nodes[] = {
    { "node_goose_filter.bpf.o", "node_goose_filter", IEC61850_ROLE_GOOSE_FILTER },
    { "node_goose_parse.bpf.o",  "node_goose_parse",  IEC61850_ROLE_GOOSE_PARSE  },
    { "node_sv_filter.bpf.o",    "node_sv_filter",    IEC61850_ROLE_SV_FILTER    },
    { "node_sv_parse.bpf.o",     "node_sv_parse",     IEC61850_ROLE_SV_PARSE     },
};

#define NUM_NODES (int)(sizeof(nodes) / sizeof(nodes[0]))

static int populate_config_map(struct xgl_graph *g, const int *indices)
{
    int config_fd;

    config_fd = xgl_graph_get_map_fd(g, "iec61850_node_config");
    if (config_fd < 0) {
        return config_fd;
    }

    for (int i = 0; i < NUM_NODES; i++) {
        __u32 role = (__u32)nodes[i].role;
        __u32 idx = (__u32)indices[i];
        int ret = bpf_map_update_elem(config_fd, &role, &idx, BPF_ANY);
        if (ret != 0) {
            return -errno;
        }
    }

    return 0;
}

int iec61850_graph_register(struct xgl_graph *g, const char *bpf_dir,
                             struct iec61850_graph_indices *out)
{
    char path[512];
    int indices[NUM_NODES];
    int ret;

    if (g == NULL || bpf_dir == NULL) {
        return -EINVAL;
    }

    /* Allocate dynamic indices and load nodes */
    for (int i = 0; i < NUM_NODES; i++) {
        indices[i] = xgl_graph_alloc_index(g);
        if (indices[i] < 0) {
            return indices[i];
        }

        (void)snprintf(path, sizeof(path), "%s/%s", bpf_dir, nodes[i].obj_file);
        ret = xgl_graph_add_node(g, indices[i], path, nodes[i].prog_name);
        if (ret != 0) {
            return ret;
        }
    }

    /* Populate config map so BPF programs know their PROG_ARRAY indices */
    ret = populate_config_map(g, indices);
    if (ret != 0) {
        return ret;
    }

    /* Return allocated indices to caller */
    if (out != NULL) {
        out->goose_filter = indices[IEC61850_ROLE_GOOSE_FILTER];
        out->goose_parse  = indices[IEC61850_ROLE_GOOSE_PARSE];
        out->sv_filter    = indices[IEC61850_ROLE_SV_FILTER];
        out->sv_parse     = indices[IEC61850_ROLE_SV_PARSE];
    }

    return 0;
}

int iec61850_graph_setup_dispatch(int dispatch_map_fd,
                                   const struct iec61850_graph_indices *indices)
{
    int ret;

    if (dispatch_map_fd < 0 || indices == NULL) {
        return -EINVAL;
    }

    /* Map EtherType 0x88B8 → GOOSE filter node */
    uint16_t goose_et = (uint16_t)ETHERTYPE_GOOSE;
    uint32_t goose_idx = (uint32_t)indices->goose_filter;
    ret = bpf_map_update_elem(dispatch_map_fd, &goose_et, &goose_idx, BPF_ANY);
    if (ret != 0) {
        return -errno;
    }

    /* Map EtherType 0x88BA → SV filter node */
    uint16_t sv_et = (uint16_t)ETHERTYPE_SV;
    uint32_t sv_idx = (uint32_t)indices->sv_filter;
    ret = bpf_map_update_elem(dispatch_map_fd, &sv_et, &sv_idx, BPF_ANY);
    if (ret != 0) {
        return -errno;
    }

    return 0;
}

int iec61850_graph_get_filter_map_fd(struct xgl_graph *g,
                                      const char *map_name)
{
    if (g == NULL || map_name == NULL) {
        return -EINVAL;
    }

    return xgl_graph_get_map_fd(g, map_name);
}
