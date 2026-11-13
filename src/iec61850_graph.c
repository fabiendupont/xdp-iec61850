/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850 XDP Graph Registration
 *
 * Dynamically allocates PROG_ARRAY indices for IEC 61850 BPF nodes
 * (GOOSE/SV filter+parse, 90-5 UDP filter + R-GOOSE/R-SV parse)
 * and populates the iec61850_node_config map so BPF programs can
 * look up their own index at runtime.
 */

#include "iec61850_graph.h"
#include <xgl/xgl_graph.h>
#include <bpf/bpf.h>

#include <string.h>
#include <stdio.h>
#include <errno.h>

/* xdp-graph-lib does not expose xgl_graph_alloc_index(); use a local
 * counter starting at 20 to stay above reserved indices (conntrack=13,
 * snat=14, ndp=15) and xdp-hsr-prp. */
static int next_alloc_index = 20;

static int xgl_graph_alloc_index(struct xgl_graph *g)
{
    (void)g;
    return next_alloc_index++;
}

/* EtherType constants */
#define ETHERTYPE_GOOSE  0x88B8U
#define ETHERTYPE_SV     0x88BAU
#define ETHERTYPE_IP     0x0800U

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
    { "node_udp_filter.bpf.o",   "node_udp_filter",   IEC61850_ROLE_UDP_FILTER   },
    { "node_rgoose_parse.bpf.o", "node_rgoose_parse", IEC61850_ROLE_RGOOSE_PARSE },
    { "node_rsv_parse.bpf.o",    "node_rsv_parse",    IEC61850_ROLE_RSV_PARSE    },
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

    if ((g == NULL) || (bpf_dir == NULL)) {
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
        out->udp_filter   = indices[IEC61850_ROLE_UDP_FILTER];
        out->rgoose_parse = indices[IEC61850_ROLE_RGOOSE_PARSE];
        out->rsv_parse    = indices[IEC61850_ROLE_RSV_PARSE];
    }

    return 0;
}

/* Roles dispatched by EtherType (must match iec61850_graph_dispatch_ethtype) */
static const int dispatch_roles[] = {
    IEC61850_ROLE_GOOSE_FILTER,
    IEC61850_ROLE_SV_FILTER,
    IEC61850_ROLE_UDP_FILTER,
};

#define NUM_DISPATCH_ROLES (int)(sizeof(dispatch_roles) / sizeof(dispatch_roles[0]))

int iec61850_graph_dispatch_ethtype(int role)
{
    switch (role) {
    case IEC61850_ROLE_GOOSE_FILTER:
        return (int)ETHERTYPE_GOOSE;
    case IEC61850_ROLE_SV_FILTER:
        return (int)ETHERTYPE_SV;
    case IEC61850_ROLE_UDP_FILTER:
        return (int)ETHERTYPE_IP;
    default:
        return -EINVAL;
    }
}

/* PROG_ARRAY index for a role within an allocated indices struct */
static int indices_role(const struct iec61850_graph_indices *indices, int role)
{
    switch (role) {
    case IEC61850_ROLE_GOOSE_FILTER: return indices->goose_filter;
    case IEC61850_ROLE_SV_FILTER:    return indices->sv_filter;
    case IEC61850_ROLE_UDP_FILTER:   return indices->udp_filter;
    default:                         return -EINVAL;
    }
}

int iec61850_graph_setup_dispatch(int dispatch_map_fd,
                                   const struct iec61850_graph_indices *indices)
{
    if ((dispatch_map_fd < 0) || (indices == NULL)) {
        return -EINVAL;
    }

    /* Map each dispatched EtherType → its filter node:
     *   0x88B8 (GOOSE) → GOOSE filter
     *   0x88BA (SV)    → SV filter
     *   0x0800 (IPv4)  → UDP filter (90-5 dispatch) */
    for (int i = 0; i < NUM_DISPATCH_ROLES; i++) {
        int role = dispatch_roles[i];
        int et = iec61850_graph_dispatch_ethtype(role);
        int node_idx = indices_role(indices, role);

        if ((et < 0) || (node_idx < 0)) {
            return -EINVAL;
        }

        uint16_t key = (uint16_t)et;
        uint32_t val = (uint32_t)node_idx;
        int ret = bpf_map_update_elem(dispatch_map_fd, &key, &val, BPF_ANY);
        if (ret != 0) {
            return -errno;
        }
    }

    return 0;
}

int iec61850_graph_get_filter_map_fd(struct xgl_graph *g,
                                      const char *map_name)
{
    if ((g == NULL) || (map_name == NULL)) {
        return -EINVAL;
    }

    return xgl_graph_get_map_fd(g, map_name);
}
