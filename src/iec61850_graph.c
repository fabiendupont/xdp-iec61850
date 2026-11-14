/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850 XDP Graph Registration
 *
 * Dynamically allocates PROG_ARRAY indices for IEC 61850 BPF nodes
 * (GOOSE/SV filter+parse, 90-5 UDP filter + R-GOOSE/R-SV parse)
 * and populates the iec61850_node_config map so BPF programs can
 * look up their own index at runtime.  Seeds the WP-5a rate-limit
 * family defaults, and exposes userspace setters for per-key and
 * per-family token-bucket limits.
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

/* ===== WP-5a: per-key token-bucket rate limiting ===== */

/* Wire format of struct iec61850_rl_bucket
 * (src/bpf/iec61850_maps.bpf.h) */
struct iec61850_rl_bucket_value {
    uint64_t rate;
    uint64_t burst;
    uint64_t tokens;
    uint64_t last_ns;
};

/* Wire format of struct iec61850_rl_config
 * (src/bpf/iec61850_maps.bpf.h) */
struct iec61850_rl_config_value {
    uint64_t rate;
    uint64_t burst;
};

/* Seed the family-default rate-limit config with the documented
 * defaults (WP-5a), so storm protection is active out of the box.
 * Retunable via iec61850_graph_set_rate_default(). */
static int populate_rl_defaults(struct xgl_graph *g)
{
    struct iec61850_rl_config_value config;
    int fd;
    int i;

    fd = xgl_graph_get_map_fd(g, "iec61850_rl_config");
    if (fd < 0) {
        return fd;
    }

    config.rate = IEC61850_RL_DEFAULT_RATE_BYTES;
    config.burst = IEC61850_RL_DEFAULT_BURST_BYTES;

    for (i = 0; i < IEC61850_RL_FAMILY_COUNT; i++) {
        __u32 fam = (__u32)i;

        if (bpf_map_update_elem(fd, &fam, &config, BPF_ANY) != 0) {
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

    /* Root dispatcher at PROG_ARRAY index 0 (attach() attaches the
     * program at index 0). Replaces the shipped xgl_dispatch, which
     * self-loops when inserted at index 0 (it tail-calls slot 0).
     * node_dispatch allocates the XGL metadata our nodes require and
     * tail-calls the filter node registered for the packet's
     * EtherType via the iec61850_dispatch map. */
    (void)snprintf(path, sizeof(path), "%s/node_dispatch.bpf.o", bpf_dir);
    ret = xgl_graph_add_node(g, 0, path, "node_dispatch");
    if (ret != 0) {
        return ret;
    }

    /* Populate config map so BPF programs know their PROG_ARRAY indices */
    ret = populate_config_map(g, indices);
    if (ret != 0) {
        return ret;
    }

    /* The root dispatcher's own index (role DISPATCH -> 0) */
    {
        int config_fd = xgl_graph_get_map_fd(g, "iec61850_node_config");
        __u32 role = IEC61850_ROLE_DISPATCH;
        __u32 idx = 0U;
        if (config_fd < 0) {
            return config_fd;
        }
        if (bpf_map_update_elem(config_fd, &role, &idx, BPF_ANY) != 0) {
            return -errno;
        }
    }

    /* Seed the rate-limit family defaults (WP-5a) */
    ret = populate_rl_defaults(g);
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

/* ===== WP-5a: per-key token-bucket rate limiting — userspace setters ===== */

/* Bucket-map name per rate-limit family (BPF-side map names) */
static const char *const rl_map_names[IEC61850_RL_FAMILY_COUNT] = {
    "goose_rl",
    "sv_rl",
    "r_rl",
};

static int rl_family_valid(int family)
{
    return (family >= 0) && (family < IEC61850_RL_FAMILY_COUNT);
}

/* Validate limits against the BPF refill-math bounds documented in
 * iec61850_graph.h: rate <= 2^31-1 B/s keeps elapsed * rate below
 * 2^63 (elapsed is capped at ~4.3 s in BPF), burst is sanity-bounded
 * and must be nonzero whenever it can ever be consumed. */
static int rl_validate_limits(const struct iec61850_rl_limits *limits)
{
    if (limits->rate > IEC61850_RL_MAX_RATE_BYTES) {
        return -EINVAL;
    }
    if (limits->burst > IEC61850_RL_MAX_BURST_BYTES) {
        return -EINVAL;
    }
    if ((limits->rate > 0U) && (limits->burst == 0U)) {
        return -EINVAL;
    }
    return 0;
}

int iec61850_graph_set_rate_limit(struct xgl_graph *g, int family,
                                  uint16_t key,
                                  const struct iec61850_rl_limits *limits)
{
    struct iec61850_rl_bucket_value bucket;
    int fd;
    int ret;

    if ((g == NULL) || (limits == NULL) || !rl_family_valid(family)) {
        return -EINVAL;
    }
    ret = rl_validate_limits(limits);
    if (ret != 0) {
        return ret;
    }

    fd = iec61850_graph_get_filter_map_fd(g, rl_map_names[family]);
    if (fd < 0) {
        return fd;
    }

    /* Bucket starts full so a legitimate burst right after the call
     * is never blocked; last_ns = 0 anchors the clock at the first
     * packet (the refill of the boot-time "elapsed" is capped at the
     * empty bucket headroom, i.e. zero). */
    bucket.rate = limits->rate;
    bucket.burst = limits->burst;
    bucket.tokens = limits->burst;
    bucket.last_ns = 0U;

    if (bpf_map_update_elem(fd, &key, &bucket, BPF_ANY) != 0) {
        return -errno;
    }
    return 0;
}

int iec61850_graph_set_rate_default(struct xgl_graph *g, int family,
                                    const struct iec61850_rl_limits *limits)
{
    struct iec61850_rl_config_value config;
    __u32 fam;
    int fd;
    int ret;

    if ((g == NULL) || (limits == NULL) || !rl_family_valid(family)) {
        return -EINVAL;
    }
    ret = rl_validate_limits(limits);
    if (ret != 0) {
        return ret;
    }

    fd = iec61850_graph_get_filter_map_fd(g, "iec61850_rl_config");
    if (fd < 0) {
        return fd;
    }

    fam = (__u32)family;
    config.rate = limits->rate;
    config.burst = limits->burst;

    if (bpf_map_update_elem(fd, &fam, &config, BPF_ANY) != 0) {
        return -errno;
    }
    return 0;
}
