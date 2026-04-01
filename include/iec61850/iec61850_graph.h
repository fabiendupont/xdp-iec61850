/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850 XDP Graph Registration
 *
 * Registers IEC 61850 BPF nodes (GOOSE filter/parse, SV filter/parse)
 * into an xgl_graph at dynamically allocated PROG_ARRAY indices.
 */

#ifndef IEC61850_GRAPH_H
#define IEC61850_GRAPH_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct xgl_graph;

/* Logical roles matching BPF-side IEC61850_ROLE_* constants */
#define IEC61850_ROLE_GOOSE_FILTER  0
#define IEC61850_ROLE_GOOSE_PARSE   1
#define IEC61850_ROLE_SV_FILTER     2
#define IEC61850_ROLE_SV_PARSE      3
#define IEC61850_ROLE_COUNT         4

/**
 * Dynamically allocated PROG_ARRAY indices for IEC 61850 nodes.
 * Populated by iec61850_graph_register().
 */
struct iec61850_graph_indices {
    int goose_filter;
    int goose_parse;
    int sv_filter;
    int sv_parse;
};

/**
 * Register IEC 61850 BPF nodes into the graph.
 *
 * Dynamically allocates PROG_ARRAY indices via xgl_graph_alloc_index()
 * and loads BPF object files from bpf_dir. Populates the
 * iec61850_node_config map so BPF programs know their own indices.
 *
 * @param g        Graph instance
 * @param bpf_dir  Directory containing .bpf.o files
 * @param out      Output: allocated indices (may be NULL if not needed)
 * @return 0 on success, negative errno on failure
 */
int iec61850_graph_register(struct xgl_graph *g, const char *bpf_dir,
                             struct iec61850_graph_indices *out);

/**
 * Populate EtherType dispatch map entries.
 *
 * Configures the dispatch map to route:
 *   - EtherType 0x88B8 (GOOSE) → GOOSE filter node
 *   - EtherType 0x88BA (SV) → SV filter node
 *
 * @param dispatch_map_fd  BPF map fd for EtherType dispatch (BPF_MAP_TYPE_HASH)
 * @param indices          Allocated indices from iec61850_graph_register()
 * @return 0 on success, negative errno on failure
 */
int iec61850_graph_setup_dispatch(int dispatch_map_fd,
                                   const struct iec61850_graph_indices *indices);

/**
 * Get the BPF map fd for a named IEC 61850 filter map.
 *
 * Retrieves pinned map fd by name from the graph. Useful for
 * populating GOOSE/SV subscription filters at runtime:
 *   - "goose_filter" → APPID-based GOOSE accept/drop
 *   - "sv_filter"    → APPID-based SV accept/drop
 *
 * @param g         Graph instance (must have IEC 61850 nodes loaded)
 * @param map_name  Map name (e.g. "goose_filter", "sv_filter")
 * @return map fd on success, negative errno on failure
 */
int iec61850_graph_get_filter_map_fd(struct xgl_graph *g,
                                      const char *map_name);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_GRAPH_H */
