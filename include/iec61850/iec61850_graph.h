/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IEC 61850 XDP Graph Registration
 *
 * Registers IEC 61850 BPF nodes (GOOSE filter/parse, SV filter/parse)
 * into an xgl_graph at PROG_ARRAY indices 14-17.
 */

#ifndef IEC61850_GRAPH_H
#define IEC61850_GRAPH_H

#ifdef __cplusplus
extern "C" {
#endif

struct xgl_graph;

/* PROG_ARRAY indices for IEC 61850 nodes */
#define IEC61850_NODE_GOOSE_FILTER  14
#define IEC61850_NODE_GOOSE_PARSE   15
#define IEC61850_NODE_SV_FILTER     16
#define IEC61850_NODE_SV_PARSE      17

/**
 * Register IEC 61850 BPF nodes into the graph.
 *
 * Loads BPF object files from bpf_dir and inserts them into
 * PROG_ARRAY at indices 14-17.
 *
 * @param g        Graph instance
 * @param bpf_dir  Directory containing .bpf.o files
 * @return 0 on success, negative errno on failure
 */
int iec61850_graph_register(struct xgl_graph *g, const char *bpf_dir);

/**
 * Populate EtherType dispatch map entries.
 *
 * Configures the dispatch map to route:
 *   - EtherType 0x88B8 (GOOSE) → node index 14
 *   - EtherType 0x88BA (SV) → node index 16
 *
 * @param dispatch_map_fd  BPF map fd for EtherType dispatch (BPF_MAP_TYPE_HASH)
 * @return 0 on success, negative errno on failure
 */
int iec61850_graph_setup_dispatch(int dispatch_map_fd);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_GRAPH_H */
