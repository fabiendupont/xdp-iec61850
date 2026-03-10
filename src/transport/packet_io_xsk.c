/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Packet I/O via AF_XDP Zero-Copy (xgl_xsk_*)
 *
 * Delegates to xdp-graph-lib's AF_XDP socket abstraction for
 * zero-copy packet I/O. The xgl_xsk_create() call prefers
 * XDP_ZEROCOPY mode and falls back to XDP_COPY automatically.
 */

#include "transport/packet_io.h"
#include <xgl/xgl_xsk.h>
#include <xgl/xgl_graph.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define XSK_FRAME_SIZE  4096U
#define XSK_NUM_FRAMES  4096U

struct packet_io_xsk_priv {
    struct xgl_xsk *xsk;
    struct xgl_graph *graph;  /* if non-NULL, use xgl_graph_create_xsk */
};

static int xsk_open(struct packet_io *io, const char *ifname, int queue_id)
{
    struct packet_io_xsk_priv *priv = io->priv;

    if (priv->xsk != NULL) {
        return -EALREADY;
    }

    if (priv->graph != NULL) {
        /* Use graph-aware create: inserts XSK fd into XSKMAP */
        priv->xsk = xgl_graph_create_xsk(priv->graph, ifname, queue_id);
    } else {
        priv->xsk = xgl_xsk_create(ifname, queue_id, XSK_FRAME_SIZE,
                                     XSK_NUM_FRAMES);
    }
    if (priv->xsk == NULL) {
        return -errno;
    }

    return 0;
}

static int xsk_recv(struct packet_io *io, void **pkt_data, uint32_t *pkt_len)
{
    struct packet_io_xsk_priv *priv = io->priv;

    if (priv->xsk == NULL) {
        return -ENODEV;
    }

    return xgl_xsk_recv(priv->xsk, pkt_data, pkt_len);
}

static int xsk_send(struct packet_io *io, const void *pkt_data, uint32_t pkt_len)
{
    struct packet_io_xsk_priv *priv = io->priv;

    if (priv->xsk == NULL) {
        return -ENODEV;
    }

    void *tx_buf = xgl_xsk_send_alloc(priv->xsk, pkt_len);
    if (tx_buf == NULL) {
        return -ENOMEM;
    }

    (void)memcpy(tx_buf, pkt_data, pkt_len);

    return xgl_xsk_send_complete(priv->xsk);
}

static void xsk_release(struct packet_io *io)
{
    struct packet_io_xsk_priv *priv = io->priv;

    if (priv->xsk != NULL) {
        xgl_xsk_recv_release(priv->xsk);
    }
}

static void xsk_close(struct packet_io *io)
{
    struct packet_io_xsk_priv *priv = io->priv;

    if (priv->xsk != NULL) {
        xgl_xsk_destroy(priv->xsk);
        priv->xsk = NULL;
    }
}

static const struct packet_io_ops xsk_ops = {
    .open    = xsk_open,
    .recv    = xsk_recv,
    .send    = xsk_send,
    .release = xsk_release,
    .close   = xsk_close,
};

struct packet_io *packet_io_create_xsk(void)
{
    struct packet_io *io = calloc(1, sizeof(*io));
    if (io == NULL) {
        return NULL;
    }

    struct packet_io_xsk_priv *priv = calloc(1, sizeof(*priv));
    if (priv == NULL) {
        free(io);
        return NULL;
    }

    io->ops = &xsk_ops;
    io->priv = priv;

    return io;
}

struct packet_io *packet_io_create_xsk_graph(struct xgl_graph *graph)
{
    if (graph == NULL) {
        return NULL;
    }

    struct packet_io *io = calloc(1, sizeof(*io));
    if (io == NULL) {
        return NULL;
    }

    struct packet_io_xsk_priv *priv = calloc(1, sizeof(*priv));
    if (priv == NULL) {
        free(io);
        return NULL;
    }

    priv->graph = graph;
    io->ops = &xsk_ops;
    io->priv = priv;

    return io;
}

void packet_io_destroy(struct packet_io *io)
{
    if (io == NULL) {
        return;
    }

    packet_io_close(io);
    free(io->priv);
    free(io);
}
