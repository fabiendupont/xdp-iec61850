/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Packet I/O via AF_XDP Zero-Copy (xgl_xsk_*)
 *
 * Delegates to xdp-graph-lib's AF_XDP socket abstraction for
 * zero-copy packet I/O. The xgl_xsk_create() call prefers
 * XDP_ZEROCOPY mode and falls back to XDP_COPY automatically.
 */

#include "transport/packet_io.h"
#include "transport/xsk_handoff.h"
#include <xgl/xgl_xsk.h>
#include <xgl/xgl_graph.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>

#define XSK_FRAME_SIZE  4096U
#define XSK_NUM_FRAMES  4096U

struct packet_io_xsk_priv {
    struct xgl_xsk *xsk;
    struct xgl_graph *graph;  /* if non-NULL, use xgl_graph_create_xsk */
};

/* MISRA 11.5: io->priv is an opaque dispatch field (void*). All assignments
 * to struct packet_io_xsk_priv* throughout this file are accepted deviations
 * per misra_deviations.md Category 3. */

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

static int xsk_recv_batch(struct packet_io *io, void **pkt_data,
                           uint32_t *pkt_lens, int max)
{
    struct packet_io_xsk_priv *priv = io->priv;

    if (priv->xsk == NULL) {
        return -ENODEV;
    }

    return xgl_xsk_recv_batch(priv->xsk, pkt_data, pkt_lens, max);
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

static void xsk_release_batch(struct packet_io *io, int count)
{
    struct packet_io_xsk_priv *priv = io->priv;

    if (priv->xsk != NULL) {
        xgl_xsk_recv_release_batch(priv->xsk, count);
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
    .open          = xsk_open,
    .recv          = xsk_recv,
    .recv_batch    = xsk_recv_batch,
    .send          = xsk_send,
    .release       = xsk_release,
    .release_batch = xsk_release_batch,
    .close         = xsk_close,
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

/* open() is a no-op for inherited sockets — the daemon already bound them. */
static int xsk_open_noop(struct packet_io *io, const char *ifname,
                          int queue_id)
{
    (void)io;
    (void)ifname;
    (void)queue_id;
    return -EALREADY;
}

static const struct packet_io_ops xsk_inherited_ops = {
    .open          = xsk_open_noop,
    .recv          = xsk_recv,
    .recv_batch    = xsk_recv_batch,
    .send          = xsk_send,
    .release       = xsk_release,
    .release_batch = xsk_release_batch,
    .close         = xsk_close,
};

struct packet_io *packet_io_create_xsk_inherited(int control_sock_fd)
{
    struct xsk_handoff_msg msg = {0};
    int fds[XSK_HANDOFF_NUM_FDS] = { -1, -1 };
    char cmsgbuf[CMSG_SPACE(sizeof(fds))];
    struct iovec iov = { .iov_base = &msg, .iov_len = sizeof(msg) };
    struct msghdr mh = {
        .msg_iov        = &iov,
        .msg_iovlen     = 1,
        .msg_control    = cmsgbuf,
        .msg_controllen = sizeof(cmsgbuf),
    };

    if (recvmsg(control_sock_fd, &mh, 0) < (ssize_t)sizeof(msg)) {
        errno = EPROTO;
        return NULL;
    }

    if (msg.magic != XSK_HANDOFF_MAGIC || msg.reserved != 0) {
        errno = EPROTO;
        return NULL;
    }

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&mh);
    if (cmsg == NULL || cmsg->cmsg_level != SOL_SOCKET ||
        cmsg->cmsg_type != SCM_RIGHTS ||
        cmsg->cmsg_len != CMSG_LEN(sizeof(fds))) {
        errno = EPROTO;
        return NULL;
    }
    (void)memcpy(fds, CMSG_DATA(cmsg), sizeof(fds));

    struct xgl_xsk *xsk = xgl_xsk_inherit(fds[XSK_HANDOFF_FD_XSK],
                                           fds[XSK_HANDOFF_FD_UMEM],
                                           msg.frame_size, msg.num_frames);
    if (xsk == NULL) {
        return NULL;
    }

    struct packet_io *io = calloc(1, sizeof(*io));
    if (io == NULL) {
        xgl_xsk_destroy(xsk);
        return NULL;
    }

    struct packet_io_xsk_priv *priv = calloc(1, sizeof(*priv));
    if (priv == NULL) {
        xgl_xsk_destroy(xsk);
        free(io);
        return NULL;
    }

    priv->xsk = xsk;
    io->ops   = &xsk_inherited_ops;
    io->priv  = priv;

    return io;
}
