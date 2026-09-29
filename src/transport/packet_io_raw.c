/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Packet I/O via Raw Sockets (fallback for testing)
 *
 * Uses AF_PACKET raw sockets for packet I/O when XDP/AF_XDP
 * is not available (e.g., unit testing, development).
 */

#include "transport/packet_io.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <poll.h>

#define RAW_BUF_SIZE 2048U

struct packet_io_raw_priv {
    int fd;
    uint8_t rx_buf[RAW_BUF_SIZE];
    uint32_t rx_len;
};

/* MISRA 11.5: io->priv is an opaque dispatch field (void*). All assignments
 * to struct packet_io_raw_priv* throughout this file are accepted deviations
 * per misra_deviations.md Category 3. */

static int raw_open(struct packet_io *io, const char *ifname, int queue_id)
{
    struct packet_io_raw_priv *priv = io->priv;

    (void)queue_id;

    if (priv->fd >= 0) {
        return -EALREADY;
    }

    priv->fd = socket(AF_PACKET, SOCK_RAW, (int)htons(ETH_P_ALL));
    if (priv->fd < 0) {
        return -errno;
    }

    if (ifname != NULL) {
        unsigned int ifindex = if_nametoindex(ifname);
        if (ifindex == 0U) {
            close(priv->fd);
            priv->fd = -1;
            return -ENODEV;
        }

        struct sockaddr_ll addr;
        (void)memset(&addr, 0, sizeof(addr));
        addr.sll_family = AF_PACKET;
        addr.sll_protocol = (uint16_t)htons(ETH_P_ALL);
        addr.sll_ifindex = (int)ifindex;

        if (bind(priv->fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            int err = errno;
            close(priv->fd);
            priv->fd = -1;
            return -err;
        }
    }

    return 0;
}

static int raw_recv(struct packet_io *io, void **pkt_data, uint32_t *pkt_len)
{
    struct packet_io_raw_priv *priv = io->priv;

    if (priv->fd < 0) {
        return -ENODEV;
    }

    struct pollfd pfd = { .fd = priv->fd, .events = POLLIN };
    int ret = poll(&pfd, 1, 0);
    if (ret <= 0) {
        return 0;
    }

    ssize_t n = recv(priv->fd, priv->rx_buf, RAW_BUF_SIZE, MSG_DONTWAIT);
    if (n <= 0) {
        return 0;
    }

    *pkt_data = priv->rx_buf;
    *pkt_len = (uint32_t)n;
    priv->rx_len = (uint32_t)n;

    return 1;
}

static int raw_send(struct packet_io *io, const void *pkt_data, uint32_t pkt_len)
{
    struct packet_io_raw_priv *priv = io->priv;

    if (priv->fd < 0) {
        return -ENODEV;
    }

    ssize_t n = send(priv->fd, pkt_data, pkt_len, MSG_DONTWAIT);
    if (n < 0) {
        return -errno;
    }

    return 0;
}

static void raw_release(struct packet_io *io)
{
    struct packet_io_raw_priv *priv = io->priv;
    priv->rx_len = 0;
}

static void raw_close(struct packet_io *io)
{
    struct packet_io_raw_priv *priv = io->priv;

    if (priv->fd >= 0) {
        close(priv->fd);
        priv->fd = -1;
    }
}

static const struct packet_io_ops raw_ops = {
    .open    = raw_open,
    .recv    = raw_recv,
    .send    = raw_send,
    .release = raw_release,
    .close   = raw_close,
};

struct packet_io *packet_io_create_raw(void)
{
    struct packet_io *io = calloc(1, sizeof(*io));
    if (io == NULL) {
        return NULL;
    }

    struct packet_io_raw_priv *priv = calloc(1, sizeof(*priv));
    if (priv == NULL) {
        free(io);
        return NULL;
    }

    priv->fd = -1;
    io->ops = &raw_ops;
    io->priv = priv;

    return io;
}
