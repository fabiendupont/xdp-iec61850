/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Abstract Packet I/O Interface
 *
 * Strategy pattern for packet I/O. Implementations:
 *   - packet_io_xsk: Zero-copy AF_XDP via xgl_xsk_* from xdp-graph-lib
 *   - packet_io_raw: Raw sockets (fallback, for testing without XDP)
 *
 * The I/O lifecycle:
 *   1. create → allocate + configure
 *   2. open   → bind to interface + queue
 *   3. recv   → receive a packet (pointer into UMEM for XSK)
 *   4. release → release received packet buffer back to pool
 *   5. send   → transmit a packet
 *   6. close  → unbind + cleanup
 *   7. destroy → free resources
 */

#ifndef IEC61850_PACKET_IO_H
#define IEC61850_PACKET_IO_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct packet_io;

struct packet_io_ops {
    int  (*open)(struct packet_io *io, const char *ifname, int queue_id);
    int  (*recv)(struct packet_io *io, void **pkt_data, uint32_t *pkt_len);
    int  (*send)(struct packet_io *io, const void *pkt_data, uint32_t pkt_len);
    void (*release)(struct packet_io *io);
    void (*close)(struct packet_io *io);
};

struct packet_io {
    const struct packet_io_ops *ops;
    void *priv;
};

struct xgl_graph;

/**
 * Create a packet_io backed by AF_XDP zero-copy (xgl_xsk_*).
 * Returns NULL on allocation failure.
 */
struct packet_io *packet_io_create_xsk(void);

/**
 * Create a packet_io backed by AF_XDP with graph registration.
 * The XSK fd is inserted into the XSKMAP at the queue_id used in open().
 * Returns NULL on allocation failure.
 */
struct packet_io *packet_io_create_xsk_graph(struct xgl_graph *graph);

/**
 * Create a packet_io backed by raw sockets (fallback for testing).
 * Returns NULL on allocation failure.
 */
struct packet_io *packet_io_create_raw(void);

/**
 * Destroy a packet_io instance (close if still open, then free).
 */
void packet_io_destroy(struct packet_io *io);

/* Convenience wrappers */

static inline int packet_io_open(struct packet_io *io, const char *ifname,
                                  int queue_id)
{
    if (io == NULL || io->ops == NULL || io->ops->open == NULL) {
        return -1;
    }
    return io->ops->open(io, ifname, queue_id);
}

static inline int packet_io_recv(struct packet_io *io, void **pkt_data,
                                  uint32_t *pkt_len)
{
    if (io == NULL || io->ops == NULL || io->ops->recv == NULL) {
        return -1;
    }
    return io->ops->recv(io, pkt_data, pkt_len);
}

static inline int packet_io_send(struct packet_io *io, const void *pkt_data,
                                  uint32_t pkt_len)
{
    if (io == NULL || io->ops == NULL || io->ops->send == NULL) {
        return -1;
    }
    return io->ops->send(io, pkt_data, pkt_len);
}

static inline void packet_io_release(struct packet_io *io)
{
    if (io != NULL && io->ops != NULL && io->ops->release != NULL) {
        io->ops->release(io);
    }
}

static inline void packet_io_close(struct packet_io *io)
{
    if (io != NULL && io->ops != NULL && io->ops->close != NULL) {
        io->ops->close(io);
    }
}

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_PACKET_IO_H */
