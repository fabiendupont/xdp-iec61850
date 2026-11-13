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
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct packet_io;

struct packet_io_ops {
    int  (*open)(struct packet_io *io, const char *ifname, int queue_id);
    int  (*recv)(struct packet_io *io, void **pkt_data, uint32_t *pkt_len);
    int  (*recv_batch)(struct packet_io *io, void **pkt_data, uint32_t *pkt_lens,
                       int max);
    int  (*send)(struct packet_io *io, const void *pkt_data, uint32_t pkt_len);
    void (*release)(struct packet_io *io);
    void (*release_batch)(struct packet_io *io, int count);
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
 * Create a packet_io by inheriting an already-bound AF_XDP socket from a
 * privileged daemon.  Receives one xsk_handoff_msg + two fds via SCM_RIGHTS
 * from control_sock_fd, then maps UMEM and all four AF_XDP rings without
 * requiring any Linux capability in the calling process.
 *
 * The returned packet_io is ready to use immediately — open() must NOT be
 * called on it.  All recv/send/release/close operations work normally.
 *
 * Returns NULL on failure (check errno).
 */
struct packet_io *packet_io_create_xsk_inherited(int control_sock_fd);

/**
 * Create a packet_io backed by raw sockets (fallback for testing).
 * Returns NULL on allocation failure.
 */
struct packet_io *packet_io_create_raw(void);

/**
 * Create a packet_io UDP sender (IEC TR 61850-90-5 publisher side):
 * sends datagrams to remote_addr:remote_port (unicast address or
 * multicast group). open(ifname, queue_id) selects the outgoing
 * interface for multicast (ifname NULL/"" = default; queue_id
 * unused). Returns NULL on failure.
 */
struct packet_io *packet_io_create_udp_sender(const char *remote_addr,
                                               uint16_t remote_port,
                                               bool multicast);

/**
 * Create a packet_io UDP receiver (IEC TR 61850-90-5 subscriber
 * side): binds local_port on INADDR_ANY. mcast_group NULL receives
 * unicast; otherwise open(ifname, ...) joins the group on ifname.
 * Returns NULL on failure.
 */
struct packet_io *packet_io_create_udp_receiver(uint16_t local_port,
                                                  const char *mcast_group);

/**
 * Destroy a packet_io instance (close if still open, then free).
 */
void packet_io_destroy(struct packet_io *io);

/* Convenience wrappers */

static inline int packet_io_open(struct packet_io *io, const char *ifname,
                                  int queue_id)
{
    if ((io == NULL) || (io->ops == NULL) || (io->ops->open == NULL)) {
        return -1;
    }
    return io->ops->open(io, ifname, queue_id);
}

static inline int packet_io_recv(struct packet_io *io, void **pkt_data,
                                  uint32_t *pkt_len)
{
    if ((io == NULL) || (io->ops == NULL) || (io->ops->recv == NULL)) {
        return -1;
    }
    return io->ops->recv(io, pkt_data, pkt_len);
}

/**
 * Batch receive: receive up to max packets in one call.
 * Returns number of packets received, or -1 on error.
 * Falls back to single recv if batch is not implemented.
 */
static inline int packet_io_recv_batch(struct packet_io *io, void **pkt_data,
                                        uint32_t *pkt_lens, int max)
{
    if ((io == NULL) || (io->ops == NULL)) {
        return -1;
    }
    if (io->ops->recv_batch != NULL) {
        return io->ops->recv_batch(io, pkt_data, pkt_lens, max);
    }
    /* Fallback: single recv */
    if ((io->ops->recv == NULL) || (max < 1)) {
        return -1;
    }
    int ret = io->ops->recv(io, &pkt_data[0], &pkt_lens[0]);
    return (ret > 0) ? 1 : ret;
}

static inline int packet_io_send(struct packet_io *io, const void *pkt_data,
                                  uint32_t pkt_len)
{
    if ((io == NULL) || (io->ops == NULL) || (io->ops->send == NULL)) {
        return -1;
    }
    return io->ops->send(io, pkt_data, pkt_len);
}

static inline void packet_io_release(struct packet_io *io)
{
    if ((io != NULL) && (io->ops != NULL) && (io->ops->release != NULL)) {
        io->ops->release(io);
    }
}

/**
 * Release a batch of received packets back to the pool.
 * Falls back to single release if batch is not implemented.
 */
static inline void packet_io_release_batch(struct packet_io *io, int count)
{
    if ((io == NULL) || (io->ops == NULL)) {
        return;
    }
    if (io->ops->release_batch != NULL) {
        io->ops->release_batch(io, count);
        return;
    }
    /* Fallback: release once (single-packet backends) */
    if (io->ops->release != NULL) {
        for (int i = 0; i < count; i++) {
            io->ops->release(io);
        }
    }
}

static inline void packet_io_close(struct packet_io *io)
{
    if ((io != NULL) && (io->ops != NULL) && (io->ops->close != NULL)) {
        io->ops->close(io);
    }
}

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_PACKET_IO_H */
