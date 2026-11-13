/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * packet_io UDP backend (IEC TR 61850-90-5 routable profiles)
 *
 * Two constructors (frozen in WP-S4):
 *   - packet_io_create_udp_sender(): publisher side. open() creates a
 *     UDP socket and connect()s it to remote_addr:remote_port so the
 *     vtable send() needs no address. With multicast=true, open()'s
 *     ifname selects the outgoing interface (IP_MULTICAST_IF); a NULL
 *     or empty ifname uses the kernel default route.
 *   - packet_io_create_udp_receiver(): subscriber side. open() binds
 *     local_port on INADDR_ANY; if a mcast_group was given at create()
 *     time, open(ifname) joins that group on ifname (IP_ADD_MEMBERSHIP).
 *
 * Buffer strategy (differs from the XSK backend on purpose):
 *   Received datagrams are copied by the kernel into private buffers
 *   inside struct packet_io_udp_priv, so release()/release_batch() are
 *   no-ops — there is no UMEM ring to give frames back to. Returned
 *   packet pointers stay valid until the next recv()/recv_batch() call
 *   on the same packet_io (same single-buffer lifetime contract as the
 *   raw backend).
 *
 * Datagram cap:
 *   The receive buffer is bounded at UDP_DGRAM_CAP (9216) bytes — the
 *   maximum routable 90-5 SPDU plus IPv4/UDP headroom. 9216 is chosen
 *   because it is the largest "jumbo-friendly" IP datagram universally
 *   accepted on Linux loopback and common 9K-MTU networks; larger
 *   datagrams are truncated by recv() (kernel semantics). No routable
 *   GOOSE/SV SPDU comes anywhere near this bound.
 *
 * Multicast options:
 *   - IP_MULTICAST_IF   set from open()'s ifname (address + ifindex
 *                       form of struct ip_mreqn; the interface must
 *                       have an IPv4 address).
 *   - IP_MULTICAST_TTL  default 5 (90-5 publisher default).
 *   - IP_MULTICAST_LOOP default OFF for senders — a publisher must not
 *                       consume its own publications. Runtime-config-
 *                       urable via packet_io_udp_set_mcast_loop()
 *                       (declared in transport/ip_udp_frame.h), e.g.
 *                       for same-host test rigs.
 *
 * Recv semantics mirror packet_io_raw exactly: poll(0) + MSG_DONTWAIT,
 * returning 0 when no datagram is queued (never blocks), 1 with data
 * otherwise. Errors are negative errno.
 *
 * This file also hosts the userspace IPv4/UDP framing helpers used by
 * 90-5 publishers on the raw AF_PACKET backend (the security signature
 * covers the IP + UDP header bytes): iec61850_ip_udp_build/_parse,
 * declared in transport/ip_udp_frame.h.
 */

#include "transport/packet_io.h"
#include "transport/ip_udp_frame.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <poll.h>

/* Maximum received datagram size (see file header comment). */
#define UDP_DGRAM_CAP 9216U

/* Maximum datagrams returned by one recv_batch() call. Bounded so the
 * private batch buffer stays small; callers loop for more. */
#define UDP_BATCH_MAX 8

/* IP_MULTICAST_TTL default for senders (IEC TR 61850-90-5). */
#define UDP_MCAST_TTL_DEFAULT 5U

/* IP_MULTICAST_LOOP default for senders: disabled. Configurable at
 * runtime via packet_io_udp_set_mcast_loop(). */
#define UDP_SENDER_MCAST_LOOP_DEFAULT false

/* IPv4 defaults for the framing helper. */
#define IP_UDP_DEFAULT_TTL 64U

struct packet_io_udp_priv {
    int fd;                        /* -1 when closed */
    bool is_sender;
    bool multicast;                /* sender: apply multicast options */
    bool mcast_loop;               /* sender: IP_MULTICAST_LOOP */
    uint16_t local_port;           /* receiver: port to bind (host order) */
    struct sockaddr_in remote;     /* sender: connect() target */
    struct in_addr mcast_group;    /* receiver: group to join (0 = none) */
    uint8_t pkt_buf[UDP_BATCH_MAX][UDP_DGRAM_CAP];
};

/* MISRA 11.5: io->priv is an opaque dispatch field (void*). All assignments
 * to struct packet_io_udp_priv* throughout this file are accepted deviations
 * per misra_deviations.md Category 3. */

/* ------------------------------------------------------------------ */
/* Socket helpers                                                      */
/* ------------------------------------------------------------------ */

static bool udp_addr_is_mcast(const struct in_addr *addr)
{
    return ((ntohl(addr->s_addr) & 0xF0000000U) == 0xE0000000U);
}

/*
 * Look up the primary IPv4 address of a network interface.
 * Returns 0 on success, -ENODEV if the name is too long or the
 * interface has no IPv4 address, else -errno from ioctl().
 */
static int udp_if_addr(int fd, const char *ifname, struct in_addr *addr_out)
{
    struct ifreq ifr;
    struct sockaddr_in *sin;
    size_t n;

    (void)memset(&ifr, 0, sizeof(ifr));
    n = strnlen(ifname, (size_t)IFNAMSIZ);
    if (n >= (size_t)IFNAMSIZ) {
        return -ENODEV;
    }
    (void)memcpy(ifr.ifr_name, ifname, n);

    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
        return -errno;
    }

    sin = (struct sockaddr_in *)&ifr.ifr_addr;
    *addr_out = sin->sin_addr;
    return 0;
}

/* ------------------------------------------------------------------ */
/* vtable: open                                                        */
/* ------------------------------------------------------------------ */

static int udp_sender_open(struct packet_io_udp_priv *priv, const char *ifname)
{
    int fd;
    int one = 1;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -errno;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
        int err = errno;
        (void)close(fd);
        return -err;
    }

    if (priv->multicast) {
        if ((ifname != NULL) && (ifname[0] != '\0')) {
            /* Select the outgoing interface for multicast. */
            unsigned int ifindex = if_nametoindex(ifname);
            struct in_addr ifaddr;
            struct ip_mreqn mreqn;
            int ret;

            if (ifindex == 0U) {
                (void)close(fd);
                return -ENODEV;
            }
            ret = udp_if_addr(fd, ifname, &ifaddr);
            if (ret != 0) {
                (void)close(fd);
                return ret;
            }

            (void)memset(&mreqn, 0, sizeof(mreqn));
            mreqn.imr_address = ifaddr;
            mreqn.imr_ifindex = (int)ifindex;
            if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &mreqn,
                           sizeof(mreqn)) < 0) {
                int err = errno;
                (void)close(fd);
                return -err;
            }
        }

        {
            unsigned char ttl = (unsigned char)UDP_MCAST_TTL_DEFAULT;
            if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl,
                           sizeof(ttl)) < 0) {
                int err = errno;
                (void)close(fd);
                return -err;
            }
        }
        {
            unsigned char loop = priv->mcast_loop ? 1U : 0U;
            if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop,
                           sizeof(loop)) < 0) {
                int err = errno;
                (void)close(fd);
                return -err;
            }
        }
    }

    /* connect() pins the destination so send() needs no address. */
    if (connect(fd, (struct sockaddr *)&priv->remote,
                sizeof(priv->remote)) < 0) {
        int err = errno;
        (void)close(fd);
        return -err;
    }

    priv->fd = fd;
    return 0;
}

static int udp_receiver_open(struct packet_io_udp_priv *priv, const char *ifname)
{
    struct sockaddr_in addr;
    int fd;
    int one = 1;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return -errno;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
        int err = errno;
        (void)close(fd);
        return -err;
    }
    /* SO_REUSEPORT is best-effort: unavailable on kernels < 3.9. */
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));

    (void)memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(priv->local_port);
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int err = errno;
        (void)close(fd);
        return -err;
    }

    if (priv->mcast_group.s_addr != 0U) {
        struct ip_mreqn mreqn;
        (void)memset(&mreqn, 0, sizeof(mreqn));
        mreqn.imr_multiaddr = priv->mcast_group;

        if ((ifname != NULL) && (ifname[0] != '\0')) {
            unsigned int ifindex = if_nametoindex(ifname);
            struct in_addr ifaddr;
            int ret;

            if (ifindex == 0U) {
                (void)close(fd);
                return -ENODEV;
            }
            ret = udp_if_addr(fd, ifname, &ifaddr);
            if (ret != 0) {
                (void)close(fd);
                return ret;
            }
            mreqn.imr_address = ifaddr;
            mreqn.imr_ifindex = (int)ifindex;
        }
        /* ifname NULL/"" joins on the kernel's default interface. */

        if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreqn,
                       sizeof(mreqn)) < 0) {
            int err = errno;
            (void)close(fd);
            return -err;
        }
    }

    priv->fd = fd;
    return 0;
}

static int udp_open(struct packet_io *io, const char *ifname, int queue_id)
{
    struct packet_io_udp_priv *priv = io->priv;

    (void)queue_id; /* queue affinity is an XSK concept, unused here */

    if (priv->fd >= 0) {
        return -EALREADY;
    }

    return priv->is_sender ? udp_sender_open(priv, ifname)
                           : udp_receiver_open(priv, ifname);
}

/* ------------------------------------------------------------------ */
/* vtable: recv / recv_batch                                           */
/* ------------------------------------------------------------------ */

/* Shared single-datagram receive into pkt_buf[slot]; returns 1 with a
 * datagram, 0 when none is queued (raw-backend semantics). */
static int udp_recv_one(struct packet_io_udp_priv *priv, int slot,
                        void **pkt_data, uint32_t *pkt_len)
{
    struct pollfd pfd = { .fd = priv->fd, .events = POLLIN };
    ssize_t n;
    int ret;

    ret = poll(&pfd, 1, 0);
    if (ret <= 0) {
        return 0;
    }

    n = recv(priv->fd, priv->pkt_buf[slot], UDP_DGRAM_CAP, MSG_DONTWAIT);
    if (n <= 0) {
        return 0;
    }

    *pkt_data = priv->pkt_buf[slot];
    *pkt_len = (uint32_t)n;
    return 1;
}

static int udp_recv(struct packet_io *io, void **pkt_data, uint32_t *pkt_len)
{
    struct packet_io_udp_priv *priv = io->priv;

    if ((pkt_data == NULL) || (pkt_len == NULL)) {
        return -EINVAL;
    }
    if (priv->fd < 0) {
        return -ENODEV;
    }
    if (priv->is_sender) {
        return -EOPNOTSUPP; /* senders do not receive */
    }

    return udp_recv_one(priv, 0, pkt_data, pkt_len);
}

static int udp_recv_batch(struct packet_io *io, void **pkt_data,
                          uint32_t *pkt_lens, int max)
{
    struct packet_io_udp_priv *priv = io->priv;
    int limit;
    int count = 0;

    if ((pkt_data == NULL) || (pkt_lens == NULL)) {
        return -EINVAL;
    }
    if (priv->fd < 0) {
        return -ENODEV;
    }
    if (priv->is_sender) {
        return -EOPNOTSUPP; /* senders do not receive */
    }

    limit = (max < UDP_BATCH_MAX) ? max : UDP_BATCH_MAX;
    while (count < limit) {
        uint32_t len = 0;
        void *data = NULL;

        if (udp_recv_one(priv, count, &data, &len) != 1) {
            break;
        }
        pkt_data[count] = data;
        pkt_lens[count] = len;
        count++;
    }

    return count;
}

/* ------------------------------------------------------------------ */
/* vtable: send                                                        */
/* ------------------------------------------------------------------ */

static int udp_send(struct packet_io *io, const void *pkt_data, uint32_t pkt_len)
{
    struct packet_io_udp_priv *priv = io->priv;
    ssize_t n;

    if (priv->fd < 0) {
        return -ENODEV;
    }
    if (!priv->is_sender) {
        return -EOPNOTSUPP; /* receivers do not send */
    }
    if (pkt_data == NULL) {
        return -EINVAL;
    }
    if ((size_t)pkt_len > IEC61850_IP_UDP_MAX_PAYLOAD) {
        return -EMSGSIZE;
    }

    n = send(priv->fd, pkt_data, pkt_len, MSG_DONTWAIT);
    if (n < 0) {
        return -errno;
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/* vtable: release / release_batch / close                             */
/* ------------------------------------------------------------------ */

/*
 * No-ops, and deliberately so: unlike the XSK backend, received
 * datagrams are copied by the kernel into private buffers — there is
 * no shared UMEM whose frames must be returned to the fill ring.
 * Dropping the pointer is the whole release.
 */
static void udp_release(struct packet_io *io)
{
    (void)io;
}

static void udp_release_batch(struct packet_io *io, int count)
{
    (void)io;
    (void)count;
}

static void udp_close(struct packet_io *io)
{
    struct packet_io_udp_priv *priv = io->priv;

    if (priv->fd >= 0) {
        (void)close(priv->fd);
        priv->fd = -1;
    }
}

static const struct packet_io_ops udp_ops = {
    .open          = udp_open,
    .recv          = udp_recv,
    .recv_batch    = udp_recv_batch,
    .send          = udp_send,
    .release       = udp_release,
    .release_batch = udp_release_batch,
    .close         = udp_close,
};

/* ------------------------------------------------------------------ */
/* Constructors (frozen in WP-S4)                                      */
/* ------------------------------------------------------------------ */

struct packet_io *packet_io_create_udp_sender(const char *remote_addr,
                                               uint16_t remote_port,
                                               bool multicast)
{
    struct packet_io *io;
    struct packet_io_udp_priv *priv;
    struct in_addr addr;

    if (remote_addr == NULL) {
        errno = EINVAL;
        return NULL;
    }
    if (inet_pton(AF_INET, remote_addr, &addr) != 1) {
        errno = EINVAL;
        return NULL;
    }
    /* The multicast flag must match the address class: a mis-flagged
     * publisher would silently miss all multicast socket options. */
    if (udp_addr_is_mcast(&addr) != multicast) {
        errno = EINVAL;
        return NULL;
    }

    io = calloc(1, sizeof(*io));
    if (io == NULL) {
        return NULL;
    }

    priv = calloc(1, sizeof(*priv));
    if (priv == NULL) {
        free(io);
        return NULL;
    }

    priv->fd = -1;
    priv->is_sender = true;
    priv->multicast = multicast;
    priv->mcast_loop = UDP_SENDER_MCAST_LOOP_DEFAULT;
    priv->remote.sin_family = AF_INET;
    priv->remote.sin_port = htons(remote_port);
    priv->remote.sin_addr = addr;

    io->ops = &udp_ops;
    io->priv = priv;

    return io;
}

struct packet_io *packet_io_create_udp_receiver(uint16_t local_port,
                                                  const char *mcast_group)
{
    struct packet_io *io;
    struct packet_io_udp_priv *priv;
    struct in_addr group;

    (void)memset(&group, 0, sizeof(group));
    if (mcast_group != NULL) {
        if ((inet_pton(AF_INET, mcast_group, &group) != 1) ||
            !udp_addr_is_mcast(&group)) {
            errno = EINVAL;
            return NULL;
        }
    }

    io = calloc(1, sizeof(*io));
    if (io == NULL) {
        return NULL;
    }

    priv = calloc(1, sizeof(*priv));
    if (priv == NULL) {
        free(io);
        return NULL;
    }

    priv->fd = -1;
    priv->is_sender = false;
    priv->local_port = local_port;
    priv->mcast_group = group;

    io->ops = &udp_ops;
    io->priv = priv;

    return io;
}

int packet_io_udp_set_mcast_loop(struct packet_io *io, bool enable)
{
    struct packet_io_udp_priv *priv;

    if ((io == NULL) || (io->ops != &udp_ops)) {
        return -EINVAL;
    }

    priv = io->priv;
    if (!priv->is_sender) {
        return -EINVAL; /* receivers never loop back sends */
    }

    if (priv->fd >= 0) {
        /* Already open: apply immediately. */
        unsigned char loop = enable ? 1U : 0U;
        if (setsockopt(priv->fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop,
                       sizeof(loop)) < 0) {
            return -errno;
        }
    }

    priv->mcast_loop = enable;
    return 0;
}

/* ------------------------------------------------------------------ */
/* IPv4 + UDP framing helpers (raw AF_PACKET wire side)                */
/* ------------------------------------------------------------------ */

/*
 * One's-complement checksum core: accumulate big-endian 16-bit words
 * (zero-padded to even length) onto seed, fold, return the SUM (not
 * its complement). Chaining buffers via seed is valid because one's
 * complement addition is associative.
 */
static uint16_t ip_udp_cksum_fold(const uint8_t *data, size_t len, uint32_t seed)
{
    uint32_t sum = seed;
    size_t i = 0U;

    while ((i + 2U) <= len) {
        sum += (((uint32_t)data[i]) << 8) | ((uint32_t)data[i + 1U]);
        i += 2U;
    }
    if (i < len) {
        sum += ((uint32_t)data[i]) << 8; /* zero-pad odd tail */
    }
    while ((sum >> 16) != 0U) {
        sum = (sum & 0xFFFFU) + (sum >> 16);
    }

    return (uint16_t)sum;
}

int iec61850_ip_udp_build(uint8_t *buf, size_t buflen, const char *src_ip,
                          const char *dst_ip, uint16_t src_port,
                          uint16_t dst_port, const uint8_t *payload,
                          size_t payload_len, uint8_t protocol_next_hdr)
{
    struct in_addr src;
    struct in_addr dst;
    uint8_t pseudo[12];
    uint16_t udp_len;
    uint16_t ck;
    size_t total_len;
    uint32_t seed;

    if ((buf == NULL) || (src_ip == NULL) || (dst_ip == NULL) ||
        ((payload == NULL) && (payload_len != 0U))) {
        return -EINVAL;
    }
    /* IPv6 / extension headers are a future addition; only UDP today. */
    if (protocol_next_hdr != (uint8_t)IPPROTO_UDP) {
        return -EPROTONOSUPPORT;
    }
    if (inet_pton(AF_INET, src_ip, &src) != 1) {
        return -EINVAL;
    }
    if (inet_pton(AF_INET, dst_ip, &dst) != 1) {
        return -EINVAL;
    }
    if (payload_len > IEC61850_IP_UDP_MAX_PAYLOAD) {
        return -EMSGSIZE;
    }

    total_len = IEC61850_IP_UDP_HEADER_LEN + payload_len;
    if (buflen < total_len) {
        return -ENOSPC;
    }
    udp_len = (uint16_t)(IEC61850_UDP_HEADER_LEN + payload_len);

    /* IPv4 header, checksum left at 0 for now. */
    (void)memset(buf, 0, IEC61850_IPV4_HEADER_LEN);
    buf[0] = 0x45U; /* version 4, IHL 5 (no options) */
    buf[2] = (uint8_t)(total_len >> 8);
    buf[3] = (uint8_t)(total_len & 0xFFU);
    buf[6] = 0x40U; /* Don't Fragment, fragment offset 0 */
    buf[8] = (uint8_t)IP_UDP_DEFAULT_TTL;
    buf[9] = (uint8_t)IPPROTO_UDP;
    (void)memcpy(&buf[12], &src, sizeof(src));
    (void)memcpy(&buf[16], &dst, sizeof(dst));

    /* UDP header, checksum left at 0 for now. */
    buf[20] = (uint8_t)(src_port >> 8);
    buf[21] = (uint8_t)(src_port & 0xFFU);
    buf[22] = (uint8_t)(dst_port >> 8);
    buf[23] = (uint8_t)(dst_port & 0xFFU);
    buf[24] = (uint8_t)(udp_len >> 8);
    buf[25] = (uint8_t)(udp_len & 0xFFU);
    buf[26] = 0U;
    buf[27] = 0U;

    if (payload_len > 0U) {
        (void)memcpy(&buf[28], payload, payload_len);
    }

    /* IPv4 header checksum (mandatory). */
    ck = (uint16_t)(~(uint32_t)ip_udp_cksum_fold(buf,
                                                 IEC61850_IPV4_HEADER_LEN, 0U));
    buf[10] = (uint8_t)(ck >> 8);
    buf[11] = (uint8_t)(ck & 0xFFU);

    /* UDP checksum over the IPv4 pseudo-header + UDP header + payload.
     * Implemented (not left at 0): the 90-5 security signature covers
     * these header bytes, so they are fully specified. A computed
     * value of 0 is transmitted as 0xFFFF per RFC 768. */
    (void)memcpy(&pseudo[0], &src, sizeof(src));
    (void)memcpy(&pseudo[4], &dst, sizeof(dst));
    pseudo[8] = 0U;
    pseudo[9] = (uint8_t)IPPROTO_UDP;
    pseudo[10] = (uint8_t)(udp_len >> 8);
    pseudo[11] = (uint8_t)(udp_len & 0xFFU);

    seed = (uint32_t)ip_udp_cksum_fold(pseudo, sizeof(pseudo), 0U);
    ck = (uint16_t)(~(uint32_t)ip_udp_cksum_fold(
                        &buf[20], IEC61850_UDP_HEADER_LEN + payload_len, seed));
    if (ck == 0U) {
        ck = 0xFFFFU;
    }
    buf[26] = (uint8_t)(ck >> 8);
    buf[27] = (uint8_t)(ck & 0xFFU);

    return 0;
}

int iec61850_ip_udp_parse(const uint8_t *buf, size_t buflen, char *src_ip,
                          size_t src_ip_len, char *dst_ip, size_t dst_ip_len,
                          uint16_t *src_port, uint16_t *dst_port,
                          const uint8_t **payload, size_t *payload_len)
{
    size_t ip_hdr_len;
    size_t udp_off;
    uint16_t total_len;
    uint16_t frag;
    uint8_t ihl;

    if ((buf == NULL) || (src_ip == NULL) || (dst_ip == NULL) ||
        (src_port == NULL) || (dst_port == NULL) ||
        (payload == NULL) || (payload_len == NULL)) {
        return -EINVAL;
    }
    if (buflen < IEC61850_IPV4_HEADER_LEN) {
        return -EBADMSG;
    }

    if ((buf[0] >> 4) != 4) {
        return -EPROTONOSUPPORT;
    }
    ihl = (uint8_t)(buf[0] & 0x0FU);
    if (ihl < 5U) {
        return -EBADMSG;
    }
    ip_hdr_len = (size_t)ihl * 4U;
    if (buflen < ip_hdr_len) {
        return -EBADMSG;
    }

    /* The IPv4 Total Length field is authoritative for the payload
     * extent (buflen may be larger, e.g. link-layer padding). */
    total_len = (uint16_t)(((uint16_t)buf[2] << 8) | (uint16_t)buf[3]);
    if ((size_t)total_len < (ip_hdr_len + IEC61850_UDP_HEADER_LEN)) {
        return -EBADMSG;
    }
    if ((size_t)total_len > buflen) {
        return -EBADMSG; /* truncated */
    }

    frag = (uint16_t)(((uint16_t)buf[6] << 8) | (uint16_t)buf[7]);
    if ((frag & 0x1FFFU) != 0U) {
        return -EPROTO; /* non-first fragment: not supported */
    }

    if (buf[9] != IPPROTO_UDP) {
        return -EPROTONOSUPPORT;
    }

    if ((src_ip_len < INET_ADDRSTRLEN) || (dst_ip_len < INET_ADDRSTRLEN)) {
        return -ENOSPC;
    }
    if (inet_ntop(AF_INET, &buf[12], src_ip, (socklen_t)src_ip_len) == NULL) {
        return -ENOSPC;
    }
    if (inet_ntop(AF_INET, &buf[16], dst_ip, (socklen_t)dst_ip_len) == NULL) {
        return -ENOSPC;
    }

    udp_off = ip_hdr_len;
    *src_port = (uint16_t)(((uint16_t)buf[udp_off] << 8) |
                           (uint16_t)buf[udp_off + 1U]);
    *dst_port = (uint16_t)(((uint16_t)buf[udp_off + 2U] << 8) |
                           (uint16_t)buf[udp_off + 3U]);

    *payload = &buf[udp_off + IEC61850_UDP_HEADER_LEN];
    *payload_len = (size_t)total_len - ip_hdr_len - IEC61850_UDP_HEADER_LEN;

    return 0;
}
