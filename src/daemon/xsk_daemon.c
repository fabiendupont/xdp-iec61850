/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * xsk-daemon — Privileged AF_XDP socket daemon for IEC 61850
 *
 * Creates a memfd-backed UMEM, binds an AF_XDP socket, loads the IEC 61850
 * XDP filter pipeline, then hands the two fds to a rootless application via
 * a Unix domain socket using SCM_RIGHTS.
 *
 * Usage:
 *   xsk-daemon --iface eth0 --queue 0
 *              --socket /run/iec61850-xsk.sock
 *              --bpf-dir /usr/lib/xdp-iec61850
 *
 * Requires: CAP_NET_ADMIN + CAP_BPF (or root).
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>

#include <bpf/bpf.h>
#include <xgl/xgl_graph.h>

#include "iec61850_graph.h"
#include "transport/xsk_handoff.h"

/* ── UMEM / ring parameters ─────────────────────────────────────────────── */

#define UMEM_FRAME_SIZE   4096U
#define UMEM_NUM_FRAMES   4096U
#define UMEM_SIZE         ((uint64_t)UMEM_FRAME_SIZE * UMEM_NUM_FRAMES)
#define RING_SIZE         UMEM_NUM_FRAMES

/* ── Internal state ─────────────────────────────────────────────────────── */

static volatile int g_running = 1;

static void handle_signal(int sig)
{
    (void)sig;
    g_running = 0;
}

/* ── memfd helper ───────────────────────────────────────────────────────── */

static int memfd_create_umem(uint64_t size)
{
    int fd = (int)syscall(SYS_memfd_create, "iec61850-umem", MFD_CLOEXEC);
    if (fd < 0) {
        perror("memfd_create");
        return -1;
    }
    if (ftruncate(fd, (off_t)size) < 0) {
        perror("ftruncate umem");
        close(fd);
        return -1;
    }
    return fd;
}

/* ── Raw AF_XDP socket creation with memfd-backed UMEM ──────────────────── */

static int create_xsk(const char *ifname, int queue_id,
                      void *umem_area, int *zerocopy_out)
{
    struct xdp_umem_reg reg;
    struct sockaddr_xdp sxdp;
    int xsk_fd;
    int ret;

    xsk_fd = socket(AF_XDP, SOCK_RAW, 0);
    if (xsk_fd < 0) {
        perror("socket AF_XDP");
        return -1;
    }

    /* Register the memfd-backed UMEM on this socket. */
    (void)memset(&reg, 0, sizeof(reg));
    reg.addr       = (uintptr_t)umem_area;
    reg.len        = UMEM_SIZE;
    reg.chunk_size = UMEM_FRAME_SIZE;
    reg.headroom   = 0;

    ret = setsockopt(xsk_fd, SOL_XDP, XDP_UMEM_REG, &reg, sizeof(reg));
    if (ret < 0) {
        perror("setsockopt XDP_UMEM_REG");
        close(xsk_fd);
        return -1;
    }

    /* Configure ring sizes. */
    uint32_t ring_sz = RING_SIZE;
    if ((setsockopt(xsk_fd, SOL_XDP, XDP_UMEM_FILL_RING,
                   &ring_sz, sizeof(ring_sz)) < 0) ||
        (setsockopt(xsk_fd, SOL_XDP, XDP_UMEM_COMPLETION_RING,
                   &ring_sz, sizeof(ring_sz)) < 0) ||
        (setsockopt(xsk_fd, SOL_XDP, XDP_RX_RING,
                   &ring_sz, sizeof(ring_sz)) < 0) ||
        (setsockopt(xsk_fd, SOL_XDP, XDP_TX_RING,
                   &ring_sz, sizeof(ring_sz)) < 0)) {
        perror("setsockopt ring sizes");
        close(xsk_fd);
        return -1;
    }

    /* Pre-populate the fill ring with all frame addresses. */
    struct xdp_mmap_offsets off;
    socklen_t optlen = sizeof(off);
    if (getsockopt(xsk_fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &optlen) < 0) {
        perror("getsockopt XDP_MMAP_OFFSETS");
        close(xsk_fd);
        return -1;
    }

    uint64_t fill_map_size = off.fr.desc + (RING_SIZE * sizeof(uint64_t));
    void *fill_map = mmap(NULL, fill_map_size,
                          PROT_READ | PROT_WRITE, MAP_SHARED | MAP_POPULATE,
                          xsk_fd, XDP_UMEM_PGOFF_FILL_RING);
    if (fill_map == MAP_FAILED) {
        perror("mmap fill ring");
        close(xsk_fd);
        return -1;
    }

    /* MISRA 11.5/18.4: mmap returns void*; byte arithmetic via char* cast is required here */
    uint32_t *prod = (uint32_t *)&((uint8_t *)fill_map)[off.fr.producer];
    uint64_t *ring = (uint64_t *)&((uint8_t *)fill_map)[off.fr.desc];
    for (uint32_t i = 0; i < RING_SIZE; i++)
        ring[i] = (uint64_t)i * UMEM_FRAME_SIZE;
    __atomic_store_n(prod, RING_SIZE, __ATOMIC_RELEASE);

    (void)munmap(fill_map, fill_map_size);

    /* Bind: prefer zero-copy, fall back to copy mode. */
    unsigned int ifindex = if_nametoindex(ifname);
    if (ifindex == 0U) {
        (void)fprintf(stderr, "if_nametoindex(%s): %s\n", ifname, strerror(errno));
        close(xsk_fd);
        return -1;
    }

    (void)memset(&sxdp, 0, sizeof(sxdp));
    sxdp.sxdp_family    = AF_XDP;
    sxdp.sxdp_ifindex   = ifindex;
    sxdp.sxdp_queue_id  = (uint32_t)queue_id;
    sxdp.sxdp_flags     = XDP_ZEROCOPY | XDP_USE_NEED_WAKEUP;

    if (bind(xsk_fd, (struct sockaddr *)&sxdp, sizeof(sxdp)) < 0) {
        if (errno == EINVAL) {
            (void)fprintf(stderr,
                          "XDP_ZEROCOPY not supported, falling back to XDP_COPY\n");
            sxdp.sxdp_flags = XDP_COPY | XDP_USE_NEED_WAKEUP;
            if (bind(xsk_fd, (struct sockaddr *)&sxdp, sizeof(sxdp)) < 0) {
                perror("bind AF_XDP (copy mode)");
                close(xsk_fd);
                return -1;
            }
            if (zerocopy_out)
                *zerocopy_out = 0;
        } else {
            perror("bind AF_XDP");
            close(xsk_fd);
            return -1;
        }
    } else {
        if (zerocopy_out)
            *zerocopy_out = 1;
    }

    return xsk_fd;
}

/* ── Unix socket: send two fds to the application ───────────────────────── */

static int send_fds(int conn_fd, int xsk_fd, int umem_fd)
{
    struct xsk_handoff_msg msg = {
        .magic      = XSK_HANDOFF_MAGIC,
        .frame_size = UMEM_FRAME_SIZE,
        .num_frames = UMEM_NUM_FRAMES,
        .reserved   = 0,
    };
    int fds[XSK_HANDOFF_NUM_FDS] = { xsk_fd, umem_fd };
    char cmsgbuf[CMSG_SPACE(sizeof(fds))];
    struct iovec iov = { .iov_base = &msg, .iov_len = sizeof(msg) };
    struct msghdr mh = {
        .msg_iov        = &iov,
        .msg_iovlen     = 1,
        .msg_control    = cmsgbuf,
        .msg_controllen = sizeof(cmsgbuf),
    };

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&mh);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(fds));
    (void)memcpy(CMSG_DATA(cmsg), fds, sizeof(fds));

    if (sendmsg(conn_fd, &mh, 0) < 0) {
        perror("sendmsg SCM_RIGHTS");
        return -1;
    }
    return 0;
}

/* ── Main ───────────────────────────────────────────────────────────────── */

static void usage(const char *prog)
{
    (void)fprintf(stderr,
                  "Usage: %s --iface <ifname> --queue <id> "
                  "--socket <path> --bpf-dir <dir>\n",
                  prog);
}

int main(int argc, char *argv[])
{
    static const struct option opts[] = {
        { "iface",   required_argument, NULL, 'i' },
        { "queue",   required_argument, NULL, 'q' },
        { "socket",  required_argument, NULL, 's' },
        { "bpf-dir", required_argument, NULL, 'b' },
        { NULL, 0, NULL, 0 },
    };

    const char *ifname   = NULL;
    const char *sock_path = NULL;
    const char *bpf_dir  = NULL;
    int queue_id = 0;
    int opt;

    while ((opt = getopt_long(argc, argv, "i:q:s:b:", opts, NULL)) != -1) {
        switch (opt) {
        case 'i': ifname    = optarg; break;
        case 'q': queue_id  = atoi(optarg); break;
        case 's': sock_path = optarg; break;
        case 'b': bpf_dir   = optarg; break;
        default:  usage(argv[0]); return 1;
        }
    }

    if ((!ifname) || (!sock_path) || (!bpf_dir)) {
        usage(argv[0]);
        return 1;
    }

    signal(SIGINT,  handle_signal);
    signal(SIGTERM, handle_signal);

    /* ── 1. Load IEC 61850 XDP filter pipeline ── */

    struct xgl_graph *g = xgl_graph_create("iec61850-daemon", 0);
    if (!g) {
        (void)fprintf(stderr, "xgl_graph_create failed\n");
        return 1;
    }

    struct iec61850_graph_indices idx;
    int ret = iec61850_graph_register(g, bpf_dir, &idx);
    if (ret != 0) {
        (void)fprintf(stderr, "iec61850_graph_register: %s\n", strerror(-ret));
        xgl_graph_destroy(g);
        return 1;
    }

    ret = xgl_graph_attach(g, ifname);
    if (ret != 0) {
        (void)fprintf(stderr, "xgl_graph_attach(%s): %s\n", ifname, strerror(-ret));
        xgl_graph_destroy(g);
        return 1;
    }

    (void)fprintf(stderr, "XDP pipeline attached to %s\n", ifname);

    /* ── 2. Create memfd-backed UMEM ── */

    int umem_fd = memfd_create_umem(UMEM_SIZE);
    if (umem_fd < 0) {
        xgl_graph_destroy(g);
        return 1;
    }

    void *umem_area = mmap(NULL, UMEM_SIZE,
                           PROT_READ | PROT_WRITE, MAP_SHARED, umem_fd, 0);
    if (umem_area == MAP_FAILED) {
        perror("mmap umem_fd");
        close(umem_fd);
        xgl_graph_destroy(g);
        return 1;
    }

    /* ── 3. Create AF_XDP socket ── */

    int zerocopy = 0;
    int xsk_fd = create_xsk(ifname, queue_id, umem_area, &zerocopy);
    if (xsk_fd < 0) {
        munmap(umem_area, UMEM_SIZE);
        close(umem_fd);
        xgl_graph_destroy(g);
        return 1;
    }

    (void)fprintf(stderr, "AF_XDP socket created (%s mode)\n",
                  zerocopy ? "zero-copy" : "copy");

    /* ── 4. Insert XSK fd into graph XSKMAP ── */

    int xskmap_fd = xgl_graph_get_map_fd(g, "xgl_xsk_map");
    if (xskmap_fd >= 0) {
        uint32_t key = (uint32_t)queue_id;
        if (bpf_map_update_elem(xskmap_fd, &key, &xsk_fd, BPF_ANY) != 0)
            (void)fprintf(stderr, "Warning: XSKMAP update failed: %s\n",
                          strerror(errno));
    } else {
        (void)fprintf(stderr, "Warning: xgl_xsk_map not found (%s) — "
                      "redirect may not work\n", strerror(-xskmap_fd));
    }

    /* ── 5. Unix socket — accept and hand off fds ── */

    int srv_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (srv_fd < 0) {
        perror("socket AF_UNIX");
        goto cleanup;
    }

    unlink(sock_path);

    struct sockaddr_un addr;
    (void)memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    (void)strncpy(addr.sun_path, sock_path, sizeof(addr.sun_path) - 1U);

    if (bind(srv_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind AF_UNIX");
        close(srv_fd);
        goto cleanup;
    }

    chmod(sock_path, 0666);

    if (listen(srv_fd, 8) < 0) {
        perror("listen");
        close(srv_fd);
        goto cleanup;
    }

    (void)fprintf(stderr, "Listening on %s\n", sock_path);

    while (g_running) {
        int conn_fd = accept(srv_fd, NULL, NULL);
        if (conn_fd < 0) {
            if (errno == EINTR)
                continue;
            perror("accept");
            break;
        }

        if (send_fds(conn_fd, xsk_fd, umem_fd) == 0)
            (void)fprintf(stderr, "Handed off fds to application\n");

        close(conn_fd);
    }

    close(srv_fd);
    unlink(sock_path);

cleanup:
    close(xsk_fd);
    munmap(umem_area, UMEM_SIZE);
    close(umem_fd);
    xgl_graph_detach(g, ifname);
    xgl_graph_destroy(g);

    return 0;
}
