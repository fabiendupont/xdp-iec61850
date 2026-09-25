/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Integration Test: rootless AF_XDP fd inheritance
 *
 * Verifies the full SCM_RIGHTS handoff path:
 *
 *   fork() → child (mini-daemon):
 *     memfd_create → UMEM → socket(AF_XDP) → setsockopt/bind → sendmsg
 *   parent (rootless app):
 *     packet_io_create_xsk_inherited() → recv/send/destroy
 *
 * Requires: root (CAP_NET_ADMIN for veth + AF_XDP bind).
 * Skips gracefully when not root or when veth creation fails.
 */

#define _POSIX_C_SOURCE 200809L

#include "transport/packet_io.h"
#include "transport/xsk_handoff.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/if_xdp.h>
#include <net/if.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>

#define VETH0 "iec_inh0"
#define VETH1 "iec_inh1"

#define FRAME_SIZE  4096U
#define NUM_FRAMES  256U
#define UMEM_SIZE   ((uint64_t)FRAME_SIZE * NUM_FRAMES)

/* ── Test harness ────────────────────────────────────────────────────────── */

static int tests_run;
static int tests_passed;
static int tests_skipped;
static int tests_failed;

#define TEST(name) \
    do { tests_run++; printf("  [TEST] %-50s ", name); } while (0)
#define PASS() \
    do { tests_passed++; printf("PASS\n"); return; } while (0)
#define SKIP(msg) \
    do { tests_skipped++; printf("SKIP: %s\n", msg); return; } while (0)
#define FAIL(msg) \
    do { tests_failed++; printf("FAIL: %s\n", msg); return; } while (0)
#define ASSERT_NONNULL(p) \
    do { if ((p) == NULL) { FAIL(#p " is NULL"); } } while (0)
#define ASSERT_EQ(a, b) \
    do { if ((a) != (b)) { \
        printf("FAIL: %s (%d) != %s (%d)\n", #a, (int)(a), #b, (int)(b)); \
        tests_failed++; return; } } while (0)
#define ASSERT_GE(a, b) \
    do { if ((a) < (b)) { \
        printf("FAIL: %s (%d) < %s (%d)\n", #a, (int)(a), #b, (int)(b)); \
        tests_failed++; return; } } while (0)

/* ── Veth helpers ────────────────────────────────────────────────────────── */

static int create_veth(void)
{
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip link del %s 2>/dev/null", VETH0);
    (void)system(cmd);
    snprintf(cmd, sizeof(cmd),
             "ip link add %s type veth peer name %s 2>/dev/null",
             VETH0, VETH1);
    if (system(cmd) != 0)
        return -1;
    snprintf(cmd, sizeof(cmd), "ip link set %s up 2>/dev/null", VETH0);
    (void)system(cmd);
    snprintf(cmd, sizeof(cmd), "ip link set %s up 2>/dev/null", VETH1);
    (void)system(cmd);
    return 0;
}

static void destroy_veth(void)
{
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ip link del %s 2>/dev/null", VETH0);
    (void)system(cmd);
}

/* ── Mini-daemon: creates and hands off the AF_XDP socket ───────────────── */

static int mini_daemon(int sock_fd)
{
    /* Create memfd-backed UMEM. */
    int umem_fd = (int)syscall(SYS_memfd_create, "test-umem", 0U);
    if (umem_fd < 0) {
        perror("memfd_create");
        return 1;
    }
    if (ftruncate(umem_fd, (off_t)UMEM_SIZE) < 0) {
        perror("ftruncate");
        close(umem_fd);
        return 1;
    }
    void *umem_area = mmap(NULL, UMEM_SIZE,
                           PROT_READ | PROT_WRITE, MAP_SHARED, umem_fd, 0);
    if (umem_area == MAP_FAILED) {
        perror("mmap umem");
        close(umem_fd);
        return 1;
    }

    /* Create AF_XDP socket and register UMEM. */
    int xsk_fd = socket(AF_XDP, SOCK_RAW, 0);
    if (xsk_fd < 0) {
        perror("socket AF_XDP");
        munmap(umem_area, UMEM_SIZE);
        close(umem_fd);
        return 1;
    }

    struct xdp_umem_reg reg = {
        .addr       = (uintptr_t)umem_area,
        .len        = UMEM_SIZE,
        .chunk_size = FRAME_SIZE,
        .headroom   = 0,
    };
    if (setsockopt(xsk_fd, SOL_XDP, XDP_UMEM_REG, &reg, sizeof(reg)) < 0) {
        perror("setsockopt XDP_UMEM_REG");
        close(xsk_fd);
        munmap(umem_area, UMEM_SIZE);
        close(umem_fd);
        return 1;
    }

    uint32_t ring_sz = NUM_FRAMES;
    if (setsockopt(xsk_fd, SOL_XDP, XDP_UMEM_FILL_RING,
                   &ring_sz, sizeof(ring_sz)) < 0 ||
        setsockopt(xsk_fd, SOL_XDP, XDP_UMEM_COMPLETION_RING,
                   &ring_sz, sizeof(ring_sz)) < 0 ||
        setsockopt(xsk_fd, SOL_XDP, XDP_RX_RING,
                   &ring_sz, sizeof(ring_sz)) < 0 ||
        setsockopt(xsk_fd, SOL_XDP, XDP_TX_RING,
                   &ring_sz, sizeof(ring_sz)) < 0) {
        perror("setsockopt ring sizes");
        close(xsk_fd);
        munmap(umem_area, UMEM_SIZE);
        close(umem_fd);
        return 1;
    }

    /* Bind to veth0 in XDP_COPY mode (no XDP program required for binding). */
    unsigned int ifindex = if_nametoindex(VETH0);
    if (ifindex == 0) {
        fprintf(stderr, "if_nametoindex(%s): %s\n", VETH0, strerror(errno));
        close(xsk_fd);
        munmap(umem_area, UMEM_SIZE);
        close(umem_fd);
        return 1;
    }

    struct sockaddr_xdp sxdp = {
        .sxdp_family   = AF_XDP,
        .sxdp_ifindex  = ifindex,
        .sxdp_queue_id = 0,
        .sxdp_flags    = XDP_COPY | XDP_USE_NEED_WAKEUP,
    };
    if (bind(xsk_fd, (struct sockaddr *)&sxdp, sizeof(sxdp)) < 0) {
        perror("bind AF_XDP");
        close(xsk_fd);
        munmap(umem_area, UMEM_SIZE);
        close(umem_fd);
        return 1;
    }

    /* Send handoff message + two fds via SCM_RIGHTS. */
    struct xsk_handoff_msg msg = {
        .magic      = XSK_HANDOFF_MAGIC,
        .frame_size = FRAME_SIZE,
        .num_frames = NUM_FRAMES,
        .reserved   = 0,
    };
    int fds[XSK_HANDOFF_NUM_FDS] = { xsk_fd, umem_fd };
    char cmsgbuf[CMSG_SPACE(sizeof(fds))];
    struct iovec iov  = { .iov_base = &msg, .iov_len = sizeof(msg) };
    struct msghdr mh  = {
        .msg_iov        = &iov,
        .msg_iovlen     = 1,
        .msg_control    = cmsgbuf,
        .msg_controllen = sizeof(cmsgbuf),
    };
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&mh);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type  = SCM_RIGHTS;
    cmsg->cmsg_len   = CMSG_LEN(sizeof(fds));
    memcpy(CMSG_DATA(cmsg), fds, sizeof(fds));

    int rc = (sendmsg(sock_fd, &mh, 0) < 0) ? 1 : 0;

    close(xsk_fd);
    munmap(umem_area, UMEM_SIZE);
    close(umem_fd);
    return rc;
}

/* ── Test cases ──────────────────────────────────────────────────────────── */

static void test_handoff_creates_valid_packet_io(void)
{
    TEST("xsk_inherited: handoff creates valid packet_io");

    if (geteuid() != 0)
        SKIP("not root");
    if (create_veth() != 0)
        SKIP("veth creation failed (no CAP_NET_ADMIN)");

    /* Create a socketpair for fd passing. */
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        destroy_veth();
        FAIL("socketpair failed");
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(sv[0]);
        close(sv[1]);
        destroy_veth();
        FAIL("fork failed");
    }

    if (pid == 0) {
        /* Child: mini-daemon */
        close(sv[0]);
        int r = mini_daemon(sv[1]);
        close(sv[1]);
        _exit(r);
    }

    /* Parent: rootless app */
    close(sv[1]);

    struct packet_io *io = packet_io_create_xsk_inherited(sv[0]);
    close(sv[0]);

    int wstatus;
    waitpid(pid, &wstatus, 0);
    int child_ok = WIFEXITED(wstatus) && WEXITSTATUS(wstatus) == 0;

    if (!child_ok) {
        if (io)
            packet_io_destroy(io);
        destroy_veth();
        FAIL("mini-daemon failed to send fds");
    }

    if (io == NULL) {
        destroy_veth();
        FAIL("packet_io_create_xsk_inherited returned NULL");
    }

    destroy_veth();
    packet_io_destroy(io);
    PASS();
}

static void test_inherited_recv_returns_empty(void)
{
    TEST("xsk_inherited: recv returns 0 on empty ring");

    if (geteuid() != 0)
        SKIP("not root");
    if (create_veth() != 0)
        SKIP("veth creation failed (no CAP_NET_ADMIN)");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        destroy_veth();
        FAIL("socketpair failed");
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(sv[0]);
        close(sv[1]);
        destroy_veth();
        FAIL("fork failed");
    }

    if (pid == 0) {
        close(sv[0]);
        _exit(mini_daemon(sv[1]));
    }

    close(sv[1]);

    struct packet_io *io = packet_io_create_xsk_inherited(sv[0]);
    close(sv[0]);

    int wstatus;
    waitpid(pid, &wstatus, 0);

    if (!io) {
        destroy_veth();
        FAIL("packet_io_create_xsk_inherited returned NULL");
    }

    /* No packets injected — recv must return 0. */
    void *pkt_data = NULL;
    uint32_t pkt_len = 0;
    int n = packet_io_recv(io, &pkt_data, &pkt_len);

    packet_io_destroy(io);
    destroy_veth();

    ASSERT_EQ(n, 0);
    PASS();
}

static void test_inherited_destroy_is_clean(void)
{
    TEST("xsk_inherited: destroy completes without crash");

    if (geteuid() != 0)
        SKIP("not root");
    if (create_veth() != 0)
        SKIP("veth creation failed (no CAP_NET_ADMIN)");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) {
        destroy_veth();
        FAIL("socketpair failed");
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(sv[0]);
        close(sv[1]);
        destroy_veth();
        FAIL("fork failed");
    }

    if (pid == 0) {
        close(sv[0]);
        _exit(mini_daemon(sv[1]));
    }

    close(sv[1]);

    struct packet_io *io = packet_io_create_xsk_inherited(sv[0]);
    close(sv[0]);

    waitpid(pid, NULL, 0);

    /* The destroy path must munmap rings + close fd without aborting. */
    packet_io_destroy(io);
    destroy_veth();

    PASS();
}

static void test_inherited_rejects_bad_magic(void)
{
    TEST("xsk_inherited: rejects handoff message with wrong magic");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0)
        FAIL("socketpair failed");

    pid_t pid = fork();
    if (pid < 0) {
        close(sv[0]);
        close(sv[1]);
        FAIL("fork failed");
    }

    if (pid == 0) {
        /* Send a corrupt handoff message (bad magic, no fds). */
        close(sv[0]);
        struct xsk_handoff_msg bad = {
            .magic      = 0xDEADBEEFU,
            .frame_size = FRAME_SIZE,
            .num_frames = NUM_FRAMES,
            .reserved   = 0,
        };
        /* Send without SCM_RIGHTS — packet_io_create_xsk_inherited must
         * reject it on magic check before touching any fds. */
        (void)send(sv[1], &bad, sizeof(bad), 0);
        close(sv[1]);
        _exit(0);
    }

    close(sv[1]);

    struct packet_io *io = packet_io_create_xsk_inherited(sv[0]);
    close(sv[0]);

    waitpid(pid, NULL, 0);

    /* Must return NULL — bad magic is rejected. */
    if (io != NULL) {
        packet_io_destroy(io);
        FAIL("should have rejected bad magic");
    }

    PASS();
}

/* ── Entry point ─────────────────────────────────────────────────────────── */

int main(void)
{
    printf("test_xsk_inherited:\n");

    test_inherited_rejects_bad_magic();     /* no root required */
    test_handoff_creates_valid_packet_io();
    test_inherited_recv_returns_empty();
    test_inherited_destroy_is_clean();

    int failures = tests_run - tests_passed - tests_skipped;
    printf("\n%d/%d tests passed, %d skipped\n",
           tests_passed, tests_run, tests_skipped);

    return (failures > 0) ? 1 : 0;
}
