/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * DIAGNOSTIC ARTIFACT ONLY — WP-ms10-investigation
 *
 * Minimal TCP logging proxy (no root needed): listens on 127.0.0.1:LPORT,
 * forwards to 127.0.0.1:RPORT, hexdumps both directions.
 * Clean-room wire observation only.
 *
 *   ./logproxy <lport> <rport>
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

struct pump_ctx {
    int src_fd;
    int dst_fd;
    const char *label;
};

static void dump(const char *dir, const unsigned char *b, size_t n)
{
    printf("--- %s (%zu bytes) ---\n", dir, n);
    for (size_t i = 0; i < n; i++) {
        printf("%02X ", b[i]);
        if ((i % 16) == 15) printf("\n");
    }
    printf("\n");
    fflush(stdout);
}

static void *pump(void *arg)
{
    struct pump_ctx *ctx = arg;
    unsigned char buf[8192];
    for (;;) {
        ssize_t n = recv(ctx->src_fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        dump(ctx->label, buf, (size_t)n);
        ssize_t off = 0;
        while (off < n) {
            ssize_t w = send(ctx->dst_fd, buf + off, (size_t)(n - off), 0);
            if (w <= 0) { goto out; }
            off += w;
        }
    }
out:
    /* unblock the peer pump so the proxy accepts new connections */
    shutdown(ctx->src_fd, SHUT_RDWR);
    shutdown(ctx->dst_fd, SHUT_RDWR);
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s <lport> <rport>\n", argv[0]);
        return 1;
    }
    int lport = atoi(argv[1]);
    int rport = atoi(argv[2]);

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    (void)setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in la = {0};
    la.sin_family = AF_INET;
    la.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    la.sin_port = htons((uint16_t)lport);
    if (bind(lfd, (struct sockaddr *)&la, sizeof(la)) < 0) { perror("bind"); return 1; }
    if (listen(lfd, 1) < 0) { perror("listen"); return 1; }

    printf("proxy listening on %d -> %d\n", lport, rport);
    fflush(stdout);

    for (;;) {
        int cfd = accept(lfd, NULL, NULL);
        if (cfd < 0) continue;

        int rfd = socket(AF_INET, SOCK_STREAM, 0);
        struct sockaddr_in ra = {0};
        ra.sin_family = AF_INET;
        ra.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ra.sin_port = htons((uint16_t)rport);
        if (connect(rfd, (struct sockaddr *)&ra, sizeof(ra)) < 0) {
            perror("connect remote");
            close(cfd);
            continue;
        }

        struct pump_ctx c2s = { .src_fd = cfd, .dst_fd = rfd, .label = "C->S (client to server)" };
        struct pump_ctx s2c = { .src_fd = rfd, .dst_fd = cfd, .label = "S->C (server to client)" };
        pthread_t t1, t2;
        pthread_create(&t1, NULL, pump, &c2s);
        pthread_create(&t2, NULL, pump, &s2c);
        pthread_join(t1, NULL);
        pthread_join(t2, NULL);
        close(cfd);
        close(rfd);
        printf("=== connection closed ===\n");
        fflush(stdout);
    }
    return 0;
}
