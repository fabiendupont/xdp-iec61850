/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * TCP Socket Implementation
 *
 * POSIX IPv4 TCP with keep-alive and TCP_NODELAY.
 *
 * License: BSD-3-Clause
 */


#include "transport/tcp_socket.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

void iec61850_tcp_conn_init(iec61850_tcp_conn_t *conn)
{
    if (conn != NULL) {
        conn->sockfd = -1;
        conn->connected = false;
    }
}

int iec61850_tcp_connect(iec61850_tcp_conn_t *conn, const char *host,
                          uint16_t port, int timeout_ms)
{
    int result;
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    char port_str[8];
    int flags;
    int optval;

    if ((conn == NULL) || (host == NULL)) {
        return IEC61850_TRANSPORT_ERR_ARGS;
    }

    (void)snprintf(port_str, sizeof(port_str), "%u", (unsigned)port);

    (void)memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if ((getaddrinfo(host, port_str, &hints, &res) != 0) || (res == NULL)) {
        return IEC61850_TRANSPORT_ERR_CONNECT;
    }

    conn->sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (conn->sockfd < 0) {
        freeaddrinfo(res);
        return IEC61850_TRANSPORT_ERR_CONNECT;
    }

    /* Set non-blocking for connect with timeout */
    flags = fcntl(conn->sockfd, F_GETFL, 0);
    (void)fcntl(conn->sockfd, F_SETFL, flags | O_NONBLOCK);

    result = connect(conn->sockfd, res->ai_addr, res->ai_addrlen);
    if ((result < 0) && (errno != EINPROGRESS)) {
        (void)close(conn->sockfd);
        conn->sockfd = -1;
        freeaddrinfo(res);
        return IEC61850_TRANSPORT_ERR_CONNECT;
    }

    freeaddrinfo(res);

    if (result < 0) {
        /* Wait for connection with timeout */
        struct pollfd pfd;
        pfd.fd = conn->sockfd;
        pfd.events = POLLOUT;

        int poll_ret = poll(&pfd, 1, timeout_ms);
        if (poll_ret <= 0) {
            (void)close(conn->sockfd);
            conn->sockfd = -1;
            return IEC61850_TRANSPORT_ERR_TIMEOUT;
        }

        /* Check for connection error */
        int so_error = 0;
        socklen_t err_len = sizeof(so_error);
        (void)getsockopt(conn->sockfd, SOL_SOCKET, SO_ERROR, &so_error, &err_len);
        if (so_error != 0) {
            (void)close(conn->sockfd);
            conn->sockfd = -1;
            return IEC61850_TRANSPORT_ERR_CONNECT;
        }
    }

    /* Set back to blocking */
    (void)fcntl(conn->sockfd, F_SETFL, flags);

    /* Enable TCP keep-alive */
    optval = 1;
    (void)setsockopt(conn->sockfd, SOL_SOCKET, SO_KEEPALIVE,
                     &optval, sizeof(optval));

    /* Disable Nagle's algorithm */
    optval = 1;
    (void)setsockopt(conn->sockfd, IPPROTO_TCP, TCP_NODELAY,
                     &optval, sizeof(optval));

    conn->connected = true;
    return IEC61850_TRANSPORT_OK;
}

int iec61850_tcp_disconnect(iec61850_tcp_conn_t *conn)
{
    if (conn == NULL) {
        return IEC61850_TRANSPORT_ERR_ARGS;
    }
    if (conn->sockfd >= 0) {
        (void)close(conn->sockfd);
        conn->sockfd = -1;
    }
    conn->connected = false;
    return IEC61850_TRANSPORT_OK;
}

int iec61850_tcp_send(iec61850_tcp_conn_t *conn, const uint8_t *data,
                       size_t len)
{
    if ((conn == NULL) || (data == NULL) || (!conn->connected)) {
        return IEC61850_TRANSPORT_ERR_ARGS;
    }

    ssize_t sent = send(conn->sockfd, data, len, MSG_NOSIGNAL);
    if (sent < 0) {
        return IEC61850_TRANSPORT_ERR_SEND;
    }

    return (int)sent;
}

int iec61850_tcp_recv(iec61850_tcp_conn_t *conn, uint8_t *buffer,
                       size_t buflen, int timeout_ms)
{
    if ((conn == NULL) || (buffer == NULL) || (!conn->connected)) {
        return IEC61850_TRANSPORT_ERR_ARGS;
    }

    struct pollfd pfd;
    pfd.fd = conn->sockfd;
    pfd.events = POLLIN;

    int poll_ret = poll(&pfd, 1, timeout_ms);
    if (poll_ret < 0) {
        return IEC61850_TRANSPORT_ERR_RECV;
    }
    if (poll_ret == 0) {
        return IEC61850_TRANSPORT_ERR_TIMEOUT;
    }

    ssize_t n = recv(conn->sockfd, buffer, buflen, 0);
    if (n < 0) {
        return IEC61850_TRANSPORT_ERR_RECV;
    }
    if (n == 0) {
        conn->connected = false;
        return IEC61850_TRANSPORT_ERR_CLOSED;
    }

    return (int)n;
}

int iec61850_tcp_recv_exact(iec61850_tcp_conn_t *conn, uint8_t *buffer,
                              size_t len, int timeout_ms)
{
    size_t received = 0;

    if ((conn == NULL) || (buffer == NULL) || (!conn->connected)) {
        return IEC61850_TRANSPORT_ERR_ARGS;
    }

    while (received < len) {
        struct pollfd pfd;
        pfd.fd = conn->sockfd;
        pfd.events = POLLIN;

        int poll_ret = poll(&pfd, 1, timeout_ms);
        if (poll_ret < 0) {
            return IEC61850_TRANSPORT_ERR_RECV;
        }
        if (poll_ret == 0) {
            return IEC61850_TRANSPORT_ERR_TIMEOUT;
        }

        ssize_t n = recv(conn->sockfd, &buffer[received], len - received, 0);
        if (n < 0) {
            return IEC61850_TRANSPORT_ERR_RECV;
        }
        if (n == 0) {
            conn->connected = false;
            return IEC61850_TRANSPORT_ERR_CLOSED;
        }
        received += (size_t)n;
    }

    return (int)received;
}

int iec61850_tcp_recv_tpkt(iec61850_tcp_conn_t *conn, uint8_t *buffer,
                             size_t buflen, int timeout_ms)
{
    int ret;

    if ((conn == NULL) || (buffer == NULL)) {
        return IEC61850_TRANSPORT_ERR_ARGS;
    }
    if (buflen < 4U) {
        return IEC61850_TRANSPORT_ERR_ARGS;
    }

    /* Read 4-byte TPKT header */
    ret = iec61850_tcp_recv_exact(conn, buffer, 4U, timeout_ms);
    if (ret < 0) { return ret; }

    /* Extract total TPKT frame length */
    uint16_t total_len = (uint16_t)((uint16_t)buffer[2] << 8U) |
                         (uint16_t)buffer[3];
    if ((total_len < 4U) || ((size_t)total_len > buflen)) {
        return IEC61850_TRANSPORT_ERR_RECV;
    }

    /* Read remaining payload */
    size_t remaining = (size_t)total_len - 4U;
    if (remaining > 0U) {
        ret = iec61850_tcp_recv_exact(conn, &buffer[4], remaining, timeout_ms);
        if (ret < 0) { return ret; }
    }

    return (int)total_len;
}

bool iec61850_tcp_is_connected(const iec61850_tcp_conn_t *conn)
{
    if (conn == NULL) {
        return false;
    }
    return conn->connected;
}

/* ========================================================================
 * Listener
 * ======================================================================== */

void iec61850_tcp_listener_init(iec61850_tcp_listener_t *listener)
{
    if (listener != NULL) {
        listener->sockfd = -1;
        listener->listening = false;
    }
}

int iec61850_tcp_listener_bind(iec61850_tcp_listener_t *listener,
                                uint16_t port)
{
    struct sockaddr_in addr;
    int optval;

    if (listener == NULL) {
        return IEC61850_TRANSPORT_ERR_ARGS;
    }

    listener->sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (listener->sockfd < 0) {
        return IEC61850_TRANSPORT_ERR_BIND;
    }

    optval = 1;
    (void)setsockopt(listener->sockfd, SOL_SOCKET, SO_REUSEADDR,
                     &optval, sizeof(optval));

    (void)memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);

    if (bind(listener->sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        (void)close(listener->sockfd);
        listener->sockfd = -1;
        return IEC61850_TRANSPORT_ERR_BIND;
    }

    return IEC61850_TRANSPORT_OK;
}

int iec61850_tcp_listener_listen(iec61850_tcp_listener_t *listener,
                                  int backlog)
{
    if ((listener == NULL) || (listener->sockfd < 0)) {
        return IEC61850_TRANSPORT_ERR_ARGS;
    }

    if (listen(listener->sockfd, backlog) < 0) {
        return IEC61850_TRANSPORT_ERR_LISTEN;
    }

    listener->listening = true;
    return IEC61850_TRANSPORT_OK;
}

int iec61850_tcp_listener_accept(iec61850_tcp_listener_t *listener,
                                  iec61850_tcp_conn_t *client,
                                  int timeout_ms)
{
    int optval;

    if ((listener == NULL) || (client == NULL) || (!listener->listening)) {
        return IEC61850_TRANSPORT_ERR_ARGS;
    }

    struct pollfd pfd;
    pfd.fd = listener->sockfd;
    pfd.events = POLLIN;

    int poll_ret = poll(&pfd, 1, timeout_ms);
    if (poll_ret <= 0) {
        return IEC61850_TRANSPORT_ERR_TIMEOUT;
    }

    int fd = accept(listener->sockfd, NULL, NULL);
    if (fd < 0) {
        return IEC61850_TRANSPORT_ERR_ACCEPT;
    }

    /* TCP_NODELAY on accepted connection */
    optval = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval));

    client->sockfd = fd;
    client->connected = true;
    return IEC61850_TRANSPORT_OK;
}

int iec61850_tcp_listener_close(iec61850_tcp_listener_t *listener)
{
    if (listener == NULL) {
        return IEC61850_TRANSPORT_ERR_ARGS;
    }
    if (listener->sockfd >= 0) {
        (void)close(listener->sockfd);
        listener->sockfd = -1;
    }
    listener->listening = false;
    return IEC61850_TRANSPORT_OK;
}
