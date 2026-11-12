/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * TCP Socket Interface for IEC 61850
 *
 * POSIX TCP sockets with keep-alive and TCP_NODELAY.
 * Replaces C++ TcpSocketConnection and TcpSocketListener.
 *
 * License: BSD-2-Clause
 */

#ifndef IEC61850_TCP_SOCKET_H
#define IEC61850_TCP_SOCKET_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Error codes */
#define IEC61850_TRANSPORT_OK              0
#define IEC61850_TRANSPORT_ERR_ARGS       (-1)
#define IEC61850_TRANSPORT_ERR_CONNECT    (-2)
#define IEC61850_TRANSPORT_ERR_SEND       (-3)
#define IEC61850_TRANSPORT_ERR_RECV       (-4)
#define IEC61850_TRANSPORT_ERR_TIMEOUT    (-5)
#define IEC61850_TRANSPORT_ERR_BIND       (-6)
#define IEC61850_TRANSPORT_ERR_LISTEN     (-7)
#define IEC61850_TRANSPORT_ERR_ACCEPT     (-8)
#define IEC61850_TRANSPORT_ERR_CLOSED     (-9)

/* TCP connection (client-side) */
typedef struct {
    int sockfd;
    bool connected;
} iec61850_tcp_conn_t;

/* TCP listener (server-side) */
typedef struct {
    int sockfd;
    bool listening;
} iec61850_tcp_listener_t;

void iec61850_tcp_conn_init(iec61850_tcp_conn_t *conn);

int iec61850_tcp_connect(iec61850_tcp_conn_t *conn, const char *host,
                          uint16_t port, int timeout_ms);

int iec61850_tcp_disconnect(iec61850_tcp_conn_t *conn);

int iec61850_tcp_send(iec61850_tcp_conn_t *conn, const uint8_t *data,
                       size_t len);

int iec61850_tcp_recv(iec61850_tcp_conn_t *conn, uint8_t *buffer,
                       size_t buflen, int timeout_ms);

/**
 * Receive exactly 'len' bytes from TCP, blocking until all received.
 * Handles fragmented reads with poll-based timeout.
 * @return number of bytes received, or negative error code
 */
int iec61850_tcp_recv_exact(iec61850_tcp_conn_t *conn, uint8_t *buffer,
                              size_t len, int timeout_ms);

/**
 * Receive a complete TPKT frame: reads 4-byte header, extracts length,
 * then reads the exact remaining payload.
 * @return total frame length, or negative error code
 */
int iec61850_tcp_recv_tpkt(iec61850_tcp_conn_t *conn, uint8_t *buffer,
                             size_t buflen, int timeout_ms);

bool iec61850_tcp_is_connected(const iec61850_tcp_conn_t *conn);

void iec61850_tcp_listener_init(iec61850_tcp_listener_t *listener);

int iec61850_tcp_listener_bind(iec61850_tcp_listener_t *listener,
                                uint16_t port);

int iec61850_tcp_listener_listen(iec61850_tcp_listener_t *listener,
                                  int backlog);

int iec61850_tcp_listener_accept(iec61850_tcp_listener_t *listener,
                                  iec61850_tcp_conn_t *client,
                                  int timeout_ms);

int iec61850_tcp_listener_close(iec61850_tcp_listener_t *listener);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_TCP_SOCKET_H */
