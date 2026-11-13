/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * TLS Socket Interface for IEC 61850 (IEC 62351-4)
 *
 * WP-S3 scaffold: implemented by WP-3b (tls-mms) against the frozen
 * interface in include/iec61850/transport/tls_socket.h.
 */

#include "transport/tls_socket.h"

#include <errno.h>

/* Placeholder until WP-3b implements this module. */
typedef int iec61850_tls_scaffold_placeholder_t;

void iec61850_tls_conn_init(iec61850_tls_conn_t *conn)
{
    if (conn == NULL) { return; }
    iec61850_tcp_conn_init(&conn->tcp);
    conn->ssl = NULL;
    conn->ctx = NULL;
    conn->handshake_done = false;
    conn->mode = IEC61850_TLS_MODE_COMPATIBLE;
}

int iec61850_tls_connect(iec61850_tls_conn_t *conn, const char *host,
                          uint16_t port, int timeout_ms,
                          const iec61850_cert_provider_t *provider,
                          iec61850_tls_mode_t mode)
{
    (void)host;
    (void)port;
    (void)timeout_ms;
    (void)provider;
    (void)mode;
    if (conn == NULL) { return -EINVAL; }
    return -ENOSYS; /* implemented by WP-3b */
}

int iec61850_tls_disconnect(iec61850_tls_conn_t *conn)
{
    (void)conn;
    return -ENOSYS; /* implemented by WP-3b */
}

int iec61850_tls_send(iec61850_tls_conn_t *conn, const uint8_t *data,
                       size_t len)
{
    (void)data;
    (void)len;
    if (conn == NULL) { return -EINVAL; }
    return -ENOSYS; /* implemented by WP-3b */
}

int iec61850_tls_recv(iec61850_tls_conn_t *conn, uint8_t *buffer,
                       size_t buflen, int timeout_ms)
{
    (void)buffer;
    (void)buflen;
    (void)timeout_ms;
    if (conn == NULL) { return -EINVAL; }
    return -ENOSYS; /* implemented by WP-3b */
}

int iec61850_tls_recv_exact(iec61850_tls_conn_t *conn, uint8_t *buffer,
                             size_t len, int timeout_ms)
{
    (void)buffer;
    (void)len;
    (void)timeout_ms;
    if (conn == NULL) { return -EINVAL; }
    return -ENOSYS; /* implemented by WP-3b */
}

int iec61850_tls_recv_tpkt(iec61850_tls_conn_t *conn, uint8_t *buffer,
                            size_t buflen, int timeout_ms)
{
    (void)buffer;
    (void)buflen;
    (void)timeout_ms;
    if (conn == NULL) { return -EINVAL; }
    return -ENOSYS; /* implemented by WP-3b */
}

bool iec61850_tls_is_connected(const iec61850_tls_conn_t *conn)
{
    if (conn == NULL) { return false; }
    return conn->handshake_done;
}

void iec61850_tls_listener_init(iec61850_tls_listener_t *listener)
{
    if (listener == NULL) { return; }
    iec61850_tcp_listener_init(&listener->tcp);
    listener->ctx = NULL;
    listener->mode = IEC61850_TLS_MODE_COMPATIBLE;
}

int iec61850_tls_listener_bind(iec61850_tls_listener_t *listener,
                                uint16_t port,
                                const iec61850_cert_provider_t *provider,
                                iec61850_tls_mode_t mode)
{
    (void)port;
    (void)provider;
    (void)mode;
    if (listener == NULL) { return -EINVAL; }
    return -ENOSYS; /* implemented by WP-3b */
}

int iec61850_tls_listener_accept(iec61850_tls_listener_t *listener,
                                  iec61850_tls_conn_t *conn,
                                  int timeout_ms)
{
    (void)conn;
    (void)timeout_ms;
    if (listener == NULL) { return -EINVAL; }
    return -ENOSYS; /* implemented by WP-3b */
}

int iec61850_tls_listener_close(iec61850_tls_listener_t *listener)
{
    (void)listener;
    return -ENOSYS; /* implemented by WP-3b */
}
