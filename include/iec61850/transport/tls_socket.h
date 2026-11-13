/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * TLS Socket Interface for IEC 61850 (IEC 62351-4)
 *
 * TLS layered between TPKT and TCP for MMS associations. Mirrors the
 * tcp_socket.h function family so the ISO stack can dispatch to
 * either; the MMS client/server select TLS vs plain TCP at
 * connection setup (default port 3782 for TLS MMS).
 *
 * Certificate-policy modes (mutually exclusive — the single
 * exclusivity under the default-on feature policy):
 * - IEC61850_TLS_MODE_COMPATIBLE: accept any certificate chain the
 *   trust store validates (interoperability default)
 * - IEC61850_TLS_MODE_STRICT_62351: enforce the IEC 62351-4
 *   certificate profile (key types/sizes, extensions) on peer
 *   certificates
 * - IEC61850_TLS_MODE_SPIFFE: accept SPIFFE X.509-SVIDs (URI SAN
 *   identity); peer identity is the spiffe:// URI
 *
 * FROZEN INTERFACE (WP-S3). Implementations change; signatures do not.
 */

#ifndef IEC61850_TLS_SOCKET_H
#define IEC61850_TLS_SOCKET_H

#include "transport/tcp_socket.h"
#include "security/cert_provider.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IEC61850_TLS_MMS_PORT_DEFAULT 3782U

typedef enum {
    IEC61850_TLS_MODE_COMPATIBLE = 0,
    IEC61850_TLS_MODE_STRICT_62351 = 1,
    IEC61850_TLS_MODE_SPIFFE = 2
} iec61850_tls_mode_t;

/* TLS connection (client-side). The TCP member carries the socket;
 * the OpenSSL state is opaque here. */
typedef struct {
    iec61850_tcp_conn_t tcp;
    void *ssl;                     /* SSL* (OpenSSL, opaque) */
    void *ctx;                     /* SSL_CTX* (OpenSSL, opaque) */
    bool handshake_done;
    iec61850_tls_mode_t mode;
} iec61850_tls_conn_t;

/* TLS listener (server-side). */
typedef struct {
    iec61850_tcp_listener_t tcp;
    void *ctx;                     /* SSL_CTX* (OpenSSL, opaque) */
    iec61850_tls_mode_t mode;
} iec61850_tls_listener_t;

void iec61850_tls_conn_init(iec61850_tls_conn_t *conn);

/**
 * Connect and perform the TLS handshake.
 * @param provider  Credential source (may be NULL: no client
 *                  certificate, system trust — opportunistic).
 * @param mode      Certificate-policy mode for the handshake.
 */
int iec61850_tls_connect(iec61850_tls_conn_t *conn, const char *host,
                          uint16_t port, int timeout_ms,
                          const iec61850_cert_provider_t *provider,
                          iec61850_tls_mode_t mode);

int iec61850_tls_disconnect(iec61850_tls_conn_t *conn);

int iec61850_tls_send(iec61850_tls_conn_t *conn, const uint8_t *data,
                       size_t len);

int iec61850_tls_recv(iec61850_tls_conn_t *conn, uint8_t *buffer,
                       size_t buflen, int timeout_ms);

int iec61850_tls_recv_exact(iec61850_tls_conn_t *conn, uint8_t *buffer,
                             size_t len, int timeout_ms);

int iec61850_tls_recv_tpkt(iec61850_tls_conn_t *conn, uint8_t *buffer,
                            size_t buflen, int timeout_ms);

bool iec61850_tls_is_connected(const iec61850_tls_conn_t *conn);

void iec61850_tls_listener_init(iec61850_tls_listener_t *listener);

/**
 * Bind + prepare the server-side TLS context.
 * @param provider  Server certificate/key source (required for a
 *                  functional listener; NULL returns -EINVAL).
 */
int iec61850_tls_listener_bind(iec61850_tls_listener_t *listener,
                                uint16_t port,
                                const iec61850_cert_provider_t *provider,
                                iec61850_tls_mode_t mode);

/**
 * Accept one connection and complete the server-side handshake.
 * @param conn Out: the accepted TLS connection.
 */
int iec61850_tls_listener_accept(iec61850_tls_listener_t *listener,
                                  iec61850_tls_conn_t *conn,
                                  int timeout_ms);

int iec61850_tls_listener_close(iec61850_tls_listener_t *listener);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_TLS_SOCKET_H */
