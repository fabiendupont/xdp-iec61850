/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * TLS Socket Implementation for IEC 61850 (IEC 62351-4)
 *
 * TLS layered between TPKT and TCP for MMS associations, per the
 * frozen interface in include/iec61850/transport/tls_socket.h
 * (WP-S3). TLS 1.2 is the minimum protocol version (IEC 62351-4).
 *
 * Certificate-policy modes (applied to the peer certificate after
 * the handshake completes):
 * - COMPATIBLE: chain validation against the configured trust
 *   store; when no trust store is configured the handshake is
 *   opportunistic (encrypted, not authenticated) — the
 *   interoperability default.
 * - STRICT_62351: chain validation plus the IEC 62351-4 profile
 *   checks on the peer certificate — key type and size (RSA >=
 *   2048 bits, EC >= 256 bits, Ed25519) and the validity window
 *   (notBefore <= now <= notAfter).
 * - SPIFFE: chain validation plus X.509-SVID shape — the
 *   certificate must carry a spiffe:// URI SAN (the workload
 *   identity); peer identity is that URI.
 *
 * Credential handling (WP-3a provider): credentials are read via
 * provider->get() and copied into the SSL_CTX at connect()/bind()
 * time. A provider refresh() therefore applies to NEW associations
 * only; mid-session renegotiation is out of scope.
 *
 * Timeout semantics mirror tcp_socket.c: the handshake and each
 * recv() call are bounded by poll()-based deadlines; send() blocks
 * until the record is written (like a blocking send(2)).
 *
 * Error mapping: TCP connect failures return the tcp layer's
 * IEC61850_TRANSPORT_ERR_CONNECT/TIMEOUT; handshake failures
 * (protocol, verification, policy) map to
 * IEC61850_TRANSPORT_ERR_CONNECT; send/recv failures map to
 * IEC61850_TRANSPORT_ERR_SEND/RECV/TIMEOUT/CLOSED.
 *
 * Compiled only with -Denable_security (IEC61850_SECURITY_ENABLED).
 *
 * License: BSD-2-Clause
 */

#include "transport/tls_socket.h"

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* ========================================================================
 * SIGPIPE suppression
 * ======================================================================== */

/*
 * OpenSSL's socket BIO writes with send(2) without MSG_NOSIGNAL, so
 * a peer that closes mid-record would raise SIGPIPE and terminate
 * the process. tcp_socket.c passes MSG_NOSIGNAL per call; for the
 * OpenSSL record layer the signal is blocked around each SSL
 * operation, any instance raised while blocked is consumed, and the
 * caller's original mask is restored — a vanished peer then
 * surfaces as an ordinary -EPIPE write error instead. No
 * process-global handler is installed.
 */
static void tls_sigpipe_block(sigset_t *old_mask)
{
    sigset_t block;

    (void)sigemptyset(&block);
    (void)sigaddset(&block, SIGPIPE);
    (void)pthread_sigmask(SIG_BLOCK, &block, old_mask);
}

static void tls_sigpipe_restore(const sigset_t *old_mask)
{
    sigset_t pipe_set;
    struct timespec zero = {0, 0};

    (void)sigemptyset(&pipe_set);
    (void)sigaddset(&pipe_set, SIGPIPE);
    /* Drain a SIGPIPE generated while blocked (peer gone). */
    while (sigtimedwait(&pipe_set, NULL, &zero) == SIGPIPE) {
        /* consumed */
    }
    (void)pthread_sigmask(SIG_SETMASK, old_mask, NULL);
}

/* ========================================================================
 * Time helpers (monotonic deadlines)
 * ======================================================================== */

static int64_t mono_ms(void)
{
    struct timespec ts;

    (void)clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((int64_t)ts.tv_sec * 1000) + (int64_t)(ts.tv_nsec / 1000000);
}

/* Clamp a remaining-deadline delta to a poll() timeout. */
static int poll_timeout(int64_t remaining_ms)
{
    if (remaining_ms <= 0) { return 0; }
    if (remaining_ms > (int64_t)INT_MAX) { return INT_MAX; }
    return (int)remaining_ms;
}

/* ========================================================================
 * SSL_CTX credential loading (from provider PEM, copied at setup)
 * ======================================================================== */

/* Load the leaf + extra chain certificates and the private key.
 * Either PEM may be NULL (component not configured); a leaf without
 * a key (or vice versa) is rejected. Returns 0 or negative errno. */
static int ctx_load_cert_key(SSL_CTX *ctx, const char *cert_pem,
                               const char *key_pem)
{
    BIO *bio = NULL;
    X509 *leaf = NULL;
    EVP_PKEY *pkey = NULL;
    int ret = -EINVAL;
    int n_chain = 0;

    if (ctx == NULL) { return -EINVAL; }
    if ((cert_pem == NULL) && (key_pem == NULL)) { return 0; }
    if ((cert_pem == NULL) || (key_pem == NULL)) { return -EINVAL; }

    /* Leaf certificate (AUX keeps any trust attributes) */
    bio = BIO_new_mem_buf(cert_pem, -1);
    if (bio == NULL) { return -ENOMEM; }
    leaf = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL);
    if (leaf == NULL) { goto done; }
    if (SSL_CTX_use_certificate(ctx, leaf) != 1) { goto done; }
    X509_free(leaf);
    leaf = NULL;

    /* Extra chain certificates (ctx takes ownership on success) */
    for (;;) {
        X509 *chain = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (chain == NULL) { break; }
        if (SSL_CTX_add_extra_chain_cert(ctx, chain) != 1) {
            X509_free(chain);
            goto done;
        }
        n_chain++;
    }
    ERR_clear_error(); /* PEM loop ends with a no-START-line error */
    BIO_free(bio);
    bio = NULL;

    /* Private key */
    bio = BIO_new_mem_buf(key_pem, -1);
    if (bio == NULL) { ret = -ENOMEM; goto done; }
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    if (pkey == NULL) { goto done; }
    if (SSL_CTX_use_PrivateKey(ctx, pkey) != 1) { goto done; }
    if (SSL_CTX_check_private_key(ctx) != 1) { goto done; }

    (void)n_chain;
    ret = 0;

done:
    BIO_free(bio);
    X509_free(leaf);
    EVP_PKEY_free(pkey);
    if (ret != 0) { ERR_clear_error(); }
    return ret;
}

/* Load every PEM certificate in trust_pem into the ctx trust store.
 * Returns 0 (at least one CA loaded) or negative errno. */
static int ctx_load_trust(SSL_CTX *ctx, const char *trust_pem)
{
    BIO *bio = NULL;
    X509_STORE *store;
    int count = 0;

    if ((ctx == NULL) || (trust_pem == NULL)) { return -EINVAL; }

    bio = BIO_new_mem_buf(trust_pem, -1);
    if (bio == NULL) { return -ENOMEM; }

    store = SSL_CTX_get_cert_store(ctx);
    if (store == NULL) {
        BIO_free(bio);
        return -ENOMEM;
    }

    for (;;) {
        X509 *ca = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (ca == NULL) { break; }
        if (X509_STORE_add_cert(store, ca) != 1) {
            X509_free(ca);
            BIO_free(bio);
            ERR_clear_error();
            return -EINVAL;
        }
        X509_free(ca);
        count++;
    }

    BIO_free(bio);
    ERR_clear_error();
    return (count > 0) ? 0 : -EINVAL;
}

/*
 * Build a client SSL_CTX from the provider's current credentials.
 * provider may be NULL (no client certificate, opportunistic).
 * Outputs *verify_enabled: whether chain verification is active.
 */
static SSL_CTX *ctx_build_client(const iec61850_cert_provider_t *provider,
                                  iec61850_tls_mode_t mode,
                                  bool *verify_enabled)
{
    SSL_CTX *ctx = NULL;
    const char *cert_pem = NULL;
    const char *key_pem = NULL;
    const char *trust_pem = NULL;
    size_t cert_len = 0;
    size_t key_len = 0;
    size_t trust_len = 0;
    bool have_trust = false;

    *verify_enabled = false;

    ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == NULL) { return NULL; }
    (void)SSL_CTX_set_min_proto_version(ctx, (int)TLS1_2_VERSION);
    /*
     * OpenSSL's generic certificate-security floor (level 2 rejects
     * e.g. RSA-1024 end-entity keys) is disabled: the certificate
     * policy here is the IEC 62351-4 mode — COMPATIBLE interoperates
     * with legacy peer credentials, STRICT_62351 enforces the
     * profile (key type/size, validity) explicitly.
     */
    SSL_CTX_set_security_level(ctx, 0);

    if (provider != NULL) {
        int ret = provider->get((iec61850_cert_provider_t *)provider,
                                &cert_pem, &cert_len, &key_pem, &key_len,
                                &trust_pem, &trust_len);
        if (ret != 0) {
            SSL_CTX_free(ctx);
            return NULL;
        }
    }

    if ((cert_pem != NULL) && (key_pem != NULL)) {
        if (ctx_load_cert_key(ctx, cert_pem, key_pem) != 0) {
            SSL_CTX_free(ctx);
            return NULL;
        }
    }

    if (trust_pem != NULL) {
        if (ctx_load_trust(ctx, trust_pem) == 0) {
            have_trust = true;
        } else {
            /* A configured trust store that cannot be parsed is a
             * configuration error, not an opportunity to fall back
             * to opportunistic mode. */
            SSL_CTX_free(ctx);
            return NULL;
        }
    }

    /*
     * Verification policy:
     * - COMPATIBLE: verify against the trust store when one is
     *   configured; without one, opportunistic (no verification).
     * - STRICT_62351 / SPIFFE: chain authentication is mandatory —
     *   verification is always active; without a trust store the
     *   handshake cannot establish a chain and fails.
     */
    if (mode == IEC61850_TLS_MODE_COMPATIBLE) {
        if (have_trust) {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
            *verify_enabled = true;
        } else {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
        }
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
        *verify_enabled = true;
    }

    return ctx;
}

/*
 * Build a server SSL_CTX from the provider's server certificate
 * (required). When a trust store is configured, client
 * certificates are requested and verified when presented
 * (SSL_VERIFY_PEER without FAIL_IF_NO_PEER_CERT: IEC 62351-4
 * mutual authentication with deployments that still allow
 * anonymous clients to be rejected by the mode policy).
 */
static SSL_CTX *ctx_build_server(const iec61850_cert_provider_t *provider,
                                  bool *verify_enabled)
{
    SSL_CTX *ctx = NULL;
    const char *cert_pem = NULL;
    const char *key_pem = NULL;
    const char *trust_pem = NULL;
    size_t cert_len = 0;
    size_t key_len = 0;
    size_t trust_len = 0;

    *verify_enabled = false;

    if (provider == NULL) { return NULL; }

    ctx = SSL_CTX_new(TLS_server_method());
    if (ctx == NULL) { return NULL; }
    (void)SSL_CTX_set_min_proto_version(ctx, (int)TLS1_2_VERSION);
    /* See ctx_build_client(): certificate policy is the mode's job
     * (IEC 62351-4), not OpenSSL's generic key-size floor. */
    SSL_CTX_set_security_level(ctx, 0);

    if (provider->get((iec61850_cert_provider_t *)provider,
                      &cert_pem, &cert_len, &key_pem, &key_len,
                      &trust_pem, &trust_len) != 0) {
        SSL_CTX_free(ctx);
        return NULL;
    }

    if ((cert_pem == NULL) || (key_pem == NULL)) {
        SSL_CTX_free(ctx);
        return NULL;
    }
    if (ctx_load_cert_key(ctx, cert_pem, key_pem) != 0) {
        SSL_CTX_free(ctx);
        return NULL;
    }

    if (trust_pem != NULL) {
        if (ctx_load_trust(ctx, trust_pem) == 0) {
            SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
            *verify_enabled = true;
        } else {
            SSL_CTX_free(ctx);
            return NULL;
        }
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    return ctx;
}

/* ========================================================================
 * Certificate-policy checks (IEC 62351-4 / SPIFFE X.509-SVID)
 * ======================================================================== */

/* IEC 62351-4 profile: key type/size and validity window.
 * Returns 0 when the profile is met, -EACCES otherwise. */
static int cert_check_62351_profile(const X509 *cert)
{
    EVP_PKEY *pkey = X509_get0_pubkey(cert);
    int key_id;
    int bits;
    const ASN1_TIME *not_before;
    const ASN1_TIME *not_after;

    if (pkey == NULL) { return -EACCES; }

    key_id = EVP_PKEY_base_id(pkey);
    bits = EVP_PKEY_bits(pkey);

    switch (key_id) {
        case EVP_PKEY_RSA:
            if (bits < 2048) { return -EACCES; }
            break;
        case EVP_PKEY_EC:
            if (bits < 256) { return -EACCES; }
            break;
        case EVP_PKEY_ED25519:
            /* 128-bit security, EdDSA curve order 256 bits */
            break;
        default:
            /* DSA, DH and exotic key types are outside the
             * IEC 62351-4 profile. */
            return -EACCES;
    }

    /* Validity window: notBefore <= now <= notAfter */
    not_before = X509_get0_notBefore(cert);
    not_after = X509_get0_notAfter(cert);
    if ((not_before == NULL) || (not_after == NULL)) { return -EACCES; }
    if (X509_cmp_current_time(not_before) > 0) { return -EACCES; }
    if (X509_cmp_current_time(not_after) < 0) { return -EACCES; }

    return 0;
}

/* SPIFFE X.509-SVID shape: a spiffe:// URI SAN must be present.
 * Returns 0 when found, -EACCES otherwise. */
static int cert_check_spiffe_uri(const X509 *cert)
{
    GENERAL_NAMES *names = NULL;
    int count;
    int i;
    int ret = -EACCES;
    static const char prefix[] = "spiffe://";
    const size_t prefix_len = sizeof(prefix) - 1U;

    names = (GENERAL_NAMES *)X509_get_ext_d2i(cert, NID_subject_alt_name,
                                               NULL, NULL);
    if (names == NULL) { return -EACCES; }

    count = sk_GENERAL_NAME_num(names);
    for (i = 0; i < count; i++) {
        GENERAL_NAME *gen = sk_GENERAL_NAME_value(names, i);
        const ASN1_IA5STRING *uri;

        if ((gen == NULL) || (gen->type != GEN_URI)) { continue; }
        uri = gen->d.uniformResourceIdentifier;
        if (uri == NULL) { continue; }
        if (((size_t)uri->length >= prefix_len) &&
            (memcmp(uri->data, prefix, prefix_len) == 0)) {
            ret = 0;
            break;
        }
    }

    GENERAL_NAMES_free(names);
    return ret;
}

/*
 * Post-handshake peer-certificate policy check.
 * Returns 0, or -EACCES when the peer fails the configured mode.
 */
static int tls_check_peer_policy(SSL *ssl, iec61850_tls_mode_t mode,
                                  bool verify_enabled)
{
    X509 *peer = NULL;
    int ret = 0;

    if (verify_enabled) {
        if (SSL_get_verify_result(ssl) != X509_V_OK) { return -EACCES; }
    }

    peer = SSL_get1_peer_certificate(ssl);
    if (peer == NULL) {
        /* No peer certificate: acceptable only in opportunistic
         * COMPATIBLE handshakes; the strict profiles require an
         * authenticated peer. */
        if (mode != IEC61850_TLS_MODE_COMPATIBLE) { return -EACCES; }
        return 0;
    }

    if (mode == IEC61850_TLS_MODE_STRICT_62351) {
        ret = cert_check_62351_profile(peer);
    } else if (mode == IEC61850_TLS_MODE_SPIFFE) {
        ret = cert_check_spiffe_uri(peer);
    } else {
        ret = 0;
    }

    X509_free(peer);
    return ret;
}

/* ========================================================================
 * Handshake (poll-driven, bounded by timeout_ms)
 * ======================================================================== */

static int set_fd_nonblocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) { return -1; }
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) { return -1; }
    return 0;
}

/*
 * Drive SSL_connect/SSL_accept to completion with a poll-based
 * deadline. The socket is kept non-blocking for the lifetime of
 * the connection so recv() timeouts mirror tcp_socket semantics.
 * Returns 0, or a negative IEC61850_TRANSPORT_ERR_* code.
 */
static int tls_do_handshake(iec61850_tls_conn_t *conn, int timeout_ms,
                              bool client_role)
{
    SSL *ssl = (SSL *)conn->ssl;
    int64_t deadline = mono_ms() + (int64_t)timeout_ms;

    if (set_fd_nonblocking(conn->tcp.sockfd) != 0) {
        return IEC61850_TRANSPORT_ERR_CONNECT;
    }

    for (;;) {
        int ret;
        int err;
        short events = 0;
        struct pollfd pfd;
        int poll_ret;
        int64_t remaining;
        sigset_t old_mask;

        tls_sigpipe_block(&old_mask);
        ret = client_role ? SSL_connect(ssl) : SSL_accept(ssl);
        tls_sigpipe_restore(&old_mask);

        if (ret == 1) { break; }

        err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_WANT_READ) {
            events = POLLIN;
        } else if (err == SSL_ERROR_WANT_WRITE) {
            events = POLLOUT;
        } else {
            /* Protocol error, certificate rejection or peer abort */
            ERR_clear_error();
            return IEC61850_TRANSPORT_ERR_CONNECT;
        }

        remaining = deadline - mono_ms();
        if (remaining <= 0) {
            ERR_clear_error();
            return IEC61850_TRANSPORT_ERR_TIMEOUT;
        }

        pfd.fd = conn->tcp.sockfd;
        pfd.events = events;
        pfd.revents = 0;
        poll_ret = poll(&pfd, 1, poll_timeout(remaining));
        if (poll_ret < 0) {
            ERR_clear_error();
            return IEC61850_TRANSPORT_ERR_CONNECT;
        }
        if (poll_ret == 0) {
            ERR_clear_error();
            return IEC61850_TRANSPORT_ERR_TIMEOUT;
        }
    }

    conn->handshake_done = true;
    return 0;
}

/* ========================================================================
 * Client connection
 * ======================================================================== */

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
    SSL_CTX *ctx = NULL;
    SSL *ssl = NULL;
    bool verify_enabled = false;
    int ret;

    if (conn == NULL) { return IEC61850_TRANSPORT_ERR_ARGS; }
    if (host == NULL) { return IEC61850_TRANSPORT_ERR_ARGS; }
    if ((mode != IEC61850_TLS_MODE_COMPATIBLE) &&
        (mode != IEC61850_TLS_MODE_STRICT_62351) &&
        (mode != IEC61850_TLS_MODE_SPIFFE)) {
        return IEC61850_TRANSPORT_ERR_ARGS;
    }

    /* Clean slate (an existing association must be dropped first) */
    if ((conn->ssl != NULL) || (conn->ctx != NULL) ||
        (conn->tcp.sockfd >= 0)) {
        return IEC61850_TRANSPORT_ERR_ARGS;
    }

    /* Credentials are snapshotted here: a later provider refresh()
     * applies to new associations only. */
    ctx = ctx_build_client(provider, mode, &verify_enabled);
    if (ctx == NULL) { return IEC61850_TRANSPORT_ERR_CONNECT; }

    /* TCP connect (poll-based timeout, keep-alive, TCP_NODELAY) */
    ret = iec61850_tcp_connect(&conn->tcp, host, port, timeout_ms);
    if (ret != 0) {
        SSL_CTX_free(ctx);
        return ret;
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL) {
        SSL_CTX_free(ctx);
        (void)iec61850_tcp_disconnect(&conn->tcp);
        return IEC61850_TRANSPORT_ERR_CONNECT;
    }
    if (SSL_set_fd(ssl, conn->tcp.sockfd) != 1) {
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        (void)iec61850_tcp_disconnect(&conn->tcp);
        return IEC61850_TRANSPORT_ERR_CONNECT;
    }

    conn->ssl = (void *)ssl;
    conn->ctx = (void *)ctx;
    conn->mode = mode;

    ret = tls_do_handshake(conn, timeout_ms, true);
    if (ret != 0) { goto fail; }

    /* Certificate-policy check for the negotiated peer */
    if (tls_check_peer_policy(ssl, mode, verify_enabled) != 0) {
        ret = IEC61850_TRANSPORT_ERR_CONNECT;
        goto fail;
    }

    return IEC61850_TRANSPORT_OK;

fail:
    ERR_clear_error();
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    conn->ssl = NULL;
    conn->ctx = NULL;
    conn->handshake_done = false;
    (void)iec61850_tcp_disconnect(&conn->tcp);
    return ret;
}

int iec61850_tls_disconnect(iec61850_tls_conn_t *conn)
{
    if (conn == NULL) { return IEC61850_TRANSPORT_ERR_ARGS; }

    if (conn->ssl != NULL) {
        /* Best-effort close_notify; the peer may already be gone */
        {
            sigset_t old_mask;
            tls_sigpipe_block(&old_mask);
            (void)SSL_shutdown((SSL *)conn->ssl);
            tls_sigpipe_restore(&old_mask);
        }
        SSL_free((SSL *)conn->ssl);
        conn->ssl = NULL;
    }
    if (conn->ctx != NULL) {
        /* ctx is owned by this conn only when connect() built it;
         * accepted connections borrow the listener's ctx (SSL_new
         * holds its own reference). */
        SSL_CTX_free((SSL_CTX *)conn->ctx);
        conn->ctx = NULL;
    }
    conn->handshake_done = false;
    (void)iec61850_tcp_disconnect(&conn->tcp);
    ERR_clear_error();
    return IEC61850_TRANSPORT_OK;
}

/* ========================================================================
 * Data path
 * ======================================================================== */

int iec61850_tls_send(iec61850_tls_conn_t *conn, const uint8_t *data,
                        size_t len)
{
    SSL *ssl;

    if ((conn == NULL) || (data == NULL) || (len == 0U) ||
        (!conn->handshake_done)) {
        return IEC61850_TRANSPORT_ERR_ARGS;
    }

    ssl = (SSL *)conn->ssl;

    if (len > (size_t)INT_MAX) { return IEC61850_TRANSPORT_ERR_ARGS; }

    for (;;) {
        int ret;
        int err;
        short events;
        struct pollfd pfd;
        int poll_ret;
        sigset_t old_mask;

        tls_sigpipe_block(&old_mask);
        ret = SSL_write(ssl, data, (int)len);
        tls_sigpipe_restore(&old_mask);

        if (ret > 0) { return ret; }

        err = SSL_get_error(ssl, ret);
        if ((err == SSL_ERROR_ZERO_RETURN) ||
            ((err == SSL_ERROR_SYSCALL) && (errno == 0))) {
            /* Peer sent close_notify */
            conn->handshake_done = false;
            conn->tcp.connected = false;
            ERR_clear_error();
            return IEC61850_TRANSPORT_ERR_CLOSED;
        }
        if (err == SSL_ERROR_WANT_WRITE) {
            events = POLLOUT;
        } else if (err == SSL_ERROR_WANT_READ) {
            events = POLLIN;
        } else {
            ERR_clear_error();
            return IEC61850_TRANSPORT_ERR_SEND;
        }

        /* Blocking send semantics (like send(2) on a blocking
         * socket): wait until the record can be written. */
        pfd.fd = conn->tcp.sockfd;
        pfd.events = events;
        pfd.revents = 0;
        poll_ret = poll(&pfd, 1, -1);
        if (poll_ret <= 0) {
            ERR_clear_error();
            return IEC61850_TRANSPORT_ERR_SEND;
        }
    }
}

int iec61850_tls_recv(iec61850_tls_conn_t *conn, uint8_t *buffer,
                        size_t buflen, int timeout_ms)
{
    SSL *ssl;
    int64_t deadline;

    if ((conn == NULL) || (buffer == NULL) || (buflen == 0U) ||
        (!conn->handshake_done)) {
        return IEC61850_TRANSPORT_ERR_ARGS;
    }

    ssl = (SSL *)conn->ssl;
    deadline = mono_ms() + (int64_t)timeout_ms;

    if (buflen > (size_t)INT_MAX) { return IEC61850_TRANSPORT_ERR_ARGS; }

    for (;;) {
        int ret;
        int err;
        int64_t remaining;
        short events;
        struct pollfd pfd;
        int poll_ret;
        sigset_t old_mask;

        tls_sigpipe_block(&old_mask);
        ret = SSL_read(ssl, buffer, (int)buflen);
        tls_sigpipe_restore(&old_mask);

        if (ret > 0) { return ret; }

        err = SSL_get_error(ssl, ret);
        if (err == SSL_ERROR_ZERO_RETURN) {
            /* Clean TLS shutdown from the peer */
            conn->handshake_done = false;
            conn->tcp.connected = false;
            ERR_clear_error();
            return IEC61850_TRANSPORT_ERR_CLOSED;
        }
        if ((err == SSL_ERROR_SYSCALL) && (errno != EAGAIN) &&
            (errno != EINPROGRESS)) {
            conn->handshake_done = false;
            conn->tcp.connected = false;
            ERR_clear_error();
            return IEC61850_TRANSPORT_ERR_CLOSED;
        }
        if (err == SSL_ERROR_WANT_READ) {
            events = POLLIN;
        } else if (err == SSL_ERROR_WANT_WRITE) {
            events = POLLOUT;
        } else if ((err == SSL_ERROR_SYSCALL) && (errno == EAGAIN)) {
            events = POLLIN;
        } else {
            ERR_clear_error();
            return IEC61850_TRANSPORT_ERR_RECV;
        }

        remaining = deadline - mono_ms();
        if (remaining <= 0) {
            ERR_clear_error();
            return IEC61850_TRANSPORT_ERR_TIMEOUT;
        }

        pfd.fd = conn->tcp.sockfd;
        pfd.events = events;
        pfd.revents = 0;
        poll_ret = poll(&pfd, 1, poll_timeout(remaining));
        if (poll_ret == 0) {
            ERR_clear_error();
            return IEC61850_TRANSPORT_ERR_TIMEOUT;
        }
        if (poll_ret < 0) {
            ERR_clear_error();
            return IEC61850_TRANSPORT_ERR_RECV;
        }
    }
}

int iec61850_tls_recv_exact(iec61850_tls_conn_t *conn, uint8_t *buffer,
                              size_t len, int timeout_ms) /* NOLINT(bugprone-easily-swappable-parameters) */
{
    size_t received = 0;

    if ((conn == NULL) || (buffer == NULL) || (len == 0U)) {
        return IEC61850_TRANSPORT_ERR_ARGS;
    }

    while (received < len) {
        int ret = iec61850_tls_recv(conn, &buffer[received],
                                     len - received, timeout_ms);
        if (ret < 0) { return ret; }
        received += (size_t)ret;
    }

    return (int)received;
}

int iec61850_tls_recv_tpkt(iec61850_tls_conn_t *conn, uint8_t *buffer,
                             size_t buflen, int timeout_ms) /* NOLINT(bugprone-easily-swappable-parameters) */
{
    int ret;
    uint16_t total_len;
    size_t remaining;

    if ((conn == NULL) || (buffer == NULL) || (buflen < 4U)) {
        return IEC61850_TRANSPORT_ERR_ARGS;
    }

    /* 4-byte TPKT header */
    ret = iec61850_tls_recv_exact(conn, buffer, 4U, timeout_ms);
    if (ret < 0) { return ret; }

    total_len = (uint16_t)((uint16_t)buffer[2] << 8U) |
                 (uint16_t)buffer[3];
    if ((total_len < 4U) || ((size_t)total_len > buflen)) {
        return IEC61850_TRANSPORT_ERR_RECV;
    }

    remaining = (size_t)total_len - 4U;
    if (remaining > 0U) {
        ret = iec61850_tls_recv_exact(conn, &buffer[4], remaining,
                                       timeout_ms);
        if (ret < 0) { return ret; }
    }

    return (int)total_len;
}

bool iec61850_tls_is_connected(const iec61850_tls_conn_t *conn)
{
    if (conn == NULL) { return false; }
    return conn->handshake_done && conn->tcp.connected;
}

/* ========================================================================
 * Listener (server side)
 * ======================================================================== */

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
    SSL_CTX *ctx;
    bool verify_enabled = false;
    int ret;

    if (listener == NULL) { return IEC61850_TRANSPORT_ERR_ARGS; }
    if (provider == NULL) { return -EINVAL; }
    if ((mode != IEC61850_TLS_MODE_COMPATIBLE) &&
        (mode != IEC61850_TLS_MODE_STRICT_62351) &&
        (mode != IEC61850_TLS_MODE_SPIFFE)) {
        return IEC61850_TRANSPORT_ERR_ARGS;
    }
    if (listener->tcp.sockfd >= 0) { return IEC61850_TRANSPORT_ERR_ARGS; }

    /* Server credentials are snapshotted here: a later provider
     * refresh() applies to newly bound listeners only. */
    ctx = ctx_build_server(provider, &verify_enabled);
    if (ctx == NULL) { return IEC61850_TRANSPORT_ERR_BIND; }

    ret = iec61850_tcp_listener_bind(&listener->tcp, port);
    if (ret != 0) {
        SSL_CTX_free(ctx);
        return ret;
    }

    ret = iec61850_tcp_listener_listen(&listener->tcp, 16);
    if (ret != 0) {
        SSL_CTX_free(ctx);
        (void)iec61850_tcp_listener_close(&listener->tcp);
        return ret;
    }

    listener->ctx = (void *)ctx;
    listener->mode = mode;
    return IEC61850_TRANSPORT_OK;
}

int iec61850_tls_listener_accept(iec61850_tls_listener_t *listener,
                                   iec61850_tls_conn_t *conn,
                                   int timeout_ms)
{
    SSL *ssl = NULL;
    bool verify_enabled;
    int ret;

    if ((listener == NULL) || (conn == NULL) ||
        (listener->ctx == NULL)) {
        return IEC61850_TRANSPORT_ERR_ARGS;
    }
    if ((conn->ssl != NULL) || (conn->ctx != NULL) ||
        (conn->tcp.sockfd >= 0)) {
        return IEC61850_TRANSPORT_ERR_ARGS;
    }

    verify_enabled =
        (SSL_CTX_get_verify_mode((SSL_CTX *)listener->ctx) ==
         SSL_VERIFY_PEER);

    /* TCP accept (poll-based timeout, TCP_NODELAY) */
    ret = iec61850_tcp_listener_accept(&listener->tcp, &conn->tcp,
                                        timeout_ms);
    if (ret != 0) { return ret; }

    ssl = SSL_new((SSL_CTX *)listener->ctx);
    if (ssl == NULL) {
        (void)iec61850_tcp_disconnect(&conn->tcp);
        ERR_clear_error();
        return IEC61850_TRANSPORT_ERR_ACCEPT;
    }
    if (SSL_set_fd(ssl, conn->tcp.sockfd) != 1) {
        SSL_free(ssl);
        (void)iec61850_tcp_disconnect(&conn->tcp);
        ERR_clear_error();
        return IEC61850_TRANSPORT_ERR_ACCEPT;
    }

    conn->ssl = (void *)ssl;
    conn->ctx = NULL; /* listener owns the ctx */
    conn->mode = listener->mode;

    /* Server-side handshake */
    ret = tls_do_handshake(conn, timeout_ms, false);
    if (ret != 0) {
        goto fail;
    }

    /* Mode policy on the client certificate when one was presented
     * (mutual authentication deployments); anonymous clients are
     * tolerated here — the STRICT/SPIFFE profiles reject only a
     * presented certificate that fails them. */
    if (SSL_get1_peer_certificate(ssl) != NULL) {
        if (tls_check_peer_policy(ssl, listener->mode,
                                   verify_enabled) != 0) {
            ret = IEC61850_TRANSPORT_ERR_ACCEPT;
            goto fail;
        }
    }

    return IEC61850_TRANSPORT_OK;

fail:
    ERR_clear_error();
    SSL_free(ssl);
    conn->ssl = NULL;
    conn->handshake_done = false;
    (void)iec61850_tcp_disconnect(&conn->tcp);
    return ret;
}

int iec61850_tls_listener_close(iec61850_tls_listener_t *listener)
{
    if (listener == NULL) { return IEC61850_TRANSPORT_ERR_ARGS; }

    if (listener->ctx != NULL) {
        SSL_CTX_free((SSL_CTX *)listener->ctx);
        listener->ctx = NULL;
    }
    ERR_clear_error();
    return iec61850_tcp_listener_close(&listener->tcp);
}
