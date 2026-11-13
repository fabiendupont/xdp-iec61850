/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Certificate Provider for IEC 61850 (IEC 62351-4 support) — implementation
 *
 * File-watch based provider. Both backends (static PEM and
 * SPIFFE/SPIRE-compatible) share one core; they differ only in the
 * error policy for a missing file during refresh (see below).
 *
 * Watch mechanism
 * ---------------
 * Every configured component (certificate, key, trust bundle) is
 * stat()ed on each refresh(). A component counts as changed when
 * dev, ino, size, mtime seconds or mtime nanoseconds differ from the
 * snapshot of the last successful load. Inode tracking makes the
 * atomic write-temp-then-rename() rotation pattern (used by
 * spiffe-helper and most credential agents) always detectable,
 * independent of filesystem timestamp granularity. Snapshots are
 * taken BEFORE reading the file, so a change that lands between the
 * stat and the read is never missed (worst case it costs one extra
 * reload on the next refresh).
 *
 * Buffer swap
 * -----------
 * get() serves borrowed pointers into the provider's internal
 * buffers. On a detected change, refresh() builds a complete fresh
 * credential set off to the side, then installs it with pointer
 * assignment only — buffers are never mutated in place, so a get()
 * caller can never observe a torn credential set. (The API contract
 * is single-threaded, poll-based refresh; the swap is nevertheless
 * written so that a concurrent reader of the pointer pair sees
 * either the whole old set or the whole new set.) Pointers returned
 * before a refresh() that reported 1 are invalid afterwards.
 *
 * Error policy (rotation safety)
 * ------------------------------
 * - static backend: a missing or unparsable file AFTER a successful
 *   create makes refresh() return a negative errno while get() keeps
 *   serving the last good credentials. The snapshot is not updated
 *   on failure, so repairing the file is picked up by the next
 *   refresh() (reported as a change).
 * - spiffe backend: same mechanics, plus a one-cycle grace for
 *   ENOENT. The first refresh() that observes a missing file treats
 *   it as "no change" (the SPIRE agent rewrite window — unlink then
 *   rewrite — is normal operation, not an error). If the file is
 *   still missing on the following refresh(), the error is reported
 *   (-ENOENT). Any other errno (e.g. EACCES) is reported immediately
 *   by both backends.
 *
 * Validation
 * ----------
 * cert/trust buffers must contain at least one PEM X.509 object,
 * key buffers at least one PEM private key (OpenSSL BIO parsers —
 * the same object types src/security/cert_manager.c loads from
 * paths). Validation is done on the in-memory buffer rather than
 * through the path-based cert_manager loaders to avoid a
 * read/parse TOCTOU between loading the bytes and checking them.
 * Content is validated at create() and on every reload.
 *
 * Destroy safety
 * --------------
 * destroy(NULL) is a no-op. A repeated iec61850_cert_provider_
 * destroy(p) with the same handle is rejected by POINTER IDENTITY
 * ONLY (the address of the most recently destroyed handle is
 * remembered; no freed storage is ever dereferenced), and
 * create() clears that record when the allocator recycles the
 * address for a live provider. A zeroed (tombstone) handle is also
 * ignored. Repeated vtable-level p->destroy(p) cannot be made safe
 * after free() and remains a caller error, as does destroying A,
 * then B, then A again.
 *
 * SPIFFE/SPIRE layout expected by _create_spiffe (what the standard
 * spiffe-helper configuration writes):
 *   cert_path  — "cert_file":    X.509-SVID certificate chain (PEM)
 *   key_path   — "key_file":     SVID private key (PEM)
 *   trust_path — "trust_bundle": SPIRE trust bundle, CA certs (PEM)
 * The files are plain PEM; the SPIFFE URI SAN identity is not
 * interpreted here (certificate-policy selection lives in
 * transport/tls_socket.h and is mutually exclusive there).
 *
 * Feature-test macros (_POSIX_C_SOURCE, _DEFAULT_SOURCE) are defined
 * globally in meson.build; nanosecond mtime comparison is used when
 * the platform exposes it (_STATBUF_ST_NSEC).
 */

#include "security/cert_provider.h"

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

/* Sanity cap per component file (trust bundles stay well below this). */
#define CERTPROV_MAX_FILE_BYTES (4u * 1024u * 1024u)

/* Component slots; small fixed index set keeps the code MISRA-friendly. */
typedef enum {
    CERTPROV_CERT = 0,
    CERTPROV_KEY = 1,
    CERTPROV_TRUST = 2,
    CERTPROV_COUNT = 3
} certprov_comp_t;

typedef struct {
    char *path;        /* owned; NULL = component not configured */
    struct stat snap;  /* stat of the last successful load */
    bool missing;      /* spiffe grace: file was ENOENT at last refresh */
} certprov_watch_t;

/* Credential set: NUL-terminated owned buffers, swapped by pointer. */
typedef struct {
    char *cert;
    size_t cert_len;
    char *key;
    size_t key_len;
    char *trust;
    size_t trust_len;
} certprov_creds_t;

typedef struct {
    certprov_watch_t watch[CERTPROV_COUNT];
    certprov_creds_t creds;
    bool spiffe; /* true = one-cycle ENOENT grace (SPIRE rewrite window) */
} certprov_priv_t;

/*
 * Double-destroy guard: records the handle released by the most
 * recent destroy(). The wrapper compares POINTER VALUES ONLY — a
 * stale handle is rejected without dereferencing freed storage —
 * so destroy(); destroy(); in a row is fully defined. The slot is
 * cleared by certprov_create() when the allocator recycles the
 * address for a live provider. Single-slot by design (the API
 * contract is single-threaded, poll-based); destroying A, B, then
 * A again is out of scope for the guard and remains a caller error,
 * as does a repeated vtable-level p->destroy(p) (which cannot be
 * made safe after free()).
 */
static iec61850_cert_provider_t *certprov_last_destroyed;

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

static bool certprov_stat_equal(const struct stat *a, const struct stat *b)
{
    if (a->st_dev != b->st_dev) { return false; }
    if (a->st_ino != b->st_ino) { return false; }
    if (a->st_size != b->st_size) { return false; }
#ifdef _STATBUF_ST_NSEC
    if (a->st_mtim.tv_sec != b->st_mtim.tv_sec) { return false; }
    if (a->st_mtim.tv_nsec != b->st_mtim.tv_nsec) { return false; }
#else
    if (a->st_mtime != b->st_mtime) { return false; }
#endif
    return true;
}

/*
 * Read one component file into a fresh NUL-terminated buffer.
 * *snap receives the stat taken BEFORE the read (never-miss
 * semantics, see file header). Returns 0 or negative errno.
 */
static int certprov_read_file(const char *path, struct stat *snap,
                              char **data_out, size_t *len_out)
{
    struct stat st;
    FILE *fp;
    char *buf;
    size_t size;
    size_t got;

    if (stat(path, &st) != 0) { return -errno; }
    if (!S_ISREG(st.st_mode)) { return -EINVAL; }
    if (st.st_size < 0) { return -EINVAL; }
    if ((unsigned long long)st.st_size >
        (unsigned long long)CERTPROV_MAX_FILE_BYTES) {
        return -EFBIG;
    }
    size = (size_t)st.st_size;

    fp = fopen(path, "rb");
    if (fp == NULL) { return -errno; }

    buf = malloc(size + 1u);
    if (buf == NULL) {
        (void)fclose(fp);
        return -ENOMEM;
    }

    got = fread(buf, 1u, size, fp);
    (void)fclose(fp);
    if (got != size) {
        /* File changed between stat and read; treat as I/O error and
         * let the next refresh retry. */
        free(buf);
        return -EIO;
    }

    buf[size] = '\0';
    *snap = st;
    *data_out = buf;
    *len_out = size;
    return 0;
}

/*
 * Validate buffer content: cert/trust need at least one PEM X.509
 * object, key at least one PEM private key. Returns 0 or -EINVAL.
 */
static int certprov_validate(const char *data, size_t len,
                             certprov_comp_t comp)
{
    BIO *bio;
    bool ok = false;

    bio = BIO_new_mem_buf(data, (int)len);
    if (bio == NULL) { return -ENOMEM; }

    if (comp == CERTPROV_KEY) {
        EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
        if (pkey != NULL) {
            EVP_PKEY_free(pkey);
            ok = true;
        }
    } else {
        /* CERTPROV_CERT and CERTPROV_TRUST (bundle: >= 1 CA cert). */
        X509 *x509 = PEM_read_bio_X509(bio, NULL, NULL, NULL);
        if (x509 != NULL) {
            X509_free(x509);
            ok = true;
        }
    }

    BIO_free(bio);
    ERR_clear_error(); /* failed parse attempts leave errors queued */
    return ok ? 0 : -EINVAL;
}

static void certprov_creds_free(certprov_creds_t *creds)
{
    if (creds == NULL) { return; }
    free(creds->cert);
    free(creds->key);
    free(creds->trust);
    memset(creds, 0, sizeof(*creds));
}

/*
 * Load every configured component into *creds (fresh buffers) and,
 * only on full success, commit the watch snapshots. On failure the
 * provider state is untouched and nothing is returned. Returns 0 or
 * negative errno.
 */
static int certprov_load_all(certprov_priv_t *priv, certprov_creds_t *creds)
{
    char *data[CERTPROV_COUNT];
    size_t len[CERTPROV_COUNT];
    struct stat snap[CERTPROV_COUNT];
    int rc = 0;
    int i;

    memset(data, 0, sizeof(data));
    memset(len, 0, sizeof(len));
    memset(snap, 0, sizeof(snap));
    memset(creds, 0, sizeof(*creds));

    for (i = 0; (i < CERTPROV_COUNT) && (rc == 0); i++) {
        const certprov_watch_t *w = &priv->watch[i];
        if (w->path == NULL) { continue; }
        rc = certprov_read_file(w->path, &snap[i], &data[i], &len[i]);
        if (rc == 0) {
            rc = certprov_validate(data[i], len[i], (certprov_comp_t)i);
        }
    }
    if (rc != 0) {
        for (i = 0; i < CERTPROV_COUNT; i++) {
            free(data[i]);
        }
        return rc;
    }

    creds->cert = data[CERTPROV_CERT];
    creds->cert_len = len[CERTPROV_CERT];
    creds->key = data[CERTPROV_KEY];
    creds->key_len = len[CERTPROV_KEY];
    creds->trust = data[CERTPROV_TRUST];
    creds->trust_len = len[CERTPROV_TRUST];

    for (i = 0; i < CERTPROV_COUNT; i++) {
        if (priv->watch[i].path != NULL) {
            priv->watch[i].snap = snap[i];
            priv->watch[i].missing = false;
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* vtable                                                              */
/* ------------------------------------------------------------------ */

static int certprov_get(iec61850_cert_provider_t *p,
                        const char **cert_pem, size_t *cert_len,
                        const char **key_pem, size_t *key_len,
                        const char **trust_pem, size_t *trust_len)
{
    certprov_priv_t *priv;

    if ((p == NULL) || (p->priv == NULL)) { return -EINVAL; }
    priv = (certprov_priv_t *)p->priv;

    /* Borrowed pointers into the internal buffers; NULL/0 for
     * components that are not configured. Individual output
     * arguments may be NULL (component not requested). */
    if (cert_pem != NULL) { *cert_pem = priv->creds.cert; }
    if (cert_len != NULL) { *cert_len = priv->creds.cert_len; }
    if (key_pem != NULL) { *key_pem = priv->creds.key; }
    if (key_len != NULL) { *key_len = priv->creds.key_len; }
    if (trust_pem != NULL) { *trust_pem = priv->creds.trust; }
    if (trust_len != NULL) { *trust_len = priv->creds.trust_len; }
    return 0;
}

static int certprov_refresh(iec61850_cert_provider_t *p)
{
    certprov_priv_t *priv;
    bool changed = false;
    bool grace = false;
    certprov_creds_t fresh;
    certprov_creds_t old;
    int rc;
    int i;

    if ((p == NULL) || (p->priv == NULL)) { return -EINVAL; }
    priv = (certprov_priv_t *)p->priv;

    for (i = 0; i < CERTPROV_COUNT; i++) {
        certprov_watch_t *w = &priv->watch[i];
        struct stat st;

        if (w->path == NULL) { continue; }

        if (stat(w->path, &st) != 0) {
            int err = errno;
            if (priv->spiffe && (err == ENOENT) && (!w->missing)) {
                /* SPIRE agent rewrite window: one refresh cycle of
                 * grace — a briefly missing file is not an error. */
                w->missing = true;
                grace = true;
                continue;
            }
            /* static backend, or persistent absence (spiffe). */
            return -err;
        }

        w->missing = false;
        if (!certprov_stat_equal(&w->snap, &st)) { changed = true; }
    }

    if (grace) {
        /* A rewrite may be in flight: report no change this cycle.
         * Snapshots are not updated, so nothing observed as changed
         * before is lost — the next refresh re-examines it. */
        return 0;
    }
    if (!changed) { return 0; }

    rc = certprov_load_all(priv, &fresh);
    if (rc != 0) {
        /* Missing/invalid content after a valid create: report the
         * error; get() keeps serving the last good credentials. */
        return rc;
    }

    /* Swap by pointer: fresh set is complete before the old one is
     * released; buffers are never mutated in place. After this,
     * pointers previously returned by get() are invalid. */
    old = priv->creds;
    priv->creds = fresh;
    certprov_creds_free(&old);
    return 1;
}

static void certprov_destroy(iec61850_cert_provider_t *p)
{
    certprov_priv_t *priv;
    int i;

    if ((p == NULL) || (p->priv == NULL)) { return; }
    priv = (certprov_priv_t *)p->priv;

    certprov_creds_free(&priv->creds);
    for (i = 0; i < CERTPROV_COUNT; i++) {
        free(priv->watch[i].path);
        priv->watch[i].path = NULL;
    }
    memset(priv, 0, sizeof(*priv));
    free(priv);

    /* Zero the handle (defense in depth for readable-but-stale
     * storage) and record the pointer VALUE before releasing it, so
     * the wrapper can reject an immediately repeated destroy without
     * touching freed memory. */
    memset(p, 0, sizeof(*p));
    certprov_last_destroyed = p;
    free(p);
}

/* ------------------------------------------------------------------ */
/* Constructors                                                        */
/* ------------------------------------------------------------------ */

static iec61850_cert_provider_t *certprov_create(const char *cert_path,
                                                 const char *key_path,
                                                 const char *trust_path,
                                                 bool spiffe)
{
    const char *paths[CERTPROV_COUNT];
    iec61850_cert_provider_t *p;
    certprov_priv_t *priv;
    certprov_creds_t creds;
    int rc;
    int i;

    paths[CERTPROV_CERT] = cert_path;
    paths[CERTPROV_KEY] = key_path;
    paths[CERTPROV_TRUST] = trust_path;

    if ((cert_path == NULL) && (key_path == NULL) && (trust_path == NULL)) {
        errno = EINVAL; /* at least one component must be configured */
        return NULL;
    }

    p = calloc(1, sizeof(*p));
    priv = calloc(1, sizeof(*priv));
    if ((p == NULL) || (priv == NULL)) {
        free(p);
        free(priv);
        errno = ENOMEM;
        return NULL;
    }
    p->priv = priv;
    priv->spiffe = spiffe;

    /* Install the vtable early so the failure path can reuse
     * iec61850_cert_provider_destroy() for full cleanup. */
    p->get = certprov_get;
    p->refresh = certprov_refresh;
    p->destroy = certprov_destroy;

    for (i = 0; i < CERTPROV_COUNT; i++) {
        if (paths[i] != NULL) {
            priv->watch[i].path = strdup(paths[i]);
            if (priv->watch[i].path == NULL) {
                errno = ENOMEM;
                iec61850_cert_provider_destroy(p);
                return NULL;
            }
        }
    }

    /* Load and validate: invalid or missing content at create fails
     * the constructor (NULL + errno). */
    rc = certprov_load_all(priv, &creds);
    if (rc != 0) {
        errno = -rc;
        iec61850_cert_provider_destroy(p);
        return NULL;
    }
    priv->creds = creds;

    /* The allocator may have recycled a recently destroyed handle's
     * address for this live provider: clear the stale-handle guard
     * so destroying THIS provider through the wrapper works. */
    if (p == certprov_last_destroyed) {
        certprov_last_destroyed = NULL;
    }
    return p;
}

iec61850_cert_provider_t *iec61850_cert_provider_create_static(
    const char *cert_path, const char *key_path, const char *trust_path)
{
    return certprov_create(cert_path, key_path, trust_path, false);
}

iec61850_cert_provider_t *iec61850_cert_provider_create_spiffe(
    const char *cert_path, const char *key_path, const char *trust_path)
{
    return certprov_create(cert_path, key_path, trust_path, true);
}

void iec61850_cert_provider_destroy(iec61850_cert_provider_t *p)
{
    if (p == NULL) { return; }
    /* Pointer-identity check only: a stale handle from a repeated
     * destroy is rejected without dereferencing freed storage. */
    if (p == certprov_last_destroyed) { return; }
    /* Zeroed (tombstone) handle: no vtable, nothing to do. */
    if (p->destroy == NULL) { return; }
    p->destroy(p);
}
