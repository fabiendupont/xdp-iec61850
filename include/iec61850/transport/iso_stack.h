/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * ISO Transport Stack for IEC 61850 MMS
 *
 * Implements the full ISO/IEC stack:
 *   TPKT (RFC 1006) → ISO Session (ISO 8327) → ISO Presentation (ISO 8823)
 *   → ACSE (ISO 8650) → MMS Application Layer
 *
 * All encode functions write to a buffer and return bytes written (or negative error).
 * All decode functions read from a buffer and return bytes consumed (or negative error).
 */

#ifndef IEC61850_ISO_STACK_H
#define IEC61850_ISO_STACK_H

#include "transport/tcp_socket.h"
#include "transport/tls_socket.h"

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum sizes */
#define IEC61850_ISO_MAX_PDU      65000
#define IEC61850_ISO_MAX_SSEL     16
#define IEC61850_ISO_MAX_OID      16
#define IEC61850_ISO_MAX_AP_TITLE 32

/* ========================================================================
 * TPKT — RFC 1006: ISO Transport over TCP
 * ======================================================================== */

#define IEC61850_TPKT_VERSION    3
#define IEC61850_TPKT_HEADER_LEN 4

/**
 * Encode TPKT header around data.
 *
 * @param buf      Output buffer (must be at least data_len + 4)
 * @param buf_size Buffer capacity
 * @param data     Payload data (copied after header)
 * @param data_len Payload length
 * @return Total frame length (header + data), or negative on error
 */
int iec61850_tpkt_encode(uint8_t *buf, size_t buf_size,
                           const uint8_t *data, size_t data_len);

/**
 * Decode TPKT header.
 *
 * @param buf      Input buffer
 * @param buf_len  Buffer length
 * @param payload  Output: pointer to payload within buf
 * @param payload_len Output: payload length
 * @return 0 on success, negative on error
 */
int iec61850_tpkt_decode(const uint8_t *buf, size_t buf_len,
                           const uint8_t **payload, size_t *payload_len);

/* ========================================================================
 * ISO Session — ISO 8327: Session Protocol
 * ======================================================================== */

/* Session SPDU types */
#define IEC61850_SI_CONNECT       0x0DU
#define IEC61850_SI_ACCEPT        0x0EU
#define IEC61850_SI_FINISH        0x09U
#define IEC61850_SI_DISCONNECT    0x0AU
#define IEC61850_SI_ABORT         0x19U
#define IEC61850_SI_DATA          0x01U

/* Session Parameter Identifiers (PI) */
#define IEC61850_SPI_VERSION       0x16U  /* Protocol Version */
#define IEC61850_SPI_CALLING_SSEL  0x33U  /* Calling Session Selector */
#define IEC61850_SPI_CALLED_SSEL   0x34U  /* Called Session Selector */
#define IEC61850_SPI_USER_DATA     0xC1U  /* User Data */
#define IEC61850_SPI_REQUIREMENTS  0x14U  /* Session User Requirements */

typedef struct {
    uint8_t calling_ssel[IEC61850_ISO_MAX_SSEL];
    size_t calling_ssel_len;
    uint8_t called_ssel[IEC61850_ISO_MAX_SSEL];
    size_t called_ssel_len;
    uint16_t user_requirements;  /* 0x0002 = duplex FU */
    uint8_t version;
} iec61850_session_params_t;

void iec61850_session_params_init(iec61850_session_params_t *params);

/**
 * Encode Session CONNECT SPDU.
 */
int iec61850_session_encode_connect(uint8_t *buf, size_t buf_size,
                                      const iec61850_session_params_t *params,
                                      const uint8_t *user_data,
                                      size_t user_data_len);

/**
 * Encode Session ACCEPT SPDU.
 */
int iec61850_session_encode_accept(uint8_t *buf, size_t buf_size,
                                     const iec61850_session_params_t *params,
                                     const uint8_t *user_data,
                                     size_t user_data_len);

/**
 * Encode Session DATA SPDU.
 */
int iec61850_session_encode_data(uint8_t *buf, size_t buf_size,
                                   const uint8_t *user_data,
                                   size_t user_data_len);

/**
 * Encode Session FINISH (disconnect) SPDU.
 */
int iec61850_session_encode_finish(uint8_t *buf, size_t buf_size,
                                     const uint8_t *user_data,
                                     size_t user_data_len);

/**
 * Decode a Session SPDU.
 *
 * @param buf      Input buffer
 * @param buf_len  Buffer length
 * @param si_type  Output: SPDU type (SI_CONNECT, SI_DATA, etc.)
 * @param params   Output: session parameters (for CONNECT/ACCEPT)
 * @param user_data Output: pointer to user data within buf
 * @param user_data_len Output: user data length
 * @return 0 on success, negative on error
 */
int iec61850_session_decode(const uint8_t *buf, size_t buf_len,
                              uint8_t *si_type,
                              iec61850_session_params_t *params,
                              const uint8_t **user_data,
                              size_t *user_data_len);

/* ========================================================================
 * ISO Presentation — ISO 8823: Presentation Protocol
 * ======================================================================== */

/* Well-known OIDs (BER-encoded value bytes, no tag/length) */
#define IEC61850_OID_ACSE_LEN  4
#define IEC61850_OID_BER_LEN   2
#define IEC61850_OID_MMS_LEN   5

extern const uint8_t IEC61850_OID_ACSE[4];   /* 2.2.1.0.1 */
extern const uint8_t IEC61850_OID_BER[2];    /* 2.1.1 */
extern const uint8_t IEC61850_OID_MMS[5];    /* 1.0.9506.2.1 */

/* Presentation Context IDs */
#define IEC61850_PCID_ACSE  1U
#define IEC61850_PCID_MMS   3U

/**
 * Encode CP (Connect Presentation) PPDU.
 * Contains presentation context list + ACSE user data.
 */
int iec61850_pres_encode_cp(uint8_t *buf, size_t buf_size,
                              const uint8_t *acse_pdu, size_t acse_len);

/**
 * Encode CPA (Connect Presentation Accept) PPDU.
 */
int iec61850_pres_encode_cpa(uint8_t *buf, size_t buf_size,
                               const uint8_t *acse_pdu, size_t acse_len);

/**
 * Encode P-DATA (User Data) PPDU.
 */
int iec61850_pres_encode_pdata(uint8_t *buf, size_t buf_size,
                                 uint8_t pcid,
                                 const uint8_t *app_pdu, size_t app_len);

/**
 * Decode a Presentation PPDU.
 *
 * @param buf      Input buffer
 * @param buf_len  Buffer length
 * @param pcid     Output: presentation context ID
 * @param app_pdu  Output: pointer to application data within buf
 * @param app_len  Output: application data length
 * @return 0 on success, negative on error
 */
int iec61850_pres_decode(const uint8_t *buf, size_t buf_len,
                           uint8_t *pcid,
                           const uint8_t **app_pdu, size_t *app_len);

/* ========================================================================
 * ACSE — ISO 8650: Association Control
 * ======================================================================== */

/* ACSE PDU tags (APPLICATION class) */
#define IEC61850_ACSE_TAG_AARQ  0x60U  /* [APPLICATION 0] */
#define IEC61850_ACSE_TAG_AARE  0x61U  /* [APPLICATION 1] */
#define IEC61850_ACSE_TAG_RLRQ  0x62U  /* [APPLICATION 2] */
#define IEC61850_ACSE_TAG_RLRE  0x63U  /* [APPLICATION 3] */

/* Association result */
typedef enum {
    IEC61850_AARE_ACCEPTED       = 0,
    IEC61850_AARE_REJECTED_PERM  = 1,
    IEC61850_AARE_REJECTED_TRANS = 2
} iec61850_aare_result_t;

typedef struct {
    uint8_t app_context_oid[IEC61850_ISO_MAX_OID];
    size_t app_context_oid_len;
    uint8_t called_ap_title[IEC61850_ISO_MAX_AP_TITLE];
    size_t called_ap_title_len;
    uint8_t calling_ap_title[IEC61850_ISO_MAX_AP_TITLE];
    size_t calling_ap_title_len;
    int32_t called_ae_qualifier;    /* -1 = absent */
    int32_t calling_ae_qualifier;   /* -1 = absent */
} iec61850_acse_params_t;

void iec61850_acse_params_init(iec61850_acse_params_t *params);

/**
 * Encode AARQ (Association Request).
 */
int iec61850_acse_encode_aarq(uint8_t *buf, size_t buf_size,
                                const iec61850_acse_params_t *params,
                                const uint8_t *app_pdu, size_t app_len);

/**
 * Encode AARE (Association Response).
 */
int iec61850_acse_encode_aare(uint8_t *buf, size_t buf_size,
                                const iec61850_acse_params_t *params,
                                iec61850_aare_result_t result,
                                const uint8_t *app_pdu, size_t app_len);

/**
 * Encode RLRQ (Release Request).
 */
int iec61850_acse_encode_rlrq(uint8_t *buf, size_t buf_size);

/**
 * Encode RLRE (Release Response).
 */
int iec61850_acse_encode_rlre(uint8_t *buf, size_t buf_size);

/**
 * Decode ACSE PDU.
 *
 * @param buf      Input buffer
 * @param buf_len  Buffer length
 * @param tag      Output: PDU tag (AARQ, AARE, RLRQ, RLRE)
 * @param params   Output: ACSE parameters
 * @param result   Output: association result (for AARE)
 * @param app_pdu  Output: embedded application PDU
 * @param app_len  Output: application PDU length
 * @return 0 on success, negative on error
 */
int iec61850_acse_decode(const uint8_t *buf, size_t buf_len,
                           uint8_t *tag,
                           iec61850_acse_params_t *params,
                           iec61850_aare_result_t *result,
                           const uint8_t **app_pdu, size_t *app_len);

/* ========================================================================
 * ISO Connection — Composite Stack
 * ======================================================================== */

typedef enum {
    IEC61850_ISO_STATE_IDLE = 0,
    IEC61850_ISO_STATE_CONNECTING,
    IEC61850_ISO_STATE_CONNECTED,
    IEC61850_ISO_STATE_RELEASING,
    IEC61850_ISO_STATE_CLOSED
} iec61850_iso_state_t;

typedef struct {
    iec61850_tcp_conn_t tcp;
    iec61850_session_params_t session_params;
    iec61850_acse_params_t acse_params;
    iec61850_iso_state_t state;
    uint32_t max_pdu_size;
    /*
     * WP-3b (IEC 62351-4): TLS transport for MMS associations.
     * When use_tls is set, the association runs over conn->tls
     * (which carries its own embedded TCP socket — the plain tcp
     * member is unused on that path). Set only through
     * iec61850_iso_connect_tls() (client) or by handing a
     * TLS-accepted connection to the server path; the plain
     * TCP path is unchanged.
     */
    iec61850_tls_conn_t tls;
    bool use_tls;
} iec61850_iso_conn_t;

void iec61850_iso_conn_init(iec61850_iso_conn_t *conn);

/**
 * Connect to an MMS server (full ISO stack negotiation).
 *
 * TCP connect → TPKT + Session CONNECT + Presentation CP + ACSE AARQ
 * → wait for AARE → establish association.
 *
 * @param conn       ISO connection
 * @param host       Server hostname or IP
 * @param port       TCP port (default 102)
 * @param mms_init   MMS InitiateRequest PDU to embed in AARQ
 * @param mms_init_len Length of MMS PDU
 * @param timeout_ms Connection timeout in milliseconds
 * @return 0 on success, negative on error
 */
int iec61850_iso_connect(iec61850_iso_conn_t *conn, const char *host,
                           uint16_t port, const uint8_t *mms_init,
                           size_t mms_init_len, int timeout_ms);

/**
 * WP-3b (IEC 62351-4): connect to an MMS server over TLS.
 *
 * TLS connect + handshake (per the certificate-policy mode), then
 * the same TPKT/Session/Presentation/ACSE negotiation as
 * iec61850_iso_connect(), with all I/O routed through the TLS
 * layer. The provider's credentials are snapshotted at connect
 * time (provider may be NULL for opportunistic client handshakes).
 *
 * Only available in security-enabled builds (returns -ENOTSUP
 * otherwise).
 *
 * @param conn       ISO connection
 * @param host       Server hostname or IP
 * @param port       TCP port (default 3782 for TLS MMS)
 * @param mms_init   MMS InitiateRequest PDU to embed in AARQ
 * @param mms_init_len Length of MMS PDU
 * @param timeout_ms Connection timeout in milliseconds
 * @param provider   Credential source (NULL = opportunistic)
 * @param mode       Certificate-policy mode
 * @return 0 on success, negative on error
 */
int iec61850_iso_connect_tls(iec61850_iso_conn_t *conn, const char *host,
                               uint16_t port, const uint8_t *mms_init,
                               size_t mms_init_len, int timeout_ms,
                               const iec61850_cert_provider_t *provider,
                               iec61850_tls_mode_t mode);

/**
 * Accept an incoming ISO connection (server-side).
 *
 * Reads TPKT+Session CONNECT, sends Session ACCEPT + ACSE AARE.
 *
 * @param conn       ISO connection (TCP already accepted)
 * @param mms_resp   MMS InitiateResponse PDU to embed in AARE
 * @param mms_resp_len Length of MMS response
 * @param mms_req    Output: received MMS InitiateRequest PDU
 * @param mms_req_len Input/output: capacity / actual length
 * @param timeout_ms Read timeout in milliseconds
 * @return 0 on success, negative on error
 */
int iec61850_iso_accept(iec61850_iso_conn_t *conn,
                          const uint8_t *mms_resp, size_t mms_resp_len,
                          uint8_t *mms_req, size_t *mms_req_len,
                          int timeout_ms);

/**
 * Send application data through the ISO stack.
 *
 * Data is wrapped: MMS → Presentation P-DATA → Session DATA → TPKT.
 */
int iec61850_iso_send(iec61850_iso_conn_t *conn,
                        const uint8_t *data, size_t data_len);

/**
 * Receive application data from the ISO stack.
 *
 * Strips: TPKT → Session → Presentation → returns MMS PDU.
 *
 * @param conn       ISO connection
 * @param buf        Output buffer for MMS PDU
 * @param buf_size   Buffer capacity
 * @param recv_len   Output: received MMS PDU length
 * @param timeout_ms Read timeout
 * @return 0 on success, negative on error
 */
int iec61850_iso_recv(iec61850_iso_conn_t *conn,
                        uint8_t *buf, size_t buf_size,
                        size_t *recv_len, int timeout_ms);

/**
 * Gracefully release the ISO connection.
 *
 * Sends RLRQ, waits for RLRE, then disconnects TCP.
 */
int iec61850_iso_disconnect(iec61850_iso_conn_t *conn);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_ISO_STACK_H */
