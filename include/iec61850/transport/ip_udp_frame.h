/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * IPv4 + UDP Frame Builder/Parser for IEC TR 61850-90-5 Routable Profiles
 *
 * 90-5 publishers using the raw AF_PACKET backend must emit complete
 * IP/UDP datagrams in userspace: the security signature (HMAC) covers
 * the IP + UDP header bytes, so the headers must be buildable and
 * parseable without kernel help.
 *
 * Frame layout produced/consumed:
 *   [IPv4 header (20 bytes, IHL=5, no options)]
 *   [UDP header (8 bytes)]
 *   [payload]
 *
 * Checksums:
 *   - IPv4 header checksum: mandatory, always computed.
 *   - UDP checksum: implemented (computed over the IPv4 pseudo-header,
 *     UDP header and payload).  A computed value of 0 is transmitted as
 *     0xFFFF per RFC 768 (0 means "checksum not used").
 *
 * Parsing is structural only (lengths, version, IHL, fragmentation);
 * checksum verification is left to the caller / security layer so that
 * a received frame can be inspected before the signature check.
 */

#ifndef IEC61850_IP_UDP_FRAME_H
#define IEC61850_IP_UDP_FRAME_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

struct packet_io;

/* Header sizes (IPv4 with IHL=5, no options) */
#define IEC61850_IPV4_HEADER_LEN     20U
#define IEC61850_UDP_HEADER_LEN       8U
#define IEC61850_IP_UDP_HEADER_LEN   28U

/* Maximum payload of an IPv4/UDP datagram */
#define IEC61850_IP_UDP_MAX_PAYLOAD  65507U  /* 65535 - 20 - 8 */

/**
 * Build an IPv4 + UDP datagram around a payload.
 *
 * The IPv4 header is fixed at 20 bytes (IHL=5, no options), TTL 64,
 * Don't-Fragment set, identification 0.  The Protocol field is taken
 * from protocol_next_hdr; only IPPROTO_UDP is accepted today (the
 * parameter exists so a later IPv6/extension-header variant can share
 * this signature).
 *
 * Both the IPv4 header checksum and the UDP checksum are computed.
 *
 * @param buf                Output buffer
 * @param buflen             Size of the output buffer
 * @param src_ip             Source IPv4 address, dotted-quad string
 * @param dst_ip             Destination IPv4 address, dotted-quad string
 * @param src_port           UDP source port (host byte order)
 * @param dst_port           UDP destination port (host byte order)
 * @param payload            Payload bytes (may be NULL iff payload_len == 0)
 * @param payload_len        Payload length
 * @param protocol_next_hdr  IP Protocol / IPv6 Next Header value
 *                           (IPPROTO_UDP only for now)
 * @return 0 on success (frame length is 28 + payload_len),
 *         negative errno on error (-EINVAL, -ENOSPC, -EMSGSIZE,
 *         -EPROTONOSUPPORT)
 */
int iec61850_ip_udp_build(uint8_t *buf, size_t buflen, const char *src_ip,
                          const char *dst_ip, uint16_t src_port,
                          uint16_t dst_port, const uint8_t *payload,
                          size_t payload_len, uint8_t protocol_next_hdr);

/**
 * Parse and validate an IPv4 + UDP datagram.
 *
 * Every header length is checked before it is read.  Rejected:
 *   - NULL arguments (-EINVAL)
 *   - truncated frames (buflen < IPv4 header, < UDP header, or shorter
 *     than the IPv4 Total Length field) (-EBADMSG)
 *   - wrong IP version or IHL < 5 (-EBADMSG / -EPROTONOSUPPORT)
 *   - IP Protocol != UDP (-EPROTONOSUPPORT)
 *   - non-zero fragment offset (fragmented datagram) (-EPROTO)
 *   - address output buffers smaller than INET_ADDRSTRLEN (-ENOSPC)
 *
 * @param buf          Received datagram
 * @param buflen       Length of the received datagram
 * @param src_ip       Output: source address, dotted-quad string
 *                     (buffer of at least INET_ADDRSTRLEN bytes)
 * @param src_ip_len   Size of the src_ip buffer
 * @param dst_ip       Output: destination address, dotted-quad string
 * @param dst_ip_len   Size of the dst_ip buffer
 * @param src_port     Output: UDP source port (host byte order)
 * @param dst_port     Output: UDP destination port (host byte order)
 * @param payload      Output: pointer into buf where the payload starts
 * @param payload_len  Output: payload length
 * @return 0 on success, negative errno on error
 */
int iec61850_ip_udp_parse(const uint8_t *buf, size_t buflen, char *src_ip,
                          size_t src_ip_len, char *dst_ip, size_t dst_ip_len,
                          uint16_t *src_port, uint16_t *dst_port,
                          const uint8_t **payload, size_t *payload_len);

/*
 * UDP backend runtime option (WP-4b).
 *
 * Enable/disable IP_MULTICAST_LOOP on a UDP *sender* created with
 * packet_io_create_udp_sender().  Disabled by default (a publisher
 * should not receive its own publications); enable it for same-host
 * testing.  May be called before open() (stored, applied at open())
 * or after open() (applied immediately).  No effect on receivers.
 *
 * @param io      A packet_io created by packet_io_create_udp_sender()
 * @param enable  true to loop multicast back to the local host
 * @return 0 on success, -EINVAL if io is not a UDP sender
 */
int packet_io_udp_set_mcast_loop(struct packet_io *io, bool enable);

#ifdef __cplusplus
}
#endif

#endif /* IEC61850_IP_UDP_FRAME_H */
