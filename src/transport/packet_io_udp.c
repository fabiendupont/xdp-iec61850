/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * packet_io UDP backend (IEC TR 61850-90-5 routable profiles)
 *
 * WP-S4 scaffold: implemented by WP-4b (udp-transport) against the
 * frozen constructors declared in include/iec61850/transport/packet_io.h.
 */

#include "transport/packet_io.h"

#include <errno.h>
#include <stdlib.h>

struct packet_io *packet_io_create_udp_sender(const char *remote_addr,
                                               uint16_t remote_port,
                                               bool multicast)
{
    (void)remote_addr;
    (void)remote_port;
    (void)multicast;
    return NULL; /* implemented by WP-4b */
}

struct packet_io *packet_io_create_udp_receiver(uint16_t local_port,
                                                  const char *mcast_group)
{
    (void)local_port;
    (void)mcast_group;
    return NULL; /* implemented by WP-4b */
}
