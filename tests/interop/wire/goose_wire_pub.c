/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * GOOSE wire publisher — sends GOOSE frames on a raw socket.
 * Used by wire capture interop tests.
 *
 * Usage: goose_wire_pub <interface>
 */


#include "goose/goose_publisher.h"
#include "transport/eth_frame.h"
#include "transport/packet_io.h"

#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    const char *iface = argc > 1 ? argv[1] : "igt0";

    struct packet_io *io = packet_io_create_raw();
    if (io == NULL) {
        fprintf(stderr, "packet_io_create_raw failed\n");
        return 1;
    }
    if (packet_io_open(io, iface, 0) != 0) {
        fprintf(stderr, "packet_io_open(%s) failed\n", iface);
        return 1;
    }

    iec61850_goose_config_t cfg;
    iec61850_goose_config_init(&cfg);
    cfg.app_id = 0x0001;
    cfg.vlan_id = 0;

    iec61850_goose_publisher_t pub;
    iec61850_goose_publisher_init(&pub, &cfg);
    iec61850_goose_publisher_set_boolean(&pub, 0, true);
    iec61850_goose_publisher_set_int32(&pub, 1, 42);

    uint8_t frame[IEC61850_MAX_FRAME_SIZE];
    size_t frame_len = 0;
    int ret = iec61850_goose_publisher_build_frame(&pub, frame, sizeof(frame),
                                                      &frame_len);
    if (ret != 0) {
        fprintf(stderr, "build_frame failed: %d\n", ret);
        return 1;
    }

    for (int i = 0; i < 5; i++) {
        packet_io_send(io, frame, (uint32_t)frame_len);
        usleep(100000);
    }
    printf("sent 5 GOOSE frames (%zu bytes each)\n", frame_len);

    iec61850_goose_publisher_destroy(&pub);
    packet_io_close(io);
    packet_io_destroy(io);
    return 0;
}
