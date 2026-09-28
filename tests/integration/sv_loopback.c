/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * SV Loopback Integration Test
 *
 * Sends SV frames on one end of a veth pair via raw socket,
 * receives them on the other end, decodes, and verifies sample
 * counter continuity and gap detection.
 *
 * Requires: CAP_NET_RAW (run as root or with sudo)
 *
 * Interface names are passed as argv[1] (tx) and argv[2] (rx).
 */


#include "sv/sv_publisher.h"
#include "sv/sv_subscriber.h"
#include "transport/packet_io.h"
#include "transport/eth_frame.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int received_count = 0;
static uint16_t last_smp_cnt = 0;
static int gap_detected = 0;

static void on_sv(const iec61850_sv_message_t *msg, void *user_data)
{
    (void)user_data;
    received_count++;
    last_smp_cnt = msg->asdu.smpCnt;
    if (msg->has_gap) {
        gap_detected = 1;
    }
}

int main(int argc, char *argv[])
{
    const char *tx_if, *rx_if;
    struct packet_io *tx_io, *rx_io;
    iec61850_sv_publisher_t pub;
    iec61850_sv_subscriber_t sub;
    iec61850_sv_config_t pub_cfg;
    iec61850_sv_sub_config_t sub_cfg;
    uint8_t frame[1518];
    size_t frame_len = 0;
    int ret, attempts;

    if (argc < 3) {
        fprintf(stderr, "SKIP: %s requires <tx_interface> <rx_interface> — run via test_sv_loopback.sh\n",
                argv[0]);
        return 77;
    }
    tx_if = argv[1];
    rx_if = argv[2];

    printf("=== SV Loopback Test ===\n");
    printf("TX: %s, RX: %s\n", tx_if, rx_if);

    /* Create raw socket I/O */
    tx_io = packet_io_create_raw();
    rx_io = packet_io_create_raw();
    if (tx_io == NULL || rx_io == NULL) {
        fprintf(stderr, "FAIL: cannot create packet_io\n");
        return 1;
    }

    ret = packet_io_open(tx_io, tx_if, 0);
    if (ret != 0) {
        fprintf(stderr, "FAIL: cannot open TX interface %s: %d\n", tx_if, ret);
        fprintf(stderr, "  (need CAP_NET_RAW — run with sudo)\n");
        return 1;
    }

    ret = packet_io_open(rx_io, rx_if, 0);
    if (ret != 0) {
        fprintf(stderr, "FAIL: cannot open RX interface %s: %d\n", rx_if, ret);
        return 1;
    }

    /* Configure and init publisher */
    iec61850_sv_config_init(&pub_cfg);
    pub_cfg.app_id = 0x4000;
    (void)strncpy(pub_cfg.sv_id, "IED1MU/LLN0$SV$smv01",
                  SV_MAX_SVID_LEN - 1);
    pub_cfg.smp_rate = 80;
    iec61850_sv_publisher_init(&pub, &pub_cfg);

    /* Configure and init subscriber */
    iec61850_sv_sub_config_init(&sub_cfg);
    sub_cfg.filter_appid = 0x4000;
    sub_cfg.smp_rate = 80;
    sub_cfg.timeout_ms = 5000;
    iec61850_sv_subscriber_init(&sub, &sub_cfg);
    iec61850_sv_subscriber_set_callback(&sub, on_sv, NULL);

    /* Frame build config — SV multicast MAC */
    iec61850_eth_frame_config_t fcfg;
    uint8_t apdu_buf[1024];
    size_t apdu_len = 0;
    memset(&fcfg, 0, sizeof(fcfg));
    fcfg.dst_mac[0] = 0x01; fcfg.dst_mac[1] = 0x0C; fcfg.dst_mac[2] = 0xCD;
    fcfg.dst_mac[3] = 0x04; fcfg.dst_mac[4] = 0x00; fcfg.dst_mac[5] = 0x01;
    fcfg.ethertype = IEC61850_ETHERTYPE_SV;
    fcfg.app_id = pub_cfg.app_id;

    /* Test 1: Publish and receive a sample */
    printf("  [TEST] publish and receive ... ");

    int32_t samples[4] = {1000, 2000, -500, 750};
    iec61850_sv_publisher_set_samples(&pub, samples, 4);
    ret = iec61850_sv_publisher_prepare(&pub, apdu_buf, sizeof(apdu_buf), &apdu_len);
    if (ret != 0) {
        printf("FAIL: prepare returned %d\n", ret);
        return 1;
    }
    ret = iec61850_eth_frame_build(frame, sizeof(frame), &fcfg,
                                     apdu_buf, apdu_len, &frame_len);
    if (ret != 0) {
        printf("FAIL: frame_build returned %d\n", ret);
        return 1;
    }

    ret = packet_io_send(tx_io, frame, (uint32_t)frame_len);
    if (ret != 0) {
        printf("FAIL: send returned %d\n", ret);
        return 1;
    }

    received_count = 0;
    attempts = 0;
    while (received_count == 0 && attempts < 100) {
        ret = iec61850_sv_subscriber_poll(&sub, rx_io);
        if (ret == 0) { usleep(10000); }
        attempts++;
    }

    if (received_count == 0) {
        printf("FAIL: no message received after %d attempts\n", attempts);
        return 1;
    }

    printf("PASS (smpCnt=%u, %d attempts)\n", last_smp_cnt, attempts);

    /* Test 2: Send multiple sequential samples, verify no gaps */
    printf("  [TEST] sequential samples (no gaps) ... ");

    received_count = 0;
    gap_detected = 0;
    for (int i = 0; i < 10; i++) {
        samples[0] = 1000 + i;
        iec61850_sv_publisher_set_samples(&pub, samples, 4);
        ret = iec61850_sv_publisher_prepare(&pub, apdu_buf, sizeof(apdu_buf), &apdu_len);
        if (ret == 0) {
            ret = iec61850_eth_frame_build(frame, sizeof(frame), &fcfg,
                                             apdu_buf, apdu_len, &frame_len);
            if (ret == 0) {
                (void)packet_io_send(tx_io, frame, (uint32_t)frame_len);
            }
        }
        usleep(1000);  /* 1ms between samples */
    }

    /* Receive all */
    attempts = 0;
    while (received_count < 10 && attempts < 200) {
        iec61850_sv_subscriber_poll(&sub, rx_io);
        usleep(5000);
        attempts++;
    }

    if (received_count < 10) {
        printf("FAIL: received only %d/10 samples\n", received_count);
        return 1;
    }

    if (gap_detected) {
        printf("FAIL: gap detected in sequential samples\n");
        return 1;
    }

    printf("PASS (%d samples, no gaps)\n", received_count);

    /* Cleanup */
    iec61850_sv_publisher_destroy(&pub);
    iec61850_sv_subscriber_destroy(&sub);
    packet_io_destroy(tx_io);
    packet_io_destroy(rx_io);

    printf("\n=== SV Loopback Test PASSED ===\n");
    return 0;
}
