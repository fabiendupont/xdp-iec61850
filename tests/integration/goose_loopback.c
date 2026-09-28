/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * GOOSE Loopback Integration Test
 *
 * Sends a GOOSE frame on one end of a veth pair via raw socket,
 * receives it on the other end, decodes, and verifies round-trip.
 *
 * Requires: CAP_NET_RAW (run as root or with sudo)
 *
 * The veth pair must be created externally (see test_goose_loopback.sh).
 * Interface names are passed as argv[1] (tx) and argv[2] (rx).
 */

#define _POSIX_C_SOURCE 200809L
#define _DEFAULT_SOURCE

#include "goose/goose_publisher.h"
#include "goose/goose_subscriber.h"
#include "transport/packet_io.h"
#include "transport/eth_frame.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int received_count = 0;
static uint32_t received_st_num = 0;
static char received_gocbref[GOOSE_MAX_GOCBREF_LEN] = {0};

static void on_goose(const iec61850_goose_message_t *msg, void *user_data)
{
    (void)user_data;
    received_count++;
    received_st_num = msg->apdu.stNum;
    (void)strncpy(received_gocbref, msg->apdu.gocbRef,
                  GOOSE_MAX_GOCBREF_LEN - 1);
}

int main(int argc, char *argv[])
{
    const char *tx_if, *rx_if;
    struct packet_io *tx_io, *rx_io;
    iec61850_goose_publisher_t pub;
    iec61850_goose_subscriber_t sub;
    iec61850_goose_config_t pub_cfg;
    iec61850_goose_sub_config_t sub_cfg;
    uint8_t frame[1518];
    size_t frame_len = 0;
    int ret, attempts;

    if (argc < 3) {
        fprintf(stderr, "SKIP: %s requires <tx_interface> <rx_interface> — run via test_goose_loopback.sh\n",
                argv[0]);
        return 77;
    }
    tx_if = argv[1];
    rx_if = argv[2];

    printf("=== GOOSE Loopback Test ===\n");
    printf("TX: %s, RX: %s\n", tx_if, rx_if);

    /* Create raw socket I/O for TX and RX */
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
    iec61850_goose_config_init(&pub_cfg);
    pub_cfg.app_id = 0x0001;
    (void)strncpy(pub_cfg.gocb_ref, "IED1LD0/LLN0$GO$gcb01",
                  GOOSE_MAX_GOCBREF_LEN - 1);
    (void)strncpy(pub_cfg.dataset, "IED1LD0/LLN0$DS1",
                  GOOSE_MAX_DATSET_LEN - 1);
    iec61850_goose_publisher_init(&pub, &pub_cfg);
    iec61850_goose_publisher_set_boolean(&pub, 0, true);
    iec61850_goose_publisher_set_int32(&pub, 1, 42);

    /* Configure and init subscriber */
    iec61850_goose_sub_config_init(&sub_cfg);
    sub_cfg.filter_appid = 0x0001;
    sub_cfg.timeout_ms = 5000;
    iec61850_goose_subscriber_init(&sub, &sub_cfg);
    iec61850_goose_subscriber_set_callback(&sub, on_goose, NULL);

    /* Frame build config */
    iec61850_eth_frame_config_t fcfg;
    uint8_t apdu_buf[1024];
    size_t apdu_len = 0;
    memset(&fcfg, 0, sizeof(fcfg));
    memcpy(fcfg.dst_mac, pub_cfg.dst_mac, 6);
    fcfg.ethertype = IEC61850_ETHERTYPE_GOOSE;
    fcfg.app_id = pub_cfg.app_id;

    /* Test 1: Publish a frame and receive it */
    printf("  [TEST] publish and receive ... ");

    ret = iec61850_goose_publisher_prepare(&pub, apdu_buf, sizeof(apdu_buf), &apdu_len);
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

    /* Poll for the frame (up to 1 second) */
    received_count = 0;
    attempts = 0;
    while (received_count == 0 && attempts < 100) {
        ret = iec61850_goose_subscriber_poll(&sub, rx_io);
        if (ret < 0) {
            printf("FAIL: poll returned %d\n", ret);
            return 1;
        }
        if (ret == 0) {
            usleep(10000);  /* 10ms */
        }
        attempts++;
    }

    if (received_count == 0) {
        printf("FAIL: no message received after %d attempts\n", attempts);
        return 1;
    }

    if (strcmp(received_gocbref, "IED1LD0/LLN0$GO$gcb01") != 0) {
        printf("FAIL: gocbRef mismatch: got '%s'\n", received_gocbref);
        return 1;
    }

    printf("PASS (%d attempts)\n", attempts);
    uint32_t first_st_num = received_st_num;

    /* Drain any queued noise before state change test */
    {
        void *drain_pkt = NULL;
        uint32_t drain_len = 0;
        while (packet_io_recv(rx_io, &drain_pkt, &drain_len) > 0) {
            packet_io_release(rx_io);
        }
    }

    /* Test 2: State change increments stNum */
    printf("  [TEST] state change round-trip ... ");

    iec61850_goose_publisher_state_change(&pub);
    iec61850_goose_publisher_set_boolean(&pub, 0, false);
    ret = iec61850_goose_publisher_prepare(&pub, apdu_buf, sizeof(apdu_buf), &apdu_len);
    if (ret != 0) {
        printf("FAIL: prepare returned %d\n", ret);
        return 1;
    }
    (void)iec61850_eth_frame_build(frame, sizeof(frame), &fcfg,
                                     apdu_buf, apdu_len, &frame_len);
    (void)packet_io_send(tx_io, frame, (uint32_t)frame_len);

    received_count = 0;
    received_st_num = 0;
    attempts = 0;
    while (received_st_num <= first_st_num && attempts < 200) {
        ret = iec61850_goose_subscriber_poll(&sub, rx_io);
        if (ret == 0) { usleep(10000); }
        attempts++;
    }

    if (received_st_num <= first_st_num) {
        printf("FAIL: stNum not incremented: %u (was %u)\n",
               received_st_num, first_st_num);
        return 1;
    }

    printf("PASS (stNum=%u)\n", received_st_num);

    /* Test 3: APPID filter — subscriber should ignore wrong APPID */
    printf("  [TEST] APPID filter ... ");

    pub_cfg.app_id = 0x9999;
    iec61850_goose_publisher_t pub2;
    iec61850_goose_publisher_init(&pub2, &pub_cfg);
    iec61850_goose_publisher_set_boolean(&pub2, 0, true);
    ret = iec61850_goose_publisher_prepare(&pub2, apdu_buf, sizeof(apdu_buf), &apdu_len);
    if (ret == 0) {
        iec61850_eth_frame_config_t fcfg2;
        memset(&fcfg2, 0, sizeof(fcfg2));
        memcpy(fcfg2.dst_mac, pub_cfg.dst_mac, 6);
        fcfg2.ethertype = IEC61850_ETHERTYPE_GOOSE;
        fcfg2.app_id = 0x9999;
        if (iec61850_eth_frame_build(frame, sizeof(frame), &fcfg2,
                                       apdu_buf, apdu_len, &frame_len) == 0) {
            (void)packet_io_send(tx_io, frame, (uint32_t)frame_len);
        }
    }
    iec61850_goose_publisher_destroy(&pub2);

    /* Wait briefly and verify no message received */
    received_count = 0;
    for (int i = 0; i < 20; i++) {
        iec61850_goose_subscriber_poll(&sub, rx_io);
        usleep(5000);
    }

    if (received_count > 0) {
        printf("FAIL: received message with wrong APPID\n");
        return 1;
    }
    printf("PASS\n");

    /* Cleanup */
    iec61850_goose_publisher_destroy(&pub);
    iec61850_goose_subscriber_destroy(&sub);
    packet_io_destroy(tx_io);
    packet_io_destroy(rx_io);

    printf("\n=== GOOSE Loopback Test PASSED ===\n");
    return 0;
}
