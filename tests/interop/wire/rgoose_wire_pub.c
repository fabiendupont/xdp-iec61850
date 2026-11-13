/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * R-GOOSE / R-SV wire publisher — IEC TR 61850-90-5 routable-profile
 * wire scenario (WP-4e).
 *
 * Publishes deterministic plain and secured 90-5 traffic on loopback
 * so a neutral capture (tshark/tcpdump on lo) can validate the
 * on-wire bytes:
 *
 *   - plain R-GOOSE: 5 SPDUs to 127.0.0.1:10201 (UDP backend, kernel
 *     IP/UDP headers)
 *   - plain R-SV:    5 SPDUs to 127.0.0.1:10202
 *   - secured R-GOOSE (HMAC-SHA256): 3 signed [Eth][IPv4][UDP][SPDU]
 *     frames to 127.0.0.1:10203, injected via a raw AF_PACKET socket
 *     on lo (needs CAP_NET_RAW; skipped with a marker otherwise)
 *   - secured R-SV:  3 signed frames to 127.0.0.1:10204
 *
 * Deterministic content (fixed keys, fixed dataset values) so the
 * committed reference capture (tests/interop/wire/reference/
 * rgoose_rsv.pcap) and the live capture carry identical payload
 * bytes; only IP identifiers/checksums/timestamps vary.
 *
 * Output markers consumed by test_wire_rgoose.sh:
 *   PLAIN_SENT rgoose <n> / PLAIN_SENT rsv <n>
 *   SECURE_SENT rgoose <n> / SECURE_SENT rsv <n>
 *   SECURE_SKIPPED <reason>
 *
 * Usage: rgoose_wire_pub
 *
 * Build (manual, matches the meson test link line):
 *   cc -std=c11 -I<src>/include/iec61850 -D_POSIX_C_SOURCE=200809L \
 *      -D_DEFAULT_SOURCE [-DIEC61850_SECURITY_ENABLED] \
 *      -o rgoose_wire_pub rgoose_wire_pub.c <libs...>
 */

#include "asn1/r_profile.h"
#include "goose/rgoose_publisher.h"
#include "goose/rgoose_subscriber.h"
#include "sv/rsv_publisher.h"
#include "sv/rsv_subscriber.h"
#include "transport/packet_io.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* Loopback ports (unique within the wire-test suite). */
#define RW_PORT_PLAIN_RGOOSE 10201U
#define RW_PORT_PLAIN_RSV    10202U
#define RW_PORT_SEC_RGOOSE   10203U
#define RW_PORT_SEC_RSV      10204U

#define RW_PLAIN_COUNT 5
#define RW_SECURE_COUNT 3

#define RW_GOCBREF "IED1LD0/LLN0$GO$gcb01"
#define RW_DATSET  "IED1LD0/LLN0$DS1"
#define RW_GOID    "IED1LD0GO"
#define RW_SVID    "IED1MU/LLN0$SV$smv01"
#define RW_SVDATSET "IED1MU/LLN0$DS1"

#ifdef IEC61850_SECURITY_ENABLED

/* Fixed test keys (mirrors the unit-test key material; deterministic
 * so the reference capture stays reproducible). */
static const uint8_t rgoose_key[16] = {
    0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U,
    0x99U, 0xAAU, 0xBBU, 0xCCU, 0xDDU, 0xEEU, 0xFFU, 0x00U
};
static const uint8_t rsv_key[16] = {
    0x21U, 0x32U, 0x43U, 0x54U, 0x65U, 0x76U, 0x87U, 0x98U,
    0xA9U, 0xBAU, 0xCBU, 0xDCU, 0xEDU, 0xFEU, 0x0FU, 0x10U
};
#define RGOOSE_KEY_ID 0xCAFEBABEU
#define RSV_KEY_ID    0xFEEDBEEFU

#endif /* IEC61850_SECURITY_ENABLED */

static int fill_rgoose_pub(iec61850_rgoose_pub_config_t *cfg, uint16_t port)
{
    iec61850_rgoose_pub_config_init(cfg);
    cfg->appid = 0x1001U;
    (void)snprintf(cfg->gocb_ref, sizeof(cfg->gocb_ref), "%s", RW_GOCBREF);
    (void)snprintf(cfg->dataset, sizeof(cfg->dataset), "%s", RW_DATSET);
    (void)snprintf(cfg->goose_id, sizeof(cfg->goose_id), "%s", RW_GOID);
    cfg->conf_rev = 1U;
    cfg->time_allowed_to_live = 2000U;
    (void)snprintf(cfg->dst_ip, sizeof(cfg->dst_ip), "127.0.0.1");
    cfg->dst_port = port;
    cfg->src_port = port;
    return 0;
}

static int fill_rsv_pub(iec61850_rsv_pub_config_t *cfg, uint16_t port)
{
    iec61850_rsv_pub_config_init(cfg);
    cfg->appid = 0x2001U;
    (void)snprintf(cfg->sv_id, sizeof(cfg->sv_id), "%s", RW_SVID);
    (void)snprintf(cfg->dataset, sizeof(cfg->dataset), "%s", RW_SVDATSET);
    cfg->conf_rev = 1U;
    cfg->smp_rate = 80U;
    cfg->num_channels = 4U;
    (void)snprintf(cfg->dst_ip, sizeof(cfg->dst_ip), "127.0.0.1");
    cfg->dst_port = port;
    cfg->src_port = port;
    return 0;
}

static int publish_plain_rgoose(void)
{
    iec61850_rgoose_pub_config_t cfg;
    iec61850_rgoose_sub_config_t scfg;
    iec61850_rgoose_publisher_t pub;
    iec61850_rgoose_subscriber_t sub;
    struct packet_io *tx;
    struct packet_io *rx;
    int rx_count = 0;
    int waited = 0;

    (void)fill_rgoose_pub(&cfg, (uint16_t)RW_PORT_PLAIN_RGOOSE);
    iec61850_rgoose_publisher_init(&pub, &cfg);
    (void)iec61850_rgoose_publisher_set_boolean(&pub, 0, true);
    (void)iec61850_rgoose_publisher_set_int32(&pub, 1, 1234);

    /* A real subscriber listens on the port: no ICMP unreachable
     * feedback on the connected sender socket, and the scenario
     * self-verifies that the published SPDUs are decodable. */
    iec61850_rgoose_sub_config_init(&scfg);
    scfg.timeout_ms = 30000U;
    iec61850_rgoose_subscriber_init(&sub, &scfg);

    tx = packet_io_create_udp_sender("127.0.0.1",
                                     (uint16_t)RW_PORT_PLAIN_RGOOSE, false);
    rx = packet_io_create_udp_receiver((uint16_t)RW_PORT_PLAIN_RGOOSE, NULL);
    if ((tx == NULL) || (rx == NULL)) {
        fprintf(stderr, "plain rgoose: udp io create failed\n");
        return -1;
    }
    if ((packet_io_open(tx, NULL, 0) != 0) ||
        (packet_io_open(rx, NULL, 0) != 0)) {
        fprintf(stderr, "plain rgoose: udp io open failed\n");
        packet_io_destroy(tx);
        packet_io_destroy(rx);
        return -1;
    }
    iec61850_rgoose_publisher_set_io(&pub, tx);

    for (int i = 0; i < RW_PLAIN_COUNT; i++) {
        if (iec61850_rgoose_publisher_publish(&pub) != 0) {
            fprintf(stderr, "plain rgoose: publish %d failed\n", i);
            return -1;
        }
        usleep(50000);
    }
    while ((rx_count < RW_PLAIN_COUNT) && (waited < 3000)) {
        rx_count += iec61850_rgoose_subscriber_poll(&sub, rx);
        usleep(1000);
        waited++;
    }

    printf("PLAIN_SENT rgoose %d\n", RW_PLAIN_COUNT);
    printf("PLAIN_RX rgoose %d\n", rx_count);
    iec61850_rgoose_publisher_destroy(&pub);
    iec61850_rgoose_subscriber_destroy(&sub);
    packet_io_close(rx);
    packet_io_close(tx);
    packet_io_destroy(rx);
    packet_io_destroy(tx);
    return (rx_count == RW_PLAIN_COUNT) ? 0 : -1;
}

static int publish_plain_rsv(void)
{
    iec61850_rsv_pub_config_t cfg;
    iec61850_rsv_sub_config_t scfg;
    iec61850_rsv_publisher_t pub;
    iec61850_rsv_subscriber_t sub;
    struct packet_io *tx;
    struct packet_io *rx;
    int32_t samples[4];
    int rx_count = 0;
    int waited = 0;

    (void)fill_rsv_pub(&cfg, (uint16_t)RW_PORT_PLAIN_RSV);
    iec61850_rsv_publisher_init(&pub, &cfg);

    iec61850_rsv_sub_config_init(&scfg);
    scfg.smp_rate = 80U;
    scfg.timeout_ms = 30000U;
    iec61850_rsv_subscriber_init(&sub, &scfg);

    tx = packet_io_create_udp_sender("127.0.0.1",
                                     (uint16_t)RW_PORT_PLAIN_RSV, false);
    rx = packet_io_create_udp_receiver((uint16_t)RW_PORT_PLAIN_RSV, NULL);
    if ((tx == NULL) || (rx == NULL)) {
        fprintf(stderr, "plain rsv: udp io create failed\n");
        return -1;
    }
    if ((packet_io_open(tx, NULL, 0) != 0) ||
        (packet_io_open(rx, NULL, 0) != 0)) {
        fprintf(stderr, "plain rsv: udp io open failed\n");
        packet_io_destroy(tx);
        packet_io_destroy(rx);
        return -1;
    }
    iec61850_rsv_publisher_set_io(&pub, tx);

    for (int i = 0; i < RW_PLAIN_COUNT; i++) {
        samples[0] = (int32_t)(1000 + i);
        samples[1] = (int32_t)(2000 + i);
        samples[2] = (int32_t)(-500 - i);
        samples[3] = (int32_t)(750 + i);
        (void)iec61850_rsv_publisher_set_samples(&pub, samples, 4);
        if (iec61850_rsv_publisher_publish(&pub) != 0) {
            fprintf(stderr, "plain rsv: publish %d failed\n", i);
            return -1;
        }
        usleep(50000);
    }
    while ((rx_count < RW_PLAIN_COUNT) && (waited < 3000)) {
        rx_count += iec61850_rsv_subscriber_poll(&sub, rx);
        usleep(1000);
        waited++;
    }

    printf("PLAIN_SENT rsv %d\n", RW_PLAIN_COUNT);
    printf("PLAIN_RX rsv %d\n", rx_count);
    iec61850_rsv_publisher_destroy(&pub);
    iec61850_rsv_subscriber_destroy(&sub);
    packet_io_close(rx);
    packet_io_close(tx);
    packet_io_destroy(rx);
    packet_io_destroy(tx);
    return (rx_count == RW_PLAIN_COUNT) ? 0 : -1;
}

#ifdef IEC61850_SECURITY_ENABLED

static int publish_secure_rgoose(struct packet_io *raw)
{
    iec61850_rgoose_pub_config_t cfg;
    iec61850_rgoose_pub_security_t sec;
    iec61850_rgoose_publisher_t pub;

    (void)fill_rgoose_pub(&cfg, (uint16_t)RW_PORT_SEC_RGOOSE);
    (void)snprintf(cfg.src_ip, sizeof(cfg.src_ip), "127.0.0.1");
    (void)memset(cfg.dst_mac, 0x00, 6);
    (void)memset(cfg.src_mac, 0x02, 6);
    iec61850_rgoose_publisher_init(&pub, &cfg);
    (void)iec61850_rgoose_publisher_set_boolean(&pub, 0, true);
    (void)iec61850_rgoose_publisher_set_int32(&pub, 1, 1234);

    (void)memset(&sec, 0, sizeof(sec));
    sec.algo = (uint16_t)IEC61850_RGOOSE_PUB_SEC_ALGO_HMAC_SHA256;
    (void)memcpy(sec.key, rgoose_key, sizeof(rgoose_key));
    sec.key_len = sizeof(rgoose_key);
    sec.key_id = RGOOSE_KEY_ID;
    sec.time_to_next_key = 720U;
    if (iec61850_rgoose_publisher_enable_security(&pub, &sec) != 0) {
        fprintf(stderr, "secure rgoose: enable_security failed\n");
        return -1;
    }
    iec61850_rgoose_publisher_set_io(&pub, raw);

    for (int i = 0; i < RW_SECURE_COUNT; i++) {
        if (iec61850_rgoose_publisher_publish(&pub) != 0) {
            fprintf(stderr, "secure rgoose: publish %d failed\n", i);
            return -1;
        }
        usleep(50000);
    }

    printf("SECURE_SENT rgoose %d\n", RW_SECURE_COUNT);
    iec61850_rgoose_publisher_destroy(&pub);
    return 0;
}

static int publish_secure_rsv(struct packet_io *raw)
{
    iec61850_rsv_pub_config_t cfg;
    iec61850_rsv_pub_security_t sec;
    iec61850_rsv_publisher_t pub;
    int32_t samples[4];

    (void)fill_rsv_pub(&cfg, (uint16_t)RW_PORT_SEC_RSV);
    (void)snprintf(cfg.src_ip, sizeof(cfg.src_ip), "127.0.0.1");
    (void)memset(cfg.dst_mac, 0x00, 6);
    (void)memset(cfg.src_mac, 0x02, 6);
    iec61850_rsv_publisher_init(&pub, &cfg);

    (void)memset(&sec, 0, sizeof(sec));
    sec.algo = (uint16_t)IEC61850_RSV_PUB_SEC_ALGO_HMAC_SHA256;
    (void)memcpy(sec.key, rsv_key, sizeof(rsv_key));
    sec.key_len = sizeof(rsv_key);
    sec.key_id = RSV_KEY_ID;
    sec.time_to_next_key = 720U;
    if (iec61850_rsv_publisher_enable_security(&pub, &sec) != 0) {
        fprintf(stderr, "secure rsv: enable_security failed\n");
        return -1;
    }
    iec61850_rsv_publisher_set_io(&pub, raw);

    for (int i = 0; i < RW_SECURE_COUNT; i++) {
        samples[0] = (int32_t)(1000 + i);
        samples[1] = (int32_t)(2000 + i);
        samples[2] = (int32_t)(-500 - i);
        samples[3] = (int32_t)(750 + i);
        (void)iec61850_rsv_publisher_set_samples(&pub, samples, 4);
        if (iec61850_rsv_publisher_publish(&pub) != 0) {
            fprintf(stderr, "secure rsv: publish %d failed\n", i);
            return -1;
        }
        usleep(50000);
    }

    printf("SECURE_SENT rsv %d\n", RW_SECURE_COUNT);
    iec61850_rsv_publisher_destroy(&pub);
    return 0;
}

static int publish_secure(void)
{
    struct packet_io *raw = packet_io_create_raw();
    int ret;

    if (raw == NULL) {
        printf("SECURE_SKIPPED raw create failed\n");
        return 0;
    }
    if (packet_io_open(raw, "lo", 0) != 0) {
        printf("SECURE_SKIPPED no CAP_NET_RAW for AF_PACKET on lo\n");
        packet_io_destroy(raw);
        return 0;
    }

    ret = publish_secure_rgoose(raw);
    if (ret == 0) {
        ret = publish_secure_rsv(raw);
    }

    packet_io_close(raw);
    packet_io_destroy(raw);
    return ret;
}

#else /* !IEC61850_SECURITY_ENABLED */

static int publish_secure(void)
{
    printf("SECURE_SKIPPED built without -Denable_security\n");
    return 0;
}

#endif /* IEC61850_SECURITY_ENABLED */

int main(void)
{
    if (publish_plain_rgoose() != 0) {
        return 1;
    }
    if (publish_plain_rsv() != 0) {
        return 1;
    }
    if (publish_secure() != 0) {
        return 1;
    }
    return 0;
}
