/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Secure GOOSE End-to-End Test
 *
 * Tests GOOSE publish with IEC 62351-6 security extension, then
 * verifies the security extension in the frame and checks PDU Length
 * includes the extension bytes.
 */


#include "goose/goose_publisher.h"
#include "goose/goose_subscriber.h"
#include "transport/eth_frame.h"
#include "security/key_manager.h"
#include "security/cert_manager.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Minimal test framework */
static int test_run = 0, test_passed = 0, test_failed = 0;
#define TEST(name) do { test_run++; printf("  [TEST] %s ...", name); } while(0)
#define PASS() do { test_passed++; printf(" PASS\n"); return; } while(0)
#define FAIL(msg) do { test_failed++; printf(" FAIL: %s\n", msg); return; } while(0)
#define ASSERT_TRUE(x) do { if (!(x)) { FAIL(#x); } } while(0)
#define ASSERT_EQ(a,b) do { if ((a) != (b)) { printf(" (got %d, want %d)", (a), (b)); FAIL(#a " != " #b); } } while(0)

static void build_path(char *buf, size_t size, const char *filename)
{
    const char *root = getenv("MESON_SOURCE_ROOT");
    if (root != NULL) {
        (void)snprintf(buf, size, "%s/tests/data/certs/%s", root, filename);
    } else {
        (void)snprintf(buf, size, "tests/data/certs/%s", filename);
    }
}

static void test_security_extension_in_frame(void)
{
    TEST("security_extension_in_frame");

    /* Load key and cert */
    iec61850_key_manager_t km;
    iec61850_key_manager_init(&km);
    char key_path[512];
    build_path(key_path, sizeof(key_path), "rsa_2048.key");
    int ret = iec61850_key_manager_load_private_key(&km, key_path, NULL);
    ASSERT_EQ(ret, IEC61850_SEC_OK);

    iec61850_cert_manager_t cm;
    iec61850_cert_manager_init(&cm);
    char cert_path[512];
    build_path(cert_path, sizeof(cert_path), "rsa_2048_cert.pem");
    ret = iec61850_cert_manager_load(&cm, cert_path);
    ASSERT_EQ(ret, IEC61850_SEC_OK);

    /* Create publisher with security */
    iec61850_goose_publisher_t pub;
    iec61850_goose_config_t cfg;
    iec61850_goose_config_init(&cfg);
    cfg.vlan_id = 0;  /* No VLAN for simpler frame parsing */
    iec61850_goose_publisher_init(&pub, &cfg);

    ret = iec61850_goose_publisher_enable_security(&pub, &km, &cm);
    ASSERT_EQ(ret, 0);

    /* Set some data */
    (void)iec61850_goose_publisher_set_boolean(&pub, 0, true);
    (void)iec61850_goose_publisher_set_int32(&pub, 1, 12345);

    /* Encode APDU */
    uint8_t apdu_buf[GOOSE_MAX_APDU_SIZE];
    size_t apdu_len = 0;
    ret = iec61850_goose_publisher_prepare(&pub, apdu_buf, sizeof(apdu_buf),
                                            &apdu_len);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(apdu_len > 0);

    /* Build frame + security extension (manual, matching publish() logic) */
    uint8_t frame_buf[IEC61850_MAX_FRAME_SIZE];
    size_t frame_len = 0;
    iec61850_eth_frame_config_t fcfg;
    (void)memset(&fcfg, 0, sizeof(fcfg));
    fcfg.dst_mac[0] = 0x01; fcfg.dst_mac[1] = 0x0C; fcfg.dst_mac[2] = 0xCD;
    fcfg.dst_mac[3] = 0x01; fcfg.dst_mac[4] = 0x00; fcfg.dst_mac[5] = 0x01;
    fcfg.ethertype = IEC61850_ETHERTYPE_GOOSE;
    fcfg.app_id = 1;

    ret = iec61850_eth_frame_build(frame_buf, sizeof(frame_buf), &fcfg,
                                    apdu_buf, apdu_len, &frame_len);
    ASSERT_EQ(ret, 0);

    /* Parse the frame to verify initial PDU Length */
    uint16_t et, appid, vlan;
    const uint8_t *parsed_apdu;
    size_t parsed_len;
    ret = iec61850_eth_frame_parse(frame_buf, frame_len,
                                    &et, &appid, &vlan, &parsed_apdu, &parsed_len, NULL);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ((int)parsed_len, (int)apdu_len);

    /* Manually sign and append security extension (matching publisher code) */
    uint8_t sig_buf[512];
    size_t sig_len = 0;
    ret = iec61850_key_manager_sign(&km, apdu_buf, apdu_len,
                                     sig_buf, sizeof(sig_buf), &sig_len);
    ASSERT_EQ(ret, IEC61850_SEC_OK);
    ASSERT_TRUE(sig_len > 0);

    /* Append a minimal security extension: tag 0xAC + length + sig */
    size_t ext_pos = frame_len;
    frame_buf[ext_pos++] = 0xAC;  /* CONSTRUCTED [12] */
    frame_buf[ext_pos++] = (uint8_t)(2 + sig_len);  /* simplified: just sig */
    frame_buf[ext_pos++] = 0x82;  /* [2] signature */
    frame_buf[ext_pos++] = (uint8_t)sig_len;
    (void)memcpy(&frame_buf[ext_pos], sig_buf, sig_len);
    ext_pos += sig_len;
    frame_len = ext_pos;

    /* Update PDU Length */
    ret = iec61850_eth_frame_update_pdu_length(frame_buf, frame_len, false);
    ASSERT_EQ(ret, 0);

    /* Parse again — PDU Length should include security extension */
    ret = iec61850_eth_frame_parse(frame_buf, frame_len,
                                    &et, &appid, &vlan, &parsed_apdu, &parsed_len, NULL);
    ASSERT_EQ(ret, 0);
    ASSERT_TRUE(parsed_len > apdu_len);  /* APDU + security extension */

    iec61850_key_manager_destroy(&km);
    iec61850_cert_manager_destroy(&cm);
    iec61850_goose_publisher_destroy(&pub);
    PASS();
}

static void test_cert_validity_check(void)
{
    TEST("cert_validity_check");

    iec61850_cert_manager_t cm;
    iec61850_cert_manager_init(&cm);
    char cert_path[512];
    build_path(cert_path, sizeof(cert_path), "rsa_2048_cert.pem");

    int ret = iec61850_cert_manager_load(&cm, cert_path);
    ASSERT_EQ(ret, IEC61850_SEC_OK);

    /* Test cert should be currently valid (generated recently) */
    bool valid = iec61850_cert_manager_is_valid_time(&cm);
    ASSERT_TRUE(valid);

    /* NULL check */
    ASSERT_TRUE(!iec61850_cert_manager_is_valid_time(NULL));

    iec61850_cert_manager_destroy(&cm);
    PASS();
}

static void test_cert_chain_self_signed(void)
{
    TEST("cert_chain_self_signed");

    iec61850_cert_manager_t cm;
    iec61850_cert_manager_init(&cm);
    char cert_path[512];
    build_path(cert_path, sizeof(cert_path), "rsa_2048_cert.pem");

    int ret = iec61850_cert_manager_load(&cm, cert_path);
    ASSERT_EQ(ret, IEC61850_SEC_OK);

    /* Self-signed cert: chain verification against itself should succeed */
    const char *ca_paths[] = { cert_path };
    ret = iec61850_cert_manager_verify_chain(&cm, ca_paths, 1);
    ASSERT_EQ(ret, IEC61850_SEC_OK);

    /* NULL args */
    ret = iec61850_cert_manager_verify_chain(NULL, ca_paths, 1);
    ASSERT_EQ(ret, IEC61850_SEC_ERR_ARGS);

    ret = iec61850_cert_manager_verify_chain(&cm, NULL, 1);
    ASSERT_EQ(ret, IEC61850_SEC_ERR_ARGS);

    iec61850_cert_manager_destroy(&cm);
    PASS();
}

int main(void)
{
    printf("\n=== Secure GOOSE E2E Tests ===\n");

    test_security_extension_in_frame();
    test_cert_validity_check();
    test_cert_chain_self_signed();

    printf("\n  Results: %d/%d passed\n\n", test_passed, test_run);
    return (test_failed > 0) ? 1 : 0;
}
