/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Fuzz Target: SCL Parser
 *
 * Persist fuzzed bytes to a temporary file and feed it to
 * iec61850_scl_parse_file. The input is attacker-controlled XML:
 * truncated documents, corrupt attribute values, deeply nested
 * elements and non-XML bytes must all be handled without crash,
 * leak, or UB, including on libxml2 error/recovery paths.
 *
 * Compatible with both AFL and libFuzzer entry points.
 *
 * Build:
 *   ninja -C builddir tests/fuzz_scl_parser
 *
 * Or run as standalone for 10 seconds with mutated input:
 *   ./builddir/tests/fuzz_scl_parser
 *
 * License: BSD-2-Clause
 */

/* Strict C11 (c_std=c11): request POSIX for mkstemp/close/fdopen/unlink. */
#define _POSIX_C_SOURCE 200809L

#include "scl/scl_parser.h"

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* mkstemp requires a modifiable template buffer */
static const char TEMP_TEMPLATE[] = "/tmp/iec61850_scl_fuzz_XXXXXX";

/* libFuzzer entry point */
#ifdef __AFL_COMPILER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char temp_path[sizeof(TEMP_TEMPLATE)];
    memcpy(temp_path, TEMP_TEMPLATE, sizeof(TEMP_TEMPLATE));

    int fd = mkstemp(temp_path);
    if (fd < 0) {
        return 0;
    }

    /* Persist the fuzz input; the parser only accepts a filename */
    FILE *fp = fdopen(fd, "wb");
    if (fp == NULL) {
        close(fd);
        unlink(temp_path);
        return 0;
    }
    if (size > 0) {
        (void)fwrite(data, 1, size, fp);
    }
    (void)fclose(fp);

    /* The document is several MB of fixed-size storage (no heap
     * members): heap-allocate it and re-init between parses. There
     * is no scl free function — iec61850_scl_doc_init is the whole
     * lifecycle. */
    iec61850_scl_doc_t *doc = (iec61850_scl_doc_t *)malloc(sizeof(*doc));
    if (doc == NULL) {
        unlink(temp_path);
        return 0;
    }

    /* Parse with an explicit IED name ... */
    iec61850_scl_doc_init(doc);
    (void)iec61850_scl_parse_file(temp_path, "IED1", doc);

    /* ... and with NULL (first-IED lookup path) */
    iec61850_scl_doc_init(doc);
    (void)iec61850_scl_parse_file(temp_path, NULL, doc);

    /* Exercise the lookup helpers with an input-derived key */
    char key[IEC61850_SCL_MAX_NAME] = {0};
    size_t key_len = (size < sizeof(key) - 1) ? size : sizeof(key) - 1;
    if (key_len > 0) {
        memcpy(key, data, key_len);
    }
    (void)iec61850_scl_find_goose_cb(doc, key);
    (void)iec61850_scl_find_sv_cb(doc, key);
    (void)iec61850_scl_find_rcb(doc, key);
    (void)iec61850_scl_find_dataset(doc, key);
    (void)iec61850_scl_find_lnode_type(doc, key);
    (void)iec61850_scl_find_do_type(doc, key);
    (void)iec61850_scl_find_da_type(doc, key);
    (void)iec61850_scl_find_enum_type(doc, key);

    free(doc);
    unlink(temp_path);
    return 0;
}

/* Standalone mode for non-fuzzer testing */
#ifndef __AFL_COMPILER
#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION

/* Minimal valid SCL document used as the mutation base so the
 * standalone loop exercises real libxml2 parse paths, not just
 * random bytes that fail at the first '<'. */
static const char STANDALONE_SEED[] =
    "<?xml version=\"1.0\"?>"
    "<SCL version=\"2007\">"
    "<IED name=\"IED1\">"
    "<AccessPoint name=\"AP1\"><Server><LDevice inst=\"LD0\">"
    "<LN0 lnClass=\"LLN0\" inst=\"\" lnType=\"LLN0\">"
    "<DataSet name=\"DS1\">"
    "<FCDA ldInst=\"LD0\" lnClass=\"XCBR\" lnInst=\"1\" "
    "doName=\"Pos\" daName=\"stVal\" fc=\"ST\"/>"
    "</DataSet>"
    "<GSEControl name=\"gcb01\" datSet=\"DS1\" confRev=\"1\" "
    "appID=\"GOOSE1\" goID=\"GOOSE_ID_1\"/>"
    "</LN0></LDevice></Server></AccessPoint></IED>"
    "<Communication><SubNetwork name=\"SN1\">"
    "<ConnectedAP iedName=\"IED1\" apName=\"AP1\">"
    "<GSE ldInst=\"LD0\" cbName=\"gcb01\"><Address>"
    "<P type=\"APPID\">0001</P><P type=\"MAC-Address\">01-0C-CD-01-00-01</P>"
    "<P type=\"VLAN-ID\">100</P><P type=\"VLAN-PRIORITY\">4</P>"
    "</Address></GSE>"
    "</ConnectedAP></SubNetwork></Communication>"
    "<DataTypeTemplates>"
    "<LNodeType id=\"LLN0\" lnClass=\"LLN0\"/>"
    "<DOType id=\"DPC_1\" cdc=\"DPC\">"
    "<DA name=\"stVal\" fc=\"ST\" bType=\"Dbpos\"/>"
    "</DOType>"
    "</DataTypeTemplates>"
    "</SCL>";

int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

    printf("SCL parser fuzz: standalone mode (10 seconds)\n");
    srand((unsigned int)time(NULL));

    size_t seed_len = sizeof(STANDALONE_SEED) - 1;
    time_t start = time(NULL);
    uint64_t iterations = 0;

    while (time(NULL) - start < 10) {
        uint8_t *buf;
        size_t len;

        if ((rand() % 2) == 0) {
            /* Fully random bytes: non-XML garbage */
            len = (size_t)(rand() % 2048);
            buf = (uint8_t *)malloc(len > 0 ? len : 1);
            if (buf == NULL) { continue; }

            for (size_t i = 0; i < len; i++) {
                buf[i] = (uint8_t)(rand() % 256);
            }
        } else {
            /* Mutation of a valid SCL document: random truncation
             * (truncated XML) plus random byte corruption (bad
             * attribute values, broken tags). */
            buf = (uint8_t *)malloc(seed_len);
            if (buf == NULL) { continue; }
            memcpy(buf, STANDALONE_SEED, seed_len);
            len = (size_t)(rand() % (int)(seed_len + 1));

            for (int i = 0; i < 8; i++) {
                if (len == 0) { break; }
                buf[(size_t)rand() % len] = (uint8_t)(rand() % 256);
            }
        }

        LLVMFuzzerTestOneInput(buf, len);
        free(buf);
        iterations++;
    }

    printf("Completed %lu iterations without crash\n", (unsigned long)iterations);
    return 0;
}

#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
#endif /* __AFL_COMPILER */
