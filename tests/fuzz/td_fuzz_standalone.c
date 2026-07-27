/*
 * Standalone driver for the fuzz targets.
 *
 * Linked in when libFuzzer is unavailable (gcc, or a clang without the
 * compiler-rt fuzzer runtime). Replays files given on the command line through
 * LLVMFuzzerTestOneInput, which is exactly what a regression corpus needs:
 *
 *     ./fuzz_td_api tests/fuzz/regressions/*
 *
 * With no arguments it reads a single input from stdin, so a crashing case can
 * be piped straight back in.
 *
 * Copyright (c) 2026 Redis, All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define TD_FUZZ_STANDALONE_MAX (16u * 1024u * 1024u)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static int run_stream(FILE *f, const char *name) {
    uint8_t *buf = (uint8_t *)malloc(TD_FUZZ_STANDALONE_MAX);
    if (buf == NULL) {
        fprintf(stderr, "out of memory\n");
        return 1;
    }
    const size_t n = fread(buf, 1, TD_FUZZ_STANDALONE_MAX, f);
    LLVMFuzzerTestOneInput(buf, n);
    printf("  ok  %-48s %zu bytes\n", name, n);
    free(buf);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        return run_stream(stdin, "<stdin>");
    }
    for (int i = 1; i < argc; i++) {
        FILE *f = fopen(argv[i], "rb");
        if (f == NULL) {
            fprintf(stderr, "cannot open %s\n", argv[i]);
            return 1;
        }
        const int rc = run_stream(f, argv[i]);
        fclose(f);
        if (rc != 0) {
            return rc;
        }
    }
    printf("replayed %d input(s) with no failure\n", argc - 1);
    return 0;
}
