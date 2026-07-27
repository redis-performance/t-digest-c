/*
 * Shared helpers for the t-digest fuzz targets.
 *
 * Copyright (c) 2026 Redis, All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef TD_FUZZ_UTIL_H
#define TD_FUZZ_UTIL_H

#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* td_fuzz_dump() reads td_histogram_t fields directly. */
#include "tdigest.h"

/*
 * Fuzz targets are built with -DNDEBUG in Release, which compiles assert() out.
 * TD_FUZZ_CHECK is always live: it is the oracle, not a debug aid.
 */
#define TD_FUZZ_CHECK(cond, ...)                                                                   \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "t-digest fuzz oracle violated: %s\n  at %s:%d\n  ", #cond, __FILE__,  \
                    __LINE__);                                                                     \
            fprintf(stderr, __VA_ARGS__);                                                          \
            fprintf(stderr, "\n");                                                                 \
            fflush(stderr);                                                                        \
            abort();                                                                               \
        }                                                                                          \
    } while (0)

/*
 * Dump enough digest state to write a standalone repro from the log alone.
 * A bare "oracle violated" line tells you a bug exists; this tells you which
 * one, without re-running the fuzzer under a debugger.
 */
#define TD_FUZZ_DUMP_CENTROIDS 12

static inline void td_fuzz_dump(const struct td_histogram *h, const char *label) {
    if (h == NULL) {
        fprintf(stderr, "  [%s] histogram = NULL\n", label);
        return;
    }
    fprintf(stderr,
            "  [%s] compression=%.17g cap=%d merged_nodes=%d unmerged_nodes=%d\n"
            "        merged_weight=%lld unmerged_weight=%lld total_compressions=%lld\n"
            "        min=%.17g max=%.17g\n",
            label, h->compression, h->cap, h->merged_nodes, h->unmerged_nodes, h->merged_weight,
            h->unmerged_weight, h->total_compressions, h->min, h->max);

    const int n = h->merged_nodes + h->unmerged_nodes;
    const int shown = (n < TD_FUZZ_DUMP_CENTROIDS) ? n : TD_FUZZ_DUMP_CENTROIDS;
    for (int i = 0; i < shown; i++) {
        fprintf(stderr, "        centroid[%d] mean=%.17g weight=%lld%s\n", i, h->nodes_mean[i],
                h->nodes_weight[i], (i >= h->merged_nodes) ? "  (unmerged)" : "");
    }
    if (n > shown) {
        fprintf(stderr, "        ... %d more centroids\n", n - shown);
    }
}

/* TD_FUZZ_CHECK plus a state dump of the histogram that failed. */
#define TD_FUZZ_CHECK_H(h, cond, ...)                                                              \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            fprintf(stderr, "t-digest fuzz oracle violated: %s\n  at %s:%d\n  ", #cond, __FILE__,  \
                    __LINE__);                                                                     \
            fprintf(stderr, __VA_ARGS__);                                                          \
            fprintf(stderr, "\n");                                                                 \
            td_fuzz_dump((h), #h);                                                                 \
            fflush(stderr);                                                                        \
            abort();                                                                               \
        }                                                                                          \
    } while (0)

/* ------------------------------------------------------------------ */
/* Byte-stream reader over the fuzzer input                            */
/* ------------------------------------------------------------------ */

typedef struct {
    const uint8_t *data;
    size_t size;
    size_t pos;
} td_fuzz_reader;

static inline void td_fuzz_reader_init(td_fuzz_reader *r, const uint8_t *data, size_t size) {
    r->data = data;
    r->size = size;
    r->pos = 0;
}

static inline int td_fuzz_eof(const td_fuzz_reader *r) { return r->pos >= r->size; }

static inline size_t td_fuzz_remaining(const td_fuzz_reader *r) { return r->size - r->pos; }

static inline uint8_t td_fuzz_u8(td_fuzz_reader *r) {
    if (td_fuzz_eof(r)) {
        return 0;
    }
    return r->data[r->pos++];
}

static inline uint64_t td_fuzz_u64(td_fuzz_reader *r) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) {
        v = (v << 8) | (uint64_t)td_fuzz_u8(r);
    }
    return v;
}

/* Raw bit pattern -> double. Deliberately yields NaN / Inf / subnormals. */
static inline double td_fuzz_f64_raw(td_fuzz_reader *r) {
    uint64_t bits = td_fuzz_u64(r);
    double d;
    memcpy(&d, &bits, sizeof(d));
    return d;
}

static inline long long td_fuzz_i64(td_fuzz_reader *r) {
    uint64_t bits = td_fuzz_u64(r);
    long long v;
    memcpy(&v, &bits, sizeof(v));
    return v;
}

/*
 * A "tame" value: cheap to encode (2 bytes) and lands in a range where a
 * t-digest behaves like a real histogram. Without this the fuzzer burns most
 * of its budget on NaN soup and never builds a digest deep enough to exercise
 * the merge / interpolation paths.
 */
static inline double td_fuzz_f64_tame(td_fuzz_reader *r) {
    static const double scales[8] = {1.0, 1e-3, 1e3, 1e6, 0.5, 100.0, 1e-6, 1e9};
    const uint8_t mag = td_fuzz_u8(r);
    const uint8_t sel = td_fuzz_u8(r);
    const double base = (double)mag;
    const double v = base * scales[sel & 7u];
    return (sel & 8u) ? -v : v;
}

/* A weight in [1, 65535] -- the well-formed side of the API contract. */
static inline long long td_fuzz_weight_tame(td_fuzz_reader *r) {
    const uint32_t lo = td_fuzz_u8(r);
    const uint32_t hi = td_fuzz_u8(r);
    return (long long)((hi << 8) | lo) + 1;
}

/* ------------------------------------------------------------------ */
/* Compression selection                                               */
/* ------------------------------------------------------------------ */

/*
 * Valid compressions only. cap_from_compression() is 6*compression+10 nodes,
 * so an unbounded compression turns the fuzzer into an allocator stress test
 * and every finding becomes an OOM. Invalid/degenerate compressions are the
 * job of fuzz_td_init, which does not allocate deeply.
 */
static const double TD_FUZZ_COMPRESSIONS[8] = {1.0,   2.0,   5.0,   10.0,
                                               50.0,  100.0, 300.0, 1000.0};

static inline double td_fuzz_pick_compression(td_fuzz_reader *r) {
    return TD_FUZZ_COMPRESSIONS[td_fuzz_u8(r) & 7u];
}

/* ------------------------------------------------------------------ */
/* Oracles                                                             */
/* ------------------------------------------------------------------ */

/* Doubles compare equal-or-both-NaN, with a relative tolerance. */
static inline int td_fuzz_close(double a, double b) {
    if (isnan(a) && isnan(b)) {
        return 1;
    }
    if (a == b) {
        return 1;
    }
    if (isnan(a) || isnan(b) || isinf(a) || isinf(b)) {
        return 0;
    }
    const double scale = fmax(1.0, fmax(fabs(a), fabs(b)));
    return fabs(a - b) <= 1e-9 * scale;
}

/* Monotonicity check with a relative slack, so FP wobble is not a finding. */
static inline int td_fuzz_ge(double v, double prev) {
    if (v >= prev) {
        return 1;
    }
    const double scale = fmax(1.0, fmax(fabs(v), fabs(prev)));
    return (prev - v) <= 1e-9 * scale;
}

/* Ascending probe points shared by the quantile and cdf oracles. */
#define TD_FUZZ_NQ 13
static const double TD_FUZZ_QUANTILES[TD_FUZZ_NQ] = {0.0,   0.0001, 0.001, 0.01, 0.1,
                                                     0.25,  0.5,    0.75,  0.9,  0.99,
                                                     0.999, 0.9999, 1.0};

#endif /* TD_FUZZ_UTIL_H */
