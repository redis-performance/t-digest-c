/*
 * fuzz_td_merge -- targets td_merge(), the API most likely to be fed
 * attacker-influenced state in a server (merging digests that arrived over the
 * wire, or from another shard).
 *
 * Two independently built digests A and B, plus a third C that receives the
 * merge, so the pre-merge state stays available as the oracle:
 *
 *   - conservation   td_size(C) == td_size(A) + td_size(B)
 *   - identity       merging an empty digest changes nothing observable
 *   - structure      the target never exceeds its own capacity
 *   - read sanity    the merged digest still satisfies the quantile contracts
 *   - self-merge     td_merge(h, h) aliases the read and write arrays; it must
 *                    not corrupt memory even though the result is meaningless
 *
 * Copyright (c) 2026 Redis, All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "td_fuzz_util.h"
#include "tdigest.h"

#define TD_FUZZ_EXACT_LIMIT 9007199254740992LL
#define TD_FUZZ_MAX_FILL 8192

/* Fill a digest from the stream. Returns the total accepted weight, or -1 if
 * accounting stopped being exact (overflow, negative weight, non-finite mean). */
static long long fill(td_histogram_t *h, td_fuzz_reader *r, unsigned budget, int raw) {
    long long total = 0;
    int exact = 1;
    for (unsigned i = 0; i < budget && !td_fuzz_eof(r); i++) {
        const double v = raw ? td_fuzz_f64_raw(r) : td_fuzz_f64_tame(r);
        const long long w = raw ? td_fuzz_i64(r) : td_fuzz_weight_tame(r);
        if (td_add(h, v, w) != 0) {
            break;
        }
        if (!isfinite(v) || w < 1 || total > TD_FUZZ_EXACT_LIMIT - w) {
            exact = 0;
        }
        if (exact) {
            total += w;
        }
    }
    return exact ? total : -1;
}

static void check_capacity(const td_histogram_t *h, const char *who) {
    TD_FUZZ_CHECK(h->merged_nodes >= 0 && h->unmerged_nodes >= 0,
                  "%s: negative node counts %d/%d", who, h->merged_nodes, h->unmerged_nodes);
    TD_FUZZ_CHECK(h->merged_nodes + h->unmerged_nodes <= h->cap,
                  "%s: node count %d+%d exceeds cap %d -- out-of-bounds write reachable", who,
                  h->merged_nodes, h->unmerged_nodes, h->cap);
}

static void check_read_sanity(td_histogram_t *h, const char *who) {
    if (td_size(h) <= 0 || td_centroid_count(h) == 0) {
        return;
    }
    const double mn = td_min(h);
    const double mx = td_max(h);
    if (!isfinite(mn) || !isfinite(mx)) {
        return;
    }
    double prev = -INFINITY;
    for (int i = 0; i < TD_FUZZ_NQ; i++) {
        const double v = td_quantile(h, TD_FUZZ_QUANTILES[i]);
        TD_FUZZ_CHECK(!isnan(v), "%s: td_quantile(%g) is NaN on a non-empty digest", who,
                      TD_FUZZ_QUANTILES[i]);
        TD_FUZZ_CHECK(td_fuzz_ge(v, mn) && td_fuzz_ge(mx, v),
                      "%s: td_quantile(%g)=%.17g escapes [%.17g, %.17g]", who,
                      TD_FUZZ_QUANTILES[i], v, mn, mx);
        TD_FUZZ_CHECK(td_fuzz_ge(v, prev), "%s: td_quantile not monotonic at q=%g", who,
                      TD_FUZZ_QUANTILES[i]);
        prev = v;
    }
    const double p = td_cdf(h, mn);
    TD_FUZZ_CHECK(!isnan(p) && p >= 0.0 && p <= 1.0, "%s: td_cdf(min)=%.17g outside [0,1]", who, p);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) {
        return 0;
    }

    td_fuzz_reader r;
    td_fuzz_reader_init(&r, data, size);

    const double comp_a = td_fuzz_pick_compression(&r);
    const double comp_b = td_fuzz_pick_compression(&r);
    const uint8_t flags = td_fuzz_u8(&r);
    const int raw_a = (flags & 1u) != 0;
    const int raw_b = (flags & 2u) != 0;
    const unsigned budget_a = ((unsigned)td_fuzz_u8(&r) * 16u) % TD_FUZZ_MAX_FILL + 1u;
    const unsigned budget_b = ((unsigned)td_fuzz_u8(&r) * 16u) % TD_FUZZ_MAX_FILL + 1u;

    td_histogram_t *a = td_new(comp_a);
    td_histogram_t *b = td_new(comp_b);
    td_histogram_t *c = td_new(comp_a);
    td_histogram_t *empty = td_new(comp_b);
    if (!a || !b || !c || !empty) {
        if (a) td_free(a);
        if (b) td_free(b);
        if (c) td_free(c);
        if (empty) td_free(empty);
        return 0;
    }

    const long long total_a = fill(a, &r, budget_a, raw_a);
    const long long total_b = fill(b, &r, budget_b, raw_b);

    /* C gets the same stream as A by replaying it -- cheaper and more faithful
     * than a deep copy the library does not expose. */
    {
        td_fuzz_reader r2;
        td_fuzz_reader_init(&r2, data, size);
        (void)td_fuzz_pick_compression(&r2);
        (void)td_fuzz_pick_compression(&r2);
        (void)td_fuzz_u8(&r2);
        (void)td_fuzz_u8(&r2);
        (void)td_fuzz_u8(&r2);
        (void)fill(c, &r2, budget_a, raw_a);
    }

    check_capacity(a, "A");
    check_capacity(b, "B");
    check_capacity(c, "C");

    const long long size_c_before = td_size(c);

    /* --- identity: merging an empty digest must not change the target --- */
    {
        const int rc = td_merge(c, empty);
        TD_FUZZ_CHECK(rc == 0, "td_merge of an empty digest returned %d", rc);
        check_capacity(c, "C after empty merge");
        if (total_a >= 0) {
            TD_FUZZ_CHECK(td_size(c) == size_c_before,
                          "merging an empty digest changed td_size: %lld -> %lld", size_c_before,
                          td_size(c));
        }
    }

    /* --- conservation --- */
    {
        const long long before = td_size(c);
        const int rc = td_merge(c, b);
        check_capacity(c, "C after merge");
        check_capacity(b, "B after merge");

        if (rc == 0) {
            if (total_a >= 0 && total_b >= 0 && total_a <= TD_FUZZ_EXACT_LIMIT - total_b) {
                TD_FUZZ_CHECK(td_size(c) == before + total_b,
                              "td_merge lost weight: %lld + %lld != %lld", before, total_b,
                              td_size(c));
            }
        } else if (total_a >= 0 && total_b >= 0) {
            /* Header: "If overflow is detected the original histogram is not
             * [changed]." */
            TD_FUZZ_CHECK(td_size(c) == before,
                          "td_merge failed with %d but left the target partially merged: "
                          "td_size %lld -> %lld",
                          rc, before, td_size(c));
        }
        check_read_sanity(c, "merged");
    }

    /* --- self-merge: source and destination alias --- */
    (void)td_merge(a, a);
    check_capacity(a, "A after self-merge");

    td_free(a);
    td_free(b);
    td_free(c);
    td_free(empty);
    return 0;
}
