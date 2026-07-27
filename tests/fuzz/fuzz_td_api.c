/*
 * fuzz_td_api -- stateful sequence fuzzer for the whole public t-digest API.
 *
 * The input byte stream is decoded as a program: an opcode plus operands per
 * step, driving two histograms. Beyond crash/sanitizer coverage the harness
 * carries a shadow model and asserts the contracts the header promises:
 *
 *   - capacity        merged_nodes + unmerged_nodes <= cap, always
 *   - accounting      td_size() == sum of weights of successful td_add() calls
 *   - failure atomic  a call returning EDOM leaves td_size() unchanged
 *   - ordering        after a compress, merged centroid means are non-decreasing
 *   - quantiles       q -> td_quantile(q) is non-decreasing and lands in [min,max]
 *   - cdf             x -> td_cdf(x) is non-decreasing and lands in [0,1]
 *   - batch == scalar td_quantiles() agrees with td_quantile() on sorted input
 *
 * The value oracles only run while the histogram is "well-formed": every
 * accepted sample had a finite mean and a weight >= 1, and the total weight is
 * still exactly representable in a double. Feeding NaN means or negative
 * weights is legal input for crash-hunting but voids the numeric contracts, so
 * those runs degrade to crash-only rather than producing false positives.
 *
 * Copyright (c) 2026 Redis, All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "td_fuzz_util.h"
#include "tdigest.h"

#include <errno.h>

#define TD_FUZZ_NHIST 2
#define TD_FUZZ_MAX_OPS 4096
#define TD_FUZZ_MAX_BURST 512

/* 2^53 -- above this a long long weight no longer round-trips through double,
 * and the library's own accounting goes through double. */
#define TD_FUZZ_EXACT_LIMIT 9007199254740992LL

typedef struct {
    td_histogram_t *h;
    long long expected_weight; /* sum of weights of accepted samples */
    int acct_ok;               /* weight accounting is still exact */
    int well_formed;           /* acct_ok && all means finite && all weights >= 1 */
} td_fuzz_slot;

static void slot_reset_model(td_fuzz_slot *s) {
    s->expected_weight = 0;
    s->acct_ok = 1;
    s->well_formed = 1;
}

/* ------------------------------------------------------------------ */
/* Structural invariants -- must hold for any input, well-formed or not */
/* ------------------------------------------------------------------ */

static void check_structure(const td_fuzz_slot *s) {
    const td_histogram_t *h = s->h;
    TD_FUZZ_CHECK(h->merged_nodes >= 0, "merged_nodes=%d", h->merged_nodes);
    TD_FUZZ_CHECK(h->unmerged_nodes >= 0, "unmerged_nodes=%d", h->unmerged_nodes);
    TD_FUZZ_CHECK(h->merged_nodes + h->unmerged_nodes <= h->cap,
                  "node count %d+%d exceeds cap %d -- out-of-bounds write reachable",
                  h->merged_nodes, h->unmerged_nodes, h->cap);
    TD_FUZZ_CHECK(td_centroid_count((td_histogram_t *)h) <= h->cap, "centroid_count %d > cap %d",
                  td_centroid_count((td_histogram_t *)h), h->cap);
}

static void check_accounting(const td_fuzz_slot *s) {
    if (!s->acct_ok) {
        return;
    }
    const long long size = td_size((td_histogram_t *)s->h);
    TD_FUZZ_CHECK(size == s->expected_weight, "td_size()=%lld but %lld was accepted", size,
                  s->expected_weight);
}

/* After any compress the merged prefix must be sorted by mean. */
static void check_ordering(const td_fuzz_slot *s) {
    if (!s->well_formed) {
        return;
    }
    const td_histogram_t *h = s->h;
    for (int i = 1; i < h->merged_nodes; i++) {
        TD_FUZZ_CHECK(h->nodes_mean[i - 1] <= h->nodes_mean[i],
                      "centroid means unsorted at %d: %.17g > %.17g", i, h->nodes_mean[i - 1],
                      h->nodes_mean[i]);
    }
}

/* ------------------------------------------------------------------ */
/* Value oracles -- well-formed histograms only                        */
/* ------------------------------------------------------------------ */

static void check_quantiles(td_fuzz_slot *s) {
    if (!s->well_formed || td_size(s->h) <= 0) {
        return;
    }
    td_histogram_t *h = s->h;
    double scalar[TD_FUZZ_NQ];
    double batch[TD_FUZZ_NQ];

    for (int i = 0; i < TD_FUZZ_NQ; i++) {
        scalar[i] = td_quantile(h, TD_FUZZ_QUANTILES[i]);
    }
    if (td_centroid_count(h) == 0) {
        return; /* compress produced nothing to interpolate over */
    }

    const double mn = td_min(h);
    const double mx = td_max(h);
    double prev = -INFINITY;
    for (int i = 0; i < TD_FUZZ_NQ; i++) {
        const double v = scalar[i];
        TD_FUZZ_CHECK(!isnan(v), "td_quantile(%g) returned NaN on a non-empty digest",
                      TD_FUZZ_QUANTILES[i]);
        TD_FUZZ_CHECK(td_fuzz_ge(v, mn) && td_fuzz_ge(mx, v),
                      "td_quantile(%g)=%.17g escapes [min=%.17g, max=%.17g]", TD_FUZZ_QUANTILES[i],
                      v, mn, mx);
        TD_FUZZ_CHECK(td_fuzz_ge(v, prev), "td_quantile not monotonic: q=%g gives %.17g after %.17g",
                      TD_FUZZ_QUANTILES[i], v, prev);
        prev = v;
    }

    /* The batch API walks the centroids once for an ascending quantile array;
     * it must land on the same values as the scalar one. */
    const int rc = td_quantiles(h, TD_FUZZ_QUANTILES, batch, TD_FUZZ_NQ);
    TD_FUZZ_CHECK(rc == 0, "td_quantiles returned %d for valid arguments", rc);
    for (int i = 0; i < TD_FUZZ_NQ; i++) {
        TD_FUZZ_CHECK(td_fuzz_close(scalar[i], batch[i]),
                      "td_quantiles(%g)=%.17g disagrees with td_quantile=%.17g",
                      TD_FUZZ_QUANTILES[i], batch[i], scalar[i]);
    }
}

static void check_cdf(td_fuzz_slot *s) {
    if (!s->well_formed || td_size(s->h) <= 0) {
        return;
    }
    td_histogram_t *h = s->h;
    td_compress(h);
    if (h->merged_nodes == 0) {
        return;
    }

    const double mn = td_min(h);
    const double mx = td_max(h);
    if (!isfinite(mn) || !isfinite(mx)) {
        return;
    }

    /* Probe strictly ascending points spanning [min, max] plus both tails. */
    const double span = mx - mn;
    double probes[TD_FUZZ_NQ];
    for (int i = 0; i < TD_FUZZ_NQ; i++) {
        probes[i] = mn + span * TD_FUZZ_QUANTILES[i];
    }

    double prev = -INFINITY;
    for (int i = 0; i < TD_FUZZ_NQ; i++) {
        if (!isfinite(probes[i])) {
            continue;
        }
        const double p = td_cdf(h, probes[i]);
        TD_FUZZ_CHECK_H(h, !isnan(p), "td_cdf(%.17g) returned NaN on a non-empty digest", probes[i]);
        TD_FUZZ_CHECK_H(h, p >= 0.0 && p <= 1.0,
                        "td_cdf(%.17g)=%.17g outside [0,1] (min=%.17g max=%.17g)", probes[i], p, mn,
                        mx);
        if (probes[i] > (i > 0 ? probes[i - 1] : -INFINITY)) {
            TD_FUZZ_CHECK_H(h, td_fuzz_ge(p, prev),
                            "td_cdf not monotonic: x=%.17g gives %.17g after %.17g", probes[i], p,
                            prev);
        }
        prev = p;
    }

    TD_FUZZ_CHECK(td_cdf(h, -INFINITY) == 0.0 || td_size(h) == 0, "td_cdf(-inf) != 0");
    TD_FUZZ_CHECK(td_cdf(h, INFINITY) == 1.0 || td_size(h) == 0, "td_cdf(+inf) != 1");
}

/* ------------------------------------------------------------------ */
/* Operations                                                          */
/* ------------------------------------------------------------------ */

static void do_add(td_fuzz_slot *s, double mean, long long weight) {
    const long long size_before = td_size(s->h);
    const int rc = td_add(s->h, mean, weight);

    if (rc != 0) {
        /* Header: "If overflow is detected the histogram is not changed." */
        TD_FUZZ_CHECK(td_add(s->h, mean, weight) == rc, "td_add is not idempotent on failure");
        if (s->acct_ok) {
            TD_FUZZ_CHECK(td_size(s->h) == size_before,
                          "td_add failed with %d but td_size moved %lld -> %lld", rc, size_before,
                          td_size(s->h));
        }
        return;
    }

    if (!isfinite(mean) || weight < 1) {
        s->well_formed = 0;
    }
    if (weight < 0 || s->expected_weight > TD_FUZZ_EXACT_LIMIT - (weight > 0 ? weight : 0)) {
        s->acct_ok = 0;
        s->well_formed = 0;
    }
    if (s->acct_ok) {
        s->expected_weight += weight;
        if (s->expected_weight >= TD_FUZZ_EXACT_LIMIT) {
            s->acct_ok = 0;
            s->well_formed = 0;
        }
    }
    check_structure(s);
    check_accounting(s);
}

static void do_compress(td_fuzz_slot *s) {
    const long long size_before = td_size(s->h);
    const int rc = td_compress(s->h);
    check_structure(s);
    if (rc == 0) {
        check_accounting(s);
        check_ordering(s);
    } else if (s->acct_ok) {
        TD_FUZZ_CHECK(td_size(s->h) == size_before,
                      "td_compress failed with %d but td_size moved %lld -> %lld", rc, size_before,
                      td_size(s->h));
    }
}

static void do_merge(td_fuzz_slot *into, td_fuzz_slot *from) {
    if (into == from) {
        return; /* self-merge is not a supported contract */
    }
    const long long into_before = td_size(into->h);
    const long long from_before = td_size(from->h);
    const int both_exact = into->acct_ok && from->acct_ok;

    const int rc = td_merge(into->h, from->h);
    check_structure(into);
    check_structure(from);

    if (rc != 0) {
        /* Header: "If overflow is detected the original histogram is not
         * [changed]." A partial merge that leaves weight behind is a
         * contract violation, not just an accuracy loss. */
        if (both_exact) {
            TD_FUZZ_CHECK(td_size(into->h) == into_before,
                          "td_merge failed with %d but left the target partially merged: "
                          "td_size %lld -> %lld",
                          rc, into_before, td_size(into->h));
        }
        into->acct_ok = 0;
        into->well_formed = 0;
        return;
    }

    if (both_exact && into_before <= TD_FUZZ_EXACT_LIMIT - from_before) {
        into->expected_weight = into_before + from_before;
    } else {
        into->acct_ok = 0;
    }
    into->well_formed = into->well_formed && from->well_formed && into->acct_ok;
    check_accounting(into);
    check_ordering(into);
}

/* Only the documented-valid index range: [0, centroid_count). A crash here is
 * a library bug, not caller misuse. */
static void do_accessors(td_fuzz_slot *s, td_fuzz_reader *r) {
    td_histogram_t *h = s->h;
    volatile double sink_d;
    volatile long long sink_l;
    volatile int sink_i;

    sink_d = td_min(h);
    sink_d = td_max(h);
    sink_l = td_size(h);
    sink_i = td_compression(h);
    const int n = td_centroid_count(h);
    TD_FUZZ_CHECK(n >= 0 && n <= h->cap, "centroid_count=%d out of [0, cap=%d]", n, h->cap);

    const long long *weights = td_centroids_weight(h);
    const double *means = td_centroids_mean(h);
    TD_FUZZ_CHECK(weights != NULL && means != NULL, "centroid arrays are NULL on a live histogram");

    if (n > 0) {
        const int pos = (int)(td_fuzz_u64(r) % (uint64_t)n);
        sink_l = td_centroids_weight_at(h, pos);
        sink_d = td_centroids_mean_at(h, pos);
        TD_FUZZ_CHECK(sink_l == weights[pos], "centroids_weight_at(%d) disagrees with the array",
                      pos);
        TD_FUZZ_CHECK(td_fuzz_close(sink_d, means[pos]),
                      "centroids_mean_at(%d) disagrees with the array", pos);
    }
    (void)sink_d;
    (void)sink_l;
    (void)sink_i;
}

static void do_trimmed_mean(td_fuzz_slot *s, td_fuzz_reader *r) {
    td_histogram_t *h = s->h;
    const double lo = td_fuzz_f64_raw(r);
    const double hi = td_fuzz_f64_raw(r);
    const double tm = td_trimmed_mean(h, lo, hi);
    const double sym = td_trimmed_mean_symmetric(h, lo);
    check_structure(s);

    if (s->well_formed && td_size(h) > 0 && td_centroid_count(h) > 0) {
        const double mn = td_min(h);
        const double mx = td_max(h);
        /* A trimmed mean over a non-empty range is an average of centroid
         * means, so it cannot escape [min, max]. NaN means "empty selection". */
        if (!isnan(tm) && isfinite(mn) && isfinite(mx)) {
            TD_FUZZ_CHECK(td_fuzz_ge(tm, mn) && td_fuzz_ge(mx, tm),
                          "td_trimmed_mean(%.17g,%.17g)=%.17g escapes [%.17g, %.17g]", lo, hi, tm,
                          mn, mx);
        }
        if (!isnan(sym) && isfinite(mn) && isfinite(mx) && lo >= 0.0 && lo <= 1.0) {
            TD_FUZZ_CHECK(td_fuzz_ge(sym, mn) && td_fuzz_ge(mx, sym),
                          "td_trimmed_mean_symmetric(%.17g)=%.17g escapes [%.17g, %.17g]", lo, sym,
                          mn, mx);
        }
    }
}

/* ------------------------------------------------------------------ */

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 3) {
        return 0;
    }

    td_fuzz_reader r;
    td_fuzz_reader_init(&r, data, size);

    td_fuzz_slot slots[TD_FUZZ_NHIST];
    for (int i = 0; i < TD_FUZZ_NHIST; i++) {
        slots[i].h = td_new(td_fuzz_pick_compression(&r));
        if (slots[i].h == NULL) {
            for (int j = 0; j < i; j++) {
                td_free(slots[j].h);
            }
            return 0;
        }
        slot_reset_model(&slots[i]);
        check_structure(&slots[i]);
    }

    int active = 0;
    unsigned ops = 0;
    while (!td_fuzz_eof(&r) && ops++ < TD_FUZZ_MAX_OPS) {
        td_fuzz_slot *s = &slots[active];
        switch (td_fuzz_u8(&r) & 0x0fu) {
        case 0:
            do_add(s, td_fuzz_f64_tame(&r), 1);
            break;
        case 1:
            do_add(s, td_fuzz_f64_tame(&r), td_fuzz_weight_tame(&r));
            break;
        case 2:
            /* Raw doubles and raw weights: NaN, Inf, 0, negative, LLONG_MAX.
             * Voids the numeric oracles but must never corrupt memory. */
            do_add(s, td_fuzz_f64_raw(&r), td_fuzz_i64(&r));
            break;
        case 3:
            do_compress(s);
            break;
        case 4:
            check_quantiles(s);
            check_structure(s);
            break;
        case 5:
            check_cdf(s);
            check_structure(s);
            break;
        case 6: {
            /* Unsorted / out-of-range quantile arrays: crash-only. The batch
             * API documents an ordered input, so values are not checked. */
            const uint8_t len = td_fuzz_u8(&r) & 0x1fu;
            double qin[32];
            double qout[32];
            for (uint8_t i = 0; i < len; i++) {
                qin[i] = td_fuzz_f64_raw(&r);
            }
            (void)td_quantiles(s->h, qin, qout, len);
            TD_FUZZ_CHECK(td_quantiles(s->h, NULL, qout, len) == EINVAL,
                          "td_quantiles accepted a NULL quantiles array");
            TD_FUZZ_CHECK(td_quantiles(s->h, qin, NULL, len) == EINVAL,
                          "td_quantiles accepted a NULL values array");
            check_structure(s);
            break;
        }
        case 7:
            do_trimmed_mean(s, &r);
            break;
        case 8: {
            const double q = td_fuzz_f64_raw(&r);
            const double v = td_quantile(s->h, q);
            if (q < 0.0 || q > 1.0 || isnan(q)) {
                TD_FUZZ_CHECK(isnan(v), "td_quantile(%.17g) returned %.17g for an out-of-range q", q,
                              v);
            }
            check_structure(s);
            break;
        }
        case 9:
            (void)td_cdf(s->h, td_fuzz_f64_raw(&r));
            check_structure(s);
            break;
        case 10:
            td_reset(s->h);
            slot_reset_model(s);
            TD_FUZZ_CHECK(td_size(s->h) == 0, "td_size()=%lld after td_reset", td_size(s->h));
            TD_FUZZ_CHECK(td_centroid_count(s->h) == 0, "centroid_count=%d after td_reset",
                          td_centroid_count(s->h));
            check_structure(s);
            break;
        case 11:
            do_merge(&slots[0], &slots[1]);
            break;
        case 12:
            do_merge(&slots[1], &slots[0]);
            break;
        case 13:
            do_accessors(s, &r);
            break;
        case 14: {
            /* Burst: grow the digest past its capacity so the merge path and
             * the implicit compress inside td_add actually run. */
            uint32_t n = td_fuzz_u8(&r);
            n = (n * 4u) + 1u;
            if (n > TD_FUZZ_MAX_BURST) {
                n = TD_FUZZ_MAX_BURST;
            }
            const double base = td_fuzz_f64_tame(&r);
            const double step = td_fuzz_f64_tame(&r);
            for (uint32_t i = 0; i < n; i++) {
                const double v = base + step * (double)i;
                if (td_add(s->h, v, 1) != 0) {
                    s->acct_ok = 0;
                    s->well_formed = 0;
                    break;
                }
                if (!isfinite(v)) {
                    s->well_formed = 0;
                }
                if (s->acct_ok) {
                    s->expected_weight += 1;
                }
            }
            check_structure(s);
            check_accounting(s);
            break;
        }
        default:
            active = (active + 1) % TD_FUZZ_NHIST;
            break;
        }
    }

    for (int i = 0; i < TD_FUZZ_NHIST; i++) {
        check_structure(&slots[i]);
        td_free(slots[i].h);
    }
    return 0;
}
