/*
 * fuzz_td_quantile -- deep oracle for the read path (td_quantile / td_quantiles / td_cdf).
 *
 * Builds one digest from a stream of samples, keeps a sorted reference copy of
 * those samples, then hammers the read APIs. Compared to fuzz_td_api this trades
 * API-sequence breadth for oracle depth:
 *
 *   - endpoints      td_quantile(0) == td_min, td_quantile(1) == td_max
 *   - monotonicity   a dense 257-point sweep of q must be non-decreasing
 *   - range          every result lands in [min, max]
 *   - idempotence    a read API must not change what the next read returns
 *   - batch==scalar  td_quantiles() matches td_quantile() point for point
 *   - rank accuracy  the true rank of td_quantile(q) is within a coarse band of q
 *
 * The rank check is deliberately coarse (see TD_FUZZ_RANK_TOLERANCE): it is a
 * "the estimator is grossly broken" detector, not an accuracy regression test.
 * t-digest's real guarantee is relative to the tails and would produce false
 * positives on adversarial inputs.
 *
 * Copyright (c) 2026 Redis, All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "td_fuzz_util.h"
#include "tdigest.h"

#define TD_FUZZ_MAX_SAMPLES 20000
#define TD_FUZZ_SWEEP 257

/*
 * Rank-accuracy gate. t-digest's rank error scales as ~1/compression, so a
 * fixed tolerance is either useless at compression 1000 or a false-positive
 * factory at compression 1. The bound below was calibrated by measuring the
 * worst observed rank error over adversarial distributions (sorted, reverse
 * sorted, heavy-tailed, bimodal at 1e9/1e-9, and 3-distinct-values with
 * massive ties) and leaving ~3x headroom:
 *
 *     compression   worst observed   bound here
 *             100          0.134        0.40
 *             300          0.051        0.13
 *            1000          0.013        0.06
 *
 * This is a "the estimator is grossly broken" detector, not an accuracy
 * regression test. Below TD_FUZZ_RANK_MIN_COMPRESSION the digest holds so few
 * centroids that no useful bound exists, so the check is skipped entirely.
 */
#define TD_FUZZ_RANK_MIN_SAMPLES 200
#define TD_FUZZ_RANK_MIN_COMPRESSION 100.0

static double rank_tolerance(double compression) { return fmax(0.06, 40.0 / compression); }

static double g_samples[TD_FUZZ_MAX_SAMPLES];

static int cmp_double(const void *a, const void *b) {
    const double x = *(const double *)a;
    const double y = *(const double *)b;
    if (x < y) {
        return -1;
    }
    if (x > y) {
        return 1;
    }
    return 0;
}

/* Number of entries in the sorted set that compare strictly less than v. */
static size_t lower_bound(const double *sorted, size_t n, double v) {
    size_t lo = 0;
    size_t hi = n;
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        if (sorted[mid] < v) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo;
}

/* Number of entries that are <= v. */
static size_t upper_bound(const double *sorted, size_t n, double v) {
    size_t lo = 0;
    size_t hi = n;
    while (lo < hi) {
        const size_t mid = lo + (hi - lo) / 2;
        if (sorted[mid] <= v) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo;
}

/*
 * How far q sits outside the rank interval that v legitimately occupies.
 *
 * Ties matter: if the sample set is 400 copies of 0.0, then 0.0 is a correct
 * answer for every q in [0,1] and a single "rank" number would make any answer
 * look wrong. Comparing against the half-open interval [#(<v), #(<=v)]/n is the
 * tie-correct formulation, and it returns 0 whenever q lands inside it.
 */
static double rank_error(const double *sorted, size_t n, double v, double q) {
    const double lo = (double)lower_bound(sorted, n, v) / (double)n;
    const double hi = (double)upper_bound(sorted, n, v) / (double)n;
    if (q < lo) {
        return lo - q;
    }
    if (q > hi) {
        return q - hi;
    }
    return 0.0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 4) {
        return 0;
    }

    td_fuzz_reader r;
    td_fuzz_reader_init(&r, data, size);

    const double compression = td_fuzz_pick_compression(&r);
    td_histogram_t *h = td_new(compression);
    if (h == NULL) {
        return 0;
    }

    const uint8_t mode = td_fuzz_u8(&r);
    const int tame_only = (mode & 1u) != 0; /* finite values, unit weights */

    size_t n = 0;
    int all_unit_weight = 1;
    int all_finite = 1;

    while (!td_fuzz_eof(&r) && n < TD_FUZZ_MAX_SAMPLES) {
        double v;
        long long w = 1;
        if (tame_only) {
            v = td_fuzz_f64_tame(&r);
        } else {
            v = td_fuzz_f64_raw(&r);
            if (mode & 2u) {
                w = td_fuzz_weight_tame(&r);
            }
        }
        if (td_add(h, v, w) != 0) {
            break;
        }
        if (!isfinite(v)) {
            all_finite = 0;
        }
        if (w != 1) {
            all_unit_weight = 0;
        }
        g_samples[n++] = v;
    }

    if (n == 0 || td_centroid_count(h) == 0) {
        td_free(h);
        return 0;
    }

    /* --- structural: never exceed the allocation --- */
    TD_FUZZ_CHECK(h->merged_nodes + h->unmerged_nodes <= h->cap, "node count %d+%d exceeds cap %d",
                  h->merged_nodes, h->unmerged_nodes, h->cap);

    if (!all_finite) {
        /* NaN/Inf samples void every numeric contract -- crash-only from here. */
        for (int i = 0; i < TD_FUZZ_SWEEP; i++) {
            (void)td_quantile(h, (double)i / (double)(TD_FUZZ_SWEEP - 1));
            (void)td_cdf(h, g_samples[i % (int)n]);
        }
        td_free(h);
        return 0;
    }

    const double mn = td_min(h);
    const double mx = td_max(h);

    /* --- endpoints are exact, not interpolated --- */
    TD_FUZZ_CHECK(td_fuzz_close(td_quantile(h, 0.0), mn),
                  "td_quantile(0)=%.17g != td_min()=%.17g", td_quantile(h, 0.0), mn);
    TD_FUZZ_CHECK(td_fuzz_close(td_quantile(h, 1.0), mx),
                  "td_quantile(1)=%.17g != td_max()=%.17g", td_quantile(h, 1.0), mx);

    /* --- dense monotonic sweep + range --- */
    double prev = -INFINITY;
    for (int i = 0; i < TD_FUZZ_SWEEP; i++) {
        const double q = (double)i / (double)(TD_FUZZ_SWEEP - 1);
        const double v = td_quantile(h, q);
        TD_FUZZ_CHECK(!isnan(v), "td_quantile(%.17g) returned NaN over %zu finite samples", q, n);
        TD_FUZZ_CHECK(td_fuzz_ge(v, mn) && td_fuzz_ge(mx, v),
                      "td_quantile(%.17g)=%.17g escapes [%.17g, %.17g]", q, v, mn, mx);
        TD_FUZZ_CHECK(td_fuzz_ge(v, prev), "td_quantile not monotonic at q=%.17g: %.17g after %.17g",
                      q, v, prev);
        /* idempotence: a read must not perturb the next read */
        TD_FUZZ_CHECK(td_fuzz_close(td_quantile(h, q), v),
                      "td_quantile(%.17g) is not idempotent: %.17g then %.17g", q, v,
                      td_quantile(h, q));
        prev = v;
    }

    /* --- batch agrees with scalar --- */
    {
        double batch[TD_FUZZ_NQ];
        double scalar[TD_FUZZ_NQ];
        for (int i = 0; i < TD_FUZZ_NQ; i++) {
            scalar[i] = td_quantile(h, TD_FUZZ_QUANTILES[i]);
        }
        const int rc = td_quantiles(h, TD_FUZZ_QUANTILES, batch, TD_FUZZ_NQ);
        TD_FUZZ_CHECK(rc == 0, "td_quantiles returned %d for valid arguments", rc);
        for (int i = 0; i < TD_FUZZ_NQ; i++) {
            TD_FUZZ_CHECK(td_fuzz_close(scalar[i], batch[i]),
                          "batch/scalar mismatch at q=%g: %.17g vs %.17g", TD_FUZZ_QUANTILES[i],
                          batch[i], scalar[i]);
        }
    }

    /* --- cdf: range, monotonic over the sorted sample set --- */
    qsort(g_samples, n, sizeof(double), cmp_double);
    {
        double prev_p = -INFINITY;
        const size_t stride = (n / 128) + 1;
        for (size_t i = 0; i < n; i += stride) {
            const double p = td_cdf(h, g_samples[i]);
            TD_FUZZ_CHECK(!isnan(p), "td_cdf(%.17g) returned NaN", g_samples[i]);
            TD_FUZZ_CHECK(p >= 0.0 && p <= 1.0, "td_cdf(%.17g)=%.17g outside [0,1]", g_samples[i],
                          p);
            TD_FUZZ_CHECK(td_fuzz_ge(p, prev_p), "td_cdf not monotonic at %.17g: %.17g after %.17g",
                          g_samples[i], p, prev_p);
            prev_p = p;
        }
    }

    /* --- coarse rank accuracy --- */
    if (all_unit_weight && n >= TD_FUZZ_RANK_MIN_SAMPLES && isfinite(mx - mn) &&
        compression >= TD_FUZZ_RANK_MIN_COMPRESSION) {
        const double tol = rank_tolerance(compression);
        for (int i = 1; i < 20; i++) {
            const double q = (double)i / 20.0;
            const double v = td_quantile(h, q);
            const double err = rank_error(g_samples, n, v, q);
            TD_FUZZ_CHECK(err <= tol,
                          "td_quantile(%.4g)=%.17g misses its rank interval by %.4g (bound %.4g) "
                          "over %zu samples at compression=%g -- estimator is grossly wrong",
                          q, v, err, tol, n, compression);
        }
    }

    td_free(h);
    return 0;
}
