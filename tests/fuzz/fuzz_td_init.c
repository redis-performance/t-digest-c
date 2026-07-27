/*
 * fuzz_td_init -- the compression parameter is the one value a caller most
 * often takes straight from user input (TDIGEST.CREATE ... COMPRESSION n), so
 * it gets its own target.
 *
 * cap_from_compression() casts the double to size_t. For NaN, negative, or
 * out-of-range values that cast is undefined behaviour in C, and the resulting
 * capacity feeds directly into the allocation size and every subsequent bounds
 * check. This target drives td_new()/td_init() with raw doubles and asserts:
 *
 *   - td_new() either returns NULL or a histogram that is internally consistent
 *   - a successful init yields cap >= 1 and usable, zeroed centroid arrays
 *   - td_init()'s return code agrees with td_new()'s NULL-ness
 *   - the first td_add() on a fresh digest cannot exceed the reported capacity
 *
 * Build with -fsanitize=undefined to catch the float-cast-overflow itself.
 * Run with ASAN_OPTIONS=allocator_may_return_null=1 so a legitimately huge
 * capacity request reports allocation failure instead of aborting the run.
 *
 * Copyright (c) 2026 Redis, All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 */
#include "td_fuzz_util.h"
#include "tdigest.h"

/* Compressions that are interesting regardless of what the fuzzer produces. */
static const double TD_FUZZ_EDGE_COMPRESSIONS[] = {
    0.0, 1.0, 0.5, 1e-300, -1.0, -0.0, 1e300, 1.0 / 3.0, 4503599627370496.0 /* 2^52 */,
};

static void exercise(double compression) {
    td_histogram_t *h = td_new(compression);
    td_histogram_t *via_init = NULL;
    const int rc = td_init(compression, &via_init);

    TD_FUZZ_CHECK((rc == 0) == (h != NULL),
                  "td_init returned %d but td_new returned %s for compression=%.17g", rc,
                  h ? "non-NULL" : "NULL", compression);

    if (h == NULL) {
        TD_FUZZ_CHECK(via_init == NULL, "td_init failed but still wrote an output pointer");
        return;
    }

    TD_FUZZ_CHECK(h->cap >= 1, "td_new(%.17g) produced cap=%d", compression, h->cap);
    TD_FUZZ_CHECK(h->nodes_mean != NULL && h->nodes_weight != NULL,
                  "td_new(%.17g) produced a histogram with NULL centroid arrays", compression);
    TD_FUZZ_CHECK(h->merged_nodes == 0 && h->unmerged_nodes == 0,
                  "fresh histogram already holds %d+%d nodes", h->merged_nodes, h->unmerged_nodes);
    TD_FUZZ_CHECK(td_size(h) == 0, "fresh histogram reports td_size()=%lld", td_size(h));
    TD_FUZZ_CHECK(td_centroid_count(h) == 0, "fresh histogram reports %d centroids",
                  td_centroid_count(h));
    TD_FUZZ_CHECK(isnan(td_quantile(h, 0.5)), "td_quantile on an empty histogram is not NaN");
    TD_FUZZ_CHECK(isnan(td_cdf(h, 0.0)), "td_cdf on an empty histogram is not NaN");

    /* A single add must stay inside the reported capacity no matter how odd
     * the compression was. */
    if (td_add(h, 1.0, 1) == 0) {
        TD_FUZZ_CHECK(h->merged_nodes + h->unmerged_nodes <= h->cap,
                      "one td_add pushed node count %d+%d past cap=%d (compression=%.17g)",
                      h->merged_nodes, h->unmerged_nodes, h->cap, compression);
        TD_FUZZ_CHECK(td_size(h) == 1, "td_size()=%lld after a single unit-weight add",
                      td_size(h));
        (void)td_compress(h);
        TD_FUZZ_CHECK(h->merged_nodes + h->unmerged_nodes <= h->cap,
                      "compress pushed node count %d+%d past cap=%d", h->merged_nodes,
                      h->unmerged_nodes, h->cap);
    }

    td_reset(h);
    TD_FUZZ_CHECK(td_size(h) == 0, "td_size()=%lld after td_reset", td_size(h));

    td_free(h);
    td_free(via_init);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0;
    }

    td_fuzz_reader r;
    td_fuzz_reader_init(&r, data, size);

    /* Always cover the fixed edge set, cheaply -- one per input, rotated. */
    const size_t nedge = sizeof(TD_FUZZ_EDGE_COMPRESSIONS) / sizeof(double);
    exercise(TD_FUZZ_EDGE_COMPRESSIONS[td_fuzz_u8(&r) % nedge]);

    unsigned rounds = 0;
    while (td_fuzz_remaining(&r) >= 8 && rounds++ < 16) {
        exercise(td_fuzz_f64_raw(&r));
    }
    return 0;
}
