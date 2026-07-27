# t-digest fuzzing

Coverage-guided fuzz targets for the public t-digest API, with oracles that check the
contracts `tdigest.h` documents — not just "did it crash".

## Targets

| Target | Drives | Oracles beyond crash/sanitizer |
|--------|--------|-------------------------------|
| `fuzz_td_api` | the whole API as an opcode program over two histograms | capacity, weight accounting, failure atomicity, centroid ordering, quantile/cdf contracts, accessor agreement |
| `fuzz_td_quantile` | one digest + a sorted reference copy of its samples | exact endpoints, dense monotonic sweep, idempotence, batch==scalar, coarse rank accuracy |
| `fuzz_td_merge` | `td_merge` — the API most likely to be fed digests from elsewhere | weight conservation, empty-merge identity, self-merge aliasing, post-merge read sanity |
| `fuzz_td_init` | the compression parameter | `td_new`/`td_init` agreement, capacity sanity, fresh-digest invariants |

## Building

```bash
cmake -S . -B build/fuzz -DBUILD_FUZZERS=ON -DBUILD_TESTS=OFF \
      -DCMAKE_C_COMPILER=clang -DCMAKE_BUILD_TYPE=Debug
cmake --build build/fuzz -j
```

Knobs:

- `-DFUZZ_ENGINE=libfuzzer` (default with clang) · `standalone` (plain `main()`, works with
  gcc, replays files given as arguments) · `oss-fuzz` (links `$LIB_FUZZING_ENGINE`)
- `-DFUZZ_SANITIZERS="address;undefined"` (default), `"memory"`, or `""` for none
- `-DFUZZ_RECOVER=ON` — keep going after a UBSan report instead of halting, so one sweep
  surfaces every distinct site. The default halts, so CI fails loudly.

The targets compile `src/tdigest.c` in rather than linking the library, so the sanitizer and
coverage instrumentation applies to the library code itself, and the oracles can read
`td_histogram_t` fields directly to assert structural invariants.

## Running

```bash
./build/fuzz/tests/fuzz/fuzz_td_api corpus/            # fuzz, seeded from the corpus
./build/fuzz/tests/fuzz/fuzz_td_api regressions/*      # replay only, exits when done
ctest -R fuzz                                          # both corpora, once each
```

Always set these — a fuzzed compression can legitimately request an enormous capacity, and
you want the library's allocation-failure path exercised rather than an allocator abort that
masks every other finding:

```bash
export ASAN_OPTIONS=allocator_may_return_null=1
export UBSAN_OPTIONS=print_stacktrace=1
export DEBUGINFOD_URLS=""    # else llvm-symbolizer fetches over the network per report
```

## Corpora

- `corpus/` — hand-encoded seeds, committed. Regenerate with `scripts/gen-seeds.py` in the
  parent workspace. Covers uniform and heavy-tailed fills, all-equal values, the smallest
  possible capacity, `LLONG_MAX` weights, non-finite means, merge traffic in both
  directions, and out-of-range/unsorted quantile arrays.
- `regressions/` — minimized inputs, one per known finding, committed. These must keep
  passing once the corresponding bug is fixed.

> **The suite is red at the baseline commit, on purpose.** `corpus/` and `regressions/` both
> reproduce open findings, so `ctest -R fuzz` and the CI workflow fail until those are fixed.
> That is the point: the tests encode bugs that exist. When upstreaming, either land the
> fixes together with the suite, or land the suite with `regressions/` held back — do not
> "fix" CI by deleting inputs or relaxing oracles.

## Writing an oracle

The value oracles only run while the histogram is *well-formed*: every accepted sample had a
finite mean and a weight ≥ 1, and the total weight is still exactly representable in a
`double`. NaN means and negative weights are legal fuzzer input for crash-hunting, but they
void the numeric contracts — asserting through them produces false positives, not findings.
Each target tracks this as a flag and degrades to crash-only when it is lost.

The rank-accuracy check in `fuzz_td_quantile` is calibrated, not guessed: the bound is ~3×
the worst error measured over adversarial distributions (sorted, reverse-sorted,
heavy-tailed, bimodal at 1e9/1e-9, and 3-distinct-values with massive ties). It is a
"grossly broken" detector, not an accuracy regression test.
