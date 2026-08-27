# Generic review checklist — not fork precedent, just relevant engineering judgment

None of these items are backed by a real reviewer comment on this fork (there are none — see
`repo-state.md`). Present them as your own reasoned assessment, not as "what maintainers here look
for."

## 1. Memory safety (C, manual allocation)

This is a hand-written C library doing its own `malloc`/`realloc`/`free` for centroid arrays and
digest structures (`src/tdigest.c`). For any change touching allocation or array sizing:
- Is every allocation's return value checked before use?
- Is every `free` paired with exactly one allocation, with no double-free or use-after-free path,
  including on error/early-return branches?
- Do array growth/resize paths handle the zero- and one-element edge cases explicitly?
- `.circleci/config.yml` runs `make sanitize` (ASan/UBSan) on every commit — if the PR's own CI run
  hasn't shown a green `sanitize` job, treat that as unverified, not as passing.

## 2. Numeric correctness

T-digest math involves weighted centroids, compression, and quantile interpolation over
floating-point and (per `src/tdigest.h`) `long long` weights. For any change touching `td_add`,
`td_merge`, `td_compress`, or quantile/rank computation:
- Are overflow/infinity cases (very large weights, `total_weight` at or near zero) considered, not
  just the typical-input path?
- Does a behavior change alter documented quantile semantics (e.g. `td_quantile` vs `td_quantiles`)
  without updating `README.md`'s API description to match?
- Is there a new or updated unit test in `tests/` exercising the specific edge case being fixed, not
  just the common case?

## 3. Build portability

This library is built via both CMake (`CMakeLists.txt`, `cmake/`) and a plain `Makefile`, and is
consumed as a submodule by other Redis projects. For any change to build files:
- Does it still build under both the Makefile path (`make full`) and the CMake path, if both are
  touched or plausibly affected?
- Does it avoid introducing a compiler/platform-specific assumption (a specific libc, endianness, a
  minimum CMake version bump) without a stated reason?
- If a new source file is added, is it wired into both `Makefile` and `CMakeLists.txt`/`cmake/` — a
  change registered in only one build path silently breaks the other for downstream consumers.

## 4. Style / lint

`.clang-format` in this repo sets 4-space indentation, a 100-column limit, and
`SortIncludes: false`. `make lint` runs clang-format checking in CI. Flag only genuine, visible
drift from this — not a personal style preference — since CI is configured to catch this
mechanically and a human reviewer's job here is to catch what CI can't (correctness, not formatting
you can't actually verify ran).

## 5. Test coverage

`tests/` holds this project's unit tests (`minunit.h`-based, per the actual source tree). For any
behavioral change:
- Is there a new test, or an existing test updated, that would fail without the fix/feature?
- For a bug fix specifically: does the added test reproduce the original bug (i.e. would it have
  failed on the pre-fix code)?

## 6. PR description quality

There is no established norm on this fork for what a PR description should contain (zero PRs to
observe). Judge each description on its own merits: does it say what changed and why, and if it's a
fix, what the observable symptom was? Don't penalize a PR for not matching some other project's
template — none exists here.

## When to say nothing

If a PR is small, the diff is self-evidently correct against the above (e.g. a comment fix, a
one-line build flag correction with clear rationale, a version bump), the honest response is
`skip_comment: true`. Manufacturing a nitpick to look thorough is worse than silence, especially here
where there's no precedent either way to fall back on.
