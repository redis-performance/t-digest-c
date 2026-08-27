---
name: t-digest-c-maintainer-review
description: Review a redis-performance/t-digest-c pull request, branch, or diff. This fork has ZERO of its own pull requests or issues (see the honesty note below) — there is no maintainer voice or review precedent to mine here. This skill is a generic, minimal C-safety checklist grounded only in what this fork's own repository actually contains today (its CircleCI checks, its Makefile targets, its lack of AGENTS.md/CONTRIBUTING.md), not in any invented reviewer personality. Use this whenever asked to review a t-digest-c PR "like a maintainer would" or wants a t-digest-c-specific pre-merge check, understanding that the honest answer is closer to "a competent C reviewer with no project-specific precedent to lean on" than "this project's maintainers."
---

# t-digest-c review (generic — no fork-specific precedent exists)

## Honesty note — read this first

`redis-performance/t-digest-c` is a **fork** of the upstream `RedisBloom/t-digest-c` ("Wicked Fast,
Accurate Quantiles Using 'T-Digests'"). As mined on 2026-08-27, directly against this fork
(`gh pr list --repo redis-performance/t-digest-c --state all`, `gh issue list --repo redis-performance/t-digest-c --state all`):

- **Zero pull requests have ever been opened against this fork.** Not one, in either state.
- **Issues are disabled** on this repository entirely.
- There is therefore **no independent review activity, no maintainer comment, no approval pattern,
  and no recorded disagreement to mine** — the situation is thinner than even a passthrough fork with
  a handful of rubber-stamp approvals (compare `redis-performance/go-ycsb`, which at least had 27 PRs
  and 5 real `APPROVED` reviews to observe). Here there is nothing.
- The commits visible in `git log` on this fork's `master` (e.g. "MOD-13821 Fix compression with
  total_weight=1 (#39)", "fixing big allocation on ubuntu20 arm (#38)") are **merge commits inherited
  from upstream `RedisBloom/t-digest-c`** — authored and reviewed by upstream's own
  maintainers/contributors (Aviv David, Tom Gabsow, Chayim Kirshen, `filipecosta90`, etc.), not by
  anyone acting as a reviewer *on this fork*. Per this skill's own scope, that upstream history is
  explicitly **not** treated as this repo's maintainer voice, and nothing below quotes or imitates it.
- There is **no `AGENTS.md` and no `CONTRIBUTING.md`** in this fork to cite as documented policy
  (unlike `go-ycsb`, which at least has those, even if unevenly enforced). The only pre-existing
  `.github` content is `release-drafter.yml`.

Given all that, **do not invent a maintainer voice, a review tone, or a "this project's reviewers
usually flag X" claim for this repository.** There is nothing to base it on. What this skill offers
instead is grounded only in things that are objectively true of this fork's repository *right now*:
what its own CI (`.circleci/config.yml`) actually checks, what its `Makefile` actually runs, and
general C memory-safety practice appropriate for a small numerical library with no test/sanitizer
gate of its own on incoming changes from this fork's perspective (see below). Treat every recommendation in `references/review-checklist.md` as
generic-but-relevant engineering judgment, never as "the maintainers would say."

## What this fork's own repository state actually shows

Read `references/repo-state.md` for the full detail. In short, as of this writing:

- CircleCI (`.circleci/config.yml`) runs four jobs on every commit: `lint` (`make lint`, clang-format
  based), `sanitize` (`make sanitize` — ASan/UBSan build and test run), `static-analysis-infer`
  (Facebook Infer), and `build` (coverage + microbenchmarks via `redisbench-admin export`). This is a
  real, currently-configured signal — but it runs on push/CircleCI's own trigger, not automatically as
  a GitHub PR check visible in this review; do not assume it has already run just because CI config
  exists.
- `.clang-format` fixes indentation (4 spaces) and a 100-column limit — flag obvious formatting drift
  only if `make lint` would plausibly catch it, not as a style opinion of your own.
- The library is small, self-contained C (`src/tdigest.c` etc.) with no external runtime
  dependencies; its own history (again, upstream-inherited, described only for objective technical
  context, not as review precedent) shows this codebase's substantive bugs have clustered around
  numeric overflow, allocation-failure handling, and platform-specific allocation/build issues — which
  is unsurprising for this kind of code and is exactly the class of issue sanitizers and static
  analysis are designed to catch, which is presumably why this repo already runs both.

## Process

1. **Get the material.** `gh pr view <n> --repo redis-performance/t-digest-c --json body,commits,files,author`
   and `gh pr diff <n> --repo redis-performance/t-digest-c`. Read the full description first. Do not
   assume a Summary/Test-plan format is expected — with zero PR history on this fork, there is no
   established norm for PR descriptions here either; judge the description on its own merits.

2. **Work the checklist** in `references/review-checklist.md`. Every item there is either (a) something
   this fork's own `.circleci/config.yml` or `Makefile` actually configures today, or (b) generic C
   memory-safety/build-portability judgment appropriate for this kind of numerical library. None of it
   is attributed to a maintainer, because none of it can honestly be.

3. **Because there is no established review precedent on this fork, do not claim precedent.** Never
   write "this is the kind of thing maintainers here usually catch" or similar — say what the concern
   is and why it matters technically, full stop.

4. **Prefer silence over manufactured nitpicks.** If a PR is small, self-evidently correct, and passes
   the checklist below, set `skip_comment=true`. With no maintainer voice to imitate, the only failure
   mode worse than saying nothing is inventing false institutional memory to sound authoritative.

5. **Land on a plain-prose verdict.** No literal "Verdict:" label, no bolded summary line, no
   `@`-mention of any GitHub username, ever — these are hard rules from the calling workflow, not
   stylistic suggestions.

## What NOT to do

- Don't claim a "maintainer voice" for this repository, named or unnamed — there is no review history
  on this fork to derive one from. Zero PRs, zero issues, zero comments.
- Don't cite the upstream `RedisBloom/t-digest-c` project's contributors, commits, or PR discussions as
  though they reflect this fork's own reviewers or policy. They don't; they're a different project's
  history that happens to be inherited into this git log.
- Don't cite `AGENTS.md` or `CONTRIBUTING.md` — this fork has neither file.
- Don't assume CircleCI has already run and passed just because `.circleci/config.yml` defines checks —
  you have no way to confirm that from a read-only PR review, so flag correctness/safety concerns on
  their own merits rather than deferring to "CI will catch it."
- Don't manufacture a duplicate-approval comment ("LGTM") to seem thorough on a routine PR — say
  nothing (`skip_comment: true`) instead.
- Don't literally `@`-mention any GitHub username, ever, for any reason.
