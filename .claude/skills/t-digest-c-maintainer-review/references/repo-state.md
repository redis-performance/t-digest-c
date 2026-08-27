# What was actually mined, and what it showed

Mined 2026-08-27 directly against `redis-performance/t-digest-c` (never against upstream
`RedisBloom/t-digest-c`, per this skill's scope).

## PR / issue history — empty

```
gh pr list --repo redis-performance/t-digest-c --state all --limit 100   -> []
gh issue list --repo redis-performance/t-digest-c --state all --limit 100 -> "issues disabled"
```

Zero pull requests, in any state, have ever been opened against this fork. Issues are disabled at the
repository level. There is no `gh api .../pulls/<n>/reviews` data to read because there are no PR
numbers to read it from. This is a stronger "no history" case than a typical thin fork — it isn't that
review comments were sparse or approvals were rubber-stamped, it's that no PR-based review event of any
kind has happened on this specific repository.

## Fork relationship

```
gh repo view redis-performance/t-digest-c --json isFork,parent
  isFork: true
  parent: RedisBloom/t-digest-c
```

`git log` on this fork's `master` shows merge commits like "Merge pull request #39 ... MOD-13821 Fix
compression with total_weight=1" authored by Aviv David, Tom Gabsow, Chayim Kirshen, and others — these
are **upstream RedisBloom PRs**, carried into this fork's history because the fork mirrors upstream's
`master`, not activity that happened on `redis-performance/t-digest-c` itself. This skill does not treat
any of it as this fork's own maintainer voice, per the task's explicit scope (only this fork's own
PR/issue history counts; upstream contributors/reviewers are not this repo's maintainers).

## Repository files that DO belong to this fork today

- `.circleci/config.yml` — real, current CI config (see below).
- `.clang-format` — 4-space indent, 100-column limit, `SortIncludes: false`.
- `Makefile` — defines `lint`, `sanitize`, `coverage`, `bench`, `static-analysis` targets among others.
- `.github/release-drafter.yml` — the only pre-existing `.github` content; unrelated to PR review.
- **No `AGENTS.md`.** **No `CONTRIBUTING.md`.** No documented contribution policy of any kind.
- `README.md` describes the library itself (t-Digest quantile estimation, descended from
  `tdunning/t-digest` and `ajwerner/tdigestc`) but says nothing about review process or contribution
  standards.

## CircleCI jobs actually configured (`.circleci/config.yml`)

| Job | What it runs | Image |
|---|---|---|
| `lint` | `make lint` (clang-format check) | `redislabsmodules/llvm-toolset:latest` |
| `sanitize` | `make sanitize` (ASan/UBSan build + test) | `redislabsmodules/llvm-toolset:latest` |
| `static-analysis-infer` | `make static-analysis` via Facebook Infer | `redisbench/infer-linux64:1.0.0` |
| `build` | `make coverage`, codecov upload, `make bench` + `redisbench-admin export` | `debian:bullseye` |

All four run on every commit per the `workflows.commit.jobs` list. This is genuine, present-tense
information about what this repository's own CI does — cited here as objective fact about the repo,
not as evidence of how any human reviewer here has behaved, since no human review has been recorded.

## Bottom line for the skill

There is no fork-specific "maintainer voice," "common nitpick," or "documented standard" to mine,
because none of the three sources that would normally supply one (merged/reviewed PRs on this repo,
issues on this repo, an AGENTS.md/CONTRIBUTING.md in this repo) contain anything. The review checklist
in `references/review-checklist.md` is deliberately generic and grounded only in the CI/Makefile facts
above plus ordinary C-safety judgment — it should be presented to the model, and by the model, as
exactly that: reasonable review practice for this kind of code, not this fork's precedent.
