# Wheeltap benchmarks and validation

Two questions, answered honestly:

1. **Is it fast enough to sit in CI?** Scan time against source size.
2. **Does it find real bugs, and what does it miss?** Findings compared against
   a published third-party audit of the same program.

The second matters far more than the first. It is written in Phase 6 and **must
include the misses** — a tool whose limits are undocumented cannot be trusted.

## Status

Not yet measured. Phase 0 vendored the corpus these numbers will come from; see
`fixtures/corpus/README.md`.

## Corpus

| Program | Rust files | Lines | Character |
|---|---|---|---|
| `escrow` | 5 | ~300 | Small, idiomatic, modern Anchor |
| `anchor-misc` | 70 | ~3,000 | Account-type and constraint coverage |
| `drift` | 116 | ~72,900 | Production DeFi protocol |

Line counts exclude the test files pruned from `drift`.

## Scan time

_Phase 6._ Wall-clock over each corpus program, on stated hardware, with the
thread count fixed. Reported alongside lines of source, to show the scaling
claimed in the build spec's invariants (linear in source size).

| Program | Lines | Files | Wall clock | Lines/sec |
|---|---|---|---|---|

## False-positive rate

_Phase 3 onward._ Every finding on the corpus is triaged by hand once and the
verdict recorded. Rate is reported per detector, because an aggregate number
hides the one rule that is ruining the experience.

| Rule | Findings on corpus | True positive | False positive | Rate |
|---|---|---|---|---|

The safe fixture corpus is a separate, absolute gate: **no safe fixture may be
flagged by any rule.** That is a build failure, not a statistic.

## Validation against a published audit

_Phase 6._ The credibility exercise. Structure:

### Which real issues Wheeltap caught

With the audit's finding ID alongside Wheeltap's, to show they are the same
issue and not a coincidence of location.

### Which it missed, and why

Grouped by the **class of analysis that would have been needed** — interprocedural
dataflow, type resolution, protocol-level reasoning about invariants no linter
can infer. This section is the most informative one in the document.

### What it flagged that the auditors did not

And whether those are valid. Some will be true issues the audit did not
prioritise; some will be false positives. Both are reported.

### Candidate programs

`drift` ships an `AUDIT.md` listing published third-party audits, which makes it
the leading candidate. Not yet decided — see *Open questions* in `PROGRESS.md`.
