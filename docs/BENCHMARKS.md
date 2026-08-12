# Wheeltap benchmarks and validation

Two questions, answered honestly:

1. **Is it fast enough to sit in CI?** Scan time against source size.
2. **Does it find real bugs, and what does it miss?** Findings compared against
   a published third-party audit of the same program.

The second matters far more than the first. It is written in Phase 6 and **must
include the misses** — a tool whose limits are undocumented cannot be trusted.

## Status

**Parsing and modelling are measured** (Phase 1). Detector cost and the audit
comparison come in Phases 3 and 6, once there are detectors to measure.

## Corpus

| Program | Rust files | Lines | Character |
|---|---|---|---|
| `escrow` | 9 | 313 | Small, idiomatic, modern Anchor |
| `anchor-misc` | 15 | 3,057 | Account-type and constraint coverage |
| `drift` | 116 | 73,011 | Production DeFi protocol |

Line counts exclude the test files pruned from `drift`.

## Scan time

Wall clock for `wheeltap debug-context`, which is the full pipeline short of
detectors: discovery, parsing, and building the program model. Release build,
single-threaded, best of five runs. Hardware: x86-64 Linux (WSL2), Rust 1.97.1.

| Program | Lines | Files | Wall clock | Lines/sec |
|---|---|---|---|---|
| `escrow` | 313 | 9 | <0.01 s | — |
| `anchor-misc` | 3,057 | 15 | 0.02 s | ~153,000 |
| `drift` | 73,011 | 116 | 0.36 s | ~203,000 |

Peak memory on `drift` is roughly 77 MB, which is the retained AST: the model
keeps `syn` nodes so that later phases can analyse handler bodies (ADR-005).

Two things follow, and both are recorded rather than assumed:

**Scaling is linear-ish in source size**, as the build spec's invariant 5
requires. Throughput rises slightly on the larger program, because fixed startup
is amortised.

**Parallelism is unnecessary.** The build spec called for `rayon` across files.
A production DeFi protocol models in under half a second on one thread, and
`syn` ASTs cannot cross threads anyway. The dependency was dropped rather than
carried unused — see ADR-005 for the measurement that decided it.

## Modelling coverage

Accuracy matters more than speed here: a fast scan of a model that missed half
the program would be worse than useless. Measured across the corpus:

| Program | Handlers | Accounts structs | Account fields | Constraints | Parse failures | Unresolved handlers |
|---|---|---|---|---|---|---|
| `escrow` | 6 | 2 | 21 | 44 | 0 | 0 |
| `anchor-misc` | 141 | 145 | 431 | 527 | 0 | 0 |
| `drift` | 262 | 155 | 855 | 1,108 | 0 | 0 |

**Zero parse failures across 76,381 lines** of real third-party code, and every
handler resolves to an Accounts struct the scan actually found. An unresolved
handler would mean the model was reasoning about less than the whole program,
so it is tracked as a first-class number rather than left implicit.

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
