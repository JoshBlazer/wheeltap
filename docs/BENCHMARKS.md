# Wheeltap benchmarks and validation

Two questions, answered honestly:

1. **Is it fast enough to sit in CI?** Scan time against source size.
2. **Does it find real bugs, and what does it miss?** Findings compared against
   a published third-party audit of the same program.

The second matters far more than the first. It is written in Phase 6 and **must
include the misses** — a tool whose limits are undocumented cannot be trusted.

## Status

**Parsing, modelling, and all twelve detectors are measured.** The audit
comparison comes in Phase 6.

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

Every finding on the corpus is triaged by hand and the verdict recorded. The
rate is reported per detector, because an aggregate hides the one rule that is
ruining the experience.

**All twelve rules, over 76,381 lines of third-party code:**

| Rule | Findings | True positive | False positive | Notes |
|---|---|---|---|---|
| WT001 | 0 | — | — | |
| WT002 | 0 | — | — | |
| WT003 | 1 | 0 | 1 | bounded by a validation in a called method |
| WT004 | 3 | 3 | 0 | Anchor's own `init_if_needed` test programs |
| WT005 | 15 | 0 | 15 | permissionless cranks — the dominant remaining gap |
| WT006 | 10 | 10 | 0 | Anchor test programs taking bumps from instruction data |
| WT007 | 0 | — | — | |
| WT008 | 0 | — | — | |
| WT009 | 0 | — | — | |
| WT010 | 0 | — | — | |
| WT011 | 4 | 0 | 4 | liquidator/user pairs distinguished by helper functions |
| WT012 | 2 | 2 | 0 | `WHITELISTED_SWAP_PROGRAMS.to_vec()` inside a loop |
| **Total** | **35** | **15** | **20** | **43% precision** |

By program: `escrow` **0**, `anchor-misc` 13, `drift` 22.

`escrow` staying at zero matters more than the totals. It is a small, correct,
idiomatic program — the closest thing the corpus has to the code a user will
point this at first — and a tool that greets them with findings on it does not
get a second run.

### The true positives are real, and they are in test code

Thirteen of the fifteen are in Anchor's own test suite, which deliberately
exercises the patterns the rules describe: `init_if_needed` with an
unconditional write, and `bump = <instruction argument>`. They are correct
findings about code written to demonstrate exactly those constructs. Nobody is
exploiting Anchor's test fixtures, but the rules did their job.

The other two are drift's `WHITELISTED_SWAP_PROGRAMS.to_vec()` inside a loop —
a genuine, if minor, compute inefficiency in production code.

### Every false positive, and why it survives

| Rule | Count | Cause |
|---|---|---|
| WT005 | 15 | **Permissionless cranks.** Drift's `UpdateUserFuelBonus` and friends take an `authority` signer that is the *caller*, while `user.authority` belongs to someone else. The rule sees a stored key and a same-named account and infers a relationship that was never intended. Separating this from the genuine article needs intent, not syntax. |
| WT011 | 4 | **Distinguished through a helper.** `is_stats_for_user(&filler, &filler_stats)?` asserts the accounts differ inside a function this analyser does not follow (ADR-001). |
| WT003 | 1 | **Bounded by a called method.** `transfer_config.validate_transfer(shares)?` two lines above the arithmetic. Same limit. |

All twenty share one root cause: **the check exists, in a function Wheeltap does
not follow.** That is the intraprocedural boundary set in ADR-001, and it is why
these rules report `confidence: medium` rather than high.

### What was tuned out, and what it cost

Nine false-positive classes were found by running against the corpus and removed
by tightening the rules — never by adjusting a fixture:

| Rule | Removed | Findings eliminated | What it cost |
|---|---|---|---|
| WT001 | matching on authority-like **names** alone | 66 | `known_gaps/WT001_unreferenced_admin` — a real vulnerability now missed |
| WT005 | reporting accounts under `init` | ~50 | nothing; there is no prior state to check |
| WT005 | ignoring constraints on the **counterparty** | 65 | nothing |
| WT005 | ignoring the zero-copy `account.load()?.field` form | 37 | nothing |
| WT005 | reporting instructions holding two accounts of one type | 30 | genuine cases where two same-typed accounts *should* be related |
| WT002 | treating `load`/`load_mut` as raw reads | 18 | nothing; that is `AccountLoader`'s validating API |
| WT011 | checking constraints but not handlers | 8 | nothing |
| WT003 | flagging raw lamport arithmetic | 8 | underflow in a hand-rolled lamport transfer |
| WT003 | *(reversed a Phase 2 decision — see below)* | | |

**On reversing the lamport decision.** Phase 2 kept `lamports` in the value-word
list deliberately, documenting six false positives as an acceptable cost. Phase 3
overturned that: writing WT008's *safe* fixture — correct, careful close code —
produced three more false positives from WT003, and the safe corpus is an
absolute gate rather than a statistic. With nine examples and none genuine, the
evidence had changed.

The structural argument was there to be made all along: lamport balances are
bounded by the total supply of SOL, so an addition cannot reach `u64::MAX`, and
the runtime enforces conservation of lamports across a transaction, so an
underflowing subtraction is rejected before it settles. Neither argument applies
to a balance the program tracks itself, which is what the rule is for.

### The absolute gate

The safe fixture corpus is not a statistic but a build failure: **no safe fixture
may be flagged by any rule**, enforced globally across every detector in
`tests/fixtures.rs`. It passes with zero findings — and it was WT003 firing
inside WT008's safe fixture that caught the lamport problem, which is precisely
the cross-detector failure the global gate exists for.

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
