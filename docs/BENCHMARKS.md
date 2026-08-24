# Wheeltap benchmarks and validation

Two questions, answered honestly:

1. **Is it fast enough to sit in CI?** Scan time against source size.
2. **Does it find real bugs, and what does it miss?** Findings compared against
   a published third-party audit of the same program.

The second matters far more than the first. It is written in Phase 6 and **must
include the misses** — a tool whose limits are undocumented cannot be trusted.

## Status

**Complete.** Parsing, modelling, all twelve detectors, and the audit
comparison are measured. The comparison against drift's two published audits
has its own document: [`docs/AUDIT.md`](AUDIT.md).

## Corpus

| Program | Rust files | Lines | Character |
|---|---|---|---|
| `escrow` | 9 | 313 | Small, idiomatic, modern Anchor |
| `anchor-misc` | 15 | 3,057 | Account-type and constraint coverage |
| `drift` | 116 | 73,011 | Production DeFi protocol |

Line counts exclude the test files pruned from `drift`.

## Scan time

Wall clock for a **full scan** — discovery, parsing, modelling, and all twelve
detectors — measured end to end as a process, so startup is included. Release
build, single-threaded, seven runs. Hardware: x86-64 Linux (WSL2), Rust 1.97.1.

| Program | Lines | Files | Best | Median | Lines/sec (median) |
|---|---|---|---|---|---|
| `escrow` | 313 | 9 | 4.5 ms | 5.0 ms | ~63,000 |
| `anchor-misc` | 3,057 | 15 | 27.6 ms | 29.5 ms | ~104,000 |
| `drift` | 73,011 | 116 | 424 ms | 558 ms | ~131,000 |
| all three at once | 76,381 | 140 | 916 ms | 1,339 ms | ~57,000 |

The last row is the interesting one. Scanning all three together costs more
than scanning them separately and adding it up — 0.92 s against 0.46 s. The
walk and the parse are linear; some detectors are not, because they ask
questions of the form *does any other account in this program …* and a bigger
model means more to look through. At this size it does not matter. At ten times
this size it would, and the honest thing is to record the shape now rather than
claim a linearity the numbers do not show.

Earlier phases measured `debug-context`, which stops before the detectors, at
0.36 s on drift. The difference — roughly 0.2 s — is what the twelve rules
cost on 73,000 lines.

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

| Rule | Findings | True positive | Unresolved | False positive | Notes |
|---|---|---|---|---|---|
| WT001 | 0 | — | — | — | |
| WT002 | 0 | — | — | — | |
| WT003 | 1 | 0 | 0 | 1 | bounded by a validation in a called method |
| WT004 | 3 | 3 | 0 | 0 | Anchor's own `init_if_needed` test programs |
| WT005 | 7 | 0 | 0 | 7 | permissionless cranks — the dominant remaining gap |
| WT006 | 10 | 10 | 0 | 0 | Anchor test programs taking bumps from instruction data |
| WT007 | 0 | — | — | — | |
| WT008 | 0 | — | — | — | |
| WT009 | 0 | — | — | — | |
| WT010 | 0 | — | — | — | |
| WT011 | 1 | 0 | 1 | 0 | aliasing drift permits on purpose and branches on elsewhere |
| WT012 | 2 | 2 | 0 | 0 | `WHITELISTED_SWAP_PROGRAMS.to_vec()` inside a loop |
| **Total** | **24** | **15** | **1** | **8** | **63% precision** |

By program: `escrow` **0**, `anchor-misc` 13, `drift` 11.

**Unresolved** is a third column because two of the categories were doing work
they should not. `FillOrder` takes two mutable `UserStats` accounts with nothing
keeping them apart — which is true — and drift permits the aliasing deliberately,
branching on it in `controller/orders.rs:1167`. Whether that is handled
correctly is a question about a controller several calls away. Filing it as a
false positive would claim the tool was wrong; filing it as a true positive
would claim a bug nobody has demonstrated.

**These numbers improved during Phase 6**, from 35 findings at 43% precision.
Comparing Wheeltap's output against drift's audits exposed two false-positive
classes with a common cause — relationships asserted in more than one place —
and both rules were fixed. [`docs/AUDIT.md`](AUDIT.md) has the detail.

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
| WT005 | 7 | **Permissionless cranks.** Drift's `UpdateUserFuelBonus` and friends take an `authority` signer that is the *caller*, while `user.authority` belongs to someone else. The rule sees a stored key and a same-named account and infers a relationship that was never intended. Separating this from the genuine article needs intent, not syntax. |
| WT003 | 1 | **Bounded by a called method.** `transfer_config.validate_transfer(shares)?` one line above the arithmetic proves the sum cannot overflow. |

All eight share one root cause: **the check exists, somewhere this analyser does
not look.** For WT003 that is a called method — the intraprocedural boundary set
in ADR-001, and why the rule reports `confidence: medium`. For WT005 it is not a
boundary at all but a question the syntax cannot answer: whether the signer is
meant to own the account or merely to call the instruction.

Two of the four false-positive classes that used to appear here are gone. WT005
reported ten account lists as unlinked where the link was built out of two
constraints, and WT011 reported four liquidation instructions where the
distinction was made between the accounts' owners rather than the accounts
themselves. Both were found by the audit comparison and fixed in Phase 6.

### What was tuned out, and what it cost

Eleven false-positive classes were found by running against the corpus and the
audits, and removed by tightening the rules — never by adjusting a fixture:

| Rule | Removed | Findings eliminated | What it cost |
|---|---|---|---|
| WT001 | matching on authority-like **names** alone | 66 | `known_gaps/WT001_unreferenced_admin` — a real vulnerability now missed |
| WT005 | reporting accounts under `init` | ~50 | nothing; there is no prior state to check |
| WT005 | ignoring constraints on the **counterparty** | 65 | nothing |
| WT005 | ignoring the zero-copy `account.load()?.field` form | 37 | nothing |
| WT005 | reporting instructions holding two accounts of one type | 30 | genuine cases where two same-typed accounts *should* be related |
| WT002 | treating `load`/`load_mut` as raw reads | 18 | nothing; that is `AccountLoader`'s validating API |
| WT011 | checking constraints but not handlers | 8 | nothing |
| WT005 | reading one constraint at a time, not the relationships they compose | 8 | nothing; found by the audit comparison |
| WT011 | requiring the comparison to name the flagged accounts | 3 | nothing; found by the audit comparison |
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

## Validation against published audits

Done, and written up separately: [`docs/AUDIT.md`](AUDIT.md).

The short version. Drift has two published audits — Neodyme (May 2024) and
Trail of Bits (February 2023) — with 30 findings between them. **Wheeltap
reproduces one, weakly.** Eleven of the thirty need reasoning about what the
protocol is *for*, which nothing in this design reaches. Every miss traced to a
limit already documented, and each one that was close enough to test was
verified by fetching the pre-fix revision the report names and scanning it,
rather than inferring the answer from the fixed code.

The exercise also found that Wheeltap was reporting drift's *fix* to
TOB-DRIFT-8 as a missing check, which is what prompted the two rule changes
above.
