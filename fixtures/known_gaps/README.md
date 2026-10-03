# Known gaps — real vulnerabilities Wheeltap does *not* catch

Everything in this directory is genuinely vulnerable code that the current
detectors miss. It is here, tested, and documented, rather than deleted.

## Why this directory exists

A detector can be made to catch any single example. The question is what it
costs elsewhere. When precision and recall genuinely conflict, the choice gets
made deliberately, and the losing side gets written down here instead of
quietly disappearing from the corpus.

The alternative — trimming a fixture until the detector passes — produces a tool
that looks better than it is. The build spec's rule is *never weaken a fixture to
silence a false positive*; this directory is the same principle applied to false
negatives.

## How it is tested

`tests/fixtures.rs` asserts these are **not** flagged. That reads backwards
until you consider what it does: when a future detector improvement starts
catching one, the test fails, and the failure says *promote this to
`fixtures/vulnerable/`*. A gap that closes silently is a gap nobody records as
closed.

## The gaps

### `ND_DFT1_IN_01_oracle_read_in_helper/` — a read one call away

An `AccountInfo` oracle with no owner constraint, whose data is read inside a
helper rather than in the handler. This is Neodyme's ND-DFT1-IN-01 against
drift, reduced to its shape.

**Why it is missed.** WT002 fires when an unvalidated account's data is
deserialised *in the handler*. `get_price(&oracle)` puts the read one call away,
so the body holds no deserialisation to find. The intraprocedural boundary
(ADR-001) cuts both ways: the same limit that stops WT002 calling drift's
zero-copy loaders critical stops it seeing this.

Verified the same way: drift's `admin.rs` at
`ac4bfd00e92105adba9809bcf1dfc50b3eb278ae`, the revision Neodyme cite and before
the fix, reports nothing.

**What would close it.** A summary of which functions dereference an
`AccountInfo`'s data, propagated to callers — the first genuinely
interprocedural analysis the tool would have.

## Closed gaps

A gap that a rule starts catching is promoted to `fixtures/vulnerable/`, under
the rule that catches it, and its write-up moves to that rule's entry in
`docs/DETECTORS.md`.

| Gap | Closed in | By | Now at |
|---|---|---|---|
| `TOB_DRIFT_8_remaining_accounts` — accounts taken from `remaining_accounts`, never related | v1.1 | WT014, on a model of remaining accounts (ADR-020) | `vulnerable/WT014_unrelated_remaining_accounts/` |
| `WT001_unreferenced_admin` — an unsigned admin nothing reads | v1.1 | WT013, which asks whether the account is used at all | `vulnerable/WT013_unused_account/` |

WT001 still does not report the second, and should not: the only signal WT001
has for it is the name `admin`, and its name-based version reported 66
findings on correct code (`docs/BENCHMARKS.md`). WT013 catches it from a
direction that costs nothing on the corpus.
