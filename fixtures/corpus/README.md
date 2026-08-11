# Corpus — vendored third-party Anchor programs

These are **real, unmodified, third-party programs**, vendored as end-to-end
scan targets. They are not Wheeltap's test fixtures for detector correctness —
those live in `fixtures/vulnerable/` and `fixtures/safe/` and are written by us.

The corpus answers a different question: *does Wheeltap survive real code?* It
is used for

- integration tests that assert the scan completes without panicking,
- Phase 1 assertions on the program model (handler and struct counts),
- Phase 6 benchmarking of scan time against source size,
- hand-triaged finding snapshots recorded in `docs/BENCHMARKS.md`.

Nothing here is compiled. The workspace manifest excludes `fixtures/`.

## Attribution

| Directory | Upstream | Commit | Licence | Vendored |
|---|---|---|---|---|
| `escrow/` | [solana-foundation/program-examples](https://github.com/solana-foundation/program-examples) — `tokens/escrow/anchor` | `4120f259886c2f711a2b77ee1798fd360ff1dab6` | MIT | 2026-08-11 |
| `anchor-misc/` | [otter-sec/anchor](https://github.com/otter-sec/anchor) — `tests/misc/programs` | `474204eebef7a48373eb4fca441f4c54b8e04348` | Apache-2.0 | 2026-08-11 |
| `drift/` | [velocity-exchange/protocol-v2](https://github.com/velocity-exchange/protocol-v2) — `programs/drift` | `13e8e9b8d614f3b62e3a65a8c372c819e6529aeb` | Apache-2.0 | 2026-08-11 |

Each directory carries its upstream `LICENSE` verbatim. Both licences permit
redistribution with attribution; neither is copyleft.

> Two of these repositories were transferred after the build specification was
> written: `coral-xyz/anchor` is now `otter-sec/anchor`, and
> `drift-labs/protocol-v2` is now `velocity-exchange/protocol-v2`. The URLs above
> are the current ones.

## Why these three

They form a deliberate size and style ladder.

**`escrow/` — ~300 lines, modern idiomatic Anchor.**
A two-party token escrow: PDAs with canonical bumps, `init`/`close`, associated
token accounts, `has_one` constraints. This is what a well-written small program
looks like, so it doubles as a real-world false-positive check — findings here
deserve scrutiny before they are believed.

**`anchor-misc/` — ~3,000 lines, constraint and account-type coverage.**
Anchor's own integration-test programs, which exercise nearly every account
type and constraint form the framework supports, including the awkward ones:
nested and multi-line `#[account(...)]` attributes, `init_if_needed`, zero-copy
loaders, optional accounts, composite account structs. This is the Phase 1
target for proving the context model parses what Anchor can actually express.
It is deliberately *not* realistic program logic — it is a syntax stress test.

**`drift/` — ~73,000 lines, production DeFi protocol.**
A perpetual futures exchange in live use, and the corpus's real-code target:
deep module trees, macro-heavy code, extensive arithmetic on balances, and CPI
throughout. It sets the bar for scan performance and is the most likely source
of false positives, because production code is full of patterns that look
dangerous in isolation and are safe in context.

It also ships an `AUDIT.md` listing published third-party audits, which makes it
the leading candidate for the Phase 6 credibility exercise — comparing
Wheeltap's findings against a real audit report. That choice is still open (see
*Open questions* in `PROGRESS.md`).

## Local modifications

Only two, both subtractive, so that the vendored trees stay faithful:

1. **`drift/`** — vendored as `programs/drift/` only (`src/`, `Cargo.toml`,
   `LICENSE`, `AUDIT.md`), not the whole repository. Its 51 test files
   (`*test*.rs`, `tests.rs`) were deleted: 76,000 lines of test code, more than
   half the program, that exercises the analyser without teaching it anything.
   Detector behaviour on `#[cfg(test)]` code is covered by purpose-built
   fixtures instead.
2. **`escrow/` and `anchor-misc/`** — the `programs/` subtree and licence only;
   TypeScript tests, `Anchor.toml` tooling config, and JavaScript dependencies
   are not vendored.

No source file has been edited. Refreshing the corpus means re-vendoring from
the commits above and updating this table.
