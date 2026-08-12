# Wheeltap — Progress

**Current phase:** 2 complete — next is 3, the full detector suite
**Last updated:** 2026-08-12
**Build status:** green — `fmt --check`, `clippy -D warnings`, and 112 tests pass
on stable 1.97.1, and the workspace builds on the 1.88 MSRV.

## Phase status

| Phase | Name | Status | Exit criteria met | Notes |
|-------|------|--------|-------------------|-------|
| 0 | Foundations | **done** | yes | CI green on a fresh clone, both jobs, at `492e419` |
| 1 | Loader, parser, program context | **done** | yes | `debug-context` models all three corpus programs accurately; 64 tests |
| 2 | Detector engine + WT001-WT003 | **done** | yes | `scan fixtures/vulnerable` catches all three; `scan fixtures/safe` reports nothing |
| 3 | Full detector suite | next | — | WT004-WT012 |
| 4 | Reporting, suppression, baselines | not started | — | |
| 5 | GitHub Action and distribution | not started | — | |
| 6 | Validation, documentation, release | not started | — | |

## Detector status

A rule is `implemented` only when its true-positive *and* false-positive
fixtures pass. Fixture counts are files, not assertions.

| ID | Name | Severity | Implemented | TP fixtures | FP fixtures | Notes |
|----|------|----------|-------------|-------------|-------------|-------|
| WT001 | Missing signer check | Critical | **yes** | 1 | 3 | High confidence. Narrow by design: fires only when *nothing* in the account list signs — see known false negatives |
| WT002 | Missing owner check | Critical | **yes** | 1 | 2 | Medium confidence; the owner assertion is looked for in the reading handler only |
| WT003 | Unchecked arithmetic | High | **yes** | 1 | 2 | Medium confidence; respects `overflow-checks = true` |
| WT004 | Account reinitialisation | High | no | 0 | 0 | Phase 3 |
| WT005 | Missing `has_one` / constraint | High | no | 0 | 0 | Phase 3 |
| WT006 | Non-canonical PDA bump | High | no | 0 | 0 | Phase 3 |
| WT007 | Arbitrary CPI target | Critical | no | 0 | 0 | Phase 3 |
| WT008 | Missing rent-exemption / close handling | Medium | no | 0 | 0 | Phase 3 |
| WT009 | Sysvar spoofing | High | no | 0 | 0 | Phase 3 |
| WT010 | Unsafe `AccountInfo` deserialisation | High | no | 0 | 0 | Phase 3 |
| WT011 | Duplicate mutable accounts | Medium | no | 0 | 0 | Phase 3 |
| WT012 | Inefficient allocation in loop | Low | no | 0 | 0 | Phase 3 |

## What works right now

**Phase 0 — scaffolding.**

- Cargo workspace laid out per build spec §4.5, with the root as the installable
  `wheeltap` binary (ADR-002).
- Four library crates with their dependency graph wired: `wheeltap-core`,
  `-rules`, `-report`, `-cli`.
- CI workflow: `fmt --check`, `clippy -D warnings`, build, test, plus a separate
  MSRV job that reads the version out of the manifest so it cannot drift.
- Corpus of three vendored real Anchor programs, licence-checked and attributed.
- Documentation: `README.md`, `DECISIONS.md` (ADR-001 to ADR-006),
  `docs/DETECTORS.md`, `docs/BENCHMARKS.md`, fixture and corpus READMEs.

**Phase 1 — the analyser.**

- **Loader.** Walks a directory or a single file, honours `.gitignore` (even
  outside a git repository), skips `target/`, `.git/`, `node_modules/`, does not
  follow symlinks, and returns files in sorted order so runs are reproducible.
- **Parser.** `syn::parse_file` with spans. A file that fails to parse, is not
  UTF-8, or is unreadable produces a warning and the scan continues.
- **`ProgramContext`.** `#[program]` modules; handlers, recognised anywhere a
  function takes a `Context<T>` (ADR-006); `#[derive(Accounts)]` structs with
  every Anchor account type, seeing through `Box` and `Option`; `#[account(...)]`
  constraints parsed into structured form; `#[account]` data structs;
  `/// CHECK:` comments; `#[instruction(...)]` argument lists.
- **Constraint parsing.** Hand-written token splitting, because Anchor's grammar
  is not Rust attribute-meta syntax — `has_one = x @ MyError` defeats
  `parse_nested_meta` outright. Distinguishes a canonical `bump` from a supplied
  `bump = expr`, which a whole detector will rest on.
- **Source map.** Span to file, line, column, and bounded snippets.
- **`wheeltap debug-context <path> [--json]`.** Prints the model.

**Measured on the corpus** (release build, single-threaded):

| Program | Files | Lines | Handlers | Accounts structs | Constraints | Time |
|---|---|---|---|---|---|---|
| `escrow` | 9 | 313 | 6 | 2 | 44 | <0.01 s |
| `anchor-misc` | 15 | 3,057 | 141 | 145 | 527 | 0.02 s |
| `drift` | 116 | 73,011 | 262 | 155 | 1,108 | 0.36 s |

Zero parse diagnostics and zero unresolved handlers across all 76,000 lines.

**Phase 2 — detectors.**

- **Engine.** `Detector` trait, registry, deduplication by identity, and a total
  ordering so two runs agree byte for byte.
- **Deterministic finding identity** per build spec §4.3:
  `hash(rule_id, relative_path, enclosing_item_path, normalised_snippet)`.
  Tested end to end against a real detector: moving the fixture down the file
  keeps the identity, changing the offending line clears the finding.
- **WT001, WT002, WT003**, fixtures first, each with its `docs/DETECTORS.md`
  entry written before the implementation.
- **JSON reporter**, versioned (`schema: 1.0`), byte-identical across runs.
- **`wheeltap scan <path>`** with `--format`, `--severity-threshold`,
  `--fail-on`, and exit codes 0 clean / 1 findings / 2 error.

**Phase 2 exit criteria, both met:**

| Gate | Result |
|---|---|
| `scan fixtures/vulnerable` catches everything | 10 findings; all three rules fire on their own fixtures |
| `scan fixtures/safe` reports nothing | 0 findings, exit 0 |

**False-positive budget on real code:** 6 findings across 76,381 lines, all
hand-triaged and all false positives, documented individually in
`docs/BENCHMARKS.md`. `escrow` is clean.

- 112 passing tests: 77 unit, 8 fixture gates, 7 corpus, 10 robustness,
  2 snapshot, plus CLI and reporter coverage.

## What does not work yet

- **Only Markdown and SARIF are missing from `scan`** — `--format markdown` and
  `--format sarif` exit 2 with "not implemented" (Phase 4).
- No suppression: neither `// wheeltap:allow(WT001)` comments nor
  `wheeltap.toml` are read yet (Phase 4). There is currently no way to silence a
  false positive short of editing the code.
- No `--baseline` diffing yet, though the identity scheme it needs is built and
  tested (Phase 4).
- Nine detectors remain (WT004-WT012).
- Module paths are resolved within a file only; `mod x;` is not followed to
  `x.rs`. Identity combines the relative file path with the in-file item path,
  so this costs nothing downstream.
- Items generated by macro *invocations* are invisible. A known and tested limit
  of syntactic analysis (ADR-001).

## Decisions made

| Date | Decision | Rationale | Alternatives rejected |
|---|---|---|---|
| 2026-08-11 | ADR-001: parse with `syn`, no rustc internals | Stable toolchain; `rustc_private` breaks every bump; the target bug classes are visible in the AST | rustc HIR/MIR (nightly, API churn); regex over source (no structure) |
| 2026-08-11 | ADR-002: repository root is the installable `wheeltap` package | Satisfies both `cargo install --path .` and `cargo install wheeltap`, which a virtual manifest cannot; the `ripgrep` layout | Keep §4.5 verbatim and change the documented install command; move the whole CLI to the root |
| 2026-08-11 | ADR-003: `syn` 3.x, edition 2024, MSRV 1.88 | `syn` 3 released since the spec was written; 2.x would fail to parse newer syntax and quietly lose coverage | Pin `syn` 2.x for API familiarity |
| 2026-08-11 | MSRV corrected 1.85 → 1.88, measured not inferred | `ignore` 0.4.30 uses let-chains (stable in 1.88), so 1.85 never built; ADR-003 amended rather than rewritten | Downgrade `ignore` to keep 1.85 (buys nothing; 1.88 is June 2025) |
| 2026-08-11 | ADR-004: `proc-macro2` `span-locations` for line/column | The caveat (proc-macro context) does not apply to a CLI; avoids recomputing offsets `syn` already has | Hand-rolled offset table from raw source |
| 2026-08-11 | Corpus: `escrow`, `anchor-misc`, `drift` | Deliberate size ladder — idiomatic small, constraint-dense medium, production large; all permissively licensed | Squads v4 (AGPL-3.0, copyleft); Marinade (unclear licence, `NOASSERTION`); SPL (archived, mostly not Anchor) |
| 2026-08-11 | Prune `drift`'s 51 test files from the corpus | 76,000 lines, more than half the program, that exercise the analyser without teaching it anything; behaviour on `#[cfg(test)]` code belongs in a purpose-built fixture | Vendor `drift` whole (repository bulk); vendor only `instructions/` (loses realistic module depth) |
| 2026-08-12 | ADR-005: no `rayon`; single-threaded analysis | `syn` ASTs are not `Send` (`proc-macro2` uses `Rc`), so shared-context parallelism will not compile; and drift models in 0.36 s, so there is nothing to win | Two-pass parallelism (doubles parse cost); discard `syn` nodes for an owned model (blinds body-level detectors) |
| 2026-08-12 | Analysis runs on a 16 MiB stack thread | `syn` is recursive-descent; a test-harness thread gets 2 MiB against the main thread's 8 MiB, so identical input aborted under `cargo test` and passed from the CLI | Leave it to the caller (behaviour varies by context); bound nesting alone (rejects legitimate code) |
| 2026-08-12 | ADR-006: handlers recognised wherever declared | Real Anchor delegates from `#[program]` to `handle_*` functions; entrypoint-only modelling saw **0** of drift's 262 handlers | Model only `#[program]` functions (misses where arithmetic and CPI actually live) |
| 2026-08-12 | Token-walking renderer instead of string post-processing | Collapsing spaces in rendered token text cannot tell `a != b` from a negation and got it wrong; `Punct::spacing()` already carries the answer | Regex/string cleanup of `TokenStream::to_string()` |
| 2026-08-12 | WT001 fires only when **nothing** in the account list signs | Name-based matching gave 66 corpus findings, all sampled ones false; requiring "no signer anywhere" gave 0 false positives and still catches the canonical bug | Keep the name path at medium confidence (66 criticals on correct code); drop WT001 entirely (loses the canonical bug) |
| 2026-08-12 | `fixtures/known_gaps/` for documented false negatives | A detector can be made to catch any one example; when precision and recall genuinely conflict the loser gets written down and tested, not deleted | Trim the fixture until the rule passes (makes the tool look better than it is) |
| 2026-08-12 | WT002 does not treat `load`/`load_mut` as raw reads | They are `AccountLoader`'s validating API; on a bare `AccountInfo` no such method exists. Including them gave 18 findings on drift, all correct zero-copy loaders | Keep them and document 18 false positives |
| 2026-08-12 | Body analysis by rendered-text matching, not only an AST visitor | Owner assertions live inside macros — `require_keys_eq!(*ctx.accounts.x.owner, ..)` — which no expression visitor walks into; missing them reports correct code as critical | Visitor only (misses macros); parse macro bodies (not generally possible) |

## Known false positives / negatives

### False positives

Six on the real corpus, all WT003, all raw lamport arithmetic. Each is triaged
individually in `docs/BENCHMARKS.md`. `lamports` stays in the value-word list
deliberately: manual lamport transfers that underflow are a real bug class, and
dropping the word would trade six documented false positives for a silent class
of misses.

### False negatives

Kept as runnable fixtures in `fixtures/known_gaps/`, with a test asserting they
are still missed — so that when a detector improvement starts catching one, the
test fails and says to promote it.

- **WT001: an unsigned authority with no `has_one` recording it.** Matching on
  authority-like names alone produced 66 findings across the corpus, every one
  sampled a false positive (`mint_authority` on `init`, drift's `drift_signer`).
  Sixty-six criticals on correct code to catch one real bug is a bad trade.
- **WT001: an account list where something else signs** but the authority still
  should have — a withdrawal authorised by a payer, say. Excluded because drift
  legitimately administers user accounts through a keeper signer, and separating
  the two needs intent.
- **WT002: ownership asserted in a called function**, not the reading handler.
  drift's zero-copy loaders do exactly this; it is the intraprocedural boundary
  from ADR-001 and is why the rule is medium confidence.
- **WT003: overflow accumulated across statements**, which needs dataflow.

### Modelling limits behind them

- **Macro-generated items are invisible.** An Accounts struct declared inside a
  macro invocation is not modelled, and nothing warns about it. Tested and
  documented rather than papered over.
- **Any function taking a `Context<T>` is modelled as a handler**, including
  helpers that are not instructions. Deliberate (ADR-006): a spurious handler
  costs a wasted pass, a missed one costs coverage silently.
- **Type aliases are not resolved.** `type MyAccount = Account<'info, Vault>;`
  models as a composite, not an `Account`. No corpus program does this, but it
  would be a false negative for the owner-check detectors.
- **Constraint assertion helpers are textual.** `asserts_owner` and friends look
  for `.owner`, `is_signer`, `key()` inside a custom constraint rather than
  understanding the expression. Good enough to suppress false positives,
  not good enough to be relied on as proof of validation.
- **Files nested more than 256 deep are skipped** with a warning rather than
  parsed. No real code approaches this.

## Open questions (for the human)

~~**Q1 — No C toolchain.**~~ **Resolved 2026-08-11.** `build-essential`
installed; the workspace builds and tests.

~~**Q2 — Git identity.**~~ **Resolved 2026-08-11.** Joshua Willie
<joshblazerwillie@gmail.com>, set in the repository-local git config. Commits
carry no AI co-authorship trailer, by explicit instruction.

~~**Q3 — Repository URL.**~~ **Resolved 2026-08-11.**
`https://github.com/JoshBlazer/wheeltap` — public, configured as `origin`, and
pushed.

~~**Q8 — GitHub authentication.**~~ **Resolved 2026-08-12.** `gh` 2.97.0 at
`~/.local/bin/gh`, authenticated as `JoshBlazer` over HTTPS with `repo` and
`workflow` scopes.

The four questions the build spec (§10) requires answering before Phase 3:

**Q4 — Anchor only for v1.0, or attempt CosmWasm?**
Recommendation: **Anchor only.** Depth beats breadth, and the detector quality
bar is the whole point of the project.

**Q5 — Publish to crates.io as `wheeltap`?**
The name appears unclaimed. Worth reserving early if the project is going ahead
under that name.

**Q6 — Which audited program for the Phase 6 validation exercise?**
Recommendation: **`drift`**, already vendored. It ships an `AUDIT.md` listing
published third-party audits, it is large enough for the comparison to be
meaningful, and it is Apache-2.0.

**Q7 — Is the GitHub Action in scope for v1.0?**
Recommendation: **in scope.** It is a large share of the project's perceived
value and the most persuasive artefact for a portfolio.

## Next actions

1. Answer Q4 to Q7 and record them in `DECISIONS.md`. **Q4 and Q6 must be
   settled before Phase 3.**
2. Begin Phase 2 — the detector engine and the first three rules:
   - `Detector` trait and registry; `Finding` with deterministic identity per
     build spec §4.3, `hash(rule_id, relative_path, enclosing_item_path,
     normalised_snippet)`. The context already carries `item_path` on every
     field and handler for exactly this.
   - **Fixtures first**, per rule: the vulnerable case, then at least two safe
     cases a naive implementation would flag, then the `docs/DETECTORS.md`
     entry, then the detector.
   - WT001 missing signer, WT002 missing owner, WT003 unchecked arithmetic.
   - JSON reporter; `wheeltap scan` with exit codes 0/1/2.
3. Phase 2 exit: `wheeltap scan fixtures/vulnerable` catches everything and
   `wheeltap scan fixtures/safe` reports nothing, with the no-false-positive
   assertion enforced globally across every rule.
