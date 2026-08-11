# Wheeltap — Progress

**Current phase:** 0 — Foundations (exit criteria met locally; unverified on CI)
**Last updated:** 2026-08-11
**Build status:** green locally — `fmt --check`, `clippy -D warnings`, and 7
tests all pass on stable 1.97.1, and the workspace builds on the 1.88 MSRV. CI
has never run: nothing is pushed yet (Q8).

## Phase status

| Phase | Name | Status | Exit criteria met | Notes |
|-------|------|--------|-------------------|-------|
| 0 | Foundations | done, pending CI | locally | Workspace, CI, docs, and corpus in place; green on stable and on MSRV. The exit criterion is "CI green on a fresh clone", which needs a push (Q8) |
| 1 | Loader, parser, program context | not started | — | |
| 2 | Detector engine + WT001-WT003 | not started | — | |
| 3 | Full detector suite | not started | — | |
| 4 | Reporting, suppression, baselines | not started | — | |
| 5 | GitHub Action and distribution | not started | — | |
| 6 | Validation, documentation, release | not started | — | |

## Detector status

No detectors implemented. A rule is `implemented` only when its true-positive
*and* false-positive fixtures pass.

| ID | Name | Severity | Implemented | TP fixtures | FP fixtures | Notes |
|----|------|----------|-------------|-------------|-------------|-------|
| WT001 | Missing signer check | Critical | no | 0 | 0 | Phase 2 |
| WT002 | Missing owner check | Critical | no | 0 | 0 | Phase 2 |
| WT003 | Unchecked arithmetic | High | no | 0 | 0 | Phase 2 |
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

- Cargo workspace laid out per build spec §4.5, with the root as the installable
  `wheeltap` binary (ADR-002).
- Four library crates with their dependency graph wired: `wheeltap-core`,
  `-rules`, `-report`, `-cli`.
- CI workflow: `fmt --check`, `clippy -D warnings`, build, test, plus a separate
  MSRV job that reads the version out of the manifest so it cannot drift.
- Corpus of three vendored real Anchor programs, licence-checked and attributed:
  `escrow` (~300 lines), `anchor-misc` (~3,000), `drift` (~72,900).
- Documentation skeletons: `README.md`, `DECISIONS.md` (ADR-001 to ADR-004),
  `docs/DETECTORS.md`, `docs/BENCHMARKS.md`, fixture and corpus READMEs.
- Seven passing unit tests pinning the foundations: `syn` parses Anchor-shaped
  source and reports usable spans, malformed source errors rather than
  panicking, the hash helper is deterministic and field-separated, the CLI
  definition is valid, exit codes match the documented contract.
- The `wheeltap` binary builds and runs: `--version`, `--help`, and both
  subcommands dispatch correctly.

## What does not work yet

- `wheeltap scan` and `wheeltap debug-context` exit 2 with "not implemented".
- No loader, no parser, no program context model, no detectors, no reporters.
- CI has never run — nothing is pushed. Phase 0's exit criterion is "CI green on
  a fresh clone", so it is met only in substance until then.

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

## Known false positives / negatives

None yet — nothing is implemented. This section stays in the file as a standing
obligation: known weaknesses get documented here rather than quietly tolerated.

## Open questions (for the human)

~~**Q1 — No C toolchain.**~~ **Resolved 2026-08-11.** `build-essential`
installed; the workspace builds and tests.

~~**Q2 — Git identity.**~~ **Resolved 2026-08-11.** Joshua Willie
<joshblazerwillie@gmail.com>, set in the repository-local git config. Commits
carry no AI co-authorship trailer, by explicit instruction.

~~**Q3 — Repository URL.**~~ **Resolved 2026-08-11.**
`https://github.com/JoshBlazer/wheeltap` — public, and configured as `origin`.
Nothing pushed yet: this machine has no GitHub credentials, so the first push
needs `gh auth login` (see Q8).

**Q8 — GitHub authentication.** `gh` 2.97.0 is installed at `~/.local/bin/gh`,
but no credentials exist on this machine — no token, no SSH key, no credential
helper. `gh auth login` is interactive and must be run by hand before the first
push.

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

1. Authenticate with GitHub (Q8) and push; confirm CI is green on a fresh clone.
   **That closes Phase 0.**
2. Answer Q4 to Q7 and record them in `DECISIONS.md`.
4. Begin Phase 1: file discovery honouring `.gitignore`, `syn::parse_file` with
   parse failures degraded to warnings, and the `ProgramContext` model —
   `#[program]` modules, `#[derive(Accounts)]` structs, Anchor account types,
   and structured `#[account(...)]` constraints.
5. Phase 1 exit: `wheeltap debug-context fixtures/corpus/escrow` prints an
   accurate model, and the same command survives `drift` without panicking.
