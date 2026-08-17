# Wheeltap — Progress

**Current phase:** 5 built — next is 6, validation and release
**Last updated:** 2026-08-17
**Build status:** green — `fmt --check`, `clippy -D warnings`, and 187 tests pass
on stable 1.97.1, and the workspace builds on the 1.88 MSRV.

## Phase status

| Phase | Name | Status | Exit criteria met | Notes |
|-------|------|--------|-------------------|-------|
| 0 | Foundations | **done** | yes | CI green on a fresh clone, both jobs, at `492e419` |
| 1 | Loader, parser, program context | **done** | yes | `debug-context` models all three corpus programs accurately; 64 tests |
| 2 | Detector engine + WT001-WT003 | **done** | yes | `scan fixtures/vulnerable` catches all three; `scan fixtures/safe` reports nothing |
| 3 | Full detector suite | **done** | yes | All twelve rules implemented; corpus hand-triaged in `docs/BENCHMARKS.md` |
| 4 | Reporting, suppression, baselines | **done** | yes | Markdown + SARIF (schema-validated), suppression, `--baseline`. The SARIF *upload* criterion is met by the `upload` job in `action.yml`, which ingests for real on every push to `main` |
| 5 | GitHub Action and distribution | **built** | partly — see note | Action, `github` annotation format, release pipeline, and crates.io packaging all done and tested. Two tasks need a human: the demo pull request and its screenshot, and a crates.io token |
| 6 | Validation, documentation, release | next | — | The audit comparison against drift's two published audits is the substantial piece |

## Detector status

A rule is `implemented` only when its true-positive *and* false-positive
fixtures pass. Fixture counts are files, not assertions.

| ID | Name | Severity | Implemented | TP fixtures | FP fixtures | Notes |
|----|------|----------|-------------|-------------|-------------|-------|
| WT001 | Missing signer check | Critical | **yes** | 1 | 3 | High confidence. Narrow by design: fires only when *nothing* in the account list signs — see known false negatives |
| WT002 | Missing owner check | Critical | **yes** | 1 | 2 | Medium confidence; the owner assertion is looked for in the reading handler only |
| WT003 | Unchecked arithmetic | High | **yes** | 1 | 2 | Medium confidence; respects `overflow-checks = true` |
| WT004 | Account reinitialisation | High | **yes** | 1 | 1 | Medium confidence; excludes token accounts, which is the idiomatic `init_if_needed` |
| WT005 | Missing `has_one` constraint | High | **yes** | 1 | 1 | Medium confidence; 15 corpus false positives on permissionless cranks — the weakest rule |
| WT006 | Non-canonical PDA bump | High | **yes** | 1 | 1 | High confidence; distinguishes instruction data from the stored-bump idiom |
| WT007 | Arbitrary CPI target | Critical | **yes** | 1 | 1 | High confidence; only the first CPI argument is the callee |
| WT008 | Unsafe account close | Medium | **yes** | 1 | 1 | Medium confidence; fires on zeroing lamports, not on moving them |
| WT009 | Sysvar spoofing | High | **yes** | 1 | 1 | High confidence; exact name match, so `rent_collector` is safe |
| WT010 | Unchecked deserialisation | High | **yes** | 1 | 1 | High confidence; lexical match on the `_unchecked` APIs |
| WT011 | Duplicate mutable accounts | Medium | **yes** | 1 | 1 | Medium confidence; reads handlers as well as constraints |
| WT012 | Allocation in a loop | Low | **yes** | 1 | 1 | Medium confidence; receiver must look like a collection |

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

**Phase 3 — the full suite.**

- **WT004-WT012 implemented**, fixtures first, each with its catalogue entry
  written before the code. Twelve rules total.
- Every rule fires on its own vulnerable fixture; **no safe fixture is flagged by
  any rule**, enforced globally.

**Measured on 76,381 lines of third-party code:** 35 findings, hand-triaged —
15 true positives, 20 false positives, 43% precision. `escrow` reports zero.
Every finding is listed with a verdict in `docs/BENCHMARKS.md`.

All 20 false positives share one cause: the check exists, in a function
Wheeltap does not follow (ADR-001). Nine false-positive classes were removed
during the phase by tightening rules — never by adjusting a fixture — including
one Phase 2 decision reversed on new evidence.

- 119 passing tests: 8 fixture gates, 7 corpus, 10 robustness, 2 snapshot, and
  unit coverage across all four crates.

**Phase 4 — output, suppression, baselines.**

- **Markdown reporter**: grouped worst-first, each finding with its snippet,
  its fix, and its identity inline.
- **SARIF 2.1.0 reporter**, validated against the official OASIS schema
  (vendored at `schemas/sarif-2.1.0.json`) in `cargo test`, not only in CI.
  Carries `partialFingerprints` so GitHub matches an alert across pushes rather
  than reopening it every time code moves, plus `security-severity` for ranking
  and parse diagnostics as tool notifications.
- **Suppression**, both mechanisms: inline `// wheeltap:allow(WT001) -- reason`
  reaching over attributes and doc comments, and `wheeltap.toml` with rule,
  glob-path, and severity-override sections. Unknown config keys are an error.
  `--no-suppress` overrides both.
- **`--baseline findings.json`**: report only what is new. Verified end to end —
  scanning the same tree twice against its own baseline reports nothing, moving
  the code reports nothing, and a genuinely new vulnerability appears.
- **`--format`, `--severity-threshold`, `--fail-on`, `--config`.**

**Phase 5 — the Action and distribution.**

- **`--format github`**: GitHub Actions workflow commands, so findings appear as
  inline annotations on the pull-request diff. Built as a reporter rather than
  as `jq` in a YAML file, because both of its hazards fail silently — an
  unescaped comma truncates a message, and a path relative to the wrong root
  still prints but stops landing on the diff (ADR-014).
- **`--emit FORMAT=PATH`**, repeatable. One scan renders annotations to the log,
  SARIF to disk, and Markdown to the job summary. Scanning three times would be
  three chances for the three reports to disagree (ADR-013).
- **The Action**, `action/action.yml`: composite, inputs `path`,
  `severity-threshold`, `fail-on`, `baseline`, `format`, `config`,
  `upload-sarif`, `sarif-file`, `job-summary`; outputs `findings`, `exit-code`,
  `sarif-file`. Defaults match the CLI exactly, so a CI result reproduces
  locally without translating flags.
- **Results published twice**, as step outputs and as `WHEELTAP_EXIT_CODE` and
  `WHEELTAP_FINDINGS` in the environment. Both are measured to survive a failing
  run — the self-test asserts through both, the failing job on the environment
  and the passing job on the outputs.
- **Both annotation channels.** Annotations always; SARIF uploaded when it can
  succeed. `upload-sarif: auto` skips private repositories and fork pull
  requests and says why, rather than failing the build over a permission the
  contributor cannot grant (ADR-015).
- **Binary resolution in three fallbacks** — run cache, release archive, build
  from source — with the version read from the pinned checkout, so the ref you
  pin is the version you get (ADR-016). The cache is keyed on a fingerprint of
  the source that produced the binary, computed by the Action; the obvious
  `github.action_ref` is a trap that resolves to the ref of the *step reading
  it* and silently pinned this repository's own CI to a stale binary for five
  commits.
- **`demo/`**: a small, correct Anchor vault and a workflow that scans it on any
  pull request touching it. It reports nothing on `main`, which is the point —
  a pull request that adds a plausible bug is what produces the annotation.
- **`release.yml`**: five platform archives, each smoke-tested against the
  vulnerable fixtures before upload, plus a tag/manifest agreement check and
  crates.io publication in dependency order.
- **Packaged for crates.io**: `[package] exclude` keeps the 3 MB vendored
  corpus, the schema, and the tests out of `cargo install wheeltap` — 13 files.

**Phase 5 tests** (the Action is tested the way people use it, as `uses:`):

| Gate | Where | Result |
|---|---|---|
| Action fails the build on vulnerable fixtures | `action.yml`, `vulnerable` job | asserts `outcome == failure`, exit 1, findings > 0 |
| Action passes on safe fixtures | `action.yml`, `safe` job | asserts exit 0 and zero findings |
| SARIF is uploaded and ingested | `action.yml`, `upload` job, `main` only | closes the Phase 4 criterion |
| A baseline suppresses pre-existing findings | `action.yml`, `baseline` job | end to end through the Action |
| **Annotations land on the line they describe** | `tests/reporting.rs` | opens every annotated path from the repository root and compares the line to the finding's snippet |
| **SARIF results land there too** | `tests/reporting.rs` | the same check on `artifactLocation.uri`, plus an assertion that the two formats name identical paths |
| Escaping survives real findings | `tests/reporting.rs` | parses each command back and rejects any property we did not emit |

## What does not work yet

- **Nothing is published yet.** The release pipeline is written and the package
  is clean, but no tag has been cut and crates.io needs a token (Phase 6).
- **No demo pull request or screenshot.** The Action's behaviour is asserted in
  CI; the persuasive artefact still has to be produced against a real PR.
- **The audit comparison is unwritten** (Phase 6). `docs/BENCHMARKS.md` has the
  false-positive measurements but not the credibility exercise.
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
| 2026-08-12 | WT003 no longer flags raw lamport arithmetic (**reverses a Phase 2 decision**) | Nine examples across the corpus and WT008's safe fixture, none genuine; lamport balances are bounded by the SOL supply and the runtime enforces conservation across a transaction | Keep and document the false positives (the Phase 2 position, overturned by the safe-fixture gate) |
| 2026-08-12 | WT005 skips accounts under `init`, unwritten accounts, and instructions holding two accounts of one type | An account being created has no prior state to check; 116 corpus findings fell to 15 | Report them and document (would have made WT005 the loudest rule by an order of magnitude) |
| 2026-08-12 | WT004 fires only on the program's own `#[account]` state | `init_if_needed` on an associated token account is the idiomatic use and appears in nearly every token program; the inner-type test excludes it exactly | Flag every `init_if_needed` (flags a language feature) |
| 2026-08-12 | WT011 and WT005 read handler bodies, not just constraints | Drift asserts `from_user_key != to_user_key` in the handler for all twelve of its transfer and liquidation instructions | Constraints only (12 false positives on drift alone) |
| 2026-08-17 | ADR-013: `--emit FORMAT=PATH` instead of one scan per consumer | Three scans for annotations, SARIF, and the job summary are three chances to describe different states of the tree | Special-purpose `--sarif-file` and `--summary-file` (two concepts where this is one) |
| 2026-08-17 | ADR-014: annotations are a reporter, not `jq` in the Action | Both failure modes are silent — an unescaped comma truncates the message, a wrongly-rooted path still prints but never reaches the diff. Shell in YAML cannot be tested; the reporter is | `jq` in the composite action (the usual approach, untestable) |
| 2026-08-17 | ADR-015: emit annotations always, upload SARIF on `auto` | An unconditional upload fails the build over a permission a fork's contributor cannot grant, on a run where the analysis worked | Upload unconditionally (breaks fork PRs and private repos); annotations only (loses persistent alerts) |
| 2026-08-17 | ADR-016: the Action's version is the ref you pinned | A `version` input is a second place to record one fact, and the mismatch it produces is invisible in the logs | Docker action (Linux only, second release pipeline); a `version` input; vendoring a binary |

## Known false positives / negatives

### False positives

Twenty on the real corpus, every one listed with a verdict in
`docs/BENCHMARKS.md`. They fall into three groups, all with the same root cause
— the validation exists in a function Wheeltap does not follow:

- **WT005, 15** — permissionless cranks, where a signer named `authority` is the
  caller rather than the account's owner. This is the weakest rule in the suite
  and the honest place to start Phase 4's suppression work.
- **WT011, 4** — liquidator/user pairs distinguished inside a helper.
- **WT003, 1** — arithmetic bounded by a `validate_*` call one line above.

**A Phase 2 decision was reversed here.** Phase 2 kept `lamports` in WT003's
value-word list, documenting six false positives as an acceptable cost for
catching underflowing hand-rolled transfers. Writing WT008's *safe* fixture
produced three more, and the safe corpus is an absolute gate rather than a
statistic. With nine examples and none genuine, the evidence had changed —
lamport balances are bounded by the SOL supply, and the runtime enforces
conservation across a transaction.

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

~~**Q4 — Anchor only for v1.0, or attempt CosmWasm?**~~ **Resolved 2026-08-12,
ADR-007.** Anchor only. Eleven of the twelve rules are questions about Anchor's
account-validation model, which CosmWasm does not have — nothing transfers.

~~**Q5 — Publish to crates.io as `wheeltap`?**~~ **Resolved 2026-08-12,
ADR-008.** Yes; `wheeltap`, `wheeltap-core`, and `wheeltap-cli` are all
unclaimed. Packaging is done and the release workflow publishes in dependency
order; the token is the only thing outstanding.

~~**Q6 — Which audited program for the Phase 6 validation exercise?**~~
**Resolved 2026-08-12, ADR-009.** `drift`, against **two** published audits —
Neodyme and Trail of Bits — both confirmed reachable.

~~**Q7 — Is the GitHub Action in scope for v1.0?**~~ **Resolved 2026-08-12,
ADR-010.** In scope, and built in Phase 5.

### Open, and needing the human

**Q9 — crates.io token.** Publication is the last step of `release.yml` and
needs `CARGO_REGISTRY_TOKEN` as a repository secret. Without it the job prints
a warning and skips rather than failing, so a tag is safe to cut either way.

**Q10 — The demo pull request.** Spec task 5.4 wants a pull request showing the
Action catching a real bug, screenshotted for the README. Opening it is an
outward-facing action on a public repository, so it is waiting on a go-ahead.
The screenshot itself has to be taken by a human.

## Next actions

1. **Phase 6, the credibility exercise.** Run Wheeltap against `drift` and
   compare with the Neodyme and Trail of Bits reports. Document what was caught,
   what was missed and what class of analysis each miss would need, and what was
   flagged that the auditors did not — **including the misses**, which is the
   part that makes the rest believable.
2. Complete `docs/BENCHMARKS.md`: scan time by program size, false-positive rate.
3. README per build spec §9, with the PR annotation screenshot and an asciinema
   recording of a scan.
4. Tag `v1.0.0`. The release workflow builds five platform archives, verifies
   the tag against the manifest, and publishes the crates once a token exists.
5. Final `PROGRESS.md`: every phase done, with the false positives and negatives
   listed rather than quietly dropped.
