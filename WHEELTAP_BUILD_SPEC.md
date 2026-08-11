# Wheeltap — Build Specification

> **Wheeltapper** *(n.)* — a railway inspector who walked the length of a stopped
> train striking each wheel with a long hammer, listening for the dull note that
> betrayed a crack invisible from the outside.

---

## 0. How to use this document

**Read this section first and follow it literally.**

You are an LLM coding agent building this project from an empty repository to a
finished, public, portfolio-grade artifact. This document is your contract.

### Your role

- You are the **implementing engineer**. The human is the reviewer and the
  decision-maker on anything ambiguous.
- Work **phase by phase, in order**. Do not begin Phase N+1 until Phase N's exit
  criteria are met and its tests pass.
- **A detector without a test corpus does not exist.** Every rule ships with
  vulnerable fixtures it must catch and safe fixtures it must not flag.
- When the spec is ambiguous or wrong, **stop and ask**. Record it in
  `PROGRESS.md` under *Open Questions* and surface it.
- This is a **security tool**. A false negative is a missed vulnerability; a false
  positive erodes trust until the tool is switched off. Both are failures. Design
  for both.

### Progress tracking (required)

Create and maintain **`PROGRESS.md`** at the repository root from Phase 0 onward.
Update at the end of every session and at every phase boundary.

```markdown
# Wheeltap — Progress

**Current phase:** 2 — Detector Engine
**Last updated:** YYYY-MM-DD
**Build status:** green | red (reason)

## Phase status
| Phase | Name | Status | Exit criteria met | Notes |
|-------|------|--------|-------------------|-------|

## Detector status
| ID | Name | Severity | Implemented | TP fixtures | FP fixtures | Notes |
|----|------|----------|-------------|-------------|-------------|-------|
| WT001 | Missing signer check | high | yes | 4 | 3 | |

## What works right now
## What does not work yet
## Decisions made
| Date | Decision | Rationale | Alternatives rejected |
## Known false positives / negatives
## Open questions (for the human)
## Next actions
```

**Rules:**
- The **Detector status** table is the heart of this file. A detector is not
  `implemented` until it passes both its true-positive and false-positive
  fixtures.
- Track known false positives openly. A security tool that hides its weaknesses is
  worse than one that documents them.
- Append-only *Decisions made*. Never rewrite history.

### Two other files you must maintain

- **`DECISIONS.md`** — ADRs. Especially: parsing strategy, severity model, output
  schema versioning.
- **`docs/DETECTORS.md`** — the public catalogue. One page per rule: what it
  finds, why it matters, a vulnerable example, a fixed example, known limits.
  This file *is* the project's credibility.

---

## 1. What Wheeltap is

Wheeltap is a **static analysis CLI and CI scanner for Rust-based smart
contracts** — primarily Anchor programs on Solana, with CosmWasm as a stretch
target.

It parses program source into an AST, walks it looking for known Solana-specific
security hazards, and emits structured findings in JSON, Markdown, and SARIF.

### The problem it solves

Solana's programming model puts the burden of account validation on the developer.
The runtime will not stop you from trusting an account that was never verified as
a signer, or that is owned by an attacker's program. The resulting bug classes are
well documented, repeatedly exploited, and — critically — **structurally
detectable in source**. Most teams still catch them only in a paid audit, late
and expensively.

### What it demonstrates (the portfolio purpose)

1. **Deep smart contract security knowledge** — you cannot write these detectors
   without genuinely understanding the vulnerability classes.
2. **Rust language tooling** — AST parsing with `syn`, visitor patterns, semantic
   analysis over untyped syntax.
3. **Security tooling craft** — severity models, confidence levels, suppression,
   SARIF, CI integration.
4. **Judgement about false positives** — which separates a real tool from a
   weekend regex script.

> **Note to the implementing agent:** the author built `Cloud Shield`, a serverless
> AWS CSPM with policy checks, a full finding lifecycle, deterministic finding
> identity, and run-over-run diffing. Wheeltap is that discipline applied to source
> code instead of cloud configuration. Reuse the *reasoning* — especially
> deterministic finding identity and diffing. Do not copy code.

---

## 2. Definition of done

- [ ] `cargo install --path .` produces a working `wheeltap` binary.
- [ ] `wheeltap scan ./programs` analyses a real open-source Anchor program and
      produces findings without crashing.
- [ ] At least **10 detectors** implemented, each with true-positive and
      false-positive fixtures.
- [ ] Output in JSON, Markdown, and valid **SARIF 2.1.0** (validated against the
      schema in CI).
- [ ] A published GitHub Action that annotates pull requests inline.
- [ ] Findings have **stable identities** across runs, enabling `--baseline` diffing.
- [ ] Suppression via inline comments and a config file, both tested.
- [ ] Benchmarked against at least one real audited program, with results compared
      against the published audit findings — documented honestly, including misses.
- [ ] `docs/DETECTORS.md` complete for every rule.
- [ ] CI green: unit, fixture corpus, snapshot, SARIF validation.

**Explicit non-goals.** No formal verification, no symbolic execution, no
full-program dataflow across CPI boundaries, no EVM/Solidity support, no
auto-fixing. Wheeltap is a fast, high-signal, syntax-and-pattern-level linter.
State this plainly — a tool that claims soundness it does not have is worse than
one with honest scope.

---

## 3. Technology choices

| Concern | Choice | Rationale |
|---|---|---|
| Language | **Rust** | Author's target language; the tool analyses Rust and should be written in it |
| Parsing | **`syn`** (full features, with spans) | Stable, well-documented, no nightly requirement |
| Traversal | **`syn::visit`** | Idiomatic visitor pattern |
| CLI | **`clap`** (derive) | Standard |
| Config | **`serde` + TOML** | `wheeltap.toml` |
| Output | **`serde_json`**, custom Markdown, SARIF 2.1.0 | SARIF is what unlocks GitHub code scanning |
| Snapshot tests | **`insta`** | Ideal for asserting on finding output |
| Fixtures | Real Anchor code, in-repo | The corpus is the product |
| CI | **GitHub Actions** | Also the delivery vehicle for the Action |

### A decision you must make deliberately (ADR-001)

**Do not attempt rustc internals, MIR, or HIR.** It requires nightly, the APIs are
unstable, and it will consume the entire project budget. Use `syn` for AST-level
analysis, and be explicit in the README that Wheeltap is a syntactic and
pattern-level analyser, not a dataflow engine.

Where a detector genuinely needs light dataflow (e.g. "is this account validated
anywhere in this function before use?"), implement a **scoped, intraprocedural**
approximation and mark those findings with `confidence: medium`. Never claim
soundness you do not have.

---

## 4. Architecture

### 4.1 Pipeline

```
  source files
       │
       ▼
  ┌─────────┐   discover .rs, respect .gitignore, detect Anchor
  │ Loader  │
  └────┬────┘
       ▼
  ┌─────────┐   syn::parse_file → AST + spans
  │ Parser  │   recover from unparseable files, do not abort the run
  └────┬────┘
       ▼
  ┌─────────┐   Anchor-aware model: programs, instruction handlers,
  │ Context │   #[derive(Accounts)] structs, constraints, account types
  └────┬────┘
       ▼
  ┌─────────┐   each detector = trait impl, run over the context
  │ Engine  │   parallel across files (rayon)
  └────┬────┘
       ▼
  ┌─────────┐   dedupe, stable IDs, apply suppressions, severity filter
  │ Findings│
  └────┬────┘
       ▼
  ┌─────────┐   JSON | Markdown | SARIF
  │Reporters│
  └─────────┘
```

### 4.2 Core types

```rust
pub struct Finding {
    pub id: FindingId,          // deterministic — see §4.3
    pub rule: &'static str,     // "WT001"
    pub severity: Severity,     // Critical | High | Medium | Low | Info
    pub confidence: Confidence, // High | Medium | Low
    pub message: String,        // what is wrong, specifically
    pub location: Location,     // file, line, column, span
    pub snippet: String,        // the offending lines
    pub remediation: String,    // what to do instead, with code
    pub references: Vec<String>,
}

pub trait Detector: Send + Sync {
    fn rule_id(&self) -> &'static str;
    fn metadata(&self) -> RuleMetadata;
    fn check(&self, ctx: &ProgramContext) -> Vec<Finding>;
}
```

### 4.3 Deterministic finding identity (critical)

Line numbers move when unrelated code is edited. If finding identity depends on
line numbers, every diff is noise and `--baseline` is useless.

Identity must be:

```
id = hash(rule_id || relative_path || enclosing_item_path || normalised_snippet)
```

where `enclosing_item_path` is e.g. `my_program::initialize::Accounts.authority`,
and `normalised_snippet` has whitespace collapsed and comments stripped. A finding
keeps its identity when code moves within a file; it changes when the offending
code itself changes.

This mirrors the run-over-run diffing in Cloud Shield and is the single most
sophisticated idea in the project. **Give it its own section in the README.**

### 4.4 Suppression

Two mechanisms, both required:

```rust
// wheeltap:allow(WT001) -- authority is validated in the CPI callee
pub authority: AccountInfo<'info>,
```

```toml
# wheeltap.toml
[suppress]
rules = ["WT007"]
paths = ["programs/legacy/**"]

[severity]
WT003 = "medium"   # downgrade for this project
```

Requiring a justification comment after `--` is good practice; enforce it with a
warning when absent.

### 4.5 Repository layout

```
wheeltap/
├── README.md
├── PROGRESS.md
├── DECISIONS.md
├── docs/
│   ├── DETECTORS.md
│   └── BENCHMARKS.md
├── crates/
│   ├── wheeltap-core/       # types, context model, engine
│   ├── wheeltap-rules/      # one module per detector
│   ├── wheeltap-report/     # JSON, Markdown, SARIF
│   └── wheeltap-cli/        # binary
├── fixtures/
│   ├── vulnerable/          # must be flagged
│   │   └── WT001_missing_signer/
│   └── safe/                # must NOT be flagged
├── action/                  # GitHub Action
├── tests/
└── .github/workflows/
```

---

## 5. The detectors

Implement in this order. Ordering is by *ratio of security value to
implementation difficulty* — the early ones are both important and tractable.

| ID | Name | Severity | Difficulty | Notes |
|---|---|---|---|---|
| WT001 | Missing signer check | Critical | Low | `AccountInfo` used as authority without `Signer` type or `is_signer` assertion |
| WT002 | Missing owner check | Critical | Low | Account deserialised without verifying `owner` is the expected program |
| WT003 | Unchecked arithmetic | High | Low | `+ - *` on balances/amounts without `checked_*`; respect `overflow-checks` in Cargo.toml |
| WT004 | Account reinitialisation | High | Medium | `init` path reachable on an already-initialised account; missing `init_if_needed` guard rails |
| WT005 | Missing `has_one` / constraint | High | Medium | Relationship between accounts asserted in comments but not in constraints |
| WT006 | Non-canonical PDA bump | High | Medium | Bump taken from user input rather than `bump` / `find_program_address` |
| WT007 | Arbitrary CPI target | Critical | Medium | Program ID for a CPI comes from an unvalidated account |
| WT008 | Missing rent-exemption / close handling | Medium | Medium | Closing without zeroing or reload; revival attacks |
| WT009 | Sysvar spoofing | High | Low | Sysvar passed as `AccountInfo` without address check |
| WT010 | Unsafe `AccountInfo` deserialisation | High | Medium | Raw `try_from_slice` on unvalidated data |
| WT011 | Duplicate mutable accounts | Medium | Medium | Two mutable account params can alias the same address |
| WT012 | Inefficient allocation in loop | Low | Low | Resource/gas hygiene; `clone()` of vectors inside loops |

**Ten is the minimum for done. Twelve is better. Quality beats count** — three
excellent detectors with clean fixture corpora beat twelve noisy ones.

### The rule for every detector

Before writing the implementation:

1. Write the vulnerable fixture. Make it realistic — it should look like code
   someone would actually ship.
2. Write at least two safe fixtures that a naive implementation would
   false-positive on. **This is the important step.**
3. Write the `docs/DETECTORS.md` entry.
4. *Then* implement.

Test-first is not a style preference here. For a security tool the fixture corpus
is the specification.

---

## 6. Phases

### Phase 0 — Foundations

**Goal.** A workspace that builds, tests, and lints on CI.

**Tasks.**
1. Cargo workspace per §4.5.
2. CI: build, `clippy -D warnings`, `fmt --check`, test.
3. `PROGRESS.md`, `DECISIONS.md`, skeleton `README.md`.
4. ADR-001: `syn`-only, no rustc internals. Record the reasoning from §3.
5. Vendor two or three real open-source Anchor programs into `fixtures/corpus/`
   as end-to-end scan targets. Check their licences and attribute.

**Exit criteria.** CI green on fresh clone.

---

### Phase 1 — Loader, parser, and program context

**Goal.** Turn a directory of Anchor source into a queryable semantic model. No
detectors yet.

**Tasks.**
1. File discovery: walk directories, respect `.gitignore`, skip `target/`.
2. `syn::parse_file` with spans preserved. **A file that fails to parse must
   produce a warning and let the run continue** — never abort the whole scan.
3. Build `ProgramContext`:
   - `#[program]` modules and their instruction handlers,
   - `#[derive(Accounts)]` structs, fields, and Anchor types
     (`Signer`, `Account<T>`, `AccountInfo`, `UncheckedAccount`, `Program`, `Sysvar`),
   - `#[account(...)]` attribute constraints, parsed into structured form
     (`mut`, `init`, `seeds`, `bump`, `has_one`, `constraint`, `close`, `owner`),
   - the mapping from handler → its Accounts struct.
4. Source-map utility: span → file, line, column, snippet.

**Tests.**
- Unit: parse each Anchor account type correctly.
- Unit: parse each constraint form, including nested and multi-line attributes.
- Unit: a syntactically invalid file yields a warning, not a panic.
- Integration: build a context from each vendored corpus program; assert expected
  handler and struct counts.
- Snapshot: serialise the context for one fixture and snapshot it.

**Exit criteria.** `wheeltap debug-context ./fixtures/corpus/<program>` prints an
accurate model of a real program.

> This phase is unglamorous and is where the project succeeds or fails. A weak
> context model makes every downstream detector a pile of special cases. Do not
> rush it.

---

### Phase 2 — Detector engine and the first three rules

**Goal.** Prove the whole pipeline end to end on a small rule set.

**Tasks.**
1. `Detector` trait, registry, parallel execution with `rayon`.
2. Finding construction with deterministic IDs per §4.3.
3. Implement **WT001** (missing signer), **WT002** (missing owner), **WT003**
   (unchecked arithmetic) — fixtures first.
4. Basic JSON reporter.
5. `wheeltap scan <path>` with exit codes: `0` clean, `1` findings at or above
   threshold, `2` internal error.

**Tests.**
- Fixture corpus: every vulnerable fixture is flagged by its rule.
- Fixture corpus: **no safe fixture is flagged by any rule.** Enforced globally,
  not per-rule — this catches cross-detector false positives.
- Unit: finding IDs are stable when code moves within a file; change when the
  code changes.
- Snapshot: full JSON output for a fixed input.

**Exit criteria.** `wheeltap scan fixtures/vulnerable` catches everything;
`wheeltap scan fixtures/safe` reports nothing.

---

### Phase 3 — Full detector suite

**Goal.** Reach 10–12 detectors without accumulating false positives.

**Tasks.**
1. Implement WT004 through WT012, fixtures first, in the order given.
2. For each, add the `docs/DETECTORS.md` entry at implementation time — not later.
3. After every third detector, re-run the whole corpus and check that the safe
   fixtures are still clean. Regressions here are the main failure mode.
4. Add `confidence` scoring; mark approximated dataflow rules `medium`.
5. Update the *Detector status* table in `PROGRESS.md` continuously.

**Tests.**
- TP and FP fixtures per detector.
- Global no-false-positive assertion across the entire safe corpus.
- Integration: scan of each vendored real program completes; findings triaged by
  hand once and recorded as an expected-output snapshot.

**Exit criteria.** Ten or more detectors, all fixtures green, and a hand-triaged
run against real code documented in `docs/BENCHMARKS.md`.

---

### Phase 4 — Reporting, suppression, and baselines

**Goal.** Make the output usable by teams, not just by its author.

**Tasks.**
1. Markdown reporter: grouped by severity, with snippets and remediation.
2. **SARIF 2.1.0** reporter: rules metadata, results, locations, fingerprints
   (use the deterministic ID as `partialFingerprints`). Validate against the
   official schema in CI.
3. Inline suppression comments and `wheeltap.toml` config per §4.4.
4. `--baseline findings.json`: report only findings not present in the baseline.
   This is Cloud Shield's diffing, ported.
5. `--severity-threshold`, `--format`, `--fail-on`.

**Tests.**
- SARIF output validates against the schema.
- Suppression: inline and config-based, both honoured; unsuppressed findings still
  reported.
- Baseline: unchanged code yields zero new findings; a new vulnerability appears;
  a moved-but-unchanged finding does **not** appear.
- Snapshot tests for all three formats.

**Exit criteria.** SARIF uploads to GitHub code scanning and annotates a PR.

---

### Phase 5 — GitHub Action and distribution

**Goal.** Make it one line to adopt.

**Tasks.**
1. Composite or Docker-based Action in `action/`.
2. Inputs: `path`, `severity-threshold`, `fail-on`, `baseline`, `format`.
3. Uploads SARIF; annotates changed lines on pull requests.
4. A demo repository (or a branch) showing the Action catching a real bug in a PR.
   **Screenshot this for the README** — it is the most persuasive single image the
   project can have.
5. Publish to crates.io. Document `cargo install wheeltap`.
6. Cache compiled binaries in the Action for speed.

**Tests.**
- The Action runs against `fixtures/vulnerable` in CI and fails the build.
- The Action runs against `fixtures/safe` and passes.
- Annotation position is correct on a PR.

**Exit criteria.** A third party can add five lines to a workflow and get findings
on their next PR.

---

### Phase 6 — Validation, documentation, release

**Goal.** Prove it finds real bugs, and say honestly what it misses.

**Tasks.**
1. **The credibility exercise:** pick a Solana program with a *published* audit
   report. Run Wheeltap. Compare findings against the audit. Document:
   - which real issues Wheeltap caught,
   - which it missed and why (be specific about the class of analysis needed),
   - what it flagged that the auditors did not, and whether those are valid.
   This section will do more for the author's credibility than any other part of
   the project. **Do not omit the misses.**
2. `docs/BENCHMARKS.md`: scan time on programs of varying size, false-positive
   rate on the corpus.
3. Complete `docs/DETECTORS.md`.
4. README per §9.
5. Demo: asciinema of a scan, plus the PR annotation screenshot.
6. Tag `v1.0.0`; publish to crates.io; publish the Action.
7. Final `PROGRESS.md`: all phases done, known false positives and negatives
   listed.

**Exit criteria.** The audit comparison is written and honest. A reviewer can see
both what the tool catches and where its limits are.

---

## 7. Testing strategy

| Level | Scope | Tooling | Gate |
|---|---|---|---|
| Unit | Context parsing, constraint parsing, ID generation | `cargo test` | Phase 1 |
| Fixture (TP) | Each detector catches its vulnerable cases | corpus harness | Phase 2+ |
| Fixture (FP) | No detector flags any safe fixture | global harness | Phase 2+ |
| Snapshot | Output stability across all formats | `insta` | Phase 2+ |
| Schema | SARIF validity | schema validator in CI | Phase 4 |
| Integration | Real programs scan without panic | corpus | Phase 1+ |
| Regression | Baseline diffing correctness | harness | Phase 4 |
| Robustness | Malformed, huge, and adversarial inputs | fuzz-lite | Phase 3+ |

**Invariants:**

1. The tool never panics on any input. Parse failures degrade to warnings.
2. No safe fixture is ever flagged.
3. Finding IDs are stable under code movement, unstable under code change.
4. Two runs over identical input produce byte-identical JSON output
   (deterministic ordering — sort findings before emitting).
5. Scan time is linear in source size.

**Robustness inputs to test explicitly:** empty files, files with only comments,
deeply nested generics, macro-heavy code, non-UTF8 bytes, 50k-line files,
symlink loops.

---

## 8. Session protocol for the implementing agent

At the **start** of every session:
1. Read `PROGRESS.md` and `DECISIONS.md` fully.
2. Run `cargo test`. If red, fix first.
3. State the current phase and the session's intent.

At the **end** of every session:
1. Build green, or record precisely why not.
2. Update `PROGRESS.md`, including the *Detector status* table.
3. Commit with a message naming the change and the phase.

**Never** mark a detector implemented without both fixture sets passing.
**Never** suppress a false positive by weakening a fixture — fix the detector.

---

## 9. README requirements

1. **One sentence** on what Wheeltap is.
2. **The problem** — why Solana's account model makes these bugs easy to write,
   with one concrete example of a real exploit class.
3. **A vulnerable code sample and the tool's output**, side by side, above the
   fold. This is the single most persuasive element; put it early.
4. **Quickstart** — install and first scan in one block.
5. **GitHub Action** — the five-line workflow snippet, and the PR screenshot.
6. **Detector catalogue** — the table, linking to `docs/DETECTORS.md`.
7. **Deterministic finding identity and baselines** — explain the mechanism.
8. **Validation against a published audit** — the honest comparison from Phase 6.
9. **Limitations** — syntactic analysis, no dataflow across CPI, no formal
   guarantees, known false positives.
10. **Contributing** — how to add a detector, since the fixture-first workflow is
    itself a signal of engineering maturity.

No marketing language. No claims of completeness. The reader is a security
engineer deciding whether the author knows what they are talking about.

---

## 10. Open questions for the human (resolve before Phase 3)

1. Anchor-only for v1.0, or attempt CosmWasm? (Recommendation: Anchor only —
   depth beats breadth.)
2. Publish to crates.io under `wheeltap`, or a namespaced alternative if taken?
3. Which audited program to use for the Phase 6 validation exercise?
4. Is the GitHub Action in scope for v1.0, or deferred? (Recommendation: in
   scope — it is a large share of the project's perceived value.)

Record answers in `DECISIONS.md` before proceeding.
