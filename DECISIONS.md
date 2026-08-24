# Wheeltap — Architecture Decision Records

Append-only. Superseded decisions are marked, never deleted.

---

## ADR-001 — Parse with `syn`; no rustc internals

**Date:** 2026-08-11
**Status:** Accepted

### Context

Wheeltap needs a program model rich enough to reason about Anchor account
structs, constraints, and instruction handlers. There are three levels of
fidelity available:

1. **`syn`** — the AST as written, on stable Rust.
2. **rustc HIR/MIR** via `rustc_private` — name resolution, types, and real
   dataflow, but requires nightly, with APIs that change without notice.
3. **rust-analyzer as a library** — semantic analysis on stable, but a very
   large dependency with no stability guarantees either.

### Decision

Use `syn` with full features and spans. Do not use rustc internals.

### Rationale

- Nightly-only APIs would make the tool unbuildable on stable, which kills
  adoption via `cargo install` and complicates the GitHub Action.
- `rustc_private` breaks on roughly every toolchain bump. The maintenance cost
  would consume the project.
- The vulnerability classes Wheeltap targets are, in the main, **structurally
  visible in the AST**: a `AccountInfo` where a `Signer` belongs, a missing
  `has_one`, arithmetic that is not `checked_*`. Type inference buys less here
  than it would for a general-purpose linter.

### Consequences

- Wheeltap is a **syntactic and pattern-level analyser, not a dataflow engine**,
  and the README says so plainly.
- Detectors needing light dataflow ("is this account validated anywhere in this
  function before use?") get a **scoped, intraprocedural approximation** and
  their findings are marked `confidence: medium`.
- We cannot resolve type aliases, follow values across function boundaries, or
  see through macro expansion beyond what `syn` parses. Each affected detector
  documents this limit in `docs/DETECTORS.md`.

### Alternatives rejected

- **rustc HIR/MIR** — nightly requirement and API churn (see above).
- **Regex/grep over source** — no structure, unacceptable false-positive rate,
  and it would not demonstrate the tooling skill this project exists to show.

---

## ADR-002 — The root package is the installable binary

**Date:** 2026-08-11
**Status:** Accepted

### Context

The build spec's definition of done requires `cargo install --path .` to produce
a `wheeltap` binary, and Phase 5 requires `cargo install wheeltap` from
crates.io. The spec's repository layout (§4.5) puts every crate under `crates/`,
which makes the repository root a **virtual manifest**. `cargo install --path .`
fails against a virtual manifest, and `cargo install wheeltap` requires a
published crate actually named `wheeltap`.

### Decision

The repository root is a real package named `wheeltap` containing only
`src/main.rs`, a three-line delegation to `wheeltap_cli::run()`. The workspace
libraries stay under `crates/` exactly as §4.5 specifies.

### Rationale

This is the layout `ripgrep` uses, for the same reason. It satisfies both
installation requirements literally without distorting the crate structure, at a
cost of one file.

### Consequences

- Five crates are published to crates.io rather than four. Only `wheeltap` is
  the user-facing name.
- The binary name is `wheeltap` regardless of which path is installed.

### Alternatives rejected

- **Keep §4.5 verbatim** and document the install command as
  `cargo install --path crates/wheeltap-cli`. Rejected: it contradicts the
  stated definition of done, and `cargo install wheeltap` would still fail.
- **Move the whole CLI to the root package.** Rejected: it dissolves the
  `wheeltap-cli` crate the layout calls for.

---

## ADR-003 — `syn` 3.x, Rust edition 2024, MSRV 1.88

**Date:** 2026-08-11
**Status:** Accepted

### Context

The build spec was written against `syn` 2.x. `syn` 3.0 has since been released:
it updates the syntax tree for three years of Rust language development and
anticipates in-flight RFCs. The `visit` module, span handling, and parsing API
that Wheeltap depends on are unchanged in shape.

### Decision

Depend on `syn` 3.x. Use Rust edition 2024 with an MSRV of **1.88**, enforced by
a dedicated CI job.

> **Amended 2026-08-11.** This ADR originally claimed an MSRV of 1.85, reasoning
> only about the edition. That was wrong: `ignore` 0.4.30 uses let-chains, which
> stabilised in 1.88, so the workspace does not build on 1.85 at all. The floor
> was measured by building on successive toolchains rather than inferred. The
> edition rationale below stands; the number does not come from it.

### Rationale

- A new security tool built on a superseded major version of its central
  dependency invites the obvious question at review time.
- `syn` 3 parses newer syntax that real programs will increasingly contain;
  on 2.x those files would fail to parse and silently reduce coverage.
- Edition 2024 has been stable since Rust 1.85 (February 2025). The effective
  floor is 1.88 (June 2025), set by a dependency rather than by our own code —
  still comfortably older than any toolchain a contributor is likely to run.

### Consequences

- Anything in the build spec that assumes `syn` 2.x API details is read as
  intent, not as literal API.
- The MSRV is a published promise; the `msrv` CI job removes `rust-toolchain.toml`
  before building, or the pin would silently defeat the check. It is measured,
  not assumed, and it is re-measured whenever a dependency is added or bumped.

### Alternatives rejected

- **Pin `syn` 2.x** for API familiarity. Rejected: accepts a known-ageing
  dependency to save a small amount of adaptation work.

---

## ADR-004 — Location and content addressing for source spans

**Date:** 2026-08-11
**Status:** Accepted

### Context

Findings must report a file, line, and column, and finding identity must survive
code movement (build spec §4.3).

### Decision

Use `proc-macro2`'s `span-locations` feature for line and column. Report columns
1-indexed. Keep positional data strictly out of the finding identity hash.

### Rationale

`span-locations` reports true positions only outside a procedural macro context.
Wheeltap is a CLI that parses files from disk, so the caveat does not apply. The
alternative — recomputing offsets from the raw source — duplicates work `syn`
has already done.

### Consequences

- Line and column are presentation, never identity. ADR for the identity scheme
  itself will be written in Phase 2 when it is implemented.

---

## ADR-005 — No `rayon`: the AST is not `Send`, and single-threaded is fast enough

**Date:** 2026-08-12
**Status:** Accepted

### Context

The build spec's architecture calls for detectors to run "parallel across files
(rayon)". Implementing the context model surfaced two facts that bear on this.

**First, `syn` ASTs cannot cross threads.** `proc-macro2` uses `Rc` in its
fallback token representation, so `syn::File` is neither `Send` nor `Sync`. This
is not fixable by feature flags: disabling the `proc-macro` feature removes
`proc_macro::Span` but leaves `Rc<Vec<TokenTree>>` behind. Any design that
shares a `ProgramContext` across rayon threads is therefore not merely
inadvisable but impossible to compile.

**Second, it does not matter.** Measured on this machine, release build:

| Program | Lines | Time | Throughput |
|---|---|---|---|
| `escrow` | 313 | <0.01 s | — |
| `anchor-misc` | 3,057 | 0.02 s | ~153,000 lines/s |
| `drift` | 73,011 | 0.36 s | ~203,000 lines/s |

A production DeFi protocol models in under half a second, single-threaded.

### Decision

Do not use `rayon`. Run loading, parsing, and detection on one thread. Drop the
dependency rather than keep it unused.

Analysis does run on a **dedicated thread with a 16 MiB stack**, for a different
reason: `syn` is recursive-descent, and the stack a caller provides varies —
a Rust test-harness thread gets 2 MiB where the main thread gets 8 MiB. Source
that analysed fine from the CLI aborted the process under `cargo test`. Behaviour
that depends on the caller's stack is not acceptable in a linter.

### Rationale

Parallelism here would buy at most a few hundred milliseconds on the largest
real program in the corpus, in exchange for an architecture that cannot hold
`syn` nodes in shared state — which means either re-parsing every file twice or
discarding the AST that body-level detectors need.

Optimising before measuring would have cost the analysis power the detectors
depend on, to save a third of a second.

### Consequences

- `ProgramContext` is free to retain `syn::ItemFn` and `syn::ItemStruct` whole,
  which is what makes Phase 3's arithmetic and CPI detectors possible at all.
- Scan time is linear in source size and stays well inside a CI budget.
- If a future program is large enough to need parallelism, the shape is known:
  fan out per file, since the AST never has to leave the thread that made it,
  and share only an owned cross-file index. Recorded here so the option is not
  rediscovered from scratch.
- Stack depth is bounded twice over: a 16 MiB analysis stack, and a cheap
  textual nesting check that refuses pathological files with a warning. A stack
  overflow aborts the process and cannot be caught, so it is the one failure
  mode that has to be prevented rather than handled.

### Alternatives rejected

- **Two-pass parallelism** — parse in parallel to build an owned index, then
  re-parse in parallel to run detectors. Doubles parse cost to parallelise a
  0.36-second workload.
- **Discard `syn` nodes after building an owned model** — makes the context
  `Send`, but blinds every detector that needs to look inside a handler body.

---

## ADR-006 — Handlers are recognised wherever they are declared

**Date:** 2026-08-12
**Status:** Accepted

### Context

The obvious reading of Anchor is that instruction handlers are the functions
inside the `#[program]` module. Modelling only those, and running the result
against the corpus, gave a clear answer: **drift reported zero handlers**.

Two things were true. Drift's vendored commit has its entire dispatch module
commented out — 245 commented handlers against one live function. And, more
importantly, drift's real logic lives in 287 `handle_*` functions under
`src/instructions/`, which the `#[program]` module only delegates to. Escrow is
the same shape at small scale: two entrypoints, four delegated functions.

This is the normal way non-trivial Anchor programs are organised.

### Decision

Model **any function whose first parameter is a `Context<T>`** as a handler,
wherever it is declared, recording whether it sits inside a `#[program]` module.
Handlers with a program are entrypoints; the rest are delegated.

`&Context<T>` counts too — escrow borrows its context in one helper.

### Rationale

The `Context<T>` parameter, not the enclosing module, is what makes a function
operate on an instruction's accounts. Detectors that read handler bodies —
unchecked arithmetic, arbitrary CPI — need the function that contains the
arithmetic and the CPI, which is the delegated one.

Modelling only entrypoints would have made those detectors analyse delegation
stubs and report nothing, on the single largest program in the corpus.

### Consequences

- Corpus coverage went from 2 handlers to 262 on drift.
- A handler's identity includes its file, so two `handle_x` functions in
  different modules are distinct.
- Some non-instruction helpers that happen to take a `Context` are modelled as
  handlers. This is the right trade: a false handler costs a detector one
  harmless pass, while a missed handler costs coverage silently.

---

## ADR-007 — Anchor only for v1.0; CosmWasm is not a stretch target

**Date:** 2026-08-12
**Status:** Accepted
**Answers:** build spec §10, question 1

### Context

The build spec offered CosmWasm as a stretch target. Three phases of
implementation give a clearer view of what that would cost than the spec could
have had when it was written.

### Decision

Anchor only. CosmWasm is not deferred, it is out of scope.

### Rationale

**Nothing transfers.** The value of this project is concentrated in
`ProgramContext`, and every part of it is Anchor-shaped: `#[derive(Accounts)]`
structs, the `#[account(...)]` constraint grammar, `Signer`/`Account`/
`AccountInfo` and what each does or does not validate, PDAs and bumps. CosmWasm
has no account model at all — it has entry points, `deps.storage`, and a message
enum. Not one of the twelve detectors survives the translation, because eleven of
them are questions about account validation and the twelfth is about compute
budget.

**The work is precision, not coverage.** Phase 3 spent far more effort tuning
false positives than writing rules. WT005 went from 116 findings on drift to 15
through four separate refinements, none of which were about the *rule* — they
were about how real Anchor code is written. A second ecosystem means a second
corpus, a second fixture set, and that whole exercise repeated with no
transferable intuition.

**Twenty known false positives argue against breadth.** The catalogue is
complete; the precision is 43% on production code. Improving that is worth more
than a shallow second target.

### Consequences

- The README says "Anchor" and does not imply a roadmap towards other ecosystems.
- The crate description and crates.io keywords say Solana and Anchor.

---

## ADR-008 — Publish as `wheeltap` on crates.io

**Date:** 2026-08-12
**Status:** Accepted
**Answers:** build spec §10, question 2

### Context

The name had to be checked rather than assumed.

### Decision

Publish as `wheeltap`. Checked 2026-08-12: `wheeltap`, `wheeltap-core`, and
`wheeltap-cli` are all unclaimed.

The root package is already named `wheeltap` (ADR-002), so `cargo install
wheeltap` and `cargo install --path .` both resolve to the binary with no
further work.

### Consequences

- Five crates are published. Only `wheeltap` is the user-facing name; the other
  four are implementation and are documented as such.
- Worth reserving before the project is public, since the name is the one thing
  that cannot be changed later without breaking every install line ever written.

---

## ADR-009 — Drift is the Phase 6 validation target

**Date:** 2026-08-12
**Status:** Accepted
**Answers:** build spec §10, question 3

### Context

Phase 6 requires comparing Wheeltap's findings against a *published* third-party
audit of a real program, and documenting the misses. The candidate has to satisfy
four things at once: a public audit report that can actually be obtained, a
permissive licence, enough size for the comparison to mean something, and code we
can model accurately.

### Decision

Drift (`velocity-exchange/protocol-v2`, vendored at `13e8e9b`), against its two
published audits:

- Neodyme, `drift-labs/audits/protocol-v2/neodyme.pdf` — verified reachable,
  1.26 MB
- Trail of Bits, `drift-labs/audits/protocol-v2/tob.pdf` — verified reachable,
  1.69 MB

**Two** independent audits by reputable firms is better than one: where they
disagree about what mattered, that disagreement is itself worth reporting.

### Rationale

- **Already vendored and already understood.** Three phases of false-positive
  triage were done against this program. Its idioms — zero-copy loaders, helper
  functions in constraints, permissionless cranks — are known, which means the
  audit comparison can be about the *analysis* rather than about learning the
  codebase.
- **Modelled completely**: 262 handlers, 155 Accounts structs, 855 fields, zero
  parse failures.
- **Apache-2.0**, so it can stay in the repository.
- **73,000 lines** of production DeFi, audited because real money depends on it.

### The objection, and why it does not carry

The vendored commit has drift's entire `#[program]` dispatch module commented
out — 245 of 246 handlers. That looked disqualifying at first.

It is not, because the dispatchers are delegation stubs. The logic the auditors
reviewed lives in the 287 `handle_*` functions under `src/instructions/`, and
those are present and modelled (ADR-006 exists because of this). What is lost is
the mapping from an instruction *name* to its handler, which matters for
presentation and not for analysis.

### Consequences

- Phase 6 must read both PDFs and map findings by hand. Budget for that.
- The comparison will be dominated by what Wheeltap **misses**, since the audits
  found economic and protocol-level issues that no syntactic analyser reaches.
  That is the honest and interesting result, and the build spec is explicit that
  the misses must not be omitted.

### Alternatives rejected

- **Squads v4** — AGPL-3.0. Copyleft makes vendoring a licensing question the
  project does not need.
- **Marinade** — licence is `NOASSERTION`; unclear terms.
- **A program audited but not vendored** — the comparison would not be
  reproducible from a fresh clone.

---

## ADR-010 — The GitHub Action is in scope for v1.0

**Date:** 2026-08-12
**Status:** Accepted
**Answers:** build spec §10, question 4

### Context

Whether Phase 5 ships with v1.0 or is deferred.

### Decision

In scope.

### Rationale

- **Adoption is the whole point.** A linter nobody runs finds nothing. Five
  lines of workflow is the difference between a tool people read about and one
  they use.
- **It is nearly free now.** SARIF output lands in Phase 4 for other reasons,
  and SARIF is exactly what GitHub code scanning consumes. The Action is
  packaging on top of work already required.
- **Speed is not a barrier.** 0.36 seconds for 73,000 lines (ADR-005) means the
  Action costs less than the checkout that precedes it.
- **It is the most persuasive artefact the project has.** A screenshot of a real
  finding annotated inline on a pull request says more than the README.

### Consequences

- Phase 5 stays in the v1.0 plan.
- The deterministic finding identity feeds SARIF `partialFingerprints`, so
  GitHub can track a finding across pushes rather than reporting it as new each
  time — which is the same property `--baseline` needs, from the same source.

---

## ADR-011 — Output schema versioning

**Date:** 2026-08-12
**Status:** Accepted

### Context

Three outputs now leave the tool, and other software reads all of them: JSON is
parsed by scripts and read back as a baseline, SARIF is consumed by GitHub, and
Markdown is read by people. Each needs a different promise.

### Decision

**JSON carries `"schema": "1.0"`.** The version is bumped on any breaking change
to the shape, and the change is recorded here. Additive fields are not breaking.

**SARIF is pinned to 2.1.0** and validated against the official schema —
vendored at `schemas/sarif-2.1.0.json` — in `cargo test`, not only in CI. A
consumer's rejection message names a schema path, not the mistake, so this
catches it at the right moment.

**SARIF fingerprints are versioned separately** as `wheeltapFindingId/v1`. If
the identity scheme ever changes, it becomes a new fingerprint key rather than
the same key with different values.

**Markdown has no compatibility promise.** It is for humans, and constraining it
would only prevent it from getting better.

### Rationale

The baseline mechanism reads JSON back, so the JSON shape is not merely output —
it is an input to a future run. A consumer that pins the version can be told
that something changed, rather than finding out when a baseline silently matches
nothing and every finding reports as new.

Versioning the fingerprint key separately matters for the same reason in
GitHub's UI: an unversioned key whose values changed would close every alert and
open an identical set, which is the exact noise `partialFingerprints` exists to
prevent.

### Consequences

- The baseline reader is deliberately minimal — it reads identities and ignores
  everything else — so a baseline written by an older or newer version still
  loads. Tested.
- A breaking JSON change requires a version bump, an entry here, and a note in
  the README.

---

## ADR-012 — Suppression is honoured without a justification, and warned about

**Date:** 2026-08-12
**Status:** Accepted

### Context

The build spec suggests requiring a justification after `--` on inline
suppressions, "enforced with a warning when absent". The stronger option is to
refuse an unjustified suppression outright.

### Decision

Honour it, and emit a warning naming the file and line.

### Rationale

The purpose of a justification is to tell the *next* reader why this finding was
dismissed, which is genuinely valuable — an unexplained suppression is a finding
that was hidden rather than answered.

But refusing to honour it does not produce a justification. It produces a
developer who deletes the finding some other way: weakening the constraint,
removing the rule from `wheeltap.toml`, or dropping the scan step. Every one of
those is worse than a suppression with a missing sentence, because every one of
them is invisible.

A warning is read by the same people who would have written the reason, at the
same moment, and costs nothing when ignored.

### Consequences

- `wheeltap.toml` rule and path suppressions are not warned about: they are
  deliberate, reviewed configuration, and the file itself is the place for the
  comment.
- The warning appears as a diagnostic, so it is in JSON and SARIF output too,
  not only on the terminal.

---

## ADR-013 — One scan renders every format: `--emit FORMAT=PATH`

**Date:** 2026-08-17
**Status:** Accepted

### Context

A CI run wants three views of the same scan at once: workflow-command
annotations in the log, SARIF on disk for code scanning to ingest, and Markdown
for the job summary. `--format` writes one thing to stdout.

The obvious workaround is to run the scanner once per consumer, which the Action
would have done three times per job.

### Decision

Add `--emit FORMAT=PATH`, repeatable, writing an additional report to a file for
each occurrence. `--format` continues to control stdout.

```console
$ wheeltap scan programs --format github \
    --emit sarif=wheeltap.sarif --emit markdown=summary.md
```

### Rationale

Three scans of the same tree is three times the work for the same answer, but
the cost is not the real objection — analysis is under a second on 73,000 lines.
The objection is that three scans are three *chances to disagree*. If a file
changes between them, the annotations, the alerts, and the summary describe
different states of the repository, and nothing in the output says so.

One scan, many renderings, makes that class of inconsistency impossible rather
than unlikely.

The alternative considered was a pair of special-purpose flags, `--sarif-file`
and `--summary-file`. Those are two concepts where this is one, and a third
consumer would have wanted a third flag.

### Consequences

- Files are written before stdout. A `wheeltap ... | head` closing the pipe must
  not be able to skip an artefact a later CI step depends on.
- Parent directories are created, so `--emit sarif=reports/out.sarif` works on a
  fresh checkout without a preceding `mkdir`.
- The split is on the *first* `=`, so paths may contain `=` and `:` — which
  Windows paths do.

---

## ADR-014 — Annotations are a reporter, not shell in the Action

**Date:** 2026-08-17
**Status:** Accepted

### Context

Inline pull-request annotations are GitHub workflow commands:

```
::error file=src/lib.rs,line=37,col=9,title=WT001 critical::message
```

The Action could produce these by piping JSON through `jq`, which is the usual
approach and needs no changes to the tool.

### Decision

Add `github` as a first-class output format in `wheeltap-report`, alongside
JSON, Markdown, and SARIF.

### Rationale

The format has two hazards that shell handles badly.

**Escaping.** Commands are line-oriented and delimited by `,` and `::`. Rust
source is full of both. An unescaped comma in a message does not fail — it
invents a property GitHub ignores, truncating the message at the comma. A
literal newline ends the command entirely. In `jq` this is a fragile
`gsub` chain; in Rust it is a function with tests that assert `%` is escaped
before the characters that use it as their prefix.

**Path resolution.** GitHub matches an annotation to a diff line by
repository-relative path. A finding's path is relative to the *scanned* root, so
scanning `programs/` yields `vault/src/lib.rs` where the repository knows
`programs/vault/src/lib.rs`. Getting this wrong is silent: the annotation still
prints in the log, it just stops appearing on the diff. Nothing fails, and the
feature looks like it works.

Silent failure is the argument. Shell in a YAML file cannot be tested;
`tests/reporting.rs` opens every annotated path from the repository root, reads
the line the annotation names, and asserts it holds the code the finding is
about.

### Consequences

- `wheeltap scan --format github` is useful outside the Action, in any CI that
  understands workflow commands.
- The renderer needs the scanned base path, so `render` takes it as an argument
  rather than reading it off the report.
- **SARIF had the same bug, and the first real upload proved it.** Seventeen
  alerts were ingested and displayed with `WT001_missing_signer/vault.rs` as
  their location — a path that does not exist in the repository, so every alert
  had no source behind it and could annotate nothing. GitHub accepts either
  rooting silently. `artifactLocation.uri` is now rooted through the same
  helper as the annotations, and two tests hold it there: one opens every SARIF
  path from the repository root and compares the line to the finding's snippet,
  the other asserts the two formats name identical paths, since a drift between
  them would put the annotation and the alert in different places with only one
  of them right.
- Five severities compress into GitHub's three levels. The real severity
  survives in the annotation title, and as a number in SARIF's
  `security-severity`.
- Coverage warnings are annotated too. A scan that stayed quiet about the files
  it could not parse would let a green check mean more than it should.

---

## ADR-015 — Both annotation channels, and `upload-sarif: auto`

**Date:** 2026-08-17
**Status:** Accepted

### Context

There are two ways to get findings onto a pull request. SARIF upload creates
persistent, deduplicated code scanning alerts. Workflow commands create inline
annotations that live only in that run.

SARIF is clearly better — except that uploading it needs
`security-events: write`, and code scanning ingest requires GitHub Advanced
Security on private repositories. A pull request from a fork has a read-only
token and cannot upload at all.

### Decision

Emit annotations always. Upload SARIF when it can succeed, decided by
`upload-sarif: auto` — the default — which skips the upload on private
repositories and on fork pull requests. `true` and `false` force the choice.

### Rationale

An unconditional upload fails the build over a permission the pull request's
author cannot grant, on a run where the analysis itself worked perfectly. The
first thing anyone does about a step that fails for reasons unrelated to their
change is delete the step.

Skipping silently is the other error. `auto` prints why it skipped and what to
set instead, so the reason is in the log rather than in a support thread.

The nuisance underneath this is that a composite action's steps do not accept
`continue-on-error` — it is only available on a job's own steps — so the action
cannot simply attempt the upload and shrug off a failure. Deciding beforehand is
the workaround, and it also produces a better message than a swallowed error
would.

### Consequences

- Annotations appear in every configuration, including fork pull requests, which
  is exactly where an external contributor most needs to see the finding.
- GitHub displays at most ten annotations of each level per step. The log and the
  SARIF report are complete; the bubbles are not. Documented in the Action's
  README, and the reason SARIF stays the primary channel.
- The self-test workflow uploads for real on pushes to `main`, which is what
  closes Phase 4's exit criterion — schema validity is not evidence of ingestion.
- `shell: bash` runs with `-e`, and **exit 1 is the scanner's success case with
  findings**. The step that captures the exit code therefore has to say `set +e`
  around the invocation — `set -uo pipefail` does not turn `-e` back off. Left
  alone the step dies on the one line that matters, recording neither the code
  nor the count, and the Action reports nothing about the run it just failed.
  This passed a local shell simulation, where `-e` is not the default, and was
  caught only by the self-test workflow running for real.
- `exit-code` and `findings` are published twice, as step outputs and as
  `WHEELTAP_EXIT_CODE` and `WHEELTAP_FINDINGS` in the environment. This was
  added on a wrong diagnosis — that a composite action's outputs are discarded
  when it fails, which was the first explanation offered for the empty values
  above. Measuring it rather than assuming it showed both channels survive a
  failing action intact. The second channel stays because it is genuinely more
  convenient from a later step, and because the self-test now asserts through
  both: the failing job on the environment, the passing job on the outputs.
  Neither contract can rot unnoticed, and the log records which is true rather
  than which was assumed.

---

## ADR-016 — The Action's version is the ref you pinned

**Date:** 2026-08-17
**Status:** Accepted

### Context

A composite action that runs a compiled binary has to get one. The usual
approaches are a `version` input, a Docker image, or vendoring a binary into the
repository.

### Decision

No version input. The Action resolves its version from the `Cargo.toml` in its
own checkout, then obtains a binary in three fallbacks: the run cache, the
release archive for that version, and a build from source.

### Rationale

A `version` input is a second place to record the same fact, and the failure it
produces — `@v1.0.0` running a `v0.9.0` binary because someone updated one line
and not the other — is invisible in the logs. Reading the version out of the
pinned checkout makes the ref the single source of truth.

Docker was the alternative. It removes the toolchain requirement, but a
container start costs more than downloading a 4 MB static binary, image
publishing is a second release pipeline to keep in step, and Docker actions run
only on Linux runners.

The build-from-source fallback exists because there is no release for every ref.
Pull requests against this repository, and anyone pinning `@main`, need a path
that works without one — and it is the path this repository's own Action tests
run on.

### Consequences

- Pinning a tag gives a download. Pinning a branch gives a build, once, then a
  cache hit; the Action says which happened.
- The cache key carries the target triple, the version, and a **fingerprint of
  the source that produced the binary**, computed in the Action itself. The
  version alone is not enough: a branch keeps its version across every commit,
  so a moving ref would serve the first binary it ever built, forever.
  `hashFiles` cannot compute the fingerprint — it resolves paths only inside the
  workspace, and a remote action is checked out well outside it.
- **`github.action_ref` was the first attempt, and it is a trap.** Expressions
  are evaluated in the context of the step that reads them, so
  `${{ github.action_ref }}` inside the `with:` of an `actions/cache@v4` step
  resolves to `v4` — a constant. This repository's own CI ran five commits
  against a stale binary because of it, including one where the SARIF fix
  described in ADR-014 had already landed and kept appearing not to work. The
  lesson is not about the cache: a build system that silently serves a stale
  artefact turns every subsequent measurement into a lie, and the only reason
  it was caught was reading the uploaded SARIF back out of GitHub rather than
  trusting that the job had gone green.
- A source build needs Rust on the runner. The Action says so by name when it is
  missing, rather than failing on `cargo: command not found`.
- Releases must ship an archive per platform with the bare binary at its root.
  `release.yml` builds five, and smoke-tests each one against the vulnerable
  fixtures before it is uploaded — a binary that builds but reports nothing
  would otherwise ship unnoticed.

---

## ADR-017 — Relationships are read as a graph, not one constraint at a time

**Date:** 2026-08-24
**Status:** Accepted

### Context

The Phase 6 audit comparison ran Wheeltap against drift and read its findings
next to Neodyme's and Trail of Bits'. Two of Wheeltap's false-positive classes
turned out to share a cause, and it was not the intraprocedural boundary that
ADR-001 predicts.

Drift ties a `user_stats` account to the `authority` that signs for it in two
steps, with a helper predicate on each account:

```rust
#[account(mut, constraint = can_sign_for_user(&user, &authority)?)]
pub user: AccountLoader<'info, User>,
#[account(mut, constraint = is_stats_for_user(&user, &user_stats)?)]
pub user_stats: AccountLoader<'info, UserStats>,
```

Neither constraint names both `user_stats` and `authority`. WT005 read one
constraint at a time, found no single check relating the two, and reported ten
account lists as unlinked.

WT011 had the mirror image. Drift rejects self-liquidation by comparing the two
`User` accounts and never the two `UserStats` accounts — it does not need to,
since each is tied to the user it belongs to. WT011 looked for a comparison
between the accounts it had flagged, and reported four more.

### Decision

Constraints build an undirected link graph over the accounts in one instruction,
walked transitively. A constraint attached to a field links that field to every
other account it names. WT005 asks whether two accounts are tied together;
WT011 asks whether they are kept apart, using the graph to find the accounts
each one stands for. The implementation is `crates/wheeltap-rules/src/links.rs`.

### Rationale

The evidence was not that the rules were noisy — that was already known and
budgeted. It was **what** they were noisy about. The check WT005 could not see
in `is_stats_for_user` is the one Trail of Bits asked drift to add in
TOB-DRIFT-8, "Missing verification of maker and maker_stats accounts". The tool
was reporting an audit's remediation as a missing check.

A rule that reports the fix as the bug is not merely imprecise. It is giving
the reader a reason to distrust the finding that would have been right.

Only constraints that assert something *relational* create an edge. `payer =
admin` and `close = destination` name another account without claiming any
correspondence, and letting them bridge the graph would tie together accounts
that merely paid for each other. Derivation counts, and counts strongly: an
address that was not derived from a key cannot be produced, so
`seeds = [b"target", pool.key().as_ref()]` is a firmer link than any comparison.

Identifiers are matched as whole words. Every mention of `user_stats` contains
`user`, and substring matching would link accounts that were never named — a
rule going quiet with nothing to show for it.

### Consequences

- Findings on drift fell from 22 to 11: WT005 from 15 to 7, WT011 from 4 to 1.
  Nothing changed on the fixture corpus — 17 on the vulnerable fixtures, 0 on
  the safe ones, before and after.
- The seven WT005 findings that remain are one class rather than two:
  permissionless instructions where the signer is the caller, not the account's
  owner. That is a question about intent and this rule will keep getting it
  wrong.
- **This is evidence, not proof.** A constraint asserting two accounts *differ*
  links them here as surely as one asserting they match. Settling it would mean
  following the helper into its body, which is exactly the boundary ADR-001
  draws. The error is toward silence, which is the right direction for a rule
  already reporting at medium confidence.
- Both changes were written fixture-first, with the drift shapes reproduced in
  `fixtures/safe/` and confirmed to be flagged before either rule was touched.
- The graph is shared, so a future rule asking either question gets it for free.

---

## ADR-018 — Audit misses are verified against the vulnerable revision

**Date:** 2026-08-24
**Status:** Accepted

### Context

Drift's audits are from February 2023 and May 2024. The vendored commit is much
newer, so most of what the auditors found is fixed in the code Wheeltap scans.

Scanning fixed code and reporting "Wheeltap did not find TOB-DRIFT-8" is
worthless in both directions: it neither shows the tool missed anything, nor
shows it would have caught it.

### Decision

For every audit finding close enough to Wheeltap's scope to be worth testing,
fetch the pre-fix revision the report names and scan that file directly. Record
the commit and the result.

### Rationale

The alternative is to reason from the fixed code about what the tool would have
done, which is exactly the kind of claim that turns out to be wrong. It costs a
`curl` and a scan to replace an inference with a measurement.

It also produced the sharpest sentence in the comparison. WT002 reports nothing
about drift's unchecked oracle *and reported nothing before the fix either* —
so its silence about that account carries no information at all. That is a much
more useful thing to be able to say than "the rule did not fire".

### Consequences

- `docs/AUDIT.md` names a commit for each verified miss, so a reader can repeat
  the check.
- Two of them are kept as runnable fixtures in `fixtures/known_gaps/`, with the
  existing gate asserting they stay missed until a rule improvement catches one.
- The pre-fix files are fetched, not vendored. They are third-party source at
  revisions with known vulnerabilities, and the repository has no reason to
  carry them.
