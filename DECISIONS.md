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
