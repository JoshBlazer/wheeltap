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

## ADR-003 — `syn` 3.x, Rust edition 2024, MSRV 1.85

**Date:** 2026-08-11
**Status:** Accepted

### Context

The build spec was written against `syn` 2.x. `syn` 3.0 has since been released:
it updates the syntax tree for three years of Rust language development and
anticipates in-flight RFCs. The `visit` module, span handling, and parsing API
that Wheeltap depends on are unchanged in shape.

### Decision

Depend on `syn` 3.x. Use Rust edition 2024 with an MSRV of 1.85, enforced by a
dedicated CI job.

### Rationale

- A new security tool built on a superseded major version of its central
  dependency invites the obvious question at review time.
- `syn` 3 parses newer syntax that real programs will increasingly contain;
  on 2.x those files would fail to parse and silently reduce coverage.
- Edition 2024 has been stable since Rust 1.85 (February 2025), comfortably
  older than any toolchain a contributor is likely to run.

### Consequences

- Anything in the build spec that assumes `syn` 2.x API details is read as
  intent, not as literal API.
- The MSRV is a published promise; the `msrv` CI job removes `rust-toolchain.toml`
  before building, or the pin would silently defeat the check.

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
