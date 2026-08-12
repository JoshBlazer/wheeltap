# Wheeltap

Static analysis for Rust-based Solana smart contracts. It parses Anchor programs
with `syn`, walks the AST for known account-validation hazards, and emits
findings as JSON, Markdown, or SARIF.

> **Wheeltapper** *(n.)* — a railway inspector who walked the length of a stopped
> train striking each wheel with a long hammer, listening for the dull note that
> betrayed a crack invisible from the outside.

> ⚠️ **Under construction — Phase 1 of 6.** The workspace, CI, and scan corpus
> are in place and green; the parser and detectors are not written yet, so the
> tool finds nothing. `PROGRESS.md` is the live status. This notice comes out at
> v1.0.0.

## The problem

Solana puts account validation entirely on the developer. The runtime will not
stop a program from trusting an account that was never checked as a signer, or
one owned by an attacker's program rather than the one you expect. Nothing
fails; the transaction simply succeeds on attacker-controlled input.

```rust
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub vault: Account<'info, Vault>,

    /// The vault's authority. Nothing here proves it signed.
    pub authority: AccountInfo<'info>,
}
```

That program hands the vault to anyone who passes the right public key. They do
not need the private key, because nothing ever asks for a signature. The fix is
one type — `Signer<'info>` — and this class of bug has drained real protocols
repeatedly.

These bugs share a useful property: they are **structurally visible in the
source**. Most teams still find them only in a paid audit, late and expensively.
Wheeltap finds this class in CI, in seconds, for free.

## What it is not

No formal verification, no symbolic execution, no dataflow across CPI
boundaries, no Solidity, no auto-fixing. Wheeltap is a fast, high-signal,
syntax-and-pattern-level linter, and claims exactly that much. Where a detector
approximates dataflow it says so, and its findings are marked
`confidence: medium`.

## Quickstart

_Not yet installable — Phase 5._ The intended shape:

```console
$ cargo install wheeltap
$ wheeltap scan ./programs
```

## Detectors

Twelve rules planned, covering missing signer and owner checks, unchecked
arithmetic, reinitialisation, PDA bump canonicality, arbitrary CPI targets,
sysvar spoofing, and account aliasing. Catalogue and build order:
[`docs/DETECTORS.md`](docs/DETECTORS.md).

## Deterministic finding identity

Line numbers move when unrelated code is edited. If finding identity depends on
line numbers, every run-over-run diff is noise and baselining is useless.

Wheeltap identifies a finding by what it *is*, not where it sits:

```
id = hash(rule_id, relative_path, enclosing_item_path, normalised_snippet)
```

where `enclosing_item_path` is something like
`my_program::initialize::Accounts.authority`, and the snippet is normalised by
collapsing whitespace and stripping comments. A finding keeps its identity when
code moves within a file, and loses it when the offending code itself changes.

That is what makes `--baseline` trustworthy: adopt Wheeltap on a large codebase,
freeze the existing findings, and fail the build only on new ones. Phase 2 and 4.

## Development

```console
$ cargo test --workspace
$ cargo clippy --workspace --all-targets -- -D warnings
$ cargo fmt --all --check
```

Requires a C toolchain for linking (`build-essential` on Debian/Ubuntu).

### Adding a detector

Fixture-first, in this order — it is enforced by review, not by convention:

1. Write the vulnerable fixture in `fixtures/vulnerable/WTnnn_name/`. Make it
   look like code someone would ship.
2. Write **at least two** safe fixtures in `fixtures/safe/` that a naive
   implementation of the rule would flag. This is the step that matters.
3. Write the `docs/DETECTORS.md` entry, including the rule's limits.
4. *Then* implement the detector.

For a security tool the fixture corpus is the specification. A false negative is
a missed vulnerability; a false positive erodes trust until the tool is switched
off. Both are failures.

## Repository

| Path | Contents |
|---|---|
| `crates/wheeltap-core` | Types, program context model, detector engine |
| `crates/wheeltap-rules` | One module per detector |
| `crates/wheeltap-report` | JSON, Markdown, SARIF reporters |
| `crates/wheeltap-cli` | Command-line interface |
| `fixtures/` | Vulnerable, safe, and vendored real-program corpora |
| `docs/` | Detector catalogue and benchmarks |
| `action/` | GitHub Action (Phase 5) |

`PROGRESS.md` tracks status; `DECISIONS.md` records why the architecture is what
it is.

## Licence

MIT or Apache-2.0, at your option. Vendored corpus programs keep their own
licences — see `fixtures/corpus/README.md`.
