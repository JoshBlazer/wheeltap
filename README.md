# Wheeltap

Static analysis for Rust-based Solana smart contracts. It parses Anchor programs
with `syn`, walks the AST for known account-validation hazards, and emits
findings as JSON, Markdown, or SARIF.

> **Wheeltapper** *(n.)* — a railway inspector who walked the length of a stopped
> train striking each wheel with a long hammer, listening for the dull note that
> betrayed a crack invisible from the outside.

> ⚠️ **Under construction — Phase 5 of 6.** All twelve detectors, three output
> formats, suppression, and baselines are implemented. The GitHub Action and
> crates.io release come next. `PROGRESS.md` is the live status. This notice
> comes out at v1.0.0.

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

Building from source works today:

```console
$ cargo build --release
$ ./target/release/wheeltap scan fixtures/vulnerable
```

```json
{
  "schema": "1.0",
  "summary": { "files_scanned": 3, "findings": 10,
               "by_severity": [{"severity": "critical", "count": 2},
                               {"severity": "high", "count": 8}] },
  "findings": [
    {
      "id": "2d70e5e62f325c65",
      "rule": "WT001",
      "severity": "critical",
      "confidence": "high",
      "file": "WT001_missing_signer/vault.rs",
      "line": 37,
      "item_path": "Withdraw.authority",
      "message": "`Withdraw.authority` is verified by a `has_one` constraint but is never required to sign, and no account in `Withdraw` signs at all. The constraint proves which account this is; it does not prove the holder authorised anything.",
      "snippet": "    pub authority: AccountInfo<'info>,"
    }
  ]
}
```

Exit codes are `0` clean, `1` findings at or above `--fail-on`, `2` internal
error. `wheeltap debug-context <path>` prints the parsed program model, which is
how you find out whether a missing finding is the rule's fault or the parser's.

```console
$ wheeltap scan ./programs --format markdown          # for a CI log
$ wheeltap scan ./programs --format sarif > out.sarif # for GitHub code scanning
$ wheeltap scan ./programs --severity-threshold high --fail-on critical
```

## Suppression

Two ways, because they answer different questions.

**Inline**, where the reason lives next to the thing it explains and survives
refactoring:

```rust
/// CHECK: authority is verified by the calling program
// wheeltap:allow(WT001) -- signature enforced across the CPI boundary
pub authority: AccountInfo<'info>,
```

The comment may sit on the finding's line or anywhere in the run of attributes
and comments directly above it. A suppression without a `-- reason` is still
honoured, and warned about: refusing it would just push people to delete the
scan instead (ADR-012).

**Configured**, in `wheeltap.toml` beside the scanned path, for adopting the
tool on a large codebase:

```toml
[suppress]
rules = ["WT012"]              # switch a rule off entirely
paths = ["programs/legacy/**"] # exempt a directory

[severity]
WT005 = "medium"               # downgrade for this project
```

Unknown keys are an error. A typo that silently switches nothing off is worse
than a failure.

Run with `--no-suppress` to see everything regardless.

## Baselines

Adopting a linter on an existing codebase has a chicken-and-egg problem: the
first run reports hundreds of findings, nobody has time to fix them, so the
build cannot fail on findings — and a check that never fails is a check nobody
reads.

```console
$ wheeltap scan ./programs --format json > baseline.json   # freeze today
$ wheeltap scan ./programs --baseline baseline.json        # fail only on new
```

This works only because finding identity is content-addressed. With positional
identity, adding an import at the top of a file would make every finding below
it "new", and the baseline would be noise within a day.

## Detectors

| ID | Name | Severity | Confidence |
|---|---|---|---|
| WT001 | Missing signer check | Critical | High |
| WT002 | Missing owner check | Critical | Medium |
| WT003 | Unchecked arithmetic | High | Medium |
| WT004 | Account reinitialisation | High | Medium |
| WT005 | Missing `has_one` constraint | High | Medium |
| WT006 | Non-canonical PDA bump | High | High |
| WT007 | Arbitrary CPI target | Critical | High |
| WT008 | Unsafe account close | Medium | Medium |
| WT009 | Sysvar spoofing | High | High |
| WT010 | Unchecked deserialisation | High | High |
| WT011 | Duplicate mutable accounts | Medium | Medium |
| WT012 | Allocation in a loop | Low | Medium |

Each rule's page in [`docs/DETECTORS.md`](docs/DETECTORS.md) gives a vulnerable
example, the fix, and — the part worth reading — **what it cannot see**.

**Severity** is the impact if the finding is real. **Confidence** is how sure
Wheeltap is that it read the code correctly: a statement about the analyser, not
the vulnerability. They are never collapsed into one number.

### Measured noise

On 76,381 lines of third-party Anchor code (Anchor's test suite and the drift
perpetuals protocol), Wheeltap reports **35 findings: 15 true positives, 20 false
positives**. A small, correct, idiomatic program reports **zero**. Every finding
is triaged individually in [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md), including
the false positives and why each survives.

Real vulnerabilities the detectors *miss* are kept as runnable fixtures in
`fixtures/known_gaps/`, with a test asserting they stay missed until a rule
improvement catches them.

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
