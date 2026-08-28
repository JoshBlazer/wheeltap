# Wheeltap

Static analysis for Rust-based Solana smart contracts. It parses Anchor programs
with `syn`, walks the AST for known account-validation hazards, and emits
findings as JSON, Markdown, or SARIF.

> **Wheeltapper** *(n.)* — a railway inspector who walked the length of a stopped
> train striking each wheel with a long hammer, listening for the dull note that
> betrayed a crack invisible from the outside.

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

Here is what Wheeltap says about it:

```console
$ wheeltap scan ./programs
```

```
WT001  critical  programs/vault/src/lib.rs:37  Withdraw.authority

  `Withdraw.authority` is verified by a `has_one` constraint but is never
  required to sign, and no account in `Withdraw` signs at all. The constraint
  proves which account this is; it does not prove the holder authorised
  anything. Public keys are public, so any caller can pass this one.

      pub authority: AccountInfo<'info>,

  Fix. Type the account as `Signer<'info>`. If it must stay an `AccountInfo`,
  require the signature explicitly with `#[account(signer)]` or
  `constraint = authority.is_signer`.

  confidence high · id 2d70e5e62f325c65
```

Half a second, and it says which account, why the constraint that *is* there
does not help, and what to write instead.

These bugs share a useful property: they are **structurally visible in the
source**. Most teams still find them only in a paid audit, late and expensively.
Wheeltap finds this class in CI, in seconds, for free.

## What it is not

No formal verification, no symbolic execution, no dataflow across CPI
boundaries, no Solidity, no auto-fixing. Wheeltap is a fast, high-signal,
syntax-and-pattern-level linter, and claims exactly that much. Where a detector
approximates dataflow it says so, and its findings are marked
`confidence: medium`.

## In CI, in five lines

```yaml
- uses: actions/checkout@v5
- uses: JoshBlazer/wheeltap/action@v1
  with:
    path: programs
```

Findings appear as inline annotations on the diff, and as code scanning alerts
where the repository can accept them. The build fails on anything at or above
`fail-on`. [`action/README.md`](action/README.md) has the inputs, the adoption
path for a codebase that already has findings, and what `upload-sarif: auto`
decides for you.

Pinning a tag gets a prebuilt binary. Pinning a branch builds from source once
and caches it, which needs a toolchain on the runner:

```yaml
- uses: dtolnay/rust-toolchain@stable
- uses: JoshBlazer/wheeltap/action@main
```

## Quickstart

```console
$ cargo install wheeltap
$ wheeltap scan ./programs
```

Or from source:

```console
$ cargo build --release
$ ./target/release/wheeltap scan fixtures/vulnerable
```

[`docs/demo.cast`](docs/demo.cast) is a fifteen-second recording of a real
session — a correct program scanning clean, the same program with a withdraw
instruction added, and 73,011 lines of production DeFi in half a second:

```console
$ asciinema play docs/demo.cast
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
$ wheeltap scan ./programs --format github            # inline PR annotations
$ wheeltap scan ./programs --severity-threshold high --fail-on critical
```

One scan can serve several consumers at once. `--emit FORMAT=PATH` is
repeatable and writes alongside whatever `--format` puts on stdout:

```console
$ wheeltap scan ./programs --format github \
    --emit sarif=wheeltap.sarif --emit markdown=summary.md
```

This is what the Action runs. Scanning three times for three consumers would be
three chances to describe three different states of the repository.

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

On 76,381 lines of third-party Anchor code — Anchor's own test suite and the
drift perpetuals protocol — Wheeltap reports **24 findings: 15 true positives,
1 unresolved, 8 false positives**. A small, correct, idiomatic program
(`escrow`) reports **zero**. Every finding is triaged individually in
[`docs/BENCHMARKS.md`](docs/BENCHMARKS.md), including the false positives and
why each survives.

Real vulnerabilities the detectors *miss* are kept as runnable fixtures in
`fixtures/known_gaps/`, with a test asserting they stay missed until a rule
improvement catches them.

A full scan of drift — 73,011 lines, 116 files, all twelve rules — takes about
half a second.

## Validation against published audits

Wheeltap was run against drift and its findings compared with the protocol's two
published audits: Neodyme (May 2024) and Trail of Bits (February 2023), 30
findings between them.

**Wheeltap reproduces one of the thirty, and only in the weakest sense.** The
full comparison is [`docs/AUDIT.md`](docs/AUDIT.md), including every miss.

| Where the thirty went | |
|---|---:|
| Reproduced, weakly — an instance of TOB-DRIFT-11's class at a different site | 1 |
| Need reasoning about what the protocol is *for* | 11 |
| Need interprocedural dataflow | 1 |
| Accounts outside `#[derive(Accounts)]` entirely | 1 |
| Need whole-program consistency | 2 |
| Engineering and language practice, not vulnerabilities | 10 |
| Types and casts — no rule covers them | 3 |
| A rule Wheeltap could have and does not | 1 |

Misses were verified rather than inferred. For each finding close enough to
Wheeltap's scope to test, the **pre-fix revision named in the report** was
fetched and scanned. Drift's `admin.rs` before the oracle fix reports zero
findings; so do the two files behind TOB-DRIFT-8. That yields the most useful
sentence in the whole exercise: WT002 said nothing about drift's unchecked
oracle *before* the fix and nothing after, so its silence about that account
carries no information at all.

The comparison also improved the tool. It showed Wheeltap reporting drift's
**fix** to TOB-DRIFT-8 as a missing check — the relationship was built out of
two constraints and the rule read them one at a time. Fixing that, and the same
cause in WT011, took findings on drift from 22 to 11 with no change on the
fixture corpus.

## Limitations

Stated once, plainly, because a security tool whose limits are undocumented
cannot be trusted:

- **Syntactic analysis only.** No formal verification, no symbolic execution, no
  solver. Wheeltap reads the AST that `syn` produces.
- **Intraprocedural.** A check in a called function is invisible (ADR-001). This
  causes false positives — a bound established one line above in a helper — and
  false negatives — a dereference that happens one call away. Rules that depend
  on it report `confidence: medium`.
- **No dataflow across CPI boundaries**, and no reasoning about what another
  program does with an account.
- **`remaining_accounts` is invisible.** Every account-validation rule starts
  from `#[derive(Accounts)]`. Accounts pulled from the iterator by hand are not
  modelled, which is how the shape of TOB-DRIFT-8 is missed entirely.
- **Macro-generated items are invisible.** An Accounts struct produced by a
  macro invocation is not modelled, and nothing warns about it.
- **Type aliases are not resolved**, and module paths are followed within a file
  only.
- **Economic and protocol reasoning is out of reach**, and always will be. Eleven
  of the thirty audit findings are of this kind.
- **Anchor only.** Native Solana programs and CosmWasm are out of scope
  (ADR-007).

A clean scan means the rules found nothing. That is a much smaller claim than
"there is nothing there", and every rule's page in
[`docs/DETECTORS.md`](docs/DETECTORS.md) says what that rule cannot see.

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
freeze the existing findings, and fail the build only on new ones. The same
identity travels in SARIF's `partialFingerprints`, so GitHub matches an alert
across pushes instead of closing and reopening every alert beneath code that
moved.

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
| `crates/wheeltap-report` | JSON, Markdown, SARIF, and annotation reporters |
| `crates/wheeltap-cli` | Command-line interface |
| `fixtures/` | Vulnerable, safe, and vendored real-program corpora |
| `docs/` | Detector catalogue, benchmarks, audit comparison |
| `action/` | GitHub Action |
| `demo/` | A small correct program the Action scans on every pull request |

`PROGRESS.md` tracks status; `DECISIONS.md` records why the architecture is what
it is.

## Licence

MIT or Apache-2.0, at your option. Vendored corpus programs keep their own
licences — see `fixtures/corpus/README.md`.
