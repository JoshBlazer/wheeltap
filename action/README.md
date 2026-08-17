# Wheeltap GitHub Action

Static analysis for Anchor programs, as five lines of workflow.

```yaml
- uses: JoshBlazer/wheeltap@v1
  with:
    path: programs
```

That scans `programs/`, annotates the pull request inline, uploads SARIF to code
scanning where it can, and fails the build on anything at or above `fail-on`.

## A complete workflow

```yaml
name: Security
on: [pull_request]

permissions:
  contents: read
  security-events: write   # only needed for the SARIF upload

jobs:
  wheeltap:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - uses: JoshBlazer/wheeltap@v1
        with:
          path: programs
```

## Inputs

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | Directory or file to scan, relative to the repository root |
| `severity-threshold` | `info` | Do not report findings below this severity |
| `fail-on` | `low` | Fail the build at or above this severity |
| `baseline` | — | A previous JSON report; only findings absent from it are reported |
| `format` | `github` | What goes to the log: `github`, `json`, `markdown`, `sarif` |
| `config` | — | Path to `wheeltap.toml` |
| `upload-sarif` | `auto` | `true`, `false`, or `auto` — see below |
| `sarif-file` | `wheeltap.sarif` | Where the SARIF report is written |
| `job-summary` | `true` | Append a Markdown report to the job summary |

Severities are `critical`, `high`, `medium`, `low`, `info`. The defaults match
the CLI exactly, so a run reproduces locally without translating flags.

## Outputs

| Output | Meaning |
|---|---|
| `findings` | Number of findings after suppression and thresholds |
| `exit-code` | `0` clean, `1` findings at or above `fail-on`, `2` error |
| `sarif-file` | Path to the SARIF report, uploaded or not |

`exit-code` is set even when the step fails, so a later step can read it — but
only if that step is marked `if: always()`.

## Two channels, deliberately

**Inline annotations** are emitted as workflow commands. They need no
permissions, work on forks, and appear on the diff in *Files changed*. GitHub
displays at most ten annotations of each level per step; the log and the SARIF
report are always complete.

**SARIF upload** produces persistent code scanning alerts that survive a
rebase, because Wheeltap's finding identity is content-addressed and travels in
`partialFingerprints`. Without it, code scanning matches on file and line, and
moving a function closes every alert underneath it and opens them again.

`upload-sarif: auto` uploads only where the upload can succeed:

| Situation | `auto` uploads? | Why |
|---|---|---|
| Public repository | yes | Code scanning ingest is free |
| Private repository | no | Needs GitHub Advanced Security — set `true` if you have it |
| Pull request from a fork | no | The token is read-only |

The alternative — uploading unconditionally — fails the build over a permission
the pull request's author cannot grant. The annotations still appear in every
one of those cases.

## Adopting on a codebase that already has findings

The first run on an existing project reports everything at once, so the build
cannot be allowed to fail, and a check that never fails is a check nobody
reads. Freeze the current state instead and fail only on what is new:

```yaml
- uses: JoshBlazer/wheeltap@v1
  with:
    path: programs
    baseline: .wheeltap-baseline.json
```

Generate the baseline once and commit it:

```console
$ wheeltap scan programs --format json > .wheeltap-baseline.json
```

The gentler alternative is `fail-on: critical`, which reports everything but
only blocks on the worst.

## Installation, and why the first run is slow

The Action resolves its version from the ref you pinned, so `@v1.2.0` gets the
`v1.2.0` binary and there is no separate version input to get out of step.

It then tries, in order: a cached binary from a previous run, the release
archive for the runner's platform, and finally a build from source. Only the
last is slow, and it applies when you pin to a ref that was never released —
a branch, or a commit. Pin a tag and the binary is a download.

Building from source needs a Rust toolchain on the runner:

```yaml
- uses: dtolnay/rust-toolchain@stable
- uses: JoshBlazer/wheeltap@main
```

Runners: Linux and macOS on x86-64 and ARM64, and Windows on x86-64.

## Suppressing a finding

Inline, where the reason survives the code moving:

```rust
// wheeltap:allow(WT001) -- signature enforced across the CPI boundary
pub authority: AccountInfo<'info>,
```

Or in `wheeltap.toml` beside the scanned path, for whole rules and directories.
See the [main README](../README.md#suppression).
