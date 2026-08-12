# Known gaps — real vulnerabilities Wheeltap does *not* catch

Everything in this directory is genuinely vulnerable code that the current
detectors miss. It is here, tested, and documented, rather than deleted.

## Why this directory exists

A detector can be made to catch any single example. The question is what it
costs elsewhere. When precision and recall genuinely conflict, the choice gets
made deliberately, and the losing side gets written down here instead of
quietly disappearing from the corpus.

The alternative — trimming a fixture until the detector passes — produces a tool
that looks better than it is. The build spec's rule is *never weaken a fixture to
silence a false positive*; this directory is the same principle applied to false
negatives.

## How it is tested

`tests/fixtures.rs` asserts these are **not** flagged. That reads backwards
until you consider what it does: when a future detector improvement starts
catching one, the test fails, and the failure says *promote this to
`fixtures/vulnerable/`*. A gap that closes silently is a gap nobody records as
closed.

## The gaps

### `WT001_unreferenced_admin/` — an unsigned admin with no recorded relationship

```rust
#[derive(Accounts)]
pub struct SetFee<'info> {
    #[account(mut, seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,

    /// CHECK: only the protocol admin can call this
    pub admin: UncheckedAccount<'info>,
}
```

Anyone can call `set_fee_bps`. The `admin` account is never required to sign,
and — unlike the vault fixture — the config does not record it with a `has_one`,
so there is no structural evidence tying this account to an authority role.

**Why WT001 misses it.** The only remaining signal is the *name*. An earlier
version of the rule did fire on names, and the corpus verdict was decisive: 66
findings across `anchor-misc` and `drift`, and every one sampled was a false
positive. Two classes dominated:

- `mint_authority` and `freeze_authority` on `init` — the authority being
  *assigned to a newly created mint*, not an account authorising the call.
- drift's `drift_signer` — a program-derived signer the program signs for
  itself.

Reporting a Critical-severity finding on 66 pieces of correct code, to catch this
one, is a bad trade. The rule that keeps the tool installed is the one that stays
quiet.

**What would close it.** Evidence that the account authorises *this* instruction
rather than merely being named like an authority — for example, seeing the field
compared against a stored admin key, or used as the authority of a CPI whose
seeds the program does not supply. That is dataflow, and it is out of scope for
a syntactic analyser (ADR-001).
