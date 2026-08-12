# Wheeltap detector catalogue

One page per rule: what it finds, why it matters, a vulnerable example, a fixed
example, and its known limits.

**Nothing is implemented yet.** This file is written detector by detector, at
implementation time, per the build order below. A rule appears here only once its
true-positive and false-positive fixtures pass — `PROGRESS.md` is the live status
table.

## Reading a finding

**Severity** is the impact if the issue is real and reachable.

| Severity | Meaning |
|---|---|
| Critical | Direct loss of funds or full authority takeover |
| High | Loss of funds under specific conditions, or bypass of an access control |
| Medium | State corruption, denial of service, or a weakened invariant |
| Low | Hygiene; no direct security impact |
| Info | Observation, no action implied |

**Confidence** is how sure Wheeltap is that it read the code correctly. It is a
statement about the *analyser*, not the vulnerability.

| Confidence | Meaning |
|---|---|
| High | The pattern is structurally unambiguous in the AST |
| Medium | Relies on an intraprocedural approximation; a validation elsewhere would be missed (see ADR-001) |
| Low | Heuristic. Expect to triage these by hand |

A Critical finding at Low confidence is worth a human minute. A Low finding at
High confidence is worth a lint fix. They are different axes and Wheeltap never
collapses them into one number.

## Build order

Ordered by ratio of security value to implementation difficulty.

| ID | Name | Severity | Phase | Status |
|---|---|---|---|---|
| WT001 | Missing signer check | Critical | 2 | not started |
| WT002 | Missing owner check | Critical | 2 | not started |
| WT003 | Unchecked arithmetic | High | 2 | not started |
| WT004 | Account reinitialisation | High | 3 | not started |
| WT005 | Missing `has_one` / constraint | High | 3 | not started |
| WT006 | Non-canonical PDA bump | High | 3 | not started |
| WT007 | Arbitrary CPI target | Critical | 3 | not started |
| WT008 | Missing rent-exemption / close handling | Medium | 3 | not started |
| WT009 | Sysvar spoofing | High | 3 | not started |
| WT010 | Unsafe `AccountInfo` deserialisation | High | 3 | not started |
| WT011 | Duplicate mutable accounts | Medium | 3 | not started |
| WT012 | Inefficient allocation in loop | Low | 3 | not started |

Ten implemented rules is the minimum bar; twelve is the target. Three excellent
detectors beat twelve noisy ones, and that trade will be made in favour of
quality if it comes to it.

---

### WT001 — Missing signer check

**Severity:** Critical · **Confidence:** High · **Since:** v0.1

#### What it finds

An account list in which **nothing signs**, and an account verified by a
`has_one` constraint is treated as the authority. All of the following must
hold:

- no field in the `#[derive(Accounts)]` struct is a `Signer` or asserts
  `signer` by constraint — nobody authorised the instruction at all;
- the field is the target of a `has_one` on another account;
- it is not itself signer-checked, not a PDA, and not address-pinned;
- it is either an unchecked type or named like an authority.

#### Why it matters

`has_one = authority` proves the account passed is the key the program recorded.
It says nothing about whether that key authorised the transaction. Public keys
are public: anyone can pass the real authority's key.

The two questions are independent, and conflating them is the bug:

- **Who is this?** — answered by `has_one`, `address`, seeds.
- **Did they agree to this?** — answered *only* by a signature.

An account list that answers the first and not the second is an access control
that checks the name on the door and never asks for the key.

#### Vulnerable

```rust
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,

    /// CHECK: the vault records this key, so it must be the right authority
    pub authority: AccountInfo<'info>,
}
```

The comment is a note, not a check. Anyone may call this and drain the vault.

#### Fixed

```rust
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,

    pub authority: Signer<'info>,
}
```

`#[account(signer)]` or `constraint = authority.is_signer` on an `AccountInfo`
are equally valid and are not flagged.

#### Limits

The rule is **deliberately narrow**, and the corpus is why. Three exclusions do
the work, each of which was added because removing it produced false positives on
real code:

- **PDA authorities are excluded.** An account with `seeds` and a canonical
  `bump` is program-derived: no private key exists, so no user *can* sign for it,
  and the program signs on its behalf via CPI seeds. Requiring `Signer` there
  would make the program unrunnable.
- **An account list where something else signs is excluded.** If a `payer` or
  `keeper` signs, the instruction has an authoriser, and deciding whether it is
  the *right* one is a judgement about intent that a syntactic analyser cannot
  make. Drift administers user accounts exactly this way — a keeper signs while
  the recorded `authority` does not, which is correct, because initialising or
  sweeping an account on someone's behalf does not need their consent. Without
  this exclusion, drift produced nine Critical findings, all wrong.
- **`has_one` expresses any relationship, not just authority.** A pool recording
  its mint uses the same syntax, so the target must also be unchecked or
  authority-named. `has_one = mint` on an `Account<'info, Mint>` is not reported.

**Known false negatives**, both documented in `fixtures/known_gaps/`:

- An unsigned authority with **no `has_one`** recording it — nothing structural
  ties the account to an authority role, and matching on the name alone produced
  66 false positives across the corpus against this one true positive.
- An account list where **something else signs** but the authority still should
  have, such as a withdrawal authorised by a payer.
- A signature asserted in a *called* function rather than in the account list
  (ADR-001).

#### Suppressing

```rust
/// CHECK: signature enforced by the calling program across the CPI boundary
// wheeltap:allow(WT001) -- authority is validated in the CPI callee
pub authority: AccountInfo<'info>,
```

#### References

- [Solana: signer authorization](https://solana.com/developers/courses/program-security/signer-auth)
- [Sealevel attacks: signer authorization](https://github.com/coral-xyz/sealevel-attacks)

---

### WT002 — Missing owner check

**Severity:** Critical · **Confidence:** Medium · **Since:** v0.1

#### What it finds

An unchecked account (`AccountInfo` or `UncheckedAccount`) whose **data is
read** in a handler, where nothing establishes which program owns it: no
`owner =`, no `address =`, and no assertion on `.owner` in the same function.

#### Why it matters

Account data is just bytes. The only thing separating a real price feed, vault,
or config account from one an attacker fabricated is the program that owns it.

An attacker deploys their own program, creates an account owned by it, writes
whatever bytes suit them, and passes it in. If the program deserialises without
checking ownership, it is reading attacker-authored state as if it were its own.
This is the usual first step in oracle manipulation.

`Account<'info, T>` performs this check for you — it verifies the owning program
and the discriminator before the handler runs. Reaching for `AccountInfo` opts
out of it.

#### Vulnerable

```rust
pub fn borrow(ctx: Context<Borrow>, amount: u64) -> Result<()> {
    let data = ctx.accounts.oracle.try_borrow_data()?;
    let feed = PriceFeed::try_from_slice(&data)?;   // trusted, unverified
    ...
}

#[derive(Accounts)]
pub struct Borrow<'info> {
    /// CHECK: the price feed for this market
    pub oracle: AccountInfo<'info>,
}
```

#### Fixed

```rust
#[derive(Accounts)]
pub struct Borrow<'info> {
    /// CHECK: owner pinned to the oracle program
    #[account(owner = pyth_oracle::ID)]
    pub oracle: AccountInfo<'info>,
}
```

Or assert in the handler before reading:

```rust
require_keys_eq!(*ctx.accounts.oracle.owner, expected_program, MyError::WrongOwner);
```

#### Limits

- **The check must be in the same function as the read.** This is an
  intraprocedural approximation (ADR-001), and the reason the rule is medium
  confidence. A program that validates ownership in a helper will be a false
  positive.
- **Only data reads are reported.** An `AccountInfo` passed to a CPI without
  being deserialised is not flagged — that is the ordinary reason to hold one,
  and flagging it would bury the real findings.
- Recognising a read is syntactic: `try_borrow_data`, `try_from_slice`,
  `deserialize`, `try_deserialize`, `Account::try_from`, and `.data`. A read
  spelled some other way is missed.

#### Suppressing

```rust
// wheeltap:allow(WT002) -- owner verified by validate_oracle() below
```

#### References

- [Solana: owner checks](https://solana.com/developers/courses/program-security/owner-checks)
- [Sealevel attacks: owner checks](https://github.com/coral-xyz/sealevel-attacks)

---

### WT003 — Unchecked arithmetic

**Severity:** High · **Confidence:** Medium · **Since:** v0.1

#### What it finds

Raw `+`, `-`, `*` (and `+=`, `-=`, `*=`) applied to values that look like
balances — `amount`, `balance`, `lamports`, `supply`, `rewards`, `shares`, and
similar — inside a handler, in a project that has not enabled
`overflow-checks`.

#### Why it matters

Solana programs ship as release builds, and **release builds wrap on overflow**.
Rust's debug-build overflow panic is not present in the deployed artifact unless
the project asks for it.

Wrapping is worse than panicking. A panic aborts the transaction and nothing
changes. Wrapping produces a *plausible wrong number* and commits it: a deposit
that wraps to a tiny balance, a reward that wraps to an enormous one. The
program reports success either way.

#### Vulnerable

```rust
stake.amount = stake.amount + amount;
pool.remaining_rewards -= rewards;
```

#### Fixed

```rust
stake.amount = stake.amount.checked_add(amount).ok_or(StakeError::Overflow)?;
pool.remaining_rewards = pool.remaining_rewards.saturating_sub(rewards);
```

Or enable it project-wide, which Wheeltap respects:

```toml
[profile.release]
overflow-checks = true
```

#### Limits

- **`overflow-checks = true` silences this rule entirely** for that project.
  That is intended: the hazard is gone. Wheeltap looks for the nearest
  `Cargo.toml` above the file.
- **Value names are a heuristic**, hence medium confidence. Wheeltap has no
  types (ADR-001), so it cannot tell a `u64` balance from a `usize` index except
  by how it is named. A balance called `qty` is missed; the rule is deliberately
  tuned to miss rather than to flood.
- Loop counters, slice lengths, offsets, and arithmetic on constants are
  excluded.
- Overflow that spans statements — a value accumulated in a loop — is not
  reported. That needs dataflow.

#### Suppressing

```rust
// wheeltap:allow(WT003) -- bounded above by MAX_SUPPLY, checked on entry
```

#### References

- [Solana: overflow and underflow](https://solana.com/developers/courses/program-security/overflow-underflow)
- [Rust: `overflow-checks`](https://doc.rust-lang.org/cargo/reference/profiles.html#overflow-checks)

---

## Template

Each entry follows this shape.

---

### WTnnn — Name

**Severity:** _ · **Confidence:** _ · **Since:** v_

#### What it finds

#### Why it matters

The exploit path, concretely. If there is a public incident of this class, cite
it.

#### Vulnerable

```rust
```

#### Fixed

```rust
```

#### Limits

What this rule cannot see, and the shapes that will produce a false positive or
a false negative. Stated plainly — a detector whose limits are undocumented
cannot be trusted by someone triaging its output.

#### Suppressing

```rust
// wheeltap:allow(WTnnn) -- justification
```

#### References
