# Wheeltap detector catalogue

One page per rule: what it finds, why it matters, a vulnerable example, a fixed
example, and its known limits.

Every rule here is implemented, and each was written fixtures-first: the
vulnerable case, then at least two safe cases a naive implementation would flag,
then this entry, then the detector. `PROGRESS.md` is the live status table.

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

## The catalogue

| ID | Name | Severity | Confidence | Status |
|---|---|---|---|---|
| WT001 | Missing signer check | Critical | High | implemented |
| WT002 | Missing owner check | Critical | Medium | implemented |
| WT003 | Unchecked arithmetic | High | Medium | implemented |
| WT004 | Account reinitialisation | High | Medium | implemented |
| WT005 | Missing `has_one` constraint | High | Medium | implemented |
| WT006 | Non-canonical PDA bump | High | High | implemented |
| WT007 | Arbitrary CPI target | Critical | High | implemented |
| WT008 | Unsafe account close | Medium | Medium | implemented |
| WT009 | Sysvar spoofing | High | High | implemented |
| WT010 | Unchecked deserialisation | High | High | implemented |
| WT011 | Duplicate mutable accounts | Medium | Medium | implemented |
| WT012 | Allocation in a loop | Low | Medium | implemented |

All twelve are implemented, each with vulnerable fixtures it must catch and safe
fixtures it must not flag. Measured noise on 76,381 lines of third-party code is
in [`BENCHMARKS.md`](BENCHMARKS.md).

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

### WT004 — Account reinitialisation

**Severity:** High · **Confidence:** Medium · **Since:** v0.1

#### What it finds

`init_if_needed` on one of the program's own state accounts, where no handler
using that account list checks whether the account already holds data.

#### Why it matters

`init_if_needed` creates the account if it is absent and runs the handler either
way. A handler that cannot tell the two cases apart will overwrite live state.

The attack is one call: pass someone else's existing account, Anchor skips
creation because it exists, and the handler assigns `profile.authority =
payer.key()` over the top. The account is now yours.

#### Vulnerable

```rust
#[account(init_if_needed, payer = payer, space = 8 + Profile::INIT_SPACE, ...)]
pub profile: Account<'info, Profile>,

// ...
profile.authority = ctx.accounts.payer.key();   // unconditional
```

#### Fixed

```rust
if profile.authority == Pubkey::default() {
    profile.authority = ctx.accounts.payer.key();   // fresh: claim it
} else {
    require_keys_eq!(profile.authority, ctx.accounts.payer.key(), Error::NotOwner);
}
```

#### Limits

- **Token accounts are excluded**, and this is what makes the rule usable.
  Creating an associated token account on demand is *the* idiomatic use of
  `init_if_needed` and appears in nearly every program that moves tokens. The
  rule fires only when the inner type is a struct declared `#[account]` in the
  scanned program — a `TokenAccount` belongs to the token program and its state
  is not ours to clobber.
- The guard is recognised syntactically (`Pubkey::default()`, `require_keys_eq!`,
  `is_initialized`, a discriminator test). A guard spelled some other way reads
  as absent.

#### Suppressing

```rust
// wheeltap:allow(WT004) -- fields are idempotent; reinitialisation is intended
```

#### References

- [Solana: reinitialization attacks](https://solana.com/developers/courses/program-security/reinitialization-attacks)

---

### WT005 — Missing `has_one` constraint

**Severity:** High · **Confidence:** Medium · **Since:** v0.1

#### What it finds

An account whose state stores a `Pubkey` field, where the same instruction also
takes an account by that name, and nothing checks that the two match.

#### Why it matters

`Treasury { authority: Pubkey }` is a claim: this treasury belongs to that key.
If the instruction takes both a treasury and an `authority` and never compares
them, the claim is documentation.

The signature can be perfectly real and the check still absent — sign with your
own key, pass someone else's treasury, and the field that would have stopped you
was never read.

#### Vulnerable

```rust
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub treasury: Account<'info, Treasury>,   // stores `authority: Pubkey`
    pub authority: Signer<'info>,             // signs, but is never compared
}
```

#### Fixed

```rust
#[account(mut, has_one = authority)]
pub treasury: Account<'info, Treasury>,
```

`constraint = treasury.authority == authority.key()` and deriving the treasury's
address from the authority with `seeds` both count, and are not flagged.

#### Limits

This rule has the widest gap between what it can see and what it must infer, and
its exclusions reflect that:

- **Accounts being created are excluded.** `init` means the handler is about to
  *write* those keys; there is nothing yet to check them against.
- **Only accounts the instruction writes are considered.**
- **An instruction holding two accounts of the same type is skipped.** Drift's
  `FillOrder` takes a `filler` and a `user`, both `AccountLoader<User>`, and its
  `authority` signs for the filler alone — so `user` deliberately has no
  relationship to it.
- The assertion is recognised on either account, in constraints or in the
  handler, and through the zero-copy `account.load()?.field` form.
- **Relationships compose.** A constraint on one account that names another
  links the two, and the rule follows those links transitively. Programs build
  a relationship out of parts:

  ```rust
  #[account(mut, constraint = can_sign_for_user(&user, &authority)?)]
  pub user: AccountLoader<'info, User>,
  #[account(mut, constraint = is_stats_for_user(&user, &user_stats)?)]
  pub user_stats: AccountLoader<'info, UserStats>,
  ```

  Neither constraint names both `user_stats` and `authority`, but together they
  tie them. Deriving one account's address from another links them the same
  way, and more strongly: `seeds = [b"target", pool.key().as_ref()]` makes a
  mismatched pair unconstructible. Reading only one constraint at a time called
  ten of drift's account lists unlinked — and the check it could not see was
  the one Trail of Bits had asked drift to add (TOB-DRIFT-8).

  The composition is treated as evidence of a relationship, not proof of one:
  a constraint asserting two accounts *differ* links them under this rule as
  surely as one asserting they match. That is the price of not following the
  helper into its body (ADR-001), and it errs toward silence. WT011 asks the
  opposite question of the same graph.

**Known false positive: permissionless cranks.** Where a signer named
`authority` is the *caller* rather than the account's owner — drift's
`UpdateUserFuelBonus` and similar — this rule reports a relationship that was
never intended. Seven of these remain on drift and are listed in
`docs/BENCHMARKS.md`. Separating them from the real thing needs intent, not
syntax.

#### Suppressing

```rust
// wheeltap:allow(WT005) -- permissionless crank; the signer is the caller
```

#### References

- [Solana: account data matching](https://solana.com/developers/courses/program-security/account-data-matching)

---

### WT006 — Non-canonical PDA bump

**Severity:** High · **Confidence:** High · **Since:** v0.1

#### What it finds

`bump = <expr>` where the expression reads an argument declared in
`#[instruction(...)]` — that is, a bump the caller supplies.

#### Why it matters

`find_program_address` returns the *canonical* bump: the highest byte that puts
the derived address off the curve. It is not the only byte that works. Several
usually produce valid, distinct addresses for the same seeds.

Letting the caller choose the bump lets them choose which address to use. They
create a second account for the same logical seeds — passing every constraint,
holding its own state, and invisible to every other instruction, which looks up
the canonical one.

#### Vulnerable

```rust
#[instruction(market_bump: u8)]
// ...
#[account(init, seeds = [b"market", creator.key().as_ref()], bump = market_bump)]
pub market: Account<'info, Market>,
```

#### Fixed

```rust
#[account(init, seeds = [b"market", creator.key().as_ref()], bump)]
pub market: Account<'info, Market>,
// then store it: market.bump = ctx.bumps.market;
```

#### Limits

- **`bump = account.bump` is not flagged**, and getting this wrong would make
  the rule useless. Reading back the bump the program itself stored at creation
  is correct, cheaper than re-deriving, and ubiquitous — drift does it 147 times
  and escrow does it too. The rule distinguishes instruction data from stored
  state by matching the argument name on a word boundary, rejecting a leading
  `.`.
- A bump passed through a struct of instruction data, rather than named directly
  as an argument, is missed.

#### Suppressing

```rust
// wheeltap:allow(WT006) -- bump validated against find_program_address above
```

#### References

- [Solana: bump seed canonicalization](https://solana.com/developers/courses/program-security/bump-seed-canonicalization)

---

### WT007 — Arbitrary CPI target

**Severity:** Critical · **Confidence:** High · **Since:** v0.1

#### What it finds

An unchecked account with no `address` constraint that is passed as the *program*
to a `CpiContext` constructor, `invoke`, or `invoke_signed`.

#### Why it matters

A cross-program invocation carries the caller's authority with it. If the callee
is whatever account the caller supplied, the caller chooses who receives that
authority — including their own program.

When the invocation is signed with a PDA's seeds, the attacker's program is
handed the vault's signature and can do anything the vault may do.

#### Vulnerable

```rust
/// CHECK: the token program to call
pub target_program: AccountInfo<'info>,

// ...
CpiContext::new_with_signer(ctx.accounts.target_program.to_account_info(), accounts, &[seeds])
```

#### Fixed

```rust
pub token_program: Program<'info, Token>,   // Anchor asserts the address
```

Or `#[account(address = expected::ID)]` where no Anchor type exists.

#### Limits

- Only the **first** argument of a CPI constructor is the callee. Accounts passed
  *to* the CPI are ordinary and are not flagged — that distinction is what keeps
  this rule off every program that makes a transfer.
- A program account stored in a variable before the call, or dispatched through a
  match, is missed.

#### Suppressing

```rust
// wheeltap:allow(WT007) -- callee verified against a whitelist above
```

#### References

- [Solana: arbitrary CPI](https://solana.com/developers/courses/program-security/arbitrary-cpi)

---

### WT008 — Unsafe account close

**Severity:** Medium · **Confidence:** Medium · **Since:** v0.1

#### What it finds

A handler that sets an account's lamports to zero without also clearing it —
no `assign`, no `realloc(0)`, no zeroing of the data, and no `close =`
constraint on the account list.

#### Why it matters

Draining the lamports is not closing the account. The runtime reclaims accounts
at the *end* of a transaction, and only if the balance is zero. Until then the
data is intact.

So the attacker calls the close instruction and, in the same transaction, sends
a few lamports back. The account survives with all its state — a position that
has been paid out and still looks unpaid.

#### Vulnerable

```rust
**position.try_borrow_mut_lamports()? = 0;
**destination.try_borrow_mut_lamports()? += balance;
// data untouched; account revivable in the same transaction
```

#### Fixed

```rust
#[account(mut, close = owner)]
pub position: Account<'info, Position>,
```

#### Limits

- **Moving lamports is not closing.** The rule fires on assignment to zero, not
  on `-=` or `+=`, so a program that pays people is not flagged.
- Data clearing is recognised syntactically (`assign`, `realloc(0`, `fill(0)`,
  `sol_memset`, the closed-account discriminator). An unusual spelling reads as
  absent.

#### Suppressing

```rust
// wheeltap:allow(WT008) -- account is zeroed by the helper below
```

#### References

- [Solana: closing accounts](https://solana.com/developers/courses/program-security/closing-accounts)

---

### WT009 — Sysvar spoofing

**Severity:** High · **Confidence:** High · **Since:** v0.1

#### What it finds

A field named exactly for a sysvar — `clock`, `rent`, `instructions`,
`slot_hashes` and the rest — that is an unchecked account with no `address`
constraint.

#### Why it matters

Sysvars are ordinary accounts at fixed, well-known addresses. Nothing about
passing one is privileged, so a caller can pass a different account and the
program reads whatever it holds.

A substituted clock unlocks a vesting schedule that has not vested. A substituted
rent sysvar defeats a rent-exemption check.

#### Vulnerable

```rust
/// CHECK: the clock sysvar
pub clock: AccountInfo<'info>,
```

#### Fixed

```rust
pub clock: Sysvar<'info, Clock>,
```

Or `#[account(address = sysvar::instructions::ID)]` for the sysvars Anchor has
no type for.

#### Limits

- The name must match **exactly**. `clock_authority` and `rent_collector` are
  ordinary accounts that happen to contain the word, and flagging them would be
  wrong — so a sysvar passed under an unusual name is missed instead.

#### Suppressing

```rust
// wheeltap:allow(WT009) -- address asserted in the handler
```

#### References

- [Solana: sysvar spoofing](https://solana.com/developers/courses/program-security/sysvar-spoofing)

---

### WT010 — Unchecked deserialisation

**Severity:** High · **Confidence:** High · **Since:** v0.1

#### What it finds

Calls to deserialisation entry points that skip the discriminator:
`try_deserialize_unchecked`, `try_from_slice_unchecked`, `try_from_unchecked`,
`deserialize_unchecked`, `load_unchecked`.

#### Why it matters

Anchor writes an eight-byte discriminator derived from the type name at the
front of every account it owns, and checks it on the way back in. The
`_unchecked` variants do not.

Without it, any account owned by the program can be read as any of its types.
Pass a `UserProfile` where a `Config` is expected and the bytes are
reinterpreted — typically leaving the attacker's key where the admin key should
have been. An owner check does not help: the owner really is this program.

#### Vulnerable

```rust
let config = Config::try_deserialize_unchecked(&mut data)?;
require_keys_eq!(config.admin, ctx.accounts.caller.key(), Error::NotAdmin);
```

#### Fixed

```rust
let config = Config::try_deserialize(&mut data)?;
```

#### Limits

- Purely lexical: the rule looks for the call, not for whether the discriminator
  is checked some other way. The `_unchecked` variants are legitimate on an
  account the program has just created and knows the layout of, and those are
  false positives.
- One finding per handler, at the handler's location rather than the call's.

#### Suppressing

```rust
// wheeltap:allow(WT010) -- account was created by this instruction
```

#### References

- [Anchor: account types](https://www.anchor-lang.com/docs/account-types)

---

### WT011 — Duplicate mutable accounts

**Severity:** Medium · **Confidence:** Medium · **Since:** v0.1

#### What it finds

Two or more mutable accounts of the same program state type in one account list,
with nothing asserting they are different accounts.

#### Why it matters

Nothing stops a caller passing the same address twice. Anchor deserialises it
once per field, into independent in-memory copies, and the handler mutates both.
Whichever is written back last wins, and the other's changes vanish.

In a transfer that means debiting one copy and crediting the other, then
discarding the debit — free money, in a loop.

#### Vulnerable

```rust
#[account(mut, has_one = owner)]
pub from: Account<'info, Balance>,
#[account(mut)]
pub to: Account<'info, Balance>,
```

#### Fixed

```rust
#[account(mut, has_one = owner, constraint = from.key() != to.key() @ Error::SameAccount)]
pub from: Account<'info, Balance>,
```

#### Limits

- **Only mutable accounts count.** Aliasing a read-only account changes nothing.
- The assertion is recognised in constraints **and in the handler**. Drift
  compares keys in the handler for all twelve of its transfer and liquidation
  instructions; checking constraints alone reported every one of them.
- Two accounts with distinct `seeds` cannot collide and are skipped.
- **The comparison need not name the flagged accounts.** Drift rejects
  self-liquidation by comparing the two `User` accounts and never the two
  `UserStats` accounts — it does not need to, because each is tied by a
  constraint to the user it belongs to, so distinct users imply distinct
  statistics. Each account is expanded into everything it stands for and the
  assertion looked for across those. Reading only the flagged pair reported
  four of drift's liquidation instructions.

**Known false positive: aliasing the program deliberately supports.** Drift's
`FillOrder` takes a `filler` and a `user` and permits them to be the same
account — a trader filling their own order — branching on it in
`controller/orders.rs` rather than rejecting it. Wheeltap sees two mutable
`UserStats` accounts with nothing keeping them apart, which is true; whether
the double deserialisation is then handled correctly is a question about the
controller, several calls away. This is the one WT011 finding left on drift and
it is the honest kind: the question is fair, and the answer is out of reach.

#### Suppressing

```rust
// wheeltap:allow(WT011) -- aliasing is idempotent here
```

#### References

- [Solana: duplicate mutable accounts](https://solana.com/developers/courses/program-security/duplicate-mutable-accounts)

---

### WT012 — Allocation in a loop

**Severity:** Low · **Confidence:** Medium · **Since:** v0.1

#### What it finds

`clone`, `to_vec`, `to_owned`, `collect`, or `concat` on a collection-shaped
receiver, inside a `for`, `while`, or `loop` body.

#### Why it matters

Compute units are a hard per-transaction budget, and heap allocation is expensive
relative to nearly everything else a program does. Cloning a collection every
iteration turns a linear pass quadratic, and a program that fits the budget in
testing stops fitting it once an account grows.

Hygiene rather than a vulnerability — hence Low. But an instruction that runs out
of compute cannot execute, and for a liquidation or a settlement that is its own
kind of security problem.

#### Vulnerable

```rust
for index in 0..pool.weights.len() {
    let snapshot = pool.weights.clone();   // every iteration
    ...
}
```

#### Fixed

```rust
let snapshot = pool.weights.clone();
for index in 0..pool.weights.len() { ... }
```

#### Limits

- The receiver must **look like a collection** by name, since there are no types
  (ADR-001). Copying a `Pubkey` in a loop is not an allocation and must not be
  flagged, so a collection with an unhelpful name is missed instead.
- Allocation inside a function *called* from the loop is not seen.

#### Suppressing

```rust
// wheeltap:allow(WT012) -- bounded to a handful of iterations
```

#### References

- [Solana: compute budget](https://solana.com/docs/core/fees#compute-budget)

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
