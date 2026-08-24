# Validation against published audits

Wheeltap was run against [drift](https://github.com/velocity-exchange/protocol-v2),
a Solana perpetuals protocol with two published third-party security audits, and
its findings compared against theirs.

## The result, stated plainly

**Of the 30 findings in the two reports, Wheeltap reproduces one, and only in
the weakest sense.** It reports an instance of the *class* Trail of Bits raised
in TOB-DRIFT-11 (inconsistent use of checked arithmetic) at a different site
from the one they cite. It finds none of the other 29.

That is the expected result, and this document is mostly about why. A syntactic
analyser and a six-person-week audit are not looking for the same things, and
the interesting question is not the score but whether the boundary between them
is where the tool claims it is.

The second result is that **the exercise made the tool better**. Comparing
Wheeltap's output against the audits exposed two false-positive classes with a
common cause, and fixing them cut findings on drift from 22 to 11 with no loss
on the fixture corpus. That is written up at the end.

## Method

| | |
|---|---|
| Target | `velocity-exchange/protocol-v2`, `programs/drift`, commit `13e8e9b`, vendored at `fixtures/corpus/drift` |
| Size | 116 files, 73,011 lines, 262 handlers, 155 account structs |
| Audit 1 | Neodyme AG, May 2024. SHA-256 `b53102cc84db7928…` |
| Audit 2 | Trail of Bits, February 2023. SHA-256 `a32979f57b9587da…` |
| Wheeltap | v0.1.0, all twelve rules, default thresholds |

Both reports are public in `drift-labs/audits`.

### The timeline problem, and what was done about it

The vendored commit is much newer than either audit, so most findings are fixed
in the code Wheeltap scanned. Comparing against fixed code would make a silent
tool look correct.

So for every finding close enough to Wheeltap's scope to be worth testing, the
**pre-fix revision named in the report was fetched and scanned separately**.
Where this document says Wheeltap missed something, that means it reported
nothing on the vulnerable code, not merely nothing on the fixed code. Those
runs are recorded below and the shapes are kept as fixtures in
`fixtures/known_gaps/`.

## The two audits

Neodyme found 10 issues: 1 critical, 2 medium, 4 low, 3 informational.

| ID | Title | Severity |
|---|---|---|
| CR-01 | Flat keeper reward can be used to bankrupt an attacker-controlled user and steal quote | Critical |
| MD-01 | Possible to open risk-increasing orders while violating initial margin requirement | Medium |
| MD-02 | Circumventing pausing of withdraw and deposit, and similar restrictions | Medium |
| LO-01 | External users can block admin from adding new Serum markets | Low |
| LO-02 | Whitelist mint check is easily circumvented | Low |
| LO-03 | Surge pricing for subaccounts is ineffective | Low |
| LO-04 | Possible to enter spot margin trading when it is disabled | Low |
| IN-01 | Admin can pass invalid oracle accounts | Info |
| IN-02 | An attacker can prevent deletion of all '0' subaccounts for all users | Info |
| IN-03 | Truncating casts | Info |

Trail of Bits found 20, one Medium and the rest Informational or Undetermined.
Half of them are about engineering practice rather than about a vulnerability —
build instructions, test coverage, code duplication, opaque test constants, and
so on. The ten bearing on security are 7, 8, 11, 12, 13, 14, 16, 18, 19 and 20.

### Where all thirty went

| Outcome | Count | Findings |
|---|---:|---|
| Reproduced, weakly | 1 | TOB-11 |
| Missed — economic and protocol reasoning | 11 | ND CR-01, MD-01, MD-02, LO-01, LO-02, LO-03, LO-04, IN-02; TOB 4, 14, 20 |
| Missed — interprocedural dataflow | 1 | ND IN-01 |
| Missed — accounts outside the declarative model | 1 | TOB 8 |
| Missed — whole-program consistency | 2 | TOB 12, 13 |
| Missed — engineering and language practice | 10 | TOB 1, 2, 3, 5, 6, 7, 9, 10, 15, 17 |
| Missed — type and cast reasoning | 3 | ND IN-03; TOB 16, 19 |
| Missed — a rule Wheeltap could have but does not | 1 | TOB 18 |
| **Total** | **30** | |

## What Wheeltap caught

### TOB-DRIFT-11 — inconsistent use of checked arithmetic (Undetermined, **unresolved**)

Trail of Bits observed that drift mixes checked and unchecked arithmetic, and
cited `num_perp_liabilities += 1` in `math/margin.rs`. They recommended
`#![deny(clippy::integer_arithmetic)]` at the crate root. Their fix review
records the finding as unresolved, and it still is.

Wheeltap reports one site of this class:

```
WT003 high src/instructions/if_staker.rs:346
  `transfer_config.current_epoch_transfer += shares` in
  `handle_transfer_protocol_if_shares` uses `+=` on a value that holds funds.
```

Two honest qualifications:

- **It is a different site.** The one Trail of Bits cite is a counter, and
  WT003 deliberately excludes counters — flagging every `+= 1` in a 73,000-line
  program is how a rule gets switched off. WT003 fires only on arithmetic over
  names that look like they hold value.
- **Wheeltap's site is not exploitable either.** The line above it calls
  `transfer_config.validate_transfer(shares)?`, which proves
  `shares < max_transfer_per_epoch - current_epoch_transfer`, so the addition
  cannot overflow. The bound is established in a method one call away, which is
  precisely the boundary ADR-001 draws. Counted strictly, this is a false
  positive that happens to land inside a real audit finding's class.

One thing did check out exactly: WT003's premise is that unchecked arithmetic
wraps silently in release builds, which is only true if `overflow-checks` is
off. Drift's workspace manifest sets `lto` and `codegen-units` under
`[profile.release]` and does not set `overflow-checks`. Verified rather than
assumed.

## What Wheeltap missed, and what each miss would need

### 1. Economic and protocol reasoning — 11 findings

Neodyme CR-01, MD-01, MD-02, LO-01, LO-02, LO-03, LO-04, IN-02; Trail of Bits
4, 14, 20.

The critical finding is the clearest case. A flat keeper reward, paid per
crank from the user's account, can be driven against a position small enough
that the rewards bankrupt it, leaving bad debt the attacker collects. Every
line involved is individually correct. The vulnerability is in the *interaction*
between a fee schedule, a liquidation threshold, and an attacker who controls
both sides.

Neodyme's LO-02 is the same shape in miniature: the whitelist check verifies
that the caller owns a token account of the right mint, and never that it holds
any tokens. Every check named in the code is performed. The one that mattered
was not written, and knowing that requires knowing what a whitelist is for.

No syntactic analyser reaches this, and none should claim to. It needs a model
of what the protocol is *for*. This is the largest group of what the audits
found, and the bulk of what an audit is worth paying for.

### 2. Interprocedural dataflow — ND-DFT1-IN-01

An `oracle: AccountInfo` with no owner constraint, whose price is read and
written into a market. This is WT002's exact shape — an unvalidated account
whose data is deserialised — and WT002 says nothing.

**Verified, not inferred.** `admin.rs` at `ac4bfd00e92105adba9809bcf1dfc50b3eb278ae`,
the revision Neodyme cite, before the fix:

```console
$ wheeltap scan admin.rs
{"summary": {"files_scanned": 1, "lines_scanned": 2816, "findings": 0}}
```

Zero. The reason is that the read is `get_pyth_price(&ctx.accounts.oracle, …)`,
so the handler body contains no dereference for WT002 to find. **WT002's silence
about this account carries no information**: it was silent before the fix and
silent after it, for the same reason.

Catching it needs a summary of which functions dereference an `AccountInfo`'s
data, propagated to callers — the first genuinely interprocedural analysis the
tool would have. Kept as `fixtures/known_gaps/ND_DFT1_IN_01_oracle_read_in_helper/`.

The `/// CHECK:` comment on that account read `checked in initialize_perp_market`,
naming a validation that did not happen. Anchor requires a comment on every
`AccountInfo`, so its presence proves only that the compiler insisted.

### 3. Accounts outside the declarative model — TOB-DRIFT-8

`handle_place_and_take_perp_order` pulled `maker` and `maker_stats` off
`ctx.remaining_accounts` and used them together with nothing checking they
belonged to the same trader.

**Verified the same way.** `optional_accounts.rs` and `user.rs` at
`8e4f15771cce51f6c74628c19b74c5e83c51ed69`, the commit before the fix: zero
findings in both.

The miss is structural. Every account-validation detector starts from
`#[derive(Accounts)]`; these accounts are never in one. `remaining_accounts` is
Anchor's escape hatch from the declarative model, and everything the model reads
goes with it. Kept as `fixtures/known_gaps/TOB_DRIFT_8_remaining_accounts/`.

This one stings, because WT005 exists to find exactly this class of unenforced
relationship — and on the *fixed* code it reports the `user`/`user_stats` pair
in the very same instruction. It asks the right question about the accounts it
can see, and cannot see the ones the finding is about.

### 4. Whole-program consistency — TOB-DRIFT-12, 13

"The exchange status check is present here and missing there" is a question
about all instructions at once. Wheeltap's rules examine one instruction at a
time by construction; a finding of the form *this one is unlike the other
fourteen* needs a notion of what the fourteen do.

This is the most plausible direction for a future rule of the three, and the
least likely to be precise.

### 5. Engineering and language practice — 10 findings

Trail of Bits 1, 2, 3, 5, 6, 7, 9, 10, 15, 17: build instructions, test
coverage, `audit.toml`, loose size coupling, the experimental status of
Anchor's zero-copy feature, hardcoded indices into account data, panics used
for error handling, test code reachable in production, code duplication, opaque
test constants.

None is a vulnerability and none is in scope for a rule. Two are the kind of
thing Clippy already answers better than a bespoke detector would. Listed in
full because leaving them out would flatter the comparison — they are a third
of what a real audit spends its time on.

### 6. Type and cast reasoning — ND-DFT1-IN-03, TOB-DRIFT-16, 19

Truncating casts, inconsistent integer widths, unaligned references. All
syntactically visible and none covered by a rule Wheeltap has. A `WT0xx —
truncating cast` rule is a real possibility; `as` conversions that narrow are
findable, and the false-positive rate would be the whole question.

### The one it could have caught — TOB-DRIFT-18

> The context definition for the `initialize` instruction defines a
> `drift_signer` account. However, this account is not used by the instruction.

An account declared in a context and never referenced by the handler is purely
syntactic: the model already holds both sides. Trail of Bits marked it
Informational and drift left it unresolved — and it is **still live** in the
scanned commit; `Initialize` declares `drift_signer` and `handle_initialize`
never mentions it.

Wheeltap does not have this rule. It is the single strongest candidate for the
next version, and the exercise is what identified it.

## What Wheeltap flagged that the auditors did not

Eleven findings on 73,011 lines. Every one triaged by hand:

| Rule | Where | Verdict |
|---|---|---|
| WT003 | `if_staker.rs:346` | **False positive** — bounded by `validate_transfer` one line above. Inside TOB-DRIFT-11's class. |
| WT005 ×7 | `keeper.rs`, `user.rs` | **False positives**, one class — see below |
| WT011 | `FillOrder.filler_stats` | **Unresolved** — a fair question with an out-of-reach answer |
| WT012 ×2 | `handle_begin_swap`, `handle_begin_lp_swap` | **True positives**, Low |

### The seven WT005 findings: permissionless instructions

All seven are instructions where a signer named `authority` is the *caller*
rather than the account's owner — `UpdateUserFuelBonus` and
`SetUserStatusToBeingLiquidated` are keeper cranks, and anyone may deposit into
another user's account. WT005 sees a stored `authority: Pubkey` and an
`authority` in the same instruction with nothing tying them, which is true, and
concludes a relationship was intended, which is not.

Separating "the signer must own this" from "anyone may call this" is a question
about intent. It is not visible in the syntax and this rule will keep getting it
wrong; the suppression is `// wheeltap:allow(WT005) -- permissionless crank`.

### The WT011 finding: an alias the program permits on purpose

`FillOrder` takes a `filler` and a `user`, each with a `UserStats` account, and
nothing keeps them apart. Drift permits a trader to fill their own order and
branches on it in `controller/orders.rs:1167`:

```rust
let is_filler_taker = user_key == filler_key;
```

So the aliasing is deliberate. Whether the resulting double deserialisation is
handled correctly is a question about a controller several calls away.

This is the most useful finding of the eleven, and the honest label is
*unresolved* rather than false positive. The tool asked a fair question about
code a reviewer would have to think about, and cannot answer it.

### The two WT012 findings: real, and small

```rust
for ix in instructions {
    let mut whitelisted_programs = WHITELISTED_SWAP_PROGRAMS.to_vec();
```

The vector is rebuilt on every iteration. Compute units are a hard
per-transaction budget on Solana, so this is a genuine if minor waste, in code
neither audit remarks on. Severity Low, correctly.

## What the comparison changed

Two false-positive classes, both with the same cause, found by asking why
Wheeltap disagreed with the auditors about drift.

**WT005 read one constraint at a time.** Drift ties a `user_stats` to the
`authority` that signs for it in two steps:

```rust
#[account(mut, constraint = can_sign_for_user(&user, &authority)?)]
pub user: AccountLoader<'info, User>,
#[account(mut, constraint = is_stats_for_user(&user, &user_stats)?)]
pub user_stats: AccountLoader<'info, UserStats>,
```

Neither constraint names both `user_stats` and `authority`, so a check reading
them singly finds nothing — ten times across drift. The relationship holds
transitively. And the check it could not see is **the one Trail of Bits asked
drift to add in TOB-DRIFT-8**: the tool was reporting the fix to an audit
finding as a missing check.

**WT011 looked for a comparison between the accounts it had flagged.** Drift
rejects self-liquidation by comparing the two `User` accounts, never the two
`UserStats` accounts — it does not need to, since each is tied to the user it
belongs to. Four more.

Constraints now build a link graph over the accounts in an instruction, walked
transitively; WT005 asks whether two accounts are tied together and WT011
whether they are kept apart. Both fixes were written fixture-first, with the
drift shapes reproduced in `fixtures/safe/` before either rule changed.

| | Before | After |
|---|---|---|
| Findings on drift | 22 | **11** |
| WT005 | 15 | **7** |
| WT011 | 4 | **1** |
| False positives on `fixtures/safe/` | 0 | **0** |
| Findings on the vulnerable fixtures | 17 | **17** |

## What this exercise says about the tool

The audits found things Wheeltap cannot find, and the gap is not one of
maturity. Twelve of the thirty findings require reasoning about what the
protocol is *for*. Nothing in the design gets there, and a version of this
document that implied otherwise would be worth less than one that says so.

What the comparison does support:

- **The boundary is where the documentation says it is.** Every miss traced to
  a limit already written down — the intraprocedural boundary of ADR-001, or
  the account model that starts at `#[derive(Accounts)]`. None was a surprise.
- **Silence is not evidence.** WT002 said nothing about the unchecked oracle
  before the fix and nothing after it. A clean scan means the rules found
  nothing, which is a much smaller claim than "there is nothing there", and
  `docs/DETECTORS.md` records for each rule what it cannot see.
- **The signal-to-noise is defensible at this size.** Eleven findings on 73,011
  lines of production DeFi, of which two are true, one is a fair open question,
  and eight are false — with every one triaged here and in
  `docs/BENCHMARKS.md`. A reviewer can read the whole list in a sitting, which
  is the property that decides whether a tool stays in CI.
- **The tool is a filter, not an audit.** It runs in half a second on a
  codebase that took six person-weeks to review. Those are different
  activities, and the honest claim is that this one catches a class of mistake
  cheaply enough to run on every pull request.

The most useful single output of this exercise was not a finding. It was
discovering that Wheeltap was reporting drift's *fix* to TOB-DRIFT-8 as a
missing check — which is the kind of thing only a comparison against real,
reviewed code will tell you.
