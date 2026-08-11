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

## Template

Each entry below follows this shape.

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
