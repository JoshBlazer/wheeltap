//! Name heuristics.
//!
//! Wheeltap has no type information (ADR-001), so for some questions the only
//! signal available is what the developer called something. That is a real
//! limitation and it is why the rules that lean on it are `confidence: medium`.
//!
//! Both lists below are deliberately **tight rather than broad**. A missed
//! finding costs one vulnerability that a human might still catch; a false
//! positive costs trust in every other finding the tool reports. Where the
//! choice is between the two, these lists choose to miss.

/// Word-parts that mark an account as an authority — something that ought to
/// have authorised the instruction.
const AUTHORITY_WORDS: &[&str] = &[
    "authority",
    "admin",
    "owner",
    "signer",
    "governance",
    "operator",
    "manager",
    "steward",
    "delegate",
    "upgrader",
];

/// Word-parts that mark a value as a balance or quantity of value — the values
/// where silent wrapping means lost or invented funds.
const VALUE_WORDS: &[&str] = &[
    "amount",
    "balance",
    "lamports",
    "supply",
    "reward",
    "share",
    "stake",
    "staked",
    "deposit",
    "borrowed",
    "collateral",
    "liquidity",
    "principal",
    "payout",
    "debt",
];

/// Names that mark a value as an index, length, or size — arithmetic on which
/// is routine and effectively never a balance bug.
const COUNTER_WORDS: &[&str] = &[
    "len",
    "index",
    "idx",
    "count",
    "offset",
    "size",
    "space",
    "cursor",
    "position",
    "capacity",
    "nonce",
    "seed",
    "bump",
    "decimals",
    "slot",
    "timestamp",
];

/// Whether an account name suggests it is an authority.
#[must_use]
pub fn is_authority_like(name: &str) -> bool {
    contains_word(name, AUTHORITY_WORDS)
}

/// Whether an expression mentions something that holds value.
#[must_use]
pub fn mentions_value(text: &str) -> bool {
    contains_word(text, VALUE_WORDS)
}

/// Whether an expression is about counting or positioning rather than value.
#[must_use]
pub fn mentions_counter(text: &str) -> bool {
    contains_word(text, COUNTER_WORDS)
}

/// Whether a whole word from `words` appears in `text`, allowing a plural `s`.
///
/// Two things have to be true at once. Without a boundary check, `share`
/// matches `shareholder_registry` and `owner` matches `downer`. Without the
/// plural, `total_shares` and `pending_rewards` — the forms real code actually
/// uses — are missed. Rust separates words with `_`, and paths with `.` and
/// `::`, so those plus the ends of the string are the boundaries that matter.
fn contains_word(text: &str, words: &[&str]) -> bool {
    let lower = text.to_ascii_lowercase();
    words.iter().any(|word| {
        lower.match_indices(word).any(|(start, matched)| {
            let before = lower[..start].chars().next_back();
            let rest = &lower[start + matched.len()..];
            // Accept a trailing plural, but only when a boundary follows it, so
            // `share` still does not match `shares_outstanding_flag_set`.
            let after = rest.chars().next();
            // Only counts when an `s` is actually there and a boundary follows
            // it. Asking whether the character after a non-existent `s` is a
            // boundary answers "yes" and matches everything.
            let plural = rest
                .strip_prefix('s')
                .is_some_and(|beyond| is_boundary(beyond.chars().next()));

            is_boundary(before) && (is_boundary(after) || plural)
        })
    })
}

/// Whether a character ends a word, treating "no character" as a boundary.
fn is_boundary(ch: Option<char>) -> bool {
    match ch {
        None => true,
        Some(c) => !c.is_ascii_alphanumeric(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognises_authority_accounts() {
        assert!(is_authority_like("authority"));
        assert!(is_authority_like("admin"));
        assert!(is_authority_like("vault_authority"));
        assert!(is_authority_like("update_authority"));
        assert!(is_authority_like("pool_owner"));
    }

    #[test]
    fn does_not_treat_ordinary_accounts_as_authorities() {
        for name in [
            "vault",
            "mint",
            "treasury",
            "maker",
            "taker",
            "destination",
            "token_program",
            "system_program",
            "offer",
            "position",
        ] {
            assert!(!is_authority_like(name), "{name} is not an authority");
        }
    }

    /// The boundary rule, which is what keeps the lists from over-matching.
    #[test]
    fn words_match_only_at_boundaries() {
        assert!(!is_authority_like("downer"), "`owner` inside `downer`");
        assert!(!mentions_value("sharegrid"), "`share` inside `sharegrid`");
        assert!(mentions_value("share_count"));
        assert!(
            mentions_value("total_shares"),
            "plural forms are what real code uses"
        );
        assert!(mentions_value("pending_rewards"));
        assert!(
            !mentions_value("shareholder_registry"),
            "plural must still respect boundaries"
        );
    }

    #[test]
    fn recognises_values_and_counters() {
        assert!(mentions_value("stake.amount"));
        assert!(mentions_value("pool.total_staked"));
        assert!(mentions_value("self.pending_rewards"));
        assert!(!mentions_value("i"));
        assert!(!mentions_value("entries"));

        assert!(mentions_counter("entries.len()"));
        assert!(mentions_counter("cursor"));
        assert!(mentions_counter("ACCOUNT_SIZE"));
        assert!(!mentions_counter("stake.amount"));
        // Constants like ANCHOR_DISCRIMINATOR are excluded by carrying no
        // value word, not by being recognised as counters.
        assert!(!mentions_value("ANCHOR_DISCRIMINATOR + 8 * MAX_ENTRIES"));
    }
}
