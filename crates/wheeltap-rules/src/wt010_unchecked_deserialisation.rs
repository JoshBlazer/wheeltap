//! WT010 — Unchecked deserialisation.
//!
//! Anchor writes an eight-byte discriminator at the front of every account it
//! owns, derived from the type name, and checks it on the way back in. The
//! `*_unchecked` variants skip that check.
//!
//! Skipping it means any account owned by the program can be read as any of its
//! types. Pass a `UserProfile` where a `Config` is expected and the bytes are
//! reinterpreted — typically leaving the attacker's key where the admin key
//! should have been. The owner check passes, because the owner really is this
//! program; only the discriminator would have caught it.

use wheeltap_core::model::ProgramContext;
use wheeltap_core::{Confidence, Detector, Finding, RuleMetadata, Severity};

use crate::body;

pub struct UncheckedDeserialisation;

const METADATA: RuleMetadata = RuleMetadata {
    id: "WT010",
    name: "Unchecked deserialisation",
    severity: Severity::High,
    confidence: Confidence::High,
    description: "Account data is deserialised without checking the discriminator",
    remediation: "Use `try_deserialize`, which verifies the discriminator, or the typed \
                  `Account<'info, T>` which does it before the handler runs. The `_unchecked` \
                  variants are for accounts you have just created and know the layout of.",
    references: &[
        "https://www.anchor-lang.com/docs/account-types",
        "https://github.com/coral-xyz/sealevel-attacks",
    ],
};

/// Deserialisation entry points that skip the discriminator.
const UNCHECKED_CALLS: &[&str] = &[
    "try_deserialize_unchecked",
    "try_from_slice_unchecked",
    "try_from_unchecked",
    "deserialize_unchecked",
    "load_unchecked",
];

impl Detector for UncheckedDeserialisation {
    fn rule_id(&self) -> &'static str {
        METADATA.id
    }

    fn metadata(&self) -> RuleMetadata {
        METADATA
    }

    fn check(&self, ctx: &ProgramContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for handler in &ctx.handlers {
            let body = body::text(handler);

            for call in UNCHECKED_CALLS {
                if !body.contains(call) {
                    continue;
                }

                findings.push(ctx.finding(
                    &METADATA,
                    handler.location,
                    &handler.item_path,
                    format!(
                        "`{}` calls `{call}`, which does not verify the account discriminator. \
                         Any account owned by this program can then be read as this type, \
                         regardless of what it actually is.",
                        handler.name
                    ),
                ));
                break;
            }
        }

        findings
    }
}
