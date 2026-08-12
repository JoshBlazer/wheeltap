//! Suppression: telling Wheeltap that a finding has been considered and
//! dismissed.
//!
//! A security tool without suppression gets switched off. There is always a
//! finding somewhere that is wrong, or right but accepted, and if the only way
//! to silence it is to stop running the tool then that is what happens.
//!
//! Two mechanisms, per build spec §4.4:
//!
//! - **Inline**, next to the code, where the reason lives with the thing it
//!   explains and travels with it through refactors.
//! - **Configured**, in `wheeltap.toml`, for whole rules or paths — adopting the
//!   tool on a large codebase, or exempting vendored directories.
//!
//! Both require a justification. An unexplained suppression is a finding that
//! was hidden rather than answered, so an inline allow without a `--` reason is
//! honoured and *warned about*: refusing it would push people back to deleting
//! the scan.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use crate::diag::Diagnostic;
use crate::finding::{Finding, Severity};
use crate::source::{FileId, SourceMap};

/// The marker that introduces an inline suppression.
const MARKER: &str = "wheeltap:allow";

/// One inline `// wheeltap:allow(WTnnn) -- reason` comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InlineAllow {
    /// Line the comment appears on, 1-indexed.
    pub line: usize,
    /// Rules named in the parentheses.
    pub rules: Vec<String>,
    /// Text after `--`, if any.
    pub justification: Option<String>,
}

/// Everything in a `wheeltap.toml`.
#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub suppress: Suppress,
    /// Per-rule severity overrides: `WT003 = "medium"`.
    #[serde(default)]
    pub severity: BTreeMap<String, Severity>,
}

#[derive(Debug, Default, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Suppress {
    /// Rules switched off entirely.
    #[serde(default)]
    pub rules: Vec<String>,
    /// Glob patterns; findings in matching files are dropped.
    #[serde(default)]
    pub paths: Vec<String>,
}

impl Config {
    /// Parse a configuration file.
    ///
    /// # Errors
    ///
    /// Returns the TOML error, including unknown keys — a typo in a suppression
    /// rule silently switching nothing off is precisely the failure this
    /// prevents.
    pub fn parse(text: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(text)
    }

    /// Load `wheeltap.toml` from a directory, if it exists.
    pub fn load(dir: &Path) -> Result<Option<Self>, ConfigError> {
        let path = dir.join("wheeltap.toml");
        if !path.is_file() {
            return Ok(None);
        }
        let text = std::fs::read_to_string(&path).map_err(|source| ConfigError::Read {
            path: path.clone(),
            source,
        })?;
        Self::parse(&text)
            .map(Some)
            .map_err(|source| ConfigError::Parse { path, source })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("could not read {path}: {source}")]
    Read {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    #[error("could not parse {path}: {source}")]
    Parse {
        path: std::path::PathBuf,
        source: toml::de::Error,
    },
}

/// Find every inline allow comment in a source file.
///
/// Scans text rather than the AST, because a comment is not in the AST. That
/// also means a `wheeltap:allow` inside a string literal counts, which is a
/// theoretical false suppression nobody will hit by accident.
#[must_use]
pub fn inline_allows(text: &str) -> Vec<InlineAllow> {
    let mut allows = Vec::new();

    for (index, line) in text.lines().enumerate() {
        let Some(at) = line.find(MARKER) else {
            continue;
        };
        let rest = &line[at + MARKER.len()..];

        // `(WT001, WT002)` — anything up to the closing paren.
        let rules: Vec<String> = rest
            .strip_prefix('(')
            .and_then(|rest| rest.split_once(')'))
            .map(|(inside, _)| {
                inside
                    .split(',')
                    .map(|rule| rule.trim().to_string())
                    .filter(|rule| !rule.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        if rules.is_empty() {
            continue;
        }

        let justification = rest
            .split_once("--")
            .map(|(_, reason)| reason.trim().to_string())
            .filter(|reason| !reason.is_empty());

        allows.push(InlineAllow {
            line: index + 1,
            rules,
            justification,
        });
    }

    allows
}

/// Decides which findings survive.
pub struct Suppressor {
    config: Config,
    /// Inline allows per file, keyed by the line they sit on.
    inline: BTreeMap<FileId, Vec<InlineAllow>>,
    globs: Vec<globset::GlobMatcher>,
}

impl Suppressor {
    /// Build a suppressor for a scan.
    #[must_use]
    pub fn new(config: Config, sources: &SourceMap) -> Self {
        let inline = sources
            .iter()
            .map(|file| (file.id, inline_allows(&file.text)))
            .filter(|(_, allows)| !allows.is_empty())
            .collect();

        let globs = config
            .suppress
            .paths
            .iter()
            .filter_map(|pattern| Some(globset::Glob::new(pattern).ok()?.compile_matcher()))
            .collect();

        Self {
            config,
            inline,
            globs,
        }
    }

    /// Apply suppression and severity overrides to a set of findings.
    ///
    /// Returns the survivors, and diagnostics for suppressions that were
    /// accepted but not explained.
    #[must_use]
    pub fn apply(&self, findings: Vec<Finding>) -> (Vec<Finding>, Vec<Diagnostic>) {
        let mut kept = Vec::with_capacity(findings.len());
        let mut diagnostics = Vec::new();

        for mut finding in findings {
            if self.config.suppress.rules.iter().any(|r| r == finding.rule) {
                continue;
            }
            if self.globs.iter().any(|glob| glob.is_match(&finding.file)) {
                continue;
            }

            if let Some(allow) = self.inline_allow_for(&finding) {
                if allow.justification.is_none() {
                    diagnostics.push(
                        Diagnostic::warning(
                            &finding.file,
                            format!(
                                "`{}` suppression for {} has no justification; \
                                 write `-- why` after the rule so the next reader knows",
                                MARKER, finding.rule
                            ),
                        )
                        .at_line(allow.line),
                    );
                }
                continue;
            }

            if let Some(severity) = self.config.severity.get(finding.rule) {
                finding.severity = *severity;
            }

            kept.push(finding);
        }

        (kept, diagnostics)
    }

    /// The inline allow covering a finding, if any.
    ///
    /// A comment counts when it is on the finding's own line, or on one of the
    /// lines immediately above it — skipping over attributes, doc comments, and
    /// other comments, because that is where the interesting code sits:
    ///
    /// ```ignore
    /// /// CHECK: validated by the CPI callee
    /// // wheeltap:allow(WT001) -- authority signs in the callee
    /// #[account(mut)]
    /// pub authority: AccountInfo<'info>,
    /// ```
    fn inline_allow_for(&self, finding: &Finding) -> Option<&InlineAllow> {
        let allows = self.inline.get(&finding.location.file)?;
        let covers = |allow: &&InlineAllow| {
            allow
                .rules
                .iter()
                .any(|rule| rule == finding.rule || rule == "*")
        };

        allows
            .iter()
            .filter(covers)
            .find(|allow| finding.suppression_lines.contains(&allow.line))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_allow_with_a_justification() {
        let allows = inline_allows("// wheeltap:allow(WT001) -- signs in the CPI callee\n");
        assert_eq!(
            allows,
            [InlineAllow {
                line: 1,
                rules: vec!["WT001".into()],
                justification: Some("signs in the CPI callee".into()),
            }]
        );
    }

    #[test]
    fn parses_several_rules_in_one_comment() {
        let allows = inline_allows("// wheeltap:allow(WT001, WT002) -- both reviewed");
        assert_eq!(allows[0].rules, ["WT001", "WT002"]);
    }

    #[test]
    fn an_allow_without_a_justification_still_parses() {
        // It is honoured and warned about. Refusing it would push people back
        // to deleting the scan, which helps nobody.
        let allows = inline_allows("// wheeltap:allow(WT003)");
        assert_eq!(allows[0].rules, ["WT003"]);
        assert!(allows[0].justification.is_none());
    }

    #[test]
    fn text_without_rules_is_not_a_suppression() {
        assert!(inline_allows("// wheeltap:allow -- no rule named").is_empty());
        assert!(inline_allows("// wheeltap:allow() -- empty").is_empty());
        assert!(inline_allows("// nothing to see").is_empty());
    }

    #[test]
    fn line_numbers_are_one_indexed() {
        let allows = inline_allows("fn a() {}\n\n// wheeltap:allow(WT001) -- reason\n");
        assert_eq!(allows[0].line, 3);
    }

    #[test]
    fn config_parses_suppression_and_severity_overrides() {
        let config = Config::parse(
            r#"
            [suppress]
            rules = ["WT007"]
            paths = ["programs/legacy/**"]

            [severity]
            WT003 = "medium"
            "#,
        )
        .expect("valid config");

        assert_eq!(config.suppress.rules, ["WT007"]);
        assert_eq!(config.suppress.paths, ["programs/legacy/**"]);
        assert_eq!(config.severity.get("WT003"), Some(&Severity::Medium));
    }

    #[test]
    fn an_empty_config_is_valid() {
        let config = Config::parse("").expect("empty is valid");
        assert!(config.suppress.rules.is_empty());
        assert!(config.severity.is_empty());
    }

    /// A typo that silently switches nothing off is worse than an error.
    #[test]
    fn unknown_keys_are_rejected() {
        assert!(
            Config::parse("[supress]\nrules = []").is_err(),
            "typo in section"
        );
        assert!(
            Config::parse("[suppress]\nrule = [\"WT001\"]").is_err(),
            "typo in key"
        );
    }
}
