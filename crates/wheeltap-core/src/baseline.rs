//! Baselines: reporting only what is new.
//!
//! Adopting a linter on an existing codebase has a chicken-and-egg problem. The
//! first run reports hundreds of findings, nobody has time to fix them, so the
//! build cannot be made to fail on findings — and a check that never fails is a
//! check nobody reads.
//!
//! A baseline resolves it. Freeze today's findings, fail the build only on new
//! ones, and the existing debt gets paid down separately instead of blocking
//! the gate.
//!
//! This only works because finding identity is content-addressed
//! (see [`crate::finding`]). If identity were positional, adding an import at
//! the top of a file would make every finding below it "new", the baseline
//! would be noise within a day, and the team would go back to ignoring the tool.

use std::collections::BTreeSet;

use serde::Deserialize;

use crate::finding::{Finding, FindingId};

/// The identities recorded in a previous run.
#[derive(Debug, Default, Clone)]
pub struct Baseline {
    ids: BTreeSet<FindingId>,
}

/// Just enough of the JSON report shape to read identities back.
///
/// Deliberately minimal: a baseline written by an older version, with fields
/// this one does not know, still loads. Everything except the identities is
/// presentation, and re-reading it would only create ways to fail.
#[derive(Debug, Deserialize)]
struct BaselineFile {
    #[serde(default)]
    findings: Vec<BaselineFinding>,
}

#[derive(Debug, Deserialize)]
struct BaselineFinding {
    id: FindingId,
}

impl Baseline {
    /// Read a baseline from the JSON of a previous run.
    ///
    /// # Errors
    ///
    /// Returns a `serde_json` error if the file is not a Wheeltap JSON report.
    pub fn parse(json: &str) -> Result<Self, serde_json::Error> {
        let file: BaselineFile = serde_json::from_str(json)?;
        Ok(Self {
            ids: file.findings.into_iter().map(|f| f.id).collect(),
        })
    }

    /// Load a baseline from a path.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read or is not a Wheeltap report.
    pub fn load(path: &std::path::Path) -> Result<Self, BaselineError> {
        let text = std::fs::read_to_string(path).map_err(|source| BaselineError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&text).map_err(|source| BaselineError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.ids.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    #[must_use]
    pub fn contains(&self, id: &FindingId) -> bool {
        self.ids.contains(id)
    }

    /// Drop findings the baseline already knows about.
    #[must_use]
    pub fn filter_new(&self, findings: Vec<Finding>) -> Vec<Finding> {
        findings
            .into_iter()
            .filter(|finding| !self.contains(&finding.id))
            .collect()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BaselineError {
    #[error("could not read baseline {path}: {source}")]
    Read {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    #[error("{path} is not a Wheeltap JSON report: {source}")]
    Parse {
        path: std::path::PathBuf,
        source: serde_json::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    const REPORT: &str = r#"{
        "schema": "1.0",
        "findings": [
            { "id": "aaaaaaaaaaaaaaaa", "rule": "WT001" },
            { "id": "bbbbbbbbbbbbbbbb", "rule": "WT003" }
        ]
    }"#;

    #[test]
    fn reads_identities_from_a_report() {
        let baseline = Baseline::parse(REPORT).expect("parse");
        assert_eq!(baseline.len(), 2);
        assert!(baseline.contains(&FindingId("aaaaaaaaaaaaaaaa".into())));
        assert!(!baseline.contains(&FindingId("cccccccccccccccc".into())));
    }

    #[test]
    fn an_empty_report_is_an_empty_baseline() {
        assert!(
            Baseline::parse(r#"{"findings": []}"#)
                .expect("parse")
                .is_empty()
        );
        assert!(Baseline::parse("{}").expect("parse").is_empty());
    }

    /// A baseline written by a different version must still load. Only the
    /// identities are read, so extra or missing fields do not matter.
    #[test]
    fn unknown_fields_are_ignored() {
        let future = r#"{
            "schema": "9.0",
            "somethingNew": true,
            "findings": [{ "id": "aaaaaaaaaaaaaaaa", "unexpected": [1, 2, 3] }]
        }"#;
        assert_eq!(Baseline::parse(future).expect("parse").len(), 1);
    }

    #[test]
    fn a_file_that_is_not_a_report_is_an_error() {
        assert!(Baseline::parse("not json").is_err());
        assert!(Baseline::parse(r#"{"findings": "wrong shape"}"#).is_err());
    }
}
