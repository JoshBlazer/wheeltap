//! Diagnostics about the scan itself, as distinct from findings about the code.
//!
//! Build spec invariant 1: the tool never panics on any input, and parse
//! failures degrade to warnings. A file Wheeltap cannot read is a gap in
//! coverage the user needs to be told about — silently skipping it would let a
//! scan report "clean" on code it never looked at.

use std::path::{Path, PathBuf};

use serde::Serialize;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// The scan continued, but this file or region was not analysed.
    Warning,
    /// The scan could not proceed at all.
    Error,
}

/// Something that went wrong while loading or parsing, not while analysing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Diagnostic {
    pub level: Level,
    pub path: PathBuf,
    /// Line, where the underlying error knows one.
    pub line: Option<usize>,
    pub message: String,
}

impl Diagnostic {
    pub fn warning(path: impl AsRef<Path>, message: impl Into<String>) -> Self {
        Self {
            level: Level::Warning,
            path: path.as_ref().to_path_buf(),
            line: None,
            message: message.into(),
        }
    }

    #[must_use]
    pub fn at_line(mut self, line: usize) -> Self {
        self.line = Some(line);
        self
    }
}

impl std::fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let level = match self.level {
            Level::Warning => "warning",
            Level::Error => "error",
        };
        write!(f, "{level}: {}", self.path.display())?;
        if let Some(line) = self.line {
            write!(f, ":{line}")?;
        }
        write!(f, ": {}", self.message)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warnings_render_with_a_line_when_one_is_known() {
        let d = Diagnostic::warning("programs/lib.rs", "expected `}`").at_line(42);
        assert_eq!(d.to_string(), "warning: programs/lib.rs:42: expected `}`");
    }

    #[test]
    fn warnings_render_without_a_line_when_none_is_known() {
        let d = Diagnostic::warning("programs/lib.rs", "not valid UTF-8");
        assert_eq!(d.to_string(), "warning: programs/lib.rs: not valid UTF-8");
    }
}
