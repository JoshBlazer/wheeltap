//! Source files and the mapping from a `syn` span back to a place a human can
//! open: file, line, column, and the offending lines themselves.

use std::path::{Path, PathBuf};

use serde::Serialize;

use crate::LineCol;

/// Index of a file within a [`SourceMap`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct FileId(pub usize);

/// A region of source, resolved to human-facing positions.
///
/// Positions are for presentation only and are deliberately excluded from
/// finding identity (ADR-004): a finding that moves down a file is the same
/// finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Location {
    pub file: FileId,
    pub start: LineCol,
    pub end: LineCol,
}

impl Location {
    /// Resolve a span within a known file.
    #[must_use]
    pub fn from_span(file: FileId, span: proc_macro2::Span) -> Self {
        let (start, end) = (span.start(), span.end());
        Self {
            file,
            start: LineCol {
                line: start.line,
                column: start.column + 1,
            },
            end: LineCol {
                line: end.line,
                column: end.column + 1,
            },
        }
    }
}

/// One parsed-or-parseable file, with its text retained for snippets.
#[derive(Debug)]
pub struct SourceFile {
    pub id: FileId,
    /// Path as the scan reached it, for display and for opening the file.
    pub path: PathBuf,
    /// Path relative to the scan root. This is the form that enters finding
    /// identity, so that identities survive the tree being checked out
    /// somewhere else.
    pub relative: PathBuf,
    pub text: String,
    /// Byte offset of the start of each line, so line lookup is a binary
    /// search rather than a rescan.
    line_starts: Vec<usize>,
}

impl SourceFile {
    fn new(id: FileId, path: PathBuf, relative: PathBuf, text: String) -> Self {
        let mut line_starts = vec![0];
        line_starts.extend(text.match_indices('\n').map(|(i, _)| i + 1));
        Self {
            id,
            path,
            relative,
            text,
            line_starts,
        }
    }

    /// The number of lines. A file with no trailing newline still counts its
    /// last line.
    #[must_use]
    pub fn line_count(&self) -> usize {
        self.line_starts.len()
    }

    /// One line of source, without its terminator. Lines are 1-indexed;
    /// out-of-range lines yield `None` rather than panicking.
    #[must_use]
    pub fn line(&self, line: usize) -> Option<&str> {
        let start = *self.line_starts.get(line.checked_sub(1)?)?;
        let end = self
            .line_starts
            .get(line)
            .map_or(self.text.len(), |next| next - 1);
        Some(self.text[start..end.min(self.text.len())].trim_end_matches('\r'))
    }

    /// The lines spanned by a location, joined with newlines.
    ///
    /// This is what a reader sees under a finding, so it is bounded: a span
    /// covering a 400-line function would otherwise print the whole function.
    #[must_use]
    pub fn snippet(&self, at: Location, max_lines: usize) -> String {
        // Clamp to the file first. A span reaching past the end means the
        // snippet stops there, which is not a truncation and must not be
        // marked as one.
        let available = at.end.line.min(self.line_count());
        let last = available.min(at.start.line + max_lines.saturating_sub(1));

        let mut out = String::new();
        for line in at.start.line..=last {
            let Some(text) = self.line(line) else { break };
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(text);
        }
        if available > last {
            out.push_str("\n// ...");
        }
        out
    }
}

/// Every file a scan loaded, indexed by [`FileId`].
#[derive(Debug, Default)]
pub struct SourceMap {
    files: Vec<SourceFile>,
}

impl SourceMap {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a file, returning its id. `root` is the scan root that `relative`
    /// is computed against.
    pub fn add(&mut self, path: PathBuf, root: &Path, text: String) -> FileId {
        let id = FileId(self.files.len());
        let relative = path.strip_prefix(root).unwrap_or(&path).to_path_buf();
        self.files.push(SourceFile::new(id, path, relative, text));
        id
    }

    #[must_use]
    pub fn get(&self, id: FileId) -> &SourceFile {
        &self.files[id.0]
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.files.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    pub fn iter(&self) -> impl Iterator<Item = &SourceFile> {
        self.files.iter()
    }

    /// The path a finding should report, in a form stable across machines.
    #[must_use]
    pub fn display_path(&self, id: FileId) -> String {
        self.get(id).relative.display().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map_with(text: &str) -> (SourceMap, FileId) {
        let mut map = SourceMap::new();
        let id = map.add(
            PathBuf::from("/root/programs/lib.rs"),
            Path::new("/root"),
            text.to_string(),
        );
        (map, id)
    }

    #[test]
    fn relative_paths_are_computed_against_the_scan_root() {
        let (map, id) = map_with("");
        assert_eq!(map.display_path(id), "programs/lib.rs");
    }

    #[test]
    fn lines_are_one_indexed_and_bounds_checked() {
        let (map, id) = map_with("alpha\nbeta\ngamma");
        let file = map.get(id);
        assert_eq!(file.line(1), Some("alpha"));
        assert_eq!(file.line(3), Some("gamma"));
        assert_eq!(file.line(4), None, "past the end yields None, not a panic");
        assert_eq!(file.line(0), None, "line 0 does not exist");
        assert_eq!(file.line_count(), 3);
    }

    #[test]
    fn carriage_returns_are_trimmed() {
        let (map, id) = map_with("alpha\r\nbeta\r\n");
        assert_eq!(map.get(id).line(1), Some("alpha"));
    }

    #[test]
    fn empty_file_has_one_empty_line() {
        let (map, id) = map_with("");
        assert_eq!(map.get(id).line(1), Some(""));
        assert_eq!(map.get(id).line_count(), 1);
    }

    #[test]
    fn snippets_are_bounded_and_marked_when_truncated() {
        let (map, id) = map_with("one\ntwo\nthree\nfour\nfive");
        let at = Location {
            file: id,
            start: LineCol { line: 2, column: 1 },
            end: LineCol { line: 5, column: 1 },
        };
        assert_eq!(map.get(id).snippet(at, 10), "two\nthree\nfour\nfive");
        assert_eq!(map.get(id).snippet(at, 2), "two\nthree\n// ...");
    }

    #[test]
    fn snippet_spanning_past_the_end_stops_cleanly() {
        let (map, id) = map_with("one\ntwo");
        let at = Location {
            file: id,
            start: LineCol { line: 1, column: 1 },
            end: LineCol {
                line: 99,
                column: 1,
            },
        };
        assert_eq!(map.get(id).snippet(at, 10), "one\ntwo");
    }
}
