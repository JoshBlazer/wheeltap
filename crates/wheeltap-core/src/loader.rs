//! Discovering Rust source and parsing it into ASTs.
//!
//! Two rules govern this module, both from the build spec:
//!
//! - A file that fails to parse produces a warning and the run continues. One
//!   unparseable file must never cost the user the other ninety-nine.
//! - Discovery order is sorted, so that two runs over identical input produce
//!   identical output (invariant 4).

use std::path::{Path, PathBuf};

use ignore::WalkBuilder;

use crate::diag::Diagnostic;
use crate::source::{FileId, SourceMap};

/// A file that parsed. Files that did not are in `diagnostics` instead.
#[derive(Debug)]
pub struct ParsedFile {
    pub id: FileId,
    pub ast: syn::File,
}

/// Everything a scan loaded from disk.
#[derive(Debug, Default)]
pub struct Load {
    /// The directory paths are reported relative to.
    pub root: PathBuf,
    pub sources: SourceMap,
    pub parsed: Vec<ParsedFile>,
    pub diagnostics: Vec<Diagnostic>,
}

impl Load {
    /// Files that were read but could not be parsed.
    #[must_use]
    pub fn unparsed_count(&self) -> usize {
        self.sources.len() - self.parsed.len()
    }
}

/// Directories never worth walking, regardless of `.gitignore`.
///
/// `target` dominates: on a built Anchor project it holds far more Rust than
/// the program does, all of it generated or vendored.
const SKIP_DIRS: &[&str] = &["target", ".git", "node_modules"];

/// Nesting depth beyond which a file is skipped rather than parsed.
///
/// `syn` is a recursive-descent parser, so nesting depth costs stack. A stack
/// overflow aborts the process and cannot be caught, which would breach the
/// never-panic invariant in the one way we cannot recover from — so absurd
/// input is refused up front instead. Real code is nowhere near this: the
/// deepest nesting in the 76,000-line corpus is in single digits.
const MAX_NESTING: usize = 256;

/// The stack given to analysis threads.
///
/// Sixteen megabytes handles nesting far past anything `MAX_NESTING` admits.
/// The default matters because it varies by caller: a Rust test harness thread
/// gets 2 MiB, where the main thread gets 8 MiB, and analysis that succeeds in
/// one and aborts in the other is not acceptable behaviour for a linter.
const ANALYSIS_STACK: usize = 16 * 1024 * 1024;

/// Run an analysis on a thread with a stack sized for deeply nested source.
///
/// The result must be `Send`, which rules out returning a [`crate::model::ProgramContext`]
/// — it holds `syn` nodes, and `proc-macro2` uses `Rc` internally (ADR-005).
/// Do the analysis inside the closure and return plain data.
///
/// # Panics
///
/// Propagates a panic from `f`, and panics if the thread cannot be spawned.
pub fn with_analysis_stack<T, F>(f: F) -> T
where
    T: Send,
    F: FnOnce() -> T + Send,
{
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .stack_size(ANALYSIS_STACK)
            .name("wheeltap-analysis".into())
            .spawn_scoped(scope, f)
            .expect("spawn analysis thread")
            .join()
            .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
    })
}

/// Approximate the deepest nesting in a source file, cheaply and without
/// parsing.
///
/// Bracket nesting is exact. Angle brackets are a heuristic — `<` counts only
/// when it directly follows an identifier character or another `<`, which is
/// what generic nesting looks like and what a comparison does not. The
/// heuristic only has to be good enough to separate real code from a
/// pathological file, and the threshold is two orders of magnitude above
/// anything real.
fn max_nesting_depth(text: &str) -> usize {
    let bytes = text.as_bytes();
    let (mut depth, mut deepest) = (0usize, 0usize);

    for (i, &byte) in bytes.iter().enumerate() {
        match byte {
            b'(' | b'[' | b'{' => {
                depth += 1;
                deepest = deepest.max(depth);
            }
            b')' | b']' | b'}' => depth = depth.saturating_sub(1),
            b'<' => {
                let follows_name = i
                    .checked_sub(1)
                    .and_then(|j| bytes.get(j))
                    .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'<');
                if follows_name {
                    depth += 1;
                    deepest = deepest.max(depth);
                }
            }
            b'>' => depth = depth.saturating_sub(1),
            _ => {}
        }
    }

    deepest
}

/// Discover `.rs` files under `path`, read them, and parse each one.
///
/// `path` may be a single file or a directory. `.gitignore` is honoured.
/// Symlinks are not followed, so a symlink loop cannot hang the walk.
#[must_use]
pub fn load(path: &Path) -> Load {
    let root = if path.is_file() {
        path.parent().unwrap_or(Path::new(".")).to_path_buf()
    } else {
        path.to_path_buf()
    };

    let mut load = Load {
        root,
        ..Default::default()
    };

    if !path.exists() {
        load.diagnostics
            .push(Diagnostic::warning(path, "path does not exist"));
        return load;
    }

    for file in discover(path, &mut load.diagnostics) {
        read_and_parse(&file, &mut load);
    }

    load
}

/// Walk `path` for Rust source, in a deterministic order.
fn discover(path: &Path, diagnostics: &mut Vec<Diagnostic>) -> Vec<PathBuf> {
    let walk = WalkBuilder::new(path)
        // Honour ignore files even when the tree is not a git repository;
        // vendored corpora and extracted archives are not repositories, and a
        // rule that only sometimes applies is worse than one that always does.
        .require_git(false)
        .git_ignore(true)
        .git_global(false)
        .hidden(false)
        .follow_links(false)
        .filter_entry(|entry| {
            !entry.file_type().is_some_and(|t| t.is_dir())
                || !entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| SKIP_DIRS.contains(&name))
        })
        .sort_by_file_path(Path::cmp)
        .build();

    let mut found = Vec::new();
    for entry in walk {
        match entry {
            Ok(entry) => {
                if entry.file_type().is_some_and(|t| t.is_file())
                    && entry.path().extension().is_some_and(|e| e == "rs")
                {
                    found.push(entry.path().to_path_buf());
                }
            }
            Err(err) => diagnostics.push(Diagnostic::warning(path, format!("walk error: {err}"))),
        }
    }
    found
}

/// Read one file and parse it, recording a warning for either failure.
fn read_and_parse(path: &Path, load: &mut Load) {
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(err) => {
            load.diagnostics
                .push(Diagnostic::warning(path, format!("could not read: {err}")));
            return;
        }
    };

    let text = match String::from_utf8(bytes) {
        Ok(text) => text,
        Err(_) => {
            load.diagnostics.push(Diagnostic::warning(
                path,
                "not valid UTF-8; skipped without analysis",
            ));
            return;
        }
    };

    let depth = max_nesting_depth(&text);
    if depth > MAX_NESTING {
        load.diagnostics.push(Diagnostic::warning(
            path,
            format!(
                "nesting is {depth} deep, over the limit of {MAX_NESTING}; \
                 skipped without analysis to avoid exhausting the stack"
            ),
        ));
        return;
    }

    let id = load.sources.add(path.to_path_buf(), &load.root, text);

    match syn::parse_file(&load.sources.get(id).text) {
        Ok(ast) => load.parsed.push(ParsedFile { id, ast }),
        Err(err) => {
            // A parse failure is a coverage gap, not a finding. Report where it
            // happened so the user can judge whether it matters.
            load.diagnostics.push(
                Diagnostic::warning(path, format!("could not parse: {err}"))
                    .at_line(err.span().start().line),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn tree(files: &[(&str, &str)]) -> TempDir {
        let dir = TempDir::new().expect("tempdir");
        for (name, contents) in files {
            let path = dir.path().join(name);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).expect("mkdir");
            }
            fs::write(path, contents).expect("write");
        }
        dir
    }

    #[test]
    fn discovers_rust_files_and_ignores_everything_else() {
        let dir = tree(&[
            ("src/lib.rs", "pub fn a() {}"),
            ("src/other.rs", "pub fn b() {}"),
            ("README.md", "not rust"),
            ("Cargo.toml", "[package]"),
        ]);

        let load = load(dir.path());
        assert_eq!(load.sources.len(), 2);
        assert_eq!(load.parsed.len(), 2);
        assert!(load.diagnostics.is_empty());
    }

    #[test]
    fn skips_target_and_other_build_directories() {
        let dir = tree(&[
            ("src/lib.rs", "pub fn a() {}"),
            ("target/debug/build/generated.rs", "pub fn generated() {}"),
            ("node_modules/pkg/thing.rs", "pub fn vendored() {}"),
        ]);

        let load = load(dir.path());
        assert_eq!(load.sources.len(), 1);
        assert_eq!(load.sources.display_path(load.parsed[0].id), "src/lib.rs");
    }

    #[test]
    fn honours_gitignore_outside_a_git_repository() {
        let dir = tree(&[
            (".gitignore", "generated/\n"),
            ("src/lib.rs", "pub fn a() {}"),
            ("generated/idl.rs", "pub fn generated() {}"),
        ]);

        let load = load(dir.path());
        assert_eq!(load.sources.len(), 1);
        assert_eq!(load.sources.display_path(load.parsed[0].id), "src/lib.rs");
    }

    /// The central robustness requirement: one bad file must not cost the run.
    #[test]
    fn an_unparseable_file_warns_and_the_scan_continues() {
        let dir = tree(&[
            ("src/good.rs", "pub fn a() {}"),
            ("src/broken.rs", "pub fn oops( {"),
        ]);

        let load = load(dir.path());
        assert_eq!(load.parsed.len(), 1, "the good file is still analysed");
        assert_eq!(load.unparsed_count(), 1);

        let diag = &load.diagnostics[0];
        assert!(diag.path.ends_with("broken.rs"));
        assert!(diag.message.contains("could not parse"));
        assert!(diag.line.is_some(), "parse errors carry a line");
    }

    #[test]
    fn non_utf8_input_warns_rather_than_panicking() {
        let dir = TempDir::new().expect("tempdir");
        fs::write(dir.path().join("bad.rs"), [0xff, 0xfe, 0x00]).expect("write");

        let load = load(dir.path());
        assert!(load.parsed.is_empty());
        assert!(load.diagnostics[0].message.contains("not valid UTF-8"));
    }

    #[test]
    fn empty_and_comment_only_files_parse_to_nothing() {
        let dir = tree(&[
            ("empty.rs", ""),
            ("comments.rs", "// nothing here\n/* nor here */\n"),
        ]);

        let load = load(dir.path());
        assert_eq!(load.parsed.len(), 2);
        assert!(load.parsed.iter().all(|f| f.ast.items.is_empty()));
        assert!(load.diagnostics.is_empty());
    }

    #[test]
    fn a_single_file_path_is_scannable() {
        let dir = tree(&[("src/lib.rs", "pub fn a() {}")]);

        let load = load(&dir.path().join("src/lib.rs"));
        assert_eq!(load.parsed.len(), 1);
        assert_eq!(load.sources.display_path(load.parsed[0].id), "lib.rs");
    }

    #[test]
    fn a_missing_path_warns_rather_than_failing_the_process() {
        let load = load(Path::new("/definitely/not/here"));
        assert!(load.parsed.is_empty());
        assert!(load.diagnostics[0].message.contains("does not exist"));
    }

    #[test]
    fn discovery_order_is_deterministic() {
        let dir = tree(&[
            ("src/zulu.rs", "pub fn z() {}"),
            ("src/alpha.rs", "pub fn a() {}"),
            ("src/mike.rs", "pub fn m() {}"),
        ]);

        let paths: Vec<_> = (0..3)
            .map(|_| {
                load(dir.path())
                    .parsed
                    .iter()
                    .map(|f| load(dir.path()).sources.display_path(f.id))
                    .collect::<Vec<_>>()
            })
            .collect();

        assert_eq!(paths[0], paths[1]);
        assert_eq!(paths[1], paths[2]);
        assert_eq!(paths[0], ["src/alpha.rs", "src/mike.rs", "src/zulu.rs"]);
    }
}
