//! Turning a finding's path back into a repository-relative one.
//!
//! A finding's path is relative to the *scanned* root, so scanning `programs/`
//! yields `vault/src/lib.rs`. Both of the formats GitHub consumes want the
//! *repository* root instead: SARIF's `artifactLocation.uri` is what links an
//! alert to its source, and a workflow command's `file=` is what places an
//! annotation on the diff.
//!
//! Getting it wrong is silent in both. The alerts appear, the annotations
//! print, and neither reaches the code it is about. That happened here: the
//! first real SARIF upload produced seventeen correct alerts pointing at
//! seventeen paths that did not exist in the repository.

use std::path::Path;

/// Join the scanned base onto a path relative to it, in GitHub's terms.
///
/// Always forward slashes: a scan on a Windows runner would otherwise emit
/// backslashes, which neither SARIF nor a workflow command will match against
/// a repository path.
#[must_use]
pub(crate) fn repo_relative(base: &Path, relative: &str) -> String {
    let base = base.to_string_lossy().replace('\\', "/");
    let base = base.trim_end_matches('/');
    let relative = relative.replace('\\', "/");

    if base.is_empty() || base == "." {
        relative
    } else {
        format!("{base}/{relative}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_base_is_prefixed() {
        assert_eq!(
            repo_relative(Path::new("programs"), "vault/src/lib.rs"),
            "programs/vault/src/lib.rs"
        );
    }

    #[test]
    fn a_root_scan_needs_no_prefix() {
        for base in ["", ".", "./"] {
            assert_eq!(repo_relative(Path::new(base), "src/lib.rs"), "src/lib.rs");
        }
    }

    #[test]
    fn windows_separators_are_normalised() {
        assert_eq!(
            repo_relative(Path::new(r"programs\vault"), r"src\lib.rs"),
            "programs/vault/src/lib.rs"
        );
    }

    #[test]
    fn a_nested_base_keeps_its_own_separators() {
        assert_eq!(
            repo_relative(Path::new("a/b/"), "c/d.rs"),
            "a/b/c/d.rs",
            "a trailing slash must not double"
        );
    }
}
