//! `wheeltap debug-context` — print the parsed program model.
//!
//! This exists to make the analyser's understanding inspectable. When a
//! detector misfires, the first question is always whether the rule is wrong or
//! whether the model handed it something wrong, and guessing at that is how
//! afternoons disappear.

use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use wheeltap_core::ProgramContext;
use wheeltap_core::summary::{AccountsSummary, ContextSummary, ProgramSummary, StateSummary};

use crate::{EXIT_CLEAN, EXIT_ERROR, write_failure};

pub fn run(path: &Path, json: bool) -> ExitCode {
    if !path.exists() {
        eprintln!("wheeltap: {}: no such file or directory", path.display());
        return ExitCode::from(EXIT_ERROR);
    }

    // Analysis runs on a thread with a stack of its own, so that deeply nested
    // source cannot overflow whatever stack the caller happened to provide.
    // The summary is plain data and crosses the thread boundary; the context
    // itself holds `syn` nodes and cannot (ADR-005).
    let summary =
        wheeltap_core::loader::with_analysis_stack(|| ProgramContext::scan(path).summary());

    let text = if json {
        match serde_json::to_string_pretty(&summary) {
            Ok(text) => text + "\n",
            Err(err) => {
                eprintln!("wheeltap: could not serialise the model: {err}");
                return ExitCode::from(EXIT_ERROR);
            }
        }
    } else {
        render(&summary)
    };

    if let Err(err) = emit(&mut io::stdout().lock(), &text) {
        return write_failure(&err);
    }

    if summary.files.scanned == 0 {
        eprintln!("wheeltap: no Rust source found under {}", path.display());
        return ExitCode::from(EXIT_ERROR);
    }

    ExitCode::from(EXIT_CLEAN)
}

/// Write output, trimming the trailing spaces that column padding leaves.
///
/// Taking the writer as a parameter rather than reaching for `println!` is what
/// makes the broken-pipe path testable — and `println!` cannot be used here
/// anyway, because it *panics* when the reader goes away.
fn emit(out: &mut impl Write, text: &str) -> io::Result<()> {
    for line in text.lines() {
        writeln!(out, "{}", line.trim_end())?;
    }
    out.flush()
}

/// Render the model as text.
fn render(summary: &ContextSummary) -> String {
    let mut out = String::new();

    out.push_str(&format!(
        "{} file{} scanned, {} lines\n",
        summary.files.scanned,
        plural(summary.files.scanned),
        summary.files.lines,
    ));

    for program in &summary.programs {
        out.push('\n');
        render_program(&mut out, program, summary);
    }

    let delegated: Vec<_> = summary
        .handlers
        .iter()
        .filter(|h| h.program.is_none())
        .collect();
    if !delegated.is_empty() {
        out.push_str(&format!("\n{} delegated handler(s)\n", delegated.len()));
        let width = delegated.iter().map(|h| h.name.len()).max().unwrap_or(0);
        for handler in &delegated {
            let accounts = handler.accounts.as_deref().unwrap_or("-");
            let mark = if handler.accounts_resolved {
                ""
            } else {
                " (unresolved)"
            };
            out.push_str(&format!(
                "  {:width$}  {}:{} -> {accounts}{mark}\n",
                handler.name, handler.file, handler.line
            ));
        }
    }

    for accounts in &summary.accounts {
        out.push('\n');
        render_accounts(&mut out, accounts);
    }

    for state in &summary.states {
        out.push('\n');
        render_state(&mut out, state);
    }

    if !summary.diagnostics.is_empty() {
        out.push_str(&format!("\n{} diagnostic(s)\n", summary.diagnostics.len()));
        for diagnostic in &summary.diagnostics {
            out.push_str(&format!("  {diagnostic}\n"));
        }
    }

    if summary.programs.is_empty() && summary.accounts.is_empty() && summary.files.scanned > 0 {
        out.push_str(
            "\nno #[program] module and no #[derive(Accounts)] struct found.\n\
             this does not look like an Anchor program.\n",
        );
    }

    out
}

fn render_program(out: &mut String, program: &ProgramSummary, summary: &ContextSummary) {
    out.push_str(&format!(
        "program {} ({}:{})\n",
        program.name, program.file, program.line
    ));

    let handlers: Vec<_> = summary
        .handlers
        .iter()
        .filter(|h| h.program.as_deref() == Some(program.name.as_str()))
        .collect();

    if handlers.is_empty() {
        out.push_str("  (no instruction entrypoints)\n");
        return;
    }

    let width = handlers.iter().map(|h| h.name.len()).max().unwrap_or(0);

    for handler in handlers {
        let accounts = handler.accounts.as_deref().unwrap_or("-");
        // An unresolved Accounts struct means the scan did not see the file
        // that declares it. Flag it: the model is incomplete, and any detector
        // reading it will be reasoning about less than the whole program.
        let mark = if handler.accounts_resolved {
            ""
        } else {
            " (unresolved)"
        };
        out.push_str(&format!(
            "  {:width$}  L{} -> {accounts}{mark}\n",
            handler.name, handler.line,
        ));
    }
}

fn render_accounts(out: &mut String, accounts: &AccountsSummary) {
    out.push_str(&format!(
        "accounts {} ({}:{})",
        accounts.name, accounts.file, accounts.line
    ));
    if let Some(args) = &accounts.instruction_args {
        out.push_str(&format!("  #[instruction({args})]"));
    }
    out.push('\n');

    if accounts.fields.is_empty() {
        out.push_str("  (no fields)\n");
        return;
    }

    let name_width = accounts
        .fields
        .iter()
        .map(|f| f.name.len())
        .max()
        .unwrap_or(0);
    let type_width = accounts
        .fields
        .iter()
        .map(|f| f.ty.len())
        .max()
        .unwrap_or(0)
        .min(40);

    for field in &accounts.fields {
        out.push_str(&format!(
            "  {:name_width$}  {:type_width$}",
            field.name, field.ty
        ));
        if !field.constraints.is_empty() {
            out.push_str(&format!("  [{}]", field.constraints.join(", ")));
        }
        if field.unchecked {
            match &field.check_comment {
                Some(reason) if !reason.is_empty() => {
                    out.push_str(&format!("  CHECK: {reason}"));
                }
                Some(_) => out.push_str("  CHECK: (empty)"),
                None => out.push_str("  (unchecked, no CHECK comment)"),
            }
        }
        out.push('\n');
    }
}

fn render_state(out: &mut String, state: &StateSummary) {
    out.push_str(&format!(
        "account state {} ({}:{})\n",
        state.name, state.file, state.line
    ));
    for field in &state.fields {
        out.push_str(&format!("  {field}\n"));
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A writer that fails the way a closed pipe does.
    struct BrokenPipe;

    impl Write for BrokenPipe {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed"))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn a_closed_pipe_is_not_an_error() {
        let err = emit(&mut BrokenPipe, "anything").expect_err("write fails");
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        // `wheeltap ... | head` must exit cleanly, not report a failure.
        assert_eq!(
            format!("{:?}", write_failure(&err)),
            format!("{:?}", ExitCode::from(EXIT_CLEAN))
        );
    }

    #[test]
    fn other_write_failures_are_reported() {
        let err = io::Error::new(io::ErrorKind::PermissionDenied, "nope");
        assert_eq!(
            format!("{:?}", write_failure(&err)),
            format!("{:?}", ExitCode::from(EXIT_ERROR))
        );
    }

    #[test]
    fn emitted_lines_have_no_trailing_whitespace() {
        let mut buffer = Vec::new();
        emit(&mut buffer, "padded    \nclean\n").expect("write");
        assert_eq!(String::from_utf8(buffer).expect("utf8"), "padded\nclean\n");
    }
}
