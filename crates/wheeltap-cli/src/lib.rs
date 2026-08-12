//! The `wheeltap` command line.
//!
//! Exit codes are part of the contract with CI and must not drift:
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0    | scan completed, nothing at or above the failure threshold |
//! | 1    | scan completed, findings at or above the threshold |
//! | 2    | internal error: Wheeltap could not complete the scan |

mod debug_context;
mod scan;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use wheeltap_core::finding::Severity;
use wheeltap_report::Format;

/// Scan completed and found nothing at or above the failure threshold.
pub const EXIT_CLEAN: u8 = 0;
/// Scan completed and found something at or above the failure threshold.
pub const EXIT_FINDINGS: u8 = 1;
/// Wheeltap could not complete the scan.
pub const EXIT_ERROR: u8 = 2;

#[derive(Debug, Parser)]
#[command(
    name = "wheeltap",
    version,
    about = "Static analysis for Rust-based Solana smart contracts",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Scan a directory of Anchor programs for security findings.
    Scan {
        /// Directory or file to scan.
        path: PathBuf,

        /// Output format.
        #[arg(long, default_value = "json")]
        format: Format,

        /// Do not report findings below this severity.
        #[arg(long, value_name = "SEVERITY", default_value = "info")]
        severity_threshold: Severity,

        /// Exit 1 when a finding at or above this severity is reported.
        #[arg(long, value_name = "SEVERITY", default_value = "low")]
        fail_on: Severity,
    },
    /// Print the parsed program model for a path, for debugging the analyser.
    DebugContext {
        /// Directory or file to model.
        path: PathBuf,
        /// Emit the model as JSON instead of text.
        #[arg(long)]
        json: bool,
    },
}

/// Decide the exit code for a failed write to stdout.
///
/// `wheeltap ... | head` closes the pipe as soon as it has what it wants. That
/// is the reader's choice, not our error, and it must not read as a crash —
/// which is exactly what `println!` would do, since it panics on `EPIPE`.
pub(crate) fn write_failure(err: &std::io::Error) -> ExitCode {
    if err.kind() == std::io::ErrorKind::BrokenPipe {
        return ExitCode::from(EXIT_CLEAN);
    }
    eprintln!("wheeltap: could not write output: {err}");
    ExitCode::from(EXIT_ERROR)
}

/// Parse arguments and run. Returns the process exit code.
#[must_use]
pub fn run() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Command::Scan {
            path,
            format,
            severity_threshold,
            fail_on,
        } => scan::run(&scan::Options {
            path: &path,
            format,
            severity_threshold,
            fail_on,
        }),
        Command::DebugContext { path, json } => debug_context::run(&path, json),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory as _;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn exit_codes_match_the_documented_contract() {
        assert_eq!((EXIT_CLEAN, EXIT_FINDINGS, EXIT_ERROR), (0, 1, 2));
    }
}
