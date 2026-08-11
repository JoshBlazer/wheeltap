//! The `wheeltap` command line.
//!
//! Exit codes are part of the contract with CI and must not drift:
//!
//! | Code | Meaning |
//! |------|---------|
//! | 0    | scan completed, nothing at or above the failure threshold |
//! | 1    | scan completed, findings at or above the threshold |
//! | 2    | internal error: Wheeltap could not complete the scan |

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

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
    },
    /// Print the parsed program model for a path, for debugging the analyser.
    DebugContext {
        /// Directory or file to model.
        path: PathBuf,
    },
}

/// Parse arguments and run. Returns the process exit code.
#[must_use]
pub fn run() -> ExitCode {
    let cli = Cli::parse();

    let unimplemented_in = |phase: &str, what: &str| -> ExitCode {
        eprintln!("wheeltap: `{what}` is not implemented yet (arrives in {phase}).");
        ExitCode::from(EXIT_ERROR)
    };

    match cli.command {
        Command::Scan { .. } => unimplemented_in("Phase 2", "scan"),
        Command::DebugContext { .. } => unimplemented_in("Phase 1", "debug-context"),
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
