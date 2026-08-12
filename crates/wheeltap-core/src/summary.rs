//! A serialisable view of the program model.
//!
//! [`ProgramContext`] holds `syn` nodes, which do not implement `Serialize` and
//! should not: dumping an AST is not a readable model. This module projects the
//! context onto plain data — the shape `wheeltap debug-context` prints and
//! snapshot tests assert on.
//!
//! Everything here is sorted, so two runs over identical input serialise
//! identically (build spec invariant 4).

use serde::Serialize;

use crate::diag::Diagnostic;
use crate::model::{AccountsStruct, Handler, ProgramContext, ProgramModule};

#[derive(Debug, Serialize)]
pub struct ContextSummary {
    pub files: FileStats,
    pub programs: Vec<ProgramSummary>,
    pub handlers: Vec<HandlerSummary>,
    pub accounts: Vec<AccountsSummary>,
    pub states: Vec<StateSummary>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Serialize)]
pub struct FileStats {
    pub scanned: usize,
    pub lines: usize,
}

#[derive(Debug, Serialize)]
pub struct ProgramSummary {
    pub name: String,
    pub file: String,
    pub line: usize,
    /// Names of the entrypoints declared in this module.
    pub entrypoints: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct HandlerSummary {
    pub name: String,
    pub path: String,
    /// The `#[program]` module this is an entrypoint of, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program: Option<String>,
    pub accounts: Option<String>,
    /// Whether the named Accounts struct was actually found in the scan. A
    /// handler pointing at a struct we never saw means the scan is missing a
    /// file, and silently modelling it as "no accounts" would hide that.
    pub accounts_resolved: bool,
    pub file: String,
    pub line: usize,
}

#[derive(Debug, Serialize)]
pub struct AccountsSummary {
    pub name: String,
    pub path: String,
    pub file: String,
    pub line: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instruction_args: Option<String>,
    pub fields: Vec<FieldSummary>,
}

#[derive(Debug, Serialize)]
pub struct FieldSummary {
    pub name: String,
    #[serde(rename = "type")]
    pub ty: String,
    pub kind: String,
    pub unchecked: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub constraints: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub check_comment: Option<String>,
    pub line: usize,
}

#[derive(Debug, Serialize)]
pub struct StateSummary {
    pub name: String,
    pub file: String,
    pub line: usize,
    pub fields: Vec<String>,
}

impl ProgramContext {
    /// Project the model onto plain, sorted, serialisable data.
    #[must_use]
    pub fn summary(&self) -> ContextSummary {
        let mut programs: Vec<_> = self.programs.iter().map(|p| self.program(p)).collect();
        programs.sort_by(|a, b| (&a.file, &a.name).cmp(&(&b.file, &b.name)));

        let mut handlers: Vec<_> = self.handlers.iter().map(|h| self.handler(h)).collect();
        handlers.sort_by(|a, b| (&a.file, a.line).cmp(&(&b.file, b.line)));

        let mut accounts: Vec<_> = self.accounts.iter().map(|a| self.accounts_of(a)).collect();
        accounts.sort_by(|a, b| (&a.file, &a.name).cmp(&(&b.file, &b.name)));

        let mut states: Vec<_> = self
            .states
            .iter()
            .map(|s| StateSummary {
                name: s.name.clone(),
                file: self.sources.display_path(s.file),
                line: s.location.start.line,
                fields: s
                    .fields
                    .iter()
                    .map(|(name, ty)| format!("{name}: {ty}"))
                    .collect(),
            })
            .collect();
        states.sort_by(|a, b| (&a.file, &a.name).cmp(&(&b.file, &b.name)));

        let mut diagnostics = self.diagnostics.clone();
        diagnostics.sort_by(|a, b| (&a.path, a.line).cmp(&(&b.path, b.line)));

        ContextSummary {
            files: FileStats {
                scanned: self.sources.len(),
                lines: self.sources.iter().map(|f| f.line_count()).sum(),
            },
            programs,
            handlers,
            accounts,
            states,
            diagnostics,
        }
    }

    fn program(&self, program: &ProgramModule) -> ProgramSummary {
        let mut entrypoints: Vec<_> = self
            .handlers
            .iter()
            .filter(|h| h.program.as_deref() == Some(program.name.as_str()))
            .map(|h| h.name.clone())
            .collect();
        entrypoints.sort();

        ProgramSummary {
            name: program.name.clone(),
            file: self.sources.display_path(program.file),
            line: program.location.start.line,
            entrypoints,
        }
    }

    fn handler(&self, handler: &Handler) -> HandlerSummary {
        HandlerSummary {
            name: handler.name.clone(),
            path: handler.item_path.clone(),
            program: handler.program.clone(),
            accounts_resolved: self.handler_accounts(handler).is_some(),
            accounts: handler.accounts_struct.clone(),
            file: self.sources.display_path(handler.file),
            line: handler.location.start.line,
        }
    }

    fn accounts_of(&self, accounts: &AccountsStruct) -> AccountsSummary {
        AccountsSummary {
            name: accounts.name.clone(),
            path: accounts.item_path.clone(),
            file: self.sources.display_path(accounts.file),
            line: accounts.location.start.line,
            instruction_args: accounts.instruction_args.clone(),
            fields: accounts
                .fields
                .iter()
                .map(|field| FieldSummary {
                    name: field.name.clone(),
                    ty: field.ty.text.clone(),
                    kind: kind_name(&field.ty.anchor),
                    unchecked: field.ty.is_unchecked(),
                    constraints: field.constraints.iter().map(|c| c.raw.clone()).collect(),
                    check_comment: field.check_comment.clone(),
                    line: field.location.start.line,
                })
                .collect(),
        }
    }
}

/// The short name of an account type, for display.
fn kind_name(anchor: &crate::model::ty::AnchorType) -> String {
    use crate::model::ty::AnchorType as T;
    match anchor {
        T::Signer => "Signer".into(),
        T::AccountInfo => "AccountInfo".into(),
        T::UncheckedAccount => "UncheckedAccount".into(),
        T::SystemAccount => "SystemAccount".into(),
        T::Account { .. } => "Account".into(),
        T::InterfaceAccount { .. } => "InterfaceAccount".into(),
        T::AccountLoader { .. } => "AccountLoader".into(),
        T::Program { .. } => "Program".into(),
        T::Interface { .. } => "Interface".into(),
        T::Sysvar { .. } => "Sysvar".into(),
        T::Composite { .. } => "Composite".into(),
        T::Other => "Other".into(),
    }
}
