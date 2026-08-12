//! The Anchor-aware program model every detector reads.
//!
//! The build spec is blunt that this is where the project succeeds or fails: a
//! weak context model turns every downstream detector into a pile of special
//! cases. So the model answers structural questions directly — *what type is
//! this account, what does it constrain, which handler uses it* — rather than
//! making each rule re-derive them from the AST.
//!
//! **Scope of resolution.** Item paths are resolved within a file, not across
//! them: `mod x;` is not followed to `x.rs`, because doing so means
//! reimplementing rustc's module resolution for no analytical gain. Identity
//! uses the relative file path *and* the in-file item path together, which is
//! unique regardless (ADR-001).

pub mod constraints;
pub mod ty;

use std::path::PathBuf;

use crate::diag::Diagnostic;
use crate::loader::Load;
use crate::source::{FileId, Location, SourceMap};
use constraints::Constraints;
use ty::FieldType;

/// One field of a `#[derive(Accounts)]` struct.
#[derive(Debug, Clone)]
pub struct AccountField {
    pub name: String,
    /// `program::Struct.field`, stable under code movement.
    pub item_path: String,
    pub ty: FieldType,
    pub constraints: Constraints,
    /// The `/// CHECK:` comment Anchor requires on unchecked accounts. Its
    /// presence is a claim by the author that validation happens elsewhere;
    /// its absence on an unchecked account is itself a smell.
    pub check_comment: Option<String>,
    /// Location of the field's name.
    pub location: Location,
    /// Location of the whole field including its attributes, for snippets.
    pub full_location: Location,
}

impl AccountField {
    /// Whether anything at all validates this account: its type, or a
    /// constraint. The starting question for most of the catalogue.
    #[must_use]
    pub fn is_validated(&self) -> bool {
        !self.ty.is_unchecked()
            || self.constraints.asserts_signer()
            || self.constraints.asserts_owner()
            || self.constraints.asserts_address()
    }
}

/// A `#[derive(Accounts)]` struct: the account list of one instruction.
#[derive(Debug, Clone)]
pub struct AccountsStruct {
    pub name: String,
    pub item_path: String,
    pub file: FileId,
    pub location: Location,
    pub fields: Vec<AccountField>,
    /// The `#[instruction(...)]` argument list, when present. Anchor needs it
    /// to use instruction arguments in seeds.
    pub instruction_args: Option<String>,
    /// Retained for detectors that need the syntax rather than the model.
    pub item: syn::ItemStruct,
}

impl AccountsStruct {
    #[must_use]
    pub fn field(&self, name: &str) -> Option<&AccountField> {
        self.fields.iter().find(|f| f.name == name)
    }
}

/// A `#[account]` data struct — the layout stored in an account, as distinct
/// from the account list of an instruction.
#[derive(Debug, Clone)]
pub struct AccountState {
    pub name: String,
    pub item_path: String,
    pub file: FileId,
    pub location: Location,
    /// Field names and rendered types.
    pub fields: Vec<(String, String)>,
    pub item: syn::ItemStruct,
}

/// A function that operates on an instruction's accounts.
///
/// Anything taking a `Context<T>` counts, wherever it is declared. Real Anchor
/// programs put a thin dispatcher in the `#[program]` module and the actual
/// work in `handle_*` functions in other modules — drift has 245 of the former
/// and 287 of the latter. Modelling only the dispatchers would leave every
/// body-level detector, arithmetic and CPI alike, looking at delegation stubs.
#[derive(Debug, Clone)]
pub struct Handler {
    pub name: String,
    pub item_path: String,
    /// The `#[derive(Accounts)]` struct named by its `Context<T>` parameter.
    pub accounts_struct: Option<String>,
    /// The `#[program]` module this was declared in, if any. A handler with
    /// `Some` is an instruction entrypoint reachable from outside; one with
    /// `None` is reached through an entrypoint.
    pub program: Option<String>,
    pub file: FileId,
    pub location: Location,
    /// Retained whole: later phases analyse handler bodies for arithmetic and
    /// cross-program invocations.
    pub item: syn::ItemFn,
}

impl Handler {
    /// Whether this handler is an instruction entrypoint.
    #[must_use]
    pub fn is_entrypoint(&self) -> bool {
        self.program.is_some()
    }
}

/// A `#[program]` module.
#[derive(Debug, Clone)]
pub struct ProgramModule {
    pub name: String,
    pub file: FileId,
    pub location: Location,
}

/// Everything a scan knows about the code under analysis.
///
/// Not `Send`/`Sync`: it retains `syn` nodes, and `proc-macro2` uses `Rc`
/// internally. See ADR-005 for what that means for parallelism.
#[derive(Debug)]
pub struct ProgramContext {
    pub root: PathBuf,
    pub sources: SourceMap,
    pub programs: Vec<ProgramModule>,
    /// Every function taking a `Context<T>`, entrypoint or not.
    pub handlers: Vec<Handler>,
    pub accounts: Vec<AccountsStruct>,
    pub states: Vec<AccountState>,
    pub diagnostics: Vec<Diagnostic>,
}

impl ProgramContext {
    /// Build the model from a loaded tree.
    #[must_use]
    pub fn build(load: Load) -> Self {
        let Load {
            root,
            sources,
            parsed,
            diagnostics,
        } = load;

        let mut ctx = Self {
            root,
            sources,
            programs: Vec::new(),
            handlers: Vec::new(),
            accounts: Vec::new(),
            states: Vec::new(),
            diagnostics,
        };

        for file in &parsed {
            let mut path = Vec::new();
            ctx.walk(&file.ast.items, file.id, &mut path, None);
        }

        ctx
    }

    /// Load a path and model it in one step.
    #[must_use]
    pub fn scan(path: &std::path::Path) -> Self {
        Self::build(crate::loader::load(path))
    }

    /// Look up an Accounts struct by name.
    #[must_use]
    pub fn accounts_struct(&self, name: &str) -> Option<&AccountsStruct> {
        self.accounts.iter().find(|a| a.name == name)
    }

    /// Look up an account data struct by name.
    #[must_use]
    pub fn state(&self, name: &str) -> Option<&AccountState> {
        self.states.iter().find(|s| s.name == name)
    }

    /// The Accounts struct a handler operates on.
    #[must_use]
    pub fn handler_accounts(&self, handler: &Handler) -> Option<&AccountsStruct> {
        self.accounts_struct(handler.accounts_struct.as_deref()?)
    }

    /// Handlers declared inside a `#[program]` module — the instruction
    /// entrypoints, as opposed to the functions they delegate to.
    pub fn entrypoints(&self) -> impl Iterator<Item = &Handler> {
        self.handlers.iter().filter(|h| h.is_entrypoint())
    }

    /// Every handler declared for a given Accounts struct.
    pub fn handlers_for<'a>(&'a self, accounts: &'a str) -> impl Iterator<Item = &'a Handler> {
        self.handlers
            .iter()
            .filter(move |h| h.accounts_struct.as_deref() == Some(accounts))
    }

    /// Whether this looks like Anchor code at all. A scan of a tree with no
    /// `#[program]` and no Accounts structs is almost certainly pointed at the
    /// wrong directory, and saying so beats reporting a confident zero.
    #[must_use]
    pub fn looks_like_anchor(&self) -> bool {
        !self.programs.is_empty() || !self.accounts.is_empty()
    }

    /// Walk items, descending through modules and recording what matters.
    ///
    /// `program` carries the name of the enclosing `#[program]` module, so a
    /// handler knows whether it is an entrypoint.
    fn walk(
        &mut self,
        items: &[syn::Item],
        file: FileId,
        path: &mut Vec<String>,
        program: Option<&str>,
    ) {
        for item in items {
            match item {
                syn::Item::Mod(module) => {
                    let name = module.ident.to_string();
                    let is_program = has_attr(&module.attrs, "program");
                    if is_program {
                        self.programs.push(ProgramModule {
                            name: name.clone(),
                            file,
                            location: Location::from_span(file, module.ident.span()),
                        });
                    }
                    if let Some((_, items)) = &module.content {
                        let inner = if is_program {
                            Some(name.clone())
                        } else {
                            program.map(str::to_string)
                        };
                        path.push(name);
                        self.walk(items, file, path, inner.as_deref());
                        path.pop();
                    }
                }
                syn::Item::Fn(func) => {
                    let scope = path.join("::");
                    if let Some(handler) = handler(func, file, &scope, program) {
                        self.handlers.push(handler);
                    }
                }
                syn::Item::Struct(item) => {
                    if derives(&item.attrs, "Accounts") {
                        self.add_accounts_struct(item, file, path);
                    } else if has_attr(&item.attrs, "account") {
                        self.add_state(item, file, path);
                    }
                }
                _ => {}
            }
        }
    }

    fn add_accounts_struct(&mut self, item: &syn::ItemStruct, file: FileId, path: &[String]) {
        let name = item.ident.to_string();
        let item_path = join(path, &name);
        let fields = item
            .fields
            .iter()
            .filter_map(|field| account_field(field, file, &item_path))
            .collect();

        self.accounts.push(AccountsStruct {
            name,
            item_path,
            file,
            location: Location::from_span(file, item.ident.span()),
            fields,
            instruction_args: instruction_args(&item.attrs),
            item: item.clone(),
        });
    }

    fn add_state(&mut self, item: &syn::ItemStruct, file: FileId, path: &[String]) {
        let name = item.ident.to_string();
        self.states.push(AccountState {
            name: name.clone(),
            item_path: join(path, &name),
            file,
            location: Location::from_span(file, item.ident.span()),
            fields: item
                .fields
                .iter()
                .filter_map(|f| Some((f.ident.as_ref()?.to_string(), ty::render(&f.ty))))
                .collect(),
            item: item.clone(),
        });
    }
}

/// Model one function as a handler, if it takes a `Context<T>`.
///
/// The `Context` parameter is what marks a function as operating on an
/// instruction's accounts. Functions without one — helpers, maths, validation
/// on plain values — are not handlers.
fn handler(
    func: &syn::ItemFn,
    file: FileId,
    scope: &str,
    program: Option<&str>,
) -> Option<Handler> {
    let first = func.sig.inputs.first()?;
    let syn::FnArg::Typed(arg) = first else {
        return None;
    };
    let accounts_struct = context_accounts_type(&arg.ty)?;

    let name = func.sig.ident.to_string();
    Some(Handler {
        item_path: if scope.is_empty() {
            name.clone()
        } else {
            format!("{scope}::{name}")
        },
        name,
        accounts_struct: Some(accounts_struct),
        program: program.map(str::to_string),
        file,
        location: Location::from_span(file, func.sig.ident.span()),
        item: func.clone(),
    })
}

/// Extract `T` from a `Context<'a, 'b, 'c, 'info, T<'info>>` parameter.
///
/// Anchor's `Context` carries four lifetimes before the accounts type, and
/// programs write anything from `Context<Initialize>` to the fully elaborated
/// form. Taking the last type argument handles every spelling. A handler may
/// also borrow its context, so a leading `&` is peeled first.
fn context_accounts_type(ty: &syn::Type) -> Option<String> {
    let ty = match ty {
        syn::Type::Reference(reference) => &reference.elem,
        other => other,
    };
    let syn::Type::Path(path) = ty else {
        return None;
    };
    let segment = path.path.segments.last()?;
    if segment.ident != "Context" {
        return None;
    }
    let syn::PathArguments::AngleBracketed(args) = &segment.arguments else {
        return None;
    };
    let last_type = args.args.iter().rev().find_map(|arg| match arg {
        syn::GenericArgument::Type(ty) => Some(ty),
        _ => None,
    })?;
    let syn::Type::Path(path) = last_type else {
        return None;
    };
    Some(path.path.segments.last()?.ident.to_string())
}

/// Model one field of an Accounts struct. Unnamed fields are skipped: Anchor
/// requires named fields, so a tuple struct is not an account list.
fn account_field(field: &syn::Field, file: FileId, struct_path: &str) -> Option<AccountField> {
    let ident = field.ident.as_ref()?;
    let name = ident.to_string();
    Some(AccountField {
        item_path: format!("{struct_path}.{name}"),
        name,
        ty: ty::classify(&field.ty),
        constraints: constraints::parse(&field.attrs, file),
        check_comment: check_comment(&field.attrs),
        location: Location::from_span(file, ident.span()),
        full_location: Location::from_span(file, span_of_field(field)),
    })
}

/// A field's span, starting at its first attribute.
///
/// `Field::span()` already covers attributes, but being explicit keeps the
/// intent visible: snippets should show the constraints, not just the name.
fn span_of_field(field: &syn::Field) -> proc_macro2::Span {
    use syn::spanned::Spanned as _;
    field.span()
}

/// The text of a `/// CHECK:` doc comment, if the field carries one.
fn check_comment(attrs: &[syn::Attribute]) -> Option<String> {
    let mut lines = Vec::new();
    for attr in attrs {
        if !attr.path().is_ident("doc") {
            continue;
        }
        let syn::Meta::NameValue(nv) = &attr.meta else {
            continue;
        };
        let syn::Expr::Lit(lit) = &nv.value else {
            continue;
        };
        let syn::Lit::Str(text) = &lit.lit else {
            continue;
        };
        lines.push(text.value().trim().to_string());
    }

    let joined = lines.join(" ");
    let trimmed = joined.trim();
    trimmed
        .strip_prefix("CHECK:")
        .or_else(|| trimmed.strip_prefix("CHECK"))
        .map(|rest| rest.trim().to_string())
}

/// The raw argument list of `#[instruction(...)]`.
fn instruction_args(attrs: &[syn::Attribute]) -> Option<String> {
    attrs.iter().find_map(|attr| {
        if !attr.path().is_ident("instruction") {
            return None;
        }
        let syn::Meta::List(list) = &attr.meta else {
            return None;
        };
        Some(ty::render_stream(&list.tokens))
    })
}

/// Whether an attribute list contains a bare `#[name]` or `#[name(...)]`.
fn has_attr(attrs: &[syn::Attribute], name: &str) -> bool {
    attrs.iter().any(|attr| attr.path().is_ident(name))
}

/// Whether `#[derive(...)]` includes a given trait.
fn derives(attrs: &[syn::Attribute], name: &str) -> bool {
    attrs.iter().any(|attr| {
        if !attr.path().is_ident("derive") {
            return false;
        }
        let mut found = false;
        // `parse_nested_meta` is safe here: unlike Anchor's constraint grammar,
        // a derive list really is a comma-separated list of paths.
        let _ = attr.parse_nested_meta(|meta| {
            if meta.path.is_ident(name) {
                found = true;
            }
            Ok(())
        });
        found
    })
}

fn join(path: &[String], name: &str) -> String {
    if path.is_empty() {
        name.to_string()
    } else {
        format!("{}::{name}", path.join("::"))
    }
}
