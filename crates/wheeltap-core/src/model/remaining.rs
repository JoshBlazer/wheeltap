//! Accounts taken from `ctx.remaining_accounts`.
//!
//! `remaining_accounts` is Anchor's escape hatch from the declarative model:
//! a slice of raw `AccountInfo`s the program walks by hand, usually with
//! `next_account_info`. None of the constraint machinery applies to them, so
//! everything the rest of the model reads from `#[derive(Accounts)]` has to be
//! recovered from statements instead.
//!
//! What is recovered is deliberately narrow: each local binding produced by
//! `AccountLoader::try_from`, `Account::try_from`, or `InterfaceAccount::try_from`
//! in a function that works on remaining accounts, and the state type it is
//! deserialised into. That is the evidence TOB-DRIFT-8 turns on — two accounts
//! taken off the list as a `User` and a `UserStats` with nothing tying them to
//! the same trader — and it is all the current rules need.

use syn::visit::Visit;

use crate::source::{FileId, Location};

/// A function or method, kept so that rules can read bodies that are not
/// handlers: the helpers remaining accounts are usually loaded in.
#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    pub item_path: String,
    pub file: FileId,
    pub location: Location,
    pub sig: syn::Signature,
    pub block: syn::Block,
    /// Whether the function works on remaining accounts: it mentions
    /// `remaining_accounts`, or takes an iterator or slice of `AccountInfo`.
    pub takes_remaining: bool,
}

/// One account deserialised from the remaining accounts.
#[derive(Debug, Clone)]
pub struct RemainingRead {
    /// Index into [`crate::ProgramContext::functions`].
    pub function: usize,
    /// The local it is bound to, e.g. `maker_stats`.
    pub binding: String,
    /// `AccountLoader`, `Account`, or `InterfaceAccount`.
    pub wrapper: String,
    /// The state type, e.g. `UserStats`.
    pub state: String,
    /// Read inside a `for`, `while`, or `loop`: one of a collection, such as
    /// a map loader walking every remaining account, rather than a fixed slot.
    pub in_loop: bool,
    pub location: Location,
}

/// Wrappers whose `try_from` checks owner and discriminator and yields a typed
/// account.
const WRAPPERS: &[&str] = &["AccountLoader", "Account", "InterfaceAccount"];

impl Function {
    pub(crate) fn new(
        name: String,
        item_path: String,
        file: FileId,
        sig: &syn::Signature,
        block: &syn::Block,
    ) -> Self {
        let takes_remaining = mentions_remaining(block) || sig.inputs.iter().any(is_account_list);
        Self {
            name,
            item_path,
            file,
            location: Location::from_span(file, sig.ident.span()),
            sig: sig.clone(),
            block: block.clone(),
            takes_remaining,
        }
    }

    /// Typed accounts this function deserialises, in source order.
    pub(crate) fn reads(&self, index: usize) -> Vec<RemainingRead> {
        if !self.takes_remaining {
            return Vec::new();
        }
        let mut visitor = Reads {
            function: index,
            file: self.file,
            loops: 0,
            found: Vec::new(),
        };
        visitor.visit_block(&self.block);
        visitor.found
    }
}

/// Whether a body names `remaining_accounts` anywhere, macros included.
///
/// A visitor rather than a token walk: this runs on every function in the
/// scan, and rendering each body to tokens first cost more than every rule
/// that reads the result.
fn mentions_remaining(block: &syn::Block) -> bool {
    struct Mentions(bool);

    impl<'ast> Visit<'ast> for Mentions {
        fn visit_ident(&mut self, ident: &'ast proc_macro2::Ident) {
            self.0 |= ident == "remaining_accounts";
        }

        fn visit_macro(&mut self, mac: &'ast syn::Macro) {
            fn walk(stream: proc_macro2::TokenStream) -> bool {
                stream.into_iter().any(|token| match token {
                    proc_macro2::TokenTree::Ident(ident) => ident == "remaining_accounts",
                    proc_macro2::TokenTree::Group(group) => walk(group.stream()),
                    _ => false,
                })
            }
            self.0 |= walk(mac.tokens.clone());
            syn::visit::visit_macro(self, mac);
        }
    }

    let mut mentions = Mentions(false);
    mentions.visit_block(block);
    mentions.0
}

/// Whether a parameter is an iterator or slice of `AccountInfo`: the shape a
/// helper receives remaining accounts in.
fn is_account_list(arg: &syn::FnArg) -> bool {
    let syn::FnArg::Typed(arg) = arg else {
        return false;
    };
    let text = super::ty::render(&arg.ty);
    text.contains("AccountInfo") && (text.contains("Iter") || text.contains('['))
}

struct Reads {
    function: usize,
    file: FileId,
    loops: usize,
    found: Vec<RemainingRead>,
}

impl<'ast> Visit<'ast> for Reads {
    fn visit_local(&mut self, local: &'ast syn::Local) {
        if let Some(read) = self.read(local) {
            self.found.push(read);
        }
        syn::visit::visit_local(self, local);
    }

    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        self.loops += 1;
        syn::visit::visit_expr_for_loop(self, node);
        self.loops -= 1;
    }

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        self.loops += 1;
        syn::visit::visit_expr_while(self, node);
        self.loops -= 1;
    }

    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        self.loops += 1;
        syn::visit::visit_expr_loop(self, node);
        self.loops -= 1;
    }
}

impl Reads {
    fn read(&self, local: &syn::Local) -> Option<RemainingRead> {
        let (binding, annotated) = match &local.pat {
            syn::Pat::Ident(ident) => (ident.ident.to_string(), None),
            syn::Pat::Type(typed) => match &*typed.pat {
                syn::Pat::Ident(ident) => (ident.ident.to_string(), Some(&*typed.ty)),
                _ => return None,
            },
            _ => return None,
        };
        let init = local.init.as_ref()?;

        let mut call = TryFrom::default();
        call.visit_expr(&init.expr);
        let wrapper = call.wrapper?;

        // The state type comes from a turbofish, `AccountLoader::<User>::try_from`,
        // or failing that from the binding's annotation.
        let state = call.turbofish.or_else(|| {
            annotated
                .map(super::ty::classify)
                .and_then(|ty| ty.inner().map(str::to_string))
        })?;

        use syn::spanned::Spanned as _;
        Some(RemainingRead {
            function: self.function,
            binding,
            wrapper,
            state,
            in_loop: self.loops > 0,
            location: Location::from_span(self.file, local.span()),
        })
    }
}

/// Finds `Wrapper::try_from(..)` or `Wrapper::<T>::try_from(..)` in an
/// expression, through the `?`, `.or(..)`, and `.map_err(..)` around it.
#[derive(Default)]
struct TryFrom {
    wrapper: Option<String>,
    turbofish: Option<String>,
}

impl<'ast> Visit<'ast> for TryFrom {
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if self.wrapper.is_none()
            && let syn::Expr::Path(path) = &*call.func
        {
            let segments: Vec<_> = path.path.segments.iter().collect();
            if let [.., wrapper, method] = segments.as_slice()
                && method.ident == "try_from"
                && WRAPPERS.iter().any(|w| wrapper.ident == w)
            {
                self.wrapper = Some(wrapper.ident.to_string());
                self.turbofish = last_type_argument(&wrapper.arguments);
            }
        }
        syn::visit::visit_expr_call(self, call);
    }
}

fn last_type_argument(arguments: &syn::PathArguments) -> Option<String> {
    let syn::PathArguments::AngleBracketed(args) = arguments else {
        return None;
    };
    args.args.iter().rev().find_map(|arg| match arg {
        syn::GenericArgument::Type(ty) => Some(super::ty::render(ty)),
        _ => None,
    })
}
