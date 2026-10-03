//! Adversarial and degenerate inputs.
//!
//! Build spec invariant 1: **the tool never panics on any input.** A security
//! scanner that crashes on one file in a repository is a scanner that gets
//! removed from CI. Each of these inputs is named in the spec's robustness list.

use std::fs;
use std::path::Path;

use tempfile::TempDir;
use wheeltap_core::ProgramContext;

fn tree(files: &[(&str, String)]) -> TempDir {
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
fn empty_and_comment_only_files() {
    let dir = tree(&[
        ("empty.rs", String::new()),
        ("comments.rs", "// nothing\n/* nor here */".into()),
        ("whitespace.rs", "\n\n   \n\t\n".into()),
    ]);

    let ctx = ProgramContext::scan(dir.path());
    assert_eq!(ctx.sources.len(), 3);
    assert!(ctx.diagnostics.is_empty());
    assert!(!ctx.looks_like_anchor());
}

/// `syn` is recursive-descent, so nesting costs stack, and the stack a caller
/// happens to provide varies — a test harness thread gets 2 MiB where the main
/// thread gets 8 MiB. Analysis therefore runs on a thread with a stack of its
/// own, and this test would abort without it.
#[test]
fn deeply_nested_generics() {
    let ty = "Box<".repeat(64) + "Account<'info, Vault>" + &">".repeat(64);
    let dir = tree(&[(
        "lib.rs",
        format!("#[derive(Accounts)] pub struct A<'info> {{ pub a: {ty}, }}"),
    )]);

    let (boxed, owner_checked) = wheeltap_core::loader::with_analysis_stack(|| {
        let ctx = ProgramContext::scan(dir.path());
        let field = &ctx
            .accounts
            .iter()
            .find(|a| a.name == "A")
            .expect("struct A")
            .fields[0];
        (field.ty.boxed, field.ty.is_owner_checked())
    });

    assert!(boxed);
    assert!(owner_checked, "sixty-four boxes still wrap an Account");
}

/// Past a point, no stack is enough, and a stack overflow aborts the process
/// rather than unwinding. Pathological nesting is therefore refused up front,
/// and reported as the coverage gap it is.
#[test]
fn pathologically_nested_source_is_skipped_with_a_warning() {
    let ty = "Box<".repeat(5_000) + "u8" + &">".repeat(5_000);
    let dir = tree(&[
        (
            "sane.rs",
            "#[derive(Accounts)] pub struct A<'info> { pub a: Signer<'info> }".into(),
        ),
        ("absurd.rs", format!("pub type Deep = {ty};")),
    ]);

    let ctx = ProgramContext::scan(dir.path());

    assert!(
        ctx.accounts.iter().find(|a| a.name == "A").is_some(),
        "the sane file is still analysed"
    );
    assert_eq!(ctx.diagnostics.len(), 1);
    assert!(ctx.diagnostics[0].path.ends_with("absurd.rs"));
    assert!(
        ctx.diagnostics[0].message.contains("nesting"),
        "{}",
        ctx.diagnostics[0].message
    );
}

#[test]
fn macro_heavy_code_does_not_derail_the_walk() {
    let dir = tree(&[(
        "lib.rs",
        r#"
            declare_id!("11111111111111111111111111111111");
            macro_rules! shout { ($x:expr) => { $x }; }
            solana_program::entrypoint!(process_instruction);

            #[program]
            pub mod thing {
                use super::*;
                pub fn go(ctx: Context<Go>) -> Result<()> { Ok(()) }
            }

            #[derive(Accounts)]
            pub struct Go<'info> { pub who: Signer<'info> }
        "#
        .into(),
    )]);

    let ctx = ProgramContext::scan(dir.path());
    assert_eq!(ctx.programs.len(), 1);
    assert_eq!(ctx.entrypoints().count(), 1);
    assert!(ctx.accounts.iter().find(|a| a.name == "Go").is_some());
}

/// Code inside a macro *invocation* is opaque to `syn`. That is a real limit of
/// syntactic analysis (ADR-001), and the point of this test is to pin the
/// behaviour honestly rather than to claim we see through it.
#[test]
fn accounts_declared_inside_a_macro_body_are_not_modelled() {
    let dir = tree(&[(
        "lib.rs",
        r"
            generate_accounts! {
                #[derive(Accounts)]
                pub struct Hidden<'info> { pub who: Signer<'info> }
            }
        "
        .into(),
    )]);

    let ctx = ProgramContext::scan(dir.path());
    assert!(
        ctx.accounts.iter().find(|a| a.name == "Hidden").is_none(),
        "a known limit: macro-generated items are invisible to a syntactic analyser"
    );
    assert_eq!(ctx.diagnostics.len(), 1, "invisible, but said so");
    assert!(ctx.diagnostics[0].message.contains("generate_accounts!"));
    assert_eq!(ctx.diagnostics[0].line, Some(2));
}

/// A macro whose *definition* is in the scan and emits Accounts structs is
/// reported at each invocation, even when the invocation passes nothing that
/// looks like Anchor. A macro that emits ordinary code is not reported: most
/// item-level macros are `declare_id!` and trait impls, and a warning on each
/// would bury the one that matters.
#[test]
fn invocations_of_macros_that_emit_accounts_are_reported() {
    let dir = tree(&[
        (
            "macros.rs",
            r"
                macro_rules! accounts_for {
                    ($name:ident) => {
                        #[derive(Accounts)]
                        pub struct $name<'info> { pub who: Signer<'info> }
                    };
                }
                macro_rules! impl_size {
                    ($t:ty) => { impl $t { pub const SIZE: usize = 8; } };
                }
            "
            .into(),
        ),
        (
            "lib.rs",
            "declare_id!(\"Mac111\");
accounts_for!(Hidden);
impl_size!(Vault);"
                .into(),
        ),
    ]);

    let ctx = ProgramContext::scan(dir.path());
    let messages: Vec<_> = ctx.diagnostics.iter().map(|d| d.message.as_str()).collect();
    assert_eq!(messages.len(), 1, "{messages:?}");
    assert!(messages[0].contains("accounts_for!"));
}

/// Field types are seen through `type` aliases, including aliases that hide
/// the `Box` or name another alias. A cycle terminates.
#[test]
fn field_types_are_seen_through_aliases() {
    use wheeltap_core::model::ty::AnchorType;

    let dir = tree(&[
        (
            "types.rs",
            r"
                pub type VaultAccount<'info> = Box<Account<'info, Vault>>;
                pub type Raw<'info> = UncheckedAccount<'info>;
                pub type StillRaw<'info> = Raw<'info>;
                pub type Loop = Pool;
                pub type Pool = Loop;
            "
            .into(),
        ),
        (
            "lib.rs",
            r"
                #[derive(Accounts)]
                pub struct A<'info> {
                    pub vault: VaultAccount<'info>,
                    pub raw: StillRaw<'info>,
                    pub cyclic: Loop,
                }
            "
            .into(),
        ),
    ]);

    let ctx = ProgramContext::scan(dir.path());
    let a = ctx.accounts.iter().find(|a| a.name == "A").expect("A");

    let vault = &a.field("vault").expect("vault").ty;
    assert_eq!(
        vault.anchor,
        AnchorType::Account {
            inner: "Vault".into()
        }
    );
    assert!(vault.boxed);
    assert_eq!(
        vault.text, "VaultAccount<'info>",
        "written as the author wrote it"
    );

    assert!(
        a.field("raw").expect("raw").ty.is_unchecked(),
        "through two aliases"
    );
    assert!(a.field("cyclic").is_some(), "a cycle terminates");
}

#[test]
fn a_very_large_file_is_handled() {
    let mut source = String::from("#[derive(Accounts)] pub struct Big<'info> {\n");
    for i in 0..5_000 {
        source.push_str(&format!(
            "    #[account(mut)] pub field_{i}: Signer<'info>,\n"
        ));
    }
    source.push_str("}\n");

    let dir = tree(&[("big.rs", source)]);
    let ctx = ProgramContext::scan(dir.path());

    let big = ctx
        .accounts
        .iter()
        .find(|a| a.name == "Big")
        .expect("Big modelled");
    assert_eq!(big.fields.len(), 5_000);
    assert!(big.fields.iter().all(|f| f.constraints.is_mut()));
}

#[test]
fn a_symlink_loop_does_not_hang_the_walk() {
    let dir = tree(&[("src/lib.rs", "pub fn a() {}".into())]);

    #[cfg(unix)]
    std::os::unix::fs::symlink(dir.path(), dir.path().join("src/loop"))
        .expect("create symlink loop");

    // Symlinks are not followed, so this terminates.
    let ctx = ProgramContext::scan(dir.path());
    assert_eq!(ctx.sources.len(), 1);
}

#[test]
fn unreadable_and_unparseable_files_are_reported_not_fatal() {
    let dir = tree(&[
        (
            "good.rs",
            "#[derive(Accounts)] pub struct A<'info> { pub a: Signer<'info> }".into(),
        ),
        ("broken.rs", "pub struct Nope { ".into()),
    ]);
    fs::write(dir.path().join("binary.rs"), [0xff, 0xfe, 0x00]).expect("write");

    let ctx = ProgramContext::scan(dir.path());
    assert!(
        ctx.accounts.iter().find(|a| a.name == "A").is_some(),
        "good file still analysed"
    );
    assert_eq!(ctx.diagnostics.len(), 2, "{:?}", ctx.diagnostics);
}

#[test]
fn scanning_a_path_that_does_not_exist_is_not_fatal() {
    let ctx = ProgramContext::scan(Path::new("/no/such/path/anywhere"));
    assert!(ctx.sources.is_empty());
    assert_eq!(ctx.diagnostics.len(), 1);
}

/// A tuple struct is not an account list; unnamed fields must not panic the
/// field walk.
#[test]
fn accounts_struct_with_unnamed_fields() {
    let dir = tree(&[(
        "lib.rs",
        "#[derive(Accounts)] pub struct Tuple<'info>(pub Signer<'info>);".into(),
    )]);

    let ctx = ProgramContext::scan(dir.path());
    let tuple = ctx
        .accounts
        .iter()
        .find(|a| a.name == "Tuple")
        .expect("modelled");
    assert!(tuple.fields.is_empty());
}

/// Two programs in one workspace define the same names, which Anchor's own
/// templates make the norm: every program has an `Initialize`. A name must
/// resolve to the definition nearest the code using it, not to whichever the
/// loader happened to read first. Before this was fixed, scanning the
/// vulnerable corpus reported WT005 against one fixture using the fields of
/// another fixture's `Config`.
#[test]
fn names_resolve_to_the_nearest_definition() {
    let program = |admin_field: &str| {
        format!(
            "pub fn set(ctx: Context<Set>) -> Result<()> {{ Ok(()) }}
             #[derive(Accounts)]
             pub struct Set<'info> {{ #[account(mut)] pub config: Account<'info, Config> }}
             #[account]
             pub struct Config {{ {admin_field} pub fee: u16 }}"
        )
    };
    let dir = tree(&[
        ("a/src/lib.rs", program("pub admin: Pubkey,")),
        ("b/src/instructions.rs", program("")),
        (
            "b/src/state.rs",
            "#[account] pub struct Unrelated { pub x: u8 }".into(),
        ),
    ]);
    let ctx = ProgramContext::scan(dir.path());

    for handler in &ctx.handlers {
        let accounts = ctx.handler_accounts(handler).expect("resolved");
        assert_eq!(accounts.file, handler.file, "a handler's own struct");

        let config = ctx.state("Config", handler.file).expect("Config resolved");
        assert_eq!(
            config.file, handler.file,
            "the Config beside it, not the other"
        );
        assert_eq!(
            ctx.handlers_for(accounts).count(),
            1,
            "each struct has one handler"
        );
    }
}
