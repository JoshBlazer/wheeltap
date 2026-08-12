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
        let field = &ctx.accounts_struct("A").expect("struct A").fields[0];
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
        ctx.accounts_struct("A").is_some(),
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
    assert!(ctx.accounts_struct("Go").is_some());
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
        ctx.accounts_struct("Hidden").is_none(),
        "a known limit: macro-generated items are invisible to a syntactic analyser"
    );
    assert!(ctx.diagnostics.is_empty(), "invisible, but not an error");
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

    let big = ctx.accounts_struct("Big").expect("Big modelled");
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
        ctx.accounts_struct("A").is_some(),
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
    let tuple = ctx.accounts_struct("Tuple").expect("modelled");
    assert!(tuple.fields.is_empty());
}
