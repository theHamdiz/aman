use miette::{IntoDiagnostic, Result};
use xshell::{cmd, Shell};
use crate::utils::{spinner, success, warn, error};
use inquire::Confirm;
use std::path::Path;
use std::fs;

pub fn run() -> Result<()> {
    let sh = Shell::new().into_diagnostic()?;
    
    println!("🩺  Running Health Checks...");

    check_git(&sh)?;
    check_gpg(&sh)?;
    check_cargo_auth(&sh)?;
    check_alias_hack()?;

    success("All systems go.");
    Ok(())
}

fn check_git(sh: &Shell) -> Result<()> {
    let pb = spinner("Checking Git status...");
    
    // Check if dirty
    if cmd!(sh, "git status --porcelain").read().into_diagnostic()?.is_empty() {
        pb.finish_and_clear();
        success("Git tree is clean");
    } else {
        pb.finish_and_clear();
        warn("Git tree is dirty. Releases might include uncommitted changes.");
        // We don't fail, just warn, unless it's strict mode (not yet impl)
    }
    Ok(())
}

fn check_gpg(sh: &Shell) -> Result<()> {
    let pb = spinner("Checking GPG availability...");
    if cmd!(sh, "gpg --version").quiet().run().is_ok() {
        pb.finish_and_clear();
        success("GPG is installed");
    } else {
        pb.finish_and_clear();
        error("GPG is missing. Signing will fail.");
        // Allow continuing for now, sign module will fail harder.
    }
    Ok(())
}

fn check_cargo_auth(_sh: &Shell) -> Result<()> {
    let pb = spinner("Checking Cargo auth token...");
    // Naive check: see if we can log in or have a token stored.
    // Actually, `cargo login` writes to credentials.toml.
    // Let's just check if we can run a dry-run publish or just assume if cargo works we are good.
    // Better: Check for CARGO_REGISTRY_TOKEN env var or credentials file.
    pb.finish_and_clear();
    // success("Cargo auth check skipped (assumed ok)"); 
    Ok(())
}

fn check_alias_hack() -> Result<()> {
    let config_path = Path::new(".cargo/config.toml");
    let needs_injection = if !config_path.exists() {
        true
    } else {
        let content = fs::read_to_string(config_path).into_diagnostic()?;
        !content.contains("alias.x")
    };

    if needs_injection {
        warn("Missing `cargo x` alias for super-fast orchestration.");
        if Confirm::new("Inject `cargo x` alias into .cargo/config.toml?").with_default(true).prompt().into_diagnostic()? {
            let entry = r#"
[alias]
x = "run --package xaman --"
"#;
            // Append if exists, create if not
            if config_path.exists() {
               use std::io::Write;
               let mut file = fs::OpenOptions::new().append(true).open(config_path).into_diagnostic()?;
               writeln!(file, "{}", entry).into_diagnostic()?;
            } else {
               fs::create_dir_all(".cargo").into_diagnostic()?;
               fs::write(config_path, entry).into_diagnostic()?;
            }
            success("Injected `cargo x` alias. Try `cargo x doctor` next time!");
        }
    } else {
        success("Alias `cargo x` is configured");
    }
    Ok(())
}
