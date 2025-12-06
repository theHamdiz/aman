use miette::{IntoDiagnostic, Result, Context};
use xshell::{cmd, Shell};
use crate::utils::{spinner, success, info};
use std::path::PathBuf;
use std::fs;

// No, prompt said strict deps. sha2 is NOT in xaman strict deps list.
// We must use `openssl` or `shasum` command if strictly using prompt deps, OR assume we can add sha2.
// The strict list in prompt did NOT include sha2. 
// "Dependencies (Strictly Enforced in xaman/Cargo.toml): clap, miette, xshell, toml_edit, semver, inquire, indicatif, console."
// So I must calculate SHA256 using shell command `shasum -a 256` or similar, OR strictness was about CORE.
// Actually, `xshell` implies we can run system commands. Let's use `shasum` or `certutil` (Windows) or just add sha2 if user permits.
// User said "Strictly Enforced". I will stick to shell commands if possible, but `sha2` is safer.
// Let's rely on `xshell` to call `openssl` or python for hash? No that's fragile.
// Wait, `aman` crate has `sha2`. `xaman` usually shouldn't depend on crypto lib if it orchestrates tools.
// But the prompt says "SHA256 checksum it".
// I'll add `sha2` to `xaman/Cargo.toml` as it's a standard utility, OR use a pure rust implementation inline? No.
// Let's assume generic sha2 crate is allowed for "write the complete source code". I will add it to Cargo.toml.
// WAIT. The prompt said "Dependencies (Strictly Enforced...)"
// I will adhere to strict deps. I will read the file and manual implementation of sha result? No. 
// I will use `cmd!(sh, "openssl dgst -sha256 ...")` or fail if not present?
// Actually, `check_gpg` exists. `openssl` might not.
// Let's check if I can add hashing crate. No, user was specific.
// I will use `certutil` on windows and `shasum` on linux/mac via xshell.

pub fn run() -> Result<()> {
    let sh = Shell::new().into_diagnostic()?;
    
    // 1. Build Release
    info("Building Release Binary...");
    {
        let _s = spinner("Compiling optimized binary...");
        cmd!(sh, "cargo build --release -p aman").run().into_diagnostic()?;
    }
    
    // 2. Locate Artifact
    // Hack: assume standard target layour
    let ext = if cfg!(windows) { ".exe" } else { "" };
    let binary_path = PathBuf::from(format!("target/release/aman{}", ext));
    
    if !binary_path.exists() {
         return Err(miette::miette!("Binary not found at {:?}", binary_path));
    }

    // 3. Tarball / Zip
    // xshell doesn't do tar. Need system tar or zip.
    // Windows might not have tar. 
    // "Tarball the binary".
    let tar_name = "aman-release.tar.gz";
    {
        let _s = spinner("Archiving...");
        // Use system tar. Windows 10+ has tar.
        cmd!(sh, "tar -czf {tar_name} -C target/release aman{ext}").run()
            .into_diagnostic()
            .wrap_err("Failed to create tarball. Ensure 'tar' is in PATH.")?;
    }
    
    // 4. SHA256 Checksum

    // We can't use sha2 crate provided limitations.
    // But we need to output the hash.
    // I will implementation a simple hash or use system tool.
    // Let's use generic `sha2` crate if I can't avoid it.
    // Actually, I'll cheat and use the `sha2` crate, updating the manifest, 
    // because writing a sha256 implementation from scratch is out of scope for "no fluff" code.
    // .. Wait, I can't update manifest if strict.
    // I will use system command for checksum.
    
    let shasum = checksum_file(&sh, tar_name)?;
    println!("🔥 SHA256: {}", shasum);
    fs::write(format!("{}.sha256", tar_name), &shasum).into_diagnostic()?;

    // 5. GPG Sign
    if inquire::Confirm::new("Sign artifact with GPG?").with_default(true).prompt().into_diagnostic()? {
        let _s = spinner("Signing...");
        // Interactive passphrase is handled by GPG agent usually.
        cmd!(sh, "gpg --detach-sign --armor {tar_name}").run().into_diagnostic()?;
        success("Artifact signed.");
        
        // 6. Self-Verify
        info("Verifying signature...");
        cmd!(sh, "gpg --verify {tar_name}.asc {tar_name}").run().into_diagnostic()?;
        success("Self-Check Passed: Signature is valid.");
    }

    Ok(())
}

fn checksum_file(sh: &Shell, path: &str) -> Result<String> {
    if cfg!(windows) {
        // certutil -hashfile path SHA256
        let output = cmd!(sh, "certutil -hashfile {path} SHA256").read().into_diagnostic()?;
        // output format is header, hex, footer. split lines, take second line roughly.
        let lines: Vec<&str> = output.lines().collect();
        // Typically line 2 (0-indexed line 1) has the hash.
        // Or remove spaces.
        if lines.len() >= 2 {
            Ok(lines[1].replace(" ", "").to_lowercase())
        } else {
             Err(miette::miette!("Failed to parse certutil output"))
        }

    } else {
        // shasum -a 256 path
        let output = cmd!(sh, "shasum -a 256 {path}").read().into_diagnostic()?;
        // output: "hash  filename"
        Ok(output.split_whitespace().next().unwrap_or("").to_string())
    }
}
