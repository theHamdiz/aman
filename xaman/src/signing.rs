use miette::{Context, IntoDiagnostic, Result};
use secrecy::{SecretVec};
use std::path::Path;

pub fn sign_artifacts() -> Result<()> {
    // TODO: support custom target dirs, hardcoded for now cause I'm lazy
    let target_dir = Path::new("target/release");
    
    // Win
    let exe_path = target_dir.join("aman.exe");
    if exe_path.exists() {
        println!("got windows binary: {:?}", exe_path);
        sign_pe(&exe_path)?;
    }

    // *nix
    let bin_path = target_dir.join("aman");
    if bin_path.exists() {
        // check for mach-o magic bytes
        if is_macho(&bin_path) {
            println!("found mach-o: {:?}", bin_path);
            sign_macho(&bin_path)?;
        } else {
             println!("found binary but not mach-o, probably elf: {:?}", bin_path);
        }
    }
    
    Ok(())
}

fn is_macho(path: &Path) -> bool {
    // rudimentary check
    use std::fs::File;
    use std::io::Read;
    if let Ok(mut f) = File::open(path) {
        let mut buf = [0u8; 4];
        if f.read_exact(&mut buf).is_ok() {
            // MH_MAGIC_64 etc
            return matches!(buf, 
                [0xfe, 0xed, 0xfa, 0xcf] | 
                [0xcf, 0xfa, 0xed, 0xfe]
            );
        }
    }
    false
}

fn sign_macho(path: &Path) -> Result<()> {
    // defaults
    let key_var = "MACOS_SIGNING_KEY";

    if std::env::var(key_var).is_err() {
        // cant sign without a key obviously
        println!("skipping mach-o signing: {} missing", key_var);
        return Ok(());
    }

    /*
    // code below for when we actually buy the certs
    let _key_data = load_secret(key_var)?;
    let _cert_data = load_secret("MACOS_CERTIFICATE")?;
    let settings = SigningSettings::default(); 
    let signer = UnifiedSigner::new(settings);
    let output_path = path.with_extension("signed");
    signer.sign_path(path, &output_path)
       .map_err(|e| miette::miette!("signing failed: {}", e))?;
    std::fs::rename(&output_path, path).into_diagnostic()?;
    */
        
    println!("fake signed mach-o at {:?}", path);
    Ok(())
}

fn sign_pe(_path: &Path) -> Result<()> {
    if std::env::var("WINDOWS_SIGNING_KEY").is_err() {
         println!("skipping authenticode: no key");
         return Ok(());
    }

    // TODO: implement actual signing with tugger-windows-codesign
    println!("would sign here if implemented");
    Ok(())
}

#[allow(dead_code)]
fn load_secret(env_var: &str) -> Result<SecretVec<u8>> {
    let var = std::env::var(env_var)
       .into_diagnostic()
       .wrap_err_with(|| format!("need env var {} for signing", env_var))?;
        
    Ok(SecretVec::new(var.into_bytes()))
}

pub fn verify_signature(_path: &Path) -> Result<()> {
    println!("verify placeholder"); // TODO
    Ok(())
}
