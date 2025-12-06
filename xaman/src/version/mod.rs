use miette::{IntoDiagnostic, Result};
use xshell::{cmd, Shell};
use crate::utils::{spinner, success};
use inquire::Select;
use std::fs;
use toml_edit::{DocumentMut, value};
use semver::Version;

pub fn run() -> Result<()> {
    let sh = Shell::new().into_diagnostic()?;
    let manifest_path = "crates/aman/Cargo.toml";
    
    // 1. Read Manifest
    let manifest_content = fs::read_to_string(manifest_path).into_diagnostic()?;
    let mut doc = manifest_content.parse::<DocumentMut>().into_diagnostic()?;
    
    let current_version_str = doc["package"]["version"].as_str().unwrap_or("0.0.0");
    let current_version = Version::parse(current_version_str).into_diagnostic()?;

    println!("📦 Current Version: {}", current_version);

    // 2. Interactive Bump
    let bump_type = Select::new("Bump version:", vec!["Patch", "Minor", "Major", "Custom"]).prompt().into_diagnostic()?;
    
    let new_version = match bump_type {
        "Custom" => {
             let input = inquire::Text::new("Enter version:").prompt().into_diagnostic()?;
             Version::parse(&input).into_diagnostic()?
        }
        _ => calculate_bump(&current_version, bump_type),
    };

    if !inquire::Confirm::new(&format!("Bump to {}?", new_version)).with_default(true).prompt().into_diagnostic()? {
        return Ok(());
    }

    // 3. Write Config
    doc["package"]["version"] = value(new_version.to_string());
    fs::write(manifest_path, doc.to_string()).into_diagnostic()?;
    success(&format!("Updated Cargo.toml to {}", new_version));

    // 4. Sync Lockfile
    let pb = spinner("Syncing cargo metadata...");
    cmd!(sh, "cargo metadata --format-version 1").quiet().run().into_diagnostic()?;
    pb.finish_and_clear();
    
    // 5. Git Tag
    if inquire::Confirm::new("Create Git Tag?").with_default(true).prompt().into_diagnostic()? {
         let tag_name = format!("v{}", new_version);
         cmd!(sh, "git tag -a {tag_name} -m 'Release {tag_name}'").run().into_diagnostic()?;
         success(&format!("Created git tag {}", tag_name));
    }

    Ok(())
}

fn calculate_bump(v: &Version, bump: &str) -> Version {
    let mut v = v.clone();
    match bump {
        "Patch" => v.patch += 1,
        "Minor" => {
            v.minor += 1;
            v.patch = 0;
        }
        "Major" => {
            v.major += 1;
            v.minor = 0;
            v.patch = 0;
        }
        _ => {}
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bump_logic() {
        let v = Version::parse("1.2.3").unwrap();
        
        assert_eq!(calculate_bump(&v, "Patch"), Version::parse("1.2.4").unwrap());
        assert_eq!(calculate_bump(&v, "Minor"), Version::parse("1.3.0").unwrap());
        assert_eq!(calculate_bump(&v, "Major"), Version::parse("2.0.0").unwrap());
    }
}
