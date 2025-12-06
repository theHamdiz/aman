# Xaman: The Orchestrator

> **"Safety" in Arabic.**  
> The God-tier release manager for Aman.

We've all been there. You have a `release.sh` script that only works on your machine because you installed `sed` via Homebrew 3 years ago. You're terrified to touch it.

**Xaman is the answer.** It replaces fragile shell scripts with strongly-typed, cross-platform Rust code.

## Before vs. After

| Feature | The Old Way (Bash/Make) | Xaman (Rust) |
| :--- | :--- | :--- |
| **Logic** | String bashing & Regex | Semver parsing & structs |
| **Platform** | Fails on Windows (CRLF issues) | Native Windows/Linux/Mac |
| **Safety** | "Did I run git clean?" | Enforced `doctor` checks |
| **Interact** | `read -p "Are you sure?"` | Beautiful TUIs (Inquire) |
| **Error** | `exit 1` (Silent failure) | `miette` fancy reports |

## Architecture

Xaman isn't just a script; it's a binary crate in the workspace.

* **`doctor`**: Ensures your environment is sane (Git status, GPG, Auth).
* **`version`**: interactive semantic version bumping + Git tagging.
* **`sign`**: Hermetic release building, checksumming, and GPG signing.

## Ingenious Hacks included

1. **The `.cargo/config.toml` Injection**:
    Run `cargo run -p xaman -- doctor` once. It detects if you lack the alias and injects `cargo x` into your config. Now you just type `cargo x sign`.

2. **Self-Verification**:
    When you run `cargo x sign`, we don't just generate the artifacts. We immediately run `gpg --verify` on the output to ensure the signature is valid *before* you upload it. Trust, but verify.

3. **Strict Dependencies**:
    We stripped out `openssl` compilation headaches. Hash calculation uses system native tools (`certutil` on Windows, `shasum` on Unix), orchestrated via `xshell`.

## Usage

```bash
# 1. Diagnose
cargo x doctor

# 2. bump version (Interactive)
cargo x version

# 3. Build & Sign
cargo x sign
```
