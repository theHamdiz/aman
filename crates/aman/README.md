# Aman - The Binary Integrity Backbone

> **"Security" in Arabic.**  
> The definitive, high-performance binary integrity & signing platform for Rust.

Aman is not just a library; it's a **compliance backbone**. It embeds cryptographic proofs directly into your executables, ensuring that *what you shipped is exactly what is running*.

---

## 🎯 Real-World Scenarios

Aman is built for distinct, high-stakes environments. Which one are you?

### Scenario A: The "Paranoid" Fintech CLI
**Problem**: You distribute a CLI tool handling crypto-wallets. If a malware wraps your binary or injects code, user funds are lost. You need **Runtime Self-Defense** and **Key Rotation** capabilities without forcing users to update the binary instantly.

**Solution**:
*   **Strict Enforcement**: App panics immediately if signature is invalid or debugger is detected.
*   **Key Rotation**: Use a long-lived Root Key to sign short-lived Delegate Keys. If a delegate key leaks, revoke it and issue a new certificate—users verify against the Root.

```rust
use aman::shield;

fn main() {
    // 🛡️ Enforces: Integrity + Anti-Debug + Expiry check
    // If verification fails, the process aborts with code 0xC0DE.
    shield! {
        keys: [include_str!("root.pub")],
        consensus: 1
    }
    
    println!("💸 Secure Transaction Started...");
}
```

### Scenario B: The Low-Power IoT Firmware
**Problem**: You are deploying firmware to embedded devices (ARM/RISC-V). You have 64KB RAM. You need verification, but standard `std` libraries are too heavy.

**Solution**:
*   **`no_std` Native**: Aman's core is `no_std` compatible (with `alloc`).
*   **Zero-Copy Verification**: Verifies binary content in-place using memory mapping (optional).
*   **Algorithm**: Use **Ed25519** for blazing fast verification on weak CPUs.

```toml
[dependencies]
aman = { version = "1.0", default-features = false, features = ["ed25519"] }
```

### Scenario C: The Corporate "3-of-5" Release
**Problem**: A rogue employee pushes a malicious update. You need to ensure that **at least 3 senior developers** have signed off on every release.

**Solution**:
*   **Multi-Signature**: Embed signatures from 5 different keys.
*   **Policy Enforcement**: Require `consensus: 3` at runtime.

```bash
# Developers sign independently
aman sign --binary myapp --key dev1.pem
aman sign --binary myapp --key dev2.pem
aman sign --binary myapp --key dev3.pem
```

---

## 🆚 Comparison

Why not just use GPG or OS Code Signing?

| Feature | Aman 🛡️ | GPG / Sigstore | OS Codesign (Authenticode/Codesign) |
| :--- | :---: | :---: | :---: |
| **Verification Scope** | **Self-Verifying** (App checks itself) | External (User checks file) | External (OS checks file) |
| **Runtime Enforcement** | ✅ **Yes** (Panic/Exit inside app) | ❌ No (Can run even if check fails) | ⚠️ OS Dependent |
| **Key Rotation** | ✅ **Root-of-Trust Chain** | ❌ Hard to rotate keys | ✅ Certificate Authorities |
| **Developer Experience** | **One Macro** (`shield!`) | ❌ Complexity Hell | ❌ Expensive Certs & Tooling |
| **Performance** | **Zero-Copy / Memory Mapped** | Slow (External processes) | Fast (Kernel space) |
| **Cross-Platform** | ✅ **Linux, Win, Mac, Embedded** | ✅ Linux/Mac mostly | ❌ OS Specific |

---

## 🛠️ Usage Guide

### 1. Installation

```toml
[dependencies]
aman = "1.0"
```

### 2. The Unified CLI (`aman`)

Aman v1.0 brings a unified toolchain.

**Generate Keys (Root CA):**
```bash
cargo run --bin aman -- keys root
# Outputs: root.pem, root.pub
```

**Generate Delegate Certificate (Valid 90 days):**
```bash
cargo run --bin aman -- keys delegate --root-key root.pem --days 90
# Outputs: delegate.pem, delegate.cert
```

**Sign Binary:**
```bash
# Standard Signing
aman sign --binary ./target/release/myapp --key delegate.pem --cert delegate.cert
```

### 3. Developer Macros

#### `aman::shield!` (Production)
The nuclear option. Use this for production releases.
```rust
aman::shield! {
    keys: [include_str!("root.pub")],
    consensus: 1
}
```

#### `aman::development!` (Debug Friendly)
Same as shield, but **warns** instead of panicking. Allows debuggers to attach.
```rust
aman::development! {
    keys: [include_str!("root.pub")]
}
```

#### `aman::check!` (Custom Logic)
Returns a `Result<(), String>` for custom error handling.
```rust
if let Err(e) = aman::check!(keys: [KEY]) {
    log::error!("Security alert: {}", e);
    // graceful shutdown
}
```

---

## 🧩 Architecture: The Aman Trust Chain

To solve the key rotation problem without forcing users to update their binaries, Aman separates **Trust Anchors** from **Signing Keys**.

1.  **Root Key (The Anchor)**: You embed the **Public Root Key** inside your binary. The Private Root Key is kept cold (offline/safe).
2.  **Delegate Key (The Signer)**: You create a temporary keypair for your CI/CD or daily signing.
3.  **Certificate**: The Root Key signs the Delegate Public Key + Expiry. This certificate is attached to the binary.

**Verification Flow:**
1.  App reads embedded **Root Key**.
2.  App reads attached **Certificate**.
3.  App validates Certificate signature using Root Key.
4.  App extracts **Delegate Key** from verified Certificate.
5.  App verifies binary integrity using Delegate Key.

---

## 📦 C / FFI Interop

Aman speaks universal C ABI. Verify your Rust binaries from Python, Node, or Legacy C++.

**Headers are automatic.**
We use `cbindgen` to generate a fresh `aman.h` every time you build. No more out-of-sync headers causing segfaults.

```c
#include "aman.h" // Generated in your target directory

int main() {
    const char* root_key = "...";
    if (aman_verify_self(root_key) != 0) {
        printf("Tampered binary!\n");
        return 1;
    }
    return 0;
}
```

## 🏗️ Project Structure

*   **`aman`**: The high-level library (what you are reading about).
*   **`aman-core`**: The low-level, `no_std` logic engine.
*   **`xaman`**: The hermetic build tool that orchestrates everything.

---

## License

MIT. Build with confidence.
