# Aman Core

> **The brain of the operation.**  
> Pure Rust, `no_std` compatible cryptographic verification logic.

Aman Core is the stripped-down, lightweight engine that powers the main Aman library. If you are building for embedded environments (like ARM Cortex-M, RISC-V) or just want the pure verification logic without the filesystem and CLI baggage, this is where you start.

## Why use Core?

* **`no_std` Native**: Zero reliance on the standard library. If you have an allocator, you can run this.
* **Pure Logic**: It takes bytes in, and tells you if they are trustworthy. No IO, no side effects.
* **Agnostic**: Works with any data source—file streams, memory buffers, or network packets.

## Quick Start

```toml
[dependencies]
aman-core = "0.1"
```

```rust
use aman_core::engine::CoreVerifier;

// 1. Setup your trust anchor (Root Public Key)
let verifier = CoreVerifier::new()
    .trust(Box::new(my_key));

// 2. Verify bytes
let data = b"Important firmware update";
let metadata = ...; // Parsed elsewhere

match verifier.verify_content(data, &metadata) {
    Ok(_) => { /* Safe to boot */ },
    Err(e) => { /* Panic immediately! */ }
}
```

This crate is the foundation. For the full experience (FS support, CLI, Macros), check out the parent `aman` crate.
