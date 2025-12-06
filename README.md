# Features
---
## Crypto stuff

Supports P-256 (the standard one) and Ed25519 (the faster one).
Can switch between SHA-256 or BLAKE3 for hashing depending on if you need speed or compatibility.
Security

Multisig support: you can require multiple people to sign a release (like 3 out of 5 devs).
Runtime checks: it tries to panic if it spots a debugger attached to the process.
Timestamps: keys and signatures can have expiry dates so they don't last forever.
Certificate chains: supports using delegate keys so you don't have to use your root key for everything.
Performance

Works with `no_std` for embedded/bare metal.
Uses memory mapping for big files so it doesn't eat all your RAM verifying things.
Modular, so you can strip out what you don't use.
Tools (`xaman`)

CLI helper for signing files in your CI pipeline.   

Helps manage versioning and releases.  

> Has a `doctor` command to check if your setup is broken.
