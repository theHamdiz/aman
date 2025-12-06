// region: Imports
extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;
// endregion: Imports

// region: Modules
#[cfg(feature = "p256")]
pub mod p256;
#[cfg(feature = "ed25519")]
pub mod ed25519;
// endregion: Modules

// region: Traits
/// A trait for cryptographic signing.
pub trait Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String>;
    fn algorithm(&self) -> crate::metadata::Algorithm;
    fn key_id(&self) -> String; // SHA256 of public key
}

/// A trait for cryptographic verification.
pub trait Verifier {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), String>;
    fn algorithm(&self) -> crate::metadata::Algorithm;
    fn key_id(&self) -> String;
}
// endregion: Traits
