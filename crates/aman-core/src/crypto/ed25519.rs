// region: Imports
use super::{Signer, Verifier};
use ed25519_dalek::{SigningKey, VerifyingKey, Signer as _, Verifier as _, Signature};
use ed25519_dalek::pkcs8::{DecodePrivateKey, DecodePublicKey};
use sha2::{Sha256, Digest};
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::format;
// endregion: Imports

// region: Signer Implementation
pub struct Ed25519Signer {
    key: SigningKey,
    kid: String,
}

impl Ed25519Signer {
    pub fn from_pem(pem: &str) -> Result<Self, String> {
        let key = SigningKey::from_pkcs8_pem(pem)
                .map_err(|e| format!("Invalid Ed25519 Private Key: {}", e))?;

        let vk = VerifyingKey::from(&key);
        let kid = hex::encode(Sha256::digest(vk.as_bytes()));

        Ok(Self { key, kid })
    }
}

impl Signer for Ed25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        let signature: Signature = self.key.sign(message);
        Ok(signature.to_vec())
    }

    fn algorithm(&self) -> crate::metadata::Algorithm {
        crate::metadata::Algorithm::Ed25519
    }
    
    fn key_id(&self) -> String {
        self.kid.clone()
    }
}
// endregion: Signer Implementation

// region: Verifier Implementation
pub struct Ed25519Verifier {
    key: VerifyingKey,
    kid: String,
}

impl Ed25519Verifier {
    pub fn from_pem(pem: &str) -> Result<Self, String> {
            let key = VerifyingKey::from_public_key_pem(pem)
            .map_err(|e| format!("Invalid Ed25519 Public Key: {}", e))?;
            
        let kid = hex::encode(Sha256::digest(key.as_bytes()));
        Ok(Self { key, kid })
    }
}

impl Verifier for Ed25519Verifier {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), String> {
        let signature = Signature::from_slice(signature)
                .map_err(|_| "Invalid Ed25519 signature bytes".to_string())?;

        self.key.verify(message, &signature)
                .map_err(|_| "Ed25519 verification failed".to_string())
    }

    fn algorithm(&self) -> crate::metadata::Algorithm {
        crate::metadata::Algorithm::Ed25519
    }
    
    fn key_id(&self) -> String {
        self.kid.clone()
    }
}
// endregion: Verifier Implementation

// region: Tests
#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_garbage_ed25519_pem() {
        let res = Ed25519Verifier::from_pem("-----BEGIN GARBAGE-----");
        assert!(res.is_err());
    }
}
// endregion: Tests
