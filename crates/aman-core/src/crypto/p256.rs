// region: Imports
use super::{Signer, Verifier};
use p256::ecdsa::{SigningKey, VerifyingKey, Signature, signature::{Signer as _, Verifier as _}};
use p256::pkcs8::{DecodePrivateKey, DecodePublicKey};
use sha2::{Sha256, Digest};
use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
// endregion: Imports

// region: Signer Implementation
pub struct P256Signer {
    key: SigningKey,
    kid: String,
}

impl P256Signer {
    pub fn from_pem(pem: &str) -> Result<Self, String> {
        let key = SigningKey::from_pkcs8_pem(pem)
            .map_err(|e| format!("Invalid P256 Private Key: {}", e))?;
            
        // Calculate Key ID from Verifying Key
        let vk = VerifyingKey::from(&key);
        let vk_bytes = vk.to_encoded_point(false).as_bytes().to_vec();
        let kid = hex::encode(Sha256::digest(&vk_bytes));
        
        Ok(Self { key, kid })
    }
}

impl Signer for P256Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        let signature: Signature = self.key.sign(message);
        Ok(signature.to_vec())
    }
    
    fn algorithm(&self) -> crate::metadata::Algorithm {
        crate::metadata::Algorithm::P256
    }
    
    fn key_id(&self) -> String {
        self.kid.clone()
    }
}
// endregion: Signer Implementation

// region: Verifier Implementation
pub struct P256Verifier {
    key: VerifyingKey,
    kid: String,
}

impl P256Verifier {
    pub fn from_pem(pem: &str) -> Result<Self, String> {
        let key = VerifyingKey::from_public_key_pem(pem)
            .map_err(|e| format!("Invalid P256 Public Key: {}", e))?;
            
        let vk_bytes = key.to_encoded_point(false).as_bytes().to_vec();
        let kid = hex::encode(Sha256::digest(&vk_bytes));
        
        Ok(Self { key, kid })
    }

    pub fn from_der(der: &[u8]) -> Result<Self, String> {
        let key = VerifyingKey::from_public_key_der(der)
                .map_err(|e| format!("Invalid P256 DER Key: {}", e))?;
        
        let vk_bytes = key.to_encoded_point(false).as_bytes().to_vec();
        let kid = hex::encode(Sha256::digest(&vk_bytes));
        
        Ok(Self { key, kid })
    }
}

impl Verifier for P256Verifier {
    fn verify(&self, message: &[u8], signature: &[u8]) -> Result<(), String> {
        let signature = Signature::try_from(signature)
            .map_err(|_| format!("Invalid P256 signature bytes"))?;
            
        self.key.verify(message, &signature)
            .map_err(|_| format!("P256 verification failed"))
    }
    fn algorithm(&self) -> crate::metadata::Algorithm {
        crate::metadata::Algorithm::P256
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
    use alloc::vec;
    use p256::pkcs8::EncodePublicKey;
    
    // Tricky: Garbage data for P256
    #[test]
    fn test_garbage_p256_der() {
        let garbage = vec![0u8, 1, 2, 3, 255];
        let res = P256Verifier::from_der(&garbage);
        assert!(res.is_err(), "Garbage DER should fail parsing");
    }

    #[test]
    fn test_garbage_p256_signature() {
        // Need a valid key to test signature verification failure
        // Generating random key for test
        // This requires 'rand' feature which is enabled in tests via dev-dep or default features
        use p256::ecdsa::SigningKey;
        use rand::rngs::OsRng;
        
        let signing_key = SigningKey::random(&mut OsRng);
        let verifying_key = p256::ecdsa::VerifyingKey::from(&signing_key);
        let der = verifying_key.to_public_key_der().unwrap().as_bytes().to_vec();
        
        let verifier = P256Verifier::from_der(&der).expect("Key gen failed");
        
        let msg = b"test";
        let garbage_sig = vec![0u8; 64];
        let res = verifier.verify(msg, &garbage_sig);
        assert!(res.is_err(), "Garbage signature should fail");
    }
}
// endregion: Tests
