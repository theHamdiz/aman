use crate::metadata::AmanMetadata;
use alloc::string::String;
use alloc::vec::Vec;


pub const MAGIC_MARKER: &[u8; 4] = b"AMAN";
pub const TRAILING_METADATA_SIZE: u64 = 8;

pub struct CoreVerifier {
    trusted_keys: Vec<alloc::boxed::Box<dyn crate::crypto::Verifier>>,
    required_signatures: usize,
    check_expiry: bool,
    now: Option<i64>, 
}

impl CoreVerifier {
    pub fn new() -> Self {
        Self {
            trusted_keys: Vec::new(),
            required_signatures: 1, 
            check_expiry: true,
            now: None,
        }
    }

    pub fn trust(mut self, verifier: alloc::boxed::Box<dyn crate::crypto::Verifier>) -> Self {
        self.trusted_keys.push(verifier);
        self
    }
    
    pub fn consensus(mut self, needed: usize) -> Self {
        self.required_signatures = needed;
        self
    }
    
    pub fn enforce_expiry(mut self, check: bool, current_time: Option<i64>) -> Self {
        self.check_expiry = check;
        self.now = current_time;
        self
    }

    // pure logic verifier
    pub fn verify_content(&self, content: &[u8], metadata: &AmanMetadata) -> Result<(), String> {
        #[cfg(feature = "blake3")]
        let hash = {
             let mut hasher = blake3::Hasher::new();
             hasher.update(content);
             let output = hasher.finalize();
             let bytes: [u8; 32] = output.into();
             bytes.to_vec()
        };

        #[cfg(not(feature = "blake3"))]
        let hash = {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(content);
            hasher.finalize().to_vec()
        };

        if hash != metadata.hash {
             return Err(alloc::format!("integrity fail: hash mismatch (exp {}, got {})", metadata.hash.len(), hash.len()));
        }

        if self.check_expiry {
            if let Some(expiry) = metadata.expiry {
                if let Some(now) = self.now {
                    if now > expiry {
                         return Err(alloc::format!("binary expired (t: {}, now: {})", expiry, now));
                    }
                }
            }
        }

        // if we have a cert, we use IT to verify signatures, but first we verify IT with our roots
        let mut active_verifiers: Vec<alloc::boxed::Box<dyn crate::crypto::Verifier>> = Vec::new();
        
        if let Some(cert) = &metadata.certificate {
            let mut root_found = false;
            
            // payload = delegate_key + expiry
            let mut payload = cert.delegate_pub_key.clone();
            payload.extend_from_slice(&cert.expiry.to_le_bytes());
            
            for root in &self.trusted_keys {
                // try all roots, we dont track rot kid
                if root.verify(&payload, &cert.root_signature).is_ok() {
                    root_found = true;
                    break;
                }
            }
            
            if !root_found {
                 return Err(alloc::format!("cert verify fail: no trusted root found"));
            }
            
            if self.check_expiry {
                if let Some(now) = self.now {
                    if now > cert.expiry {
                        return Err(alloc::format!("cert expired, rotate keys"));
                    }
                }
            }
            
            // use delegate key
            #[cfg(feature = "p256")]
            {
                active_verifiers.push(alloc::boxed::Box::new(crate::crypto::p256::P256Verifier::from_der(&cert.delegate_pub_key).map_err(|e| alloc::format!("bad delegate key: {}", e))?));
            }
        }

        let mut valid_count = 0;
        
        let keys_to_check = if metadata.certificate.is_some() {
            &active_verifiers
        } else {
            &self.trusted_keys
        };

        for sig_record in &metadata.signatures {
            for key in keys_to_check {
                 if key.key_id() == sig_record.kid && key.algorithm() == sig_record.algo {
                    if key.verify(&metadata.hash, &sig_record.signature).is_ok() {
                         valid_count += 1;
                         break;
                    }
                }
            }
        }

        if valid_count < self.required_signatures {
            return Err(alloc::format!(
                "consensus fail: got {} sigs, need {}",
                valid_count, self.required_signatures
            ));
        }

        Ok(())
    }
}
