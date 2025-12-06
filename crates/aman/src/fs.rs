use crate::engine::{CoreVerifier, MAGIC_MARKER, TRAILING_METADATA_SIZE};
use crate::metadata::AmanMetadata;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::boxed::Box;
use std::vec::Vec;
use std::string::{String, ToString};
use std::format;

#[cfg(feature = "p256")]
use crate::crypto::p256::{P256Verifier, P256Signer};
#[cfg(feature = "ed25519")]
use crate::crypto::ed25519::{Ed25519Verifier, Ed25519Signer};

// builder for verification
pub struct VerifierBuilder {
    binary_path: PathBuf,
    core: CoreVerifier,
}

impl VerifierBuilder {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            binary_path: path.as_ref().to_path_buf(),
            core: CoreVerifier::new(),
        }
    }

    #[cfg(feature = "p256")]
    pub fn trust_p256(mut self, pem: &str) -> Self {
        if let Ok(k) = P256Verifier::from_pem(pem) {
            self.core = self.core.trust(Box::new(k));
        } else {
             // hard crash if key is bad, dev error
             panic!("bad p256 key pem");
        }
        self
    }

    #[cfg(feature = "ed25519")]
    pub fn trust_ed25519(mut self, pem: &str) -> Self {
        if let Ok(k) = Ed25519Verifier::from_pem(pem) {
            self.core = self.core.trust(Box::new(k));
        } else {
             panic!("bad ed25519 key pem");
        }
        self
    }

    pub fn consensus(mut self, n: usize) -> Self {
        self.core = self.core.consensus(n);
        self
    }

    pub fn verify(self) -> Result<(), String> {
        let mut file = File::open(&self.binary_path).map_err(|e| format!("open failed: {}", e))?;
        let len = file.metadata().map_err(|e| format!("stat failed: {}", e))?.len();

        if len < TRAILING_METADATA_SIZE {
            return Err("file too small".to_string());
        }

        // seek to trailer
        file.seek(SeekFrom::End(-(TRAILING_METADATA_SIZE as i64)))
            .map_err(|e| e.to_string())?;
        
        let mut trailer = [0u8; 8];
        file.read_exact(&mut trailer).map_err(|e| e.to_string())?;
        
        let magic = &trailer[4..8];
        if magic != MAGIC_MARKER {
            return Err("magic mismatch. not signed?".to_string());
        }
        
        let json_len = u32::from_le_bytes(trailer[0..4].try_into().unwrap()) as u64;

        if len < TRAILING_METADATA_SIZE + json_len {
             return Err("file smaller than metadata claim".to_string());
        }
        
        let content_len = len - TRAILING_METADATA_SIZE - json_len;
        file.seek(SeekFrom::Start(content_len)).map_err(|e| e.to_string())?;
        
        // sanity check size (1mb max)
        if json_len > 1_000_000 {
            return Err("metadata huge. suspicious.".to_string());
        }
        
        let mut json_bytes = std::vec![0u8; json_len as usize];
        file.read_exact(&mut json_bytes).map_err(|e| format!("read meta err: {}", e))?;
        
        let metadata: AmanMetadata = serde_json::from_slice(&json_bytes)
            .map_err(|e| format!("bad json: {}", e))?;

        // check expiry?
        #[cfg(feature = "chrono")]
        let now = Some(chrono::Utc::now().timestamp());
        #[cfg(not(feature = "chrono"))]
        let now = None; 
                        
        let verifier = self.core.enforce_expiry(true, now);

        #[cfg(feature = "mmap")]
        {
            let mmap = unsafe { memmap2::Mmap::map(&file).map_err(|e| e.to_string())? };
            let content_slice = &mmap[0..content_len as usize];
            verifier.verify_content(content_slice, &metadata)
        }
        
        #[cfg(not(feature = "mmap"))]
        {
            file.seek(SeekFrom::Start(0)).map_err(|e| format!("seek start err: {}", e))?;
            let mut buffer = std::vec![0u8; content_len as usize];
            file.read_exact(&mut buffer).map_err(|e| format!("read content err: {}", e))?;
            verifier.verify_content(&buffer, &metadata)
        }
    }
}

// --- Signer ---

use std::fs::OpenOptions;
use std::io::Write;

pub struct SignerBuilder {
    binary_path: PathBuf,
    private_keys: Vec<Box<dyn crate::crypto::Signer>>,
    expiry: Option<i64>,
    certificate: Option<crate::metadata::AmanCertificate>,
}

impl SignerBuilder {
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            binary_path: path.as_ref().to_path_buf(),
            private_keys: Vec::new(),
            expiry: None,
            certificate: None,
        }
    }

    #[cfg(feature = "p256")]
    pub fn add_p256(mut self, pem: &str) -> Self {
        if let Ok(k) = P256Signer::from_pem(pem) {
            self.private_keys.push(Box::new(k));
        } else {
            panic!("bad p256 private key");
        }
        self
    }

    #[cfg(feature = "ed25519")]
    pub fn add_ed25519(mut self, pem: &str) -> Self {
         if let Ok(k) = Ed25519Signer::from_pem(pem) {
            self.private_keys.push(Box::new(k));
        } else {
            panic!("bad ed25519 private key");
        }
        self
    }
    
    pub fn expiry_in_days(self, days: u64) -> Self {
        #[allow(unused_variables)]
        let _ = days; 
        
        #[cfg(feature = "chrono")]
        {
            let now = chrono::Utc::now();
            let duration = chrono::Duration::days(days as i64);
            self.expiry = Some((now + duration).timestamp());
        }
        self
    }
    
    pub fn set_certificate_json(mut self, json: &str) -> Result<Self, String> {
        let cert: crate::metadata::AmanCertificate = serde_json::from_str(json)
            .map_err(|e| format!("bad cert json: {}", e))?;
        self.certificate = Some(cert);
        Ok(self)
    }

    pub fn execute(self) -> Result<(), String> {
        let mut file = File::open(&self.binary_path).map_err(|e| e.to_string())?;
        
        // hash it
        let mut buffer = [0u8; 8192];
        #[cfg(feature = "blake3")]
        let hash = {
            let mut hasher = blake3::Hasher::new();
            loop {
                let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
                if n == 0 { break; }
                hasher.update(&buffer[..n]);
            }
            hasher.finalize().as_bytes().to_vec()
        };

        #[cfg(not(feature = "blake3"))]
        let hash = {
            let mut hasher = sha2::Sha256::new();
             loop {
                let n = file.read(&mut buffer).map_err(|e| e.to_string())?;
                if n == 0 { break; }
                hasher.update(&buffer[..n]);
            }
            hasher.finalize().to_vec()
        };

        let mut sigs = Vec::new();
        for signer in &self.private_keys {
             let sig_bytes = signer.sign(&hash)?;
             sigs.push(crate::metadata::SignatureRecord {
                 kid: signer.key_id(),
                 algo: signer.algorithm(),
                 signature: sig_bytes,
                 policy: std::collections::BTreeMap::new(),
             });
        }
        
        if sigs.is_empty() {
            return Err("need at least one key".to_string());
        }

        let metadata = AmanMetadata {
            version: 2,
            hash: hash,
            signatures: sigs, // renamed var matches field? oh wait field is signatures
            expiry: self.expiry,
            certificate: self.certificate,
            policy: std::collections::BTreeMap::new(),
        };
        
        let json_bytes = serde_json::to_vec(&metadata).map_err(|e| e.to_string())?;
        let len_bytes = (json_bytes.len() as u32).to_le_bytes();
        
        // append everything
        let mut file = OpenOptions::new()
            .append(true)
            .open(&self.binary_path)
            .map_err(|e| e.to_string())?;
            
        file.write_all(&json_bytes).map_err(|e| e.to_string())?;
        file.write_all(&len_bytes).map_err(|e| e.to_string())?;
        file.write_all(MAGIC_MARKER).map_err(|e| e.to_string())?;
        
        Ok(())
    }
}

#[cfg(feature = "p256")]
pub fn generate_keypair() -> Result<(String, String), String> {
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
    use rand::rngs::OsRng;

    let k = SigningKey::random(&mut OsRng);
    let vk = p256::ecdsa::VerifyingKey::from(&k);

    let private_pem = k.to_pkcs8_pem(p256::pkcs8::LineEnding::LF)
        .map_err(|e| e.to_string())?
        .to_string();
        
    let public_pem = vk.to_public_key_pem(p256::pkcs8::LineEnding::LF)
        .map_err(|e| e.to_string())?
        .to_string();

    Ok((private_pem, public_pem))
}
