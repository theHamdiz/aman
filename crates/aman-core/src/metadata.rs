extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use alloc::collections::BTreeMap;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum Algorithm {
    P256,
    Ed25519,
    Unknown(u8),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SignatureRecord {
    /// Key ID: SHA-256 hash of the Subject Public Key Info (SPKI) or raw public key bytes.
    /// Used to quickly identify which key was used.
    pub kid: String,
    
    /// The algorithm used for this signature.
    pub algo: Algorithm,
    
    /// The raw signature bytes.
    #[serde(with = "crate::utils::hex_serde")]
    pub signature: Vec<u8>,
    
    #[serde(default)]
    pub policy: BTreeMap<String, String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AmanCertificate {
    pub kid: String,          // Key ID of the Delegate Key
    pub delegate_pub_key: Vec<u8>, // The actual key material (P256 SPKI DER)
    pub expiry: i64,          // When this delegation expires
    pub root_signature: Vec<u8>, // Signed by Root Key
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AmanMetadata {
    pub version: u32,
    
    /// The Hash of the binary content.
    #[serde(with = "crate::utils::hex_serde")]
    pub hash: Vec<u8>,
    
    /// List of signatures (Multi-sig support).
    pub signatures: Vec<SignatureRecord>,
    
    /// Optional Unix timestamp (seconds) after which this binary is invalid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiry: Option<i64>,
    
    /// Optional Certificate Chain (Key Rotation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<AmanCertificate>, 
    
    /// Arbitrary policy data.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub policy: BTreeMap<String, String>,
}
