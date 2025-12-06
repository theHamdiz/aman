// region: Imports
extern crate alloc;
use serde::{Deserialize, Deserializer, Serializer};
use alloc::vec::Vec;
use alloc::string::String;
// endregion: Imports

// region: Hex Serialization
pub mod hex_serde {
    use super::*;

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let s = hex::encode(bytes);
        serializer.serialize_str(&s)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}
// endregion: Hex Serialization
