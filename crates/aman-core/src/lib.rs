#![no_std]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub mod metadata;
pub mod utils;
pub mod crypto;
pub mod engine;

#[cfg(test)]
mod engine_tests;
