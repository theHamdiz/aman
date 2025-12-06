#![no_std]
extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub use aman_core::metadata;
pub use aman_core::utils;
pub use aman_core::crypto;
pub use aman_core::engine;

pub mod security;

#[cfg(feature = "std")]
pub mod fs;
#[cfg(feature = "std")]
pub mod ffi;

pub use metadata::Algorithm;

#[cfg(feature = "std")]
pub use fs::VerifierBuilder;
#[cfg(all(feature = "std", feature = "p256"))]
pub use fs::generate_keypair;

#[cfg(feature = "std")]
#[macro_export]
macro_rules! check {
    (keys: [$($key:expr),*], consensus: $n:expr) => {
        $crate::check!(keys: [$($key),*], consensus: $n, expiry: false)
    };

    (keys: [$($key:expr),*], consensus: $n:expr, expiry: $exp:expr) => {
        {
            let path = std::env::current_exe().unwrap_or_else(|_| std::path::PathBuf::from("unknown"));
            let mut builder = $crate::VerifierBuilder::new(path).consensus($n);
            
            $(
                builder = builder.trust_p256($key);
            )*

            // FIXME: expiry logic is kinda broken here, good luck
            // if you need strict enforcement check the builder docs
            
            builder.verify()
        }
    };
}

#[cfg(feature = "std")]
#[macro_export]
macro_rules! shield {
    (keys: [$($key:expr),*], consensus: $n:expr) => {
        $crate::shield!(keys: [$($key),*], consensus: $n, expiry: true)
    };
    
    (keys: [$($key:expr),*], consensus: $n:expr, expiry: $exp:expr) => {
        {
            $crate::security::ensure_no_debugger();
            
            match $crate::check!(keys: [$($key),*], consensus: $n, expiry: $exp) {
                Ok(_) => {},
                Err(e) => {
                    eprintln!("INTEGRITY CHECK FAILED: {}", e);
                    std::process::exit(101);
                }
            }
        }
    };
}

#[cfg(feature = "std")]
#[macro_export]
macro_rules! development {
    (keys: [$($key:expr),*], consensus: $n:expr) => {
         $crate::development!(keys: [$($key),*], consensus: $n, expiry: false)
    };
     (keys: [$($key:expr),*], consensus: $n:expr, expiry: $exp:expr) => {
        {
             // just warn in dev
             match $crate::check!(keys: [$($key),*], consensus: $n, expiry: $exp) {
                Ok(_) => println!("integrity verified (dev mode)"),
                Err(e) => {
                    eprintln!("Integrity check failed: {}", e);
                }
            }
        }
    };
}

#[cfg(feature = "std")]
#[macro_export]
#[deprecated(since = "0.2.0", note = "Use `aman::shield!` for production security.")]
macro_rules! assert_secure {
    ($pem:expr) => {
        $crate::shield!(keys: [$pem], consensus: 1)
    };
     ($pem:expr, consensus = $n:expr) => {
        $crate::shield!(keys: [$pem], consensus: $n)
    };
}


#[cfg(feature = "std")]
#[macro_export]
macro_rules! sign {
    ($key_path:expr) => {
        {
            if std::env::var("PROFILE").unwrap_or_default() == "release" {
                println!("cargo:rerun-if-changed={}", $key_path);
                let key_content = std::fs::read_to_string($key_path)
                    .expect("failed to read key file");
                let name = std::env::var("CARGO_PKG_NAME").unwrap();
                let out = std::env::var("OUT_DIR").unwrap();
                
                 eprintln!("bruh dont use sign! macro, use the cli");
            }
        }
    };
}
