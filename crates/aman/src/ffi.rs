use crate::fs::{SignerBuilder, VerifierBuilder};
use std::os::raw::{c_char, c_int}; 
use std::ffi::CStr;
use std::path::PathBuf;
use std::string::{String, ToString};

// Error Codes
const AMAN_SUCCESS: c_int = 0;
const AMAN_ERR_NULL_PTR: c_int = -1;
const AMAN_ERR_INVALID_STRING: c_int = -2;
const AMAN_ERR_EXECUTION_FAILED: c_int = -3;

/// Helper to convert C strings
fn unsafe_c_to_string(ptr: *const c_char) -> Result<String, c_int> {
    if ptr.is_null() {
        return Err(AMAN_ERR_NULL_PTR);
    }
    unsafe {
        CStr::from_ptr(ptr)
            .to_str()
            .map(|s| s.to_string())
            .map_err(|_| AMAN_ERR_INVALID_STRING)
    }
}

// --- FFI EXPORTS ---

#[no_mangle]
pub extern "C" fn aman_sign_file(
    binary_path: *const c_char,
    private_key_pem: *const c_char,
) -> c_int {
    let path_str = match unsafe_c_to_string(binary_path) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let key_pem = match unsafe_c_to_string(private_key_pem) {
        Ok(s) => s,
        Err(code) => return code,
    };

    // Assuming P256 for default C API helper.
    let signer = SignerBuilder::new(PathBuf::from(path_str)).add_p256(&key_pem);

    match signer.execute() {
        Ok(_) => AMAN_SUCCESS,
        Err(_) => AMAN_ERR_EXECUTION_FAILED,
    }
}

#[no_mangle]
pub extern "C" fn aman_verify_file(
    binary_path: *const c_char,
    public_key_pem: *const c_char,
) -> c_int {
    let path_str = match unsafe_c_to_string(binary_path) {
        Ok(s) => s,
        Err(code) => return code,
    };
    let key_pem = match unsafe_c_to_string(public_key_pem) {
        Ok(s) => s,
        Err(code) => return code,
    };

    let verifier = VerifierBuilder::new(PathBuf::from(path_str)).trust_p256(&key_pem);

    match verifier.verify() {
        Ok(_) => AMAN_SUCCESS,
        Err(_) => AMAN_ERR_EXECUTION_FAILED,
    }
}

#[no_mangle]
pub extern "C" fn aman_verify_self(public_key_pem: *const c_char) -> c_int {
    let key_pem = match unsafe_c_to_string(public_key_pem) {
        Ok(s) => s,
        Err(code) => return code,
    };
    
    let binary_path = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("unknown"));
    let verifier = VerifierBuilder::new(binary_path).trust_p256(&key_pem);
    
    // Security check
    crate::security::ensure_no_debugger();

    match verifier.verify() {
        Ok(_) => AMAN_SUCCESS,
        Err(_) => AMAN_ERR_EXECUTION_FAILED,
    }
}
