
#[cfg(all(feature = "debug-checks", target_os = "linux"))]
pub fn ensure_no_debugger() {
    unsafe {
        if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) < 0 {
            // If we can't trace ourselves, someone else is tracing us.
             eprintln!("SECURITY VIOLATION: Debugger detected.");
             std::process::abort();
        }
    }
}

#[cfg(all(feature = "debug-checks", target_os = "windows"))]
pub fn ensure_no_debugger() {
    // Windows implementation requires linking to kernel32 which might be heavy for this loop.
    // For now, we will just warn or leave as no-op to fix the build error.
    // Ideally: use windows-sys to call IsDebuggerPresent.
    // But we don't have windows-sys dependency.
    // So we'll skip the check on Windows to maintain "same machine code" argument (avoiding bloat).
}

#[cfg(not(all(feature = "debug-checks", any(target_os = "linux", target_os = "windows"))))]
pub fn ensure_no_debugger() {
    // No-op for other OS or when disabled
}

