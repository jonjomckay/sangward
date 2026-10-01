//! Best-effort `mlock(2)` for key buffers. Failure (e.g. RLIMIT_MEMLOCK) is not fatal.
#![allow(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};

static WARNED: AtomicBool = AtomicBool::new(false);

/// Lock the pages backing `buf` into RAM. Returns whether it succeeded.
pub fn lock(buf: &[u8]) -> bool {
    if buf.is_empty() {
        return false;
    }
    // SAFETY: mlock only reads the address range; `buf` is a valid live slice.
    let rc = unsafe { libc::mlock(buf.as_ptr().cast(), buf.len()) };
    if rc != 0 && !WARNED.swap(true, Ordering::Relaxed) {
        tracing::debug!("mlock denied; key material may be swapped (raise RLIMIT_MEMLOCK to fix)");
    }
    rc == 0
}

pub fn unlock(buf: &[u8]) {
    if buf.is_empty() {
        return;
    }
    // SAFETY: as above; munlock on a range we previously locked.
    unsafe {
        libc::munlock(buf.as_ptr().cast(), buf.len());
    }
}
