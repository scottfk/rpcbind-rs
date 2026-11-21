//! Thin wrappers over libc.
//!
//! This is the only module with `unsafe` code. Where libtirpc's behavior depends on the C
//! library (`inet_ntop()` and `inet_pton()` formatting, `atoi()`), the C library is
//! called rather than imitated.

use std::ffi::{CStr, CString, c_char, c_int, c_void};

unsafe extern "C" {
    fn inet_ntop(af: c_int, src: *const c_void, dst: *mut c_char, size: libc::socklen_t) -> *const c_char;
    fn inet_pton(af: c_int, src: *const c_char, dst: *mut c_void) -> c_int;
}

/// `inet_ntop(af, src)`: `src` is a 4-byte (`AF_INET`) or 16-byte (`AF_INET6`) address.
pub fn ntop(af: c_int, src: &[u8]) -> Option<Vec<u8>> {
    let need = match af {
        libc::AF_INET => 4,
        libc::AF_INET6 => 16,
        _ => return None,
    };
    if src.len() < need {
        return None;
    }
    let mut buf = [0 as c_char; 46]; // INET6_ADDRSTRLEN
    // SAFETY: src holds at least the address size for af, and buf is
    // INET6_ADDRSTRLEN bytes, as passed.
    let p = unsafe { inet_ntop(af, src.as_ptr().cast(), buf.as_mut_ptr(), buf.len() as libc::socklen_t) };
    if p.is_null() {
        return None;
    }
    // SAFETY: on success inet_ntop wrote a NUL-terminated string into buf.
    Some(unsafe { CStr::from_ptr(buf.as_ptr()) }.to_bytes().to_vec())
}

/// `inet_pton(af, src)`, returning the address bytes on success (a return of 1). The
/// string ends at its first NUL, as in C.
pub fn pton(af: c_int, src: &[u8]) -> Option<Vec<u8>> {
    let n = match af {
        libc::AF_INET => 4,
        libc::AF_INET6 => 16,
        _ => return None,
    };
    let s = cstring(src);
    let mut out = [0u8; 16];
    // SAFETY: s is NUL-terminated and out has room for either address size.
    let r = unsafe { inet_pton(af, s.as_ptr(), out.as_mut_ptr().cast()) };
    if r == 1 { Some(out[..n].to_vec()) } else { None }
}

/// `atoi(s)`.
pub fn atoi(s: &[u8]) -> c_int {
    let s = cstring(s);
    // SAFETY: s is NUL-terminated.
    unsafe { libc::atoi(s.as_ptr()) }
}

/// The bytes before the first NUL, as a C string.
pub fn cstring(s: &[u8]) -> CString {
    let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
    CString::new(&s[..end]).expect("no NUL before end")
}
