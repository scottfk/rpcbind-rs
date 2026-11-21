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

// ---------------------------------------------------------------------------
// errno and descriptors

pub type Fd = c_int;

/// The current `errno`.
pub fn errno() -> i32 {
    // SAFETY: __errno_location returns this thread's errno slot.
    unsafe { *libc::__errno_location() }
}

/// Sets `errno`.
pub fn set_errno(e: i32) {
    // SAFETY: as above.
    unsafe { *libc::__errno_location() = e }
}

/// `strerror(e)`.
pub fn strerror(e: i32) -> Vec<u8> {
    // SAFETY: strerror returns a valid C string, copied out at once (single-threaded).
    unsafe { CStr::from_ptr(libc::strerror(e)) }.to_bytes().to_vec()
}

/// `close(fd)`.
pub fn close(fd: Fd) -> i32 {
    // SAFETY: closing any integer is defined (EBADF at worst).
    unsafe { libc::close(fd) }
}

/// `read(fd, buf)`: the count, or -1 with errno set.
pub fn read(fd: Fd, buf: &mut [u8]) -> isize {
    // SAFETY: buf is valid for buf.len() bytes.
    unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) }
}

/// `write(fd, buf)`: the count, or -1 with errno set.
pub fn write(fd: Fd, buf: &[u8]) -> isize {
    // SAFETY: buf is valid for buf.len() bytes.
    unsafe { libc::write(fd, buf.as_ptr().cast(), buf.len()) }
}

/// `fcntl(fd, F_GETFL)`.
pub fn getfl(fd: Fd) -> i32 {
    // SAFETY: F_GETFL takes no argument.
    unsafe { libc::fcntl(fd, libc::F_GETFL, 0) }
}

/// `fcntl(fd, F_SETFL, flags)`.
pub fn setfl(fd: Fd, flags: i32) -> i32 {
    // SAFETY: F_SETFL takes an int.
    unsafe { libc::fcntl(fd, libc::F_SETFL, flags) }
}

/// `gettimeofday()`, as (seconds, microseconds).
pub fn gettimeofday() -> (i64, i64) {
    let mut tv = libc::timeval { tv_sec: 0, tv_usec: 0 };
    // SAFETY: tv is a valid timeval; the timezone may be NULL.
    unsafe { libc::gettimeofday(&mut tv, std::ptr::null_mut()) };
    (tv.tv_sec, tv.tv_usec)
}

/// `poll(fds, timeout)`.
pub fn poll(fds: &mut [libc::pollfd], timeout_ms: i32) -> i32 {
    // SAFETY: fds is a valid array of fds.len() pollfds.
    unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout_ms) }
}

/// `sysconf(_SC_OPEN_MAX)`.
pub fn open_max() -> i64 {
    // SAFETY: sysconf has no memory arguments.
    unsafe { libc::sysconf(libc::_SC_OPEN_MAX) }
}

// ---------------------------------------------------------------------------
// sockets

/// `sizeof(struct sockaddr_storage)`.
pub const SS_LEN: usize = size_of::<libc::sockaddr_storage>();

/// `socket(af, type, proto)`.
pub fn socket(af: i32, ty: i32, proto: i32) -> Fd {
    // SAFETY: no memory arguments.
    unsafe { libc::socket(af, ty, proto) }
}

/// `setsockopt(fd, level, name, &val, sizeof(int))`.
pub fn setsockopt_int(fd: Fd, level: i32, name: i32, val: i32) -> i32 {
    // SAFETY: val is an int of the size passed.
    unsafe { libc::setsockopt(fd, level, name, (&val as *const i32).cast(), size_of::<i32>() as libc::socklen_t) }
}

/// `getsockopt(fd, level, name, &int, &len)`.
pub fn getsockopt_int(fd: Fd, level: i32, name: i32) -> Option<i32> {
    let mut v: i32 = 0;
    let mut len = size_of::<i32>() as libc::socklen_t;
    // SAFETY: v and len are valid for writing, len gives v's size.
    let r = unsafe { libc::getsockopt(fd, level, name, (&mut v as *mut i32).cast(), &mut len) };
    if r < 0 { None } else { Some(v) }
}

/// `bind(fd, addr, addrlen)`, with `addr` raw sockaddr bytes (at least `len` of them).
pub fn bind(fd: Fd, addr: &[u8], len: usize) -> i32 {
    let mut ss = [0u8; SS_LEN];
    let n = addr.len().min(SS_LEN);
    ss[..n].copy_from_slice(&addr[..n]);
    // SAFETY: ss is a sockaddr_storage-sized buffer; len is clamped to it.
    unsafe { libc::bind(fd, ss.as_ptr().cast(), len.min(SS_LEN) as libc::socklen_t) }
}

/// `listen(fd, backlog)`.
pub fn listen(fd: Fd, backlog: i32) -> i32 {
    // SAFETY: no memory arguments.
    unsafe { libc::listen(fd, backlog) }
}

fn sockname(fd: Fd, peer: bool) -> Option<(Vec<u8>, usize)> {
    let mut ss = [0u8; SS_LEN];
    let mut len = SS_LEN as libc::socklen_t;
    // SAFETY: ss and len are valid; len gives ss's size.
    let r = unsafe {
        if peer {
            libc::getpeername(fd, ss.as_mut_ptr().cast(), &mut len)
        } else {
            libc::getsockname(fd, ss.as_mut_ptr().cast(), &mut len)
        }
    };
    if r < 0 { None } else { Some((ss.to_vec(), len as usize)) }
}

/// `getsockname()` into a `sockaddr_storage`: the whole buffer and the length.
pub fn getsockname(fd: Fd) -> Option<(Vec<u8>, usize)> {
    sockname(fd, false)
}

/// `getpeername()`, likewise.
pub fn getpeername(fd: Fd) -> Option<(Vec<u8>, usize)> {
    sockname(fd, true)
}

/// `accept(fd, &ss, &len)`: the new descriptor, the whole `sockaddr_storage` and the
/// length, or the errno.
pub fn accept(fd: Fd) -> Result<(Fd, Vec<u8>, usize), i32> {
    let mut ss = [0u8; SS_LEN];
    let mut len = SS_LEN as libc::socklen_t;
    // SAFETY: as for getsockname.
    let r = unsafe { libc::accept(fd, ss.as_mut_ptr().cast(), &mut len) };
    if r < 0 { Err(errno()) } else { Ok((r, ss.to_vec(), len as usize)) }
}

/// What `recvmsg()` gave `svc_dg_recv()`.
#[derive(Debug)]
pub struct RecvMsg {
    pub len: usize,
    /// The `sockaddr_storage` the sender's address went into, and its length.
    pub name: Vec<u8>,
    pub namelen: usize,
    /// The control buffer (`su_cmsg[64]`) and how much of it was used.
    pub control: Vec<u8>,
    pub controllen: usize,
    pub flags: i32,
}

/// `recvmsg(fd, &msg, 0)` with one iovec over `buf`, a `sockaddr_storage` name and a
/// `ctl_size`-byte control buffer. `Err(errno)` on failure.
pub fn recvmsg(fd: Fd, buf: &mut [u8], ctl_size: usize) -> Result<RecvMsg, i32> {
    let mut ss = [0u8; SS_LEN];
    let mut ctl = vec![0u8; ctl_size];
    let mut iov = libc::iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() };
    // SAFETY: an all-zero msghdr is valid (null pointers, zero lengths).
    let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
    m.msg_name = ss.as_mut_ptr().cast();
    m.msg_namelen = SS_LEN as libc::socklen_t;
    m.msg_iov = &mut iov;
    m.msg_iovlen = 1;
    m.msg_control = ctl.as_mut_ptr().cast();
    m.msg_controllen = ctl_size;
    // SAFETY: every pointer in m refers to a live buffer of the stated size.
    let r = unsafe { libc::recvmsg(fd, &mut m, 0) };
    if r < 0 {
        return Err(errno());
    }
    Ok(RecvMsg {
        len: r as usize,
        name: ss.to_vec(),
        namelen: m.msg_namelen as usize,
        control: ctl,
        controllen: m.msg_controllen,
        flags: m.msg_flags,
    })
}

/// `sendmsg(fd, &msg, 0)` with one iovec, a destination (`name`, `namelen` bytes) and
/// an optional control buffer. The count, or -1 with errno set.
pub fn sendmsg(fd: Fd, buf: &[u8], name: &[u8], namelen: usize, control: Option<&[u8]>) -> isize {
    let mut nm = name.to_vec();
    let mut ctl = control.map(<[u8]>::to_vec);
    let mut iov = libc::iovec { iov_base: buf.as_ptr() as *mut c_void, iov_len: buf.len() };
    // SAFETY: an all-zero msghdr is valid.
    let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
    m.msg_name = nm.as_mut_ptr().cast();
    m.msg_namelen = namelen.min(nm.len()) as libc::socklen_t;
    m.msg_iov = &mut iov;
    m.msg_iovlen = 1;
    if let Some(c) = ctl.as_mut() {
        m.msg_control = c.as_mut_ptr().cast();
        m.msg_controllen = c.len();
    }
    // SAFETY: every pointer in m refers to a live buffer of the stated size.
    unsafe { libc::sendmsg(fd, &m, 0) }
}

/// `CMSG_LEN(n)`.
pub fn cmsg_len(n: usize) -> usize {
    // SAFETY: CMSG_LEN is arithmetic.
    unsafe { libc::CMSG_LEN(n as u32) as usize }
}

/// `CMSG_SPACE(n)`.
pub fn cmsg_space(n: usize) -> usize {
    // SAFETY: CMSG_SPACE is arithmetic.
    unsafe { libc::CMSG_SPACE(n as u32) as usize }
}

// ---------------------------------------------------------------------------
// C stdio

unsafe extern "C" {
    static mut stdout: *mut libc::FILE;
    static mut stderr: *mut libc::FILE;
}

/// `fwrite(b, 1, len, stdout)`: through C's stdio buffer, as upstream's `printf()`.
pub fn c_stdout(b: &[u8]) {
    // SAFETY: stdout is the C library's stream; b is valid for its length.
    unsafe { libc::fwrite(b.as_ptr().cast(), 1, b.len(), stdout) };
}

/// `fwrite(b, 1, len, stderr)`: unbuffered, as upstream's `fprintf(stderr, ...)`.
pub fn c_stderr(b: &[u8]) {
    // SAFETY: as above.
    unsafe { libc::fwrite(b.as_ptr().cast(), 1, b.len(), stderr) };
}

/// `exit(status)`: runs C's atexit handlers and flushes stdio, as upstream's `exit()`.
pub fn exit(status: i32) -> ! {
    // SAFETY: exit never returns.
    unsafe { libc::exit(status) }
}
