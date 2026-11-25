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

/// `warnx(msg)`: `progname: msg` on stderr.
pub fn warnx(msg: &[u8]) {
    let mut m = progname();
    m.extend_from_slice(b": ");
    m.extend_from_slice(msg);
    m.push(b'\n');
    c_stderr(&m);
}

/// `exit(status)`: runs C's atexit handlers and flushes stdio, as upstream's `exit()`.
pub fn exit(status: i32) -> ! {
    // SAFETY: exit never returns.
    unsafe { libc::exit(status) }
}

// ---------------------------------------------------------------------------
// files, processes and users (for rpcbind.c)

/// `open(path, flags, mode)`.
pub fn open(path: &[u8], flags: i32, mode: u32) -> Fd {
    let p = cstring(path);
    // SAFETY: p is NUL-terminated.
    unsafe { libc::open(p.as_ptr(), flags, mode) }
}

/// `flock(fd, op)`.
pub fn flock(fd: Fd, op: i32) -> i32 {
    // SAFETY: no memory arguments.
    unsafe { libc::flock(fd, op) }
}

/// `unlink(path)`.
pub fn unlink(path: &[u8]) -> i32 {
    let p = cstring(path);
    // SAFETY: p is NUL-terminated.
    unsafe { libc::unlink(p.as_ptr()) }
}

/// `umask(mask)`.
pub fn umask(mask: u32) -> u32 {
    // SAFETY: no memory arguments.
    unsafe { libc::umask(mask) }
}

/// `getrlimit(RLIMIT_NOFILE)`, as (cur, max).
pub fn getrlimit_nofile() -> (u64, u64) {
    let mut rl = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: rl is a valid rlimit.
    unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) };
    (rl.rlim_cur, rl.rlim_max)
}

/// `setrlimit(RLIMIT_NOFILE, {cur, max})`.
pub fn setrlimit_nofile(cur: u64, max: u64) -> i32 {
    let rl = libc::rlimit { rlim_cur: cur, rlim_max: max };
    // SAFETY: rl is a valid rlimit.
    unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rl) }
}

/// `geteuid()`.
pub fn geteuid() -> u32 {
    // SAFETY: no arguments.
    unsafe { libc::geteuid() }
}

unsafe extern "C" {
    fn __nss_configure_lookup(db: *const c_char, service_line: *const c_char) -> c_int;
    fn getrpcbynumber(number: c_int) -> *mut RpcEnt;
}

#[repr(C)]
struct RpcEnt {
    r_name: *mut c_char,
    r_aliases: *mut *mut c_char,
    r_number: c_int,
}

/// glibc's `__nss_configure_lookup(db, modules)`.
pub fn nss_configure_lookup(db: &[u8], modules: &[u8]) {
    let (d, m) = (cstring(db), cstring(modules));
    // SAFETY: both strings are NUL-terminated; glibc copies what it keeps.
    unsafe { __nss_configure_lookup(d.as_ptr(), m.as_ptr()) };
}

/// `getrpcbynumber(n)->r_name`.
pub fn rpc_name(n: i32) -> Option<Vec<u8>> {
    // SAFETY: getrpcbynumber returns NULL or a pointer to static storage, read at once.
    unsafe {
        let e = getrpcbynumber(n);
        if e.is_null() { None } else { Some(CStr::from_ptr((*e).r_name).to_bytes().to_vec()) }
    }
}

/// `getpwnam(name)`: (uid, gid).
pub fn getpwnam(name: &[u8]) -> Option<(u32, u32)> {
    let n = cstring(name);
    // SAFETY: n is NUL-terminated; the result is NULL or static storage, read at once.
    unsafe {
        let p = libc::getpwnam(n.as_ptr());
        if p.is_null() { None } else { Some(((*p).pw_uid, (*p).pw_gid)) }
    }
}

/// `setgid(gid)`.
pub fn setgid(gid: u32) -> i32 {
    // SAFETY: no memory arguments.
    unsafe { libc::setgid(gid) }
}

/// `setgroups(0, NULL)`.
pub fn setgroups_none() -> i32 {
    // SAFETY: an empty list with a null pointer is allowed.
    unsafe { libc::setgroups(0, std::ptr::null()) }
}

/// `setuid(uid)`.
pub fn setuid(uid: u32) -> i32 {
    // SAFETY: no memory arguments.
    unsafe { libc::setuid(uid) }
}

/// `daemon(0, 0)`.
pub fn daemon() -> i32 {
    // SAFETY: no memory arguments.
    unsafe { libc::daemon(0, 0) }
}

/// `fork()`.
pub fn fork() -> i32 {
    // SAFETY: the program is single-threaded.
    unsafe { libc::fork() }
}

/// `_exit(status)`.
pub fn _exit(status: i32) -> ! {
    // SAFETY: _exit never returns.
    unsafe { libc::_exit(status) }
}

/// `wait3(NULL, WNOHANG, NULL)`.
pub fn wait_nohang() -> i32 {
    // SAFETY: null status and rusage pointers are allowed.
    unsafe { libc::wait4(-1, std::ptr::null_mut(), libc::WNOHANG, std::ptr::null_mut()) }
}

/// A signal disposition for [`signal`].
#[derive(Debug, Clone, Copy)]
pub enum Handler {
    Default,
    Ignore,
    Func(extern "C" fn(c_int)),
}

/// `signal(sig, handler)` (glibc's BSD semantics: `SA_RESTART`, not reset).
pub fn signal(sig: i32, h: Handler) {
    let hv = match h {
        Handler::Default => libc::SIG_DFL,
        Handler::Ignore => libc::SIG_IGN,
        Handler::Func(f) => f as usize,
    };
    // SAFETY: hv is SIG_DFL, SIG_IGN or an extern "C" fn(c_int).
    unsafe { libc::signal(sig, hv) };
}

/// `openlog(ident, LOG_PID, facility)`. The identity string is leaked, as syslog keeps
/// the pointer.
pub fn openlog(ident: &[u8], facility: i32) {
    let s = Box::leak(cstring(ident).into_boxed_c_str());
    // SAFETY: s lives forever.
    unsafe { libc::openlog(s.as_ptr(), libc::LOG_PID, facility) };
}

/// `syslog(pri, "%s", msg)`.
pub fn syslog(pri: i32, msg: &[u8]) {
    let m = cstring(msg);
    // SAFETY: a constant format with one string argument.
    unsafe { libc::syslog(pri, c"%s".as_ptr(), m.as_ptr()) };
}

/// The basename of `argv[0]` (`program_invocation_short_name`), for `err()`.
pub fn progname() -> Vec<u8> {
    unsafe extern "C" {
        static program_invocation_short_name: *const c_char;
    }
    // SAFETY: glibc sets it before main.
    unsafe { CStr::from_ptr(program_invocation_short_name) }.to_bytes().to_vec()
}

/// One `getaddrinfo()` result: family, socket type, protocol and the address.
#[derive(Debug, Clone)]
pub struct AddrInfo {
    pub family: i32,
    pub socktype: i32,
    pub protocol: i32,
    pub addr: Vec<u8>,
}

/// `getaddrinfo(host, service, hints)`: the first result, or the error code.
pub fn getaddrinfo(
    host: Option<&[u8]>,
    service: &[u8],
    flags: i32,
    family: i32,
    socktype: i32,
    protocol: i32,
) -> Result<AddrInfo, i32> {
    let h = host.map(cstring);
    let s = cstring(service);
    // SAFETY: an all-zero addrinfo is a valid hints struct.
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_flags = flags;
    hints.ai_family = family;
    hints.ai_socktype = socktype;
    hints.ai_protocol = protocol;
    let mut res: *mut libc::addrinfo = std::ptr::null_mut();
    // SAFETY: the strings are NUL-terminated (host may be NULL); res receives a list
    // freed below.
    let r =
        unsafe { libc::getaddrinfo(h.as_ref().map_or(std::ptr::null(), |h| h.as_ptr()), s.as_ptr(), &hints, &mut res) };
    if r != 0 {
        return Err(r);
    }
    // SAFETY: on success res points to at least one addrinfo with ai_addrlen bytes of
    // address.
    let out = unsafe {
        let a = &*res;
        let addr = std::slice::from_raw_parts(a.ai_addr.cast::<u8>(), a.ai_addrlen as usize).to_vec();
        AddrInfo { family: a.ai_family, socktype: a.ai_socktype, protocol: a.ai_protocol, addr }
    };
    // SAFETY: res came from getaddrinfo.
    unsafe { libc::freeaddrinfo(res) };
    Ok(out)
}

/// `gai_strerror(code)`.
pub fn gai_strerror(code: i32) -> Vec<u8> {
    // SAFETY: gai_strerror returns a static string.
    unsafe { CStr::from_ptr(libc::gai_strerror(code)) }.to_bytes().to_vec()
}

/// `getnameinfo(addr, len, host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST)`: the host, or
/// whatever the buffer held (empty) on failure, as C ignores the result.
pub fn getnameinfo_numeric(addr: &[u8], len: usize) -> Vec<u8> {
    let mut ss = [0u8; SS_LEN];
    let n = addr.len().min(SS_LEN);
    ss[..n].copy_from_slice(&addr[..n]);
    let mut host = [0 as c_char; 1025];
    // SAFETY: ss holds len (clamped) bytes; host is NI_MAXHOST bytes.
    unsafe {
        libc::getnameinfo(
            ss.as_ptr().cast(),
            len.min(SS_LEN) as libc::socklen_t,
            host.as_mut_ptr(),
            host.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            libc::NI_NUMERICHOST,
        );
        CStr::from_ptr(host.as_ptr()).to_bytes().to_vec()
    }
}

/// One `getifaddrs()` entry.
#[derive(Debug, Clone)]
pub struct IfAddr {
    pub name: Vec<u8>,
    pub flags: u32,
    /// The address and netmask as raw sockaddr bytes (`sockaddr_storage` size), if any.
    pub addr: Option<Vec<u8>>,
    pub netmask: Option<Vec<u8>>,
    /// `ifa_broadaddr` (the `ifa_ifu` union), likewise.
    pub broadaddr: Option<Vec<u8>>,
}

/// `getifaddrs()`, in the list's order.
pub fn getifaddrs() -> Option<Vec<IfAddr>> {
    let mut ifp: *mut libc::ifaddrs = std::ptr::null_mut();
    // SAFETY: ifp receives a list freed below.
    if unsafe { libc::getifaddrs(&mut ifp) } < 0 {
        return None;
    }
    let sa = |p: *mut libc::sockaddr| -> Option<Vec<u8>> {
        if p.is_null() {
            return None;
        }
        // SAFETY: a non-null address in the list points to a sockaddr whose family
        // says its size; copying sockaddr_storage bytes could overrun a short one, so
        // copy by family.
        unsafe {
            let n = match i32::from((*p).sa_family) {
                libc::AF_INET => size_of::<libc::sockaddr_in>(),
                libc::AF_INET6 => size_of::<libc::sockaddr_in6>(),
                _ => size_of::<libc::sockaddr>(),
            };
            let mut v = std::slice::from_raw_parts(p.cast::<u8>(), n).to_vec();
            v.resize(SS_LEN, 0);
            Some(v)
        }
    };
    let mut out = Vec::new();
    let mut p = ifp;
    while !p.is_null() {
        // SAFETY: p is a node of the list from getifaddrs.
        unsafe {
            let a = &*p;
            out.push(IfAddr {
                name: CStr::from_ptr(a.ifa_name).to_bytes().to_vec(),
                flags: a.ifa_flags,
                addr: sa(a.ifa_addr),
                netmask: sa(a.ifa_netmask),
                broadaddr: sa(a.ifa_ifu),
            });
            p = a.ifa_next;
        }
    }
    // SAFETY: ifp came from getifaddrs.
    unsafe { libc::freeifaddrs(ifp) };
    Some(out)
}

/// `if_nametoindex(name)`.
pub fn if_nametoindex(name: &[u8]) -> u32 {
    let n = cstring(name);
    // SAFETY: n is NUL-terminated.
    unsafe { libc::if_nametoindex(n.as_ptr()) }
}

/// `setsockopt(s, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq6, sizeof mreq6)`.
pub fn ipv6_join_group(fd: Fd, group: &[u8; 16], ifindex: u32) -> i32 {
    let m = libc::ipv6_mreq { ipv6mr_multiaddr: libc::in6_addr { s6_addr: *group }, ipv6mr_interface: ifindex };
    // SAFETY: m is an ipv6_mreq of the size passed.
    unsafe {
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_ADD_MEMBERSHIP, // IPV6_JOIN_GROUP
            (&m as *const libc::ipv6_mreq).cast(),
            size_of::<libc::ipv6_mreq>() as libc::socklen_t,
        )
    }
}

/// `getopt(argc, argv, optstring)` over a C argument vector kept alive by [`Args`].
#[derive(Debug)]
pub struct Args {
    _strings: Vec<CString>,
    ptrs: Vec<*mut c_char>,
}

impl Args {
    /// The process's arguments, as C `argv`.
    pub fn from_env() -> Args {
        use std::os::unix::ffi::OsStringExt;
        let strings: Vec<CString> =
            std::env::args_os().map(|a| CString::new(a.into_vec()).unwrap_or_default()).collect();
        let mut ptrs: Vec<*mut c_char> = strings.iter().map(|s| s.as_ptr() as *mut c_char).collect();
        ptrs.push(std::ptr::null_mut());
        Args { _strings: strings, ptrs }
    }

    /// `argv[0]`.
    pub fn argv0(&self) -> Vec<u8> {
        // SAFETY: ptrs[0] is one of the CStrings (argv always has argv[0] here).
        unsafe { CStr::from_ptr(self.ptrs[0]) }.to_bytes().to_vec()
    }

    /// `getopt()`: the option character (as an int: '?' for errors), or -1, with
    /// `optarg`. glibc prints its own messages to stderr, as for C rpcbind.
    pub fn getopt(&mut self, optstring: &std::ffi::CStr) -> (i32, Option<Vec<u8>>) {
        unsafe extern "C" {
            static mut optarg: *mut c_char;
        }
        let argc = (self.ptrs.len() - 1) as c_int;
        // SAFETY: ptrs is a NULL-terminated array of pointers to live strings; getopt
        // permutes the array, which we own.
        let c = unsafe { libc::getopt(argc, self.ptrs.as_mut_ptr(), optstring.as_ptr()) };
        // SAFETY: optarg is set by getopt to NULL or into one of our strings.
        let arg = unsafe {
            let p = optarg;
            if p.is_null() { None } else { Some(CStr::from_ptr(p).to_bytes().to_vec()) }
        };
        (c, arg)
    }
}

impl Args {
    /// `argv + optind`: the operands left after [`Args::getopt`] returned -1 (glibc
    /// moves them to the end).
    pub fn rest(&self) -> Vec<Vec<u8>> {
        unsafe extern "C" {
            static mut optind: c_int;
        }
        // SAFETY: optind is getopt's global, read after it is done.
        let i = (unsafe { optind } as usize).min(self.ptrs.len() - 1);
        self.ptrs[i..self.ptrs.len() - 1]
            .iter()
            // SAFETY: each pointer is one of our live CStrings.
            .map(|&p| unsafe { CStr::from_ptr(p) }.to_bytes().to_vec())
            .collect()
    }
}

/// `raise(sig)`.
pub fn raise(sig: i32) -> i32 {
    // SAFETY: no memory arguments.
    unsafe { libc::raise(sig) }
}

/// The peer's effective uid on a local socket (`getpeereid()`, which libtirpc builds on
/// `SO_PEERCRED`).
pub fn peer_uid(fd: Fd) -> Option<u32> {
    let mut c = libc::ucred { pid: 0, uid: 0, gid: 0 };
    let mut len = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: c and len are valid; len gives c's size.
    let r = unsafe {
        libc::getsockopt(fd, libc::SOL_SOCKET, libc::SO_PEERCRED, (&mut c as *mut libc::ucred).cast(), &mut len)
    };
    if r == 0 { Some(c.uid) } else { None }
}

/// Whether `malloc(n)` would succeed now: C code allocates a decoded length before
/// reading the bytes, so a huge length fails (or not) at the allocation.
pub fn malloc_ok(n: usize) -> bool {
    // SAFETY: the block is freed at once and never touched.
    unsafe {
        let p = libc::malloc(n.max(1));
        let ok = !p.is_null();
        libc::free(p);
        ok
    }
}

/// `time(NULL)`.
pub fn time() -> i64 {
    // SAFETY: a null pointer is allowed.
    unsafe { libc::time(std::ptr::null_mut()) }
}

// ---------------------------------------------------------------------------
// for the client side (rpcinfo)

/// A sockaddr in a `sockaddr_storage`-sized buffer, for passing to the kernel.
fn ss_buf(addr: &[u8]) -> [u8; SS_LEN] {
    let mut ss = [0u8; SS_LEN];
    let n = addr.len().min(SS_LEN);
    ss[..n].copy_from_slice(&addr[..n]);
    ss
}

/// `connect(fd, addr, len)`: `Err(errno)` on failure.
pub fn connect(fd: Fd, addr: &[u8], len: usize) -> Result<(), i32> {
    let ss = ss_buf(addr);
    // SAFETY: ss is a sockaddr_storage-sized buffer; len is clamped to it.
    let r = unsafe { libc::connect(fd, ss.as_ptr().cast(), len.min(SS_LEN) as libc::socklen_t) };
    if r < 0 { Err(errno()) } else { Ok(()) }
}

/// `sendto(fd, buf, len, 0, addr, alen)`, or with no address when `addr` is `None`.
pub fn sendto(fd: Fd, buf: &[u8], addr: Option<(&[u8], usize)>) -> isize {
    match addr {
        None => {
            // SAFETY: buf is valid for its length; a null address is allowed.
            unsafe { libc::sendto(fd, buf.as_ptr().cast(), buf.len(), 0, std::ptr::null(), 0) }
        }
        Some((a, len)) => {
            let ss = ss_buf(a);
            // SAFETY: buf is valid for its length; ss holds the address.
            unsafe {
                libc::sendto(
                    fd,
                    buf.as_ptr().cast(),
                    buf.len(),
                    0,
                    ss.as_ptr().cast(),
                    len.min(SS_LEN) as libc::socklen_t,
                )
            }
        }
    }
}

/// `recvfrom(fd, buf, len, 0, NULL, NULL)`: the count or `Err(errno)`.
pub fn recvfrom(fd: Fd, buf: &mut [u8]) -> Result<usize, i32> {
    // SAFETY: buf is valid for writing its length; null address pointers are allowed.
    let r = unsafe {
        libc::recvfrom(fd, buf.as_mut_ptr().cast(), buf.len(), 0, std::ptr::null_mut(), std::ptr::null_mut())
    };
    if r < 0 { Err(errno()) } else { Ok(r as usize) }
}

/// `recvfrom(fd, buf, len, 0, &ss, &alen)` with `alen` in and out: the count or
/// `Err(errno)`. The address goes into `ss` (a `sockaddr_storage`).
pub fn recvfrom_addr(fd: Fd, buf: &mut [u8], ss: &mut [u8; SS_LEN], alen: &mut usize) -> Result<usize, i32> {
    let mut len = (*alen).min(SS_LEN) as libc::socklen_t;
    // SAFETY: buf and ss are valid for writing; len is at most ss's size.
    let r = unsafe { libc::recvfrom(fd, buf.as_mut_ptr().cast(), buf.len(), 0, ss.as_mut_ptr().cast(), &mut len) };
    if r < 0 {
        return Err(errno());
    }
    *alen = len as usize;
    Ok(r as usize)
}

/// What `recvmsg(fd, &msg, MSG_ERRQUEUE)` returned for `clnt_dg_call()`.
#[derive(Debug)]
pub struct ErrQueue {
    pub len: usize,
    /// The payload (an `outlen`-byte buffer).
    pub data: Vec<u8>,
    /// The `sockaddr_in` the offender's address went into, and the length returned.
    pub name: Vec<u8>,
    pub namelen: usize,
    pub flags: i32,
    /// Each control message: level, type and data.
    pub cmsgs: Vec<(i32, i32, Vec<u8>)>,
}

/// `recvmsg(fd, &msg, MSG_ERRQUEUE)` with an `iov_len`-byte payload buffer, a
/// `sockaddr_in` name and a 256-byte control buffer, as `clnt_dg_call()` does.
pub fn recvmsg_errqueue(fd: Fd, iov_len: usize) -> Result<ErrQueue, i32> {
    let mut data = vec![0u8; iov_len];
    let mut name = [0u8; size_of::<libc::sockaddr_in>()];
    let mut ctl = [0u8; 256];
    let mut iov = libc::iovec { iov_base: data.as_mut_ptr().cast(), iov_len };
    // SAFETY: an all-zero msghdr is valid.
    let mut m: libc::msghdr = unsafe { std::mem::zeroed() };
    m.msg_name = name.as_mut_ptr().cast();
    m.msg_namelen = name.len() as libc::socklen_t;
    m.msg_iov = &mut iov;
    m.msg_iovlen = 1;
    m.msg_control = ctl.as_mut_ptr().cast();
    m.msg_controllen = ctl.len();
    // SAFETY: every pointer in m refers to a live buffer of the stated size.
    let r = unsafe { libc::recvmsg(fd, &mut m, libc::MSG_ERRQUEUE) };
    if r < 0 {
        return Err(errno());
    }
    let mut cmsgs = Vec::new();
    // SAFETY: m describes the control buffer the kernel filled; CMSG_* walk it within
    // msg_controllen.
    unsafe {
        let mut c = libc::CMSG_FIRSTHDR(&m);
        while !c.is_null() {
            let hdr = &*c;
            let dlen = hdr.cmsg_len.saturating_sub(libc::CMSG_LEN(0) as usize);
            let d = std::slice::from_raw_parts(libc::CMSG_DATA(c), dlen).to_vec();
            cmsgs.push((hdr.cmsg_level, hdr.cmsg_type, d));
            c = libc::CMSG_NXTHDR(&m, c);
        }
    }
    Ok(ErrQueue {
        len: r as usize,
        data,
        name: name.to_vec(),
        namelen: m.msg_namelen as usize,
        flags: m.msg_flags,
        cmsgs,
    })
}

/// `ioctl(fd, FIONBIO, &1)`.
pub fn set_fionbio(fd: Fd) {
    let one: c_int = 1;
    // SAFETY: FIONBIO takes a pointer to an int.
    unsafe { libc::ioctl(fd, libc::FIONBIO, &one) };
}

/// `fcntl(fd, F_DUPFD, min)`.
pub fn dupfd(fd: Fd, min: Fd) -> Fd {
    // SAFETY: no memory arguments.
    unsafe { libc::fcntl(fd, libc::F_DUPFD, min) }
}

/// `fsync(fd)`.
pub fn fsync(fd: Fd) -> i32 {
    // SAFETY: no memory arguments.
    unsafe { libc::fsync(fd) }
}

/// `getpid()`.
pub fn getpid() -> i32 {
    // SAFETY: no arguments.
    unsafe { libc::getpid() }
}

/// `getegid()`.
pub fn getegid() -> u32 {
    // SAFETY: no arguments.
    unsafe { libc::getegid() }
}

/// `getgroups()`: the supplementary groups, or `Err(errno)`.
pub fn getgroups() -> Result<Vec<u32>, i32> {
    loop {
        // SAFETY: a zero size with a null list only counts.
        let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        if n < 0 {
            return Err(errno());
        }
        let mut g = vec![0 as libc::gid_t; n as usize + 1];
        // SAFETY: g has room for n groups.
        let m = unsafe { libc::getgroups(n, g.as_mut_ptr()) };
        if m < 0 {
            let e = errno();
            if e == libc::EINVAL {
                continue;
            }
            return Err(e);
        }
        g.truncate(m as usize);
        return Ok(g);
    }
}

/// `gethostname(buf, MAXHOSTNAMELEN + 1)`, NUL-terminated at the end of the buffer.
pub fn gethostname() -> Result<Vec<u8>, i32> {
    let mut b = [0 as c_char; 65];
    // SAFETY: b is valid for its length.
    if unsafe { libc::gethostname(b.as_mut_ptr(), b.len()) } < 0 {
        return Err(errno());
    }
    b[64] = 0;
    // SAFETY: b is NUL-terminated.
    Ok(unsafe { CStr::from_ptr(b.as_ptr()) }.to_bytes().to_vec())
}

/// Every `getaddrinfo(host, service, hints)` result, in order, or the error code.
pub fn getaddrinfo_all(
    host: Option<&[u8]>,
    service: &[u8],
    family: i32,
    socktype: i32,
    protocol: i32,
) -> Result<Vec<AddrInfo>, i32> {
    let h = host.map(cstring);
    let s = cstring(service);
    // SAFETY: an all-zero addrinfo is a valid hints struct.
    let mut hints: libc::addrinfo = unsafe { std::mem::zeroed() };
    hints.ai_family = family;
    hints.ai_socktype = socktype;
    hints.ai_protocol = protocol;
    let mut res: *mut libc::addrinfo = std::ptr::null_mut();
    // SAFETY: the strings are NUL-terminated (host may be NULL); res receives a list
    // freed below.
    let r =
        unsafe { libc::getaddrinfo(h.as_ref().map_or(std::ptr::null(), |h| h.as_ptr()), s.as_ptr(), &hints, &mut res) };
    if r != 0 {
        return Err(r);
    }
    let mut out = Vec::new();
    let mut p = res;
    while !p.is_null() {
        // SAFETY: p is a node of the list, with ai_addrlen bytes of address.
        unsafe {
            let a = &*p;
            let addr = std::slice::from_raw_parts(a.ai_addr.cast::<u8>(), a.ai_addrlen as usize).to_vec();
            out.push(AddrInfo { family: a.ai_family, socktype: a.ai_socktype, protocol: a.ai_protocol, addr });
            p = a.ai_next;
        }
    }
    // SAFETY: res came from getaddrinfo.
    unsafe { libc::freeaddrinfo(res) };
    Ok(out)
}

/// `getnameinfo(addr, len, host, NI_MAXHOST, NULL, 0, flags)`: the host name, or the
/// error code.
pub fn getnameinfo(addr: &[u8], len: usize, flags: i32) -> Result<Vec<u8>, i32> {
    let ss = ss_buf(addr);
    let mut host = [0 as c_char; 1025];
    // SAFETY: ss holds len (clamped) bytes; host is NI_MAXHOST bytes.
    let r = unsafe {
        libc::getnameinfo(
            ss.as_ptr().cast(),
            len.min(SS_LEN) as libc::socklen_t,
            host.as_mut_ptr(),
            host.len() as libc::socklen_t,
            std::ptr::null_mut(),
            0,
            flags,
        )
    };
    if r != 0 {
        return Err(r);
    }
    // SAFETY: getnameinfo NUL-terminates on success.
    Ok(unsafe { CStr::from_ptr(host.as_ptr()) }.to_bytes().to_vec())
}

/// `getrpcbyname(name)->r_number`.
pub fn rpc_number(name: &[u8]) -> Option<i32> {
    unsafe extern "C" {
        fn getrpcbyname(name: *const c_char) -> *mut RpcEnt;
    }
    let n = cstring(name);
    // SAFETY: n is NUL-terminated; the result is NULL or static storage, read at once.
    unsafe {
        let e = getrpcbyname(n.as_ptr());
        if e.is_null() { None } else { Some((*e).r_number) }
    }
}

/// `strtol(s, &end, 10)`: the value (saturated as glibc does) and whether all of `s`
/// was used and at least one digit was read (`end != s && *end == '\0'`).
pub fn strtol10(s: &[u8]) -> (i64, bool) {
    let c = cstring(s);
    let mut end: *mut c_char = std::ptr::null_mut();
    // SAFETY: c is NUL-terminated; end receives a pointer into it.
    let v = unsafe { libc::strtol(c.as_ptr(), &mut end, 10) };
    // SAFETY: end points into c, at or after its start.
    let used = unsafe { end.offset_from(c.as_ptr()) } as usize;
    (v as i64, used != 0 && used == c.as_bytes().len())
}

/// `strtoul(s, &end, 0)`: the value, how many bytes were used, and whether errno was
/// `ERANGE`.
pub fn strtoul0(s: &[u8]) -> (u64, usize, bool) {
    let c = cstring(s);
    let mut end: *mut c_char = std::ptr::null_mut();
    set_errno(0);
    // SAFETY: c is NUL-terminated; end receives a pointer into it.
    let v = unsafe { libc::strtoul(c.as_ptr(), &mut end, 0) };
    let erange = errno() == libc::ERANGE;
    // SAFETY: end points into c, at or after its start.
    let used = unsafe { end.offset_from(c.as_ptr()) } as usize;
    (v as u64, used, erange)
}
