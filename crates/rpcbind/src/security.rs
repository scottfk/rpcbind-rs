//! `security.c`: access checks for `SET`/`UNSET`, and `-l` logging.

use tirpc::addr::Netbuf;
use tirpc::sys;

/// `RPCBPROC_SET`, `RPCBPROC_UNSET` (and `PMAPPROC_SET`/`UNSET`).
const SET: u32 = 1;
const UNSET: u32 = 2;

/// `log_severity`: `LOG_AUTH|LOG_INFO`.
pub const LOG_SEVERITY: i32 = libc::LOG_AUTH | libc::LOG_INFO;

/// The options `check_access()` reads.
#[derive(Debug, Clone, Copy, Default)]
pub struct Access {
    pub insecure: bool,
    pub oldstyle_local: bool,
    pub verboselog: bool,
}

fn family(nb: &Netbuf) -> i32 {
    nb.family()
}

/// The IPv4 address of a sockaddr_in, or the last word of a sockaddr_in6's.
fn v4(nb: &Netbuf) -> [u8; 4] {
    nb.buf.get(4..8).map_or([0; 4], |b| b.try_into().unwrap())
}

fn v6(nb: &Netbuf) -> [u8; 16] {
    nb.buf.get(8..24).map_or([0; 16], |b| b.try_into().unwrap())
}

fn v6_is_loopback_or_mapped(a: &[u8; 16]) -> bool {
    let loopback = a[..15].iter().all(|&b| b == 0) && a[15] == 1;
    let mapped = a[..10].iter().all(|&b| b == 0) && a[10] == 0xff && a[11] == 0xff && a[12..] == [127, 0, 0, 1];
    loopback || mapped
}

/// `is_loopback()`.
pub fn is_loopback(acc: &Access, nb: &Netbuf) -> bool {
    match family(nb) {
        libc::AF_INET => acc.oldstyle_local && v4(nb) == [127, 0, 0, 1],
        libc::AF_INET6 => acc.oldstyle_local && v6_is_loopback_or_mapped(&v6(nb)),
        libc::AF_LOCAL => true,
        _ => false,
    }
}

/// `is_localroot()`.
pub fn is_localroot(acc: &Access, nb: &Netbuf) -> bool {
    let port = u16::from_be_bytes([nb.buf.get(2).copied().unwrap_or(0), nb.buf.get(3).copied().unwrap_or(0)]);
    match family(nb) {
        libc::AF_INET => acc.oldstyle_local && v4(nb) == [127, 0, 0, 1] && port < 1024,
        libc::AF_INET6 => acc.oldstyle_local && v6_is_loopback_or_mapped(&v6(nb)) && port < 1024,
        _ => false,
    }
}

/// `check_access()`. (No libwrap in this build.)
pub fn check_access(acc: &Access, caller: &Netbuf, proc_: u32, prog: u32) -> bool {
    if (proc_ == SET || proc_ == UNSET) && !acc.insecure && !is_loopback(acc, caller) {
        if acc.verboselog {
            logit(LOG_SEVERITY, caller, proc_, prog, b" declined (non-loopback sender)");
        }
        return false;
    }
    if acc.verboselog {
        logit(LOG_SEVERITY, caller, proc_, prog, b"");
    }
    true
}

/// `logit()`: in a forked child (so a slow `getrpcbynumber()` or `syslog()` can't hang
/// the daemon), log `connect from <host> to <proc>(<prog>)<text>`.
pub fn logit(severity: i32, addr: &Netbuf, procnum: u32, prognum: u32, text: &[u8]) {
    const PROCMAP: [&str; 13] = [
        "null",
        "set",
        "unset",
        "getport/addr",
        "dump",
        "callit",
        "gettime",
        "uaddr2taddr",
        "taddr2uaddr",
        "getversaddr",
        "indirect",
        "getaddrlist",
        "getstat",
    ];
    if sys::fork() != 0 {
        return;
    }
    let progname = if prognum == 0 {
        Vec::new()
    } else {
        sys::rpc_name(prognum as i32).unwrap_or_else(|| prognum.to_string().into_bytes())
    };
    let procname = PROCMAP.get(procnum as usize).map_or_else(|| procnum.to_string(), |s| s.to_string());
    let fromname = match family(addr) {
        libc::AF_LOCAL => b"local".to_vec(),
        libc::AF_INET => sys::getnameinfo_numeric(&addr.buf, size_of::<libc::sockaddr_in>()),
        libc::AF_INET6 => sys::getnameinfo_numeric(&addr.buf, size_of::<libc::sockaddr_in6>()),
        // size 0: getnameinfo() fails and fromname is whatever the stack held.
        _ => Vec::new(),
    };
    let mut msg = b"connect from ".to_vec();
    msg.extend_from_slice(&fromname);
    msg.extend_from_slice(b" to ");
    msg.extend_from_slice(procname.as_bytes());
    msg.push(b'(');
    msg.extend_from_slice(&progname);
    msg.push(b')');
    msg.extend_from_slice(text);
    sys::syslog(severity, &msg);
    sys::_exit(0);
}
