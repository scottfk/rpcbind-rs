//! `rpc_generic.c`'s address helpers: socket info from a netconfig entry, and
//! conversions between transport addresses (`struct netbuf`) and universal addresses
//! (`h1.h2.h3.h4.p1.p2`, `x:x::x.p1.p2`, or a local socket path).

use crate::netconfig::{NC_TPI_CLTS, NC_TPI_COTS_ORD, NC_TPI_RAW, Netconfig};
use crate::sys;

/// `struct netbuf`: a socket address as raw `struct sockaddr` bytes. `buf` holds
/// `maxlen` bytes, of which the first `len` are the address; the rest is kept because C
/// code reads past `len` in places (see [`taddr2uaddr_af`]).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Netbuf {
    pub buf: Vec<u8>,
    pub len: usize,
}

impl Netbuf {
    /// A netbuf holding exactly `bytes`.
    pub fn from_bytes(bytes: &[u8]) -> Netbuf {
        Netbuf { buf: bytes.to_vec(), len: bytes.len() }
    }

    /// The address bytes (`buf[..len]`).
    pub fn addr(&self) -> &[u8] {
        &self.buf[..self.len.min(self.buf.len())]
    }

    /// `sa_family`, or `AF_UNSPEC` for a buffer too short to hold one.
    pub fn family(&self) -> i32 {
        if self.buf.len() < 2 { libc::AF_UNSPEC } else { i32::from(u16::from_ne_bytes([self.buf[0], self.buf[1]])) }
    }
}

const SIN_LEN: usize = size_of::<libc::sockaddr_in>();
const SIN6_LEN: usize = size_of::<libc::sockaddr_in6>();
const SUN_LEN_MAX: usize = size_of::<libc::sockaddr_un>();
/// `offsetof(struct sockaddr_un, sun_path)`.
const SUN_PATH_OFF: usize = 2;
const SUN_PATH_LEN: usize = SUN_LEN_MAX - SUN_PATH_OFF;
/// `RPC_MAXADDRSIZE`.
const RPC_MAXADDRSIZE: usize = 1024;

/// `struct __rpc_sockinfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SockInfo {
    pub af: i32,
    pub proto: i32,
    pub socktype: i32,
    pub alen: usize,
}

/// `na_cvt[]`.
const NA_CVT: &[(&[u8], i32, i32)] = &[
    (b"udp", libc::AF_INET, libc::IPPROTO_UDP),
    (b"tcp", libc::AF_INET, libc::IPPROTO_TCP),
    (b"udp6", libc::AF_INET6, libc::IPPROTO_UDP),
    (b"tcp6", libc::AF_INET6, libc::IPPROTO_TCP),
    (b"local", libc::AF_LOCAL, 0),
];

/// `__rpc_seman2socktype()`.
pub fn seman2socktype(semantics: u32) -> Option<i32> {
    match semantics {
        NC_TPI_CLTS => Some(libc::SOCK_DGRAM),
        NC_TPI_COTS_ORD => Some(libc::SOCK_STREAM),
        NC_TPI_RAW => Some(libc::SOCK_RAW),
        _ => None,
    }
}

/// `__rpc_get_a_size()`.
pub fn get_a_size(af: i32) -> usize {
    match af {
        libc::AF_INET => SIN_LEN,
        libc::AF_INET6 => SIN6_LEN,
        libc::AF_LOCAL => SUN_LEN_MAX,
        _ => RPC_MAXADDRSIZE,
    }
}

/// `__rpc_nconf2sockinfo()`: by netid only (`unix` counts as `local`). Fails for
/// `tpi_cots`, which has no socket type.
pub fn nconf2sockinfo(nconf: &Netconfig) -> Option<SockInfo> {
    for &(netid, af, proto) in NA_CVT {
        if nconf.netid == netid || (nconf.netid == b"unix" && netid == b"local") {
            let socktype = seman2socktype(nconf.semantics)?;
            return Some(SockInfo { af, proto, socktype, alen: get_a_size(af) });
        }
    }
    None
}

/// `__rpc_sockinfo2netid()`: `local_exists` is whether `getnetconfigent("local")`
/// found an entry (when it didn't, local sockets are `unix`).
pub fn sockinfo2netid(si: &SockInfo, local_exists: bool) -> Option<&'static [u8]> {
    for &(netid, af, proto) in NA_CVT {
        if af == si.af && proto == si.proto {
            return Some(if netid == b"local" && !local_exists { b"unix" } else { netid });
        }
    }
    None
}

/// `taddr2uaddr()`.
pub fn taddr2uaddr(nconf: &Netconfig, nbuf: &Netbuf) -> Option<Vec<u8>> {
    taddr2uaddr_af(nconf2sockinfo(nconf)?.af, nbuf)
}

/// `uaddr2taddr()`.
pub fn uaddr2taddr(nconf: &Netconfig, uaddr: &[u8]) -> Option<Netbuf> {
    uaddr2taddr_af(nconf2sockinfo(nconf)?.af, uaddr)
}

fn port_uaddr(host: &[u8], port: u16) -> Vec<u8> {
    let mut s = host.to_vec();
    s.extend_from_slice(format!(".{}.{}", port >> 8, port & 0xff).as_bytes());
    s
}

/// `__rpc_taddr2uaddr_af()`.
pub fn taddr2uaddr_af(af: i32, nbuf: &Netbuf) -> Option<Vec<u8>> {
    if nbuf.len == 0 {
        return None;
    }
    let b = &nbuf.buf;
    match af {
        libc::AF_INET => {
            if nbuf.len < SIN_LEN || b.len() < SIN_LEN {
                return None;
            }
            let host = sys::ntop(af, &b[4..8])?;
            Some(port_uaddr(&host, u16::from_be_bytes([b[2], b[3]])))
        }
        libc::AF_INET6 => {
            if nbuf.len < SIN6_LEN || b.len() < SIN6_LEN {
                return None;
            }
            let host = sys::ntop(af, &b[8..24])?;
            Some(port_uaddr(&host, u16::from_be_bytes([b[2], b[3]])))
        }
        libc::AF_LOCAL => {
            let path_len = nbuf.len as isize - SUN_PATH_OFF as isize;
            if path_len < 0 {
                return None;
            }
            // "%c%.*s" with sun_path[0] (or '@' for an abstract name) and then
            // path_len - 1 bytes of sun_path + 1, stopping at a NUL.
            let path = b.get(SUN_PATH_OFF..).unwrap_or(&[]);
            let first = path.first().copied().unwrap_or(0);
            let mut s = vec![if first == 0 { b'@' } else { first }];
            let rest = path.get(1..).unwrap_or(&[]);
            // QUIRK: for an unnamed socket (len == 2, as a local client's address
            // usually is), the precision is -1, which printf ignores: the string runs on
            // past len, through whatever the buffer holds, up to a NUL.
            let limit = if path_len - 1 < 0 { rest.len() } else { (path_len as usize - 1).min(rest.len()) };
            s.extend(rest[..limit].iter().take_while(|&&c| c != 0));
            Some(s)
        }
        _ => None,
    }
}

/// `__rpc_uaddr2taddr_af()`.
pub fn uaddr2taddr_af(af: i32, uaddr: &[u8]) -> Option<Netbuf> {
    let mut addrstr = uaddr[..uaddr.iter().position(|&b| b == 0).unwrap_or(uaddr.len())].to_vec();
    let mut port: u32 = 0;
    // AF_LOCAL addresses are absolute paths or abstract names; anything else is
    // AF_INET or AF_INET6, with the port as the last two dotted parts.
    if addrstr.first() != Some(&b'/') && addrstr.first() != Some(&b'@') {
        let p = addrstr.iter().rposition(|&b| b == b'.')?;
        let portlo = sys::atoi(&addrstr[p + 1..]) as u32;
        addrstr.truncate(p);
        let p = addrstr.iter().rposition(|&b| b == b'.')?;
        let porthi = sys::atoi(&addrstr[p + 1..]) as u32;
        addrstr.truncate(p);
        port = (porthi << 8) | portlo;
    }
    // htons(port) keeps the low 16 bits.
    let port_be = (port as u16).to_be_bytes();
    let family = (af as u16).to_ne_bytes();
    match af {
        libc::AF_INET => {
            let a = sys::pton(af, &addrstr)?;
            let mut b = vec![0u8; SIN_LEN];
            b[0..2].copy_from_slice(&family);
            b[2..4].copy_from_slice(&port_be);
            b[4..8].copy_from_slice(&a);
            Some(Netbuf { buf: b, len: SIN_LEN })
        }
        libc::AF_INET6 => {
            let a = sys::pton(af, &addrstr)?;
            let mut b = vec![0u8; SIN6_LEN];
            b[0..2].copy_from_slice(&family);
            b[2..4].copy_from_slice(&port_be);
            b[8..24].copy_from_slice(&a);
            Some(Netbuf { buf: b, len: SIN6_LEN })
        }
        libc::AF_LOCAL => {
            let mut b = vec![0u8; SUN_LEN_MAX];
            b[0..2].copy_from_slice(&family);
            // strncpy(sun_path, addrstr, sizeof(sun_path) - 1)
            let n = addrstr.len().min(SUN_PATH_LEN - 1);
            b[SUN_PATH_OFF..SUN_PATH_OFF + n].copy_from_slice(&addrstr[..n]);
            let len = SUN_PATH_OFF + n; // SUN_LEN()
            if b[SUN_PATH_OFF] == b'@' {
                b[SUN_PATH_OFF] = 0; // abstract address
            }
            Some(Netbuf { buf: b, len })
        }
        // C returns an uninitialized netbuf here, but nconf2sockinfo() only gives the
        // three families above.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inet_round_trip() {
        let nb = uaddr2taddr_af(libc::AF_INET, b"127.0.0.1.0.111").unwrap();
        assert_eq!(nb.len, 16);
        assert_eq!(&nb.buf[2..8], &[0, 111, 127, 0, 0, 1]);
        assert_eq!(taddr2uaddr_af(libc::AF_INET, &nb).unwrap(), b"127.0.0.1.0.111");
        let nb = uaddr2taddr_af(libc::AF_INET6, b"::1.8.1").unwrap();
        assert_eq!(taddr2uaddr_af(libc::AF_INET6, &nb).unwrap(), b"::1.8.1");
    }

    #[test]
    fn port_parts_wrap_like_c() {
        // porthi 999 << 8 | 999, truncated by htons.
        let nb = uaddr2taddr_af(libc::AF_INET, b"10.0.0.1.999.999").unwrap();
        let port = ((999u32 << 8) | 999) as u16;
        assert_eq!(&nb.buf[2..4], &port.to_be_bytes());
        assert!(uaddr2taddr_af(libc::AF_INET, b"10.0.0.1").is_none()); // "10.0" isn't an address
        assert!(uaddr2taddr_af(libc::AF_INET, b"nodots").is_none());
    }

    #[test]
    fn local_paths() {
        let nb = uaddr2taddr_af(libc::AF_LOCAL, b"/run/rpcbind.sock").unwrap();
        assert_eq!(nb.len, 2 + 17);
        assert_eq!(taddr2uaddr_af(libc::AF_LOCAL, &nb).unwrap(), b"/run/rpcbind.sock");
        let nb = uaddr2taddr_af(libc::AF_LOCAL, b"@abs").unwrap();
        assert_eq!(nb.buf[2], 0);
        assert_eq!(taddr2uaddr_af(libc::AF_LOCAL, &nb).unwrap(), b"@abs");
        // An unnamed socket: the bytes past len are read up to a NUL.
        let mut b = vec![0u8; 110];
        b[0..2].copy_from_slice(&(libc::AF_LOCAL as u16).to_ne_bytes());
        b[3..6].copy_from_slice(b"xyz");
        assert_eq!(taddr2uaddr_af(libc::AF_LOCAL, &Netbuf { buf: b, len: 2 }).unwrap(), b"@xyz");
    }
}
