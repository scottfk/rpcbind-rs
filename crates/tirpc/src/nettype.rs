//! Transport classes: `rpc_generic.c`'s `__rpc_setconf()`/`__rpc_getconf()`/
//! `__rpc_endconf()` and `getnettype()`, and `getnetpath.c` (the `NETPATH` variable).

use crate::clnt::Lib;
use crate::netconfig::{NC_TPI_CLTS, NC_TPI_COTS, NC_TPI_COTS_ORD, NC_VISIBLE, NcHandle, Netconfig};
use crate::sys;

/// `_RPC_*` nettypes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetType {
    None,
    Netpath,
    Visible,
    CircuitV,
    DatagramV,
    CircuitN,
    DatagramN,
    Tcp,
    Udp,
}

/// `getnettype()`: case-insensitive; no name is `netpath`.
pub fn getnettype(name: Option<&[u8]>) -> NetType {
    let Some(n) = name.filter(|n| !n.is_empty()) else {
        return NetType::Netpath;
    };
    const L: [(&[u8], NetType); 8] = [
        (b"netpath", NetType::Netpath),
        (b"visible", NetType::Visible),
        (b"circuit_v", NetType::CircuitV),
        (b"datagram_v", NetType::DatagramV),
        (b"circuit_n", NetType::CircuitN),
        (b"datagram_n", NetType::DatagramN),
        (b"tcp", NetType::Tcp),
        (b"udp", NetType::Udp),
    ];
    L.iter().find(|(s, _)| s.eq_ignore_ascii_case(n)).map_or(NetType::None, |&(_, t)| t)
}

/// `struct netpath_vars`.
#[derive(Debug)]
struct Netpath {
    nc: Option<NcHandle>,
    /// Our copy of `NETPATH` (NUL-terminated), if it was set.
    buf: Option<Vec<u8>>,
    /// `netpath`: where the next token starts, or `None` (NULL).
    pos: Option<usize>,
}

/// The handle `__rpc_setconf()` returns.
#[derive(Debug)]
pub struct ConfHandle {
    nettype: NetType,
    netpath: Option<Netpath>,
    nc: Option<NcHandle>,
}

const NETCONFIG_FAIL: &[u8] = b"rpc: failed to open /etc/netconfig";

/// `setnetpath()`.
fn setnetpath(lib: &mut Lib) -> Option<Netpath> {
    let Some(h) = lib.nc.setnetconfig() else {
        sys::syslog(libc::LOG_ERR, NETCONFIG_FAIL);
        return None;
    };
    match std::env::var_os("NETPATH") {
        None => Some(Netpath { nc: Some(h), buf: None, pos: None }),
        Some(v) => {
            lib.nc.endnetconfig(h);
            let mut b = std::os::unix::ffi::OsStrExt::as_bytes(v.as_os_str()).to_vec();
            if let Some(n) = b.iter().position(|&c| c == 0) {
                b.truncate(n);
            }
            b.push(0);
            Some(Netpath { nc: None, buf: Some(b), pos: Some(0) })
        }
    }
}

fn strchr(b: &[u8], from: usize, c: u8) -> Option<usize> {
    b[from..].iter().position(|&x| x == c || x == 0).map(|i| from + i).filter(|&i| b[i] == c)
}

/// `strcpy(&b[to], &b[from])` for `to < from`.
fn shift_down(b: &mut [u8], to: usize, from: usize) {
    let end = from + b[from..].iter().position(|&x| x == 0).unwrap_or(b.len() - from);
    b.copy_within(from..=end.min(b.len() - 1), to);
}

/// `_get_next_token()`: cut the string at the first unescaped `token`, removing the
/// escapes, and return where the rest starts.
fn get_next_token(b: &mut [u8], npp: usize, token: u8) -> Option<usize> {
    let cp = strchr(b, npp, token)?;
    if cp > npp && b[cp - 1] == b'\\' && cp > npp + 1 && b[cp - 2] != b'\\' {
        shift_down(b, cp - 1, cp);
        return get_next_token(b, cp, token);
    }
    b[cp] = 0;
    let rest = cp + 1;
    let mut ep = npp;
    while let Some(mut np) = strchr(b, ep, b'\\') {
        if b[np + 1] == b'\\' {
            np += 1;
        }
        ep = np + 1;
        shift_down(b, np, ep);
    }
    Some(rest)
}

/// `getnetpath()`.
fn getnetpath(lib: &mut Lib, np: &mut Netpath) -> Option<Netconfig> {
    let Some(buf) = np.buf.as_mut() else {
        // NETPATH unset: the visible entries of /etc/netconfig.
        loop {
            if np.nc.is_none() {
                np.nc = lib.nc.setnetconfig();
                if np.nc.is_none() {
                    sys::syslog(libc::LOG_ERR, NETCONFIG_FAIL);
                }
            }
            let nc = lib.nc.getnetconfig(np.nc.as_mut()?)?;
            if nc.flag & NC_VISIBLE != 0 {
                return Some(nc);
            }
        }
    };
    while let Some(p) = np.pos {
        if buf[p] == 0 {
            break;
        }
        np.pos = get_next_token(buf, p, b':');
        let end = p + buf[p..].iter().position(|&c| c == 0).unwrap_or(0);
        let id = buf[p..end].to_vec();
        if let Some(nc) = lib.nc.getnetconfigent(&id) {
            return Some(nc);
        }
    }
    None
}

/// `__rpc_setconf()`.
pub fn setconf(lib: &mut Lib, nettype: Option<&[u8]>) -> Option<ConfHandle> {
    let t = getnettype(nettype);
    match t {
        NetType::Netpath | NetType::CircuitN | NetType::DatagramN => {
            let np = setnetpath(lib)?;
            Some(ConfHandle { nettype: t, netpath: Some(np), nc: None })
        }
        NetType::Visible | NetType::CircuitV | NetType::DatagramV | NetType::Tcp | NetType::Udp => {
            let Some(h) = lib.nc.setnetconfig() else {
                sys::syslog(libc::LOG_ERR, NETCONFIG_FAIL);
                return None;
            };
            Some(ConfHandle { nettype: t, netpath: None, nc: Some(h) })
        }
        NetType::None => None,
    }
}

/// `__rpc_getconf()`: the next entry of the class.
pub fn getconf(lib: &mut Lib, h: &mut ConfHandle) -> Option<Netconfig> {
    loop {
        let nc = if let Some(np) = h.netpath.as_mut() {
            getnetpath(lib, np)?
        } else {
            lib.nc.getnetconfig(h.nc.as_mut()?)?
        };
        let s = nc.semantics;
        if s != NC_TPI_CLTS && s != NC_TPI_COTS && s != NC_TPI_COTS_ORD {
            continue;
        }
        let visible = nc.flag & NC_VISIBLE != 0;
        let cots = s == NC_TPI_COTS || s == NC_TPI_COTS_ORD;
        let inet = nc.protofmly == b"inet" || nc.protofmly == b"inet6";
        let ok = match h.nettype {
            NetType::Visible => visible,
            NetType::Netpath | NetType::None => true,
            NetType::CircuitV => visible && cots,
            NetType::CircuitN => cots,
            NetType::DatagramV => visible && s == NC_TPI_CLTS,
            NetType::DatagramN => s == NC_TPI_CLTS,
            NetType::Tcp => cots && inet && nc.proto == b"tcp",
            NetType::Udp => s == NC_TPI_CLTS && inet && nc.proto == b"udp",
        };
        if ok {
            return Some(nc);
        }
    }
}

/// `__rpc_endconf()`.
pub fn endconf(lib: &mut Lib, h: ConfHandle) {
    if let Some(np) = h.netpath {
        if let Some(n) = np.nc {
            lib.nc.endnetconfig(n);
        }
    } else if let Some(n) = h.nc {
        lib.nc.endnetconfig(n);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(s: &[u8]) -> Vec<Vec<u8>> {
        let mut b = s.to_vec();
        b.push(0);
        let mut out = Vec::new();
        let mut p = Some(0);
        while let Some(i) = p {
            if b[i] == 0 {
                break;
            }
            p = get_next_token(&mut b, i, b':');
            let end = i + b[i..].iter().position(|&c| c == 0).unwrap();
            out.push(b[i..end].to_vec());
        }
        out
    }

    #[test]
    fn netpath_tokens() {
        assert_eq!(tokens(b"tcp:udp"), [b"tcp".to_vec(), b"udp".to_vec()]);
        assert_eq!(tokens(b"a\\:b:c"), [b"a:b".to_vec(), b"c".to_vec()]);
        assert_eq!(tokens(b"::tcp"), [Vec::<u8>::new(), Vec::new(), b"tcp".to_vec()]);
    }
}
