//! `rpcb_clnt.c`: talking to rpcbind as a client: the address cache, handles to the
//! local and remote rpcbind, `__rpcb_findaddr_timed()` (`GETADDR`, falling back to
//! portmap's `GETPORT`), `rpcb_getaddr()` and `rpcb_unset()`.

use crate::addr::{self, Netbuf};
use crate::clnt::{
    self, CacheEntry, Client, Control, Lib, RPC_ANYFD, RPC_CANTDECODEARGS, RPC_FAILED, RPC_N2AXLATEFAILURE,
    RPC_PMAPFAILURE, RPC_PROGNOTREGISTERED, RPC_PROGUNAVAIL, RPC_PROGVERSMISMATCH, RPC_SUCCESS, RPC_UNKNOWNHOST,
    RPC_UNKNOWNPROTO, Timeval,
};
use crate::netconfig::{NC_TPI_CLTS, NC_TPI_COTS, NC_TPI_COTS_ORD, Netconfig};
use crate::rpcb_prot::{self, Rpcb};
use crate::svc::{get_t_size, nconf2fd};
use crate::sys;
use crate::xdr;

pub const RPCBPROG: u32 = 100000;
pub const RPCBVERS: u32 = 3;
pub const RPCBVERS4: u32 = 4;
pub const PMAPVERS: u32 = 2;
pub const RPCBPROC_SET: u32 = 1;
pub const RPCBPROC_UNSET: u32 = 2;
pub const RPCBPROC_GETADDR: u32 = 3;
pub const PMAPPROC_GETPORT: u32 = 3;

/// `tottimeout`.
pub const TOTTIMEOUT: Timeval = Timeval::secs(60);
/// `rpcbrmttime`.
const RPCBRMTTIME: Timeval = Timeval::secs(15);
const CACHESIZE: usize = 6;
/// `_PATH_RPCBINDSOCK`.
pub const RPCBINDSOCK: &[u8] = b"/run/rpcbind.sock";

/// A `struct sockaddr_un` for `path` (a leading NUL for the abstract name) and its
/// `SUN_LEN_A()` length, in a netbuf of `sizeof(struct sockaddr_un)`.
pub fn sun_netbuf(path: &[u8]) -> Netbuf {
    let mut b = vec![0u8; size_of::<libc::sockaddr_un>()];
    b[..2].copy_from_slice(&(libc::AF_LOCAL as u16).to_ne_bytes());
    b[2..2 + path.len()].copy_from_slice(path);
    // SUN_LEN_A: offsetof(sun_path) + 1 + strlen(sun_path + 1)
    let rest = b[3..].iter().position(|&c| c == 0).unwrap_or(b.len() - 3);
    Netbuf { buf: b, len: 2 + 1 + rest }
}

fn copy_of_cached(lib: &Lib, host: &[u8], netid: &[u8]) -> Option<CacheEntry> {
    lib.cache.iter().find(|c| c.host == host && c.netid == netid).cloned()
}

/// `delete_cache()`: the first entry whose address starts with `addr`'s bytes.
fn delete_cache(lib: &mut Lib, addr: &Netbuf) {
    let a = addr.addr();
    if let Some(i) = lib.cache.iter().position(|c| c.taddr.buf.get(..a.len()) == Some(a)) {
        lib.cache.remove(i);
    }
}

/// `add_cache()`: in front, dropping the oldest when full.
fn add_cache(lib: &mut Lib, host: &[u8], netid: &[u8], taddr: &Netbuf, uaddr: Option<&[u8]>) {
    let e = CacheEntry {
        host: host.to_vec(),
        netid: netid.to_vec(),
        uaddr: uaddr.map(<[u8]>::to_vec),
        taddr: Netbuf::from_bytes(taddr.addr()),
    };
    if lib.cache.len() >= CACHESIZE {
        lib.cache.pop();
    }
    lib.cache.insert(0, e);
}

/// `getclnthandle()`: a handle to the rpcbind on `host` over `nconf`, and (when
/// `want_targaddr`) the universal address it was reached at.
pub fn getclnthandle(
    lib: &mut Lib,
    host: Option<&[u8]>,
    nconf: Option<&Netconfig>,
    want_targaddr: bool,
) -> (Option<Client>, Option<Vec<u8>>) {
    let Some(nconf) = nconf else {
        lib.createerr.stat = RPC_UNKNOWNPROTO;
        return (None, None);
    };
    let loopback = nconf.protofmly == b"loopback";
    if !loopback && host.is_none() {
        lib.createerr.stat = RPC_UNKNOWNHOST;
        return (None, None);
    }
    if let Some(h) = host
        && let Some(c) = copy_of_cached(lib, h, &nconf.netid)
    {
        if let Some(cl) = clnt::clnt_tli_create(lib, RPC_ANYFD, Some(nconf), &c.taddr, RPCBPROG, RPCBVERS4) {
            return (Some(cl), if want_targaddr { c.uaddr } else { None });
        }
        delete_cache(lib, &c.taddr);
    }
    let Some(si) = addr::nconf2sockinfo(nconf) else {
        lib.createerr.stat = RPC_UNKNOWNPROTO;
        return (None, None);
    };
    if loopback {
        return local_rpcb(lib, want_targaddr);
    }
    let res = match sys::getaddrinfo_all(host, b"sunrpc", si.af, si.socktype, si.proto) {
        Ok(r) => r,
        Err(_) => {
            lib.createerr.stat = RPC_UNKNOWNHOST;
            return (None, None);
        }
    };
    let mut client = None;
    let mut targaddr = None;
    for r in &res {
        let taddr = Netbuf::from_bytes(&r.addr);
        if let Some(cl) = clnt::clnt_tli_create(lib, RPC_ANYFD, Some(nconf), &taddr, RPCBPROG, RPCBVERS4) {
            let tmp = if want_targaddr { addr::taddr2uaddr(nconf, &taddr) } else { None };
            if let Some(h) = host {
                add_cache(lib, h, &nconf.netid, &taddr, tmp.as_deref());
            }
            targaddr = tmp;
            client = Some(cl);
            break;
        }
    }
    if client.is_some() && want_targaddr && targaddr.is_none() {
        sys::c_stderr(b"No targaddr provided\n");
    }
    (client, targaddr)
}

/// `local_rpcb()`: the local rpcbind, through its socket (the abstract name first),
/// or else over the last loopback-capable stream transport in `/etc/netconfig`.
pub fn local_rpcb(lib: &mut Lib, want_targaddr: bool) -> (Option<Client>, Option<Vec<u8>>) {
    let mut abs = vec![0u8];
    abs.extend_from_slice(RPCBINDSOCK);
    for path in [&abs[..], RPCBINDSOCK] {
        let sock = sys::socket(libc::AF_LOCAL, libc::SOCK_STREAM, 0);
        if sock < 0 {
            break;
        }
        let nbuf = sun_netbuf(path);
        let tsize = get_t_size(0, 0);
        if let Some(mut cl) = clnt::clnt_vc_create(lib, sock, &nbuf, RPCBPROG, RPCBVERS, tsize, tsize) {
            cl.control(Control::SetFdClose);
            let t = want_targaddr.then(|| {
                let mut p = path.to_vec();
                if p[0] == 0 {
                    p[0] = b'@';
                }
                p
            });
            return (Some(cl), t);
        }
        sys::close(sock);
    }
    if lib.loopnconf.is_none() {
        let Some(mut h) = lib.nc.setnetconfig() else {
            sys::syslog(libc::LOG_ERR, b"rpc: failed to open /etc/netconfig");
            lib.createerr.stat = RPC_UNKNOWNPROTO;
            return (None, None);
        };
        let mut tmp: Option<(Netconfig, &'static [u8])> = None;
        while let Some(nc) = lib.nc.getnetconfig(&mut h) {
            if (nc.protofmly == b"inet6" || nc.protofmly == b"inet")
                && (nc.semantics == NC_TPI_COTS || nc.semantics == NC_TPI_COTS_ORD)
            {
                let fd = nconf2fd(&nc);
                if fd < 0 {
                    continue;
                }
                sys::close(fd);
                let host: &'static [u8] = if nc.protofmly == b"inet" { b"127.0.0.1" } else { b"::1" };
                // QUIRK: no break: the last such entry wins (tcp6, normally).
                tmp = Some((nc, host));
            }
        }
        let Some((t, host)) = tmp else {
            lib.createerr.stat = RPC_UNKNOWNPROTO;
            lib.nc.endnetconfig(h);
            return (None, None);
        };
        let ent = lib.nc.getnetconfigent(&t.netid);
        lib.nc.endnetconfig(h);
        match ent {
            Some(e) => lib.loopnconf = Some((e, host)),
            None => return getclnthandle(lib, Some(host), None, want_targaddr),
        }
    }
    let (nc, host) = lib.loopnconf.clone().unwrap();
    getclnthandle(lib, Some(host), Some(&nc), want_targaddr)
}

/// `rpcb_unset()`: unset through the local rpcbind; the reply's boolean (FALSE when
/// the call fails).
pub fn rpcb_unset(lib: &mut Lib, prog: u32, vers: u32, nconf: Option<&Netconfig>) -> bool {
    let (Some(mut client), _) = local_rpcb(lib, false) else {
        return false;
    };
    let parms = Rpcb {
        prog,
        vers,
        netid: nconf.map_or(Vec::new(), |n| n.netid.clone()),
        addr: Vec::new(),
        owner: sys::geteuid().to_string().into_bytes(),
    };
    let mut rslt = false;
    client.call(
        RPCBPROC_UNSET,
        &mut |x| rpcb_prot::put_rpcb(x, &parms),
        &mut |x| match xdr::get_bool(x) {
            Some(b) => {
                rslt = b;
                true
            }
            None => false,
        },
        TOTTIMEOUT,
    );
    client.destroy();
    rslt
}

/// `getpmaphandle()` for an `nconf` (always given here).
fn getpmaphandle(lib: &mut Lib, nconf: &Netconfig, host: Option<&[u8]>) -> (Option<Client>, Option<Vec<u8>>) {
    let mut r = (None, None);
    if nconf.proto == b"udp" || nconf.proto == b"tcp" {
        if nconf.protofmly != b"inet" {
            return (None, None);
        }
        r = getclnthandle(lib, host, Some(nconf), true);
    }
    if let Some(c) = r.0.as_mut() {
        c.control(Control::SetVers(PMAPVERS));
    }
    r
}

/// `__try_protocol_version_2()`: portmap's `GETPORT`, and the address of the portmapper
/// with that port.
fn try_protocol_version_2(
    lib: &mut Lib,
    prog: u32,
    vers: u32,
    nconf: &Netconfig,
    host: Option<&[u8]>,
    tp: Timeval,
) -> Option<Netbuf> {
    if nconf.proto != b"udp" && nconf.proto != b"tcp" {
        return None;
    }
    let (Some(mut client), _) = getpmaphandle(lib, nconf, host) else {
        return None;
    };
    client.control(Control::SetRetryTimeout(RPCBRMTTIME));
    let prot = if nconf.proto == b"tcp" { libc::IPPROTO_TCP } else { libc::IPPROTO_UDP } as u32;
    let mut port: u32 = 0;
    let st = client.call(
        PMAPPROC_GETPORT,
        &mut |x| x.put_long(prog) && x.put_long(vers) && x.put_long(prot) && x.put_long(0),
        &mut |x| match x.get_long() {
            // xdr_u_short()
            Some(v) if v <= 0xffff => {
                port = v;
                true
            }
            _ => false,
        },
        tp,
    );
    let out = if st != RPC_SUCCESS {
        lib.createerr.stat = RPC_PMAPFAILURE;
        lib.createerr.error = client.geterr();
        None
    } else if port == 0 {
        lib.createerr.stat = RPC_PROGNOTREGISTERED;
        None
    } else {
        let remote = client.svc_addr();
        let mut a = remote.addr().to_vec();
        a[2..4].copy_from_slice(&(port as u16).to_be_bytes());
        Some(Netbuf::from_bytes(&a))
    };
    client.destroy();
    out
}

/// `__rpc_fixup_addr()`: a link- or site-local IPv6 answer takes the scope of the
/// address rpcbind was reached at.
fn fixup_addr(new: &mut Netbuf, svc: &Netbuf) {
    let (n, s) = (&mut new.buf, &svc.buf);
    if n.len() < 28 || s.len() < 28 {
        return;
    }
    let fam = |b: &[u8]| i32::from(u16::from_ne_bytes([b[0], b[1]]));
    if fam(n) != fam(s) || fam(n) != libc::AF_INET6 {
        return;
    }
    let ll = |b: &[u8]| b[8] == 0xfe && b[9] & 0xc0 == 0x80;
    let sl = |b: &[u8]| b[8] == 0xfe && b[9] & 0xc0 == 0xc0;
    if (ll(n) && ll(s)) || (sl(n) && sl(s)) {
        let scope: [u8; 4] = s[24..28].try_into().unwrap();
        n[24..28].copy_from_slice(&scope);
    }
}

/// `__rpcb_findaddr_timed()`: the address of (`prog`, `vers`) on `host` over `nconf`,
/// asking rpcbind (version 4, then 3) and then, for `inet`, the portmapper. With `clpp`,
/// the datagram handle to rpcbind is handed back for reuse.
pub fn rpcb_findaddr_timed(
    lib: &mut Lib,
    prog: u32,
    vers: u32,
    nconf: &Netconfig,
    host: Option<&[u8]>,
    clpp: Option<&mut Option<Client>>,
    tp: Option<Timeval>,
) -> Option<Netbuf> {
    let tp = tp.unwrap_or(TOTTIMEOUT);
    let mut address: Option<Netbuf> = None;
    let (client, r_addr) = getclnthandle(lib, host, Some(nconf), true);
    let mut client = client;
    let done = 'find: {
        let Some(cl) = client.as_mut() else {
            break 'find false;
        };
        let parms = Rpcb {
            prog,
            vers,
            netid: nconf.netid.clone(),
            addr: r_addr.unwrap_or_default(),
            owner: b"libtirpc".to_vec(),
        };
        // QUIRK: RPCB_V2FIRST, once seen, is remembered (a static) for the process.
        if std::env::var_os("RPCB_V2FIRST").is_some() {
            lib.portmap_first = true;
        }
        let mut try_rpcbind = !lib.portmap_first;
        loop {
            if try_rpcbind {
                cl.control(Control::SetRetryTimeout(RPCBRMTTIME));
                for v in [RPCBVERS4, RPCBVERS] {
                    cl.control(Control::SetVers(v));
                    let mut ua: Option<Vec<u8>> = None;
                    let st = cl.call(
                        RPCBPROC_GETADDR,
                        &mut |x| rpcb_prot::put_rpcb(x, &parms),
                        &mut |x| {
                            ua = xdr::get_string(x, u32::MAX).map(rpcb_prot::c_str);
                            ua.is_some()
                        },
                        tp,
                    );
                    match st {
                        RPC_SUCCESS => {
                            let ua = ua.unwrap_or_default();
                            if ua.is_empty() {
                                lib.createerr.stat = RPC_PROGNOTREGISTERED;
                                break 'find false;
                            }
                            let Some(mut a) = addr::uaddr2taddr(nconf, &ua) else {
                                lib.createerr.stat = RPC_N2AXLATEFAILURE;
                                break 'find false;
                            };
                            let servaddr = cl.svc_addr();
                            fixup_addr(&mut a, &servaddr);
                            address = Some(a);
                            break 'find true;
                        }
                        RPC_PROGVERSMISMATCH => {
                            if cl.geterr().low() > RPCBVERS4 {
                                break 'find false;
                            }
                        }
                        RPC_PROGUNAVAIL | RPC_CANTDECODEARGS => {}
                        _ => {
                            lib.createerr.stat = st;
                            lib.createerr.error = cl.geterr();
                            break 'find false;
                        }
                    }
                }
                if lib.portmap_first {
                    break 'find false;
                }
            }
            // portmap:
            if nconf.protofmly == b"inet" {
                address = try_protocol_version_2(lib, prog, vers, nconf, host, tp);
                if address.is_none() {
                    if lib.portmap_first {
                        try_rpcbind = true;
                        continue;
                    }
                    break 'find false;
                }
            }
            break;
        }
        if address.as_ref().is_none_or(|a| a.len == 0) {
            lib.createerr.stat = RPC_PROGNOTREGISTERED;
            lib.createerr.error = cl.geterr();
        }
        false
    };
    if !done && let Some(c) = client.take() {
        c.destroy();
    }
    if nconf.semantics != NC_TPI_CLTS
        && let Some(c) = client.take()
    {
        c.destroy();
    }
    match clpp {
        Some(p) => *p = client,
        None => {
            if let Some(c) = client {
                c.destroy();
            }
        }
    }
    address
}

/// `rpcb_getaddr()`: the address, if it fits in `maxlen` bytes.
pub fn rpcb_getaddr(
    lib: &mut Lib,
    prog: u32,
    vers: u32,
    nconf: &Netconfig,
    maxlen: usize,
    host: &[u8],
) -> Option<Netbuf> {
    let na = rpcb_findaddr_timed(lib, prog, vers, nconf, Some(host), None, None)?;
    if na.len > maxlen {
        lib.createerr.stat = RPC_FAILED;
        return None;
    }
    Some(na)
}
