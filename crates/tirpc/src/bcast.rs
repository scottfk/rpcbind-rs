//! `clnt_bcast.c`: `rpc_broadcast()`, a `NULL`-argument call sent through rpcbind's
//! `CALLIT` (and portmap's, for UDP over IPv4) to every broadcast address, with the
//! replies handed to a callback. Also `auth_unix.c`'s `authunix_create_default()`,
//! which only the broadcast uses.

use crate::addr::{self, Netbuf};
use crate::clnt::{
    Lib, RPC_CANTENCODEARGS, RPC_CANTRECV, RPC_CANTSEND, RPC_SUCCESS, RPC_SYSTEMERROR, RPC_TIMEDOUT, RPC_UNKNOWNPROTO,
    decode_reply,
};
use crate::netconfig::{NC_TPI_CLTS, Netconfig};
use crate::rpcb_prot;
use crate::svc::get_t_size;
use crate::sys::{self, Fd, SS_LEN};
use crate::xdr::{self, RPC_MAXDATASIZE, XdrDecode, XdrEncode, XdrMem};

const MAXBCAST: usize = 20;
const INITTIME: i32 = 4000;
const WAITTIME: i32 = 8000;
/// `RPCB_MULTICAST_ADDR`.
const RPCB_MULTICAST_ADDR: &[u8] = b"ff02::202";
const NGRPS: usize = 16;
const MAX_MACHINE_NAME: usize = 255;

/// `authunix_create_default()`: the marshalled `AUTH_SYS` body, or `None` (and
/// `RPC_SYSTEMERROR`). It clears `rpc_createerr` first.
fn authunix_default(lib: &mut Lib) -> Option<Vec<u8>> {
    lib.createerr = Default::default();
    let fail = |lib: &mut Lib, e: i32| {
        lib.createerr.error.set_errno(e);
        lib.createerr.stat = RPC_SYSTEMERROR;
        None
    };
    let machname = match sys::gethostname() {
        Ok(h) => h,
        Err(e) => return fail(lib, e),
    };
    let uid = sys::geteuid();
    let gid = sys::getegid();
    let mut gids = match sys::getgroups() {
        Ok(g) => g,
        Err(e) => return fail(lib, e),
    };
    gids.truncate(NGRPS);
    // authunix_create(): xdr_authunix_parms() into MAX_AUTH_BYTES.
    let mut mem = [0u8; crate::rpc::MAX_AUTH_BYTES];
    let mut x = XdrMem::new(&mut mem);
    let (s, _) = sys::gettimeofday();
    let ok = x.put_long(s as u32)
        && xdr::put_string(&mut x, &machname, MAX_MACHINE_NAME as u32)
        && x.put_long(uid)
        && x.put_long(gid)
        && x.put_long(gids.len() as u32)
        && gids.iter().all(|&g| x.put_long(g));
    if !ok {
        lib.createerr.stat = RPC_CANTENCODEARGS;
        return None;
    }
    let n = x.getpos();
    Some(mem[..n].to_vec())
}

/// One broadcast address (`struct broadif`).
#[derive(Debug, Clone)]
struct Broadif {
    addr: [u8; SS_LEN],
}

/// `__rpc_getbroadifs()`: IPv4 broadcast addresses, or the rpcbind multicast group on
/// each multicast-capable IPv6 interface, with rpcbind's port.
fn getbroadifs(af: i32, proto: i32, socktype: i32) -> Vec<Broadif> {
    let Some(ifs) = sys::getifaddrs() else {
        return Vec::new();
    };
    let Ok(res) = sys::getaddrinfo_all(None, b"sunrpc", af, socktype, proto) else {
        return Vec::new();
    };
    let port = [res[0].addr[2], res[0].addr[3]];
    let mut out = Vec::new();
    for ifa in &ifs {
        let Some(a) = &ifa.addr else { continue };
        if i32::from(u16::from_ne_bytes([a[0], a[1]])) != af || ifa.flags & libc::IFF_UP as u32 == 0 {
            continue;
        }
        let index = sys::if_nametoindex(&ifa.name);
        let mut b = [0u8; SS_LEN];
        if let Some(ba) =
            ifa.broadaddr.as_ref().filter(|_| af != libc::AF_INET6 && ifa.flags & libc::IFF_BROADCAST as u32 != 0)
        {
            b.copy_from_slice(&ba[..SS_LEN]);
            b[2..4].copy_from_slice(&port);
        } else if af == libc::AF_INET6 && ifa.flags & libc::IFF_MULTICAST as u32 != 0 {
            b[..2].copy_from_slice(&(libc::AF_INET6 as u16).to_ne_bytes());
            b[2..4].copy_from_slice(&port);
            let g = sys::pton(libc::AF_INET6, RPCB_MULTICAST_ADDR).unwrap_or_default();
            b[8..24].copy_from_slice(&g);
            b[24..28].copy_from_slice(&index.to_ne_bytes());
        } else {
            continue;
        }
        out.push(Broadif { addr: b });
    }
    out
}

/// One transport in the broadcast (`fdlist[]`).
#[derive(Debug)]
struct Bfd {
    fd: Fd,
    proto: i32,
    nconf: Netconfig,
    asize: usize,
    dsize: usize,
    raddr: [u8; SS_LEN],
    nal: Vec<Broadif>,
}

/// `xdr_callmsg()` encoding of a call with an `AUTH_SYS` credential and a null
/// verifier.
fn put_callmsg(x: &mut dyn XdrEncode, xid: u32, prog: u32, vers: u32, proc_: u32, cred: &[u8]) -> bool {
    x.put_long(xid)
        && x.put_long(0)
        && x.put_long(2)
        && x.put_long(prog)
        && x.put_long(vers)
        && x.put_long(proc_)
        && x.put_long(1)
        && xdr::put_bytes(x, cred, crate::rpc::MAX_AUTH_BYTES as u32)
        && x.put_long(0)
        && x.put_long(0)
}

/// `rpc_broadcast(prog, vers, proc, xdr_void, NULL, xdr_void, NULL, each, NULL)`:
/// `each` gets the server's address and transport, and ends the broadcast by returning
/// true.
pub fn rpc_broadcast(
    lib: &mut Lib,
    prog: u32,
    vers: u32,
    proc_: u32,
    each: &mut dyn FnMut(&Netbuf, &Netconfig) -> bool,
) -> u32 {
    let Some(cred) = authunix_default(lib) else {
        return RPC_SYSTEMERROR;
    };
    let mut stat = RPC_SUCCESS;
    let Some(mut handle) = crate::nettype::setconf(lib, Some(b"datagram_n")) else {
        return RPC_UNKNOWNPROTO;
    };
    let mut fds: Vec<Bfd> = Vec::new();
    let mut maxbufsize = 0usize;
    let mut pmap_flag = false;
    let mut udpbufsz = 0usize;
    while let Some(nconf) = crate::nettype::getconf(lib, &mut handle) {
        if nconf.semantics != NC_TPI_CLTS {
            continue;
        }
        if fds.len() >= MAXBCAST {
            break;
        }
        let Some(si) = addr::nconf2sockinfo(&nconf) else { continue };
        let nal = getbroadifs(si.af, si.proto, si.socktype);
        if nal.is_empty() {
            continue;
        }
        let fd = sys::socket(si.af, si.socktype, si.proto);
        if fd < 0 {
            stat = RPC_CANTSEND;
            continue;
        }
        let dsize = get_t_size(si.proto, 0);
        if maxbufsize <= dsize {
            maxbufsize = dsize;
        }
        if si.af == libc::AF_INET && si.proto == libc::IPPROTO_UDP {
            udpbufsz = dsize;
            pmap_flag = true;
        }
        fds.push(Bfd { fd, proto: si.proto, nconf, asize: addr::get_a_size(si.af), dsize, raddr: [0; SS_LEN], nal });
    }
    let stat = broadcast(lib, &mut fds, stat, maxbufsize, pmap_flag, udpbufsz, &cred, prog, vers, proc_, each);
    for f in &fds {
        sys::close(f.fd);
    }
    crate::nettype::endconf(lib, handle);
    stat
}

#[allow(clippy::too_many_arguments)]
fn broadcast(
    lib: &mut Lib,
    fds: &mut [Bfd],
    mut stat: u32,
    maxbufsize: usize,
    pmap_flag: bool,
    udpbufsz: usize,
    cred: &[u8],
    prog: u32,
    vers: u32,
    proc_: u32,
    each: &mut dyn FnMut(&Netbuf, &Netconfig) -> bool,
) -> u32 {
    if fds.is_empty() {
        return if stat == RPC_SUCCESS { RPC_UNKNOWNPROTO } else { stat };
    }
    if maxbufsize == 0 {
        return if stat == RPC_SUCCESS { RPC_CANTSEND } else { stat };
    }
    let mut inbuf = vec![0u8; maxbufsize];
    let mut outbuf = vec![0u8; maxbufsize];
    let xid = {
        let (s, us) = sys::gettimeofday();
        (sys::getpid() as u32) ^ (s as u32) ^ (us as u32)
    };
    let outlen = {
        let mut x = XdrMem::new(&mut outbuf);
        // xdr_rpcb_rmtcallargs(): prog, vers, proc, then the argument length (0).
        if !(put_callmsg(&mut x, xid, 100000, 3, 5, cred)
            && x.put_long(prog)
            && x.put_long(vers)
            && x.put_long(proc_)
            && x.put_long(0))
        {
            return RPC_CANTENCODEARGS;
        }
        x.getpos()
    };
    let mut outbuf_pmap = vec![0u8; udpbufsz];
    let mut outlen_pmap = 0;
    if pmap_flag {
        let mut x = XdrMem::new(&mut outbuf_pmap);
        if !(put_callmsg(&mut x, xid.wrapping_add(1), 100000, 2, 5, cred)
            && x.put_long(prog)
            && x.put_long(vers)
            && x.put_long(proc_)
            && x.put_long(0))
        {
            return RPC_CANTENCODEARGS;
        }
        outlen_pmap = x.getpos();
    }
    let mut pfd: Vec<libc::pollfd> =
        fds.iter().map(|f| libc::pollfd { fd: f.fd, events: crate::svc::POLL_EVENTS, revents: 0 }).collect();
    let mut msec = INITTIME;
    while msec <= WAITTIME {
        for f in fds.iter() {
            if f.dsize < outlen {
                stat = RPC_CANTSEND;
                continue;
            }
            for bip in &f.nal {
                sys::setsockopt_int(f.fd, libc::SOL_SOCKET, libc::SO_BROADCAST, 1);
                if !lib.lowvers && sys::sendto(f.fd, &outbuf[..outlen], Some((&bip.addr, f.asize))) != outlen as isize {
                    sys::warnx(b"rpc_broadcast_exp: cannot send broadcast packet");
                    stat = RPC_CANTSEND;
                    continue;
                }
                // QUIRK: the portmap packet goes out on udp6 as well.
                if pmap_flag
                    && f.proto == libc::IPPROTO_UDP
                    && sys::sendto(f.fd, &outbuf_pmap[..outlen_pmap], Some((&bip.addr, f.asize)))
                        != outlen_pmap as isize
                {
                    sys::warnx(b"clnt_bcast: Cannot send broadcast packet");
                    stat = RPC_CANTSEND;
                    continue;
                }
            }
        }
        // recv_again:
        'recv: loop {
            let pollretval = sys::poll(&mut pfd, msec);
            match pollretval {
                0 => {
                    stat = RPC_TIMEDOUT;
                    break 'recv;
                }
                -1 => continue 'recv,
                _ => {}
            }
            let mut found = 0;
            let mut i = 0;
            while i < fds.len() && found < pollretval {
                let f = &mut fds[i];
                i += 1;
                if pfd[i - 1].revents == 0 {
                    continue;
                }
                found += 1;
                if pfd[i - 1].revents & libc::POLLNVAL != 0 {
                    pfd[i - 1].fd = -1;
                    continue;
                }
                let inlen = loop {
                    match sys::recvfrom_addr(f.fd, &mut inbuf[..f.dsize], &mut f.raddr, &mut f.asize) {
                        Err(libc::EINTR) => continue,
                        r => break r,
                    }
                };
                let Ok(inlen) = inlen else {
                    sys::warnx(b"clnt_bcast: Cannot receive reply to broadcast");
                    stat = RPC_CANTRECV;
                    continue;
                };
                if inlen < 4 {
                    continue;
                }
                let pmap_reply = if inbuf[..4] == outbuf[..4] {
                    false
                } else if pmap_flag && inbuf[..4] == outbuf_pmap[..4] {
                    true
                } else {
                    continue;
                };
                let mut x = XdrMem::new(&mut inbuf[..inlen]);
                let mut done = false;
                if let Some(m) = decode_reply(&mut x)
                    && m.accepted_success()
                {
                    if pmap_reply {
                        // xdr_rmtcallres(): the port, the results' length, xdr_void.
                        if let Some(port) = get_rmtcallres(&mut x) {
                            f.raddr[2..4].copy_from_slice(&(port as u16).to_be_bytes());
                            let taddr = Netbuf { buf: f.raddr.to_vec(), len: SS_LEN };
                            done = each(&taddr, &f.nconf);
                        }
                    } else if let Some(uaddr) = get_rpcb_rmtcallres(&mut x) {
                        let np = addr::uaddr2taddr(&f.nconf, &uaddr).or_else(|| ipv6v4_fixup(&f.raddr, &uaddr));
                        if let Some(np) = np {
                            done = each(&np, &f.nconf);
                        }
                    }
                }
                if done {
                    return RPC_SUCCESS;
                }
                continue 'recv;
            }
            // Every ready descriptor was skipped without a matching reply: C's for loop
            // ends and so does this round.
            break 'recv;
        }
        msec += msec;
    }
    stat
}

/// `xdr_rmtcallres()` decoding: the port (`xdr_reference` of a `u_long`) and the
/// results' length; the results are `xdr_void`.
fn get_rmtcallres(x: &mut dyn XdrDecode) -> Option<u32> {
    let port = x.get_long()?;
    x.get_long()?;
    Some(port)
}

/// `xdr_rpcb_rmtcallres()` decoding: the server's universal address and the results'
/// length.
fn get_rpcb_rmtcallres(x: &mut dyn XdrDecode) -> Option<Vec<u8>> {
    // QUIRK: C decodes the address into a 1024-byte stack buffer with a 9000-byte limit.
    let a = rpcb_prot::c_str(xdr::get_string(x, RPC_MAXDATASIZE)?);
    x.get_long()?;
    Some(a)
}

/// `__ipv6v4_fixup()`: an IPv6 universal address in a reply that came over IPv4.
/// QUIRK: the port is read from the wrong structure (the netbuf header, not its
/// buffer), so it is always 0.
fn ipv6v4_fixup(ss: &[u8; SS_LEN], uaddr: &[u8]) -> Option<Netbuf> {
    if i32::from(u16::from_ne_bytes([ss[0], ss[1]])) != libc::AF_INET {
        return None;
    }
    let np = addr::uaddr2taddr_af(libc::AF_INET6, uaddr)?;
    // ((struct sockaddr_in6 *) np)->sin6_port: bytes 2-3 of the netbuf, the top half of
    // maxlen (sizeof(struct sockaddr_in6)).
    let maxlen = (np.buf.len() as u32).to_ne_bytes();
    let mut sin = ss[..size_of::<libc::sockaddr_in>()].to_vec();
    sin[2..4].copy_from_slice(&maxlen[2..4]);
    Some(Netbuf::from_bytes(&sin))
}
