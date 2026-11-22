//! `util.c`: `network_init()`. (`addrmerge()` comes with the protocol, in phase 2.)

use tirpc::sys;

/// `local_in4`/`local_in6`: the wildcard `sunrpc` addresses (used only by remote
/// calls, which this build leaves out).
#[derive(Debug, Default)]
pub struct LocalAddrs {
    pub in4: Option<Vec<u8>>,
    pub in6: Option<Vec<u8>>,
}

/// `RPCB_MULTICAST_ADDR`, ff02::202.
const RPCB_MULTICAST_ADDR: [u8; 16] = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02, 0x02];

/// `network_init()`.
pub fn network_init(debugging: bool) -> LocalAddrs {
    let mut la = LocalAddrs::default();
    match sys::getaddrinfo(None, b"sunrpc", 0, libc::AF_INET, 0, 0) {
        Err(e) => {
            if debugging {
                let mut m = b"can't get local ip4 address: ".to_vec();
                m.extend_from_slice(&sys::gai_strerror(e));
                m.push(b'\n');
                sys::c_stderr(&m);
            }
        }
        Ok(a) => la.in4 = Some(a.addr),
    }
    match sys::getaddrinfo(None, b"sunrpc", 0, libc::AF_INET6, 0, 0) {
        Err(e) => {
            if debugging {
                let mut m = b"can't get local ip6 address: ".to_vec();
                m.extend_from_slice(&sys::gai_strerror(e));
                m.push(b'\n');
                sys::c_stderr(&m);
            }
        }
        Ok(a) => la.in6 = Some(a.addr),
    }
    // Join the RPC IPv6 multicast group on every interface.
    let Some(ifs) = sys::getifaddrs() else {
        return la;
    };
    let s = sys::socket(libc::AF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_UDP);
    if s < 0 {
        if debugging {
            let mut m = b"socket(AF_INET6) failed: ".to_vec();
            m.extend_from_slice(&sys::strerror(sys::errno()));
            m.push(b'\n');
            sys::c_stderr(&m);
        }
        return la;
    }
    let mut last = 0u32;
    for ifa in &ifs {
        let Some(a) = &ifa.addr else { continue };
        if i32::from(u16::from_ne_bytes([a[0], a[1]])) != libc::AF_INET6 || ifa.flags & libc::IFF_MULTICAST as u32 == 0
        {
            continue;
        }
        let ifindex = sys::if_nametoindex(&ifa.name);
        if ifindex == last {
            continue; // already did this one
        }
        last = ifindex;
        if sys::ipv6_join_group(s, &RPCB_MULTICAST_ADDR, ifindex) < 0 && debugging {
            let mut m = b"setsockopt v6 multicast: ".to_vec();
            m.extend_from_slice(&sys::strerror(sys::errno()));
            m.push(b'\n');
            sys::c_stderr(&m);
        }
    }
    // QUIRK: the memberships belong to this socket, so closing it leaves the groups.
    sys::close(s);
    la
}

/// `IFF_UP`, `IFF_LOOPBACK`, `IFF_POINTOPOINT`.
const IFF_UP: u32 = libc::IFF_UP as u32;
const IFF_LOOPBACK: u32 = libc::IFF_LOOPBACK as u32;
const IFF_POINTOPOINT: u32 = libc::IFF_POINTOPOINT as u32;

fn family(sa: &[u8]) -> i32 {
    i32::from(u16::from_ne_bytes([sa[0], sa[1]]))
}

/// The address bytes of a sockaddr_in (4) or sockaddr_in6 (16).
fn inaddr(sa: &[u8], af: i32) -> &[u8] {
    match af {
        libc::AF_INET => &sa[4..8],
        _ => &sa[8..24],
    }
}

fn scope_id(sa: &[u8]) -> u32 {
    u32::from_ne_bytes(sa[24..28].try_into().unwrap())
}

fn is_linklocal(a: &[u8]) -> bool {
    a[0] == 0xfe && (a[1] & 0xc0) == 0x80
}

/// `bitmaskcmp()`: whether the masked addresses differ.
fn bitmaskcmp(a: &[u8], b: &[u8], mask: &[u8]) -> bool {
    a.iter().zip(b).zip(mask).any(|((x, y), m)| x & m != y & m)
}

/// `addrmerge()`: the server's universal address rewritten to use the address of the
/// interface the caller (or the client's hint) can reach us on.
pub fn addrmerge(
    fdlist: &crate::check_bound::FdList,
    caller: &tirpc::addr::Netbuf,
    serv_uaddr: &[u8],
    clnt_uaddr: Option<&[u8]>,
    netid: &[u8],
) -> Option<Vec<u8>> {
    use tirpc::addr;
    let nconf = fdlist.get_conf(netid)?;
    let caller_uaddr = addr::taddr2uaddr(nconf, caller)?;
    // Use the client's hint unless its family differs from the caller's.
    let caller_sa: Vec<u8> = {
        let mut v = caller.buf.clone();
        v.resize(v.len().max(sys::SS_LEN), 0);
        v
    };
    let mut hint_sa = None;
    if let Some(c) = clnt_uaddr {
        hint_sa = Some(addr::uaddr2taddr(nconf, c)?.buf);
    }
    let hint_sa = match hint_sa {
        Some(h) if family(&h) == family(&caller_sa) => {
            let mut h = h;
            h.resize(h.len().max(sys::SS_LEN), 0);
            h
        }
        _ => caller_sa.clone(),
    };
    // A local caller: just return the server address.
    if caller_uaddr.starts_with(b"0.0.0.0.") || caller_uaddr.starts_with(b"::.") || caller_uaddr.first() == Some(&b'/')
    {
        return Some(serv_uaddr.to_vec());
    }
    let ifs = sys::getifaddrs()?;
    let hf = family(&hint_sa);
    let all = [0xffu8; 16];
    let mut bestif: Option<usize> = None;
    let mut exactif: Option<usize> = None;
    for (i, ifa) in ifs.iter().enumerate() {
        let Some(ifsa) = &ifa.addr else { continue };
        if family(ifsa) != hf || ifa.flags & IFF_UP == 0 {
            continue;
        }
        let mask = ifa.netmask.clone().unwrap_or_else(|| vec![0; sys::SS_LEN]);
        match hf {
            libc::AF_INET => {
                if !bitmaskcmp(inaddr(ifsa, hf), inaddr(&hint_sa, hf), inaddr(&mask, hf)) {
                    if bestif.is_none() {
                        bestif = Some(i);
                    }
                    if !bitmaskcmp(inaddr(ifsa, hf), inaddr(&hint_sa, hf), &all[..4]) {
                        exactif = Some(i);
                        break;
                    }
                }
            }
            libc::AF_INET6 => {
                if is_linklocal(inaddr(ifsa, hf))
                    && is_linklocal(inaddr(&caller_sa, hf))
                    && is_linklocal(inaddr(&hint_sa, hf))
                {
                    if scope_id(ifsa) == scope_id(&caller_sa) {
                        bestif = Some(i);
                        break;
                    }
                } else if !bitmaskcmp(inaddr(ifsa, hf), inaddr(&hint_sa, hf), inaddr(&mask, hf)) {
                    if bestif.is_none() {
                        bestif = Some(i);
                    }
                    if !bitmaskcmp(inaddr(ifsa, hf), inaddr(&hint_sa, hf), &all) {
                        exactif = Some(i);
                        break;
                    }
                }
            }
            _ => continue,
        }
        // QUIRK: remember the first usable interface, preferring "normal" ones to
        // loopback and point-to-point ones; this runs for every interface, so a
        // network (not exact) match on loopback gives way to the first normal one.
        let lp = IFF_LOOPBACK | IFF_POINTOPOINT;
        if bestif.is_none_or(|b| ifa.flags & lp == 0 && ifs[b].flags & lp != 0) {
            bestif = Some(i);
        }
    }
    let best = exactif.or(bestif)?;
    // The address of `best` with the port of serv_uaddr.
    let serv = addr::uaddr2taddr(nconf, serv_uaddr)?;
    let ifsa = ifs[best].addr.as_ref()?;
    let (size, port_off) = match family(ifsa) {
        libc::AF_INET => (size_of::<libc::sockaddr_in>(), 2),
        _ => (size_of::<libc::sockaddr_in6>(), 2),
    };
    let mut ss = ifsa[..size].to_vec();
    ss[port_off..port_off + 2].copy_from_slice(&serv.buf[2..4]);
    addr::taddr2uaddr(nconf, &tirpc::addr::Netbuf { len: size, buf: ss })
}
