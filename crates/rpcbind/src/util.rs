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
