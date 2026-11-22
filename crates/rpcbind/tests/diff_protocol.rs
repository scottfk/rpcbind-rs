//! Phase 2: the portmap v2 and rpcbind v3/v4 procedures.

mod common;
use common::*;

const PMAP: u32 = 100000;
const AUTH_SYS: u32 = 1;

/// `struct rpcb` arguments.
fn rpcb(prog: u32, vers: u32, netid: &str, addr: &str, owner: &str) -> String {
    format!(
        "{}{}{}{}",
        words(&[prog, vers]),
        opaque(netid.as_bytes()),
        opaque(addr.as_bytes()),
        opaque(owner.as_bytes())
    )
}

/// `struct pmap` arguments.
fn pmap(prog: u32, vers: u32, prot: u32, port: u32) -> String {
    words(&[prog, vers, prot, port])
}

/// A probe command sending `msg` on a fresh connection to the local socket, then
/// reading the reply.
fn local(c: Case, name: &str, msg: &str) -> Case {
    c.probe(format!("conn {name} unix /run/rpcbind.sock"))
        .probe(format!("send {name} {}", record(msg)))
        .probe(format!("recv {name}"))
        .probe(format!("close {name}"))
}

fn tcp(c: Case, name: &str, host: &str, msg: &str) -> Case {
    c.probe(format!("conn {name} tcp {host} 111"))
        .probe(format!("send {name} {}", record(msg)))
        .probe(format!("recv {name}"))
        .probe(format!("close {name}"))
}

/// A send over UDP, TCP (v4 and v6) and the local socket.
fn everywhere(mut c: Case, xid: u32, prog: u32, vers: u32, proc_: u32, args: &str) -> Case {
    let m = |x| call(x, prog, vers, proc_, args);
    c = c.probe(format!("udp 127.0.0.1 111 {}", m(xid)));
    c = c.probe(format!("udp ::1 111 {}", m(xid + 1)));
    c = tcp(c, &format!("t{xid}"), "127.0.0.1", &m(xid + 2));
    c = tcp(c, &format!("s{xid}"), "::1", &m(xid + 3));
    local(c, &format!("l{xid}"), &m(xid + 4))
}

/// Non-loopback interfaces: a netkit pair, with IPv4 and IPv6 addresses on both ends.
fn interfaces(c: Case) -> Case {
    c.setup("ip link add n0 type netkit peer name n1 || exit 93")
        .setup("ip link set n0 up; ip link set n1 up")
        .setup("ip addr add 192.168.50.1/24 dev n0; ip addr add 192.168.60.1/24 dev n1")
        .setup("ip addr add fd00:50::1/64 dev n0 nodad; ip addr add fd00:60::1/64 dev n1 nodad")
        .setup("ip addr add 10.9.0.1/16 dev lo")
}

/// Registrations made as root over the local socket.
fn registered(mut c: Case) -> Case {
    let regs = [
        (100003, 3, "udp", "0.0.0.0.8.1"),
        (100003, 3, "tcp", "0.0.0.0.8.1"),
        (100003, 4, "tcp", "0.0.0.0.8.1"),
        (100003, 3, "udp6", "::.8.1"),
        (100003, 3, "tcp6", "::.8.1"),
        (100005, 1, "udp", "0.0.0.0.78.80"),
        (100005, 3, "udp", "0.0.0.0.78.80"),
        (100005, 3, "tcp", "0.0.0.0.78.81"),
        (100005, 3, "local", "/run/mountd.sock"),
        (100024, 1, "udp", "127.0.0.1.3.233"),
        (200000, 1, "tcp", "192.168.50.1.4.1"),
    ];
    for (i, (p, v, n, a)) in regs.iter().enumerate() {
        c = local(c, &format!("r{i}"), &call(1000 + i as u32, PMAP, 4, 1, &rpcb(*p, *v, n, a, "ignored")));
    }
    c
}

// ---------------------------------------------------------------------------
// listing

#[test]
fn dump_initial() {
    let mut c = Case::new("dump_initial", &["-f"]);
    for (vers, proc_) in [(2, 4), (3, 4), (4, 4)] {
        c = everywhere(c, vers * 100, PMAP, vers, proc_, "");
    }
    check(c);
}

#[test]
fn dump_after_registrations() {
    let mut c = registered(Case::new("dump_after_registrations", &["-f"]));
    for (vers, proc_) in [(2, 4), (3, 4), (4, 4)] {
        c = everywhere(c, vers * 100, PMAP, vers, proc_, "");
    }
    check(c);
}

// ---------------------------------------------------------------------------
// SET and UNSET

#[test]
fn set_unset_sequences() {
    let mut c = Case::new("set_unset_sequences", &["-f"]);
    let steps = [
        (3, 1, rpcb(300000, 1, "udp", "0.0.0.0.10.1", "")),
        (3, 1, rpcb(300000, 1, "udp", "0.0.0.0.10.1", "")), // same again: TRUE
        (3, 1, rpcb(300000, 1, "udp", "0.0.0.0.10.2", "")), // different address: FALSE
        (4, 1, rpcb(300000, 2, "UDP", "0.0.0.0.10.3", "")), // netids match without case
        (4, 1, rpcb(300000, 1, "UDP", "0.0.0.0.10.9", "")), // so this clashes with "udp": FALSE
        (4, 1, rpcb(300002, 1, "Udp", "0.0.0.0.10.7", "")),
        (4, 3, rpcb(300002, 1, "", "", "")), // found on transport "udp"
        (3, 2, rpcb(300002, 1, "UDP", "", "")),
        (4, 1, rpcb(300000, 1, "tcp", "0.0.0.0.10.4", "")),
        (4, 1, rpcb(300000, 1, "sctp", "0.0.0.0.10.5", "")), // a netid rpcbind doesn't serve
        (4, 1, rpcb(300000, 1, "", "0.0.0.0.10.6", "")),
        (4, 1, rpcb(300001, 1, "udp", "garbage", "")), // not a universal address
        (4, 1, rpcb(300001, 1, "tcp", "0.0.0.0.999.999", "")),
        (3, 4, String::new()),
        (2, 4, String::new()),
        (3, 2, rpcb(300000, 1, "udp", "", "")),
        (4, 2, rpcb(300000, 2, "", "", "")),    // "" unsets every netid
        (4, 2, rpcb(399999, 1, "udp", "", "")), // nothing there: still TRUE
        (4, 4, String::new()),
        (2, 4, String::new()),
    ];
    for (i, (v, p, a)) in steps.iter().enumerate() {
        c = local(c, &format!("x{i}"), &call(i as u32 + 1, PMAP, *v, *p, a));
    }
    check(c);
}

#[test]
fn set_access() {
    // SET and UNSET are refused unless from loopback (or local), without -i.
    for (name, args) in
        [("set_access", &["-f"][..]), ("set_access_insecure", &["-f", "-i"]), ("set_access_logged", &["-f", "-l"])]
    {
        let mut c = interfaces(Case::new(name, args));
        let set = |x| call(x, PMAP, 4, 1, &rpcb(310000, 1, "udp", "0.0.0.0.10.1", ""));
        let unset = |x| call(x, PMAP, 3, 2, &rpcb(310000, 1, "udp", "", ""));
        c = c
            .probe(format!("udpfrom 192.168.50.1 192.168.50.1 111 {}", set(1)))
            .probe(format!("udpfrom fd00:50::1 fd00:50::1 111 {}", set(2)))
            .probe(format!("udpfrom 10.9.0.1 127.0.0.1 111 {}", set(3)))
            .probe(format!("udp 127.0.0.1 111 {}", set(4)))
            .probe(format!("udp ::1 111 {}", call(5, PMAP, 4, 1, &rpcb(310001, 1, "udp6", "::.10.1", ""))))
            .probe(format!("udpfrom 192.168.50.1 192.168.50.1 111 {}", unset(6)))
            .probe(format!("udpfrom 192.168.50.1 192.168.50.1 111 {}", call(7, PMAP, 2, 1, &pmap(310002, 1, 17, 999))))
            .probe(format!("udpfrom 192.168.50.1 192.168.50.1 111 {}", call(8, PMAP, 2, 3, &pmap(310000, 1, 17, 0))))
            .probe(format!(
                "udpfrom 192.168.50.1 192.168.50.1 111 {}",
                call(9, PMAP, 4, 3, &rpcb(310000, 1, "udp", "", ""))
            ));
        c = local(c, "d", &call(20, PMAP, 4, 4, ""));
        check(c);
    }
}

#[test]
fn owners() {
    // Over the local socket the owner is the caller's uid ("superuser" for root);
    // elsewhere "superuser" from a reserved loopback port, else "unknown".
    let mut c = Case::new("owners", &["-f"]);
    let sock = "/run/rpcbind.sock";
    let set = |x, prog, netid: &str| record(&call(x, PMAP, 4, 1, &rpcb(prog, 1, netid, "0.0.0.0.10.1", "x")));
    let unset = |x, prog, netid: &str| record(&call(x, PMAP, 4, 2, &rpcb(prog, 1, netid, "", "")));
    c = c
        .probe(format!("ucall 1000 unix {sock} {}", set(1, 320000, "udp")))
        .probe(format!("ucall 1000 unix {sock} {}", set(2, 320000, "tcp")))
        .probe(format!("ucall 1001 unix {sock} {}", set(3, 320000, "udp6")))
        .probe(format!("ucall 1001 unix {sock} {}", unset(4, 320000, "udp"))) // not the owner
        .probe(format!("ucall 1000 unix {sock} {}", unset(5, 320000, ""))) // stops at the 1001 entry
        .probe(format!("ucall 1000 unix {sock} {}", set(6, 320001, "udp")))
        .probe(format!("ucall 1000 unix {sock} {}", unset(7, 320001, "udp")))
        .probe(format!("udp 127.0.0.1 111 {}", call(8, PMAP, 4, 1, &rpcb(320002, 1, "udp", "0.0.0.0.10.1", ""))))
        .probe(format!("udp 127.0.0.1 111 {}", call(12, PMAP, 4, 1, &rpcb(320004, 1, "udp", "0.0.0.0.10.2", ""))))
        // Owned by "unknown": a TCP caller on a non-reserved port is "unknown" too.
        .probe("conn tu tcp 127.0.0.1 111")
        .probe(format!("send tu {}", record(&call(13, PMAP, 4, 2, &rpcb(320004, 1, "udp", "", "")))))
        .probe("recv tu")
        .probe("close tu")
        .probe(format!("ucall 1000 unix {sock} {}", unset(14, 320002, "udp")))
        .probe(format!("ucall 1000 unix {sock} {}", record(&call(9, PMAP, 2, 1, &pmap(320003, 1, 6, 2049)))))
        .probe(format!("ucall 1001 unix {sock} {}", record(&call(10, PMAP, 2, 2, &pmap(320003, 1, 0, 0)))))
        .probe(format!("ucall 1000 unix {sock} {}", record(&call(11, PMAP, 2, 2, &pmap(320003, 1, 0, 0)))));
    c = local(c, "d3", &call(20, PMAP, 3, 4, ""));
    c = local(c, "d2", &call(21, PMAP, 2, 4, ""));
    check(c);
}

// ---------------------------------------------------------------------------
// portmap v2

#[test]
fn portmap() {
    let mut c = Case::new("portmap", &["-f"]);
    let steps: Vec<(u32, String)> = vec![
        (1, pmap(330000, 1, 17, 2049)),
        (1, pmap(330000, 1, 6, 2049)),
        (1, pmap(330000, 2, 6, 65535)),
        (1, pmap(330000, 3, 6, 0x12345)), // port above 16 bits
        (1, pmap(330001, 1, 99, 1)),      // not TCP or UDP: FALSE
        (1, pmap(330001, 1, 0, 1)),
        (3, pmap(330000, 1, 17, 0)),
        (3, pmap(330000, 2, 17, 0)), // only TCP has v2
        (3, pmap(330000, 9, 6, 0)),  // another version's port
        (3, pmap(330000, 3, 6, 0)),
        (3, pmap(100000, 2, 17, 0)), // portmap itself
        (3, pmap(100000, 4, 6, 0)),
        (3, pmap(339999, 1, 17, 0)),
        (3, pmap(330000, 1, 99, 0)),
        (4, String::new()),
        (2, pmap(330000, 1, 0, 0)), // both protocols
        (2, pmap(330000, 2, 17, 0)),
        (4, String::new()),
        (3, words(&[330000, 1])), // short arguments
        (1, words(&[330000])),
    ];
    for (i, (p, a)) in steps.iter().enumerate() {
        c = c.probe(format!("udp 127.0.0.1 111 {}", call(i as u32 + 1, PMAP, 2, *p, a)));
    }
    c = local(c, "d", &call(50, PMAP, 3, 4, ""));
    check(c);
}

#[test]
fn portmap_without_ipv4() {
    // No udp/tcp transports: udptrans and tcptrans are "".
    let nc = "udp6 tpi_clts v inet6 udp - -\ntcp6 tpi_cots_ord v inet6 tcp - -\nlocal tpi_cots_ord - loopback - - -\n";
    let mut c = Case::new("portmap_without_ipv4", &["-f"]).netconfig(nc);
    c = local(c, "a", &call(1, PMAP, 4, 1, &rpcb(340000, 1, "udp6", "::.8.1", "")));
    c = local(c, "b", &call(2, PMAP, 2, 1, &pmap(340001, 1, 17, 2049)));
    c = local(c, "c", &call(3, PMAP, 2, 3, &pmap(340001, 1, 17, 0)));
    c = local(c, "d", &call(4, PMAP, 4, 4, ""));
    c = local(c, "e", &call(5, PMAP, 2, 2, &pmap(340000, 1, 0, 0))); // "" unsets every netid
    c = local(c, "f", &call(6, PMAP, 4, 4, ""));
    c = local(c, "g", &call(7, PMAP, 2, 4, ""));
    check(c);
}

// ---------------------------------------------------------------------------
// GETADDR, GETVERSADDR, GETADDRLIST and addrmerge()

#[test]
fn getaddr_merging() {
    let mut c = registered(interfaces(Case::new("getaddr_merging", &["-f"])));
    let queries = [
        (100003, 3, ""),
        (100003, 9, ""), // another version: ALLVERS answers anyway
        (100005, 3, ""),
        (100024, 1, ""), // registered with a specific address
        (200000, 1, ""),
        (100003, 3, "192.168.60.1.0.0"), // a hint
        (100003, 3, "fd00:60::1.0.0"),   // a hint of the other family
        (100003, 3, "10.9.0.1.0.0"),
        (100003, 3, "bogus"),
        (399999, 1, ""),
    ];
    let mut x = 1;
    for (prog, vers, hint) in queries {
        for v in [3, 4] {
            for proc_ in if v == 4 { &[3u32, 9, 11][..] } else { &[3u32][..] } {
                let m = call(x, PMAP, v, *proc_, &rpcb(prog, vers, "", hint, ""));
                for (src, dst) in [
                    ("127.0.0.1", "127.0.0.1"),
                    ("127.0.0.5", "127.0.0.5"),
                    ("10.9.0.1", "10.9.0.1"),
                    ("192.168.50.1", "192.168.50.1"),
                    ("192.168.60.1", "192.168.50.1"),
                    ("::1", "::1"),
                    ("fd00:50::1", "fd00:50::1"),
                    ("fd00:60::1", "fd00:50::1"),
                ] {
                    c = c.probe(format!("udpfrom {src} {dst} 111 {m}"));
                }
                c = tcp(c, &format!("t{x}"), "192.168.50.1", &m);
                c = local(c, &format!("l{x}"), &m);
                x += 1;
            }
        }
    }
    // The statistics these lookups left.
    c = local(c, "stat", &call(999, PMAP, 4, 12, ""));
    check(c);
}

#[test]
fn getaddrlist_unknown_netid() {
    // One registration on a netid rpcbind doesn't serve makes GETADDRLIST send nothing.
    let mut c = Case::new("getaddrlist_unknown_netid", &["-f"]);
    c = local(c, "a", &call(1, PMAP, 4, 1, &rpcb(350000, 1, "udp", "0.0.0.0.8.1", "")));
    c = local(c, "b", &call(2, PMAP, 4, 11, &rpcb(350000, 1, "", "", "")));
    c = local(c, "c", &call(3, PMAP, 4, 1, &rpcb(350000, 1, "sctp", "0.0.0.0.8.2", "")));
    c = local(c, "d", &call(4, PMAP, 4, 11, &rpcb(350000, 1, "", "", "")));
    c = c.probe(format!("udp 127.0.0.1 111 {}", call(5, PMAP, 4, 11, &rpcb(350000, 1, "", "", ""))));
    c = local(c, "e", &call(6, PMAP, 4, 3, &rpcb(350000, 1, "", "", "")));
    check(c);
}

// ---------------------------------------------------------------------------
// address conversion and time

#[test]
fn address_conversion() {
    let mut c = Case::new("address_conversion", &["-f"]);
    let uaddrs =
        ["127.0.0.1.0.111", "::1.8.1", "/run/rpcbind.sock", "@abstract", "1.2.3.4.999.999", "nodots", "", "1.2.3.4"];
    let mut x = 1;
    for v in [3, 4] {
        for u in uaddrs {
            c = everywhere(c, x, PMAP, v, 7, &opaque(u.as_bytes()));
            x += 5;
        }
        let sin = |port: u16, a: [u8; 4]| {
            let mut b = vec![2u8, 0];
            b.extend_from_slice(&port.to_be_bytes());
            b.extend_from_slice(&a);
            b.extend_from_slice(&[0; 8]);
            b
        };
        let mut sin6 = vec![10u8, 0, 0, 111, 0, 0, 0, 0];
        sin6.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        sin6.extend_from_slice(&[0; 4]);
        let mut sun = vec![1u8, 0];
        sun.extend_from_slice(b"/run/x.sock");
        let netbufs: Vec<(u32, Vec<u8>)> = vec![
            (16, sin(111, [127, 0, 0, 1])),
            (16, sin(2049, [10, 1, 2, 3])),
            (28, sin6.clone()),
            (128, sun.clone()),
            (15, sin(111, [127, 0, 0, 1])[..15].to_vec()), // too short for a sockaddr_in
            (8, sin(111, [127, 0, 0, 1])),                 // longer than maxlen
            (9001, sin(111, [127, 0, 0, 1])),              // maxlen too large
            (0, Vec::new()),
        ];
        for (maxlen, b) in netbufs {
            c = everywhere(c, x, PMAP, v, 8, &(words(&[maxlen]) + &opaque(&b)));
            x += 5;
        }
    }
    check(c);
}

#[test]
fn gettime() {
    let mut c = Case::new("gettime", &["-f"]).faketime(1_763_000_000);
    c = everywhere(c, 1, PMAP, 3, 6, "");
    c = everywhere(c, 10, PMAP, 4, 6, "");
    c = c.probe("run @T@/bin/tirpcprobe gettime 127.0.0.1");
    check(c);
}

// ---------------------------------------------------------------------------
// CALLIT, INDIRECT, BCAST (no forwarding in this build)

#[test]
fn remote_calls() {
    for (name, args) in [
        ("remote_calls", &["-f"][..]),
        ("remote_calls_debug", &["-f", "-d", "-l"]),
        ("remote_calls_insecure", &["-f", "-i"]),
    ] {
        let mut c = registered(Case::new(name, args)).probe("timeout 150");
        let targets = [
            (100003, 3, 0), // NULLPROC: always allowed
            (100003, 3, 1), // NFS: refused
            (100005, 3, 1), // MNT: refused
            (100005, 3, 2), // DUMP: allowed
            (100005, 9, 2), // version mismatch
            (100024, 1, 1), // allowed
            (100004, 1, 3), // YPPROC_MATCH: refused
            (100007, 2, 2), // YPBINDPROC_SETDOM: refused
            (100000, 2, 3), // ourselves: refused unless -i
            (399999, 1, 1), // not registered
        ];
        let mut x = 1;
        for (prog, vers, proc_) in targets {
            let args = words(&[prog, vers, proc_]) + &opaque(b"some-args");
            for (v, p) in [(2, 5), (3, 5), (4, 5), (4, 10)] {
                let m = call(x, PMAP, v, p, &args);
                c = c.probe(format!("udp 127.0.0.1 111 {m}"));
                c = c.probe(format!("udp ::1 111 {}", call(x + 1, PMAP, v, p, &args)));
                c = tcp(c, &format!("t{x}"), "127.0.0.1", &m);
                x += 2;
            }
        }
        // Malformed and huge argument lengths.
        for (i, a) in [words(&[100003, 3]), words(&[100003, 3, 0, 0xffff_fff0]), words(&[100003, 3, 0, 20]) + "abcd"]
            .iter()
            .enumerate()
        {
            c = c.probe(format!("udp 127.0.0.1 111 {}", call(500 + i as u32, PMAP, 4, 10, a)));
            c = c.probe(format!("udp 127.0.0.1 111 {}", call(600 + i as u32, PMAP, 2, 5, a)));
        }
        // AUTH_SYS and other flavors.
        let cred = auth_sys(1, b"client", 1000, 100, &[100]);
        let args = words(&[100005, 3, 2]) + &opaque(b"");
        c = c.probe(format!("udp 127.0.0.1 111 {}{args}", call_auth(700, PMAP, 4, 10, (AUTH_SYS, &cred), (0, b""))));
        c = local(c, "stat", &call(999, PMAP, 4, 12, ""));
        check(c);
    }
}

// ---------------------------------------------------------------------------
// big replies and malformed arguments

#[test]
fn big_dump() {
    // More registrations than a 9000-byte UDP reply holds: UDP gets SYSTEM_ERR, TCP and
    // the local socket get several fragments.
    let mut c = Case::new("big_dump", &["-f"]).probe("conn big unix /run/rpcbind.sock");
    let mut all = String::new();
    for i in 0..300u32 {
        all.push_str(&record(&call(
            i + 1,
            PMAP,
            4,
            1,
            &rpcb(400000 + i, 1, "tcp", &format!("0.0.0.0.{}.{}", i / 256, i % 256), ""),
        )));
    }
    c = c.probe(format!("send big {all}"));
    for _ in 0..300 {
        c = c.probe("recv big");
    }
    c = c.probe("close big");
    for (v, p) in [(2, 4), (3, 4), (4, 4)] {
        c = everywhere(c, 1000 + v * 10, PMAP, v, p, "");
    }
    c = local(c, "stat", &call(2000, PMAP, 4, 12, ""));
    check(c);
}

#[test]
fn malformed_arguments() {
    let mut c = Case::new("malformed_arguments", &["-f", "-d"]);
    let long = "x".repeat(9001);
    let args = [
        (4, 1, words(&[1, 2])),                                            // truncated rpcb
        (4, 1, words(&[1, 2]) + &opaque(long.as_bytes())),                 // string over 9000 bytes
        (4, 1, rpcb(410000, 1, "udp\0junk", "0.0.0.0.8.1\0more", "o\0p")), // NULs inside strings
        (3, 3, words(&[410000, 1]) + &words(&[0xffff_ffff])),
        (4, 7, words(&[9001])),
        (4, 7, opaque(&[b'1'; 100]) + "deadbeef"), // trailing bytes are ignored
        (4, 8, words(&[16, 17])),
        (4, 9, String::new()),
        (4, 11, words(&[1])),
        (2, 1, String::new()),
        (2, 4, "ffffffff".into()), // DUMP ignores arguments
    ];
    for (i, (v, p, a)) in args.iter().enumerate() {
        c = c.probe(format!("udp 127.0.0.1 111 {}", call(i as u32 + 1, PMAP, *v, *p, a)));
        c = local(c, &format!("l{i}"), &call(i as u32 + 100, PMAP, *v, *p, a));
    }
    c = local(c, "d", &call(500, PMAP, 4, 4, ""));
    c = local(c, "stat", &call(501, PMAP, 4, 12, ""));
    check(c);
}

// ---------------------------------------------------------------------------
// real clients: libtirpc and rpcinfo

#[test]
fn libtirpc_clients() {
    let p = "run @T@/bin/tirpcprobe";
    let c = Case::new("libtirpc_clients", &["-f"])
        .probe(format!("{p} set 100099 1 udp 0.0.0.0.3.9"))
        .probe(format!("{p} set 100099 1 tcp 0.0.0.0.3.9"))
        .probe(format!("{p} set 100099 1 udp6 ::.3.9"))
        .probe(format!("{p} set 100099 1 local /run/svc.sock"))
        .probe(format!("{p} -u 1000 set 100098 1 udp 0.0.0.0.3.10"))
        .probe(format!("{p} -u 1000 set 100098 2 tcp 0.0.0.0.3.10"))
        .probe(format!("{p} pmapset 100097 1 17 1234"))
        .probe(format!("{p} -u 1000 pmapset 100097 2 6 1235"))
        .probe(format!("{p} getaddr 100099 1 udp 127.0.0.1"))
        .probe(format!("{p} getaddr 100099 1 tcp6 ::1"))
        .probe(format!("{p} getaddr 100099 1 local localhost"))
        .probe(format!("{p} getaddr 100096 1 udp 127.0.0.1"))
        .probe(format!("{p} getport 127.0.0.1 100097 1 17"))
        .probe(format!("{p} getport 127.0.0.1 100099 1 6"))
        .probe("run @T@/bin/rpcinfo -p 127.0.0.1")
        .probe("run @T@/bin/rpcinfo -s")
        .probe("run @T@/bin/rpcinfo -l 127.0.0.1 100099 1")
        .probe("run @T@/bin/rpcinfo -m")
        .probe(format!("{p} -u 1001 unset 100098 1"))
        .probe(format!("{p} -u 1000 unset 100098 1"))
        .probe(format!("{p} -u 1000 unset 100099 1"))
        .probe(format!("{p} unset 100099 1 udp"))
        .probe(format!("{p} -u 1000 pmapunset 100097 2"))
        .probe(format!("{p} pmapunset 100097 1"))
        .probe("run @T@/bin/rpcinfo")
        .probe("run @T@/bin/rpcinfo -T udp 127.0.0.1 100000 2")
        .probe("run @T@/bin/rpcinfo -T tcp6 ::1 100000")
        .probe("run @T@/bin/rpcinfo -t 127.0.0.1 100000")
        .probe("run @T@/bin/rpcinfo -u 127.0.0.1 100024")
        .probe("run @T@/bin/rpcinfo -d 100098 2")
        .probe("run @T@/bin/rpcinfo -s")
        .probe("run @T@/bin/rpcinfo -m");
    check(c);
}
