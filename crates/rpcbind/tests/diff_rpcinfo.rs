//! Phase 4: rpcinfo. Each case runs three ways (C rpcbind with C rpcinfo, C rpcbind
//! with rpcinfo-rs, rpcbind-rs with rpcinfo-rs) and all three must agree.

mod common;
use common::*;

const PMAP: u32 = 100000;

/// `run @T@/bin/rpcinfo ARGS`.
fn ri(c: Case, args: &str) -> Case {
    c.probe(format!("run @T@/bin/rpcinfo {args}").trim_end().to_string())
}

fn ris(mut c: Case, all: &[&str]) -> Case {
    for a in all {
        c = ri(c, a);
    }
    c
}

/// Registrations over the local socket (owner from the socket: root, "superuser").
fn reg(mut c: Case, regs: &[(u32, u32, &str, &str)]) -> Case {
    for (i, (p, v, n, a)) in regs.iter().enumerate() {
        c = local(c, &format!("g{i}"), &call(7000 + i as u32, PMAP, 4, 1, &rpcb(*p, *v, n, a, "x")));
    }
    c
}

const SERVICES: &[(u32, u32, &str, &str)] = &[
    (100003, 3, "udp", "0.0.0.0.8.1"),
    (100003, 3, "tcp", "0.0.0.0.8.1"),
    (100003, 4, "tcp", "0.0.0.0.8.1"),
    (100003, 3, "udp6", "::.8.1"),
    (100003, 3, "tcp6", "::.8.1"),
    (100005, 1, "udp", "0.0.0.0.78.80"),
    (100005, 3, "tcp", "0.0.0.0.78.81"),
    (100005, 3, "local", "/run/mountd.sock"),
    (100024, 1, "udp", "127.0.0.1.3.233"),
    (300000, 1, "tcp", "127.0.0.1.4.1"),
    (300000, 2147483648, "udp", "127.0.0.1.4.2"),
    (300000, 2147483648, "tcp", "127.0.0.1.4.2"),
];

#[test]
fn dumps() {
    let c = Case::new("ri_dumps", &["-f"]);
    let c = ris(c, &["", "-s", "-p", "-m"]);
    let c = reg(c, SERVICES);
    let c = ris(
        c,
        &[
            "",
            "-s",
            "-p",
            "127.0.0.1",
            "-s 127.0.0.1",
            "-p 127.0.0.1",
            "::1",
            "-s ::1",
            "-p ::1",
            "localhost",
            "-T tcp 127.0.0.1",
            "-T udp 127.0.0.1",
            "-T tcp6 ::1",
            "-T udp6 ::1",
            "-T local 127.0.0.1",
            "-T tcp ::1",
            "-T nosuch 127.0.0.1",
            "-s -T udp 127.0.0.1",
            "nosuchhost.invalid",
            "-p nosuchhost.invalid",
            "-s nosuchhost.invalid",
            "-p 127.0.0.1 extra",
            "a b",
        ],
    );
    check_rpcinfo(c);
}

#[test]
fn addrlists() {
    let c = reg(Case::new("ri_addrlists", &["-f"]), SERVICES);
    let c = ris(
        c,
        &[
            "-l 127.0.0.1 100003 3",
            "-l 127.0.0.1 nfs 3",
            "-l ::1 100003 3",
            "-l -T udp 127.0.0.1 100005 1",
            "-l -T local 127.0.0.1 100005 3",
            "-l -T tcp6 ::1 100005 3",
            "-l -T nosuch 127.0.0.1 100005 3",
            "-l 127.0.0.1 100099 1",
            "-l -- 127.0.0.1 300000 -2147483648",
            "-l 127.0.0.1 100003",
            "-l 127.0.0.1 nosuchservice 1",
            "-l nosuchhost.invalid 100003 3",
        ],
    );
    check_rpcinfo(c);
}

#[test]
fn pings() {
    let c = reg(Case::new("ri_pings", &["-f"]), SERVICES);
    let c = ris(
        c,
        &[
            "-t 127.0.0.1 100000",
            "-u 127.0.0.1 100000",
            "-t 127.0.0.1 100000 3",
            "-u 127.0.0.1 portmapper 2",
            "-u 127.0.0.1 rpcbind 5",
            "-n 111 -t 127.0.0.1 100000 4",
            "-t ::1 100000",
            "-u localhost 100000 2",
            "-t 127.0.0.1 100099",
            "-u 127.0.0.1 100099 1",
            "-u 127.0.0.1 100024 1",
            "-t 127.0.0.1 300000 1",
            "-t 127.0.0.1 100003",
            "-T tcp 127.0.0.1 100000",
            "-T udp 127.0.0.1 100000 3",
            "-T tcp6 ::1 100000 4",
            "-T udp6 ::1 100000",
            "-T local x 100000",
            "-T local x 100000 2",
            "-T udp 127.0.0.1 100099",
            "-T tcp 127.0.0.1 100024 1",
            "-T udp 127.0.0.1 100024 1",
            "-T nosuch 127.0.0.1 100000",
            "-T tcp nosuchhost.invalid 100000",
            "-t nosuchhost.invalid 100000",
            "-t 127.0.0.1 100000 4294967295",
            "-t 127.0.0.1 100000 -1",
            "-u 127.0.0.1 4294967296 2",
            "-t 127.0.0.1",
        ],
    );
    check_rpcinfo(c);
}

#[test]
fn addrpings() {
    let c = Case::new("ri_addrpings", &["-f"]);
    let c = ris(
        c,
        &[
            "-a 127.0.0.1.0.111 -T tcp 100000",
            "-a 127.0.0.1.0.111 -T udp 100000",
            "-a 127.0.0.1.0.111 -T udp 100000 2",
            "-a ::1.0.111 -T tcp6 100000 3",
            "-a ::1.0.111 -T udp6 100000",
            "-a /run/rpcbind.sock -T local 100000",
            "-a /run/rpcbind.sock -T local 100000 4",
            "-a 127.0.0.1.0.111 -T tcp 100099",
            "-a 127.0.0.1.0.112 -T tcp 100000 2",
            "-a 127.0.0.1.0.112 -T udp 100000 2",
            "-a 127.0.0.1.0.112 -T udp 100000",
            "-a 127.0.0.1 -T udp 100000 2",
            "-a 127.0.0.1.0.111 -T nosuch 100000",
            "-a 127.0.0.1.0.111 100000",
            "-a 127.0.0.1.0.111 -T tcp",
        ],
    );
    check_rpcinfo(c);
}

#[test]
fn deletes() {
    let c = reg(Case::new("ri_deletes", &["-f"]), SERVICES);
    let c = ris(
        c,
        &[
            "-d 100003 3",
            "-d -T tcp 100005 3",
            "-d -T nosuch 100005 3",
            "-d 100099 1",
            "-d foo bar",
            "-d 100000 bar",
            "-d nfs 4",
            "-d 300000",
            "-s",
            "-d -- 300000 -2147483648",
            "-s",
        ],
    );
    check_rpcinfo(c);
}

#[test]
fn arguments() {
    let c = Case::new("ri_arguments", &["-f"]);
    let c = ris(
        c,
        &[
            "-z",
            "-p -s",
            "-a",
            "-T",
            "-n 5x -p",
            "-n 5 -p",
            "-n -5 -t 127.0.0.1 100000 2",
            "-u",
            "-b",
            "-b 1",
            "-d",
            "-l",
            "-m extra args",
            "-t 127.0.0.1 -5",
            "-t 127.0.0.1 12a",
            "-t 127.0.0.1 12-",
            "-t 127.0.0.1 ''",
            "-t 127.0.0.1 99999999999999999999 2",
        ],
    );
    check_rpcinfo(c);
}

#[test]
fn stats() {
    let mut c = reg(Case::new("ri_stats", &["-f"]), SERVICES);
    // Lookups that succeed and fail, by portmap and rpcbind, and a CALLIT.
    c = c.probe(format!("udp 127.0.0.1 111 {}", call(1, PMAP, 2, 3, &pmap(100003, 3, 17, 0))));
    c = c.probe(format!("udp 127.0.0.1 111 {}", call(2, PMAP, 2, 3, &pmap(100099, 1, 6, 0))));
    c = c.probe(format!("udp 127.0.0.1 111 {}", call(3, PMAP, 3, 3, &rpcb(100005, 3, "tcp", "", ""))));
    c = c.probe(format!("udp 127.0.0.1 111 {}", call(4, PMAP, 4, 3, &rpcb(0x9000_0000, 1, "udp", "", ""))));
    c = c.probe(format!("udp 127.0.0.1 111 {}", call(5, PMAP, 4, 11, &rpcb(100003, 3, "udp", "", ""))));
    c = c.probe(format!("udp 127.0.0.1 111 {}", call(6, PMAP, 2, 5, &words(&[100003, 3, 0, 0]))));
    let c = ris(c, &["-m", "-m 127.0.0.1", "-m ::1", "-m nosuchhost.invalid"]);
    check_rpcinfo(c);
}

#[test]
fn broadcast_loopback_only() {
    let c = ris(Case::new("ri_broadcast_lo", &["-f"]), &["-b 100000 2", "-b nfs 3", "-b 100000"]);
    check_rpcinfo(c);
}

/// A netkit pair with an IPv4 broadcast address on n0.
fn bcast_if(c: Case) -> Case {
    c.setup("ip link add n0 type netkit peer name n1 || exit 93")
        .setup("ip link set n0 up; ip link set n1 up")
        .setup("ip addr add 10.20.0.1/16 brd + dev n0")
}

#[test]
fn broadcast_replies() {
    // rpcbind on loopback only, so the broadcast address is free for a fake responder
    // answering both kinds of CALLIT; a silent one at 127.0.0.5 for a timeout.
    let c = bcast_if(Case::new("ri_broadcast", &["-f", "-h", "127.0.0.1"]))
        .probe("responder 10.20.255.255 111 10.20.0.9.3.4 5000")
        .probe("responder 127.0.0.5 999 - -");
    let c = ris(c, &["-b 100000 2", "-a 127.0.0.5.3.231 -T udp 100000 2"]);
    check_rpcinfo(c);
}

#[test]
fn broadcast_odd_replies() {
    // An IPv6 address in a reply over IPv4 (libtirpc "fixes" it, with port 0), and no
    // portmap replies.
    let c = bcast_if(Case::new("ri_broadcast_odd", &["-f", "-h", "127.0.0.1"]))
        .probe("responder 10.20.255.255 111 ::1.0.111 -");
    let c = ris(c, &["-b 100000 2"]);
    check_rpcinfo(c);
}

#[test]
fn broadcast_unanswered() {
    let c = ris(bcast_if(Case::new("ri_broadcast_none", &["-f"])), &["-b 100099 1"]);
    check_rpcinfo(c);
}

#[test]
fn no_local_socket() {
    // Without the local socket, rpcinfo's own lookups fail, and libtirpc's
    // rpcb_unset() falls back to the last loopback stream transport (tcp6, ::1).
    let c = reg(Case::new("ri_no_socket", &["-f"]), SERVICES).probe("run rm /run/rpcbind.sock");
    let c = ris(c, &["", "-s", "-p", "-m", "-d 100003 3", "-d -T udp 100005 1", "-s 127.0.0.1", "-T local x 100000"]);
    check_rpcinfo(c);
}

const NETCONFIG: &str = "udp        tpi_clts      v     inet     udp     -       -
tcp        tpi_cots_ord  v     inet     tcp     -       -
mytcp      tpi_cots_ord  v     inet     tcp     -       -
myudp      tpi_clts      -     inet     udp     -       -
local      tpi_cots_ord  -     loopback  -      -       -
";

#[test]
fn custom_netconfig() {
    // Netids libtirpc has no socket type for (nconf2fd() gives descriptor 0), no IPv6,
    // and the loopback fallback over tcp.
    let c = reg(Case::new("ri_netconfig", &["-f"]).netconfig(NETCONFIG), &SERVICES[..3]);
    let c = ris(
        c,
        &[
            "",
            "127.0.0.1",
            "-T mytcp 127.0.0.1",
            "-T mytcp 127.0.0.1 100000",
            "-T myudp 127.0.0.1 100000 2",
            "-a 127.0.0.1.0.111 -T mytcp 100000",
            "-a 127.0.0.1.0.111 -T myudp 100000 2",
            "-l -T mytcp 127.0.0.1 100000 4",
            "-t 127.0.0.1 100000",
            "-T tcp6 ::1 100000",
            "-b 100000 2",
        ],
    )
    .probe("run rm /run/rpcbind.sock");
    let c = ris(c, &["-d 100003 3", "-s 127.0.0.1"]);
    check_rpcinfo(c);
}

#[test]
fn environment() {
    let e = "run env";
    let r = "@T@/bin/rpcinfo";
    let mut c = reg(Case::new("ri_environment", &["-f"]), SERVICES);
    for l in [
        format!("{e} NETPATH=udp:tcp {r} 127.0.0.1"),
        format!("{e} NETPATH=udp {r} -s 127.0.0.1"),
        format!("{e} NETPATH= {r} -m 127.0.0.1"),
        format!("{e} NETPATH=nosuch:tcp6 {r} -l ::1 100003 3"),
        format!("{e} NETPATH=a\\:b:tcp {r} 127.0.0.1"),
        format!("{e} NETPATH=udp6 {r} -s 127.0.0.1"),
        format!("{e} RPCB_V2FIRST=1 {r} -T udp 127.0.0.1 100000 2"),
        format!("{e} RPCB_V2FIRST=1 {r} -T tcp 127.0.0.1 100003 3"),
        format!("{e} RPCB_V2FIRST=1 {r} -T tcp6 ::1 100000"),
        format!("{e} RPCB_V2FIRST=1 {r} -T udp 127.0.0.1 100099"),
        format!("{e} RPCB_V2FIRST=1 {r} -u 127.0.0.1 100024 1"),
        format!("{e} RPCB_V2FIRST=1 {r} -t 127.0.0.1 300000"),
    ] {
        c = c.probe(l);
    }
    check_rpcinfo(c);
}

#[test]
fn long_names() {
    // clnt_pcreateerror() cuts its message at 255 bytes.
    let long = format!("{}.example.invalid", vec!["a".repeat(60); 4].join("."));
    let known = format!("{}.test", vec!["b".repeat(60); 4].join("."));
    let c = Case::new("ri_long_names", &["-f"])
        .file("hosts", format!("127.0.0.1 localhost {known}\n::1 localhost\n").as_bytes())
        .setup("mount --bind $R/hosts /etc/hosts");
    let c = reg(c, &[SERVICES[1], SERVICES[8]]);
    let c = ris(
        c,
        &[
            // A host name of 248 bytes leaves room for only part of the message, and
            // libtirpc appends past its buffer before cutting it.
            &format!("-t {known} 100003 3"),
            &format!("-p {long}"),
            &format!("-t {long} 100000"),
            &format!("-s {long}"),
            &format!("-T tcp {long} 100000"),
            &format!("-l {long} 100000 2"),
            &format!("-p {known}"),
            &format!("-t {known} 100024 1"),
            &format!("-u {known} 100024 1"),
            &format!("-T udp {known} 100024 1"),
            &format!("-s {known}"),
        ],
    );
    check_rpcinfo(c);
}

/// A reply message: `XID`, REPLY, then the words given.
fn reply(ws: &[u32]) -> String {
    format!("XID{}", words(&[1]) + &words(ws))
}

#[test]
fn odd_servers() {
    // Fake servers answering every call with scripted replies.
    let ok = reply(&[0, 0, 0, 0]);
    let servers: &[(&str, u16, Vec<String>)] = &[
        // a call (not a reply) first, then the answer: skipped on a stream
        ("tcp", 701, vec![format!("XID{}", words(&[0, 2, 1, 1])), ok.clone()]),
        // another call's xid first: skipped
        ("tcp", 702, vec![format!("00000bad{}", words(&[1, 0, 0, 0, 0])), ok.clone()]),
        // denied: authentication, known and unknown reasons; RPC version mismatch
        ("tcp", 703, vec![reply(&[1, 1, 5])]),
        ("udp", 704, vec![reply(&[1, 1, 99])]),
        ("tcp", 705, vec![reply(&[1, 0, 2, 2])]),
        // accepted with an unknown status, and the known failures
        ("tcp", 706, vec![reply(&[0, 0, 0, 9])]),
        ("udp", 707, vec![reply(&[0, 0, 0, 4])]),
        ("udp", 708, vec![reply(&[0, 0, 0, 5])]),
        ("tcp", 709, vec![reply(&[0, 0, 0, 3])]),
        // a version range: every version gets the mismatch
        ("tcp", 710, vec![reply(&[0, 0, 0, 2, 7, 9])]),
        // garbage over UDP; a short datagram; a stale xid (both end the 10 s at once)
        ("udp", 711, vec![format!("XID{}", words(&[7]))]),
        ("udp", 712, vec!["0102".into()]),
        ("udp", 713, vec![format!("00000bad{}", words(&[1, 0, 0, 0, 0]))]),
        // a zero record mark fails the decode, and skipping the rest of that "record"
        // swallows the good reply after it: a timeout
        ("tcp", 714, vec!["raw:00000000".into(), ok.clone()]),
        // a verifier over 400 bytes is undecodable and skipped
        ("tcp", 715, vec![format!("XID{}{}", words(&[1, 0, 0, 401]), "00".repeat(404) + &words(&[0])), ok.clone()]),
    ];
    let mut c = Case::new("ri_odd_servers", &["-f"]);
    for (p, port, rs) in servers {
        c = c.probe(format!("fakesrv {p} 127.0.0.7 {port} {}", rs.join(" ")));
    }
    for (p, port, _) in servers {
        let ua = format!("127.0.0.7.{}.{}", port >> 8, port & 0xff);
        c = ri(c, &format!("-a {ua} -T {p} 100000 2"));
    }
    let c = ris(c, &["-a 127.0.0.7.2.198 -T tcp 100000"]);
    check_rpcinfo(c);
}
