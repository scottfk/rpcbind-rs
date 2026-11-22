//! Phase 1: startup, options, transports from netconfig, signals, and the RPC layer
//! (NULL calls, rejections, authentication, framing). Procedures other than NULL are
//! phase 2, so every call here is a NULL call or one rejected before dispatch.

mod common;
use common::*;

const PMAP: u32 = 100000;
const AUTH_SYS: u32 = 1;

fn null(xid: u32, vers: u32) -> String {
    call(xid, PMAP, vers, 0, "")
}

/// NULL calls for each version over every transport rpcbind serves by default.
fn all_transports(mut c: Case) -> Case {
    let mut xid = 100;
    for vers in [2, 3, 4] {
        for host in ["127.0.0.1", "::1"] {
            xid += 1;
            c = c.probe(format!("udp {host} 111 {}", null(xid, vers)));
            let name = format!("c{xid}");
            xid += 1;
            c = c
                .probe(format!("conn {name} tcp {host} 111"))
                .probe(format!("send {name} {}", record(&null(xid, vers))))
                .probe(format!("recv {name}"))
                .probe(format!("close {name}"));
        }
        xid += 1;
        let name = format!("l{xid}");
        c = c
            .probe(format!("conn {name} unix /run/rpcbind.sock"))
            .probe(format!("send {name} {}", record(&null(xid, vers))))
            .probe(format!("recv {name}"))
            .probe(format!("close {name}"));
    }
    c
}

// ---------------------------------------------------------------------------
// options

#[test]
fn version() {
    check(Case::new("version", &["-v"]));
}

#[test]
fn version_after_other_options() {
    check(Case::new("version_after_other_options", &["-d", "-l", "-v", "-x"]));
}

#[test]
fn bad_options() {
    for (name, args) in [
        ("bad_option", &["-x"][..]),
        ("bad_option_w", &["-w"]),
        ("missing_h_argument", &["-h"]),
        ("long_option", &["--help"]),
        ("bad_option_after_f", &["-f", "-q"]),
    ] {
        check(Case::new(name, args));
    }
}

#[test]
fn abort_without_debug() {
    check(Case::new("abort_without_debug", &["-a", "-f"]).probe(format!("udp 127.0.0.1 111 {}", null(1, 2))));
}

#[test]
fn foreground_all_transports() {
    check(all_transports(Case::new("foreground_all_transports", &["-f"])));
}

#[test]
fn daemon_mode() {
    check(all_transports(Case::new("daemon_mode", &[])));
}

#[test]
fn debug_foreground() {
    check(all_transports(Case::new("debug_foreground", &["-d", "-d", "-a", "-f"])));
}

#[test]
fn insecure_and_verbose() {
    check(all_transports(Case::new("insecure_and_verbose", &["-i", "-l", "-f"])));
}

#[test]
fn verbose_log_daemon() {
    check(all_transports(Case::new("verbose_log_daemon", &["-l"])));
}

#[test]
fn run_as_daemon_user() {
    check(all_transports(Case::new("run_as_daemon_user", &["-s", "-f"])));
}

#[test]
fn trailing_arguments() {
    check(Case::new("trailing_arguments", &["-f", "extra", "args"]).probe(format!("udp 127.0.0.1 111 {}", null(1, 3))));
}

// ---------------------------------------------------------------------------
// -h: addresses for UDP

#[test]
fn hosts_v4() {
    check(all_transports(Case::new("hosts_v4", &["-f", "-h", "127.0.0.1"])));
}

#[test]
fn hosts_v6() {
    check(all_transports(Case::new("hosts_v6", &["-f", "-h", "::1"])));
}

#[test]
fn hosts_both_and_extra_address() {
    check(
        all_transports(
            Case::new("hosts_both_and_extra_address", &["-f", "-h", "127.0.0.7", "-h", "::1", "-h", "127.0.0.1"])
                .setup("ip addr add 127.0.0.7/8 dev lo 2>/dev/null; true"),
        )
        .probe(format!("udp 127.0.0.7 111 {}", null(1, 2))),
    );
}

#[test]
fn hosts_name() {
    check(all_transports(Case::new("hosts_name", &["-f", "-h", "localhost"])));
}

#[test]
fn hosts_unbindable() {
    // Not an address of this host: the bind fails (and the umask stays changed).
    check(all_transports(Case::new("hosts_unbindable", &["-f", "-h", "192.0.2.1", "-h", "2001:db8::1"])));
}

#[test]
fn hosts_unresolvable() {
    check(all_transports(Case::new("hosts_unresolvable", &["-f", "-h", "no-such-host.invalid"])));
}

#[test]
fn hosts_star() {
    // "*" becomes NULL in place: the second UDP transport dereferences it.
    check(Case::new("hosts_star", &["-f", "-h", "*"]).probe(format!("udp 127.0.0.1 111 {}", null(1, 2))));
}

// ---------------------------------------------------------------------------
// startup failures

#[test]
fn already_running() {
    check(Case::new("already_running", &["-f"]).setup("flock /run/rpcbind.lock sleep 3 &").setup("sleep 0.1"));
}

#[test]
fn stale_socket_replaced() {
    check(
        Case::new("stale_socket_replaced", &["-f"])
            .setup("echo stale >/run/rpcbind.sock")
            .probe(format!("udp 127.0.0.1 111 {}", null(1, 4))),
    );
}

#[test]
fn port_in_use() {
    check(all_transports(
        Case::new("port_in_use", &["-f"]).setup("python3 -c 'import socket,time\ns=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\ns.bind((\"0.0.0.0\",111))\ntime.sleep(5)' &").setup("sleep 0.3"),
    ));
}

const STD_NETCONFIG: &str = "udp        tpi_clts      v     inet     udp     -       -
tcp        tpi_cots_ord  v     inet     tcp     -       -
udp6       tpi_clts      v     inet6    udp     -       -
tcp6       tpi_cots_ord  v     inet6    tcp     -       -
rawip      tpi_raw       -     inet      -      -       -
local      tpi_cots_ord  -     loopback  -      -       -
unix       tpi_cots_ord  -     loopback  -      -       -
";

#[test]
fn netconfig_variants() {
    let cases: &[(&str, String)] = &[
        ("netconfig_empty", String::new()),
        ("netconfig_blank_line_first", format!("\n{STD_NETCONFIG}")),
        ("netconfig_blank_line_middle", STD_NETCONFIG.replace("udp6 ", "\nudp6 ")),
        ("netconfig_comments", format!("# header\n#udp tpi_clts v inet udp - -\n{STD_NETCONFIG}# end\n")),
        ("netconfig_indented_comment", STD_NETCONFIG.replace("rawip", " # note\nrawip")),
        (
            "netconfig_unix_only",
            STD_NETCONFIG.replace("local      tpi_cots_ord  -     loopback  -      -       -\n", ""),
        ),
        ("netconfig_no_local", "udp tpi_clts v inet udp - -\ntcp tpi_cots_ord v inet tcp - -\n".into()),
        (
            "netconfig_ipv4_only",
            "udp tpi_clts v inet udp - -\ntcp tpi_cots_ord v inet tcp - -\nlocal tpi_cots_ord - loopback - - -\n"
                .into(),
        ),
        (
            "netconfig_ipv6_only",
            "udp6 tpi_clts v inet6 udp - -\ntcp6 tpi_cots_ord v inet6 tcp - -\nlocal tpi_cots_ord - loopback - - -\n"
                .into(),
        ),
        ("netconfig_local_visible", STD_NETCONFIG.replace("local      tpi_cots_ord  -", "local      tpi_cots_ord  v")),
        ("netconfig_tpi_cots", STD_NETCONFIG.replace("tcp        tpi_cots_ord", "tcp        tpi_cots    ")),
        ("netconfig_bad_semantics", STD_NETCONFIG.replace("tcp6       tpi_cots_ord", "tcp6       tpi_bogus   ")),
        ("netconfig_bad_flag", STD_NETCONFIG.replace("udp6       tpi_clts      v", "udp6       tpi_clts      x")),
        ("netconfig_no_final_newline", STD_NETCONFIG.trim_end().to_string()),
        ("netconfig_no_final_newline_short", "udp tpi_clts v inet udp - -\nlocal tpi_cots_ord - loopback - - -".into()),
        ("netconfig_unknown_netid", format!("{STD_NETCONFIG}sctp tpi_cots_ord v inet sctp - -\n")),
        ("netconfig_duplicate", format!("{STD_NETCONFIG}udp tpi_clts v inet udp - -\n")),
        (
            "netconfig_tabs_and_lookups",
            STD_NETCONFIG.replace(
                "udp        tpi_clts      v     inet     udp     -       -",
                "udp\ttpi_clts\tvb\tinet\tudp\t/dev/udp\tlib1.so,lib2\\,x.so",
            ),
        ),
        ("netconfig_long_line", format!("{}{STD_NETCONFIG}", "#".repeat(1500) + "\n")),
        (
            "netconfig_long_entry",
            STD_NETCONFIG.replace(
                "rawip      tpi_raw       -     inet      -      -       -",
                &format!("rawip tpi_raw - inet - - {}", "x".repeat(1200)),
            ),
        ),
    ];
    for (name, text) in cases {
        check(all_transports(Case::new(name, &["-f"]).netconfig(text)));
    }
}

// ---------------------------------------------------------------------------
// signals

#[test]
fn signals() {
    for sig in ["INT", "QUIT", "TERM", "HUP", "USR1", "USR2", "PIPE"] {
        check(
            Case::new(&format!("signal_{sig}"), &["-f"]).signal(sig).probe(format!("udp 127.0.0.1 111 {}", null(1, 2))),
        );
    }
}

#[test]
fn signal_daemon_mode() {
    check(Case::new("signal_daemon_mode", &[]).signal("INT").probe(format!("udp 127.0.0.1 111 {}", null(1, 2))));
}

// ---------------------------------------------------------------------------
// the RPC layer: dispatch and rejections

#[test]
fn rejections() {
    let mut c = Case::new("rejections", &["-f"]);
    let calls = [
        call(1, 100003, 3, 0, ""), // program not registered
        call(2, PMAP, 1, 0, ""),   // version too low
        call(3, PMAP, 5, 0, ""),   // version too high
        call(4, PMAP, 2, 6, ""),   // v2 procedure out of range
        call(5, PMAP, 3, 9, ""),   // v3
        call(6, PMAP, 4, 13, ""),  // v4
        call(7, PMAP, 4, 0xffffffff, ""),
        call(8, 0, 0, 0, ""),
        null(9, 2) + "deadbeef", // NULL ignores extra arguments
    ];
    for (i, k) in calls.iter().enumerate() {
        c = c.probe(format!("udp 127.0.0.1 111 {k}"));
        c = c
            .probe(format!("conn t{i} tcp 127.0.0.1 111"))
            .probe(format!("send t{i} {}", record(k)))
            .probe(format!("recv t{i}"))
            .probe(format!("close t{i}"));
        c = c
            .probe(format!("conn u{i} unix /run/rpcbind.sock"))
            .probe(format!("send u{i} {}", record(k)))
            .probe(format!("recv u{i}"))
            .probe(format!("close u{i}"));
    }
    check(c);
}

#[test]
fn not_calls() {
    let mut c = Case::new("not_calls", &["-f"]);
    let msgs = [
        words(&[1, 0, 3, PMAP, 2, 0, 0, 0, 0, 0]), // RPC version 3
        words(&[2, 0, 1, PMAP, 2, 0, 0, 0, 0, 0]), // RPC version 1
        words(&[3, 1, 0, 0, 0, 0]),                // a reply
        words(&[4, 7, 2, PMAP, 2, 0, 0, 0, 0, 0]), // bad direction
    ];
    for (i, m) in msgs.iter().enumerate() {
        c = c.probe(format!("udp 127.0.0.1 111 {m}"));
        c = c
            .probe(format!("conn t{i} tcp 127.0.0.1 111"))
            .probe(format!("send t{i} {}", record(m)))
            .probe(format!("recv t{i}"))
            // Is the connection still usable afterwards?
            .probe(format!("send t{i} {}", record(&null(50 + i as u32, 2))))
            .probe(format!("recv t{i}"))
            .probe(format!("close t{i}"));
    }
    check(c);
}

#[test]
fn authentication() {
    let good = auth_sys(12345, b"client.example", 1000, 100, &[100, 10, 4]);
    let long_name = auth_sys(1, &[b'a'; 255], 0, 0, &[]);
    let too_long_name = auth_sys(1, &[b'a'; 256], 0, 0, &[]);
    let sixteen = auth_sys(1, b"h", 0, 0, &[7; 16]);
    let seventeen = auth_sys(1, b"h", 0, 0, &[7; 17]);
    let calls = [
        call_auth(1, PMAP, 2, 0, (AUTH_SYS, &good), (0, b"")),
        call_auth(2, PMAP, 3, 0, (AUTH_SYS, &good), (0, b"vvvv")), // AUTH_NONE verf with a body
        call_auth(3, PMAP, 4, 0, (AUTH_SYS, &good), (7, b"verifier-bytes")), // echoed
        call_auth(4, PMAP, 2, 0, (AUTH_SYS, &good[..good.len() - 4]), (0, b"")), // short
        call_auth(5, PMAP, 2, 0, (AUTH_SYS, &good[..8]), (0, b"")),
        call_auth(6, PMAP, 2, 0, (AUTH_SYS, b""), (0, b"")),
        call_auth(7, PMAP, 2, 0, (AUTH_SYS, &[good.clone(), b"trailing".to_vec()].concat()), (0, b"")),
        call_auth(8, PMAP, 2, 0, (AUTH_SYS, &long_name), (0, b"")),
        call_auth(9, PMAP, 2, 0, (AUTH_SYS, &too_long_name), (0, b"")),
        call_auth(10, PMAP, 2, 0, (AUTH_SYS, &sixteen), (0, b"")),
        call_auth(11, PMAP, 2, 0, (AUTH_SYS, &seventeen), (0, b"")),
        call_auth(12, PMAP, 2, 0, (2, b"short-hand"), (0, b"")), // AUTH_SHORT
        call_auth(13, PMAP, 2, 0, (3, b"des"), (0, b"")),        // AUTH_DES
        call_auth(14, PMAP, 2, 0, (6, b"gss"), (0, b"")),        // RPCSEC_GSS
        call_auth(15, PMAP, 2, 0, (99, b""), (0, b"")),
        call_auth(16, PMAP, 2, 0, (0, &[1u8; 400]), (0, &[2u8; 400])), // the largest allowed
        call_auth(17, PMAP, 2, 0, (0, &[1u8; 401]), (0, b"")),         // too large
        call_auth(18, PMAP, 2, 0, (0, b""), (0, &[2u8; 401])),
        call_auth(19, 100003, 3, 0, (AUTH_SYS, &good), (5, b"xyz")), // PROG_UNAVAIL carries the verifier
        call_auth(20, PMAP, 9, 0, (AUTH_SYS, &good), (5, b"xyz")),   // PROG_MISMATCH too
        call_auth(21, PMAP, 4, 99, (AUTH_SYS, &good), (5, b"xyz")),  // PROC_UNAVAIL too
        call_auth(22, 100003, 3, 0, (99, b""), (5, b"xyz")),         // auth is checked first
    ];
    let mut c = Case::new("authentication", &["-f"]);
    for (i, k) in calls.iter().enumerate() {
        c = c.probe(format!("udp 127.0.0.1 111 {k}"));
        c = c
            .probe(format!("conn t{i} tcp ::1 111"))
            .probe(format!("send t{i} {}", record(k)))
            .probe(format!("recv t{i}"))
            .probe(format!("close t{i}"));
    }
    check(c);
}

#[test]
fn authentication_daemon_mode() {
    // The "bad auth_len" printf goes to stdout, which daemon() pointed at /dev/null.
    let good = auth_sys(1, b"h", 0, 0, &[1, 2]);
    check(Case::new("authentication_daemon_mode", &[]).probe(format!(
        "udp 127.0.0.1 111 {}",
        call_auth(1, PMAP, 2, 0, (AUTH_SYS, &good[..good.len() - 4]), (0, b""))
    )));
}

// ---------------------------------------------------------------------------
// UDP framing

#[test]
fn udp_short_and_stale() {
    let full = call_auth(1, PMAP, 2, 0, (AUTH_SYS, &auth_sys(1, b"host", 5, 6, &[1, 2, 3])), (0, b""));
    let c = Case::new("udp_short_and_stale", &["-f"])
        .probe(format!("udp 127.0.0.1 111 {}", hex(&[0u8; 15]))) // under 16 bytes
        .probe(format!("udp 127.0.0.1 111 {}", words(&[9, 0, 2, PMAP]))) // 16 bytes: the rest is read from the buffer
        .probe(format!("udp 127.0.0.1 111 {full}"))
        // A header cut short: the credential comes from what the last call left.
        .probe(format!("udp 127.0.0.1 111 {}", words(&[2, 0, 2, PMAP, 2, 0])))
        .probe(format!("udp 127.0.0.1 111 {}", &full[..full.len() - 16]))
        .probe(format!("udp 127.0.0.1 111 {}", words(&[3, 0, 2, PMAP, 3, 0, 0])))
        .probe(format!("udp 127.0.0.1 111 {}", null(4, 4)))
        .probe(format!("udp 127.0.0.1 111 {}", words(&[5, 0, 2, PMAP])))
        .probe(format!("udp 127.0.0.1 111 {}", hex(&[0xffu8; 9000])))
        .probe(format!("udp 127.0.0.1 111 {}{}", null(6, 2), hex(&[0u8; 9100])));
    check(c);
}

#[test]
fn udp_reply_source_address() {
    // Replies leave from the address the call came to (IP_PKTINFO).
    check(
        Case::new("udp_reply_source_address", &["-f"])
            .setup("ip addr add 10.11.12.13/24 dev lo")
            .setup("ip addr add fd00::5/64 dev lo nodad")
            .probe(format!("udp 127.0.0.9 111 {}", null(1, 2)))
            .probe(format!("udp 10.11.12.13 111 {}", null(2, 3)))
            .probe(format!("udpfrom 10.11.12.13 127.0.0.1 111 {}", null(3, 4)))
            .probe(format!("udp fd00::5 111 {}", null(4, 4)))
            .probe(format!("udpfrom fd00::5 ::1 111 {}", null(5, 3))),
    );
}

// ---------------------------------------------------------------------------
// stream framing

#[test]
fn stream_framing() {
    let n1 = null(1, 2);
    let n2 = null(2, 3);
    let rec1 = record(&n1);
    let half = n2.len() / 2;
    let c = Case::new("stream_framing", &["-f"])
        // Two records in one write.
        .probe("conn a tcp 127.0.0.1 111")
        .probe(format!("send a {rec1}{}", record(&n2)))
        .probe("recv a")
        .probe("recv a")
        .probe("close a")
        // A record in pieces, header first one byte at a time.
        .probe("conn b tcp 127.0.0.1 111")
        .probe(format!("send b {}", &rec1[..2]))
        .probe("sleep 50")
        .probe(format!("send b {}", &rec1[2..6]))
        .probe("sleep 50")
        .probe(format!("send b {}", &rec1[6..20]))
        .probe("sleep 50")
        .probe(format!("send b {}", &rec1[20..]))
        .probe("recv b")
        .probe("close b")
        // A call split over two fragments.
        .probe("conn c tcp 127.0.0.1 111")
        .probe(format!("send c {}{}", fragment(&n2[..half]), record(&n2[half..])))
        .probe("recv c")
        .probe("recv c")
        .probe("close c")
        // A call in a non-last fragment alone.
        .probe("conn d tcp 127.0.0.1 111")
        .probe(format!("send d {}", fragment(&n1)))
        .probe("recv d")
        .probe("send d 80000000")
        .probe("recv d")
        .probe("close d")
        // An empty fragment.
        .probe("conn e tcp 127.0.0.1 111")
        .probe("send e 80000000")
        .probe("recv e")
        .probe("close e")
        // Too large: 9001 bytes, and two fragments adding up to more than 9000.
        .probe("conn f tcp 127.0.0.1 111")
        .probe(format!("send f {:08x}", 0x8000_0000u32 | 9001))
        .probe("recv f")
        .probe("close f")
        .probe("conn g unix /run/rpcbind.sock")
        .probe(format!("send g {:08x}{}{:08x}", 5000u32, hex(&[0u8; 5000]), 0x8000_0000u32 | 4001))
        .probe("recv g")
        .probe("recv g")
        .probe("close g")
        // The largest record allowed.
        .probe("conn h tcp ::1 111")
        .probe(format!("send h {}", record(&(n1.clone() + &hex(&[0u8; 9000 - 40])))))
        .probe("recv h")
        .probe("close h")
        // A record cut off by EOF, and a truncated call.
        .probe("conn i tcp 127.0.0.1 111")
        .probe(format!("send i {}", &rec1[..30]))
        .probe("close i")
        .probe("conn j tcp 127.0.0.1 111")
        .probe(format!("send j {}", record(&n1[..40])))
        .probe("recv j")
        .probe("close j")
        // Still serving.
        .probe(format!("udp 127.0.0.1 111 {}", null(99, 4)));
    check(c);
}

#[test]
fn many_connections() {
    let mut c = Case::new("many_connections", &["-f"]);
    for i in 0..40 {
        c = c.probe(format!("conn k{i} tcp 127.0.0.1 111"));
    }
    for i in (0..40).rev() {
        c = c.probe(format!("send k{i} {}", record(&null(i, 2)))).probe(format!("recv k{i}"));
    }
    for i in 0..40 {
        c = c.probe(format!("close k{i}"));
    }
    check(c);
}
