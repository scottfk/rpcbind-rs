//! Phase 3: hostile input. Connection floods and the idle-connection cleanup, slow,
//! half-open and stalled clients, the cases behind CVE-2017-8779 ("rpcbomb") and
//! CVE-2015-7236, memory staying bounded, and mutated calls on every transport.

mod common;
use common::*;

const PMAP: u32 = 100000;
const AUTH_SYS: u32 = 1;

fn null(xid: u32, vers: u32) -> String {
    call(xid, PMAP, vers, 0, "")
}

fn rpcb(prog: u32, vers: u32, netid: &str, addr: &str, owner: &str) -> String {
    format!(
        "{}{}{}{}",
        words(&[prog, vers]),
        opaque(netid.as_bytes()),
        opaque(addr.as_bytes()),
        opaque(owner.as_bytes())
    )
}

/// Send `msg` as a record on connection `name` and read the reply.
fn ask(c: Case, name: &str, msg: &str) -> Case {
    c.probe(format!("send {name} {}", record(msg))).probe(format!("recv {name}"))
}

/// Is every connection `k0`..`k{n-1}` still served? Each answers a NULL call or not.
fn roll_call(mut c: Case, n: u32, xid: u32) -> Case {
    for i in 0..n {
        c = ask(c, &format!("k{i}"), &null(xid + i, 2));
    }
    c
}

// ---------------------------------------------------------------------------
// connection floods

/// With 32 descriptors, `_rpc_dtablesize()` is 32 and an accept that brings the open
/// slots to 24 or more closes connections: those idle over 15 seconds, or else the
/// least active one (as `__svc_destroy_idle()` finds them, slot index for descriptor).
#[test]
fn flood_low_fd_limit() {
    for (name, how) in [("flood_tcp", "tcp 127.0.0.1 111"), ("flood_local", "unix /run/rpcbind.sock")] {
        let mut c = Case::new(name, &["-f"]).nofile(32).probe("timeout 200");
        for i in 0..30 {
            c = c.probe(format!("conn k{i} {how}")).probe("sleep 3");
            // Some connections talk, which makes them more recently active.
            if i % 3 == 0 {
                c = ask(c, &format!("k{i}"), &null(100 + i, 2));
            }
        }
        c = roll_call(c, 30, 1000);
        c = c.probe(format!("udp 127.0.0.1 111 {}", null(1, 3)));
        check(c);
    }
}

/// On a stopped clock no connection is less active than another, so the least-active
/// pass closes nothing and descriptors run out: accept() fails (again on every poll
/// round) and the connection waits in the backlog. Then the clock moves 20 seconds on
/// and one connection closes: the waiting one is accepted, and that accept closes
/// every connection idle for over 15 seconds that the slot-index lookup finds.
#[test]
fn flood_stopped_clock() {
    let mut c = Case::new("flood_stopped_clock", &["-f"]).nofile(32).faketime(1_800_000_000).probe("timeout 200");
    for i in 0..25 {
        c = c.probe(format!("conn k{i} tcp 127.0.0.1 111"));
        c = ask(c, &format!("k{i}"), &null(100 + i, 2));
    }
    c = c.probe("clock 1800000020").probe("close k0").probe("sleep 100");
    c = c.probe(format!("udp 127.0.0.1 111 {}", null(1, 2))).probe(format!("udp 127.0.0.1 111 {}", null(2, 2)));
    c = c.probe("close k1").probe("sleep 100");
    for i in 2..25 {
        c = ask(c, &format!("k{i}"), &null(1000 + i, 2));
    }
    c = c.probe(format!("udp 127.0.0.1 111 {}", null(3, 3)));
    check(c);
}

/// Idle connections on a moving clock: some go quiet, the clock moves past 15
/// seconds, and the flood that follows closes only those (and the ones the slot-index
/// lookup misses stay). Each connection answers a call before the next step, so it
/// has been accepted (one a poll round) when the clock moves.
#[test]
fn idle_cleanup() {
    let mut c = Case::new("idle_cleanup", &["-f"]).nofile(32).faketime(1_800_000_000).probe("timeout 200");
    for i in 0..12 {
        c = c.probe(format!("conn k{i} tcp 127.0.0.1 111"));
        c = ask(c, &format!("k{i}"), &null(50 + i, 2));
    }
    c = c.probe("clock 1800000016");
    for i in 0..6 {
        c = ask(c, &format!("k{i}"), &null(100 + i, 2));
    }
    for i in 12..24 {
        c = c.probe(format!("conn k{i} unix /run/rpcbind.sock"));
        c = ask(c, &format!("k{i}"), &null(100 + i, 2));
    }
    c = roll_call(c, 24, 1000);
    check(c);
}

// ---------------------------------------------------------------------------
// slow, half-open and stalled clients

#[test]
fn slow_and_half_open() {
    let n1 = record(&null(1, 2));
    let big = record(&call(2, PMAP, 4, 3, &rpcb(100003, 3, "tcp", "", "")));
    let c = Case::new("slow_and_half_open", &["-f"])
        .probe("timeout 300")
        // A record left half-sent doesn't hold up anyone else.
        .probe("conn a tcp 127.0.0.1 111")
        .probe(format!("send a {}", &n1[..30]))
        .probe("conn b unix /run/rpcbind.sock")
        .probe(format!("send b {n1}"))
        .probe("recv b")
        .probe(format!("udp 127.0.0.1 111 {}", null(3, 3)))
        .probe(format!("send a {}", &n1[30..]))
        .probe("recv a")
        // A header promising more than ever comes.
        .probe(format!("send b {:08x}{}", 0x8000_0000u32 | 4000, &n1[8..]))
        .probe("recv b")
        .probe("conn c tcp ::1 111")
        .probe(format!("send c {big}"))
        .probe("recv c")
        // Half-closed after the call: the reply still comes, then the close.
        .probe("conn d tcp 127.0.0.1 111")
        .probe(format!("send d {big}{n1}"))
        .probe("shutw d")
        .probe("recv d")
        .probe("recv d")
        .probe("recv d")
        .probe("conn e unix /run/rpcbind.sock")
        .probe(format!("send e {n1}"))
        .probe("shutw e")
        .probe("recv e")
        .probe("recv e")
        // Gone before the reply: reset, or closed with the call unread.
        .probe("conn f tcp 127.0.0.1 111")
        .probe(format!("send f {big}{big}{big}"))
        .probe("reset f")
        .probe("conn g unix /run/rpcbind.sock")
        .probe(format!("send g {big}{big}{big}"))
        .probe("close g")
        .probe("conn h tcp 127.0.0.1 111")
        .probe("reset h")
        .probe("sleep 100")
        // Still serving, and a and b are still open.
        .probe(format!("send a {n1}"))
        .probe("recv a")
        .probe(format!("udp ::1 111 {}", null(4, 4)))
        .probe("close a")
        .probe("close b")
        .probe("close c");
    check(c);
}

/// A client that sends calls and never reads the replies: once the socket buffer is
/// full, `write_vc()` spins for up to two seconds and then drops the connection. The
/// others wait, then are served.
#[test]
fn stalled_reader() {
    let mut c = Case::new("stalled_reader", &["-f"]).probe("conn reg unix /run/rpcbind.sock");
    let mut all = String::new();
    for i in 0..150u32 {
        let netid = format!("tcp{}", "x".repeat(40));
        all.push_str(&record(&call(i + 1, PMAP, 4, 1, &rpcb(400000 + i, 1, &netid, "0.0.0.0.8.1", ""))));
    }
    c = c.probe(format!("send reg {all}")).probe("timeout 300");
    for _ in 0..150 {
        c = c.probe("recv reg");
    }
    c = c.probe("close reg").probe("conn other tcp 127.0.0.1 111");
    let dumps: String = (0..200).map(|i| record(&call(1000 + i, PMAP, 4, 4, ""))).collect();
    c = c
        .probe("conn slow unix /run/rpcbind.sock")
        .probe(format!("send slow {dumps}"))
        .probe("sleep 200")
        .probe("timeout 5000");
    c = ask(c, "other", &null(5, 2));
    c = c.probe("timeout 3000").probe("drain slow").probe(format!("udp 127.0.0.1 111 {}", null(6, 3)));
    check(c);
}

// ---------------------------------------------------------------------------
// CVE-2017-8779 and CVE-2015-7236

/// "rpcbomb": arguments claiming huge lengths, sent again and again. libtirpc before
/// 1.0.2 allocated the claimed size and rpcbind never freed it; now each call is
/// refused (or answered) and the daemon stays small. The check is the resident peak
/// (`VmHWM`, about 3 MB for both): C still allocates, untouched, whatever size a
/// `CALLIT` argument claims, so the virtual peaks differ.
#[test]
fn rpcbomb() {
    let huge = |n: u32| words(&[n]);
    let bombs = [
        (4, 3, words(&[100003, 3]) + &huge(0xffff_fff0)), // GETADDR netid
        (3, 1, words(&[100003, 3]) + &opaque(b"tcp") + &huge(0x7fff_ffff)), // SET addr
        (4, 2, words(&[100003, 3, 0x40_0000])),           // UNSET netid
        (4, 9, huge(0xffff_ffff)),                        // UADDR2TADDR
        (4, 8, words(&[16, 0xffff_0000])),                // TADDR2UADDR netbuf
        (4, 11, words(&[100003, 3]) + &huge(0x1000_0000)), // GETADDRLIST
        (2, 5, words(&[100003, 3, 0, 0xffff_fff0])),      // PMAP CALLIT args
        (4, 10, words(&[100005, 3, 2, 0x7fff_fffc])),     // INDIRECT args
        (3, 5, words(&[100024, 1, 1, 0x1000_0000])),      // CALLIT, registered
    ];
    let mut c = Case::new("rpcbomb", &["-f"]).probe("sync on").probe("timeout 5").probe("mem 16000");
    for (i, (v, p, a)) in bombs.iter().enumerate() {
        let m = call(i as u32 + 1, PMAP, *v, *p, a);
        c = c.probe(format!("udpn 300 127.0.0.1 111 {m}"));
        c = c.probe(format!("udpn 100 ::1 111 {m}"));
        c = c.probe(format!("conn t{i} unix /run/rpcbind.sock"));
        for _ in 0..20 {
            c = ask(c, &format!("t{i}"), &m);
        }
        // Over a stream the claimed bytes are waited for; a short record ends it.
        c = c.probe(format!("conn s{i} tcp 127.0.0.1 111"));
        c = c.probe(format!("send s{i} {:08x}{m}", 0x8000_0000u32 | 8000)).probe(format!("recv s{i}"));
    }
    c = c.probe("mem 16000").probe(format!("udp 127.0.0.1 111 {}", call(99, PMAP, 4, 12, "")));
    check(c);
}

/// CVE-2015-7236 was a use-after-free in `PMAPPROC_CALLIT` with crafted arguments.
/// The forwarding code is compiled out, but the calls are still decoded, checked and
/// counted: truncated, padded and mis-sized ones, in every version, many times.
#[test]
fn callit_crafted() {
    let mut c = Case::new("callit_crafted", &["-f", "-d"]).probe("sync on").probe("timeout 5");
    c = c.probe(format!("udp 127.0.0.1 111 {}", call(1, PMAP, 2, 1, &words(&[100024, 1, 17, 1000]))));
    let variants = [
        String::new(),
        words(&[100024]),
        words(&[100024, 1]),
        words(&[100024, 1, 1]),
        words(&[100024, 1, 1, 0]),
        words(&[100024, 1, 1, 3]) + "616263",
        words(&[100024, 1, 1, 3]) + "61626300",
        words(&[100024, 1, 1, 9000]) + &hex(&[7u8; 100]),
        words(&[100024, 1, 1, 8]) + &hex(&[7u8; 4]),
        words(&[100024, 2, 1, 4]) + "00000001",
        words(&[0, 0, 0, 0]),
        words(&[100000, 2, 5, 16]) + &words(&[100000, 2, 5, 0]),
        words(&[100000, 4, 10, 16]) + &words(&[100000, 4, 10, 0]),
    ];
    for (i, a) in variants.iter().enumerate() {
        for (v, p) in [(2, 5), (3, 5), (4, 5), (4, 10)] {
            let m = call(10 + i as u32 * 10 + v + p, PMAP, v, p, a);
            c = c.probe(format!("udpn 50 127.0.0.1 111 {m}"));
            c = c.probe(format!("conn t{i}_{v}_{p} tcp 127.0.0.1 111"));
            c = ask(c, &format!("t{i}_{v}_{p}"), &m);
            c = ask(c, &format!("t{i}_{v}_{p}"), &m);
        }
    }
    let cred = auth_sys(1, b"client", 0, 0, &[]);
    let m = call_auth(900, PMAP, 2, 5, (AUTH_SYS, &cred), (0, b"")) + &words(&[100024, 1, 1, 0]);
    c = c.probe(format!("udpn 50 ::1 111 {m}"));
    c = c.probe("conn stat unix /run/rpcbind.sock");
    c = ask(c, "stat", &call(999, PMAP, 4, 12, ""));
    check(c);
}

/// `xdr_netbuf()` refuses to free a netbuf whose `maxlen` is over 9000, which is what
/// made it fail to decode: with `-d` that is logged after the decode error (without a
/// newline in version 3), and `-a` then aborts.
#[test]
fn netbuf_free_failure() {
    for (name, args) in
        [("netbuf_free", &["-f"][..]), ("netbuf_free_debug", &["-f", "-d"]), ("netbuf_free_abort", &["-f", "-d", "-a"])]
    {
        let mut c = Case::new(name, args).probe("sync on").probe("timeout 5");
        for (i, a) in
            [words(&[9000, 0]), words(&[9001]), words(&[9001, 16]), words(&[0xffff_ffff, 0])].iter().enumerate()
        {
            for v in [3, 4] {
                c = c.probe(format!("conn t{i}_{v} unix /run/rpcbind.sock"));
                c = ask(c, &format!("t{i}_{v}"), &call(10 * i as u32 + v, PMAP, v, 8, a));
            }
        }
        c = c.probe("sync off").probe(format!("udp ::1 111 {}", null(1, 2)));
        check(c);
    }
}

// ---------------------------------------------------------------------------
// mutated calls

/// xorshift64*, so the mutations are the same every run.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap()).collect()
}

/// Well-formed calls of every procedure, to mutate.
fn seeds() -> Vec<Vec<u8>> {
    let cred = auth_sys(7, b"fuzz", 0, 0, &[0, 1]);
    let user = auth_sys(7, b"fuzz", 1000, 100, &[100]);
    let r = rpcb(100003, 3, "tcp", "127.0.0.1.8.1", "");
    let s = [
        call(1, PMAP, 2, 1, &words(&[100003, 3, 6, 2049])),
        call(1, PMAP, 2, 2, &words(&[100003, 3, 6, 2049])),
        call(1, PMAP, 2, 3, &words(&[100003, 3, 6, 0])),
        call(1, PMAP, 2, 4, ""),
        call(1, PMAP, 2, 5, &(words(&[100003, 3, 0]) + &opaque(b"args"))),
        call(1, PMAP, 3, 1, &r),
        call(1, PMAP, 3, 2, &r),
        call(1, PMAP, 3, 3, &r),
        call(1, PMAP, 3, 4, ""),
        call(1, PMAP, 3, 6, ""),
        call(1, PMAP, 3, 7, &opaque(b"127.0.0.1.0.111")),
        call(1, PMAP, 3, 8, &opaque(&[2, 0, 0, 111, 127, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0])),
        call(1, PMAP, 4, 1, &r),
        call(1, PMAP, 4, 3, &r),
        call(1, PMAP, 4, 9, &r),
        call(1, PMAP, 4, 10, &(words(&[100003, 3, 0]) + &opaque(b""))),
        call(1, PMAP, 4, 11, &r),
        call(1, PMAP, 4, 12, ""),
        call_auth(1, PMAP, 4, 1, (AUTH_SYS, &cred), (0, b"")) + &r,
        call_auth(1, PMAP, 4, 2, (AUTH_SYS, &user), (0, b"")) + &r,
        call_auth(1, PMAP, 2, 3, (2, b"shortcred"), (0, b"")) + &words(&[100003, 3, 17, 0]),
    ];
    s.iter().map(|h| unhex(h)).collect()
}

/// One mutation of `m`.
fn mutate(rng: &mut Rng, m: &[u8]) -> Vec<u8> {
    const WORDS: [u32; 12] = [0, 1, 2, 3, 4, 0x7fff_ffff, 0x8000_0000, 0xffff_ffff, 400, 401, 9000, 0x1_0000];
    let mut v = m.to_vec();
    for _ in 0..1 + rng.below(3) {
        match rng.below(6) {
            0 => {
                let i = rng.below(v.len());
                v[i] ^= 1 << rng.below(8);
            }
            1 => {
                let i = rng.below(v.len());
                v[i] = rng.next() as u8;
            }
            2 if v.len() >= 4 => {
                let i = rng.below(v.len() / 4) * 4;
                v[i..i + 4].copy_from_slice(&WORDS[rng.below(WORDS.len())].to_be_bytes());
            }
            3 => {
                let n = rng.below(v.len());
                v.truncate(n.max(1));
            }
            4 => {
                for _ in 0..1 + rng.below(12) {
                    v.push(rng.next() as u8);
                }
            }
            _ => {
                // Duplicate a word, shifting the rest.
                if v.len() >= 4 {
                    let i = rng.below(v.len() / 4) * 4;
                    let w = v[i..i + 4].to_vec();
                    v.splice(i..i, w);
                }
            }
        }
    }
    v
}

/// `RPCBIND_FUZZ=SEED:COUNT[:ARGS]` runs COUNT more mutations from SEED as well (or
/// only, with `RPCBIND_FUZZ_ONLY` set), with the daemon options ARGS (comma-separated,
/// default `-f`).
#[test]
fn mutated_calls() {
    let seeds = seeds();
    let extra = std::env::var("RPCBIND_FUZZ").ok().map(|v| {
        let mut f = v.splitn(3, ':');
        let seed = f.next().unwrap().parse::<u64>().expect("RPCBIND_FUZZ=SEED:COUNT[:ARGS]");
        let n = f.next().expect("RPCBIND_FUZZ=SEED:COUNT[:ARGS]").parse::<u32>().unwrap();
        let args: Vec<&'static str> = f.next().unwrap_or("-f").split(',').map(|a| &*a.to_string().leak()).collect();
        (seed, n, args.leak() as &[&str])
    });
    let mut cases = vec![
        ("mutated_calls".to_string(), 0x5eed_0001u64, 400u32, &["-f"][..]),
        // Not -l: its forks' SIGCHLD runs the handler on the stack where libtirpc keeps
        // the leftover credential bytes, so C's own "bad auth_len" numbers vary.
        ("mutated_calls_debug".to_string(), 0x5eed_0002, 400, &["-f", "-d", "-i"]),
    ];
    if let Some((s, n, a)) = extra {
        cases.push((format!("mutated_calls_{s}"), s, n, a));
    }
    if std::env::var_os("RPCBIND_FUZZ_ONLY").is_some() {
        cases.drain(..2);
    }
    for (name, seed, count, args) in cases {
        let mut rng = Rng(seed);
        let mut c = Case::new(&name, args).faketime(1_800_000_000).probe("sync on").probe("timeout 5");
        // Short AUTH_SYS credentials are parsed from leftover bytes (QUIRKS.md). In C a
        // refused indirect call forks a logit() child, and the SIGCHLD handler's frame
        // lands on those bytes, so which "bad auth_len" line (or none) a short
        // credential gets can't be compared here. The reply is the same either way:
        // a credential that passes the length check was read from its own bytes.
        // (leftover_credentials_move and authentication compare those lines.)
        c = c.drop_stdout("bad auth_len ");
        for i in 0..count {
            let k = rng.below(seeds.len());
            let m = mutate(&mut rng, &seeds[k]);
            match i % 4 {
                0 => c = c.probe(format!("udp 127.0.0.1 111 {}", hex(&m))),
                1 => c = c.probe(format!("udp ::1 111 {}", hex(&m))),
                2 => {
                    c = c.probe(format!("conn t{i} tcp 127.0.0.1 111"));
                    c = ask(c, &format!("t{i}"), &hex(&m)).probe(format!("close t{i}"));
                }
                _ => {
                    c = c.probe(format!("conn l{i} unix /run/rpcbind.sock"));
                    c = ask(c, &format!("l{i}"), &hex(&m)).probe(format!("close l{i}"));
                }
            }
        }
        c = c.probe("conn end unix /run/rpcbind.sock");
        c = ask(c, "end", &call(9000, PMAP, 4, 4, ""));
        c = ask(c, "end", &call(9001, PMAP, 4, 12, ""));
        check(c);
    }
}

// ---------------------------------------------------------------------------
// leftover credential bytes

/// A short `AUTH_SYS` credential is parsed from leftover bytes (QUIRKS.md), and where
/// they are read from moves down 16 bytes whenever the poll table outgrows the next
/// multiple of two slots. Fill the area, then grow the table one connection at a time,
/// reading after each with credentials of 16 bytes or more: the 16 bytes that come
/// into view below the old place are other locals in C (addresses among them), so a
/// read that reaches them can't be compared. An empty credential reads only bytes
/// that are known: right after a fill, or after a read of 16 bytes or more.
#[test]
fn leftover_credentials_move() {
    let mut c = Case::new("leftover_credentials_move", &["-f"]).probe("timeout 200");
    let mut fill = Vec::new();
    for w in [7u32, 4, 0x6162_6364, 1000, 100, 3, 11, 12, 13, 2, 0, 4, 9, 1, 5, 6] {
        fill.extend_from_slice(&w.to_be_bytes());
    }
    while fill.len() < 400 {
        fill.extend_from_slice(&((fill.len() as u32 / 4) % 5).to_be_bytes());
    }
    let prime = format!("udp 127.0.0.1 111 {}", call_auth(1, PMAP, 2, 0, (AUTH_SYS, &fill), (0, b"")));
    let short = |x: u32, len: usize| call_auth(x, PMAP, 2, 0, (AUTH_SYS, &fill[..len]), (0, b""));
    c = c.probe(&prime).probe(format!("udp 127.0.0.1 111 {}", short(2, 0)));
    for k in 0..14u32 {
        // The area moves from the round after the accept: two answered calls make
        // sure the reads come later than that.
        c = c.probe(format!("conn g{k} unix /run/rpcbind.sock"));
        c = c.probe(format!("udp 127.0.0.1 111 {}", null(100 + k, 2)));
        c = c.probe(format!("udp 127.0.0.1 111 {}", null(200 + k, 2)));
        c = c.probe(format!("udp 127.0.0.1 111 {}", short(10 + k, 16 + 4 * (k as usize % 3))));
        c = c.probe(format!("udp ::1 111 {}", short(30 + k, 0)));
        if k % 5 == 4 {
            c = c.probe(&prime);
        }
    }
    // Closing connections doesn't shrink the table.
    for k in 0..14 {
        c = c.probe(format!("close g{k}"));
    }
    c = c.probe("sleep 50").probe(format!("udp 127.0.0.1 111 {}", short(60, 4)));
    // A call that fails to decode still leaves what it copied: a credential before a
    // verifier that is too long, and on a stream, the part of a credential its record
    // holds.
    let other: Vec<u8> = [9u32, 4, 0x7778_797a, 0, 0, 2, 21, 22, 23, 24].iter().flat_map(|w| w.to_be_bytes()).collect();
    let bad = call_auth(70, PMAP, 2, 0, (AUTH_SYS, &other), (0, &[0u8; 401]));
    c = c.probe(format!("udp 127.0.0.1 111 {bad}")).probe(format!("udp 127.0.0.1 111 {}", short(71, 0)));
    // The header and a credential length of 40, then 12 of those bytes.
    let cut = call_auth(72, PMAP, 2, 0, (AUTH_SYS, &fill[..40]), (0, b""));
    let cut = format!("{}{}", &cut[..2 * 32], words(&[5, 0, 77]));
    c = c.probe("conn cut tcp 127.0.0.1 111").probe(format!("send cut {}", record(&cut))).probe("recv cut");
    c = c.probe(format!("udp 127.0.0.1 111 {}", short(73, 0)));
    check(c);
}
