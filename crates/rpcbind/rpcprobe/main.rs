//! rpcprobe: send raw requests to rpcbind and print what comes back, for the
//! differential tests. Reads a script from stdin, one command per line:
//!
//! - `udp HOST PORT HEX` - send a datagram from a fresh socket; prints `reply HEX` or
//!   `noreply` (after 500 ms).
//! - `udpfrom SRC HOST PORT HEX` - the same, from the local address SRC.
//! - `conn NAME tcp HOST PORT` / `conn NAME unix PATH` - connect; prints `connected` or
//!   `connect-failed ERRNO`.
//! - `send NAME HEX` - write the bytes; prints `sent` or `send-failed ERRNO`.
//! - `recv NAME` - read one record (up to its last fragment), or until EOF or 500 ms of
//!   silence; prints `record HEX` (each fragment's header included), `eof`, `partial HEX`
//!   or `nodata`.
//! - `close NAME`
//! - `ucall UID unix PATH HEX` - in a child running as
//!   UID: connect, send HEX, read one record; prints what `recv` would.
//! - `run CMD ARGS...` - run a program (`@T@/bin/tirpcprobe ...`), print its output.
//! - `timeout MS` - wait this long for replies from now on (default 500)
//! - `sleep MS`
//! - `shutw NAME` - shut down the writing side; prints `shut`.
//! - `reset NAME` - close with a reset (`SO_LINGER` 0); prints `reset`.
//! - `drain NAME` - read and discard until EOF, an error or silence; prints `eof`,
//!   `read-failed ERRNO` or `open`.
//! - `udpn COUNT HOST PORT HEX` - send the datagram COUNT times from one socket, each
//!   after the last one's reply or silence; prints `replies N last HEX`.
//! - `sync on`/`sync off` - from now on, before reporting `noreply`, `nodata` or `partial`, make
//!   sure the daemon has handled everything sent so far, with a call on a new local
//!   connection: the daemon accepts it in a poll round that saw everything sent
//!   before as ready, and answers it in a later one. Then look once more.
//! - `clock SECS` - set the daemon's fake clock (`$TEST_FAKETIME`).
//! - `mem KB` - the daemon's peak resident size (`VmHWM`): prints `mem ok` if under KB,
//!   else `mem over SIZE`.
//!
//! - `responder ADDR PORT UADDR PMAPPORT` - answer broadcast `CALLIT`s at ADDR:PORT
//!   from a background thread: an rpcbind (v3/v4) call gets a success with the
//!   universal address UADDR, a portmap (v2) one a success with port PMAPPORT; `-`
//!   leaves that kind unanswered. Prints `responding` or `bind-failed ERRNO`.
//!
//! - `fakesrv udp|tcp ADDR PORT REPLY...` - a fake server in a background thread: each
//!   call (a datagram, or a record on a connection) gets every REPLY in turn, a hex
//!   message with `XID` standing for the call's xid, sent as a datagram or as one
//!   record (`raw:HEX` is sent as is, with no record mark). Prints `serving` or
//!   `bind-failed ERRNO`.
//!
//! Every line printed starts with the command's line number, so output stays aligned.

use std::collections::HashMap;
use std::io::{BufRead, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// How long to wait for a reply (`timeout MS` changes it).
static WAIT_MS: AtomicU64 = AtomicU64::new(500);
/// `sync on`.
static SYNC: AtomicBool = AtomicBool::new(false);

/// Wait until the daemon has handled everything sent before (see `sync on`).
fn sync() -> bool {
    if !SYNC.load(Ordering::Relaxed) {
        return false;
    }
    // A call for a version that isn't registered: answered without being counted, and
    // on its own connection, so no transport's buffers change.
    let mut m = Vec::new();
    for w in [0x5359_4e43u32, 0, 2, 100000, 99, 0, 0, 0, 0, 0] {
        m.extend_from_slice(&u32::to_be_bytes(w));
    }
    let mut rec = (0x8000_0000u32 | m.len() as u32).to_be_bytes().to_vec();
    rec.extend_from_slice(&m);
    let mut s = UnixStream::connect("/run/rpcbind.sock").expect("sync connect");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(&rec).expect("sync send");
    let mut buf = [0u8; 64];
    assert!(s.read(&mut buf).expect("sync: no answer") > 0, "sync: closed");
    true
}

fn wait() -> Duration {
    Duration::from_millis(WAIT_MS.load(Ordering::Relaxed))
}

enum Stream {
    Tcp(TcpStream),
    Unix(UnixStream),
}

/// A connection, with bytes read past the last record.
struct Conn {
    s: Stream,
    pending: Vec<u8>,
}

impl Conn {
    fn new(s: Stream) -> Conn {
        Conn { s, pending: Vec::new() }
    }
    fn stream(&mut self) -> &mut dyn ReadWrite {
        match &mut self.s {
            Stream::Tcp(s) => s,
            Stream::Unix(s) => s,
        }
    }
    fn set_timeout(&self, d: Duration) {
        match &self.s {
            Stream::Tcp(s) => s.set_read_timeout(Some(d)).unwrap(),
            Stream::Unix(s) => s.set_read_timeout(Some(d)).unwrap(),
        }
    }
}

trait ReadWrite: Read + Write {}
impl<T: Read + Write> ReadWrite for T {}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hex")).collect()
}

fn errno(e: &std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(-1)
}

fn udp(src: Option<&str>, host: &str, port: &str, data: &[u8]) -> String {
    let dst: SocketAddr = format!("{}:{port}", if host.contains(':') { format!("[{host}]") } else { host.into() })
        .parse()
        .expect("address");
    let bind = match src {
        Some(s) if s.contains(':') => format!("[{s}]:0"),
        Some(s) => format!("{s}:0"),
        None if dst.is_ipv6() => "[::]:0".into(),
        None => "0.0.0.0:0".into(),
    };
    let sock = UdpSocket::bind(bind).expect("bind");
    sock.set_read_timeout(Some(wait())).unwrap();
    if let Err(e) = sock.send_to(data, dst) {
        return format!("send-failed {}", errno(&e));
    }
    let mut buf = vec![0u8; 65536];
    let mut r = sock.recv_from(&mut buf);
    if r.is_err() && sync() {
        sock.set_nonblocking(true).unwrap();
        r = sock.recv_from(&mut buf);
    }
    match r {
        Ok((n, from)) => format!("reply {} from {}", hex(&buf[..n]), from.ip()),
        Err(_) => "noreply".into(),
    }
}

/// `udpn`: the same datagram many times, one at a time.
fn udpn(count: usize, host: &str, port: &str, data: &[u8]) -> String {
    let dst: SocketAddr = format!("{}:{port}", if host.contains(':') { format!("[{host}]") } else { host.into() })
        .parse()
        .expect("address");
    let sock = UdpSocket::bind(if dst.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" }).expect("bind");
    sock.set_read_timeout(Some(wait())).unwrap();
    let mut buf = vec![0u8; 65536];
    let (mut replies, mut last) = (0, String::new());
    for _ in 0..count {
        if let Err(e) = sock.send_to(data, dst) {
            return format!("send-failed {}", errno(&e));
        }
        let mut r = sock.recv_from(&mut buf);
        if r.is_err() && sync() {
            sock.set_nonblocking(true).unwrap();
            r = sock.recv_from(&mut buf);
            sock.set_nonblocking(false).unwrap();
        }
        if let Ok((n, _)) = r {
            replies += 1;
            last = hex(&buf[..n]);
        }
    }
    format!("replies {replies} last {last}")
}

/// `drain`: read until the daemon closes the connection.
fn drain(c: &mut Conn) -> String {
    c.set_timeout(wait());
    c.pending.clear();
    let mut buf = [0u8; 65536];
    loop {
        match c.stream().read(&mut buf) {
            Ok(0) => return "eof".into(),
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => return "open".into(),
            Err(e) => return format!("read-failed {}", errno(&e)),
        }
    }
}

/// `mem`: the largest `VmHWM` of the processes named rpcbind.
fn mem(limit_kb: u64) -> String {
    let mut peak = 0;
    for e in std::fs::read_dir("/proc").expect("/proc").flatten() {
        let d = e.path();
        if std::fs::read_to_string(d.join("comm")).is_ok_and(|c| c.trim_end() == "rpcbind")
            && let Ok(st) = std::fs::read_to_string(d.join("status"))
            && let Some(l) = st.lines().find(|l| l.starts_with("VmHWM:"))
        {
            peak = peak.max(l.split_whitespace().nth(1).and_then(|v| v.parse().ok()).unwrap_or(0));
        }
    }
    if peak < limit_kb { "mem ok".into() } else { format!("mem over {peak} kB") }
}

fn recv(c: &mut Conn) -> String {
    c.set_timeout(wait());
    let mut synced = false;
    let mut got = std::mem::take(&mut c.pending);
    let mut buf = [0u8; 65536];
    loop {
        // A complete record: fragments up to one with the last-fragment bit.
        let mut off = 0;
        let mut done = false;
        while off + 4 <= got.len() {
            let h = u32::from_be_bytes(got[off..off + 4].try_into().unwrap());
            let len = (h & 0x7fff_ffff) as usize;
            if off + 4 + len > got.len() {
                break;
            }
            off += 4 + len;
            if h & 0x8000_0000 != 0 {
                done = true;
                break;
            }
        }
        if done {
            c.pending = got[off..].to_vec();
            return format!("record {}", hex(&got[..off]));
        }
        match c.stream().read(&mut buf) {
            Ok(0) => {
                return if got.is_empty() { "eof".into() } else { format!("partial {} eof", hex(&got)) };
            }
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                if !synced && sync() {
                    synced = true;
                    c.set_timeout(Duration::from_millis(1));
                    continue;
                }
                return if got.is_empty() { "nodata".into() } else { format!("partial {}", hex(&got)) };
            }
            Err(e) => return format!("read-failed {}", errno(&e)),
        }
    }
}

/// `ucall`: fork, become `uid`, connect, send, read one record; the child prints.
fn ucall(uid: u32, rest: &[&str]) -> String {
    let (path, data) = match rest {
        ["unix", path, data] => (*path, *data),
        _ => panic!("rpcprobe: bad ucall"),
    };
    let (r, w) = {
        let mut fds = [0; 2];
        // SAFETY: fds has room for two descriptors.
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        (fds[0], fds[1])
    };
    // SAFETY: the child only switches ids, does its I/O and exits.
    let pid = unsafe { libc::fork() };
    if pid == 0 {
        // SAFETY: plain id changes in the child.
        unsafe {
            libc::close(r);
            if libc::setgroups(0, std::ptr::null()) != 0 || libc::setgid(uid) != 0 || libc::setuid(uid) != 0 {
                libc::_exit(3);
            }
        }
        let out = match UnixStream::connect(path) {
            Err(e) => format!("connect-failed {}", errno(&e)),
            Ok(s) => {
                let mut c = Conn::new(Stream::Unix(s));
                match c.stream().write_all(&unhex(data)) {
                    Err(e) => format!("send-failed {}", errno(&e)),
                    Ok(()) => recv(&mut c),
                }
            }
        };
        // SAFETY: writing our buffer to the pipe, then exiting.
        unsafe {
            libc::write(w, out.as_ptr().cast(), out.len());
            libc::_exit(0);
        }
    }
    // SAFETY: closing our write end, reading the child's answer, reaping it.
    unsafe {
        libc::close(w);
        let mut buf = vec![0u8; 1 << 20];
        let mut got = Vec::new();
        loop {
            let n = libc::read(r, buf.as_mut_ptr().cast(), buf.len());
            if n <= 0 {
                break;
            }
            got.extend_from_slice(&buf[..n as usize]);
        }
        libc::close(r);
        let mut st = 0;
        libc::waitpid(pid, &mut st, 0);
        String::from_utf8_lossy(&got).to_string()
    }
}

/// The `responder` thread's reply to one call, if any.
fn respond(req: &[u8], uaddr: &str, port: &str) -> Option<Vec<u8>> {
    if req.len() < 24 {
        return None;
    }
    let vers = u32::from_be_bytes(req[16..20].try_into().unwrap());
    let mut r = req[..4].to_vec();
    for w in [1u32, 0, 0, 0, 0] {
        r.extend_from_slice(&w.to_be_bytes());
    }
    if vers == 2 {
        let p: u32 = port.parse().ok()?;
        r.extend_from_slice(&p.to_be_bytes());
    } else {
        if uaddr == "-" {
            return None;
        }
        r.extend_from_slice(&(uaddr.len() as u32).to_be_bytes());
        r.extend_from_slice(uaddr.as_bytes());
        r.resize(r.len().div_ceil(4) * 4, 0);
    }
    r.extend_from_slice(&0u32.to_be_bytes());
    Some(r)
}

fn responder(addr: &str, port: &str, uaddr: &str, pmapport: &str) -> String {
    let s = match UdpSocket::bind(format!("{addr}:{port}")) {
        Ok(s) => s,
        Err(e) => return format!("bind-failed {}", errno(&e)),
    };
    let (u, p) = (uaddr.to_string(), pmapport.to_string());
    std::thread::spawn(move || {
        let mut b = [0u8; 9000];
        while let Ok((n, from)) = s.recv_from(&mut b) {
            if let Some(r) = respond(&b[..n], &u, &p) {
                let _ = s.send_to(&r, from);
            }
        }
    });
    "responding".into()
}

/// A `fakesrv` reply for a call with this xid: the bytes, and whether to send them
/// without a record mark.
fn fake_reply(t: &str, xid: &[u8]) -> (Vec<u8>, bool) {
    let (raw, t) = match t.strip_prefix("raw:") {
        Some(r) => (true, r),
        None => (false, t),
    };
    (unhex(&t.replace("XID", &hex(xid))), raw)
}

fn fakesrv(proto: &str, addr: &str, port: &str, replies: &[&str]) -> String {
    let replies: Vec<String> = replies.iter().map(|s| s.to_string()).collect();
    let at = format!("{addr}:{port}");
    match proto {
        "udp" => {
            let s = match UdpSocket::bind(&at) {
                Ok(s) => s,
                Err(e) => return format!("bind-failed {}", errno(&e)),
            };
            std::thread::spawn(move || {
                let mut b = [0u8; 9000];
                while let Ok((n, from)) = s.recv_from(&mut b) {
                    if n < 4 {
                        continue;
                    }
                    for t in &replies {
                        let _ = s.send_to(&fake_reply(t, &b[..4]).0, from);
                    }
                }
            });
        }
        _ => {
            let l = match std::net::TcpListener::bind(&at) {
                Ok(l) => l,
                Err(e) => return format!("bind-failed {}", errno(&e)),
            };
            std::thread::spawn(move || {
                for c in l.incoming() {
                    let Ok(mut c) = c else { continue };
                    'conn: loop {
                        // One record: fragments up to the last.
                        let mut rec = Vec::new();
                        loop {
                            let mut h = [0u8; 4];
                            if c.read_exact(&mut h).is_err() {
                                break 'conn;
                            }
                            let h = u32::from_be_bytes(h);
                            let mut f = vec![0u8; (h & 0x7fff_ffff) as usize];
                            if c.read_exact(&mut f).is_err() {
                                break 'conn;
                            }
                            rec.extend_from_slice(&f);
                            if h & 0x8000_0000 != 0 {
                                break;
                            }
                        }
                        if rec.len() < 4 {
                            continue;
                        }
                        for t in &replies {
                            let (b, raw) = fake_reply(t, &rec[..4]);
                            let mut m =
                                if raw { Vec::new() } else { (0x8000_0000u32 | b.len() as u32).to_be_bytes().to_vec() };
                            m.extend_from_slice(&b);
                            if c.write_all(&m).is_err() {
                                break 'conn;
                            }
                        }
                    }
                }
            });
        }
    }
    "serving".into()
}

fn main() {
    let mut conns: HashMap<String, Conn> = HashMap::new();
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for (n, line) in stdin.lock().lines().enumerate() {
        let line = line.unwrap();
        let w: Vec<&str> = line.split_whitespace().collect();
        let r = match w.as_slice() {
            [] => continue,
            ["udp", host, port, data] => udp(None, host, port, &unhex(data)),
            ["udpfrom", src, host, port, data] => udp(Some(src), host, port, &unhex(data)),
            ["conn", name, "tcp", host, port] => {
                let a = if host.contains(':') { format!("[{host}]:{port}") } else { format!("{host}:{port}") };
                match TcpStream::connect(a) {
                    Ok(s) => {
                        conns.insert(name.to_string(), Conn::new(Stream::Tcp(s)));
                        "connected".into()
                    }
                    Err(e) => format!("connect-failed {}", errno(&e)),
                }
            }
            ["conn", name, "unix", path] => match UnixStream::connect(path) {
                Ok(s) => {
                    conns.insert(name.to_string(), Conn::new(Stream::Unix(s)));
                    "connected".into()
                }
                Err(e) => format!("connect-failed {}", errno(&e)),
            },
            ["send", name, data] => match conns.get_mut(*name).map(|c| c.stream().write_all(&unhex(data))) {
                Some(Ok(())) => "sent".into(),
                Some(Err(e)) => format!("send-failed {}", errno(&e)),
                None => "no-such-connection".into(),
            },
            ["recv", name] => match conns.get_mut(*name) {
                Some(c) => recv(c),
                None => "no-such-connection".into(),
            },
            ["close", name] => {
                conns.remove(*name);
                "closed".into()
            }
            ["ucall", uid, rest @ ..] => ucall(uid.parse().unwrap(), rest),
            ["run", cmd, args @ ..] => {
                let o = std::process::Command::new(cmd).args(args).output().expect("run");
                let mut t = String::from_utf8_lossy(&o.stdout).trim_end().replace('\n', " / ");
                let e = String::from_utf8_lossy(&o.stderr).trim_end().replace('\n', " / ");
                if !e.is_empty() {
                    t = format!("{t} [stderr: {e}]");
                }
                format!("{t} [{}]", o.status.code().map_or("signal".into(), |c| c.to_string()))
            }
            ["sync", on @ ("on" | "off")] => {
                SYNC.store(*on == "on", Ordering::Relaxed);
                continue;
            }
            ["timeout", ms] => {
                WAIT_MS.store(ms.parse().unwrap(), Ordering::Relaxed);
                continue;
            }
            ["shutw", name] => match conns.get(*name).map(|c| &c.s) {
                Some(Stream::Tcp(s)) => {
                    s.shutdown(std::net::Shutdown::Write).unwrap();
                    "shut".into()
                }
                Some(Stream::Unix(s)) => {
                    s.shutdown(std::net::Shutdown::Write).unwrap();
                    "shut".into()
                }
                None => "no-such-connection".into(),
            },
            ["reset", name] => {
                if let Some(Conn { s: Stream::Tcp(s), .. }) = conns.get(*name) {
                    let l = libc::linger { l_onoff: 1, l_linger: 0 };
                    // SAFETY: setting SO_LINGER on our own socket from a valid struct.
                    unsafe {
                        libc::setsockopt(
                            std::os::fd::AsRawFd::as_raw_fd(s),
                            libc::SOL_SOCKET,
                            libc::SO_LINGER,
                            (&raw const l).cast(),
                            std::mem::size_of::<libc::linger>() as libc::socklen_t,
                        );
                    }
                }
                conns.remove(*name);
                "reset".into()
            }
            ["drain", name] => match conns.get_mut(*name) {
                Some(c) => drain(c),
                None => "no-such-connection".into(),
            },
            ["udpn", count, host, port, data] => udpn(count.parse().unwrap(), host, port, &unhex(data)),
            ["clock", secs] => {
                // In place, at a fixed width: the shim has the file mapped.
                let f = std::env::var("TEST_FAKETIME").expect("TEST_FAKETIME");
                let mut fh = std::fs::OpenOptions::new().write(true).open(f).unwrap();
                fh.write_all(format!("{:020} 000000000\n", secs.parse::<i64>().unwrap()).as_bytes()).unwrap();
                continue;
            }
            ["mem", kb] => mem(kb.parse().unwrap()),
            ["responder", addr, port, uaddr, pmapport] => responder(addr, port, uaddr, pmapport),
            ["fakesrv", proto @ ("udp" | "tcp"), addr, port, replies @ ..] => fakesrv(proto, addr, port, replies),
            ["sleep", ms] => {
                std::thread::sleep(Duration::from_millis(ms.parse().unwrap()));
                continue;
            }
            _ => panic!("rpcprobe: bad command: {line}"),
        };
        writeln!(out, "{} {r}", n + 1).unwrap();
        out.flush().unwrap();
    }
}
