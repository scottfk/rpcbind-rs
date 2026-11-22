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
//!
//! Every line printed starts with the command's line number, so output stays aligned.

use std::collections::HashMap;
use std::io::{BufRead, ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use std::sync::atomic::{AtomicU64, Ordering};

/// How long to wait for a reply (`timeout MS` changes it).
static WAIT_MS: AtomicU64 = AtomicU64::new(500);

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
    match sock.recv_from(&mut buf) {
        Ok((n, from)) => format!("reply {} from {}", hex(&buf[..n]), from.ip()),
        Err(_) => "noreply".into(),
    }
}

fn recv(c: &mut Conn) -> String {
    c.set_timeout(wait());
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
            ["timeout", ms] => {
                WAIT_MS.store(ms.parse().unwrap(), Ordering::Relaxed);
                continue;
            }
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
