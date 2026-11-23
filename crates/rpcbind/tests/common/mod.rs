//! Differential test harness: run C rpcbind and rpcbind-rs in identical sandboxes, send
//! both the same requests, and compare everything observable.
//!
//! # The sandbox
//!
//! Each run gets a fresh directory `T` under `target/difftest/<case>/<impl>`, bound onto
//! `target/difftest/.root` inside the sandbox so both implementations see the same paths
//! (`@T@` in a case stands for it). The sandbox has new user, mount, network and pid
//! namespaces. Ids are mapped with the setuid `newuidmap`/`newgidmap` helpers and the
//! invoking user's subordinate ranges: id 0 is the invoking user and ids 1-65536 the first
//! subordinate ids, so the sandbox has a real root that can call `setgroups()`, and the
//! system's users (`daemon` for `-s`) exist.
//!
//! Inside, a shell runs as pid 1. It mounts `/proc` and a tmpfs on `/run`, brings up
//! `lo` (and whatever the case adds), starts the daemon from `T/bin/rpcbind`, waits
//! until it sleeps in `poll()` (or has exited), runs `rpcprobe` with the case's requests,
//! snapshots the sockets and `/run`, sends the case's signal, and waits for it to end.
//! `/dev/log` is a socket the harness reads; `/etc/netconfig` can be the case's own.
//!
//! # What is compared
//!
//! The daemon's stdout, stderr and exit status, every syslog message (time stamps and
//! pids normalized), every reply the probe got, the listening sockets, and `/run` before
//! and after the signal.
//!
//! The C program comes from `$RPCBIND_REFERENCE` (a build tree), by default
//! `../rpcbind` (tools/build-reference.sh builds it there).

#![allow(dead_code)]

use std::ffi::{CString, c_char, c_int};
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn workspace_dir() -> PathBuf {
    manifest_dir().join("../..").canonicalize().unwrap()
}

/// The C reference build tree.
pub fn reference_dir() -> PathBuf {
    std::env::var_os("RPCBIND_REFERENCE").map_or_else(|| workspace_dir().join("../rpcbind"), PathBuf::from)
}

pub fn reference_binary() -> PathBuf {
    let p = reference_dir().join("rpcbind");
    assert!(p.exists(), "no C reference at {} (run tools/build-reference.sh)", p.display());
    p
}

pub fn reference_rpcinfo() -> PathBuf {
    reference_dir().join("rpcinfo")
}

pub fn rust_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rpcbind"))
}

/// rpcinfo-rs: another package's binary, so it is looked for next to rpcbind-rs (`make
/// check` builds it first).
pub fn rust_rpcinfo() -> PathBuf {
    let p = rust_binary().with_file_name("rpcinfo");
    assert!(p.exists(), "no {} (cargo build -p rpcinfo, with the same profile)", p.display());
    p
}

pub fn probe_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_rpcprobe"))
}

/// Build a C helper once into target/difftest/.tools.
fn build_tool(name: &str, args: &[&str], src: &str, libs: &[&str]) -> PathBuf {
    let dir = workspace_dir().join("target/difftest/.tools");
    std::fs::create_dir_all(&dir).unwrap();
    let out = dir.join(name);
    let tmp = dir.join(format!("{name}.{}", std::process::id()));
    let st = Command::new("cc")
        .args(args)
        .arg("-o")
        .arg(&tmp)
        .arg(manifest_dir().join(src))
        .args(libs)
        .status()
        .expect("cc");
    assert!(st.success(), "building {name} failed");
    std::fs::rename(&tmp, &out).unwrap();
    out
}

/// tests/tirpcprobe.c, built once against the system libtirpc.
pub fn tirpcprobe_binary() -> PathBuf {
    static BUILT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BUILT
        .get_or_init(|| {
            build_tool("tirpcprobe", &["-O2", "-Wall", "-I/usr/include/tirpc"], "tests/tirpcprobe.c", &["-ltirpc"])
        })
        .clone()
}

/// tests/shim/faketime.c, the LD_PRELOAD clock.
pub fn shim() -> PathBuf {
    static BUILT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BUILT
        .get_or_init(|| build_tool("faketime.so", &["-shared", "-fPIC", "-O2"], "tests/shim/faketime.c", &["-ldl"]))
        .clone()
}

/// Where every run's `T` appears inside its sandbox.
pub fn fixed_root() -> PathBuf {
    let p = workspace_dir().join("target/difftest/.root");
    std::fs::create_dir_all(&p).unwrap();
    p
}

/// One test case.
#[derive(Debug, Clone)]
pub struct Case {
    pub name: String,
    pub args: Vec<String>,
    /// `/etc/netconfig`'s contents, if not the system's.
    pub netconfig: Option<String>,
    /// Shell lines run before the daemon starts (as root, in the sandbox).
    pub setup: Vec<String>,
    /// The probe script (see rpcprobe/main.rs).
    pub probe: Vec<String>,
    /// The signal that ends the daemon.
    pub signal: String,
    /// Extra files under T: (relative path, contents).
    pub files: Vec<(String, Vec<u8>)>,
    /// A fixed clock for the daemon (seconds), through the faketime shim.
    pub faketime: Option<i64>,
    /// The daemon's descriptor limit (`ulimit -n`), if not inherited.
    pub nofile: Option<u32>,
    /// Daemon stdout lines starting with this aren't compared.
    pub drop_stdout: Option<String>,
}

impl Case {
    pub fn new(name: &str, args: &[&str]) -> Case {
        Case {
            name: name.to_string(),
            args: args.iter().map(|s| s.to_string()).collect(),
            netconfig: None,
            setup: Vec::new(),
            probe: Vec::new(),
            signal: "TERM".into(),
            files: Vec::new(),
            faketime: None,
            nofile: None,
            drop_stdout: None,
        }
    }

    pub fn netconfig(mut self, text: &str) -> Case {
        self.netconfig = Some(text.to_string());
        self
    }

    pub fn setup(mut self, line: &str) -> Case {
        self.setup.push(line.to_string());
        self
    }

    pub fn probe(mut self, line: impl Into<String>) -> Case {
        self.probe.push(line.into());
        self
    }

    pub fn signal(mut self, sig: &str) -> Case {
        self.signal = sig.to_string();
        self
    }

    pub fn faketime(mut self, secs: i64) -> Case {
        self.faketime = Some(secs);
        self
    }

    pub fn drop_stdout(mut self, prefix: &str) -> Case {
        self.drop_stdout = Some(prefix.to_string());
        self
    }

    pub fn nofile(mut self, n: u32) -> Case {
        self.nofile = Some(n);
        self
    }

    pub fn file(mut self, path: &str, contents: &[u8]) -> Case {
        self.files.push((path.to_string(), contents.to_vec()));
        self
    }
}

/// Everything a run produced, normalized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub status: String,
    pub stdout: String,
    pub stderr: String,
    pub syslog: Vec<String>,
    pub probe: String,
    pub sockets: String,
    pub run_before: String,
    pub run_after: String,
}

fn cstr(s: impl AsRef<[u8]>) -> CString {
    CString::new(s.as_ref().to_vec()).unwrap()
}

fn path_c(p: &Path) -> CString {
    cstr(p.to_str().unwrap())
}

/// The invoking user's first subordinate id, from /etc/subuid or /etc/subgid.
fn subordinate(file: &str, name: &str, id: u32) -> u32 {
    let text = std::fs::read_to_string(file).unwrap_or_default();
    for line in text.lines() {
        let f: Vec<&str> = line.split(':').collect();
        if f.len() == 3 && (f[0] == name || f[0] == id.to_string()) && f[2].parse::<u32>().unwrap_or(0) >= 65536 {
            return f[1].parse().unwrap();
        }
    }
    panic!("no subordinate range of 65536 ids for {name} in {file}: the sandbox needs one");
}

fn pipe() -> (c_int, c_int) {
    let mut fds = [0 as c_int; 2];
    // SAFETY: fds has room for two ints.
    assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
    (fds[0], fds[1])
}

/// fork(); the child enters new user, mount, network and pid namespaces, makes the
/// binds, and forks pid 1 of the new pid namespace, which execs `sh -c script`. The
/// child exits with pid 1's status. Returns the child's pid.
fn spawn_in_sandbox(binds: &[(CString, CString)], script: &str, stdio: [c_int; 3]) -> u32 {
    // SAFETY: getuid/getgid have no preconditions.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let name = std::env::var("USER").unwrap_or_default();
    let subuid = subordinate("/etc/subuid", &name, uid);
    let subgid = subordinate("/etc/subgid", &name, gid);

    let sh = cstr("/bin/sh");
    let argv_s = [cstr("sh"), cstr("-c"), cstr(script)];
    let mut argv: Vec<*const c_char> = argv_s.iter().map(|a| a.as_ptr()).collect();
    argv.push(std::ptr::null());
    let envp_s = [cstr("PATH=/usr/sbin:/usr/bin:/sbin:/bin"), cstr("LC_ALL=C")];
    let mut envp: Vec<*const c_char> = envp_s.iter().map(|a| a.as_ptr()).collect();
    envp.push(std::ptr::null());
    let (up_r, up_w) = pipe();
    let (go_r, go_w) = pipe();
    let root = cstr("/");

    // SAFETY: between fork and exec the child only makes async-signal-safe system calls
    // on memory prepared above, then execs or _exits.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0, "fork failed");
    if pid == 0 {
        // SAFETY: as above.
        unsafe {
            libc::close(go_w);
            libc::close(up_r);
            let flags = libc::CLONE_NEWUSER | libc::CLONE_NEWNS | libc::CLONE_NEWNET | libc::CLONE_NEWPID;
            if libc::unshare(flags) != 0 {
                libc::_exit(120);
            }
            libc::write(up_w, b"u".as_ptr().cast(), 1);
            let mut b = [0u8; 1];
            if libc::read(go_r, b.as_mut_ptr().cast(), 1) != 1 {
                libc::_exit(121);
            }
            let none = std::ptr::null::<c_char>();
            if libc::mount(none, root.as_ptr(), none, libc::MS_REC | libc::MS_PRIVATE, std::ptr::null()) != 0 {
                libc::_exit(122);
            }
            for (src, dst) in binds {
                if libc::mount(src.as_ptr(), dst.as_ptr(), none, libc::MS_BIND | libc::MS_REC, std::ptr::null()) != 0 {
                    libc::_exit(123);
                }
            }
            if libc::setgid(0) != 0 || libc::setuid(0) != 0 {
                libc::_exit(124);
            }
            let init = libc::fork();
            if init < 0 {
                libc::_exit(125);
            }
            if init == 0 {
                for (i, fd) in stdio.iter().enumerate() {
                    libc::dup2(*fd, i as c_int);
                }
                libc::execve(sh.as_ptr(), argv.as_ptr(), envp.as_ptr());
                libc::_exit(127);
            }
            // up_w is close-on-exec only for the exec'd child; close ours.
            libc::close(up_w);
            let mut st: c_int = 0;
            libc::waitpid(init, &mut st, 0);
            libc::_exit(if libc::WIFEXITED(st) { libc::WEXITSTATUS(st) } else { 126 });
        }
    }
    // SAFETY: closing our copies of the child's ends.
    unsafe {
        libc::close(go_r);
        libc::close(up_w);
    }
    let mut b = [0u8; 1];
    // SAFETY: reading one byte into b.
    let n = unsafe { libc::read(up_r, b.as_mut_ptr().cast(), 1) };
    assert_eq!(n, 1, "sandbox child failed before unshare");
    for (tool, host, sub) in [("newuidmap", uid, subuid), ("newgidmap", gid, subgid)] {
        let st = Command::new(tool)
            .arg(pid.to_string())
            .args(["0", &host.to_string(), "1", "1", &sub.to_string(), "65536"])
            .status()
            .unwrap_or_else(|e| panic!("{tool}: {e}"));
        assert!(st.success(), "{tool} failed");
    }
    // SAFETY: writing one byte from a static buffer, then closing.
    unsafe {
        libc::write(go_w, b"g".as_ptr().cast(), 1);
        libc::close(go_w);
        libc::close(up_r);
    }
    pid as u32
}

/// waitpid with a timeout; the status as text.
fn wait(pid: u32, timeout: Duration) -> String {
    let deadline = Instant::now() + timeout;
    loop {
        let mut st: c_int = 0;
        // SAFETY: st is a valid out-pointer.
        let r = unsafe { libc::waitpid(pid as i32, &mut st, libc::WNOHANG) };
        if r == pid as i32 {
            return if libc::WIFEXITED(st) { format!("exit {}", libc::WEXITSTATUS(st)) } else { "killed".into() };
        }
        if Instant::now() > deadline {
            // SAFETY: killing and reaping our own child (the pid namespace goes with it).
            unsafe {
                libc::kill(pid as i32, libc::SIGKILL);
                libc::waitpid(pid as i32, &mut st, 0);
            }
            return "timeout".into();
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Shell-quote a word.
fn q(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// The pid-1 script.
fn script(case: &Case, r: &Path) -> String {
    let r = r.display();
    let args: Vec<String> = case.args.iter().map(|a| q(a)).collect();
    let mut s = format!(
        r#"set -u
R={r}
mount -t proc proc /proc || exit 90
mount -t tmpfs -o mode=755 tmpfs /run || exit 91
ip link set lo up || exit 92
"#
    );
    for l in &case.setup {
        s.push_str(l);
        s.push('\n');
    }
    s.push_str(&format!(
        r#"
pids() {{ for p in /proc/[0-9]*; do [ "$(cat $p/comm 2>/dev/null)" = rpcbind ] && echo ${{p#/proc/}}; done; }}
({nofile}{env}exec "$R/bin/rpcbind" {args}) >"$R/out/stdout" 2>"$R/out/stderr" &
DPID=$!
# Ready: a daemon process asleep in poll(), or none left (it exited).
i=0
while [ $i -lt 300 ]; do
  ready=
  for p in $(pids); do
    case "$(cat /proc/$p/wchan 2>/dev/null)" in *poll*) ready=1;; esac
  done
  [ -n "$ready" ] && break
  [ -z "$(pids)" ] && break
  sleep 0.01; i=$((i+1))
done
[ $i -ge 300 ] && echo "not ready" >"$R/out/notready"
TEST_FAKETIME="$R/faketime" "$R/bin/rpcprobe" <"$R/probe.in" >"$R/out/probe" 2>&1
sleep 0.05
cat /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6 /proc/net/unix >"$R/out/sockets" 2>/dev/null
ls -ln /run | tail -n +2 | awk '{{print $1, $3, $4, $5, $NF}}' >"$R/out/run_before"
for p in $(pids); do kill -{sig} $p; done
# The launched process: ended by the signal, or still running (an ignored signal).
j=0
while kill -0 $DPID 2>/dev/null && [ "$(cat /proc/$DPID/stat 2>/dev/null | cut -d' ' -f3)" != Z ] && [ $j -lt 100 ]; do sleep 0.01; j=$((j+1)); done
if [ $j -ge 100 ]; then
  echo "still running" >"$R/out/status"
  kill -KILL $DPID; wait $DPID
else
  wait $DPID
  echo "exit $?" >"$R/out/status"
fi
# A daemon()ized child.
j=0
while [ -n "$(pids)" ] && [ $j -lt 100 ]; do sleep 0.01; j=$((j+1)); done
if [ -n "$(pids)" ]; then
  echo "daemon still running" >>"$R/out/status"
  for p in $(pids); do kill -KILL $p; done
fi
ls -ln /run | tail -n +2 | awk '{{print $1, $3, $4, $5, $NF}}' >"$R/out/run_after"
exit 0
"#,
        args = args.join(" "),
        sig = case.signal,
        nofile = case.nofile.map_or(String::new(), |n| format!("ulimit -n {n} && ")),
        env = if case.faketime.is_some() { "LD_PRELOAD=\"$R/bin/faketime.so\" TEST_FAKETIME=\"$R/faketime\" " } else { "" }
    ));
    s
}

/// Remove a previous run's directory.
fn clean(t: &Path) {
    if t.exists() {
        std::fs::remove_dir_all(t).unwrap_or_else(|e| panic!("can't clean {}: {e}", t.display()));
    }
}

/// `/proc/net/{tcp,udp}[6]` and `unix` as readable, sorted lines.
fn render_sockets(raw: &str) -> String {
    let mut out = Vec::new();
    let mut section = "";
    for line in raw.lines() {
        if line.trim_start().starts_with("sl") {
            section = "inet";
            continue;
        }
        if line.starts_with("Num") {
            section = "unix";
            continue;
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        match section {
            "inet" if f.len() > 3 => {
                let (addr, port) = f[1].split_once(':').unwrap();
                let port = u16::from_str_radix(port, 16).unwrap();
                let state = f[3];
                let a = if addr.len() == 8 {
                    let v = u32::from_str_radix(addr, 16).unwrap().to_le_bytes();
                    format!("{}.{}.{}.{}", v[0], v[1], v[2], v[3])
                } else {
                    let mut b = [0u8; 16];
                    for i in 0..4 {
                        let w = u32::from_str_radix(&addr[8 * i..8 * i + 8], 16).unwrap().to_le_bytes();
                        b[4 * i..4 * i + 4].copy_from_slice(&w);
                    }
                    std::net::Ipv6Addr::from(b).to_string()
                };
                // Only rpcbind's own bound sockets (unconnected UDP, listening TCP):
                // connections and TIME_WAIT leftovers depend on timing.
                if state == "07" || state == "0A" {
                    out.push(format!("inet {a} {port} st={state}"));
                }
            }
            "unix" if f.len() >= 8 && f[5] == "01" => {
                out.push(format!("unix type={} st={} {}", f[4], f[5], f[7]));
            }
            _ => {}
        }
    }
    out.sort();
    out.join("\n")
}

/// A syslog datagram, normalized: `<pri>` kept, the time stamp dropped, `[pid]` replaced.
fn render_syslog(msg: &[u8]) -> String {
    let s = String::from_utf8_lossy(msg).to_string();
    let Some(end) = s.find('>') else { return s };
    let (pri, rest) = s.split_at(end + 1);
    // "Mmm dd hh:mm:ss " is 16 bytes.
    let rest = rest.get(16..).unwrap_or(rest);
    let rest = match (rest.find('['), rest.find("]: ")) {
        (Some(a), Some(b)) if a < b => format!("{}[@PID@]{}", &rest[..a], &rest[b + 1..]),
        _ => rest.to_string(),
    };
    format!("{pri}{rest}")
}

fn read(t: &Path, f: &str) -> String {
    String::from_utf8_lossy(&std::fs::read(t.join(f)).unwrap_or_default()).to_string()
}

/// Run one implementation, with C rpcinfo in `T/bin`.
pub fn run(case: &Case, bin: &Path, label: &str) -> Outcome {
    run_with(case, bin, reference_rpcinfo().exists().then(reference_rpcinfo).as_deref(), label)
}

/// Run one daemon, with `rpcinfo` (if any) in `T/bin`.
pub fn run_with(case: &Case, bin: &Path, rpcinfo: Option<&Path>, label: &str) -> Outcome {
    let base = workspace_dir().join("target/difftest").join(&case.name);
    let t = base.join(label);
    clean(&t);
    for d in ["bin", "out"] {
        std::fs::create_dir_all(t.join(d)).unwrap();
    }
    // Hard links, not copies: a copy is open for writing for a moment, and a parallel
    // test's fork() in that moment makes exec fail with ETXTBSY.
    let link = |src: &Path, dst: &str| {
        let d = t.join(dst);
        if std::fs::hard_link(src, &d).is_err() {
            std::fs::copy(src, &d).unwrap();
        }
    };
    link(bin, "bin/rpcbind");
    link(&probe_binary(), "bin/rpcprobe");
    link(&tirpcprobe_binary(), "bin/tirpcprobe");
    if let Some(secs) = case.faketime {
        link(&shim(), "bin/faketime.so");
        std::fs::write(t.join("faketime"), format!("{secs:020} 000000000\n")).unwrap();
    }
    if let Some(p) = rpcinfo {
        link(p, "bin/rpcinfo");
    }
    let root = fixed_root();
    let probe: Vec<String> = case.probe.iter().map(|l| l.replace("@T@", root.to_str().unwrap())).collect();
    std::fs::write(t.join("probe.in"), probe.join("\n") + "\n").unwrap();
    for (p, c) in &case.files {
        let f = t.join(p);
        std::fs::create_dir_all(f.parent().unwrap()).unwrap();
        std::fs::write(f, c).unwrap();
    }
    let mut binds = vec![(path_c(&t), path_c(&root))];
    if let Some(nc) = &case.netconfig {
        std::fs::write(t.join("netconfig"), nc).unwrap();
        binds.push((path_c(&t.join("netconfig")), cstr("/etc/netconfig")));
    }
    let devlog = t.join("devlog");
    let log = UnixDatagram::bind(&devlog).unwrap();
    log.set_nonblocking(true).unwrap();
    binds.push((path_c(&devlog), cstr("/dev/log")));

    let err = std::fs::File::create(t.join("out/sandbox")).unwrap();
    let null = std::fs::File::open("/dev/null").unwrap();
    use std::os::fd::AsRawFd;
    let pid = spawn_in_sandbox(&binds, &script(case, &root), [null.as_raw_fd(), err.as_raw_fd(), err.as_raw_fd()]);
    let st = wait(pid, Duration::from_secs(120));
    assert_eq!(st, "exit 0", "{}/{label}: sandbox {st}:\n{}", case.name, read(&t, "out/sandbox"));
    assert!(!t.join("out/notready").exists(), "{}/{label}: the daemon never became ready", case.name);

    let mut syslog = Vec::new();
    let mut buf = vec![0u8; 65536];
    while let Ok(n) = log.recv(&mut buf) {
        syslog.push(render_syslog(&buf[..n]));
    }
    let fix = |s: String| s.replace(root.to_str().unwrap(), "@T@");
    Outcome {
        status: read(&t, "out/status").trim().to_string(),
        stdout: {
            let out = fix(read(&t, "out/stdout"));
            match &case.drop_stdout {
                Some(p) => out.split_inclusive('\n').filter(|l| !l.starts_with(p.as_str())).collect(),
                None => out,
            }
        },
        stderr: fix(read(&t, "out/stderr")),
        syslog: syslog.into_iter().map(fix).collect(),
        probe: read(&t, "out/probe"),
        sockets: render_sockets(&read(&t, "out/sockets")),
        run_before: read(&t, "out/run_before"),
        run_after: read(&t, "out/run_after"),
    }
}

/// Run both and compare; returns the C outcome.
pub fn check(case: Case) -> Outcome {
    let c = run(&case, &reference_binary(), "c");
    let r = run(&case, &rust_binary(), "r");
    if std::env::var_os("RPCBIND_DIFF_SHOW").is_some() {
        eprintln!("=== {} ===\n{c:#?}", case.name);
    }
    compare(&case.name, &c, &r, "Rust");
    c
}

/// Run C rpcbind with C rpcinfo, C rpcbind with rpcinfo-rs, and rpcbind-rs with
/// rpcinfo-rs, and compare the last two with the first; returns the C outcome.
pub fn check_rpcinfo(case: Case) -> Outcome {
    let (cb, rb) = (reference_binary(), rust_binary());
    let (ci, ri) = (reference_rpcinfo(), rust_rpcinfo());
    assert!(ci.exists(), "no C rpcinfo at {}", ci.display());
    let c = run_with(&case, &cb, Some(&ci), "c");
    let cr = run_with(&case, &cb, Some(&ri), "cr");
    let r = run_with(&case, &rb, Some(&ri), "r");
    if std::env::var_os("RPCBIND_DIFF_SHOW").is_some() {
        eprintln!("=== {} ===\n{c:#?}", case.name);
    }
    compare(&case.name, &c, &cr, "C rpcbind + Rust rpcinfo");
    compare(&case.name, &c, &r, "Rust");
    c
}

fn compare(name: &str, c: &Outcome, r: &Outcome, label: &str) {
    if c != r {
        let mut msg = format!("case {name} differs:\n");
        macro_rules! field {
            ($f:ident) => {
                if c.$f != r.$f {
                    msg.push_str(&format!("--- {}\n  C:    {:?}\n  {label}: {:?}\n", stringify!($f), c.$f, r.$f));
                }
            };
        }
        field!(status);
        field!(stdout);
        field!(stderr);
        field!(syslog);
        field!(probe);
        field!(sockets);
        field!(run_before);
        field!(run_after);
        panic!("{msg}");
    }
}

/// `struct rpcb` arguments.
pub fn rpcb(prog: u32, vers: u32, netid: &str, addr: &str, owner: &str) -> String {
    format!(
        "{}{}{}{}",
        words(&[prog, vers]),
        opaque(netid.as_bytes()),
        opaque(addr.as_bytes()),
        opaque(owner.as_bytes())
    )
}

/// `struct pmap` arguments.
pub fn pmap(prog: u32, vers: u32, prot: u32, port: u32) -> String {
    words(&[prog, vers, prot, port])
}

/// A probe command sending `msg` on a fresh connection to the local socket, then
/// reading the reply.
pub fn local(c: Case, name: &str, msg: &str) -> Case {
    c.probe(format!("conn {name} unix /run/rpcbind.sock"))
        .probe(format!("send {name} {}", record(msg)))
        .probe(format!("recv {name}"))
        .probe(format!("close {name}"))
}

pub fn tcp(c: Case, name: &str, host: &str, msg: &str) -> Case {
    c.probe(format!("conn {name} tcp {host} 111"))
        .probe(format!("send {name} {}", record(msg)))
        .probe(format!("recv {name}"))
        .probe(format!("close {name}"))
}

/// Non-loopback interfaces: a netkit pair, with IPv4 and IPv6 addresses on both ends.
pub fn interfaces(c: Case) -> Case {
    c.setup("ip link add n0 type netkit peer name n1 || exit 93")
        .setup("ip link set n0 up; ip link set n1 up")
        .setup("ip addr add 192.168.50.1/24 dev n0; ip addr add 192.168.60.1/24 dev n1")
        .setup("ip addr add fd00:50::1/64 dev n0 nodad; ip addr add fd00:60::1/64 dev n1 nodad")
        .setup("ip addr add 10.9.0.1/16 dev lo")
}

// ---------------------------------------------------------------------------
// building requests

/// Hex of big-endian words.
pub fn words(ws: &[u32]) -> String {
    ws.iter().map(|w| format!("{w:08x}")).collect()
}

/// Hex of raw bytes.
pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// XDR opaque: length, bytes, padding.
pub fn opaque(b: &[u8]) -> String {
    let mut v = (b.len() as u32).to_be_bytes().to_vec();
    v.extend_from_slice(b);
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
    hex(&v)
}

/// A call message (xid, prog, vers, proc) with AUTH_NONE credentials and verifier, then
/// `args` (hex).
pub fn call(xid: u32, prog: u32, vers: u32, proc_: u32, args: &str) -> String {
    format!("{}{args}", words(&[xid, 0, 2, prog, vers, proc_, 0, 0, 0, 0]))
}

/// A call with the given credential and verifier (flavor, body).
pub fn call_auth(xid: u32, prog: u32, vers: u32, proc_: u32, cred: (u32, &[u8]), verf: (u32, &[u8])) -> String {
    format!(
        "{}{}{}{}{}",
        words(&[xid, 0, 2, prog, vers, proc_]),
        words(&[cred.0]),
        opaque(cred.1),
        words(&[verf.0]),
        opaque(verf.1)
    )
}

/// An `AUTH_SYS` credential body.
pub fn auth_sys(stamp: u32, machine: &[u8], uid: u32, gid: u32, gids: &[u32]) -> Vec<u8> {
    let mut v = stamp.to_be_bytes().to_vec();
    v.extend_from_slice(&(machine.len() as u32).to_be_bytes());
    v.extend_from_slice(machine);
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
    for w in [uid, gid, gids.len() as u32] {
        v.extend_from_slice(&w.to_be_bytes());
    }
    for g in gids {
        v.extend_from_slice(&g.to_be_bytes());
    }
    v
}

/// A record-marked message: one last fragment.
pub fn record(msg_hex: &str) -> String {
    format!("{:08x}{msg_hex}", 0x8000_0000u32 | (msg_hex.len() / 2) as u32)
}

/// A fragment without the last-fragment bit.
pub fn fragment(msg_hex: &str) -> String {
    format!("{:08x}{msg_hex}", (msg_hex.len() / 2) as u32)
}
