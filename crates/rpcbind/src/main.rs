//! `rpcbind.c`: the universal addresses to RPC program number mapper.
//!
//! Built as Gentoo builds rpcbind 1.2.8 with every USE flag off: `PORTMAP`, `INET6` and
//! `CHECK_LOCAL` on; no warm starts, remote calls, libwrap, systemd or `RPCBIND_DEBUG`;
//! user `root`, NSS modules `files`, state directory `/run/rpcbind`.

mod check_bound;
mod pmap_svc;
mod rpcb_stat;
mod rpcb_svc;
mod rpcb_svc_4;
mod rpcb_svc_com;
mod security;
mod util;
mod xlog;

use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};

use tirpc::addr::{self, Netbuf};
use tirpc::netconfig::{NC_TPI_CLTS, NC_TPI_COTS, NC_TPI_COTS_ORD, NC_VISIBLE, Netconfig, NetconfigDb};
use tirpc::rpcb_prot::{Pmap, Rpcb};
use tirpc::svc::{self, RPC_MAXDATASIZE, Request, Service, Svc};
use tirpc::sys;

use check_bound::FdList;
use rpcb_stat::Stats;
use security::Access;
use xlog::Xlog;

const PACKAGE_STRING: &str = "rpcbind 1.2.8";
const RPCBIND_STATEDIR: &str = "/run/rpcbind";
const RPCBIND_USER: &[u8] = b"root";
const NSS_MODULES: &[u8] = b"files";
/// `RUN_AS`: the user for `-s`.
const RUN_AS: &[u8] = b"daemon";
/// `RPCBINDDLOCK`.
const RPCBINDDLOCK: &[u8] = b"/run/rpcbind.lock";
/// libtirpc's `_PATH_RPCBINDSOCK`.
const PATH_RPCBINDSOCK: &[u8] = b"/run/rpcbind.sock";

const PMAPPROG: u32 = 100000;
const PMAPVERS: u32 = 2;
const PMAPPORT: u32 = 111;
const RPCBPROG: u32 = 100000;
const RPCBVERS: u32 = 3;
const RPCBVERS4: u32 = 4;

/// Dispatch routine numbers for `svc_reg()`/`svc_register()`.
const DISPATCH_PMAP: u32 = 2;
const DISPATCH_RPCB_3: u32 = 3;
const DISPATCH_RPCB_4: u32 = 4;

/// `rpcbindlockfd` and `createdsocket`, for the signal handler.
static LOCKFD: AtomicI32 = AtomicI32::new(-1);
static CREATEDSOCKET: AtomicBool = AtomicBool::new(false);

/// rpcbind's globals.
#[derive(Debug, Default)]
pub struct Rpcbind {
    pub debugging: i32,
    pub doabort: bool,
    pub dofork: bool,
    pub runasdaemon: bool,
    pub access: Access,
    /// `hosts`: `-h` addresses. An entry can become `None`: `"*"` is replaced by NULL
    /// in place.
    pub hosts: Vec<Option<Vec<u8>>>,
    /// `list_rbl` (newest first).
    pub list_rbl: Vec<Rpcb>,
    /// `list_pml` (newest first).
    pub list_pml: Vec<Pmap>,
    pub udptrans: Option<Vec<u8>>,
    pub tcptrans: Option<Vec<u8>>,
    pub fdlist: FdList,
    pub stats: Stats,
    pub xlog: Xlog,
    pub db: NetconfigDb,
    pub local: util::LocalAddrs,
}

impl Service for Rpcbind {
    fn dispatch(&mut self, dispatch: u32, req: &mut Request<'_>) {
        match dispatch {
            DISPATCH_PMAP => pmap_svc::pmap_service(self, req),
            DISPATCH_RPCB_3 => rpcb_svc::rpcb_service_3(self, req),
            DISPATCH_RPCB_4 => rpcb_svc_4::rpcb_service_4(self, req),
            _ => unreachable!(),
        }
    }
}

/// `err(1, "%s", what)`.
fn err(what: &[u8]) -> ! {
    let e = sys::errno();
    let mut m = sys::progname();
    m.extend_from_slice(b": ");
    m.extend_from_slice(what);
    m.extend_from_slice(b": ");
    m.extend_from_slice(&sys::strerror(e));
    m.push(b'\n');
    sys::c_stderr(&m);
    sys::exit(1);
}

/// `errx(1, "%s", what)`.
fn errx(what: &[u8]) -> ! {
    let mut m = sys::progname();
    m.extend_from_slice(b": ");
    m.extend_from_slice(what);
    m.push(b'\n');
    sys::c_stderr(&m);
    sys::exit(1);
}

/// `syslog(pri, fmt...)` with `%m` already expanded by the caller where used.
fn syslog(pri: i32, msg: impl AsRef<[u8]>) {
    sys::syslog(pri, msg.as_ref());
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// `version()`.
fn version() {
    let s = format!(
        "{PACKAGE_STRING}\ndebug: no, libset debug: no, libwrap: no, nss modules: {}, remote calls: no, \
         statedir: {RPCBIND_STATEDIR}, systemd: no, user: {}, warm start: no\n",
        String::from_utf8_lossy(NSS_MODULES),
        String::from_utf8_lossy(RPCBIND_USER)
    );
    sys::c_stderr(s.as_bytes());
}

/// `parseargs()`.
fn parseargs(rb: &mut Rpcbind, args: &mut sys::Args) {
    rb.access.oldstyle_local = true;
    loop {
        let (c, optarg) = args.getopt(c"adfh:ilsvw");
        if c == -1 {
            break;
        }
        match c as u8 {
            b'a' => rb.doabort = true,
            b'd' => rb.debugging += 1,
            b'h' => rb.hosts.push(Some(optarg.unwrap_or_default())),
            b'i' => rb.access.insecure = true,
            b'l' => rb.access.verboselog = true,
            b's' => rb.runasdaemon = true,
            b'f' => rb.dofork = false,
            b'v' => {
                version();
                sys::exit(0);
            }
            // 'w' is in the option string, but WARMSTART isn't compiled in.
            _ => {
                sys::c_stderr(b"usage: rpcbind [-adfhilsvw]\n");
                sys::exit(1);
            }
        }
    }
    if rb.doabort && rb.debugging == 0 {
        sys::c_stderr(b"-a (abort) specified without -d (debugging) -- ignored.\n");
        rb.doabort = false;
    }
}

/// `rpcbind_abort()`.
pub fn rpcbind_abort() -> ! {
    std::process::abort();
}

/// `terminate()`: the `SIGINT`/`SIGTERM`/`SIGQUIT` handler.
extern "C" fn terminate(_sig: i32) {
    sys::close(LOCKFD.load(Ordering::Relaxed));
    if CREATEDSOCKET.load(Ordering::Relaxed) {
        sys::unlink(PATH_RPCBINDSOCK);
    }
    sys::unlink(RPCBINDDLOCK);
    sys::exit(0);
}

/// `reap()`: the `SIGCHLD` handler.
extern "C" fn reap(_sig: i32) {
    let e = sys::errno();
    while sys::wait_nohang() > 0 {}
    sys::set_errno(e);
}

/// `S_IXUSR|S_IXGRP|S_IXOTH`.
const UMASK_X: u32 = 0o111;

/// A `sockaddr_un` for `path`, and its `SUN_LEN()`.
fn sockaddr_un(path: &[u8]) -> Netbuf {
    let mut b = vec![0u8; size_of::<libc::sockaddr_un>()];
    b[0..2].copy_from_slice(&(libc::AF_LOCAL as u16).to_ne_bytes());
    b[2..2 + path.len()].copy_from_slice(path);
    Netbuf { buf: b, len: 2 + path.len() }
}

impl Rpcbind {
    /// `rbllist_add()`.
    fn rbllist_add(&mut self, prog: u32, vers: u32, nconf: &Netconfig, addr: &Netbuf) {
        self.list_rbl.insert(
            0,
            Rpcb {
                prog,
                vers,
                netid: nconf.netid.clone(),
                // taddr2uaddr() can fail (NULL), which DUMP would then encode; it
                // doesn't for the addresses rpcbind binds.
                addr: addr::taddr2uaddr(nconf, addr).unwrap_or_default(),
                owner: b"superuser".to_vec(),
            },
        );
    }

    /// `init_transport()`: set up one netconfig entry. 0 on success.
    fn init_transport(&mut self, svc: &mut Svc, nconf: &Netconfig) -> i32 {
        if nconf.semantics != NC_TPI_CLTS && nconf.semantics != NC_TPI_COTS && nconf.semantics != NC_TPI_COTS_ORD {
            return 1; // not my type
        }
        let Some(mut si) = addr::nconf2sockinfo(nconf) else {
            syslog(libc::LOG_ERR, cat(&[b"cannot get information for ", &nconf.netid]));
            return 1;
        };
        let netid = nconf.netid.clone();
        let local = netid == b"local" || netid == b"unix";
        let mut taddr = Netbuf::default();
        let mut sa = Netbuf::default();
        if local {
            sys::unlink(PATH_RPCBINDSOCK);
            CREATEDSOCKET.store(true, Ordering::Relaxed);
            sa = sockaddr_un(PATH_RPCBINDSOCK);
        }
        let (h_family, h_socktype, h_proto) = (si.af, si.socktype, si.proto);
        let fd;
        let my_xprt;
        if nconf.semantics == NC_TPI_CLTS {
            // If no hosts were specified, just bind to INADDR_ANY. Otherwise make sure
            // 127.0.0.1 (or ::1) is added to the list.
            let nhosts = self.hosts.len();
            let mut nhostsbak = nhosts + 1;
            let mut hosts = self.hosts.clone();
            hosts.push(None);
            if nhostsbak == 1 {
                hosts[0] = Some(b"*".to_vec());
            } else if h_family == libc::AF_INET {
                hosts[nhostsbak - 1] = Some(b"127.0.0.1".to_vec());
            } else if h_family == libc::AF_INET6 {
                hosts[nhostsbak - 1] = Some(b"::1".to_vec());
            } else {
                return 1;
            }
            let mut checkbind = 0;
            let mut last = None;
            let mut last_fd = -1;
            while nhostsbak > 0 {
                nhostsbak -= 1;
                let f = svc::nconf2fd(nconf);
                if f < 0 {
                    syslog(libc::LOG_ERR, cat(&[b"cannot create socket for ", &netid]));
                    self.hosts = hosts[..nhosts].to_vec();
                    return 1;
                }
                let mut flags = libc::AI_PASSIVE;
                // QUIRK: a NULL left by an earlier "*" (from -h '*') is passed to
                // inet_pton(), which crashes C rpcbind.
                let Some(host) = hosts[nhostsbak].clone() else {
                    null_deref_crash();
                };
                // Skip (leaking the socket) an address of the other family.
                match h_family {
                    libc::AF_INET => {
                        if sys::pton(libc::AF_INET, &host).is_some() {
                            flags |= libc::AI_NUMERICHOST;
                        } else if sys::pton(libc::AF_INET6, &host).is_some() {
                            continue;
                        }
                    }
                    libc::AF_INET6 => {
                        if sys::pton(libc::AF_INET6, &host).is_some() {
                            flags |= libc::AI_NUMERICHOST;
                        } else if sys::pton(libc::AF_INET, &host).is_some() {
                            continue;
                        }
                    }
                    _ => {}
                }
                if host == b"*" {
                    hosts[nhostsbak] = None;
                }
                let h = hosts[nhostsbak].clone();
                let res = sys::getaddrinfo(h.as_deref(), b"rpcbind", flags, h_family, h_socktype, h_proto)
                    .or_else(|_| sys::getaddrinfo(h.as_deref(), b"portmapper", flags, h_family, h_socktype, h_proto));
                let res = match res {
                    Ok(r) => r,
                    Err(code) => {
                        syslog(
                            libc::LOG_ERR,
                            cat(&[b"cannot get local address for ", &netid, b": ", &sys::gai_strerror(code)]),
                        );
                        continue;
                    }
                };
                let oldmask = sys::umask(UMASK_X);
                if sys::bind(f, &res.addr, res.addr.len()) != 0 {
                    let e = sys::strerror(sys::errno());
                    let shown: &[u8] = h.as_deref().unwrap_or(b"*");
                    // QUIRK: the umask isn't restored, and the socket is leaked.
                    syslog(libc::LOG_ERR, cat(&[b"cannot bind ", shown, b" on ", &netid, b": ", &e]));
                    continue;
                }
                checkbind += 1;
                sys::umask(oldmask);
                taddr = Netbuf::from_bytes(&res.addr);
                match svc.svc_tli_create(f, Some(nconf), Some(&taddr), RPC_MAXDATASIZE, RPC_MAXDATASIZE) {
                    Some(x) => {
                        last = Some(x);
                        last_fd = f;
                    }
                    None => {
                        syslog(libc::LOG_ERR, cat(&[&netid, b": could not create service"]));
                        self.hosts = hosts[..nhosts].to_vec();
                        sys::close(f);
                        return 1;
                    }
                }
            }
            // hosts[] is the program's array, modified in place ("*" -> NULL); the slot
            // added for the loopback address is reallocated each time.
            self.hosts = hosts[..nhosts].to_vec();
            if checkbind == 0 {
                return 1;
            }
            fd = last_fd;
            my_xprt = last;
        } else {
            let f = svc::nconf2fd(nconf);
            if f < 0 {
                syslog(libc::LOG_ERR, cat(&[b"cannot create socket for ", &netid]));
                return 1;
            }
            if !local {
                let res =
                    sys::getaddrinfo(None, b"rpcbind", libc::AI_PASSIVE, h_family, h_socktype, h_proto).or_else(|_| {
                        sys::getaddrinfo(None, b"portmapper", libc::AI_PASSIVE, h_family, h_socktype, h_proto)
                    });
                match res {
                    Ok(r) => sa = Netbuf::from_bytes(&r.addr),
                    Err(code) => {
                        let m = cat(&[b"cannot get local address for ", &netid, b": ", &sys::gai_strerror(code)]);
                        sys::c_stdout(&m); // printf() without a newline
                        syslog(libc::LOG_ERR, &m);
                        return 1;
                    }
                }
            }
            let oldmask = sys::umask(UMASK_X);
            if let Some(s2) = svc::fd2sockinfo(f) {
                si = s2;
            }
            if sys::setsockopt_int(f, libc::SOL_SOCKET, libc::SO_REUSEADDR, 1) != 0 {
                syslog(libc::LOG_ERR, cat(&[b"cannot set SO_REUSEADDR on ", &netid]));
                return 1;
            }
            if sys::bind(f, &sa.buf, sa.len) < 0 {
                let e = sys::strerror(sys::errno());
                syslog(libc::LOG_ERR, cat(&[b"cannot bind ", &netid, b": ", &e]));
                return 1;
            }
            sys::umask(oldmask);
            taddr = sa.clone();
            sys::listen(f, libc::SOMAXCONN);
            match svc.svc_tli_create(f, Some(nconf), Some(&taddr), RPC_MAXDATASIZE, RPC_MAXDATASIZE) {
                Some(x) => my_xprt = Some(x),
                None => {
                    syslog(libc::LOG_ERR, cat(&[&netid, b": could not create service"]));
                    sys::close(f);
                    return 1;
                }
            }
            fd = f;
        }
        let x = my_xprt.expect("a transport");
        // Register both versions for tcp/ip and udp/ip.
        if si.af == libc::AF_INET && (si.proto == libc::IPPROTO_TCP || si.proto == libc::IPPROTO_UDP) {
            let prot = si.proto as u32;
            if si.proto == libc::IPPROTO_TCP {
                self.tcptrans = Some(netid.clone());
            } else {
                self.udptrans = Some(netid.clone());
            }
            self.list_pml.insert(0, Pmap { prog: PMAPPROG, vers: PMAPVERS, prot, port: PMAPPORT });
            self.list_pml.insert(0, Pmap { prog: PMAPPROG, vers: RPCBVERS, prot, port: PMAPPORT });
            self.list_pml.insert(0, Pmap { prog: PMAPPROG, vers: RPCBVERS4, prot, port: PMAPPORT });
            self.rbllist_add(PMAPPROG, PMAPVERS, nconf, &taddr);
        }
        // Portmap over IPv4, and over AF_LOCAL to know the caller.
        if (si.af == libc::AF_INET || si.af == libc::AF_LOCAL)
            && !svc.svc_register(x, PMAPPROG, PMAPVERS, DISPATCH_PMAP)
        {
            syslog(libc::LOG_ERR, cat(&[b"could not register on ", &netid]));
            sys::close(fd);
            return 1;
        }
        if !svc.svc_reg(x, RPCBPROG, RPCBVERS, DISPATCH_RPCB_3) {
            syslog(libc::LOG_ERR, cat(&[b"could not register ", &netid, b" version 3"]));
            sys::close(fd);
            return 1;
        }
        self.rbllist_add(RPCBPROG, RPCBVERS, nconf, &taddr);
        if !svc.svc_reg(x, RPCBPROG, RPCBVERS4, DISPATCH_RPCB_4) {
            syslog(libc::LOG_ERR, cat(&[b"could not register ", &netid, b" version 4"]));
            sys::close(fd);
            return 1;
        }
        self.rbllist_add(RPCBPROG, RPCBVERS4, nconf, &taddr);
        // Decide if bound checking works for this transport (it never does).
        let mut db = std::mem::take(&mut self.db);
        self.fdlist.add_bndlist(&mut db, nconf);
        self.db = db;
        0
    }
}

/// What C does when `-h '*'` reaches a second UDP transport: dereference NULL. A
/// segmentation fault, so the way it dies matches.
fn null_deref_crash() -> ! {
    // Rust's runtime has its own SIGSEGV handler (for stack overflows).
    sys::signal(libc::SIGSEGV, sys::Handler::Default);
    sys::raise(libc::SIGSEGV);
    std::process::abort();
}

/// `my_svc_run()`.
fn my_svc_run(rb: &mut Rpcbind, svc: &mut Svc) {
    loop {
        let mut fds = svc.pollfds();
        if fds.is_empty() {
            return;
        }
        let n = sys::poll(&mut fds, 30 * 1000);
        if n <= 0 {
            continue; // errors are taken to come from signal handlers
        }
        // check_rmtcalls(): no remote calls in this build.
        let mut out = Vec::new();
        svc.getreq_poll(rb, &fds, n, &mut out);
        if !out.is_empty() {
            sys::c_stdout(&out);
        }
    }
}

fn main() {
    let mut args = sys::Args::from_env();
    let argv0 = args.argv0();
    let mut rb = Rpcbind { dofork: true, ..Default::default() };
    parseargs(&mut rb, &mut args);

    // Check that another rpcbind isn't already running.
    let lockfd = sys::open(RPCBINDDLOCK, libc::O_RDONLY | libc::O_CREAT, 0o444);
    if lockfd == -1 {
        err(RPCBINDDLOCK);
    }
    LOCKFD.store(lockfd, Ordering::Relaxed);
    if sys::flock(lockfd, libc::LOCK_EX | libc::LOCK_NB) == -1 && sys::errno() == libc::EWOULDBLOCK {
        errx(b"another rpcbind is already running. Aborting");
    }

    let (cur, max) = sys::getrlimit_nofile();
    if cur < 128 {
        let cur = if max <= 128 { max } else { 128 };
        sys::setrlimit_nofile(cur, max);
    }

    if sys::geteuid() != 0 {
        sys::c_stderr(b"Sorry. You are not superuser\n");
        sys::exit(1);
    }

    // Make sure we use the local service file for service lookups.
    sys::nss_configure_lookup(b"services", NSS_MODULES);

    let Some(mut nc_handle) = rb.db.setnetconfig() else {
        syslog(libc::LOG_ERR, "could not read /etc/netconfig");
        sys::exit(1);
    };
    let nconf = rb.db.getnetconfigent(b"local").or_else(|| rb.db.getnetconfigent(b"unix"));
    let Some(nconf) = nconf else {
        syslog(libc::LOG_ERR, cat(&[&argv0, b": can't find local transport\n"]));
        sys::exit(1);
    };
    rb.xlog.open(b"rpcbind");
    if rb.dofork {
        rb.xlog.set_syslog(true);
        rb.xlog.set_stderr(false);
    } else {
        rb.xlog.set_syslog(false);
        rb.xlog.set_stderr(true);
    }
    if rb.debugging > 0 {
        rb.xlog.config(xlog::D_ALL, true);
    }
    let mut svc = Svc::default();
    svc.set_connmaxrec(RPC_MAXDATASIZE as i32);

    rb.init_transport(&mut svc, &nconf);
    loop {
        let mut db = std::mem::take(&mut rb.db);
        let next = db.getnetconfig(&mut nc_handle);
        rb.db = db;
        let Some(nconf) = next else { break };
        if nconf.flag & NC_VISIBLE != 0 {
            rb.init_transport(&mut svc, &nconf);
        }
    }
    rb.db.endnetconfig(nc_handle);

    if rb.udptrans.is_none() {
        rb.udptrans = Some(Vec::new());
    }
    if rb.tcptrans.is_none() {
        rb.tcptrans = Some(Vec::new());
    }

    // Catch the usual termination signals for graceful exit, ignore others.
    sys::signal(libc::SIGCHLD, sys::Handler::Func(reap));
    sys::signal(libc::SIGINT, sys::Handler::Func(terminate));
    sys::signal(libc::SIGTERM, sys::Handler::Func(terminate));
    sys::signal(libc::SIGQUIT, sys::Handler::Func(terminate));
    sys::signal(libc::SIGPIPE, sys::Handler::Ignore);
    sys::signal(libc::SIGHUP, sys::Handler::Ignore);
    sys::signal(libc::SIGUSR1, sys::Handler::Ignore);
    sys::signal(libc::SIGUSR2, sys::Handler::Ignore);

    if rb.dofork && sys::daemon() != 0 {
        err(b"fork failed");
    }

    // RPCBIND_USER is always set ("root"), so the switch always happens.
    let id: &[u8] = if rb.runasdaemon { RUN_AS } else { RPCBIND_USER };
    // Make sure we use the local password file for these lookups.
    sys::nss_configure_lookup(b"passwd", NSS_MODULES);
    let Some((uid, gid)) = sys::getpwnam(id) else {
        let e = sys::strerror(sys::errno());
        syslog(libc::LOG_ERR, cat(&[b"cannot get uid of '", id, b"': ", &e]));
        sys::exit(1);
    };
    if sys::setgid(gid) == -1 {
        let e = sys::strerror(sys::errno());
        syslog(
            libc::LOG_ERR,
            cat(&[b"setgid to '", id, b"' (", (gid as i32).to_string().as_bytes(), b") failed: ", &e]),
        );
        sys::exit(1);
    }
    if sys::setgroups_none() == -1 {
        let e = sys::strerror(sys::errno());
        syslog(libc::LOG_ERR, cat(&[b"dropping supplemental groups failed: ", &e]));
        sys::exit(1);
    }
    if sys::setuid(uid) == -1 {
        let e = sys::strerror(sys::errno());
        syslog(
            libc::LOG_ERR,
            cat(&[b"setuid to '", id, b"' (", (uid as i32).to_string().as_bytes(), b") failed: ", &e]),
        );
        sys::exit(1);
    }

    rb.local = util::network_init(rb.debugging > 0);

    my_svc_run(&mut rb, &mut svc);
    syslog(libc::LOG_ERR, "svc_run returned unexpectedly");
    rpcbind_abort();
}
