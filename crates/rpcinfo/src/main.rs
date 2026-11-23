//! rpcinfo: report RPC information. A port of rpcbind 1.2.8's `rpcinfo.c`, built
//! as Gentoo builds it (`PORTMAP` defined), over the `tirpc` crate.
//!
//! Output goes through C's stdio, as upstream's `printf()` does: stdout is buffered
//! until exit and stderr is not, so the two interleave as they do in C.

use tirpc::addr::{self, Netbuf};
use tirpc::clnt::{
    self, Client, Control, Lib, RPC_ANYFD, RPC_FAILED, RPC_N2AXLATEFAILURE, RPC_PMAPFAILURE, RPC_PROGUNAVAIL,
    RPC_PROGVERSMISMATCH, RPC_RPCBFAILURE, RPC_SUCCESS, RPC_TIMEDOUT, RPC_TLIERROR, RPC_UNKNOWNHOST, RPC_UNKNOWNPROTO,
    Timeval,
};
use tirpc::netconfig::{NC_TPI_CLTS, NC_TPI_COTS, Netconfig};
use tirpc::rpcb_clnt::{self, RPCBINDSOCK, RPCBPROG, RPCBVERS, RPCBVERS4};
use tirpc::rpcb_prot::{self, Rpcb, RpcbStat};
use tirpc::sys;

const PMAPPROG: u32 = 100000;
const PMAPVERS: u32 = 2;
const PMAPPROC_DUMP: u32 = 4;
const RPCBPROC_DUMP: u32 = 4;
const RPCBPROC_GETADDRLIST: u32 = 11;
const RPCBPROC_GETSTAT: u32 = 12;
const NULLPROC: u32 = 0;
const MIN_VERS: u64 = 0;
const MAX_VERS: u64 = 4294967295;
const UNKNOWN: &[u8] = b"unknown";
const IPPROTO_UDP: u32 = 17;
const IPPROTO_TCP: u32 = 6;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Function {
    None,
    PmapDump,
    TcpPing,
    UdpPing,
    Broadcast,
    Deletes,
    AddrPing,
    ProgPing,
    RpcbDump,
    RpcbDumpShort,
    RpcbAddrList,
    RpcbGetStat,
}

/// `printf()` to C's stdout.
fn out(b: impl AsRef<[u8]>) {
    sys::c_stdout(b.as_ref());
}

/// `fprintf(stderr, ...)`.
fn err(b: impl AsRef<[u8]>) {
    sys::c_stderr(b.as_ref());
}

fn cat(parts: &[&[u8]]) -> Vec<u8> {
    parts.concat()
}

/// `%-Ns`: left-justified in `w` columns.
fn left(s: &[u8], w: usize) -> Vec<u8> {
    let mut v = s.to_vec();
    while v.len() < w {
        v.push(b' ');
    }
    v
}

/// `%Ns`: right-justified in `w` columns.
fn right(s: &[u8], w: usize) -> Vec<u8> {
    let mut v = vec![b' '; w.saturating_sub(s.len())];
    v.extend_from_slice(s);
    v
}

fn num(n: impl std::fmt::Display) -> Vec<u8> {
    n.to_string().into_bytes()
}

/// `getrpcbynumber(n)->r_name`.
fn rpc_name(prog: u32) -> Option<Vec<u8>> {
    sys::rpc_name(prog as i32)
}

/// `exit(status)`, flushing stdout.
fn exit(status: i32) -> ! {
    sys::exit(status)
}

struct Rpcinfo {
    lib: Lib,
}

fn main() {
    let mut args = sys::Args::from_env();
    let mut function = Function::None;
    let mut errflg = false;
    let mut netid: Option<Vec<u8>> = None;
    let mut address: Option<Vec<u8>> = None;
    let mut portnum: u16 = 0;
    let set = |function: &mut Function, errflg: &mut bool, f: Function| {
        if *function != Function::None {
            *errflg = true;
        } else {
            *function = f;
        }
    };
    loop {
        let (c, optarg) = args.getopt(c"a:bdlmn:pstT:u");
        if c == -1 {
            break;
        }
        match c as u8 {
            b'p' => set(&mut function, &mut errflg, Function::PmapDump),
            b't' => set(&mut function, &mut errflg, Function::TcpPing),
            b'u' => set(&mut function, &mut errflg, Function::UdpPing),
            b'n' => {
                let a = optarg.unwrap_or_default();
                let (v, ok) = sys::strtol10(&a);
                portnum = v as u16;
                if !ok {
                    err(cat(&[b"rpcinfo: ", &a, b" is illegal port number\n"]));
                    exit(1);
                }
            }
            b'a' => {
                address = optarg;
                set(&mut function, &mut errflg, Function::AddrPing);
            }
            b'b' => set(&mut function, &mut errflg, Function::Broadcast),
            b'd' => set(&mut function, &mut errflg, Function::Deletes),
            b'l' => set(&mut function, &mut errflg, Function::RpcbAddrList),
            b'm' => set(&mut function, &mut errflg, Function::RpcbGetStat),
            b's' => set(&mut function, &mut errflg, Function::RpcbDumpShort),
            b'T' => netid = optarg,
            b'?' => errflg = true,
            _ => {}
        }
    }
    if errflg || (function == Function::AddrPing && netid.is_none()) {
        usage();
        exit(1);
    }
    let rest = args.rest();
    if function == Function::None {
        function = if rest.len() > 1 { Function::ProgPing } else { Function::RpcbDump };
    }
    let mut r = Rpcinfo { lib: Lib::default() };
    let netid = netid.as_deref();
    match function {
        Function::PmapDump => {
            if portnum != 0 {
                usage();
                exit(1);
            }
            r.pmapdump(&rest);
        }
        Function::UdpPing => r.ip_ping(b"udp", &rest),
        Function::TcpPing => r.ip_ping(b"tcp", &rest),
        Function::Broadcast => r.brdcst(&rest),
        Function::Deletes => r.deletereg(netid, &rest),
        Function::AddrPing => r.addrping(address.as_deref().unwrap_or_default(), netid, &rest),
        Function::ProgPing => r.progping(netid, &rest),
        Function::RpcbDump | Function::RpcbDumpShort => r.rpcbdump(function, netid, &rest),
        Function::RpcbGetStat => r.rpcbgetstat(&rest),
        Function::RpcbAddrList => r.rpcbaddrlist(netid, &rest),
        Function::None => {}
    }
    exit(0);
}

fn usage() {
    err("Usage: rpcinfo [-m | -s] [host]\n");
    err("       rpcinfo -p [host]\n");
    err("       rpcinfo -T netid host prognum [versnum]\n");
    err("       rpcinfo -l host prognum versnum\n");
    err("       rpcinfo [-n portnum] -u | -t host prognum [versnum]\n");
    err("       rpcinfo -a serv_address -T netid prognum [version]\n");
    err("       rpcinfo -b prognum versnum\n");
    err("       rpcinfo -d [-T netid] prognum versnum\n");
}

/// `getprognum()`: a name from `/etc/rpc`, or a number.
fn getprognum(arg: &[u8]) -> u64 {
    // QUIRK: `while (*tptr && isdigit(*tptr++));` steps past the first non-digit, so
    // the test that follows looks at the character after it (a "-5" is a name) and at
    // the non-digit itself only when it ends the string.
    let mut t = 0;
    while t < arg.len() {
        let c = arg[t];
        t += 1;
        if !c.is_ascii_digit() {
            break;
        }
    }
    let at = arg.get(t).copied().unwrap_or(0);
    let prev = if t == 0 { 0 } else { arg[t - 1] };
    if at != 0 || prev.is_ascii_alphabetic() {
        match sys::rpc_number(arg) {
            Some(n) => n as i64 as u64,
            None => {
                err(cat(&[b"rpcinfo: ", arg, b" is unknown service\n"]));
                exit(1);
            }
        }
    } else {
        let (v, ok) = sys::strtol10(arg);
        if !ok {
            err(cat(&[b"rpcinfo: ", arg, b" is illegal program number\n"]));
            exit(1);
        }
        v as u64
    }
}

/// `getvers()`. QUIRK: `(int) strtol()`, stored in a `u_long`, so -1 (and
/// 4294967295) is 2^64-1.
fn getvers(arg: &[u8]) -> u64 {
    let (v, ok) = sys::strtol10(arg);
    if !ok {
        err(cat(&[b"rpcinfo: ", arg, b" is illegal version number\n"]));
        exit(1);
    }
    v as i32 as i64 as u64
}

/// `spaces(howmany)`.
fn spaces(howmany: i64) -> &'static str {
    const S: &str = "                                                                ";
    if howmany <= 0 || howmany > 65 {
        return "";
    }
    // QUIRK: 65 reads the byte before the array; nothing prints that many.
    &S[..(howmany as usize).min(64)]
}

const MINUTE: Timeval = Timeval::secs(60);
const TEN: Timeval = Timeval::secs(10);

fn void_args(_: &mut dyn tirpc::xdr::XdrEncode) -> bool {
    true
}

fn void_res(_: &mut dyn tirpc::xdr::XdrDecode) -> bool {
    true
}

/// `sa_len()`.
fn sa_len(nb: &Netbuf) -> usize {
    match nb.family() {
        libc::AF_LOCAL => size_of::<libc::sockaddr_un>(),
        libc::AF_INET => size_of::<libc::sockaddr_in>(),
        libc::AF_INET6 => size_of::<libc::sockaddr_in6>(),
        _ => 0,
    }
}

/// `struct rpcbdump_short`.
struct Short {
    prog: u64,
    /// Newest first; `int`s.
    vlist: Vec<i32>,
    nlist: Vec<Vec<u8>>,
    owner: Vec<u8>,
}

impl Rpcinfo {
    fn pcreateerror(&mut self, s: &[u8]) {
        clnt::pcreateerror(&mut self.lib, s);
    }

    fn perror(&mut self, cl: &Client, s: &[u8]) {
        clnt::perror(&mut self.lib, cl, s);
    }

    fn nc_perror(&self, s: &[u8]) {
        err(cat(&[s, b": ", self.lib.nc.nc_sperror().as_bytes(), b"\n"]));
    }

    /// rpcinfo's own `local_rpcb()`: one socket, tried at the abstract name and then
    /// the path.
    fn local_rpcb(&mut self, prog: u32, vers: u32) -> Option<Client> {
        let sock = sys::socket(libc::AF_LOCAL, libc::SOCK_STREAM, 0);
        if sock < 0 {
            return None;
        }
        let mut abs = vec![0u8];
        abs.extend_from_slice(RPCBINDSOCK);
        let nb = rpcb_clnt::sun_netbuf(&abs);
        if let Some(c) = clnt::clnt_vc_create(&mut self.lib, sock, &nb, prog, vers, 0, 0) {
            return Some(c);
        }
        let nb = rpcb_clnt::sun_netbuf(RPCBINDSOCK);
        clnt::clnt_vc_create(&mut self.lib, sock, &nb, prog, vers, 0, 0)
    }

    /// `ip_ping_one()`.
    fn ip_ping_one(cl: &mut Client, vers: u64) -> u32 {
        cl.control(Control::SetVers(vers as u32));
        cl.call(NULLPROC, &mut void_args, &mut void_res, TEN)
    }

    /// `ip_ping()` (`-t`, `-u`). QUIRK: the `-n` port is parsed but never used.
    fn ip_ping(&mut self, proto: &[u8], argv: &[Vec<u8>]) {
        if argv.len() < 2 || argv.len() > 3 {
            usage();
            exit(1);
        }
        let hostname = &argv[0];
        let prognum = getprognum(&argv[1]);
        let vers = if argv.len() == 2 { MIN_VERS } else { getvers(&argv[2]) };
        let mut client = self.ip_getclient(hostname, prognum as u32, vers as u32, proto);
        let rpc_stat = Self::ip_ping_one(&mut client, vers);
        if argv.len() != 2 {
            if self.pstatus(&client, prognum, vers) < 0 {
                exit(1);
            }
            client.destroy();
            return;
        }
        let (minvers, maxvers);
        if rpc_stat == RPC_PROGVERSMISMATCH {
            let e = client.geterr();
            minvers = u64::from(e.low());
            maxvers = u64::from(e.high());
        } else if rpc_stat == RPC_SUCCESS {
            let st = Self::ip_ping_one(&mut client, MAX_VERS);
            if st == RPC_PROGVERSMISMATCH {
                let e = client.geterr();
                minvers = u64::from(e.low());
                maxvers = u64::from(e.high());
            } else if st == RPC_SUCCESS {
                minvers = 0;
                maxvers = MAX_VERS;
            } else {
                self.pstatus(&client, prognum, MAX_VERS);
                exit(1);
            }
        } else {
            self.pstatus(&client, prognum, 0);
            exit(1);
        }
        let mut failure = false;
        let mut v = minvers;
        while v <= maxvers {
            Self::ip_ping_one(&mut client, v);
            if self.pstatus(&client, prognum, v) < 0 {
                failure = true;
            }
            v += 1;
        }
        if failure {
            exit(1);
        }
        client.destroy();
    }

    /// `pmapdump()` (`-p`).
    fn pmapdump(&mut self, argv: &[Vec<u8>]) {
        if argv.len() > 1 {
            usage();
            exit(1);
        }
        let host = argv.first();
        let client = match host {
            Some(h) => Some(self.ip_getclient(h, PMAPPROG, PMAPVERS, b"tcp")),
            None => self.local_rpcb(PMAPPROG, PMAPVERS),
        };
        let Some(mut client) = client else {
            if self.lib.createerr.stat == RPC_TLIERROR {
                self.lib.createerr.stat = RPC_PMAPFAILURE;
                self.lib.createerr.error.status = RPC_FAILED;
            }
            self.pcreateerror(b"rpcinfo: can't contact portmapper");
            exit(1);
        };
        let mut head = Vec::new();
        let st = client.call(
            PMAPPROC_DUMP,
            &mut void_args,
            &mut |x| match rpcb_prot::get_pmaplist(x) {
                Some(v) => {
                    head = v;
                    true
                }
                None => false,
            },
            MINUTE,
        );
        if st != RPC_SUCCESS {
            if st == RPC_PROGVERSMISMATCH || st == RPC_PROGUNAVAIL {
                if client.geterr().low() > PMAPVERS {
                    let h: &[u8] = host.map_or(b"(null)", |h| h);
                    err(cat(&[h, b" does not support portmapper.  Try rpcinfo ", h, b" instead\n"]));
                }
                exit(1);
            }
            self.perror(&client, b"rpcinfo: can't contact portmapper");
            exit(1);
        }
        if head.is_empty() {
            out("No remote programs registered.\n");
            return;
        }
        out("   program vers proto   port  service\n");
        for p in &head {
            let mut l = right(&num(p.prog), 10);
            l.extend(right(&num(p.vers), 5));
            l.extend(match p.prot {
                IPPROTO_UDP => right(b"udp", 6),
                IPPROTO_TCP => right(b"tcp", 6),
                n => right(&num(n), 6),
            });
            l.extend(right(&num(p.port), 7));
            if let Some(n) = rpc_name(p.prog) {
                l.extend_from_slice(b"  ");
                l.extend(n);
            }
            l.push(b'\n');
            out(l);
        }
    }

    /// `ip_getclient()`: the first transport of `proto` (in `/etc/netconfig` order)
    /// whose rpcbind knows the program, or exit.
    fn ip_getclient(&mut self, hostname: &[u8], prognum: u32, versnum: u32, proto: &[u8]) -> Client {
        let mut saved = RPC_SUCCESS;
        let mut result: Option<(Netconfig, Netbuf)> = None;
        if let Some(mut h) = self.lib.nc.setnetconfig() {
            while let Some(nc) = self.lib.nc.getnetconfig(&mut h) {
                if nc.proto != proto {
                    continue;
                }
                if let Some(a) = rpcb_clnt::rpcb_getaddr(&mut self.lib, prognum, versnum, &nc, sys::SS_LEN, hostname) {
                    let ent = self.lib.nc.getnetconfigent(&nc.netid);
                    self.lib.nc.endnetconfig(h);
                    result = ent.map(|e| (e, a));
                    break;
                }
                if self.lib.createerr.stat != RPC_UNKNOWNHOST {
                    self.pcreateerror(hostname);
                    exit(1);
                }
                saved = self.lib.createerr.stat;
            }
        }
        let Some((nc, bind_address)) = result else {
            if saved != RPC_SUCCESS {
                self.lib.createerr.stat = saved;
                self.pcreateerror(hostname);
            } else {
                err(cat(&[b"Cannot find suitable transport for protocol ", proto, b"\n"]));
            }
            exit(1);
        };
        match clnt::clnt_tli_create(&mut self.lib, RPC_ANYFD, Some(&nc), &bind_address, prognum, versnum) {
            Some(c) => c,
            None => {
                self.pcreateerror(hostname);
                exit(1);
            }
        }
    }

    /// `brdcst()` (`-b`).
    fn brdcst(&mut self, argv: &[Vec<u8>]) {
        if argv.len() != 2 {
            usage();
            exit(1);
        }
        let prognum = getprognum(&argv[0]);
        let vers = getvers(&argv[1]);
        let st = tirpc::bcast::rpc_broadcast(&mut self.lib, prognum as u32, vers as u32, NULLPROC, &mut reply_proc);
        if st != RPC_SUCCESS && st != RPC_TIMEDOUT {
            err(cat(&[b"rpcinfo: broadcast failed: ", clnt::sperrno(st).as_bytes(), b"\n"]));
            exit(1);
        }
        exit(0);
    }

    /// `rpcbdump()` (no option, or `-s`).
    fn rpcbdump(&mut self, dumptype: Function, netid: Option<&[u8]>, argv: &[Vec<u8>]) {
        if argv.len() > 1 {
            usage();
            exit(1);
        }
        let client = match argv.first() {
            Some(host) => match netid {
                None => self.clnt_rpcbind_create(host, RPCBVERS, false).0,
                Some(id) => {
                    let Some(nc) = self.lib.nc.getnetconfigent(id) else {
                        self.nc_perror(b"rpcinfo: invalid transport");
                        exit(1);
                    };
                    self.getclnthandle(host, &nc, RPCBVERS, false).0
                }
            },
            None => self.local_rpcb(PMAPPROG, RPCBVERS),
        };
        let Some(mut client) = client else {
            self.pcreateerror(b"rpcinfo: can't contact rpcbind");
            exit(1);
        };
        let mut head: Vec<Rpcb> = Vec::new();
        let dump = |cl: &mut Client, head: &mut Vec<Rpcb>| {
            cl.call(
                RPCBPROC_DUMP,
                &mut void_args,
                &mut |x| match rpcb_prot::get_rpcblist(x) {
                    Some(v) => {
                        *head = v;
                        true
                    }
                    None => false,
                },
                MINUTE,
            )
        };
        let st = dump(&mut client, &mut head);
        if st != RPC_SUCCESS {
            let failed = 'f: {
                if st != RPC_PROGVERSMISMATCH && st != RPC_PROGUNAVAIL {
                    break 'f true;
                }
                // QUIRK: for PROGUNAVAIL the versions are whatever the error union held.
                let e = client.geterr();
                if e.low() == RPCBVERS4 {
                    client.control(Control::SetVers(RPCBVERS4));
                    break 'f dump(&mut client, &mut head) != RPC_SUCCESS;
                }
                if e.high() == PMAPVERS {
                    client.control(Control::SetVers(PMAPVERS));
                    let mut pm = Vec::new();
                    let st = client.call(
                        PMAPPROC_DUMP,
                        &mut void_args,
                        &mut |x| match rpcb_prot::get_pmaplist(x) {
                            Some(v) => {
                                pm = v;
                                true
                            }
                            None => false,
                        },
                        MINUTE,
                    );
                    if st != RPC_SUCCESS {
                        break 'f true;
                    }
                    head = pm
                        .iter()
                        .map(|p| Rpcb {
                            prog: p.prog,
                            vers: p.vers,
                            netid: match p.prot {
                                IPPROTO_UDP => b"udp".to_vec(),
                                IPPROTO_TCP => b"tcp".to_vec(),
                                n => right(&num(n), 6),
                            },
                            owner: UNKNOWN.to_vec(),
                            addr: format!("0.0.0.0.{}.{}", (p.port >> 8) & 0xff, p.port & 0xff).into_bytes(),
                        })
                        .collect();
                }
                false
            };
            if failed {
                self.perror(&client, b"rpcinfo: can't contact rpcbind: ");
                exit(1);
            }
        }
        if head.is_empty() {
            out("No remote programs registered.\n");
        } else if dumptype == Function::RpcbDump {
            out("   program version netid     address                service    owner\n");
            for r in &head {
                let mut l = right(&num(r.prog), 10);
                l.extend(right(&num(r.vers), 5));
                l.extend_from_slice(b"    ");
                l.extend(left(&r.netid, 9));
                l.push(b' ');
                l.extend(left(&r.addr, 22));
                l.push(b' ');
                l.extend(left(&rpc_name(r.prog).unwrap_or_else(|| b"-".to_vec()), 10));
                l.push(b' ');
                l.extend_from_slice(&r.owner);
                l.push(b'\n');
                out(l);
            }
        } else {
            let mut rs: Vec<Short> = Vec::new();
            for r in &head {
                let prog = u64::from(r.prog);
                let i = match rs.iter().position(|s| s.prog == prog) {
                    Some(i) => i,
                    None => {
                        rs.push(Short { prog, vlist: Vec::new(), nlist: Vec::new(), owner: r.owner.clone() });
                        rs.len() - 1
                    }
                };
                let s = &mut rs[i];
                // add_version(): QUIRK: the list holds ints compared against the
                // u_long, so a version of 2^31 or more never matches and repeats.
                let v = u64::from(r.vers);
                if !s.vlist.iter().any(|&x| x as i64 as u64 == v) {
                    s.vlist.insert(0, v as u32 as i32);
                }
                if !s.nlist.contains(&r.netid) {
                    s.nlist.insert(0, r.netid.clone());
                }
            }
            out("   program version(s) netid(s)                         service     owner\n");
            for s in &rs {
                let mut l = right(&num(s.prog), 10);
                l.extend_from_slice(b"  ");
                let vs: Vec<String> = s.vlist.iter().map(|v| v.to_string()).collect();
                l.extend(left(vs.join(",").as_bytes(), 10));
                // The netids, cut to the 255 bytes left in the buffer.
                let mut buf: Vec<u8> = Vec::new();
                let mut netidmax: usize = 255;
                for (k, n) in s.nlist.iter().enumerate() {
                    buf.extend_from_slice(&n[..n.len().min(netidmax)]);
                    if n.len() < netidmax {
                        netidmax -= n.len();
                    } else {
                        break;
                    }
                    if k + 1 < s.nlist.len() && netidmax > 1 {
                        buf.push(b',');
                        netidmax -= 1;
                    }
                }
                l.extend(left(&buf, 32));
                l.push(b' ');
                l.extend(left(&rpc_name(s.prog as u32).unwrap_or_else(|| b"-".to_vec()), 11));
                l.push(b' ');
                l.extend_from_slice(&s.owner);
                l.push(b'\n');
                out(l);
            }
        }
        client.destroy();
    }

    /// `rpcbaddrlist()` (`-l`).
    fn rpcbaddrlist(&mut self, netid: Option<&[u8]>, argv: &[Vec<u8>]) {
        if argv.len() != 3 {
            usage();
            exit(1);
        }
        let host = &argv[0];
        let (client, targaddr) = match netid {
            None => self.clnt_rpcbind_create(host, RPCBVERS4, true),
            Some(id) => {
                let Some(nc) = self.lib.nc.getnetconfigent(id) else {
                    self.nc_perror(b"rpcinfo: invalid transport");
                    exit(1);
                };
                self.getclnthandle(host, &nc, RPCBVERS4, true)
            }
        };
        let Some(mut client) = client else {
            self.pcreateerror(b"rpcinfo: can't contact rpcbind");
            exit(1);
        };
        let prog = getprognum(&argv[1]) as u32;
        let vers = getvers(&argv[2]) as u32;
        let cl_netid = client.netid.clone().unwrap_or_default();
        let r_addr = match targaddr {
            None => Vec::new(),
            Some(t) => match self.lib.nc.getnetconfigent(&cl_netid) {
                Some(nc) => addr::taddr2uaddr(&nc, &t).unwrap_or_default(),
                None => Vec::new(),
            },
        };
        let parms = Rpcb { prog, vers, netid: cl_netid, addr: r_addr, owner: Vec::new() };
        let mut head = Vec::new();
        let st = client.call(
            RPCBPROC_GETADDRLIST,
            &mut |x| rpcb_prot::put_rpcb(x, &parms),
            &mut |x| match rpcb_prot::get_rpcb_entry_list(x) {
                Some(v) => {
                    head = v;
                    true
                }
                None => false,
            },
            MINUTE,
        );
        if st != RPC_SUCCESS {
            self.perror(&client, b"rpcinfo: can't contact rpcbind: ");
            exit(1);
        }
        if head.is_empty() {
            out("No remote programs registered.\n");
        } else {
            out("   program vers  tp_family/name/class    address\t\t  service\n");
            for re in &head {
                let mut l = right(&num(prog), 10);
                l.extend(right(&num(vers), 3));
                l.extend_from_slice(b"    ");
                let class: &[u8] = match re.nc_semantics {
                    NC_TPI_CLTS => b"clts",
                    NC_TPI_COTS => b"cots",
                    _ => b"cots_ord",
                };
                let buf = cat(&[&re.nc_protofmly, b"/", &re.nc_proto, b"/", class, b" "]);
                l.extend(left(&buf, 24));
                l.extend(left(&re.maddr, 24));
                l.push(b' ');
                l.extend(left(&rpc_name(prog).unwrap_or_else(|| b"-".to_vec()), 13));
                l.push(b'\n');
                out(l);
            }
        }
        client.destroy();
    }

    /// `rpcbgetstat()` (`-m`).
    fn rpcbgetstat(&mut self, argv: &[Vec<u8>]) {
        let client = match argv.first() {
            Some(host) => self.clnt_rpcbind_create(host, RPCBVERS4, false).0,
            None => self.local_rpcb(PMAPPROG, RPCBVERS4),
        };
        let Some(mut client) = client else {
            self.pcreateerror(b"rpcinfo: can't contact rpcbind");
            exit(1);
        };
        let mut inf: [RpcbStat; 3] = Default::default();
        let st = client.call(
            RPCBPROC_GETSTAT,
            &mut void_args,
            &mut |x| match rpcb_prot::get_rpcb_stat_byvers(x) {
                Some(v) => {
                    inf = v;
                    true
                }
                None => false,
            },
            MINUTE,
        );
        if st != RPC_SUCCESS {
            self.perror(&client, b"rpcinfo: can't contact rpcbind: ");
            exit(1);
        }
        const PMAPHDR: [&str; 6] = ["NULL", "SET", "UNSET", "GETPORT", "DUMP", "CALLIT"];
        const RPCB3HDR: [&str; 9] = ["NULL", "SET", "UNSET", "GETADDR", "DUMP", "CALLIT", "TIME", "U2T", "T2U"];
        const RPCB4HDR: [&str; 13] = [
            "NULL", "SET", "UNSET", "GETADDR", "DUMP", "CALLIT", "TIME", "U2T", "T2U", "VERADDR", "INDRECT", "GETLIST",
            "GETSTAT",
        ];
        out("PORTMAP (version 2) statistics\n");
        stat_table(&inf[0], &PMAPHDR, 0..=5, false);
        out("\n\n");
        if inf[0].info[5] != 0 {
            out("PMAP_RMTCALL call statistics\n");
            print_rmtcallstat(2, &inf[0]);
            out("\n");
        }
        if inf[0].info[3] != 0 {
            out("PMAP_GETPORT call statistics\n");
            print_getaddrstat(&inf[0]);
            out("\n");
        }
        out("RPCBIND (version 3) statistics\n");
        stat_table(&inf[1], &RPCB3HDR, 0..=8, false);
        out("\n\n");
        if inf[1].info[5] != 0 {
            out("RPCB_RMTCALL (version 3) call statistics\n");
            print_rmtcallstat(3, &inf[1]);
            out("\n");
        }
        if inf[1].info[3] != 0 {
            out("RPCB_GETADDR (version 3) call statistics\n");
            print_getaddrstat(&inf[1]);
            out("\n");
        }
        out("RPCBIND (version 4) statistics\n");
        stat_table(&inf[2], &RPCB4HDR, 0..=8, true);
        out("\n");
        stat_table(&inf[2], &RPCB4HDR, 9..=12, true);
        out("\n");
        if inf[2].info[5] != 0 || inf[2].info[10] != 0 {
            out("\n");
            out("RPCB_RMTCALL (version 4) call statistics\n");
            print_rmtcallstat(4, &inf[2]);
        }
        if inf[2].info[3] != 0 {
            out("\n");
            out("RPCB_GETADDR (version 4) call statistics\n");
            print_getaddrstat(&inf[2]);
        }
        client.destroy();
    }

    /// `deletereg()` (`-d`).
    fn deletereg(&mut self, netid: Option<&[u8]>, argv: &[Vec<u8>]) {
        if argv.len() != 2 {
            usage();
            exit(1);
        }
        let mut nconf = None;
        if let Some(id) = netid {
            nconf = self.lib.nc.getnetconfigent(id);
            if nconf.is_none() {
                err(cat(&[b"rpcinfo: netid ", id, b" not supported\n"]));
                exit(1);
            }
        }
        // QUIRK: gcc evaluates rpcb_unset()'s arguments right to left.
        let vers = getvers(&argv[1]);
        let prog = getprognum(&argv[0]);
        if !rpcb_clnt::rpcb_unset(&mut self.lib, prog as u32, vers as u32, nconf.as_ref()) {
            err(cat(&[b"rpcinfo: Could not delete registration for prog ", &argv[0], b" version ", &argv[1], b"\n"]));
            exit(1);
        }
    }

    /// `clnt_addr_create()`: a handle on one socket kept for the whole run.
    fn clnt_addr_create(
        &mut self,
        st: &mut AddrState,
        address: &[u8],
        nconf: &Netconfig,
        prog: u32,
        vers: u32,
    ) -> Client {
        if st.fd == RPC_ANYFD {
            st.fd = tirpc::svc::nconf2fd(nconf);
            if st.fd == -1 {
                self.lib.createerr.stat = RPC_TLIERROR;
                self.pcreateerror(b"rpcinfo");
                exit(1);
            }
            match addr::uaddr2taddr(nconf, address) {
                Some(nb) => st.nbuf = nb,
                None => {
                    let mut m = sys::progname();
                    m.extend_from_slice(b": rpcinfo: no address for client handle\n");
                    err(m);
                    exit(1);
                }
            }
        }
        match clnt::clnt_tli_create(&mut self.lib, st.fd, Some(nconf), &st.nbuf, prog, vers) {
            Some(c) => c,
            None => {
                self.pcreateerror(b"rpcinfo");
                exit(1);
            }
        }
    }

    /// `addrping()` (`-a`).
    fn addrping(&mut self, address: &[u8], netid: Option<&[u8]>, argv: &[Vec<u8>]) {
        if argv.is_empty() || argv.len() > 2 || netid.is_none() {
            usage();
            exit(1);
        }
        let id = netid.unwrap();
        let Some(nconf) = self.lib.nc.getnetconfigent(id) else {
            err(cat(&[b"rpcinfo: Could not find ", id, b"\n"]));
            exit(1);
        };
        let prognum = getprognum(&argv[0]) as u32;
        let versnum = if argv.len() == 1 { MIN_VERS as u32 } else { getvers(&argv[1]) as u32 };
        let mut st = AddrState { fd: RPC_ANYFD, nbuf: Netbuf::default() };
        let mut client = self.clnt_addr_create(&mut st, address, &nconf, prognum, versnum);
        let rpc_stat = client.call(NULLPROC, &mut void_args, &mut void_res, TEN);
        if argv.len() == 2 {
            let failure = self.pstatus(&client, u64::from(prognum), u64::from(versnum)) < 0;
            client.destroy();
            if failure {
                exit(1);
            }
            return;
        }
        client.control(Control::SetFdNclose);
        let fd = client.fd();
        let (minvers, maxvers): (u32, u32);
        if rpc_stat == RPC_PROGVERSMISMATCH {
            let e = client.geterr();
            minvers = e.low();
            maxvers = e.high();
        } else if rpc_stat == RPC_SUCCESS {
            client.destroy();
            client = self.clnt_addr_create(&mut st, address, &nconf, prognum, MAX_VERS as u32);
            let s = client.call(NULLPROC, &mut void_args, &mut void_res, TEN);
            if s == RPC_PROGVERSMISMATCH {
                let e = client.geterr();
                minvers = e.low();
                maxvers = e.high();
            } else if s == RPC_SUCCESS {
                minvers = 0;
                maxvers = MAX_VERS as u32;
            } else {
                self.pstatus(&client, u64::from(prognum), MAX_VERS);
                exit(1);
            }
        } else {
            self.pstatus(&client, u64::from(prognum), 0);
            exit(1);
        }
        client.destroy();
        let mut failure = false;
        // QUIRK: a 32-bit counter: a maximum of 2^32-1 never ends.
        let mut v = minvers;
        loop {
            if v > maxvers {
                break;
            }
            let mut c = self.clnt_addr_create(&mut st, address, &nconf, prognum, v);
            c.call(NULLPROC, &mut void_args, &mut void_res, TEN);
            if self.pstatus(&c, u64::from(prognum), u64::from(v)) < 0 {
                failure = true;
            }
            c.destroy();
            v = v.wrapping_add(1);
        }
        sys::close(fd);
        if failure {
            exit(1);
        }
    }

    /// `progping()` (`-T netid host prog [vers]`).
    fn progping(&mut self, netid: Option<&[u8]>, argv: &[Vec<u8>]) {
        // QUIRK: without -T this is a usage error; the NETPATH branch is unreachable.
        if argv.len() < 2 || argv.len() > 3 || netid.is_none() {
            usage();
            exit(1);
        }
        let prognum = getprognum(&argv[1]) as u32;
        let mut versnum = if argv.len() == 2 { MIN_VERS as u32 } else { getvers(&argv[2]) as u32 };
        let id = netid.unwrap();
        let Some(nconf) = self.lib.nc.getnetconfigent(id) else {
            err(cat(&[b"rpcinfo: Could not find ", id, b"\n"]));
            exit(1);
        };
        let Some(mut client) = clnt::clnt_tp_create(&mut self.lib, &argv[0], prognum, versnum, Some(&nconf)) else {
            self.pcreateerror(b"rpcinfo");
            exit(1);
        };
        let rpc_stat = client.call(NULLPROC, &mut void_args, &mut void_res, TEN);
        if argv.len() == 3 {
            let failure = self.pstatus(&client, u64::from(prognum), u64::from(versnum)) < 0;
            client.destroy();
            if failure {
                exit(1);
            }
            return;
        }
        let (minvers, maxvers): (u32, u32);
        if rpc_stat == RPC_PROGVERSMISMATCH {
            let e = client.geterr();
            minvers = e.low();
            maxvers = e.high();
        } else if rpc_stat == RPC_SUCCESS {
            versnum = MAX_VERS as u32;
            client.control(Control::SetVers(versnum));
            let s = client.call(NULLPROC, &mut void_args, &mut void_res, TEN);
            if s == RPC_PROGVERSMISMATCH {
                let e = client.geterr();
                minvers = e.low();
                maxvers = e.high();
            } else if s == RPC_SUCCESS {
                minvers = 0;
                maxvers = MAX_VERS as u32;
            } else {
                self.pstatus(&client, u64::from(prognum), MAX_VERS);
                exit(1);
            }
        } else {
            self.pstatus(&client, u64::from(prognum), 0);
            exit(1);
        }
        let mut failure = false;
        let mut v = minvers;
        while v <= maxvers {
            client.control(Control::SetVers(v));
            client.call(NULLPROC, &mut void_args, &mut void_res, TEN);
            if self.pstatus(&client, u64::from(prognum), u64::from(v)) < 0 {
                failure = true;
            }
            // QUIRK: as in addrping(), a 32-bit counter.
            v = v.wrapping_add(1);
        }
        client.destroy();
        if failure {
            exit(1);
        }
    }

    /// `pstatus()`.
    fn pstatus(&mut self, client: &Client, prog: u64, vers: u64) -> i32 {
        if client.geterr().status != RPC_SUCCESS {
            self.perror(client, b"rpcinfo");
            out(format!("program {prog} version {vers} is not available\n"));
            -1
        } else {
            out(format!("program {prog} version {vers} ready and waiting\n"));
            0
        }
    }

    /// `clnt_rpcbind_create()`: rpcbind on `host` over the first stream, then datagram,
    /// transport that works.
    fn clnt_rpcbind_create(&mut self, host: &[u8], vers: u32, want: bool) -> (Option<Client>, Option<Netbuf>) {
        self.lib.createerr.stat = RPC_SUCCESS;
        for class in [&b"circuit_n"[..], b"circuit_v", b"datagram_v"] {
            let Some(mut h) = tirpc::nettype::setconf(&mut self.lib, Some(class)) else {
                continue;
            };
            let mut r = (None, None);
            while r.0.is_none() {
                let Some(nc) = tirpc::nettype::getconf(&mut self.lib, &mut h) else {
                    if self.lib.createerr.stat == RPC_SUCCESS {
                        self.lib.createerr.stat = RPC_UNKNOWNPROTO;
                    }
                    break;
                };
                r = self.getclnthandle(host, &nc, vers, want);
            }
            if r.0.is_some() {
                return r;
            }
            tirpc::nettype::endconf(&mut self.lib, h);
        }
        (None, None)
    }

    /// rpcinfo's own `getclnthandle()`. QUIRK: it takes the host's first address for
    /// the `rpcbind` (or `portmapper`) service, whatever its family.
    fn getclnthandle(
        &mut self,
        host: &[u8],
        nconf: &Netconfig,
        vers: u32,
        want: bool,
    ) -> (Option<Client>, Option<Netbuf>) {
        let res = sys::getaddrinfo(Some(host), b"rpcbind", 0, 0, 0, 0)
            .or_else(|_| sys::getaddrinfo(Some(host), b"portmapper", 0, 0, 0, 0));
        let Ok(res) = res else {
            self.lib.createerr.stat = RPC_N2AXLATEFAILURE;
            return (None, None);
        };
        let a = Netbuf::from_bytes(&res.addr);
        let client = clnt::clnt_tli_create(&mut self.lib, RPC_ANYFD, Some(nconf), &a, RPCBPROG, vers);
        if client.is_none() && self.lib.createerr.stat == RPC_TLIERROR {
            self.lib.createerr.stat = RPC_RPCBFAILURE;
            self.lib.createerr.error.status = RPC_FAILED;
        }
        let t = (client.is_some() && want).then_some(a);
        (client, t)
    }
}

/// `clnt_addr_create()`'s statics.
struct AddrState {
    fd: i32,
    nbuf: Netbuf,
}

/// `reply_proc()`: print each broadcast reply.
fn reply_proc(who: &Netbuf, nconf: &Netconfig) -> bool {
    let hostname = sys::getnameinfo(&who.buf, sa_len(who), 0).unwrap_or_else(|_| UNKNOWN.to_vec());
    let uaddr = addr::taddr2uaddr(nconf, who).unwrap_or_else(|| UNKNOWN.to_vec());
    out(cat(&[&uaddr, b"\t", &hostname, b"\n"]));
    false
}

/// One table of `rpcbgetstat()`: the header line, then the counts line in
/// `linebuf`, each field padded to the next tab stop.
fn stat_table(s: &RpcbStat, hdr: &[&str], range: std::ops::RangeInclusive<usize>, v4: bool) {
    let mut line = String::new();
    for i in range {
        let mut field = match i {
            1 => format!("{}/", s.setinfo),
            2 => format!("{}/", s.unsetinfo),
            3 => format!("{}/", s.addrinfo.iter().fold(0i32, |a, p| a.wrapping_add(p.success))),
            5 => format!("{}/", s.rmtinfo.iter().fold(0i32, |a, p| a.wrapping_add(p.success))),
            _ => String::new(),
        };
        // XXX upstream: v4 GETADDR includes GETADDRLIST.
        if v4 && i == 3 {
            field.push_str(&s.info[3].wrapping_add(s.info[RPCBPROC_GETADDRLIST as usize]).to_string());
        } else {
            field.push_str(&s.info[i].to_string());
        }
        let flen = field.len() as i64;
        let stop = 8 * (1 + flen / 8);
        out(format!("{}{}", hdr[i], spaces(stop - hdr[i].len() as i64)));
        line.push_str(&field);
        line.push_str(spaces(stop - flen));
    }
    out(format!("\n{line}"));
}

/// `print_rmtcallstat()`.
fn print_rmtcallstat(rtype: u32, s: &RpcbStat) {
    if rtype == 4 {
        out("prog\t\tvers\tproc\tnetid\tindirect success failure\n");
    } else {
        out("prog\t\tvers\tproc\tnetid\tsuccess\tfailure\n");
    }
    for p in &s.rmtinfo {
        let mut l = match rpc_name(p.prog) {
            Some(n) => left(&n, 16),
            None => left(&num(p.prog as i32), 16),
        };
        l.extend(format!("{}\t{}\t", p.vers as i32, p.proc_ as i32).into_bytes());
        l.extend_from_slice(&p.netid);
        l.push(b'\t');
        if rtype == 4 {
            l.extend(format!("{}\t ", p.indirect).into_bytes());
        }
        l.extend(format!("{}\t{}\n", p.success, p.failure).into_bytes());
        out(l);
    }
}

/// `print_getaddrstat()`.
fn print_getaddrstat(s: &RpcbStat) {
    out("prog\t\tvers\tnetid\t  success\tfailure\n");
    for a in &s.addrinfo {
        let mut l = match rpc_name(a.prog) {
            Some(n) => left(&n, 16),
            None => left(&num(a.prog as i32), 16),
        };
        l.extend(format!("{}\t", a.vers as i32).into_bytes());
        l.extend_from_slice(&a.netid);
        l.extend(format!("\t  {:<12}\t{}\n", a.success, a.failure).into_bytes());
        out(l);
    }
}
