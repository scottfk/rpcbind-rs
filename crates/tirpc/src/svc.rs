//! The RPC server side: `svc.c` (registration, the poll-slot table, dispatch and error
//! replies), `svc_dg.c` (UDP), `svc_vc.c` (TCP and local stream sockets, in the
//! non-blocking mode rpcbind selects) and `svc_generic.c` (`svc_tli_create()`).
//!
//! The program's dispatch routines are reached through [`Service::dispatch`] with the
//! number the program gave [`Svc::svc_reg`]/[`Svc::svc_register`], and see the call
//! through a [`Request`].

use crate::addr::{self, Netbuf, SockInfo};
use crate::netconfig::{Netconfig, NetconfigDb};
use crate::rpc::{self, AuthStat, Authenticated, CallMsg, CredArea, OpaqueAuth, ReplyBody};
use crate::sys::{self, Fd};
use crate::xdr::{XdrDecode, XdrEncode, XdrMem};
use crate::xdr_rec::{ReadResult, RecIo, RecStream, XprtStat};

/// `RPC_MAXDATASIZE`.
pub const RPC_MAXDATASIZE: usize = 9000;
/// The size of `svc_dg`'s control-message buffer (`su_cmsg`).
const SU_CMSG: usize = 64;
/// `FD_SETSIZE`, the cap on `_rpc_dtablesize()`.
const FD_SETSIZE: i64 = 1024;
/// The events every slot polls for.
pub const POLL_EVENTS: i16 = libc::POLLIN | libc::POLLPRI | libc::POLLRDNORM | libc::POLLRDBAND;

/// The program's dispatch routines.
pub trait Service {
    /// Handle a call for a registered program and version. `dispatch` is the number
    /// given at registration.
    fn dispatch(&mut self, dispatch: u32, req: &mut Request<'_>);
}

/// `struct svc_callout`.
#[derive(Debug, Clone)]
struct Callout {
    prog: u32,
    vers: u32,
    netid: Option<Vec<u8>>,
    dispatch: u32,
}

/// The UDP transport (`struct svc_dg_data` and its `SVCXPRT`).
#[derive(Debug)]
pub struct DgXprt {
    /// `rpc_buffer(xprt)`: received calls and encoded replies share it, and decoding
    /// runs over all of it, so a short datagram reads the bytes earlier ones left.
    buf: Vec<u8>,
    /// Where decoding stopped after the call header, and the bytes left (`su_xdrs`).
    pos: usize,
    handy: usize,
    xid: u32,
    /// The `IP_PKTINFO`/`IPV6_PKTINFO` message from the call, with the interface index
    /// cleared, sent back with the reply so it leaves from the address it came to.
    control: Option<Vec<u8>>,
}

/// A connection (`struct cf_conn`).
#[derive(Debug)]
pub struct ConnXprt {
    rec: RecStream,
    strm_stat: XprtStat,
    x_id: u32,
    last_recv_time: (i64, i64),
}

/// A listening stream socket (`struct cf_rendezvous`).
#[derive(Debug)]
pub struct ListenXprt {
    sendsize: usize,
    recvsize: usize,
    maxrec: usize,
}

#[derive(Debug)]
pub enum Kind {
    Dg(DgXprt),
    Listen(ListenXprt),
    Conn(ConnXprt),
}

/// `SVCXPRT`.
#[derive(Debug)]
pub struct Xprt {
    pub fd: Fd,
    /// `xp_netid`.
    pub netid: Option<Vec<u8>>,
    /// `xp_rtaddr`: the caller's address.
    pub rtaddr: Netbuf,
    /// `xp_ltaddr`.
    pub ltaddr: Netbuf,
    /// `xp_verf`: the verifier for this call's accepted replies.
    verf: OpaqueAuth,
    pub kind: Kind,
}

/// One call being dispatched (`struct svc_req` with its transport).
#[derive(Debug)]
pub struct Request<'a> {
    pub call: &'a CallMsg,
    pub auth: &'a Authenticated,
    pub xprt: &'a mut Xprt,
}

/// `svc_dg_recv()`/`svc_vc_recv()` results.
enum Recv {
    Call(CallMsg),
    None,
}

/// libtirpc's server globals: the callout list, the transports by descriptor, and the
/// poll table.
#[derive(Debug)]
pub struct Svc {
    callouts: Vec<Callout>,
    /// `__svc_xports`, indexed by descriptor.
    xports: Vec<Option<Xprt>>,
    /// `svc_pollfd`, with -1 for a free slot.
    pollfd: Vec<libc::pollfd>,
    /// `__svc_maxrec` (`RPC_SVC_CONNMAXREC_SET`).
    maxrec: usize,
    dtablesize: usize,
    cred_area: CredArea,
}

impl Default for Svc {
    fn default() -> Self {
        let mut size = sys::open_max();
        if size > FD_SETSIZE {
            size = FD_SETSIZE;
        }
        let dtablesize = size.max(0) as usize;
        Svc {
            callouts: Vec::new(),
            xports: (0..dtablesize).map(|_| None).collect(),
            pollfd: Vec::new(),
            maxrec: 0,
            dtablesize,
            cred_area: CredArea::default(),
        }
    }
}

impl Request<'_> {
    /// `svc_getcaller()`/`svc_getrpccaller()`.
    pub fn caller(&self) -> &Netbuf {
        &self.xprt.rtaddr
    }

    /// `svc_getargs()`: decode the arguments with `f`.
    pub fn getargs<T>(&mut self, f: impl FnOnce(&mut dyn XdrDecode) -> Option<T>) -> Option<T> {
        match &mut self.xprt.kind {
            Kind::Dg(d) => {
                let mut x = XdrMem::resume(&mut d.buf, d.pos, d.handy);
                let r = f(&mut x);
                d.pos = x.getpos();
                d.handy = x.handy();
                r
            }
            Kind::Conn(c) => f(&mut c.rec.decoder()),
            Kind::Listen(_) => std::process::abort(), // ops.xp_getargs = abort
        }
    }

    /// `svc_sendreply()`.
    pub fn sendreply(&mut self, results: &mut dyn FnMut(&mut dyn XdrEncode) -> bool) -> bool {
        let verf = self.xprt.verf.clone();
        reply(self.xprt, &verf, &mut ReplyBody::Success(results))
    }

    /// `svcerr_noproc()`.
    pub fn svcerr_noproc(&mut self) {
        let verf = self.xprt.verf.clone();
        reply(self.xprt, &verf, &mut ReplyBody::ProcUnavail);
    }

    /// `svcerr_decode()`.
    pub fn svcerr_decode(&mut self) {
        let verf = self.xprt.verf.clone();
        reply(self.xprt, &verf, &mut ReplyBody::GarbageArgs);
    }

    /// `svcerr_systemerr()`.
    pub fn svcerr_systemerr(&mut self) {
        let verf = self.xprt.verf.clone();
        reply(self.xprt, &verf, &mut ReplyBody::SystemErr);
    }

    /// `svcerr_noprog()`.
    pub fn svcerr_noprog(&mut self) {
        let verf = self.xprt.verf.clone();
        reply(self.xprt, &verf, &mut ReplyBody::ProgUnavail);
    }

    /// `svcerr_progvers()`.
    pub fn svcerr_progvers(&mut self, low: u32, high: u32) {
        let verf = self.xprt.verf.clone();
        reply(self.xprt, &verf, &mut ReplyBody::ProgMismatch { low, high });
    }

    /// `svcerr_weakauth()`.
    pub fn svcerr_weakauth(&mut self) {
        reply(self.xprt, &OpaqueAuth::default(), &mut ReplyBody::AuthError(AuthStat::TooWeak));
    }
}

/// `SVC_REPLY()`: `svc_dg_reply()` or `svc_vc_reply()`.
fn reply(xprt: &mut Xprt, verf: &OpaqueAuth, body: &mut ReplyBody<'_>) -> bool {
    let fd = xprt.fd;
    match &mut xprt.kind {
        Kind::Dg(d) => {
            let mut x = XdrMem::new(&mut d.buf);
            if !rpc::encode_reply(&mut x, d.xid, verf, body) {
                return false;
            }
            let slen = x.getpos();
            let n = sys::sendmsg(fd, &d.buf[..slen], &xprt.rtaddr.buf, xprt.rtaddr.len, d.control.as_deref());
            n == slen as isize
        }
        Kind::Conn(c) => {
            let mut io = ConnIo { fd, strm_stat: &mut c.strm_stat, last_recv_time: &mut c.last_recv_time };
            let mut e = c.rec.encoder(&mut io);
            let ok = rpc::encode_reply(&mut e, c.x_id, verf, body);
            e.endofrecord(true);
            ok
        }
        Kind::Listen(_) => std::process::abort(),
    }
}

/// `read_vc()`/`write_vc()` for a non-blocking connection.
struct ConnIo<'a> {
    fd: Fd,
    strm_stat: &'a mut XprtStat,
    last_recv_time: &'a mut (i64, i64),
}

impl RecIo for ConnIo<'_> {
    fn read(&mut self, buf: &mut [u8]) -> ReadResult {
        sys::set_errno(0);
        let n = sys::read(self.fd, buf);
        if n < 0 {
            let e = sys::errno();
            if e == libc::EAGAIN || e == libc::EWOULDBLOCK {
                return ReadResult::WouldBlock;
            }
            *self.strm_stat = XprtStat::Died;
            return ReadResult::Error;
        }
        if n == 0 {
            return ReadResult::Eof;
        }
        *self.last_recv_time = sys::gettimeofday();
        ReadResult::Data(n as usize)
    }

    fn write(&mut self, buf: &[u8]) -> bool {
        let tv0 = sys::gettimeofday();
        let mut off = 0;
        while off < buf.len() {
            let i = sys::write(self.fd, &buf[off..]);
            if i < 0 {
                if sys::errno() != libc::EAGAIN {
                    *self.strm_stat = XprtStat::Died;
                    return false;
                }
                // For non-blocking connections, don't take more than 2 seconds. QUIRK:
                // retried at once, not after a poll(): a client that doesn't read
                // stalls the daemon for those 2 seconds.
                if sys::gettimeofday().0 - tv0.0 >= 2 {
                    *self.strm_stat = XprtStat::Died;
                    return false;
                }
                continue;
            }
            off += i as usize;
        }
        true
    }
}

/// `__rpc_fd2sockinfo()`.
pub fn fd2sockinfo(fd: Fd) -> Option<SockInfo> {
    let (ss, len) = sys::getsockname(fd)?;
    let ty = sys::getsockopt_int(fd, libc::SOL_SOCKET, libc::SO_TYPE)?;
    let af = i32::from(u16::from_ne_bytes([ss[0], ss[1]]));
    let proto = if af != libc::AF_LOCAL {
        match ty {
            libc::SOCK_STREAM => libc::IPPROTO_TCP,
            libc::SOCK_DGRAM => libc::IPPROTO_UDP,
            _ => return None,
        }
    } else {
        0
    };
    Some(SockInfo { af, proto, socktype: ty, alen: len })
}

/// `__rpc_nconf2fd()`: a socket for the entry, `IPV6_V6ONLY` for IPv6. Returns 0 (not
/// -1) for an entry it has no socket type for, as C does.
pub fn nconf2fd(nconf: &Netconfig) -> Fd {
    let Some(si) = addr::nconf2sockinfo(nconf) else {
        return 0;
    };
    let fd = sys::socket(si.af, si.socktype, si.proto);
    if fd >= 0 && si.af == libc::AF_INET6 {
        sys::setsockopt_int(fd, libc::SOL_IPV6, libc::IPV6_V6ONLY, 1);
    }
    fd
}

/// `__rpc_sockisbound()`.
fn sockisbound(fd: Fd) -> bool {
    let Some((ss, len)) = sys::getsockname(fd) else {
        return false;
    };
    match i32::from(u16::from_ne_bytes([ss[0], ss[1]])) {
        libc::AF_INET | libc::AF_INET6 => u16::from_ne_bytes([ss[2], ss[3]]) != 0,
        libc::AF_LOCAL => len > 2,
        _ => false,
    }
}

/// `__rpc_get_t_size()`.
pub fn get_t_size(proto: i32, size: usize) -> usize {
    let maxsize = 256 * 1024;
    let defsize = match proto {
        libc::IPPROTO_TCP => 64 * 1024,
        libc::IPPROTO_UDP => 8800, // UDPMSGSIZE
        _ => RPC_MAXDATASIZE,
    };
    if size == 0 {
        return defsize;
    }
    size.min(maxsize)
}

/// `svc_dg_valid_pktinfo()`, on what `recvmsg()` returned: the control message to send
/// back, with its interface index cleared, or `None`.
fn valid_pktinfo(m: &sys::RecvMsg) -> Option<Vec<u8>> {
    if m.flags & libc::MSG_CTRUNC != 0 {
        return None;
    }
    let hdr = size_of::<libc::cmsghdr>();
    if m.controllen < hdr {
        return None;
    }
    let c = &m.control[..m.controllen];
    let cmsg_len = usize::from_ne_bytes(c[0..8].try_into().unwrap());
    let level = i32::from_ne_bytes(c[8..12].try_into().unwrap());
    let ty = i32::from_ne_bytes(c[12..16].try_into().unwrap());
    if cmsg_len < hdr {
        return None;
    }
    // CMSG_NXTHDR(): another header fits after this one?
    let next = (cmsg_len + 7) & !7;
    if next + hdr <= m.controllen {
        return None;
    }
    let family = i32::from(u16::from_ne_bytes([m.name[0], m.name[1]]));
    let mut out = c.to_vec();
    match family {
        libc::AF_INET => {
            if level != libc::SOL_IP
                || ty != libc::IP_PKTINFO
                || cmsg_len < sys::cmsg_len(size_of::<libc::in_pktinfo>())
            {
                return None;
            }
            // ipi_ifindex is the first field of the data.
            out[hdr..hdr + 4].fill(0);
        }
        libc::AF_INET6 => {
            if level != libc::SOL_IPV6
                || ty != libc::IPV6_PKTINFO
                || cmsg_len < sys::cmsg_len(size_of::<libc::in6_pktinfo>())
            {
                return None;
            }
            // ipi6_ifindex follows the 16-byte address.
            out[hdr + 16..hdr + 20].fill(0);
        }
        _ => return None,
    }
    Some(out)
}

impl Svc {
    /// `rpc_control(RPC_SVC_CONNMAXREC_SET, &val)`.
    pub fn set_connmaxrec(&mut self, val: i32) -> bool {
        if val <= 0 {
            return false;
        }
        self.maxrec = val as usize;
        true
    }

    /// `svc_pollfd`, as `my_svc_run()` copies it before each `poll()`.
    pub fn pollfds(&self) -> Vec<libc::pollfd> {
        self.pollfd.iter().map(|p| libc::pollfd { fd: p.fd, events: p.events, revents: 0 }).collect()
    }

    /// The transport registered for a descriptor.
    pub fn xprt(&self, fd: Fd) -> Option<&Xprt> {
        self.xports.get(fd as usize).and_then(Option::as_ref)
    }

    /// `xprt_register()`: install the transport, and take the first free poll slot or
    /// add one. A descriptor beyond the table isn't registered (and the transport is
    /// dropped without closing it, as C leaks it).
    fn xprt_register(&mut self, xprt: Xprt) -> bool {
        let fd = xprt.fd;
        if fd < 0 || fd as usize >= self.dtablesize {
            std::mem::forget(xprt);
            return false;
        }
        self.xports[fd as usize] = Some(xprt);
        if let Some(slot) = self.pollfd.iter_mut().find(|p| p.fd == -1) {
            slot.fd = fd;
            slot.events = POLL_EVENTS;
            return true;
        }
        self.pollfd.push(libc::pollfd { fd, events: POLL_EVENTS, revents: 0 });
        true
    }

    /// `__xprt_do_unregister()`.
    fn xprt_unregister(&mut self, fd: Fd) -> Option<Xprt> {
        if fd < 0 || fd as usize >= self.dtablesize {
            return None;
        }
        let x = self.xports[fd as usize].take()?;
        for p in &mut self.pollfd {
            if p.fd == fd {
                p.fd = -1;
            }
        }
        Some(x)
    }

    /// `SVC_DESTROY()`: unregister and close.
    fn destroy(&mut self, fd: Fd) {
        if self.xprt_unregister(fd).is_some() {
            sys::close(fd);
        }
    }

    /// `svc_tli_create(fd, nconf, bindaddr, sendsz, recvsz)` for a socket rpcbind made
    /// and bound itself. `bindaddr` is used only if the socket isn't bound yet.
    pub fn svc_tli_create(
        &mut self,
        fd: Fd,
        nconf: Option<&Netconfig>,
        bindaddr: Option<&Netbuf>,
        sendsz: usize,
        recvsz: usize,
    ) -> Option<Fd> {
        let si = fd2sockinfo(fd)?;
        if !sockisbound(fd) {
            let b = bindaddr?;
            if sys::bind(fd, &b.buf, si.alen) < 0 {
                return None;
            }
            // bindaddr->qlen is never set by rpcbind; this path isn't reached there.
            sys::listen(fd, 0);
        }
        let mut xprt = match si.socktype {
            libc::SOCK_STREAM => {
                if sys::getpeername(fd).is_some() {
                    return None; // svc_fd_create(): an accepted socket; rpcbind never passes one
                }
                self.vc_create(fd, &si, sendsz, recvsz)?
            }
            libc::SOCK_DGRAM => self.dg_create(fd, &si, sendsz, recvsz)?,
            _ => return None,
        };
        if let Some(nc) = nconf {
            xprt.netid = Some(nc.netid.clone());
        }
        self.xprt_register(xprt).then_some(fd)
    }

    /// `svc_dg_create()` (without registering).
    fn dg_create(&mut self, fd: Fd, si: &SockInfo, sendsize: usize, recvsize: usize) -> Option<Xprt> {
        let sendsize = get_t_size(si.proto, sendsize);
        let recvsize = get_t_size(si.proto, recvsize);
        let iosz = sendsize.max(recvsize).div_ceil(4) * 4;
        let (ss, slen) = sys::getsockname(fd)?;
        match si.af {
            libc::AF_INET => {
                sys::setsockopt_int(fd, libc::SOL_IP, libc::IP_PKTINFO, 1);
            }
            libc::AF_INET6 => {
                sys::setsockopt_int(fd, libc::SOL_IPV6, libc::IPV6_RECVPKTINFO, 1);
            }
            _ => {}
        }
        Some(Xprt {
            fd,
            netid: None,
            rtaddr: Netbuf::default(),
            ltaddr: Netbuf::from_bytes(&ss[..slen]),
            verf: OpaqueAuth::default(),
            kind: Kind::Dg(DgXprt { buf: vec![0; iosz], pos: 0, handy: iosz, xid: 0, control: None }),
        })
    }

    /// `svc_vc_create()` (without registering).
    fn vc_create(&mut self, fd: Fd, si: &SockInfo, sendsize: usize, recvsize: usize) -> Option<Xprt> {
        let sendsize = get_t_size(si.proto, sendsize);
        let recvsize = get_t_size(si.proto, recvsize);
        // xp_ltaddr is the whole sockaddr_storage, not just the address's length.
        let (ss, _) = sys::getsockname(fd)?;
        Some(Xprt {
            fd,
            netid: None,
            rtaddr: Netbuf::default(),
            ltaddr: Netbuf::from_bytes(&ss),
            verf: OpaqueAuth::default(),
            kind: Kind::Listen(ListenXprt { sendsize, recvsize, maxrec: self.maxrec }),
        })
    }

    /// `svc_reg(xprt, prog, vers, dispatch, NULL)`: the callout is for the transport's
    /// netid. (No `rpcb_set()`: rpcbind passes no netconfig.)
    pub fn svc_reg(&mut self, fd: Fd, prog: u32, vers: u32, dispatch: u32) -> bool {
        let Some(x) = self.xprt(fd) else {
            return false;
        };
        let netid = x.netid.clone();
        if let Some(s) = self.find(prog, vers, netid.as_deref()) {
            return s.dispatch == dispatch;
        }
        self.callouts.insert(0, Callout { prog, vers, netid, dispatch });
        true
    }

    /// `svc_register(xprt, prog, vers, dispatch, 0)`: a callout for any netid. (No
    /// `pmap_set()`: rpcbind passes protocol 0.)
    pub fn svc_register(&mut self, _fd: Fd, prog: u32, vers: u32, dispatch: u32) -> bool {
        if let Some(s) = self.find(prog, vers, None) {
            return s.dispatch == dispatch;
        }
        self.callouts.insert(0, Callout { prog, vers, netid: None, dispatch });
        true
    }

    /// `svc_find()`.
    fn find(&self, prog: u32, vers: u32, netid: Option<&[u8]>) -> Option<&Callout> {
        self.callouts.iter().find(|s| {
            s.prog == prog && s.vers == vers && (netid.is_none() || s.netid.is_none() || s.netid.as_deref() == netid)
        })
    }

    /// `svc_getreq_poll()`: handle the ready descriptors in `pfds` (the copy that was
    /// polled), stopping after `pollretval` of them.
    pub fn getreq_poll(&mut self, svc: &mut dyn Service, pfds: &[libc::pollfd], pollretval: i32, stdout: &mut Vec<u8>) {
        // The calls of this round find the credential area where this round's copy of
        // the poll table puts it.
        self.cred_area.set_poll_slots(pfds.len());
        let mut found = 0;
        let mut i = 0;
        // C loops to the current svc_max_pollfd, which can be past the copy after an
        // accept, but it always reaches pollretval first.
        while i < self.pollfd.len() {
            let Some(p) = pfds.get(i) else { break };
            if p.fd != -1 && p.revents != 0 {
                if p.revents & libc::POLLNVAL != 0 {
                    self.xprt_unregister(p.fd);
                } else {
                    self.getreq_common(svc, p.fd, stdout);
                }
                found += 1;
                if found >= pollretval {
                    break;
                }
            }
            i += 1;
        }
    }

    /// `svc_getreq_common()`.
    fn getreq_common(&mut self, svc: &mut dyn Service, fd: Fd, stdout: &mut Vec<u8>) {
        if self.xprt(fd).is_none() {
            return;
        }
        loop {
            if let Recv::Call(call) = self.recv(fd) {
                let auth = rpc::authenticate(&call, &self.cred_area, stdout);
                let mut xprt = self.xports[fd as usize].take().expect("registered");
                match auth {
                    Err(why) => {
                        reply(&mut xprt, &OpaqueAuth::default(), &mut ReplyBody::AuthError(why));
                    }
                    Ok(auth) => {
                        xprt.verf = auth.verf.clone();
                        let mut low = u32::MAX;
                        let mut high = 0u32;
                        let mut prog_found = false;
                        let mut target = None;
                        for s in &self.callouts {
                            if s.prog == call.prog {
                                if s.vers == call.vers {
                                    target = Some(s.dispatch);
                                    break;
                                }
                                prog_found = true;
                                low = low.min(s.vers);
                                high = high.max(s.vers);
                            }
                        }
                        let verf = xprt.verf.clone();
                        match target {
                            Some(d) => svc.dispatch(d, &mut Request { call: &call, auth: &auth, xprt: &mut xprt }),
                            None if prog_found => {
                                reply(&mut xprt, &verf, &mut ReplyBody::ProgMismatch { low, high });
                            }
                            None => {
                                reply(&mut xprt, &verf, &mut ReplyBody::ProgUnavail);
                            }
                        }
                    }
                }
                self.xports[fd as usize] = Some(xprt);
            }
            match self.stat(fd) {
                XprtStat::Died => {
                    self.destroy(fd);
                    break;
                }
                XprtStat::MoreReqs => continue,
                XprtStat::Idle => break,
            }
        }
    }

    /// `SVC_STAT()`.
    fn stat(&mut self, fd: Fd) -> XprtStat {
        let Some(x) = self.xports[fd as usize].as_mut() else {
            return XprtStat::Idle;
        };
        match &mut x.kind {
            Kind::Dg(_) | Kind::Listen(_) => XprtStat::Idle,
            Kind::Conn(c) => {
                if c.strm_stat == XprtStat::Died {
                    XprtStat::Died
                } else if !c.rec.eof() {
                    XprtStat::MoreReqs
                } else {
                    XprtStat::Idle
                }
            }
        }
    }

    /// `SVC_RECV()`.
    fn recv(&mut self, fd: Fd) -> Recv {
        let x = self.xports[fd as usize].as_mut().expect("registered");
        match &mut x.kind {
            Kind::Dg(d) => {
                let m = loop {
                    match sys::recvmsg(fd, &mut d.buf, SU_CMSG) {
                        Err(libc::EINTR) => continue,
                        Err(_) => return Recv::None,
                        Ok(m) => break m,
                    }
                };
                if m.len < 16 {
                    return Recv::None;
                }
                x.rtaddr = Netbuf::from_bytes(&m.name[..m.namelen.min(m.name.len())]);
                d.control = valid_pktinfo(&m);
                let mut xd = XdrMem::new(&mut d.buf);
                let call = rpc::decode_call(&mut xd, &mut self.cred_area);
                d.pos = xd.getpos();
                d.handy = xd.handy();
                match call {
                    Some(c) => {
                        d.xid = c.xid;
                        Recv::Call(c)
                    }
                    None => Recv::None,
                }
            }
            Kind::Conn(c) => {
                let mut io = ConnIo { fd, strm_stat: &mut c.strm_stat, last_recv_time: &mut c.last_recv_time };
                let mut st = XprtStat::Idle;
                let got = c.rec.getrec(&mut io, &mut st, true);
                c.strm_stat = st;
                if !got {
                    return Recv::None;
                }
                match rpc::decode_call(&mut c.rec.decoder(), &mut self.cred_area) {
                    Some(call) => {
                        c.x_id = call.xid;
                        Recv::Call(call)
                    }
                    None => {
                        c.strm_stat = XprtStat::Died;
                        Recv::None
                    }
                }
            }
            Kind::Listen(_) => {
                self.rendezvous_request(fd);
                Recv::None
            }
        }
    }

    /// `rendezvous_request()`: accept a connection and register it.
    fn rendezvous_request(&mut self, fd: Fd) {
        let Some(Xprt { kind: Kind::Listen(l), .. }) = self.xprt(fd) else {
            return;
        };
        let (sendsize, recvsize, maxrec) = (l.sendsize, l.recvsize, l.maxrec);
        let (sock, ss, len) = loop {
            match sys::accept(fd) {
                Err(libc::EINTR) => continue,
                Err(_) => return,
                Ok(r) => break r,
            }
        };
        // makefd_xprt()
        let netid = fd2sockinfo(sock).and_then(|si| {
            let local = NetconfigDb::default().getnetconfigent(b"local").is_some();
            addr::sockinfo2netid(&si, local).map(<[u8]>::to_vec)
        });
        let mut rtaddr = Netbuf::from_bytes(&ss);
        rtaddr.len = len;
        if fd2sockinfo(sock).is_some_and(|si| si.proto == libc::IPPROTO_TCP) {
            sys::setsockopt_int(sock, libc::IPPROTO_TCP, libc::TCP_NODELAY, 1);
        }
        // The record stream is made with the listener's sizes, then set non-blocking.
        // Only the non-blocking mode is ported: rpcbind always sets a maxrec.
        let rec = RecStream::new(sendsize, recvsize, maxrec);
        let flags = sys::getfl(sock);
        if flags == -1 || sys::setfl(sock, flags | libc::O_NONBLOCK) == -1 {
            return;
        }
        let xprt = Xprt {
            fd: sock,
            netid,
            rtaddr,
            ltaddr: Netbuf::default(),
            verf: OpaqueAuth::default(),
            kind: Kind::Conn(ConnXprt { rec, strm_stat: XprtStat::Idle, x_id: 0, last_recv_time: sys::gettimeofday() }),
        };
        self.xprt_register(xprt);
        let nfds = self.pollfd.iter().filter(|p| p.fd != -1).count();
        if nfds >= (self.dtablesize / 5) * 4 && self.destroy_idle(15) == 0 {
            self.destroy_idle(0);
        }
    }

    /// `__svc_destroy_idle(timeout)`.
    fn destroy_idle(&mut self, timeout: i64) -> usize {
        let now = sys::gettimeofday();
        let mut cleaned = 0;
        let mut tmax = (0i64, 0i64);
        let mut least_active = None;
        // QUIRK: the loop runs over poll slots but looks transports up by slot index, as
        // if it were a descriptor, and goes one slot past the end. That slot's fd is
        // heap bytes past the array (malloc's next chunk header, or slack), which are
        // practically never -1, so it counts as in use: the transport whose descriptor
        // is the table's size is checked too.
        for i in 0..=self.pollfd.len() {
            if self.pollfd.get(i).is_some_and(|p| p.fd == -1) {
                continue;
            }
            let Some(Some(x)) = self.xports.get(i) else { continue };
            let Kind::Conn(c) = &x.kind else { continue };
            let fd = x.fd;
            if timeout == 0 {
                let diff = sub_tv(now, c.last_recv_time);
                if diff > tmax {
                    tmax = diff;
                    least_active = Some(fd);
                }
                continue;
            }
            if now.0 - c.last_recv_time.0 > timeout {
                self.destroy(fd);
                cleaned += 1;
            }
        }
        if timeout == 0
            && let Some(fd) = least_active
        {
            self.destroy(fd);
            cleaned += 1;
        }
        cleaned
    }
}

/// `timersub()`, as a comparable pair.
fn sub_tv(a: (i64, i64), b: (i64, i64)) -> (i64, i64) {
    let (mut s, mut u) = (a.0 - b.0, a.1 - b.1);
    if u < 0 {
        s -= 1;
        u += 1_000_000;
    }
    (s, u)
}
