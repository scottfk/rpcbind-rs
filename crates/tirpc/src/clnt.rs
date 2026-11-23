//! The client side: `clnt_vc.c` (stream clients), `clnt_dg.c` (datagram clients),
//! `clnt_generic.c` (`clnt_tli_create()` and friends), `rpc_prot.c`'s reply decoding,
//! `clnt_perror.c` and `bindresvport.c`.
//!
//! libtirpc keeps process-wide state (`rpc_createerr`, the netconfig cache, the rpcbind
//! address cache, the reserved-port cursor, the `clnt_perror()` buffer); here it lives
//! in one [`Lib`] value that every call takes.

use crate::addr::{self, Netbuf, SockInfo};
use crate::netconfig::{NC_TPI_CLTS, NC_TPI_COTS, NC_TPI_COTS_ORD, Netconfig, NetconfigDb};
use crate::svc::{fd2sockinfo, get_t_size, nconf2fd};
use crate::sys::{self, Fd, SS_LEN};
use crate::xdr::{self, UNIT, XdrDecode, XdrEncode, XdrMem};
use crate::xdr_rec::{ReadResult, RecIo, RecStream};

// `enum clnt_stat`.
pub const RPC_SUCCESS: u32 = 0;
pub const RPC_CANTENCODEARGS: u32 = 1;
pub const RPC_CANTDECODERES: u32 = 2;
pub const RPC_CANTSEND: u32 = 3;
pub const RPC_CANTRECV: u32 = 4;
pub const RPC_TIMEDOUT: u32 = 5;
pub const RPC_VERSMISMATCH: u32 = 6;
pub const RPC_AUTHERROR: u32 = 7;
pub const RPC_PROGUNAVAIL: u32 = 8;
pub const RPC_PROGVERSMISMATCH: u32 = 9;
pub const RPC_PROCUNAVAIL: u32 = 10;
pub const RPC_CANTDECODEARGS: u32 = 11;
pub const RPC_SYSTEMERROR: u32 = 12;
pub const RPC_UNKNOWNHOST: u32 = 13;
pub const RPC_PMAPFAILURE: u32 = 14;
pub const RPC_RPCBFAILURE: u32 = RPC_PMAPFAILURE;
pub const RPC_PROGNOTREGISTERED: u32 = 15;
pub const RPC_FAILED: u32 = 16;
pub const RPC_UNKNOWNPROTO: u32 = 17;
pub const RPC_UNKNOWNADDR: u32 = 19;
pub const RPC_TLIERROR: u32 = 20;
pub const RPC_N2AXLATEFAILURE: u32 = 22;

/// `RPC_ANYFD`.
pub const RPC_ANYFD: Fd = -1;

/// `struct rpc_err`: the status and the two-word union (`re_errno`, `re_why`,
/// `re_vers.low/high`, `re_lb.s1/s2` all share it), which keeps whatever an earlier
/// error left there.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RpcErr {
    pub status: u32,
    pub w: [u32; 2],
}

impl RpcErr {
    pub fn errno(&self) -> i32 {
        self.w[0] as i32
    }
    pub fn set_errno(&mut self, e: i32) {
        self.w[0] = e as u32;
    }
    /// `re_vers.low`.
    pub fn low(&self) -> u32 {
        self.w[0]
    }
    /// `re_vers.high`.
    pub fn high(&self) -> u32 {
        self.w[1]
    }
}

/// `struct rpc_createerr`.
#[derive(Debug, Clone, Copy, Default)]
pub struct CreateErr {
    pub stat: u32,
    pub error: RpcErr,
}

/// `struct timeval`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Timeval {
    pub sec: i64,
    pub usec: i64,
}

impl Timeval {
    pub const fn secs(sec: i64) -> Timeval {
        Timeval { sec, usec: 0 }
    }
    fn ms(&self) -> i32 {
        (self.sec * 1000 + self.usec / 1000) as i32
    }
}

/// One rpcbind address cache entry (`struct address_cache`).
#[derive(Debug, Clone)]
pub(crate) struct CacheEntry {
    pub host: Vec<u8>,
    pub netid: Vec<u8>,
    pub uaddr: Option<Vec<u8>>,
    pub taddr: Netbuf,
}

/// libtirpc's process-wide client state.
#[derive(Debug)]
pub struct Lib {
    pub nc: NetconfigDb,
    /// `rpc_createerr`.
    pub createerr: CreateErr,
    /// `front`: newest first, at most `CACHESIZE`.
    pub(crate) cache: Vec<CacheEntry>,
    /// `local_rpcb()`'s `loopnconf` and `hostname`.
    pub(crate) loopnconf: Option<(Netconfig, &'static [u8])>,
    /// `__rpc_lowvers`.
    pub lowvers: bool,
    /// `__rpcb_findaddr_timed()`'s `portmap_first`.
    pub(crate) portmap_first: bool,
    /// `bindresvport_sa()`'s blacklist (read once) and `startport`.
    resv_blacklist: Option<Vec<u16>>,
    resv_startport: u16,
    /// `clnt_vc_create()`'s `disrupt`.
    disrupt: u32,
    /// `clnt_perror.c`'s `buf`, kept between calls.
    perror_buf: Vec<u8>,
}

impl Default for Lib {
    fn default() -> Self {
        Lib::new(NetconfigDb::default())
    }
}

impl Lib {
    pub fn new(nc: NetconfigDb) -> Lib {
        Lib {
            nc,
            createerr: CreateErr::default(),
            cache: Vec::new(),
            loopnconf: None,
            lowvers: false,
            portmap_first: false,
            resv_blacklist: None,
            resv_startport: STARTPORT,
            disrupt: 0,
            perror_buf: vec![0; CLNT_PERROR_BUFLEN],
        }
    }
}

/// `__RPC_GETXID()`.
fn getxid() -> u32 {
    let (s, us) = sys::gettimeofday();
    (sys::getpid() as u32) ^ (s as u32) ^ (us as u32)
}

/// The marshalled `AUTH_NONE` credential and verifier (`authnone_marshal()`).
const AUTHNONE: [u8; 16] = [0; 16];

// ---------------------------------------------------------------------------
// replies

/// What `xdr_replymsg()` decoded.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ReplyMsg {
    xid: u32,
    /// `rp_stat`: 0 accepted, 1 denied.
    rp_stat: i32,
    /// `ar_stat` or `rj_stat`.
    stat: i32,
    /// `ar_vers`/`rj_vers` (low, high) or `rj_why` in the first word.
    w: [u32; 2],
}

impl ReplyMsg {
    /// `MSG_ACCEPTED` with `SUCCESS`.
    pub(crate) fn accepted_success(&self) -> bool {
        self.rp_stat == 0 && self.stat == 0
    }
}

/// `xdr_replymsg()` decoding, with `xdr_void` for the results (they are decoded after).
pub(crate) fn decode_reply(x: &mut dyn XdrDecode) -> Option<ReplyMsg> {
    let xid = x.get_long()?;
    let dir = xdr::get_i32(x)?;
    if dir != 1 {
        return None;
    }
    let rp_stat = xdr::get_i32(x)?;
    let mut m = ReplyMsg { xid, rp_stat, stat: 0, w: [0; 2] };
    match rp_stat {
        0 => {
            // xdr_accepted_reply(): the verifier (xdr_opaque_auth), then the status.
            xdr::get_i32(x)?;
            xdr::get_bytes(x, crate::rpc::MAX_AUTH_BYTES as u32)?;
            m.stat = xdr::get_i32(x)?;
            if m.stat == 2 {
                m.w[0] = x.get_long()?;
                m.w[1] = x.get_long()?;
            }
        }
        1 => {
            // xdr_rejected_reply()
            m.stat = xdr::get_i32(x)?;
            match m.stat {
                0 => {
                    m.w[0] = x.get_long()?;
                    m.w[1] = x.get_long()?;
                }
                1 => m.w[0] = x.get_long()?,
                _ => return None,
            }
        }
        _ => return None,
    }
    Some(m)
}

/// `_seterr_reply()`.
fn seterr_reply(m: &ReplyMsg, e: &mut RpcErr) {
    match m.rp_stat {
        0 => {
            if m.stat == 0 {
                e.status = RPC_SUCCESS;
                return;
            }
            // accepted()
            e.status = match m.stat {
                1 => RPC_PROGUNAVAIL,
                2 => RPC_PROGVERSMISMATCH,
                3 => RPC_PROCUNAVAIL,
                4 => RPC_CANTDECODEARGS,
                5 => RPC_SYSTEMERROR,
                _ => {
                    e.w = [0, m.stat as u32];
                    RPC_FAILED
                }
            };
        }
        _ => {
            // rejected(): only RPC_MISMATCH and AUTH_ERROR decode.
            e.status = if m.stat == 0 { RPC_VERSMISMATCH } else { RPC_AUTHERROR };
        }
    }
    match e.status {
        RPC_VERSMISMATCH | RPC_PROGVERSMISMATCH => e.w = m.w,
        RPC_AUTHERROR => e.w[0] = m.w[0],
        _ => {}
    }
}

// ---------------------------------------------------------------------------
// the handles

/// A client handle (`CLIENT`).
#[derive(Debug)]
pub struct Client {
    /// `cl_netid`: `None` for NULL (`clnt_vc_create()`/`clnt_dg_create()` alone).
    pub netid: Option<Vec<u8>>,
    /// `cl_tp`.
    pub tp: Option<Vec<u8>>,
    t: Transport,
}

#[derive(Debug)]
enum Transport {
    Vc(Box<Vc>),
    Dg(Box<Dg>),
}

/// `struct ct_data`.
#[derive(Debug)]
struct Vc {
    fd: Fd,
    closeit: bool,
    wait: Timeval,
    waitset: bool,
    addr: Netbuf,
    error: RpcErr,
    /// `ct_mcallc`: the marshalled call header, xid first.
    mcall: [u8; 24],
    mpos: usize,
    rec: RecStream,
}

/// `struct cu_data`.
#[derive(Debug)]
struct Dg {
    fd: Fd,
    closeit: bool,
    raddr: [u8; SS_LEN],
    rlen: usize,
    wait: Timeval,
    total: Timeval,
    error: RpcErr,
    xdrpos: usize,
    outbuf: Vec<u8>,
    inbuf: Vec<u8>,
    connect: bool,
    connected: bool,
}

/// `CLNT_CONTROL` requests that rpcinfo and libtirpc's own callers make.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Control {
    SetFdClose,
    SetFdNclose,
    SetVers(u32),
    SetProg(u32),
    SetRetryTimeout(Timeval),
}

/// `read_vc()`/`write_vc()` over a connection, recording errors in `ct_error`.
struct VcIo<'a> {
    fd: Fd,
    ms: i32,
    error: &'a mut RpcErr,
}

impl RecIo for VcIo<'_> {
    fn read(&mut self, buf: &mut [u8]) -> ReadResult {
        if buf.is_empty() {
            return ReadResult::Data(0);
        }
        loop {
            let mut p = [libc::pollfd { fd: self.fd, events: libc::POLLIN, revents: 0 }];
            match sys::poll(&mut p, self.ms) {
                0 => {
                    self.error.status = RPC_TIMEDOUT;
                    return ReadResult::Error;
                }
                -1 => {
                    let e = sys::errno();
                    if e == libc::EINTR {
                        continue;
                    }
                    self.error.status = RPC_CANTRECV;
                    self.error.set_errno(e);
                    return ReadResult::Error;
                }
                _ => break,
            }
        }
        match sys::read(self.fd, buf) {
            0 => {
                self.error.set_errno(libc::ECONNRESET);
                self.error.status = RPC_CANTRECV;
                ReadResult::Error
            }
            -1 => {
                self.error.set_errno(sys::errno());
                self.error.status = RPC_CANTRECV;
                ReadResult::Error
            }
            n => ReadResult::Data(n as usize),
        }
    }

    fn write(&mut self, buf: &[u8]) -> bool {
        let mut off = 0;
        while off < buf.len() {
            let i = sys::write(self.fd, &buf[off..]);
            if i == -1 {
                self.error.set_errno(sys::errno());
                self.error.status = RPC_CANTSEND;
                return false;
            }
            off += i as usize;
        }
        true
    }
}

/// `time_not_ok()` in `clnt_vc.c` (-1 is not allowed).
fn vc_time_not_ok(t: &Timeval) -> bool {
    t.sec <= -1 || t.sec > 100_000_000 || t.usec <= -1 || t.usec > 1_000_000
}

/// `time_not_ok()` in `clnt_dg.c` (-1 is allowed).
fn dg_time_not_ok(t: &Timeval) -> bool {
    t.sec < -1 || t.sec > 100_000_000 || t.usec < -1 || t.usec > 1_000_000
}

/// `clnt_vc_create()`.
pub fn clnt_vc_create(
    lib: &mut Lib,
    fd: Fd,
    raddr: &Netbuf,
    prog: u32,
    vers: u32,
    sendsz: usize,
    recvsz: usize,
) -> Option<Client> {
    if lib.disrupt == 0 {
        // C seeds it with the address of the caller's netbuf.
        lib.disrupt = (raddr as *const Netbuf as usize) as u32;
    }
    if sys::getpeername(fd).is_none() {
        let e = sys::errno();
        if e != libc::ENOTCONN {
            lib.createerr.stat = RPC_SYSTEMERROR;
            lib.createerr.error.set_errno(e);
            return None;
        }
        if let Err(e) = sys::connect(fd, &raddr.buf, raddr.len)
            && e != libc::EISCONN
        {
            lib.createerr.stat = RPC_SYSTEMERROR;
            lib.createerr.error.set_errno(e);
            return None;
        }
    }
    // A failure here sets no error, as in C.
    let si = fd2sockinfo(fd)?;
    let mut addr = Netbuf { buf: vec![0; raddr.buf.len()], len: raddr.len };
    let n = raddr.len.min(raddr.buf.len());
    addr.buf[..n].copy_from_slice(&raddr.buf[..n]);
    lib.disrupt = lib.disrupt.wrapping_add(1);
    let xid = lib.disrupt ^ getxid();
    let mut mcall = [0u8; 24];
    for (i, w) in [xid, 0, 2, prog, vers].iter().enumerate() {
        mcall[i * UNIT..(i + 1) * UNIT].copy_from_slice(&w.to_be_bytes());
    }
    let sendsz = get_t_size(si.proto, sendsz);
    let recvsz = get_t_size(si.proto, recvsz);
    Some(Client {
        netid: None,
        tp: None,
        t: Transport::Vc(Box::new(Vc {
            fd,
            closeit: false,
            wait: Timeval::default(),
            waitset: false,
            addr,
            error: RpcErr::default(),
            mcall,
            mpos: 5 * UNIT,
            rec: RecStream::new(sendsz, recvsz, 0),
        })),
    })
}

/// `clnt_dg_create()`.
pub fn clnt_dg_create(
    lib: &mut Lib,
    fd: Fd,
    svcaddr: &Netbuf,
    prog: u32,
    vers: u32,
    sendsz: usize,
    recvsz: usize,
) -> Option<Client> {
    let Some(si) = fd2sockinfo(fd) else {
        lib.createerr.stat = RPC_TLIERROR;
        lib.createerr.error.set_errno(0);
        return None;
    };
    let sendsz = xdr::rndup(get_t_size(si.proto, sendsz));
    let recvsz = xdr::rndup(get_t_size(si.proto, recvsz));
    let mut raddr = [0u8; SS_LEN];
    let n = svcaddr.len.min(svcaddr.buf.len()).min(SS_LEN);
    raddr[..n].copy_from_slice(&svcaddr.buf[..n]);
    let mut outbuf = vec![0u8; sendsz];
    {
        let mut x = XdrMem::new(&mut outbuf);
        for w in [getxid(), 0, 2, prog, vers] {
            x.put_long(w);
        }
    }
    sys::setsockopt_int(fd, libc::SOL_IP, libc::IP_RECVERR, 1);
    sys::set_fionbio(fd);
    Some(Client {
        netid: None,
        tp: None,
        t: Transport::Dg(Box::new(Dg {
            fd,
            closeit: false,
            raddr,
            rlen: svcaddr.len,
            wait: Timeval::secs(15),
            total: Timeval { sec: -1, usec: -1 },
            error: RpcErr::default(),
            xdrpos: 5 * UNIT,
            outbuf,
            inbuf: vec![0u8; recvsz],
            connect: false,
            connected: false,
        })),
    })
}

/// Arguments to encode: `xdr_void` is `|_| true`.
pub type Args<'a> = &'a mut dyn FnMut(&mut dyn XdrEncode) -> bool;
/// Results to decode.
pub type Results<'a> = &'a mut dyn FnMut(&mut dyn XdrDecode) -> bool;

impl Client {
    /// `CLNT_CALL()`.
    pub fn call(&mut self, proc_: u32, args: Args<'_>, results: Results<'_>, timeout: Timeval) -> u32 {
        match &mut self.t {
            Transport::Vc(ct) => vc_call(ct, proc_, args, results, timeout),
            Transport::Dg(cu) => dg_call(cu, proc_, args, results, timeout),
        }
    }

    /// `CLNT_GETERR()`.
    pub fn geterr(&self) -> RpcErr {
        match &self.t {
            Transport::Vc(ct) => ct.error,
            Transport::Dg(cu) => cu.error,
        }
    }

    /// `CLNT_CONTROL()`.
    pub fn control(&mut self, req: Control) -> bool {
        match (&mut self.t, req) {
            (Transport::Vc(ct), Control::SetFdClose) => ct.closeit = true,
            (Transport::Vc(ct), Control::SetFdNclose) => ct.closeit = false,
            (Transport::Dg(cu), Control::SetFdClose) => cu.closeit = true,
            (Transport::Dg(cu), Control::SetFdNclose) => cu.closeit = false,
            (Transport::Vc(ct), Control::SetVers(v)) => ct.mcall[16..20].copy_from_slice(&v.to_be_bytes()),
            (Transport::Vc(ct), Control::SetProg(v)) => ct.mcall[12..16].copy_from_slice(&v.to_be_bytes()),
            (Transport::Dg(cu), Control::SetVers(v)) => cu.outbuf[16..20].copy_from_slice(&v.to_be_bytes()),
            (Transport::Dg(cu), Control::SetProg(v)) => cu.outbuf[12..16].copy_from_slice(&v.to_be_bytes()),
            (Transport::Dg(cu), Control::SetRetryTimeout(t)) => {
                if dg_time_not_ok(&t) {
                    return false;
                }
                cu.wait = t;
            }
            (Transport::Vc(_), Control::SetRetryTimeout(_)) => return false,
        }
        true
    }

    /// `CLGET_FD`.
    pub fn fd(&self) -> Fd {
        match &self.t {
            Transport::Vc(ct) => ct.fd,
            Transport::Dg(cu) => cu.fd,
        }
    }

    /// `CLGET_SVC_ADDR`: the server's address (a datagram client's is its whole
    /// `sockaddr_storage`, with `len` of it the address).
    pub fn svc_addr(&self) -> Netbuf {
        match &self.t {
            Transport::Vc(ct) => ct.addr.clone(),
            Transport::Dg(cu) => Netbuf { buf: cu.raddr.to_vec(), len: cu.rlen },
        }
    }

    /// `CLSET_SVC_ADDR`. Stream clients refuse it; datagram clients refuse any
    /// address shorter than a `sockaddr_storage`, which is every real one.
    pub fn set_svc_addr(&mut self, a: &Netbuf) -> bool {
        match &mut self.t {
            Transport::Vc(_) => false,
            Transport::Dg(cu) => {
                if a.len < SS_LEN {
                    return false;
                }
                let n = a.len.min(a.buf.len()).min(SS_LEN);
                cu.raddr[..n].copy_from_slice(&a.buf[..n]);
                cu.rlen = a.len;
                true
            }
        }
    }

    /// `CLNT_DESTROY()`.
    pub fn destroy(self) {
        match self.t {
            Transport::Vc(ct) => {
                if ct.closeit && ct.fd != -1 {
                    sys::close(ct.fd);
                }
            }
            Transport::Dg(cu) => {
                if cu.closeit {
                    sys::close(cu.fd);
                }
            }
        }
    }
}

/// `clnt_vc_call()`.
fn vc_call(ct: &mut Vc, proc_: u32, args: Args<'_>, results: Results<'_>, timeout: Timeval) -> u32 {
    if !ct.waitset && !vc_time_not_ok(&timeout) {
        ct.wait = timeout;
    }
    // shipnow: results are never NULL here.
    let shipnow = true;
    let Vc { fd, wait, error, mcall, mpos, rec, .. } = ct;
    let mut io = VcIo { fd: *fd, ms: wait.ms(), error };
    io.error.status = RPC_SUCCESS;
    // x_id = ntohl(--(*msg_x_id)): the decrement is of the network-order word as a
    // host integer.
    let raw = u32::from_ne_bytes(mcall[0..4].try_into().unwrap()).wrapping_sub(1);
    mcall[0..4].copy_from_slice(&raw.to_ne_bytes());
    let x_id = u32::from_be_bytes(mcall[0..4].try_into().unwrap());
    let ok = {
        let mut e = rec.encoder(&mut io);
        e.put_bytes(&mcall[..*mpos]) && e.put_long(proc_) && e.put_bytes(&AUTHNONE) && args(&mut e)
    };
    if !ok {
        if io.error.status == RPC_SUCCESS {
            io.error.status = RPC_CANTENCODEARGS;
        }
        rec.endofrecord(&mut io, true);
        return io.error.status;
    }
    if !rec.endofrecord(&mut io, shipnow) {
        io.error.status = RPC_CANTSEND;
        return RPC_CANTSEND;
    }
    if timeout.sec == 0 && timeout.usec == 0 {
        io.error.status = RPC_TIMEDOUT;
        return RPC_TIMEDOUT;
    }
    let reply = loop {
        if !rec.skiprecord(&mut io) {
            return io.error.status;
        }
        match decode_reply(&mut rec.blocking_decoder(&mut io)) {
            None => {
                // QUIRK: an undecodable reply is skipped, with the rest of its "record".
                if io.error.status == RPC_SUCCESS {
                    continue;
                }
                return io.error.status;
            }
            Some(m) if m.xid == x_id => break m,
            Some(_) => {}
        }
    };
    seterr_reply(&reply, io.error);
    if io.error.status == RPC_SUCCESS && !results(&mut rec.blocking_decoder(&mut io)) && io.error.status == RPC_SUCCESS
    {
        io.error.status = RPC_CANTDECODERES;
    }
    io.error.status
}

/// `clnt_dg_call()`.
fn dg_call(cu: &mut Dg, proc_: u32, args: Args<'_>, results: Results<'_>, utimeout: Timeval) -> u32 {
    let timeout = if cu.total.usec == -1 { utimeout } else { cu.total };
    let mut total_time = timeout.ms();
    if cu.connect && !cu.connected {
        if let Err(e) = sys::connect(cu.fd, &cu.raddr, cu.rlen) {
            cu.error.set_errno(e);
            cu.error.status = RPC_CANTSEND;
            return cu.error.status;
        }
        cu.connected = true;
    }
    let xid = u32::from_be_bytes(cu.outbuf[0..4].try_into().unwrap()).wrapping_add(1);
    cu.outbuf[0..4].copy_from_slice(&xid.to_be_bytes());
    let outlen = {
        let pos = cu.xdrpos;
        let len = cu.outbuf.len();
        let mut x = XdrMem::resume(&mut cu.outbuf, pos, len - pos);
        if !(x.put_long(proc_) && x.put_bytes(&AUTHNONE) && args(&mut x)) {
            cu.error.status = RPC_CANTENCODEARGS;
            return cu.error.status;
        }
        x.getpos()
    };
    if timeout.sec == 0 && timeout.usec == 0 {
        cu.error.status = RPC_TIMEDOUT;
        return cu.error.status;
    }
    let dest = if cu.connected { None } else { Some((&cu.raddr[..], cu.rlen)) };
    let recvlen: isize = 'send: loop {
        if total_time <= 0 {
            cu.error.status = RPC_TIMEDOUT;
            return cu.error.status;
        }
        let nextsend_time = cu.wait.ms();
        if sys::sendto(cu.fd, &cu.outbuf[..outlen], dest) != outlen as isize {
            cu.error.set_errno(sys::errno());
            cu.error.status = RPC_CANTSEND;
            return cu.error.status;
        }
        let mut pfd = [libc::pollfd { fd: cu.fd, events: libc::POLLIN, revents: 0 }];
        let mut tv = 0;
        while total_time > 0 {
            tv = total_time.min(nextsend_time);
            match sys::poll(&mut pfd, tv) {
                0 => {
                    total_time -= tv;
                    continue 'send;
                }
                -1 => {
                    let e = sys::errno();
                    if e == libc::EINTR {
                        continue;
                    }
                    cu.error.status = RPC_CANTRECV;
                    cu.error.set_errno(e);
                    return cu.error.status;
                }
                _ => {}
            }
            break;
        }
        if pfd[0].revents & libc::POLLERR != 0
            && let Some(e) = recverr(cu, outlen)
        {
            cu.error.set_errno(e);
            cu.error.status = RPC_CANTRECV;
            return cu.error.status;
        }
        let r = loop {
            match sys::recvfrom(cu.fd, &mut cu.inbuf) {
                Err(libc::EINTR) => continue,
                Err(e) => break Err(e),
                Ok(n) => break Ok(n),
            }
        };
        let recvlen = match r {
            Err(e) if e != libc::EWOULDBLOCK => {
                cu.error.set_errno(e);
                cu.error.status = RPC_CANTRECV;
                return cu.error.status;
            }
            // QUIRK: -1 (EWOULDBLOCK) passes the unsigned `recvlen < sizeof(u_int32_t)`
            // test, so the buffer's stale contents are checked for the xid.
            Err(_) => -1,
            // QUIRK: a short datagram, like a stale xid below, costs a whole retransmit
            // interval (15 s, more than most timeouts) and resends at once.
            Ok(n) if n < UNIT => {
                total_time -= tv;
                continue 'send;
            }
            Ok(n) => n as isize,
        };
        if cu.inbuf[0..4] != cu.outbuf[0..4] {
            total_time -= tv;
            continue 'send;
        }
        break recvlen;
    };
    let len = if recvlen < 0 { cu.inbuf.len() } else { recvlen as usize };
    let mut x = XdrMem::new(&mut cu.inbuf[..len]);
    match decode_reply(&mut x) {
        Some(m) => {
            if m.rp_stat == 0 && m.stat == 0 {
                cu.error.status = RPC_SUCCESS;
            } else {
                seterr_reply(&m, &mut cu.error);
            }
            if cu.error.status == RPC_SUCCESS && !results(&mut x) && cu.error.status == RPC_SUCCESS {
                cu.error.status = RPC_CANTDECODERES;
            }
        }
        None => cu.error.status = RPC_CANTDECODERES,
    }
    cu.error.status
}

/// The `IP_RECVERR` check after `POLLERR`: the queued error's errno, when the queued
/// datagram is ours and came back from the server's address.
fn recverr(cu: &Dg, outlen: usize) -> Option<i32> {
    let q = sys::recvmsg_errqueue(cu.fd, outlen).ok()?;
    let sin = &cu.raddr;
    let n = q.len.min(q.data.len());
    let ours = q.data[..n] == cu.outbuf[..n]
        && q.flags & libc::MSG_ERRQUEUE != 0
        && ((q.namelen == 0 && q.len >= 12)
            || (q.namelen == size_of::<libc::sockaddr_in>()
                && i32::from(u16::from_ne_bytes([q.name[0], q.name[1]])) == libc::AF_INET
                && q.name[4..8] == sin[4..8]
                && q.name[2..4] == sin[2..4]));
    if !ours {
        return None;
    }
    q.cmsgs.iter().find(|(l, t, _)| *l == libc::SOL_IP && *t == libc::IP_RECVERR).map(|(_, _, d)| {
        // struct sock_extended_err: ee_errno first.
        i32::from_ne_bytes(d[0..4].try_into().unwrap())
    })
}

// ---------------------------------------------------------------------------
// clnt_generic.c

/// `__rpc_minfd`.
const RPC_MINFD: Fd = 3;

/// `__rpc_raise_fd()`. `fsync()` fails on sockets, so in practice the descriptor stays.
fn raise_fd(fd: Fd) -> Fd {
    if fd >= RPC_MINFD {
        return fd;
    }
    let nfd = sys::dupfd(fd, RPC_MINFD);
    if nfd == -1 {
        return fd;
    }
    if sys::fsync(nfd) == -1 {
        sys::close(nfd);
        return fd;
    }
    if sys::close(fd) == -1 {
        sys::syslog(libc::LOG_ERR, format!("could not close() fd {fd}; mem & fd leak").as_bytes());
    }
    nfd
}

/// `__rpc_socktype2seman()`.
fn socktype2seman(t: i32) -> Option<u32> {
    match t {
        libc::SOCK_DGRAM => Some(NC_TPI_CLTS),
        libc::SOCK_STREAM => Some(NC_TPI_COTS_ORD),
        libc::SOCK_RAW => Some(crate::netconfig::NC_TPI_RAW),
        _ => None,
    }
}

/// `clnt_tli_create()`: `fd` is `RPC_ANYFD` to open one from `nconf`.
pub fn clnt_tli_create(
    lib: &mut Lib,
    fd: Fd,
    nconf: Option<&Netconfig>,
    svcaddr: &Netbuf,
    prog: u32,
    vers: u32,
) -> Option<Client> {
    let mut fd = fd;
    let mut madefd = false;
    let servtype;
    let si: SockInfo;
    let err = |lib: &mut Lib, fd: Fd, madefd: bool| {
        lib.createerr.stat = RPC_SYSTEMERROR;
        lib.createerr.error.set_errno(sys::errno());
        if madefd {
            sys::close(fd);
        }
        None
    };
    if fd == RPC_ANYFD {
        let Some(nc) = nconf else {
            lib.createerr.stat = RPC_UNKNOWNPROTO;
            return None;
        };
        fd = nconf2fd(nc);
        if fd == -1 {
            return err(lib, fd, false);
        }
        if fd < RPC_MINFD {
            fd = raise_fd(fd);
        }
        madefd = true;
        servtype = nc.semantics;
        match fd2sockinfo(fd) {
            Some(s) => si = s,
            None => return err(lib, fd, madefd),
        }
        bindresvport(lib, fd);
    } else {
        match fd2sockinfo(fd) {
            Some(s) => si = s,
            None => return err(lib, fd, madefd),
        }
        match socktype2seman(si.socktype) {
            Some(s) => servtype = s,
            None => {
                lib.createerr.stat = RPC_UNKNOWNPROTO;
                return None;
            }
        }
    }
    if si.af != svcaddr.family() {
        lib.createerr.stat = RPC_UNKNOWNHOST;
        if madefd {
            sys::close(fd);
        }
        return None;
    }
    let cl = match servtype {
        NC_TPI_COTS => clnt_vc_create(lib, fd, svcaddr, prog, vers, 0, 0),
        NC_TPI_COTS_ORD => {
            if let Some(nc) = nconf
                && (nc.protofmly == b"inet" || nc.protofmly == b"inet6")
            {
                sys::setsockopt_int(fd, libc::IPPROTO_TCP, libc::TCP_NODELAY, 1);
            }
            clnt_vc_create(lib, fd, svcaddr, prog, vers, 0, 0)
        }
        NC_TPI_CLTS => clnt_dg_create(lib, fd, svcaddr, prog, vers, 0, 0),
        _ => return err(lib, fd, madefd),
    };
    let Some(mut cl) = cl else {
        if madefd {
            sys::close(fd);
        }
        return None;
    };
    match nconf {
        Some(nc) => {
            cl.netid = Some(nc.netid.clone());
            cl.tp = Some(nc.device.clone());
        }
        None => {
            cl.netid = Some(Vec::new());
            cl.tp = Some(Vec::new());
        }
    }
    if madefd {
        cl.control(Control::SetFdClose);
    }
    Some(cl)
}

/// `clnt_tp_create()`.
pub fn clnt_tp_create(lib: &mut Lib, host: &[u8], prog: u32, vers: u32, nconf: Option<&Netconfig>) -> Option<Client> {
    let Some(nc) = nconf else {
        lib.createerr.stat = RPC_UNKNOWNPROTO;
        return None;
    };
    let mut cl = None;
    let svcaddr = crate::rpcb_clnt::rpcb_findaddr_timed(lib, prog, vers, nc, Some(host), Some(&mut cl), None)?;
    match cl {
        None => clnt_tli_create(lib, RPC_ANYFD, Some(nc), &svcaddr, prog, vers),
        Some(mut c) => {
            if c.set_svc_addr(&svcaddr) {
                if c.netid.is_none() {
                    c.netid = Some(nc.netid.clone());
                }
                if c.tp.is_none() {
                    c.tp = Some(nc.device.clone());
                }
                c.control(Control::SetProg(prog));
                c.control(Control::SetVers(vers));
                Some(c)
            } else {
                c.destroy();
                clnt_tli_create(lib, RPC_ANYFD, Some(nc), &svcaddr, prog, vers)
            }
        }
    }
}

/// `clnt_create()`: each transport of the class in turn until one works.
pub fn clnt_create(lib: &mut Lib, host: &[u8], prog: u32, vers: u32, nettype: Option<&[u8]>) -> Option<Client> {
    if let Some(n) = nettype
        && n.len() >= 32
    {
        lib.createerr.stat = RPC_UNKNOWNPROTO;
        return None;
    }
    let Some(mut h) = crate::nettype::setconf(lib, nettype) else {
        lib.createerr.stat = RPC_UNKNOWNPROTO;
        return None;
    };
    lib.createerr.stat = RPC_SUCCESS;
    let mut saved: Option<CreateErr> = None;
    let mut clnt = None;
    while clnt.is_none() {
        let Some(nc) = crate::nettype::getconf(lib, &mut h) else {
            if lib.createerr.stat == RPC_SUCCESS {
                lib.createerr.stat = RPC_UNKNOWNPROTO;
            }
            break;
        };
        clnt = clnt_tp_create(lib, host, prog, vers, Some(&nc));
        if clnt.is_none() && lib.createerr.stat != RPC_N2AXLATEFAILURE && lib.createerr.stat != RPC_UNKNOWNHOST {
            saved = Some(lib.createerr);
        }
    }
    if (lib.createerr.stat == RPC_N2AXLATEFAILURE || lib.createerr.stat == RPC_UNKNOWNHOST)
        && let Some(s) = saved
        && s.stat != RPC_SUCCESS
    {
        lib.createerr = s;
    }
    crate::nettype::endconf(lib, h);
    clnt
}

// ---------------------------------------------------------------------------
// bindresvport.c

const STARTPORT: u16 = 600;
const LOWPORT: u16 = 512;
const ENDPORT: u16 = 1023;

/// `load_blacklist()`: `/etc/bindresvport.blacklist`.
fn load_blacklist() -> Vec<u16> {
    let Ok(text) = std::fs::read("/etc/bindresvport.blacklist") else {
        return Vec::new();
    };
    let mut list = Vec::new();
    for line in text.split_inclusive(|&b| b == b'\n') {
        let mut l = line;
        if let Some(i) = l.iter().position(|&b| b == b'#') {
            l = &l[..i];
        }
        while let [c, rest @ ..] = l
            && c.is_ascii_whitespace()
        {
            l = rest;
        }
        let l = l.strip_suffix(b"\n").unwrap_or(l);
        if l.is_empty() {
            continue;
        }
        // strtoul(cp, &tmp, 0), then only spaces may follow.
        let (port, used, erange) = sys::strtoul0(l);
        if !l[used..].iter().all(|b| b.is_ascii_whitespace()) || (port == u64::MAX && erange) {
            continue;
        }
        if port < u64::from(LOWPORT) || port > u64::from(ENDPORT) {
            continue;
        }
        list.push(port as u16);
    }
    list
}

/// `bindresvport(fd, NULL)`: bind to a reserved port, starting from one picked by pid.
pub fn bindresvport(lib: &mut Lib, fd: Fd) -> i32 {
    if lib.resv_blacklist.is_none() {
        lib.resv_blacklist = Some(load_blacklist());
    }
    let Some((mut ss, _)) = sys::getsockname(fd) else {
        return -1;
    };
    let af = i32::from(u16::from_ne_bytes([ss[0], ss[1]]));
    let salen = match af {
        libc::AF_INET => size_of::<libc::sockaddr_in>(),
        libc::AF_INET6 => size_of::<libc::sockaddr_in6>(),
        _ => {
            sys::set_errno(libc::EPFNOSUPPORT);
            return -1;
        }
    };
    let mut port = u16::from_be_bytes([ss[2], ss[3]]);
    let mut startport = lib.resv_startport;
    let mut nports = usize::from(ENDPORT - startport + 1);
    let mut endport = ENDPORT;
    let npts = ENDPORT - STARTPORT + 1;
    if port == 0 {
        port = (sys::getpid() as u16 % npts) + STARTPORT;
    }
    let black = lib.resv_blacklist.clone().unwrap_or_default();
    let mut res = -1;
    sys::set_errno(libc::EADDRINUSE);
    loop {
        let mut i = 0;
        while i < nports {
            if !black.contains(&port) {
                ss[2..4].copy_from_slice(&port.to_be_bytes());
                res = sys::bind(fd, &ss, salen);
                if res >= 0 || sys::errno() != libc::EADDRINUSE {
                    break;
                }
            }
            port += 1;
            if port > endport {
                port = startport;
            }
            i += 1;
        }
        if i == nports && startport != LOWPORT {
            startport = LOWPORT;
            lib.resv_startport = LOWPORT;
            endport = STARTPORT - 1;
            nports = usize::from(STARTPORT - LOWPORT);
            port = LOWPORT + port % (STARTPORT - LOWPORT);
            continue;
        }
        break;
    }
    res
}

// ---------------------------------------------------------------------------
// clnt_perror.c

const CLNT_PERROR_BUFLEN: usize = 256;

/// `clnt_sperrno()`.
pub fn sperrno(stat: u32) -> &'static str {
    const L: [&str; 18] = [
        "RPC: Success",
        "RPC: Can't encode arguments",
        "RPC: Can't decode result",
        "RPC: Unable to send",
        "RPC: Unable to receive",
        "RPC: Timed out",
        "RPC: Incompatible versions of RPC",
        "RPC: Authentication error",
        "RPC: Program unavailable",
        "RPC: Program/version mismatch",
        "RPC: Procedure unavailable",
        "RPC: Server can't decode arguments",
        "RPC: Remote system error",
        "RPC: Unknown host",
        "RPC: Port mapper failure",
        "RPC: Program not registered",
        "RPC: Failed (unspecified error)",
        "RPC: Unknown protocol",
    ];
    L.get(stat as usize).copied().unwrap_or("RPC: (unknown error code)")
}

/// `auth_errmsg()`.
fn auth_errmsg(why: u32) -> Option<&'static str> {
    const L: [&str; 8] = [
        "Authentication OK",
        "Invalid client credential",
        "Server rejected credential",
        "Invalid client verifier",
        "Server rejected verifier",
        "Client credential too weak",
        "Invalid server verifier",
        "Failed (unspecified error)",
    ];
    L.get(why as usize).copied()
}

/// C string operations on the `clnt_perror()` buffer. QUIRK: C overruns it in places
/// (its `strncat()` limits come from a length it doesn't update); here it just grows,
/// and the result is cut at byte 255 as C cuts it.
struct CBuf<'a>(&'a mut Vec<u8>);

impl CBuf<'_> {
    fn ensure(&mut self, n: usize) {
        if self.0.len() < n {
            self.0.resize(n, 0);
        }
    }
    fn strlen(&self, at: usize) -> usize {
        self.0[at..].iter().position(|&b| b == 0).unwrap_or(self.0.len() - at)
    }
    /// `snprintf(buf + at, n, "%s", s)`: the length `s` would have.
    fn snprintf(&mut self, at: usize, n: usize, s: &[u8]) -> usize {
        if n > 0 {
            let k = s.len().min(n - 1);
            self.ensure(at + k + 1);
            self.0[at..at + k].copy_from_slice(&s[..k]);
            self.0[at + k] = 0;
        }
        s.len()
    }
    /// `strncpy(buf + at, s, n)`.
    fn strncpy(&mut self, at: usize, s: &[u8], n: usize) {
        self.ensure(at + n);
        let k = s.len().min(n);
        self.0[at..at + k].copy_from_slice(&s[..k]);
        for b in &mut self.0[at + k..at + n] {
            *b = 0;
        }
    }
    /// `strncat(buf, s, n)`, `n` as a `size_t` (a "negative" one is huge).
    fn strncat(&mut self, s: &[u8], n: isize) {
        let at = self.strlen(0);
        let k = if n < 0 { s.len() } else { s.len().min(n as usize) };
        self.ensure(at + k + 1);
        self.0[at..at + k].copy_from_slice(&s[..k]);
        self.0[at + k] = 0;
    }
    fn result(&mut self) -> Vec<u8> {
        self.ensure(CLNT_PERROR_BUFLEN);
        self.0[CLNT_PERROR_BUFLEN - 1] = 0;
        let n = self.strlen(0);
        self.0[..n].to_vec()
    }
}

/// `clnt_sperror(rpch, s)`.
pub fn sperror(lib: &mut Lib, cl: &Client, s: &[u8]) -> Vec<u8> {
    let e = cl.geterr();
    let mut b = CBuf(&mut lib.perror_buf);
    let mut str_ = 0usize;
    let mut len = CLNT_PERROR_BUFLEN;
    let mut pre = s.to_vec();
    pre.extend_from_slice(b": ");
    if b.snprintf(str_, len, &pre) > 0 {
        let i = b.strlen(str_);
        str_ += i;
        len -= i;
    }
    b.strncpy(str_, sperrno(e.status).as_bytes(), len - 1);
    let i = b.strlen(str_);
    str_ += i;
    len -= i;
    let mut add = |b: &mut CBuf<'_>, t: &[u8]| {
        b.snprintf(str_, len, t);
        let i = b.strlen(str_);
        if i > 0 {
            str_ += i;
            len -= i;
        }
    };
    match e.status {
        RPC_SUCCESS
        | RPC_CANTENCODEARGS
        | RPC_CANTDECODERES
        | RPC_TIMEDOUT
        | RPC_PROGUNAVAIL
        | RPC_PROCUNAVAIL
        | RPC_CANTDECODEARGS
        | RPC_SYSTEMERROR
        | RPC_UNKNOWNHOST
        | RPC_UNKNOWNPROTO
        | RPC_PMAPFAILURE
        | RPC_PROGNOTREGISTERED
        | RPC_FAILED => {}
        RPC_CANTSEND | RPC_CANTRECV => {
            let mut t = b"; errno = ".to_vec();
            t.extend_from_slice(&sys::strerror(e.errno()));
            add(&mut b, &t);
        }
        RPC_VERSMISMATCH | RPC_PROGVERSMISMATCH => {
            add(&mut b, format!("; low version = {}, high version = {}", e.low(), e.high()).as_bytes());
        }
        RPC_AUTHERROR => {
            add(&mut b, b"; why = ");
            match auth_errmsg(e.w[0]) {
                Some(m) => add(&mut b, m.as_bytes()),
                None => add(&mut b, format!("(unknown authentication error - {})", e.w[0] as i32).as_bytes()),
            }
        }
        _ => add(&mut b, format!("; s1 = {}, s2 = {}", e.w[0], e.w[1]).as_bytes()),
    }
    b.result()
}

/// `clnt_perror(rpch, s)`.
pub fn perror(lib: &mut Lib, cl: &Client, s: &[u8]) {
    let mut m = sperror(lib, cl, s);
    m.push(b'\n');
    sys::c_stderr(&m);
}

/// `clnt_spcreateerror(s)`.
pub fn spcreateerror(lib: &mut Lib, s: &[u8]) -> Vec<u8> {
    let ce = lib.createerr;
    let mut b = CBuf(&mut lib.perror_buf);
    let mut len = CLNT_PERROR_BUFLEN as isize;
    let mut pre = s.to_vec();
    pre.extend_from_slice(b": ");
    b.snprintf(0, CLNT_PERROR_BUFLEN, &pre);
    let i = b.strlen(0) as isize;
    if i > 0 {
        len -= i;
    }
    b.strncat(sperrno(ce.stat).as_bytes(), len - 1);
    match ce.stat {
        RPC_PMAPFAILURE => {
            b.strncat(b" - ", len - 1);
            let err = sperrno(ce.error.status);
            b.strncat(&err.as_bytes()[5..], len - 5);
            if ce.error.status == RPC_CANTSEND || ce.error.status == RPC_CANTRECV {
                let i = b.strlen(0);
                len -= i as isize;
                let mut t = format!(": errno {} (", ce.error.errno()).into_bytes();
                t.extend_from_slice(&sys::strerror(ce.error.errno()));
                t.push(b')');
                // A "negative" size_t is huge: no limit.
                let n = if len < 0 { usize::MAX } else { len as usize };
                b.snprintf(i, n, &t);
            }
        }
        RPC_SYSTEMERROR => {
            b.strncat(b" - ", len - 1);
            b.strncat(&sys::strerror(ce.error.errno()), len - 4);
        }
        _ => {}
    }
    b.result()
}

/// `clnt_pcreateerror(s)`.
pub fn pcreateerror(lib: &mut Lib, s: &[u8]) {
    let mut m = spcreateerror(lib, s);
    m.push(b'\n');
    sys::c_stderr(&m);
}

/// The address family of a netconfig entry, for callers that build addresses.
pub fn nconf_af(nc: &Netconfig) -> Option<i32> {
    addr::nconf2sockinfo(nc).map(|s| s.af)
}
