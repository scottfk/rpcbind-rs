//! `rpcb_svc.c`: rpcbind version 3, and the decode-check-reply sequence it shares with
//! version 4.

use crate::Rpcbind;
use crate::rpcb_stat::RPCBVERS_3_STAT;
use crate::rpcb_svc_com::{VersType, access};
use crate::security::check_access;
use crate::xlog::LOG_DEBUG_KIND;
use tirpc::rpcb_prot::{self, Rpcb, RpcbEntry, WireNetbuf};
use tirpc::svc::Request;
use tirpc::xdr::{self, RPC_MAXDATASIZE, XdrDecode, XdrEncode};

/// A procedure's decoded arguments.
#[derive(Debug)]
pub enum Args {
    Void,
    Rpcb(Rpcb),
    Str(Vec<u8>),
    Netbuf(WireNetbuf),
}

/// What to decode.
#[derive(Debug, Clone, Copy)]
pub enum ArgType {
    Void,
    Rpcb,
    /// `xdr_wrapstring`.
    Str,
    Netbuf,
}

/// A procedure's result, for `svc_sendreply()`; `None` sends nothing.
#[derive(Debug)]
pub enum Res {
    None,
    Bool(bool),
    Str(Vec<u8>),
    RpcbList,
    /// `xdr_u_long` of a `time_t`.
    Time(i64),
    Netbuf(u32, Vec<u8>),
    Entries(Vec<RpcbEntry>),
    Stat,
}

fn decode(t: ArgType, x: &mut dyn XdrDecode) -> Option<Args> {
    Some(match t {
        ArgType::Void => Args::Void,
        ArgType::Rpcb => Args::Rpcb(rpcb_prot::get_rpcb(x)?),
        ArgType::Str => {
            let mut s = xdr::get_string(x, RPC_MAXDATASIZE)?;
            if let Some(n) = s.iter().position(|&b| b == 0) {
                s.truncate(n);
            }
            Args::Str(s)
        }
        ArgType::Netbuf => Args::Netbuf(rpcb_prot::get_netbuf(x)?),
    })
}

fn encode(rb: &Rpcbind, res: &Res, x: &mut dyn XdrEncode) -> bool {
    match res {
        Res::None => true,
        Res::Bool(b) => xdr::put_bool(x, *b),
        Res::Str(s) => xdr::put_string(x, s, RPC_MAXDATASIZE),
        Res::RpcbList => rpcb_prot::put_rpcblist(x, &rb.list_rbl),
        Res::Time(t) => x.put_long(*t as u32),
        Res::Netbuf(maxlen, b) => rpcb_prot::put_netbuf(x, *maxlen, b),
        Res::Entries(e) => rpcb_prot::put_rpcb_entry_list(x, e),
        Res::Stat => rpcb_prot::put_rpcb_stat_byvers(x, &rb.stats.inf),
    }
}

/// The common tail of `rpcb_service_3()`/`rpcb_service_4()`: decode the arguments,
/// check access, run the procedure, reply. `nl` is "\n" for version 4's debug messages.
pub fn serve(
    rb: &mut Rpcbind,
    req: &mut Request<'_>,
    vers: u32,
    argt: ArgType,
    local: fn(&mut Rpcbind, &Args, &mut Request<'_>, u32) -> Res,
    nl: &str,
) {
    let proc_ = req.call.proc_;
    let Some(args) = req.getargs(|x| decode(argt, x)) else {
        req.svcerr_decode();
        if rb.debugging > 0 {
            rb.xlog.xlog(LOG_DEBUG_KIND, format!("rpcbind: could not decode{nl}").as_bytes());
        }
        return;
    };
    // SET, UNSET and GETADDR log the program; the rest log 0.
    let setprog = match (&args, proc_) {
        (Args::Rpcb(r), 1..=3) => r.prog,
        _ => 0,
    };
    if !access(rb, req, proc_, setprog) {
        req.svcerr_weakauth();
        return;
    }
    let res = local(rb, &args, req, vers);
    if matches!(res, Res::None) {
        return;
    }
    let ok = {
        let rb_ref: &Rpcbind = rb;
        req.sendreply(&mut |x| encode(rb_ref, &res, x))
    };
    if !ok {
        req.svcerr_systemerr();
        if rb.debugging > 0 {
            rb.xlog.xlog(LOG_DEBUG_KIND, format!("rpcbind: svc_sendreply{nl}").as_bytes());
            if rb.doabort {
                crate::rpcbind_abort();
            }
        }
    }
}

fn rpcb(a: &Args) -> &Rpcb {
    match a {
        Args::Rpcb(r) => r,
        _ => unreachable!(),
    }
}

pub fn set(rb: &mut Rpcbind, a: &Args, req: &mut Request<'_>, v: u32) -> Res {
    Res::Bool(rb.set_com(rpcb(a), req, v))
}

pub fn unset(rb: &mut Rpcbind, a: &Args, req: &mut Request<'_>, v: u32) -> Res {
    Res::Bool(rb.unset_com(rpcb(a), req, v))
}

/// `rpcbproc_getaddr_3_local()`/`rpcbproc_getaddr_4_local()`.
pub fn getaddr(rb: &mut Rpcbind, a: &Args, req: &mut Request<'_>, v: u32) -> Res {
    Res::Str(rb.getaddr_com(rpcb(a), req, v, VersType::All))
}

/// `rpcbproc_dump_3_local()`/`rpcbproc_dump_4_local()`.
pub fn dump(_rb: &mut Rpcbind, _a: &Args, _req: &mut Request<'_>, _v: u32) -> Res {
    Res::RpcbList
}

/// `rpcbproc_gettime_com()`.
pub fn gettime(_rb: &mut Rpcbind, _a: &Args, _req: &mut Request<'_>, _v: u32) -> Res {
    Res::Time(tirpc::sys::time())
}

pub fn uaddr2taddr(rb: &mut Rpcbind, a: &Args, req: &mut Request<'_>, _v: u32) -> Res {
    let Args::Str(u) = a else { unreachable!() };
    let (maxlen, b) = rb.uaddr2taddr_com(u, req);
    Res::Netbuf(maxlen, b)
}

pub fn taddr2uaddr(rb: &mut Rpcbind, a: &Args, req: &mut Request<'_>, _v: u32) -> Res {
    let Args::Netbuf(n) = a else { unreachable!() };
    Res::Str(rb.taddr2uaddr_com(&n.buf, req))
}

/// `rpcb_service_3()`.
pub fn rpcb_service_3(rb: &mut Rpcbind, req: &mut Request<'_>) {
    rb.stats.procinfo(RPCBVERS_3_STAT, req.call.proc_);
    type L = fn(&mut Rpcbind, &Args, &mut Request<'_>, u32) -> Res;
    let (argt, local): (ArgType, L) = match req.call.proc_ {
        0 => {
            // This call just logs, no actual checks.
            check_access(&rb.access, req.caller(), 0, 0);
            req.sendreply(&mut |_| true);
            return;
        }
        1 => (ArgType::Rpcb, set),
        2 => (ArgType::Rpcb, unset),
        3 => (ArgType::Rpcb, getaddr),
        4 => (ArgType::Void, dump),
        5 => {
            rb.callit_com(req, 5, 3);
            return;
        }
        6 => (ArgType::Void, gettime),
        7 => (ArgType::Str, uaddr2taddr),
        8 => (ArgType::Netbuf, taddr2uaddr),
        _ => {
            req.svcerr_noproc();
            return;
        }
    };
    serve(rb, req, 3, argt, local, "");
}
