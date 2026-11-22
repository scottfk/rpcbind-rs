//! `rpcb_svc_4.c`: rpcbind version 4.

use crate::Rpcbind;
use crate::rpcb_stat::RPCBVERS_4_STAT;
use crate::rpcb_svc::{self, ArgType, Args, Res, serve};
use crate::rpcb_svc_com::VersType;
use crate::security::check_access;
use tirpc::rpcb_prot::RpcbEntry;
use tirpc::svc::Request;

/// `rpcbproc_getversaddr_4_local()`.
fn getversaddr(rb: &mut Rpcbind, a: &Args, req: &mut Request<'_>, v: u32) -> Res {
    let Args::Rpcb(r) = a else { unreachable!() };
    Res::Str(rb.getaddr_com(r, req, v, VersType::One))
}

/// `rpcbproc_getaddrlist_4_local()`: merged addresses of the program and version on every
/// transport of the caller's protocol family.
fn getaddrlist(rb: &mut Rpcbind, a: &Args, req: &mut Request<'_>, _v: u32) -> Res {
    let Args::Rpcb(reg) = a else { unreachable!() };
    let netid = req.xprt.netid.clone().unwrap_or_default();
    let Some(reg_nconf) = rb.fdlist.get_conf(&netid).cloned() else {
        return Res::None;
    };
    let saddr = if reg.addr.is_empty() { None } else { Some(reg.addr.clone()) };
    let mut list = Vec::new();
    let mut maddr: Option<Vec<u8>> = None;
    let entries: Vec<_> = rb.list_rbl.iter().filter(|r| r.prog == reg.prog && r.vers == reg.vers).cloned().collect();
    for r in entries {
        // QUIRK: an entry whose netid rpcbind doesn't serve fails the whole
        // procedure, which then sends no reply at all.
        let Some(nconf) = rb.fdlist.get_conf(&r.netid).cloned() else {
            return Res::None;
        };
        if nconf.protofmly != reg_nconf.protofmly {
            continue; // not the same protocol family
        }
        match rb.fdlist.mergeaddr(req.caller(), &r.netid, &r.addr, saddr.as_deref()) {
            None => {
                maddr = None;
                continue;
            }
            Some(m) if m.is_empty() => {
                // The server died: unset this combination.
                rb.delete_prog(reg.prog);
                maddr = Some(m);
                continue;
            }
            Some(m) => {
                maddr = Some(m.clone());
                list.push(RpcbEntry {
                    maddr: m,
                    nc_netid: nconf.netid.clone(),
                    nc_semantics: nconf.semantics,
                    nc_protofmly: nconf.protofmly.clone(),
                    nc_proto: nconf.proto.clone(),
                });
            }
        }
    }
    // getaddrlist info is also counted as getaddr, with the last merged address.
    let fd = std::mem::take(&mut rb.fdlist);
    rb.stats.getaddr(&fd, 2, reg.prog, reg.vers, &netid, maddr.as_deref());
    rb.fdlist = fd;
    Res::Entries(list)
}

/// `rpcbproc_getstat()`.
fn getstat(_rb: &mut Rpcbind, _a: &Args, _req: &mut Request<'_>, _v: u32) -> Res {
    Res::Stat
}

/// `rpcb_service_4()`.
pub fn rpcb_service_4(rb: &mut Rpcbind, req: &mut Request<'_>) {
    rb.stats.procinfo(RPCBVERS_4_STAT, req.call.proc_);
    type L = fn(&mut Rpcbind, &Args, &mut Request<'_>, u32) -> Res;
    let (argt, local): (ArgType, L) = match req.call.proc_ {
        0 => {
            check_access(&rb.access, req.caller(), 0, 0);
            req.sendreply(&mut |_| true);
            return;
        }
        1 => (ArgType::Rpcb, rpcb_svc::set),
        2 => (ArgType::Rpcb, rpcb_svc::unset),
        3 => (ArgType::Rpcb, rpcb_svc::getaddr),
        9 => (ArgType::Rpcb, getversaddr),
        4 => (ArgType::Void, rpcb_svc::dump),
        10 | 5 => {
            // RPCBPROC_INDIRECT, and RPCBPROC_BCAST (CALLIT's number).
            let p = req.call.proc_;
            rb.callit_com(req, p, 4);
            return;
        }
        6 => (ArgType::Void, rpcb_svc::gettime),
        7 => (ArgType::Str, rpcb_svc::uaddr2taddr),
        8 => (ArgType::Netbuf, rpcb_svc::taddr2uaddr),
        11 => (ArgType::Rpcb, getaddrlist),
        12 => (ArgType::Void, getstat),
        _ => {
            req.svcerr_noproc();
            return;
        }
    };
    serve(rb, req, 4, argt, local, "\n");
}
