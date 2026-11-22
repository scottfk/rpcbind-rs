//! `pmap_svc.c`: portmap version 2.

use crate::Rpcbind;
use crate::rpcb_stat::RPCBVERS_2_STAT;
use crate::rpcb_svc_com::getowner;
use crate::security::check_access;
use crate::xlog::L_ERROR;
use tirpc::rpcb_prot::{self, Pmap, Rpcb};
use tirpc::svc::Request;

const PMAPPROC_SET: u32 = 1;
const PMAPPROC_UNSET: u32 = 2;
const PMAPPROC_GETPORT: u32 = 3;
const PMAPPROC_DUMP: u32 = 4;

/// After a failed `svc_sendreply()`.
fn sendreply_failed(rb: &Rpcbind) {
    if rb.debugging > 0 {
        rb.xlog.xlog(L_ERROR, b"portmap: svc_sendreply failed!\n");
        if rb.doabort {
            crate::rpcbind_abort();
        }
    }
}

/// `xdr_long` of a C `long` (`TRUE`/`FALSE`, or a port).
fn reply_long(rb: &Rpcbind, req: &mut Request<'_>, v: u32) {
    if !req.sendreply(&mut |x| x.put_long(v)) {
        sendreply_failed(rb);
    }
}

/// `pmapproc_change()`: `SET` and `UNSET`.
fn pmapproc_change(rb: &mut Rpcbind, req: &mut Request<'_>, op: u32) {
    // Can't use getpwnam here: we might end up calling ourselves and looping.
    let owner = getowner(rb, req);
    let Some(reg) = req.getargs(rpcb_prot::get_pmap) else {
        req.svcerr_decode();
        return;
    };
    if !check_access(&rb.access, req.caller(), op, reg.prog) {
        req.svcerr_weakauth();
        return;
    }
    let ans = if op == PMAPPROC_SET {
        match rb.ipprot2netid(reg.prot) {
            None => false,
            Some(netid) => {
                let (hi, lo) = ((reg.port >> 8) & 0xff, reg.port & 0xff);
                let addr = if netid.starts_with(b"udp6") || netid.starts_with(b"tcp6") {
                    format!("::.{hi}.{lo}")
                } else {
                    format!("0.0.0.0.{hi}.{lo}")
                };
                let r = Rpcb { prog: reg.prog, vers: reg.vers, netid, addr: addr.into_bytes(), owner: Vec::new() };
                rb.map_set(&r, &owner)
            }
        }
    } else {
        // Unset on the TCP transport, then the UDP one. QUIRK: with no IPv4 transport
        // of a kind its name is "", which map_unset() takes as every netid.
        let tcp = rb.tcptrans.clone().unwrap_or_default();
        let udp = rb.udptrans.clone().unwrap_or_default();
        let a1 = rb.map_unset(reg.prog, reg.vers, &tcp, &owner);
        let a2 = rb.map_unset(reg.prog, reg.vers, &udp, &owner);
        a1 || a2
    };
    reply_long(rb, req, u32::from(ans));
    if op == PMAPPROC_SET {
        rb.stats.set(RPCBVERS_2_STAT, ans);
    } else {
        rb.stats.unset(RPCBVERS_2_STAT, ans);
    }
}

/// `find_service_pmap()`.
fn find_service_pmap(rb: &Rpcbind, prog: u32, vers: u32, prot: u32) -> Option<Pmap> {
    let mut hit = None;
    for p in &rb.list_pml {
        if p.prog != prog || p.prot != prot {
            continue;
        }
        hit = Some(*p);
        if p.vers == vers {
            break;
        }
    }
    hit
}

/// `pmapproc_getport()`.
fn pmapproc_getport(rb: &mut Rpcbind, req: &mut Request<'_>) {
    let Some(reg) = req.getargs(rpcb_prot::get_pmap) else {
        req.svcerr_decode();
        return;
    };
    if !check_access(&rb.access, req.caller(), PMAPPROC_GETPORT, reg.prog) {
        req.svcerr_weakauth();
        return;
    }
    let mut port = 0;
    if let Some(f) = find_service_pmap(rb, reg.prog, reg.vers, reg.prot)
        && let Some(netid) = rb.ipprot2netid(reg.prot)
    {
        let serveuaddr = format!("0.0.0.0.{}.{}", (f.port >> 8) & 0xff, f.port & 0xff);
        if rb.fdlist.is_bound(&netid, serveuaddr.as_bytes()) {
            port = f.port;
        } else {
            // This service is dead; delete it.
            rb.delete_prog(reg.prog);
        }
    }
    reply_long(rb, req, port);
    let netid = rb.ipprot2netid(reg.prot).unwrap_or_else(|| b"<unknown>".to_vec());
    // QUIRK: the "address" counted is udptrans when a port was found.
    let uaddr = if port != 0 { rb.udptrans.clone().unwrap_or_default() } else { Vec::new() };
    let fd = std::mem::take(&mut rb.fdlist);
    rb.stats.getaddr(&fd, RPCBVERS_2_STAT, reg.prog, reg.vers, &netid, Some(&uaddr));
    rb.fdlist = fd;
}

/// `pmapproc_dump()`.
fn pmapproc_dump(rb: &mut Rpcbind, req: &mut Request<'_>) {
    if req.getargs(|_| Some(())).is_none() {
        req.svcerr_decode();
        return;
    }
    if !check_access(&rb.access, req.caller(), PMAPPROC_DUMP, 0) {
        req.svcerr_weakauth();
        return;
    }
    let ok = {
        let list = &rb.list_pml;
        req.sendreply(&mut |x| rpcb_prot::put_pmaplist(x, list))
    };
    if !ok {
        sendreply_failed(rb);
    }
}

/// `pmap_service()`.
pub fn pmap_service(rb: &mut Rpcbind, req: &mut Request<'_>) {
    rb.stats.procinfo(RPCBVERS_2_STAT, req.call.proc_);
    match req.call.proc_ {
        0 => {
            check_access(&rb.access, req.caller(), 0, 0);
            if !req.sendreply(&mut |_| true) && rb.debugging > 0 && rb.doabort {
                crate::rpcbind_abort();
            }
        }
        PMAPPROC_SET | PMAPPROC_UNSET => {
            let op = req.call.proc_;
            pmapproc_change(rb, req, op);
        }
        PMAPPROC_GETPORT => pmapproc_getport(rb, req),
        PMAPPROC_DUMP => pmapproc_dump(rb, req),
        5 => rb.callit_com(req, 5, 2),
        _ => req.svcerr_noproc(),
    }
}
