//! `pmap_svc.c`: portmap version 2.

use crate::Rpcbind;
use crate::rpcb_stat::RPCBVERS_2_STAT;
use crate::security::check_access;
use tirpc::svc::Request;

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
        // SET, UNSET, GETPORT, DUMP, CALLIT: phase 2.
        1..=5 => crate::not_ported(rb, req),
        _ => req.svcerr_noproc(),
    }
}
