//! `rpcb_svc.c`: rpcbind version 3.

use crate::Rpcbind;
use crate::rpcb_stat::RPCBVERS_3_STAT;
use crate::security::check_access;
use tirpc::svc::Request;

/// `rpcb_service_3()`.
pub fn rpcb_service_3(rb: &mut Rpcbind, req: &mut Request<'_>) {
    rb.stats.procinfo(RPCBVERS_3_STAT, req.call.proc_);
    match req.call.proc_ {
        0 => {
            // This call just logs, no actual checks.
            check_access(&rb.access, req.caller(), 0, 0);
            req.sendreply(&mut |_| true);
        }
        // SET, UNSET, GETADDR, DUMP, CALLIT, GETTIME, UADDR2TADDR, TADDR2UADDR: phase 2.
        1..=8 => crate::not_ported(rb, req),
        _ => req.svcerr_noproc(),
    }
}
