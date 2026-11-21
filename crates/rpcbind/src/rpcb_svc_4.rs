//! `rpcb_svc_4.c`: rpcbind version 4.

use crate::Rpcbind;
use crate::rpcb_stat::RPCBVERS_4_STAT;
use crate::security::check_access;
use tirpc::svc::Request;

/// `rpcb_service_4()`.
pub fn rpcb_service_4(rb: &mut Rpcbind, req: &mut Request<'_>) {
    rb.stats.procinfo(RPCBVERS_4_STAT, req.call.proc_);
    match req.call.proc_ {
        0 => {
            check_access(&rb.access, req.caller(), 0, 0);
            req.sendreply(&mut |_| true);
        }
        // SET .. GETSTAT: phase 2.
        1..=12 => crate::not_ported(rb, req),
        _ => req.svcerr_noproc(),
    }
}
