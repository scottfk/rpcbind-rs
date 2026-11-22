//! `rpcb_stat.c`: the counters `GETSTAT` reports.

use crate::check_bound::FdList;
use tirpc::rpcb_prot::{AddrStat, RPCBVERS_STAT, RmtcallStat, Rpcb, RpcbStat};

pub const RPCBVERS_2_STAT: usize = 0;
pub const RPCBVERS_3_STAT: usize = 1;
pub const RPCBVERS_4_STAT: usize = 2;

/// `rpcb_highproc_2/3/4`: `CALLIT`, `TADDR2UADDR`, `GETSTAT`.
const HIGHPROC: [u32; RPCBVERS_STAT] = [5, 8, 12];

/// `RPCBPROC_INDIRECT`.
const RPCBPROC_INDIRECT: u32 = 10;

/// `inf`.
#[derive(Debug, Default)]
pub struct Stats {
    pub inf: [RpcbStat; RPCBVERS_STAT],
}

impl Stats {
    /// `rpcbs_procinfo()`.
    pub fn procinfo(&mut self, rtype: usize, proc_: u32) {
        if rtype >= RPCBVERS_STAT || proc_ > HIGHPROC[rtype] {
            return;
        }
        self.inf[rtype].info[proc_ as usize] += 1;
    }

    /// `rpcbs_set()`. `rtype` is `rpcbversnum - 2` and can be out of range.
    pub fn set(&mut self, rtype: usize, success: bool) {
        if rtype >= RPCBVERS_STAT || !success {
            return;
        }
        self.inf[rtype].setinfo += 1;
    }

    /// `rpcbs_unset()`.
    pub fn unset(&mut self, rtype: usize, success: bool) {
        if rtype >= RPCBVERS_STAT || !success {
            return;
        }
        self.inf[rtype].unsetinfo += 1;
    }

    /// `rpcbs_getaddr()`: count a lookup as a success (a non-empty address) or failure.
    /// New entries go at the head; a netid rpcbind doesn't serve isn't counted.
    pub fn getaddr(&mut self, fdlist: &FdList, rtype: usize, prog: u32, vers: u32, netid: &[u8], uaddr: Option<&[u8]>) {
        if rtype >= RPCBVERS_STAT {
            return;
        }
        let ok = uaddr.is_some_and(|u| !u.is_empty());
        for al in &mut self.inf[rtype].addrinfo {
            if al.prog == prog && al.vers == vers && al.netid == netid {
                if ok {
                    al.success += 1;
                } else {
                    al.failure += 1;
                }
                return;
            }
        }
        let Some(nconf) = fdlist.get_conf(netid) else {
            return;
        };
        let (success, failure) = if ok { (1, 0) } else { (0, 1) };
        self.inf[rtype].addrinfo.insert(0, AddrStat { prog, vers, success, failure, netid: nconf.netid.clone() });
    }

    /// `rpcbs_rmtcall()`.
    #[allow(clippy::too_many_arguments)]
    pub fn rmtcall(
        &mut self,
        fdlist: &FdList,
        rtype: usize,
        rpcbproc: u32,
        prog: u32,
        vers: u32,
        proc_: u32,
        netid: &[u8],
        rbl: Option<&Rpcb>,
    ) {
        if rtype >= RPCBVERS_STAT {
            return;
        }
        let ok = rbl.is_some_and(|r| r.vers == vers);
        for rl in &mut self.inf[rtype].rmtinfo {
            if rl.prog == prog && rl.vers == vers && rl.proc_ == proc_ && rl.netid == netid {
                if ok {
                    rl.success += 1;
                } else {
                    rl.failure += 1;
                }
                if rpcbproc == RPCBPROC_INDIRECT {
                    rl.indirect += 1;
                }
                return;
            }
        }
        let Some(nconf) = fdlist.get_conf(netid) else {
            return;
        };
        let (success, failure) = if ok { (1, 0) } else { (0, 1) };
        // QUIRK: a new entry counts as indirect whatever the procedure was.
        self.inf[rtype]
            .rmtinfo
            .insert(0, RmtcallStat { prog, vers, proc_, success, failure, indirect: 1, netid: nconf.netid.clone() });
    }
}
