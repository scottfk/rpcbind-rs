//! `rpcb_stat.c`: the counters `GETSTAT` reports.

/// `RPCBSTAT_HIGHPROC`.
pub const RPCBSTAT_HIGHPROC: usize = 13;
/// `RPCBVERS_STAT`.
pub const RPCBVERS_STAT: usize = 3;
pub const RPCBVERS_2_STAT: usize = 0;
pub const RPCBVERS_3_STAT: usize = 1;
pub const RPCBVERS_4_STAT: usize = 2;

/// `rpcb_highproc_2/3/4`: `CALLIT`, `TADDR2UADDR`, `GETSTAT`.
const HIGHPROC: [u32; RPCBVERS_STAT] = [5, 8, 12];

/// `rpcb_stat`, one per version.
#[derive(Debug, Clone, Default)]
pub struct RpcbStat {
    pub info: [i32; RPCBSTAT_HIGHPROC],
    pub setinfo: i32,
    pub unsetinfo: i32,
}

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
}
