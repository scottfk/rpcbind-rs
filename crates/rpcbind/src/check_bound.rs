//! `check_bound.c`: the transports rpcbind serves (`fdlist`), for looking up a netid's
//! netconfig entry. Bound checking itself is compiled in but always off
//! (`check_binding = FALSE`).

use tirpc::netconfig::{Netconfig, NetconfigDb};

/// `fdhead`..`fdtail`.
#[derive(Debug, Default)]
pub struct FdList {
    pub list: Vec<Netconfig>,
}

impl FdList {
    /// `add_bndlist()`: -1 if the netid isn't in netconfig.
    pub fn add_bndlist(&mut self, db: &mut NetconfigDb, nconf: &Netconfig) -> i32 {
        let Some(n) = db.getnetconfigent(&nconf.netid) else {
            return -1;
        };
        self.list.push(n);
        0
    }

    /// `rpcbind_get_conf()`.
    pub fn get_conf(&self, netid: &[u8]) -> Option<&Netconfig> {
        self.list.iter().find(|n| n.netid == netid)
    }
}
