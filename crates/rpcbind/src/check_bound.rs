//! `check_bound.c`: the transports rpcbind serves (`fdlist`), for looking up a netid's
//! netconfig entry. Bound checking itself is compiled in but always off
//! (`check_binding = FALSE`).

use tirpc::addr::Netbuf;
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

impl FdList {
    /// `is_bound()`: bound checking is off, so always true.
    pub fn is_bound(&self, _netid: &[u8], _uaddr: &[u8]) -> bool {
        true
    }

    /// `mergeaddr()`: `None` if rpcbind doesn't serve the netid.
    pub fn mergeaddr(&self, caller: &Netbuf, netid: &[u8], uaddr: &[u8], saddr: Option<&[u8]>) -> Option<Vec<u8>> {
        let nconf = self.get_conf(netid)?;
        // check_bound() is always TRUE ("that server died" can't happen).
        let c_uaddr = match saddr {
            Some(s) => s.to_vec(),
            None => match tirpc::addr::taddr2uaddr(nconf, caller) {
                Some(u) => u,
                None => {
                    let mut m = b"taddr2uaddr failed for ".to_vec();
                    m.extend_from_slice(&nconf.netid);
                    tirpc::sys::syslog(libc::LOG_ERR, &m);
                    return None;
                }
            },
        };
        crate::util::addrmerge(self, caller, uaddr, Some(&c_uaddr), netid)
    }
}
