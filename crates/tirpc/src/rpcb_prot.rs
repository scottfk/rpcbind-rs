//! The rpcbind and portmap protocol types: libtirpc's `rpcb_prot.c` (`xdr_rpcb`,
//! `xdr_rpcblist_ptr`, `xdr_rpcb_entry_list_ptr`, `xdr_netbuf`), `rpcb_st_xdr.c`
//! (`xdr_rpcb_stat_byvers`) and `pmap_prot.c`/`pmap_prot2.c` (`xdr_pmap`,
//! `xdr_pmaplist_ptr`).

use crate::xdr::{self, RPC_MAXDATASIZE, XdrDecode, XdrEncode};

/// The bytes of a decoded string up to its first NUL: everything that uses it in C
/// (`strdup`, `strcmp`, `strlen`) stops there.
pub fn c_str(mut v: Vec<u8>) -> Vec<u8> {
    if let Some(n) = v.iter().position(|&b| b == 0) {
        v.truncate(n);
    }
    v
}

/// `struct rpcb` (`RPCB`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Rpcb {
    pub prog: u32,
    pub vers: u32,
    pub netid: Vec<u8>,
    pub addr: Vec<u8>,
    pub owner: Vec<u8>,
}

/// `xdr_rpcb()` decoding. The strings are cut at their first NUL, as C sees them.
pub fn get_rpcb(x: &mut dyn XdrDecode) -> Option<Rpcb> {
    let prog = x.get_long()?;
    let vers = x.get_long()?;
    let netid = c_str(xdr::get_string(x, RPC_MAXDATASIZE)?);
    let addr = c_str(xdr::get_string(x, RPC_MAXDATASIZE)?);
    let owner = c_str(xdr::get_string(x, RPC_MAXDATASIZE)?);
    Some(Rpcb { prog, vers, netid, addr, owner })
}

/// `xdr_rpcb()` encoding.
pub fn put_rpcb(x: &mut dyn XdrEncode, r: &Rpcb) -> bool {
    x.put_long(r.prog)
        && x.put_long(r.vers)
        && xdr::put_string(x, &r.netid, RPC_MAXDATASIZE)
        && xdr::put_string(x, &r.addr, RPC_MAXDATASIZE)
        && xdr::put_string(x, &r.owner, RPC_MAXDATASIZE)
}

/// `xdr_rpcblist_ptr()` encoding: each entry after a TRUE, then FALSE.
pub fn put_rpcblist<'a>(x: &mut dyn XdrEncode, list: impl IntoIterator<Item = &'a Rpcb>) -> bool {
    for r in list {
        if !(xdr::put_bool(x, true) && put_rpcb(x, r)) {
            return false;
        }
    }
    xdr::put_bool(x, false)
}

/// `struct rpcb_entry`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RpcbEntry {
    pub maddr: Vec<u8>,
    pub nc_netid: Vec<u8>,
    pub nc_semantics: u32,
    pub nc_protofmly: Vec<u8>,
    pub nc_proto: Vec<u8>,
}

/// `xdr_rpcb_entry_list_ptr()` encoding.
pub fn put_rpcb_entry_list(x: &mut dyn XdrEncode, list: &[RpcbEntry]) -> bool {
    for e in list {
        let ok = xdr::put_bool(x, true)
            && xdr::put_string(x, &e.maddr, RPC_MAXDATASIZE)
            && xdr::put_string(x, &e.nc_netid, RPC_MAXDATASIZE)
            && x.put_long(e.nc_semantics)
            && xdr::put_string(x, &e.nc_protofmly, RPC_MAXDATASIZE)
            && xdr::put_string(x, &e.nc_proto, RPC_MAXDATASIZE);
        if !ok {
            return false;
        }
    }
    xdr::put_bool(x, false)
}

/// `struct netbuf` on the wire: `maxlen`, then `len` bytes.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WireNetbuf {
    pub maxlen: u32,
    pub buf: Vec<u8>,
}

/// `xdr_netbuf()` decoding. `maxlen` is the struct's field, which keeps what was read
/// when decoding fails: see [`netbuf_frees`].
pub fn get_netbuf(x: &mut dyn XdrDecode, maxlen: &mut u32) -> Option<WireNetbuf> {
    *maxlen = x.get_long()?;
    if *maxlen > RPC_MAXDATASIZE {
        return None;
    }
    let buf = xdr::get_bytes(x, *maxlen)?;
    Some(WireNetbuf { maxlen: *maxlen, buf })
}

/// Whether `xdr_netbuf()` with `XDR_FREE` succeeds on a netbuf whose `maxlen` field
/// holds this. QUIRK: it checks the limit before freeing, so a netbuf that failed to
/// decode for a `maxlen` over `RPC_MAXDATASIZE` can't be freed (`svc_freeargs()`
/// fails).
pub fn netbuf_frees(maxlen: u32) -> bool {
    maxlen <= RPC_MAXDATASIZE
}

/// `xdr_netbuf()` encoding.
pub fn put_netbuf(x: &mut dyn XdrEncode, maxlen: u32, buf: &[u8]) -> bool {
    if !x.put_long(maxlen) {
        return false;
    }
    if maxlen > RPC_MAXDATASIZE {
        return false;
    }
    xdr::put_bytes(x, buf, maxlen)
}

/// `struct pmap`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Pmap {
    pub prog: u32,
    pub vers: u32,
    pub prot: u32,
    pub port: u32,
}

/// `xdr_pmap()` decoding (four `xdr_u_long`s, one unit each).
pub fn get_pmap(x: &mut dyn XdrDecode) -> Option<Pmap> {
    Some(Pmap { prog: x.get_long()?, vers: x.get_long()?, prot: x.get_long()?, port: x.get_long()? })
}

/// `xdr_pmaplist_ptr()` encoding.
pub fn put_pmaplist<'a>(x: &mut dyn XdrEncode, list: impl IntoIterator<Item = &'a Pmap>) -> bool {
    for p in list {
        let ok = xdr::put_bool(x, true)
            && x.put_long(p.prog)
            && x.put_long(p.vers)
            && x.put_long(p.prot)
            && x.put_long(p.port);
        if !ok {
            return false;
        }
    }
    xdr::put_bool(x, false)
}

/// `RPCBSTAT_HIGHPROC`.
pub const RPCBSTAT_HIGHPROC: usize = 13;
/// `RPCBVERS_STAT`.
pub const RPCBVERS_STAT: usize = 3;

/// `rpcbs_addrlist`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AddrStat {
    pub prog: u32,
    pub vers: u32,
    pub success: i32,
    pub failure: i32,
    pub netid: Vec<u8>,
}

/// `rpcbs_rmtcalllist`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RmtcallStat {
    pub prog: u32,
    pub vers: u32,
    pub proc_: u32,
    pub success: i32,
    pub failure: i32,
    pub indirect: i32,
    pub netid: Vec<u8>,
}

/// `rpcb_stat`. The lists are newest first, as C prepends.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RpcbStat {
    pub info: [i32; RPCBSTAT_HIGHPROC],
    pub setinfo: i32,
    pub unsetinfo: i32,
    pub addrinfo: Vec<AddrStat>,
    pub rmtinfo: Vec<RmtcallStat>,
}

/// `xdr_rpcb_stat_byvers()` encoding. The lists go through `xdr_pointer()`: a TRUE
/// before each element, then FALSE.
pub fn put_rpcb_stat_byvers(x: &mut dyn XdrEncode, inf: &[RpcbStat; RPCBVERS_STAT]) -> bool {
    for s in inf {
        for &v in &s.info {
            if !x.put_long(v as u32) {
                return false;
            }
        }
        if !(x.put_long(s.setinfo as u32) && x.put_long(s.unsetinfo as u32)) {
            return false;
        }
        for a in &s.addrinfo {
            let ok = xdr::put_bool(x, true)
                && x.put_long(a.prog)
                && x.put_long(a.vers)
                && x.put_long(a.success as u32)
                && x.put_long(a.failure as u32)
                && xdr::put_string(x, &a.netid, RPC_MAXDATASIZE);
            if !ok {
                return false;
            }
        }
        if !xdr::put_bool(x, false) {
            return false;
        }
        for r in &s.rmtinfo {
            // The six numbers go inline when the buffer has room, else one by one: the
            // same bytes, flushed at the same place.
            let ok = xdr::put_bool(x, true)
                && x.put_long(r.prog)
                && x.put_long(r.vers)
                && x.put_long(r.proc_)
                && x.put_long(r.success as u32)
                && x.put_long(r.failure as u32)
                && x.put_long(r.indirect as u32)
                && xdr::put_string(x, &r.netid, RPC_MAXDATASIZE);
            if !ok {
                return false;
            }
        }
        if !xdr::put_bool(x, false) {
            return false;
        }
    }
    true
}

// ---------------------------------------------------------------------------
// client-side decoding (rpcinfo)

/// `xdr_pmaplist_ptr()` decoding.
pub fn get_pmaplist(x: &mut dyn XdrDecode) -> Option<Vec<Pmap>> {
    let mut v = Vec::new();
    while xdr::get_bool(x)? {
        v.push(get_pmap(x)?);
    }
    Some(v)
}

/// `xdr_rpcblist_ptr()` decoding.
pub fn get_rpcblist(x: &mut dyn XdrDecode) -> Option<Vec<Rpcb>> {
    let mut v = Vec::new();
    while xdr::get_bool(x)? {
        v.push(get_rpcb(x)?);
    }
    Some(v)
}

/// `xdr_rpcb_entry_list_ptr()` decoding.
pub fn get_rpcb_entry_list(x: &mut dyn XdrDecode) -> Option<Vec<RpcbEntry>> {
    let mut v = Vec::new();
    while xdr::get_bool(x)? {
        let maddr = c_str(xdr::get_string(x, RPC_MAXDATASIZE)?);
        let nc_netid = c_str(xdr::get_string(x, RPC_MAXDATASIZE)?);
        let nc_semantics = x.get_long()?;
        let nc_protofmly = c_str(xdr::get_string(x, RPC_MAXDATASIZE)?);
        let nc_proto = c_str(xdr::get_string(x, RPC_MAXDATASIZE)?);
        v.push(RpcbEntry { maddr, nc_netid, nc_semantics, nc_protofmly, nc_proto });
    }
    Some(v)
}

/// `xdr_rpcb_stat_byvers()` decoding.
pub fn get_rpcb_stat_byvers(x: &mut dyn XdrDecode) -> Option<[RpcbStat; RPCBVERS_STAT]> {
    let mut out: [RpcbStat; RPCBVERS_STAT] = Default::default();
    for s in &mut out {
        for v in &mut s.info {
            *v = xdr::get_i32(x)?;
        }
        s.setinfo = xdr::get_i32(x)?;
        s.unsetinfo = xdr::get_i32(x)?;
        while xdr::get_bool(x)? {
            let prog = x.get_long()?;
            let vers = x.get_long()?;
            let success = xdr::get_i32(x)?;
            let failure = xdr::get_i32(x)?;
            let netid = c_str(xdr::get_string(x, RPC_MAXDATASIZE)?);
            s.addrinfo.push(AddrStat { prog, vers, success, failure, netid });
        }
        while xdr::get_bool(x)? {
            let prog = x.get_long()?;
            let vers = x.get_long()?;
            let proc_ = x.get_long()?;
            let success = xdr::get_i32(x)?;
            let failure = xdr::get_i32(x)?;
            let indirect = xdr::get_i32(x)?;
            let netid = c_str(xdr::get_string(x, RPC_MAXDATASIZE)?);
            s.rmtinfo.push(RmtcallStat { prog, vers, proc_, success, failure, indirect, netid });
        }
    }
    Some(out)
}
