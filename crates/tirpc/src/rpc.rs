//! RPC messages and server-side authentication: `rpc_callmsg.c` (`xdr_callmsg()`
//! decoding), `rpc_prot.c` (`xdr_replymsg()` encoding), `svc_auth.c`
//! (`_gss_authenticate()`) and `svc_auth_unix.c`.

use crate::xdr::{self, XdrDecode, XdrEncode, rndup};

/// `RPC_MSG_VERSION`.
pub const RPC_MSG_VERSION: u32 = 2;
/// `MAX_AUTH_BYTES`.
pub const MAX_AUTH_BYTES: usize = 400;
/// `RQCRED_SIZE`.
const RQCRED_SIZE: usize = 400;
/// `MAX_MACHINE_NAME`.
const MAX_MACHINE_NAME: usize = 255;
/// `NGRPS`.
const NGRPS: usize = 16;

// msg_type
const CALL: u32 = 0;
const REPLY: u32 = 1;
// reply_stat
const MSG_ACCEPTED: u32 = 0;
const MSG_DENIED: u32 = 1;
// reject_stat
const AUTH_ERROR: u32 = 1;

// auth flavors
pub const AUTH_NONE: u32 = 0;
pub const AUTH_SYS: u32 = 1;
pub const AUTH_SHORT: u32 = 2;
pub const AUTH_DES: u32 = 3;

/// `enum auth_stat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum AuthStat {
    Ok = 0,
    BadCred = 1,
    RejectedCred = 2,
    BadVerf = 3,
    RejectedVerf = 4,
    TooWeak = 5,
    InvalidResp = 6,
    Failed = 7,
}

/// `struct opaque_auth`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct OpaqueAuth {
    pub flavor: u32,
    pub body: Vec<u8>,
}

/// The call part of `struct rpc_msg`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CallMsg {
    pub xid: u32,
    pub prog: u32,
    pub vers: u32,
    pub proc_: u32,
    pub cred: OpaqueAuth,
    pub verf: OpaqueAuth,
}

/// `struct authunix_parms` as `_svcauth_unix()` leaves it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AuthUnix {
    pub time: u32,
    pub machname: Vec<u8>,
    pub uid: u32,
    pub gid: u32,
    pub gids: Vec<u32>,
}

/// One `opaque_auth` body in `xdr_callmsg()` decoding: inline if the stream can, else
/// `xdr_opaque()`. Both read `len` bytes and skip the padding.
fn get_auth_body(x: &mut dyn XdrDecode, len: usize) -> Option<Vec<u8>> {
    if len == 0 {
        return Some(Vec::new());
    }
    if len > MAX_AUTH_BYTES {
        return None;
    }
    if let Some(b) = x.inline(rndup(len)) {
        return Some(b[..len].to_vec());
    }
    xdr::get_opaque(x, len)
}

/// `xdr_callmsg()`, decoding. `None` (the call is dropped, or a stream connection
/// closed) for a reply, an RPC version other than 2, an oversized credential or
/// verifier, or a message cut short.
pub fn decode_call(x: &mut dyn XdrDecode) -> Option<CallMsg> {
    // The inline fast path and the xdr_* fallback accept and reject the same input;
    // they differ only in where a failure is noticed, which isn't visible.
    let xid = x.get_long()?;
    if x.get_long()? != CALL {
        return None;
    }
    if x.get_long()? != RPC_MSG_VERSION {
        return None;
    }
    let prog = x.get_long()?;
    let vers = x.get_long()?;
    let proc_ = x.get_long()?;
    let cflavor = x.get_long()?;
    let clen = x.get_long()? as usize;
    let cbody = get_auth_body(x, clen)?;
    let vflavor = x.get_long()?;
    let vlen = x.get_long()? as usize;
    let vbody = get_auth_body(x, vlen)?;
    Some(CallMsg {
        xid,
        prog,
        vers,
        proc_,
        cred: OpaqueAuth { flavor: cflavor, body: cbody },
        verf: OpaqueAuth { flavor: vflavor, body: vbody },
    })
}

/// `svc_getreq_common()`'s `cred_area` (credential at 0, verifier at
/// `MAX_AUTH_BYTES`, cooked credential after). In C it's a local array that lands at the
/// same stack address on every call, so bytes from earlier calls remain past a short
/// credential; `_svcauth_unix()` reads them. Kept here across calls for the same effect.
#[derive(Debug)]
pub struct CredArea {
    area: Vec<u8>,
}

impl Default for CredArea {
    fn default() -> Self {
        CredArea { area: vec![0; 2 * MAX_AUTH_BYTES + RQCRED_SIZE] }
    }
}

impl CredArea {
    /// What `xdr_callmsg()` copies into the area for this call.
    pub fn load(&mut self, call: &CallMsg) {
        self.area[..call.cred.body.len()].copy_from_slice(&call.cred.body);
        let v = MAX_AUTH_BYTES;
        self.area[v..v + call.verf.body.len()].copy_from_slice(&call.verf.body);
    }

    fn u32_at(&self, off: usize) -> u32 {
        u32::from_be_bytes(self.area[off..off + 4].try_into().unwrap())
    }
}

/// What authentication decided: the verifier for an accepted reply, and the parsed
/// `AUTH_SYS` credential if there was one.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Authenticated {
    pub verf: OpaqueAuth,
    pub unix: Option<AuthUnix>,
}

/// `_gss_authenticate()` with libtirpc 1.3.7 as Gentoo builds it (no RPCSEC_GSS, no
/// AUTH_DES). `stdout` collects `_svcauth_unix()`'s `printf()`.
pub fn authenticate(call: &CallMsg, area: &CredArea, stdout: &mut Vec<u8>) -> Result<Authenticated, AuthStat> {
    match call.cred.flavor {
        AUTH_NONE => Ok(Authenticated::default()),
        AUTH_SYS => svcauth_unix(call, area, stdout),
        AUTH_SHORT => Err(AuthStat::RejectedCred),
        AUTH_DES => Err(AuthStat::Failed),
        _ => Err(AuthStat::RejectedCred),
    }
}

/// `_svcauth_unix()`. `XDR_INLINE()` of the whole credential always succeeds on its
/// memory stream, so only the inline path runs: it reads the fields at fixed offsets,
/// past the credential's end if it's short (see [`CredArea`]), and only then checks the
/// length.
fn svcauth_unix(call: &CallMsg, area: &CredArea, stdout: &mut Vec<u8>) -> Result<Authenticated, AuthStat> {
    let auth_len = call.cred.body.len();
    let mut off = 0;
    let time = area.u32_at(off);
    let str_len = area.u32_at(off + 4) as usize;
    off += 8;
    if str_len > MAX_MACHINE_NAME {
        return Err(AuthStat::BadCred);
    }
    let machname = area.area[off..off + str_len].to_vec();
    let str_len = rndup(str_len);
    off += str_len;
    let uid = area.u32_at(off);
    let gid = area.u32_at(off + 4);
    let gid_len = area.u32_at(off + 8) as usize;
    off += 12;
    if gid_len > NGRPS {
        return Err(AuthStat::BadCred);
    }
    let gids = (0..gid_len).map(|i| area.u32_at(off + 4 * i)).collect();
    if (5 + gid_len) * 4 + str_len > auth_len {
        stdout.extend_from_slice(format!("bad auth_len gid {gid_len} str {str_len} auth {auth_len}\n").as_bytes());
        return Err(AuthStat::BadCred);
    }
    let verf = if call.verf.body.is_empty() {
        OpaqueAuth::default()
    } else {
        // QUIRK: the client's verifier (flavor and body) is echoed in the reply.
        call.verf.clone()
    };
    Ok(Authenticated { verf, unix: Some(AuthUnix { time, machname, uid, gid, gids }) })
}

/// The body of a reply: `accepted_reply` or `rejected_reply`.
pub enum ReplyBody<'a> {
    /// `SUCCESS`, with the results' encoder.
    Success(&'a mut dyn FnMut(&mut dyn XdrEncode) -> bool),
    ProgUnavail,
    ProgMismatch {
        low: u32,
        high: u32,
    },
    ProcUnavail,
    GarbageArgs,
    SystemErr,
    /// `MSG_DENIED` with `AUTH_ERROR`.
    AuthError(AuthStat),
}

impl std::fmt::Debug for ReplyBody<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ReplyBody::Success(_) => f.write_str("Success(..)"),
            ReplyBody::ProgUnavail => f.write_str("ProgUnavail"),
            ReplyBody::ProgMismatch { low, high } => write!(f, "ProgMismatch({low}, {high})"),
            ReplyBody::ProcUnavail => f.write_str("ProcUnavail"),
            ReplyBody::GarbageArgs => f.write_str("GarbageArgs"),
            ReplyBody::SystemErr => f.write_str("SystemErr"),
            ReplyBody::AuthError(s) => write!(f, "AuthError({s:?})"),
        }
    }
}

/// `xdr_replymsg()` encoding, then the results (`SVCAUTH_WRAP()` with no wrapping).
pub fn encode_reply(x: &mut dyn XdrEncode, xid: u32, verf: &OpaqueAuth, body: &mut ReplyBody<'_>) -> bool {
    if !(x.put_long(xid) && x.put_long(REPLY)) {
        return false;
    }
    if let ReplyBody::AuthError(why) = body {
        return x.put_long(MSG_DENIED) && x.put_long(AUTH_ERROR) && x.put_long(*why as u32);
    }
    if !x.put_long(MSG_ACCEPTED) {
        return false;
    }
    // xdr_opaque_auth()
    if !(x.put_long(verf.flavor) && xdr::put_bytes(x, &verf.body, MAX_AUTH_BYTES as u32)) {
        return false;
    }
    match body {
        ReplyBody::Success(results) => x.put_long(0) && results(x),
        ReplyBody::ProgUnavail => x.put_long(1),
        ReplyBody::ProgMismatch { low, high } => x.put_long(2) && x.put_long(*low) && x.put_long(*high),
        ReplyBody::ProcUnavail => x.put_long(3),
        ReplyBody::GarbageArgs => x.put_long(4),
        ReplyBody::SystemErr => x.put_long(5),
        ReplyBody::AuthError(_) => unreachable!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::xdr::XdrMem;

    fn call_bytes(rpcvers: u32, cred: (u32, &[u8]), verf: (u32, &[u8])) -> Vec<u8> {
        let mut v = Vec::new();
        for w in [7u32, CALL, rpcvers, 100000, 2, 0, cred.0, cred.1.len() as u32] {
            v.extend_from_slice(&w.to_be_bytes());
        }
        v.extend_from_slice(cred.1);
        v.resize(rndup(v.len()), 0);
        v.extend_from_slice(&verf.0.to_be_bytes());
        v.extend_from_slice(&(verf.1.len() as u32).to_be_bytes());
        v.extend_from_slice(verf.1);
        v.resize(rndup(v.len()), 0);
        v
    }

    fn sys_cred(name: &[u8], gids: &[u32]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&1u32.to_be_bytes());
        v.extend_from_slice(&(name.len() as u32).to_be_bytes());
        v.extend_from_slice(name);
        v.resize(rndup(v.len()), 0);
        for w in [1000u32, 100, gids.len() as u32] {
            v.extend_from_slice(&w.to_be_bytes());
        }
        for g in gids {
            v.extend_from_slice(&g.to_be_bytes());
        }
        v
    }

    #[test]
    fn decodes_and_rejects() {
        let mut b = call_bytes(2, (AUTH_NONE, b""), (AUTH_NONE, b""));
        let c = decode_call(&mut XdrMem::new(&mut b)).unwrap();
        assert_eq!((c.xid, c.prog, c.vers, c.proc_), (7, 100000, 2, 0));
        let mut b = call_bytes(3, (AUTH_NONE, b""), (AUTH_NONE, b""));
        assert!(decode_call(&mut XdrMem::new(&mut b)).is_none());
        let big = vec![0u8; 401];
        let mut b = call_bytes(2, (AUTH_SYS, &big), (AUTH_NONE, b""));
        assert!(decode_call(&mut XdrMem::new(&mut b)).is_none());
    }

    #[test]
    fn auth_sys() {
        let cred = sys_cred(b"host", &[1, 2]);
        let mut b = call_bytes(2, (AUTH_SYS, &cred), (9, b"abcd"));
        let c = decode_call(&mut XdrMem::new(&mut b)).unwrap();
        let mut area = CredArea::default();
        area.load(&c);
        let mut out = Vec::new();
        let a = authenticate(&c, &area, &mut out).unwrap();
        assert_eq!(a.verf, OpaqueAuth { flavor: 9, body: b"abcd".to_vec() });
        let u = a.unix.unwrap();
        assert_eq!((u.uid, u.gid, u.gids, u.machname), (1000, 100, vec![1, 2], b"host".to_vec()));
        // Cut short: the missing gid is read from what the area held before.
        let short = &cred[..cred.len() - 4];
        let mut b = call_bytes(2, (AUTH_SYS, short), (AUTH_NONE, b""));
        let c = decode_call(&mut XdrMem::new(&mut b)).unwrap();
        area.load(&c);
        assert_eq!(authenticate(&c, &area, &mut out), Err(AuthStat::BadCred));
        assert_eq!(out, b"bad auth_len gid 2 str 4 auth 28\n");
    }
}
