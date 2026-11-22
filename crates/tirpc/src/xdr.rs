//! `xdr.c`: XDR primitives, over any stream.
//!
//! libtirpc's primitives call the stream's `getlong`/`putlong`/`getbytes`/`putbytes`/
//! `inline` operations in a fixed order, and on a record stream that order decides where
//! output fragments end, so the primitives here make exactly the same stream calls.
//! Decoding and encoding are separate traits rather than one `XDR` with an `x_op`.

/// `BYTES_PER_XDR_UNIT`.
pub const UNIT: usize = 4;

/// `RNDUP()`.
pub fn rndup(n: usize) -> usize {
    n.div_ceil(UNIT) * UNIT
}

/// The decoding half of `struct xdr_ops`.
pub trait XdrDecode {
    /// `x_getlong`: one big-endian 32-bit unit.
    fn get_long(&mut self) -> Option<u32>;
    /// `x_getbytes`: `buf.len()` raw bytes.
    fn get_bytes(&mut self, buf: &mut [u8]) -> bool;
    /// `x_inline` for decoding: `len` bytes straight from the stream's buffer, or `None`
    /// when the stream can't provide them in one piece (the caller then falls back to
    /// `get_long`/`get_bytes`).
    fn inline(&mut self, len: usize) -> Option<&[u8]>;
}

/// The encoding half of `struct xdr_ops`.
pub trait XdrEncode {
    /// `x_putlong`.
    fn put_long(&mut self, v: u32) -> bool;
    /// `x_putbytes`.
    fn put_bytes(&mut self, b: &[u8]) -> bool;
}

/// `xdr_u_int()`, `xdr_u_int32_t()`, `xdr_u_long()` decoding (all one unit).
pub fn get_u32(x: &mut dyn XdrDecode) -> Option<u32> {
    x.get_long()
}

/// `xdr_int()` and `xdr_enum()` decoding.
pub fn get_i32(x: &mut dyn XdrDecode) -> Option<i32> {
    x.get_long().map(|v| v as i32)
}

/// `xdr_bool()` decoding: anything but 0 is true.
pub fn get_bool(x: &mut dyn XdrDecode) -> Option<bool> {
    x.get_long().map(|v| v != 0)
}

/// `xdr_u_int()` (and friends) encoding.
pub fn put_u32(x: &mut dyn XdrEncode, v: u32) -> bool {
    x.put_long(v)
}

/// `xdr_bool()` encoding.
pub fn put_bool(x: &mut dyn XdrEncode, v: bool) -> bool {
    x.put_long(u32::from(v))
}

/// `xdr_opaque()` decoding: `cnt` bytes, then the padding (read and ignored).
///
/// A length from the wire can be up to 4 GB, so the bytes are read in pieces and the
/// buffer grows only as they arrive: a short stream fails long before a large
/// allocation.
pub fn get_opaque(x: &mut dyn XdrDecode, cnt: usize) -> Option<Vec<u8>> {
    if cnt == 0 {
        return Some(Vec::new());
    }
    const CHUNK: usize = 64 * 1024;
    let mut v = Vec::new();
    if cnt <= CHUNK {
        v.resize(cnt, 0);
        if !x.get_bytes(&mut v) {
            return None;
        }
    } else {
        // Both streams fail a getbytes they can't satisfy whole; in pieces, a stream
        // that runs out fails on the piece that crosses its end. Either way decoding
        // stops there.
        let mut chunk = vec![0u8; CHUNK];
        let mut left = cnt;
        while left > 0 {
            let n = left.min(CHUNK);
            if !x.get_bytes(&mut chunk[..n]) {
                return None;
            }
            v.extend_from_slice(&chunk[..n]);
            left -= n;
        }
    }
    let pad = rndup(cnt) - cnt;
    if pad == 0 {
        return Some(v);
    }
    let mut crud = [0u8; UNIT];
    if x.get_bytes(&mut crud[..pad]) { Some(v) } else { None }
}

/// `xdr_opaque()` encoding: the bytes, then zero padding, as two `put_bytes` calls.
pub fn put_opaque(x: &mut dyn XdrEncode, b: &[u8]) -> bool {
    if b.is_empty() {
        return true;
    }
    if !x.put_bytes(b) {
        return false;
    }
    let pad = rndup(b.len()) - b.len();
    pad == 0 || x.put_bytes(&[0u8; UNIT][..pad])
}

/// `xdr_bytes()` decoding: a length (at most `maxsize`), then the opaque bytes.
///
/// C allocates the length before reading anything; if that fails it prints
/// `xdr_bytes: out of memory` (through `warnx()`) and fails.
pub fn get_bytes(x: &mut dyn XdrDecode, maxsize: u32) -> Option<Vec<u8>> {
    let size = x.get_long()?;
    if size > maxsize {
        return None;
    }
    if size != 0 && !crate::sys::malloc_ok(size as usize) {
        let mut m = crate::sys::progname();
        m.extend_from_slice(b": xdr_bytes: out of memory\n");
        crate::sys::c_stderr(&m);
        return None;
    }
    get_opaque(x, size as usize)
}

/// `xdr_bytes()` encoding.
pub fn put_bytes(x: &mut dyn XdrEncode, b: &[u8], maxsize: u32) -> bool {
    let size = b.len() as u32;
    if !x.put_long(size) {
        return false;
    }
    if size > maxsize {
        return false;
    }
    put_opaque(x, b)
}

/// `xdr_string()` decoding. The result keeps every byte sent, NULs included; C code that
/// reads it as a string stops at the first NUL, so callers do the same where it matters.
pub fn get_string(x: &mut dyn XdrDecode, maxsize: u32) -> Option<Vec<u8>> {
    let size = x.get_long()?;
    if size > maxsize {
        return None;
    }
    // nodesize = size + 1 overflows to 0 only for size == u32::MAX, which maxsize
    // already rules out for every caller.
    if size == u32::MAX {
        return None;
    }
    get_opaque(x, size as usize)
}

/// `xdr_string()` encoding: `strlen()` bytes of `s`.
pub fn put_string(x: &mut dyn XdrEncode, s: &[u8], maxsize: u32) -> bool {
    let s = &s[..s.iter().position(|&b| b == 0).unwrap_or(s.len())];
    let size = s.len() as u32;
    if !x.put_long(size) {
        return false;
    }
    if size > maxsize {
        return false;
    }
    put_opaque(x, s)
}

/// `RPC_MAXDATASIZE`, `xdr_wrapstring()`'s limit.
pub const RPC_MAXDATASIZE: u32 = 9000;

/// `xdrmem_create()`'s stream: a fixed buffer, with `x_handy` bytes left.
///
/// Decoding reads from the whole buffer it was created over, not just the bytes a
/// datagram filled (see `svc_dg`).
#[derive(Debug)]
pub struct XdrMem<'a> {
    buf: &'a mut [u8],
    pos: usize,
    handy: usize,
}

impl<'a> XdrMem<'a> {
    /// `xdrmem_create(xdrs, buf, buf.len(), op)`.
    pub fn new(buf: &'a mut [u8]) -> XdrMem<'a> {
        let handy = buf.len();
        XdrMem { buf, pos: 0, handy }
    }

    /// A stream over `buf` positioned at `pos` with `handy` bytes left, to carry on
    /// where an earlier one stopped (`svc_dg` decodes the arguments from the same
    /// `XDR` that decoded the call header).
    pub fn resume(buf: &'a mut [u8], pos: usize, handy: usize) -> XdrMem<'a> {
        XdrMem { buf, pos, handy }
    }

    /// `x_handy`.
    pub fn handy(&self) -> usize {
        self.handy
    }

    /// `XDR_GETPOS()`.
    pub fn getpos(&self) -> usize {
        self.pos
    }

    /// `XDR_SETPOS()`.
    pub fn setpos(&mut self, pos: usize) -> bool {
        let last = self.pos + self.handy;
        if pos > last {
            return false;
        }
        self.pos = pos;
        self.handy = last - pos;
        true
    }

    /// `XDR_INLINE()` for encoding.
    pub fn inline_mut(&mut self, len: usize) -> Option<&mut [u8]> {
        if self.handy < len {
            return None;
        }
        let start = self.pos;
        self.handy -= len;
        self.pos += len;
        Some(&mut self.buf[start..start + len])
    }
}

impl XdrDecode for XdrMem<'_> {
    fn get_long(&mut self) -> Option<u32> {
        if self.handy < UNIT {
            return None;
        }
        self.handy -= UNIT;
        let p = self.pos;
        self.pos += UNIT;
        Some(u32::from_be_bytes(self.buf[p..p + UNIT].try_into().unwrap()))
    }

    fn get_bytes(&mut self, out: &mut [u8]) -> bool {
        let len = out.len();
        if self.handy < len {
            return false;
        }
        self.handy -= len;
        out.copy_from_slice(&self.buf[self.pos..self.pos + len]);
        self.pos += len;
        true
    }

    fn inline(&mut self, len: usize) -> Option<&[u8]> {
        if self.handy < len {
            return None;
        }
        let start = self.pos;
        self.handy -= len;
        self.pos += len;
        Some(&self.buf[start..start + len])
    }
}

impl XdrEncode for XdrMem<'_> {
    fn put_long(&mut self, v: u32) -> bool {
        if self.handy < UNIT {
            return false;
        }
        self.handy -= UNIT;
        self.buf[self.pos..self.pos + UNIT].copy_from_slice(&v.to_be_bytes());
        self.pos += UNIT;
        true
    }

    fn put_bytes(&mut self, b: &[u8]) -> bool {
        if self.handy < b.len() {
            return false;
        }
        self.handy -= b.len();
        self.buf[self.pos..self.pos + b.len()].copy_from_slice(b);
        self.pos += b.len();
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opaque_padding_and_limits() {
        let mut buf = [0u8; 16];
        let mut x = XdrMem::new(&mut buf);
        assert!(put_string(&mut x, b"abcde", 10));
        assert_eq!(x.getpos(), 12);
        assert_eq!(&buf[..12], b"\0\0\0\x05abcde\0\0\0");
        let mut x = XdrMem::new(&mut buf);
        assert_eq!(get_string(&mut x, 10).unwrap(), b"abcde");
        let mut x = XdrMem::new(&mut buf);
        assert!(get_string(&mut x, 4).is_none());
        // Encoding writes the length before failing the size check, as C does.
        let mut out = [0u8; 8];
        let mut x = XdrMem::new(&mut out);
        assert!(!put_bytes(&mut x, b"abcdef", 4));
        assert_eq!(x.getpos(), 4);
    }

    #[test]
    fn mem_bounds() {
        let mut buf = [0u8; 6];
        let mut x = XdrMem::new(&mut buf);
        assert!(x.get_long().is_some());
        assert!(x.get_long().is_none());
        assert!(x.setpos(0));
        assert!(!x.setpos(7));
    }
}
