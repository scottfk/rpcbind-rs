//! `xdr_rec.c`: the record-marking stream for stream transports, in the non-blocking
//! mode `svc_vc` uses once `RPC_SVC_CONNMAXREC_SET` is set (as rpcbind always does).
//!
//! Input: `__xdrrec_getrec()` collects a whole record (every fragment, up to `maxrec`
//! bytes) into the input buffer with one `read()` per call, and decoding then works on
//! that buffer only. Output: replies are written through a `sendsize` buffer, and a
//! record is split into fragments exactly where libtirpc's `putlong`/`putbytes` flush.
//!
//! Clients (`clnt_vc`) use the stream in its ordinary blocking mode instead: input is
//! read on demand, one `read()` of up to the free buffer per refill, through
//! [`RecStream::skiprecord`] and [`RecStream::blocking_decoder`].

use crate::xdr::{UNIT, XdrDecode, XdrEncode};

/// `LAST_FRAG`.
const LAST_FRAG: u32 = 0x8000_0000;

/// What a non-blocking `read_vc()` returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadResult {
    /// `n > 0` bytes were read.
    Data(usize),
    /// `read()` failed with `EAGAIN`: read_vc returns 0 with errno `EAGAIN`.
    WouldBlock,
    /// `read()` returned 0: read_vc returns 0 with errno 0.
    Eof,
    /// `read()` failed otherwise: read_vc returns -1 (and marks the stream dead).
    Error,
}

/// `readit`/`writeit`: the transport's `read_vc()`/`write_vc()`.
pub trait RecIo {
    fn read(&mut self, buf: &mut [u8]) -> ReadResult;
    /// Writes all of `buf`, returning whether it all went.
    fn write(&mut self, buf: &[u8]) -> bool;
}

/// `enum xprt_stat`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XprtStat {
    Died,
    MoreReqs,
    Idle,
}

/// `RECSTREAM`, non-blocking.
#[derive(Debug)]
pub struct RecStream {
    // output
    out: Vec<u8>,
    out_finger: usize,
    frag_header: usize,
    frag_sent: bool,
    // input
    in_buf: Vec<u8>,
    in_finger: usize,
    in_boundry: usize,
    fbtbc: usize,
    last_frag: bool,
    recvsize: usize,
    in_haveheader: bool,
    in_header: [u8; 4],
    in_hdrlen: usize,
    in_reclen: usize,
    in_received: usize,
    in_maxrec: usize,
}

/// `fix_buf_size()`.
fn fix_buf_size(s: usize) -> usize {
    crate::xdr::rndup(if s < 100 { 4000 } else { s })
}

impl RecStream {
    /// `xdrrec_create()` followed by `__xdrrec_setnonblock(maxrec)`.
    pub fn new(sendsize: usize, recvsize: usize, maxrec: usize) -> RecStream {
        let sendsize = fix_buf_size(sendsize);
        let recvsize = fix_buf_size(recvsize);
        RecStream {
            out: vec![0; sendsize],
            out_finger: UNIT,
            frag_header: 0,
            frag_sent: false,
            in_buf: vec![0; recvsize],
            in_finger: recvsize,
            in_boundry: recvsize,
            fbtbc: 0,
            last_frag: true,
            recvsize,
            in_haveheader: false,
            in_header: [0; 4],
            in_hdrlen: 0,
            in_reclen: 0,
            in_received: 0,
            in_maxrec: if maxrec == 0 { recvsize } else { maxrec },
        }
    }

    /// `__xdrrec_getrec()`: read toward a complete record. True when one is ready to
    /// decode; `stat` says what to do otherwise.
    pub fn getrec(&mut self, io: &mut dyn RecIo, stat: &mut XprtStat, expectdata: bool) -> bool {
        let zero = |stat: &mut XprtStat, r: ReadResult| {
            *stat = match r {
                ReadResult::WouldBlock => XprtStat::Idle,
                _ if expectdata => XprtStat::Died,
                _ => XprtStat::Idle,
            };
        };
        if !self.in_haveheader {
            let mut hdr = [0u8; 4];
            let want = 4 - self.in_hdrlen;
            let n = match io.read(&mut hdr[..want]) {
                ReadResult::Data(n) => n,
                ReadResult::Error => {
                    *stat = XprtStat::Died;
                    return false;
                }
                r => {
                    zero(stat, r);
                    return false;
                }
            };
            self.in_header[self.in_hdrlen..self.in_hdrlen + n].copy_from_slice(&hdr[..n]);
            self.in_hdrlen += n;
            if self.in_hdrlen < 4 {
                *stat = XprtStat::MoreReqs;
                return false;
            }
            let header = u32::from_be_bytes(self.in_header);
            let fraglen = (header & !LAST_FRAG) as usize;
            // `(int)` of a 31-bit length is never negative.
            if fraglen == 0 || fraglen > self.in_maxrec || self.in_reclen + fraglen > self.in_maxrec {
                *stat = XprtStat::Died;
                return false;
            }
            self.in_reclen += fraglen;
            if self.in_reclen > self.recvsize {
                // realloc_stream(): unreachable while maxrec <= recvsize, as in rpcbind.
                self.in_buf.resize(self.in_reclen, 0);
                self.recvsize = self.in_reclen;
                self.in_boundry = self.in_reclen;
            }
            if header & LAST_FRAG != 0 {
                self.last_frag = true;
            }
            self.in_haveheader = true;
        }
        let (start, end) = (self.in_received, self.in_reclen);
        let n = match io.read(&mut self.in_buf[start..end]) {
            ReadResult::Data(n) => n,
            ReadResult::Error => {
                *stat = XprtStat::Died;
                return false;
            }
            r => {
                zero(stat, r);
                return false;
            }
        };
        self.in_received += n;
        if self.in_received == self.in_reclen {
            self.in_haveheader = false;
            self.in_hdrlen = 0;
            // QUIRK: in non-blocking mode last_frag starts true and is never cleared,
            // so every fragment, LAST_FRAG or not, is taken as a whole record, and the
            // next fragment's header starts a new one. See QUIRKS.md.
            if self.last_frag {
                self.fbtbc = self.in_reclen;
                self.in_boundry = self.in_reclen;
                self.in_finger = 0;
                self.in_reclen = 0;
                self.in_received = 0;
                *stat = XprtStat::MoreReqs;
                return true;
            }
        }
        *stat = XprtStat::MoreReqs;
        false
    }

    /// `xdrrec_eof()`.
    pub fn eof(&mut self) -> bool {
        // Non-blocking: skip_input_bytes() works within the buffer, and
        // set_input_fragment() always fails.
        while self.fbtbc > 0 || !self.last_frag {
            if self.fbtbc > self.in_boundry - self.in_finger {
                return true;
            }
            self.in_finger += self.fbtbc;
            self.fbtbc = 0;
            if !self.last_frag {
                return true;
            }
        }
        self.in_finger == self.in_boundry
    }

    /// `flush_out()`.
    fn flush_out(&mut self, io: &mut dyn RecIo, eor: bool) -> bool {
        let len = (self.out_finger - self.frag_header - UNIT) as u32;
        let mask = if eor { LAST_FRAG } else { 0 };
        self.out[self.frag_header..self.frag_header + UNIT].copy_from_slice(&(len | mask).to_be_bytes());
        if !io.write(&self.out[..self.out_finger]) {
            return false;
        }
        self.frag_header = 0;
        self.out_finger = UNIT;
        true
    }

    /// `xdrrec_endofrecord(xdrs, sendnow)`.
    pub fn endofrecord(&mut self, io: &mut dyn RecIo, sendnow: bool) -> bool {
        if sendnow || self.frag_sent || self.out_finger + UNIT >= self.out.len() {
            self.frag_sent = false;
            return self.flush_out(io, true);
        }
        let len = (self.out_finger - self.frag_header - UNIT) as u32;
        self.out[self.frag_header..self.frag_header + UNIT].copy_from_slice(&(len | LAST_FRAG).to_be_bytes());
        self.frag_header = self.out_finger;
        self.out_finger += UNIT;
        true
    }

    /// `fill_input_buf()`, blocking: one read into the buffer, starting at the same
    /// offset within a unit as the old boundary.
    fn fill_input_buf(&mut self, io: &mut dyn RecIo) -> bool {
        let i = self.in_boundry % UNIT;
        let len = self.in_buf.len() - i;
        match io.read(&mut self.in_buf[i..i + len]) {
            ReadResult::Data(n) => {
                self.in_finger = i;
                self.in_boundry = i + n;
                true
            }
            _ => false,
        }
    }

    /// `get_input_bytes()`, blocking.
    fn get_input_bytes(&mut self, io: &mut dyn RecIo, out: &mut [u8]) -> bool {
        let mut done = 0;
        while done < out.len() {
            let current = self.in_boundry - self.in_finger;
            if current == 0 {
                if !self.fill_input_buf(io) {
                    return false;
                }
                continue;
            }
            let current = current.min(out.len() - done);
            out[done..done + current].copy_from_slice(&self.in_buf[self.in_finger..self.in_finger + current]);
            self.in_finger += current;
            done += current;
        }
        true
    }

    /// `set_input_fragment()`, blocking. A zero header fails; `LAST_FRAG` with length 0
    /// is accepted.
    fn set_input_fragment(&mut self, io: &mut dyn RecIo) -> bool {
        let mut h = [0u8; 4];
        if !self.get_input_bytes(io, &mut h) {
            return false;
        }
        let header = u32::from_be_bytes(h);
        self.last_frag = header & LAST_FRAG != 0;
        // QUIRK: last_frag is already cleared, so skiprecord() then reads the next
        // header and skips that record too.
        if header == 0 {
            return false;
        }
        self.fbtbc = (header & !LAST_FRAG) as usize;
        true
    }

    /// `skip_input_bytes()`, blocking.
    fn skip_input_bytes(&mut self, io: &mut dyn RecIo, mut cnt: usize) -> bool {
        while cnt > 0 {
            let current = self.in_boundry - self.in_finger;
            if current == 0 {
                if !self.fill_input_buf(io) {
                    return false;
                }
                continue;
            }
            let current = current.min(cnt);
            self.in_finger += current;
            cnt -= current;
        }
        true
    }

    /// `xdrrec_skiprecord()`, blocking: skip what is left of the current record, so that
    /// decoding starts on the next one.
    pub fn skiprecord(&mut self, io: &mut dyn RecIo) -> bool {
        while self.fbtbc > 0 || !self.last_frag {
            if !self.skip_input_bytes(io, self.fbtbc) {
                return false;
            }
            self.fbtbc = 0;
            if !self.last_frag && !self.set_input_fragment(io) {
                return false;
            }
        }
        self.last_frag = false;
        true
    }

    /// The stream for decoding in blocking mode, reading through `io` as needed.
    pub fn blocking_decoder<'a>(&'a mut self, io: &'a mut dyn RecIo) -> BlockingDecoder<'a> {
        BlockingDecoder { r: self, io }
    }

    /// The stream for decoding the current record.
    pub fn decoder(&mut self) -> RecDecoder<'_> {
        RecDecoder { r: self }
    }

    /// The stream for encoding a reply, writing full fragments through `io`.
    pub fn encoder<'a>(&'a mut self, io: &'a mut dyn RecIo) -> RecEncoder<'a> {
        RecEncoder { r: self, io }
    }
}

/// A [`RecStream`] in `XDR_DECODE`.
#[derive(Debug)]
pub struct RecDecoder<'a> {
    r: &'a mut RecStream,
}

impl XdrDecode for RecDecoder<'_> {
    /// `xdrrec_getlong()`.
    fn get_long(&mut self) -> Option<u32> {
        let r = &mut *self.r;
        if r.fbtbc >= UNIT && r.in_boundry - r.in_finger >= UNIT {
            let v = u32::from_be_bytes(r.in_buf[r.in_finger..r.in_finger + UNIT].try_into().unwrap());
            r.fbtbc -= UNIT;
            r.in_finger += UNIT;
            return Some(v);
        }
        let mut b = [0u8; 4];
        if self.get_bytes(&mut b) { Some(u32::from_be_bytes(b)) } else { None }
    }

    /// `xdrrec_getbytes()`.
    fn get_bytes(&mut self, out: &mut [u8]) -> bool {
        let r = &mut *self.r;
        let mut done = 0;
        while done < out.len() {
            let current = r.fbtbc;
            if current == 0 {
                // last_frag, or set_input_fragment() failing when non-blocking.
                return false;
            }
            let current = (out.len() - done).min(current);
            // get_input_bytes(), non-blocking.
            if current > r.in_boundry - r.in_finger {
                return false;
            }
            out[done..done + current].copy_from_slice(&r.in_buf[r.in_finger..r.in_finger + current]);
            r.in_finger += current;
            r.fbtbc -= current;
            done += current;
        }
        true
    }

    /// `xdrrec_inline()`, decoding.
    fn inline(&mut self, len: usize) -> Option<&[u8]> {
        let r = &mut *self.r;
        if len <= r.fbtbc && r.in_finger + len <= r.in_boundry {
            let start = r.in_finger;
            r.fbtbc -= len;
            r.in_finger += len;
            return Some(&r.in_buf[start..start + len]);
        }
        None
    }
}

/// A [`RecStream`] in `XDR_DECODE`, blocking (a client's).
pub struct BlockingDecoder<'a> {
    r: &'a mut RecStream,
    io: &'a mut dyn RecIo,
}

impl std::fmt::Debug for BlockingDecoder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BlockingDecoder").field("r", &self.r).finish_non_exhaustive()
    }
}

impl XdrDecode for BlockingDecoder<'_> {
    /// `xdrrec_getlong()`.
    fn get_long(&mut self) -> Option<u32> {
        let r = &mut *self.r;
        if r.fbtbc >= UNIT && r.in_boundry - r.in_finger >= UNIT {
            let v = u32::from_be_bytes(r.in_buf[r.in_finger..r.in_finger + UNIT].try_into().unwrap());
            r.fbtbc -= UNIT;
            r.in_finger += UNIT;
            return Some(v);
        }
        let mut b = [0u8; 4];
        if self.get_bytes(&mut b) { Some(u32::from_be_bytes(b)) } else { None }
    }

    /// `xdrrec_getbytes()`: across fragments, reading as needed.
    fn get_bytes(&mut self, out: &mut [u8]) -> bool {
        let mut done = 0;
        while done < out.len() {
            let current = self.r.fbtbc;
            if current == 0 {
                if self.r.last_frag || !self.r.set_input_fragment(self.io) {
                    return false;
                }
                continue;
            }
            let current = (out.len() - done).min(current);
            if !self.r.get_input_bytes(self.io, &mut out[done..done + current]) {
                return false;
            }
            self.r.fbtbc -= current;
            done += current;
        }
        true
    }

    /// `xdrrec_inline()`, decoding: only from what is already buffered.
    fn inline(&mut self, len: usize) -> Option<&[u8]> {
        let r = &mut *self.r;
        if len <= r.fbtbc && r.in_finger + len <= r.in_boundry {
            let start = r.in_finger;
            r.fbtbc -= len;
            r.in_finger += len;
            return Some(&r.in_buf[start..start + len]);
        }
        None
    }
}

/// A [`RecStream`] in `XDR_ENCODE`.
pub struct RecEncoder<'a> {
    r: &'a mut RecStream,
    io: &'a mut dyn RecIo,
}

impl std::fmt::Debug for RecEncoder<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecEncoder").field("r", &self.r).finish_non_exhaustive()
    }
}

impl RecEncoder<'_> {
    /// `xdrrec_endofrecord()`.
    pub fn endofrecord(&mut self, sendnow: bool) -> bool {
        self.r.endofrecord(self.io, sendnow)
    }
}

impl XdrEncode for RecEncoder<'_> {
    /// `xdrrec_putlong()`: flushes a fragment only when the unit doesn't fit.
    fn put_long(&mut self, v: u32) -> bool {
        if self.r.out_finger + UNIT > self.r.out.len() {
            self.r.frag_sent = true;
            if !self.r.flush_out(self.io, false) {
                return false;
            }
        }
        let p = self.r.out_finger;
        self.r.out[p..p + UNIT].copy_from_slice(&v.to_be_bytes());
        self.r.out_finger += UNIT;
        true
    }

    /// `xdrrec_putbytes()`: flushes a fragment as soon as the buffer is full.
    fn put_bytes(&mut self, b: &[u8]) -> bool {
        let mut b = b;
        while !b.is_empty() {
            let room = self.r.out.len() - self.r.out_finger;
            let current = b.len().min(room);
            let p = self.r.out_finger;
            self.r.out[p..p + current].copy_from_slice(&b[..current]);
            self.r.out_finger += current;
            b = &b[current..];
            if self.r.out_finger == self.r.out.len() {
                self.r.frag_sent = true;
                if !self.r.flush_out(self.io, false) {
                    return false;
                }
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Pipe {
        input: Vec<u8>,
        pos: usize,
        chunk: usize,
        output: Vec<Vec<u8>>,
    }

    impl RecIo for Pipe {
        fn read(&mut self, buf: &mut [u8]) -> ReadResult {
            if self.pos == self.input.len() {
                return ReadResult::WouldBlock;
            }
            let n = buf.len().min(self.chunk).min(self.input.len() - self.pos);
            buf[..n].copy_from_slice(&self.input[self.pos..self.pos + n]);
            self.pos += n;
            ReadResult::Data(n)
        }
        fn write(&mut self, buf: &[u8]) -> bool {
            self.output.push(buf.to_vec());
            true
        }
    }

    fn pipe(input: &[u8], chunk: usize) -> Pipe {
        Pipe { input: input.to_vec(), pos: 0, chunk, output: Vec::new() }
    }

    #[test]
    fn record_in_pieces() {
        let mut input = (0x8000_0008u32).to_be_bytes().to_vec();
        input.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 2]);
        let mut io = pipe(&input, 3);
        let mut r = RecStream::new(9000, 9000, 9000);
        let mut st = XprtStat::Idle;
        let mut n = 0;
        while !r.getrec(&mut io, &mut st, true) {
            assert_eq!(st, XprtStat::MoreReqs);
            n += 1;
        }
        assert_eq!(n, 3); // 3+1 header bytes, then 3, 3, 2 body bytes
        let mut d = r.decoder();
        assert_eq!(d.get_long(), Some(1));
        assert_eq!(d.get_long(), Some(2));
        assert_eq!(d.get_long(), None);
        assert!(r.eof());
        assert!(!r.getrec(&mut io, &mut st, true));
        assert_eq!(st, XprtStat::Idle);
    }

    #[test]
    fn oversized_and_empty_fragments_kill() {
        let mut st = XprtStat::Idle;
        let mut r = RecStream::new(9000, 9000, 9000);
        assert!(!r.getrec(&mut pipe(&(0x8000_0000u32 | 9001).to_be_bytes(), 4), &mut st, true));
        assert_eq!(st, XprtStat::Died);
        let mut r = RecStream::new(9000, 9000, 9000);
        assert!(!r.getrec(&mut pipe(&0x8000_0000u32.to_be_bytes(), 4), &mut st, true));
        assert_eq!(st, XprtStat::Died);
    }

    struct Blocking {
        input: Vec<u8>,
        pos: usize,
        chunk: usize,
    }

    impl RecIo for Blocking {
        fn read(&mut self, buf: &mut [u8]) -> ReadResult {
            if self.pos == self.input.len() {
                return ReadResult::Error;
            }
            let n = buf.len().min(self.chunk).min(self.input.len() - self.pos);
            buf[..n].copy_from_slice(&self.input[self.pos..self.pos + n]);
            self.pos += n;
            ReadResult::Data(n)
        }
        fn write(&mut self, _: &[u8]) -> bool {
            true
        }
    }

    #[test]
    fn blocking_records() {
        // Two fragments then a second record; the first is decoded across the
        // fragment boundary, and skiprecord() drops the rest of it.
        let mut input = 6u32.to_be_bytes().to_vec();
        input.extend_from_slice(&[0, 0, 0, 1, 0, 0]);
        input.extend_from_slice(&(0x8000_0006u32).to_be_bytes());
        input.extend_from_slice(&[0, 2, 0, 0, 0, 3]);
        input.extend_from_slice(&(0x8000_0004u32).to_be_bytes());
        input.extend_from_slice(&[0, 0, 0, 9]);
        let mut io = Blocking { input, pos: 0, chunk: 5 };
        let mut r = RecStream::new(100, 100, 0);
        assert!(r.skiprecord(&mut io));
        {
            let mut d = r.blocking_decoder(&mut io);
            assert_eq!(d.get_long(), Some(1));
            assert_eq!(d.get_long(), Some(2));
        }
        assert!(r.skiprecord(&mut io));
        assert_eq!(r.blocking_decoder(&mut io).get_long(), Some(9));
        assert!(!r.skiprecord(&mut io) || r.blocking_decoder(&mut io).get_long().is_none());
    }

    #[test]
    fn reply_fragments() {
        // putbytes fills the buffer exactly, flushes a fragment, and endofrecord then
        // sends an empty last fragment.
        let mut io = pipe(&[], 1);
        let mut r = RecStream::new(100, 100, 100);
        {
            let mut e = r.encoder(&mut io);
            assert!(e.put_bytes(&[7u8; 96]));
            assert!(e.endofrecord(true));
        }
        assert_eq!(io.output.len(), 2);
        assert_eq!(&io.output[0][..4], &96u32.to_be_bytes());
        assert_eq!(io.output[1], LAST_FRAG.to_be_bytes());
        // putlong flushes lazily: 24 units fit, and endofrecord sends one last fragment.
        let mut io = pipe(&[], 1);
        let mut r = RecStream::new(100, 100, 100);
        {
            let mut e = r.encoder(&mut io);
            for i in 0..24 {
                assert!(e.put_long(i));
            }
            assert!(e.endofrecord(true));
        }
        assert_eq!(io.output.len(), 1);
        assert_eq!(&io.output[0][..4], &(LAST_FRAG | 96).to_be_bytes());
    }
}
