//! `getnetconfig.c`: the `/etc/netconfig` database.
//!
//! libtirpc keeps one process-wide cache of the entries `getnetconfig()` has read, shared
//! by every handle, and `getnetconfigent()` searches that cache before reading the file
//! again on its own. [`NetconfigDb`] is that state; the program owns one and passes it
//! where C would use the globals.
//!
//! Lines are read with `fgets()` into a 1000-byte buffer, so a longer line is read as
//! several lines, and parsing follows `parse_ncp()` exactly, including its quirks (see
//! QUIRKS.md).

use std::fs::File;
use std::io::{BufReader, Read};

/// `NETCONFIG`.
pub const NETCONFIG: &str = "/etc/netconfig";

/// `MAXNETCONFIGLINE`: the `fgets()` buffer size.
const MAXNETCONFIGLINE: usize = 1000;

// nc_semantics values (<netconfig.h>).
pub const NC_TPI_CLTS: u32 = 1;
pub const NC_TPI_COTS: u32 = 2;
pub const NC_TPI_COTS_ORD: u32 = 3;
pub const NC_TPI_RAW: u32 = 4;

// nc_flag bits.
pub const NC_NOFLAG: u32 = 0x00;
pub const NC_VISIBLE: u32 = 0x01;
pub const NC_BROADCAST: u32 = 0x02;

// nc_error values.
pub const NC_NONETCONFIG: i32 = libc::ENOENT;
pub const NC_NOMEM: i32 = libc::ENOMEM;
pub const NC_NOTINIT: i32 = libc::EINVAL;
pub const NC_BADFILE: i32 = libc::EBADF;
pub const NC_NOTFOUND: i32 = libc::ENOPROTOOPT;

/// `struct netconfig`. Strings are the bytes from the file (never containing NUL).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Netconfig {
    pub netid: Vec<u8>,
    pub semantics: u32,
    pub flag: u32,
    pub protofmly: Vec<u8>,
    pub proto: Vec<u8>,
    pub device: Vec<u8>,
    pub lookups: Vec<Vec<u8>>,
}

/// A handle from [`NetconfigDb::setnetconfig`] (`struct netconfig_vars`).
#[derive(Debug)]
pub struct NcHandle {
    valid: bool,
    /// `flag`: false until the first `getnetconfig()`.
    started: bool,
    /// `nc_configs`: index of the current entry in the cache.
    current: Option<usize>,
}

/// `fgets()` over a buffered file: reads at most `size - 1` bytes, stopping after a
/// newline. `None` at end of file with nothing read (or on a read error, as `fgets()`
/// returns NULL for both).
#[derive(Debug)]
struct Fgets {
    r: BufReader<File>,
}

impl Fgets {
    fn open(path: &str) -> Option<Fgets> {
        File::open(path).ok().map(|f| Fgets { r: BufReader::new(f) })
    }

    fn fgets(&mut self, size: usize) -> Option<Vec<u8>> {
        let mut line = Vec::new();
        let mut b = [0u8; 1];
        while line.len() < size - 1 {
            match self.r.read(&mut b) {
                Ok(1) => {
                    line.push(b[0]);
                    if b[0] == b'\n' {
                        break;
                    }
                }
                Ok(_) => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => return None,
            }
        }
        if line.is_empty() { None } else { Some(line) }
    }
}

/// The C string in a buffer: the bytes before the first NUL.
fn c_str(buf: &[u8]) -> &[u8] {
    match buf.iter().position(|&b| b == 0) {
        Some(n) => &buf[..n],
        None => buf,
    }
}

/// `strtok_r(.., "\t ", ..)` over `s`, starting at `*pos`.
fn strtok<'a>(s: &'a [u8], pos: &mut usize) -> Option<&'a [u8]> {
    let delim = |b: u8| b == b'\t' || b == b' ';
    while *pos < s.len() && delim(s[*pos]) {
        *pos += 1;
    }
    if *pos >= s.len() {
        return None;
    }
    let start = *pos;
    while *pos < s.len() && !delim(s[*pos]) {
        *pos += 1;
    }
    let tok = &s[start..*pos];
    if *pos < s.len() {
        *pos += 1; // the delimiter is overwritten with NUL and skipped
    }
    Some(tok)
}

/// `parse_ncp()`: parse one line as read by `fgets()`. `Err(())` sets `NC_BADFILE`.
fn parse_ncp(line: &[u8]) -> Result<Netconfig, ()> {
    let s = c_str(line);
    // QUIRK: `stringp[strlen(stringp)-1] = '\0'` drops the last byte whether or not it
    // is a newline (the last line of a file without one, or a 999-byte piece of a long
    // line, loses a real character). An empty string (a line starting with NUL) would
    // write before the buffer; here it just fails to parse.
    let s = match s.len() {
        0 => return Err(()),
        n => &s[..n - 1],
    };
    let mut pos = 0;
    let netid = strtok(s, &mut pos).ok_or(())?;
    let semantics = match strtok(s, &mut pos).ok_or(())? {
        b"tpi_cots_ord" => NC_TPI_COTS_ORD,
        b"tpi_cots" => NC_TPI_COTS,
        b"tpi_clts" => NC_TPI_CLTS,
        b"tpi_raw" => NC_TPI_RAW,
        _ => return Err(()),
    };
    let mut flag = NC_NOFLAG;
    for &c in strtok(s, &mut pos).ok_or(())? {
        match c {
            b'-' => {}
            b'v' => flag |= NC_VISIBLE,
            b'b' => flag |= NC_BROADCAST,
            _ => return Err(()),
        }
    }
    let protofmly = strtok(s, &mut pos).ok_or(())?;
    let proto = strtok(s, &mut pos).ok_or(())?;
    let device = strtok(s, &mut pos).ok_or(())?;
    let lookups_tok = strtok(s, &mut pos).ok_or(())?;
    // nc_lookups is a comma-separated list, with `\` escapes (`_get_next_token()`).
    // rpcbind never uses it (only in RPCBIND_DEBUG output), so the escapes aren't
    // interpreted; the entry parses or fails the same either way.
    let lookups =
        if lookups_tok == b"-" { Vec::new() } else { lookups_tok.split(|&b| b == b',').map(<[u8]>::to_vec).collect() };
    Ok(Netconfig {
        netid: netid.to_vec(),
        semantics,
        flag,
        protofmly: protofmly.to_vec(),
        proto: proto.to_vec(),
        device: device.to_vec(),
        lookups,
    })
}

/// libtirpc's netconfig globals: `nc_file`, `ni` (the cache) and `nc_error`.
#[derive(Debug)]
pub struct NetconfigDb {
    path: String,
    file: Option<Fgets>,
    eof: bool,
    refs: u32,
    entries: Vec<Netconfig>,
    /// `nc_error`.
    pub error: i32,
}

impl Default for NetconfigDb {
    fn default() -> Self {
        Self::with_path(NETCONFIG)
    }
}

impl NetconfigDb {
    /// A database reading `path` instead of `/etc/netconfig` (for tests).
    pub fn with_path(path: &str) -> NetconfigDb {
        NetconfigDb { path: path.to_string(), file: None, eof: false, refs: 0, entries: Vec::new(), error: 0 }
    }

    /// `setnetconfig()`.
    pub fn setnetconfig(&mut self) -> Option<NcHandle> {
        self.refs += 1;
        if self.file.is_none() {
            self.file = Fgets::open(&self.path);
        }
        if self.file.is_some() {
            return Some(NcHandle { valid: true, started: false, current: None });
        }
        self.refs -= 1;
        self.error = NC_NONETCONFIG;
        None
    }

    /// `getnetconfig()`: the next entry. `None` at the end of the file, and also at the
    /// first line that doesn't parse.
    pub fn getnetconfig(&mut self, h: &mut NcHandle) -> Option<Netconfig> {
        if self.file.is_none() || !h.valid {
            self.error = NC_NOTINIT;
            return None;
        }
        if !h.started {
            h.started = true;
            h.current = if self.entries.is_empty() { None } else { Some(0) };
            if let Some(i) = h.current {
                return Some(self.entries[i].clone());
            }
        } else if let Some(i) = h.current
            && i + 1 < self.entries.len()
        {
            h.current = Some(i + 1);
            return Some(self.entries[i + 1].clone());
        }
        if self.eof {
            return None;
        }
        let file = self.file.as_mut()?;
        let line = loop {
            match file.fgets(MAXNETCONFIGLINE) {
                None => {
                    self.eof = true;
                    return None;
                }
                Some(l) if l[0] == b'#' => continue,
                Some(l) => break l,
            }
        };
        match parse_ncp(&line) {
            Err(()) => {
                // QUIRK: a line that doesn't parse (a blank line, say) ends the listing,
                // but not the file: eof isn't set, so the next call reads on.
                self.error = NC_BADFILE;
                None
            }
            Ok(nc) => {
                self.entries.push(nc.clone());
                h.current = Some(self.entries.len() - 1);
                Some(nc)
            }
        }
    }

    /// `endnetconfig()`.
    pub fn endnetconfig(&mut self, h: NcHandle) -> i32 {
        if !h.valid {
            self.error = NC_NOTINIT;
            return -1;
        }
        self.refs = self.refs.saturating_sub(1);
        if self.refs > 0 {
            return 0;
        }
        self.eof = false;
        self.entries.clear();
        self.file = None;
        0
    }

    /// `getnetconfigent()`: the entry for `netid`, from the cache or else by reading the
    /// file again from the start.
    pub fn getnetconfigent(&mut self, netid: &[u8]) -> Option<Netconfig> {
        self.error = NC_NOTFOUND;
        if netid.is_empty() {
            return None;
        }
        if netid == b"unix" {
            crate::sys::c_stderr(b"The local transport is called \"unix\" in /etc/netconfig.\n");
            crate::sys::c_stderr(b"Please change this to \"local\" manually or run mergemaster(8).\n");
        }
        if !self.entries.is_empty() {
            if let Some(nc) = self.entries.iter().find(|e| e.netid == netid) {
                return Some(nc.clone());
            }
            if self.eof {
                return None;
            }
        }
        let Some(mut file) = Fgets::open(&self.path) else {
            self.error = NC_NONETCONFIG;
            return None;
        };
        loop {
            let line = loop {
                match file.fgets(MAXNETCONFIGLINE) {
                    None => return None,
                    Some(l) if l[0] == b'#' => continue,
                    Some(l) => break l,
                }
            };
            let s = c_str(&line);
            // QUIRK: a line with no tab or space (a blank line, say) stops the search:
            // entries after it can't be found by name.
            let Some(len) = s.iter().position(|&b| b == b'\t' || b == b' ') else {
                self.error = NC_BADFILE;
                return None;
            };
            if &s[..len] == netid {
                return parse_ncp(&line).ok();
            }
        }
    }

    /// `nc_sperror()`.
    pub fn nc_sperror(&self) -> &'static str {
        match self.error {
            NC_NONETCONFIG => "Netconfig database not found",
            NC_NOMEM => "Not enough memory",
            NC_NOTINIT => "Not initialized",
            NC_BADFILE => "Netconfig database has invalid format",
            NC_NOTFOUND => "Netid not found in netconfig database",
            _ => "Unknown network selection error",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db(text: &[u8]) -> (NetconfigDb, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("tirpc-nc-{}-{:p}", std::process::id(), text));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("netconfig");
        std::fs::write(&p, text).unwrap();
        (NetconfigDb::with_path(p.to_str().unwrap()), dir)
    }

    fn ids(d: &mut NetconfigDb) -> Vec<String> {
        let mut h = d.setnetconfig().unwrap();
        let mut v = Vec::new();
        while let Some(nc) = d.getnetconfig(&mut h) {
            v.push(String::from_utf8(nc.netid).unwrap());
        }
        d.endnetconfig(h);
        v
    }

    const STD: &[u8] = b"#comment\nudp        tpi_clts      v     inet     udp     -       -\n\
tcp        tpi_cots_ord  v     inet     tcp     -       -\n\
local      tpi_cots_ord  -     loopback  -      -       -\n";

    #[test]
    fn parses_standard() {
        let (mut d, dir) = db(STD);
        assert_eq!(ids(&mut d), ["udp", "tcp", "local"]);
        let l = d.getnetconfigent(b"local").unwrap();
        assert_eq!(l.semantics, NC_TPI_COTS_ORD);
        assert_eq!(l.flag, NC_NOFLAG);
        assert_eq!(l.protofmly, b"loopback");
        assert_eq!(l.proto, b"-");
        assert!(l.lookups.is_empty());
        let u = d.getnetconfigent(b"udp").unwrap();
        assert_eq!((u.semantics, u.flag), (NC_TPI_CLTS, NC_VISIBLE));
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn blank_line_ends_listing_and_search() {
        let (mut d, dir) = db(b"udp tpi_clts v inet udp - -\n\ntcp tpi_cots_ord v inet tcp - -\n");
        assert!(d.getnetconfigent(b"tcp").is_none());
        assert_eq!(d.error, NC_BADFILE);
        assert_eq!(ids(&mut d), ["udp"]);
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn last_byte_dropped() {
        let (mut d, dir) = db(b"udp tpi_clts v inet udp - ab");
        let u = d.getnetconfigent(b"udp").unwrap();
        assert_eq!(u.lookups, [b"a".to_vec()]);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
