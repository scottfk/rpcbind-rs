//! `xlog.c`: messages to syslog and/or stderr.

use tirpc::sys;

pub const L_FATAL: i32 = 0x0100;
pub const L_ERROR: i32 = 0x0200;
pub const L_WARNING: i32 = 0x0400;
pub const L_NOTICE: i32 = 0x0800;
pub const L_ALL: i32 = 0xFF00;
pub const D_ALL: i32 = 0x00FF;
/// rpcbind passes syslog's `LOG_DEBUG` (7) as the kind for its debug messages, which
/// xlog reads as debug facilities 1-3.
#[allow(dead_code)] // the protocol code logs with it, in phase 2
pub const LOG_DEBUG_KIND: i32 = libc::LOG_DEBUG;

/// xlog's globals.
#[derive(Debug)]
pub struct Xlog {
    log_stderr: bool,
    log_syslog: bool,
    logging: bool,
    logmask: i32,
    log_name: Vec<u8>,
}

impl Default for Xlog {
    fn default() -> Self {
        Xlog { log_stderr: true, log_syslog: true, logging: false, logmask: 0, log_name: Vec::new() }
    }
}

impl Xlog {
    /// `xlog_open()`: `openlog()` and the name. (The `SIGUSR1`/`SIGUSR2` toggle handlers
    /// it installs are replaced by `SIG_IGN` in `main()` before they could run.)
    pub fn open(&mut self, progname: &[u8]) {
        sys::openlog(progname, libc::LOG_DAEMON);
        self.log_name = progname[..progname.len().min(255)].to_vec();
    }

    pub fn set_stderr(&mut self, on: bool) {
        self.log_stderr = on;
    }

    pub fn set_syslog(&mut self, on: bool) {
        self.log_syslog = on;
    }

    /// `xlog_config(fac, on)`.
    pub fn config(&mut self, fac: i32, on: bool) {
        if on {
            self.logmask |= fac;
            self.logging = true;
        } else {
            self.logmask &= !fac;
        }
    }

    /// `xlog()` / `xlog_backend()`, with the message already formatted.
    pub fn xlog(&self, kind: i32, msg: &[u8]) {
        if kind & L_ALL == 0 && !(self.logging && kind & self.logmask != 0) {
            return;
        }
        if self.log_syslog {
            match kind {
                L_FATAL | L_ERROR => sys::syslog(libc::LOG_ERR, msg),
                L_WARNING => sys::syslog(libc::LOG_WARNING, msg),
                L_NOTICE => sys::syslog(libc::LOG_NOTICE, msg),
                _ if !self.log_stderr => sys::syslog(libc::LOG_INFO, msg),
                _ => {}
            }
        }
        if self.log_stderr {
            let mut line = self.log_name.clone();
            line.extend_from_slice(b": ");
            line.extend_from_slice(msg);
            line.push(b'\n');
            sys::c_stderr(&line);
        }
        if kind == L_FATAL {
            sys::exit(1);
        }
    }
}
