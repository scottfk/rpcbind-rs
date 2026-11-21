# rpcbind-rs

A drop-in port/reimplementation of rpcbind (and rpcinfo) in Rust. Currently just
something fun for me to tinker with in Claude.

## Goals

- **Drop-in compatible with rpcbind 1.2.8** (Gentoo's `net-nds/rpcbind`): the same
  options, messages, syslog lines and exit statuses, the same sockets bound the same way
  (from `/etc/netconfig`), the same lock file and local socket, and byte-for-byte the
  same replies to every portmap (v2) and rpcbind (v3, v4) request, malformed ones
  included. `rpcinfo` gives the same output. Upstream quirks are reproduced on purpose
  and listed in [QUIRKS.md](QUIRKS.md). Improvements come later, as deliberate changes.
- **No libtirpc.** Upstream gets XDR, the RPC message layer, the transports and
  `/etc/netconfig` from libtirpc. The point of this port is that rpcbind is a root
  daemon parsing untrusted network input, so those parts are reimplemented in Rust
  (in `crates/tirpc`), following libtirpc 1.3.7's behavior where it shows on the wire or
  in messages. Wrapping libtirpc over FFI would keep the C parser.
- **Linux only.**
- **Small and boring:** `libc` as the only crate dependency, no async (a `poll()` loop
  like upstream's), and `unsafe` confined to one `sys` module.

## Status

Phase 1 of 5 is in progress (branch `phase1-startup`). Done so far, in `crates/tirpc`:

- `/etc/netconfig` (`getnetconfig.c`), with libtirpc's shared cache and its parsing
  quirks;
- universal and transport address conversions (`rpc_generic.c`);
- XDR primitives and the memory stream (`xdr.c`, `xdr_mem.c`), making the same stream
  calls in the same order as libtirpc;
- the record-marking stream in its non-blocking server mode (`xdr_rec.c`), including
  where reply fragments are split;
- call decoding, reply encoding and server-side authentication (`rpc_callmsg.c`,
  `rpc_prot.c`, `svc_auth.c`, `svc_auth_unix.c`);
- the `sys` module: libc calls for sockets, stdio and the address functions.

Next: the transports and dispatcher (`svc.c`, `svc_dg.c`, `svc_vc.c`), then
`rpcbind.c`'s startup and the differential harness. The `rpcbind` binary is a stub until
then.

The plan and its status live in the [roadmap](#roadmap) below, which is updated as each
step lands.

The reference is the `rpcbind-1.2.8` release tarball, built as Gentoo builds it
([tools/build-reference.sh](tools/build-reference.sh)), against the system libtirpc
1.3.7:

- USE="-debug -remotecalls -selinux -systemd -tcpd -warmstarts": no `-w` warm starts,
  no `CALLIT`/`INDIRECT` forwarding, no TCP wrappers, no socket activation;
- `/sbin/rpcbind` and `/sbin/rpcinfo`, state directory `/run/rpcbind`;
- upstream's defaults: `-DCHECK_LOCAL -DPORTMAP -DINET6`, user `root`, NSS modules
  `files`; syslog to `LOG_DAEMON` once logging is set up (`LOG_USER` before that) and
  `LOG_AUTH` for `-l` lines.

The reference build imports exactly the same libc and libtirpc symbols as the installed
binaries. The libtirpc 1.3.7 sources (also Gentoo's tarball) are kept beside it in
`../libtirpc`, for reading.

## Planned layout

Upstream is about 6,100 lines of C in `src/`, plus the parts of libtirpc it relies on.
The port follows the files:

| Path | What |
|---|---|
| `crates/tirpc/` | the libtirpc subset: XDR, RPC messages and auth (`AUTH_NONE`, `AUTH_SYS`), record marking, the datagram, stream and local transports (with peer credentials), the service dispatcher, `/etc/netconfig`, universal addresses, and `sys.rs` (every libc call) |
| `crates/rpcbind/src/main.rs` | `rpcbind.c`: options, the lock, transports from netconfig, privilege drop, the loop |
| `crates/rpcbind/src/rpcb_svc_com.rs` | `rpcb_svc_com.c`: the registration list, `SET`/`UNSET`, `GETADDR`, `DUMP`, `GETTIME`, address conversions |
| `crates/rpcbind/src/{pmap_svc,rpcb_svc,rpcb_svc_4,rpcb_stat}.rs` | the v2, v3 and v4 dispatchers and `GETSTAT` |
| `crates/rpcbind/src/{security,check_bound,util,xlog}.rs` | access checks and `-l` logging, the transport list, `addrmerge()`, messages |
| `crates/rpcinfo/` | `rpcinfo.c` |
| `tests/` | differential tests and the harness |
| `contrib/gentoo/` | a `net-nds/rpcbind` live ebuild, and how to switch and roll back |
| `tools/` | the reference build |

## Testing (planned)

`make check` will build the C reference into `../rpcbind` if it isn't there, then run
the differential suite. Each case starts C rpcbind and the port in turn, in a private
user, mount and network namespace (a real root, its own loopback and test interfaces,
its own `/run` and `/etc`), sends both the same sequence of requests, and compares:

- every reply, byte for byte (the transaction ids are the test's own);
- stdout, stderr, the exit status and syslog lines (captured on the sandbox's
  `/dev/log`);
- the sockets each daemon left listening (family, type, address, owner, mode of
  `/run/rpcbind.sock`) and the files under `/run`.

Requests come from three clients: the C reference `rpcinfo`, a small C probe linked
with the system libtirpc (`rpcb_set()`, `pmap_set()`, `rpcb_getaddr()` and friends, as
NFS daemons call them, including over the local socket as other users), and raw packets
written by the test, for malformed, truncated, oversized and hostile input.

## Roadmap

1. **Startup and the RPC layer (in progress, branch `phase1-startup`):** `crates/tirpc` (XDR, messages, auth, record marking,
   the three transports, netconfig, universal addresses, the dispatcher with its error
   replies), and `rpcbind.c`: options, `-v`, the lock, the rlimit and superuser checks,
   one transport per netconfig entry (`-h` addresses, `SO_REUSEADDR`, `IPV6_V6ONLY`,
   the local socket and its mode), the privilege drop, signals, `daemon()` and the
   loop. Tested with `NULL` calls on every program and version, and the rejections
   (wrong program, version, procedure, RPC version, auth) for everything else.
2. **The protocol (planned):** portmap v2 (`pmap_svc.c`) and rpcbind v3/v4 (`rpcb_svc*.c`):
   `SET`/`UNSET` with owners taken from local-socket credentials, `GETADDR` and
   `GETVERSADDR` with `addrmerge()` choosing the interface address, `DUMP`,
   `GETADDRLIST`, `GETTIME`, `UADDR2TADDR`/`TADDR2UADDR`, `GETSTAT` counters, and the
   access checks and `-i`/`-l` logging (`security.c`). Tested with C `rpcinfo`, the
   libtirpc probe and several interfaces in the test namespace.
3. **Hostile input (planned):** malformed and truncated XDR, oversized and fragmented records,
   idle and half-open connections, many clients at once, and the cases behind past
   CVEs (CVE-2017-8779 "rpcbomb" and CVE-2015-7236), checked for the same replies and
   bounded memory.
4. **rpcinfo (planned):** every mode (`-p`, `-s`, `-m`, `-l`, `-T`, `-u`, `-t`, `-a`, `-b`, `-d`,
   `-n`), run against both daemons.
5. **Packaging (planned):** a Gentoo ebuild (a `net-nds/rpcbind` drop-in, the same init script and
   conf.d), rehearsed on the test VM with a real NFS client and server stack
   (`rpc.statd`, `rpc.mountd`, `nfsd`, a mount and file locks), and rolled back through a
   binary package of the C build.

Not planned unless needed: the build options hydra doesn't use (warm starts, remote
calls, TCP wrappers, systemd socket activation, `RPCBIND_DEBUG`). The ebuild will
require them off.

### After rpcbind

`crates/tirpc` is meant to carry over to the NFS daemons: an `nfs-utils-rs` covering
`rpc.statd` and `sm-notify` first (network-facing, root, a long bug history), then
`libnfsidmap` (C ABI and plugins) and `rpc.idmapd`. autofs is out of scope for now: it
is much larger and its behavior can only be tested on a VM with real mounts.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

The same license as upstream rpcbind and libtirpc: the 3-clause BSD license.
[LICENSE](LICENSE) is upstream's `COPYING`, unchanged; the Sun Microsystems notices in
upstream's source files (also 3-clause BSD) apply to the ported code, and are kept in
[LICENSES/Sun-BSD-3-Clause.txt](LICENSES/Sun-BSD-3-Clause.txt).
