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

Phases 1 and 2 of 5 are done: phase 1 is merged (PR #2) and phase 2, the protocol, is
on branch `phase2-protocol` (PR pending). The port now serves every procedure C
rpcbind does in this build.

Phase 1, the RPC layer in `crates/tirpc` and rpcbind's startup:

- `/etc/netconfig` (`getnetconfig.c`), address conversions (`rpc_generic.c`), XDR
  (`xdr.c`, `xdr_mem.c`), the record stream in its non-blocking server mode
  (`xdr_rec.c`), messages and authentication (`rpc_callmsg.c`, `rpc_prot.c`,
  `svc_auth*.c`), and the transports and dispatcher (`svc.c`, `svc_dg.c`, `svc_vc.c`,
  `svc_generic.c`);
- `rpcbind.c`, `xlog.c`, `security.c`, `check_bound.c` and `network_init()`.

Phase 2, the protocol:

- portmap v2 (`pmap_svc.c`): `SET`, `UNSET`, `GETPORT`, `DUMP`, `CALLIT`;
- rpcbind v3 and v4 (`rpcb_svc.c`, `rpcb_svc_4.c`, `rpcb_svc_com.c`): `SET`, `UNSET`
  with owners, `GETADDR`, `GETVERSADDR`, `GETADDRLIST`, `DUMP`, `GETTIME`,
  `UADDR2TADDR`, `TADDR2UADDR`, `GETSTAT`, and `CALLIT`/`INDIRECT`/`BCAST` up to the
  missing forwarding socket;
- `addrmerge()` and `mergeaddr()`, all of `rpcb_stat.c`, and libtirpc's XDR for these
  types (`rpcb_prot.c`, `rpcb_st_xdr.c`, `pmap_prot*.c`) in `tirpc::rpcb_prot`.

The differential suite has 47 tests (80 cases), all passing: 32 from phase 1 and 15 for
the protocol, which register and look up services over every transport, as root and as
other users over the local socket, from non-loopback addresses on netkit interfaces,
through the system libtirpc (`rpcb_set()`, `pmap_set()`, `rpcb_getaddr()`...) and C
`rpcinfo`. Mutants that undo reproduced quirks are caught (four in phase 1, five in
phase 2).

Next: phase 3, hostile input.

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

## Testing

```sh
make check
```

This builds the C reference into `../rpcbind` if it isn't there, then runs the unit
tests and the differential suite ([crates/rpcbind/tests/](crates/rpcbind/tests/)). Each
case starts C rpcbind and then the port, each in a private user, mount, network and pid
namespace (ids mapped from your subordinate ranges, so there's a real root and the
system's users exist; its own loopback, `/proc` and `/run`; `/dev/log` captured; the
case's own `/etc/netconfig` if it has one), sends both the same requests with
`rpcprobe` (raw datagrams, connections and record fragments), and compares:

- every reply, byte for byte, and which address UDP replies came from;
- stdout, stderr, the exit status and every syslog line (time stamps and pids
  normalized);
- the sockets the daemon has bound (unconnected UDP, listening TCP, the local socket)
  and `/run` (names, modes, owners) before and after the signal that ends it.

To see what each case produced: `RPCBIND_DIFF_SHOW=1 cargo test -- --nocapture`. Each
run's files stay in `target/difftest/<case>/{c,r}/`.

The probe can also run commands in the sandbox: C `rpcinfo` and `tirpcprobe`
([crates/rpcbind/tests/tirpcprobe.c](crates/rpcbind/tests/tirpcprobe.c)), which calls
rpcbind through the system libtirpc as RPC services do, optionally as another user.
Cases can add netkit interfaces, and a fixed clock for the daemon (the LD_PRELOAD shim
in `crates/rpcbind/tests/shim/`) for `GETTIME`.

## Roadmap

1. **Startup and the RPC layer (merged, PR #2):** `crates/tirpc` (XDR, messages, auth, record marking,
   the three transports, netconfig, universal addresses, the dispatcher with its error
   replies), and `rpcbind.c`: options, `-v`, the lock, the rlimit and superuser checks,
   one transport per netconfig entry (`-h` addresses, `SO_REUSEADDR`, `IPV6_V6ONLY`,
   the local socket and its mode), the privilege drop, signals, `daemon()` and the
   loop. Tested with `NULL` calls on every program and version, and the rejections
   (wrong program, version, procedure, RPC version, auth) for everything else.
2. **The protocol (done, branch `phase2-protocol`):** portmap v2 (`pmap_svc.c`) and rpcbind v3/v4 (`rpcb_svc*.c`):
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
