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

All five phases are done and merged (PRs #2 to #6). I am now eating my own dogfood,
running it on hydra, my daily driver, as I do the other -rs ports: since 2026-11-25
`/sbin/rpcbind` and `rpcinfo` there are this port, installed with the ebuild below,
with no libtirpc in either. After the restart `rpc.statd` registered again and the
NFSv4 mounts carried on. The port serves every procedure C
rpcbind does in this build and holds up the same way under floods, stalls and garbage,
and rpcinfo-rs gives the same output as C rpcinfo in every mode.

`crates/tirpc` also serves [nfs-utils-rs](https://github.com/scottfk/nfs-utils-rs):
`bindresvport_sa()` and reply decoding for its `sm-notify` (PR #11), and for its
`rpc.statd` the server side rpcbind itself doesn't use: `svc_tli_create()` making its
own socket (`RPC_ANYFD`), `svc_reg()` with a netconfig (registering with rpcbind through
`rpcb_set()`), `svc_fdset` and `svc_getreqset()` for a `select()` loop.

And [autofs-rs](https://github.com/scottfk/autofs-rs), for the automounter's NFS probes
and export lists (PR #13): `CLSET_TIMEOUT` (`Control::SetTimeout`) and an `AUTH_SYS`
credential on a client (`authunix_create_default()` as `cl_auth`).

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

Phase 3, hostile input:

- connection floods under a low descriptor limit and the idle-connection cleanup
  (`__svc_destroy_idle()` with its slot-index lookup), on a real and a fake clock;
- half-sent records, half-closed and reset connections, and a client that never
  reads its replies (`write_vc()`'s two-second stall);
- the "rpcbomb" (CVE-2017-8779) and crafted `CALLIT` (CVE-2015-7236) cases, repeated,
  with the daemon's resident peak checked (about 3 MB for both);
- mutated calls of every procedure on every transport, 800 in the suite and 27,000
  more run once over six option sets, all matching; they turned up the
  `svc_freeargs()` failure for oversized netbufs and how libtirpc's leftover
  credential bytes are left by failed decodes and move with the poll table.

Phase 4, `rpcinfo`:

- the client half of libtirpc in `crates/tirpc`: stream and datagram clients
  (`clnt_vc.c`, `clnt_dg.c`, with the record stream's blocking mode), `clnt_generic.c`,
  `bindresvport.c`, reply decoding (`rpc_prot.c`), `clnt_perror.c`, the rpcbind client
  calls (`rpcb_clnt.c`: the address cache, `GETADDR` with the portmap fallback,
  `rpcb_unset()`), `clnt_bcast.c`, transport classes and `NETPATH` (`getnetpath.c`);
- `rpcinfo.c` in `crates/rpcinfo`: every mode (`-p`, `-s`, `-m`, `-l`, `-T`, `-t`, `-u`,
  `-a`, `-b`, `-d`, `-n`) with its messages, exit codes and output formats.

Each rpcinfo case runs three ways (C rpcbind with C rpcinfo, C rpcbind with rpcinfo-rs,
rpcbind-rs with rpcinfo-rs), and all three must agree. Besides rpcbind itself they talk
to fake servers in the probe: scripted replies over UDP and TCP (garbage, stale xids,
denials, unknown statuses, a zero record mark, silence) and a broadcast responder.

The differential suite has 73 tests (110 cases), all passing: 32 from phase 1, 15 for
the protocol, 10 for hostile input and 16 for rpcinfo. Mutants that undo reproduced
quirks are caught (four in phase 1, five in phase 2, five in phase 3, nine in phase 4).

Phase 5, packaging:

- [contrib/gentoo/net-nds/rpcbind](contrib/gentoo/net-nds/rpcbind), the
  `rpcbind-1.2.8_p9999` live ebuild (see [Installing on Gentoo](#installing-on-gentoo));
- the rehearsal on the test VM (Gentoo, kernel 6.18, nfs-utils 2.8.5), with
  [tools/vm-nfscheck.sh](tools/vm-nfscheck.sh) and
  [tools/vm-bootcheck.sh](tools/vm-bootcheck.sh). The ebuild built and installed over C
  rpcbind with the same files as C's package, plus the port's README and QUIRKS. Both
  programs need only libc and libgcc_s. A real NFS server and client then ran on it
  through OpenRC: `rpc.statd`, `rpc.mountd`, `nfsd`, the kernel's lockd, `rpc.idmapd`,
  NFSv3 and NFSv4.2 mounts over loopback, file I/O, and contended `flock` and `lockf`
  locks. The script also restarted rpcbind, which takes its dependents with it, and
  stopped everything. In all 61 steps rpcbind-rs reported the same as C, call counts
  in `rpcinfo -m` included. A boot with rpcbind, `nfs` and `nfsclient` in the default
  runlevel matched as well. The guest then went back to C from a binary package, which
  matched the first C runs.

The rehearsal found one problem, in the rollback command rather than the port. With a
binhost configured, `emerge -1K` took the binhost's newer `rpcbind-1.2.8-3`, built with
`selinux`, and its policy packages over the local quickpkg. `--getbinpkg=n` picks the
local package.

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

## Layout

Upstream is about 6,100 lines of C in `src/`, plus the parts of libtirpc it relies on.
The port follows the files:

| Path | What |
|---|---|
| `crates/tirpc/` | the libtirpc subset: XDR, RPC messages and auth (`AUTH_NONE`, `AUTH_SYS`), record marking, the datagram, stream and local transports (with peer credentials), the service dispatcher, the clients, the rpcbind client calls and broadcast, `/etc/netconfig` and `NETPATH`, universal addresses, and `sys.rs` (every libc call) |
| `crates/rpcbind/src/main.rs` | `rpcbind.c`: options, the lock, transports from netconfig, privilege drop, the loop |
| `crates/rpcbind/src/rpcb_svc_com.rs` | `rpcb_svc_com.c`: the registration list, `SET`/`UNSET`, `GETADDR`, `DUMP`, `GETTIME`, address conversions |
| `crates/rpcbind/src/{pmap_svc,rpcb_svc,rpcb_svc_4,rpcb_stat}.rs` | the v2, v3 and v4 dispatchers and `GETSTAT` |
| `crates/rpcbind/src/{security,check_bound,util,xlog}.rs` | access checks and `-l` logging, the transport list, `addrmerge()`, messages |
| `crates/rpcinfo/` | `rpcinfo.c`: every mode, over the `tirpc` clients |
| `tests/` | differential tests and the harness |
| `contrib/gentoo/` | the `net-nds/rpcbind` live ebuild (see [Installing on Gentoo](#installing-on-gentoo)) |
| `tools/` | the reference build, and the NFS and boot checks run on the test VM |

## Testing

```sh
make check
```

This builds the C reference into `../rpcbind` if it isn't there, builds rpcinfo-rs,
then runs the unit tests and the differential suite ([crates/rpcbind/tests/](crates/rpcbind/tests/)). Each
case starts C rpcbind and then the port, each in a private user, mount, network and pid
namespace (ids mapped from your subordinate ranges, so there's a real root and the
system's users exist; its own loopback, `/proc` and `/run`; `/dev/log` captured; the
case's own `/etc/netconfig` if it has one), sends both the same requests with
`rpcprobe` ([crates/rpcbind/rpcprobe/](crates/rpcbind/rpcprobe/): raw datagrams, connections and record fragments), and compares:

- every reply, byte for byte, and which address UDP replies came from;
- stdout, stderr, the exit status and every syslog line (time stamps and pids
  normalized);
- the sockets the daemon has bound (unconnected UDP, listening TCP, the local socket)
  and `/run` (names, modes, owners) before and after the signal that ends it.

To see what each case produced: `RPCBIND_DIFF_SHOW=1 cargo test -- --nocapture`. Each
run's files stay in `target/difftest/<case>/{c,r}/` (and `cr/`, C rpcbind with
rpcinfo-rs, for the rpcinfo cases).

The probe can also run commands in the sandbox: `rpcinfo` (C, or rpcinfo-rs in the
rpcinfo cases) and `tirpcprobe`
([crates/rpcbind/tests/tirpcprobe.c](crates/rpcbind/tests/tirpcprobe.c)), which calls
rpcbind through the system libtirpc as RPC services do, optionally as another user.
Cases can add netkit interfaces, a descriptor limit for the daemon, and a fake clock
(the LD_PRELOAD shim in `crates/rpcbind/tests/shim/`) that the probe can move. In
`sync on` mode the probe makes sure the daemon has handled everything sent before it
reports a missing reply, so cases don't depend on timing. For rpcinfo it can serve
scripted replies over UDP or TCP (`fakesrv`) and answer broadcasts (`responder`) from
background threads. `RPCBIND_FUZZ=SEED:COUNT`
adds a longer run of mutated calls (see `crates/rpcbind/tests/diff_hostile.rs`).

## Roadmap

1. **Startup and the RPC layer (merged, PR #2):** `crates/tirpc` (XDR, messages, auth, record marking,
   the three transports, netconfig, universal addresses, the dispatcher with its error
   replies), and `rpcbind.c`: options, `-v`, the lock, the rlimit and superuser checks,
   one transport per netconfig entry (`-h` addresses, `SO_REUSEADDR`, `IPV6_V6ONLY`,
   the local socket and its mode), the privilege drop, signals, `daemon()` and the
   loop. Tested with `NULL` calls on every program and version, and the rejections
   (wrong program, version, procedure, RPC version, auth) for everything else.
2. **The protocol (merged, PR #3):** portmap v2 (`pmap_svc.c`) and rpcbind v3/v4 (`rpcb_svc*.c`):
   `SET`/`UNSET` with owners taken from local-socket credentials, `GETADDR` and
   `GETVERSADDR` with `addrmerge()` choosing the interface address, `DUMP`,
   `GETADDRLIST`, `GETTIME`, `UADDR2TADDR`/`TADDR2UADDR`, `GETSTAT` counters, and the
   access checks and `-i`/`-l` logging (`security.c`). Tested with C `rpcinfo`, the
   libtirpc probe and several interfaces in the test namespace.
3. **Hostile input (merged, PR #4):** malformed and truncated XDR, oversized and fragmented records,
   idle and half-open connections, many clients at once, and the cases behind past
   CVEs (CVE-2017-8779 "rpcbomb" and CVE-2015-7236), checked for the same replies and
   bounded memory.
4. **rpcinfo (merged, PR #5):** every mode (`-p`, `-s`, `-m`, `-l`, `-T`, `-u`, `-t`, `-a`, `-b`, `-d`,
   `-n`), run against both daemons.
5. **Packaging (merged, PR #6):** a Gentoo ebuild (a `net-nds/rpcbind` drop-in, the same init script and
   conf.d), rehearsed on the test VM with a real NFS client and server stack
   (`rpc.statd`, `rpc.mountd`, `nfsd`, a mount and file locks), and rolled back through a
   binary package of the C build.

Not planned unless needed: the build options hydra doesn't use (warm starts, remote
calls, TCP wrappers, systemd socket activation, `RPCBIND_DEBUG`). The ebuild doesn't
offer them.

### After rpcbind

`crates/tirpc` is meant to carry over to the NFS daemons: an `nfs-utils-rs` covering
`rpc.statd` and `sm-notify` first (network-facing, root, a long bug history), then
`libnfsidmap` (C ABI and plugins) and `rpc.idmapd`. autofs is out of scope for now: it
is much larger and its behavior can only be tested on a VM with real mounts.

## Installing on Gentoo

[contrib/gentoo/net-nds/rpcbind](contrib/gentoo/net-nds/rpcbind) is
`rpcbind-1.2.8_p9999`, a drop-in for `net-nds/rpcbind-1.2.8`. It installs the port's
`/sbin/rpcbind` and `/sbin/rpcinfo`, with the man pages and documents from the
`rpcbind-1.2.8` tarball and Gentoo's init script and conf.d. The README and QUIRKS
are added under the docs, in `rpcbind-rs/`. The ebuild is live: it builds this
repository's `main`, so it has no keywords and is pinned to the 1.2.8 it ports. As
root, with the ebuild in a local repository (here `localrepo`):

```sh
cp -r contrib/gentoo/net-nds /var/db/repos/localrepo/
echo '=net-nds/rpcbind-1.2.8_p9999 **' > /etc/portage/package.accept_keywords/rpcbind
echo '>net-nds/rpcbind-1.2.8_p9999' > /etc/portage/package.mask/rpcbind
quickpkg --include-config=y net-nds/rpcbind   # C's package, to go back to
emerge -1 =net-nds/rpcbind-1.2.8_p9999
rc-service rpcbind restart
```

The running rpcbind keeps the old program until it is restarted. A restart loses every
registration, since there are no warm starts. OpenRC restarts the services that need
rpcbind (`rpc.statd`, `nfs`, `nfsclient`), and they register again. The kernel's
lockd does not re-register while NFS mounts keep it running, which is true with C as well.
To go back, use `emerge -1K --getbinpkg=n =net-nds/rpcbind-1.2.8` (from the binary
package; without `--getbinpkg=n` a binhost's build, with other flags, can win) or
`emerge -1 =net-nds/rpcbind-1.2.8`. The flags `debug`, `remotecalls`, `systemd`,
`tcpd` and `warmstarts` are not offered: the port covers the build hydra uses, with
all of them off.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

The same license as upstream rpcbind and libtirpc: the 3-clause BSD license.
[LICENSE](LICENSE) is upstream's `COPYING`, unchanged; the Sun Microsystems notices in
upstream's source files (also 3-clause BSD) apply to the ported code, and are kept in
[LICENSES/Sun-BSD-3-Clause.txt](LICENSES/Sun-BSD-3-Clause.txt).
