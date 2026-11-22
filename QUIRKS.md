# Upstream quirks, kept on purpose

rpcbind-rs reproduces rpcbind **1.2.8** (with libtirpc 1.3.7), as Gentoo builds it,
exactly, including behavior that looks like a bug. Each item here is marked `QUIRK` in the
source. Fixing one is a deliberate, separate change (ideally upstream as well), not
something to slip into the port.

Severity: **high** means a remote or local client can change or break registrations, or
get wrong answers; **medium** means it's surprising and user-visible; **low** means it's
cosmetic or hard to hit.

## /etc/netconfig (libtirpc)

| Severity | Quirk | Where | Test |
|---|---|---|---|
| medium | A line that doesn't parse (a blank line, an indented comment) ends `getnetconfig()`'s listing, so rpcbind silently sets up no transports after it. `getnetconfigent()` also stops searching there: if `local` comes after it, rpcbind prints libtirpc's "The local transport is called \"unix\"" advice to stderr and exits with "can't find local transport" (to syslog only). | `tirpc::netconfig` (`getnetconfig`, `getnetconfigent`) | unit `blank_line_ends_listing_and_search`; `netconfig_variants` (`netconfig_blank_line_*`, `netconfig_indented_comment`) |
| low | `parse_ncp()` drops the last byte of every line, newline or not: the last line of a file without a final newline loses its last character, as does each 999-byte piece of a longer line. | `tirpc::netconfig` (`parse_ncp`) | unit `last_byte_dropped`; `netconfig_variants` (`netconfig_no_final_newline*`, `netconfig_long_*`) |

## Addresses (libtirpc)

| Severity | Quirk | Where | Test |
|---|---|---|---|
| low | The universal address of an unnamed local socket (length 2) is read past the address, up to a NUL, because `%.*s` gets a precision of -1. | `tirpc::addr` (`taddr2uaddr_af`) | unit `local_paths`; phase 2 |
| low | Port parts of a universal address go through `atoi()` and are combined as `hi << 8 \| lo` before `htons()` truncates them, so out-of-range parts (`999.999`) wrap instead of failing. | `tirpc::addr` (`uaddr2taddr_af`) | unit `port_parts_wrap_like_c` |

## RPC layer (libtirpc)

| Severity | Quirk | Where | Test |
|---|---|---|---|
| medium | On a TCP or local connection, every record fragment is taken as a whole call, `LAST_FRAG` or not: in non-blocking mode `last_frag` starts true and is never cleared. A call sent in several fragments is decoded from its first fragment, and each later fragment's first word is read as a record header. | `tirpc::xdr_rec` (`getrec`) | `stream_framing` |
| low | A short `AUTH_SYS` credential is parsed from the bytes past its end, left over in a stack buffer from earlier calls, before the length check rejects it; the `bad auth_len` line `_svcauth_unix()` prints to stdout shows those leftover numbers. | `tirpc::rpc` (`svcauth_unix`, `CredArea`) | unit `auth_sys`; `authentication` |
| low | For `AUTH_SYS` calls, the reply's verifier is the client's own verifier (flavor and bytes) whenever it isn't empty; other flavors get `AUTH_NONE`. | `tirpc::rpc` (`svcauth_unix`) | unit `auth_sys`; `authentication` |
| medium | A UDP call is decoded from the transport's whole 9000-byte buffer, not just the datagram: a datagram cut short (at least 16 bytes) is completed with whatever earlier calls and replies left there, and can be answered. Bytes from other clients' requests can end up in a reply (an `AUTH_SYS` verifier is echoed). | `tirpc::svc` (`recv`, `DgXprt`) | `udp_short_and_stale` |
| low | Version mismatches report the lowest and highest version of the program on any transport, and portmap v2 is answered over IPv6 too: callouts are matched without their netid. | `tirpc::svc` (`getreq_common`) | `rejections`, `foreground_all_transports` |
| low | When the descriptor table is four-fifths full, the idle-connection cleanup looks transports up by poll-slot index as if it were a descriptor, and reads one slot past the end. | `tirpc::svc` (`destroy_idle`) | phase 3 |
| low | A call that isn't a call, or has an RPC version other than 2, gets no reply (no `RPC_MISMATCH`): over UDP it's dropped, and on a connection the connection is closed. | `tirpc::rpc` (`decode_call`) | `not_calls` |

## Startup (rpcbind.c, util.c)

| Severity | Quirk | Where | Test |
|---|---|---|---|
| medium | `-h` applies to UDP only: TCP always listens on the wildcard address. For UDP, 127.0.0.1 and ::1 are added to the list. | `main.rs` (`init_transport`) | `hosts_*` |
| low | `-h '*'` is replaced by NULL in the shared list, so the next UDP transport passes NULL to `inet_pton()` and rpcbind dies of a segmentation fault. | `main.rs` (`init_transport`, `null_deref_crash`) | `hosts_star` |
| low | When a UDP bind fails (an `-h` address the host doesn't have), the socket is leaked and the umask stays at 0111 for the rest of the run; an `-h` address of the other family also leaks a socket. | `main.rs` (`init_transport`) | `hosts_unbindable` |
| low | Because `RPCBIND_USER` defaults to `root`, rpcbind always "switches" to root, calling `setgroups(0, NULL)`: it fails to start where that's not allowed (a user namespace with `setgroups` denied), after binding its sockets. | `main.rs` (`main`) | none (the harness maps ids with `newuidmap` so it's allowed) |
| low | The local socket is set up first, from `getnetconfigent("local")` (or `"unix"`), and its failure goes to syslog only, as `<argv[0]>: can't find local transport` with a trailing newline. | `main.rs` (`main`) | `netconfig_no_local` |
| low | `network_init()` joins the RPC IPv6 multicast group on a socket it then closes, which leaves the group again: it has no effect. | `util.rs` (`network_init`) | none (not observable) |
| low | The "cannot get local address" message for a stream transport is also `printf()`ed to stdout, without a newline. | `main.rs` (`init_transport`) | none (needs a broken services database) |
