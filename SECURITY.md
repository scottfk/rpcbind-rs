# Security

rpcbind-rs is a reimplementation of rpcbind. It runs as root, listens on TCP and UDP port
111 on every interface (unless `-h` limits it), and parses requests from anyone who can
reach it. NFS, NIS and other RPC services trust what it says about where they live.
Security bugs here matter, even though this is a hobby project.

## Status and supported versions

rpcbind-rs is pre-release (0.x). There are no maintained release branches: only the latest
`main` gets fixes.

## What counts as a security issue

These are the kinds of bugs I most want to hear about:

- **Untrusted input.** Crashes, panics, hangs, unbounded memory or descriptor use, or
  amplification from requests a remote or local client can send: malformed XDR, huge
  lengths, fragmented or never-finished records, connection floods.
- **Registration tampering.** Ways to set, change or remove another service's mapping that
  C rpcbind refuses: non-loopback `SET`/`UNSET` without `-i`, spoofed owners, or a local
  user unregistering a root service.
- **Wrong answers.** `GETADDR`, `GETPORT` or `DUMP` replies that point clients somewhere
  C rpcbind wouldn't.
- **Privilege boundaries.** The lock file, the local socket or its mode, the user switch
  (`-s`), or descriptors leaking into the children `-l` forks.
- **Memory safety.** Unsoundness in the `unsafe` code, or anything reachable from safe code
  that causes undefined behavior.
- **Divergence from upstream that weakens security.** For example, an access check that C
  rpcbind does and rpcbind-rs skips.

Upstream behavior that is reproduced on purpose will be listed in QUIRKS.md. Reports about
it are still welcome, especially if the impact is worse than described. It will be fixed as
deliberate changes.

If the same bug is also present in **upstream C rpcbind or libtirpc**, please report it to
the [linux-nfs list](https://linux-nfs.org) maintainers as well. Upstream's fix is what
rpcbind-rs will follow.

## How to report

For anything that could be exploited, **please don't put the details in a public issue.**
Email them to me instead:

    scone-void-baggage (at) duck (dot) com

(Replace `(at)` with `@` and `(dot)` with `.`, and remove the spaces.)

If you don't get a reply, open an issue on <https://github.com/scottfk/rpcbind-rs/issues>
that only says you've sent a security report, without any details.

For low-risk problems, such as hardening suggestions or issues that need root already (a
malicious `/etc/netconfig`, for instance), a normal public issue is fine.

Useful things to include:

- The commit you tested.
- The options rpcbind-rs ran with, the registrations at the time, and the requests (a
  packet capture or a script is ideal).
- What happened, and what C rpcbind does at the pinned release (`tools/REFERENCE_TAG`).

## What to expect

This is a spare-time project, so I can't promise a response time, but I'll acknowledge
security reports as soon as I can, fix confirmed bugs on `main`, and credit you in the
commit unless you'd rather I didn't.
