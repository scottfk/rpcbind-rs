# Upstream quirks, kept on purpose

rpcbind-rs reproduces rpcbind **1.2.8** (with libtirpc 1.3.7), as Gentoo builds it,
exactly, including behavior that looks like a bug. Each item here is marked `QUIRK` in the
source. Fixing one is a deliberate, separate change (ideally upstream as well), not
something to slip into the port.

Severity: **high** means a remote or local client can change or break registrations, or
get wrong answers; **medium** means it's surprising and user-visible; **low** means it's
cosmetic or hard to hit.

None listed yet.
