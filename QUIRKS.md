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
| medium | A line that doesn't parse (a blank line, an indented comment) ends `getnetconfig()`'s listing, so rpcbind silently sets up no transports after it. `getnetconfigent()` also stops searching there: if `local` comes after it, rpcbind prints libtirpc's "The local transport is called \"unix\"" advice to stderr and exits with "can't find local transport" (to syslog only). | `tirpc::netconfig` (`getnetconfig`, `getnetconfigent`) | unit `blank_line_ends_listing_and_search`; differential in phase 1 |
| low | `parse_ncp()` drops the last byte of every line, newline or not: the last line of a file without a final newline loses its last character, as does each 999-byte piece of a longer line. | `tirpc::netconfig` (`parse_ncp`) | unit `last_byte_dropped` |

## Addresses (libtirpc)

| Severity | Quirk | Where | Test |
|---|---|---|---|
| low | The universal address of an unnamed local socket (length 2) is read past the address, up to a NUL, because `%.*s` gets a precision of -1. | `tirpc::addr` (`taddr2uaddr_af`) | unit `local_paths`; differential in phase 2 |
| low | Port parts of a universal address go through `atoi()` and are combined as `hi << 8 \| lo` before `htons()` truncates them, so out-of-range parts (`999.999`) wrap instead of failing. | `tirpc::addr` (`uaddr2taddr_af`) | unit `port_parts_wrap_like_c` |
