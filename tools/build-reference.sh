#!/bin/bash
# build-reference.sh - build upstream C rpcbind and rpcinfo at the pinned release, for the differential tests
#
# 20261121 - Created by Claude (claude.ai, Anthropic) - scottfk
#
# Usage: tools/build-reference.sh [DIR]
#
# DIR defaults to ../rpcbind (next to this checkout), which is where the
# tests will look (override with RPCBIND_REFERENCE=/path/to/rpcbind).
# The sources are the rpcbind-1.2.8 release tarball, the same one Gentoo's
# net-nds/rpcbind-1.2.8 builds (upstream's git is git:// only and its
# release tags don't match the tarball's generated files). The build uses
# the ebuild's configure flags for hydra's
# USE="-debug -remotecalls -selinux -systemd -tcpd -warmstarts".

set -euo pipefail

here=$(cd "$(dirname "$0")/.." && pwd)
dir=${1:-$here/../rpcbind}
rel=$(cat "$here/tools/REFERENCE_TAG")
distdir=${DISTDIR:-/var/cache/distfiles}
tarball=$distdir/$rel.tar.bz2
url=https://downloads.sourceforge.net/rpcbind/$rel.tar.bz2

if [[ ! -f $dir/configure.ac ]]; then
	if [[ ! -f $tarball ]]; then
		tarball=$(mktemp -d)/$rel.tar.bz2
		curl -fsSL -o "$tarball" "$url"
	fi
	mkdir -p "$dir"
	tar -xjf "$tarball" -C "$dir" --strip-components=1
fi
cd "$dir"
if [[ ! -f Makefile ]]; then
	# Gentoo bug 705224: don't use the rpcsvc headers.
	ac_cv_header_rpcsvc_mount_h=no \
	CFLAGS="${CFLAGS:--O3 -pipe -march=native}" \
	LDFLAGS="${LDFLAGS:--Wl,-O1 -Wl,--as-needed -Wl,-z,pack-relative-relocs}" \
	./configure -q --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
		--bindir=/sbin --sbindir=/sbin --with-statedir=/run/rpcbind \
		--with-systemdsystemunitdir=no \
		--disable-debug --disable-rmtcalls --disable-warmstarts --disable-libwrap
fi
make -s
echo "reference: $dir ($(ls rpcbind rpcinfo | tr '\n' ' '))"
