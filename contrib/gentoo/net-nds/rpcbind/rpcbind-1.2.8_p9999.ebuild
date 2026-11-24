# Copyright 1999-2026 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2
# 20261123 - Created by Claude (claude.ai, Anthropic) - scottfk

# net-nds/rpcbind 1.2.8 with rpcbind and rpcinfo replaced by rpcbind-rs's
# (a strict-compatibility Rust port that doesn't link libtirpc, built live
# from git).  The man pages and documents are the rpcbind-1.2.8 tarball's,
# and the init script and conf.d are net-nds/rpcbind-1.2.8's, so this
# installs the same files as the C package built with
# USE="-debug -remotecalls -systemd -tcpd -warmstarts".
# rpcbind-rs ports 1.2.8 only; pin it with a package.mask of
# >net-nds/rpcbind-1.2.8_p9999.  To go back to C:
# emerge -1 =net-nds/rpcbind-1.2.8, or from a binary package made with
# quickpkg: emerge -1K --getbinpkg=n =net-nds/rpcbind-1.2.8 (without
# --getbinpkg=n, a binhost's newer build with other flags can win).

EAPI=8

MY_P="rpcbind-1.2.8"
# rpcbind-rs's Cargo.lock: update together.
CRATES="libc@0.2.191"
RUST_MIN_VER="1.88.0"

inherit cargo git-r3

DESCRIPTION="portmap replacement which supports RPC over various protocols (rpcbind-rs programs)"
HOMEPAGE="https://github.com/scottfk/rpcbind-rs https://sourceforge.net/projects/rpcbind/"

EGIT_REPO_URI="https://github.com/scottfk/rpcbind-rs.git"
SRC_URI="
	https://downloads.sourceforge.net/rpcbind/${MY_P}.tar.bz2
	${CARGO_CRATE_URIS}
"
S="${WORKDIR}/${MY_P}"
# The rpcbind-rs checkout.
RS="${WORKDIR}/rpcbind-rs"
EGIT_CHECKOUT_DIR="${RS}"

# GPL-2 for init script (bug #426104)
LICENSE="BSD GPL-2"
# Dependent crate licenses
LICENSE+=" || ( Apache-2.0 MIT )"
SLOT="0"
# rpcbind-rs ports the build without warm starts, remote-call forwarding,
# TCP wrappers, socket activation or debug output, so those flags are gone.
IUSE="selinux"
# The differential tests need the C build and user namespaces.
RESTRICT="test"

RDEPEND="
	selinux? ( sec-policy/selinux-rpcbind )
"

src_unpack() {
	cargo_src_unpack
	git-r3_src_unpack
}

src_configure() {
	pushd "${RS}" >/dev/null || die
	cargo_src_configure
	popd >/dev/null || die
}

src_compile() {
	pushd "${RS}" >/dev/null || die
	# Not the workspace: rpcprobe is a test tool.
	cargo_src_compile --bin rpcbind --bin rpcinfo
	popd >/dev/null || die
}

src_test() {
	:
}

src_install() {
	into /
	dosbin "${RS}/$(cargo_target_dir)"/{rpcbind,rpcinfo}
	doman man/rpcbind.8 man/rpcinfo.8
	einstalldocs
	docinto rpcbind-rs
	dodoc "${RS}"/{README,QUIRKS}.md

	newinitd "${FILESDIR}"/${PN}.initd ${PN}
	newconfd "${FILESDIR}"/${PN}.confd ${PN}
}

pkg_postinst() {
	elog "rpcbind and rpcinfo are now rpcbind-rs's.  Its known differences from C"
	elog "are in ${EROOT}/usr/share/doc/${PF}/rpcbind-rs/QUIRKS.md*."
	elog "A running rpcbind keeps the old program until it is restarted.  A restart"
	elog "drops every registration; \"rc-service rpcbind restart\" restarts the NFS"
	elog "services too, and they register again."
	elog "To go back, emerge the C release: emerge -1 =net-nds/rpcbind-1.2.8"
	elog "(or emerge -1K --getbinpkg=n =net-nds/rpcbind-1.2.8 from a quickpkg)."
}
