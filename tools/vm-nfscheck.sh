#!/bin/bash
# vm-nfscheck.sh - exercise rpcbind with a real NFS server and client in the test VM
# 20261123 - Created by Claude (claude.ai, Anthropic) - scottfk
# 20261123 - Wait out nfsd's grace period before locking and viewing - Claude - scottfk
#
# Usage (as root in the guest): vm-nfscheck.sh OUTDIR
# Starts rpcbind, the NFS server (statd, mountd, nfsd, lockd) and client
# through OpenRC, exports /srv/nfs to 127.0.0.1, mounts it with NFSv3 and
# NFSv4.2, takes and contends locks over both, restarts rpcbind (OpenRC
# restarts what needs it), and stops everything, recording what rpcbind
# reports at each step.  Most ports are random per run, so every port
# is written as PORT in the *.norm files (diff them with whitespace squeezed).

out=${1:?usage: vm-nfscheck.sh OUTDIR}
rm -rf "$out"; mkdir -p "$out"
exec 3>"$out/log"
step=0

note() { echo "== $*" >&3; }
# run NAME CMD...: record CMD's output, status in OUTDIR/NN-NAME
run() {
	local name=$1; shift
	step=$((step + 1))
	local f; f=$(printf '%s/%02d-%s' "$out" "$step" "$name")
	timeout 60 "$@" >"$f" 2>&1
	echo "exit $?" >>"$f"
	echo "$(basename "$f"): $*" >&3
}
views() {
	local tag=$1
	run "$tag-p" rpcinfo -p
	run "$tag-s" rpcinfo -s
	run "$tag-m" rpcinfo -m
	run "$tag-dump" rpcinfo
	run "$tag-pings" sh -c 'for p in 100000 100003 100005 100021 100024 100227; do
		for t in tcp udp; do rpcinfo -T $t 127.0.0.1 $p 2>&1; done; done;
		rpcinfo -u localhost status; rpcinfo -t localhost mountd 3; rpcinfo -l localhost 100021 4; rpcinfo -a 127.0.0.1.0.111 -T udp 100000 2'
	run "$tag-showmount" sh -c 'showmount -e 127.0.0.1; showmount -a 127.0.0.1'
	run "$tag-sock" sh -c 'ss -Hlnp | grep -w rpcbind | awk "{print \$1, \$2, \$5}" | sort; ls -l /run/rpcbind.sock /run/rpcbind.lock 2>&1 | cut -c1-10,35-'
}
locks() {
	local tag=$1 m=$2
	run "$tag-io" sh -c "echo hello-$tag > $m/f-$tag && sync && cat $m/f-$tag && ls $m | sort"
	# A lock held in the background must make a second non-blocking try fail,
	# and be granted to a waiting one once released (NLM over v3, in-protocol on v4).
	run "$tag-lock" sh -c "
		flock $m/lk-$tag sleep 4 & sleep 1
		flock -n $m/lk-$tag true; echo contended=\$?
		flock -w 20 $m/lk-$tag true; echo waited=\$?
		wait
		python3 -c 'import fcntl,os; f=os.open(\"$m/lk-$tag\", os.O_RDWR); fcntl.lockf(f, fcntl.LOCK_EX|fcntl.LOCK_NB); print(\"lockf ok\")'"
}

mkdir -p /srv/nfs /mnt/v3 /mnt/v4
chmod 1777 /srv/nfs
rm -f /srv/nfs/*
echo '/srv/nfs 127.0.0.1(rw,sync,no_subtree_check,no_root_squash,fsid=0)' >/etc/exports
rc-service nfsclient stop >/dev/null 2>&1; rc-service nfs stop >/dev/null 2>&1
rc-service rpc.statd stop >/dev/null 2>&1; rc-service rpcbind stop >/dev/null 2>&1
rm -rf /var/lib/nfs/sm/* /var/lib/nfs/sm.bak/*

note binary
run binary sh -c 'ls -l /sbin/rpcbind /sbin/rpcinfo | cut -c1-10,24-; for b in /sbin/rpcbind /sbin/rpcinfo; do grep -qa /rustc/ $b && echo "$b rust" || echo "$b C"; done'

note start
run start-rpcbind rc-service rpcbind start
views a-rpcbind-only
run start-nfs rc-service nfs start
run start-nfsclient rc-service nfsclient start
# nfsd refuses NLM locks for its 90-second grace period (clients retry), and
# registers asynchronously: wait it out.
sleep 95
run status sh -c 'rc-status -a | grep -E "rpc|nfs" | sed "s/ *\[.*\]//" | sort'
views b-serving

note mounts
run mount-v3 mount -t nfs -o vers=3 127.0.0.1:/srv/nfs /mnt/v3
run mount-v4 mount -t nfs -o vers=4.2 127.0.0.1:/ /mnt/v4
run mounts sh -c 'grep -E " /mnt/v[34] " /proc/mounts | sed -E "s/,(addr|clientaddr|mountaddr|mountport|port)=[^,]*//g"'
locks v3 /mnt/v3
locks v4 /mnt/v4
run sm sh -c 'ls /var/lib/nfs/sm /var/lib/nfs/sm.bak'
views c-mounted

note restart
run restart-rpcbind rc-service rpcbind restart
sleep 95
run status2 sh -c 'rc-status -a | grep -E "rpc|nfs" | sed "s/ *\[.*\]//" | sort'
views d-restarted
locks v3r /mnt/v3
locks v4r /mnt/v4

note stop
run umount sh -c 'umount /mnt/v3 /mnt/v4; grep -c " /mnt/v" /proc/mounts'
run stop-nfsclient rc-service nfsclient stop
run stop-nfs rc-service nfs stop
views e-after-nfs-stop
run stop-statd rc-service rpc.statd stop
run stop-rpcbind rc-service rpcbind stop
run after-stop sh -c 'pgrep -l rpcbind; ls /run/rpcbind.sock /run/rpcbind.lock 2>&1; rpcinfo -p'
run syslog sh -c 'grep -ah -E "rpcbind|rpcinfo" /var/log/messages 2>/dev/null | tail -20 | sed -E "s/^.{16}//"; dmesg | grep -iE "rpcbind|lockd|nfsd|rpc" | sed -E "s/^\[[ 0-9.]+\] //" | sort -u'

# Normalized copies: random ports become PORT, so C and Rust runs compare.
for f in "$out"/[0-9]*; do
	sed -E -e 's/(^ *[0-9]{6} +[0-9]+ +(tcp|udp) +)([0-9]+)/\1PORT/' \
		-e 's/\.([0-9]+)\.([0-9]+)( |$)/.P.P\3/g' \
		-e 's/\b(port|mountport)=[0-9]+/\1=PORT/g' \
		-e 's/127\.0\.0\.1:([0-9]+)/127.0.0.1:PORT/g' \
		-e 's/\[::\]:([0-9]+)/[::]:PORT/g' -e 's/\*:([0-9]+)/*:PORT/g' \
		-e 's/0\.0\.0\.0:([0-9]+)/0.0.0.0:PORT/g' \
		-e 's/users:\(\("rpcbind",pid=[0-9]+/users:(("rpcbind",pid=N/g' \
		"$f" >"$f.norm"
done
echo done >&3
