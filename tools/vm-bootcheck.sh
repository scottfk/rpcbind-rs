#!/bin/bash
# vm-bootcheck.sh - record rpcbind and NFS state after a boot with them in the default runlevel
# 20261123 - Created by Claude (claude.ai, Anthropic) - scottfk
# Usage (as root in the guest): vm-bootcheck.sh OUTDIR
out=${1:?usage: vm-bootcheck.sh OUTDIR}
rm -rf "$out"; mkdir -p "$out"
# Boot finished and nfsd's grace period over.
while ! rc-status -r 2>/dev/null | grep -qx default || pgrep -x openrc >/dev/null; do sleep 2; done
up=$(cut -d. -f1 /proc/uptime); [ "$up" -lt 110 ] && sleep $((110 - up))
i=0
run() {
	local name=$1; shift; i=$((i + 1))
	local f; f=$(printf '%s/%02d-%s' "$out" $i "$name")
	timeout 60 "$@" >"$f" 2>&1; echo "exit $?" >>"$f"
}
run binary sh -c 'for b in /sbin/rpcbind /sbin/rpcinfo; do grep -qa /rustc/ $b && echo "$b rust" || echo "$b C"; done'
run status sh -c 'rc-status -a | grep -E "rpc|nfs" | sed -E "s/ +/ /g" | sort'
run s rpcinfo -s
run p rpcinfo -p
run m rpcinfo -m
run showmount showmount -e 127.0.0.1
run mount sh -c 'mount -t nfs -o vers=3 127.0.0.1:/srv/nfs /mnt/v3 && echo boot > /mnt/v3/boot && cat /mnt/v3/boot'
run lock sh -c 'flock /mnt/v3/lk-boot sleep 4 & sleep 1; flock -n /mnt/v3/lk-boot true; echo contended=$?; flock -w 20 /mnt/v3/lk-boot true; echo waited=$?; wait'
run umount umount /mnt/v3
run ps sh -c 'ps -eo user,args | grep -E "^[a-z]+ +(/sbin/rpcbind|/usr/sbin/rpc\.)" | sort'
for f in "$out"/[0-9]*; do
	sed -E -e 's/(^ *[0-9]{6} +[0-9]+ +(tcp|udp) +)([0-9]+)/\1PORT/' -e 's/[[:space:]]+/ /g' "$f" >"$f.norm"
done
echo done
