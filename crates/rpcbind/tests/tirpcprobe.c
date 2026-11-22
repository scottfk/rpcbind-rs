/*
 * tirpcprobe.c - call rpcbind through the system libtirpc, as RPC services do
 *
 * 20261122 - Created by Claude (claude.ai, Anthropic) - scottfk
 *
 * Usage: tirpcprobe [-u UID] COMMAND ARGS...
 *   set PROG VERS NETID UADDR    rpcb_set()
 *   unset PROG VERS [NETID]      rpcb_unset() (no NETID: all)
 *   pmapset PROG VERS PROT PORT  pmap_set()
 *   pmapunset PROG VERS          pmap_unset()
 *   getaddr PROG VERS NETID HOST rpcb_getaddr()
 *   getport HOST PROG VERS PROT  pmap_getport()
 *   gettime HOST                 rpcb_gettime()
 * Prints one line with the result. -u switches to UID (and gid UID) first.
 */

#include <rpc/rpc.h>
#include <rpc/pmap_clnt.h>
#include <netconfig.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <grp.h>

static unsigned long num(const char *s)
{
	return strtoul(s, NULL, 0);
}

int main(int argc, char **argv)
{
	int i = 1;

	if (argc > 2 && strcmp(argv[1], "-u") == 0) {
		uid_t u = (uid_t)num(argv[2]);
		if (setgroups(0, NULL) || setgid(u) || setuid(u)) {
			perror("setuid");
			return 2;
		}
		i = 3;
	}
	if (i >= argc)
		return 2;
	const char *cmd = argv[i++];
	char **a = argv + i;
	int n = argc - i;

	if (strcmp(cmd, "set") == 0 && n == 4) {
		struct netconfig *nc = getnetconfigent(a[2]);
		struct netbuf *nb = nc ? uaddr2taddr(nc, a[3]) : NULL;
		if (!nb) {
			printf("set: bad netid or address\n");
			return 1;
		}
		printf("set=%d\n", rpcb_set(num(a[0]), num(a[1]), nc, nb));
	} else if (strcmp(cmd, "unset") == 0 && (n == 2 || n == 3)) {
		struct netconfig *nc = n == 3 ? getnetconfigent(a[2]) : NULL;
		printf("unset=%d\n", rpcb_unset(num(a[0]), num(a[1]), nc));
	} else if (strcmp(cmd, "pmapset") == 0 && n == 4) {
		printf("pmapset=%d\n", pmap_set(num(a[0]), num(a[1]), (int)num(a[2]), (unsigned short)num(a[3])));
	} else if (strcmp(cmd, "pmapunset") == 0 && n == 2) {
		printf("pmapunset=%d\n", pmap_unset(num(a[0]), num(a[1])));
	} else if (strcmp(cmd, "getaddr") == 0 && n == 4) {
		struct netconfig *nc = getnetconfigent(a[2]);
		struct netbuf nb;
		char buf[128];
		nb.buf = buf;
		nb.maxlen = sizeof buf;
		nb.len = 0;
		if (!nc) {
			printf("getaddr: bad netid\n");
			return 1;
		}
		if (rpcb_getaddr(num(a[0]), num(a[1]), nc, &nb, a[3])) {
			char *u = taddr2uaddr(nc, &nb);
			printf("getaddr=%s\n", u ? u : "(null)");
		} else {
			printf("getaddr failed: %s\n", clnt_spcreateerror(""));
		}
	} else if (strcmp(cmd, "getport") == 0 && n == 4) {
		struct sockaddr_in sin;
		memset(&sin, 0, sizeof sin);
		sin.sin_family = AF_INET;
		inet_pton(AF_INET, a[0], &sin.sin_addr);
		printf("getport=%u\n", pmap_getport(&sin, num(a[1]), num(a[2]), (unsigned)num(a[3])));
	} else if (strcmp(cmd, "gettime") == 0 && n == 1) {
		time_t t = 0;
		printf("gettime=%s\n", rpcb_gettime(a[0], &t) ? "ok" : "failed");
	} else {
		fprintf(stderr, "tirpcprobe: bad command\n");
		return 2;
	}
	return 0;
}
