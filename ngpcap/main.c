/*
 * Copyright (c) 2025 David Marker <dave@freedave.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <assert.h>
#include <err.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/event.h>
#include <sys/param.h>
#include <sys/jail.h>
#include <sys/sysctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <jail.h>

#include "ring32.h"

#include <netgraph/ng_pcap.h>

#include "ngpcap.h"

/* name of our utility */
#define	ME	"ngpcap"


/*
 * The single purpose of this utility is to create ng_pcap(4) and connect it
 * to desired sources then make that data available on stdout in pcap(3) format.
 */

static void
Usage(const char *format, ...)
{
	if (format != NULL) {
		va_list ap;
		va_start(ap, format);
		(void) vfprintf(stderr, format, ap);
		va_end(ap);
	}

	(void) fprintf(
	    stderr,
	    "USAGE: " ME " [-n] [-j jail] [-s snaplen] <spec> [spec ...]\n"
	    "-n\t\tDisable automatic loading of netgraph(4) kernel modules.\n"
	    "-j jail\t\tSwitch to jail for all references.\n"
	    "-s snaplen\tSnarf snaplen bytes of data from each packet rather "
	    "than\n\t\tthe default of " STRFY(NG_PACP_MAX_SNAPLEN) " bytes.\n\n"
	    "You provide up to " STRFY(NG_PCAP_MAX_LINKS) " pcap specifications "
	    "to snoop. Specifications have 3\ncomponents separated by colon:\n"
	    "\tlayer\tone of the strings `ether', `inet4', or `inet6'.\n"
	    "\tnode\ta valid netgraph(4) node name or ID (not path).\n"
	    "\thook\ta valid netgraph(4) hook name for the node.\n"
	);

	exit(EX_USAGE);
}
/*
 * Module global, for err_cleanup to find everything.
 * Start with invalid values our error cleanup can check for.
 */
static struct {
	struct ring32	buffer;
	ngctx		ctrl;
	ngctx		data;
	ng_ID_t		pcap;
	int		kq;
} G = {
	.ctrl = -1,
	.data = -1,
	.pcap = 0,
	.kq = -1,
};

/*
 * ng_pcap(4) automatically shuts itself down when it loses the socket connected
 * to `snoop` making cleanup kind of un-necessary.
 * TODO: verify that and if true remove this code...
 *
 * G.buffer always gets ring32_fini called on it. So don't set up err function
 * until after successfully initializing G.buffer
 */
static void
err_cleanup(int _)
{
	ring32_fini(&G.buffer);

	if (G.kq != -1)
		(void)close(G.kq);

	if (G.ctrl == -1)
		return; /* can't shutdown without this */

	if (G.pcap != 0)
		ng_shutdown_node(G.ctrl, G.pcap);

	close(G.ctrl);
	close(G.data);
}

static __inline int
checkcomponent(const char *name, const char *parsed, size_t max, const char **set)
{
	int rc = 0;
	
	if (parsed != NULL) {
		if (strlen(parsed) > (max)) {
			warnx("`%s': name too long: `%s'", name, parsed), rc++;
		} else
			*set = parsed[0] == '\0' ? NULL: parsed;
	}

	return (rc);
}

struct pcap_spec {
	enum pkt_type	pkt;
	const char	*node;
	const char	*hook;
};
/*
 * This will split a string like "inet:node:hook" into separate parts
 * for a struct pcap_spec.
 *
 * So that users don't have to play "fetch a rock" with their input we
 * warn and return -1 after reporting as many issues as we can find.
 *
 */
static int
parse_spec(char *arg, struct pcap_spec *ps)
{
	int	rc = 0;
	char **iter, *components[3] = {NULL};
	const char *layer;

	assert(arg != NULL);
	assert(ps != NULL);

	for (iter = components; (*iter = strsep(&arg, ":")) != NULL;)
		if (++iter >= &components[nitems(components)])
			break;

	if (arg != NULL) warnx(
		"unrecognized components pcap specification: `%s'", arg
	), rc++;

	rc += checkcomponent(
		"layer", components[0], NG_PCAP_PKT_TYPE_LENGTH, &layer
	);
	rc += checkcomponent("node", components[1], NG_NODELEN, &ps->node);
	rc += checkcomponent("hook", components[2], NG_HOOKLEN, &ps->hook);

	/*
	 * At this point `arg` has had '\0' inserted along it so for
	 * errors we need to recreate it. Lets skip any unrecognized
	 * jibberish, we already warned about it.
	 */
#	define ARGFMT	"%s:%s:%s"
#	define ARGS	components[0], components[1], components[2]
	if (layer == NULL) {
		warnx("spec `" ARGFMT "': layer is missing", ARGS);
		rc++;
	} else {
		if (strcmp(layer, HOOK_PKT_ETHER) == 0) {
			ps->pkt = PKT_ETHER;
#		ifdef INET
		} else if (strcmp(layer, HOOK_PKT_INET) == 0) {
			ps->pkt = PKT_INET4;
#		endif
#		ifdef INET6
		} else if (strcmp(layer, HOOK_PKT_INET6) == 0) {
			ps->pkt = PKT_INET6;
#		endif
		} else warnx(
			"layer `%s' is not one of `%s', `%s', or `%s'",
			layer, HOOK_PKT_ETHER, HOOK_PKT_INET, HOOK_PKT_INET6
		), rc++;
	}

	if (ps->node == NULL) warnx(
		"spec `" ARGFMT "': node is missing", ARGS
	), rc++;

	if (ps->hook == NULL) warnx(
		"spec `" ARGFMT "': hook is missing", ARGS
	), rc++;
#	undef ARGS
#	undef ARGFMT

	return (rc == 0) ? 0 : -1;
}

/*
 * Anyway we need to be able to store `size` if at all possible. This can't be
 * compile time checked. ring32_init will fail if its not [0,19] for 4k pages.
 */
static uint8_t
calc_lgpages(size_t size)
{

	size_t npage, pagesz = (size_t) getpagesize();

	/*
	 * if you overflow this division will be zero and the return value
	 * will be 0, which results in just 1 page (the minimum possible).
	 */
	npage = (size + pagesz - 1) / pagesz; /* round up */

	/* round up to a power of 2 */
	npage--;
	npage |= npage >> 1;
	npage |= npage >> 2;
	npage |= npage >> 4;
	npage |= npage >> 8;
	npage |= npage >> 16;
	npage++;

	return (uint8_t)(ffsl(npage) - 1);
}

/*
 * pretty much snaked from D24620
 * I don't know if I need this...
 */
static void
prepare_socket(int fd)
{
	int rc, sbsz;
	size_t msbsz;
	unsigned long maxsbsz;

	/* [min,max] for us should be [4096,8388608] so it can be too big! */

	msbsz = sizeof(maxsbsz);
	rc = sysctlbyname("kern.ipc.maxsockbuf", &maxsbsz, &msbsz, NULL, 0);
	if (rc == -1) err(
		ERRALT(EX_OSERR), "can't get 'kern.ipc.maxsockbuf' value"
	);

	/*
	 * We can't set the socket buffer size to kern.ipc.maxsockbuf value, as
	 * it takes into account the mbuf(9) overhead.
	 */
	maxsbsz = maxsbsz * MCLBYTES / (MSIZE + MCLBYTES);
	sbsz = (int) maxsbsz;

	/* Why am I not just setting it to max if I set at all? */

	rc = setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sbsz, sizeof(sbsz));
	if (rc == -1) err(
		ERRALT(EX_OSERR), "can't set RX buffer size"
	);
}

static void
set_nonblocking(int fd)
{
	int flags;

	flags = fcntl(fd, F_GETFL);
	if (flags == -1) err(
		ERRALT(EX_OSERR), "fcntl: can't retrieve flags"
	);

	if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) err(
		ERRALT(EX_OSERR), "fcntl: can't set flags"
	);
}


static void
read_event(int fd, struct ring32 *ring)
{
	size_t count;
	ssize_t rc;

	do {
		rc = ring32_read_advance(
			ring,
			read(fd, ring32_read_buffer(&G.buffer, &count), count)
		);
	} while(rc == -1 && errno == EAGAIN);

	/* TODO: error check? ran out of data? other side closed? */
}

static void
write_event(int fd, struct ring32 *ring)
{
	size_t count;
	ssize_t rc;

	do {
		rc = ring32_write_advance(
			ring,
			write(fd, ring32_write_buffer(&G.buffer, &count), count)
		);
	} while(rc == -1 && errno == EAGAIN);

	/* TODO: must be a pipe condition when tcpdump dies from CTRL-C */
}

int
main(int argc, char **argv)
{
	int ch, ix, rc = 0, jid = 0, load_kmod = 1;
	int32_t snaplen = NG_PACP_MAX_SNAPLEN; /* same default as tcpdump */
	const char *jail = NULL;
	struct kevent evt[2];
	struct pcap_spec intercepts[NG_PCAP_MAX_LINKS];

	setvbuf(stdout, NULL, _IONBF, BUFSIZ);

	/* use getopt_long so they can place options anywhere */
	while ((ch = getopt_long(argc, argv, ":nj:s:", NULL, NULL)) != -1) {
		switch (ch) {
		case 'j':
			jail = optarg;
			if (strlen(jail) > MAXHOSTNAMELEN) Usage(
				ME ": `%s' exceeds %d characters\n\n",
				jail, MAXHOSTNAMELEN
			);
			break;
		case 'n':
			load_kmod = 0; /* user asked not to */
			break;
		case 's':
		    {
			char *ep;
			int32_t maybe;

			maybe = strtoul(optarg, &ep, 10);
			if (*ep) Usage(
				ME ": snaplen must be integer: \"%s\"\n\n",
				optarg
			); else {
				if (maybe > NG_PACP_MAX_SNAPLEN) Usage(
					ME ": snaplen > %d\n\n",
					NG_PACP_MAX_SNAPLEN
				);
				if (maybe < NG_PACP_MIN_SNAPLEN) Usage(
					ME ": snaplen < %d\n\n",
					NG_PACP_MIN_SNAPLEN
				);
				snaplen = maybe;
			}
			break;
		    }
		default:
			Usage(
				ME ": unrecognized option `%s'\n\n",
				argv[optind - 1]
			);
		}
	}
	argv += optind;
	argc -= optind;

	if ( argc < 1) Usage(
		ME ": must minimally provide one pcap specification\n\n"
	);
	if (argc > NG_PCAP_PKT_TYPE_LENGTH) Usage(
		ME ": can have at most " STRFY(NG_PCAP_PKT_TYPE_LENGTH)
		" pcap specifications\n\n"
	);

	for (ix = 0; ix < argc; ix++) {
		rc += parse_spec(argv[ix], &intercepts[ix]);
	}
	if (rc != 0) Usage("\n\n"); /* already used warn(3) parsing */

	/*
	 * Unless told not to, make sure we have modules loaded. This fails if
	 * run in a jail and modules are not already loaded, c’est la vie.
	 */
	if (load_kmod != 0) {
		kld_ensure_load("ng_socket");
		kld_ensure_load("ng_pcap");
	}

	/*
	 * if we have a jail to switch to it must be before we create ng_pcap
	 */
	if (jail != NULL) {
		int jid = jail_getid(jail);

		if (jid == -1) errx(
			ERRALT(EX_NOHOST), "%s", jail_errmsg
		);
		if (jail_attach(jid) != 0) errx(
			ERRALT(EX_OSERR), "cannot attach to jail"
		);
	}

	if (ring32_init(&G.buffer, calc_lgpages(snaplen * 3)) == -1) err(
		ERRALT(EX_OSERR), "unable to initialize buffer"
	); else
		err_set_exit(err_cleanup);

	ng_create_context(&G.ctrl, &G.data);

	for (ix = 0; ix < argc; ix++) {
		G.pcap = ngp_connect_src(
			G.ctrl, G.pcap, (uint8_t)ix,
			intercepts[ix].node,
			intercepts[ix].hook
		);
		ngp_set_type(G.ctrl, G.pcap, (uint8_t)ix, intercepts[ix].pkt);
	}
	ngp_set_snaplen(G.ctrl, G.pcap, snaplen); /* must be before snoop */
	ngp_connect_snp(G.ctrl, G.pcap, ".", "pcap");

	set_nonblocking(G.data);
	set_nonblocking(STDOUT_FILENO);

	G.kq = kqueue();
	if (G.kq == -1) err(
		ERRALT(EX_OSERR), "kqueue: unable to create"
	);

	EV_SET(&evt[0], G.data, EVFILT_READ, EV_ADD, 0, 0, read_event);
	EV_SET(&evt[1], STDOUT_FILENO, EVFILT_WRITE, EV_ADD, 0, 0, write_event);

	/* register events, leave disabled */
	do {
		rc = kevent(G.kq, evt, nitems(evt), NULL, 0, NULL);
	} while(rc == -1 && errno == EINTR);
	if (rc == -1) err(
		ERRALT(EX_OSERR), ": kevent failed to register events"
	);

	evt[0].flags &= ~(EV_ADD); /* won't be adding any more */
	evt[1].flags &= ~(EV_ADD);

	do {
		struct kevent ready[2];
		struct kevent *chg = evt;
		int nchg = nitems(evt);

		/*
		 * Order matters as EVREAD is evt[0]. If we can't read we
		 * advance chgs to point to evt[1]. Only read if there is at
		 * least `snaplen' bytes free.
		 */
		if (ring32_free(&G.buffer) >= snaplen) {
			evt[0].flags |= (EV_ENABLE | EV_DISPATCH);
		} else {
			chg++; /* not altering read */
			nchg--;
		}
		if (!ring32_empty(&G.buffer)) {
			evt[1].flags |= (EV_ENABLE | EV_DISPATCH);
		} else {
			nchg--;
		}
		assert(ix != 0); /* can't be full & empty */

		do {
			rc = kevent(G.kq, chg, nchg, ready, 2, NULL);
		} while (rc == -1 && errno == EINTR);
		if (rc == -1) err(
			ERRALT(EX_OSERR), ": kevent loop failed"
		);

		for (ix=0; ix < rc; ix++) {
			void (*process)(int, struct ring32 *) = ready[ix].udata;
			process(ready[ix].ident, &G.buffer);
		}
	} while (1);

	return (0);
}
