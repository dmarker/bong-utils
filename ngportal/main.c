/*
 * Copyright (c) 2025 David Marker <dave@freedave.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <assert.h>
#include <err.h>
#include <getopt.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/param.h>
#include <sys/jail.h>
#include <sys/wait.h>
#include <jail.h>

#include <netgraph/ng_wormhole.h>

#include "ngportal.h"

/* name of our utility */
#define	ME	"ngportal"

/*
 * The single purpose of this utility is to create and connect an ng_wormhole(4)
 * that exists in the current vnet and a separate jail vnet.
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

	/*
	 * Sadly users don't need to know or care that providing both jail names
	 * means we create a 2 pairs of wormholes then collapse them into a
	 * single pair that remains in both jails. The portal gun is more
	 * mysterious than they will ever know.
	 */
	(void) fprintf(stderr,
	    "USAGE: " ME " [-n] [-j jail] spec1 [spec2]\n"
	    "-n\tDisable automatic loading of netgraph(4) kernel modules.\n"
	    "-j jail\tSwitch to jail for all references.\n\n"
	    "You provide 2 wormhole specifications (components of which are\n"
	    "separated by colons). The wormhole spec componentes are:\n"
	    "\t[jail][:name][:node:hook]\n"
	    "For each spec the components are:\n"
	    "jail\t\tjail reference for remaining components. If not preset it\n"
	    "\t\tdefaults to where `" ME "' is run (see `-j' above).\n"
	    "name\t\tset the netgraph name of the wormhole to [name] in [jail].\n"
	    "node:hook\tconnect the wormhole in [jail] to this [node:hook] pair.\n\n"
	    "Without a jail componet the spec assumes the jail where `" ME "' was\n"
	    "run or the jail from `-j'. But the jails from spec1 and spec2 MUST be\n"
	    "different. Without a name the wormhole can only be accessed by ID.\n"
	    "Without a [node:hook] netgraph path the wormhole is left unconnected\n"
	    "but is held open by the other side. It can be connected to later with\n"
	    "ngctl(8).\n");

	exit(EX_USAGE);
}

/*
 * Module global, for err_cleanup to find everything.
 * Start with invalid values our error cleanup can check for.
 */
static struct {
	ngctx	fd;
	ng_ID_t	wh[2];
} G = {
	.fd = -1,
	.wh = { 0, 0 } /* invalid ng_ID_t */
};

static void
err_cleanup(int _)
{
	assert(G.fd != -1); /* should not set until have this */

	if (G.wh[0] != 0)
		ng_shutdown_node(G.fd, G.wh[0]);
	if (G.wh[1] != 0)
		ng_shutdown_node(G.fd, G.wh[1]);

	close(G.fd);
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

struct wh_spec {
	const char *jail;
	const char *name;
	const char *node;
	const char *hook;
};

/*
 * This will split a string like "jail:name:node:hook" into separate
 * parts: "jail", "name", "node", "hook".
 *
 * We have an extra ':' after jail. And an extra ':' after name. That's so
 * we can replace with '\0' and slice string up with strsep. But
 * the last component found does not need to have a ':' after it.
 *
 * But you can't provide node and not provide hook.
 *
 * So that users don't have to play "fetch a rock" with their input we
 * warn and return -1 after reporting as many issues as we can find.
 *
 */
static int
parse_spec(char *arg, struct wh_spec *whs)
{
	int	rc = 0;
	char **iter, *components[4] = {NULL};

	assert(arg != NULL);
	assert(whs != NULL);

	/* almost straight from man page :) */
	for (iter = components; (*iter = strsep(&arg, ":")) != NULL;)
		if (++iter >= &components[4])
			break;

	if (arg != NULL) warnx(
		"unrecognized components after wormhole spec: `%s'", arg
	), rc++;

	rc += checkcomponent("jail", components[0], MAXHOSTNAMELEN, &whs->jail);
	rc += checkcomponent("name", components[1], NG_NODELEN, &whs->name);
	rc += checkcomponent("node", components[2], NG_NODELEN, &whs->node);
	rc += checkcomponent("hook", components[3], NG_NODELEN, &whs->hook);

	/* node,hook must both be set or both be unset */
	if (components[2] != NULL && components[3] == NULL)
		warnx("node: `%s': set but missing hook", components[2]), rc++;
	if (components[2] == NULL && components[3] != NULL)
		warnx("hook: `%s': set but missing node", components[3]), rc++;

	return (rc == 0) ? 0 : -1;
}

static void
jail_name_connect(
	int jid, ng_ID_t wh, const char *name, const char *node, const char *hook
) {
	int rc;
	pid_t pid;
	assert(jid > 0); /* system is 0 */
	assert(wh > 0);

	if (name == NULL && node == NULL)
		return; /* nothing to do so don't fork etc */

	pid = fork();
	if (pid == -1) err(
		ERREXIT, "%s: fork()", __func__
	);
	if (pid == 0) { /* child */
		(void) close(G.fd);
		G.fd = -1;
		/* child never has to close wormholes */
		G.wh[0] = G.wh[1] = 0;
		if (jail_attach(jid) != 0)
			errx(ERRALT(EX_OSERR), "cannot attach to jail (jid=%d)",
			    jid);
		/* must get new context */
		ng_create_context(&G.fd, NULL);
		wh_name(G.fd, wh, name);
		wh_connect(G.fd, wh, node, hook);
		(void) close(G.fd);
		exit(0);
	} else { /* parent */
		int status;
		do {
			rc = wait(&status);
		} while (rc == -1 && errno == EINTR);
		if (rc == -1) err(
			EX_OSERR, "failed to wait for child in prison"
		);
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) err(
			EX_OSERR, "child failed its mission"
		);
	}
}

int
main(int argc, char **argv)
{
	int  ix, ch, rc = 0;
	bool load_kmod = true, attached = false;

	int		jids[2] = {0};
	struct wh_spec	spec_storage[2]; // don't access, use whs
	struct wh_spec	*whs[] = {&spec_storage[0], &spec_storage[1]};
	struct wh_spec	*ws;
	
	ng_ID_t farside; /* for side(s) we open */

	setvbuf(stdout, NULL, _IONBF, BUFSIZ);

	while ((ch = getopt_long(argc, argv, ":nj:", NULL, NULL)) != -1) {
		switch (ch) {
		case 'j': {
			int jid;

			if (strlen(optarg) > MAXHOSTNAMELEN)
				Usage(ME ": `%s' exceeds %d characters\n\n",
				    optarg, MAXHOSTNAMELEN);

			jid = jail_getid(optarg);
			if (jid == -1)
				errx(ERRALT(EX_NOHOST), "%s", jail_errmsg);

			if (jail_attach(jid) != 0)
				errx(ERRALT(EX_OSERR), "cannot attach to jail");

			attached = true;
			break;
		}
		case 'n':
			load_kmod = 0; /* user asked not to */
			break;
		default:
			Usage(ME ": unrecognized option `%s'\n\n",
			    argv[optind - 1]);
		}
	}
	argv += optind;
	argc -= optind;

	switch (argc) {
	case 0:
		Usage(ME ": must minimally provide `jail' of one spec\n\n");
	case 2:	/* must come before case 1 */
		rc += parse_spec(argv[1], whs[1]);
		/* fallthrough */
	case 1:
		rc += parse_spec(argv[0], whs[0]);
		break;
	default:
		Usage(ME ": too many arguments provided\n\n");
	}
	if (rc != 0)
		Usage("\n\n");

	if (whs[0]->jail == NULL && whs[1]->jail == NULL)
		Usage(ME ": duplicate (default) jail reference detected\n\n");

	/*
	 * Ensure whs[0] always has a non-NULL jail. Do this swap before
	 * setting up `jids` so array indices in `whs` always match.
	 */
	if (whs[0]->jail == NULL) {
		void *tmp = whs[0];
		whs[0] = whs[1];
		whs[1] = tmp;
	}

	/* comparing jail names won't work, one could be given numerically */
	for (ix = 0; ix < nitems(whs); ix++) {
		if (whs[ix]->jail == NULL)
			continue;

		jids[ix] = jail_getid(whs[ix]->jail);
		if (jids[ix] == -1) errx(
			ERRALT(EX_NOHOST), "%s", jail_errmsg
		);
	}

	/*
	 * the kernel code specifically prevents this too, but this is a bettter
	 * message than just "invalid argument".
	 */
	if (jids[0] == jids[1])
		Usage( ME ": duplicate jail reference detected\n\n");

	/*
	 * Unless told not to (or we definitely are in a jail) try to make sure
	 * we have modules loaded.
	 */
	if (load_kmod && !attached) {
		kld_ensure_load("ng_socket");
		kld_ensure_load("ng_wormhole");
	}

	ng_create_context(&G.fd, NULL);	/* open netgraph socket */
	err_set_exit(err_cleanup);	/* and now set up error cleanup */

	/* this one is always created and opened etc. */
	G.wh[0] = wh_create(G.fd);
	ws = whs[0];
	farside = wh_open(G.fd, G.wh[0], ws->jail);
	jail_name_connect(
		jids[0], farside, ws->name, ws->node, ws->hook
	);

	ws = whs[1];
	if (jids[1] != 0) {
		/*
		 * In this case we have to make another wormhole.
		 * Then we have to collapse it with G.wh[0]
		 */
		char pth[NG_NODESIZ];

		G.wh[1] = wh_create(G.fd);
		farside = wh_open(G.fd, G.wh[1], ws->jail);
		jail_name_connect(
			jids[1], farside, ws->name, ws->node, ws->hook
		);

		/* not IDFMT, it can't have ':' on end */
		snprintf(pth, sizeof(pth), "[%08x]", G.wh[1]);
		wh_connect(G.fd, G.wh[0], pth, NG_WORMHOLE_HOOK);
	} else {
		/* just deal with connecting in current vnet */
		wh_name(G.fd, G.wh[0], ws->name);
		wh_connect(G.fd, G.wh[0], ws->node, ws->hook);
	}

	return (0);
}
