/*
 * Copyright (c) 2025 David Marker <dave@freedave.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <assert.h>
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netgraph/ng_wormhole.h>

#include "ngportal.h"

/*
 * NOTE: this is remains connected to control socket otherwise it would shutdown
 *	 since it doesn't persist. It is disconnected as part of ng_wormhole_open.
 */
ng_ID_t
wh_create(ngctx ctrl)
{
#	define	OURHK	"tmp"
	int rc;
	struct ng_mesg *resp;
	struct ngm_mkpeer msg = {
		.type = NG_WORMHOLE_NODE_TYPE,
		.ourhook = OURHK,
		.peerhook = NG_WORMHOLE_HOOK,
	};
	const char	*pth = ".:" OURHK;
	ng_ID_t nd;
#	undef OURHK

	assert(ctrl >= 0);

	rc = NgSendMsg(
		ctrl, ".", NGM_GENERIC_COOKIE, NGM_MKPEER, &msg, sizeof(msg)
	);
	if (rc == -1) err(
		ERREXIT, "unable to create %s", msg.type
	);

	rc = NgSendMsg(ctrl, pth, NGM_GENERIC_COOKIE, NGM_NODEINFO, NULL, 0);
	if (rc == -1) errx(
		ERREXIT, "unable to request %s info, presumed dead", msg.type
	);

	rc = NgAllocRecvMsg(ctrl, &resp, NULL);
	if (rc == -1) err(
		ERREXIT, "unable to retrieve %s info, presumed dead", msg.type
	);

	/*
	 * This warns about structure alignment but is also done in ngctl(8).
	 */
	nd = ((struct nodeinfo *) resp->data)->id;
	free(resp);

	/* valid netgraph IDs start at 1 */
	if (nd == 0) err(
		ERREXIT, "invalid node id for wormhole, presumed dead"
	);

	return (nd);
}

void
wh_name(ngctx ctrl, ng_ID_t wh, const char *name)
{
	int rc;
	struct ngm_name msg;
	char pth[NG_NODESIZ + 1]; /* extra for ':' */

	assert(ctrl >= 0);
	assert(wh > 0);

	if (name == NULL)
		return; /* no name given */

	assert(strlen(name) < NG_NODELEN);

	snprintf(msg.name, sizeof(msg.name), "%s", name);
	snprintf(pth, sizeof(pth), IDFMT, wh);

	rc = NgSendMsg(ctrl, pth, NGM_GENERIC_COOKIE, NGM_NAME, &msg, sizeof(msg));
	if (rc == -1) err(
		ERREXIT, "failed to name `%s'", pth
	);
}

void
wh_connect(ngctx ctrl, ng_ID_t wh, const char *peer, const char *peerhook)
{
	int rc;
	struct ngm_connect msg = { .ourhook = NG_WORMHOLE_HOOK };
	char pth[NG_NODESIZ];

	assert(ctrl >= 0);
	assert(wh > 0);

	if (peer == NULL)
		return; /* nothing to connect */

	assert(peerhook != NULL);
	assert(strlen(peer) < sizeof(msg.path) - 2); /* for ':' and '\0' */
	assert(strlen(peerhook) < sizeof(msg.peerhook) - 1); /* for '\0' */

	snprintf(pth, sizeof(pth), IDFMT, wh);

	snprintf(msg.path, sizeof(msg.path), "%s:", peer);
	strncpy(msg.peerhook, peerhook, sizeof(msg.peerhook));

	rc = NgSendMsg(ctrl, pth, NGM_GENERIC_COOKIE, NGM_CONNECT, &msg,
	    sizeof(msg));
	if (rc == -1) {
		/* something standard going on, like maybe node doesn't exist */
		if (strcmp(peerhook, NG_WORMHOLE_HOOK) != 0)
			goto generic_err;

		/*
		 * You can connect wormholes together, `ngportal` does so when
		 * 2 jails specified. But there are 2 cases it will fail.
		 *
		 * EINVAL means other side not open. EDOOFUS means that if the
		 * connection were allowed (which it isn't by kernel) it would
		 * result in a connected pair of wormholes in the same vnet.
		 * Obviously pointles.
		 */
		if (errno == EINVAL) err(
			EX_DATAERR,
			"unable to connect to `%s%s', not opened",
			msg.path, msg.peerhook /* we opened before connect */
		);
		if (errno == EDOOFUS) err(
			EX_DATAERR,
			"forbidden: collapse would result in connected "
			"wormholes in the same vnet"
		);

generic_err:
		err(EX_DATAERR, "unable to connect `%s%s' to `%s%s'", pth,
		    msg.ourhook, msg.path, msg.peerhook);

	}
}

ng_ID_t
wh_open(ngctx ctrl, ng_ID_t wh, const char *jail)
{
	int rc;
	ng_ID_t nd;
	char pth[NG_NODESIZ];
	struct hooklist *hlist;
	struct nodeinfo *ninfo;
	struct ng_mesg *resp;
	struct ngm_rmhook msg = { .ourhook = NG_WORMHOLE_HOOK };

	assert(ctrl >= 0);
	assert(wh > 0);
	assert(jail != NULL);
	assert(strlen(jail) < MAXHOSTNAMELEN);

	snprintf(pth, sizeof(pth), IDFMT, wh);

	rc = NgSendMsg(ctrl, pth, NGM_WORMHOLE_COOKIE, NGM_WORMHOLE_OPEN, jail,
	   strlen(jail) + 1);
	if (rc == -1)
		errx(ERREXIT, "unable to open wormhole in `%s'", jail);

	/*
	 * Now the struct calls them `eh` and `warp`. But to inform users what
	 * is going on we helpfully name the warp hooks after the jail ID they
	 * are in. It can't be the jail name as that can far exceed the length
	 * of hooks.
	 *
	 * The point is we have a jail name (not id, or it could be we don't
	 * know since both are valid).
	 *
	 */
	rc = NgSendMsg(ctrl, pth, NGM_GENERIC_COOKIE, NGM_LISTHOOKS, NULL, 0);
	if (rc == -1)
		errx(ERREXIT,
		    "unable to request wormhole node list, presumed dead");

	rc = NgAllocRecvMsg(ctrl, &resp, NULL);
	if (rc == -1)
		errx(ERREXIT, "unable to get response for wormhole node list, "
		    "presumed dead");

	hlist = (struct hooklist *) resp->data;
	ninfo = &hlist->nodeinfo;
	assert(ninfo->hooks == 2); /* socket and our other wormhole */
	if (strcmp(hlist->link[0].nodeinfo.type, NG_WORMHOLE_NODE_TYPE) == 0) {
		nd = hlist->link[0].nodeinfo.id;
	} else {
		assert(strcmp(hlist->link[1].nodeinfo.type,
		    NG_WORMHOLE_NODE_TYPE) == 0);
		nd = hlist->link[1].nodeinfo.id;
	}
	free(resp);

	rc = NgSendMsg(ctrl, pth, NGM_GENERIC_COOKIE, NGM_RMHOOK, &msg,
	    sizeof(msg));
	if (rc == -1)
		errx(ERREXIT, "unable to rmhook `%s' from `%s'",
		    msg.ourhook, pth);

	return (nd);
}
