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

#include "common.h"


/* Just wrapping up NgMkSockNode and calling `err` upon failure. */
void
ng_create_context(ngctx *ctrl, ngctx *data)
{
	int	rc;
	char    name[NG_NODESIZ];

	assert(ctrl != NULL); /* data can be NULL */

	snprintf(name, sizeof(name), "ngctl%d", getpid());
	name[NG_NODESIZ - 1] = '\0';

	rc = NgMkSockNode(name, ctrl, data);
	if (rc == -1) err(
		ERREXIT, "%s: failed to initialize netgraph(4)", __func__
	);
}


/* NOTE: only called from the cleanup. already in an `err` function */
void
ng_shutdown_node(ngctx ctrl, ng_ID_t nd)
{
	int rc;
	char pth[NG_NODESIZ];

	assert(ctrl >= 0);
	assert(nd > 0);
	
	snprintf(pth, NG_NODESIZ, IDFMT, nd);

	rc = NgSendMsg(ctrl, pth, NGM_GENERIC_COOKIE, NGM_SHUTDOWN, NULL, 0);
	if (rc == -1) (void) fprintf(
		stderr,
		"Failed to shutdown node.\ntry:\n\tngctl shutdown %s\n", pth
	);
}
