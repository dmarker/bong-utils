/*
 * Copyright (c) 2025 David Marker <dave@freedave.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <sysexits.h>
#include <netgraph.h>

#define	STRFY2(x)	#x
#define	STRFY(x)	STRFY2(x)

#define ERREXIT ((errno == EPERM) ? EX_NOPERM : EX_OSERR)
#define ERRALT(alt) ((errno == EPERM) ? EX_NOPERM : alt)

/* remove 1 for '\0' */
#define	NG_NODELEN	(NG_NODESIZ - 1)
#define	NG_HOOKLEN	(NG_HOOKSIZ - 1)

/* strangely kernel only allows one level of `node:hook` in a path but
 * has massive NG_PATHSIZ so lets not use it.
 * Also since there is a ':' and a '\0' we can just add.
 */
#define NG_PATHSIZE	(NG_HOOKSIZ + NG_HOOKSIZ)
#define NG_PATHLEN	(NG_PATHSIZE - 1)

/* netgraph functions: ng.c */
#define IDFMT "[%08x]:"
typedef int ngctx;

void	ng_create_context(ngctx *, ngctx *);
void	ng_shutdown_node(ngctx, ng_ID_t);

/*
 * module loading: kld.c
 */
void	kld_ensure_load(const char *);
