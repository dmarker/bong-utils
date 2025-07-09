/*
 * Copyright (c) 2025 David Marker <dave@freedave.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <net/if.h>
#include <sys/param.h>
#include <sysexits.h>
#include <netgraph.h>

#include "common.h"

/* remove 1 for '\0' */
#define	NG_NODELEN	(NG_NODESIZ - 1)
#define	NG_HOOKLEN	(NG_HOOKSIZ - 1)

#define	LLNAMSIZ	18
#define	LLNAMLEN	(LLNAMSIZ - 1)

/* wh.c */
ng_ID_t	 wh_create(ngctx);
ng_ID_t	 wh_open(ngctx, ng_ID_t, const char *);
void	 wh_name(ngctx, ng_ID_t, const char *);
void	 wh_connect(ngctx, ng_ID_t, const char *, const char *);
