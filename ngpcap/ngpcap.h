/*
 * Copyright (c) 2025 David Marker <dave@freedave.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <netgraph.h>
#include <stdbool.h>

#include "common.h"


enum pkt_type {
	PKT_ETHER = 0, /* must start with 0 */
#	ifdef INET
	PKT_INET4,
#	endif
#	ifdef INET6
	PKT_INET6
#	endif
};

void	ngp_set_snaplen(ngctx, ng_ID_t, int32_t);
ng_ID_t	ngp_connect_src(ngctx, ng_ID_t, uint8_t, const char *, const char *);
ng_ID_t	ngp_connect_snp(ngctx, ng_ID_t, const char *, const char *);
void	ngp_set_type(ngctx, ng_ID_t, uint8_t, enum pkt_type);
