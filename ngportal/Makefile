#
# Copyright (c) 2025 David Marker <dave@freedave.net>
#
# SPDX-License-Identifier: BSD-2-Clause
#

LOCALBASE?=/usr/local

BINDIR=	${LOCALBASE}/bin
SHAREDIR=${LOCALBASE}/share

PROG=	ngportal
MAN=	ngportal.8
SRCS=	kld.c ng.c wormhole.c main.c
LIBADD=	jail netgraph
CFLAGS+=-I${.CURDIR}/../common
MK_DEBUG_FILES= no

WARNS?=1

.PATH:  ${.CURDIR}/../common

.include <bsd.prog.mk>
