#
# Copyright (c) 2025 David Marker <dave@freedave.net>
#
# SPDX-License-Identifier: BSD-2-Clause
#

LOCALBASE?=/usr/local

BINDIR=	${LOCALBASE}/bin
SHAREDIR=${LOCALBASE}/share

PROG=	ngpcap
MAN=
#MAN=	ngpcap.8
SRCS=	kld.c ng.c pcap.c ring32.c main.c
LIBADD=	jail netgraph
CFLAGS+=-I${.CURDIR}/../common
CFLAGS+=-I${LOCALBASE}/include
MK_DEBUG_FILES= no

CFLAGS.main.c += -DINET -DINET6
CFLAGS.pcap.c += -DINET -DINET6

WARNS?=1

.PATH:  ${.CURDIR}/../common

.include <bsd.prog.mk>
