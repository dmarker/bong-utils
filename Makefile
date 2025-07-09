#
# Copyright (c) 2025 David Marker <dave@freedave.net>
#
# SPDX-License-Identifier: BSD-2-Clause
#

SUBDIR=	\
	jeiface \
	ngpcap \
	ngportal \
	rc.d

.include <bsd.arch.inc.mk>

SUBDIR_PARALLEL=

.include <bsd.subdir.mk>
