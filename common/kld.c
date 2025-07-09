/*
 * Copyright (c) 2025 David Marker <dave@freedave.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <assert.h>
#include <err.h>
#include <string.h>
#include <sys/linker.h>
#include <sys/module.h>

#include "common.h"

void
kld_ensure_load(const char *search)
{
	int fileid, modid;
	const char *cp;
	struct module_stat mstat;

	assert(search != NULL);

	/* scan files in kernel */
	mstat.version = sizeof(struct module_stat);
	for (fileid = kldnext(0); fileid > 0; fileid = kldnext(fileid)) {
		/* scan modules in file */
		for (modid = kldfirstmod(fileid); modid > 0;
		     modid = modfnext(modid)) {
			if (modstat(modid, &mstat) < 0)
				continue;
			/* strip bus name if present */
			if ((cp = strchr(mstat.name, '/')) != NULL) {
				cp++;
			} else {
				cp = mstat.name;
			}

			/* found, already loaded */
			if (strcmp(search, cp) == 0)
				return;
		}
	}

	/*
	 * In theory you could use ngportal(8) or ngpcap(8) in a jail before
	 * loading a required netgraph(4) module. Only thing we can do is let
	 * you know the kernel modules can't be loaded.
	 */
	if (kldload(search) == -1)
		err(ERREXIT, "%s: unable to load kernel module \"%s\"",
		    __func__, search);
}
