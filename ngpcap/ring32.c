/*
 * Copyright (c) 2025 David Marker <dave@freedave.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>

#include "ring32.h"

/*
 * For a `struct ring32` we can't accurately represent a capacity of the max
 * size. Because its 2^32 - 1. That breaks our rules that we must be both a
 * power of 2 as well as a multiple of page size (itself a power of 2).
 *
 * That means `lgpages` can only be in range [0,19] for 4k pages. And using 19
 * gives you 2gb for a buffer size which is already excessive for a ring buffer.
 *
 * The formula for your buffer size 2^(lgpagesz + lgpages). Usually you have
 * 4k pages which is 2^12. So your size will typically be 2^(12 + lgpages).
 * The more important value to know is the page size.
 */
int
ring32_init(struct ring32 *rb, uint8_t lgpages)
{
	int shm;
	uint32_t pagesz = (uint32_t) getpagesize();
	int lgpagesz = ffsl(pagesz) - 1; /* for MAP_ALIGNED */

	uint32_t capacity;
	uint8_t	*data, *copy;


	if (rb == NULL) {
		errno = EINVAL;
		return (-1);
	}

	/*
	 * Make sure we can actually handle the size.
	 * This may seem overly complicated but it works for all possible R_SZ
	 * without having to change anything.
	 */
	if ((lgpagesz + lgpages) > (8 * sizeof(rb->capacity) - 1)) {
		errno = EDOM;
		return (-1);
	}

	/* the test above guaranteed this would fit */
	capacity = 1 << (lgpages + lgpagesz);

	shm = shm_open(SHM_ANON, O_RDWR | O_EXCL | O_CREAT, 0600);
	if (shm == -1)
		return (-1);	/* shm_open set errno */

	/* we only need ring->capacity as we map that same region twice */
	if (ftruncate(shm, (off_t)capacity) == -1) {
		/* shouldn't happen per man page but in case that changes */
		return (-1);
	}

	data = mmap(
		0, capacity,
		PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_ALIGNED(lgpagesz),
		shm, (off_t)0
	);
	if (data == MAP_FAILED) {
		int save_err = errno; /* mmap set */
		(void) close(shm);
		errno = save_err;
		return (-1);
	}

	/*
	 * NOTE: it doesn't appear, even though we use shm_open(2), that we are
	 *       required to go touch all the pages to force allocations. But if
	 *       we did, this is where we would. (By writing a '0' to one byte
	 *       of each page of `data`).
	 */

	/* force the next address but map same data */
	copy = mmap(
		data + capacity, capacity,
		PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_FIXED,
		shm, (off_t)0
	);
	if (copy == MAP_FAILED) {
		int save_err = errno;
		(void) munmap(data, capacity);
		(void) close(shm);
		errno = save_err;
		return (-1);
	}
	close(shm); /* no longer needed */

	/*
	 * kind of annoying way to initialize rb by memcpy, all part of the
	 * `const compromise` for structure members.
	 */
	struct ring32 initializer = {
		.capacity = capacity,
		.mask = capacity - 1,
		.index = { .start = 0, .end = 0 },
		.maps = { .data = data, .copy = copy },
	};
	memcpy(rb, &initializer, sizeof(*rb));

	return (0);
}


int
ring32_fini(struct ring32 *rb)
{

	if (rb == NULL) {
		errno = EINVAL;
		return (-1);
	}
	if (rb->capacity == 0) {
		errno = ENXIO;
		return (-1);
	}
	(void) munmap(rb->maps.copy, rb->capacity);
	(void) munmap(rb->maps.data, rb->capacity);
	bzero(rb, sizeof(*rb));

	return (0);
}
