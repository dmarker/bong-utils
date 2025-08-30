/*
 * Copyright (c) 2025 David Marker <dave@freedave.net>
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#ifndef __FREEDAVE_NET_RING_H__
#define __FREEDAVE_NET_RING_H__

#include <assert.h>
#include <stdbool.h>
#include <stddef.h>
#include <sys/types.h>


struct ring32 {
	const uint32_t		capacity;
	const uint32_t		mask;
	struct {
		uint32_t	start;
		uint32_t	end;
	}			index;	/* group indices */
	struct {
		uint8_t	* const	data;
		uint8_t	* const	copy;	/* mapped right after data */
	}			maps;
};

/*
 * This checks validity by making sure `rb` isn't null and has a capacity > 0,
 * a mask > 0 and using them verifies it is a power of 2.
 *
 * This doesn't check that capacity is a multiple of page size though.
 */
#ifdef NDEBUG
#	define SANITY_CHECK(rb)
#else
#	define SANITY_CHECK(rb) {			\
		assert(rb != NULL);			\
		assert(rb->capacity != 0);		\
		assert(rb->mask != 0);			\
		assert((rb->capacity & rb->mask) == 0);	\
	}
#endif

/*
 * ring32_count is the consumed space available to write from. Most other
 * functions are counting on this one to check `ring32` to be
 * valid.
 */
static __inline uint32_t
ring32_count(struct ring32 *rb)
{
	SANITY_CHECK(rb);

	uint32_t count = (rb->index.end - rb->index.start);
	assert(count <= rb->capacity);

	return (count);
}

/* ring[16|32]_free is the available space to read into */
static __inline uint32_t
ring32_free(struct ring32 *rb)
{
	uint32_t count = ring32_count(rb);
	return (rb->capacity - count);
}

static __inline bool
ring32_full(struct ring32 *rb)
{
	uint32_t count = ring32_count(rb);
	return (rb->capacity == count);
}

static __inline bool
ring32_empty(struct ring32 *rb)
{
	SANITY_CHECK(rb);
	return (rb->index.start == rb->index.end);
}

static __inline void *
ring32_read_buffer(struct ring32 *rb, size_t *nbytes)
{
	void *result;
	uint32_t avail = ring32_free(rb);

	result = (avail > 0) ? &rb->maps.data[rb->index.end & rb->mask] : NULL;
	if (nbytes != NULL)
		*nbytes = avail;

	return (result);
}

static __inline void *
ring32_write_buffer(struct ring32 *rb, size_t *nbytes)
{
	void *result;
	uint32_t count = ring32_count(rb);

	result = (count > 0) ? &rb->maps.data[rb->index.start & rb->mask] : NULL;
	if (nbytes != NULL)
		*nbytes = count;

	return (result);
}

static __inline ssize_t
ring32_read_advance(struct ring32 *rb, ssize_t nread)
{
	SANITY_CHECK(rb);

	/* on a failed read we don't advance */
	if (nread == -1)
		return (nread);

	assert(nread <= rb->capacity);
	rb->index.end += nread;

	return (nread);
}

static __inline ssize_t
ring32_write_advance(struct ring32 *rb, ssize_t nwrit)
{
	SANITY_CHECK(rb);

	/* on a failed write we don't advance */
	if (nwrit == -1)
		return (nwrit);

	assert(nwrit <= rb->capacity);
	rb->index.start += nwrit;

	return (nwrit);
}


/*
 * The only 2 functions that aren't inline.
 *
 * For ring[16|32]_init you have to pass a `struct ring[16|32]` that will be
 * filled out and have memory mapped in for you. Much like MAP_ALIGNED for mmap,
 * the second argument to ring32_init is a binary logarithm of the number of
 * pages you want mapped. For a 4k page and R_SZ=32, valid values are [0,19].
 * For 4k page and R_SZ=16, valid values are [0,3].
 *
 * These will return -1 on failure and set `errno`, they don't assert.
 */
int	ring32_init(struct ring32 *, uint8_t);
int	ring32_fini(struct ring32 *);


#ifdef TEST
/*
 * These two functions are intentionally using different pointers to show that
 * they are mapped to the same memory. Homage to Beagle Bros.
 */

static __inline uint8_t
ring32_peek(struct ring32 *rb, uint32_t idx)
{
	assert((idx & rb->mask) == idx);
	return rb->maps.data[idx & rb->mask];
}

/* whole point is to show that our copy effects the main data */
static __inline void
ring32_poke(struct ring32 *rb, uint32_t idx, uint8_t val)
{
	assert((idx & rb->mask) == idx);
	rb->maps.copy[idx & rb->mask] = val;
}
#endif /* TEST */
#endif /* __FREEDAVE_NET_RING_H__ */
