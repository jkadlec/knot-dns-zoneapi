#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define _public_ __attribute__((visibility("default")))
#define _hidden_ __attribute__((visibility("hidden")))

#define _unused_ __attribute__((unused))

/**
 * Macro to clear a structure of known size.
 *
 * \param pointer Pointer to the structure.
 */
#define clear_struct(pointer) memset((pointer), '\0', sizeof(*(pointer)))

#define _cleanup_(var) __attribute__((cleanup(var)))

static inline void close_ptr(int *ptr)
{
	if (*ptr != -1) {
		close(*ptr);
	}
}
static inline void fclose_ptr(FILE **ptr)
{
	if (*ptr) {
		fclose(*ptr);
	}
}

static inline void free_ptr(void *ptr)
{
	free(*(void **)ptr);
}

#define _cleanup_free_ _cleanup_(free_ptr)
#define _cleanup_fclose_ _cleanup_(fclose_ptr)
#define _cleanup_fclose_ _cleanup_(fclose_ptr)
