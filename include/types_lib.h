#ifndef AURA_TYPES_H
#define AURA_TYPES_H

#include "memory_lib.h"
#include "slab_lib.h"
#include <stdio.h>
#include <stdlib.h>

/**
 * It looks like struct iovec
 * but base is a char *
 */
struct aura_iovec {
    char *base;
    size_t len;
};

static inline struct aura_iovec *aura_iovec_init(struct aura_memory_ctx *mc, size_t len) {
    struct aura_iovec *iov = aura_alloc(mc, sizeof(*iov));
    if (iov == NULL)
        return NULL;

    iov->base = aura_alloc(mc, len);
    if (iov->base == NULL)
        return NULL;

    iov->len = len;
    return iov;
}

static inline void aura_iovec_destroy(struct aura_iovec *iov) {
    if (!iov)
        return;

    if (iov->base)
        aura_free(iov->base);
    iov->base = NULL;
    iov->len = 0;

    aura_free(iov);
}

#endif