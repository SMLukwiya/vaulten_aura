#ifndef AURA_DENSE_POOL_INTERNAL_H
#define AURA_DENSE_POOL_INTERNAL_H

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define A_DENSE_POOL_INVALID_IDX UINT32_MAX
#define A_DENSE_POOL_DEFAULT_SZ 64

static inline uint32_t aura_dense_pool_core_lease(uint32_t *free_stack, uint32_t *free_top) {
    return free_stack[--(*free_top)];
}

static inline void aura_dense_pool_core_release(uint32_t *free_stack, uint32_t *free_top, uint32_t idx) {
    free_stack[(*free_top)++] = idx;
}

#endif