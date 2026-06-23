#include "dynamic.h"

#ifndef a_min
#define a_min(x, y) ((x) < (y) ? (x) : (y))
#endif

struct aura_dyn_dense_pool *aura_dyn_dense_pool_create(uint64_t cap, uint64_t struct_size) {
    struct aura_dyn_dense_pool *pool;
    uint64_t pool_size;
    uint32_t *free_stack;

    if (cap >= UINT32_MAX || cap == 0)
        return NULL;

    pool_size = A_DYN_DENSE_POOL_SIZE(cap, struct_size);
    pool = calloc(1, pool_size);
    if (!pool)
        return NULL;

    free_stack = A_DYN_DENSE_POOL_FREE_STACK(pool);
    for (int i = 0; i < cap; ++i)
        /* Initialize so index 0 is at the top of the free stack */
        free_stack[pool->free_top++] = cap - 1 - i;

    pool->cap = cap;
    pool->elem_size = struct_size;
    return pool;
}

void aura_dyn_dense_pool_destroy(struct aura_dyn_dense_pool *pool) {
    if (!pool)
        return;
    free(pool);
}

/**
 * Internal function to grow dynamic
 * dense pool.
 */
static int a_dense_pool_grow(struct aura_dyn_dense_pool *pool) {
    struct aura_dyn_dense_pool *p = pool;
    uint32_t cap;
    uint64_t pool_size;
    uint32_t *free_stack;

    if (pool->cap == UINT32_MAX - 1)
        return A_DENSE_POOL_FULL;
    cap = a_min(pool->cap * 2, UINT32_MAX - 1);

    pool_size = A_DYN_DENSE_POOL_SIZE(cap, pool->elem_size);
    pool = realloc(pool, pool_size);
    if (!pool) {
        pool = p;
        return A_DENSE_POOL_MEM_ERR;
    }

    free_stack = A_DYN_DENSE_POOL_FREE_STACK(pool);
    for (uint32_t i = pool->cap; i < cap; ++i) {
        free_stack[pool->free_top++] = cap - 1 - i;
    }

    pool->cap = cap;
    return A_DENSE_POOL_OK;
}

uint32_t aura_dyn_dense_pool_lease(struct aura_dyn_dense_pool *pool) {
    uint32_t idx, *free_stack;

    if (pool->free_top == 0) {
        if (a_dense_pool_grow(pool) < 0)
            return A_DENSE_POOL_INVALID_IDX;
    }

    free_stack = A_DYN_DENSE_POOL_FREE_STACK(pool);
    return aura_dense_pool_core_lease(free_stack, &pool->free_top);
}

void *aura_dyn_dense_pool_get_slot(struct aura_dyn_dense_pool *pool, uint32_t idx) {
    if (idx == A_DENSE_POOL_INVALID_IDX)
        return NULL;

    void *slots = A_DYN_DENSE_POOL_SLOTS(pool, pool->cap);
    return (slots + (pool->elem_size * idx));
}

void aura_dyn_dense_pool_release(struct aura_dyn_dense_pool *pool, uint32_t idx) {
    if (idx == A_DENSE_POOL_INVALID_IDX)
        return;

    uint32_t *free_stack = A_DYN_DENSE_POOL_FREE_STACK(pool);
    return aura_dense_pool_core_release(free_stack, &pool->free_top, idx);
}