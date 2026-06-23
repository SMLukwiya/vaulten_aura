#ifndef AURA_DENSE_POOL_STATIC_LIB_H
#define AURA_DENSE_POOL_STATIC_LIB_H

#include "internal.h"

/**
 * static dense pool definition
 * The managed structure is part
 * of the dense pool structure. Therefore
 * both slots and free indexes are managed
 * internally by the structure.
 */
#define A_DEFINE_DENSE_POOL(name, size, struct_type)                                                                    \
    struct aura_##name##_dense_pool {                                                                                   \
        struct_type slots[size];                                                                                        \
        uint32_t free_stack[size];                                                                                      \
        uint32_t free_top;                                                                                              \
    };                                                                                                                  \
                                                                                                                        \
    /* Initialize dense pool */                                                                                         \
    static inline void aura_##name##_dense_pool_init(struct aura_##name##_dense_pool *pool) {                           \
        memset(pool, 0, sizeof(*pool));                                                                                 \
                                                                                                                        \
        pool->free_top = (size);                                                                                        \
        for (int i = 0; i < size; ++i)                                                                                  \
            /* Initialize so index 0 is at the top of the free stack */                                                 \
            pool->free_stack[i] = size - 1 - i;                                                                         \
    }                                                                                                                   \
                                                                                                                        \
    /**                                                                                                                 \
     * This call returns the index of the actual slot                                                                   \
     * structure that is managed by the pool, if not invalid,                                                           \
     * the caller can safely use it to get the actual slot                                                              \
     */                                                                                                                 \
    static inline uint32_t aura_##name##_dense_pool_lease(struct aura_##name##_dense_pool *pool) {                      \
        if (pool->free_top == 0)                                                                                        \
            return A_DENSE_POOL_INVALID_IDX;                                                                            \
        return aura_dense_pool_core_lease(pool->free_stack, &pool->free_top);                                           \
    }                                                                                                                   \
                                                                                                                        \
    static inline struct_type *aura_##name##_dense_pool_get_slot(struct aura_##name##_dense_pool *pool, uint32_t idx) { \
        return &pool->slots[idx];                                                                                       \
    }                                                                                                                   \
                                                                                                                        \
    static inline void                                                                                                  \
    aura_##name##_dense_pool_release(struct aura_##name##_dense_pool *pool, uint32_t idx) {                             \
        aura_dense_pool_core_release(pool->free_stack, &pool->free_top, idx);                                           \
    }                                                                                                                   \
                                                                                                                        \
    static inline struct_type *aura_##name##_dense_pool_get_entries(struct aura_##name##_dense_pool *pool) {            \
        return pool->slots;                                                                                             \
    }

/**
 * static dense pool index manager definition
 * The managed structure is not part
 * of the dense pool structure. The pool
 * simply manages indexes for the external structure,
 * what is returned is an index that you can safely
 * use on the the external slots structure.
 * NOTE: the pool size must be the same size
 * as the external structure being managed.
 * Size meaning the number of slots available
 */
#define A_DEFINE_DENSE_POOL_IDX_MAN(name, size)                                                                                \
    struct aura_##name##_dense_pool_idx_man {                                                                                  \
        uint32_t free_stack[size];                                                                                             \
        uint32_t free_top;                                                                                                     \
    };                                                                                                                         \
                                                                                                                               \
    static inline void aura_##name##_dense_pool_idx_man_init(struct aura_##name##_dense_pool_idx_man *pool) {                  \
        memset(pool, 0, sizeof(*pool));                                                                                        \
                                                                                                                               \
        pool->free_top = (size);                                                                                               \
        for (int i = 0; i < size; ++i)                                                                                         \
            /* Initialize so index 0 is at the top of the free stack */                                                        \
            pool->free_stack[i] = size - 1 - i;                                                                                \
    }                                                                                                                          \
                                                                                                                               \
    /**                                                                                                                        \
     * This call returns an index that can be used to                                                                          \
     * index into the external slot. Only valid if                                                                             \
     * the index is not A_DENSE_POOL_INVALID_IDX                                                                               \
     */                                                                                                                        \
    static inline uint32_t aura_##name##_dense_pool_idx_man_lease(struct aura_##name##_dense_pool_idx_man *pool) {             \
        if (pool->free_top == 0)                                                                                               \
            return A_DENSE_POOL_INVALID_IDX;                                                                                   \
        return aura_dense_pool_core_lease(pool->free_stack, &pool->free_top);                                                  \
    }                                                                                                                          \
                                                                                                                               \
    static inline void aura_##name##_dense_pool_idx_man_release(struct aura_##name##_dense_pool_idx_man *pool, uint32_t idx) { \
        aura_dense_pool_core_release(pool->free_stack, &pool->free_top, idx);                                                  \
    }

#endif