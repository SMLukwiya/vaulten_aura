#ifndef AURA_DENSE_POOL_DYNAMIC_H
#define AURA_DENSE_POOL_DYNAMIC_H

#include "internal.h"
#include <stdlib.h>

typedef enum {
    A_DENSE_POOL_OK,
    A_DENSE_POOL_MEM_ERR = -1,  /* Out of memory error */
    A_DENSE_POOL_FULL = -2,     /* Pool is full and can not grow */
    A_DENSE_POOL_INV_ARGS = -3, /* Invalid arguments passed */
    A_DENSE_POOL_INV_OP = -4,   /* Invalid operation attempted */
} aura_dense_pool_err_t;

/* Dense pool structure */
struct aura_dyn_dense_pool {
    uint32_t cap;
    uint32_t free_top;
    uint32_t elem_size;
    /**
     * variable tail structure has
     * the struct slots and free stack
     */
    uint8_t tail[];
};

#define A_DYN_DENSE_POOL_SIZE(cap, struct_size) \
    sizeof(struct aura_dyn_dense_pool) + (cap * sizeof(uint32_t)) + (cap * struct_size)

#define A_DYN_DENSE_POOL_FREE_STACK(p) ((uint32_t *)(p)->tail)
#define A_DYN_DENSE_POOL_SLOTS(p, cap) (A_DYN_DENSE_POOL_FREE_STACK(p) + cap)

/**
 * Create a new pool strucure,
 * cap is the capacity to use
 */
struct aura_dyn_dense_pool *aura_dyn_dense_pool_create(uint64_t cap, uint64_t struct_size);

/**
 * Destroy dyn pool
 */
void aura_dyn_dense_pool_destroy(struct aura_dyn_dense_pool *pool);

/**
 * Returns the next free slot index
 */
uint32_t aura_dyn_dense_pool_lease(struct aura_dyn_dense_pool *pool);

/**
 * Returns the slot pointed to by idx
 * if idx is invalid, returns NULL
 */
void *aura_dyn_dense_pool_get_slot(struct aura_dyn_dense_pool *pool, uint32_t idx);

/**
 * Release the slot and index
 * pointed to by idx.
 * If idx is invalid, nothing happens
 */
void aura_dyn_dense_pool_release(struct aura_dyn_dense_pool *pool, uint32_t idx);

#endif