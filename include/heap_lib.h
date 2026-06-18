#ifndef AURA_HEAP_LIB_H
#define AURA_HEAP_LIB_H

#include "memory_lib.h"
#include "slab_lib.h"

#include <stdbool.h>
#include <stdio.h>

#define A_HEAP_IDX_INVALID SIZE_MAX

typedef enum {
    A_HP_TYPE_MAX_HEAP,
    A_HP_TYPE_MIN_HEAP
} aura_heap_t;

/* Heap entry structure */
struct aura_heap_ent {
    uint32_t idx;
};

typedef int (*hp_compare_fn)(struct aura_heap_ent *, struct aura_heap_ent *);

/* Heap structure */
struct aura_heap {
    struct aura_heap_ent **entries;
    struct aura_mem_ctx *mc;
    uint32_t size;
    uint32_t cap;
    hp_compare_fn cmp; /* Compare function */
    aura_heap_t type;  /* Heap type (see aura_heap_t) */
};

static inline bool aura_heap_is_full(struct aura_heap *hp) {
    return hp->size >= hp->cap;
}

static inline bool aura_heap_is_empty(struct aura_heap *hp) {
    return hp->size == 0;
}

#define aura_heap_for_each(heap, cursor) for (int i = 1; (heap) && (i <= (heap)->size) && ((cursor) = (heap)->entries[i], 1); ++i)

int aura_heap_init(struct aura_heap *hp, struct aura_mem_ctx *mc, uint32_t cap,
                   hp_compare_fn cmp, aura_heap_t hp_type);

void aura_heap_destroy(struct aura_heap *hp);

struct aura_heap_ent *aura_heap_peek(struct aura_heap *hp);

void aura_heap_dump(struct aura_heap *hp, bool is_daemon);

int aura_heap_push(struct aura_heap *hp, struct aura_heap_ent *e);

struct aura_heap_ent *aura_heap_pop(struct aura_heap *hp);

void aura_heap_del(struct aura_heap *hp, struct aura_heap_ent *e);

#endif