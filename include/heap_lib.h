#ifndef AURA_HEAP_LIB_H
#define AURA_HEAP_LIB_H

#include <stdbool.h>
#include <stdio.h>

typedef int (*compare_fn)(const void *, const void *);
typedef void (*destructor_fn)(const void *);

/* Heap structure */
struct aura_heap {
    void **data;
    size_t size;
    size_t cap;
    size_t elem_size;
    compare_fn cmp;
};

static bool aura_heap_is_full(struct aura_heap *hp) {
    return hp->size + 1 >= hp->cap;
}

static bool aura_heap_is_empty(struct aura_heap *hp) {
    return hp->size == 0;
}

#define aura_heap_for_each(heap, cursor) for (int i = 1; (heap) && (i <= (heap)->size) && ((cursor) = (heap)->data[i], 1); ++i)

struct aura_heap *aura_heap_create(size_t capacity, compare_fn cmp);

void aura_heap_destroy(struct aura_heap *heap, destructor_fn destructor);

bool aura_max_heap_push(struct aura_heap *hp, void *element);

bool aura_min_heap_push(struct aura_heap *hp, void *element);

void *aura_heap_peek(struct aura_heap *hp);

void *aura_max_heap_delete(struct aura_heap *hp);

void *aura_min_heap_delete(struct aura_heap *hp);

void aura_heap_dump(struct aura_heap *hp, bool is_daemon);

#endif