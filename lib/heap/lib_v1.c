#include "error_lib.h"
#include "lib.h"

#include <assert.h>
#include <stdlib.h>

#ifndef a_max
#define a_max(x, y) ((x) > (y) ? (x) : (y))
#endif

#define left(x) (((x) << 1) + 1)
#define right(x) (((x) << 1) + 2)
#define parent(x) (((x) - 1) >> 1)

int aura_heap_init(struct aura_heap *hp, struct aura_mem_ctx *mc, uint32_t cap,
                   hp_compare_fn cmp, aura_heap_t hp_type) {
    if (cap >= UINT32_MAX)
        return -1;

    hp->entries = aura_alloc(mc, cap * sizeof(struct aura_heap_ent));
    if (!hp->entries)
        return -1;

    hp->mc = mc;
    hp->size = 0;
    hp->cap = cap;
    hp->cmp = cmp;
    hp->type = hp_type;
    return 0;
}

void aura_heap_destroy(struct aura_heap *hp) {
    if (!hp)
        return;

    if (hp->entries)
        aura_free(hp->entries);
    hp->entries = NULL;
    hp->cap = hp->size = 0;
}

static inline void a_swap(struct aura_heap_ent **a, struct aura_heap_ent **b) {
    struct aura_heap_ent *tmp = *a;

    *a = *b;
    (*a)->idx = (*b)->idx;
    *b = tmp;
    (*b)->idx = tmp->idx;
}

static inline int a_hp_grow(struct aura_heap *hp) {
    hp->cap = a_max(4, hp->cap * 2);
    if (hp->cap >= UINT32_MAX)
        return -1;

    hp->entries = aura_realloc(hp->mc, hp->entries, hp->cap * sizeof(struct aura_heap_ent));
    if (!hp->entries)
        return -1;

    return 0;
}

static inline void a_hp_bubble_up(struct aura_heap *hp, size_t idx) {
    size_t p;

    if (hp->type == A_HP_TYPE_MIN_HEAP) {
        while (idx > 0) {
            p = parent(idx);
            if (hp->cmp(hp->entries[p], hp->entries[idx]) < 0)
                break;

            a_swap(&hp->entries[p], &hp->entries[idx]);
            idx = p;
        }
    } else {
        while (idx > 0) {
            p = parent(idx);
            if (hp->cmp(hp->entries[p], hp->entries[idx]) > 0)
                break;

            a_swap(&hp->entries[p], &hp->entries[idx]);
            idx = p;
        }
    }
}

static inline void a_hp_bubble_down(struct aura_heap *hp, size_t idx) {
    int i, l, r;

    if (hp->type == A_HP_TYPE_MIN_HEAP) {
        while (idx < hp->size) {
            l = left(idx);
            if (l >= hp->size)
                break;

            r = right(idx);
            if (r < hp->size && hp->cmp(hp->entries[r], hp->entries[l]) < 0)
                i = r;
            else
                i = l;

            if (hp->cmp(hp->entries[i], hp->entries[idx]) > 0)
                break;

            a_swap(&hp->entries[i], &hp->entries[idx]);
            idx = i;
        }
    } else {
        while (idx < hp->size) {
            l = left(idx);
            if (l >= hp->size)
                break;

            r = right(idx);
            if (r < hp->size && hp->cmp(hp->entries[r], hp->entries[l]) > 0)
                i = r;
            else
                i = l;

            if (hp->cmp(hp->entries[idx], hp->entries[i]) > 0)
                break;

            a_swap(&hp->entries[idx], &hp->entries[i]);
            idx = i;
        }
    }
}

int aura_heap_push(struct aura_heap *hp, struct aura_heap_ent *e) {
    size_t pos;

    if (aura_heap_is_full(hp))
        if (a_hp_grow(hp) < 0)
            return -1;

    pos = hp->size;
    hp->entries[pos] = e;
    e->idx = pos;
    hp->size++;
    a_hp_bubble_up(hp, pos);

    return 0;
}

struct aura_heap_ent *aura_heap_peek(struct aura_heap *hp) {
    if (aura_heap_is_empty(hp))
        return NULL;

    return hp->entries[0];
}

struct aura_heap_ent *aura_heap_pop(struct aura_heap *hp) {
    if (aura_heap_is_empty(hp))
        return NULL;

    struct aura_heap_ent *e = hp->entries[0];
    --(hp->size);
    hp->entries[0] = hp->entries[hp->size];
    hp->entries[0]->idx = hp->entries[hp->size]->idx;

    e->idx = UINT32_MAX;
    a_hp_bubble_down(hp, 0);

    return e;
}

void aura_heap_del(struct aura_heap *hp, struct aura_heap_ent *e) {
    assert(hp->entries[e->idx] == e);

    --hp->size;
    if (e->idx == hp->size)
        return;

    if (e->idx == 0) {
        aura_heap_pop(hp);
        return;
    }

    hp->entries[e->idx] = hp->entries[hp->size];
    hp->entries[e->idx]->idx = hp->entries[hp->size]->idx;

    a_hp_bubble_up(hp, e->idx);
    a_hp_bubble_down(hp, e->idx);
    e->idx = UINT32_MAX;
}

void aura_heap_dump(struct aura_heap *hp, bool is_daemon) {
    app_debug(is_daemon, 0, "AURA HEAP");
    app_debug(is_daemon, 0, "   Size: %lu", hp->size);
    app_debug(is_daemon, 0, "   Cap: %lu", hp->cap);
    app_debug(is_daemon, 0, "   Data ptr: %p", hp->entries);
    app_debug(is_daemon, 0, "   Cmp fn ptr: %p", hp->cmp);
}
