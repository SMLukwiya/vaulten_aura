#include "error_lib.h"
#include "heap_lib.h"
#include <stdlib.h>

static inline int left(int i) {
    return i << 1;
}

static inline int right(int i) {
    return (i << 1) + 1;
}

static inline int parent(int i) {
    return i >> 1;
}

struct aura_heap *aura_heap_create(size_t capacity, compare_fn cmp) {
    struct aura_heap *hp;
    if ((hp = malloc(sizeof(struct aura_heap))) == NULL)
        return NULL;

    if ((hp->data = malloc((capacity + 1) * sizeof(void *))) == NULL) {
        free(hp);
        return NULL;
    }

    hp->data[0] = NULL;
    hp->size = 0;
    hp->cap = capacity + 1;
    hp->cmp = cmp;
    hp->elem_size = sizeof(void *);
    return hp;
}

void aura_heap_destroy(struct aura_heap *heap, destructor_fn destructor) {
    if (!heap)
        return;

    if (destructor)
        for (int i = 1; i <= heap->size; ++i) {
            destructor(heap->data[i]);
        }

    if (heap->data)
        free(heap->data);
    heap->data = NULL;
    heap->cap = heap->size = 0;
}

static inline void swap(void **a, void **b) {
    void *temp = *a;
    *a = *b;
    *b = temp;
}

/* Build max heap by insertion */
static void aura_max_heap_insert(struct aura_heap *hp, size_t i) {
    int _parent;

    /**
     * Only run when we have more than 1 item in heap
     */
    while (i > 1) {
        _parent = parent(i);
        if (hp->cmp(hp->data[i], hp->data[_parent]) > 0) {
            swap(&hp->data[i], &hp->data[_parent]);
            i = _parent;
        } else
            break;
    }
}

bool aura_max_heap_push(struct aura_heap *hp, void *element) {
    if (aura_heap_is_full(hp))
        return false;

    hp->size++;
    hp->data[hp->size] = element;
    aura_max_heap_insert(hp, hp->size);
    return true;
}

static void aura_max_heapify(struct aura_heap *hp, size_t i) {
    int child;

    while (i < hp->size) {
        child = 2 * i;
        if (child < hp->size && hp->cmp(hp->data[child + 1], hp->data[child]) > 0)
            child++;

        if (child <= hp->size && hp->cmp(hp->data[child], hp->data[i]) > 0) {
            swap(&hp->data[i], &hp->data[child]);
            i = child;
        } else
            break;
    }
}

void *aura_max_heap_delete(struct aura_heap *hp) {
    void *item;

    if (aura_heap_is_empty(hp))
        return NULL;

    item = hp->data[1];
    swap(&hp->data[1], &hp->data[hp->size]);
    --(hp->size);
    aura_max_heapify(hp, 1);

    return item;
}

void *aura_max_heap_peek(struct aura_heap *hp) {
    if (hp->size == 1)
        return NULL;

    return hp->data[hp->size];
}

/* Build min heap by insertion */
static void aura_min_heap_insert(struct aura_heap *hp, size_t i) {
    int _parent;

    while (i > 1) {
        _parent = parent(i);
        if (hp->cmp(hp->data[i], hp->data[_parent]) < 0) {
            swap(&hp->data[i], &hp->data[_parent]);
            i = _parent;
        } else
            break;
    }
}

bool aura_min_heap_push(struct aura_heap *hp, void *element) {
    if (aura_heap_is_full(hp))
        return false;

    hp->size++;
    hp->data[hp->size] = element;
    aura_min_heap_insert(hp, hp->size);
    return true;
}

void *aura_min_heap_peak(struct aura_heap *hp) {
    if (hp->size == 1)
        return NULL;

    return hp->data[1];
}

static void aura_min_heapify(struct aura_heap *hp, size_t i) {
    int child;

    while (i < hp->size) {
        child = 2 * i;
        if (child < hp->size && hp->cmp(hp->data[child + 1], hp->data[child]) < 0)
            child++;

        if (child <= hp->size && hp->cmp(hp->data[child], hp->data[i]) < 0) {
            swap(&hp->data[i], &hp->data[child]);
            i = child;
        } else
            break;
    }
}

void *aura_min_heap_delete(struct aura_heap *hp) {
    void *item;

    if (aura_heap_is_empty(hp))
        return NULL;

    item = hp->data[1];
    swap(&hp->data[1], &hp->data[hp->size]);
    --(hp->size);
    aura_min_heapify(hp, 1);

    return item;
}

void aura_heap_dump(struct aura_heap *hp, bool is_daemon) {
    app_debug(is_daemon, 0, "AURA HEAP");
    app_debug(is_daemon, 0, "   Size: %lu", hp->size);
    app_debug(is_daemon, 0, "   Cap: %lu", hp->cap);
    app_debug(is_daemon, 0, "   Elem size: %lu", hp->elem_size);
    app_debug(is_daemon, 0, "   Data ptr: %p", hp->data);
    app_debug(is_daemon, 0, "   Cmp fn ptr: %p", hp->cmp);
}