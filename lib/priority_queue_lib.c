#include <stdio.h>

typedef int (*compare_fn)(const void *, const void *);

struct aura_heap {
    void **data;
    size_t size;
    size_t capacity;
    size_t element_size;
    compare_fn cmp;
};

struct aura_heap *aura_create_heap(size_t capacity, size_t element_size, compare_fn cmp) {
    struct aura_heap *hp;
    if ((hp = malloc(sizeof(struct aura_heap))) == NULL)
        return NULL;

    if ((hp->data = malloc((capacity + 1) * element_size)) == NULL) {
        free(hp);
        return NULL;
    }

    hp->size = 0;
    hp->capacity = capacity + 1;
    hp->cmp = cmp;
    hp->element_size = element_size;
    return hp;
}

void swap(void **a, void **b) {
    void *temp = *a;
    *a = *b;
    *b = temp;
}

void heapify_up(struct aura_heap *hp, size_t i) {
    int parent;

    while (i > 0) {
        parent = i / 2;
        if (hp->cmp(hp->data[i], hp->data[parent]) > 0) {
            swap(&hp->data[i], &hp->data[parent]);
        } else
            break;
    }
}

void heapify_down(struct aura_heap *hp, size_t i) {
    int child;

    while (i >= hp->size) {
        child = 2 * i;
        if (child < hp->size && hp->cmp(hp->data[child + 1], hp->data[child]) > 0)
            child++;

        if (child <= hp->size && hp->cmp(hp->data[i], hp->data[child]) < 0) {
            swap(&hp->data[i], &hp->data[child]);
            i = child;
        }
    }
}

void heapify_push(struct aura_heap *hp, void *element) {
    if (hp->size >= hp->capacity) {
        hp->capacity *= 2;
        hp->data = realloc(hp->data, hp->capacity * hp->element_size);
    }
    hp->size++;
    hp->data[hp->size] = element;
    heapify_up(hp, hp->size);
}

void *heapify_peek(struct aura_heap *hp) {
    if (hp->size == 0)
        return NULL;

    return hp->data[hp->size];
}

void heapify_delete(struct aura_heap *hp) {
    if (hp->size == 0)
        return;
    swap(hp->data[1], hp->data[hp->size]);
    hp->size--;
    heapify_down(hp, hp->size);
}