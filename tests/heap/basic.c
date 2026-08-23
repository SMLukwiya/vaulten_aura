#include "heap/lib.h"
#include "list_lib.h"
#include <assert.h>
#include <stdlib.h>

struct aura_mem_ctx mc;

struct hp_testnode {
    int priority;
    struct aura_heap_ent hp_ent;
};

static void a_test_resources_create(void) {
    aura_mem_ctx_init(&mc);
    assert(aura_create_dynamic_slab_alloc_caches(&mc) == 0);
}

static void a_test_resources_destroy() {
    aura_mem_ctx_destroy(&mc);
}

/* compare function */
static int a_cmp_fn(struct aura_heap_ent *_e1, struct aura_heap_ent *_e2) {
    struct hp_testnode *e1, *e2;

    e1 = aura_container_of(_e1, struct hp_testnode, hp_ent);
    e2 = aura_container_of(_e2, struct hp_testnode, hp_ent);

    return e1->priority - e2->priority;
}

/* destructor function */
void a_dtor_fn(const void *elem) {
    if (elem)
        aura_free((void *)elem);
}

static void a_test_max_heap_insert_delete(void) {
    struct aura_heap *hp;
    struct aura_heap_ent *e;
    struct hp_testnode *node;

    int priorities[] = {20, 40, 30, 5, 10};

    hp = aura_alloc(&mc, sizeof(*hp));
    assert(hp != NULL);

    assert(aura_heap_init(hp, &mc, 5, a_cmp_fn, A_HP_TYPE_MAX_HEAP) == 0);
    assert(hp->size == 0);
    assert(hp->cap == 5);

    /* INSERT */
    for (int i = 0; i < 5; ++i) {
        node = aura_alloc(&mc, sizeof(struct hp_testnode));
        node->priority = priorities[i];
        assert(aura_heap_push(hp, &node->hp_ent) == 0);
    }

    /* ORDER */
    int largest_value = 40;
    e = aura_heap_pop(hp);
    node = aura_container_of(e, struct hp_testnode, hp_ent);
    assert(node->priority == largest_value);
    a_dtor_fn(node);

    largest_value = 30;
    e = aura_heap_pop(hp);
    node = aura_container_of(e, struct hp_testnode, hp_ent);
    assert(node->priority == largest_value);
    a_dtor_fn(node);

    while (hp->size > 0) {
        e = aura_heap_pop(hp);
        assert(e != NULL);
        node = aura_container_of(e, struct hp_testnode, hp_ent);
        assert(node->priority <= largest_value);
        largest_value = node->priority;
        a_dtor_fn(node);
    }

    aura_heap_destroy(hp);
    aura_free(hp);
}

static void a_test_min_heap_insert_delete(void) {
    struct aura_heap *hp;
    struct aura_heap_ent *e;
    struct hp_testnode *node;

    int priorities[] = {20, 40, 30, 5, 10};

    hp = aura_alloc(&mc, sizeof(*hp));
    assert(hp != NULL);

    assert(aura_heap_init(hp, &mc, 5, a_cmp_fn, A_HP_TYPE_MIN_HEAP) == 0);
    assert(hp->size == 0);
    assert(hp->cap == 5);

    /* INSERT */
    for (int i = 0; i < 5; ++i) {
        node = aura_alloc(&mc, sizeof(struct hp_testnode));
        node->priority = priorities[i];
        assert(aura_heap_push(hp, &node->hp_ent) == 0);
    }

    /* ORDER */
    int smallest_value = 5;
    e = aura_heap_pop(hp);
    assert(e != NULL);
    node = aura_container_of(e, struct hp_testnode, hp_ent);
    assert(node->priority == smallest_value);
    a_dtor_fn(node);

    smallest_value = 10;
    e = aura_heap_pop(hp);
    assert(e != NULL);
    node = aura_container_of(e, struct hp_testnode, hp_ent);
    assert(node->priority == smallest_value);
    a_dtor_fn(node);

    while (hp->size > 0) {
        e = aura_heap_pop(hp);
        assert(e != NULL);
        node = aura_container_of(e, struct hp_testnode, hp_ent);
        assert(node->priority >= smallest_value);
        smallest_value = node->priority;
        a_dtor_fn(node);
    }

    aura_heap_destroy(hp);
    aura_free(hp);
}

int main(int argc, char **argv) {
    a_test_resources_create();
    a_test_max_heap_insert_delete();
    a_test_min_heap_insert_delete();
    a_test_resources_destroy();
    return 0;
}
