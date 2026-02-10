#include "heap_lib.h"
#include <assert.h>
#include <stdlib.h>

#define HP_CAP 10

struct hp_testnode {
    int priority;
    char name[16];
};

static int a_hp_test_compare_fn(const void *elem1, const void *elem2) {
    struct hp_testnode *_elem1, *_elem2;

    _elem1 = (struct hp_testnode *)elem1;
    _elem2 = (struct hp_testnode *)elem2;

    return _elem1->priority - _elem2->priority;
}

void a_hp_test_destructor_fn(const void *elem) {
    /**
     * This check for elem seems redundant, but just in case
     */
    if (elem)
        free((void *)elem);
}

static void a_test_max_heap_insert_delete(void) {
    struct aura_heap *hp;
    struct hp_testnode *node;

    int priorities[] = {20, 40, 30, 5, 10};

    hp = aura_heap_create(5, a_hp_test_compare_fn);
    assert(hp != NULL);
    assert(hp->size == 0);
    assert(hp->cap == 6); /* 5+1 for 1 indexed array */

    /* INSERT */
    for (int i = 0; i < 5; ++i) {
        node = malloc(sizeof(struct hp_testnode));
        node->priority = priorities[i];
        bool rv = aura_max_heap_push(hp, (void *)node);
        assert(rv == true);
    }

    /* ORDER */
    int largest_value = 40;
    node = (struct hp_testnode *)aura_max_heap_delete(hp);
    assert(node->priority == largest_value);
    free(node);

    largest_value = 30;
    node = (struct hp_testnode *)aura_max_heap_delete(hp);
    assert(node->priority == largest_value);
    free(node);

    while (hp->size > 0) {
        node = (struct hp_testnode *)aura_max_heap_delete(hp);
        assert(node != NULL);
        assert(node->priority <= largest_value);
        largest_value = node->priority;
        free(node);
    }

    aura_heap_destroy(hp, a_hp_test_destructor_fn);
}

static void a_test_min_heap_insert_delete(void) {
    struct aura_heap *hp;
    struct hp_testnode *node;

    int priorities[] = {20, 40, 30, 5, 10};

    hp = aura_heap_create(5, a_hp_test_compare_fn);
    assert(hp != NULL);
    assert(hp->size == 0);
    assert(hp->cap == 6);

    /* INSERT */
    for (int i = 0; i < 5; ++i) {
        node = malloc(sizeof(struct hp_testnode));
        node->priority = priorities[i];
        bool rv = aura_min_heap_push(hp, (void *)node);
        assert(rv == true);
    }

    /* ORDER */
    int smallest_value = 5;
    node = (struct hp_testnode *)aura_min_heap_delete(hp);
    assert(node->priority == smallest_value);
    free(node);

    smallest_value = 10;
    node = (struct hp_testnode *)aura_min_heap_delete(hp);
    assert(node->priority == smallest_value);
    free(node);

    while (hp->size > 0) {
        node = (struct hp_testnode *)aura_min_heap_delete(hp);
        assert(node != NULL);
        assert(node->priority >= smallest_value);
        smallest_value = node->priority;
        free(node);
    }

    aura_heap_destroy(hp, a_hp_test_destructor_fn);
}

int main(int argc, char **argv) {
    a_test_max_heap_insert_delete();
    a_test_min_heap_insert_delete();
    return 0;
}