#include "lru_cache.h"
#include "bitmap_lib.h"
#include "bug_lib.h"
#include <string.h>
#include <string_lib.h>

int aura_lru_cache_init(struct aura_lru_cache *lc, struct aura_mem_ctx *mc,
                        const char *name, uint8_t cache_id, uint32_t e_cnt,
                        uint32_t obj_size, uint32_t e_off) {
    struct aura_lru_entry *ent;
    struct aura_slab_cache *sc;
    int i;

    if (e_cnt > A_LC_MAX_CNT)
        return -1;

    char *cache_name = aura_strndup(mc, name, strlen(name));
    if (!cache_name)
        return -1;

    memset(lc, 0, sizeof(*lc));
    lc->entries = aura_alloc(mc, (e_cnt * sizeof(struct aura_lru_entry *)));
    if (!lc->entries) {
        aura_free(cache_name);
        return -1;
    }

    lc->lru_hash = aura_alloc(mc, e_cnt * sizeof(struct aura_list_head));
    if (!lc->lru_hash) {
        aura_free(cache_name);
        aura_free(lc->entries);
        return -1;
    }

    sc = aura_slab_cache_create(mc, cache_id, cache_name, obj_size, NULL, 0);
    if (!sc) {
        aura_free(cache_name);
        aura_free(lc->entries);
        aura_free(lc->lru_hash);
        return -1;
    }

    aura_list_head_init(&lc->lru);
    aura_list_head_init(&lc->in_use);
    aura_list_head_init(&lc->free);

    lc->name = name;
    // lc->obj_size = obj_size;
    lc->nr_entries = e_cnt;
    lc->entry_off = e_off;
    lc->lru_cache = sc;

    for (i = 0; i < e_cnt; ++i) {
        void *e = aura_slab_alloc(sc, obj_size);
        if (!e)
            break;

        ent = e + e_off;
        ent->lru_number = A_LC_FREE;
        ent->refcnt = 0;
        aura_list_head_init(&ent->hash);
        aura_list_add_tail(&lc->free, &ent->list);
        lc->entries[i] = ent;

        /* Initialize the hash list while at it */
        aura_list_head_init(&lc->lru_hash[i]);
    }

    if (i == e_cnt)
        return 0;

    while (i) {
        ent = lc->entries[--i];
        /* Get the object start position */
        aura_slab_free((void *)((void *)ent - e_off));
    }

    aura_free(cache_name);
    aura_free(lc->lru_hash);
    aura_free(lc->entries);
    return -1;
}

static void a_lru_free_by_index(struct aura_lru_cache *lc, uint32_t i) {
    void *p = lc->entries[i];
    A_BUG_ON_2(!p, true);

    /* Get structure start position */
    p -= lc->entry_off;
    aura_slab_free(p);
}

void aura_lru_cache_destroy(struct aura_lru_cache *lc) {
    if (!lc)
        return;

    for (int i = 0; i < lc->nr_entries; ++i)
        a_lru_free_by_index(lc, i);

    aura_free((void *)lc->name);
    aura_free(lc->entries);
    aura_free(lc->lru_hash);
    aura_slab_cache_destroy(lc->lru_cache);
}

static inline struct aura_list_head *a_lru_hash(struct aura_lru_cache *lc, uint64_t entry_nr) {
    return lc->lru_hash + (entry_nr % lc->nr_entries);
}

static struct aura_lru_entry *a_lru_find(struct aura_lru_cache *lc, uint64_t entry_nr) {
    struct aura_lru_entry *e;

    A_BUG_ON_2(!lc, true);
    // A_BUG_ON_2(!lc->nr_entries, true);

    a_list_for_each(e, a_lru_hash(lc, entry_nr), hash) {
        if (e->lru_number != entry_nr)
            continue;

        if (e->lru_number == entry_nr)
            return e;
        break;
    }

    return NULL;
}

struct aura_lru_entry *aura_lru_cache_find(struct aura_lru_cache *lc, uint64_t entry_nr) {
    return a_lru_find(lc, entry_nr);
}

void aura_lru_cache_del(struct aura_lru_cache *lc, struct aura_lru_entry *e) {
    A_BUG_ON_2(e->refcnt, true);

    e->lru_number = 0;
    aura_list_delete(&e->hash);
    aura_list_head_init(&e->hash);
    aura_list_move(&lc->free, &e->list);
}

static int a_lru_entry_available(struct aura_lru_cache *lc) {
    if (!aura_list_is_empty(&lc->free))
        return 1;
    if (!aura_list_is_empty(&lc->lru))
        return 1;

    return 0;
}

static struct aura_lru_entry *a_lru_cache_prepare_for_action(struct aura_lru_cache *lc, uint64_t entry_nr) {
    struct aura_lru_entry *e;

    if (!aura_list_is_empty(&lc->free)) {
        a_list_dequeue(e, &lc->free, list);
    } else if (!aura_list_is_empty(&lc->lru)) {
        a_list_dequeue(e, &lc->lru, list);
    } else
        return NULL;

    e->lru_number = entry_nr;

    /* Clear any hash link if present */
    if (!aura_list_is_empty(&e->hash))
        aura_list_delete(&e->hash);

    /* Insert into hash table */
    aura_list_add(a_lru_hash(lc, entry_nr), &e->hash);

    return e;
}

struct aura_lru_entry *aura_lru_cache_get(struct aura_lru_cache *lc, uint64_t entry_nr) {
    struct aura_lru_entry *e;

    if (aura_bitmap_test_bit(A_LC_WAITING, (uint64_t *)&lc->flags)) {
        ++lc->waiting;
        return NULL;
    }

    e = a_lru_find(lc, entry_nr);
    if (e) {
        ++e->refcnt;
        /* If first use, update usage data */
        if (e->refcnt++ == 0)
            lc->used++;
        aura_list_move(&lc->in_use, &e->list);

        return e;
    }

    /* Cache miss */
    ++lc->misses;

    if (!a_lru_entry_available(lc)) {
        aura_bitmap_set_bit(A_LC_WAITING, (uint64_t *)&lc->flags);
        return NULL;
    }

    e = a_lru_cache_prepare_for_action(lc, entry_nr);
    A_BUG_ON_2(!e, true);

    aura_bitmap_clear_bit(A_LC_WAITING, (uint64_t *)&lc->flags);
    A_BUG_ON_2(++e->refcnt != 1, true);
    ++lc->used;

    return e;
}