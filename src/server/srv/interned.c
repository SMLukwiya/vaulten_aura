#include "interned.h"
#include "error_lib.h"
#include "hasher_lib.h"
#include "slab.h"
#include "string_lib.h"
#include "utils_lib.h"

static struct aura_interned_str_arena *a_interned_str_arena_create(struct aura_mem_ctx *mc) {
    struct aura_interned_str_arena *arena;

    arena = aura_alloc(mc, sizeof(*arena));
    if (!arena)
        return NULL;
    memset(arena, 0, sizeof(*arena));

    arena->cap = A_INTERNED_STR_ARENA_SIZE;
    arena->used = 0;
    arena->next = NULL;
    return arena;
}

static void a_interned_str_arena_destroy(struct aura_interned_str_arena *arena) {
    if (!arena)
        return;

    aura_free(arena);
}

struct aura_intern_tab *aura_intern_tab_create(struct aura_mem_ctx *mc) {
    struct aura_intern_tab *tab;

    tab = aura_alloc(mc, sizeof(*tab));
    if (!tab)
        return NULL;
    memset(tab, 0, sizeof(*tab));

    tab->arena = a_interned_str_arena_create(mc);
    if (!tab->arena) {
        aura_free(tab);
        return NULL;
    }
    tab->mc = mc;
    tab->cap = A_INTERNED_TAB_SLOT_CNT;
    tab->cnt = 0;
    tab->next = NULL;
    return tab;
}

void aura_intern_tab_destroy(struct aura_intern_tab *tab) {
    if (!tab)
        return;

    if (tab->arena) {
        do {
            a_interned_str_arena_destroy(tab->arena);
        } while ((tab->arena = tab->arena->next));
    }

    aura_free(tab);
}

static inline uint32_t a_interned_str_hash(char *str) {
    uint32_t hash, hval;

    hval = FNV1_32A_INIT;
    hash = fnv_32a_str(str, hval);
    return hash;
}

struct aura_interned_str *aura_interned_str_find(struct aura_intern_tab *tab, char *str, size_t len) {
    uint32_t hash, idx, stored_idx;
    struct aura_interned_str *i_str;

    if (len == 0)
        return NULL;

    hash = a_interned_str_hash(str);

    while (tab) {
        idx = aura_intern_tab_get_idx(hash, tab->cap);
        stored_idx = idx;

        while (tab->entries[idx].data) {
            i_str = &tab->entries[idx];
            if (hash == i_str->hash && aura_mem_is_eq(str, len, i_str->data, i_str->len))
                return i_str;

            idx = (idx + 1) & A_INTERNED_TAB_SLOT_MASK;
            /**
             * We have fully wrapped around back to the
             * index we started from
             */
            if (stored_idx == idx)
                break;
        }

        tab = tab->next;
    }

    return NULL;
}

static inline struct aura_interned_str *a_intern_tab_get_slot(struct aura_intern_tab *tab, uint32_t idx) {
    uint32_t stored_idx;
    struct aura_intern_tab *prev_tab;

    while (tab && aura_intern_tab_full(tab)) {
        prev_tab = tab;
        tab = tab->next;
    }

    /* No availble table, chain a new table */
    if (!tab) {
        prev_tab->next = aura_intern_tab_create(prev_tab->mc);
        if (!prev_tab->next)
            return NULL;
        tab = prev_tab->next;
    }

    if (!tab->entries[idx].data) {
        tab->cnt++;
        return &tab->entries[idx];
    }

    /* store starting index */
    stored_idx = idx;
    do {
        idx = (idx + 1) & A_INTERNED_TAB_SLOT_MASK;
        /* Fully wrapped around */
        if (stored_idx == idx)
            break;

        if (!tab->entries[idx].data) {
            tab->cnt++;
            return &tab->entries[idx];
        }
    } while (idx < tab->cap);

    return NULL;
}

static const char *a_interned_str_insert_into_arena(struct aura_mem_ctx *mc,
                                                    struct aura_interned_str_arena *arena,
                                                    char *str, size_t len) {
    struct aura_interned_str_arena *prev_arena;
    char *s;
    /**
     * Available space is too small, search or
     * create a new arena to add the str to.
     */
    if ((arena->cap - arena->used) < len + 1) {
        prev_arena = arena;

        while ((arena = arena->next) && (arena->cap - arena->used) < len + 1)
            prev_arena = arena;

        /* Create a new arena, and point to it */
        if (!arena) {
            prev_arena->next = a_interned_str_arena_create(mc);
            if (!prev_arena->next)
                return NULL;

            arena = prev_arena->next;
        }
    };

    s = arena->data + arena->used;
    memcpy(s, str, len);
    s[len] = '\0'; /* null terminated */
    arena->used += len + 1;
    return (const char *)s;
}

struct aura_interned_str *aura_interned_str_add(struct aura_intern_tab *tab, char *str, size_t len) {
    struct aura_interned_str *i_str;
    uint32_t hash, idx;

    hash = a_interned_str_hash(str);
    idx = aura_intern_tab_get_idx(hash, tab->cap);
    i_str = a_intern_tab_get_slot(tab, idx);
    if (!i_str)
        return NULL;

    i_str->data = a_interned_str_insert_into_arena(tab->mc, tab->arena, str, len);
    if (!i_str->data)
        return NULL;
    i_str->hash = hash;
    i_str->len = len;

    return i_str;
}

struct aura_interned_str *aura_interned_str_find_or_add(struct aura_intern_tab *tab, char *str, size_t len) {
    struct aura_interned_str *i_str;

    if (len == 0)
        return NULL;

    i_str = aura_interned_str_find(tab, str, len);
    if (i_str)
        return i_str;

    i_str = aura_interned_str_add(tab, str, len);
    if (!i_str)
        return NULL;

    return i_str;
}