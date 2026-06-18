#include "interned.h"
#include "error_lib.h"
#include "hasher_lib.h"
#include "slab_lib.h"
#include "string_lib.h"

static struct aura_interned_str_arena *a_interned_str_arena_create(struct aura_mem_ctx *mc) {
    struct aura_interned_str_arena *arena;

    arena = aura_alloc(mc, sizeof(*arena));
    if (!arena)
        return NULL;

    arena->data = aura_alloc(mc, 1024);
    if (!arena->data) {
        aura_free(arena);
        return NULL;
    }
    arena->cap = 1024;
    arena->used = 0;
    arena->next = NULL;
    return arena;
}

static void a_interned_str_arena_destroy(struct aura_interned_str_arena *arena) {
    if (!arena)
        return;

    if (arena->data)
        aura_free(arena->data);
    aura_free(arena);
}

struct aura_intern_tab *aura_intern_tab_create(struct aura_mem_ctx *mc, size_t size) {
    struct aura_intern_tab *tab;

    if (size == 0)
        return NULL;

    tab = aura_alloc(mc, sizeof(*tab));
    if (!tab)
        return NULL;

    tab->entries = aura_alloc(mc, sizeof(struct aura_interned_str) * size);
    if (!tab->entries) {
        aura_free(tab);
        return NULL;
    }
    memset(tab->entries, 0, sizeof(struct aura_interned_str) * size);
    tab->arena = a_interned_str_arena_create(mc);
    if (!tab->arena) {
        aura_free(tab);
        aura_free(tab->entries);
        return NULL;
    }
    tab->mc = mc;
    tab->cap = size;
    tab->cnt = 0;
    return tab;
}

int aura_intern_tab_create2(struct aura_intern_tab *tab, struct aura_mem_ctx *mc, size_t size) {

    if (size == 0)
        return -1;

    tab->entries = aura_alloc(mc, sizeof(struct aura_interned_str) * size);
    if (!tab->entries)
        return -1;

    memset(tab->entries, 0, sizeof(struct aura_interned_str) * size);
    tab->arena = a_interned_str_arena_create(mc);
    if (!tab->arena) {
        aura_free(tab->entries);
        return -1;
    }
    tab->mc = mc;
    tab->cap = size;
    tab->cnt = 0;
    return 0;
}

void aura_intern_tab_destroy(struct aura_intern_tab *tab) {
    if (!tab)
        return;

    if (tab->arena) {
        do {
            a_interned_str_arena_destroy(tab->arena);
        } while ((tab->arena = tab->arena->next));
    }

    if (tab->entries)
        aura_free(tab->entries);

    aura_free(tab);
}

void aura_intern_tab_destroy2(struct aura_intern_tab *tab) {
    if (!tab)
        return;

    if (tab->arena) {
        do {
            a_interned_str_arena_destroy(tab->arena);
        } while ((tab->arena = tab->arena->next));
    }

    if (tab->entries)
        aura_free(tab->entries);
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
    idx = aura_intern_tab_get_idx(hash, tab->cap);

    stored_idx = idx;
    while (tab->entries[idx].data) {
        i_str = &tab->entries[idx];
        if (hash == i_str->hash && aura_mem_is_eq(str, len, i_str->data, i_str->len))
            return i_str;

        idx = (idx + 1) & (tab->cap - 1);
        /**
         * We have fully wrapped around back to the
         * index we started from
         */
        if (stored_idx == idx)
            break;
    }

    return NULL;
}

static inline struct aura_interned_str *a_intern_tab_get_slot(struct aura_intern_tab *tab, uint32_t idx) {
    uint32_t stored_idx;

    if (!tab->entries[idx].data)
        return &tab->entries[idx];

    /* store starting index */
    stored_idx = idx;
redo:
    do {
        idx = (idx + 1) & (tab->cap - 1);
        /* Fully wrapped around */
        if (stored_idx == idx)
            break;
        if (!tab->entries[idx].data)
            return &tab->entries[idx];
    } while (idx < tab->cap);

    /* We need more slots */
    if (stored_idx == idx) {
        idx = tab->cap;
        tab->cap *= 2;
        tab->entries = aura_realloc(tab->mc, tab->entries, (sizeof(struct aura_interned_str) * tab->cap));
        if (!tab->entries)
            return NULL;
        memset(&tab->entries[idx], 0, sizeof(struct aura_interned_str) * (tab->cap - idx));
        goto redo;
    }
    return NULL;
}

static const char *a_interned_str_insert_into_arena(struct aura_mem_ctx *mc, struct aura_interned_str_arena *arena, char *str, size_t len) {
    struct aura_interned_str_arena *curr_arena, *next_arena;
    char *s;
    /**
     * Available space is too small, search or
     * create a new arena and add the str there,
     */
    if ((arena->cap - arena->used) < len + 1) {
        curr_arena = arena;
        while ((next_arena = arena->next) && (next_arena->cap - next_arena->used) < len + 1)
            curr_arena = next_arena;

        /* Create a new arena, and point to it */
        if (!next_arena) {
            arena = a_interned_str_arena_create(mc);
            if (!arena)
                return NULL;
            curr_arena->next = arena;
        } else {
            /* update arena pointer */
            arena = next_arena;
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
    if (!i_str) {
        /* @todo: We must allocated more from above */
        return NULL;
    }

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