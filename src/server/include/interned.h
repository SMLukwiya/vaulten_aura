#ifndef AURA_SRV_INTERNED_STR_H
#define AURA_SRV_INTERNED_STR_H

#include "memory_lib.h"

#include <stdint.h>
#include <stdlib.h>

/* Interned string structure */
struct aura_interned_str {
    uint32_t hash;    /* string hash */
    uint32_t len;     /* string len */
    const char *data; /* null terminated string */
};

/* Interned string arena structure */
struct aura_interned_str_arena {
    struct aura_interned_str_arena *next; /* pointer to next arena */
    size_t used;                          /* size consumed */
    size_t cap;                           /* capacity */
    char *data;                           /* pointer to memory location */
};

/* Intern table structure */
struct aura_intern_tab {
    struct aura_memory_ctx *mc;
    struct aura_interned_str *entries;
    size_t cnt;                            /* number of entries */
    size_t cap;                            /* capacity of table (MUST be power of 2) */
    struct aura_interned_str_arena *arena; /* pointer to the first arena */
};

/* Get index from hash */
static inline uint32_t aura_intern_tab_get_idx(uint32_t hash, size_t bucket_size) {
    return hash &= (bucket_size - 1);
}

/**
 * Create interned table structure
 * Ensure size is a multiple of 2 for now
 */
struct aura_intern_tab *aura_intern_tab_create(struct aura_memory_ctx *mc, size_t size);

/**
 * Destroy intern tab and attached str arenas
 */
void aura_intern_tab_destroy(struct aura_intern_tab *tab);

/**
 * Add provided string to intern table
 */
struct aura_interned_str *aura_interned_str_add(struct aura_intern_tab *tab, char *str, size_t len);

/**
 * Find an interned string
 */
struct aura_interned_str *aura_interned_str_find(struct aura_intern_tab *tab, char *str, size_t len);

/**
 * Attempt to find interned string, otherwise
 * create if not found
 */
struct aura_interned_str *aura_interned_str_find_or_add(struct aura_intern_tab *tab, char *str, size_t len);

#endif