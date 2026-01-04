#ifndef AURA_SLAB_H
#define AURA_SLAB_H

#include "align_lib.h"
#include "list_lib.h"
#include "memory_lib.h"
#include <stdint.h>

#define A_PAGE_SIZE 4096
#define A_SLAB_DEBUG 1
#define A_SLAB_STATS 1
#define A_SLAB_POISON 1
#define A_SLAB_REDZONE 1
#define A_SLAB_DEBUG_DEFAULT (A_SLAB_POISON | A_SLAB_REDZONE)

#define ptr_size (sizeof(void *))

#if A_SLAB_REDZONE
#define A_REDZONE_SIZE (ptr_size)
#define A_REDZONE_PATTERN 0x4C4C4C4C
#else
#define A_REDZONE_SIZE 0
#endif

#define VAL(x) #x
#define STR(x) VAL(x)
#define a_get_slab_name(size) ((size) < 1024) ? STR(size) "B" : ((size) < 1048576) ? STR(size) "KB" \
                                                                                   : STR(size) "MB"
#define A_MAX_SLAB_NAME 128

/* Object header structure */
struct aura_object_hdr {
    struct aura_memory_ctx *mem_ctx;
    uint16_t size;
    uint8_t slab_cache_id;
    uint16_t slab_id;
    void *next;
#if A_SLAB_DEBUG
    uint64_t magic;
    void *alloc_site;
    void *free_site;
#endif
};

#if A_SLAB_DEBUG
#define A_OBJECT_HEADER_SIZE sizeof(struct aura_object_hdr)
#define A_MAGIC_ALLOC 0xA110CADEADBEEF
#define A_MAGIC_FREE 0xA110CAF333BEEF
#else
#define A_OBJECT_HEADER_SIZE sizeof(struct aura_object_hdr)
#endif

typedef enum {
    A_DYNAMIC_SLAB_ID = 1
} slab_cache_id;

struct aura_cache_stats {
    uint64_t total_allocations;
    uint64_t total_frees;
    uint64_t active_allocations;
    uint64_t total_slabs;
    uint64_t total_memory;
    uint64_t wasted_memory;
    uint64_t cache_misses;
};

/**
 * Slab cache structure
 */
struct aura_slab_cache {
    uint32_t obj_size; /* object size without metadata*/
    uint32_t size;     /* object size including metadata */
    uint32_t slab_size;
    uint32_t slab_max_id;
    uint32_t offset; /* free pointer offset */

    void (*ctor)(void *);
    uint32_t objs_per_slab;
    uint32_t low_water_mark;
    uint32_t high_water_mark;
#if A_SLAB_STATS
    struct aura_cache_stats stats;
#endif
    struct aura_list_head cache_list;
    struct aura_list_head full_list;
    struct aura_list_head partial_list;
    struct aura_list_head free_list;
    char name[A_MAX_SLAB_NAME];
    struct aura_memory_ctx *mem_ctx;
    uint8_t slab_cache_id;
    uint8_t flags;
};

/**
 * Slab structure
 */
struct aura_slab {
    struct aura_slab_cache *slab_cache;
    void *obj;       /* pointer to first slab object */
    void *free_list; /* pointer to free object */
    uint32_t in_use; /* object allocated/present in the slab  */
    struct aura_list_head slab_list;
    uint8_t slab_id;
};

struct aura_slab_info {
};

/**
 *
 */
typedef enum {
    A_SLAB_CACHE_ID_DYAMIC = 1,
    A_SLAB_CACHE_ID_SOCK = 2,
    A_SLAB_CACHE_ID_CONNECTION = 3,
    A_SLAB_CACHE_ID_STREAM = 4
} aura_slab_cache_id;

/**
 * Slab Debug Stuff
 */
#if A_SLAB_DEBUG
#define A_SLAB_ASSERT(condition, message)                                                  \
    do {                                                                                   \
        if (!(condition)) {                                                                \
            /* a_slab_panic() */                                                           \
            app_debug(true, 0, "ASSERT FAILED: %s at %s:%u", message, __FILE__, __LINE__); \
        }                                                                                  \
    } while (0)

#define A_RECORD_ALLOC_SITE(header)                       \
    do {                                                  \
        header->alloc_site = __builtin_return_address(0); \
        header->magic = A_MAGIC_ALLOC;                    \
    } while (0)

#define A_RECORD_FREE_SITE(header)                       \
    do {                                                 \
        header->free_site = __builtin_return_address(0); \
        header->magic = A_MAGIC_FREE;                    \
    } while (0)

#define A_VALIDATE_HEADER(header)                                                  \
    do {                                                                           \
        if (header->magic != A_MAGIC_ALLOC /* && header->free != A_MAGIC_FREE*/) { \
            /* a_slab_panic() */                                                   \
            app_debug(true, 0, "Corrupted header magic: 0x%1x", header->magic);    \
        }                                                                          \
    } while (0)

#else
#define A_SLAB_ASSERT(condition, message) \
    do {                                  \
    } while (0)
#define A_RECORD_ALLOC_SITE(header) \
    do {                            \
    } while (0)
#define A_RECORD_FREE_SITE(header) \
    do {                           \
    } while (0)
#define A_VALIDATE_HEADER(header) \
    do {                          \
    } while (0)
#endif

#if A_SLAB_POISON
#define A_SLAB_ALLOC_POISON_PATTERN 0x5A5A5A5A5A5A5A5A
#define A_SLAB_FREE_POISON_PATTERN 0x6B6B6B6B6B6B6B6B

static inline void a_verify_poison_pattern(void *ptr, uint64_t size, uint64_t expected) {}

#define A_POISON_OBJECT(ptr, size) memset(ptr, A_SLAB_ALLOC_POISON_PATTERN & 0xFF, size)
#define A_UNPOISON_OBJECT(ptr, size) memset(ptr, A_SLAB_FREE_POISON_PATTERN & 0xFF, size)
#define A_VERIFY_POISON(ptr, size, expected) a_verify_poison_pattern(ptr, size, expected)
#else
#define A_POISON_OBJECT(ptr, size) \
    do {                           \
    } while (0)
#define A_UNPOISON_OBJECT(ptr, size) \
    do {                             \
    } while (0)
#define A_VERIFY_POISON(ptr, size, expected) \
    do {                                     \
    } while (0)
#endif

static inline int aura_get_dynamic_slab_index(size_t size) {
    if ((size % 64) == 0)
        return (size / 64) - 1;
    else
        return size / 64;
}

/* Determine object index from a given position */
static inline uint32_t get_object_idx(const struct aura_slab_cache *cache, const struct aura_slab *slab, void *obj) {
    return ((obj - slab->obj) / cache->size);
}

static inline unsigned objs_per_slab(const struct aura_slab_cache *cache) { /* inline */
    return cache->objs_per_slab;
}

/**
 * Search for cache with the given ID
 * from the list of caches
 */
static inline struct aura_slab_cache *aura_slab_cache_find_by_id(struct aura_memory_ctx *mc, uint8_t sc_id) {
    struct aura_slab_cache *sc;

    a_list_for_each(sc, &mc->slab_cache_list, cache_list) {
        if (sc->slab_cache_id == sc_id)
            return sc;
    }

    return NULL;
}

/**
 * Creates a new slab cache with the provided name
 * and slab cache id
 */
struct aura_slab_cache *aura_slab_cache_create(struct aura_memory_ctx *m_ctx, uint8_t s_cache_id, const char *name, size_t obj_size, void (*ctor)(void *), uint32_t flags);

/**
 * Create caches for dynamic slab pool
 */
bool aura_create_dynamic_slab_alloc_caches(struct aura_memory_ctx *m_ctx);
void aura_slab_cache_destroy(struct aura_slab_cache *sc);
void *aura_slab_alloc(struct aura_slab_cache *sc);

/**
 * Free the slot pointed to by ptr from the
 * associated slab. Information about the slab is
 * retrieved from the header info of this ptr
 */
void aura_slab_free(void *ptr);

/**
 * Allocator function
 * Gets memory from dynamic slab pool
 * returning NULL if it fails
 */
void *aura_alloc(struct aura_memory_ctx *mc, size_t size);

/** */
void *aura_realloc(struct aura_memory_ctx *mc, void *ptr, size_t size);

/**
 * Free memory pointed to by ptr
 */
void aura_free(void *ptr);

void get_slap_info(struct aura_slab_cache *s, struct aura_slab_info *sinfo);

/* Print slab */
void aura_slab_dump(struct aura_slab *slab);

/* Print slab cache */
void aura_slab_cache_dump(struct aura_slab_cache *sc);

/* Print slab object header */
void aura_slab_obj_header_dump(struct aura_object_hdr *hdr);

#endif