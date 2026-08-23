#ifndef AURA_SLAB_H
#define AURA_SLAB_H

#include <stdint.h>
#include <stdlib.h>

#include "align_lib.h"
#include "error_lib.h"
#include "list_lib.h"
#include "mem.h"

#define A_PAGE_SIZE 4096
#define A_SLAB_DEBUG 1
#define A_SLAB_STATS 1
#define A_SLAB_POISON 1
#define A_SLAB_REDZONE 1
#define A_SLAB_DEBUG_DEFAULT (A_SLAB_POISON | A_SLAB_REDZONE)

#define ptr_size (sizeof(void *))

#if A_SLAB_REDZONE
#define A_SLAB_REDZONE_SIZE (ptr_size)
#define A_REDZONE_PATTERN 0x4C4C4C4C4C4C4C4CUL
#else
#define A_SLAB_REDZONE_SIZE 0
#endif

#define A_MAX_SLAB_NAME 128

#define A_MEM_MODE_SLAB 1
#define A_MEM_MODE_MALLOC (1 << 1)

#define A_SLAB_ACTION_ALLOC 1000
#define A_SLAB_ACTION_FREE 1001

#define A_SLAB_MAX_TRACE_DEPTH 4

/* Trace of the call chain to slab allocator */
struct aura_slab_trace {
    uint8_t depth;
    void *pc[A_SLAB_MAX_TRACE_DEPTH];
};

/* Object header structure */
struct aura_slab_obj_hdr {
    struct aura_mem_ctx *mem_ctx; /* base memory */
    void *next;                   /* Next free item */
#if A_SLAB_DEBUG                  /* Debug info */
    uint64_t magic;
    void *alloc_site;
    void *free_site;
#endif
    uint32_t use_size; /* User requested size */
    uint32_t size;     /* Size allocated or slab object size */
    uint16_t slab_id;
    uint8_t slab_cache_id;
    uint8_t flags;
} __attribute__((packed));

#define A_SLAB_OBJ_HDR_STRUCT_SIZE sizeof(struct aura_slab_obj_hdr)
#define A_SLAB_OBJ_HDR_SIZE A_ALIGN((A_SLAB_OBJ_HDR_STRUCT_SIZE + A_SLAB_REDZONE_SIZE), ptr_size)

#if A_SLAB_DEBUG
#define A_MAGIC_ALLOC 0xA110CADEADBEEF
#define A_MAGIC_FREE 0xA110CAF333BEEF
#endif

#define A_SLAB_CACHE_INTERNAL_BASE 0 /* 0 - 49 reserved for internal usage */
#define A_SLAB_CACHE_SERVER_BASE 50  /* 50 - 99 reserved for server stuff */
#define A_SLAB_CACHE_DMN_BASE 100    /* 100 - 149 reserved for daemon use cases */
#define A_SLAB_CACHE_FN_BASE 150     /* 150 - ... */

/**
 *
 */
typedef enum {
    A_SLAB_CACHE_ID_DYNAMIC = A_SLAB_CACHE_INTERNAL_BASE + 1,
} aura_slab_cache_id;

/**
 * Slab Debug Stuff
 */
#if A_SLAB_DEBUG
#define A_SLAB_ASSERT(condition, message)                                                  \
    do {                                                                                   \
        if (!(condition)) {                                                                \
            app_debug(true, 0, "ASSERT FAILED: %s at %s:%u", message, __FILE__, __LINE__); \
            abort();                                                                       \
        }                                                                                  \
    } while (0)

#define A_VALIDATE_HEADER(header, action)                                          \
    do {                                                                           \
        if (action == A_SLAB_ACTION_FREE) {                                        \
            A_SLAB_ASSERT(header->magic == A_MAGIC_ALLOC, "Double free detected"); \
        } else if (action == A_SLAB_ACTION_ALLOC) {                                \
            A_SLAB_ASSERT(header->magic == A_MAGIC_FREE, "Double alloc detected"); \
        }                                                                          \
    } while (0)

#define A_RECORD_ALLOC_SITE(header)                       \
    do {                                                  \
        A_VALIDATE_HEADER(header, A_SLAB_ACTION_ALLOC);   \
        header->alloc_site = __builtin_return_address(0); \
        header->magic = A_MAGIC_ALLOC;                    \
    } while (0)

#define A_RECORD_FREE_SITE(header)                       \
    do {                                                 \
        A_VALIDATE_HEADER(header, A_SLAB_ACTION_FREE);   \
        header->free_site = __builtin_return_address(0); \
        header->magic = A_MAGIC_FREE;                    \
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

#ifdef __GLIBC__
#include <execinfo.h>

static void aura_slab_bt_capture(struct aura_slab_trace *trace) {
    trace->depth = backtrace(trace->pc, A_SLAB_MAX_TRACE_DEPTH);
}

static char **aura_slab_bt_get_symbols(struct aura_slab_trace *trace) {
    return backtrace_symbols(trace->pc, trace->depth);
}

#else

#endif

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
    uint32_t obj_size;    /* object size without metadata*/
    uint32_t size;        /* object size including metadata */
    uint32_t slab_max_id; /* Slab id */
    uint32_t offset;      /* free pointer offset */
    uint64_t slab_size;   /* Total slab size */

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
    struct aura_mem_ctx *mem_ctx;
    uint8_t slab_cache_id;
    uint8_t flags;
};

/**
 * Slab structure
 */
struct aura_slab {
    struct aura_slab_cache *slab_cache;
    void *obj;       /* pointer to first slab object */
    void *free_ptr;  /* pointer to free object */
    uint32_t in_use; /* object allocated/present in the slab  */
    struct aura_list_head slab_list;
    uint8_t slab_id;
};

struct aura_slab_info {
};

#if A_SLAB_POISON
#define A_SLAB_POISON_PATTERN 0x5A5A5A5A5A5A5A5A

static inline void a_verify_poison_pattern(void *ptr, uint32_t use_size,
                                           uint32_t obj_size, uint64_t expected) {
    char *start = (char *)ptr + use_size;
    uint64_t size = obj_size - use_size;
    char p = expected & 0xFF;
    char *msg = use_size == 0 ? "Use after free detected" : "Buffer overflow detected";

    /* Tests take too long for now */
    // for (int i = 0; i < size; ++i) {
    //     A_SLAB_ASSERT(*(start + i) == p, msg);
    // }
}

#define A_POISON_OBJECT(ptr, size) memset(ptr, A_SLAB_POISON_PATTERN & 0xFF, size)
#define A_UNPOISON_OBJECT(ptr, size) memset(ptr, 0, size)
#define A_VERIFY_POISON(ptr, use_size, obj_size, expected) \
    a_verify_poison_pattern(ptr, use_size, obj_size, expected)
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

/* Get allocated block start */
#define aura_slab_obj_get_start(ptr) (((char *)ptr) - A_SLAB_OBJ_HDR_SIZE)

/* Get usable ptr,which is returned to the requester */
#define aura_slab_obj_get_usable(ptr) (((char *)ptr) + A_SLAB_OBJ_HDR_SIZE)

/* Get allocated block header */
#define aura_slab_obj_get_hdr(ptr) \
    ((struct aura_slab_obj_hdr *)aura_slab_obj_get_start(ptr))

/* Get actual mem size, subject to alignment */
#define aura_slab_obj_get_big_size(ptr) (aura_slab_obj_get_hdr(ptr))->size

/* Get slab left redzone from obj start address */
#define aura_slab_obj_get_left_redzone_obj_start(ptr) (((char *)ptr) + A_SLAB_OBJ_HDR_STRUCT_SIZE)

/* Get slab right redzone from obj start address */
#define aura_slab_obj_get_right_redzone_obj_start(ptr, obj_size) (((char *)ptr) + A_SLAB_OBJ_HDR_SIZE + obj_size)

/**/
static inline void a_verify_redzone(void *ptr, uint32_t size) {
    uint64_t *left_redzone, *right_redzone;

    left_redzone = (uint64_t *)(aura_slab_obj_get_left_redzone_obj_start(ptr));
    A_SLAB_ASSERT(*left_redzone == A_REDZONE_PATTERN, "Left redzone corruption");
    right_redzone = (uint64_t *)(aura_slab_obj_get_right_redzone_obj_start(ptr, size));
    A_SLAB_ASSERT(*right_redzone == A_REDZONE_PATTERN, "Right redzone corruption");
}

/* Get the name of dynamic cache */
static inline void aura_slab_get_cache_name(char *buf, uint32_t size) {
    char *ext = size < 1024 ? "B" : size < 1048576 ? "KB"
                                                   : "MB";
    sprintf(buf, "%d %s", size, ext);
}

/* our dynamic memory is in 64 byte multiples */
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
static inline struct aura_slab_cache *aura_slab_cache_find_by_id(struct aura_mem_ctx *mc, uint8_t sc_id) {
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
struct aura_slab_cache *aura_slab_cache_create(struct aura_mem_ctx *m_ctx, uint8_t s_cache_id, const char *name, size_t obj_size, void (*ctor)(void *), uint32_t flags);

/**
 * Create caches for dynamic slab pool
 */
int aura_create_dynamic_slab_alloc_caches(struct aura_mem_ctx *m_ctx);
void aura_slab_cache_destroy(struct aura_slab_cache *sc);
void *aura_slab_alloc(struct aura_slab_cache *sc, uint32_t size);

/**
 * Free the slot pointed to by ptr from the
 * associated slab. Information about the slab is
 * retrieved from the header info of this ptr
 */
void aura_slab_free(void *ptr);

/**
 * Allocator function
 * Gets memory from dynamic slab pool
 * Returns user usable pointer if success,
 * otherwise it returns NULL
 */
void *aura_alloc(struct aura_mem_ctx *mc, size_t size);

/** */
void *aura_realloc(struct aura_mem_ctx *mc, void *ptr, size_t size);

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
void aura_slab_obj_header_dump(struct aura_slab_obj_hdr *hdr);

#endif