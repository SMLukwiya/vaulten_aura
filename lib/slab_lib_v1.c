#include "bug_lib.h"
#include "compiler_lib.h"
#include "error_lib.h"
#include "list_lib.h"
#include "memory_lib.h"
#include "slab_lib.h"
#include "utils_lib.h"

/**
 * Random allocations could
 * possibly be satisfied from here!
 */
uint32_t dynamic_slab_pool[] = {
  64,
  128,
  192,
  256,
  320,
  384,
  448,
  512,
  576,
  640,
  704,
  768,
  832,
  896,
  960,
  1024,
  /**/
};

static inline uint32_t a_num_of_objs(uint32_t degree, uint32_t size) {
    return ((A_PAGE_SIZE << degree) / size);
}

/**
 * We try and calculate what order of pages would gives us
 * minimum waste!
 */
static inline uint32_t a_calculate_slab_order_2(uint32_t min_order, uint32_t max_order, uint32_t size) {
    uint32_t order, slab_size, rem, fraction, final_order, min_rem;

    /* default remainder */
    min_rem = ((uint32_t)A_PAGE_SIZE << min_order) % size;
    final_order = max_order;

    for (order = min_order; order <= max_order; ++order) {
        slab_size = (uint32_t)A_PAGE_SIZE << order;

        rem = slab_size % size;
        if (rem < min_rem) {
            final_order = a_min(order, final_order);
            min_rem = rem;
        }
    }

    return final_order;
}

/**
 * Determine the order and distribution of data within a slap object
 */
static inline void a_calculate_sizes(struct aura_slab_cache *s) {
    uint32_t size = s->size;
    uint32_t order;

    size = A_ALIGN(size, ptr_size);
    s->size = size;
    order = a_calculate_slab_order_2(0, 2, size);
    s->objs_per_slab = a_num_of_objs(2, size);
    s->slab_size = A_PAGE_SIZE << order;
}

struct aura_slab_cache *aura_slab_cache_create(struct aura_memory_ctx *m_ctx,
                                               uint8_t s_cache_id, const char *name,
                                               size_t obj_size, void (*ctor)(void *),
                                               uint32_t flags) {
    struct aura_slab_cache *s_cache;
    int err;

    A_BUG_ON_2(s_cache_id == 0, true);

    obj_size = A_ALIGN(obj_size, ptr_size);
    s_cache = calloc(1, sizeof(*s_cache));
    if (s_cache == NULL)
        return NULL;

    s_cache->slab_cache_id = s_cache_id;
    snprintf(s_cache->name, A_MAX_SLAB_NAME - 1, "%s", name);
    s_cache->name[A_MAX_SLAB_NAME] = '\0';
    s_cache->obj_size = obj_size;
    s_cache->size = obj_size + A_OBJECT_HEADER_SIZE + (A_REDZONE_SIZE * 2);
    s_cache->ctor = ctor;
    s_cache->flags = flags;
    s_cache->mem_ctx = m_ctx;
    a_calculate_sizes(s_cache);

    a_list_head_init(&s_cache->cache_list);
    a_list_head_init(&s_cache->full_list);
    a_list_head_init(&s_cache->free_list);
    a_list_head_init(&s_cache->partial_list);
    a_list_add_tail(&m_ctx->slab_cache_list, &s_cache->cache_list);

    return s_cache;
}

/**
 * Setup the header for a slab object, and
 * add debug and checking info if applicable
 */
static void *a_setup_object(struct aura_slab_cache *sc, void *obj) {
    char *user_ptr;
    struct aura_object_hdr *obj_hdr;
    uint64_t *left_redzone, *right_redzone;
    int i;

    obj_hdr = (struct aura_object_hdr *)obj;
    obj_hdr->slab_cache_id = sc->slab_cache_id;
    obj_hdr->slab_id = sc->slab_max_id++;
    obj_hdr->size = sc->obj_size;
    obj_hdr->mem_ctx = sc->mem_ctx;
    user_ptr = obj + A_OBJECT_HEADER_SIZE + A_REDZONE_SIZE;

#if A_SLAB_REDZONE
    // left_redzone = (uint64_t *)obj + A_OBJECT_HEADER_SIZE;
    // right_redzone = (uint64_t *)user_ptr + sc->obj_size;
    /** @todo, there may be no need for this */
    for (i = 0; i < A_REDZONE_SIZE / sizeof(uint64_t); ++i) {
        // left_redzone[i] = A_REDZONE_PATTERN;
        // right_redzone[i] = A_REDZONE_PATTERN;
    }
#endif

#if A_SLAB_POISON
    // A_POISON_OBJECT(user_ptr, sc->obj_size);
#endif
    return obj;
}

/**
 * Insert a free pointer into a slab object
 */
static inline void a_set_free_pointer(struct aura_slab_cache *sc, void *object, void *free_ptr) {
    char *user_ptr;

    struct aura_object_hdr *obj_hdr;

    obj_hdr = (struct aura_object_hdr *)object;
    obj_hdr->next = free_ptr;
}

/**
 * Extract the free pointer stored in the slab object
 */
static inline void *a_get_free_pointer(void *object) {
    struct aura_object_hdr *obj_hdr;
    char *user_ptr;
    uint64_t next_ptr;

    obj_hdr = (struct aura_object_hdr *)object;
    return obj_hdr->next;
}

/**
 * Creates a new slab for the given slab cache
 */
struct aura_slab *a_slab_create(struct aura_slab_cache *sc) {
    struct aura_slab *slab;
    uint32_t slab_size;
    uint32_t obj_stride;
    struct aura_object_hdr *obj_hdr;
    char *slab_mem, *obj_start, *next, *p;
    int i;

    slab_size = sc->slab_size;
    /* Let's store slab header outside allocation area */
    slab = calloc(1, sizeof(*slab));
    if (!slab)
        return NULL;

    obj_start = aligned_alloc(64, slab_size);
    if (!obj_start) {
        free(slab);
        return NULL;
    }

    // no debug stuff for now

    slab->slab_cache = sc;
    a_list_head_init(&slab->slab_list);
    slab_mem = obj_start;
    obj_stride = sc->size;

    obj_start = a_setup_object(sc, slab_mem);
    slab->obj = slab->free_list = obj_start;
    for (i = 0, p = obj_start; i < sc->objs_per_slab - 1; ++i, p = next) {
        next = p + obj_stride;
        next = a_setup_object(sc, next);
        a_set_free_pointer(sc, p, next);
    }

    sc->stats.total_slabs++;
    sc->stats.total_memory += sc->slab_size + sizeof(*slab);
    /** @todo: calculate wasted memory */
    a_set_free_pointer(sc, p, NULL);
    a_list_add_tail(&sc->free_list, &slab->slab_list);

    return slab;
}

/* Free a slab */
void a_slab_destroy(struct aura_slab *s) {
    void *slab_mem;

    if (unlikely(s))
        return;

    slab_mem = s->obj;
    if (likely(slab_mem)) {
        free(slab_mem);
    }
    free(s);
}

/**
 * Loops through cache, delete all slab lists
 * Removes cache from cache list and frees cache memory
 */
void aura_slab_cache_destroy(struct aura_slab_cache *sc) {
    struct aura_slab *s, *_s;

    if (unlikely(sc))
        return;

    a_list_for_each_safe_to_delete(s, _s, &sc->free_list, slab_list) {
        a_slab_destroy(s);
        a_list_delete(&s->slab_list);
    }

    a_list_for_each_safe_to_delete(s, _s, &sc->partial_list, slab_list) {
        a_slab_destroy(s);
        a_list_delete(&s->slab_list);
    }

    a_list_for_each_safe_to_delete(s, _s, &sc->full_list, slab_list) {
        a_slab_destroy(s);
        a_list_delete(&s->slab_list);
    }

    a_list_delete(&sc->cache_list);
    free(sc);
}

/* Retrieve object size without metadata */
static inline unsigned int slab_cache_size(struct aura_slab_cache *s_cache) {
    return s_cache->obj_size;
}

static inline bool slap_update_free_list() {}

static inline void set_original_size(struct aura_slab_cache *s, void *obj, unsigned int orig_size) {
    /**
     * This is the original requested size by the user
     * Only for proper debug
     * check if we are in debug mode
     * set original size in metadata area (could be per object)
     */
}

static inline unsigned int get_original_size(struct aura_slab_cache *s, void *obj) {
    /**
     * If not in debug mode, return the cache obj_size
     * then return saved metadata size
     */
}

/**
 * Allocate an object from a slab from the
 * given cache
 */
void *aura_slab_alloc(struct aura_slab_cache *sc) {
    struct aura_slab *slab;
    struct aura_object_hdr *hdr;
    void *obj, *next_free, *user_ptr;

    A_BUG_ON_2(!sc, true);
    if (a_list_is_empty(&sc->partial_list)) {
        sc->stats.cache_misses++;
        if (a_list_is_empty(&sc->free_list)) {
            slab = a_slab_create(sc);
        } else {
            slab = a_list_first_entry(&sc->free_list, struct aura_slab, slab_list);
        }
        /**
         * If we were on the free list,
         * we move to the partial list
         */
        a_list_delete(&slab->slab_list);
        a_list_add_tail(&sc->partial_list, &slab->slab_list);
    } else {
        slab = a_list_first_entry(&sc->partial_list, struct aura_slab, slab_list);
    }

    obj = slab->free_list;
    A_BUG_ON_2(!obj, true); /* corrupted free object */

    next_free = a_get_free_pointer(obj);
    slab->free_list = next_free;
    slab->in_use++;
    A_BUG_ON_2(slab->in_use > sc->objs_per_slab, true);

    if (slab->in_use == sc->objs_per_slab) {
        a_list_delete(&slab->slab_list);
        a_list_add_tail(&sc->full_list, &slab->slab_list);
    }

    sc->stats.total_allocations++;
    sc->stats.active_allocations++;
    // high water mark

    hdr = (struct aura_object_hdr *)obj;
    user_ptr = (char *)obj + A_OBJECT_HEADER_SIZE + A_REDZONE_SIZE;
    aura_slab_obj_header_dump(hdr);

#if A_SLAB_DEBUG
    A_RECORD_ALLOC_SITE(hdr);
// A_VALIDATE_HEADER(hdr);
#endif

#if A_SLAB_POISON
    A_VERIFY_POISON(obj, sc->obj_size, A_SLAB_ALLOC_POISON_PATTERN);
#endif

#if A_SLAB_REDZONE
    // verify redzone
#endif

    return user_ptr;
}

/**
 * Find the slab with the given ID
 * from the list of slabs on a cache
 */
static inline struct aura_slab *a_find_slab(struct aura_slab_cache *sc, uint8_t slab_id) {
    struct aura_slab *slab;

    /* try partial list first */
    a_list_for_each(slab, &sc->partial_list, slab_list) {
        if (slab->slab_id == slab_id && slab->slab_cache->slab_cache_id == sc->slab_cache_id)
            return slab;
    }

    a_list_for_each(slab, &sc->full_list, slab_list) {
        if (slab->slab_id == slab_id && slab->slab_cache->slab_cache_id == sc->slab_cache_id)
            return slab;
    }

    return NULL;
}

void aura_slab_free(void *ptr) {
    struct aura_slab_cache *sc;
    struct aura_slab *slab;
    struct aura_object_hdr *hdr;
    uint32_t index;

    if (unlikely(ptr)) {
        return;
    }

    hdr = (struct aura_object_hdr *)((char *)ptr - A_OBJECT_HEADER_SIZE - A_REDZONE_SIZE);

#if A_SLAB_DEBUG
    // A_VALIDATE_HEADER(hdr);
    if (hdr->magic == A_MAGIC_FREE) { /** @todo: this could be the validation function when freeing */
        // double free detected
        return;
    }
    A_RECORD_FREE_SITE(hdr);
#endif

    /* dynamic slab pool */
    if (hdr->slab_cache_id == A_SLAB_CACHE_ID_DYAMIC) {
        index = aura_get_dynamic_slab_index(hdr->size);
        sc = hdr->mem_ctx->dynamic_slab_caches[index];
    } else {
        sc = aura_slab_cache_find_by_id(hdr->mem_ctx, hdr->slab_cache_id);
    }

    A_BUG_ON_2(sc == NULL, true);
    A_BUG_ON_2(hdr->size != sc->obj_size, true);

    slab = a_find_slab(sc, hdr->slab_id);
    A_BUG_ON_2(slab == NULL, true);

#if A_SLAB_REDZONE
    // verify_redzone();
#endif

#if A_SLAB_POISON
    A_UNPOISON_OBJECT(ptr, sc->obj_size);
#endif

    a_set_free_pointer(sc, ptr, slab->free_list);
    slab->free_list = ptr;

    sc->stats.total_frees++;
    sc->stats.active_allocations--;

    if (slab->in_use == sc->objs_per_slab) {
        /* If we were in full list, move to partial */
        a_list_delete(&slab->slab_list);
        a_list_add_tail(&sc->partial_list, &slab->slab_list);
    } else if (slab->in_use == 1) {
        a_list_delete(&slab->slab_list);
        a_list_add_tail(&sc->free_list, &slab->slab_list);
    }
    slab->in_use--;
}

bool aura_create_dynamic_slab_alloc_caches(struct aura_memory_ctx *m_ctx) {
    struct aura_slab_cache *sc;
    struct aura_slab *slab;
    uint32_t i, idx, max_size, obj_size;
    uint32_t arr_size;

    arr_size = ARRAY_SIZE(dynamic_slab_pool);
    max_size = dynamic_slab_pool[arr_size - 1];

    for (i = 0; i < arr_size; ++i) {
        obj_size = dynamic_slab_pool[i];
        sc = aura_slab_cache_create(m_ctx, A_SLAB_CACHE_ID_DYAMIC, a_get_slab_name(obj_size), obj_size, NULL, 0);
        if (!sc) {
            return false;
        }
        slab = a_slab_create(sc);
        if (!slab) {
            aura_slab_cache_destroy(sc);
            return false;
        }
        m_ctx->dynamic_slab_caches[i] = sc;
    }

    return true;
}

void *aura_alloc(struct aura_memory_ctx *mc, size_t size) {
    struct aura_slab_cache *sc;
    uint32_t index;
    void *ptr;
    struct aura_object_hdr *hdr;

    if (size == 0 || size > INT32_MAX)
        return NULL;

    index = aura_get_dynamic_slab_index(size); /* our dynamic memory is in 64 byte multiples */
    if (index > 15) {
        /* size exceed max dynamic memory cache */
        /** @todo: get from buddy */
        ptr = malloc(size + A_OBJECT_HEADER_SIZE + A_REDZONE_SIZE);
        hdr = (struct aura_object_hdr *)ptr;
        hdr->mem_ctx == NULL;
        hdr->size = size;
        ptr += A_OBJECT_HEADER_SIZE + A_REDZONE_SIZE;
    } else {
        sc = mc->dynamic_slab_caches[index];
        ptr = aura_slab_alloc(sc);
    }

    return ptr;
}

void *aura_realloc(struct aura_memory_ctx *mc, void *ptr, size_t size) {
    struct aura_slab_cache *sc;
    uint32_t index;
    void *_ptr;
    struct aura_object_hdr *hdr;
    size_t old_size;

    if (ptr == NULL)
        return aura_alloc(mc, size);

    hdr = (struct aura_object_hdr *)(((char *)ptr) - A_OBJECT_HEADER_SIZE - A_REDZONE_SIZE);
    index = aura_get_dynamic_slab_index(size);
    old_size = hdr->size;

    if (index > 15) {
        if (hdr->mem_ctx == NULL) {
            _ptr = realloc(ptr, size + A_OBJECT_HEADER_SIZE + A_REDZONE_SIZE);
        } else {
            /* switching to malloc */
            _ptr = malloc(size + A_OBJECT_HEADER_SIZE + A_REDZONE_SIZE);
            memcpy(_ptr + A_OBJECT_HEADER_SIZE + A_REDZONE_SIZE, ptr, old_size);
            aura_free(ptr);
        }
        hdr = (struct aura_object_hdr *)_ptr;
        hdr->mem_ctx == NULL;
        hdr->size = size;
    } else {
        if (hdr->mem_ctx == NULL) {
            _ptr = aura_alloc(mc, size);
            memcpy(_ptr, ptr, old_size);
            free(ptr);
        } else {
            _ptr = aura_alloc(mc, size);
            memcpy(_ptr + A_OBJECT_HEADER_SIZE + A_REDZONE_SIZE, ptr, old_size);
            hdr = (struct aura_object_hdr *)_ptr;
            hdr->mem_ctx == NULL;
            hdr->size = size;
            aura_free(ptr);
        }
    }
    return _ptr;
}

void aura_free(void *ptr) {
    struct aura_object_hdr *hdr;

    hdr = (struct aura_object_hdr *)(((char *)ptr) - A_OBJECT_HEADER_SIZE - A_REDZONE_SIZE);
    if (hdr->mem_ctx == NULL) {
        /* malloc allocated */
        ptr -= (A_OBJECT_HEADER_SIZE + A_REDZONE_SIZE);
        free(ptr);
    } else {
        aura_slab_free(ptr);
    }
}

/**
 * discard empty slabs and promotes the slab filled up to the head.
 * Create a per cache type version of this function (maybe not, since I must fill a list before I allocate a new one)
 */
static int slab_cache_shrink_(struct aura_slab_cache *s) {
    return 1;
}

int slab_cache_shrink(struct aura_slab_cache *s_cache) {
    slab_cache_shrink(s_cache);
}

static void list_slab_objects(struct aura_slab_cache *s, struct aura_slab *slab) {
}

void aura_slab_cache_validate(struct aura_slab_cache *sc) {
    struct aura_slab *s;

    a_list_for_each(s, &sc->partial_list, slab_list) {
        // a_validate_slab_integrity(s);
    }

    a_list_for_each(s, &sc->full_list, slab_list) {
        // a_validate_slab_integrity(s);
    }

    app_debug(true, 0, "Slab cache validation completed successfully");
}

void aura_slab_dump(struct aura_slab *slab) {
    app_debug(true, 0, "SLAB DUMP");
    app_debug(true, 0, "    Slab id: %zu", slab->slab_id);
    app_debug(true, 0, "    Slab cache id: %zu", slab->slab_cache->slab_cache_id);
    app_debug(true, 0, "    Object size: %zu", slab->slab_cache->obj_size);
    app_debug(true, 0, "    Slab size: %zu", slab->slab_cache->slab_size);
    app_debug(true, 0, "    Total in use: %zu", slab->in_use);
    app_debug(true, 0, "    Total per slab: %zu", slab->slab_cache->objs_per_slab);
    app_debug(true, 0, "    First slab object: %p", slab->obj);
    app_debug(true, 0, "    First free object: %p", slab->free_list);
}

/**/
void aura_slab_cache_dump(struct aura_slab_cache *sc) {
    struct aura_slab *s;

    app_debug(true, 0, "SLAB CACHE DUMP: %s ===", sc->name);
    app_debug(true, 0, "    Slab Cache id: %zu", sc->slab_cache_id);
    app_debug(true, 0, "    Object size: %zu", sc->obj_size);
    app_debug(true, 0, "    Object + meta size: %zu", sc->size);
    app_debug(true, 0, "    Slab size: %zu", sc->slab_size);
    app_debug(true, 0, "    Objects/slab: %zu", sc->objs_per_slab);

    app_debug(true, 0, "    STATS");
    app_debug(true, 0, "        Total allocations: %zu", sc->stats.total_allocations);
    app_debug(true, 0, "        Total frees: %zu", sc->stats.total_frees);
    app_debug(true, 0, "        Active allocations: %zu", sc->stats.active_allocations);
    app_debug(true, 0, "        Total memory: %zu", sc->stats.total_memory);
    app_debug(true, 0, "        Total wasted memory: %zu", sc->stats.wasted_memory);
    app_debug(true, 0, "        slab Count: %zu", sc->stats.total_slabs);

    app_debug(true, 0, "    PARTIAL LIST");
    a_list_for_each(s, &sc->partial_list, slab_list) {
        aura_slab_dump(s);
    }

    app_debug(true, 0, "    FULL LIST");
    a_list_for_each(s, &sc->full_list, slab_list) {
        aura_slab_dump(s);
    }

    app_debug(true, 0, "    FREE LIST");
    a_list_for_each(s, &sc->free_list, slab_list) {
        aura_slab_dump(s);
    }
}

/** */
void aura_slab_obj_header_dump(struct aura_object_hdr *hdr) {
    app_debug(true, 0, "SLAB OBJ HEADER");
    app_debug(true, 0, "    Slab id: %u", hdr->slab_id);
    app_debug(true, 0, "    Slab cache id: %u", hdr->slab_cache_id);
    app_debug(true, 0, "    Size: %u,", hdr->size);
    app_debug(true, 0, "    Mem ctx: %p", hdr->mem_ctx);
    app_debug(true, 0, "    Magic: %lu", hdr->magic);
}