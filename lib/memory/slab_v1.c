#include "bug_lib.h"
#include "compiler_lib.h"
#include "error_lib.h"
#include "slab.h"
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
static inline uint32_t a_calculate_slab_order(uint32_t min_order, uint32_t max_order, uint32_t size) {
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
static inline void a_calculate_slab_sizes(struct aura_slab_cache *sc) {
    uint32_t size = sc->size;
    uint32_t order;

    order = a_calculate_slab_order(0, 2, size);
    sc->objs_per_slab = a_num_of_objs(order, size);
    sc->slab_size = A_PAGE_SIZE << order;
}

struct aura_slab_cache *aura_slab_cache_create(struct aura_mem_ctx *m_ctx,
                                               uint8_t s_cache_id, const char *name,
                                               size_t obj_size, void (*ctor)(void *),
                                               uint32_t flags) {
    struct aura_slab_cache *s_cache;
    int err;

    A_BUG_ON_2(s_cache_id == 0, true);

    obj_size = A_ALIGN(obj_size, ptr_size);
    s_cache = calloc(1, sizeof(*s_cache));
    if (!s_cache)
        return NULL;

    s_cache->slab_cache_id = s_cache_id;
    snprintf(s_cache->name, A_MAX_SLAB_NAME - 1, "%s", name);
    s_cache->obj_size = obj_size;
    s_cache->size = A_ALIGN(obj_size + A_SLAB_OBJ_HDR_SIZE + A_SLAB_REDZONE_SIZE, ptr_size);
    s_cache->ctor = ctor;
    s_cache->flags = flags;
    s_cache->mem_ctx = m_ctx;
    a_calculate_slab_sizes(s_cache);

    aura_list_head_init(&s_cache->cache_list);
    aura_list_head_init(&s_cache->full_list);
    aura_list_head_init(&s_cache->free_list);
    aura_list_head_init(&s_cache->partial_list);
    aura_list_add_tail(&m_ctx->slab_cache_list, &s_cache->cache_list);

    return s_cache;
}

/**
 * Setup the header for a slab object, and
 * add debug and checking info if applicable
 */
static void a_set_slab_obj(struct aura_slab_cache *sc, void *obj) {
    struct aura_slab_obj_hdr *obj_hdr;
    uint64_t *left_redzone, *right_redzone;
    int i;

    obj_hdr = (struct aura_slab_obj_hdr *)obj;
    memset(obj_hdr, 0, sizeof(*obj_hdr));
    obj_hdr->slab_cache_id = sc->slab_cache_id;
    obj_hdr->slab_id = sc->slab_max_id;
    obj_hdr->size = sc->obj_size;
    obj_hdr->mem_ctx = sc->mem_ctx;
    obj_hdr->flags |= A_MEM_MODE_SLAB;
    obj_hdr->next = NULL;
#if A_SLAB_DEBUG
    obj_hdr->magic = A_MAGIC_FREE;
#endif

#if A_SLAB_REDZONE
    left_redzone = (uint64_t *)(aura_slab_obj_get_left_redzone_obj_start(obj));
    *left_redzone = A_REDZONE_PATTERN;
    right_redzone = (uint64_t *)(aura_slab_obj_get_right_redzone_obj_start(obj, obj_hdr->size));
    *right_redzone = A_REDZONE_PATTERN;
#endif

#if A_SLAB_POISON
    A_POISON_OBJECT(aura_slab_obj_get_usable(obj), obj_hdr->size);
#endif
}

/**
 * Insert a free pointer into a slab object
 */
static inline void a_set_free_pointer(void *object, void *free_ptr) {
    ((struct aura_slab_obj_hdr *)object)->next = free_ptr;
}

/**
 * Extract the free pointer stored in the slab object
 */
static inline void *a_get_free_pointer(void *object) {
    return ((struct aura_slab_obj_hdr *)object)->next;
}

/**
 * Creates a new slab for the given slab cache
 */
struct aura_slab *a_slab_create(struct aura_slab_cache *sc) {
    struct aura_slab *slab;
    uint32_t obj_stride;
    char *obj_start, *next, *p;
    int i;

    /* Let's store slab header outside allocation area */
    slab = calloc(1, sizeof(*slab));
    if (!slab)
        return NULL;

    obj_start = calloc(1, sc->slab_size);
    if (!obj_start) {
        sys_debug(true, errno, "a_slab_create: aligned_alloc");
        free(slab);
        return NULL;
    }

    aura_list_head_init(&slab->slab_list);
    slab->slab_cache = sc;
    obj_stride = sc->size;
    slab->slab_id = ++sc->slab_max_id;

    /* Initialize the slab objects */
    a_set_slab_obj(sc, obj_start);
    /* Set slab objects and free list */
    slab->obj = slab->free_ptr = obj_start;
    for (i = 0, p = obj_start; i < sc->objs_per_slab - 1; ++i, p = next) {
        next = p + obj_stride;
        a_set_slab_obj(sc, next);
        a_set_free_pointer(p, next);
    }

    a_set_free_pointer(p, NULL);
    sc->stats.total_slabs++;
    sc->stats.total_memory += sc->size + sizeof(*slab);
    /** @todo: calculate wasted memory */
    aura_list_add(&sc->free_list, &slab->slab_list);

    return slab;
}

/* Free a slab */
void a_slab_destroy(struct aura_slab *s) {
    void *slab_mem;

    if (!s)
        return;

    slab_mem = s->obj;
    if (slab_mem)
        free(slab_mem);

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

    while (!aura_list_is_empty(&sc->free_list)) {
        a_list_dequeue(s, &sc->free_list, slab_list);
        a_slab_destroy(s);
    }

    while (!aura_list_is_empty(&sc->partial_list)) {
        a_list_dequeue(s, &sc->partial_list, slab_list);
        a_slab_destroy(s);
    }

    while (!aura_list_is_empty(&sc->full_list)) {
        a_list_dequeue(s, &sc->full_list, slab_list);
        a_slab_destroy(s);
    }

    aura_list_delete(&sc->cache_list);
    free(sc);
}

/* Retrieve object size without metadata */
static inline unsigned int slab_cache_size(struct aura_slab_cache *s_cache) {
    return s_cache->obj_size;
}

/**
 * Allocates an object from a slab from the
 * given cache, returns the user usable ptr.
 */
void *aura_slab_alloc(struct aura_slab_cache *sc, uint32_t size) {
    struct aura_slab *slab;
    struct aura_slab_obj_hdr *hdr;
    void *obj, *user_ptr;
    uint32_t objs_per_slab = sc->objs_per_slab;

    A_BUG_ON_2(!sc, true);
    if (!aura_list_is_empty(&sc->partial_list)) {
        slab = a_list_first_entry(&sc->partial_list, struct aura_slab, slab_list);
    } else {

        if (aura_list_is_empty(&sc->free_list)) {
            sc->stats.cache_misses++;
            slab = a_slab_create(sc);
            if (!slab)
                return NULL;
        } else {
            slab = a_list_first_entry(&sc->free_list, struct aura_slab, slab_list);
        }
    }

    A_BUG_ON_2(slab->in_use >= objs_per_slab, true);
    A_BUG_ON_2(!slab->free_ptr, true); /* corrupted free object */

    obj = slab->free_ptr;
    slab->free_ptr = a_get_free_pointer(obj);

    /* Move to full list when there are no free objects */
    ++slab->in_use;
    if (slab->in_use == objs_per_slab) {
        aura_list_move(&sc->full_list, &slab->slab_list);
    } else if (slab->in_use == 1)
        /* Move to partial list if we were on the free list */
        aura_list_move(&sc->partial_list, &slab->slab_list);

    A_BUG_ON_2(slab->in_use != objs_per_slab && !slab->free_ptr, true);

    user_ptr = aura_slab_obj_get_usable(obj);

    sc->stats.total_allocations++;
    sc->stats.active_allocations++;

    hdr = (struct aura_slab_obj_hdr *)obj;
#if A_SLAB_DEBUG
    A_RECORD_ALLOC_SITE(hdr);
#endif

#if A_SLAB_POISON
    A_VERIFY_POISON(user_ptr, hdr->use_size, hdr->size, A_SLAB_POISON_PATTERN);
    A_UNPOISON_OBJECT(user_ptr, hdr->use_size);
#endif

#if A_SLAB_REDZONE
    a_verify_redzone(obj, hdr->size);
#endif

    hdr->use_size = size;
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
    struct aura_slab_obj_hdr *hdr;
    struct aura_slab *slab;
    uint32_t index;

    if (!ptr)
        return;

    hdr = aura_slab_obj_get_hdr(ptr);
    A_BUG_ON_2((hdr->flags & A_MEM_MODE_SLAB) == 0, true);

    /* dynamic slab pool */
    if (hdr->slab_cache_id == A_SLAB_CACHE_ID_DYNAMIC) {
        index = aura_get_dynamic_slab_index(hdr->size);
        sc = hdr->mem_ctx->dynamic_slab_caches[index];
    } else {
        sc = aura_slab_cache_find_by_id(hdr->mem_ctx, hdr->slab_cache_id);
    }

    A_BUG_ON_2(!sc, true);
    A_BUG_ON_2(hdr->size != sc->obj_size, true);

    slab = a_find_slab(sc, hdr->slab_id);
    A_BUG_ON_2(!slab, true);
    A_BUG_ON_2(slab->in_use < sc->objs_per_slab && !slab->free_ptr, true);

#if A_SLAB_DEBUG
    A_RECORD_FREE_SITE(hdr);
#endif

#if A_SLAB_REDZONE
    a_verify_redzone((void *)hdr, hdr->size);
#endif

#if A_SLAB_POISON
    A_VERIFY_POISON(ptr, hdr->use_size, hdr->size, A_SLAB_POISON_PATTERN);
    A_POISON_OBJECT(ptr, hdr->size);
#endif

    void *free_ = slab->free_ptr;
    a_set_free_pointer(aura_slab_obj_get_start(ptr), slab->free_ptr);
    slab->free_ptr = aura_slab_obj_get_start(ptr);

    ++sc->stats.total_frees;
    --sc->stats.active_allocations;

    if (slab->in_use == sc->objs_per_slab) {
        /* If we were in full list, move to partial */
        aura_list_move(&sc->partial_list, &slab->slab_list);
    } else if (slab->in_use == 1) {
        aura_list_move(&sc->free_list, &slab->slab_list);
    }
    --slab->in_use;
    hdr->use_size = 0;
}

int aura_create_dynamic_slab_alloc_caches(struct aura_mem_ctx *m_ctx) {
    struct aura_slab_cache *sc;
    struct aura_slab *slab;
    uint32_t i, obj_size;
    char name[64];

    for (i = 0; i < ARRAY_SIZE(dynamic_slab_pool); ++i) {
        obj_size = dynamic_slab_pool[i];
        aura_slab_get_cache_name(name, obj_size);
        sc = aura_slab_cache_create(m_ctx, A_SLAB_CACHE_ID_DYNAMIC, name, obj_size, NULL, 0);
        if (!sc) {
            return -1;
        }
        slab = a_slab_create(sc);
        if (!slab) {
            aura_slab_cache_destroy(sc);
            return -1;
        }
        m_ctx->dynamic_slab_caches[i] = sc;
    }

    return 0;
}

void *aura_alloc(struct aura_mem_ctx *mc, size_t size) {
    struct aura_slab_cache *sc;
    struct aura_slab_obj_hdr *hdr;
    uint32_t index;
    void *ptr;

    if (size == 0 || size > UINT32_MAX)
        return NULL;

    /**
     * There are some usecase that just require simple malloc
     * like testing some sections that use memory context
     */
    index = aura_get_dynamic_slab_index(size);
    if (index > 15 || !mc) {
        /* size exceed max dynamic memory cache */
        /** @todo: get from buddy */
        ptr = calloc(1, size + A_SLAB_OBJ_HDR_SIZE);
        if (!ptr)
            return NULL;
        hdr = (struct aura_slab_obj_hdr *)ptr;
        memset(hdr, 0, sizeof(*hdr));
        hdr->flags |= A_MEM_MODE_MALLOC;
        hdr->size = size;
        ptr = aura_slab_obj_get_usable(ptr);
    } else {
        sc = mc->dynamic_slab_caches[index];
        ptr = aura_slab_alloc(sc, size);
    }

    return ptr;
}

void *aura_realloc(struct aura_mem_ctx *mc, void *ptr, size_t size) {
    struct aura_slab_cache *sc;
    struct aura_slab_obj_hdr *hdr;
    size_t old_size;
    uint32_t index;
    void *_ptr;

    if (!ptr)
        return aura_alloc(mc, size);

    hdr = aura_slab_obj_get_hdr(ptr);
    index = aura_get_dynamic_slab_index(size);
    old_size = hdr->size;

    if (index > 15) {
        /* If was already using malloc */
        if (hdr->flags & A_MEM_MODE_MALLOC) {
            _ptr = realloc(aura_slab_obj_get_start(ptr), size + A_SLAB_OBJ_HDR_SIZE);
            if (!_ptr)
                return NULL;
        } else {
            /**
             * switching from slab to malloc
             * size is greater than old_size at this point.
             */
            _ptr = calloc(1, size + A_SLAB_OBJ_HDR_SIZE);
            if (!_ptr)
                return NULL;
            memcpy(aura_slab_obj_get_usable(_ptr), ptr, a_min(size, old_size));
            aura_free(ptr);
        }

        hdr = (struct aura_slab_obj_hdr *)_ptr;
        memset(hdr, 0, sizeof(*hdr));
        hdr->flags |= A_MEM_MODE_MALLOC;
        hdr->size = size;
        _ptr = aura_slab_obj_get_usable(_ptr);
    } else {
        /* switching back from malloc */
        sc = mc->dynamic_slab_caches[index];
        if (hdr->flags & A_MEM_MODE_MALLOC) {
            _ptr = aura_slab_alloc(sc, size);

            if (!_ptr)
                return NULL;
            memcpy(_ptr, ptr, a_min(size, old_size));

            aura_slab_free(ptr);
        } else {
            /**
             * If size is smaller than old_size(obj size for slab), then
             * we can use the same allocated block with
             * the update metadata, actual_size
             * of the allocated block haven't changed.
             */
            if (size <= old_size) {
                _ptr = ptr;
            } else {
                _ptr = aura_slab_alloc(sc, size);
                if (!_ptr)
                    return NULL;
                memcpy(_ptr, ptr, a_min(size, old_size));

                aura_slab_free(ptr);
            }
        }
    }

    return _ptr;
}

void aura_free(void *ptr) {
    struct aura_slab_obj_hdr *hdr;

    if (!ptr)
        return;

    hdr = aura_slab_obj_get_hdr(ptr);
    if (hdr->flags & A_MEM_MODE_MALLOC) {
        /* malloc allocated */
        ptr = aura_slab_obj_get_start(ptr);
        free(ptr);
    } else {
        aura_slab_free(ptr);
    }
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
    app_debug(true, 0, "    First free object: %p", slab->free_ptr);
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
void aura_slab_obj_header_dump(struct aura_slab_obj_hdr *hdr) {
    app_debug(true, 0, "SLAB OBJ HEADER");
    app_debug(true, 0, "    Slab cache id: %u", hdr->slab_cache_id);
    app_debug(true, 0, "    Slab id: %u", hdr->slab_id);
    app_debug(true, 0, "    Size: %u,", hdr->size);
    app_debug(true, 0, "    Mem ctx: %p", hdr->mem_ctx);
    app_debug(true, 0, "    Next: %p", hdr->next);
    app_debug(true, 0, "    Magic: %lu", hdr->magic);
    app_debug(true, 0, "    Alloc site: %p", hdr->alloc_site);
    app_debug(true, 0, "    Free site: %p", hdr->free_site);
    app_debug(true, 0, "    Mode: %s", hdr->flags & A_MEM_MODE_MALLOC ? "malloc" : "slab");
}
