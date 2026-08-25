#ifndef AURA_LRU_CACHE_H
#define AURA_LRU_CACHE_H

#include <stdint.h>

#include "list_lib.h"
#include "mem.h"
#include "slab.h"

#define A_LC_MAX_CNT (1 << 16)
#define A_LC_FREE (0U)

#define aura_lru_cache_entry(ptr, type, member) aura_container_of(ptr, type, member)

enum {
    A_LC_WAITING, /* Waiting for a cache slot to become free */
};

/* LRU cache entry */
struct aura_lru_entry {
    struct aura_list_head list; /* Link to lru list or free list */
    struct aura_list_head hash; /* Link in lru_cache->lru_hash to handle collision */
    uint64_t lru_number;
    uint32_t refcnt;
};

struct aura_lru_cache {
    struct aura_list_head lru;    /* Holds LRU list */
    struct aura_list_head free;   /* Holds free list */
    struct aura_list_head in_use; /* Holds in use list */

    struct aura_slab_cache *lru_cache; /* Slab cache backing cache entries */
    // uint64_t obj_size;                 /* Cache item size */
    uint64_t entry_off;                   /* Offset of the aura lru entry(after the real cache item) */
    uint32_t nr_entries;                  /* Number of cache entries */
    const char *name;                     /* Cache name */
    struct aura_list_head *lru_hash;      /* LRU hash list links for quick lookup */
    struct aura_lru_entry **entries;      /* Cache entries */
    uint32_t used, hits, misses, waiting; /* stats */
    uint32_t flags;                       /* Flags*/
};

/**
 * Create a LRU cache structure.
 * e_cnt both the size of the cache and
 * the hash list count.
 * @todo: perhaps e_cnt could be split from hash list count:
 *        This way we can hold more items and use the hash list chain as well.
 */
int aura_lru_cache_init(struct aura_lru_cache *lc, struct aura_mem_ctx *mc,
                        const char *name, uint8_t cache_id, uint32_t e_cnt,
                        uint32_t obj_size, uint32_t e_off);

void aura_lru_cache_destroy(struct aura_lru_cache *lc);

struct aura_lru_entry *aura_lru_cache_find(struct aura_lru_cache *lc, uint64_t entry_nr);

struct aura_lru_entry *aura_lru_cache_get(struct aura_lru_cache *lc, uint64_t entry_nr);

#endif