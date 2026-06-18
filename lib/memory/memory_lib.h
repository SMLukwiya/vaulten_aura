#ifndef AURA_MEMORY_H
#define AURA_MEMORY_H

#include "list_lib.h"
#include <pthread.h>
#include <stdint.h>

/* Memory context structure */
struct aura_mem_ctx {
    uint32_t mem_limit;                              /* memory cap */
    struct aura_slab_cache *dynamic_slab_caches[16]; /* table for dynamic slab cache (16 in total) */
    struct aura_list_head slab_cache_list;
};

/* Memory ctx APIs */
void aura_mem_ctx_init(struct aura_mem_ctx *mc);
void aura_mem_ctx_destroy(struct aura_mem_ctx *mc);
void aura_mem_ctx_dump(struct aura_mem_ctx *mc);

#endif