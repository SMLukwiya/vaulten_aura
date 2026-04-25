#ifndef AURA_HASHMAP_LIB_H
#define AURA_HASHMAP_LIB_H

#include "hasher_lib.h"
#include "memory_lib.h"
#include "slab_lib.h"

#include <stdint.h>
#include <stdlib.h>

#define A_RH_MAP_KEY_EMPTY 0ULL

struct aura_rh_map_bucket {
    uint64_t key;
    void *data;
};

struct aura_rh_map {
    struct aura_memory_ctx *mc;
    struct aura_rh_map_bucket *buckets;
    size_t cap;
    size_t cnt;
    size_t mask;
};

static inline uint64_t a_rh_map_hash64(uint64_t key) {
    size_t hval = FNV1A_64_INIT;

    return fnv_64a_buf(&key, sizeof(uint64_t), hval);
}

static inline size_t aura_rh_map_slot64(struct aura_rh_map *map, uint64_t key) {
    return (size_t)(a_rh_map_hash64(key)) & map->mask;
}

static inline size_t a_rh_map_probe_dist64(struct aura_rh_map *map, size_t slot, uint64_t key) {
    size_t _slot = aura_rh_map_slot64(map, key);
    return (slot + map->cap - _slot) & map->mask;
}

#endif