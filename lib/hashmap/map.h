#ifndef AURA_HASHMAP_H
#define AURA_HASHMAP_H

#include "hasher_lib.h"
#include "mem.h"
#include "slab.h"

#include <stdint.h>
#include <stdlib.h>

#define A_RH_KEY_EMPTY UINT64_MAX
#define A_RH_PSL_EMPTY UINT8_MAX

typedef enum {
    A_RH_KEY_U64,
    A_RH_KEY_STR,
} a_rh_map_key_t;

/* RH key type structure */
struct aura_rh_map_key {
    union {
        uint64_t num;
        struct {
            const char *base;
            uint32_t len;
            uint8_t tag;
        } str;
    };
    uint8_t psl;
};

/* RH bucket structure */
struct aura_rh_map_bucket {
    struct aura_rh_map_key key;
    void *data;
};

/* RH map structure */
struct aura_rh_map {
    struct aura_mem_ctx *mc;
    struct aura_rh_map_bucket *buckets;
    uint32_t cap;
    uint32_t cnt;
    uint32_t mask;
    bool can_resize; /* is this map allowed to resize */
    uint8_t key_type;
};

static inline uint32_t aura_rh_map_hash32(uint64_t key, uint32_t len) {
    uint64_t hval = FNV1_32A_INIT;
    return fnv_32a_buf((void *)key, (size_t)len, hval);
}

static inline uint64_t aura_rh_map_hash64(uint64_t key, size_t len) {
    size_t hval = FNV1A_64_INIT;

    return fnv_64a_buf((void *)key, len, hval);
}

static inline uint64_t aura_rh_map_slot64(struct aura_rh_map *map, uint64_t key, uint64_t len) {
    return (uint64_t)(aura_rh_map_hash64(key, len)) & map->mask;
}

static inline uint32_t aura_rh_map_slot32(struct aura_rh_map *map, uint64_t key, uint32_t len) {
    return (uint32_t)(aura_rh_map_hash32(key, len)) & map->mask;
}

static inline bool aura_rh_map_is_empty(struct aura_rh_map *map) {
    return map->cnt == 0;
}

static inline uint32_t aura_rh_map_get_cnt(struct aura_rh_map *map) {
    return map->cnt;
}

/* Initialize RH key structure */
static inline void aura_rh_map_key_init(struct aura_rh_map_key *key, uint64_t key_val,
                                        uint32_t len, a_rh_map_key_t key_type) {
    uint32_t hash;

    if (key_type == A_RH_KEY_U64) {
        key->num = key_val;
        key->psl = 0;
    } else {
        hash = aura_rh_map_hash32(key_val, len);
        key->str.base = (void *)key_val;
        key->str.len = len;
        // key->str.tag = (uint8_t)(hash >> 56);
        key->str.tag = (uint8_t)(hash >> 24);
    }
}

/* Initialize RH map */
int aura_rh_map_init(struct aura_rh_map *map, struct aura_mem_ctx *mc,
                     uint32_t initial_cap, a_rh_map_key_t key_type, bool can_resize);

/* Free RH map */
void aura_rh_map_destroy(struct aura_rh_map *map);

/* Insert into RH map */
int aura_rh_map_put(struct aura_rh_map *map, struct aura_rh_map_key *key, void *data);

/* Get entry with given key from RH map */
void *aura_rh_map_get(struct aura_rh_map *map, struct aura_rh_map_key *key);

/* Delete entry with given key from RH map */
int aura_rh_map_del(struct aura_rh_map *map, struct aura_rh_map_key *key, void **data_out);

#endif