#include "error_lib.h"
#include "map.h"
#include "string_lib.h"

int aura_rh_map_init(struct aura_rh_map *map, struct aura_mem_ctx *mc,
                     uint32_t initial_cap, a_rh_map_key_t key_type, bool can_resize) {
    uint32_t cap = 8;

    while (cap < initial_cap)
        cap <<= 1;

    memset(map, 0, sizeof(*map));
    map->buckets = aura_alloc(mc, sizeof(*map->buckets) * cap);
    if (!map->buckets)
        return -1;
    memset(map->buckets, 0, sizeof(*map->buckets) * cap);

    for (int i = 0; i < cap; ++i) {
        map->buckets[i].key.num = A_RH_KEY_EMPTY;
        map->buckets[i].key.psl = A_RH_PSL_EMPTY;
    }

    map->mc = mc;
    map->cap = cap;
    map->cnt = 0;
    map->mask = cap - 1;
    map->can_resize = can_resize;
    map->key_type = key_type;
    return 0;
}

void aura_rh_map_destroy(struct aura_rh_map *map) {
    if (!map)
        return;

    if (map->buckets) {
        if (map->key_type == A_RH_KEY_STR)
            for (int i = 0; i < map->cap; ++i) {
                if (map->buckets[i].key.psl != A_RH_PSL_EMPTY)
                    aura_free((void *)map->buckets[i].key.str.base);
            }
        aura_free(map->buckets);
    }
    memset(map, 0, sizeof(*map));
}

static int a_rh_map_put(struct aura_rh_map *map, struct aura_rh_map_key *key, void *data) {
    uint32_t idx, hash;
    struct aura_rh_map_bucket *b;
    struct aura_rh_map_key _key;

    memcpy(&_key, key, sizeof(_key));

    struct aura_rh_map_bucket curr = {_key, data};
    curr.key.psl = 0;
    if (map->key_type == A_RH_KEY_STR) {
        /* duplicate key string */
        _key.str.base = aura_strndup(map->mc, _key.str.base, _key.str.len);
        idx = aura_rh_map_slot32(map, (uint64_t)key->str.base, key->str.len);
    } else {
        idx = aura_rh_map_slot32(map, (uint64_t)&key->num, (uint32_t)sizeof(uint64_t));
    }

    for (;;) {
        b = &map->buckets[idx];

        if (b->key.psl == A_RH_PSL_EMPTY) {
            *b = curr;
            map->cnt++;
            return 0;
        }

        /* update value */
        if (map->key_type == A_RH_KEY_U64) {
            if (b->key.num == key->num) {
                b->data = data;
                return 0;
            }
        } else {
            if (b->key.str.tag == curr.key.str.tag)
                if (strncmp(b->key.str.base, curr.key.str.base, curr.key.str.len) == 0) {
                    b->data = data;
                    return 0;
                }
        }

        if (curr.key.psl > b->key.psl) {
            /* Robin hood swap */
            struct aura_rh_map_bucket temp = *b;
            *b = curr;
            curr = temp;
        }

        idx = (idx + 1) & map->mask;
        curr.key.psl++;
    }
}

static int a_rh_map_resize(struct aura_rh_map *map, uint32_t new_cap) {
    struct aura_rh_map_bucket *old, *new;
    uint32_t old_cap;

    /* ensure power of 2 */
    if (new_cap == 0 || new_cap & (new_cap - 1) != 0)
        return -1;

    old = map->buckets;
    old_cap = map->cap;
    new = aura_alloc(map->mc, sizeof(*new) * new_cap);
    if (!new)
        return -1;

    map->buckets = new;
    map->cap = new_cap;
    map->mask = new_cap - 1;
    map->cnt = 0;

    for (int i = 0; i < old_cap; ++i) {
        if (map->key_type == A_RH_KEY_U64) {
            if (old[i].key.num != A_RH_KEY_EMPTY)
                a_rh_map_put(map, &old[i].key, old[i].data);
        } else {
            if (old[i].key.str.base)
                a_rh_map_put(map, &old[i].key, old[i].data);
        }
    }

    aura_free(old);
    return 0;
}

int aura_rh_map_put(struct aura_rh_map *map, struct aura_rh_map_key *key, void *data) {
    if (map->key_type == A_RH_KEY_U64) {
        if (key->num == A_RH_KEY_EMPTY)
            return -1;
    } else {
        if (!key->str.base)
            return -1;
    }

    /* grow map if load factor ~ 80% */
    if (map->can_resize && ((map->cnt + 1) * 100) >= map->cap * 80) {
        if (!a_rh_map_resize(map, map->cap << 1))
            return -1;
    }

    return a_rh_map_put(map, key, data);
}

void *aura_rh_map_get(struct aura_rh_map *map, struct aura_rh_map_key *key) {
    struct aura_rh_map_bucket *b;
    uint32_t idx;

    if (map->key_type == A_RH_KEY_U64) {
        if (key->num == A_RH_KEY_EMPTY)
            return NULL;
        idx = aura_rh_map_slot32(map, (uint64_t)&key->num, (uint32_t)sizeof(uint64_t));
    } else {
        if (!key->str.base)
            return NULL;
        idx = aura_rh_map_slot32(map, (uint64_t)key->str.base, key->str.len);
    }

    for (;;) {
        b = &map->buckets[idx];
        if (b->key.psl == A_RH_PSL_EMPTY)
            return NULL;

        if (map->key_type == A_RH_KEY_U64) {
            if (b->key.num == key->num)
                return b->data;
        } else {
            if (b->key.str.tag == key->str.tag) {
                if (strncmp(b->key.str.base, key->str.base, key->str.len) == 0) {
                    return b->data;
                }
            }
        }

        /* if current probe distance is smaller, key cannot be later */
        if (key->psl > b->key.psl)
            return NULL;

        idx = (idx + 1) & map->mask;
        key->psl++;
    }
}

int aura_rh_map_del(struct aura_rh_map *map, struct aura_rh_map_key *key, void **data_out) {
    struct aura_rh_map_bucket *b, *nb;
    uint32_t idx, curr, next;

    if (data_out)
        *data_out = NULL;
    if (map->key_type == A_RH_KEY_U64) {
        if (key->num == A_RH_KEY_EMPTY)
            return 0;

        idx = aura_rh_map_slot32(map, (uint64_t)&key->num, (uint32_t)sizeof(uint64_t));
    } else {
        if (!key->str.base)
            return 0;

        idx = aura_rh_map_slot32(map, (uint64_t)key->str.base, key->str.len);
    }

    for (;;) {
        b = &map->buckets[idx];
        if (b->key.psl == A_RH_PSL_EMPTY)
            return 0;

        if (map->key_type == A_RH_KEY_U64) {
            if (b->key.num == key->num)
                break;
        } else {
            if (b->key.str.tag == key->str.tag)
                if (strncmp(b->key.str.base, key->str.base, key->str.len) == 0) {
                    break;
                }
        }

        idx = (idx + 1) & map->mask;
    }

    if (data_out)
        *data_out = map->buckets[idx].data;
    /* backward shift delete */
    curr = idx;
    next = (curr + 1) & map->mask;

    for (;;) {
        nb = &map->buckets[next];

        /* If slot is empty or should not be shifted */
        if (nb->key.psl == A_RH_PSL_EMPTY || nb->key.psl == 0) {
            memset(&map->buckets[curr], 0, sizeof(struct aura_rh_map_bucket));
            map->buckets[curr].key.num = A_RH_KEY_EMPTY;
            map->buckets[curr].key.psl = A_RH_PSL_EMPTY;
            break;
        }
        map->buckets[curr] = *nb;
        curr = next;
        next = (next + 1) & map->mask;
    }
    map->cnt--;
    return 0;
}