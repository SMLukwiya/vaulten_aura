#include "hashmap_lib.h"

int aura_rh_map_init(struct aura_rh_map *map, struct aura_memory_ctx *mc, size_t initial_cap) {
    size_t cap = 8;

    while (cap < initial_cap)
        cap << 1;

    memset(map, 0, sizeof(*map));
    map->buckets = aura_alloc(mc, sizeof(*map->buckets) * cap);
    if (!map->buckets)
        return -1;
    memset(map->buckets, 0, sizeof(*map->buckets) * cap);

    map->mc = mc;
    map->cap = cap;
    map->cnt = 0;
    map->mask = cap - 1;
    return 0;
}

void aura_rh_map_destroy(struct aura_rh_map *map) {
    if (!map)
        return;

    if (map->buckets)
        aura_free(map->buckets);
    memset(map, 0, sizeof(*map));
}

static int a_rh_map_put(struct aura_rh_map *map, uint64_t key, void *data) {
    size_t idx, dist, other_dist;
    struct aura_rh_map_bucket *b;

    idx = aura_rh_map_slot64(map, key);
    dist = 0;

    struct aura_rh_map_bucket curr = {key, data};
    for (;;) {
        b = &map->buckets[idx];

        if (b->key == A_RH_MAP_KEY_EMPTY) {
            *b = curr;
            map->cnt++;
            return 0;
        }

        /* update value */
        if (b->key == key) {
            b->data = data;
            return 0;
        }

        other_dist = a_rh_map_probe_dist64(map, idx, b->key);
        if (other_dist < dist) {
            /* Robin hood swap */
            struct aura_rh_map_bucket temp = *b;
            *b = curr;
            curr = temp;
            dist = other_dist;
        }

        idx = (idx + 1) & map->mask;
        dist++;
    }
}

static int aura_rh_map_resize(struct aura_rh_map *map, size_t new_cap) {
    struct aura_rh_map_bucket *old, *new;
    size_t old_cap;

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
        if (old[i].key != A_RH_MAP_KEY_EMPTY)
            a_rh_map_put(map, old[i].key, old[i].data);
    }

    aura_free(old);
    return 0;
}

void *aura_rh_map_get(struct aura_rh_map *map, uint64_t key) {
    size_t idx, dist, other_dist;
    struct aura_rh_map_bucket *b;

    if (key == A_RH_MAP_KEY_EMPTY)
        return NULL;

    idx = a_rh_map_hash64(key);
    dist = 0;

    for (;;) {
        b = &map->buckets[idx];
        if (b->key == A_RH_MAP_KEY_EMPTY)
            return NULL;

        if (b->key == key)
            return b->data;

        other_dist = a_rh_map_probe_dist64(map, idx, b->key);

        /* if current probe distance is smaller, key cannot be later */
        if (other_dist < dist)
            return NULL;

        idx = (idx + 1) & map->mask;
        dist++;
    }
}

int aura_rh_map_del(struct aura_rh_map *map, uint64_t key, void **data_out) {
    size_t idx, curr, next;
    struct aura_rh_map_bucket *b, *nb;

    *data_out = NULL;
    if (key == A_RH_MAP_KEY_EMPTY)
        return 0;

    idx = a_rh_map_hash64(key);

    for (;;) {
        b = &map->buckets[idx];

        if (b->key == A_RH_MAP_KEY_EMPTY)
            return 0;

        if (b->key == key)
            break;

        idx = (idx + 1) & map->mask;
    }

    *data_out = map->buckets[idx].data;
    /* backward shift delete */
    curr = idx;
    next = (curr + 1) & map->mask;

    for (;;) {
        nb = &map->buckets[next];

        /* If slot is empty or should not be shifted */
        if (nb->key == A_RH_MAP_KEY_EMPTY || a_rh_map_probe_dist64(map, next, nb->key) == 0) {
            map->buckets[curr].key = A_RH_MAP_KEY_EMPTY;
            map->buckets[curr].data = NULL;
            break;
        }
        map->buckets[curr] = *nb;
        curr = next;
        next = (next + 1) & map->mask;
    }
    map->cnt--;
    return 0;
}