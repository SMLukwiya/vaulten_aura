#include "host.h"
#include "socket_srv.h"
#include <string.h>

extern struct aura_srv_global_conf *glob_conf;

void aura_host_pool_init(struct aura_srv_host_pool *pool) {
    memset(pool, 0, sizeof(*pool));
}

/**
 * Add host configuration to the global config list
 * and return the offset of the newly added conf
 */
static inline struct aura_srv_host_conf *a_host_conf_get_slot(struct aura_srv_host_pool *pool) {

    if (pool->cnt >= pool->cap) {
        pool->cap = pool->cap == 0 ? 5 : pool->cap * 2;
        pool->hosts = realloc(pool->hosts, sizeof(struct aura_srv_host_conf) * pool->cap);
        if (!pool->hosts)
            return NULL;
    }

    return &pool->hosts[pool->cnt++];
}

struct aura_srv_host_conf *aura_host_config_create(struct aura_srv_host_pool *pool, const char *hostname,
                                                   uint32_t default_tls_idx, struct aura_iovec *h2_frames) {
    struct aura_srv_host_conf *host;

    host = a_host_conf_get_slot(pool);
    if (!host)
        return NULL;

    host->hostname.base = strdup(hostname);
    host->hostname.len = strlen(hostname);
    host->def_tls_off = default_tls_idx;
    if (aura_router_init(&host->router) < 0)
        return NULL;

    if (h2_frames != NULL)
        host->h2_origin_frame = h2_frames;

    return host;
}

void aura_host_pool_destroy(struct aura_srv_host_pool *pool) {
    if (!pool)
        return;

    free(pool->hosts);
    memset(pool, 0, sizeof(*pool));
}

struct aura_srv_host_conf *aura_host_config_find(struct aura_srv_host_pool *pool, const char *hostname) {
    for (int i = 0; i < pool->cnt; ++i) {
        if (strcasecmp(hostname, pool->hosts[i].hostname.base) == 0) {
            return &pool->hosts[i];
        }
    }

    return NULL;
}
