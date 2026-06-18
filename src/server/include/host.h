#ifndef AURA_SRV_HOST
#define AURA_SRV_HOST

#include "route_srv.h"
#include "types_lib.h"
#include <stdint.h>

/* Security policy structure */
struct aura_srv_sec_policy {
    void *waf_config; /* web application firewall */
    void *ratelimiter_config;
    void *ip_acl;       /* ACLs */
    uint32_t policy_id; /* unique ID for logging */
};

/* Server host config structure */
struct aura_srv_host_conf {
    struct aura_iovec hostname;
    uint32_t def_tls_off; /* default tls identity offset */
    uint32_t *other_tls_off;
    uint32_t other_tls_cnt;
    struct aura_router router;
    struct aura_iovec *h2_origin_frame;
    struct aura_srv_sec_policy *def_security_policy; /* default security policy */
};

struct aura_srv_host_pool {
    struct aura_srv_host_conf *hosts;
    size_t cnt;
    size_t cap;
};

/* Initialize host configuration pool */
void aura_host_pool_init(struct aura_srv_host_pool *pool);

/**
 * Create host conf for this hostname, insert into global
 * host conf table and return the offset of the added conf
 */
struct aura_srv_host_conf *aura_host_config_create(struct aura_srv_host_pool *pool, const char *hostname,
                                                   uint32_t default_tls_idx, struct aura_iovec *h2_frames);

/* Destroy host config pool */
void aura_host_pool_destroy(struct aura_srv_host_pool *pool);

/* Find host by hostname */
struct aura_srv_host_conf *aura_host_config_find(struct aura_srv_host_pool *pool, const char *hostname);

#endif