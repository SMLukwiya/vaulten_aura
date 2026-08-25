#ifndef AURA_ROUTE_H
#define AURA_ROUTE_H

#include "fn/lib.h"
#include "header_srv.h"
#include "http_lib.h"
#include "radix/tree.h"
#include "types_lib.h"

#include <strings.h>

struct aura_router;

/* Route structure */
struct aura_route {
    struct aura_router *router; /* router to which route belongs */
    void *bpf_program;
    uint32_t flag; /* config flags, only http2 enabled now */
    char url[256];
};

/* Route pool structure */
struct aura_route_pool {
    struct aura_route *routes;
    uint32_t cap;
    uint32_t cnt;
};

/* Router structure */
struct aura_router {
    struct aura_srv_ctx *srv_ctx;
    aura_rax_tree_t r_tree;
    struct aura_route_pool route_pool;
    // struct router_t *next; /* v1 routes to v2 routes */
};

/**
 * Initialize a new router to hold routes
 * associated with functions
 */
int aura_router_init(struct aura_router *router);

/**
 * Free router resources
 */
void aura_router_destroy(struct aura_router *router);

/**
 * Add a new route to the router,
 * attaching associates workqueue and function
 * to the route.
 */
int aura_route_add(struct aura_router *router, struct aura_fn *fn);

/**
 * Free a route and resources
 */
bool aura_route_remove(struct aura_route *route);

/**
 * Match an incoming requests against
 * the list of routes returning NULL is not
 * route is matched
 */
struct aura_route *aura_route_match(struct aura_router *router, const char *pattern, size_t pattern_len, uint8_t method);

#endif