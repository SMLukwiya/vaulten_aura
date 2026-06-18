#include "route_srv.h"
#include "error_lib.h"
#include "worker_srv.h"

int aura_router_init(struct aura_router *router) {
    memset(router, 0, sizeof(*router));
    router->r_tree = aura_rax_new();
    if (!router->r_tree)
        return -1;

    return 0;
}

void aura_router_destroy(struct aura_router *router) {
    if (!router)
        return;

    if (router->r_tree)
        aura_rax_free(router->r_tree);

    if (router->route_pool.routes)
        free(router->route_pool.routes);
    memset(router, 0, sizeof(*router));
}

/**
 * Free a single route, clearing the work queue associated
 * with that route and the function resources being held by
 * the route
 */
static inline bool a_route_destroy(struct aura_route *route) {
    if (!route)
        return true;

    if (route->fn)
        aura_fn_destroy(route->fn);

    if (aura_work_queue_destroy(route->wq) != 0) {
        /** @todo: Failed to destroy work queue, what should I do?? */
        return false;
    }

    /* remove from tree */
    aura_rax_remove(route->router->r_tree, route->fn->meta.http_trigger.path.base, route->fn->meta.http_trigger.path.len, NULL);

    memset(route, 0, sizeof(*route));
    /** @todo: a new slot is free on the vector, either keep a free offset for later use or compact memory */

    return true;
}

static inline struct aura_route *a_router_get_slot(struct aura_route_pool *pool) {
    if (pool->cnt >= pool->cap) {
        pool->cap = pool->cap == 0 ? 5 : pool->cap * 2;
        pool->routes = realloc(pool->routes, pool->cap * sizeof(struct aura_route));
        if (!pool->routes)
            /** @todo: restore old values and report accordingly */
            return NULL;
    }

    return &pool->routes[pool->cnt++];
}

int aura_route_add(struct aura_router *router, struct aura_fn *fn) {
    aura_rax_node_t *n;
    struct aura_route *new_route;
    char *pattern;
    uint64_t pattern_len;
    bool res;

    pattern = fn->meta.http_trigger.path.base;
    pattern_len = fn->meta.http_trigger.path.len;
    /* check for existent route */
    n = aura_rax_lookup(router->r_tree, pattern, pattern_len);
    if (n) {
        /* route already exists in router */
        errno = EEXIST;
        return -1;
    }

    new_route = a_router_get_slot(&router->route_pool);
    if (!new_route)
        return -1;
    memset(new_route, 0, sizeof(*new_route));

    // new_route->version = 0x1;
    new_route->router = router;
    snprintf(new_route->url, sizeof(new_route->url), "%s", fn->meta.host);
    if (pattern[0] != '/') {
        /** @todo: complete */
    }

    strncat(new_route->url + strlen(new_route->url), pattern, sizeof(new_route->url) - strlen(new_route->url) - 1);
    new_route->fn = fn;
    new_route->wq = malloc(sizeof(struct aura_work_queue));
    if (!new_route->wq)
        return -1;

    res = aura_work_queue_init(new_route->wq, router->srv_ctx, fn);
    if (res) {
        sys_debug(true, errno, "Failed to initialize workqueue: %d", res);
        return -1;
    }

    res = aura_rax_insert(router->r_tree, pattern, pattern_len, A_RAX_NODE_TYPE_SPARSE, a_rax_data_init_ptr(new_route));
    if (!res) {
        a_route_destroy(new_route);
        return -1;
    }

    return 0;
}

bool aura_route_remove(struct aura_route *route) {
    return a_route_destroy(route);
}

struct aura_route *aura_route_match(struct aura_router *router, const char *pattern,
                                    size_t pattern_len, a_http_method_t method) {
    aura_rax_node_t *node;

    node = aura_rax_lookup(router->r_tree, pattern, pattern_len);
    if (!node)
        return NULL;

    return node->data.ptr_val;
}
