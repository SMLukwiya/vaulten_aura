#include "route_srv.h"
#include "error_lib.h"

bool aura_router_init(struct aura_router *router) {
    router->r_tree = aura_rax_new();
    if (!router->r_tree)
        return false;

    router->route_pool.cap = router->route_pool.cnt = 0;
    router->route_pool.routes = NULL;
    return true;
}

bool aura_router_destroy(struct aura_router *router) {
    if (!router)
        return true;

    if (router->r_tree)
        aura_rax_free(router->r_tree);

    router->r_tree = NULL;
    return true;
}

/**
 * Free a single route, clearing the work queue associated
 * with that route and the function resources being held by
 * the route
 */
static inline bool a_route_destroy(struct aura_route *route) {
    int res;

    if (!route)
        return true;

    // destroy function

    res = aura_work_queue_destroy(&route->wq);
    if (res != 0) {
        /** @todo: Failed to destroy work queue, what should I do?? */
        return false;
    }

    /* remove from tree */
    aura_rax_remove(route->router->r_tree, route->fn_image.http_trigger.path.base, route->fn_image.http_trigger.path.len, NULL);

    memset(route, 0, sizeof(*route));
    /** @todo: a new slot is free on the vector, either keep a free offset for later use or compact memory */

    return true;
}

bool aura_route_add(struct aura_router *router, uint32_t version, struct aura_fn *fn) {
    aura_rax_node_t *n;
    struct aura_route *new_route;
    char *pattern;
    uint64_t pattern_len;
    bool res;

    pattern = fn->http_trigger.path.base;
    pattern_len = fn->http_trigger.path.len;
    /* check for existent route */
    n = aura_rax_lookup(router->r_tree, pattern, pattern_len);
    if (n) {
        /* route already exists in router */
        errno = EEXIST;
        return false;
    }

    if (router->route_pool.cnt >= router->route_pool.cap) {
        router->route_pool.cap = router->route_pool.cap == 0 ? 5 : router->route_pool.cap * 2;
        router->route_pool.routes = realloc(router->route_pool.routes, router->route_pool.cap * sizeof(struct aura_route));
        if (router->route_pool.routes == NULL)
            /** @todo: restore old values and report accordingly */
            return false;
    }

    new_route = &router->route_pool.routes[router->route_pool.cnt];
    res = aura_work_queue_init(&new_route->wq, fn->fn_concurrency.min_instances, fn->fn_concurrency.max_instances, A_WQ_JS);
    if (res) {
        sys_debug(true, errno, "Failed to initialize workqueue: %d", res);
        return false;
    }

    memcpy(&new_route->fn_image, fn, sizeof(*fn));

    res = aura_rax_insert(router->r_tree, pattern, pattern_len, A_RAX_NODE_TYPE_SPARSE, a_rax_data_init_int(router->route_pool.cnt));
    if (!res) {
        a_route_destroy(new_route);
        return false;
    }

    router->route_pool.cnt++;
    return true;
}

bool aura_route_remove(struct aura_route *route) {
    return a_route_destroy(route);
}

struct aura_route *aura_route_match(struct aura_router *router, struct aura_iovec *pattern, a_http_method_t method) {
    int len;
    aura_rax_node_t *node;
    struct aura_route *curr_route;

    node = aura_rax_lookup(router->r_tree, pattern->base, pattern->len);
    if (!node)
        return NULL;
    /** @todo: should I check if route at this position is valid first */
    return &router->route_pool.routes[node->data.int_val];
}

bool aura_route_request_init(struct aura_http_req *req) {
    memset(req, 0, sizeof(*req));

    req->version = 0x10000;
    req->version_len = 3;
    return true;
}

void aura_route_request_destroy(struct aura_http_req *req) {
    if (!req)
        return;

    if (req->path.base != NULL)
        aura_free(req->path.base);
}
