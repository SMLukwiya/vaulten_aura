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

    if (router->route_pool.routes)
        free(router->route_pool.routes);
    memset(router, 0, sizeof(*router));

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

    res = aura_work_queue_destroy(route->wq);
    if (res != 0) {
        /** @todo: Failed to destroy work queue, what should I do?? */
        return false;
    }

    /* remove from tree */
    aura_rax_remove(route->router->r_tree, route->fn->meta.http_trigger.path.base, route->fn->meta.http_trigger.path.len, NULL);

    memset(route, 0, sizeof(*route));
    /** @todo: a new slot is free on the vector, either keep a free offset for later use or compact memory */

    return true;
}

bool aura_route_add(struct aura_router *router, struct aura_fn *fn) {
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
    new_route->version = 0x1;
    new_route->router = router;
    snprintf(new_route->url, sizeof(new_route->url), "%s", fn->meta.host);
    if (pattern[0] != '/') {
        /** @todo: complete */
    }
    strncat(new_route->url + strlen(new_route->url), pattern, sizeof(new_route->url) - strlen(new_route->url) - 1);
    new_route->fn = fn;
    new_route->wq = malloc(sizeof(struct aura_work_queue));
    if (!new_route->wq)
        return false;

    res = aura_work_queue_init(new_route->wq, fn);
    if (res) {
        sys_debug(true, errno, "Failed to initialize workqueue: %d", res);
        return false;
    }

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
    aura_rax_node_t *node;

    node = aura_rax_lookup(router->r_tree, pattern->base, pattern->len);
    if (!node)
        return NULL;

    if (node->data.int_val > router->route_pool.cnt) {
        app_debug(true, 0, "aura_route_match: Invalid offset: %d", node->data.int_val);
        return NULL;
    }
    return &router->route_pool.routes[node->data.int_val];
}

bool aura_route_request_init(struct aura_http_req *req) {
    memset(req, 0, sizeof(*req));

    req->version = 0x10000;
    req->version_len = 3;
    req->headers.cap = 0;
    req->headers.cnt = 0;
    req->headers.entries = NULL;
    return true;
}

void aura_route_request_destroy(struct aura_http_req *req) {
    if (!req)
        return;

    if (req->path.base != NULL)
        aura_free(req->path.base);

    if (req->headers.entries) {
        aura_free(req->headers.entries);
        req->headers.entries = NULL;
    }
}
