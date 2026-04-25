#include "route_srv.h"
#include "error_lib.h"

int aura_router_init(struct aura_router *router, struct aura_srv_ctx *srv_ctx) {
    router->r_tree = aura_rax_new();
    if (!router->r_tree)
        return -1;

    router->srv_ctx = srv_ctx;
    router->route_pool.cap = router->route_pool.cnt = 0;
    router->route_pool.routes = NULL;
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

    if (router->route_pool.cnt >= router->route_pool.cap) {
        router->route_pool.cap = router->route_pool.cap == 0 ? 5 : router->route_pool.cap * 2;
        router->route_pool.routes = realloc(router->route_pool.routes, router->route_pool.cap * sizeof(struct aura_route));
        if (router->route_pool.routes == NULL)
            /** @todo: restore old values and report accordingly */
            return -1;
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
        return -1;

    res = aura_work_queue_init(new_route->wq, router->srv_ctx, fn);
    if (res) {
        sys_debug(true, errno, "Failed to initialize workqueue: %d", res);
        return -1;
    }

    res = aura_rax_insert(router->r_tree, pattern, pattern_len, A_RAX_NODE_TYPE_SPARSE, a_rax_data_init_int(router->route_pool.cnt));
    if (!res) {
        a_route_destroy(new_route);
        return -1;
    }

    router->route_pool.cnt++;
    return 0;
}

bool aura_route_remove(struct aura_route *route) {
    return a_route_destroy(route);
}

struct aura_route *aura_route_match(struct aura_router *router, const char *pattern, size_t pattern_len, a_http_method_t method) {
    aura_rax_node_t *node;

    node = aura_rax_lookup(router->r_tree, pattern, pattern_len);
    if (!node)
        return NULL;

    if (node->data.int_val > router->route_pool.cnt) {
        app_debug(true, 0, "aura_route_match: Invalid offset: %d", node->data.int_val);
        return NULL;
    }
    return &router->route_pool.routes[node->data.int_val];
}

static void a_route_header_vector_destroy(struct aura_header_vector *hdr_vec) {
    struct aura_header_field *hdr;
    for (int i = 0; i < hdr_vec->cnt; ++i) {
        hdr = &hdr_vec->entries[i];
        if (!hdr->value_interned)
            if (hdr->value.raw.str && --hdr->value.raw.ref_cnt == 0)
                aura_iovec_destroy(hdr->value.raw.str);
    }
}

void aura_route_request_init(struct aura_http_req *req) {
    memset(req, 0, sizeof(*req));

    req->version = 0x10000;
    req->version_len = 3;
    req->headers.cap = 0;
    req->headers.cnt = 0;
    req->headers.entries = NULL;
}

void aura_route_request_destroy(struct aura_http_req *req) {
    if (!req)
        return;

    if (req->path.base)
        aura_free(req->path.base);

    if (req->authority.base)
        aura_free(req->authority.base);

    /** @todo: destroy raw ptr data  */
    if (req->raw_ptr.base) {
        aura_free(req->raw_ptr.base);
    }

    a_route_header_vector_destroy(&req->headers);
}

bool aura_route_response_init(struct aura_http_res *res) {
    memset(res, 0, sizeof(*res));

    res->version = 0x10000;
}

void aura_route_response_destroy(struct aura_http_res *res) {
    if (!res)
        return;

    if (res->body) {
        /** @todo: destroy body */
        aura_free((void *)res->body);
    }

    a_route_header_vector_destroy(&res->headers);
}
