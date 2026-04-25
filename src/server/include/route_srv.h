#ifndef AURA_ROUTE_H
#define AURA_ROUTE_H

#include "function_lib.h"
#include "header_srv.h"
#include "http_lib.h"
#include "radix_lib.h"
#include "types_lib.h"
#include "worker_srv.h"

#include <strings.h>

/* Http request structure */
struct aura_http_req {
    a_http_method_t method;
    a_http_scheme_t scheme;
    struct aura_iovec path;
    struct aura_iovec authority;
    size_t content_length;
    struct aura_header_vector headers;
    struct aura_iovec raw_ptr; /* pointer to connection data, zero copy */
    size_t query_offset;       /* where ? is at ,perhaps maynot apply */
    int version;               /* represent in numeric */
    uint8_t version_len;
};

/* Http response structure */
struct aura_http_res {
    int version;
    const char *reason;
    const char *body;
    size_t content_length;
    struct aura_header_vector headers;
    uint16_t status_code;
};

/* Route structure */
struct aura_route {
    uint32_t version;
    char url[256];
    struct aura_fn *fn;
    struct aura_work_queue *wq;
    struct aura_router *router; /* router to which route belongs */
};

/* Router structure */
struct aura_router {
    struct aura_srv_ctx *srv_ctx;
    aura_rax_tree_t *r_tree;
    struct {
        struct aura_route *routes;
        uint32_t cap;
        uint32_t cnt;
    } route_pool;
    // struct router_t *next; /* v1 routes to v2 routes */
};

/**
 * Initialize a new router to hold routes
 * associated with functions
 */
int aura_router_init(struct aura_router *router, struct aura_srv_ctx *);

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
struct aura_route *aura_route_match(struct aura_router *router, const char *pattern, size_t pattern_len, a_http_method_t method);

/**/
void aura_route_request_init(struct aura_http_req *req);
void aura_route_request_destroy(struct aura_http_req *req);

/**/
bool aura_route_response_init(struct aura_http_res *res);
void aura_route_response_destroy(struct aura_http_res *res);

#endif