#ifndef AURA_ROUTE_H
#define AURA_ROUTE_H

#include "exec/worker_srv.h"
#include "function_lib.h"
#include "header_srv.h"
#include "radix_lib.h"
#include "types_lib.h"

#include <strings.h>

typedef enum {
    A_REQ_BODY_NONE,
    A_REQ_BODY_OPEN,
    A_REQ_BODY_COMPLETE,
    A_REQ_BODY_ERROR
} aura_req_body_state_t;

typedef enum {
    HTTP_NONE,
    HTTP_GET,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE,
    HTTP_PATCH,
    HTTP_HEAD,
} a_http_method_t;

/* Http request structure */
struct aura_http_req {
    a_http_method_t method;
    struct aura_iovec scheme;
    struct aura_iovec path;
    struct aura_iovec authority;
    struct aura_http_hdrs *headers;
    uint8_t num_of_headers;
    size_t content_length;
    struct aura_iovec *raw_ptr; /* pointer to connection data, zero copy */
    size_t query_offset;        /* where ? is at ,perhaps maynot apply */
    int version;                /* represent in numeric */
    uint8_t version_len;
};

/* Http response structure */
struct aura_http_res {
    struct aura_http_hdrs *headers;  /* headers array */
    struct aura_http_hdrs *trailers; /* same as above */
    const char *reason;
    const char *version;
    const char *body;
    size_t content_length;
    uint16_t status_code;
    uint8_t num_of_headers;
};

struct aura_route {
    uint32_t version;
    struct aura_fn fn_image;
    struct aura_work_queue wq;
    struct aura_router *router; /* router to which route belongs */
};

struct aura_router {
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
bool aura_router_init(struct aura_router *router);

/**
 * Free router resources
 */
bool aura_router_destroy(struct aura_router *router);

/**
 * Add a new route to the router,
 * attaching associates workqueue and function
 * to the route.
 */
bool aura_route_add(struct aura_router *router, uint32_t version, struct aura_fn *fn);

/**
 * Free a route and resources
 */
bool aura_route_remove(struct aura_route *route);

/**
 * Match an incoming requests against
 * the list of routes returning NULL is not
 * route is matched
 */
struct aura_route *aura_route_match(struct aura_router *router, struct aura_iovec *pattern, a_http_method_t method);

bool aura_route_request_init(struct aura_http_req *req);
void aura_route_request_destroy(struct aura_http_req *req);

/**/
bool aura_route_response_init();
void aura_route_response_destroy(struct aura_http_req *req);

#endif