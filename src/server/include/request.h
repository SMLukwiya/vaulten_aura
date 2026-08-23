#ifndef AURA_SRV_REQUEST_H

#include "header_srv.h"
#include "http_lib.h"
#include "types_lib.h"
#include <string.h>

/* Http request structure */
struct aura_http_req {
    struct aura_iovec path;
    struct {
        struct aura_iovec host;
        uint16_t port;
    } authority;
    size_t content_length; /** @todo: may not be needed */
    const char *body;      /* request body, zero copy */
    struct aura_iovec query;
    struct aura_header_vector2 headers;
    int version; /* represent in numeric */
    uint8_t method;
    uint8_t scheme;
};

/* Http response structure */
struct aura_http_res {
    int version;
    const char *reason;
    const char *body;
    size_t content_length; /* = SIZE_MAX when there is no data */
    struct aura_header_vector2 headers;
    uint16_t status_code;
};

/**/
void aura_route_req_init(struct aura_http_req *req);
void aura_route_req_destroy(struct aura_http_req *req);

/**/
void aura_route_res_init(struct aura_http_res *res);
void aura_route_response_destroy(struct aura_http_res *res);

#endif