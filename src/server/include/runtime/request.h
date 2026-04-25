#ifndef AURA_RUNTIME_REQUEST_H
#define AURA_RUNTIME_REQUEST_H

#include "types_lib.h"

struct aura_rt_header_field {
    struct aura_iovec name;
    struct aura_iovec value;
};

struct aura_rt_header_field_vec {
    struct aura_rt_header_field *entries;
    size_t cnt;
    size_t cap;
};

/* JS request object */
typedef struct aura_js_request {
    int method;
    struct aura_iovec url;
    struct aura_iovec scheme;
    struct aura_rt_header_field_vec headers;
    const uint8_t *body;
    size_t body_len;
} Request;

/* JS response object */
typedef struct aura_js_response {
    uint16_t status;
    struct aura_rt_header_field_vec headers;
    const uint8_t *body;
    size_t body_len;
} Response;

/* Create runtime request object */
Request *aura_rt_create_req(struct aura_memory_ctx *mc);

/* Create runtime response object */
Response *aura_rt_create_res(struct aura_memory_ctx *mc);

/* Get header field slot from Request object */
struct aura_rt_header_field *aura_rt_req_get_header_slot(struct aura_memory_ctx *mc, Request *req);

/* Get header field slot from Response object */
struct aura_rt_header_field *aura_rt_res_get_header_slot(struct aura_memory_ctx *mc, Response *resp);

/* Destroy runtime request object */
void aura_rt_req_destroy(Request *req);

/* Destroy runtime response object */
void aura_rt_res_destroy(Response *res);

/* Print runtime response */
void aura_rt_resp_dump(Response *resp);

#endif