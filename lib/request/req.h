#ifndef AURA_REQUEST_H
#define AURA_REQUEST_H

#include <stdint.h>

#include "stream/lib.h"
#include "types_lib.h"
#include "url/lib.h"

/* Key value iovec */
struct aura_kv_iovec {
    struct aura_iovec key;
    struct aura_iovec value;
};

/* Key value vector */
struct aura_kv_vec {
    struct aura_kv_iovec *entries;
    uint32_t cnt;
    uint32_t cap;
};

/* Body consumption state */
typedef enum {
    A_BODY_CONSUMED,
    A_BODY_CONSUMING,
    A_BODY_NOT_CONSUMED,
} a_bc_state;

/* Body consumer */
struct aura_body_consumer {
    void *opaque;
    void (*opaque_destructor_fn)(void *);
    a_bc_state state;
};

/* JS request object */
typedef struct aura_qjs_request {
    struct aura_iovec url;
    struct aura_url parsed_url;
    struct aura_iovec scheme;
    struct aura_kv_vec headers;
    const uint8_t *body;
    uint64_t body_len;
    struct aura_stream_provider *sp; /* request stream */
    struct aura_body_consumer bc;    /* body consumer */
    uint8_t method;
    bool streaming;
} Request;

/* JS response object */
typedef struct aura_qjs_response {
    const uint8_t *body;
    uint64_t body_len;
    struct aura_iovec url;
    const uint8_t *status_text;
    struct aura_kv_vec headers;      /* headers vector */
    struct aura_stream_provider *sp; /* response stream */
    struct aura_body_consumer bc;    /* body consumer */
    uint16_t status;
    bool redirected;
    bool body_used;
    bool ok;
    bool streaming;
} Response;

/* Create request object */
Request *aura_task_create2(struct aura_mem_ctx *mc, uint8_t method, struct aura_kv_vec *headers,
                           const uint8_t *body, uint64_t cont_len, uint8_t *url);

/* Create response object */
Response *aura_res_create(struct aura_mem_ctx *mc);

/* Destroy request object */
void aura_req_destroy(Request *req);

/* Destroy response object */
void aura_res_destroy(Response *res);

struct aura_kv_iovec *aura_req_get_kv_slot(struct aura_mem_ctx *mc, Request *req);
struct aura_kv_iovec *aura_res_get_kv_slot(struct aura_mem_ctx *mc, Response *resp);

/* */
int aura_req_stream_provider_create(struct aura_mem_ctx *mc, Request *req,
                                    struct aura_stream_src_ops *ops, void *opaque,
                                    opaque_destructor_fn fn);

/**/
int aura_res_stream_provider_create(struct aura_mem_ctx *mc, Response *res,
                                    struct aura_stream_src_ops *ops, void *opaque,
                                    opaque_destructor_fn fn);

/* Print request */
void aura_req_dump(Request *req);
/* Print response */
void aura_res_dump(Response *res);

#endif