#include "runtime/request.h"
#include "error_lib.h"

Request *aura_rt_create_req(struct aura_memory_ctx *mc) {
    Request *req;

    req = aura_alloc(mc, sizeof(*req));
    if (!req)
        return NULL;

    memset(req, 0, sizeof(*req));
    return req;
}

Response *aura_rt_create_res(struct aura_memory_ctx *mc) {
    Response *resp;
    /** @todo: should native buffer be attached to res, (res->body) = pointer(stream->data) */

    resp = aura_alloc(mc, sizeof(*resp));
    if (!resp)
        return NULL;

    memset(resp, 0, sizeof(*resp));
    return resp;
}

static inline struct aura_rt_header_field *a_rt_req_get_header_slot(struct aura_memory_ctx *mc, struct aura_rt_header_field_vec *headers) {
    struct aura_rt_header_field *hdr_field;

    if (headers->cnt >= headers->cap) {
        headers->cap = headers->cap == 0 ? 10 : headers->cap * 2;
        headers->entries = aura_realloc(mc, headers->entries, sizeof(struct aura_rt_header_field) * headers->cap);
        if (!headers->entries)
            return NULL;
    }
    return &headers->entries[headers->cnt++];
}

struct aura_rt_header_field *aura_rt_req_get_header_slot(struct aura_memory_ctx *mc, Request *req) {
    return a_rt_req_get_header_slot(mc, &req->headers);
}

struct aura_rt_header_field *aura_rt_res_get_header_slot(struct aura_memory_ctx *mc, Response *resp) {
    return a_rt_req_get_header_slot(mc, &resp->headers);
}

void aura_rt_req_destroy(Request *req) {
    if (!req)
        return;

    if (req->url.base)
        aura_free(req->url.base);

    for (int i = 0; i < req->headers.cnt; ++i) {
        aura_free(req->headers.entries[i].name.base);
        aura_free(req->headers.entries[i].value.base);
    }

    aura_free(req->headers.entries);
    aura_free(req);
}

void aura_rt_res_destroy(Response *res) {
    if (!res)
        return;

    for (int i = 0; i < res->headers.cnt; ++i) {
        aura_free(res->headers.entries[i].name.base);
        aura_free(res->headers.entries[i].value.base);
    }

    if (res->body)
        aura_free((void *)res->body);

    aura_free(res->headers.entries);
    aura_free(res);
}

void aura_rt_resp_dump(Response *resp) {
    app_debug(true, 0, "AURA_RT_RESPONSE");
    app_debug(true, 0, "    Status: %d", resp->status);
    app_debug(true, 0, "    Body: %p", resp->body);
    app_debug(true, 0, "    Body Len: %lu", resp->body_len);
    app_debug(true, 0, "    Header Cnt: %lu", resp->headers.cnt);
}