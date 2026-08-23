#include "runtime/request.h"
#include "error_lib.h"
#include "url/lib.h"

_Request *aura_rt_create_req(struct aura_mem_ctx *mc) {
    _Request *req;

    req = aura_alloc(mc, sizeof(*req));
    if (!req)
        return NULL;

    memset(req, 0, sizeof(*req));
    return req;
}

_Response *aura_rt_create_res(struct aura_mem_ctx *mc) {
    _Response *resp;
    /** @todo: should native buffer be attached to res, (res->body) = pointer(stream->data) */

    resp = aura_alloc(mc, sizeof(*resp));
    if (!resp)
        return NULL;

    memset(resp, 0, sizeof(*resp));
    return resp;
}

static inline struct aura_basic_header *a_rt_req_get_header_slot(struct aura_mem_ctx *mc, struct aura_header_vector2 *headers) {
    struct aura_basic_header *hdr_field;

    if (headers->cnt >= headers->cap) {
        headers->cap = headers->cap == 0 ? 10 : headers->cap * 2;
        headers->entries = aura_realloc(mc, headers->entries, sizeof(struct aura_basic_header) * headers->cap);
        if (!headers->entries)
            return NULL;
    }
    return &headers->entries[headers->cnt++];
}

struct aura_basic_header *aura_rt_req_get_header_slot(struct aura_mem_ctx *mc, _Request *req) {
    return a_rt_req_get_header_slot(mc, &req->headers);
}

struct aura_basic_header *aura_rt_res_get_header_slot(struct aura_mem_ctx *mc, _Response *resp) {
    return a_rt_req_get_header_slot(mc, &resp->headers);
}

void aura_rt_req_destroy(_Request *req) {
    if (!req)
        return;

    if (req->url.base)
        aura_free(req->url.base);

    aura_url_destroy(&req->parsed_url);

    for (int i = 0; i < req->headers.cnt; ++i) {
        aura_free(req->headers.entries[i].name.base);
        aura_free(req->headers.entries[i].value.base);
    }

    aura_free(req->headers.entries);
    aura_free(req);
}

void aura_rt_res_destroy(_Response *res) {
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

void aura_rt_resp_dump(_Response *resp) {
    app_debug(true, 0, "AURA_RT_RESPONSE");
    app_debug(true, 0, "    Status: %d", resp->status);
    app_debug(true, 0, "    Body: %p", resp->body);
    app_debug(true, 0, "    Body Len: %lu", resp->body_len);
    app_debug(true, 0, "    Header Cnt: %lu", resp->headers.cnt);
}