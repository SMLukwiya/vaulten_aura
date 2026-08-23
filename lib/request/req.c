#include "req.h"
#include "error_lib.h"
#include "http_lib.h"
#include "string_lib.h"

Request *aura_task_create2(struct aura_mem_ctx *mc, uint8_t method, struct aura_kv_vec *headers,
                           const uint8_t *body, uint64_t cont_len, uint8_t *url) {
    Request *req;

    req = aura_alloc(mc, sizeof(*req));
    if (!req)
        return NULL;
    memset(req, 0, sizeof(*req));

    req->url.base = aura_strdup(mc, url);
    req->url.len = strlen(url);
    req->method = method;

    req->headers.cnt = req->headers.cap = 0;
    if (headers->entries && headers->cnt > 0) {
        req->headers.entries = aura_alloc(mc, sizeof(*req->headers.entries) * headers->cnt);
        if (!req->headers.entries) {
            aura_req_destroy(req);
            return NULL;
        }

        for (int i = 0; i < headers->cnt; ++i) {
            req->headers.entries[i].key.base = aura_strdup(mc, headers->entries[i].key.base);
            req->headers.entries[i].key.len = headers->entries[i].key.len;
        }
        req->headers.cnt = req->headers.cap = req->headers.cnt;
    }

    req->body = NULL;
    req->body_len = 0;
    if (req->method == A_HTTP_POST) {
        req->body = body;
        req->body_len = cont_len;

        return req;
    }
}

void aura_req_destroy(Request *req) {
    if (!req)
        return;

    if (req->url.base)
        aura_free(req->url.base);

    aura_url_destroy(&req->parsed_url);

    for (int i = 0; i < req->headers.cnt; ++i) {
        aura_free(req->headers.entries[i].key.base);
        aura_free(req->headers.entries[i].value.base);
    }

    if (req->bc.opaque)
        req->bc.opaque_destructor_fn(req->bc.opaque);

    aura_free(req->headers.entries);
    aura_free(req);
}

int aura_req_stream_provider_create(struct aura_mem_ctx *mc, Request *req,
                                    struct aura_stream_src_ops *ops, void *opaque,
                                    opaque_destructor_fn fn) {
    req->sp = aura_alloc(mc, sizeof(*req->sp));
    if (!req->sp) {
        return -1;
    }

    if (aura_stream_provider_init(req->sp, req, ops, opaque, fn) < 0) {
        return -1;
    }

    return 0;
}

int aura_res_stream_provider_create(struct aura_mem_ctx *mc, Response *res,
                                    struct aura_stream_src_ops *ops, void *opaque,
                                    opaque_destructor_fn fn) {
    res->sp = aura_alloc(mc, sizeof(*res->sp));
    if (!res->sp) {
        return -1;
    }

    if (aura_stream_provider_init(res->sp, res, ops, opaque, fn) < 0) {
        return -1;
    }

    return 0;
}

Response *aura_res_create(struct aura_mem_ctx *mc) {
    Response *resp;

    resp = aura_alloc(mc, sizeof(*resp));
    if (!resp)
        return NULL;

    memset(resp, 0, sizeof(*resp));
    return resp;
}

void aura_res_destroy(Response *res) {
    if (!res)
        return;

    if (res->body)
        aura_free((void *)res->body);

    for (int i = 0; i < res->headers.cnt; ++i) {
        aura_free(res->headers.entries[i].key.base);
        aura_free(res->headers.entries[i].value.base);
    }
    aura_free(res->headers.entries);
    aura_free(res);
}

static inline struct aura_kv_iovec *a_req_get_kv_slot(struct aura_mem_ctx *mc,
                                                      struct aura_kv_vec *headers) {
    if (headers->cnt >= headers->cap) {
        headers->cap = headers->cap == 0 ? 10 : headers->cap * 2;
        headers->entries = aura_realloc(mc, headers->entries, sizeof(struct aura_kv_iovec) * headers->cap);
        if (!headers->entries)
            return NULL;
    }
    return &headers->entries[headers->cnt++];
}

struct aura_kv_iovec *aura_req_get_kv_slot(struct aura_mem_ctx *mc, Request *req) {
    return a_req_get_kv_slot(mc, &req->headers);
}

struct aura_kv_iovec *aura_res_get_kv_slot(struct aura_mem_ctx *mc, Response *resp) {
    return a_req_get_kv_slot(mc, &resp->headers);
}

void aura_req_dump(Request *req) {
    app_debug(true, 0, "AURA_REQUEST");
    app_debug(true, 0, " url=%s", req->url);
    app_debug(true, 0, " scheme=%s", req->scheme.base);
    app_debug(true, 0, " method=%d", req->method);
    app_debug(true, 0, " streaming=%d", req->streaming);
    app_debug(true, 0, " body=%p", req->body);
    app_debug(true, 0, " body len=%zu", req->body_len);
    app_debug(true, 0, " stream prov=%p", req->sp);
    app_debug(true, 0, " body consumer state=%d", req->bc.state);
    app_debug(true, 0, " body consumer data=%p", req->bc.opaque);
}

void aura_res_dump(Response *resp) {
    app_debug(true, 0, "AURA_RT_RESPONSE");
    app_debug(true, 0, "    Status: %d", resp->status);
    app_debug(true, 0, "    Body: %p", resp->body);
    app_debug(true, 0, "    Body Len: %lu", resp->body_len);
    app_debug(true, 0, "    Header Cnt: %lu", resp->headers.cnt);
}