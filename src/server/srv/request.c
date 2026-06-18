#include "request.h"

static void a_route_hdr_vec_destroy(struct aura_header_vector2 *hdr_vec) {
    struct aura_basic_header *hdr;
    for (int i = 0; i < hdr_vec->cnt; ++i) {
        hdr = &hdr_vec->entries[i];
        aura_free(hdr->name.base);
        aura_free(hdr->value.base);
    }
}

void aura_route_req_init(struct aura_http_req *req) {
    memset(req, 0, sizeof(*req));

    req->version = 0x10000;
    req->headers.cap = 0;
    req->headers.cnt = 0;
    req->headers.entries = NULL;
    req->content_length = SIZE_MAX;
}

void aura_route_req_destroy(struct aura_http_req *req) {
    if (!req)
        return;

    if (req->path.base)
        aura_free(req->path.base);

    if (req->authority.host.base)
        aura_free(req->authority.host.base);

    if (req->query.base)
        aura_free(req->query.base);

    /** @todo: destroy raw ptr data  */
    if (req->body)
        aura_free((void *)req->body);

    a_route_hdr_vec_destroy(&req->headers);
}

void aura_route_res_init(struct aura_http_res *res) {
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

    a_route_hdr_vec_destroy(&res->headers);
}