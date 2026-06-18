
#include "h2/stream.h"
#include "bug_lib.h"
#include "h2/hpack.h"
#include "h2/server.h"
#include "server_srv.h"
#include "string_lib.h"
#include "time_lib.h"

struct aura_h2_stream *aura_h2_stream_open(struct aura_h2_core *core, struct aura_mem_ctx *mc,
                                           uint32_t stream_id, uint8_t initial_state, uint32_t flags,
                                           uint64_t glob_seq, void *user_data, user_data_destructor dtor) {
    struct aura_h2_stream *s;
    struct aura_slab_cache *sc;

    sc = aura_slab_cache_find_by_id(mc, A_SLAB_CACHE_ID_H2_STREAM);
    s = aura_slab_alloc(sc);
    if (!s)
        return NULL;
    memset(s, 0, sizeof(*s));

    s->h2_c = core;
    s->stream_id = stream_id;
    s->user_data = user_data;
    s->user_data_dtor = dtor;
    s->local_window_size = A_H2_INITIAL_WINDOW_SIZE;
    s->peer_window_size = A_H2_INITIAL_WINDOW_SIZE;
    s->state = initial_state;
    s->flags = flags;
    s->prio.urgency = A_PRI_EXT_DEFAULT_URGENCY;
    s->prio.incremental = false;
    s->glob_seq = glob_seq;
    aura_list_head_init(&s->s_list);
    aura_list_head_init(&s->data_list);

    aura_route_req_init(&s->req);
    aura_route_res_init(&s->res);

    if (aura_now_ts(&s->start_ts, CLOCK_MONOTONIC) < 0) {
        aura_slab_free(s);
        return NULL;
    }

    if (aura_sliding_buf_init(&s->sync, mc, 0, A_SLIDING_BUF_FL_NONE) < 0) {
        aura_slab_free(s);
        return NULL;
    }

    if (aura_sliding_buf_init(&s->data, mc, 0, A_SLIDING_BUF_FL_NONE) < 0) {
        aura_sliding_buf_destroy(&s->sync);
        aura_slab_free(s);
        return NULL;
    }

    return s;
}

/**
 *
 */
void aura_set_priority(struct aura_h2_stream *s, struct aura_h2_priority *p) {
    /* Not supported */
    return;
}

/**
 *
 */
static void request_write_and_close() {}

/**
 *
 */
static void send_refused_stream() {}

/** */
static int aura_h2_stream_push_promise_send(struct aura_h2_core *h2_ctx, struct aura_h2_stream *stream) {
    /* Not supported! */
    return 0;
}

bool aura_h2_stream_can_send(struct aura_h2_stream *s, bool is_server) {
    if (!s)
        false;

    if (aura_h2_conn_is_closing(s->h2_c))
        return false;

    if (s->state == A_H2_STREAM_STATE_HALF_CLOSED_LOCAL ||
        s->state == A_H2_STREAM_STATE_CLOSING ||
        s->state == A_H2_STREAM_STATE_CLOSED)
        return false;

    if (aura_h2_stream_is_paused(s))
        return false;

    /* Local initiated stream can start sending immediately */
    if (aura_h2_conn_stream_is_local(s->stream_id, is_server)) {
        return true;
    }

    if (s->state == A_H2_STREAM_STATE_OPEN ||
        s->state == A_H2_STREAM_STATE_HALF_CLOSED_REMOTE)
        return true;

    return false;
}

void aura_h2_stream_destroy(struct aura_h2_stream *s, bool server) {
    if (!s)
        return;

    s->user_data_dtor(s->user_data);
    aura_route_req_destroy(&s->req);
    aura_route_response_destroy(&s->res);

    aura_sliding_buf_destroy(&s->sync);
    aura_sliding_buf_destroy(&s->data);

    aura_slab_free(s);
}

void aura_h2_stream_dump(struct aura_h2_stream *stream) {
    app_debug(true, 0, "AURA H2 STREAM");
    app_debug(true, 0, "    stream id: %u", stream->stream_id);
    app_debug(true, 0, "    strean state: %d", stream->state);
    app_debug(true, 0, "    stream header buf size: %lu", aura_sliding_buf_read_len(&stream->sync));
}

int aura_h2_stream_claim_rt_request(struct aura_mem_ctx *mc, struct aura_h2_stream *stream, Request *req) {
    struct aura_basic_header *header;

    /* Take ownership of url structure and its underlying memory */
    stream->req.authority.host = req->parsed_url.authority.host;
    stream->req.path = req->parsed_url.path;
    stream->req.scheme = req->parsed_url.scheme;
    stream->req.query = req->parsed_url.query;
    /* Delete parsed url from request */
    memset(&req->parsed_url, 0, sizeof(struct aura_url));

    /* Take ownership of request body */
    stream->req.content_length = req->body_len;
    stream->req.body = req->body;
    /* Delete body from req strucure */
    req->body = NULL;

    stream->req.method = req->method;
    stream->req.headers.entries = NULL;
    stream->req.headers.cnt = stream->req.headers.cap = 0;
    // stream->req.headers = req->headers;

    if (req->headers.entries && req->headers.cnt > 0) {
        stream->req.headers.entries = aura_alloc(mc, sizeof(struct aura_basic_header) * req->headers.cnt);
        if (!stream->req.headers.entries)
            return -1;

        /* Take ownership of request headers */
        for (int i = 0; i < req->headers.cnt; ++i) {
            // header = &req->headers.entries[i];
            // stream->req.headers.entries[i].name.base = aura_strndup(mc, header->name.base, header->name.len);
            // stream->req.headers.entries[i].value.base = aura_strndup(mc, header->value.base, header->value.len);
            stream->req.headers.entries[i] = req->headers.entries[i];
            // memset(&req->headers.entries[i], 0, sizeof(*req->headers.entries));
            stream->req.headers.cnt++;
        }
        /* release headers from request object */
        req->headers.cnt = 0;
    }

    aura_rt_req_destroy(req);

    return 0;
}

int aura_h2_stream_claim_rt_response(struct aura_h2_stream *stream, Response *resp, struct aura_mem_ctx *mc) {
    // struct aura_basic_header *header;

    stream->res.status_code = resp->status;
    stream->res.content_length = resp->body_len;
    stream->res.body = resp->body;
    resp->body = NULL;
    stream->res.headers.entries = NULL;
    stream->res.headers.cnt = stream->res.headers.cap = 0;
    // stream->res.headers = resp->headers;

    if (resp->headers.entries && resp->headers.cnt > 0) {
        stream->res.headers.entries = aura_alloc(mc, sizeof(*resp->headers.entries) * resp->headers.cnt);
        if (!stream->res.headers.entries)
            return -1;

        /* Take ownership of response headers */
        for (int i = 0; i < resp->headers.cnt; ++i) {
            // memcpy(&stream->res.headers.entries[i], header, sizeof(*header));
            stream->res.headers.entries[i] = resp->headers.entries[i];
            stream->res.headers.cnt++;
        }
        /* release headers from response object */
        resp->headers.cnt = 0;
    }

    // memset(resp, 0, sizeof(resp));
    // aura_rt_res_destroy(resp);

    return 0;
}

int aura_h2_stream_cmp_fn(struct aura_heap_ent *e1, struct aura_heap_ent *e2) {
    struct aura_h2_stream *s1, *s2;

    s1 = aura_container_of(e1, struct aura_h2_stream, hp_ent);
    s2 = aura_container_of(e1, struct aura_h2_stream, hp_ent);

    if (s1->vruntime == s2->vruntime)
        return s1->glob_seq - s2->glob_seq;

    if (s2->vruntime >= A_H2_STREAM_MAX_VRUNTIME)
        return -1;

    return s1->vruntime - s2->vruntime;
}