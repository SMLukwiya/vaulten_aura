
#include "h2/stream.h"
#include "bug_lib.h"
#include "h2/h2_srv.h"
#include "h2/hpack_srv.h"
#include "server_srv.h"
#include "time_lib.h"

int aura_h2_stream_init(struct aura_h2_stream *stream, struct aura_memory_ctx *mc, uint32_t stream_id,
                        uint8_t initial_state, uint32_t flags, void *user_data) {
    struct aura_slab_cache *sc;
    int res;

    app_debug(true, 0, "aura_h2_stream_init <<<<");

    memset(stream, 0, sizeof(*stream));
    stream->stream_id = stream_id;
    stream->user_data = user_data;
    stream->local_window_size.available = A_H2_INITIAL_WINDOW_SIZE;
    stream->peer_window_size.available = A_H2_INITIAL_WINDOW_SIZE;
    stream->state = initial_state;
    stream->flags = flags;
    stream->outbound_queue.blocked_by_connection = false;
    stream->outbound_queue.blocked_by_flow_control = false;
    stream->outbound_queue.pending_bytes = 0;
    a_list_head_init(&stream->outbound_queue.f_list);
    res = aura_now_ts(&stream->start_ts, CLOCK_MONOTONIC);
    a_list_head_init(&stream->s_list);
    stream->sync = aura_sliding_buffer_create(mc, 0, false);
    stream->data = aura_sliding_buffer_create(mc, 0, false);
    if (!stream->sync || !stream->data) {
        aura_h2_stream_destroy(stream);
        return -1;
    }
    aura_route_request_init(&stream->req);

    return 0;
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
void aura_h2_stream_(struct aura_h2_stream *stream) {
    app_debug(true, 0, "aura_h2_stream_destroy <<<< ");
    int res;

    if (!stream) {
        /* EINVAL */
        return;
    }

    aura_sliding_buffer_destroy(stream->sync);
    aura_sliding_buffer_destroy(stream->data);

    aura_route_request_destroy(&stream->req);

    /* @todo: update stats */
    if (aura_h2_stream_is_even_numbered(stream->stream_id))
        --stream->h2_ctx->num_outbound_streams;
    else
        --stream->h2_ctx->num_inbound_streams;

    stream->state = A_H2_STREAM_STATE_CLOSED;
    aura_slab_free((void *)stream);
}

/**
 *
 */
void aura_h2_stream_reset(struct aura_h2_stream *stream) {
    /** @todo: we are able to reject a frame upto the level of tls record generation, is there need to detect state or flags */
    aura_h2_stream_destroy(stream);
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
static int aura_h2_stream_push_promise_send(struct aura_h2_ctx *h2_ctx, struct aura_h2_stream *stream) {
    /* Not supported! */
    return 0;
}

bool aura_h2_stream_can_send(struct aura_h2_stream *stream) {
    if (!stream)
        false;

    app_debug(true, 0, "aura_h2_stream_can_send <<< _A");
    if (aura_h2_conn_is_closing(stream->h2_ctx))
        return false;

    aura_h2_stream_dump(stream);
    if (stream->state == A_H2_STREAM_STATE_HALF_CLOSED_LOCAL ||
        stream->state == A_H2_STREAM_STATE_CLOSING ||
        stream->state == A_H2_STREAM_STATE_CLOSED)
        return false;

    /* Local initiated stream can start sending immediately */
    if (aura_h2_conn_stream_is_local(stream->h2_ctx, stream->stream_id)) {
        /**
         * RST STREAM queued but not yet sent
         */
        // if (stream->state == A_H2_STREAM_STATE_CLOSING || stream->state == A_H2_STREAM_STATE_CLOSED)
        //     return false;
        return true;
    }

    if (stream->state == A_H2_STREAM_STATE_OPEN ||
        stream->state == A_H2_STREAM_STATE_HALF_CLOSED_REMOTE)
        return true;

    return false;
}

void aura_h2_stream_destroy(struct aura_h2_stream *stream) {
    if (stream->sync)
        aura_sliding_buffer_destroy(stream->sync);

    if (stream->data)
        aura_sliding_buffer_destroy(stream->data);

    aura_route_request_destroy(&stream->req);
    aura_route_response_destroy(&stream->res);

    /** @todo: how to handle user data */
}

void aura_h2_stream_dump(struct aura_h2_stream *stream) {
    app_debug(true, 0, "AURA H2 STREAM");
    app_debug(true, 0, "    stream id: %u", stream->stream_id);
    app_debug(true, 0, "    strean state: %d", stream->state);
    app_debug(true, 0, "    stream header buf size: %lu", aura_sliding_buffer_available_read(stream->sync));
}

int aura_h2_stream_claim_rt_response(struct aura_h2_stream *stream, Response *resp) {
    struct aura_header_field *header;
    app_debug(true, 0, "aura_h2_stream_claim_rt_response <<<<");

    stream->res.status_code = resp->status;
    stream->res.content_length = resp->body_len;
    stream->res.body = resp->body;
    stream->res.headers.entries = NULL;
    stream->res.headers.cnt = stream->res.headers.cap = 0;

    if (resp->headers.entries && resp->headers.cnt > 0) {
        stream->res.headers.entries = aura_alloc(stream->h2_ctx->conn->mc, sizeof(struct aura_header_field) * resp->headers.cnt);
        if (!stream->res.headers.entries)
            return -1;

        for (int i = 0; i < resp->headers.cnt; ++i) {
            header = aura_header_field_create(stream->h2_ctx->intern_tab, resp->headers.entries[i].name.base, resp->headers.entries[i].name.len, resp->headers.entries[i].value.base, resp->headers.entries[i].value.len);
            if (!header) {
                aura_free(stream->res.headers.entries);
                return -1;
            }
            memcpy(&stream->res.headers.entries[i], header, sizeof(*header));
            stream->res.headers.cnt++;
        }
    }

    return 0;
}
