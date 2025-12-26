
#include "h2/stream.h"
#include "bug_lib.h"
#include "h2/connection.h"
#include "h2/hpack_srv.h"
#include "server_srv.h"
#include "time_lib.h"

struct aura_h2_stream *aura_h2_stream_open(struct aura_h2_conn *conn, uint32_t stream_id, uint8_t starting_state, uint32_t flags) {
    struct aura_h2_stream *stream;
    bool fresh_stream;
    int res;

    if (starting_state == A_H2_STREAM_STATE_RESERVED) {
        stream->flags |= A_H2_STREAM_FLAG_PUSH;
    }

    /**
     * Push promise is not yet supported, stream should always be NULL here,
     * unless we are being haunted by something!!!!
     */
    fresh_stream = false;
    stream = aura_h2_find_stream(conn, stream_id);
    if (stream) {
        A_BUG_ON_2(stream->state != A_H2_STREAM_STATE_IDLE, true);
        stream->state = starting_state;
        --conn->num_of_idle_streams;
    } else {
        stream = aura_alloc(conn->mc, sizeof(*stream)); /** @todo: change to slab` */
        if (!stream)
            return NULL;
        memset(stream, 0, sizeof(*stream));
        fresh_stream = true;
        /* This can be extracted into it's own function */
        stream->stream_id = stream_id;
        stream->conn = conn;
        stream->local_window_size.available = A_H2_INITIAL_WINDOW_SIZE;
        stream->peer_window_size.available = A_H2_INITIAL_WINDOW_SIZE;
        stream->state = A_H2_STREAM_STATE_IDLE;
        stream->flags = flags;
        stream->outbound_queue.blocked_by_connection = false;
        stream->outbound_queue.blocked_by_flow_control = false;
        stream->outbound_queue.pending_bytes = 0;
        a_list_head_init(&stream->outbound_queue.f_list);
        res = aura_now_ts(&stream->start_ts);
        a_list_head_init(&stream->s_list);
        aura_sliding_buffer_create(conn->mc, &stream->sync, 0);
        aura_sliding_buffer_create(conn->mc, &stream->data, 0);

        aura_route_request_init(&stream->req);
    }

    switch (starting_state) {
        /* Not yet supported */
    case A_H2_STREAM_STATE_RESERVED:
        /**
         * It's reserved local, therefore, it would not read data according to rfc,
         * so we add the flag to indicate we won't be reading anything on the stream A_H2_FORBID_READ
         *
         * if not ours, we update flags to indicate no write
         * update the number of incoming reserved streams
         */
        if (a_h2_did_we_initiate_this_stream_id(conn, stream->stream_id)) {
            stream->state = A_H2_STREAM_STATE_HALF_CLOSED_LOCAL;
        } else {
            stream->state = A_H2_STREAM_STATE_HALF_CLOSED_REMOTE;
        }
        break;
    case A_H2_STREAM_STATE_IDLE:
        ++conn->num_of_idle_streams;
        break;
    default:
        /**
         * normal streams,
         * If it's our stream, increment outgoing stream
         * else increment incoming stream
         */
        if (a_h2_did_we_initiate_this_stream_id(conn, stream->stream_id))
            ++conn->num_outbound_streams;
        else
            ++conn->num_inbound_streams;
    }

    return stream;
}

/**
 *
 */
void record_stream_termination(struct aura_h2_stream *stream, const char *str) {}

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
void aura_h2_stream_abandon(struct aura_h2_stream *stream) {
    if (!stream)
        return;

    // update abandoned streams cnt

    record_stream_termination(stream, "abandoned");
}

/**
 *
 */
void aura_h2_stream_close(struct aura_h2_stream *stream) {
    bool stream_is_ours;
    int res;

    if (!stream) {
        /* EINVAL */
        return;
    }

    /* detach from queue */
    a_list_delete(&stream->s_list);

    aura_sliding_buffer_destroy(&stream->sync);
    aura_sliding_buffer_destroy(&stream->data);

    aura_route_request_destroy(&stream->req);

    /* @todo: update stats */
    stream_is_ours = a_h2_stream_is_even_numbered(stream->stream_id);
    if (stream_is_ours)
        --stream->conn->num_outbound_streams;
    else
        --stream->conn->num_inbound_streams;

    stream->state = A_H2_STREAM_STATE_CLOSED;
    aura_free(stream);
}

/**
 *
 */
void aura_h2_stream_reset(struct aura_h2_stream *stream) {
    /** @todo: we are able to reject a frame upto the level of tls record generation, is there need to detect state or flags */
    aura_h2_stream_close(stream);
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
static int aura_h2_stream_push_promise_send(struct aura_h2_conn *conn, struct aura_h2_stream *stream) {
    /* Not supported! */
    return 0;
}
