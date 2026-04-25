#ifndef AURA_SRV_STREAM_H
#define AURA_SRV_STREAM_H

#include "bug_lib.h"
#include "h2/frame.h"
#include "list_lib.h"
#include "memory_lib.h"
#include "route_srv.h"
#include <stdint.h>
#include <sys/time.h>

#define TEMP_SMALL_BUF_SIZE 256

typedef enum {
    A_H2_STREAM_FLAG_NONE = 0,
    A_H2_STREAM_FLAG_READ_HEADERS = 1,
    A_H2_STREAM_FLAG_CONTINUATION = 1 << 2,
    A_H2_STREAM_FLAG_HEADERS_RECEIVED = 1 << 3,
    A_H2_STREAM_FLAG_READ_DATA = 1 << 4,
    A_H2_STREAM_FLAG_READ_TRAILERS = 1 << 5,
    A_H2_STREAM_FLAG_EXECUTING = 1 << 6,
    A_H2_STREAM_FLAG_PAUSED_FLOW_CONTROL = 1 << 7,
    A_H2_STREAM_FLAG_PUSH = 1 << 8,
    A_H2_STREAM_FLAG_SEND_HEADERS = 1 << 9,
    A_H2_STREAM_FLAG_HEADERS_SENT = 1 << 10,
    A_H2_STREAM_FLAG_SEND_DATA = 1 << 11,
} aura_h2_stream_flags_t;

typedef enum {
    A_H2_STREAM_STATE_IDLE,
    A_H2_STREAM_STATE_OPEN,
    A_H2_STREAM_STATE_RESERVED_LOCAL,
    A_H2_STREAM_STATE_RESERVED_REMOTE,
    A_H2_STREAM_STATE_RESERVED, /* used to cover both local and peer's reserved states  */
    A_H2_STREAM_STATE_HALF_CLOSED_REMOTE,
    A_H2_STREAM_STATE_HALF_CLOSED_LOCAL,
    A_H2_STREAM_STATE_CLOSING,
    A_H2_STREAM_STATE_CLOSED
} aura_h2_stream_state_t;

#define aura_h2_stream_is_even_numbered(id) (((id) & 0x1) == 0)
#define aura_h2_stream_is_odd_numbered(id) (((id) & 0x1) == 1)

struct aura_h2_stream_outbound_queue {
    struct aura_list_head f_list;
    size_t pending_bytes;
    bool blocked_by_flow_control;
    bool blocked_by_connection;
};

/* H2 stream structure */
struct aura_h2_stream {
    uint32_t stream_id;
    struct aura_h2_ctx *h2_ctx; /* connection structure this streams belongs to */
    aura_h2_stream_state_t state;
    struct aura_h2_window local_window_size;
    struct aura_h2_window peer_window_size;
    struct aura_h2_priority priority;
    uint32_t consumed_bytes; /* window accumulator */
    uint64_t content_length; /* content len of req/res */
    uint32_t received_len;   /* content len received so far */
    struct timespec start_ts;
    uint16_t status_code; /* server response status code */

    struct aura_sliding_buf *sync; /* Headers buffer */
    struct aura_sliding_buf *data; /* Data buffer */
    struct aura_h2_stream_outbound_queue outbound_queue;

    bool reset_by_peer : 1;
    bool reset_by_peer_action : 1;

    aura_h2_stream_flags_t flags;

    struct aura_http_req req;
    struct aura_http_res res;
    struct aura_list_head s_list;
    bool queued;
    void *user_data;
};

static inline size_t aura_h2_stream_get_local_window_size(struct aura_h2_stream *stream) {
    return stream->local_window_size.available;
}

static inline size_t aura_h2_stream_get_peer_window_size(struct aura_h2_stream *stream) {
    return stream->peer_window_size.available;
}

/**
 * Check if given stream can receive headers
 * Returns 0 if it can, otherwise returns error and indicated error level
 * is the stream cannot receive headers.
 */
static inline int aura_h2_conn_stream_headers_allowed(struct aura_h2_stream *stream, bool *is_stream_error) {
    if (stream->state == A_H2_STREAM_STATE_RESERVED_LOCAL || stream->flags & A_H2_STREAM_FLAG_CONTINUATION) {
        *is_stream_error = false;
        return A_H2_PROTOCOL_ERROR;
    }

    if (stream->state == A_H2_STREAM_STATE_HALF_CLOSED_REMOTE) {
        *is_stream_error = true;
        return A_H2_STREAM_CLOSED_ERROR;
    }

    if (stream->state == A_H2_STREAM_STATE_CLOSED) {
        *is_stream_error = false;
        return A_H2_STREAM_CLOSED_ERROR;
    }

    return A_H2_ERROR_NONE;
}

static inline bool aura_h2_stream_trailing_headers(struct aura_h2_stream *stream) {
    return stream->state == A_H2_STREAM_STATE_CLOSING;
}

/* Defer I/O on given stream due to flow control */
static inline void aura_h2_stream_pause(struct aura_h2_stream *stream) {
    A_BUG_ON_2(aura_sliding_buffer_is_empty(stream->data), true);

    stream->flags |= A_H2_STREAM_FLAG_PAUSED_FLOW_CONTROL;
}

/* Resume I/O on given stream */
static inline void aura_h2_stream_resume(struct aura_h2_stream *stream) {
    stream->flags &= ~A_H2_STREAM_FLAG_PAUSED_FLOW_CONTROL;
}

/**
 * Return true if stream was can now resume I/O, otherwise false
 * @c: current window size
 * @n: updated window size
 */
static inline bool aura_h2_stream_should_resume_send(int32_t c, int32_t n) {
    return (c <= 0 && n > 0);
}

/**
 * Returns true if stream has pending data to send,
 * otherwise false
 */
static inline bool aura_h2_stream_has_pending_data(struct aura_h2_stream *stream) {
    return !aura_sliding_buffer_is_empty(stream->data);
}

static inline bool aura_h2_stream_is_push_stream(uint32_t stream_id) {
    return aura_h2_stream_is_even_numbered(stream_id);
}

/**
 * Intialize a new stream on the connection
 */
int aura_h2_stream_init(struct aura_h2_stream *stream, struct aura_memory_ctx *mc, uint32_t stream_id,
                        uint8_t starting_state, uint32_t flags, void *user_data);

/**/
void aura_h2_stream_reset(struct aura_h2_stream *stream);
/**/
void aura_h2_stream_destroy(struct aura_h2_stream *stream);

/** */
bool aura_h2_stream_can_send(struct aura_h2_stream *stream);

/** */
void aura_h2_stream_dump(struct aura_h2_stream *stream);

/* Claim values from rt response object */
int aura_h2_stream_claim_rt_response(struct aura_h2_stream *stream, Response *resp);
#endif