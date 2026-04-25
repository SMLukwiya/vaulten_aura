#ifndef AURA_H2_H
#define AURA_H2_H

#include "bug_lib.h"
#include "connection.h"
#include "core.h"
#include "error_lib.h"
#include "h2/frame.h"
#include "h2/hpack_srv.h"
#include "h2/scheduler.h"
#include "h2/stream.h"
#include "list_lib.h"
#include "memory_lib.h"
#include "route_srv.h"
#include "slab_lib.h"
#include "types_lib.h"
#include <stdint.h>

#define A_H2_DATA_PAYLOAD 16384 /* 16KB */
#define A_H2_CONNECTION_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
const static struct aura_iovec aura_h2_connection_preface = {
  .base = A_H2_CONNECTION_PREFACE,
  .len = sizeof(A_H2_CONNECTION_PREFACE) - 1,
};

static const struct aura_iovec a_h2_error_reasons[] = {
  a_str_lit_static(NULL),
  a_str_lit_static("INVALID argument"),
  a_str_lit_static("SETTINGS expected"),
  a_str_lit_static("MAX CONCURRENT streams exceeded"),
  a_str_lit_static("Internal server error"),
};

typedef enum {
    A_H2_ERROR_IDX_NONE = 0,
    A_H2_ERROR_IDX_INVALID_ARG = 1,
    A_H2_ERROR_IDX_SETTINGS_EXPECTED = 2,
    A_H2_ERROR_IDX_MAX_CONC_STREAMS = 3,
    AURA_H2_ERROR_IDX_INTERNAL_ERROR = 4
} aura_h2_error_idx;

static const uint8_t a_h2_frame_lengths[] = {
  [A_H2_FRAME_TYPE_RST_STREAM] = 4,
  [A_H2_FRAME_TYPE_SETTINGS] = 6,
  [A_H2_FRAME_TYPE_PING] = 8,
  [A_H2_FRAME_TYPE_GOAWAY] = 8,
  [A_H2_FRAME_TYPE_WINDOW_UPDATE] = 4,
};

static int error_table[] = {
  [A_H2_PROTOCOL_ERROR] = A_PROGRESS_ERROR,
  [A_H2_FRAME_SIZE_ERROR] = A_PROGRESS_ERROR,
  [A_H2_COMPRESSION_ERROR] = A_PROGRESS_ERROR,
  [A_H2_FLOW_CONTROL_ERROR] = A_PROGRESS_ERROR,
  [A_H2_SETTINGS_TIMEOUT_ERROR] = A_PROGRESS_ERROR,
  [A_H2_FRAME_INCOMPLETE] = A_PROGRESS_BLOCKED,
  [A_H2_ERROR_NONE] = A_PROGRESS_DONE,
  [A_H2_ERROR_IN_PROGRESS] = A_PROGRESS_BLOCKED,
};

typedef enum {
    A_H2_PROCESS_OK,
    A_H2_PROCESS_DROP,
    A_H2_PROCESS_BACKPRESSURE,
    A_H2_PROCESS_REJECT,
    A_H2_PROCESS_TERMINATE
} aura_h2_process_result_t;

typedef enum {
    A_H2_CONN_STATE_PREFACE,
    A_H2_CONN_STATE_PREFACE_SETTINGS,
    A_H2_CONN_STATE_FRAMES,
    A_H2_CONN_STATE_CLOSING,
    A_H2_CONN_STATE_CLEANUP,
} aura_h2_conn_state_t;

typedef enum {
    A_H2_CONN_FLAG_NONE = 0,
    A_H2_CONN_FLAG_EXPECT_CONTINUATION,
    A_H2_CONN_FLAG_GOAWAY_QUEUED,
    A_H2_CONN_FLAG_GOAWAY_SENT,
    A_H2_CONN_FLAG_GOAWAY_RECEIVED,
} aura_h2_conn_flags_t;

extern const struct aura_h2_settings aura_h2_default_settings;

#define A_H2_DEFAULT_OUTPUT_BUF_SIZE 81920          /* connection flow control window plus alpha */
#define A_H2_DEFAULT_OUTPUT_BUF_SOFT_MAX 524288     /* 512KB */
#define A_H2_DEFAULT_OUTPUT_BUF_WRITE_TIMEOUT 60000 /* 60s close if write not complete */

/* Forward declarations */
struct aura_conn;
struct aura_h2_callbacks;
typedef int (*aura_h2_state_handler)(struct aura_h2_ctx *h2_conn);

/**
 * H2 callbacks
 */
struct aura_h2_callbacks {
    /**
     * callback to receive data from sock
     */
    int (*receive_callback)(struct aura_h2_ctx *conn);
    /**
     * callback to send data to sock
     */
    int (*send_callback)(struct aura_h2_ctx *conn);
    /**
     *
     */
    int (*header_begin_callback)(struct aura_h2_ctx *conn, struct aura_h2_frame *frame, struct aura_h2_stream **stream);
    /**
     * callback when header is received
     */
    int (*header_callback)(struct aura_h2_ctx *conn, struct aura_h2_stream *stream, const uint8_t *src, size_t len);
    /**
     * callback when data is received
     */
    int (*receive_data_callback)(struct aura_h2_ctx *conn);
    /**
     * callback
     */
    int (*send_data_callback)(struct aura_h2_ctx *conn);
};

/* aura h2 conn context */
struct aura_h2_ctx {
    bool is_server;
    struct aura_conn *conn;             /* Generic connection to which protocol belongs */
    struct aura_list_head stream_list;  /* streams attached to this connection */
    struct aura_list_head pending_reqs; /* Requests that should be handled immediately connection is valid */
    struct aura_h2_scheduler scheduler;

    struct aura_list_head peer_unacknowledged_settings;
    uint32_t peer_unacknowledged_settings_cnt; /* settings we have sent and not received any ACK for! */
    uint32_t local_unacknowledged_settings;    /* settings we have received and not yet sent any ACK for! */
    uint32_t next_stream_id;                   /* Max stream id from which we can the next valid stream_id (< 1 << 31) */
    uint32_t max_sent_stream_id;               /* Max stream id initiated from our side, client or server */
    uint32_t max_received_stream_id;           /* Max stream id received from peer */
    uint32_t last_processed_stream_id;         /* Last stream id that received any processing (used in GOAWAY) */
    uint32_t local_goaway_stream_id;           /* Last stream id we used in a GOAWAY */
    uint32_t peer_goaway_stream_id;            /* Last stream id received from a peer's GOAWAY */

    uint64_t num_of_streams;        /* Total number of streams of all kinds still on the streams list */
    uint64_t num_of_closed_streams; /* Number of closed streams still in stream list */
    uint64_t num_of_idle_streams;   /* Number of idle streams still in stream list */

    struct aura_h2_window local_window_size;
    struct aura_h2_window peer_window_size;
    struct aura_h2_settings peer_settings;  /* connection peer's settings */
    struct aura_h2_settings local_settings; /* our local settings */

    // stream reset rate
    // stream glitch rate
    uint64_t num_outbound_streams; /* number of outbound streams */
    uint64_t num_inbound_streams;  /* number of inbound streams */
    struct aura_h2_callbacks callbacks;
    aura_h2_state_handler state_handler;

    aura_h2_conn_state_t state;

    struct aura_hpack_dyn_table input_hdr_table;
    struct aura_hpack_dyn_table output_hdr_table;
    struct aura_intern_tab *intern_tab;
    uint32_t consumed;
    uint32_t last_record_size;

    struct aura_sliding_buf *headers_to_parse; /* holds headers not yet parsed (continuation frame needed) */

    struct {
        struct timespec conn_started_at;
        struct timespec settings_sent_at;
        struct timespec settings_ack_at;
    } timestamps;
    uint32_t flags;
};

/**
 * Create response for error on given stream
 * closing the stream after submitting
 */
int aura_submit_error_response(struct aura_h2_ctx *conn, struct aura_h2_stream *stream, int status);

/**
 * Construct a response to send to the peer
 */
// int aura_submit_response(struct aura_h2_ctx *h2_ctx, int status, struct aura_header_field *hdrs,
//                          size_t num_of_hdrs, struct aura_h2_stream *stream, size_t content_length,
//                          struct aura_sliding_buf *buf, bool end_stream);
int aura_h2_submit_rt_response(struct aura_h2_ctx *h2_ctx, struct aura_h2_stream *stream, Response *resp);

/* Create h2 server connection */
struct aura_h2_ctx *aura_h2_server_conn_create(struct aura_memory_ctx *mc);

/* Create h2 client connection */
struct aura_h2_ctx *aura_h2_client_conn_create(struct aura_memory_ctx *mc);

struct aura_h2_ctx *aura_h2_ctx_init(struct aura_memory_ctx *mc, bool is_server);

/**/
void aura_h2_ctx_destroy(struct aura_h2_ctx *h2_ctx);
/** */
struct aura_h2_stream *aura_h2_conn_stream_open(struct aura_h2_ctx *h2_ctx, uint32_t stream_id,
                                                uint8_t initial_state, uint8_t flags, void *user_data);

int aura_h2_process(void *protocol_ctx);

/**
 * Find a stream with given stream id
 * Returns NULL if unsuccessful
 */
static inline struct aura_h2_stream *aura_h2_conn_find_stream(struct aura_h2_ctx *conn, uint32_t stream_id) {
    struct aura_h2_stream *s;
    a_list_for_each(s, &conn->stream_list, s_list) {
        if (s->stream_id == stream_id) {
            return s;
        }
    }
    return NULL;
}

/**
 * Returns true if this is stream id was created by us
 */
static inline bool aura_h2_conn_stream_is_local(struct aura_h2_ctx *h2_ctx, uint32_t stream_id) {
    if (likely(stream_id == 0))
        return false;

    if (likely(h2_ctx->is_server))
        /* server push streams */
        return aura_h2_stream_is_even_numbered(stream_id);
    else
        /* client sent streams */
        return aura_h2_stream_is_odd_numbered(stream_id);
}

static inline void aura_h2_consume_window(struct aura_h2_window *w, uint64_t bytes) {
    w->available -= bytes;
}

/**
 * Check if number of active outbound streams is
 * larger than peers max_concurrent_streams
 */
static inline bool aura_h2_max_concurrent_outbound_streams_reached(struct aura_h2_ctx *h2_ctx) {
    return h2_ctx->num_outbound_streams >= h2_ctx->peer_settings.max_conc_streams;
}

/**
 * Returns true if we have reached the max concurrrent streams
 * per connection
 */
static inline bool aura_h2_conn_max_conc_inbound_streams_reached(struct aura_h2_ctx *h2_ctx) {
    return h2_ctx->num_inbound_streams >= h2_ctx->local_settings.max_conc_streams;
}

static inline size_t a_h2_get_conn_local_window_size(struct aura_h2_ctx *h2_ctx) {
    return h2_ctx->local_window_size.available;
}

static inline size_t a_h2_get_conn_peer_window_size(struct aura_h2_ctx *h2_ctx) {
    return h2_ctx->peer_window_size.available;
}

/**
 * Test if we can open a new stream on
 * this current connection
 * @todo: both checks may be redundant
 */
static inline bool aura_h2_conn_new_streams_allowed(struct aura_h2_ctx *h2_ctx) {
    if (h2_ctx->state == A_H2_CONN_STATE_CLOSING)
        return false;
    if (h2_ctx->flags & (A_H2_CONN_FLAG_GOAWAY_RECEIVED | A_H2_CONN_FLAG_GOAWAY_SENT))
        return false;
    return true;
}

/**
 * Returns number of active streams
 */
static inline uint64_t aura_conn_get_active_streams(struct aura_h2_ctx *h2_ctx) {
    return (h2_ctx->num_of_streams) - (h2_ctx->num_of_idle_streams + h2_ctx->num_of_closed_streams);
}

/* Return true if this a new stream id from peer */
static inline bool aura_h2_conn_peer_stream_id_new(struct aura_h2_ctx *h2_ctx, uint32_t stream_id) {
    if (stream_id == 0)
        return false;

    return stream_id > h2_ctx->max_received_stream_id;
}

/**
 * Test if the stream id received represents
 * an idle stream
 */
static inline bool aura_h2_stream_is_idle(struct aura_h2_ctx *h2_ctx, uint32_t stream_id) {
    if (aura_h2_conn_stream_is_local(h2_ctx, stream_id))
        return stream_id > h2_ctx->next_stream_id;

    return aura_h2_conn_peer_stream_id_new(h2_ctx, stream_id);
}

/**
 * Returns true if connection can read
 * data from peer, otherwise false
 */
static inline bool aura_conn_can_read(struct aura_h2_ctx *h2_ctx) {
    uint64_t num_active_streams;

    /**
     * Read incoming frames that may have already been sent
     * before GOAWAY was sent or received
     */
    if (aura_conn_get_active_streams(h2_ctx) > 0)
        return true;

    return (h2_ctx->flags & (A_H2_CONN_FLAG_GOAWAY_SENT | A_H2_CONN_FLAG_GOAWAY_RECEIVED)) == 0;
}

/**
 * Returns true if connection can write to peer,
 * otherwise false
 */
static inline bool aura_conn_can_write(struct aura_h2_ctx *h2_ctx) {

    /* queues no subject to flow control */
    // if (!a_list_is_empty(&h2_ctx->sender.queues.urgent.head) ||
    if (!a_list_is_empty(&h2_ctx->scheduler.queues.urgent.head) ||
        !a_list_is_empty(&h2_ctx->scheduler.queues.control.head))
        return true;

    if (!a_list_is_empty(&h2_ctx->scheduler.queues.data.head) && h2_ctx->peer_window_size.available > 0)
        return true;

    /* check syn headers against peer max concurrent */

    return false;
}

/**
 * Test if the connection has initiated
 * closing state
 */
static inline bool aura_h2_conn_is_closing(struct aura_h2_ctx *h2_ctx) {
    return (!aura_conn_can_read(h2_ctx) && aura_conn_can_write(h2_ctx));
}

/**
 * Get the max flow control size for data reading
 * taking into account stream and connection window size
 */
static inline size_t aura_h2_conn_get_flow_control_size(struct aura_h2_ctx *h2_ctx, struct aura_h2_stream *stream) {
    ssize_t size;

    size = a_min(h2_ctx->peer_window_size.available, a_min(stream->peer_window_size.available, A_H2_DATA_PAYLOAD));
    return a_max(size, 0);
}

/* Transition h2 state */
static inline void aura_h2_conn_transition_state(struct aura_h2_ctx *h2_conn, aura_h2_conn_state_t new_state) {
    if (h2_conn->state != new_state)
        h2_conn->state = new_state;
}

/* Transition h2 state handler */
static inline void aura_h2_conn_transition_state_handler(struct aura_h2_ctx *h2_conn, aura_h2_state_handler handler) {
    if (h2_conn->state_handler != handler)
        h2_conn->state_handler = handler;
}

/* Returns true if error is fatal */
static inline bool aura_h2_error_is_fatal(int err) {
}

/* Return true is error is non fatal */
static inline bool aura_h2_error_is_non_fatal(int err) {}

static inline uint32_t a_calculate_frame_len(uint8_t frame_type, uint32_t cnt, uint32_t additional_len) {
    uint32_t frame_len;

    switch (frame_type) {
    case A_H2_FRAME_TYPE_RST_STREAM:
        frame_len = a_h2_frame_lengths[A_H2_FRAME_TYPE_RST_STREAM] + A_H2_FRAME_HEADER_SIZE;
        break;
    case A_H2_FRAME_TYPE_SETTINGS:
        frame_len = a_h2_frame_lengths[A_H2_FRAME_TYPE_SETTINGS] * cnt;
        frame_len += A_H2_FRAME_HEADER_SIZE;
        break;
    case A_H2_FRAME_TYPE_PING:
        frame_len = a_h2_frame_lengths[A_H2_FRAME_TYPE_PING] + A_H2_FRAME_HEADER_SIZE;
        break;
    case A_H2_FRAME_TYPE_GOAWAY:
        frame_len = a_h2_frame_lengths[A_H2_FRAME_TYPE_GOAWAY] + additional_len;
        frame_len += A_H2_FRAME_HEADER_SIZE;
        break;
    case A_H2_FRAME_TYPE_WINDOW_UPDATE:
        frame_len = a_h2_frame_lengths[A_H2_FRAME_TYPE_WINDOW_UPDATE] + A_H2_FRAME_HEADER_SIZE;
        break;
    default:
        app_debug(true, 0, "a_calculate_frame_len: Unknown frame type: %d", frame_type);
        frame_len = 0;
    }

    return frame_len;
}

/****======================================= */
int aura_h2_conn_enqueue_goaway(struct aura_h2_ctx *h2_ctx, uint32_t last_stream_id,
                                int err_code, const struct aura_iovec *reason);

struct aura_h2_stream *aura_h2_conn_stream_open(struct aura_h2_ctx *h2_ctx, uint32_t stream_id,
                                                uint8_t initial_state, uint8_t flags, void *user_data);

int aura_setup_preface_settings(struct aura_h2_ctx *h2_ctx);

static inline void aura_send_stream_error(struct aura_h2_ctx *h2_ctx, struct aura_h2_stream *stream, int err_num);

int aura_h2_send_rst_frame(struct aura_h2_ctx *h2_ctx, uint32_t stream_id, int err_num);

int aura_process_settings(struct aura_h2_ctx *h2_ctx, struct aura_h2_in_frame *in_frame);

int aura_process_priority(struct aura_h2_ctx *h2_ctx, struct aura_h2_in_frame *frame);

int aura_process_ping(struct aura_h2_ctx *h2_ctx, struct aura_h2_in_frame *in_frame);

int aura_process_goaway(struct aura_h2_ctx *h2_ctx, struct aura_h2_in_frame *in_frame);

int aura_process_rst_stream(struct aura_h2_ctx *h2_ctx, struct aura_h2_in_frame *in_frame);

int aura_process_window_update(struct aura_h2_ctx *h2_ctx, struct aura_h2_in_frame *in_frame);

int aura_process_continuation(struct aura_h2_ctx *h2_ctx, struct aura_h2_in_frame *in_frame);

void aura_enqueue_write(struct aura_h2_ctx *h2_ctx);

#endif