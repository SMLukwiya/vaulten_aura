#ifndef AURA_SRV_CONNECTION_H
#define AURA_SRV_CONNECTION_H

#include "error_lib.h"
#include "h2/frame.h"
#include "h2/hpack_srv.h"
#include "h2/stream.h"
#include "list_lib.h"
#include "route_srv.h"
#include "types_lib.h"
#include <stdint.h>

#define A_H2_CONNECTION_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
const static struct aura_iovec aura_h2_connection_preface = {
  .base = A_H2_CONNECTION_PREFACE,
  .len = sizeof(A_H2_CONNECTION_PREFACE) - 1,
};

typedef enum {
    A_H2_STATE_CONN_OPEN,
    A_H2_STATE_CONN_HALF_CLOSED,
    A_H2_STATE_CONN_CLOSING
} aura_h2_conn_state_t;

typedef enum {
    A_H2_CONN_FLAG_NONE = 0,
    A_H2_CONN_GOAWAY_QUEUED = 1, /** @todo: not used */
    A_H2_CONN_GOAWAY_GRACEFUL_TERM_SENT = 2,
    A_H2_CONN_GOAWAY_IMMEDIATE_TERM_SENT = 3,
    A_H2_CONN_GOAWAY_RECEIVED = 4,
} aura_h2_conn_flags_t;

extern const struct aura_h2_settings aura_h2_default_settings;

struct aura_h2_conn_stream_num {
    uint32_t open;
    uint32_t half_closed;
    uint32_t sending_body;
};

/**
 * H2 callbacks
 */
struct aura_h2_callbacks {
    /**
     * callback to receive data from sock
     */
    int (*receive_callback)(struct aura_h2_conn *conn);
    /**
     * callback to send data to sock
     */
    int (*send_callback)(struct aura_h2_conn *conn);
    /**
     *
     */
    int (*header_begin_callback)(struct aura_h2_conn *conn, struct aura_h2_frame *frame, struct aura_h2_stream **stream);
    /**
     * callback when header is received
     */
    int (*header_callback)(struct aura_h2_conn *conn, struct aura_h2_stream *stream, const uint8_t *src, size_t len);
    /**
     * callback when data is received
     */
    int (*receive_data_callback)(struct aura_h2_conn *conn);
    /**
     * callback
     */
    int (*send_data_callback)(struct aura_h2_conn *conn);
};

/**
 * Control queues for output frames
 */
struct aura_h2_conn_queues {
    /* Urgent frames (GOAWAY, RST and the likes) */
    struct {
        struct aura_list_head head;
        size_t cnt;
    } urgent;

    /* Control frames (Headers, Settings, and the likes) */
    struct {
        struct aura_list_head head;
        size_t cnt;
    } control;

    /* Data frames subject to control flow */
    struct {
        struct aura_list_head head;
        size_t cnt;
    } data;

    size_t total_frames;
    size_t total_bytes_sent;
};

/**
 * Sender engine responsible for
 * scheduling and sending data to the peer
 */
struct aura_h2_sender_engine {
    struct aura_h2_conn_queues queues;
    struct aura_sliding_buf write_buf;

    struct aura_h2_out_frame *current_frame;

    uint64_t bytes_sent_this_tick;
    uint64_t last_tick_time;
    size_t max_bytes_per_tick;
};

/**
 * An H2 connection structure
 */
struct aura_h2_conn {
    bool is_server;
    bool preface_processed; /* Whether preface has been processed */
    struct aura_memory_ctx *mc;
    struct aura_srv_sock *sock;        /* socket that accepted this conn */
    struct aura_srv_ctx *srv_ctx;      /* global server context */
    struct aura_route *route;          /* route that handles this connection */
    struct aura_list_head stream_list; /* streams attached to this connection */
    struct aura_h2_sender_engine sender;

    struct aura_list_head peer_unacknowledged_settings;
    uint32_t peer_unacknowledged_settings_cnt; /* settings we have sent and not received any ACK for! */
    uint32_t local_unacknowledged_settings;    /* settings we have received and not yet sent any ACK for! */
    uint32_t max_open_stream_id;               /* Max stream id from which we can the next valid stream_id (< 1 << 31) */
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

    struct aura_h2_callbacks callbacks;

    // stream reset rate
    // stream glitch rate
    uint64_t num_outbound_streams; /* number of outbound streams */
    uint64_t num_inbound_streams;  /* number of inbound streams */

    aura_h2_conn_state_t state;

    struct aura_hpack_hdr_table input_hdr_table;
    struct aura_hpack_hdr_table output_hdr_table;
    uint32_t consumed;
    uint32_t last_record_size;

    struct aura_sliding_buf headers_to_parse; /* holds headers not yet parsed (continuation frame needed) */

    struct {
        struct timeval settings_sent_at;
        struct timeval settings_ack_at;
    } timestamps;

    struct aura_list_head conn_list; /* link in queue */
    uint32_t flags;
};

/**
 * Find a stream with given stream id
 * Returns NULL if unsuccessful
 */
static inline struct aura_h2_stream *aura_h2_find_stream(struct aura_h2_conn *conn, uint32_t stream_id) {
    struct aura_h2_stream *s;
    a_list_for_each(s, &conn->stream_list, s_list) {
        if (s->stream_id == stream_id) {
            return s;
        }
    }
    return NULL;
}

/**
 * @c: current window size
 * @n: updated window size
 */
static inline bool aura_h2_stream_should_resume_send(int32_t c, int32_t n) {
    return (c <= 0 && n > 0);
}

static inline bool aura_h2_stream_has_pending_data(struct aura_h2_stream *stream) {
    return aura_sliding_buffer_is_empty(&stream->data) == false;
}

/**
 * Returns true if this is stream id was created by us
 */
static inline bool a_h2_did_we_initiate_this_stream_id(struct aura_h2_conn *conn, uint32_t stream_id) {
    if (likely(stream_id == 0))
        return false;

    if (likely(conn->is_server))
        /* server push streams */
        return a_h2_stream_is_even_numbered(stream_id);
    else
        /* client sent streams */
        return a_h2_stream_is_odd_numbered(stream_id);
}

static inline void aura_h2_consume_window(struct aura_h2_window *w, uint64_t bytes) {
    w->available -= bytes;
}

/**
 * Check if number of active outbound streams is
 * larger than peers max_concurrent_streams
 */
static inline bool aura_h2_concurrent_outbound_streams_max(struct aura_h2_conn *conn) {
    return conn->num_outbound_streams >= conn->peer_settings.max_conc_streams;
}

static inline size_t a_h2_get_conn_local_window_size(struct aura_h2_conn *conn) {
    return conn->local_window_size.available;
}

static inline size_t a_h2_get_conn_peer_window_size(struct aura_h2_conn *conn) {
    return conn->peer_window_size.available;
}

/**
 * Initiate the process of closing the connection
 */
static inline void aura_h2_connection_initiate_closing(struct aura_h2_conn *conn, uint32_t last_stream_id) {
    conn->last_processed_stream_id = last_stream_id;
    conn->flags |= A_H2_CONN_GOAWAY_RECEIVED;
    conn->flags = A_H2_STATE_CONN_CLOSING;
    /** @todo: maybe start graceful shutdown timer */
}

/**
 * Test if we can open a new stream on
 * this current connection
 */
static inline bool a_h2_conn_allow_new_streams(struct aura_h2_conn *conn) {
    if (conn->state == A_H2_STATE_CONN_CLOSING)
        return false;
    if (conn->flags & (A_H2_CONN_GOAWAY_RECEIVED | A_H2_CONN_GOAWAY_GRACEFUL_TERM_SENT))
        return false;
    return true;
}

/**
 * Returns number of active streams
 */
static inline uint64_t a_conn_get_active_streams(struct aura_h2_conn *conn) {
    return (conn->num_of_streams) - (conn->num_of_idle_streams + conn->num_of_closed_streams);
}

/**
 * Returns true if we have reached the max concurrrent streams
 * per connection
 */
static inline bool a_conn_has_reached_max_concurrent_streams(struct aura_h2_conn *conn) {
    return (conn->num_inbound_streams >= conn->local_settings.max_conc_streams);
}

/**
 * Test if the connection has initiated
 * closing state
 */
static inline bool conn_is_closing(struct aura_h2_conn *conn) {
    /* goaway sent and conn doesn't want to read or write */
    if (conn->state == A_H2_STATE_CONN_CLOSING)
        return true;

    if (conn->flags & A_H2_CONN_GOAWAY_RECEIVED || conn->flags & A_H2_CONN_GOAWAY_GRACEFUL_TERM_SENT)
        return true;

    return false;
}

/* Return true if this a new stream id from peer */
static inline bool a_h2_peer_stream_id_new(struct aura_h2_conn *conn, uint32_t stream_id) {
    if (stream_id == 0)
        return false;

    return !a_h2_did_we_initiate_this_stream_id(conn, stream_id) && stream_id > conn->max_received_stream_id;
}

/**
 * Test if the stream id received represents
 * an idle stream
 */
static inline bool aura_h2_stream_is_idle(struct aura_h2_conn *conn, uint32_t stream_id) {
    if (a_h2_did_we_initiate_this_stream_id(conn, stream_id))
        return stream_id > conn->max_open_stream_id;

    return a_h2_peer_stream_id_new(conn, stream_id);
}

/* Returns true if error is fatal */
static inline bool aura_h2_error_is_fatal(int err) {
}

/* Return true is error is non fatal */
static inline bool aura_h2_error_is_non_fatal(int err) {}

/** */
struct aura_h2_conn *aura_h2_create_connection_server(struct aura_srv_sock *sock, struct aura_srv_ctx *ctx);

/** */
int aura_conn_parse_input(struct aura_h2_conn *conn);

/** */
void aura_h2_connection_close(struct aura_h2_conn *conn);

/** */
void a_enqueue_write(struct aura_h2_conn *conn);

#endif