#include "h2/connection.h"
#include "bug_lib.h"
#include "h2/h2_srv.h"
#include "route_srv.h"
#include "server_srv.h"
#include "slab_lib.h"
#include "socket_srv.h"
#include "utils_lib.h"

/* String errors that can be sent to the peer */
const struct aura_iovec a_h2_error_reasons[] = {
  a_str_lit_static(NULL),
  a_str_lit_static("INVALID argument"),
  a_str_lit_static("SETTINGS expected"),
  a_str_lit_static("MAX CONCURRENT streams exceeded"),
};

typedef enum {
    A_H2_ERROR_IDX_NONE = 0,
    A_H2_ERROR_IDX_INVALID_ARG = 1,
    A_H2_ERROR_IDX_SETTINGS_EXPECTED = 2,
    A_H2_ERROR_IDX_MAX_CONC_STREAMS = 3
} aura_h2_error_idx;

const uint8_t a_h2_frame_lengths[] = {
  [A_H2_FRAME_TYPE_RST_STREAM] = 4,
  [A_H2_FRAME_TYPE_SETTINGS] = 6,
  [A_H2_FRAME_TYPE_PING] = 8,
  [A_H2_FRAME_TYPE_GOAWAY] = 8,
  [A_H2_FRAME_TYPE_WINDOW_UPDATE] = 4,
};

/**
 * Allocate slab slot for new connection
 */
struct aura_h2_conn *a_conn_alloc(struct aura_memory_ctx *mc) {
    app_debug(true, 0, "<><><> a_conn_alloc");
    struct aura_slab_cache *sc;
    struct aura_h2_conn *conn;

    sc = aura_slab_cache_find_by_id(mc, A_SLAB_CACHE_ID_CONNECTION);
    A_BUG_ON_2(!sc, true);

    conn = aura_slab_alloc(sc);
    aura_slab_cache_dump(sc);
    return conn;
}

static int a_process_headers_early_bailout(struct aura_h2_conn *conn, struct aura_h2_stream *stream, const uint8_t *src, size_t len);

/**
 *
 */
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
        app_debug(true, 0, "Frame length error, Unknown frame type: %d", frame_type);
        frame_len = 0;
    }

    return frame_len;
}

/**
 *
 */
static inline int a_update_window_size(struct aura_h2_window *w, uint32_t n) {
    int64_t new_sz;

    new_sz = w->available + n;
    if (new_sz > INT32_MAX)
        return A_H2_FLOW_CONTROL_ERROR;
    w->available = new_sz;

    return 0;
}

/**
 *
 */
static inline int a_update_stream_peer_window_size(struct aura_h2_stream *stream, uint32_t n) {
    struct aura_h2_window *w;
    int64_t cur_sz, updated_sz;
    int res;

    w = &stream->peer_window_size;
    cur_sz = w->available;
    res = a_update_window_size(w, n);
    if (res != 0)
        return res;

    updated_sz = w->available;
    if (aura_h2_stream_should_resume_send(cur_sz, updated_sz) && aura_h2_stream_has_pending_data(stream)) {
        // reactivate for sending
    }
    return 0;
}

/* Returns true for trailing header */
static bool a_h2_is_trailer_headers(struct aura_h2_stream *s, struct aura_h2_frame *f, bool is_server) {
    if (!s || f->type != A_H2_FRAME_TYPE_HEADERS)
        return false;

    return s->flags & (A_H2_STREAM_FLAG_HEADERS_RECEIVED | A_H2_STREAM_FLAG_HEADERS_SENT) != 0;
}

static inline bool a_h2_stream_is_reserved_local(struct aura_h2_stream *s) {
    return s->state == A_H2_STREAM_STATE_RESERVED_LOCAL;
}

static inline bool a_h2_stream_is_reserved_remote(struct aura_h2_stream *s) {
    return s->state == A_H2_STREAM_STATE_RESERVED_REMOTE;
}

/**/
void a_enqueue_write(struct aura_h2_conn *conn) {
    aura_socket_write(conn->sock);
}

/**
 *
 */
static void a_h2_stream_reset(struct aura_h2_conn *conn, struct aura_h2_stream *s) {

    switch (s->state) {
    case A_H2_STREAM_STATE_IDLE:
    case A_H2_STREAM_STATE_OPENING:
    case A_H2_STREAM_STATE_HALF_CLOSED_LOCAL:
    }
}

/** */
static int a_h2_connection_terminate(struct aura_h2_conn *conn, uint32_t last_stream_id,
                                     int err_code, const struct aura_iovec *reason) {
    struct aura_h2_out_frame *goaway_frame;
    uint32_t goaway_frame_len;
    int res;

    if (conn->flags & (A_H2_CONN_GOAWAY_GRACEFUL_TERM_SENT | A_H2_CONN_GOAWAY_IMMEDIATE_TERM_SENT))
        return 0;

    aura_h2_connection_initiate_closing(conn, last_stream_id);

    /* enqueue goaway */
    goaway_frame = aura_encode_control_frame(
      &conn->srv_ctx->glob_conf->mem_ctx,
      &conn->sender.write_buf,
      A_H2_FRAME_TYPE_GOAWAY,
      0, 0, reason->base, reason->len, goaway_frame_len);

    if (!goaway_frame) {
        return ENOMEM; /** @todo: use app errors */
    }

    conn->flags |= A_H2_CONN_GOAWAY_GRACEFUL_TERM_SENT;
    return 0;
}

/**
 *
 */
static int a_process_invalid_connection() {
}

/** */
int a_begin_headers_callback(struct aura_h2_conn *conn, struct aura_h2_frame *frame, struct aura_h2_stream **stream) {
    app_debug(true, 0, "a_begin_headers_callback <<<<");
    struct aura_h2_stream *_stream;
    int res;

    if (a_h2_peer_stream_id_new(conn, frame->stream_id)) {
        if (a_h2_stream_is_even_numbered(frame->stream_id)) {
            res = a_h2_connection_terminate(
              conn, conn->last_processed_stream_id,
              A_H2_PROTOCOL_ERROR,
              &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG]);
            return res;
        }

        if (a_conn_has_reached_max_concurrent_streams(conn)) {
            res = a_h2_connection_terminate(
              conn, conn->last_processed_stream_id,
              A_H2_PROTOCOL_ERROR,
              &a_h2_error_reasons[A_H2_ERROR_IDX_MAX_CONC_STREAMS]);
        }

        if (!a_h2_conn_allow_new_streams(conn)) {
            return AURA_H2_ERROR_IGNORE;
        }

        _stream = aura_h2_stream_open(conn, frame->stream_id, A_H2_STREAM_STATE_IDLE, A_H2_STREAM_FLAG_PREFACE);
        if (!_stream) {
            return AURA_H2_ERROR_INTERNAL;
        }

        if (a_h2_frame_is_end_stream(frame->flags) && a_h2_frame_is_end_headers(frame->flags)) {
            /* prepare response */
            _stream->state = A_H2_STREAM_STATE_HALF_CLOSED_REMOTE;
        } else if (!a_h2_frame_is_end_stream(frame->flags))
            _stream->flags |= A_H2_STREAM_FLAG_CONTINUATION;
        else
            _stream->flags |= A_H2_STREAM_FLAG_READ_DATA;
    } else {
        /** @todo: push promise not supported */
        _stream = aura_h2_find_stream(conn, frame->stream_id);
        if (!_stream)
            return A_H2_STREAM_CLOSED_ERROR;

        /* trailer */
        if (!a_h2_frame_is_end_stream(frame->flags)) {
            /* trailer must contain end stream flag */
            return A_H2_PROTOCOL_ERROR;
        }

        if (!a_h2_frame_is_end_headers(frame->flags))
            _stream->flags |= A_H2_STREAM_FLAG_CONTINUATION;
    }

    *stream = _stream;
    return A_H2_ERROR_NONE;
}

/** */
static inline int a_handle_trailing_headers() {
    /* handle trailer headers and its continuation */
}

/**
 *
 */
int a_headers_callback(struct aura_h2_conn *conn, struct aura_h2_stream *stream, const uint8_t *src, size_t len) {
    app_debug(true, 0, "a_headers_callback <<<<");

    if (stream->flags & A_H2_STREAM_FLAG_CONTINUATION) {
        return a_handle_trailing_headers();
    } else {
        return a_process_headers_early_bailout(conn, stream, src, len);
    }
}

/** */
struct aura_h2_conn *a_h2_connection_init(struct aura_srv_sock *sock, struct aura_srv_ctx *srv_ctx, bool is_server) {
    app_debug(true, 0, "a_h2_connection_init <<<<");
    struct aura_h2_conn *conn;
    struct aura_h2_stream *zero_id_stream;
    struct aura_h2_callbacks callbacks;

    callbacks.header_begin_callback = a_begin_headers_callback;
    callbacks.header_callback = a_headers_callback;

    conn = a_conn_alloc(&srv_ctx->glob_conf->mem_ctx);
    app_debug(true, 0, "Created a connection: %p", conn);
    if (!conn)
        return NULL;

    conn->is_server = is_server;
    conn->preface_processed = false;
    conn->mc = &srv_ctx->glob_conf->mem_ctx;
    conn->sock = sock;
    conn->srv_ctx = srv_ctx;
    conn->peer_window_size.available = A_H2_INITIAL_WINDOW_SIZE;
    conn->local_window_size.available = A_H2_INITIAL_WINDOW_SIZE;
    memcpy(&conn->peer_settings, &aura_h2_default_settings, sizeof(struct aura_h2_settings));
    memcpy(&conn->local_settings, &aura_h2_default_settings, sizeof(struct aura_h2_settings));
    conn->local_goaway_stream_id = A_H2_STREAM_ID_MASK;
    conn->peer_goaway_stream_id = A_H2_STREAM_ID_MASK;
    // conn->local_unacknowledged_settings = aura_h2_default_settings.max_conc_streams;
    conn->peer_unacknowledged_settings_cnt = aura_h2_default_settings.max_conc_streams;
    // conn->max_inbound_reserved_streams = 200;
    conn->state = A_H2_STATE_CONN_OPEN;
    conn->input_hdr_table.max_dynamic_size = aura_h2_default_settings.hdr_table_size;
    conn->output_hdr_table.max_dynamic_size = aura_h2_default_settings.hdr_table_size;
    aura_sliding_buffer_create(&srv_ctx->glob_conf->mem_ctx, &conn->headers_to_parse, 0);
    aura_sliding_buffer_create(&srv_ctx->glob_conf->mem_ctx, &conn->sender.write_buf, 0);
    a_list_head_init(&conn->sender.queues.urgent.head);
    conn->sender.queues.urgent.cnt = 0;
    a_list_head_init(&conn->sender.queues.control.head);
    conn->sender.queues.control.cnt = 0;
    a_list_head_init(&conn->sender.queues.data.head);
    conn->sender.queues.data.cnt = 0;
    a_list_head_init(&conn->stream_list);
    a_list_head_init(&conn->conn_list);
    // a_list_head_init(&conn->peer_unacknowledged_settings);
    conn->callbacks = callbacks;

    return conn;
}

void aura_h2_connection_close(struct aura_h2_conn *conn) {
    /**/
}

/** */
struct aura_h2_conn *aura_h2_create_connection_server(struct aura_srv_sock *sock, struct aura_srv_ctx *ctx) {
    struct aura_h2_conn *conn;

    conn = a_h2_connection_init(sock, ctx, true);
    if (!conn)
        return NULL;

    conn->max_open_stream_id = 2;
    return conn;
}

/** */
struct aura_h2_conn *aura_h2_create_connection_client(struct aura_srv_sock *sock, struct aura_srv_ctx *ctx) {
    struct aura_h2_conn *conn;

    conn = a_h2_connection_init(sock, ctx, false);
    if (!conn)
        return NULL;

    conn->max_open_stream_id = 1;
    return conn;
}

/* ---- some functions are parts of stream.c ---- */

/** */
static int a_h2_data_frame_append(struct aura_h2_conn *conn, struct aura_h2_stream *s) {
    // assert s is not queued

    /* add to the queue */
    // s->queued = 1;
    return 0;
}

/** */
static int a_h2_data_frame_remove(struct aura_h2_conn *conn, struct aura_h2_stream *s) {
    // assert s is queued
    // remove from queue
    // update not queued anymore
    return 0;
}

/** */
static int a_h2_stream_defer(struct aura_h2_conn *conn, struct aura_h2_stream *s, uint8_t flags) {
    // assert I have Item
    // add the necessary flags
    /* if not queued, return */
    // remove from queue
    return 0;
}

/** */
static int a_h2_stream_resume(struct aura_h2_conn *conn, struct aura_h2_stream *s) {
    // remove whatever flags
    // if the stream still somehow has some kind of defered flag, return 0

    /* push back to queue */
    return 0;
}

/**
 *
 */
static inline bool a_h2_send_rst_frame(struct aura_h2_conn *conn, struct aura_h2_stream *stream, int err_num) {
    struct aura_h2_out_frame *rst_frame;
    uint32_t frame_len;

    if (stream->state == A_H2_STREAM_STATE_CLOSING) {
        return true;
    }

    /*
        if stream is idle, protocol error
    */

    /* if we are client and the stream is ours, cancel and headers associated with this stream
        that creates new headers like push and request headers
    */

    // update error stats
    /* create out frame and enqueue */
    frame_len = a_calculate_frame_len(A_H2_FRAME_TYPE_RST_STREAM, 0, 0);
    rst_frame = aura_encode_control_frame(
      conn->mc, &conn->sender.write_buf,
      A_H2_FRAME_TYPE_RST_STREAM, 0,
      stream->stream_id, NULL, 0, frame_len);
    if (rst_frame == NULL) {
        /* will be process in the next tick */
        return false;
    }
    a_list_add_tail(&conn->sender.queues.control.head, &rst_frame->f_list);
    // rst_frame = a_enqueue_frame(conn, A_H2_FRAME_TYPE_RST_STREAM, 0, &frame_len, 0, NULL);
    // aura_encode_rst_stream_frame(rst_frame, frame_len, stream_id, err_num);
    // a_enqueue_write(conn);

    return true;
}

/** */
int close_if_cannot_read_or_write() {}

/** */
static inline bool can_send(struct aura_h2_conn *conn, struct aura_h2_stream *stream) {
    if (!stream) {
        /* stream closed error */
    }

    /* if conn is closing, return connection closing error*/
    /* if shutdown for write, return that flag */
    return true;
}

static inline bool can_receive_request(struct aura_h2_conn *conn) {
    /* we are not server, we have a valid next stream id, we have not received goaway and we are not closing connection*/
}

/* check if things that can open streams can be sent */
static inline bool can_send_request_headers() {}

static inline int can_send_response_headers() {
    /* can_send(), proceed */
    /* if we are not server, protocol error */
    /* if stream state is opening, then YES */
    /* if stream state is closing, then CLOSING error */
    /* else invalid stream state */
    return 0;
}

/** */
static inline int can_send_push_response_headers() {
    /* can_send(), proceed */
    /* if not server, protocol error */
    /* if state is not reserved, protocol error */
    /* if goaway has been received, stream start not allow error */
    return 0;
}

/** */
static inline int can_send_trailer_headers() {
    /* can_send() */
    /* if stream state open, YES */
    /* if stream is closing, stream closing error */
    /* if this is our server, then YES (find out how this works) */
    /* invalid stream state */
}

/** */
static inline int can_send_push_promise() {
    /* if not server, protocol error */
    /* if can_send(), proceed */
    /* remote settings enable_push if off, push disabled error */
    /* if stream state is closing, stream closing error */
    /* if goaway received, stream start not allowed */
    return 0;
}

/** */
static inline int can_send_window_update() {
    /* is conn closing, conn closing error */
    /* if stream id = 0, conn level window update */
    /* if no stream, stream closed error */
    /* if stream closing, stream closing error */
    /* if reserved local, invalid state error */
    return 0;
}

/** */
static inline int can_send_origin() {
    /* if conn closing, conn closing error */
    return 0;
}

/** */
static inline size_t a_h2_get_flow_control_window(struct aura_h2_conn *conn,
                                                  struct aura_h2_stream *stream,
                                                  uint32_t requested_window_size) {
    a_min(a_min(a_min(requested_window_size, stream->peer_window_size.available), conn->peer_window_size.available), conn->peer_settings.max_frame_size);
}

/** */
static inline int can_send_data() {
    /* can_send(), proceed */
    /* if our stream, if state closing, closing error, if state reserved, invalid state, else YES */
    /* not ours, state is opened, YES */
    /* not ours stream is closing, closing error */
    /* invalid stream state */
    return 0;
}

/**
 * Returns true if connection can handle reading
 * received data from peer
 */
static bool a_conn_can_read(struct aura_h2_conn *conn) {
    uint64_t num_active_streams;

    if (conn->flags & A_H2_CONN_GOAWAY_IMMEDIATE_TERM_SENT)
        return false;

    num_active_streams = a_conn_get_active_streams(conn);
    if (num_active_streams > 0)
        return true;

    return (conn->flags & (A_H2_CONN_GOAWAY_GRACEFUL_TERM_SENT | A_H2_CONN_GOAWAY_RECEIVED)) == 0;
}

/**
 * Returns true if connection can write to peer
 */
static bool a_conn_can_write(struct aura_h2_conn *conn) {
    if (conn->flags & A_H2_CONN_GOAWAY_IMMEDIATE_TERM_SENT)
        return false;

    /* if any of the queues have stuff, we may be able to write */
    if (!a_list_is_empty(&conn->sender.queues.urgent.head) || !a_list_is_empty(&conn->sender.queues.control.head))
        return true;

    if (!a_list_is_empty(&conn->sender.queues.data.head) && conn->peer_window_size.available > 0)
        return true;

    /* check syn headers against peer max concurrent */

    return false;
}

/**
 *  Prepare server preface
 */
static void a_setup_server_preface(struct aura_h2_conn *conn) {
    app_debug(true, 0, "a_setup_server_preface <<<<");
    uint32_t settings_frame_len, window_update_frame_len;
    struct aura_h2_out_frame *settings_frame, *window_update_frame;
    uint32_t initial_window_size;

    struct aura_h2_settings_payload settings[] = {
      {.settings_id = A_H2_SETTINGS_MAX_CONCURRENT_STREAMS, .value = aura_h2_default_settings.max_conc_streams},
    };

    settings_frame_len = a_calculate_frame_len(A_H2_FRAME_TYPE_SETTINGS, ARRAY_SIZE(settings), 0);
    settings_frame = aura_encode_control_frame(
      conn->mc,
      &conn->sender.write_buf,
      A_H2_FRAME_TYPE_SETTINGS, 0, 0,
      (void *)&settings, ARRAY_SIZE(settings), settings_frame_len);

    if (settings_frame == NULL) {
        /* will be process in the next tick */
        return;
    }
    a_list_add_tail(&conn->sender.queues.urgent.head, &settings_frame->f_list);

    window_update_frame_len = a_calculate_frame_len(A_H2_FRAME_TYPE_WINDOW_UPDATE, 0, 0);
    initial_window_size = A_H2_INITIAL_WINDOW_SIZE;
    window_update_frame = aura_encode_control_frame(
      conn->mc,
      &conn->sender.write_buf,
      A_H2_FRAME_TYPE_WINDOW_UPDATE,
      0, 0, (uint8_t *)&initial_window_size,
      0, window_update_frame_len);

    if (window_update_frame == NULL) {
        // destroy_outbound_frame();
        /* will be process in the next tick */
        return;
    }
    a_list_add_tail(&conn->sender.queues.urgent.head, &window_update_frame->f_list);
}

/**
 * Process connection preface
 * @src: bytes received from peer
 * @len: length of received bytes
 * @consumed: pointer
 */
static inline int a_process_preface(struct aura_h2_conn *conn,
                                    const uint8_t *src, size_t len,
                                    size_t *consumed) {
    app_debug(true, 0, "a_process_preface <<<<");
    int res;

    if (len < aura_h2_connection_preface.len)
        return A_H2_FRAME_INCOMPLETE;

    if (memcmp(aura_h2_connection_preface.base, src, aura_h2_connection_preface.len) != 0)
        return A_H2_PROTOCOL_ERROR;

    *consumed = aura_h2_connection_preface.len;
    a_setup_server_preface(conn);
    // encode origin if present
    // setup start time
    a_enqueue_write(conn);
    return A_H2_ERROR_NONE;
}

/**
 *
 */
static inline void aura_send_stream_error(struct aura_h2_conn *conn, struct aura_h2_stream *s, int err_num) {
    uint8_t *rst_frame;
    uint32_t frame_len;

    aura_h2_stream_reset(s);

    // update error stats
    a_h2_send_rst_frame(conn, s, err_num);
    // a_enqueue_write(conn);
}

/**
 * Handle settings frame
 */
static int a_process_settings(struct aura_h2_conn *conn, struct aura_h2_in_frame *in_frame) {
    app_debug(true, 0, "a_process_settings <<<<");
    struct aura_h2_frame *frame;
    uint32_t prev_window_sz, increment;
    uint32_t frame_len;
    struct aura_h2_out_frame *settings_ack_frame;
    struct aura_h2_stream *s;
    int res;

    frame = &in_frame->frame;
    if (frame->stream_id != 0) {
        a_h2_connection_terminate(
          conn, conn->last_processed_stream_id,
          A_H2_PROTOCOL_ERROR,
          &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG]);
        return A_H2_PROTOCOL_ERROR;
    }

    if (a_h2_frame_is_acknowledgement(frame->flags)) {
        if (frame->len != 0) {
            a_h2_connection_terminate(
              conn, conn->last_processed_stream_id,
              A_H2_FRAME_SIZE_ERROR,
              &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG]);
            return A_H2_FRAME_SIZE_ERROR;
        }
    } else {
        prev_window_sz = conn->peer_settings.initial_window_size;
        res = aura_h2_parse_frame_payload(in_frame);
        if (res != A_H2_ERROR_NONE) {
            a_h2_connection_terminate(
              conn, conn->last_processed_stream_id,
              res, &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG]);

            return res;
        }

        /* schedule ack */
        frame_len = a_calculate_frame_len(A_H2_FRAME_TYPE_SETTINGS, 0, 0);
        settings_ack_frame = aura_encode_control_frame(
          conn->mc,
          &conn->sender.write_buf,
          A_H2_FRAME_TYPE_SETTINGS,
          A_H2_FRAME_FLAG_ACK, 0,
          NULL, 0, frame_len);

        if (settings_ack_frame == NULL) {
            return AURA_H2_ERROR_INTERNAL;
        }
        a_list_add_tail(&conn->sender.queues.urgent.head, &settings_ack_frame->f_list);
        // a_enqueue_write(conn);

        /* update stream window */
        if (prev_window_sz != conn->peer_settings.initial_window_size) {
            increment = conn->peer_settings.initial_window_size - prev_window_sz;
            a_list_for_each(s, &conn->stream_list, s_list) {
                res = a_update_stream_peer_window_size(s, increment);
                if (res != 0) {
                    /* schedule stream reset FLOW CONTROL ERROR for all violators */
                    aura_send_stream_error(conn, s, res);
                }
            }
        }
    }

    return A_H2_ERROR_NONE;
}

/**
 *
 */
static int a_process_push_promise(struct aura_h2_conn *conn, struct aura_h2_in_frame *in_frame) {
    /* this client must work for satan trying to send us a push! */
    return A_H2_PROTOCOL_ERROR;
}

/** */
a_http_method_t a_is_header_method_valid(const char *method) {
    if (strcmp(method, "GET") == 0)
        return HTTP_GET;

    if (strcmp(method, "POST") == 0)
        return HTTP_POST;

    if (strcmp(method, "PUT") == 0)
        return HTTP_PUT;

    if (strcmp(method, "HEAD") == 0)
        return HTTP_HEAD;

    /** @todo: add others */

    return HTTP_NONE;
}

/**
 * Parsed authority callback
 */
static inline int a_header_authority_cb(struct aura_h2_conn *conn, struct aura_h2_stream *stream,
                                        struct aura_iovec *name, struct aura_iovec *value) {
    app_debug(true, 0, "a_header_authority_cb <<<< value: %s", value->base);
    /**/
    return HPACK_OK;
}

/**
 * Parsed method callback
 */
static inline int a_header_method_cb(struct aura_h2_conn *conn, struct aura_h2_stream *stream,
                                     struct aura_iovec *name, struct aura_iovec *value) {
    app_debug(true, 0, "a_header_method_cb <<<< value: %s", value->base);
    uint64_t content_len;
    a_http_method_t method;

    if (strcmp(value->base, "CONNECT") == 0 || strcmp(value->base, "TRACE") == 0) {
        /* unsupported methods */
        return HPACK_ERR_PROTOCOL;
    }

    method = a_is_header_method_valid(value->base);
    if (method == HTTP_NONE)
        return HPACK_ERR_PROTOCOL;

    stream->req.method = method;
    return HPACK_OK;
}

/**
 * Parsed path callback
 */
static inline int a_header_path_cb(struct aura_h2_conn *conn, struct aura_h2_stream *stream,
                                   struct aura_iovec *name, struct aura_iovec *value) {
    app_debug(true, 0, "a_header_path_cb <<<<: value: %s", value ? value->base : "NIL");
    struct aura_srv_host_conf *host;
    struct aura_route *route;
    uint32_t host_off;

    host_off = conn->sock->host_conf_off;
    host = &conn->srv_ctx->glob_conf->host_pool.hosts[host_off];
    A_BUG_ON_2(host == NULL, true);

    /* check for duplicate header */
    if (stream->req.path.base != NULL)
        return HPACK_ERR_PROTOCOL;

    if (value->len == 0) {
        return HPACK_ERR_PROTOCOL;
    }
    stream->req.path.base = aura_alloc(conn->mc, value->len);
    memcpy(stream->req.path.base, value->base, value->len);

    /* validate if requested route/fn exists */
    route = aura_route_match(&host->router, value, stream->req.method);
    if (!route) {
        // 404
        return HPACK_ERR_PATH_EMPTY;
    }

    /* set route so we don't have to search again */
    conn->route = route;
    return HPACK_OK;
}

/**
 * Parsed scheme callback
 */
static inline int a_header_scheme_cb(struct aura_h2_conn *conn, struct aura_h2_stream *stream,
                                     struct aura_iovec *name, struct aura_iovec *value) {
    app_debug(true, 0, "a_header_scheme_cb <<<< value: %s", value->base);
    /**/
    return HPACK_OK;
}

/**
 * Parsed status callback
 */
static inline int a_header_status_callback(struct aura_h2_conn *conn, struct aura_h2_stream *stream,
                                           struct aura_iovec *name, struct aura_iovec *value) {
    int status;
    char *c;

    app_debug(true, 0, "a_header_status_callback <<<< value: %s", value->base);

    if (stream->res.status_code != 0)
        return A_H2_PROTOCOL_ERROR;

    /* parse */
    if (value->len != 3) {
        return A_H2_COMPRESSION_ERROR;
    }

    c = value->base;
#define PARSE_DIGIT(mul, min_digit)               \
    do {                                          \
        if (*c < '0' + (min_digit) || '9' < *c) { \
            return A_H2_PROTOCOL_ERROR;           \
        }                                         \
        status += (*c - '0') * mul;               \
        ++c;                                      \
    } while (0);
    PARSE_DIGIT(100, 1);
    PARSE_DIGIT(10, 0);
    PARSE_DIGIT(1, 0);
#undef PARSE_DIGIT

    stream->res.status_code = status;

    return A_H2_ERROR_NONE;
}

static void aura_h2_process_request(struct aura_h2_conn *conn, struct aura_h2_stream *stream) {
    app_debug(true, 0, "aura_h2_process_request <<<<");
    struct aura_route *route;
    struct aura_work_queue *wq;
    struct aura_task *task;
    Request *js_req;
    int res;

    if (stream->state == A_H2_STREAM_STATE_HALF_CLOSED_REMOTE) {
        // forward to route handler/path handler
        route = conn->route;
        A_BUG_ON_2(route == NULL, true);
        task = aura_alloc(conn->mc, sizeof(*task));
        if (!task)
            return;

        js_req = aura_alloc(conn->mc, sizeof(*js_req));
        if (!js_req) {
            aura_free(task);
            return;
        }

        js_req->method = stream->req.method;
        js_req->headers = stream->req.headers;
        js_req->body = stream->req.raw_ptr->base;
        js_req->body_len = stream->req.content_length;

        task->data = (void *)js_req;
        task->stream_id = stream->stream_id;
        task->mc = conn->mc;
        res = aura_work_queue_add(&route->wq, task);
        if (res) {
            app_debug(true, 0, "Failed to enqueue request: %s", res);
            return;
        }
    }
}

/**
 *
 */
static int a_process_headers_early_bailout(struct aura_h2_conn *conn, struct aura_h2_stream *stream, const uint8_t *src, size_t len) {
    app_debug(true, 0, "a_process_headers_early_bailout <<<<");
    int res;

    /** @todo: update request structure connected to stream in the various callbacks */
    static hpack_header_cb cb[] = {
      a_header_authority_cb,
      a_header_method_cb,
      a_header_path_cb,
      a_header_scheme_cb,
      a_header_status_callback,
    };

    res = hpack_parse_request(conn, stream, src, len, cb);

    /** @todo: complete the list, see where to send early errors these functions */
    switch (res) {
    case HPACK_OK:
        // process requests
        aura_h2_process_request(conn, stream);
        break;
    case HPACK_ERR_PROTOCOL:
        return A_H2_PROTOCOL_ERROR;
    case HPACK_ERR_COMPRESSION:
        return A_H2_COMPRESSION_ERROR;
    case HPACK_ERR_PATH_EMPTY:
        res = aura_submit_error_response(conn, stream, 404);
        a_enqueue_write(conn);
        break;
    default:
    }
    return A_H2_ERROR_NONE;
}

/**
 *
 */
static int a_process_data(struct aura_h2_conn *conn, struct aura_h2_in_frame *in_frame) {
    struct aura_h2_data_payload payload;
    struct aura_h2_stream *stream;
    struct aura_h2_out_frame *rst_frame;
    int frame_len;
    int res, err, reason_idx;

    if (aura_h2_stream_is_idle(conn, in_frame->frame.stream_id)) {
        err = A_H2_PROTOCOL_ERROR;
        reason_idx = A_H2_ERROR_IDX_INVALID_ARG;
        goto exception;
    }

    stream = aura_h2_find_stream(conn, in_frame->frame.stream_id);
    if (!stream) {
        goto stream_closed;
    }

    /* @todo: fix stream states for better checking */
    if (stream->state == A_H2_STREAM_STATE_RESERVED || stream->state != A_H2_STREAM_STATE_OPENED) {
        err = A_H2_PROTOCOL_ERROR;
        reason_idx = A_H2_ERROR_IDX_INVALID_ARG;
        goto exception;
    }

    if (stream->state == A_H2_STREAM_STATE_CLOSING) {
        return 0; /* ignore data payload */
    }

    if (stream->state == A_H2_STREAM_STATE_HALF_CLOSED_REMOTE) {
        goto stream_closed;
    }

    res = aura_h2_parse_frame_payload(in_frame);
    if (res != A_H2_ERROR_NONE) {
        err = res;
        reason_idx = A_H2_ERROR_IDX_INVALID_ARG;
        goto exception;
    }

// consume window and check if update needs to be sent
// otherwize sending for a non existing stream is some bullshit return protocol error

// check if the payload length is not the frame lenth, meaning we still have data to receive
// send window update if need be
// handle payload, if not end stream copy payload over to conn buffer or hand it over
stream_closed:
    frame_len = a_calculate_frame_len(A_H2_FRAME_TYPE_RST_STREAM, 0, 0);
    err = A_H2_STREAM_CLOSED_ERROR;
    rst_frame = aura_encode_control_frame(
      conn->mc,
      &conn->sender.write_buf,
      A_H2_FRAME_TYPE_RST_STREAM,
      0, in_frame->frame.stream_id,
      (void *)&err, 0,
      frame_len);
    a_list_add_tail(&conn->sender.queues.control.head, &rst_frame->f_list);
    return 0; /* ignore data frame */

exception:
    return a_h2_connection_terminate(
      conn, conn->last_processed_stream_id,
      res, &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG]);
}

/**
 *
 */
static int a_process_header(struct aura_h2_conn *conn, struct aura_h2_in_frame *in_frame) {
    app_debug(true, 0, "a_process_header <<<<");
    struct aura_h2_hdrs_payload hdrs;
    struct aura_h2_stream *stream;
    struct aura_h2_frame *frame;
    int res;

    res = aura_h2_parse_frame_payload(in_frame);
    if (res != A_H2_ERROR_NONE) {
        res = a_h2_connection_terminate(
          conn, conn->last_processed_stream_id,
          res, &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG]);
        return res;
    }

    frame = &in_frame->frame;
    if (a_h2_stream_is_push_stream(frame->stream_id)) {
        res = a_h2_connection_terminate(
          conn, conn->last_processed_stream_id,
          A_H2_PROTOCOL_ERROR,
          &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG]);
        return res;
    }

    /* call on begin headers */
    res = conn->callbacks.header_begin_callback(conn, frame, &stream);
    if (res != A_H2_ERROR_NONE) {
        res = a_h2_connection_terminate(
          conn, conn->last_processed_stream_id,
          res, &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG]);
        return res;
    }

    if (stream->flags & A_H2_STREAM_FLAG_CONTINUATION) {
        aura_sliding_buffer_append(&conn->headers_to_parse, hdrs.headers, hdrs.headers_len);
        return A_H2_ERROR_NONE;
    }

    /* call process header callback */
    res = conn->callbacks.header_callback(conn, stream, frame->payload, frame->len);

    return A_H2_ERROR_NONE;
}

/**
 *
 */
static int a_process_priority(struct aura_h2_conn *conn, struct aura_h2_in_frame *frame) {
    /**/
}

/**
 *
 */
static int a_process_ping(struct aura_h2_conn *conn, struct aura_h2_in_frame *in_frame) {
    struct aura_h2_ping_payload payload;
    struct aura_h2_frame *frame;
    uint32_t frame_len;
    struct aura_h2_out_frame *ping_frame;
    int res;

    frame = &in_frame->frame;
    res = aura_h2_parse_frame_payload(in_frame);
    if (res != A_H2_ERROR_NONE) {
        res = a_h2_connection_terminate(
          conn, conn->last_processed_stream_id,
          res, &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG]);
        return res;
    }

    if (!a_h2_frame_is_acknowledgement(frame->flags)) {
        ping_frame = aura_encode_control_frame(
          conn->mc,
          &conn->sender.write_buf,
          A_H2_FRAME_TYPE_PING,
          0, 0,
          payload.data,
          64,
          frame_len);
        a_list_add_tail(&conn->sender.queues.urgent.head, &ping_frame->f_list);
        a_enqueue_write(conn);
    }

    return res;
}

/**
 *
 */
static int a_process_goaway(struct aura_h2_conn *conn, struct aura_h2_in_frame *in_frame) {
    struct aura_h2_goaway_payload payload;
    struct aura_h2_frame *frame;
    int res;

    frame = &in_frame->frame;
    res = aura_h2_parse_frame_payload(in_frame);
    if (res != A_H2_ERROR_NONE)
        return res;

    res = a_h2_connection_terminate(
      conn, payload.last_stream_id,
      payload.error_code, &payload.debug_data);
    return res;
}

/**
 *
 */
static int a_process_rst_stream(struct aura_h2_conn *conn, struct aura_h2_in_frame *in_frame) {
    struct aura_h2_rst_stream_payload payload;
    struct aura_h2_stream *stream;
    struct aura_h2_frame *frame;
    int res;

    frame = &in_frame->frame;
    res = aura_h2_parse_frame_payload(in_frame);
    if (res != A_H2_ERROR_NONE) {
        res = a_h2_connection_terminate(
          conn, conn->last_processed_stream_id,
          res, &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG]);
        return res;
    }

    if (aura_h2_stream_is_idle(conn, frame->stream_id)) {
        /* client is on some psychic sh!t */
        res = a_h2_connection_terminate(
          conn, conn->last_processed_stream_id,
          A_H2_PROTOCOL_ERROR,
          &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG]);
        return res;
    }

    stream = aura_h2_find_stream(conn, frame->stream_id);
    if (stream == NULL)
        return A_H2_ERROR_NONE;

    // update stats
    aura_h2_stream_close(stream);

    // check for dos attempts and insult client accordingly

    return A_H2_ERROR_NONE;
}

/**
 *
 */
static int a_process_window_update(struct aura_h2_conn *conn, struct aura_h2_in_frame *in_frame) {
    struct aura_h2_window_update_payload payload;
    struct aura_h2_stream *stream;
    struct aura_h2_frame *frame;
    int res;
    bool error_is_stream_level;

    frame = &in_frame->frame;
    error_is_stream_level = frame->stream_id != 0;
    res = aura_h2_parse_frame_payload(in_frame);
    if (res != A_H2_ERROR_NONE) {
        if (error_is_stream_level) {
            stream = aura_h2_find_stream(conn, frame->stream_id);
            if (stream != NULL) {
                // @todo: frame reset by peer, perform appropriate actions
                // close stream related things (see aura_h2_stream_reset in stream.c)
            }
            aura_send_stream_error(conn, stream, res);
            return 0;
        } else {
            res = a_h2_connection_terminate(
              conn, conn->last_processed_stream_id,
              res,
              &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG]);
            return res;
        }
    }

    if (frame->stream_id == 0) {
        res = a_update_window_size(&conn->peer_window_size, payload.increment);
        if (res != 0)
            return res;
        goto out;
    }

    if (!aura_h2_stream_is_idle(conn, frame->stream_id)) {
        stream = aura_h2_find_stream(conn, frame->stream_id);
        if (stream != NULL) {
            res = a_update_stream_peer_window_size(stream, payload.increment);
            if (res != 0) {
                aura_send_stream_error(conn, stream, res);
            }
        }
        goto out;
    }

    // @todo: report invalid
    // A_H2_PROTOCOL_ERROR
out:
    return 0;
}

/**
 *
 */
int a_process_frame(struct aura_h2_conn *conn, const uint8_t *src, size_t len, size_t *consumed) {
    struct aura_h2_in_frame in_frame;
    int res;

    static int (*frame_handlers[])(struct aura_h2_conn *conn, struct aura_h2_in_frame *frame) = {
      [A_H2_FRAME_TYPE_DATA] = a_process_data,
      [A_H2_FRAME_TYPE_HEADERS] = a_process_header,
      [A_H2_FRAME_TYPE_PRIORITY] = a_process_priority,
      [A_H2_FRAME_TYPE_RST_STREAM] = a_process_rst_stream,
      [A_H2_FRAME_TYPE_SETTINGS] = a_process_settings,
      [A_H2_FRAME_TYPE_PUSH_PROMISE] = a_process_push_promise,
      [A_H2_FRAME_TYPE_PING] = a_process_ping,
      [A_H2_FRAME_TYPE_GOAWAY] = a_process_goaway,
      [A_H2_FRAME_TYPE_WINDOW_UPDATE] = a_process_window_update,
    };

    res = aura_h2_parse_frame_header(&in_frame, src, len, A_H2_MIN_FRAME_SIZE, consumed);
    if (res != A_H2_ERROR_NONE)
        return res;

    if (in_frame.frame.type >= ARRAY_SIZE(frame_handlers)) {
        app_debug(true, 0, "Unknown frame type: %d", in_frame.frame.type);
        return res;
    }

    res = frame_handlers[in_frame.frame.type](conn, &in_frame);
    return res;
}

int aura_conn_parse_input(struct aura_h2_conn *conn) {
    size_t consumed = 0, len;
    uint8_t *src;
    int res = 0;

    if (!a_conn_can_read(conn)) {
        return 0;
    }

    len = aura_sliding_buffer_available_read(&conn->sock->plain_read_buf);
    while (len > 0) {
        src = aura_sliding_buffer_read_pointer(&conn->sock->plain_read_buf);

        /* first conn frame */
        if (!conn->preface_processed) {
            res = a_process_preface(conn, src, len, &consumed);
            conn->preface_processed = true;
        } else {
            res = a_process_frame(conn, src, len, &consumed);
        }

        len -= consumed;
        aura_sliding_buffer_consume(&conn->sock->plain_read_buf, consumed);
        if (res != 0)
            break;
    }

    return res;
}