#include "h2/h2_srv.h"

void aura_enqueue_write(struct aura_h2_ctx *h2_ctx) {
    app_debug(true, 0, "aura_enqueue_write <<<<");
    h2_ctx->conn->callbacks.on_write(h2_ctx->conn);
}

/* update connection window size */
static inline int a_update_window_size(struct aura_h2_window *w, uint32_t n) {
    int64_t new_sz;

    new_sz = w->available + n;
    if (new_sz > INT32_MAX)
        return A_H2_FLOW_CONTROL_ERROR;
    w->available = new_sz;

    return 0;
}

/**
 * Update stream window size
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
        aura_h2_stream_resume(stream);
    }
    return 0;
}

/**/
int aura_h2_conn_enqueue_goaway(struct aura_h2_ctx *h2_ctx, uint32_t last_stream_id,
                                int err_code, const struct aura_iovec *reason) {
    struct aura_h2_sched_evt *evt;
    struct aura_h2_goaway_payload payload;
    uint32_t frame_len;
    uint8_t *output_data;
    int res;

    if (h2_ctx->flags & A_H2_CONN_FLAG_GOAWAY_SENT)
        return 0;

    payload.error_code = err_code;
    payload.last_stream_id = last_stream_id;
    payload.debug_data.base = reason->base;
    payload.debug_data.len = reason->len;

    frame_len = a_calculate_frame_len(A_H2_FRAME_TYPE_GOAWAY, 0, reason ? reason->len : 0);
    output_data = aura_encode_control_frame(
      h2_ctx->scheduler.write_buf, A_H2_FRAME_TYPE_GOAWAY,
      0, 0, frame_len, (const uint8_t *)&payload, 0);
    if (!output_data)
        return A_H2_INTERNAL_ERROR;

    evt = aura_sched_evt_create(h2_ctx->conn->mc, NULL, h2_ctx->scheduler.write_buf, AURA_H2_SCHED_OP_URGENT_WRITE, output_data, frame_len, false);
    if (!evt)
        return A_H2_INTERNAL_ERROR;
    /* enqueue goaway */
    a_list_add_tail(&h2_ctx->scheduler.queues.urgent.head, &evt->e_list);

    h2_ctx->flags |= A_H2_CONN_FLAG_GOAWAY_SENT;
    return 0;
}

/**
 * Create and enqueue RST frame for given stream
 */
int aura_h2_send_rst_frame(struct aura_h2_ctx *h2_ctx, uint32_t stream_id, int err_num) {
    struct aura_h2_sched_evt *rst_evt;
    uint32_t frame_len;
    uint8_t *output_data;

    /* create out frame and enqueue */
    frame_len = a_calculate_frame_len(A_H2_FRAME_TYPE_RST_STREAM, 0, 0);
    output_data = aura_encode_control_frame(
      h2_ctx->scheduler.write_buf, A_H2_FRAME_TYPE_RST_STREAM, 0,
      stream_id, frame_len, (uint8_t *)&err_num, sizeof(int));
    if (!output_data)
        return -1;

    rst_evt = aura_sched_evt_create(h2_ctx->conn->mc, NULL, h2_ctx->scheduler.write_buf, AURA_H2_SCHED_OP_URGENT_WRITE, output_data, frame_len, false);
    if (!rst_evt)
        return -1;

    a_list_add_tail(&h2_ctx->scheduler.queues.control.head, &rst_evt->e_list);
    aura_enqueue_write(h2_ctx);

    return 0;
}

/**
 * Allocate slab slot for new connection
 */
struct aura_h2_ctx *a_conn_alloc(struct aura_memory_ctx *mc) {
    struct aura_slab_cache *sc;
    struct aura_h2_ctx *conn;

    sc = aura_slab_cache_find_by_id(mc, A_SLAB_CACHE_ID_CONNECTION);
    A_BUG_ON_2(!sc, true);

    conn = aura_slab_alloc(sc);
    return conn;
}

/** */
struct aura_h2_ctx *aura_h2_ctx_init(struct aura_memory_ctx *mc, bool is_server) {
    struct aura_h2_ctx *h2_ctx;
    struct aura_h2_stream *zero_id_stream;
    struct aura_h2_callbacks callbacks;

    h2_ctx = a_conn_alloc(mc);
    if (!h2_ctx)
        return NULL;

    h2_ctx->is_server = is_server;
    h2_ctx->flags = A_H2_CONN_FLAG_NONE;
    h2_ctx->peer_window_size.available = A_H2_INITIAL_WINDOW_SIZE;
    h2_ctx->local_window_size.available = A_H2_INITIAL_WINDOW_SIZE;
    memcpy(&h2_ctx->peer_settings, &aura_h2_default_settings, sizeof(struct aura_h2_settings));
    memcpy(&h2_ctx->local_settings, &aura_h2_default_settings, sizeof(struct aura_h2_settings));
    h2_ctx->local_goaway_stream_id = A_H2_STREAM_ID_MASK;
    h2_ctx->peer_goaway_stream_id = A_H2_STREAM_ID_MASK;
    h2_ctx->peer_unacknowledged_settings_cnt = aura_h2_default_settings.max_conc_streams;
    h2_ctx->state = A_H2_CONN_STATE_PREFACE;
    h2_ctx->last_processed_stream_id = 0;
    h2_ctx->input_hdr_table.max_size = aura_h2_default_settings.hdr_table_size;
    h2_ctx->output_hdr_table.max_size = aura_h2_default_settings.hdr_table_size;
    // h2_ctx->max_inbound_reserved_streams = 200;
    h2_ctx->max_received_stream_id = 0;
    h2_ctx->max_sent_stream_id = 0;
    a_list_head_init(&h2_ctx->stream_list);
    a_list_head_init(&h2_ctx->pending_reqs);
    h2_ctx->scheduler.write_buf = aura_sliding_buffer_create(mc, 0, false);
    if (!h2_ctx->scheduler.write_buf) {
        aura_slab_free(h2_ctx);
        return NULL;
    }
    h2_ctx->intern_tab = aura_intern_tab_create(mc, 128); /** @todo: #define this value(128) */
    if (!h2_ctx->intern_tab) {
        aura_sliding_buffer_destroy(h2_ctx->scheduler.write_buf);
        aura_slab_free(h2_ctx);
        return NULL;
    }
    a_list_head_init(&h2_ctx->scheduler.queues.urgent.head);
    h2_ctx->scheduler.queues.urgent.cnt = 0;
    a_list_head_init(&h2_ctx->scheduler.queues.control.head);
    h2_ctx->scheduler.queues.control.cnt = 0;
    a_list_head_init(&h2_ctx->scheduler.queues.data.head);
    h2_ctx->scheduler.queues.data.cnt = 0;
    h2_ctx->scheduler.bytes_sent_this_tick = 0;
    h2_ctx->scheduler.max_bytes_per_tick = 0;
    h2_ctx->scheduler.last_tick_time = 0;

    if (is_server) {
        h2_ctx->headers_to_parse = aura_sliding_buffer_create(mc, 0, false);
        h2_ctx->next_stream_id = 2;
        if (!h2_ctx->headers_to_parse) {
            aura_sliding_buffer_destroy(h2_ctx->scheduler.write_buf);
            aura_slab_free(h2_ctx);
            return NULL;
        }

        h2_ctx->callbacks = callbacks;
    } else {
        h2_ctx->next_stream_id = 1;
    }

    return h2_ctx;
}

struct aura_h2_stream *aura_h2_conn_stream_open(struct aura_h2_ctx *h2_ctx, uint32_t stream_id,
                                                uint8_t initial_state, uint8_t flags, void *user_data) {
    struct aura_slab_cache *sc;
    struct aura_h2_stream *stream;

    app_debug(true, 0, "aura_h2_conn_stream_open <<<");
    sc = aura_slab_cache_find_by_id(h2_ctx->conn->mc, A_SLAB_CACHE_ID_STREAM);
    stream = aura_slab_alloc(sc);
    if (!stream)
        return NULL;

    if (aura_h2_stream_init(stream, h2_ctx->conn->mc, stream_id, initial_state, flags, user_data) < 0) {
        aura_h2_stream_destroy(stream);
        return NULL;
    }

    stream->h2_ctx = h2_ctx;
    if (initial_state == A_H2_STREAM_STATE_IDLE)
        ++h2_ctx->num_of_idle_streams;

    if (h2_ctx->conn->is_server) {
        h2_ctx->max_received_stream_id = stream_id;
    } else {
        h2_ctx->next_stream_id += 2; /* @todo: create a proper function here */
        h2_ctx->max_sent_stream_id = stream_id;
    }

    a_list_add_tail(&h2_ctx->stream_list, &stream->s_list);
    return stream;
}

void aura_h2_ctx_destroy(struct aura_h2_ctx *h2_ctx) {
    struct aura_h2_stream *stream;

    if (!h2_ctx)
        return;

    aura_sliding_buffer_destroy(h2_ctx->scheduler.write_buf);
    while (!a_list_is_empty(&h2_ctx->stream_list)) {
        a_list_dequeue(stream, &h2_ctx->stream_list, s_list);
        /* destroy stream */
        aura_h2_stream_destroy(stream);
    }

    aura_hpack_header_tab_dispose(&h2_ctx->input_hdr_table);
    aura_hpack_header_tab_dispose(&h2_ctx->output_hdr_table);

    aura_intern_tab_destroy(h2_ctx->intern_tab);

    if (h2_ctx->headers_to_parse)
        aura_sliding_buffer_destroy(h2_ctx->headers_to_parse);

    aura_slab_cache_destroy((void *)h2_ctx);
}

/**
 * Returns true if the connection can receive a request,
 * otherwise false
 */
static inline bool can_receive_request(struct aura_h2_ctx *h2_ctx) {
    /* we are not server, we have a valid next stream id, we have not received goaway and we are not closing connection*/
}

/**
 * Returns true if given stream can create
 * and send request headers, otherwise false
 */
static inline bool can_send_request_headers() {}

/**
 * Returns true if given stream can create
 * and send response headers, otherwise false
 */
static inline int can_send_response_headers() {
    /* can_send(), proceed */
    /* if we are not server, protocol error */
    /* if stream state is opening, then YES */
    /* if stream state is closing, then CLOSING error */
    /* else invalid stream state */
    return 0;
}

/**
 * Returns true if given stream can send trailer headers,
 * otherwise false
 */
static inline int can_send_trailer_headers() {
    /* can_send() */
    /* if stream state open, YES */
    /* if stream is closing, stream closing error */
    /* if this is our server, then YES (find out how this works) */
    /* invalid stream state */
}

/**
 * Returns true if given connection can send
 * window updates, otherwise false
 */
static inline int can_send_window_update() {
    /* is conn closing, conn closing error */
    /* if stream id = 0, conn level window update */
    /* if no stream, stream closed error */
    /* if stream closing, stream closing error */
    /* if reserved local, invalid state error */
    return 0;
}

int aura_setup_preface_settings(struct aura_h2_ctx *h2_ctx) {
    app_debug(true, 0, "a_setup_server_preface <<<<");
    uint32_t frame_len;
    uint8_t *output_data;
    struct aura_h2_sched_evt *settings_evt, *window_update_evt;
    uint32_t initial_window_size;
    const struct aura_iovec *reason;
    int error;

    struct aura_h2_settings_payload settings[] = {
      {.settings_id = A_H2_SETTINGS_MAX_CONCURRENT_STREAMS, .value = aura_h2_default_settings.max_conc_streams},
    };

    frame_len = a_calculate_frame_len(A_H2_FRAME_TYPE_SETTINGS, ARRAY_SIZE(settings), 0);
    output_data = aura_encode_control_frame(
      h2_ctx->scheduler.write_buf, A_H2_FRAME_TYPE_SETTINGS, 0, 0,
      frame_len, (void *)&settings, ARRAY_SIZE(settings));

    if (!output_data) {
        error = A_H2_INTERNAL_ERROR;
        reason = &a_h2_error_reasons[AURA_H2_ERROR_IDX_INTERNAL_ERROR];
        goto goaway;
    }

    settings_evt = aura_sched_evt_create(h2_ctx->conn->mc, NULL, h2_ctx->scheduler.write_buf, AURA_H2_SCHED_OP_URGENT_WRITE, output_data, frame_len, false);
    if (!settings_evt) {
        error = A_H2_INTERNAL_ERROR;
        reason = &a_h2_error_reasons[AURA_H2_ERROR_IDX_INTERNAL_ERROR];
        goto goaway;
    }
    a_list_add_tail(&h2_ctx->scheduler.queues.urgent.head, &settings_evt->e_list);

    frame_len = a_calculate_frame_len(A_H2_FRAME_TYPE_WINDOW_UPDATE, 0, 0);
    initial_window_size = A_H2_INITIAL_WINDOW_SIZE;
    output_data = aura_encode_control_frame(
      h2_ctx->scheduler.write_buf, A_H2_FRAME_TYPE_WINDOW_UPDATE, 0, 0,
      frame_len, (uint8_t *)&initial_window_size, 0);

    if (!output_data) {
        aura_h2_scheduler_evt_destroy(settings_evt);
        error = A_H2_INTERNAL_ERROR;
        reason = &a_h2_error_reasons[AURA_H2_ERROR_IDX_INTERNAL_ERROR];
        goto goaway;
    }

    window_update_evt = aura_sched_evt_create(h2_ctx->conn->mc, NULL, h2_ctx->scheduler.write_buf, AURA_H2_SCHED_OP_URGENT_WRITE, output_data, frame_len, false);
    if (!window_update_evt) {
        aura_h2_scheduler_evt_destroy(settings_evt);
        error = A_H2_INTERNAL_ERROR;
        reason = &a_h2_error_reasons[AURA_H2_ERROR_IDX_INTERNAL_ERROR];
        goto goaway;
    }
    a_list_add_tail(&h2_ctx->scheduler.queues.urgent.head, &window_update_evt->e_list);
    return A_H2_ERROR_NONE;

goaway:
    aura_h2_conn_enqueue_goaway(h2_ctx, h2_ctx->last_processed_stream_id, error, reason);
    return error;
}

/**
 * Close given stream and schedule RESET frame
 */
static inline void aura_send_stream_error(struct aura_h2_ctx *h2_ctx, struct aura_h2_stream *stream, int err_num) {
    uint8_t *rst_frame;
    uint32_t frame_len;

    // aura_h2_stream_reset(s);
    if (stream->state == A_H2_STREAM_STATE_CLOSING) {
        return;
    }

    /*
        if stream is idle, protocol error
    */

    if (aura_h2_send_rst_frame(h2_ctx, stream->stream_id, err_num) < 0) {
        aura_h2_conn_enqueue_goaway(h2_ctx, h2_ctx->last_processed_stream_id, AURA_H2_ERROR_IDX_INTERNAL_ERROR, &a_h2_error_reasons[AURA_H2_ERROR_IDX_INTERNAL_ERROR]);
        return;
    }

    // update error stats

    /* if we are client and the stream is ours, cancel and headers associated with this stream
    that creates new headers like push and request headers
*/
    // aura_enqueue_write(conn);
}

/**
 * Handle settings frame
 */
int aura_process_settings(struct aura_h2_ctx *h2_ctx, struct aura_h2_in_frame *in_frame) {
    app_debug(true, 0, "a_process_settings <<<<");
    struct aura_h2_frame *frame;
    uint32_t prev_window_sz, delta;
    uint32_t frame_len;
    uint8_t *output_data;
    struct aura_h2_out_frame *settings_ack_frame;
    struct aura_h2_sched_evt *settings_ack_evt;
    struct aura_h2_stream *stream;
    int res;

    /* Check if we expect continuation frame */
    if (h2_ctx->flags & A_H2_CONN_FLAG_EXPECT_CONTINUATION) {
        return A_H2_PROTOCOL_ERROR;
    }

    frame = &in_frame->frame;
    if (frame->stream_id != 0) {
        aura_h2_conn_enqueue_goaway(h2_ctx, h2_ctx->last_processed_stream_id, A_H2_PROTOCOL_ERROR, &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG]);
        return A_H2_PROTOCOL_ERROR;
    }

    if (aura_h2_frame_is_acknowledgement(frame->flags)) {
        if (frame->len != 0) {
            aura_h2_conn_enqueue_goaway(h2_ctx, h2_ctx->last_processed_stream_id, A_H2_FRAME_SIZE_ERROR, &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG]);
            return A_H2_FRAME_SIZE_ERROR;
        }
    } else {
        /* Store prev window size before updating it */
        prev_window_sz = h2_ctx->peer_settings.initial_window_size;
        res = aura_h2_parse_frame_payload(in_frame);
        if (res != A_H2_ERROR_NONE) {
            aura_h2_conn_enqueue_goaway(h2_ctx, h2_ctx->last_processed_stream_id, res, &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG]);
            return res;
        }

        /* schedule ack */
        frame_len = a_calculate_frame_len(A_H2_FRAME_TYPE_SETTINGS, 0, 0);
        output_data = aura_encode_control_frame(
          h2_ctx->scheduler.write_buf,
          A_H2_FRAME_TYPE_SETTINGS,
          A_H2_FRAME_FLAG_ACK, 0,
          frame_len, NULL, 0);
        if (!output_data) {
            aura_h2_conn_enqueue_goaway(h2_ctx, h2_ctx->last_processed_stream_id, A_H2_INTERNAL_ERROR, &a_h2_error_reasons[AURA_H2_ERROR_IDX_INTERNAL_ERROR]);
            return A_H2_INTERNAL_ERROR;
        }

        settings_ack_evt = aura_sched_evt_create(h2_ctx->conn->mc, NULL, h2_ctx->scheduler.write_buf, AURA_H2_SCHED_OP_URGENT_WRITE, output_data, frame_len, false);
        if (!settings_ack_evt) {
            aura_h2_conn_enqueue_goaway(h2_ctx, h2_ctx->last_processed_stream_id, A_H2_INTERNAL_ERROR, &a_h2_error_reasons[AURA_H2_ERROR_IDX_INTERNAL_ERROR]);
            return A_H2_INTERNAL_ERROR;
        }

        a_list_add_tail(&h2_ctx->scheduler.queues.urgent.head, &settings_ack_evt->e_list);

        /* Check prev window against updated window */
        if (prev_window_sz != h2_ctx->peer_settings.initial_window_size) {
            delta = h2_ctx->peer_settings.initial_window_size - prev_window_sz;
            a_list_for_each(stream, &h2_ctx->stream_list, s_list) {
                res = a_update_stream_peer_window_size(stream, delta);
                if (res != 0) {
                    /* schedule stream reset FLOW CONTROL ERROR for all violators */
                    aura_send_stream_error(h2_ctx, stream, res);
                }
            }
        }
    }

    return A_H2_ERROR_NONE;
}

/**
 *
 */
int aura_process_priority(struct aura_h2_ctx *h2_ctx, struct aura_h2_in_frame *frame) {
    /**/
    /* Check if we expect continuation frame */
    if (h2_ctx->flags & A_H2_CONN_FLAG_EXPECT_CONTINUATION) {
        return A_H2_PROTOCOL_ERROR;
    }

    return A_H2_ERROR_NONE;
}

/**
 *
 */
int aura_process_ping(struct aura_h2_ctx *h2_ctx, struct aura_h2_in_frame *in_frame) {
    struct aura_h2_ping_payload payload;
    struct aura_h2_frame *frame;
    uint32_t frame_len;
    struct aura_h2_sched_evt *ping_evt;
    uint8_t *output_data;
    int res;

    /* Check if we expect continuation frame */
    if (h2_ctx->flags & A_H2_CONN_FLAG_EXPECT_CONTINUATION) {
        return A_H2_PROTOCOL_ERROR;
    }

    frame = &in_frame->frame;
    res = aura_h2_parse_frame_payload(in_frame);
    if (res != A_H2_ERROR_NONE) {
        aura_h2_conn_enqueue_goaway(h2_ctx, h2_ctx->last_processed_stream_id, res, &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG]);
        return res;
    }

    if (!aura_h2_frame_is_acknowledgement(frame->flags)) {
        output_data = aura_encode_control_frame(
          h2_ctx->scheduler.write_buf, A_H2_FRAME_TYPE_PING,
          0, 0, frame_len, payload.data, 64);
        a_list_add_tail(&h2_ctx->scheduler.queues.urgent.head, &ping_evt->e_list);
        aura_enqueue_write(h2_ctx);
    }

    return res;
}

/**
 *
 */
int aura_process_goaway(struct aura_h2_ctx *h2_ctx, struct aura_h2_in_frame *in_frame) {
    app_debug(true, 0, ">>>>>>>>>> PROCESSING GO AWAY");
    struct aura_h2_goaway_payload payload;
    struct aura_h2_frame *frame;
    int res;

    /* Check if we expect continuation frame */
    if (h2_ctx->flags & A_H2_CONN_FLAG_EXPECT_CONTINUATION) {
        return A_H2_PROTOCOL_ERROR;
    }

    frame = &in_frame->frame;
    res = aura_h2_parse_frame_payload(in_frame);
    if (res != A_H2_ERROR_NONE)
        return res;

    aura_h2_conn_enqueue_goaway(h2_ctx, h2_ctx->last_processed_stream_id, payload.error_code, &payload.debug_data);
    return res;
}

/**
 *
 */
int aura_process_rst_stream(struct aura_h2_ctx *h2_ctx, struct aura_h2_in_frame *in_frame) {
    struct aura_h2_rst_stream_payload payload;
    struct aura_h2_stream *stream;
    struct aura_h2_frame *frame;
    int res;

    /* Check if we expect continuation frame */
    if (h2_ctx->flags & A_H2_CONN_FLAG_EXPECT_CONTINUATION) {
        return A_H2_PROTOCOL_ERROR;
    }

    frame = &in_frame->frame;
    res = aura_h2_parse_frame_payload(in_frame);
    if (res != A_H2_ERROR_NONE) {
        aura_h2_conn_enqueue_goaway(h2_ctx, h2_ctx->last_processed_stream_id, res, &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG]);
        return res;
    }

    if (aura_h2_stream_is_idle(h2_ctx, frame->stream_id)) {
        aura_h2_conn_enqueue_goaway(h2_ctx, h2_ctx->last_processed_stream_id, A_H2_PROTOCOL_ERROR, &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG]);
        return res;
    }

    stream = aura_h2_conn_find_stream(h2_ctx, frame->stream_id);
    if (stream == NULL)
        return A_H2_ERROR_NONE;

    // update stats
    aura_h2_stream_destroy(stream);

    // check for dos attempts and insult client accordingly

    return A_H2_ERROR_NONE;
}

/**
 *
 */
int aura_process_window_update(struct aura_h2_ctx *h2_ctx, struct aura_h2_in_frame *in_frame) {
    struct aura_h2_window_update_payload payload;
    struct aura_h2_stream *stream;
    struct aura_h2_frame *frame;
    int res;
    bool error_is_stream_level;

    /* Check if we expect continuation frame */
    if (h2_ctx->flags & A_H2_CONN_FLAG_EXPECT_CONTINUATION) {
        return A_H2_PROTOCOL_ERROR;
    }

    frame = &in_frame->frame;
    error_is_stream_level = frame->stream_id != 0;
    res = aura_h2_parse_frame_payload(in_frame);
    if (res != A_H2_ERROR_NONE) {
        if (error_is_stream_level) {
            stream = aura_h2_conn_find_stream(h2_ctx, frame->stream_id);
            if (stream != NULL) {
                // @todo: frame reset by peer, perform appropriate actions
                // close stream related things (see aura_h2_stream_reset in stream.c)
            }
            aura_send_stream_error(h2_ctx, stream, res);
            return 0;
        } else {
            aura_h2_conn_enqueue_goaway(h2_ctx, h2_ctx->last_processed_stream_id, res, &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG]);
            return res;
        }
    }

    if (frame->stream_id == 0) {
        res = a_update_window_size(&h2_ctx->peer_window_size, payload.increment);
        if (res != 0)
            return res;
        goto out;
    }

    if (!aura_h2_stream_is_idle(h2_ctx, frame->stream_id)) {
        stream = aura_h2_conn_find_stream(h2_ctx, frame->stream_id);
        if (stream != NULL) {
            res = a_update_stream_peer_window_size(stream, payload.increment);
            if (res != 0) {
                aura_send_stream_error(h2_ctx, stream, res);
            }
        }
        goto out;
    }

    // @todo: report invalid
    // A_H2_PROTOCOL_ERROR
out:
    return 0;
}

int aura_process_continuation(struct aura_h2_ctx *h2_ctx, struct aura_h2_in_frame *in_frame) {
    struct aura_h2_stream *stream;
    size_t avail_read;
    uint8_t *read_ptr;
    int ret;

    stream = aura_h2_conn_find_stream(h2_ctx, in_frame->frame.stream_id);
    if (!stream || !(stream->flags & A_H2_STREAM_FLAG_CONTINUATION)) {
        return A_H2_PROTOCOL_ERROR;
    }

    avail_read = aura_sliding_buffer_available_read(h2_ctx->headers_to_parse);
    if (avail_read + in_frame->frame.len > A_MAX_REQ_LEN) {
        if (aura_h2_send_rst_frame(h2_ctx, stream->stream_id, A_H2_REFUSED_STREAM_ERROR) < 0)
            aura_h2_conn_enqueue_goaway(h2_ctx, h2_ctx->last_processed_stream_id, A_H2_INTERNAL_ERROR, &a_h2_error_reasons[AURA_H2_ERROR_IDX_INTERNAL_ERROR]);
    }

    if (aura_sliding_buffer_append(h2_ctx->headers_to_parse, in_frame->frame.payload, in_frame->frame.len) < 0)
        aura_h2_conn_enqueue_goaway(h2_ctx, h2_ctx->last_processed_stream_id, A_H2_INTERNAL_ERROR, &a_h2_error_reasons[AURA_H2_ERROR_IDX_INTERNAL_ERROR]);

    if (in_frame->frame.flags & A_H2_FRAME_FLAG_END_HEADERS) {
        h2_ctx->flags &= ~A_H2_CONN_FLAG_EXPECT_CONTINUATION;
        read_ptr = aura_sliding_buffer_read_pointer(h2_ctx->headers_to_parse);
        avail_read = aura_sliding_buffer_available_read(h2_ctx->headers_to_parse);
        ret = h2_ctx->callbacks.header_callback(h2_ctx, stream, read_ptr, avail_read);
        aura_sliding_buffer_destroy(h2_ctx->headers_to_parse);
    }

    return ret;
}