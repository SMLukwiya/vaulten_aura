#include "h2/server.h"
#include "bug_lib.h"
#include "connection.h"
#include "error_lib.h"
#include "executors/js/quickjs/bindings.h"
#include "fn/lib.h"
#include "h2/hpack.h"
#include "h2/scheduler.h"
#include "h2/sentinel.h"
#include "header.h"
#include "route_srv.h"
#include "server_srv.h"
#include "slab.h"
#include "socket_srv.h"
#include "string/lib.h"
#include "utils_lib.h"
#include "worker_srv.h"

extern const struct aura_hpack_static_table static_table;

/**
 * Handle client first settings frame after connection preface
 */
static int a_srv_process_preface_settings(struct aura_h2_server_conn *c, struct aura_sliding_buf *plain_buf);

/* process frames */
int aura_h2_srv_process_frame(struct aura_h2_server_conn *c, struct aura_sliding_buf *buf);

int aura_h2_srv_conn_init(struct aura_h2_server_conn *c, struct aura_mem_ctx *mc) {
    if (aura_h2_core_init(&c->core, mc, true) < 0) {
        aura_slab_free(c);
        return -1;
    }

    return 0;
}

void aura_h2_srv_conn_destroy(struct aura_h2_server_conn *c) {
    aura_h2_core_destroy(&c->core, true);
}

static bool aura_h2_srv_can_transmit(void *payload) {
    struct aura_h2_sched_iov *s_iov = payload;
    struct aura_h2_stream_desc *stream_desc;
    uint32_t wind_sz;

    app_debug(true, 0, ">>>> aura_h2_srv_can_transmit");
    aura_h2_sched_iov_dump(s_iov);

    /* both header and body are present */
    switch (s_iov->type) {
    case A_H2_SCHED_RESPONSE:
        s_iov->allowed_len = s_iov->header_len;
        stream_desc = aura_h2_conn_stream_desc_get(s_iov->h2_c, s_iov->stream_desc_idx);
        wind_sz = aura_h2_stream_desc_can_proceed(stream_desc, s_iov->stream_id);
        if (wind_sz > 0)
            s_iov->allowed_len += a_min(wind_sz, s_iov->data_len);

        return true;

    case A_H2_SCHED_DATA:
        stream_desc = aura_h2_conn_stream_desc_get(s_iov->h2_c, s_iov->stream_desc_idx);
        wind_sz = aura_h2_stream_desc_can_proceed(stream_desc, s_iov->stream_id);
        if (wind_sz > 0)
            s_iov->allowed_len = wind_sz;

        return wind_sz > 0;

    case A_H2_SCHED_HDR:
        s_iov->allowed_len = s_iov->header_len;
        return true;

    default:
        s_iov->allowed_len = s_iov->data_len;
        return true;
    }
}

/**
 * Trigger write to the parent connection fd
 */
static int inline a_h2_srv_trigger_flush(struct aura_h2_core *h2_c, struct aura_sliding_buf *buf) {
    struct aura_h2_server_conn *c;
    struct aura_conn *p_conn;
    uint8_t *read_ptr;
    uint64_t read_len;
    int64_t bytes_written;

    read_ptr = aura_sliding_buf_read_ptr(buf);
    read_len = aura_sliding_buf_read_len(buf);
    app_debug(true, 0, ">>>> a_h2_srv_trigger_flush len=%lu", read_len);
    if (read_len > 0) {
        c = aura_container_of(h2_c, struct aura_h2_server_conn, core);
        p_conn = aura_container_of(c, struct aura_conn, h2_server);
        bytes_written = aura_write(p_conn->sock.sock_fd, read_ptr, read_len);
        if (bytes_written != read_len) {
            if (bytes_written > 0) {
                aura_sliding_buf_consume(buf, bytes_written);
                /**
                 * Copy the remaining data to the residual buffer,
                 * which is sent immediately we have a signal to write
                 */
                if (aura_sliding_buf_copy(&p_conn->residual_buf, buf) < 0)
                    return A_FQ_FATAL;

                return A_FQ_STALLED;
            }

            if (bytes_written == 0)
                return A_FQ_STALLED;

            return A_FQ_FATAL;
        }

        aura_sliding_buf_consume(buf, bytes_written);
    }

    app_debug(true, 0, "FINISHED WRITING <<<<<<<<<< fq empty=%d, out_empty=%d, pri_empty=%d, spill_empty=%d", aura_fq_is_empty(h2_c->fq), aura_h2_sched_dense_pool_is_empty(&h2_c->out_frame_pool), aura_h2_sched_pri_slot_empty(&h2_c->scheduler), aura_h2_sched_spill_slot_empty(&h2_c->scheduler));

    return A_FQ_OK;
}

static inline int a_h2_srv_encrypt(struct aura_tls_ctx *tls, struct aura_mem_ctx *mc, struct aura_h2_sched_iov *s_iov, bool final) {
    bool done;
    int64_t rv;

    app_debug(true, 0, ">>>> a_h2_srv_encrypt");
again:
    done = false;
    rv = aura_tls_encode(tls, mc, s_iov, &done, final);
    if (rv < 0) {
        if (s_iov)
            aura_h2_sched_iov_destroy(s_iov);
        return A_FQ_FATAL;
    }
    app_debug(true, 0, "a_h2_srv_encrypt rv=%d, done=%d", rv, done);

    /**
     * This happens when nothing is encoded due to encrypted buffer
     * being filled up, So we try and write immediately.
     */
    if (rv == 0 && !done) {
        if ((rv = a_h2_srv_trigger_flush(s_iov->h2_c, &tls->encrypted_write_buf)) != A_FQ_OK)
            return rv;

        /**
         * If frame could not proceed because
         * the TLS buffer was full, try again
         */
        goto again;
    }

    if (done) {
        aura_h2_sched_iov_destroy(s_iov);

        return A_FQ_RELEASED;
    } else {
        /**
         * Only part of the data was encrypted, we update the
         * len, try and flush again, then repeat the encryption
         * routine all over again
         */
        /* Bytes were sliced, trigger flush  */
        if ((rv = a_h2_srv_trigger_flush(s_iov->h2_c, &tls->encrypted_write_buf)) != A_FQ_OK)
            return rv;

        goto again;

        return A_FQ_OK;
    }
}

/**
 * Encrypt enqueued frames for wrire transmission
 */
static int aura_h2_srv_encrypt(void *payload) {
    struct aura_h2_sched_iov *s_iov = payload;
    struct aura_h2_server_conn *c;
    struct aura_conn *conn;
    struct aura_tls_ctx *tls_ctx;
    bool done;
    int64_t rv;

    c = aura_container_of(s_iov->h2_c, struct aura_h2_server_conn, core);
    conn = aura_container_of(c, struct aura_conn, h2_server);
    tls_ctx = &conn->tls_ctx;

    if (conn->is_secure) {
        return a_h2_srv_encrypt(tls_ctx, conn->mc, s_iov, false);
    } else {
        /** @todo: send without encryption */
    }

    return A_FQ_OK;
}

/**
 * Trigger write at the end of encryption,
 * after the flight queue has visited all
 * entries
 */
static int aura_h2_srv_write_complete(void *payload) {
    struct aura_h2_core *h2_c = payload;
    struct aura_h2_server_conn *c;
    struct aura_conn *conn;
    struct aura_tls_ctx *tls_ctx;

    app_debug(true, 0, ">>>> aura_h2_srv_write_complete");
    c = aura_container_of(h2_c, struct aura_h2_server_conn, core);
    conn = aura_container_of(c, struct aura_conn, h2_server);
    tls_ctx = &conn->tls_ctx;

    int64_t rv = a_h2_srv_encrypt(tls_ctx, conn->mc, NULL, true);
    if (rv == A_FQ_FATAL)
        return rv;

    return a_h2_srv_trigger_flush(h2_c, &tls_ctx->encrypted_write_buf);
}

int aura_h2_srv_write(struct aura_h2_server_conn *c) {
    struct aura_conn *p_conn;
    ssize_t tls_bytes_written, encrypted_written;
    uint8_t *read_ptr;
    size_t read_len;
    struct aura_h2_send_iov *send_iov;
    int rv;

    app_debug(true, 0, ">>>> aura_h2_srv_write");
    p_conn = aura_container_of(c, struct aura_conn, h2_server);
    rv = aura_h2_schedule(&c->core);

    rv = aura_flight_queue_flush(
      c->core.fq,
      aura_h2_srv_can_transmit,
      aura_h2_srv_encrypt,
      NULL, /* no per item completion function */
      aura_h2_srv_write_complete);
    switch (rv) {
    case A_FQ_STALLED:
        int r;
        if (aura_evt_loop_modify(p_conn->srv_ctx->evt_loop, p_conn->sock.sock_fd, p_conn, AURA_EVENT_READ | AURA_EVENT_WRITE) < 0) {
            aura_list_move(&p_conn->srv_ctx->queues.reap, &p_conn->c_list);
            rv = A_ERR_FATAL;
        }
        break;

    case A_FQ_FATAL:
    case A_FQ_RELEASED:
    case A_FQ_ABORTED:
        /* Move to closing queue */
        aura_list_move(&p_conn->srv_ctx->queues.reap, &p_conn->c_list);
        rv = A_ERR_FATAL;
        break;

    case A_FQ_OK:
    default:
        rv = A_ERR_NONE;
        break;
    }

    return rv;
}

/**
 * Returns true if header received is a trailing header,
 * otherwise false
 */
static inline bool a_h2_is_trailer_headers(struct aura_h2_stream *s, struct aura_h2_frame *f, bool is_server) {
    if (!s || f->type != A_H2_FRAME_TYPE_HDRS)
        return false;

    return s->flags & (A_H2_STREAM_FLAG_HDRS_RECD | A_H2_STREAM_FLAG_HDRS_SENT);
}

/** */
static inline int a_handle_trailing_headers() {
    /* handle trailer headers and its continuation */
    return 0;
}

int aura_submit_response(struct aura_h2_server_conn *h2_conn, struct aura_h2_stream *stream, bool end_stream) {
    size_t offset;
    uint8_t *src_in, *dest;
    struct aura_h2_sched_evt *evt;
    size_t remaining, chunk;
    uint8_t type, flags;
    bool is_first, has_body = false;
    int rv;

    app_debug(true, 0, "aura_submit_response <<<<");

    //     rv = aura_hpack_encoder_adjust_tab_size(&h2_conn->enc);
    //     if (rv != A_HPACK_OK)
    //         return aura_h2_translate_hpack_error(rv);

    //     aura_hpack_encode_status(&h2_conn->enc, stream->res.status_code);

    //     rv = aura_hpack_encode_headers(&h2_conn->enc, h2_conn->intern_tab, stream->res.headers.entries, stream->res.headers.cnt);
    //     if (rv < 0)
    //         return aura_h2_translate_hpack_error(rv);

    //     if (stream->res.content_length != SIZE_MAX) {
    //         has_body = true;

    //         rv = aura_hpack_encode_content_length(&h2_conn->enc, stream->res.content_length);
    //         if (rv < 0)
    //             return aura_h2_translate_hpack_error(rv);
    //     }

    //     src_in = aura_sliding_buf_read_ptr(h2_conn->enc.buf);
    //     // size_t len = remaining = aura_sliding_buf_read_len(h2_conn->enc.buf);
    //     remaining = aura_sliding_buf_read_len(h2_conn->enc.buf);
    //     offset = 0;

    //     is_first = true;
    //     rv = 0;
    //     end_stream = !has_body && end_stream;
    //     while (remaining > 0) {
    //         chunk = a_min(remaining, h2_conn->peer_settings.max_frame_size);
    //         type = is_first ? A_H2_FRAME_TYPE_HDRS : A_H2_FRAME_TYPE_CONT;
    //         flags = remaining == chunk ? A_H2_FRAME_FLAG_END_HEADERS : 0;
    //         /* defer sending END_STREAM until final headers block */
    //         flags |= (end_stream && (flags & A_H2_FRAME_FLAG_END_HEADERS)) ? A_H2_FRAME_FLAG_END_STREAM : 0;
    //         rv = aura_h2_encode_hdr_frame(stream->sync, stream->stream_id, type, flags, src_in + offset, chunk);
    //         if (rv < 0)
    //             break;

    //         is_first = false;
    //         offset += chunk;
    //         remaining -= chunk;
    //     }

    //     if (rv != A_H2_ERR_NONE)
    //         goto out;

    //     evt = aura_sched_evt_create(h2_conn->conn->mc, stream, stream->sync, AURA_H2_SCHED_OP_HEADER_WRITE, NULL, 0, end_stream);
    //     if (!evt) {
    //         rv = A_H2_INTERNAL_ERR;
    //         goto out;
    //     }
    //     aura_list_add_tail(&h2_conn->scheduler.queues.data.head, &evt->e_list);
    //     stream->flags |= A_H2_STREAM_FLAG_SEND_HDRS;

    //     if (stream->res.body && stream->res.content_length != SIZE_MAX) {
    //         evt = aura_sched_evt_create(
    //           h2_conn->conn->mc, stream, stream->data, AURA_H2_SCHED_OP_DATA_WRITE, NULL, 0, end_stream);
    //         if (!evt) {
    //             rv = A_H2_INTERNAL_ERR;
    //             goto out;
    //         }
    //         aura_list_add_tail(&h2_conn->scheduler.queues.data.head, &evt->e_list);
    //         stream->flags |= A_H2_STREAM_FLAG_SEND_DATA;
    //     }

    // out:
    //     // aura_sliding_buf_consume(h2_conn->enc.buf, offset);
    //     aura_sliding_buf_reset(h2_conn->enc.buf);
    //     return rv;
}

struct aura_kv_iovec *a_get_slot(struct aura_h2_stream *stream, struct aura_mem_ctx *mc) {

    if (stream->res.headers.cnt >= stream->res.headers.cap) {
        stream->res.headers.cap = stream->res.headers.cap == 0 ? 16 : stream->res.headers.cap * 2;
        stream->res.headers.entries = aura_realloc(mc, stream->res.headers.entries, sizeof(*(stream->res.headers.entries)) * stream->res.headers.cap);
        if (stream->res.headers.entries == NULL)
            return NULL;
    }

    return &stream->res.headers.entries[stream->res.headers.cnt++];
}

/**
 * Prepare error response for submitting on the wire
 * and call the underlying callback to send the data
 */
int aura_h2_submit_error_response(struct aura_h2_core *h2_c, struct aura_h2_stream *stream,
                                  int status, uint8_t *body, uint64_t len) {
    struct aura_h2_server_conn *c = aura_container_of(h2_c, struct aura_h2_server_conn, core);
    struct aura_conn *conn = aura_container_of(c, struct aura_conn, h2_server);

    app_debug(true, 0, ">>>> aura_h2_submit_error_response");
    stream->res.content_length = SIZE_MAX;
    if (body) {
        stream->res.content_length = len;
        stream->res.body = body;
    }
    struct aura_kv_iovec *slot = a_get_slot(stream, conn->mc);
    slot->key.len = sizeof("content-type") - 1;
    slot->key.base = aura_strndup(conn->mc, "content-type", slot->key.len);
    slot->value.len = sizeof("application/json") - 1;
    slot->value.base = aura_strndup(conn->mc, "application/json", slot->value.len);

    stream->res.status_code = status;
    stream->flags &= ~A_H2_STREAM_FLAG_EXECUTE;
    aura_h2_conn_sched_attach_stream(h2_c, stream);

    return 0;
}

int aura_h2_submit_rt_response(struct aura_h2_core *h2_conn, struct aura_h2_stream *stream,
                               Response *resp, struct aura_mem_ctx *mc) {
    int status, rv;

    rv = A_H2_ERR_NONE;
    if (resp->status < 100 || resp->status > 500) {
        // return aura_submit_response(h2_conn, stream, true);
    } else {
        if (aura_h2_stream_claim_rt_response(stream, resp, mc) < 0) {
            return A_H2_INTERNAL_ERR;
        }

        // return aura_submit_response(h2_conn, stream, true);
    }
}

/* Prepares connection for immediate closing */
static int a_h2_srv_close_conn_immediate(struct aura_h2_server_conn *c, int err, int err_str_idx) {
    struct aura_conn *conn;
    struct aura_iovec reason = aura_h2_err_string[err_str_idx];

    app_debug(true, 0, ">>>> a_h2_srv_close_conn_immediate");
    int rv = aura_h2_conn_enqueue_goaway(&c->core, c->core.local_goaway_stream_id, err, &reason);
    if (rv != A_H2_ERR_NONE)
        return rv;

    aura_h2_conn_transition_state(&c->state, A_H2_CONN_STATE_CLOSED);
    conn = aura_container_of(c, struct aura_conn, h2_server);
    aura_conn_transition_state(conn, A_CONN_STATE_CLOSED);

    return A_H2_ERR_NONE;
}

/* Prepare connection for graceful closing */
static int a_h2_srv_close_connection(struct aura_h2_server_conn *c, int err, int err_str_idx) {
    struct aura_conn *conn;
    struct aura_iovec reason = aura_h2_err_string[err_str_idx];
    int rv = A_H2_ERR_NONE;

    if (c->state == A_H2_CONN_STATE_CLOSING)
        return rv;

    rv = aura_h2_conn_enqueue_goaway(&c->core, c->core.local_goaway_stream_id, err, &reason);
    if (rv != A_H2_ERR_NONE)
        return rv;

    aura_h2_conn_transition_state(&c->state, A_H2_CONN_STATE_CLOSING);
    conn = aura_container_of(c, struct aura_conn, h2_server);
    aura_conn_transition_state(conn, A_CONN_STATE_CLOSING);
    conn->ops->on_deadline_update(conn, A_DL_CONN_GOAWAY_GRACIOUS);
    conn->ops->on_timer_update(conn);

    return A_H2_ERR_NONE;
}

static int a_setup_server_preface(struct aura_h2_core *h2_c, int *err_str_idx) {
    uint32_t settings_len, wind_len, total_len; /* Frame length */
    uint8_t *out_data, *frame;
    uint32_t initial_window_size;
    const struct aura_iovec *reason;
    struct aura_h2_sched_iov *s_iov;
    int error;

    app_debug(true, 0, ">>>> a_setup_server_preface");
    struct aura_h2_settings_payload settings[] = {
      {.settings_id = A_H2_SETTINGS_MAX_CONCURRENT_STREAMS, .value = aura_h2_default_settings.max_conc_streams},
    };

    settings_len = aura_calc_frame_len(A_H2_FRAME_TYPE_SETTINGS, ARRAY_SIZE(settings), 0);

    out_data = aura_h2_encode_ctrl_frame(
      &h2_c->scheduler.write_buf,
      A_H2_FRAME_TYPE_SETTINGS,
      A_H2_FRAME_FLAG_NONE,
      0,
      settings_len,
      (void *)&settings,
      ARRAY_SIZE(settings));
    if (!out_data) {
        *err_str_idx = A_H2_ERR_STR_IDX_INTERNAL_ERROR;
        return A_H2_INTERNAL_ERR;
    }

    /**
     * Store buffer start for first frame
     * Since both frames will be written inorder
     * we can use a single s_iov entry
     */
    frame = out_data;

    wind_len = aura_calc_frame_len(A_H2_FRAME_TYPE_WIND_UPDATE, 0, 0);
    initial_window_size = A_H2_INITIAL_WINDOW_SIZE;

    out_data = aura_h2_encode_ctrl_frame(
      &h2_c->scheduler.write_buf,
      A_H2_FRAME_TYPE_WIND_UPDATE,
      A_H2_FRAME_FLAG_NONE,
      0,
      wind_len,
      (uint8_t *)&initial_window_size,
      0);
    if (!out_data) {
        *err_str_idx = A_H2_ERR_STR_IDX_INTERNAL_ERROR;
        return A_H2_INTERNAL_ERR;
    }

    s_iov = aura_h2_get_sched_iov(h2_c, A_H2_SCHED_CONTROL);
    if (!s_iov) {
        /* @todo: close connection */
        app_exit(true, 0, "NOT SCHED IOV CLOSE CONN PROBABLY");
    }

    s_iov->type = A_H2_SCHED_CONTROL;
    s_iov->data = frame;
    s_iov->data_len = settings_len + wind_len;
    s_iov->buf = &h2_c->scheduler.write_buf;
    aura_sliding_buf_reference(s_iov->buf);
    s_iov->stream_id = 0;
    s_iov->end_stream = false;
    aura_h2_sched_accum_bytes(&h2_c->scheduler, s_iov);

    return A_H2_ERR_NONE;
}

/**
 * Handle server connection preface
 * We do not consider h2 established at this point yet.
 * Simply close connection
 */
int aura_h2_srv_process_preface(struct aura_h2_server_conn *c, struct aura_sliding_buf *plain_buf) {
    int res, len;
    uint8_t *src;

    app_debug(true, 0, ">>>> aura_h2_srv_process_preface");
    src = aura_sliding_buf_read_ptr(plain_buf);
    len = aura_sliding_buf_read_len(plain_buf);

    if (len < aura_h2_conn_preface.len) {
        /* frame incomplete */
        return A_ERR_AGAIN;
    }
    aura_hex_dump_syslog(LOG_DEBUG, "H2", src, len);

    if (memcmp(aura_h2_conn_preface.base, src, aura_h2_conn_preface.len) != 0) {
        /* protocol error, no goaway, simply close connection */
        return A_ERR_FATAL;
    }

    aura_sliding_buf_consume(plain_buf, aura_h2_conn_preface.len);
    // encode origin if present
    aura_h2_conn_transition_state(&c->state, A_H2_CONN_STATE_PREFACE_SETTINGS);

    return A_ERR_NONE;
}

/** */
static int a_srv_process_preface_settings(struct aura_h2_server_conn *c, struct aura_sliding_buf *plain_buf) {
    struct aura_h2_in_frame *in_frame = &c->core.in_frame;
    int rv, len, frame_len, err_str_idx;
    uint8_t *src;

    app_debug(true, 0, ">>>> a_srv_process_preface_settings");
    src = aura_sliding_buf_read_ptr(plain_buf);
    len = aura_sliding_buf_read_len(plain_buf);
    rv = aura_h2_parse_frame_header(in_frame, src, len, c->core.local_settings.max_frame_size);
    if (rv != A_H2_ERR_NONE)
        return aura_h2_get_app_error(rv);

    if (in_frame->frame.type != A_H2_FRAME_TYPE_SETTINGS)
        return a_h2_srv_close_conn_immediate(c, A_H2_PROTOCOL_ERR, A_H2_ERR_STR_IDX_INVALID_ARG);

    frame_len = A_H2_FRAME_HEADER_SIZE + in_frame->frame.len;
    rv = aura_h2_conn_process_settings(&c->core, in_frame, true, &err_str_idx);
    aura_sliding_buf_consume(plain_buf, frame_len);
    if (rv != A_H2_ERR_NONE)
        return a_h2_srv_close_conn_immediate(c, rv, err_str_idx);

    rv = a_setup_server_preface(&c->core, &err_str_idx);
    if (rv != A_H2_ERR_NONE)
        return a_h2_srv_close_conn_immediate(c, rv, err_str_idx);

    aura_h2_conn_transition_state(&c->state, A_H2_CONN_STATE_FRAMES);

    /**
     * Beyond this points, h2 errors would be communicated via goaway and resets.
     * The connection shutdown state would determine if
     * we would tear down the connection, but we would be returning
     * ERR NONE for the various scenarios
     */
    struct aura_conn *conn = aura_container_of(c, struct aura_conn, h2_server);
    aura_conn_transition_state(conn, A_CONN_STATE_ACTIVE);
    aura_h2_frame_reset_inframe(in_frame);

    return A_ERR_NONE;
}

/**
 *
 */
static int a_srv_process_push_promise(struct aura_h2_server_conn *c, struct aura_h2_in_frame *in_frame,
                                      struct aura_mem_ctx *mc) {
    return a_h2_srv_close_conn_immediate(c, A_H2_PROTOCOL_ERR, A_H2_ERR_STR_IDX_INTERNAL_ERROR);
}

/**
 * Returns true if provided method is valid,
 * otherwise false
 */
uint8_t a_is_header_method_valid(const char *method) {
    if (strcasecmp(method, "GET") == 0)
        return A_HTTP_GET;

    if (strcasecmp(method, "POST") == 0)
        return A_HTTP_POST;

    if (strcasecmp(method, "PUT") == 0)
        return A_HTTP_PUT;

    if (strcasecmp(method, "HEAD") == 0)
        return A_HTTP_HEAD;

    /** @todo: add others */

    return A_HTTP_NONE;
}

/**
 * Returns 0 if the parsed authority is among list
 * of allowed authority for a given server, otherwise err;
 */
static int a_header_authority_cb(struct aura_h2_core *h2_c, struct aura_h2_stream *stream,
                                 struct aura_iovec *name, struct aura_iovec *value, bool process) {
    app_debug(true, 0, ">>>> a_header_authority_cb value: %s", value->base);

    struct aura_h2_server_conn *c = aura_container_of(h2_c, struct aura_h2_server_conn, core);
    struct aura_conn *conn = aura_container_of(c, struct aura_conn, h2_server);
    if (process)
        stream->req.authority.host.base = aura_strndup(conn->mc, value->base, value->len);
    return A_HPACK_OK;
}

/**
 * Return 0 if the parsed method is valid and
 * supported by server, otherwise -1;
 */
static int a_header_method_cb(struct aura_h2_core *h2_c, struct aura_h2_stream *stream,
                              struct aura_iovec *name, struct aura_iovec *value, bool process) {
    uint64_t content_len;
    uint8_t method;

    app_debug(true, 0, ">>>> a_header_method_cb value: %s", value->base);
    if (strcmp(value->base, "CONNECT") == 0 || strcmp(value->base, "TRACE") == 0) {
        /* unsupported methods */
        return A_HPACK_INVALID_VALUE_ERR;
    }

    method = a_is_header_method_valid(value->base);
    if (method == A_HTTP_NONE)
        return A_HPACK_INVALID_VALUE_ERR;

    if (process)
        stream->req.method = method;
    return A_HPACK_OK;
}

/**
 * Get and attach host config associated with parsed
 * path, validate that path is supported by hosts,
 * return 0 if satisfied, otherwise err
 */

static int a_header_path_cb(struct aura_h2_core *h2_c, struct aura_h2_stream *stream,
                            struct aura_iovec *name, struct aura_iovec *value, bool process) {
    struct aura_srv_host_conf *host;
    struct aura_fn_registry_ent *fn_ent;
    struct aura_h2_server_conn *c;
    struct aura_conn *conn;

    app_debug(true, 0, ">>>> a_header_path_cb val=%s, len=%u", value->base, value->len);
    c = aura_container_of(h2_c, struct aura_h2_server_conn, core);
    conn = aura_container_of(c, struct aura_conn, h2_server);
    host = conn->host;
    A_BUG_ON_2(!host, true);

    /* validate if requested route/fn exists */
    if (process) {
        fn_ent = host->evt_src.ops->find_fn(&host->evt_src, value);
        stream->req.path.base = aura_strndup(conn->mc, value->base, value->len);
        app_debug(true, 0, "function entry=%p", fn_ent);
        if (!fn_ent) {
            /* 404 */
            return A_HPACK_INVALID_PATH_ERR;
        }

        /* If we already have the method */
        uint8_t method = stream->req.method;
        if (method != A_HTTP_NONE) {
            for (int i = 0; i < fn_ent->fn->meta.triggers.cnt; ++i)
                if (fn_ent->fn->meta.triggers.entries[i].trigger == A_FN_TRIGGER_HTTP) {
                    if (fn_ent->fn->meta.triggers.entries[i].http.method != method) {
                        /* 404 */
                        return A_HPACK_INVALID_PATH_ERR; /* @todo: perhaps distinguish as seperate internal error */
                    }
                    break;
                }
        }

        /* set route so we don't have to search again */
        conn->fn_ent = fn_ent;
    }
    return A_HPACK_OK;
}

/**
 * Returns 0 if parsed scheme is valid and
 * supported, otherwise err
 */
static int a_header_scheme_cb(struct aura_h2_core *h2_c, struct aura_h2_stream *stream,
                              struct aura_iovec *name, struct aura_iovec *value, bool process) {
    /**/
    app_debug(true, 0, ">>>> a_header_scheme_cb %s", value->base);
    if (process) {
        stream->req.scheme = aura_http_scheme_get_scheme_t(value->base, value->len);
        if (stream->req.scheme == A_SCHEME_NONE)
            return A_HPACK_INVALID_VALUE_ERR;
    }
    return A_HPACK_OK;
}

/**
 * Returns 0 if parsed status is valid number,
 * otherwise return err;
 */
static int a_header_status_cb(struct aura_h2_core *h2_c, struct aura_h2_stream *stream,
                              struct aura_iovec *name, struct aura_iovec *value, bool process) {
    int status;
    char *c;

    if (stream->res.status_code != 0)
        return A_HPACK_DUPLICATE_HDR_ERR;

    /* parse */
    if (value->len != 3) {
        return A_HPACK_DUPLICATE_HDR_ERR;
    }

    c = value->base;
#define PARSE_DIGIT(mul, min_digit)               \
    do {                                          \
        if (*c < '0' + (min_digit) || '9' < *c) { \
            return A_HPACK_DUPLICATE_HDR_ERR;     \
        }                                         \
        status += (*c - '0') * mul;               \
        ++c;                                      \
    } while (0);
    PARSE_DIGIT(100, 1);
    PARSE_DIGIT(10, 0);
    PARSE_DIGIT(1, 0);
#undef PARSE_DIGIT

    stream->res.status_code = status;

    return A_HPACK_OK;
}

/**
 * Validate content length
 */
static int a_header_content_len_cb(struct aura_h2_core *h2_c, struct aura_h2_stream *stream,
                                   struct aura_iovec *name, struct aura_iovec *value, bool process) {

    return A_HPACK_OK;
}

static int a_header_priority_cb(struct aura_h2_core *h2_c, struct aura_h2_stream *stream,
                                struct aura_iovec *name, struct aura_iovec *value,
                                bool process) {
    struct aura_pri_ext prio_ext;

    app_debug(true, 0, ">>>> a_header_priority_cb val=%s", value->base);
    if (!process) {
        if (aura_h2_parse_http_prio(&prio_ext, value->base, value->len) < 0) {
            stream->flags |= A_H2_STREAM_FLAG_BAD_PRIO;
            return A_HPACK_INVALID_HDR_FIELD_ERR;
        }

        aura_h2_update_stream_priority(h2_c, stream, &prio_ext);
    }

    return A_HPACK_OK;
}

/**
 * Can this request create a task
 */
static inline bool a_h2_srv_conn_can_execute(struct aura_h2_server_conn *c, struct aura_h2_stream *s) {
    struct aura_conn *conn = aura_container_of(c, struct aura_conn, h2_server);
    if (conn->state == A_CONN_STATE_CLOSING) {
    }
}

/**
 * P
 */
static int aura_h2_srv_process_request(struct aura_h2_server_conn *c, uint32_t stream_id) {
    struct aura_h2_stream *stream;
    struct aura_fn_registry_ent *fn_ent;
    struct aura_work_queue *wq;
    struct aura_conn *conn;
    struct aura_task *task;
    Request *req;
    Response *resp;
    char *url;
    uint64_t url_len;
    int rv;

    stream = aura_h2_conn_find_stream(&c->core, stream_id);
    if (!stream)
        return A_H2_ERR_NONE;

    if (stream->flags & A_H2_STREAM_FLAG_EXECUTE) {
        /* forward to route handler/path handler */
        conn = aura_container_of(c, struct aura_conn, h2_server);
        fn_ent = conn->fn_ent;
        A_BUG_ON_2(!fn_ent, true);

        /* @todo: load the function to cache */
        if (fn_ent->load_state == A_FN_UNLOADED) {
            /* @todo: could it be activated and done async */
        }

        /* calculate url len */
        const char *scheme = a_http_scheme_str[stream->req.scheme];
        url = aura_url_construct(conn->mc, scheme, stream->req.authority.host.base, stream->req.path.base, NULL, 0);
        if (!url)
            return A_H2_INTERNAL_ERR;
        req = aura_js_req_create(
          conn->mc,
          stream->req.method,
          &stream->req.headers,
          stream->req.body,
          stream->req.content_length,
          url);
        aura_free(url);
        if (!req)
            return A_H2_INTERNAL_ERR;

        /* Since body could have been transfered to the request, account for it on the stream */
        if (aura_http_method_can_accept_body(stream->req.method)) {
            stream->req.body = NULL;
            stream->req.content_length = 0;
        }

        /* Create task */
        task = aura_task_create(conn->mc, fn_ent->fn->meta.fn_id, NULL, 0, req, A_TASK_PENDING);
        if (!task) {
            aura_js_req_destroy(req);
            return A_H2_INTERNAL_ERR;
        }

        /* enqueue task */
        aura_fn_queue_enqueue_task(&fn_ent->fn_queue, task);

        if (rv) {
            aura_js_req_destroy(req);
            aura_free(task);
            return A_H2_INTERNAL_ERR;
        }
    }

    return A_H2_ERR_NONE;
}

/**
 * Begin processing of the headers.
 * Perform sanity checks on new stream id.
 * Open new stream for new connections, or
 * locate existing streams for trailer headers.
 * Return the errors encountered while also setting
 * the error string index using err_idx, otherwise return A_H2_ERR_NONE.
 */
int a_srv_pre_headers_processing(struct aura_h2_server_conn *c, struct aura_h2_in_frame *in_frame,
                                 struct aura_h2_stream **stream, struct aura_mem_ctx *mc, int *err_idx) {
    const struct aura_iovec *reason;
    struct aura_h2_sched_iov *s_iov;
    struct aura_h2_frame *frame = &in_frame->frame;
    bool is_stream_error;
    int rv, err;

    app_debug(true, 0, ">>>> a_srv_pre_headers_processing");
    if (aura_h2_conn_peer_stream_id_new(&c->core, frame->stream_id, true)) {
        app_debug(true, 0, "a_srv_pre_headers_processing new stream");
        /* Client initiated streams must have odd stream id */
        if (aura_h2_stream_is_even_numbered(frame->stream_id)) {
            *err_idx = A_H2_ERR_STR_IDX_INVALID_ARG;
            return A_H2_PROTOCOL_ERR;
        }

        /* If can not accept new stream headers, refuse new stream attempt */
        if (!aura_h2_srv_conn_new_streams_allowed(c)) {
            if (aura_h2_conn_enqueue_rst_frame(&c->core, frame->stream_id, A_H2_REFUSED_STREAM_ERR) < 0) {
                *err_idx = A_H2_ERR_STR_IDX_INTERNAL_ERROR;
                return A_H2_INTERNAL_ERR;
            }
            return A_H2_ERR_NONE;
        }

        *stream = aura_h2_conn_stream_open(
          &c->core,
          mc,
          frame->stream_id,
          A_H2_STREAM_STATE_IDLE,
          A_H2_STREAM_FLAG_NONE,
          NULL,
          NULL,
          true);

        if (!(*stream)) {
            *err_idx = A_H2_ERR_STR_IDX_INTERNAL_ERROR;
            return A_H2_INTERNAL_ERR;
        }

        if (aura_h2_frame_is_end_stream(frame->flags) && aura_h2_frame_is_end_headers(frame->flags)) {
            /* transition states and prepare for response */
            (*stream)->state = A_H2_STREAM_STATE_OPEN;
            (*stream)->state = A_H2_STREAM_STATE_HALF_CLOSED_REMOTE;
            (*stream)->flags |= A_H2_STREAM_FLAG_HDRS_RECD | A_H2_STREAM_FLAG_EXECUTE;
            aura_h2_conn_transition_state(&c->state, A_H2_CONN_STATE_FRAMES);
        } else if (aura_h2_frame_is_end_headers(frame->flags)) {
            (*stream)->state = A_H2_STREAM_STATE_OPEN;
            (*stream)->flags |= (A_H2_STREAM_FLAG_READ_DATA | A_H2_STREAM_FLAG_HDRS_RECD);
            aura_h2_conn_transition_state(&c->state, A_H2_CONN_STATE_FRAMES);
        } else {
            (*stream)->state = A_H2_STREAM_STATE_OPEN;
            if (aura_h2_frame_is_end_stream(frame->flags)) {
                (*stream)->state = A_H2_STREAM_STATE_HALF_CLOSED_REMOTE;
                (*stream)->flags |= A_H2_STREAM_FLAG_END_STREAM;
            }

            aura_h2_sen_update(&c->core.sen, A_H2_SEN_EVT_TINY_FRAME_FLOOD, in_frame->hdrs_payload.len);
            /* Store stream id for continuation frame checking */
            c->core.cont_stream_id = (*stream)->stream_id;
            aura_h2_conn_transition_state(&c->state, A_H2_CONN_STATE_CONT);
        }

    } else {
        /** @todo: push promise not supported */
        app_debug(true, 0, "a_srv_pre_headers_processing existing stream");
        *stream = aura_h2_conn_find_stream(&c->core, frame->stream_id);
        if (!(*stream)) {
            if (aura_h2_conn_enqueue_rst_frame(&c->core, frame->stream_id, A_H2_STREAM_CLOSED_ERR) < 0) {
                *err_idx = A_H2_ERR_STR_IDX_INTERNAL_ERROR;
                return A_H2_INTERNAL_ERR;
            }
            return A_H2_ERR_NONE;
        }

        /* trailer header block must contain end stream flag */
        if (!aura_h2_frame_is_end_stream(frame->flags)) {
            *err_idx = A_H2_ERR_STR_IDX_INVALID_ARG;
            return A_H2_PROTOCOL_ERR;
        }

        if (!aura_h2_stream_can_recv_hdrs(*stream)) {
            if ((*stream)->state == A_H2_STREAM_STATE_RESERVED_REMOTE) {
                *err_idx = A_H2_ERR_STR_IDX_INVALID_ARG;
                return A_H2_PROTOCOL_ERR;
            } else {
                if (aura_h2_conn_close_stream(&c->core, *stream, A_H2_STREAM_CLOSED_ERR, true) < 0) {
                    *err_idx = A_H2_ERR_STR_IDX_INTERNAL_ERROR;
                    return A_H2_INTERNAL_ERR;
                }
                return A_H2_ERR_NONE;
            }
        }

        (*stream)->state = A_H2_STREAM_STATE_HALF_CLOSED_REMOTE;
        (*stream)->flags |= A_H2_STREAM_FLAG_READ_TRAILER;

        if (aura_h2_frame_is_end_headers(frame->flags)) {
            /* do nothing */
        } else {
            aura_h2_sen_update(&c->core.sen, A_H2_SEN_EVT_TINY_FRAME_FLOOD, in_frame->hdrs_payload.len);
            c->state = A_H2_CONN_STATE_CONT;
        }
    }

    return A_H2_ERR_NONE;
}

static inline int a_h2_srv_parse_header_payload(struct aura_h2_core *core, struct aura_mem_ctx *mc,
                                                struct aura_h2_stream *stream, const uint8_t *src_in,
                                                uint64_t in_len, int *err_idx) {
    struct aura_hpack_decoder *dec = &core->dec;
    struct aura_header_field dec_hdr;
    const uint8_t *end = src_in + in_len;
    struct aura_iovec name, value;
    bool final = stream->flags & A_H2_STREAM_FLAG_HDRS_RECD;
    struct aura_h2_server_conn *c = aura_container_of(core, struct aura_h2_server_conn, core);
    int64_t rv;

    while (true) {
        rv = aura_hpack_decode(dec, src_in, end, core->intern_tab, &dec_hdr, final);
        if (rv != A_HPACK_OK) {
            if (aura_hpack_hdr_err_fatal(rv)) {
                /* Close connection */
                *err_idx = A_H2_ERR_STR_IDX_INVALID_ARG;
                return aura_h2_translate_hpack_error(rv);
            } else {
                /**
                 * stream error.
                 * we must still process entire header
                 * to preserve the decoder state across multiple
                 * streams
                 */
            }
        }

        src_in += rv;

        if (dec->flags & A_HDR_FIELD_FLAG_EMIT) {
            name.base = (char *)dec_hdr.name->data;
            name.len = dec_hdr.name->len;
            if (dec_hdr.flags & A_HDR_FIELD_FLAG_VALUE_INTERNED) {
                value.base = (char *)dec_hdr.value.interned->data;
                value.len = dec_hdr.value.interned->len;
            } else {
                value.base = (char *)dec_hdr.value.raw.str.base;
                value.len = dec_hdr.value.raw.str.len;
            }

            stream->received_headers += (name.len + value.len + 32);
            if (stream->received_headers > core->local_settings.max_hdr_list_size)
                aura_hpack_set_decoder_soft_err(dec, A_HPACK_HEADER_SIZE_TOO_LARGE);

            if (aura_hpack_is_pseudo_header(name.base)) {
                if (dec->regular_hdr_field_seen)
                    /** @todo: better error perhaps  */
                    aura_hpack_set_decoder_soft_err(dec, A_HPACK_INVALID_HDR_FIELD_ERR);

                switch (dec_hdr.token) {
                case A_TOKEN_METHOD:
                    /* Duplicate */
                    if (dec->pseudo_flags & A_H2_PSEUDO_HDR_METHOD) {
                        aura_hpack_set_decoder_soft_err(dec, A_HPACK_DUPLICATE_HDR_ERR);
                        break;
                    }

                    dec->pseudo_flags |= A_H2_PSEUDO_HDR_METHOD;
                    rv = a_header_method_cb(core, stream, &name, &value, dec->soft_error == 0);
                    aura_hpack_set_decoder_soft_err(dec, rv);
                    break;

                case A_TOKEN_SCHEME:
                    /* Duplicate */
                    if (dec->pseudo_flags & A_H2_PSEUDO_HDR_SCHEME) {
                        aura_hpack_set_decoder_soft_err(dec, A_HPACK_DUPLICATE_HDR_ERR);
                        break;
                    }

                    dec->pseudo_flags |= A_H2_PSEUDO_HDR_SCHEME;
                    rv = a_header_scheme_cb(core, stream, &name, &value, dec->soft_error == 0);
                    aura_hpack_set_decoder_soft_err(dec, rv);
                    break;

                case A_TOKEN_AUTHORITY:
                    /* Duplicate */
                    if (dec->pseudo_flags & A_H2_PSEUDO_HDR_AUTHORITY) {
                        aura_hpack_set_decoder_soft_err(dec, A_HPACK_DUPLICATE_HDR_ERR);
                        break;
                    }

                    dec->pseudo_flags |= A_H2_PSEUDO_HDR_AUTHORITY;
                    rv = a_header_authority_cb(core, stream, &name, &value, dec->soft_error == 0);
                    aura_hpack_set_decoder_soft_err(dec, rv);
                    break;

                case A_TOKEN_PATH:
                    /* Duplicate */
                    if (dec->pseudo_flags & A_H2_PSEUDO_HDR_PATH) {
                        aura_hpack_set_decoder_soft_err(dec, A_HPACK_DUPLICATE_HDR_ERR);
                        break;
                    }

                    dec->pseudo_flags |= A_H2_PSEUDO_HDR_PATH;
                    rv = a_header_path_cb(core, stream, &name, &value, dec->soft_error == 0);
                    aura_hpack_set_decoder_soft_err(dec, rv);
                    break;

                default:
                    /**/
                    aura_hpack_set_decoder_soft_err(dec, A_HPACK_INVALID_HDR_FIELD_ERR);
                    break;
                }

            } else {
                dec->regular_hdr_field_seen = true;
                app_debug(true, 0, ">> regular header -> name=%s, value=%s, token=%d", name.base, value.base, dec_hdr.token);
                switch (dec_hdr.token) {
                case A_TOKEN_CONTENT_LENGTH:
                    rv = a_header_content_len_cb(core, stream, &name, &value, dec->soft_error == 0);
                    aura_hpack_set_decoder_soft_err(dec, rv);
                    break;

                case A_TOKEN_PRIORITY:
                    if (!(stream->flags & A_H2_STREAM_FLAG_READ_TRAILER) &&
                        !aura_h2_stream_is_push_stream(stream->stream_id) &&
                        !(stream->flags & A_H2_STREAM_FLAG_BAD_PRIO)) {
                        rv = a_header_priority_cb(core, stream, &name, &value, dec->soft_error == 0);
                        aura_hpack_set_decoder_soft_err(dec, rv);
                    }
                    break;

                case A_TOKEN_EXPECT:
                case A_TOKEN_ACCEPT:
                case A_TOKEN_ACCEPT_ENCODING:
                case A_TOKEN_USER_AGENT:
                    break;

                case A_TOKEN_HOST:
                    /**
                     * From the HTTP/2 RFC, server SHOULD treat a request as malformed
                     * if this value defers from the :authority value, but we simply
                     * skip it in this case.
                     */
                    if (dec->pseudo_flags & A_H2_PSEUDO_HDR_AUTHORITY)
                        break;

                    rv = a_header_authority_cb(core, stream, &name, &value, dec->soft_error == 0);
                    aura_hpack_set_decoder_soft_err(dec, rv);
                    break;

                case A_TOKEN_TE:
                    if (aura_lc_str_is_eq(value.base, value.len, str_lit("trailers"))) {
                        /**/
                    }
                    break;

                default:
                    /* rest of the header fields that are marked as special are rejected */
                    app_debug(true, 0, "hpack unknown special header: %s (ignore)", name.base);
                    /* @todo */
                    // aura_hpack_set_decoder_soft_err(dec, A_HPACK_INVALID_HDR_FIELD_ERR);
                    break;
                }
                /**
                 * If we encounter an error at any point, we are likely to destroy the stream,
                 * so no need to pass headers on stream request structure
                 */
                if (dec->soft_error == 0)
                    aura_header_add_header_field(mc, &stream->req.headers, &dec_hdr);
            }
        }

        if (dec->flags & A_HDR_FIELD_FLAG_FINAL) {
            break;
        }

        /**
         * Wait for more bytes
         */
        if (src_in == end && !final) {
            return A_H2_IN_PROGRESS_ERR;
        }
    }

    if (final) {
        int soft_err = dec->soft_error;

        /**
         * Validation
         * Missing required pseudo headers
         */
        if ((dec->pseudo_flags & A_H2_REQ_PSEUDO_HDRS) != A_H2_REQ_PSEUDO_HDRS) {
            /* close stream */
            app_debug(true, 0, ">> missing required pseudo header");
            return aura_h2_conn_close_stream(core, stream, A_H2_PROTOCOL_ERR, true);
        }

        aura_hpack_decoder_reset(dec);

        if (soft_err == 0) {
            return A_H2_ERR_NONE;
        }

        aura_h2_sen_update(&core->sen, A_H2_SEN_EVT_HPACK_ANOMALY, 0);
        switch (soft_err) {
        case A_HPACK_INVALID_PATH_ERR:
            /* 404 */
            return aura_h2_submit_error_response(core, stream, 404, NULL, 0);

        case A_HPACK_HEADER_SIZE_TOO_LARGE:
            /* 431 */
            return aura_h2_submit_error_response(core, stream, 431, NULL, 0);

        default:
            /* Usual stream errors */
            return aura_h2_conn_close_stream(core, stream, aura_h2_translate_hpack_error(soft_err), true);
        }
    }

    return A_H2_ERR_NONE;
}

/**
 * Parse the header data received.
 * Parsing does not wait for end headers and as such,
 * can be streamed. A fatal error returns the error
 * and uses err_idx to show the reason for failure.
 */
static int a_h2_srv_process_headers_early_bailout(struct aura_h2_core *h2_c, struct aura_h2_stream *stream,
                                                  struct aura_mem_ctx *mc, const uint8_t *src_in,
                                                  size_t in_len, int *err_idx) {
    struct aura_hpack_decoder *dec = &h2_c->dec;
    struct aura_header_field dec_hdr;
    const uint8_t *end = src_in + in_len;
    struct aura_iovec name, value;
    bool final = stream->flags & A_H2_STREAM_FLAG_HDRS_RECD;
    struct aura_h2_server_conn *c = aura_container_of(h2_c, struct aura_h2_server_conn, core);
    int rv;
    int soft_err;

    app_debug(true, 0, "a_srv_process_headers_early_bailout_A");

    rv = a_h2_srv_parse_header_payload(h2_c, mc, stream, src_in, in_len, err_idx);
    if (rv != A_H2_ERR_NONE) {
        if (rv == A_H2_IN_PROGRESS_ERR)
            return rv;

        *err_idx = A_H2_ERR_STR_IDX_INVALID_ARG;
        return aura_h2_translate_hpack_error(rv);
    }

    return rv;
}

static int a_srv_process_cont(struct aura_h2_server_conn *c, struct aura_h2_in_frame *in_frame,
                              struct aura_mem_ctx *mc) {
    struct aura_h2_stream *stream;
    const uint8_t *src_in;
    uint64_t in_len;
    struct aura_hpack_decoder *dec = &c->core.dec;
    int rv, err_idx, soft_err;
    bool final;

    app_debug(true, 0, ">>>> a_srv_process_cont");
    stream = aura_h2_conn_find_stream(&c->core, in_frame->frame.stream_id);
    A_BUG_ON_2(!stream, true);

    if (in_frame->frame.flags & A_H2_FRAME_FLAG_END_HEADERS) {
        stream->flags |= (A_H2_STREAM_FLAG_HDRS_RECD);
        aura_h2_conn_transition_state(&c->state, A_H2_CONN_STATE_FRAMES);
        final = true;
        if (stream->flags & A_H2_STREAM_FLAG_END_STREAM)
            stream->flags |= A_H2_STREAM_FLAG_EXECUTE;
    }

    rv = aura_h2_parse_frame_payload(in_frame);
    if (rv != A_H2_ERR_NONE) {
        err_idx = A_H2_ERR_STR_IDX_INVALID_ARG;
        goto terminate_conn;
    }

    in_len = in_frame->cont_payload.len;
    src_in = in_frame->cont_payload.src;
    rv = a_h2_srv_parse_header_payload(&c->core, mc, stream, src_in, in_len, &err_idx);
    if (rv != A_H2_ERR_NONE) {
        if (rv == A_H2_IN_PROGRESS_ERR)
            return rv;

        err_idx = A_H2_ERR_STR_IDX_INVALID_ARG;
        goto terminate_conn;
    }

    return aura_h2_srv_process_request(c, in_frame->frame.stream_id);

terminate_conn:
    return a_h2_srv_close_conn_immediate(c, rv, err_idx);
}

/**/
static int a_srv_process_header(struct aura_h2_server_conn *c, struct aura_h2_in_frame *in_frame,
                                struct aura_mem_ctx *mc) {
    struct aura_h2_stream *stream = NULL;
    struct aura_h2_frame *frame = &in_frame->frame;
    int rv, err_str_idx;

    rv = aura_h2_parse_frame_payload(in_frame);
    if (rv != A_H2_ERR_NONE) {
        err_str_idx = A_H2_ERR_STR_IDX_INVALID_ARG;
        goto terminate_conn;
    }

    if (aura_h2_stream_is_push_stream(frame->stream_id)) {
        rv = A_H2_PROTOCOL_ERR;
        err_str_idx = A_H2_ERR_STR_IDX_INVALID_ARG;
        goto terminate_conn;
    }

    rv = a_srv_pre_headers_processing(c, in_frame, &stream, mc, &err_str_idx);
    if (rv != A_H2_ERR_NONE)
        goto terminate_conn;

    /* zero size header frame */
    if (in_frame->hdrs_payload.len == 0)
        aura_h2_sen_update(&c->core.sen, A_H2_SEN_EVT_EMPTY_HDR_ONLY_STREAM, 0);

    if (stream->state == A_H2_STREAM_STATE_HALF_CLOSED_REMOTE && stream->flags & A_H2_STREAM_FLAG_READ_TRAILER) {
        rv = a_handle_trailing_headers();
    } else {
        rv = a_h2_srv_process_headers_early_bailout(
          &c->core,
          stream,
          mc,
          in_frame->hdrs_payload.src,
          in_frame->hdrs_payload.len,
          &err_str_idx);
    }

    if (rv != A_H2_ERR_NONE) {
        if (rv == A_H2_IN_PROGRESS_ERR)
            return rv;

        goto terminate_conn;
    }

    /* Because 'a_srv_headers_cb' can delete a stream, pass the stream id to the process function */
    return aura_h2_srv_process_request(c, frame->stream_id);

terminate_conn:
    return a_h2_srv_close_conn_immediate(c, rv, err_str_idx);
}

/**
 *
 */
static int a_srv_process_data(struct aura_h2_server_conn *c, struct aura_h2_in_frame *in_frame,
                              struct aura_mem_ctx *mc) {
    struct aura_h2_data_payload *payload;
    struct aura_h2_closed_stream_ent *closed_stream_entry;
    struct aura_h2_stream *stream;
    struct aura_sliding_buf *buf;
    bool process = false;
    int rv, err_idx;

    if (aura_h2_srv_conn_stream_state_violation(&c->core, in_frame->frame.stream_id)) {
        rv = A_H2_PROTOCOL_ERR;
        err_idx = A_H2_ERR_STR_IDX_INVALID_ARG;
        goto exception;
    }

    stream = aura_h2_conn_find_stream(&c->core, in_frame->frame.stream_id);
    if (!stream) {
        closed_stream_entry = aura_h2_conn_closed_stream_rb_get(&c->core, in_frame->frame.stream_id);
        if (!closed_stream_entry) {
            /* stream closed for long, penalize */
            aura_h2_sen_update(&c->core.sen, A_H2_SEN_EVT_STALE, 0);
            if (aura_h2_conn_should_send_wind_update(&c->core)) {
                rv = aura_h2_conn_enqueue_wind_update(&c->core, 0, c->core.bytes_since_wind_update);
                if (rv != A_H2_ERR_NONE)
                    return rv;
            }
        }

        /* Protocol error */
        if (closed_stream_entry->shutdown_flag & A_H2_STREAM_SHUTDOWN_FLAG_RST_RECD) {
            rv = A_H2_PROTOCOL_ERR;
            err_idx = A_H2_ERR_STR_IDX_INVALID_ARG;
            goto exception;
        }

        if (aura_h2_conn_should_send_wind_update(&c->core)) {
            rv = aura_h2_conn_enqueue_wind_update(&c->core, 0, c->core.bytes_since_wind_update);
            if (rv != A_H2_ERR_NONE)
                return rv;
        }

        /* ignore and update glitch counter */
        return A_H2_ERR_NONE;
    }

    if (aura_h2_stream_can_recv_data(stream)) {
        aura_h2_conn_close_stream(&c->core, stream, A_H2_STREAM_CLOSED_ERR, true);
        return A_H2_ERR_NONE;
    }

    /* Extract DATA payload */
    rv = aura_h2_parse_frame_payload(in_frame);
    if (rv != A_H2_ERR_NONE) {
        err_idx = A_H2_ERR_STR_IDX_INVALID_ARG;
        goto exception;
    }

    /* Empty DATA frame */
    if (!aura_h2_frame_is_end_stream(in_frame->frame.flags) && payload->len == 0) {
        aura_h2_sen_update(&c->core.sen, A_H2_SEN_EVT_EMPTY_HDR_ONLY_STREAM, 0);
        return A_H2_ERR_NONE;
    }

    stream->received_len += payload->len;
    if (stream->received_len > A_H2_MAX_DEFAULT_DATA_SZ) {
        aura_h2_conn_close_stream(&c->core, stream, A_H2_REFUSED_STREAM_ERR, true);
        return A_H2_ERR_NONE;
    }

    /* Fast path: single data frame with end stream */
    if (aura_h2_frame_is_end_stream(in_frame->frame.flags) && aura_list_is_empty(&stream->data_list)) {
        buf = aura_sliding_buf_create(mc, payload->len, A_SLIDING_BUF_FL_FIXED);
        if (!buf) {
            rv = A_H2_INTERNAL_ERR;
            err_idx = A_H2_ERR_STR_IDX_INTERNAL_ERROR;
            goto exception;
        }

        aura_list_add_tail(&stream->data_list, &buf->allocated.link);
        if (aura_sliding_buf_append(buf, payload->data, payload->len) < 0) {
            rv = A_H2_INTERNAL_ERR;
            err_idx = A_H2_ERR_STR_IDX_INTERNAL_ERROR;
            goto exception;
        }

        stream->req.body = aura_sliding_buf_read_ptr(buf);
        stream->req.content_length = aura_sliding_buf_read_len(buf);
        process = true;
    } else {
        uint8_t *src = (uint8_t *)payload->data;
        size_t chunk, remaining = payload->len;

        /**
         * Create a fresh buffer or
         * Get the last buffer in the chain,
         * Fill it up and create next entry if
         * it can't hold all the data
         */
        if (aura_list_is_empty(&stream->data_list)) {
            buf = aura_sliding_buf_create(mc, A_H2_SRV_DATA_BUF_SZ, A_SLIDING_BUF_FL_FIXED);
            aura_list_add_tail(&stream->data_list, &buf->allocated.link);
        } else
            buf = a_list_last_entry(&stream->data_list, struct aura_sliding_buf, allocated.link);

        while (remaining > 0) {
            if (aura_sliding_buf_is_full(buf)) {
                buf = aura_sliding_buf_create(mc, A_H2_SRV_DATA_BUF_SZ, A_SLIDING_BUF_FL_FIXED);
                if (!buf) {
                    rv = A_H2_INTERNAL_ERR;
                    err_idx = A_H2_ERR_STR_IDX_INTERNAL_ERROR;
                    goto exception;
                }
                aura_list_add_tail(&stream->data_list, &buf->allocated.link);
            }

            chunk = a_min(aura_sliding_buf_write_len(buf), remaining);
            /* This will succeed since we are not copying beyond buffer */
            aura_sliding_buf_append(buf, src, chunk);
            remaining -= chunk;
            src += chunk;
        }

        /* Flatten the collected data */
        if (aura_h2_frame_is_end_stream(in_frame->frame.flags)) {
            struct aura_sliding_buf *final_buf;

            final_buf = aura_sliding_buf_create(mc, stream->received_len, A_SLIDING_BUF_FL_FIXED);
            if (!final_buf) {
                rv = A_H2_INTERNAL_ERR;
                err_idx = A_H2_ERR_STR_IDX_INTERNAL_ERROR;
                goto exception;
            }

            while (!aura_list_is_empty(&stream->data_list)) {
                a_list_dequeue(buf, &stream->data_list, allocated.link);
                aura_sliding_buf_append(final_buf, aura_sliding_buf_read_ptr(buf), aura_sliding_buf_read_len(buf));
                aura_sliding_buf_destroy(buf);
            }

            /* Make the final buffer the only entry in the data list */
            stream->req.body = aura_sliding_buf_read_ptr(final_buf);
            stream->req.content_length = aura_sliding_buf_read_len(final_buf);
            process = true;
        }
    }

    if (process) {
        return aura_h2_srv_process_request(c, stream->stream_id);
    } else
        return A_H2_ERR_NONE;

exception:
    return a_h2_srv_close_conn_immediate(c, rv, err_idx);
}

/* Deprecated priority */
static int a_srv_process_prio(struct aura_h2_server_conn *c, struct aura_h2_in_frame *in_frame,
                              struct aura_mem_ctx *mc) {
    int rv;
    rv = aura_h2_parse_frame_payload(in_frame);
    if (rv != A_H2_ERR_NONE) {
        /* @todo: connection error */
        return rv;
    }

    /* deprecated, penalize */
    /** @todo: probably define DEPRECATED PRIO SEN EVT(may not be needed) */
    aura_h2_sen_update(&c->core.sen, A_H2_SEN_EVT_STALE, 0);
    return rv;
}

static int a_srv_process_rst(struct aura_h2_server_conn *c, struct aura_h2_in_frame *in_frame,
                             struct aura_mem_ctx *mc) {
    aura_h2_sen_update(&c->core.sen, A_H2_SEN_EVT_RST, 0);
    return aura_h2_conn_process_rst_stream(&c->core, in_frame, true);
}

static int a_srv_process_settings(struct aura_h2_server_conn *c, struct aura_h2_in_frame *in_frame,
                                  struct aura_mem_ctx *mc) {
    int rv, err_str_idx;
    aura_h2_sen_update(&c->core.sen, A_H2_SEN_EVT_SETTINGS_FLOOD, 0);
    app_debug(true, 0, ">>>> a_srv_process_settings");

    rv = aura_h2_conn_process_settings(&c->core, in_frame, true, &err_str_idx);
    if (rv != A_H2_ERR_NONE)
        return a_h2_srv_close_conn_immediate(c, rv, err_str_idx);

    if (c->state == A_H2_CONN_STATE_PREFACE_SETTINGS) {
        rv = a_setup_server_preface(&c->core, &err_str_idx);
        if (rv != A_H2_ERR_NONE)
            return a_h2_srv_close_conn_immediate(c, rv, err_str_idx);

        aura_h2_conn_transition_state(&c->state, A_H2_CONN_STATE_FRAMES);

        /**
         *
         */
        struct aura_conn *conn = aura_container_of(c, struct aura_conn, h2_server);
        aura_conn_transition_state(conn, A_CONN_STATE_ACTIVE);
    }

    return rv;
}

static int a_srv_process_ping(struct aura_h2_server_conn *c, struct aura_h2_in_frame *in_frame,
                              struct aura_mem_ctx *mc) {
    aura_h2_sen_update(&c->core.sen, A_H2_SEN_EVT_PING_FLOOD, 0);
    return aura_h2_conn_process_ping(&c->core, in_frame);
}

static int a_srv_process_goaway(struct aura_h2_server_conn *c, struct aura_h2_in_frame *in_frame,
                                struct aura_mem_ctx *mc) {
    return aura_h2_conn_process_goaway(&c->core, in_frame, true);
}

static int a_srv_process_window_update(struct aura_h2_server_conn *c, struct aura_h2_in_frame *in_frame,
                                       struct aura_mem_ctx *mc) {
    aura_h2_sen_update(&c->core.sen, A_H2_SEN_EVT_WIND_UPDATE_FLOOD, 0);
    return aura_h2_conn_process_wind_update(&c->core, in_frame, true);
}

static int a_srv_process_update_priority(struct aura_h2_server_conn *c, struct aura_h2_in_frame *in_frame,
                                         struct aura_mem_ctx *mc) {
    struct aura_h2_stream *stream;
    struct aura_pri_ext prio_ext;
    struct aura_h2_prio_update_payload *payload = &in_frame->prio_update_payload;
    struct aura_h2_closed_stream_ent *close_stream_ent;
    int rv;

    rv = aura_h2_parse_frame_payload(in_frame);
    if (rv != A_H2_ERR_NONE)
        return a_h2_srv_close_conn_immediate(c, rv, A_H2_ERR_STR_IDX_INVALID_ARG);

    stream = aura_h2_conn_find_stream(&c->core, payload->stream_id);
    if (!stream) {
        close_stream_ent = aura_h2_conn_closed_stream_rb_get(&c->core, payload->stream_id);
        if (!close_stream_ent) {
            /* stream closed for long, penalize */
            aura_h2_sen_update(&c->core.sen, A_H2_SEN_EVT_STALE, 0);
        }
    }

    if (aura_h2_stream_can_process_prioity_update(stream)) {
        if (aura_h2_parse_http_prio(&prio_ext, in_frame->prio_update_payload.prio, in_frame->prio_update_payload.len) < 0) {
            stream->flags |= A_H2_STREAM_FLAG_BAD_PRIO;
            return A_H2_ERR_NONE;
        }

        aura_h2_update_stream_priority(&c->core, stream, &prio_ext);
    }

    return A_H2_ERR_NONE;
}

int aura_h2_srv_process_frame(struct aura_h2_server_conn *c, struct aura_sliding_buf *buf) {
    struct aura_h2_in_frame *in_frame = &c->core.in_frame;
    struct aura_conn *conn = aura_container_of(c, struct aura_conn, h2_server);
    uint8_t *src;
    uint32_t len;
    int rv, sentinel_action;

    app_debug(true, 0, ">>>> aura_h2_srv_process_frame");
    static int (*frame_handlers[])(struct aura_h2_server_conn *c, struct aura_h2_in_frame *buf, struct aura_mem_ctx *mc) = {
      [A_H2_FRAME_TYPE_DATA] = a_srv_process_data,
      [A_H2_FRAME_TYPE_HDRS] = a_srv_process_header,
      [A_H2_FRAME_TYPE_PRIO] = a_srv_process_prio,
      [A_H2_FRAME_TYPE_RST] = a_srv_process_rst,
      [A_H2_FRAME_TYPE_SETTINGS] = a_srv_process_settings,
      [A_H2_FRAME_TYPE_PUSH_PROMISE] = a_srv_process_push_promise,
      [A_H2_FRAME_TYPE_PING] = a_srv_process_ping,
      [A_H2_FRAME_TYPE_GOAWAY] = a_srv_process_goaway,
      [A_H2_FRAME_TYPE_WIND_UPDATE] = a_srv_process_window_update,
      [A_H2_FRAME_TYPE_CONT] = a_srv_process_cont,
      [A_H2_FRAME_TYPE_PRIO_UPDATE] = a_srv_process_update_priority,
    };

    len = aura_sliding_buf_read_len(buf);
    src = aura_sliding_buf_read_ptr(buf);

    if (!in_frame->frame_hdr_read) {
        rv = aura_h2_parse_frame_header(in_frame, src, len, c->core.peer_settings.max_frame_size);
        if (rv != A_H2_ERR_NONE) {
            /**
             * only setup goaway for established connections,
             * otherwise for very early errors, simply close
             * the connection
             */
            if (rv == A_H2_FRAME_SIZE_ERR && aura_conn_is_established(conn)) {
                rv = a_h2_srv_close_conn_immediate(c, rv, A_H2_ERR_STR_IDX_INVALID_ARG);
            }

            return aura_h2_get_app_error(rv);
        }
    }

    aura_h2_frame_dump(&in_frame->frame);

    if (aura_h2_frame_is_complete(in_frame, len)) {
        /**
         * Special handling First settings
         * We expect a settings frame
         */
        if (c->state == A_H2_CONN_STATE_PREFACE_SETTINGS && in_frame->frame.type != A_H2_FRAME_TYPE_SETTINGS) {
            rv = a_h2_srv_close_conn_immediate(c, A_H2_PROTOCOL_ERR, A_H2_ERR_STR_IDX_INVALID_ARG);
            aura_sliding_buf_consume(buf, in_frame->expected_bytes);
            return aura_h2_get_app_error(rv);
        }

        /**
         * Special handling
         * We expect continuation frame
         * in strict sequence.
         */
        if (c->state == A_H2_CONN_STATE_CONT &&
            (in_frame->frame.type != A_H2_FRAME_TYPE_CONT ||
             c->core.cont_stream_id != in_frame->frame.stream_id)) {
            rv = a_h2_srv_close_conn_immediate(c, A_H2_PROTOCOL_ERR, A_H2_ERR_STR_IDX_INVALID_ARG);
            aura_sliding_buf_consume(buf, in_frame->expected_bytes);
            return aura_h2_get_app_error(rv);
        }

        if (in_frame->frame.type >= ARRAY_SIZE(frame_handlers)) {
            app_debug(true, 0, "Unknown frame type: %d", in_frame->frame.type);
            /* Consume and ignore unknown frame types */
            aura_sliding_buf_consume(buf, in_frame->expected_bytes);
            return rv;
        }

        rv = frame_handlers[in_frame->frame.type](c, in_frame, conn->mc);
        aura_sliding_buf_consume(buf, in_frame->expected_bytes);
        aura_h2_frame_reset_inframe(in_frame);

        /* Run sentinel */
        sentinel_action = aura_h2_sen_evaluate(&c->core.sen);
        app_debug(true, 0, ">>> Sentinel action=%d", sentinel_action);
        switch (sentinel_action) {
        case A_CONN_SEN_ACT_THROTTLE:
            aura_conn_sentinel_update(conn, A_CONN_SEN_ACT_THROTTLE, (void *)a_time_s_to_ms(5));
            break;

        case A_CONN_SEN_ACT_HARD_CLOSE:
            aura_conn_sentinel_update(conn, A_CONN_SEN_ACT_HARD_CLOSE, NULL);
            break;

        default:
            break;
        }

        return aura_h2_get_app_error(rv);
    }

    return A_ERR_AGAIN;
}

int aura_h2_srv_process(struct aura_h2_server_conn *c, struct aura_sliding_buf *buf) {
    int rv = A_ERR_NONE;

    app_debug(true, 0, ">>>> aura_h2_srv_process");
    while (!aura_sliding_buf_is_empty(buf)) {
        app_debug(true, 0, "aura_h2_srv_processing len=%u", aura_sliding_buf_read_len(buf));
        switch (c->state) {
        case A_H2_CONN_STATE_PREFACE:
            rv = aura_h2_srv_process_preface(c, buf);
            break;

        case A_H2_CONN_STATE_PREFACE_SETTINGS:
        case A_H2_CONN_STATE_FRAMES:
        case A_H2_CONN_STATE_CONT:
            rv = aura_h2_srv_process_frame(c, buf);
            break;

        default:
            rv = A_H2_PROTOCOL_ERR;
            break;
        }

        switch (rv) {
        case A_ERR_FATAL:
            return rv;

        case A_ERR_AGAIN:
        case A_ERR_NONE:
        default:
            break;
        }
    }

    return rv;
}
