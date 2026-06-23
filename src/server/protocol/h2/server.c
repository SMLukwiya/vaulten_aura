#include "h2/server.h"
#include "bug_lib.h"
#include "connection.h"
#include "error_lib.h"
#include "h2/hpack.h"
#include "h2/scheduler.h"
#include "h2/sentinel.h"
#include "header_srv.h"
#include "route_srv.h"
#include "runtime/js.h"
#include "server_srv.h"
#include "slab.h"
#include "socket_srv.h"
#include "string_lib.h"
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

    stream_desc = aura_h2_conn_stream_desc_get(s_iov->h2_c, s_iov->stream_desc_idx);
    wind_sz = aura_h2_stream_desc_can_proceed(stream_desc, s_iov->stream_id);
    if (wind_sz > 0)
        s_iov->allowed_len = wind_sz;

    return wind_sz > 0;
}

/**
 * Trigger write to the parent connection fd
 */
static int inline a_h2_srv_trigger_flush(struct aura_h2_core *h2_c, struct aura_sliding_buf *buf) {
    struct aura_h2_server_conn *c;
    struct aura_conn *p_conn;
    uint8_t *read_ptr;
    size_t read_len;
    ssize_t bytes_written;

    read_ptr = aura_sliding_buf_read_ptr(buf);
    read_len = aura_sliding_buf_read_len(buf);
    if (read_len > 0) {
        c = aura_container_of(h2_c, struct aura_h2_server_conn, core);
        p_conn = c->conn;
        bytes_written = p_conn->ops->on_write(read_ptr, read_len);
        if (bytes_written != read_len) {
            if (bytes_written > 0)
                aura_sliding_buf_consume(buf, bytes_written);

            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return A_FQ_STALLED;

            return A_FQ_FATAL;
        }

        aura_sliding_buf_consume(buf, bytes_written);
    }

    return A_FQ_OK;
}

/**
 * Encrypt enqueued frames for wrire transmission
 */
static int aura_h2_srv_encrypt(void *payload) {
    struct aura_h2_sched_iov *s_iov = payload;
    struct aura_h2_server_conn *c;
    struct aura_tls_ctx *tls_ctx;
    bool is_secure, end_stream;
    size_t len, tls_len, remaining;
    ssize_t rv;

    c = aura_container_of(s_iov->h2_c, struct aura_h2_server_conn, core);
    tls_ctx = &c->conn->tls_ctx;

    if (c->conn->is_secure) {
        end_stream = s_iov->end_stream && (s_iov->data_len == s_iov->allowed_len);
        len = a_min(s_iov->data_len, s_iov->allowed_len);

    again:
        rv = aura_tls_encode(tls_ctx, s_iov->data, len, s_iov->type, s_iov->stream_id, end_stream);
        if (rv < 0) {
            aura_h2_sched_iov_destroy(s_iov);
            return A_FQ_FATAL;
        }

        /* Trigger flush */
        if (rv == 0) {
            if ((rv = a_h2_srv_trigger_flush(s_iov->h2_c, &tls_ctx->encrypted_write_buf)) != A_FQ_OK)
                return rv;

            /**
             * If frame could not proceed because
             * the TLS buffer was full, try again
             */
            goto again;
        }

        aura_sliding_buf_consume(s_iov->buf, rv);
        if (s_iov->data_len == rv) {
            aura_h2_sched_iov_destroy(s_iov);
            aura_h2_conn_after_frame_sent(s_iov->h2_c, s_iov->stream_id, s_iov->type, len, end_stream);

            return A_FQ_RELEASED;
        } else {
            s_iov->data_len -= rv;
            s_iov->data += rv;

            /**
             * If everything was flushed and
             * If only part of the data was sent,
             * flush and continue encoding the remaining parts
             */
            len -= rv;
            if (len > 0) {
                /* Bytes were sliced, trigger flush  */
                if ((rv = a_h2_srv_trigger_flush(s_iov->h2_c, &tls_ctx->encrypted_write_buf)) != A_FQ_OK)
                    return rv;

                goto again;
            }

            return A_FQ_OK;
        }
    } else {
    }

    return A_FQ_OK;
}

/**
 * Trigger write at the end of encryption,
 * after the flight queue has visited all
 * entries
 */
static int aura_h2_srv_write_complete(void *payload) {
    struct aura_h2_sched_iov *s_iov = payload;
    struct aura_h2_server_conn *c;
    struct aura_tls_ctx *tls_ctx;

    c = aura_container_of(s_iov->h2_c, struct aura_h2_server_conn, core);
    tls_ctx = &c->conn->tls_ctx;

    return a_h2_srv_trigger_flush(s_iov->h2_c, &tls_ctx->encrypted_write_buf);
}

int aura_h2_srv_write(struct aura_h2_server_conn *c) {
    struct aura_conn *p_conn;
    ssize_t tls_bytes_written, encrypted_written;
    uint8_t *read_ptr;
    size_t read_len;
    struct aura_h2_send_iov *send_iov;
    int rv;

    p_conn = c->conn;
    rv = aura_h2_schedule(&c->core);

    rv = aura_flight_queue_flush(&c->core.fq, aura_h2_srv_can_transmit, aura_h2_srv_encrypt, aura_h2_srv_write_complete);
    switch (rv) {
    case A_FQ_STALLED:
        int r;
        if (aura_evt_loop_modify(p_conn->srv_ctx->evt_loop, p_conn->sock.sock_fd, p_conn, AURA_EVENT_READ | AURA_EVENT_WRITE) < 0) {
            aura_list_move(&p_conn->srv_ctx->queues.reap, &p_conn->c_list);
            rv = A_H2_IN_PROGRESS_ERR;
        }
        break;

    case A_FQ_FATAL:
        /* Move to closing queue */
        aura_list_move(&p_conn->srv_ctx->queues.reap, &p_conn->c_list);
        rv = A_H2_INTERNAL_ERR;
        break;

    case A_FQ_OK:
        break;
    }

    /** @todo: get h2 error representation */
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

/**
 * Prepare error response for submitting on the wire
 * and call the underlying callback to send the data
 */
int aura_h2_submit_error_response(struct aura_h2_core *h2_c, struct aura_h2_stream *stream, int status) {
    struct aura_hpack_static_table_entry *entry;
    struct aura_http_res res;

    // return aura_submit_response(h2_c, stream, true);
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

static int a_setup_server_preface(struct aura_h2_core *h2_c) {
    uint32_t settings_len, wind_len, total_len; /* Frame length */
    uint8_t *out_data, *frame;
    uint32_t initial_window_size;
    const struct aura_iovec *reason;
    struct aura_h2_sched_iov *s_iov;
    int error;

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
        error = A_H2_INTERNAL_ERR;
        reason = &aura_h2_err_string[A_H2_ERR_STR_IDX_INTERNAL_ERROR];
        goto goaway;
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
        error = A_H2_INTERNAL_ERR;
        reason = &aura_h2_err_string[A_H2_ERR_STR_IDX_INTERNAL_ERROR];
        goto goaway;
    }

    s_iov = aura_h2_get_sched_iov(&h2_c->scheduler, A_H2_SCHED_CONTROL);
    if (!s_iov) {
        /* @todo: close connection */
    }

    s_iov->type = A_H2_SCHED_CONTROL;
    s_iov->data = frame;
    s_iov->data_len = settings_len + wind_len;
    s_iov->buf = &h2_c->scheduler.write_buf;
    s_iov->stream_id = 0;
    s_iov->end_stream = false;
    aura_h2_sched_accum_bytes(&h2_c->scheduler, s_iov);

    return A_H2_ERR_NONE;

goaway:
    aura_h2_conn_enqueue_goaway(h2_c, h2_c->local_goaway_stream_id, error, reason);
    return error;
}

/**
 * Handle server connection preface
 */
int aura_h2_srv_process_preface(struct aura_h2_server_conn *c, struct aura_sliding_buf *plain_buf) {
    int res, len;
    uint8_t *src;

    src = aura_sliding_buf_read_ptr(plain_buf);
    len = aura_sliding_buf_read_len(plain_buf);

    if (len < aura_h2_conn_preface.len)
        return A_H2_FRAME_INCOMPLETE;

    if (memcmp(aura_h2_conn_preface.base, src, aura_h2_conn_preface.len) != 0)
        return A_H2_PROTOCOL_ERR;

    aura_sliding_buf_consume(plain_buf, aura_h2_conn_preface.len);
    // encode origin if present
    aura_h2_conn_transition_state(&c->state, A_H2_CONN_STATE_PREFACE_SETTINGS);
    // aura_h2_conn_transition_state_handler(c->state_handler, a_srv_process_preface_settings);

    return A_H2_ERR_NONE;
}

static int a_srv_process_preface_settings(struct aura_h2_server_conn *c, struct aura_sliding_buf *plain_buf) {
    struct aura_h2_in_frame *in_frame = &c->core.in_frame;
    int rv, len, frame_len;
    uint8_t *src;

    src = aura_sliding_buf_read_ptr(plain_buf);
    len = aura_sliding_buf_read_len(plain_buf);
    rv = aura_h2_parse_frame_header(in_frame, src, len, c->core.local_settings.max_frame_size);
    if (rv != A_H2_ERR_NONE)
        return rv;

    if (in_frame->frame.type != A_H2_FRAME_TYPE_SETTINGS)
        return A_H2_PROTOCOL_ERR;

    frame_len = A_H2_FRAME_HEADER_SIZE + in_frame->frame.len;
    rv = aura_h2_conn_process_settings(&c->core, in_frame, true);
    aura_sliding_buf_consume(plain_buf, frame_len);
    if (rv != A_H2_ERR_NONE)
        return rv;

    rv = a_setup_server_preface(&c->core);
    if (rv != A_H2_ERR_NONE)
        return rv;

    aura_h2_conn_transition_state(&c->state, A_H2_CONN_STATE_FRAMES);
    // aura_h2_conn_transition_state_handler(c->state_handler, aura_h2_srv_process_frame);

    return rv;
}

/**
 *
 */
static int a_srv_process_push_promise(struct aura_h2_server_conn *c, struct aura_h2_in_frame *in_frame) {
    return aura_h2_conn_enqueue_goaway(
      &c->core,
      c->core.local_goaway_stream_id,
      A_H2_PROTOCOL_ERR,
      &aura_h2_err_string[A_H2_ERR_STR_IDX_INVALID_ARG]);
}

/**
 * Returns true if provided method is valid,
 * otherwise false
 */
a_http_method_t a_is_header_method_valid(const char *method) {
    if (strcasecmp(method, "GET") == 0)
        return HTTP_GET;

    if (strcasecmp(method, "POST") == 0)
        return HTTP_POST;

    if (strcasecmp(method, "PUT") == 0)
        return HTTP_PUT;

    if (strcasecmp(method, "HEAD") == 0)
        return HTTP_HEAD;

    /** @todo: add others */

    return HTTP_NONE;
}

/**
 * Returns 0 if the parsed authority is among list
 * of allowed authority for a given server, otherwise err;
 */
static inline int a_header_authority_cb(struct aura_h2_core *h2_c, struct aura_h2_stream *stream,
                                        const char *name, size_t name_len, const char *value,
                                        size_t value_len) {
    app_debug(true, 0, "a_header_authority_cb <<<< value: %s", value);

    struct aura_h2_server_conn *c = aura_container_of(h2_c, struct aura_h2_server_conn, core);
    stream->req.authority.host.base = aura_strndup(c->conn->mc, value, value_len);
    return A_HPACK_OK;
}

/**
 * Return 0 if the parsed method is valid and
 * supported by server, otherwise -1;
 */
static inline int a_header_method_cb(struct aura_h2_core *h2_c, struct aura_h2_stream *stream,
                                     const char *name, size_t name_len, const char *value,
                                     size_t val_len) {
    uint64_t content_len;
    a_http_method_t method;

    app_debug(true, 0, "a_header_method_cb <<<< value: %s", value);
    if (strcmp(value, "CONNECT") == 0 || strcmp(value, "TRACE") == 0) {
        /* unsupported methods */
        return A_HPACK_UNSUPPORTED_METHOD_ERR;
    }

    method = a_is_header_method_valid(value);
    if (method == HTTP_NONE)
        return A_HPACK_INVALID_METHOD_ERR;

    stream->req.method = method;
    return A_HPACK_OK;
}

/**
 * Get and attach host config associated with parsed
 * path, validate that path is supported by hosts,
 * return 0 if satisfied, otherwise err
 */

static inline int a_header_path_cb(struct aura_h2_core *h2_c, struct aura_h2_stream *stream,
                                   const char *name, size_t name_len, const char *val, size_t v_len) {
    struct aura_srv_host_conf *host;
    struct aura_route *route;
    struct aura_h2_server_conn *c;

    c = aura_container_of(h2_c, struct aura_h2_server_conn, core);
    host = c->conn->host;
    A_BUG_ON_2(!host, true);
    app_debug(true, 0, "a_header_path_cb <<<< val=%s", val);

    /* validate if requested route/fn exists */
    route = aura_route_match(&host->router, val, v_len, stream->req.method);
    if (!route) {
        /* 404 */
        return A_HPACK_INVALID_PATH_ERR;
    }
    stream->req.path.base = aura_strndup(c->conn->mc, val, v_len);

    /* set route so we don't have to search again */
    c->conn->route = route;
    return A_HPACK_OK;
}

static a_http_scheme_t a_http_get_scheme(const char *scheme, size_t len) {
    if (strncasecmp(scheme, "HTTP", len) == 0)
        return SCHEME_HTTP;
    else if (strncasecmp(scheme, "HTTPS", len) == 0)
        return SCHEME_HTTPS;
    else
        return SCHEME_NONE;
}

/**
 * Returns 0 if parsed scheme is valid and
 * supported, otherwise err
 */
static inline int a_header_scheme_cb(struct aura_h2_core *h2_conn, struct aura_h2_stream *stream,
                                     const char *name, size_t name_len, const char *value, size_t val_len) {
    /**/
    app_debug(true, 0, "a_header_scheme_cb <<<<: %s", value);
    stream->req.scheme = a_http_get_scheme(value, val_len);
    if (stream->req.scheme == SCHEME_NONE)
        return A_HPACK_INVALID_SCHEME_ERR;
    return A_HPACK_OK;
}

/**
 * Returns 0 if parsed status is valid number,
 * otherwise return err;
 */
static inline int a_header_status_cb(struct aura_h2_core *h2_conn, struct aura_h2_stream *stream,
                                     const char *name, size_t name_len, const char *value, size_t val_len) {
    int status;
    char *c;

    if (stream->res.status_code != 0)
        return A_HPACK_DUPLICATE_STATUS_ERR;

    /* parse */
    if (val_len != 3) {
        return A_HPACK_INVALID_STATUS_ERR;
    }

    c = (char *)value;
#define PARSE_DIGIT(mul, min_digit)               \
    do {                                          \
        if (*c < '0' + (min_digit) || '9' < *c) { \
            return A_HPACK_INVALID_STATUS_ERR;    \
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
static inline int a_header_content_len_cb(struct aura_h2_core *h2_conn, struct aura_h2_stream *stream,
                                          const char *name, size_t name_len, const char *value, size_t val_len) {

    return A_HPACK_OK;
}

/**
 * P
 */
static int aura_h2_srv_process_request(struct aura_h2_server_conn *c, struct aura_h2_stream *stream) {
    struct aura_route *route;
    struct aura_work_queue *wq;
    struct aura_task *task;
    Request *req;
    Response *resp;
    int rv;

    if (stream->state == A_H2_STREAM_STATE_HALF_CLOSED_REMOTE) {
        /* forward to route handler/path handler */
        route = c->conn->route;
        A_BUG_ON_2(!route, true);

        /* Create task */
        task = aura_task_create(
          stream,
          c->conn->mc,
          c->conn->route->url,
          c->conn->srv_ctx->next_task_id++,
          c->conn->conn_id,
          c->conn->conn_tab_idx,
          A_TASK_PROTOCOL_H2);
        if (!task)
            return A_H2_INTERNAL_ERR;

        rv = aura_work_queue_add(route->wq, route->fn, task);
        if (rv) {
            aura_rt_req_destroy(req);
            aura_free(task);
            return A_H2_INTERNAL_ERR;
        }

        stream->flags |= A_H2_STREAM_FLAG_EXECUTE;
    }

    return A_H2_ERR_NONE;
}

/** */
int a_srv_begin_headers(struct aura_h2_server_conn *c, struct aura_h2_in_frame *in_frame,
                        struct aura_h2_stream **stream) {
    const struct aura_iovec *reason;
    struct aura_h2_sched_iov *s_iov;
    struct aura_h2_frame *frame = &in_frame->frame;
    struct aura_mem_ctx *mc = c->conn->mc;
    bool is_stream_error;
    int rv, err;

    if (aura_h2_conn_peer_stream_id_new(&c->core, frame->stream_id, true)) {
        if (aura_h2_stream_is_even_numbered(frame->stream_id)) {
            err = A_H2_PROTOCOL_ERR;
            reason = &aura_h2_err_string[A_H2_ERR_STR_IDX_INVALID_ARG];
            goto goaway;
        }

        if (!aura_h2_srv_conn_new_streams_allowed(c)) {
            s_iov = aura_h2_get_sched_iov(&c->core.scheduler, A_H2_SCHED_URGENT);
            if (!s_iov) {
                /* @todo: close connection */
            }
            if (aura_h2_conn_enqueue_rst_frame(&c->core, frame->stream_id, A_H2_REFUSED_STREAM_ERR) < 0) {
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

        if (!*stream) {
            err = A_H2_INTERNAL_ERR;
            reason = &aura_h2_err_string[A_H2_ERR_STR_IDX_INTERNAL_ERROR];
            goto goaway;
        }

        (*stream)->received_headers += in_frame->hdrs_payload.len;
        if (aura_h2_frame_is_end_stream(frame->flags) && aura_h2_frame_is_end_headers(frame->flags)) {
            /* prepare response */
            (*stream)->state = A_H2_STREAM_STATE_HALF_CLOSED_REMOTE;
            (*stream)->flags |= A_H2_STREAM_FLAG_HDRS_RECD;
        } else if (aura_h2_frame_is_end_headers(frame->flags)) {
            (*stream)->state = A_H2_STREAM_STATE_OPEN;
            (*stream)->flags |= (A_H2_STREAM_FLAG_READ_DATA | A_H2_STREAM_FLAG_HDRS_RECD);
        } else {
            aura_h2_sen_update(&c->core.sen, A_H2_SEN_EVT_TINY_FRAME_FLOOD, in_frame->hdrs_payload.len);
            (*stream)->flags |= A_H2_STREAM_FLAG_CONT;
        }

        aura_h2_conn_transition_state(&c->state, A_H2_CONN_STATE_FRAMES);
    } else {
        /** @todo: push promise not supported */
        *stream = aura_h2_conn_find_stream(&c->core, frame->stream_id);
        if (!(*stream)) {
            s_iov = aura_h2_get_sched_iov(&c->core.scheduler, A_H2_SCHED_URGENT);
            if (!s_iov) {
                /* @todo: close connection */
            }

            if (aura_h2_conn_enqueue_rst_frame(&c->core, frame->stream_id, A_H2_STREAM_CLOSED_ERR) < 0) {
                return A_H2_INTERNAL_ERR;
            }

            return A_H2_ERR_NONE;
        }

        /* trailer must contain end stream flag */
        if (!aura_h2_frame_is_end_stream(frame->flags) && (*stream)->flags) {
            err = A_H2_PROTOCOL_ERR;
            reason = &aura_h2_err_string[A_H2_ERR_STR_IDX_INVALID_ARG];
            goto goaway;
        }

        (*stream)->received_headers += in_frame->hdrs_payload.len;
        if (!aura_h2_stream_can_recv_hdrs(*stream)) {
            if ((*stream)->state == A_H2_STREAM_STATE_RESERVED_REMOTE) {
                rv = A_H2_PROTOCOL_ERR;
                reason = &aura_h2_err_string[A_H2_ERR_STR_IDX_INVALID_ARG];
                goto goaway;
            } else {
                if (aura_h2_conn_send_stream_error(&c->core, *stream, A_H2_STREAM_CLOSED_ERR, true) < 0)
                    return A_H2_INTERNAL_ERR;
            }
        }

        if (aura_h2_frame_is_end_headers(frame->flags)) {
            (*stream)->state = A_H2_STREAM_STATE_HALF_CLOSED_REMOTE;
        } else {
            aura_h2_sen_update(&c->core.sen, A_H2_SEN_EVT_TINY_FRAME_FLOOD, in_frame->hdrs_payload.len);
            (*stream)->flags |= A_H2_STREAM_FLAG_CONT;
        }
    }

    return A_H2_ERR_NONE;

goaway:
    aura_h2_conn_transition_state(&c->state, A_H2_CONN_STATE_CLOSING);
    aura_conn_transition_state(c->conn, A_CONN_STATE_CLOSING);
    aura_h2_conn_enqueue_goaway(&c->core, c->core.local_goaway_stream_id, err, reason);
    return err;
}

static int a_srv_process_headers_early_bailout(struct aura_h2_core *h2_c, struct aura_h2_stream *stream,
                                               struct aura_mem_ctx *mc, const uint8_t *src_in,
                                               size_t in_len) {
    struct aura_hpack_decoder *dec = &h2_c->dec;
    struct aura_header_field dec_hdr;
    const uint8_t *end = src_in + in_len, *name, *value;
    size_t n_len, v_len;
    bool final = stream->flags & A_H2_STREAM_FLAG_HDRS_RECD;
    ssize_t rv;
    int soft_err;

    while (true) {
        rv = aura_hpack_decode(dec, src_in, end, h2_c->intern_tab, &dec_hdr, final);
        if (rv < A_HPACK_OK) {
            if (aura_hpack_hdr_err_fatal(rv)) {
                /* Close connection */
                // aura_h2_conn_transition_state(h2_c, A_H2_CONN_STATE_CLOSING);
                // aura_conn_transition_state(h2_c->conn, A_CONN_STATE_CLOSING);
                aura_h2_conn_enqueue_goaway(
                  h2_c,
                  h2_c->local_goaway_stream_id,
                  rv,
                  &aura_h2_err_string[A_H2_ERR_STR_IDX_INVALID_ARG]);

                return rv;
            } else {
                /* Stream error */
            }
        }

        src_in += rv;

        if (dec->flags & A_HDR_FIELD_FLAG_EMIT) {
            name = dec_hdr.name->data;
            n_len = dec_hdr.name->len;
            if (dec_hdr.flags & A_HDR_FIELD_FLAG_VALUE_INTERNED) {
                value = dec_hdr.value.interned->data;
                v_len = dec_hdr.value.interned->len;
            } else {
                value = dec_hdr.value.raw.str.base;
                v_len = dec_hdr.value.raw.str.len;
            }

            if (aura_hpack_is_pseudo_header(name)) {
                switch (dec_hdr.token) {
                case A_TOKEN_METHOD:
                    /* Duplicate */
                    if (dec->pseudo_flags & A_H2_PSEUDO_HDR_METHOD) {
                        aura_hpack_set_decoder_soft_err(dec, A_HPACK_DUPLICATE_METHOD_ERR);
                        break;
                    }

                    dec->pseudo_flags |= A_H2_PSEUDO_HDR_METHOD;
                    rv = a_header_method_cb(h2_c, stream, name, n_len, value, v_len);
                    aura_hpack_set_decoder_soft_err(dec, rv);
                    break;

                case A_TOKEN_SCHEME:
                    /* Duplicate */
                    if (dec->pseudo_flags & A_H2_PSEUDO_HDR_SCHEME) {
                        aura_hpack_set_decoder_soft_err(dec, A_HPACK_DUPLICATE_SCHEME_ERR);
                        break;
                    }

                    dec->pseudo_flags |= A_H2_PSEUDO_HDR_SCHEME;
                    rv = a_header_scheme_cb(h2_c, stream, name, n_len, value, v_len);
                    aura_hpack_set_decoder_soft_err(dec, rv);
                    break;

                case A_TOKEN_AUTHORITY:
                    /* Duplicate */
                    if (dec->pseudo_flags & A_H2_PSEUDO_HDR_AUTHORITY) {
                        aura_hpack_set_decoder_soft_err(dec, A_HPACK_DUPLICATE_AUTHORITY_ERR);
                        break;
                    }

                    dec->pseudo_flags |= A_H2_PSEUDO_HDR_AUTHORITY;
                    rv = a_header_authority_cb(h2_c, stream, name, n_len, value, v_len);
                    aura_hpack_set_decoder_soft_err(dec, rv);
                    break;

                case A_TOKEN_PATH:
                    /* Duplicate */
                    if (dec->pseudo_flags & A_H2_PSEUDO_HDR_PATH) {
                        aura_hpack_set_decoder_soft_err(dec, A_HPACK_DUPLICATE_PATH_ERR);
                        break;
                    }

                    dec->pseudo_flags |= A_H2_PSEUDO_HDR_PATH;
                    rv = a_header_path_cb(h2_c, stream, name, n_len, value, v_len);
                    aura_hpack_set_decoder_soft_err(dec, rv);
                    break;

                default:
                    /**/
                    aura_hpack_set_decoder_soft_err(dec, A_HPACK_INVALID_HDR_FIELD_ERR);
                    break;
                }

            } else {
                switch (dec_hdr.token) {
                case A_TOKEN_CONTENT_LENGTH:
                    rv = a_header_content_len_cb(h2_c, stream, name, n_len, value, v_len);
                    aura_hpack_set_decoder_soft_err(dec, rv);
                    break;

                case A_TOKEN_EXPECT:
                case A_TOKEN_PRIORITY:
                case A_TOKEN_ACCEPT:
                case A_TOKEN_ACCEPT_ENCODING:
                case A_TOKEN_USER_AGENT:
                    break;

                case A_TOKEN_HOST:
                    /* HTTP2 allows the use of host header (in place of :authority) */
                    if (dec->pseudo_flags & A_H2_PSEUDO_HDR_AUTHORITY)
                        break;

                    rv = a_header_authority_cb(h2_c, stream, name, n_len, value, v_len);
                    aura_hpack_set_decoder_soft_err(dec, rv);
                    break;

                case A_TOKEN_TE:
                    if (aura_lc_str_is_eq(value, v_len, str_lit("trailers"))) {
                        /**/
                    }
                    break;

                default:
                    /* rest of the header fields that are marked as special are rejected */
                    app_debug(true, 0, "hpack unknown special header: %s (ignore)", name);
                    aura_hpack_set_decoder_soft_err(dec, A_HPACK_INVALID_HDR_FIELD_ERR);
                    break;
                }
                /**
                 * If we encounter an error at any point, we are likely to destroy the stream,
                 * so no need to pass headers on stream request structure
                 */
                if (dec->soft_error == 0)
                    aura_add_header(mc, &stream->req.headers, &dec_hdr);
            }
        }

        if (dec->flags & A_HDR_FIELD_FLAG_FINAL) {
            /* end headers */
            soft_err = dec->soft_error;
            dec->state = A_HPACK_STATE_DECODE_START;
            dec->soft_error = 0;
            dec->err_state = false;
            break;
        }

        /**
         * Wait for more bytes
         */
        if (src_in == end) {
            return A_H2_ERR_NONE;
        }
    }

    /**
     * Validation
     * Missing required pseudo headers
     */
    if ((dec->pseudo_flags & A_H2_REQ_PSEUDO_HDRS) != A_H2_REQ_PSEUDO_HDRS) {
        /* Close connection */
        // aura_h2_conn_transition_state(h2_c, A_H2_CONN_STATE_CLOSING);
        // aura_conn_transition_state(h2_c->conn, A_CONN_STATE_CLOSING);
        aura_h2_conn_enqueue_goaway(
          h2_c,
          h2_c->local_goaway_stream_id,
          rv,
          &aura_h2_err_string[A_H2_ERR_STR_IDX_INVALID_ARG]);

        return A_ERR_NONE;
    }

    if (soft_err == 0) {
        // aura_conn_transition_state(h2_c->conn, A_CONN_STATE_PROCESS_REQ);
        return rv;
    }

    switch (soft_err) {
    case A_HPACK_INVALID_PATH_ERR:
        /* 404 */
        stream->res.status_code = 404;
        stream->res.content_length = SIZE_MAX;
        // return aura_submit_response(h2_c, stream, true);

    default:
        break;
    }

    return A_H2_ERR_NONE;
}

int a_srv_headers_cb(struct aura_h2_core *h2_c, struct aura_h2_stream *stream,
                     struct aura_mem_ctx *mc, const uint8_t *src, size_t len) {
    app_debug(true, 0, "a_srv_headers_cb <<<<");

    if (stream->state == A_H2_STREAM_STATE_HALF_CLOSED_REMOTE) {
        return a_handle_trailing_headers();
    } else {
        return a_srv_process_headers_early_bailout(h2_c, stream, mc, src, len);
    }
}

static int a_srv_process_cont(struct aura_h2_server_conn *c, struct aura_h2_in_frame *in_frame) {
    return aura_h2_conn_process_cont(&c->core, in_frame, true);
}

/**/
static int a_srv_process_header(struct aura_h2_server_conn *c, struct aura_h2_in_frame *in_frame) {
    struct aura_h2_stream *stream = NULL;
    struct aura_h2_frame *frame = &in_frame->frame;
    const struct aura_iovec *reason;
    struct aura_mem_ctx *mc = c->conn->mc;
    int rv;

    app_debug(true, 0, "a_srv_process_header <<<<");
    rv = aura_h2_parse_frame_payload(in_frame);
    if (rv < A_H2_ERR_NONE) {
        reason = &aura_h2_err_string[A_H2_ERR_STR_IDX_INVALID_ARG];
        goto goaway;
    }

    if (aura_h2_stream_is_push_stream(frame->stream_id)) {
        rv = A_H2_PROTOCOL_ERR;
        reason = &aura_h2_err_string[A_H2_ERR_STR_IDX_INVALID_ARG];
        goto goaway;
    }

    rv = a_srv_begin_headers(c, in_frame, &stream);
    if (rv != A_H2_ERR_NONE)
        return rv;

    if (stream->flags & A_H2_STREAM_FLAG_CONT) {
        /* Transition to expect cont */
        // aura_h2_conn_transition_state();
        // aura_h2_conn_transition_state_handler(c->state_handler, a_srv_process_cont);
    }

    /* zero size header frame */
    if (in_frame->hdrs_payload.len == 0)
        aura_h2_sen_update(&c->core.sen, A_H2_SEN_EVT_EMPTY_HDR_ONLY_STREAM, 0);

    rv = a_srv_headers_cb(&c->core, stream, mc, in_frame->hdrs_payload.src, in_frame->hdrs_payload.len);
    if (rv != A_H2_ERR_NONE)
        return rv;

    return rv = aura_h2_srv_process_request(c, stream);

goaway:
    aura_h2_conn_enqueue_goaway(&c->core, c->core.local_goaway_stream_id, rv, reason);
    return rv;
}

/**
 *
 */
static int a_srv_process_data(struct aura_h2_server_conn *c, struct aura_h2_in_frame *in_frame) {
    struct aura_h2_data_payload *payload;
    struct aura_h2_stream *stream;
    const struct aura_iovec *reason;
    struct aura_h2_closed_stream_ent *closed_stream_entry;
    struct aura_mem_ctx *mc = c->conn->mc;
    struct aura_sliding_buf *buf;
    bool process = false;
    int rv;

    if (aura_h2_srv_conn_stream_state_violation(&c->core, in_frame->frame.stream_id)) {
        rv = A_H2_PROTOCOL_ERR;
        reason = &aura_h2_err_string[A_H2_ERR_STR_IDX_INVALID_ARG];
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
            reason = &aura_h2_err_string[A_H2_ERR_STR_IDX_INVALID_ARG];
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
        aura_h2_conn_send_stream_error(&c->core, stream, A_H2_STREAM_CLOSED_ERR, true);
        return A_H2_ERR_NONE;
    }

    /* Extract DATA payload */
    rv = aura_h2_parse_frame_payload(in_frame);
    if (rv != A_H2_ERR_NONE) {
        reason = &aura_h2_err_string[A_H2_ERR_STR_IDX_INVALID_ARG];
        goto exception;
    }

    /* Empty DATA frame */
    if (!aura_h2_frame_is_end_stream(in_frame->frame.flags) && payload->len == 0) {
        aura_h2_sen_update(&c->core.sen, A_H2_SEN_EVT_EMPTY_HDR_ONLY_STREAM, 0);
        return A_H2_ERR_NONE;
    }

    stream->received_len += payload->len;
    if (stream->received_len > A_H2_MAX_DEFAULT_DATA_SZ) {
        aura_h2_conn_send_stream_error(&c->core, stream, A_H2_REFUSED_STREAM_ERR, true);
        return A_H2_ERR_NONE;
    }

    /* Fast path: single data frame with end stream */
    if (aura_h2_frame_is_end_stream(in_frame->frame.flags) && aura_list_is_empty(&stream->data_list)) {
        buf = aura_sliding_buf_create(mc, payload->len, A_SLIDING_BUF_FL_FIXED);
        if (!buf) {
            rv = A_H2_INTERNAL_ERR;
            reason = &aura_h2_err_string[A_H2_ERR_STR_IDX_INTERNAL_ERROR];
            goto exception;
        }

        aura_list_add_tail(&stream->data_list, &buf->allocated.link);
        if (aura_sliding_buf_append(buf, payload->data, payload->len) < 0) {
            rv = A_H2_INTERNAL_ERR;
            reason = &aura_h2_err_string[A_H2_ERR_STR_IDX_INTERNAL_ERROR];
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
                    reason = &aura_h2_err_string[A_H2_ERR_STR_IDX_INTERNAL_ERROR];
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
                reason = &aura_h2_err_string[A_H2_ERR_STR_IDX_INTERNAL_ERROR];
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
        /* @todo: process the request */
    } else
        return A_H2_ERR_NONE;

exception:
    return aura_h2_conn_enqueue_goaway(&c->core, c->core.local_goaway_stream_id, rv, reason);
}

/* Deprecated priority */
static int a_srv_process_prio(struct aura_h2_server_conn *c, struct aura_h2_in_frame *in_frame) {
    int rv;
    rv = aura_h2_parse_frame_payload(in_frame);
    if (rv != A_H2_ERR_NONE)
        return rv;

    /* deprecated, penalize */
    /** @todo: define DEPRECATED PRIO SEN EVT */
    aura_h2_sen_update(&c->core.sen, A_H2_SEN_EVT_STALE, 0);
    return rv;
}

static int a_srv_process_rst(struct aura_h2_server_conn *c, struct aura_h2_in_frame *in_frame) {
    aura_h2_sen_update(&c->core.sen, A_H2_SEN_EVT_RST, 0);
    return aura_h2_conn_process_rst_stream(&c->core, in_frame, true);
}

static int a_srv_process_settings(struct aura_h2_server_conn *c, struct aura_h2_in_frame *in_frame) {
    aura_h2_sen_update(&c->core.sen, A_H2_SEN_EVT_SETTINGS_FLOOD, 0);
    return aura_h2_conn_process_settings(&c->core, in_frame, true);
}

static int a_srv_process_ping(struct aura_h2_server_conn *c, struct aura_h2_in_frame *in_frame) {
    aura_h2_sen_update(&c->core.sen, A_H2_SEN_EVT_PING_FLOOD, 0);
    return aura_h2_conn_process_ping(&c->core, in_frame);
}

static int a_srv_process_goaway(struct aura_h2_server_conn *c, struct aura_h2_in_frame *in_frame) {
    return aura_h2_conn_process_goaway(&c->core, in_frame, true);
}

static int a_srv_process_window_update(struct aura_h2_server_conn *c, struct aura_h2_in_frame *in_frame) {
    aura_h2_sen_update(&c->core.sen, A_H2_SEN_EVT_WIND_UPDATE_FLOOD, 0);
    return aura_h2_conn_process_wind_update(&c->core, in_frame, true);
}

int aura_h2_srv_process_frame(struct aura_h2_server_conn *c, struct aura_sliding_buf *buf) {
    struct aura_h2_in_frame *in_frame = &c->core.in_frame;
    uint8_t *src;
    uint32_t len;
    int rv;

    static int (*frame_handlers[])(struct aura_h2_server_conn *c, struct aura_h2_in_frame *f) = {
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
    };

    len = aura_sliding_buf_read_len(buf);
    src = aura_sliding_buf_read_ptr(buf);

    if (!in_frame->frame_hdr_read) {
        rv = aura_h2_parse_frame_header(in_frame, src, len, c->core.peer_settings.max_frame_size);
        if (rv != A_H2_ERR_NONE)
            return rv;
    }

    if (aura_h2_frame_is_complete(in_frame, len)) {
        // frame_len = A_H2_FRAME_HEADER_SIZE + in_frame->frame.len;
        if (in_frame->frame.type >= ARRAY_SIZE(frame_handlers)) {
            app_debug(true, 0, "Unknown frame type: %d", in_frame->frame.type);
            /* Consume and ignore unknown frame types */
            aura_sliding_buf_consume(buf, in_frame->expected_bytes);
            return rv;
        }

        /**
         * Special handling
         * We expect continuation frame
         * in strict sequence.
         */
        if (c->state == A_H2_CONN_STATE_CONN && in_frame->frame.type != A_H2_FRAME_TYPE_CONT) {
            rv = aura_h2_conn_enqueue_goaway(
              &c->core,
              c->core.local_goaway_stream_id,
              A_H2_PROTOCOL_ERR,
              &aura_h2_err_string[A_H2_ERR_STR_IDX_INVALID_ARG]);
            return A_H2_PROTOCOL_ERR;
        }

        rv = frame_handlers[in_frame->frame.type](c, in_frame);
        aura_sliding_buf_consume(buf, in_frame->expected_bytes);
        aura_h2_frame_reset_inframe(in_frame);
        return rv;
    }

    return A_H2_FRAME_INCOMPLETE;
}

int aura_h2_srv_process(struct aura_h2_server_conn *c, struct aura_sliding_buf *buf) {
    int rv = A_ERR_NONE;

    while (!aura_sliding_buf_is_empty(buf)) {
        switch (c->state) {
        case A_H2_CONN_STATE_PREFACE:
            rv = aura_h2_srv_process_preface(c, buf);
            break;

        case A_H2_CONN_STATE_PREFACE_SETTINGS:
            rv = a_srv_process_preface_settings(c, buf);
            break;

        case A_H2_CONN_STATE_FRAMES:
            rv = aura_h2_srv_process_frame(c, buf);
            break;

        default:
            break;
        }
        // rv = c->state_handler(c, buf);
        rv = aura_h2_get_app_error(rv);
        switch (rv) {
        case A_ERR_AGAIN:
        case A_ERR_FATAL:
        case A_ERR_NONE:
        default:
            break;
        }
    }

    return rv;
}
