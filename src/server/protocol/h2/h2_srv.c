#include "h2/h2_srv.h"
#include "bug_lib.h"
#include "error_lib.h"
#include "h2/hpack_srv.h"
#include "header_srv.h"
#include "route_srv.h"
#include "runtime/js.h"
#include "server_srv.h"
#include "slab_lib.h"
#include "socket_srv.h"
#include "string_lib.h"
#include "utils_lib.h"

static int a_process_headers_early_bailout(struct aura_h2_ctx *h2_ctx, struct aura_h2_stream *stream, const uint8_t *src, size_t len);
int aura_h2_process_preface_settings(struct aura_h2_ctx *h2_ctx);
int aura_process_frame(struct aura_h2_ctx *h2_ctx);

/**
 * Returns true if header received is a trailing header,
 * otherwise false
 */
static bool a_h2_is_trailer_headers(struct aura_h2_stream *s, struct aura_h2_frame *f, bool is_server) {
    if (!s || f->type != A_H2_FRAME_TYPE_HEADERS)
        return false;

    return s->flags & (A_H2_STREAM_FLAG_HEADERS_RECEIVED | A_H2_STREAM_FLAG_HEADERS_SENT);
}

/** */
int a_begin_headers_callback(struct aura_h2_ctx *h2_ctx, struct aura_h2_frame *frame, struct aura_h2_stream **stream) {
    bool is_stream_error;
    int res, err;
    const struct aura_iovec *reason;

    *stream = NULL;
    if (aura_h2_conn_peer_stream_id_new(h2_ctx, frame->stream_id)) {
        if (aura_h2_stream_is_even_numbered(frame->stream_id)) {
            err = A_H2_PROTOCOL_ERROR;
            reason = &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG];
            goto goaway;
        }

        if (aura_h2_conn_max_conc_inbound_streams_reached(h2_ctx)) {
            err = A_H2_PROTOCOL_ERROR;
            reason = &a_h2_error_reasons[A_H2_ERROR_IDX_MAX_CONC_STREAMS];
            goto goaway;
        }

        if (!aura_h2_conn_new_streams_allowed(h2_ctx)) {
            /** @todo: could register the id somewhere, so I can drop further frames */
            /* @todo: once the rst has failed, should goaway be sent or simply close */
            if (aura_h2_send_rst_frame(h2_ctx, frame->stream_id, A_H2_REFUSED_STREAM_ERROR) < 0)
                aura_h2_conn_enqueue_goaway(h2_ctx, h2_ctx->last_processed_stream_id, A_H2_PROTOCOL_ERROR, &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG]);
            return -1;
        }

        *stream = aura_h2_conn_stream_open(h2_ctx, frame->stream_id, A_H2_STREAM_STATE_IDLE, 0, NULL);
        if (!*stream) {
            err = A_H2_INTERNAL_ERROR;
            reason = &a_h2_error_reasons[AURA_H2_ERROR_IDX_INTERNAL_ERROR];
            goto goaway;
            // return A_H2_INTERNAL_ERROR;
        }

        if (aura_h2_frame_is_end_stream(frame->flags) && aura_h2_frame_is_end_headers(frame->flags)) {
            /* prepare response */
            (*stream)->state = A_H2_STREAM_STATE_HALF_CLOSED_REMOTE;
            (*stream)->flags |= A_H2_STREAM_FLAG_HEADERS_RECEIVED;
        } else if (aura_h2_frame_is_end_headers(frame->flags)) {
            (*stream)->state = A_H2_STREAM_STATE_OPEN;
            (*stream)->flags |= (A_H2_STREAM_FLAG_READ_DATA | A_H2_STREAM_FLAG_HEADERS_RECEIVED);
        } else {
            (*stream)->flags |= A_H2_STREAM_FLAG_CONTINUATION;
        }
        aura_h2_conn_transition_state(h2_ctx, A_H2_CONN_STATE_FRAMES);
    } else {
        /** @todo: push promise not supported */
        int rv;
        *stream = aura_h2_conn_find_stream(h2_ctx, frame->stream_id);
        if (!*stream) {
            if (aura_h2_send_rst_frame(h2_ctx, frame->stream_id, A_H2_STREAM_CLOSED_ERROR) < 0)
                aura_h2_conn_enqueue_goaway(h2_ctx, h2_ctx->last_processed_stream_id, A_H2_PROTOCOL_ERROR, &a_h2_error_reasons[AURA_H2_ERROR_IDX_INTERNAL_ERROR]);
            return -1;
        }

        /* trailer */
        if (!aura_h2_frame_is_end_stream(frame->flags) && (*stream)->flags) {
            /* trailer must contain end stream flag */
            err = A_H2_PROTOCOL_ERROR;
            reason = &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG];
            goto goaway;
        }

        rv = aura_h2_conn_stream_headers_allowed((*stream), &is_stream_error);
        if (rv != A_H2_ERROR_NONE) {
            if (is_stream_error && rv != A_H2_STREAM_CLOSED_ERROR) {
                uint32_t frame_len;
                struct aura_h2_sched_evt *evt;
                uint8_t *output_data;

                /* schedule reset */
                if (aura_h2_send_rst_frame(h2_ctx, (*stream)->stream_id, rv) < 0) {
                    aura_h2_conn_enqueue_goaway(h2_ctx, h2_ctx->last_processed_stream_id, A_H2_INTERNAL_ERROR, &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG]);
                    return -1;
                }

                return rv;
            } else if (!is_stream_error) {
                err = rv;
                reason = &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG];
                goto goaway;
            } else
                return rv;
        }

        if (aura_h2_frame_is_end_headers(frame->flags)) {
            (*stream)->state = A_H2_STREAM_STATE_HALF_CLOSED_REMOTE;
        } else {
            (*stream)->flags |= A_H2_STREAM_FLAG_CONTINUATION;
        }
    }

    return A_H2_ERROR_NONE;

goaway:
    aura_h2_conn_transition_state(h2_ctx, A_H2_CONN_STATE_CLOSING);
    aura_conn_transition_state(h2_ctx->conn, A_CONN_STATE_CLOSING);
    aura_h2_conn_enqueue_goaway(h2_ctx, h2_ctx->last_processed_stream_id, err, reason);
    return err;
}

/** */
static inline int a_handle_trailing_headers() {
    /* handle trailer headers and its continuation */
    return 0;
}

/**
 *
 */
int a_headers_callback(struct aura_h2_ctx *conn, struct aura_h2_stream *stream, const uint8_t *src, size_t len) {
    app_debug(true, 0, "a_headers_callback <<<<");

    if (stream->state == A_H2_STREAM_STATE_CLOSING) {
        return a_handle_trailing_headers();
    } else {
        return a_process_headers_early_bailout(conn, stream, src, len);
    }
}

/**
 *
 */
static void a_h2_stream_reset(struct aura_h2_ctx *h2_ctx, struct aura_h2_stream *s) {

    switch (s->state) {
    case A_H2_STREAM_STATE_IDLE:
    case A_H2_STREAM_STATE_HALF_CLOSED_LOCAL:
    }
}

/**
 * Prepare response for submitting on the wire
 * and call the underlying callback to send the data
 */
int aura_submit_response(struct aura_h2_ctx *h2_ctx, int status, struct aura_header_field *hdrs,
                         size_t num_of_hdrs, struct aura_h2_stream *stream, size_t content_length,
                         struct aura_sliding_buf *buf, bool end_stream) {
    size_t hdr_size, offset;
    uint8_t *start, *dest;
    struct aura_h2_out_frame *out_frame;
    struct aura_h2_sched_evt *evt;
    size_t remaining, chunk;
    uint8_t type, flags;
    bool is_first;
    int rv;

    app_debug(true, 0, "aura_submit_response <<<");
    hdr_size = aura_get_headers_size(hdrs, num_of_hdrs);
    hdr_size += A_STATUS_HEADER_SIZE;
    hdr_size += A_DYNAMIC_TABLE_UPDATE_SIZE;

    if (content_length != SIZE_MAX)
        hdr_size += (3 + sizeof(UINT64_MAX_STR) - 1);

    start = aura_alloc(h2_ctx->conn->mc, hdr_size);
    dest = start;
    dest = aura_header_table_adjust_size(&h2_ctx->output_hdr_table, h2_ctx->output_hdr_table.max_size, dest);
    dest = aura_encode_status(dest, status);

    for (int i = 0; i < num_of_hdrs; ++i) {
        dest = aura_encode_header(h2_ctx->conn->mc, &h2_ctx->conn->srv_ctx->static_tab, &h2_ctx->output_hdr_table, dest, hdrs + i);
    }

    if (content_length != SIZE_MAX)
        dest = aura_encode_content_length(dest, content_length);

    remaining = hdr_size;
    offset = 0;

    is_first = true;
    rv = 0;
    while (remaining > 0) {
        chunk = remaining > h2_ctx->peer_settings.max_frame_size ? h2_ctx->peer_settings.max_frame_size : remaining;
        type = is_first ? A_H2_FRAME_TYPE_HEADERS : A_H2_FRAME_TYPE_CONTINUATION;
        flags = remaining == chunk ? A_H2_FRAME_FLAG_END_HEADERS : 0;
        flags |= (end_stream && flags & A_H2_FRAME_FLAG_END_HEADERS) ? A_H2_FRAME_FLAG_END_STREAM : 0;
        if (aura_produce_header_frame(buf, stream->stream_id, type, flags, start + offset, chunk) < 0) {
            rv = -1;
            break;
        }

        is_first = false;
        offset += chunk;
        remaining -= chunk;
    }

    if (rv != 0)
        goto out;

    evt = aura_sched_evt_create(h2_ctx->conn->mc, stream, buf, AURA_H2_SCHED_OP_HEADER_WRITE, NULL, 0, end_stream);
    if (!evt) {
        rv = -1;
        goto out;
    }
    a_list_add_tail(&h2_ctx->scheduler.queues.data.head, &evt->e_list);
    stream->flags |= A_H2_STREAM_FLAG_SEND_HEADERS;

    if (stream->res.body && stream->res.content_length > 0) {
        /** @todo: schedule for data */
    }

out:
    aura_free(start);
    return rv;
}

int aura_submit_response2(struct aura_h2_ctx *h2_ctx, struct aura_h2_stream *stream, bool end_stream) {
    size_t hdr_size, offset;
    uint8_t *start, *dest;
    struct aura_h2_out_frame *out_frame;
    struct aura_h2_sched_evt *evt;
    struct aura_header_field *hdrs;
    size_t remaining, chunk;
    uint8_t type, flags;
    bool is_first, has_body;
    int rv;

    app_debug(true, 0, "aura_submit_response2 <<< max frame");
    hdrs = stream->res.headers.entries;
    has_body = false;
    hdr_size = aura_get_headers_size(hdrs, stream->res.headers.cnt);
    hdr_size += A_STATUS_HEADER_SIZE;
    hdr_size += A_DYNAMIC_TABLE_UPDATE_SIZE;

    if (stream->res.content_length != SIZE_MAX) {
        has_body = true;
        hdr_size += (3 + sizeof(UINT64_MAX_STR) - 1);
    }

    start = aura_alloc(h2_ctx->conn->mc, hdr_size);
    dest = start;
    dest = aura_header_table_adjust_size(&h2_ctx->output_hdr_table, h2_ctx->output_hdr_table.max_size, dest);
    dest = aura_encode_status(dest, stream->res.status_code);

    for (int i = 0; i < stream->res.headers.cnt; ++i) {
        dest = aura_encode_header(h2_ctx->conn->mc, &h2_ctx->conn->srv_ctx->static_tab, &h2_ctx->output_hdr_table, dest, hdrs + i);
    }

    if (stream->res.content_length != SIZE_MAX)
        dest = aura_encode_content_length(dest, stream->res.content_length);

    remaining = hdr_size;
    offset = 0;

    is_first = true;
    rv = 0;
    while (remaining > 0) {
        chunk = a_min(remaining, h2_ctx->peer_settings.max_frame_size);
        type = is_first ? A_H2_FRAME_TYPE_HEADERS : A_H2_FRAME_TYPE_CONTINUATION;
        flags = remaining == chunk ? A_H2_FRAME_FLAG_END_HEADERS : 0;
        flags |= (!has_body && end_stream && flags & A_H2_FRAME_FLAG_END_HEADERS) ? A_H2_FRAME_FLAG_END_STREAM : 0;
        if (aura_produce_header_frame(stream->sync, stream->stream_id, type, flags, start + offset, chunk) < 0) {
            rv = -1;
            break;
        }

        is_first = false;
        offset += chunk;
        remaining -= chunk;
    }

    if (rv != 0)
        goto out;

    evt = aura_sched_evt_create(h2_ctx->conn->mc, stream, stream->sync, AURA_H2_SCHED_OP_HEADER_WRITE, NULL, 0, end_stream);
    if (!evt) {
        rv = -1;
        goto out;
    }
    a_list_add_tail(&h2_ctx->scheduler.queues.data.head, &evt->e_list);
    stream->flags |= A_H2_STREAM_FLAG_SEND_HEADERS;

    if (stream->res.body && stream->res.content_length > 0) {
        evt = aura_sched_evt_create(h2_ctx->conn->mc, stream, stream->data, AURA_H2_SCHED_OP_DATA_WRITE, NULL, 0, end_stream);
        if (!evt) {
            rv = -1;
            goto out;
        }
        a_list_add_tail(&h2_ctx->scheduler.queues.data.head, &evt->e_list);
    }

out:
    aura_free(start);
    return rv;
}

/**
 * Prepare error response for submitting on the wire
 * and call the underlying callback to send the data
 */
int aura_submit_error_response(struct aura_h2_ctx *h2_ctx, struct aura_h2_stream *stream, int status) {
    struct aura_http_hdr_set *hdrs;
    struct aura_hpack_static_table_entry *entry;
    size_t res;
    app_debug(true, 0, "aura_submit_error_response <<<<");
    // aura_h2_stream_dump(stream);

    // entry = hpack_static_header_table_get(A_TOKEN_CONTENT_TYPE);
    // hdrs[0].name = &entry->name;
    // hdrs[0].value->base = "text/html; charset=UTF-8";
    // hdrs[0].value->len = sizeof("text/html; charset=UTF-8") - 1;

    switch (status) {
    case 404:
        break;
    default:
        break;
    }

    // res = aura_submit_response(h2_ctx, status, /*hdrs*/ NULL, /*ARRAY_SIZE(hdrs)*/ 0, stream->stream_id, SIZE_MAX, &stream->data, true);
    res = aura_submit_response(h2_ctx, status, /*hdrs*/ NULL, /*ARRAY_SIZE(hdrs)*/ 0, stream, SIZE_MAX, stream->sync, true);
    return A_H2_ERROR_NONE;
}

int aura_h2_submit_rt_response(struct aura_h2_ctx *h2_ctx, struct aura_h2_stream *stream, Response *resp) {
    int status, rv;
    app_debug(true, 0, "aura_h2_submit_rt_response <<<<");

    rv = 0;
    if (resp->status < 100 || resp->status > 500) {
        rv = aura_submit_error_response(h2_ctx, stream, 500);
        aura_enqueue_write(h2_ctx);
    } else {
        if (aura_h2_stream_claim_rt_response(stream, resp) < 0) {
            rv = -1;
        } else
            // aura_rt_res_destroy(resp);
            rv = aura_submit_response2(h2_ctx, stream, true);
    }

    if (rv == 0)
        aura_enqueue_write(h2_ctx);

    // app_exit(true, 0, "");
    return rv;
}

static int a_setup_server_preface(struct aura_h2_ctx *h2_ctx) {
    uint32_t frame_len;
    uint8_t *output_data;
    struct aura_h2_sched_evt *settings_evt, *window_update_evt;
    uint32_t initial_window_size;
    const struct aura_iovec *reason;
    int error;

    app_debug(true, 0, "a_setup_server_preface <<<<");
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
 * Handle connection preface
 */
int aura_h2_process_preface(struct aura_h2_ctx *h2_ctx) {
    int res, len;
    uint8_t *src;

    len = aura_sliding_buffer_available_read(h2_ctx->conn->plain_read_buf);
    src = aura_sliding_buffer_read_pointer(h2_ctx->conn->plain_read_buf);

    if (len < aura_h2_connection_preface.len)
        return A_H2_FRAME_INCOMPLETE;

    if (memcmp(aura_h2_connection_preface.base, src, aura_h2_connection_preface.len) != 0)
        return A_H2_PROTOCOL_ERROR;

    aura_sliding_buffer_consume(h2_ctx->conn->plain_read_buf, aura_h2_connection_preface.len);
    // encode origin if present
    aura_now_ts(&h2_ctx->timestamps.conn_started_at, CLOCK_MONOTONIC);
    aura_h2_conn_transition_state(h2_ctx, A_H2_CONN_STATE_PREFACE_SETTINGS);
    aura_h2_conn_transition_state_handler(h2_ctx, aura_h2_process_preface_settings);
    return A_H2_ERROR_NONE;
}

/**
 * Handle first settings frame after connection preface
 */
int aura_h2_process_preface_settings(struct aura_h2_ctx *h2_ctx) {
    struct aura_h2_in_frame in_frame;
    int res, len, frame_len;
    uint8_t *src;

    src = aura_sliding_buffer_read_pointer(h2_ctx->conn->plain_read_buf);
    len = aura_sliding_buffer_available_read(h2_ctx->conn->plain_read_buf);
    res = aura_h2_parse_frame_header(&in_frame, src, len, h2_ctx->local_settings.max_frame_size, &frame_len);
    if (res != A_H2_ERROR_NONE)
        return res;

    if (in_frame.frame.type != A_H2_FRAME_TYPE_SETTINGS)
        return A_H2_PROTOCOL_ERROR;

    aura_sliding_buffer_consume(h2_ctx->conn->plain_read_buf, frame_len);
    res = aura_process_settings(h2_ctx, &in_frame);
    if (res != A_H2_ERROR_NONE)
        return res;

    res = a_setup_server_preface(h2_ctx);
    if (res == A_H2_ERROR_NONE) {
        aura_h2_conn_transition_state(h2_ctx, A_H2_CONN_STATE_FRAMES);
        aura_h2_conn_transition_state_handler(h2_ctx, aura_process_frame);
        aura_enqueue_write(h2_ctx);
    }

    return res;
}

/**
 *
 */
static int a_process_push_promise(struct aura_h2_ctx *h2_ctx, struct aura_h2_in_frame *in_frame) {
    /* Check if we expect continuation frame */
    if (h2_ctx->flags & A_H2_CONN_FLAG_EXPECT_CONTINUATION) {
        return A_H2_PROTOCOL_ERROR;
    }

    return A_H2_PROTOCOL_ERROR;
}

/**
 * Returns true if provided method is valid,
 * otherwise false
 */
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
 * Returns 0 if the parsed authority is among list
 * of allowed authority for a given server, otherwise err;
 */
static inline int a_header_authority_cb(struct aura_h2_ctx *h2_ctx, struct aura_h2_stream *stream,
                                        const char *name, size_t name_len, const char *value, size_t value_len) {
    app_debug(true, 0, "a_header_authority_cb <<<< value: %s", value);
    /**/
    return A_HPACK_OK;
}

/**
 * Return 0 if the parsed method is valid and
 * supported by server, otherwise -1;
 */
static inline int a_header_method_cb(struct aura_h2_ctx *h2_ctx, struct aura_h2_stream *stream,
                                     const char *name, size_t name_len, const char *value, size_t val_len) {
    app_debug(true, 0, "a_header_method_cb <<<< value: %s", value);
    uint64_t content_len;
    a_http_method_t method;

    if (strcmp(value, "CONNECT") == 0 || strcmp(value, "TRACE") == 0) {
        /* unsupported methods */
        return A_HPACK_PROTOCOL_ERR;
    }

    method = a_is_header_method_valid(value);
    if (method == HTTP_NONE)
        return A_HPACK_PROTOCOL_ERR;

    stream->req.method = method;
    return A_HPACK_OK;
}

/**
 * Get and attach host config associated with parsed
 * path, validate that path is supported by hosts,
 * return 0 if satisfied, otherwise err
 */
static inline int a_header_path_cb(struct aura_h2_ctx *h2_ctx, struct aura_h2_stream *stream,
                                   const char *name, size_t name_len, const char *value, size_t val_len) {
    struct aura_srv_host_conf *host;
    struct aura_route *route;

    host = h2_ctx->conn->host;
    A_BUG_ON_2(!host, true);
    app_debug(true, 0, "a_header_path_cb <<<< value: %s", value);

    /* check for duplicate header */
    if (stream->req.path.base != NULL)
        return A_HPACK_PROTOCOL_ERR;

    if (val_len == 0) {
        return A_HPACK_PROTOCOL_ERR;
    }
    stream->req.path.base = aura_alloc(h2_ctx->conn->mc, val_len);
    memcpy(stream->req.path.base, value, val_len);

    /* validate if requested route/fn exists */
    route = aura_route_match(&host->router, value, val_len, stream->req.method);
    if (!route) {
        // 404
        return A_HPACK_PATH_EMPTY_ERR;
    }

    /* set route so we don't have to search again */
    h2_ctx->conn->route = route;
    return A_HPACK_OK;
}

/**
 * Returns 0 if parsed scheme is valid and
 * supported, otherwise err
 */
static inline int a_header_scheme_cb(struct aura_h2_ctx *h2_ctx, struct aura_h2_stream *stream,
                                     const char *name, size_t name_len, const char *value, size_t val_len) {
    /**/
    app_debug(true, 0, "a_header_scheme_cb <<<<: %s", value);
    return A_HPACK_OK;
}

/**
 * Returns 0 if parsed status is valid number,
 * otherwise return err;
 */
static inline int a_header_status_callback(struct aura_h2_ctx *h2_ctx, struct aura_h2_stream *stream,
                                           const char *name, size_t name_len, const char *value, size_t val_len) {
    int status;
    char *c;

    if (stream->res.status_code != 0)
        return A_H2_PROTOCOL_ERROR;

    /* parse */
    if (val_len != 3) {
        return A_H2_COMPRESSION_ERROR;
    }

    // c = value->base;
    c = (char *)value;
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

/**
 * P
 */
static int aura_h2_process_request(struct aura_h2_ctx *h2_ctx, struct aura_h2_stream *stream) {
    struct aura_route *route;
    struct aura_work_queue *wq;
    struct aura_task *task;
    Request *req;
    Response *resp;
    int res;

    app_debug(true, 0, "aura_h2_process_request <<<<");
    if (stream->state == A_H2_STREAM_STATE_HALF_CLOSED_REMOTE) {
        /* forward to route handler/path handler */
        route = h2_ctx->conn->route;
        A_BUG_ON_2(!route, true);
        /* Create task */
        task = aura_task_create(h2_ctx->conn->mc, h2_ctx->conn->srv_ctx->next_task_id++,
                                h2_ctx->conn, stream, A_TASK_PROTOCOL_H2, h2_ctx->conn->route->url,
                                stream->req.method, &stream->req.headers, stream->req.raw_ptr.base, stream->req.content_length);
        if (!task)
            return A_H2_INTERNAL_ERROR;

        res = aura_work_queue_add(route->wq, route->fn, task);
        if (res) {
            aura_rt_req_destroy(req);
            aura_free(task);
            app_debug(true, 0, "aura_h2_process_request: aura_work_queue_add: %d", res);
            return A_H2_INTERNAL_ERROR;
        }

        stream->flags |= A_H2_STREAM_FLAG_EXECUTING;
    }

    return A_H2_ERROR_NONE;
}

/**
 *
 */
static int a_process_headers_early_bailout(struct aura_h2_ctx *h2_ctx, struct aura_h2_stream *stream, const uint8_t *src, size_t len) {
    app_debug(true, 0, "a_process_headers_early_bailout <<<<");
    int res, ret_val;

    /** @todo: update request structure connected to stream in the various callbacks */
    static hpack_header_cb cb[] = {
      a_header_authority_cb,
      a_header_method_cb,
      a_header_path_cb,
      a_header_scheme_cb,
      a_header_status_callback,
    };

    res = aura_hpack_parse_request(h2_ctx, stream, src, len, cb);

    /** @todo: complete the list, see where to send early errors these functions */
    switch (res) {
    case A_HPACK_OK:
        /* Can enqueue early requests that don't need data */
        aura_conn_transition_state(h2_ctx->conn, A_CONN_STATE_PROCESS_REQ);
        ret_val = aura_h2_process_request(h2_ctx, stream);
        if (ret_val == A_H2_ERROR_NONE)
            return A_H2_ERROR_IN_PROGRESS;
        else
            return ret_val;
    case A_HPACK_PROTOCOL_ERR:
        aura_h2_conn_transition_state(h2_ctx, A_H2_CONN_STATE_CLOSING);
        aura_conn_transition_state(h2_ctx->conn, A_CONN_STATE_CLOSING);
        aura_h2_conn_enqueue_goaway(h2_ctx, h2_ctx->last_processed_stream_id, A_H2_PROTOCOL_ERROR, &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG]);
        aura_enqueue_write(h2_ctx);
        return A_H2_PROTOCOL_ERROR;
    case A_HPACK_COMPRESSION_ERR:
        aura_h2_conn_transition_state(h2_ctx, A_H2_CONN_STATE_CLOSING);
        aura_conn_transition_state(h2_ctx->conn, A_CONN_STATE_CLOSING);
        aura_h2_conn_enqueue_goaway(h2_ctx, h2_ctx->last_processed_stream_id, A_H2_COMPRESSION_ERROR, &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG]);
        aura_enqueue_write(h2_ctx);
        return A_H2_COMPRESSION_ERROR;
    case A_HPACK_PATH_EMPTY_ERR:
        aura_h2_conn_transition_state(h2_ctx, A_H2_CONN_STATE_CLOSING);
        aura_conn_transition_state(h2_ctx->conn, A_CONN_STATE_CLOSING);
        ret_val = aura_submit_error_response(h2_ctx, stream, 404);
        aura_enqueue_write(h2_ctx);
        return ret_val;
    default:
        break;
    }
    return A_H2_ERROR_NONE;
}

/**
 *
 */
static int a_process_data(struct aura_h2_ctx *h2_ctx, struct aura_h2_in_frame *in_frame) {
    struct aura_h2_data_payload payload;
    struct aura_h2_stream *stream;
    struct aura_h2_sched_evt *rst_evt;
    uint8_t *output_data;
    const struct aura_iovec *reason;
    int frame_len;
    int res, err;

    /* Check if we expect continuation frame */
    if (h2_ctx->flags & A_H2_CONN_FLAG_EXPECT_CONTINUATION) {
        return A_H2_PROTOCOL_ERROR;
    }

    if (aura_h2_stream_is_idle(h2_ctx, in_frame->frame.stream_id)) {
        err = A_H2_PROTOCOL_ERROR;
        reason = &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG];
        goto exception;
    }

    stream = aura_h2_conn_find_stream(h2_ctx, in_frame->frame.stream_id);
    if (!stream) {
        goto stream_closed;
    }

    /* @todo: fix stream states for better checking */
    if (stream->state == A_H2_STREAM_STATE_RESERVED || stream->state != A_H2_STREAM_STATE_OPEN) {
        err = A_H2_PROTOCOL_ERROR;
        reason = &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG];
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
        reason = &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG];
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
    output_data = aura_encode_control_frame(
      h2_ctx->scheduler.write_buf, A_H2_FRAME_TYPE_RST_STREAM,
      0, in_frame->frame.stream_id, frame_len, (void *)&err, 0);
    if (!output_data) {
        aura_h2_conn_enqueue_goaway(h2_ctx, h2_ctx->last_processed_stream_id, A_H2_INTERNAL_ERROR, &a_h2_error_reasons[A_H2_INTERNAL_ERROR]);
        return A_H2_INTERNAL_ERROR;
    }

    rst_evt = aura_sched_evt_create(h2_ctx->conn->mc, stream, h2_ctx->scheduler.write_buf, AURA_H2_SCHED_OP_CONTROL_WRITE, output_data, frame_len, false);
    if (!rst_evt) {
        aura_h2_conn_enqueue_goaway(h2_ctx, h2_ctx->last_processed_stream_id, A_H2_INTERNAL_ERROR, &a_h2_error_reasons[A_H2_INTERNAL_ERROR]);
        return A_H2_INTERNAL_ERROR;
    }
    a_list_add_tail(&h2_ctx->scheduler.queues.control.head, &rst_evt->e_list);
    /* ignore data frame */
    return 0;

exception:
    return aura_h2_conn_enqueue_goaway(h2_ctx, h2_ctx->last_processed_stream_id, err, reason);
}

/**
 *
 */
static int a_process_header(struct aura_h2_ctx *h2_ctx, struct aura_h2_in_frame *in_frame) {
    app_debug(true, 0, "a_process_header <<<<");
    struct aura_h2_stream *stream;
    struct aura_h2_frame *frame;
    int res;

    /* Check if we expect continuation frame */
    if (h2_ctx->flags & A_H2_CONN_FLAG_EXPECT_CONTINUATION) {
        return A_H2_PROTOCOL_ERROR;
    }

    res = aura_h2_parse_frame_payload(in_frame);
    if (res != A_H2_ERROR_NONE) {
        aura_h2_conn_enqueue_goaway(h2_ctx, h2_ctx->last_processed_stream_id, res, &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG]);
        return res;
    }

    frame = &in_frame->frame;
    if (aura_h2_stream_is_push_stream(frame->stream_id)) {
        aura_h2_conn_enqueue_goaway(h2_ctx, h2_ctx->last_processed_stream_id, A_H2_PROTOCOL_ERROR, &a_h2_error_reasons[A_H2_ERROR_IDX_INVALID_ARG]);
        return res;
    }

    /* call on begin headers */
    res = h2_ctx->callbacks.header_begin_callback(h2_ctx, frame, &stream);
    if (res != A_H2_ERROR_NONE) {
        return res;
    }

    if (stream->flags & A_H2_STREAM_FLAG_CONTINUATION) {
        if (aura_sliding_buffer_append(h2_ctx->headers_to_parse, frame->payload, frame->len) < 0)
            aura_h2_conn_enqueue_goaway(h2_ctx, h2_ctx->last_processed_stream_id, A_H2_PROTOCOL_ERROR, &a_h2_error_reasons[AURA_H2_ERROR_IDX_INTERNAL_ERROR]);
        h2_ctx->flags |= A_H2_CONN_FLAG_EXPECT_CONTINUATION;
        return A_H2_ERROR_NONE;
    }

    res = h2_ctx->callbacks.header_callback(h2_ctx, stream, frame->payload, frame->len);
    return res;
}

int aura_process_frame(struct aura_h2_ctx *h2_ctx) {
    struct aura_h2_in_frame in_frame;
    int res, len;
    int frame_len;
    uint8_t *src;

    static int (*frame_handlers[])(struct aura_h2_ctx *h2_ctx, struct aura_h2_in_frame *frame) = {
      [A_H2_FRAME_TYPE_DATA] = a_process_data,
      [A_H2_FRAME_TYPE_HEADERS] = a_process_header,
      [A_H2_FRAME_TYPE_PRIORITY] = aura_process_priority,
      [A_H2_FRAME_TYPE_RST_STREAM] = aura_process_rst_stream,
      [A_H2_FRAME_TYPE_SETTINGS] = aura_process_settings,
      [A_H2_FRAME_TYPE_PUSH_PROMISE] = a_process_push_promise,
      [A_H2_FRAME_TYPE_PING] = aura_process_ping,
      [A_H2_FRAME_TYPE_GOAWAY] = aura_process_goaway,
      [A_H2_FRAME_TYPE_WINDOW_UPDATE] = aura_process_window_update,
      [A_H2_FRAME_TYPE_CONTINUATION] = aura_process_continuation,
    };

    len = aura_sliding_buffer_available_read(h2_ctx->conn->plain_read_buf);
    src = aura_sliding_buffer_read_pointer(h2_ctx->conn->plain_read_buf);

    res = aura_h2_parse_frame_header(&in_frame, src, len, A_H2_MIN_FRAME_SIZE, &frame_len);
    if (res != A_H2_ERROR_NONE)
        return res;

    if (in_frame.frame.type >= ARRAY_SIZE(frame_handlers)) {
        app_debug(true, 0, "Unknown frame type: %d", in_frame.frame.type);
        /* Consume and ignore unknown frame types */
        aura_sliding_buffer_consume(h2_ctx->conn->plain_read_buf, frame_len);
        return res;
    }

    aura_sliding_buffer_consume(h2_ctx->conn->plain_read_buf, frame_len);
    res = frame_handlers[in_frame.frame.type](h2_ctx, &in_frame);
    return res;
}

/** */
struct aura_h2_ctx *aura_h2_server_conn_create(struct aura_memory_ctx *mc) {
    struct aura_h2_ctx *h2_ctx;

    h2_ctx = aura_h2_ctx_init(mc, true);
    if (!h2_ctx)
        return NULL;

    h2_ctx->callbacks.header_begin_callback = a_begin_headers_callback;
    h2_ctx->callbacks.header_callback = a_headers_callback;
    aura_h2_conn_transition_state(h2_ctx, A_H2_CONN_STATE_PREFACE);
    aura_h2_conn_transition_state_handler(h2_ctx, aura_h2_process_preface);

    return h2_ctx;
}

int aura_h2_process(void *protocol_ctx) {
    struct aura_h2_ctx *h2_conn;
    size_t n_read, avail_write;
    int rv, err_idx;
    app_debug(true, 0, "aura_h2_process <<<<: %p", protocol_ctx);

    h2_conn = protocol_ctx;
    while (!aura_sliding_buffer_is_empty(h2_conn->conn->plain_read_buf)) {
        rv = h2_conn->state_handler(h2_conn);
        if (rv != A_H2_ERROR_NONE)
            return error_table[rv];
    }

    if (rv == A_H2_ERROR_NONE)
        return A_PROGRESS_DONE;

    if (aura_sliding_buffer_is_empty(h2_conn->conn->plain_read_buf))
        return A_PROGRESS_BLOCKED;

    return A_PROGRESS_DONE;
}