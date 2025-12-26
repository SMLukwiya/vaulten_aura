#include "h2/h2_srv.h"
#include "error_lib.h"
#include "h2/hpack_srv.h"
#include "header_srv.h"
#include "server_srv.h"

int aura_decode_tls_input(struct aura_srv_sock *sock) {
    app_debug(true, 0, ">>> aura_decode_tls_input");
    char *src, *write_ptr;
    ptls_buffer_t read_buf;
    size_t consumed, len, avail_write;
    int res;

    if (!aura_sliding_buffer_is_empty(&sock->tls_ctx->encrypted_read_buf)) {
        len = aura_sliding_buffer_available_read(&sock->tls_ctx->encrypted_read_buf);
        avail_write = aura_sliding_buffer_available_write(&sock->plain_read_buf);
        write_ptr = aura_sliding_buffer_write_pointer(&sock->plain_read_buf);

        if (!write_ptr) {
            /* initialize plainbuf for the first time */
            res = aura_sliding_buffer_ensure_capacity(&sock->plain_read_buf, 16384);
            if (!res)
                return 1;
            avail_write = aura_sliding_buffer_available_write(&sock->plain_read_buf);
            write_ptr = aura_sliding_buffer_write_pointer(&sock->plain_read_buf);
        }

        ptls_buffer_init(&read_buf, write_ptr, avail_write);

        do {
            src = aura_sliding_buffer_read_pointer(&sock->tls_ctx->encrypted_read_buf);
            consumed = len;

            res = ptls_receive(sock->tls_ctx->ptls, &read_buf, src, &consumed);
            if (res != 0)
                break;
            len -= consumed;
            aura_sliding_buffer_consume(&sock->tls_ctx->encrypted_read_buf, consumed);
        } while (len > 0);

        if (read_buf.is_allocated) {
            len = aura_sliding_buffer_append(&sock->plain_read_buf, read_buf.base, read_buf.off);
            if (len == 0)
                return 1;

            ptls_buffer_dispose(&read_buf);
        } else {
            aura_sliding_buffer_commit_write(&sock->plain_read_buf, read_buf.off);
        }

        if (res == PTLS_ERROR_IN_PROGRESS)
            return PTLS_ERROR_IN_PROGRESS;

        if (res != 0)
            return 1;
    }

    return 0;
}

/**
 *
 */
void aura_h2_proceed(struct aura_srv_sock *sock, struct aura_srv_ctx *srv_ctx) {
    app_debug(true, 0, ">>>> aura_h2_proceed");
    size_t n_read, avail_write;
    int res, err_idx;

    avail_write = aura_sliding_buffer_available_write(&sock->tls_ctx->encrypted_read_buf);
    n_read = aura_sliding_buffer_append_from_fd(&sock->tls_ctx->encrypted_read_buf, sock->sock_fd, avail_write);
    if (n_read == -1) {
        aura_h2_connection_close(sock->h2_conn);
        return;
    }

    if (n_read == 0 && aura_sliding_buffer_is_empty(&sock->tls_ctx->encrypted_read_buf)) {
        /* rearm socket */
        return;
    }

    // update bytes read as well
    res = aura_decode_tls_input(sock);
    if (res == 1) {
        app_debug(true, 0, "ERROR decoding the tls input");
        aura_h2_connection_close(sock->h2_conn);
    }

    if (res == PTLS_ERROR_IN_PROGRESS) {
        /* rearm socket */
        return;
    }

    if (sock->h2_conn == NULL) {
        sock->h2_conn = aura_h2_create_connection_server(sock, srv_ctx);
        if (sock->h2_conn == NULL)
            sys_exit(true, errno, "Out of memory: aura_h2_proceed");
    }

    res = aura_conn_parse_input(sock->h2_conn);

    if (res == A_H2_FRAME_INCOMPLETE) {
        /* rearm and proceed */
        return;
    }

    if (res == A_H2_PREFACE_ERROR) {
        /* can't proceed, bye! */
        aura_h2_connection_close(sock->h2_conn);
        return;
    }

    return;
}

void aura_socket_write(struct aura_srv_sock *sock) {
    ssize_t bytes_written;

    if (sock->tls_ctx->ptls != NULL) {
        bytes_written = aura_sock_write_tls(sock);
    } else
        bytes_written = aura_write(sock->sock_fd, sock->write.buf.base, sock->write.buf.len - sock->write.pending_off);
}

int aura_submit_error_response(struct aura_h2_conn *conn, struct aura_h2_stream *stream, int status) {
    struct aura_http_hdr_set *hdrs;
    struct aura_hpack_static_table_entry *entry;

    stream->state = A_H2_STREAM_STATE_CLOSING;
    stream->flags |= A_H2_STREAM_FLAG_SEND_HEADERS;

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

    return aura_submit_response(conn, status, /*hdrs*/ NULL, /*ARRAY_SIZE(hdrs)*/ 0, stream->stream_id, SIZE_MAX, &stream->sync, true);
}

size_t aura_submit_response(struct aura_h2_conn *conn, int status, struct aura_http_hdr_set *hdrs,
                            size_t num_of_hdrs, uint32_t stream_id, size_t content_length,
                            struct aura_sliding_buf *buf, bool end_stream) {
    size_t hdr_size, offset;
    uint8_t *_dest, *dest;
    struct aura_h2_out_frame *out_frame;
    size_t remaining, chunk;
    uint8_t type, flags;
    bool is_first;

    hdr_size = get_headers_size(hdrs, num_of_hdrs);
    hdr_size += A_STATUS_HEADER_SIZE;
    hdr_size += DYNAMIC_TABLE_UPDATE_SIZE;

    if (content_length != SIZE_MAX)
        hdr_size += (3 + sizeof("18446744073709551615") - 1);

    _dest = aura_alloc(conn->mc, hdr_size);
    dest = _dest;
    dest = header_table_adjust_size(&conn->output_hdr_table, conn->output_hdr_table.max_dynamic_size, dest);
    dest = encode_status(dest, status);

    for (int i = 0; i < num_of_hdrs; ++i) {
        dest = encode_header(conn->mc, &conn->output_hdr_table, dest, hdrs + i);
    }

    if (content_length != SIZE_MAX)
        dest = encode_content_length(dest, content_length);

    remaining = hdr_size;
    offset = 0;

    is_first = true;
    while (remaining > 0) {
        chunk = remaining > conn->peer_settings.max_frame_size ? conn->peer_settings.max_frame_size : remaining;
        type = is_first ? A_H2_FRAME_TYPE_HEADERS : A_H2_FRAME_TYPE_CONTINUATION;
        flags = remaining == chunk ? A_H2_FRAME_FLAG_END_HEADERS : 0;
        flags |= end_stream ? A_H2_FRAME_FLAG_END_STREAM : 0;
        out_frame = aura_produce_header_frame(conn->mc, buf, stream_id, type, flags, _dest + offset, chunk);

        /* add to stream outbound queue */

        /* schedule on connection data frame */
        a_list_add_tail(&conn->sender.queues.control.head, &out_frame->f_list);

        offset += chunk;
        remaining -= chunk;
    }

    aura_free(_dest);

    return 0;
}