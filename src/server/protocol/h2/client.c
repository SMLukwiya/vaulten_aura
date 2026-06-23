#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include "h2/client.h"
#include "connection.h"
#include "header_srv.h"
#include "pending_req.h"
#include "picotls.h"
#include "server_srv.h"
#include "socket_srv.h"
#include "url/lib.h"

extern const struct aura_hpack_static_table static_table;

void aura_cli_handle_conn_failure(struct aura_conn *conn);

int aura_h2_client_conn_init(struct aura_h2_client_conn *c, struct aura_mem_ctx *mc) {
    int rv = aura_h2_core_init(&c->core, mc, false);
    if (rv < 0)
        return -1;

    pthread_mutex_init(&c->mutex, NULL);
    atomic_store(&c->ref_cnt, 1);

    aura_h2_conn_transition_state(&c->state, A_H2_CONN_STATE_PREFACE);
    // aura_h2_conn_transition_state_handler(NULL, aura_h2_client_preface_setup);

    return A_H2_ERR_NONE;
}

void aura_h2_cli_conn_destroy(struct aura_h2_client_conn *c) {
    aura_h2_core_destroy(&c->core, false);
    pthread_mutex_destroy(&c->mutex);
}

int aura_h2_client_request_send(struct aura_h2_core *h2_c, struct aura_h2_stream *stream) {
    const uint8_t *src_in;
    bool has_body = false, end_stream = false, is_first_frame = true;
    size_t len, remaining, offset, chunk;
    int rv, type, flags;

    rv = aura_hpack_encoder_adjust_tab_size(&h2_c->enc);
    if (rv != A_HPACK_OK)
        return rv;

    rv = aura_hpack_encode_headers(
      &h2_c->enc,
      h2_c->intern_tab,
      stream->req.headers.entries,
      stream->req.headers.cnt);
    if (rv < 0)
        return rv;

    if (stream->res.content_length != SIZE_MAX) {
        rv = aura_hpack_encode_content_length(&h2_c->enc, stream->res.content_length);
        if (rv < 0)
            return rv;
    }

    src_in = aura_sliding_buf_read_ptr(&h2_c->enc.enc_buf);
    remaining = aura_sliding_buf_read_len(&h2_c->enc.enc_buf);
    offset = 0;
    rv = 0;
    end_stream = !has_body;

    while (remaining > 0) {
        chunk = a_min(remaining, h2_c->peer_settings.max_frame_size);
        type = is_first_frame ? A_H2_FRAME_TYPE_HDRS : A_H2_FRAME_TYPE_CONT;
        flags = remaining == chunk ? A_H2_FRAME_FLAG_END_HEADERS : 0;
        /* defer sending END_STREAM until final headers block */
        flags |= (end_stream && (flags & A_H2_FRAME_FLAG_END_HEADERS)) ? A_H2_FRAME_FLAG_END_STREAM : 0;
        rv = aura_h2_encode_hdr_frame(
          &stream->sync,
          stream->stream_id,
          type, flags,
          src_in + offset,
          chunk);
        if (rv < 0)
            break;

        is_first_frame = false;
        offset += chunk;
        remaining -= chunk;
    }

    if (rv != A_H2_ERR_NONE)
        goto out;

    stream->flags |= A_H2_STREAM_FLAG_SEND_HDRS;
    len = stream->res.content_length;
    src_in = stream->res.body;
    offset = 0;
    if (stream->res.body && len != SIZE_MAX && len != 0) {
        while (len > 0) {
            chunk = a_min(len, h2_c->peer_settings.max_frame_size);
            flags |= (len == chunk && end_stream) ? A_H2_FRAME_FLAG_END_STREAM : 0;
            if (aura_h2_encode_data_frame(&stream->sync, stream->stream_id, flags, src_in + offset, chunk, 0) < 0)
                return -1;

            offset += chunk;
            len -= chunk;
        }

        stream->flags |= A_H2_STREAM_FLAG_SEND_DATA;
    }

    /* @todo: SEND */

out:
    aura_sliding_buf_reset(&h2_c->enc.enc_buf);
    return rv;
}

/**
 * Handle first settings frame after connection preface
 */
int aura_h2_client_process_preface_settings(struct aura_h2_core *h2_c) {
    struct aura_h2_in_frame in_frame;
    int rv, len, frame_len;
    uint8_t *src;

    // src = aura_sliding_buf_read_ptr(h2_c->conn->plain_read_buf);
    // len = aura_sliding_buf_read_len(h2_c->conn->plain_read_buf);
    // rv = aura_h2_parse_frame_header(&in_frame, src, len, h2_c->local_settings.max_frame_size);
    // if (rv != A_H2_ERR_NONE)
    //     return rv;

    // if (in_frame.frame.type != A_H2_FRAME_TYPE_SETTINGS)
    //     return A_H2_PROTOCOL_ERR;

    // frame_len = A_H2_FRAME_HEADER_SIZE + in_frame.frame.len;
    // aura_sliding_buf_consume(h2_c->conn->plain_read_buf, frame_len);
    // rv = aura_h2_conn_process_settings(h2_c, &in_frame);
    // if (rv != A_H2_ERR_NONE)
    //     return rv;

    // aura_h2_conn_transition_state(h2_c, A_H2_CONN_STATE_FRAMES);
    // aura_h2_conn_transition_state_handler(h2_c, aura_h2_srv_process);

    return A_H2_ERR_NONE;
}

int aura_h2_client_handle_queued_streams(struct aura_h2_client_conn *c) {
    struct aura_req_coordinator *req_c;
    struct aura_pending_req *p_req;
    struct aura_h2_stream *stream;
    struct aura_js_fetch_ctx *fetch_ctx;
    struct aura_list_head process_list, fail_list;
    int rv;

    rv = aura_h2_client_process_preface_settings(&c->core);
    if (rv != A_H2_ERR_NONE)
        return rv;

    // req_c = &c->conn->srv_ctx->req_coord;
    aura_list_head_init(&process_list);
    aura_list_head_init(&fail_list);

    pthread_mutex_lock(&req_c->mutex);
    while (!aura_list_is_empty(&req_c->head))
        aura_list_move(&process_list, &p_req->p_list);
    pthread_mutex_unlock(&req_c->mutex);

    while (!aura_list_is_empty(&process_list)) {
        a_list_dequeue(p_req, &process_list, p_list);

        switch (p_req->type) {
        case A_PENDING_REQ_H2_JS:
            // a_list_dequeue(p_req, &req_c->head, p_list);
            // stream = aura_h2_conn_stream_open(
            //   &c->core,
            //   &c->conn->mc,
            //   &c->core.next_stream_id,
            //   A_H2_STREAM_STATE_IDLE,
            //   0,
            //   p_req->user_data,
            //   p_req->destructor,
            //   false);
            // if (!stream) {
            //     fetch_ctx = p_req->user_data;
            //     aura_qjs_trigger_promise_rejection(fetch_ctx->ctx, fetch_ctx->reject, "some error");
            //     aura_pending_req_destroy(p_req);
            //     continue;
            // }
            /* Stream has claimed ownership user_data */
            p_req->user_data = NULL;

            /**
             * This consumes request object fetch_ctx->req.
             */
            aura_h2_stream_claim_rt_request(c->conn->mc, stream, fetch_ctx->req);
            fetch_ctx->req = NULL;

            aura_pending_req_destroy(p_req);
            // aura_h2_client_flush(c);
            break;

        default:
            break;
        }
    }

    return A_H2_ERR_NONE;
}

int aura_h2_client_preface_setup(struct aura_h2_core *h2_c) {
    uint8_t *write_ptr, *conn_preface;
    struct aura_h2_pending_req *req;
    struct aura_h2_stream *stream;
    size_t len;
    int rv;

    app_debug(true, 0, "aura_h2_client_preface_setup <<<");
    // if (aura_sliding_buf_append(h2_c->scheduler.write_buf, aura_h2_conn_preface.base, aura_h2_conn_preface.len) < 0)
    //     return A_H2_INTERNAL_ERR;

    /**
     * Since this is the first byte of the connection.
     * Read pointer returns the correct pointer to
     * connection preface
     */
    // conn_preface = aura_sliding_buf_read_ptr(h2_c->scheduler.write_buf);

    /* setup settings and initial window update */
    // rv = aura_h2_setup_preface_settings(h2_c);
    if (rv < 0) {

        return rv;
    }

    /* pick the first stream queued */
    // req = NULL;
    // while (!aura_list_is_empty(&h2_c->pending_reqs)) {
    //     a_list_dequeue(req, &h2_c->pending_reqs, head);
    //     break;
    // }

    // aura_h2_conn_transition_state(h2_c, A_H2_CONN_STATE_FRAMES);
    // aura_h2_conn_transition_state_handler(h2_c, aura_h2_client_handle_queued_streams);
    return A_H2_ERR_NONE;
}

int aura_client_init(struct aura_srv_sock *sock, const char *host, int type) {
    struct addrinfo *aip, *addr, hint;
    int fd;
    int reuse = 1;
    int err = 0;

    app_debug(true, 0, "aura_client_init <<<<");
    memset(&hint, 0, sizeof(struct addrinfo));
    hint.ai_socktype = SOCK_STREAM;
    hint.ai_protocol = IPPROTO_TCP;
    hint.ai_flags = AI_NUMERICSERV | AI_ADDRCONFIG;

    if ((err = getaddrinfo(host, "9443", &hint, &addr)) < 0) {
        sys_debug(true, 0, "failed to resolve address %s", gai_strerror(err));
        return -1;
    }

    aip = addr;
    do {
        fd = socket(aip->ai_addr->sa_family, SOCK_STREAM, aip->ai_protocol);
        if (fd < 0) {
            continue;
        }

        if (connect(fd, aip->ai_addr, aip->ai_addrlen) == 0)
            break;
        close(fd);
    } while ((aip = aip->ai_next));

    /* No connect attempt worked */
    if (aip == NULL)
        return -1;

    if (aura_sock_init(sock, fd, aip->ai_addr, aip->ai_addrlen, 0) < 0)
        return -1;

    return 0;
}

int aura_client_handshake_init(struct aura_conn *conn) {
    ptls_buffer_t send_buf;
    int res, rv;
    size_t in_len;
    uint8_t cbuf_small[16384];
    ptls_iovec_t alpn_list[1];
    ptls_handshake_properties_t client_hs_prop = {{{{NULL}, ptls_iovec_init(NULL, 0)}}};

    ptls_buffer_init(&send_buf, cbuf_small, sizeof(cbuf_small));
    in_len = 0;
    static const ptls_iovec_t protocols[] = {{(uint8_t *)"h2", 2}};
    client_hs_prop.client.negotiated_protocols.list = protocols;
    client_hs_prop.client.negotiated_protocols.count = PTLS_ELEMENTSOF(protocols);
    /** @todo: Set this */

    ptls_set_server_name(conn->tls_ctx.ptls, conn->server_name.base, 0);
    res = ptls_handshake(conn->tls_ctx.ptls, &send_buf, NULL, &in_len, &client_hs_prop);
    if (send_buf.off > 0) {
        if (aura_write(conn->sock.sock_fd, send_buf.base, send_buf.off) < 0) {
            return -1;
        }
    }

    if (res == PTLS_ERROR_ASYNC_OPERATION || res == PTLS_ERROR_IN_PROGRESS) {
        return 0;
    }

    return -1;
}

/**
 * Create client requests
 */
int aura_h2_client_req_create(struct aura_js_fetch_ctx *fetch_ctx, struct aura_srv_ctx *srv_ctx) {
    struct aura_conn *conn;
    struct aura_h2_client_conn *c;
    struct aura_h2_stream *stream;
    struct aura_rh_map_key key;
    struct aura_pending_req *pending_req;
    Request *req = fetch_ctx->req;
    struct aura_mem_ctx *mc = srv_ctx->mc;
    int rv;

    if (aura_url_parse(mc, req->url.base, req->url.len, &req->parsed_url) < 0) {
        return -1;
    }

    /* Search in connection pool matching connection */
    aura_rh_map_key_init(&key, (uint64_t)req->parsed_url.authority.host.base, req->parsed_url.authority.host.len, A_RH_KEY_STR);

    pthread_mutex_lock(&srv_ctx->conn_pool.mutex);
    conn = aura_rh_map_get(&srv_ctx->conn_pool.pool, &key);

    if (!conn) {
        struct aura_srv_sock sock;

        conn = aura_conn_create(srv_ctx, false, true, false);
        if (!conn) {
            pthread_mutex_unlock(&srv_ctx->conn_pool.mutex);
            return -1;
        }

        if (aura_rh_map_put(&srv_ctx->conn_pool.pool, &key, conn) > 0) {
            aura_conn_destroy(conn);
            pthread_mutex_unlock(&srv_ctx->conn_pool.mutex);
            return -1;
        }
        pthread_mutex_unlock(&srv_ctx->conn_pool.mutex);

        /**
         * We don't lock the conn while doing
         * the heavy conn setup work, we only
         * lock while updating the state, since thats
         * the only thing other threads care about
         */
        if (aura_client_init(&conn->sock, req->parsed_url.authority.host.base, SOCK_STREAM) < 0) {
            rv = -1;
            goto err;
        }
        aura_conn_set_server_name(conn, req->parsed_url.authority.host.base, req->parsed_url.authority.host.len);

        /* Create underlying protocol ctx */
        // if (conn->protocol_callbacks.on_create(conn) < 0) {
        //     rv = -1;
        //     goto err;
        // }
        // h2_conn = conn->protocol_ctx.ctx;

        /* add to event loop */
        if (conn->srv_ctx->evt_loop->ops->add(conn->srv_ctx->evt_loop, conn->sock.sock_fd, conn, AURA_EVENT_READ) < 0) {
            rv = -1;
            goto err;
        }

        /* Initialize handshake after successful creation of connection */
        if (aura_client_handshake_init(conn) < 0) {
            conn->srv_ctx->evt_loop->ops->remove(conn->srv_ctx->evt_loop, conn->sock.sock_fd);
            rv = -1;
            goto err;
        }

        /* Attach request to run once handshake completes */
        pending_req = aura_pending_req_create(
          mc,
          A_PENDING_REQ_H2_JS,
          (void *)fetch_ctx,
          (user_data_destructor)aura_qjs_fetch_ctx_destroy,
          conn,
          req->parsed_url.authority.host.base,
          req->parsed_url.authority.host.len);
        if (!pending_req) {
            conn->srv_ctx->evt_loop->ops->remove(conn->srv_ctx->evt_loop, conn->sock.sock_fd);
            rv = -1;
            goto err;
        }

        aura_pending_req_add(&conn->srv_ctx->req_coord, pending_req);

    } else {
        pthread_mutex_unlock(&srv_ctx->conn_pool.mutex);

        /* lock the conn itself to check valid state */
        pthread_mutex_lock(&c->mutex);

        if (conn->state == A_CONN_STATE_CONNECTING) {
            pthread_mutex_unlock(&c->mutex);

            pending_req = aura_pending_req_create(
              mc,
              A_PENDING_REQ_H2_JS,
              (void *)fetch_ctx,
              (user_data_destructor)aura_qjs_fetch_ctx_destroy,
              conn,
              req->parsed_url.authority.host.base,
              req->parsed_url.authority.host.len);
            /* return to the caller so it errors fails js request immediately */
            if (!pending_req) {
                return -1;
            }

            aura_pending_req_add(&conn->srv_ctx->req_coord, pending_req);
            rv = 0;
        } else {
            /* Connection in ready state */

            c = &conn->h2_client;
            stream = aura_h2_conn_stream_open(
              &c->core,
              mc,
              c->core.next_stream_id,
              A_H2_STREAM_STATE_IDLE,
              0,
              (void *)fetch_ctx,
              (user_data_destructor)aura_qjs_fetch_ctx_destroy,
              false);
            if (!stream) {
                pthread_mutex_unlock(&c->mutex);
                return -1;
            }

            if (aura_h2_stream_claim_rt_request(mc, stream, req) < 0) {
                aura_h2_stream_destroy(stream, false);
                pthread_mutex_unlock(&c->mutex);
                return -1;
            }

            rv = aura_h2_client_request_send(&c->core, stream);
            if (rv < 0) {
                aura_h2_stream_destroy(stream, false);
                pthread_mutex_unlock(&c->mutex);
                return -1;
            }
            pthread_mutex_unlock(&c->mutex);

            rv = 0;
        }
    }

    return rv;

err:
    aura_cli_handle_conn_failure(conn);
    return rv;

    // else if (conn->state == A_CONN_STATE_CONNECTING) {
    //     pthread_mutex_unlock(&glob_conf->conn_pool.mutex);

    //     pending_req = aura_pending_req_create(
    //       mc,
    //       A_PENDING_REQ_H2_JS,
    //       (void *)fetch_ctx,
    //       aura_qjs_fetch_ctx_destroy,
    //       req->parsed_url.authority.host.base,
    //       req->parsed_url.authority.host.len);
    //     if (!pending_req) {
    //         conn->srv_ctx->evt_loop->ops->remove(conn->srv_ctx->evt_loop, conn->sock.sock_fd);
    //         rv = -1;
    //         goto err;
    //     }

    //     aura_pending_req_add(&conn->srv_ctx->pending_req_coord, pending_req);

    // pending_req = aura_alloc(mc, sizeof(*pending_req));
    // if (!pending_req) {
    //     pthread_mutex_unlock(&glob_conf->conn_pool.mutex);
    //     // aura_conn_destroy(conn);
    //     return -1;
    // }

    // aura_list_head_init(&pending_req->head);
    // pending_req->req = req;
    // pending_req->user_data = user_data;
    // aura_list_add_tail(&h2_conn->pending_reqs, &pending_req->head);

    // pthread_mutex_unlock(&glob_conf->conn_pool.mutex);
    //     rv = 0;
    // }
    // else if (conn->state == A_CONN_STATE_CLOSING) {
    // }
    // else {
    //     /* Connection in ready state */
    //     pthread_mutex_unlock(&glob_conf->conn_pool.mutex);

    //     h2_conn = conn->protocol_ctx.ctx;
    //     stream = aura_h2_conn_stream_open(h2_conn, h2_conn->next_stream_id, A_H2_STREAM_STATE_IDLE, 0, user_data);
    //     if (!stream) {
    //         pthread_mutex_unlock(&glob_conf->conn_pool.mutex);
    //         return -1;
    //     }

    //     if (aura_h2_stream_claim_rt_request(stream, req) < 0) {
    //         pthread_mutex_unlock(&glob_conf->conn_pool.mutex);
    //         return -1;
    //     }

    //     pthread_mutex_unlock(&glob_conf->conn_pool.mutex);
    //     rv = 0;
    // }

    // return rv;

    // err:
    //     aura_cli_handle_conn_failure(conn);
    //     return rv;

    // if (conn->state == A_CONN_STATE_PROCESS_REQ) {
    //     pthread_mutex_unlock(&glob_conf->conn_pool.mutex);
    //     h2_conn = conn->protocol_ctx.ctx;
    //     stream = aura_h2_conn_stream_open(h2_conn, h2_conn->next_stream_id, A_H2_STREAM_STATE_IDLE, 0, user_data);
    //     if (!stream) {
    //         return -1;
    //     }

    //     return 0;
    // }

    /* Create new connection  */
    // conn = aura_conn_create(&glob_conf->mem_ctx, false, true, false);
    // if (!conn)
    //     return -1;

    // if (aura_client_init(&conn->sock, req->parsed_url.authority.host.base, SOCK_STREAM) < 0) {
    //     aura_conn_destroy(conn);
    //     return -1;
    // }
    // aura_conn_set_server_name(conn, req->parsed_url.authority.host.base);

    // if (aura_rh_map_put(&glob_conf->conn_pool, &key, conn) > 0) {
    //     aura_conn_destroy(conn);
    //     return -1;
    // }

    // /* Create underlying protocol ctx */
    // if (conn->protocol_callbacks.on_create(conn) < 0) {
    //     aura_conn_destroy(conn);
    //     return -1;
    // }
    // h2_conn = conn->protocol_ctx.ctx;

    // /* Attach request to be created once handshake completes */
    // /** @todo: could leave in its own function */
    // struct aura_h2_pending_req *pending_req;
    // pending_req = aura_alloc(mc, sizeof(*pending_req));
    // if (!pending_req) {
    //     aura_conn_destroy(conn);
    //     return -1;
    // }
    // aura_list_head_init(&pending_req->head);
    // pending_req->req = req;
    // pending_req->user_data = user_data;
    // aura_list_add_tail(&h2_conn->pending_reqs, &pending_req->head);

    // /* Store peer socket in sock map */
    // conn->srv_ctx->glob_conf->conn_map[conn->sock.sock_fd] = conn;

    // /* add to event loop */
    // if (conn->srv_ctx->evt_loop->ops->add(conn->srv_ctx->evt_loop, conn->sock.sock_fd, conn, AURA_EVENT_READ) < 0) {
    //     aura_conn_destroy(conn);
    //     return -1;
    // }

    // /* Initialize handshake after successful creation of connection */
    // if (aura_client_handshake_init(conn) < 0) {
    //     conn->srv_ctx->evt_loop->ops->remove(conn->srv_ctx->evt_loop, conn->sock.sock_fd);
    //     aura_conn_destroy(conn);
    //     return -1;
    // }

    // return 0;
}

void aura_h2_fetch_ctx_req_destroy(void *data) {
    struct aura_h2_pending_req *p_req = data;
    struct aura_js_fetch_ctx *fetch_ctx;

    if (!p_req)
        return;

    // if (p_req->req)
    //     aura_rt_req_destroy(p_req->req);

    // fetch_ctx = p_req->user_data;
    // if (fetch_ctx)
    //     aura_qjs_fetch_ctx_destroy(fetch_ctx);

    aura_free(p_req);
}

void aura_cli_handle_conn_failure(struct aura_conn *conn) {
    struct aura_rh_map_key key;
    struct aura_h2_client_conn *c = &conn->h2_client;

    /* Search in connection pool matching connection */
    aura_rh_map_key_init(&key, (uint64_t)conn->server_name.base, conn->server_name.len, A_RH_KEY_STR);

    /**
     * acquire global pool mutex, remove conn
     * so new threads can't see it completely,
     */
    pthread_mutex_lock(&conn->srv_ctx->conn_pool.mutex);
    aura_rh_map_del(&conn->srv_ctx->conn_pool.pool, &key, NULL);
    pthread_mutex_unlock(&conn->srv_ctx->conn_pool.mutex);

    /**
     * Lock conn mutex and update state,
     */
    pthread_mutex_lock(&c->mutex);
    // aura_conn_transition_state(c, A_CONN_STATE_CLOSING);
    pthread_mutex_unlock(&c->mutex);

    /**
     * Collect the pending requests to fail
     */
    struct aura_list_head fail_list;
    struct aura_pending_req *p_req, *next_req;

    aura_list_head_init(&fail_list);
    pthread_mutex_lock(&conn->srv_ctx->req_coord.mutex);
    while (!aura_list_is_empty(&conn->srv_ctx->req_coord.head)) {
        a_list_dequeue(p_req, &conn->srv_ctx->req_coord.head, p_list);
        aura_list_move(&fail_list, &p_req->p_list);
    }
    // a_list_for_each_safe_to_delete(p_req, next_req, &conn->srv_ctx->req_coord.head, p_list) {
    //     if (p_req->associated_handler == conn) {
    //         aura_list_delete(p_req);
    //         aura_list_add_tail(&fail_list, &p_req->p_list);
    //     }
    // }
    pthread_mutex_unlock(&conn->srv_ctx->req_coord.mutex);

    /* Fail to collected requests */
    struct aura_js_fetch_ctx *fetch_ctx;
    while (!aura_list_is_empty(&fail_list)) {
        a_list_dequeue(p_req, &conn->srv_ctx->req_coord.head, p_list);

        fetch_ctx = p_req->user_data;
        aura_qjs_trigger_promise_rejection(fetch_ctx->ctx, fetch_ctx->reject, "SOME ERROR");
        aura_pending_req_destroy(p_req);
    }

    /* Clean up failed conn */
    aura_conn_destroy(conn);
}

int aura_process_frame(struct aura_h2_core *h2_c) {
    struct aura_h2_in_frame in_frame;
    int res, len;
    int frame_len;
    uint8_t *src;

    static int (*frame_handlers[])(struct aura_h2_core *h2_c, struct aura_h2_in_frame *frame) = {
      //   [A_H2_FRAME_TYPE_DATA] = a_process_data,
      //   [A_H2_FRAME_TYPE_HDRS] = a_process_header,
      //   [A_H2_FRAME_TYPE_PRIO] = aura_process_priority,
      //   [A_H2_FRAME_TYPE_RST] = aura_h2_conn_process_rst_stream,
      //   [A_H2_FRAME_TYPE_SETTINGS] = aura_h2_conn_process_settings,
      //   [A_H2_FRAME_TYPE_PUSH_PROMISE] = a_process_push_promise,
      //   [A_H2_FRAME_TYPE_PING] = aura_process_ping,
      //   [A_H2_FRAME_TYPE_GOAWAY] = aura_h2_conn_process_goaway,
      //   [A_H2_FRAME_TYPE_WIND_UPDATE] = aura_h2_conn_process_wind_update,
      //   [A_H2_FRAME_TYPE_CONT] = aura_h2_conn_process_cont,
    };

    // len = aura_sliding_buf_read_len(h2_conn->conn->plain_read_buf);
    // src = aura_sliding_buf_read_ptr(h2_conn->conn->plain_read_buf);

    res = aura_h2_parse_frame_header(&in_frame, src, len, h2_c->peer_settings.max_frame_size);
    if (res != A_H2_ERR_NONE)
        return res;

    frame_len = A_H2_FRAME_HEADER_SIZE + in_frame.frame.len;
    if (in_frame.frame.type >= ARRAY_SIZE(frame_handlers)) {
        /* Consume and ignore unknown frame types */
        // aura_sliding_buf_consume(h2_c->conn->plain_read_buf, frame_len);
        return res;
    }

    res = frame_handlers[in_frame.frame.type](h2_c, &in_frame);
    // aura_sliding_buf_consume(h2_conn->conn->plain_read_buf, frame_len);
    return res;
}