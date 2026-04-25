#include "connection.h"
#include "h2/h2_srv.h"
#include "h2/scheduler.h"
#include "picotls.h"
#include "server_srv.h"
#include "socket_srv.h"

extern struct aura_srv_global_conf *glob_conf;

int aura_conn_handle_handshake(struct aura_conn *conn);

/**
 * Retrieve generic conn cache slab and allocate a slot
 */
static inline struct aura_conn *a_conn_alloc(struct aura_memory_ctx *mc) {
    struct aura_slab_cache *sc;
    struct aura_conn *conn;

    sc = NULL;
    sc = aura_slab_cache_find_by_id(mc, A_SLAB_CACHE_GENERIC_CONNECTION);

    A_BUG_ON_2(!sc, true);
    conn = aura_slab_alloc(sc);
    return conn;
}

/**/
struct aura_conn *aura_conn_create(struct aura_memory_ctx *mc, bool is_server, bool is_tls, bool is_quic) {
    struct aura_conn *conn;

    app_debug(true, 0, "aura_conn_create <<<>>> is_server: %d", is_server);
    conn = a_conn_alloc(mc);
    if (!conn)
        return NULL;
    memset(conn, 0, sizeof(*conn));
    conn->is_server = is_server;
    aura_conn_transition_state(conn, A_CONN_STATE_CONNECTING);
    conn->mc = mc;
    conn->tls_ctx = NULL;

    if (is_tls) {
        conn->tls_ctx = aura_alloc(mc, sizeof(*(conn->tls_ctx)));
        if (!conn->tls_ctx)
            goto exception_conn;
        memset(conn->tls_ctx, 0, sizeof(*conn->tls_ctx));
        conn->tls_ctx->ptls = NULL;
    }
    conn->in_active = false;
    conn->in_reap = false;
    conn->srv_ctx = glob_conf->srv_ctx;
    if (is_quic) {
        conn->type.quic = true;
        conn->type.tcp = false;

    } else {
        conn->type.tcp = true;
        conn->type.quic = false;
    }
    conn->plain_read_buf = aura_sliding_buffer_create(mc, 0, false);
    conn->plain_write_buf = aura_sliding_buffer_create(mc, A_MAX_RECORD_TLS_RECORD_SIZE, true); /* cap at this value */

    if (!conn->plain_read_buf || !conn->plain_write_buf)
        goto exception_tls;

    a_list_head_init(&conn->c_list);
    a_list_head_init(&conn->send_iov_list);
    a_list_head_init(&conn->tasks);
    aura_conn_attach_callbacks(conn, is_quic);
    aura_conn_prot_attach_callbacks(conn, is_quic ? A_PROTOCOL_UDP : A_PROTOCOL_TCP);

    if (is_tls) {
        conn->tls_ctx->encrypted_read_buf = aura_sliding_buffer_create(mc, 4096, false);
        conn->tls_ctx->encrypted_write_buf = aura_sliding_buffer_create(mc, 0, false);
        if (!conn->tls_ctx->encrypted_read_buf || !conn->tls_ctx->encrypted_write_buf)
            goto exception_buf;

        /* create tls for new conn */
        if (conn->is_server)
            conn->tls_ctx->ptls = ptls_server_new(conn->srv_ctx->listener_conf->tls_pool.entries[0].contexts.ptls.ctx);
        else
            conn->tls_ctx->ptls = ptls_client_new(conn->srv_ctx->listener_conf->tls_pool.entries[0].contexts.ptls.client_ctx);
        *ptls_get_data_ptr(conn->tls_ctx->ptls) = conn;
        /* Attach sock as opaque data to tls object */
        aura_conn_transition_state(conn, A_CONN_STATE_TLS_HANDSHAKE);
        aura_conn_transition_state_handler(conn, aura_conn_handle_handshake);
    } else {
        aura_conn_transition_state(conn, A_CONN_STATE_READ_REQ);
        aura_conn_transition_state_handler(conn, aura_conn_handle_handshake);
    }

    return conn;

exception_buf:
    if (is_tls) {
        aura_sliding_buffer_destroy(conn->tls_ctx->encrypted_read_buf);
        aura_sliding_buffer_destroy(conn->tls_ctx->encrypted_write_buf);
    }
exception_tls:
    aura_sliding_buffer_destroy(conn->plain_read_buf);
    aura_sliding_buffer_destroy(conn->plain_write_buf);
    if (conn->tls_ctx)
        aura_free(conn->tls_ctx);
exception_conn:
    aura_slab_free(conn);
    return NULL;
}

/**/
void aura_conn_destroy(struct aura_conn *conn) {
    if (!conn)
        return;

    app_debug(true, 0, "aura_conn_destroy <<<");
    if (conn->tls_ctx)
        aura_tls_free(conn->tls_ctx);
    aura_sliding_buffer_destroy(conn->plain_read_buf);
    aura_sliding_buffer_destroy(conn->plain_write_buf);

    if (conn->protocol_ctx.ctx)
        conn->protocol_callbacks.on_destroy(conn);

    if (conn->route) {
    }

    while (!a_list_is_empty(&conn->send_iov_list)) {
        struct aura_h2_send_iov *send_iov;
        a_list_dequeue(send_iov, &conn->send_iov_list, list);
        free(send_iov);
    }

    /* clear from sock table */
    glob_conf->conn_map[conn->sock.sock_fd] = NULL;
    close(conn->sock.sock_fd);
    aura_slab_free(conn);
}

/** */
int aura_h2_conn_create(struct aura_conn *conn) {
    struct aura_h2_ctx *h2_ctx;
    app_debug(true, 0, "aura_h2_conn_create <<<");

    if (conn->is_server)
        h2_ctx = aura_h2_server_conn_create(conn->mc);
    else
        h2_ctx = aura_h2_client_conn_create(conn->mc);
    if (!h2_ctx)
        return -1;

    conn->protocol_ctx.ctx = h2_ctx;
    conn->protocol_ctx.protocol_state_handler = aura_h2_process;
    h2_ctx->conn = conn;

    return 0;
}

void aura_h2_conn_destroy(struct aura_conn *conn) {
    struct aura_h2_ctx *h2_ctx;
    h2_ctx = conn->protocol_ctx.ctx;
    aura_h2_ctx_destroy(h2_ctx);
}

void aura_conn_prot_attach_callbacks(struct aura_conn *conn, int protocol) {
    if (protocol == A_PROTOCOL_TCP) {
        conn->protocol_callbacks.on_create = aura_h2_conn_create;
        conn->protocol_callbacks.on_destroy = aura_h2_conn_destroy;
        conn->protocol_callbacks.on_schedule = aura_h2_schedule;
    }
}

int aura_conn_on_read_tcp(struct aura_conn *conn) {
    ssize_t n_read;
    size_t avail_write;
    struct aura_sliding_buf *buf;
    int fd = conn->sock.sock_fd;
    struct aura_tls_ctx *tls_ctx = conn->tls_ctx;
    struct aura_sliding_buf *plain_buf = conn->plain_read_buf;

    app_debug(true, 0, "a_sock_on_read_tcp_2 <<<<");
    if (tls_ctx) {
        buf = tls_ctx->encrypted_read_buf;
        avail_write = aura_sliding_buffer_available_write(buf);
        n_read = aura_sliding_buffer_append_from_fd(buf, fd, avail_write);
        if (n_read == -1) {
            sys_debug(true, errno, "a_sock_on_read_tcp: aura_sliding_buffer_append_from_fd error:");
            return A_PROGRESS_ERROR;
        }

        if (n_read == 0 && aura_sliding_buffer_is_empty(tls_ctx->encrypted_read_buf)) {
            /* rearm socket */
            return A_PROGRESS_BLOCKED;
        }

        /* Remove from polling loop */
        int res = aura_tls_input_decode(tls_ctx->ptls, tls_ctx->encrypted_read_buf, plain_buf);
        if (res < 0)
            return A_PROGRESS_ERROR;

        if (res == PTLS_ERROR_IN_PROGRESS)
            return A_PROGRESS_BLOCKED;

        return A_PROGRESS_DONE;

    } else {
        avail_write = aura_sliding_buffer_available_write(plain_buf);
        n_read = aura_sliding_buffer_append_from_fd(plain_buf, fd, avail_write);
        if (n_read == -1) {
            sys_debug(true, errno, "a_sock_on_read_tcp: aura_sliding_buffer_append_from_fd error:");
            return A_PROGRESS_ERROR;
        }

        if (n_read == 0 && aura_sliding_buffer_is_empty(plain_buf)) {
            /* rearm socket */
            return A_PROGRESS_BLOCKED;
        }
    }

    return A_PROGRESS_DONE;
}

ssize_t aura_conn_write_tls(int fd, struct aura_tls_ctx *tls_ctx, struct aura_list_head *send_iov_list) {
    ssize_t tls_bytes_written, encrypted_written;
    uint8_t *read_ptr;
    size_t read_len;
    struct aura_h2_send_iov *send_iov;

    app_debug(true, 0, "aura_conn_write_tls <<< sockfd: %d", fd);

    int res = aura_tls_input_encode(tls_ctx, send_iov_list);
    if (res < 0)
        return -1;

    /* nothing to write */
    if (res == 0)
        return 0;

    read_ptr = aura_sliding_buffer_read_pointer(tls_ctx->encrypted_write_buf);
    read_len = aura_sliding_buffer_available_read(tls_ctx->encrypted_write_buf);
    encrypted_written = aura_write(fd, read_ptr, read_len);
    if (encrypted_written == -1) {
        return -1;
    }

    aura_sliding_buffer_consume(tls_ctx->encrypted_write_buf, encrypted_written);

    /** @todo: check if all written, repeat write until all written */

    return encrypted_written;
}

int aura_conn_on_write_tcp(struct aura_conn *conn) {
    ssize_t bytes_written;
    struct aura_h2_send_iov *send_iov;
    app_debug(true, 0, "aura_conn_on_write_tcp <<<<");

    /*schedule*/
    while (true) {
        send_iov = aura_alloc(conn->mc, sizeof(*send_iov));
        if (!send_iov)
            return -1;

        app_debug(true, 0, "aura_conn_on_write_tcp_loop <<<<");
        if (conn->protocol_callbacks.on_schedule(conn, (void *)send_iov) < 0)
            break;
        a_list_add_tail(&conn->send_iov_list, &send_iov->list);
    }

    if (conn->tls_ctx->ptls != NULL) {
        bytes_written = aura_conn_write_tls(conn->sock.sock_fd, conn->tls_ctx, &conn->send_iov_list);
    } else {
        uint8_t *read_ptr;
        size_t read_len;

        read_ptr = aura_sliding_buffer_read_pointer(conn->plain_write_buf);
        read_len = aura_sliding_buffer_available_read(conn->plain_write_buf);
        bytes_written = aura_write(conn->sock.sock_fd, read_ptr, read_len);
        if (bytes_written == -1) {
            return -1;
        }

        aura_sliding_buffer_consume(conn->plain_write_buf, bytes_written);
    }
    return bytes_written;
}

void aura_conn_attach_callbacks(struct aura_conn *conn, bool is_quic) {
    if (is_quic) {

    } else {
        conn->callbacks.on_read = aura_conn_on_read_tcp;
        conn->callbacks.on_write = aura_conn_on_write_tcp;
    }
}

int aura_conn_on_readable(struct aura_conn *conn) {
    struct aura_h2_ctx *h2_conn;
    int rv;

    switch (conn->state) {
    case A_CONN_STATE_READ_REQ:
    case A_CONN_STATE_READ_RESP:
        rv = conn->callbacks.on_read(conn);
        if (rv == A_PROGRESS_ERROR)
            return rv;
        break;

    case A_H2_CONN_STATE_PREFACE:
    case A_H2_CONN_STATE_PREFACE_SETTINGS:
        if (conn->is_server) {
            rv = conn->callbacks.on_read(conn);
            if (rv == A_PROGRESS_ERROR)
                return rv;
        }
        break;
    }

    if (aura_sliding_buffer_is_empty(conn->plain_read_buf)) {
        return A_PROGRESS_BLOCKED;
    }

    if (!conn->protocol_ctx.ctx)
        if (conn->protocol_callbacks.on_create(conn) < 0)
            return A_PROGRESS_ERROR;

    rv = conn->protocol_ctx.protocol_state_handler(conn->protocol_ctx.ctx);
    return rv;
}

void a_on_async_job_complete(void *sock) {
    struct aura_srv_sock *a_sock = sock;
    // assert in flight

    // aura_handle_handshake(a_sock);
}

/**
 *
 */
static void aura_conn_handle_handshake_async(struct aura_conn *conn, ptls_buffer_t *w_buf) {
    ptls_async_job_t *job;
    // assert not currently in flight
    // set socket in fllight

    /* keep buffer and wait for next */
    if (conn->tls_ctx->ptls != NULL) {
        conn->tls_ctx->async.w_buf = *w_buf;
        *w_buf = (ptls_buffer_t){NULL};

        job = ptls_get_async_job(conn->tls_ctx->ptls);
        if (job->set_completion_callback != NULL) /* this should always pass */
            job->set_completion_callback(job, a_on_async_job_complete, conn);
    }
}

static inline void aura_conn_handshake_complete(struct aura_conn *conn) {
    app_debug(true, 0, ">>>>aura_handshake_complete:");
    int res;
    size_t len;

    assert(!conn->tls_ctx->async.in_flight);
    assert(conn->tls_ctx->ptls);

    if (conn->tls_ctx->async.sock_closed) {
        conn->state = A_H2_CONN_STATE_CLOSING;
        return;
    }

    conn->tls_ctx->record_overhead = ptls_get_record_overhead(conn->tls_ctx->ptls);
    aura_conn_transition_state(conn, A_CONN_STATE_READ_REQ);
    aura_conn_transition_state_handler(conn, aura_conn_on_readable);
}

/**
 *
 */
static inline void aura_conn_handshake_failed(struct aura_conn *conn) {
    app_debug(true, 0, ">>>> aura_conn_handshake_failed");
    /**/
}

int aura_conn_handle_handshake(struct aura_conn *conn) {
    app_debug(true, 0, ">>>> aura_conn_handle_handshake:");
    ptls_buffer_t w_buf;
    void *send_buf, *read_ptr;
    size_t consumed;
    int res, n_read;
    int ret_val;

    n_read = aura_sliding_buffer_append_from_fd(conn->tls_ctx->encrypted_read_buf, conn->sock.sock_fd, 4096);
    if (n_read == -1) {
        aura_conn_transition_state(conn, A_CONN_STATE_CLOSING);
        return A_PROGRESS_ERROR;
    }

    if (n_read == 0 && aura_sliding_buffer_is_empty(conn->tls_ctx->encrypted_read_buf))
        /* add back for polling */
        return A_PROGRESS_BLOCKED;

    if (conn->tls_ctx->async.w_buf.base != NULL) {
        w_buf = conn->tls_ctx->async.w_buf;
        conn->tls_ctx->async.w_buf = (ptls_buffer_t){NULL};
    } else
        ptls_buffer_init(&w_buf, "", 0);

    read_ptr = aura_sliding_buffer_read_pointer(conn->tls_ctx->encrypted_read_buf);
    consumed = aura_sliding_buffer_available_read(conn->tls_ctx->encrypted_read_buf);
    res = ptls_handshake(conn->tls_ctx->ptls, &w_buf, read_ptr, &consumed, NULL);
    aura_sliding_buffer_consume(conn->tls_ctx->encrypted_read_buf, consumed);

    if (res == PTLS_ERROR_ASYNC_OPERATION) {
        return A_PROGRESS_BLOCKED;
    }

    /* send stuff if available */
    if (w_buf.off != 0) {
        aura_write(conn->sock.sock_fd, w_buf.base, w_buf.off);
    }
    ptls_buffer_dispose(&w_buf);

    if (res == 0) {
        aura_conn_handshake_complete(conn);
        ret_val = A_PROGRESS_DONE;
    } else if (res == PTLS_ERROR_IN_PROGRESS) {
        /* add back so we can rearm conn fd and try again */
        ret_val = A_PROGRESS_BLOCKED;
    } else {
        aura_conn_handshake_failed(conn);
        ret_val = A_PROGRESS_ERROR;
    }

    return ret_val;
}

int aura_conn_tcp_listener_event_handler(struct aura_srv_listener *listener, struct aura_srv_ctx *srv_ctx) {
    struct aura_conn *conn;
    bool is_tls;

    app_debug(true, 0, "aura_conn_tcp_listener_event_handler <<<<");
    is_tls = listener->tls;

    conn = aura_conn_create(&glob_conf->mem_ctx, true, is_tls, listener->quic);
    if (!conn)
        return -1;

    if (aura_socket_accept(&conn->sock, listener->fd, is_tls, 0) < 0) {
        aura_conn_destroy(conn);
        return -1;
    }

    /* Store peer socket in sock map */
    conn->srv_ctx->glob_conf->conn_map[conn->sock.sock_fd] = conn;

    app_debug(true, 0, "SERVER CONNECTED FD: %d", conn->sock.sock_fd);
    /* Add peer sock fd to poll */ /** @todo: WRITE_EVENT */
    if (srv_ctx->evt_loop->ops->add(srv_ctx->evt_loop, conn->sock.sock_fd, AURA_EVENT_READ) < 0) {
        aura_conn_destroy(conn);
        return -1;
    }

    return 0;
}

int aura_conn_listener_event_handler(struct aura_srv_listener *listener, struct aura_srv_ctx *srv_ctx) {
    app_debug(true, 0, "aura_conn_listener_event_handler <<<< ");
    return 0;
}

void aura_conn_process_active_queue(struct aura_srv_ctx *srv_ctx) {
    struct aura_conn *conn;
    int res;

    // app_debug(true, 0, "aura_conn_process_active_queue <<<<");
    while (!a_list_is_empty(&srv_ctx->queues.active)) {
        a_list_dequeue(conn, &srv_ctx->queues.active, c_list);

        res = conn->state_handler(conn);
        if (!conn->is_server)
            aura_dump_conn(conn);

        switch (res) {
        case A_PROGRESS_BLOCKED:
            break;

        case A_PROGRESS_DONE:
            if (!aura_conn_should_close(conn)) {
                break;
            }
        case A_PROGRESS_ERROR:
            srv_ctx->evt_loop->ops->remove(srv_ctx->evt_loop, conn->sock.sock_fd);
            a_list_delete(&conn->c_list);
            a_list_add_tail(&srv_ctx->queues.reap, &conn->c_list);
            aura_conn_transition_state(conn, A_CONN_STATE_CLOSING);
            conn->in_reap = true;
            conn->in_active = false;
            break;
        }
    }
}

void aura_conn_process_completions(struct aura_srv_ctx *srv_ctx) {
    struct aura_completion *comp;
    struct aura_conn *conn;
    struct aura_task *task;
    Response *resp;
    int rv;

    while (!a_list_is_empty(&srv_ctx->completions.list)) {
        pthread_mutex_lock(&srv_ctx->completions.lock);
        a_list_dequeue(comp, &srv_ctx->completions.list, c_list);
        pthread_mutex_unlock(&srv_ctx->completions.lock);
        aura_task_dump(comp->task);

        switch (comp->task->protocol) {
        case A_TASK_PROTOCOL_H2:
            task = comp->task;
            conn = comp->task->conn;
            resp = task->res_data;
            aura_rt_resp_dump(resp);
            A_BUG_ON_2(!resp, true);
            rv = aura_h2_submit_rt_response(conn->protocol_ctx.ctx, task->stream, resp);
            if (rv < 0) {
                a_list_delete(&conn->c_list);
                a_list_add_tail(&srv_ctx->queues.reap, &conn->c_list);
                aura_conn_transition_state(conn, A_CONN_STATE_CLOSING);
                conn->in_reap = true;
                conn->in_active = false;
            }
            break;
        case A_TASK_PROTOCOL_H3:
        default:
            break;
        }
    }
}

void aura_conn_process_reap_queue(struct aura_srv_ctx *srv_ctx) {
    struct aura_conn *conn;

    while (!a_list_is_empty(&srv_ctx->queues.reap)) {
        /* @todo: remove from timer */
        a_list_dequeue(conn, &srv_ctx->queues.reap, c_list);

        aura_conn_destroy(conn);
    }
}

void aura_dump_conn(struct aura_conn *conn) {
    app_debug(true, 0, "AURA_GENERIC_CONN");
    app_debug(true, 0, "    Is server: %d", conn->is_server);
    app_debug(true, 0, "    State: %d", conn->state);
    app_debug(true, 0, "    Type: %s", conn->type.quic ? "UDP" : "TCP");
    app_debug(true, 0, "    Sock_fd: %d", conn->sock.sock_fd);
}