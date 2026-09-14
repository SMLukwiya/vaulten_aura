#include "connection.h"
#include "data_path/data_path.h"
#include "executors/js/quickjs/bindings.h"
#include "h2/scheduler.h"
#include "picotls.h"
#include "server_srv.h"
#include "socket_srv.h"
#include "time_lib.h"
#include "tls_srv.h"

extern struct aura_srv_global_conf *glob_conf;

int aura_conn_handle_handshake(struct aura_conn *conn);
void aura_conn_reschedule_active_timer(struct aura_conn *conn);
int aura_conn_update_timer(struct aura_conn *conn, aura_conn_deadline_t type);

struct aura_dp_result aura_handshake_hook(struct aura_dp_msg *dp_msg);
struct aura_dp_result aura_tls_decrypt_hook(struct aura_dp_msg *dp_msg);
struct aura_dp_result aura_h2_server_process_hook(struct aura_dp_msg *msg);
struct aura_dp_result aura_h2_server_write_hook(struct aura_dp_msg *dp_msg);

/**
 * Retrieve generic conn cache slab and allocate a slot
 */
static inline struct aura_conn *a_conn_alloc(struct aura_mem_ctx *mc) {
    struct aura_slab_cache *sc;
    struct aura_conn *conn;

    sc = NULL;
    sc = aura_slab_cache_find_by_id(mc, A_SLAB_CACHE_GENERIC_CONN);

    A_BUG_ON_2(!sc, true);
    conn = aura_slab_alloc(sc, sizeof(*conn));
    return conn;
}

void aura_conn_timer_cb(struct aura_timer_node *tn) {
    struct aura_conn *conn;

    conn = tn->user_data;
    aura_conn_destroy(conn);
}

static inline void a_conn_deadline_init(struct aura_deadline *dl, uint64_t expires_at, uint32_t flags) {
    dl->at = expires_at;
    dl->flags = flags;
}

static struct aura_dp_pipeline_hook AURA_HANDSHAKE_PIPELINE[] = {
  {.fn_name = "Handshake", .fn = aura_handshake_hook},
};

static struct aura_dp_pipeline_hook PRODUCTION_INBOUND_PIPELINE[] = {
  {.fn_name = "TLS_Decryption", .fn = aura_tls_decrypt_hook},
  {.fn_name = "HTTP2_Parser", .fn = aura_h2_server_process_hook},
  {.fn_name = "HTTP2 writer", .fn = aura_h2_server_write_hook},
};

static struct aura_dp_pipeline_hook CLEARTEXT_TEST_PIPELINE[] = {
  {.fn_name = "HTTP2_Parser", .fn = aura_h2_server_process_hook},
  {.fn_name = "HTTP2 writer", .fn = aura_h2_server_write_hook},
};

struct aura_conn_ops conn_ops = {
  .on_deadline_update = aura_conn_update_timer,
  .on_timer_update = aura_conn_reschedule_active_timer,
};

/**/
struct aura_conn *aura_conn_create(struct aura_srv_ctx *s_ctx, bool is_server,
                                   bool is_tls, a_transport_protocol prot) {
    struct aura_mem_ctx *mc = &s_ctx->glob_conf->mem_ctx;
    struct aura_conn *conn;
    struct aura_conn_tab_ent *tab_ent;
    uint32_t tab_ent_idx;
    uint64_t now;

    app_debug(true, 0, ">>>> aura_conn_create");
    conn = a_conn_alloc(mc);
    if (!conn)
        return NULL;
    memset(conn, 0, sizeof(*conn));

    conn->is_server = is_server;
    conn->ev_src.ev_type = A_EV_TYPE_CONN;
    conn->sock.sock_fd = A_INVALID_SOCK_FD;
    conn->mc = mc;
    conn->srv_ctx = s_ctx;
    conn->prot_type = prot;
    /* Set conn protocol ops */
    conn->ops = &conn_ops;
    aura_conn_transition_state(conn, A_CONN_STATE_CONNECTING);

    /* insert conn into global conn tab, get tab index */
    tab_ent_idx = aura_dyn_dense_pool_lease(s_ctx->conn_tab);
    if (tab_ent_idx == A_DENSE_POOL_INVALID_IDX)
        goto exception_conn;
    /* Get table slot */
    tab_ent = aura_dyn_dense_pool_get_slot(s_ctx->conn_tab, tab_ent_idx);
    tab_ent->conn = conn;
    conn->conn_tab_idx = tab_ent_idx;
    conn->conn_id = tab_ent->generation;

    aura_list_head_init(&conn->c_list);
    aura_list_head_init(&conn->tasks);

    if (aura_sliding_buf_init(&conn->plain_read_buf, mc, 0, A_SLIDING_BUF_FL_NONE) < 0)
        goto exception_buf;

    if (aura_sliding_buf_init(&conn->residual_buf, mc, 0, A_SLIDING_BUF_FL_NONE) < 0) {
        goto exception_buf;
    }

    /** @todo: make TO configurable */
    now = aura_now_ms(CLOCK_MONOTONIC);
    a_conn_deadline_init(&conn->deadlines.keep_alive, now + a_time_s_to_ms(30), A_TIMER_FLAG_EXTENDABLE | A_TIMER_FLAG_TERMINAL | A_TIMER_FLAG_ACTIVE);
    a_conn_deadline_init(&conn->deadlines.lifetime, now + a_time_s_to_ms(30 * 60), A_TIMER_FLAG_TERMINAL | A_TIMER_FLAG_ACTIVE);
    a_conn_deadline_init(&conn->deadlines.goaway_final, UINT64_MAX, A_TIMER_FLAG_TERMINAL | A_TIMER_FLAG_ACTIVE);
    a_conn_deadline_init(&conn->deadlines.goaway_gracious, UINT64_MAX, A_TIMER_FLAG_TERMINAL | A_TIMER_FLAG_ACTIVE);
    a_conn_deadline_init(&conn->deadlines.throttle, UINT64_MAX, A_TIMER_FLAG_TERMINAL | A_TIMER_FLAG_ACTIVE);

    aura_timer_node_init(&conn->timer, NULL, UINT64_MAX, conn);
    aura_conn_reschedule_active_timer(conn);

    if (is_tls) {
        conn->is_secure = true;
        conn->tls_ctx.async.wait_fd = -1;

        if (aura_sliding_buf_init(&conn->tls_ctx.encrypted_read_buf, mc, A_MAX_RECORD_TLS_BUFFER_SIZE, A_SLIDING_BUF_FL_NONE) < 0) {
            goto exception_buf;
        }
        if (aura_sliding_buf_init(&conn->tls_ctx.encrypted_write_buf, mc, 0, A_SLIDING_BUF_FL_NONE) < 0) {
            aura_sliding_buf_destroy(&conn->tls_ctx.encrypted_read_buf);
            goto exception_buf;
        }

        /* create tls ctx for new conn */
        if (conn->is_server)
            conn->tls_ctx.ptls = ptls_server_new(conn->srv_ctx->glob_conf->listeners.tls_pool.entries[0].contexts.ptls.ctx);
        else
            conn->tls_ctx.ptls = ptls_client_new(conn->srv_ctx->glob_conf->listeners.tls_pool.entries[0].contexts.ptls.client_ctx);

        /* Attach sock as opaque data to tls object */
        *ptls_get_data_ptr(conn->tls_ctx.ptls) = conn;
        aura_conn_transition_state(conn, A_CONN_STATE_HANDSHAKE);
        aura_list_add_tail(&s_ctx->queues.handshake, &conn->c_list);
        aura_conn_attach_inbound_hooks(conn, AURA_HANDSHAKE_PIPELINE, ARR_CNT(AURA_HANDSHAKE_PIPELINE));
    } else {
        aura_conn_transition_state(conn, A_CONN_STATE_ACTIVE);
        aura_conn_attach_inbound_hooks(conn, CLEARTEXT_TEST_PIPELINE, ARR_CNT(CLEARTEXT_TEST_PIPELINE));
        /**
         * Assume h2 as default and attach
         * protocol ops immediately
         */
        aura_conn_prot_attach_ops(conn, prot);
        aura_list_add_tail(&s_ctx->queues.active, &conn->c_list);
    }

    return conn;

exception_buf:
    aura_sliding_buf_destroy(&conn->plain_read_buf);

exception_conn:
    aura_slab_free(conn);
    return NULL;
}

/**/
void aura_conn_destroy(struct aura_conn *conn) {
    if (!conn)
        return;

    app_debug(true, 0, "A_CONN_DESTROY");
    if (conn->sock.sock_fd != A_INVALID_SOCK_FD)
        close(conn->sock.sock_fd);

    if (conn->is_secure)
        aura_tls_free(&conn->tls_ctx);

    aura_sliding_buf_destroy(&conn->plain_read_buf);
    aura_sliding_buf_destroy(&conn->residual_buf);

    if (conn->prot_ops)
        /* underlying protocol was setup */
        conn->prot_ops->destroy(conn);

    aura_timer_shutdown(&conn->srv_ctx->timer_wheel, &conn->timer);

    /* Release conn table slot */
    struct aura_conn_tab_ent *te = aura_dyn_dense_pool_get_slot(conn->srv_ctx->conn_tab, conn->conn_tab_idx);
    /* invalidate generation */
    te->generation++;
    aura_dyn_dense_pool_release(conn->srv_ctx->conn_tab, conn->conn_tab_idx);

    if (!conn->is_server) {
        app_debug(true, 0, "A_CONN_DESTROY_CLIENT");
        /* Clear from connection pool if client */
        struct aura_rh_map_key key;

        aura_rh_map_key_init(&key, (uint64_t)conn->server_name.base, conn->server_name.len, A_RH_KEY_STR);
        aura_rh_map_del(&conn->srv_ctx->conn_pool.pool, &key, NULL);
        aura_free(conn->server_name.base);

        /**
         * Collect cli pending requests to fail
         */
        struct aura_list_head fail_list;
        struct aura_pending_req *p_req, *next_req;

        aura_list_head_init(&fail_list);
        pthread_mutex_lock(&conn->srv_ctx->req_coord.mutex);
        while (!aura_list_is_empty(&conn->srv_ctx->req_coord.head)) {
            a_list_dequeue(p_req, &conn->srv_ctx->req_coord.head, p_list);
            aura_list_move(&fail_list, &p_req->p_list);
        }

        pthread_mutex_unlock(&conn->srv_ctx->req_coord.mutex);

        /* Fail the collected requests */
        struct aura_qjs_fetch_ctx *fetch_ctx;
        while (!aura_list_is_empty(&fail_list)) {
            a_list_dequeue(p_req, &conn->srv_ctx->req_coord.head, p_list);

            switch (p_req->type) {
            case A_PENDING_REQ_H2_JS:
                fetch_ctx = p_req->user_data;
                aura_qjs_trigger_promise_rejection(fetch_ctx->ctx, fetch_ctx->reject, "SOME ERROR");
                aura_pending_req_destroy(p_req);
                break;

            default:
                break;
            }
        }
    }

    aura_slab_free(conn);
}

/* Initialize H2 server protocol structure */
static int aura_conn_h2_srv_prot_init(struct aura_conn *conn) {
    struct aura_h2_server_conn *c = &conn->h2_server;

    if (aura_h2_srv_conn_init(c, conn->mc) < 0)
        return -1;

    return 0;
}

/* Destroy H2 server protocol */
static void aura_conn_h2_srv_prot_destroy(struct aura_conn *conn) {
    struct aura_h2_server_conn *c = &conn->h2_server;
    aura_h2_srv_conn_destroy(c);
}

/* Process H2 server protocol data */
static int aura_conn_h2_srv_prot_process(struct aura_conn *conn) {
    struct aura_h2_server_conn *c = &conn->h2_server;
    int rv;

    app_debug(true, 0, ">>>> aura_conn_h2_srv_prot_process");
    while (!aura_sliding_buf_is_empty(&conn->plain_read_buf)) {
        rv = c->state_handler(c, &conn->plain_read_buf);
        rv = aura_h2_get_app_error(rv);
        if (rv != A_ERR_NONE)
            break;
    }
    return rv;
}

struct aura_dp_result aura_h2_server_process_hook(struct aura_dp_msg *dp_msg) {
    struct aura_conn *conn = dp_msg->owner;
    struct aura_h2_server_conn *c = &conn->h2_server;
    int rv;
    struct aura_dp_result result = {
      .rv = A_DP_HOOK_DONE,
      .target_idx = dp_msg->active_idx,
    };

    app_debug(true, 0, ">>>> aura_h2_server_process_hook");

    rv = c->state_handler(c, &dp_msg->buf);
    app_debug(true, 0, ">>>> aura_h2_server_process_hook rv=%d", rv);

    switch (rv) {
    case A_ERR_AGAIN:
        result.rv = A_DP_HOOK_WAIT;
        break;

    case A_ERR_FATAL:
        result.rv = A_DP_HOOK_ERR;
        break;

    case A_ERR_NONE:
    default:
        break;
    }
    result.target_idx = ++dp_msg->active_idx;

    return result;
}

struct aura_dp_result aura_h2_server_write_hook(struct aura_dp_msg *dp_msg) {
    struct aura_conn *conn = dp_msg->owner;
    struct aura_h2_server_conn *c = &conn->h2_server;
    int rv;
    struct aura_dp_result result = {
      .rv = A_DP_HOOK_DONE,
      .target_idx = dp_msg->active_idx,
    };

    rv = aura_h2_srv_write(c);

    switch (rv) {
    case A_ERR_AGAIN:
        result.rv = A_DP_HOOK_WAIT;
        break;

    case A_ERR_FATAL:
        result.rv = A_DP_HOOK_ERR;
        break;

    case A_ERR_NONE:
    default:
        break;
    }
    result.target_idx = ++dp_msg->active_idx;

    return result;
}

/* Process server handshake completion */
static void aura_conn_h2_srv_prot_handshake_comp(struct aura_conn *conn) {
    struct aura_h2_server_conn *c = &conn->h2_server;
    aura_h2_srv_on_handshake_complete(c);
}

static struct aura_conn_prot_ops aura_conn_h2_srv_ops = {
  .init = aura_conn_h2_srv_prot_init,
  .destroy = aura_conn_h2_srv_prot_destroy,
  .process = aura_conn_h2_srv_prot_process,
  .handshake_complete = aura_conn_h2_srv_prot_handshake_comp,
};

/* Attach server conn protocol operations */
void aura_conn_prot_attach_srv_ops(struct aura_conn *conn, int protocol) {
    if (protocol == A_PROTOCOL_TCP) {
        conn->prot_ops = &aura_conn_h2_srv_ops;
    }
}

/* Create H2 client connection structure */
static int aura_conn_h2_cli_prot_init(struct aura_conn *conn) {
    struct aura_h2_client_conn *c = &conn->h2_client;

    if (aura_h2_client_conn_init(c, conn->mc) < 0)
        return -1;

    return 0;
}

/* Destroy H2 client protocol */
static void aura_conn_h2_cli_prot_destroy(struct aura_conn *conn) {
    struct aura_h2_client_conn *c = &conn->h2_client;
    aura_h2_cli_conn_destroy(c);
}

/* Process H2 protocol data */
static int aura_conn_h2_cli_process(struct aura_conn *conn) {
    struct aura_h2_client_conn *c = &conn->h2_client;
    return c->state_handler(c);
}

/* Process client handshake completion */
static void aura_conn_on_handshake_complete_cli_prot(struct aura_conn *conn) {
    struct aura_h2_client_conn *c = &conn->h2_client;
    aura_h2_cli_on_handshake_complete(c);
}

static struct aura_conn_prot_ops aura_conn_h2_cli_ops = {
  .init = aura_conn_h2_cli_prot_init,
  .destroy = aura_conn_h2_cli_prot_destroy,
  .process = aura_conn_h2_cli_process,
  .handshake_complete = aura_conn_on_handshake_complete_cli_prot,
};

/* Attach client conn protocol operations */
void aura_conn_prot_attach_cli_ops(struct aura_conn *conn, int protocol) {
    if (protocol == A_PROTOCOL_TCP) {
        conn->prot_ops = &aura_conn_h2_cli_ops;
    }
}

void aura_conn_prot_attach_ops(struct aura_conn *conn, int prot) {
    if (conn->is_server) {
        aura_conn_prot_attach_srv_ops(conn, prot);
    } else {
        aura_conn_prot_attach_cli_ops(conn, prot);
    }
}

static int aura_conn_handshake(struct aura_conn *conn) {
    ssize_t n_read;
    uint8_t *src;
    size_t read_len, write_len;
    struct aura_dp_msg msg;
    int64_t rv, fd = conn->sock.sock_fd;

    aura_dp_msg_init(&msg);
    aura_dp_msg_attach_inbound_hook(&msg, conn->in_hooks, conn->in_hooks_cnt);
    aura_dp_msg_attach_owner(&msg, (void *)&conn->tls_ctx);

    /* async handshake resumption */
    if (conn->tls_ctx.async.wait_fd != -1) {
        if (aura_sliding_buf_copy(&msg.buf, &conn->residual_buf) < 0)
            return A_ERR_FATAL;

    } else {
        read_len = aura_sliding_buf_read_len(&conn->residual_buf);
        /**
         * We choked in the previous tick,
         * flush out first
         */
        if (read_len > 0) {
            src = aura_sliding_buf_read_ptr(&conn->residual_buf);
            rv = aura_write(conn->sock.sock_fd, src, read_len);
            if (rv < 0)
                return A_ERR_FATAL;
            else if (rv != read_len) {
                aura_sliding_buf_consume(&conn->residual_buf, rv);
                return A_ERR_AGAIN;
            }

            aura_sliding_buf_consume(&conn->residual_buf, rv);
        }

        /**
         * Initialize msg buffer as we know
         * its x-tics
         */
        if (aura_sliding_buf_init(&msg.buf, conn->mc, A_HANDSHAKE_BUF_SZ, A_SLIDING_BUF_FL_MOVABLE | A_SLIDING_BUF_FL_COMPACTABLE) < 0)
            return A_ERR_FATAL;

        rv = aura_sliding_buf_append_from_fd(&msg.buf, fd, A_HANDSHAKE_BUF_SZ);
        aura_hex_dump_syslog(LOG_INFO, "HANDSHAKE", aura_sliding_buf_read_ptr(&msg.buf), rv);
        if (rv < 0) {
            aura_dp_msg_destroy(&msg);
            return A_ERR_FATAL;
        }

        if (rv == 0) {
            aura_dp_msg_destroy(&msg);
            return A_ERR_AGAIN;
        }
    }

    rv = aura_dp_pipeline_execute(&msg);
    switch (rv) {
    case A_DP_HOOK_WAIT:
        if (aura_sliding_buf_copy(&conn->residual_buf, &msg.buf) < 0) {
            rv = A_ERR_FATAL;
        } else
            rv = A_ERR_AGAIN;
        break;

    case A_DP_HOOK_ERR:
        rv = A_ERR_FATAL;
        break;

    case A_DP_HOOK_DONE:
    default:
        rv = A_ERR_NONE;
        break;
    }

    aura_dp_msg_destroy(&msg);
    return rv;
}

static inline int a_conn_handshake_complete(struct aura_conn *conn) {
    A_BUG_ON_2(conn->tls_ctx.async.in_flight, true);

    app_debug(true, 0, ">>>> a_conn_handshake_complete:");
    if (conn->tls_ctx.async.sock_closed) {
        /**
         * Remove conn from conn pool and
         * move it to reap queue and
         * prepare for destruction
         */
        if (!conn->is_server) {
            struct aura_rh_map_key key;

            aura_rh_map_key_init(&key, (uint64_t)conn->server_name.base, conn->server_name.len, A_RH_KEY_STR);

            pthread_mutex_unlock(&conn->srv_ctx->conn_pool.mutex);
            aura_rh_map_del(&conn->srv_ctx->conn_pool.pool, &key, NULL);
            pthread_mutex_unlock(&conn->srv_ctx->conn_pool.mutex);
        } else {
            aura_conn_transition_state(conn, A_CONN_STATE_CLOSING);
        }

        return -1;
    }

    conn->tls_ctx.record_overhead = ptls_get_record_overhead(conn->tls_ctx.ptls);
    aura_conn_attach_inbound_hooks(conn, PRODUCTION_INBOUND_PIPELINE, ARR_CNT(PRODUCTION_INBOUND_PIPELINE));
    aura_conn_transition_state(conn, A_CONN_STATE_ESTABLISHED);

    const char *prot = ptls_get_negotiated_protocol(conn->tls_ctx.ptls);
    if (strncasecmp(prot, "h2", sizeof("h2") - 1) == 0) {
        aura_conn_prot_attach_ops(conn, A_PROTOCOL_TCP);
        if (conn->prot_ops->init(conn) < 0)
            return -1;
        conn->prot_ops->handshake_complete(conn);
    }

    return 0;
}

static int a_handle_handshake_async(struct aura_tls_ctx *tls_ctx, ptls_buffer_t *w_buf) {
    ptls_async_job_t *async_job;
    struct aura_conn *conn;
    int wait_fd;

    app_debug(true, 0, ">>>> a_handle_handshake_async");
    A_BUG_ON_2(tls_ctx->async.in_flight, true);
    tls_ctx->async.in_flight = true;

    /* retain ptls write buf */
    tls_ctx->async.w_buf = *w_buf;
    async_job = ptls_get_async_job(tls_ctx->ptls);
    wait_fd = async_job->get_fd(async_job);
    tls_ctx->async.wait_fd = wait_fd;

    /* Add wait fd to epoll */
    conn = aura_container_of(tls_ctx, struct aura_conn, tls_ctx);
    if (aura_evt_loop_add(conn->srv_ctx->evt_loop, wait_fd, conn, AURA_EVENT_READ) < 0)
        return -1;

    return 0;
}

struct aura_dp_result aura_handshake_hook(struct aura_dp_msg *dp_msg) {
    struct aura_tls_ctx *tls_ctx = dp_msg->owner;
    ptls_buffer_t w_buf;
    struct aura_conn *conn;
    uint8_t *read_ptr;
    size_t consumed;
    ssize_t written;
    int rv;
    struct aura_dp_result result = {
      .rv = A_DP_HOOK_DONE,
      .target_idx = dp_msg->active_idx,
    };

    app_debug(true, 0, ">>>> aura_handshake_hook");
    /* Remove from polling loop */
    if (tls_ctx->async.wait_fd == -1) {
        ptls_buffer_init(&w_buf, "", 0);
    } else {
        w_buf = tls_ctx->async.w_buf;
        tls_ctx->async.w_buf = (ptls_buffer_t){NULL};
        A_BUG_ON_2(!tls_ctx->async.in_flight, true);
        tls_ctx->async.in_flight = false;
        tls_ctx->async.wait_fd = -1;
    }

    read_ptr = aura_sliding_buf_read_ptr(&dp_msg->buf);
    consumed = aura_sliding_buf_read_len(&dp_msg->buf);
    rv = ptls_handshake(tls_ctx->ptls, &w_buf, read_ptr, &consumed, NULL);
    aura_sliding_buf_consume(&dp_msg->buf, consumed);

    if (rv == PTLS_ERROR_ASYNC_OPERATION) {
        if (a_handle_handshake_async(tls_ctx, &w_buf) < 0)
            result.rv = A_DP_HOOK_ERR;
        else
            result.rv = A_DP_HOOK_WAIT;

        return result;
    }

    /* send stuff if available */
    if (w_buf.off != 0) {
        conn = aura_container_of(tls_ctx, struct aura_conn, tls_ctx);
        written = aura_write(conn->sock.sock_fd, w_buf.base, w_buf.off);
        if (written < 0) {
            result.rv = A_DP_HOOK_ERR;
            return result;
        } else if (written != w_buf.off) {
            /** @todo: choked, add to residual, keep tract we are still in handshake */
            result.rv = A_DP_HOOK_WAIT;
            return result;
        }
    }
    ptls_buffer_dispose(&w_buf);

    /**
     * Check for APLN regardless of handshake outcome
     * It would be null since we only set it for h2
     */
    if (!ptls_get_negotiated_protocol(tls_ctx->ptls)) {
        app_debug(true, 0, "Missing negotiated alpn");
        result.rv = A_DP_HOOK_ERR;
        return result;
    }

    if (rv == 0) {
        if (a_conn_handshake_complete(conn) < 0)
            result.rv = A_DP_HOOK_ERR;
        else
            result.rv = A_DP_HOOK_DONE;
    } else if (rv == PTLS_ERROR_IN_PROGRESS) {
        result.rv = A_DP_HOOK_WAIT;
        return result;
    } else {
        result.rv = A_DP_HOOK_ERR;
        return result;
    }

    result.target_idx = ++dp_msg->active_idx;
    return result;
}

struct aura_dp_result aura_tls_decrypt_hook(struct aura_dp_msg *dp_msg) {
    struct aura_conn *conn = dp_msg->owner;
    struct aura_tls_ctx *tls = &conn->tls_ctx;
    struct aura_dp_result result = {
      .rv = A_DP_HOOK_DONE,
      .target_idx = dp_msg->active_idx,
    };

    app_debug(true, 0, ">>>> aura_tls_decrypt_hook");
    int rv = aura_tls_input_decode(tls->ptls, &dp_msg->buf, &conn->send_close_notify);
    if (rv < 0) {
        result.rv = A_DP_HOOK_ERR;
    } else if (rv == PTLS_ERROR_IN_PROGRESS) {
        result.rv = A_DP_HOOK_WAIT;
    } else {
        /* Decryption successful */
        result.rv = A_DP_HOOK_CONT;
    }
    /* Move to next index */
    result.target_idx = ++dp_msg->active_idx;

    return result;
}

int aura_conn_tcp_listener_event_handler(struct aura_srv_listener *listener, struct aura_srv_ctx *srv_ctx) {
    struct aura_conn *conn;
    bool is_tls;

    app_debug(true, 0, "aura_conn_tcp_listener_event_handler <<<< listener_fd=%d", listener->fd);
    is_tls = listener->tls;
    conn = aura_conn_create(srv_ctx, true, is_tls, A_PROTOCOL_TCP);
    if (!conn)
        return -1;

    if (aura_sock_accept(&conn->sock, listener->fd, is_tls, 0) < 0) {
        aura_conn_destroy(conn);
        return -1;
    }

    /* Add peer socket in sock map */
    // aura_conn_add_to_conn_map(srv_ctx, conn);

    /* Add peer sock fd to poll */
    if (aura_evt_loop_add(srv_ctx->evt_loop, conn->sock.sock_fd, conn, AURA_EVENT_READ) < 0) {
        aura_conn_destroy(conn);
        return -1;
    }

    return 0;
}

void aura_conn_process_handshake_queue(struct aura_srv_ctx *srv_ctx) {
    struct aura_conn *conn, *_c;
    int rv;

    aura_list_for_each_safe_to_delete(conn, _c, &srv_ctx->queues.handshake, c_list) {
        rv = aura_conn_handshake(conn);

        switch (rv) {
        case A_ERR_AGAIN:
            break;

        case A_ERR_FATAL:
            aura_list_move(&srv_ctx->queues.reap, &conn->c_list);
            break;

        case A_ERR_NONE:
            aura_list_move(&srv_ctx->queues.active, &conn->c_list);
            break;

        default:
            break;
        }
    }
}

static void aura_conn_send_close_notify(struct aura_conn *conn) {
    int64_t rv;

    app_debug(true, 0, "aura_conn_send_close_notify <<< send=%d", conn->send_close_notify);
    if (conn->is_secure) {
        struct aura_tls_ctx *tls = &conn->tls_ctx;

        if (aura_sliding_buf_is_empty(&conn->residual_buf) && conn->send_close_notify) {
            rv = aura_tls_send_close_notify(tls->ptls, conn->sock.sock_fd);
            if (rv < 0) {
                app_debug(true, 0, "RACE: Client don't care about recipricol notify");
            }
            aura_conn_transition_state(conn, A_CONN_STATE_CLOSING);
        }
    }
}

static int aura_conn_process(struct aura_conn *conn) {
    uint8_t *src;
    size_t read_len;
    struct aura_dp_msg msg;
    int64_t rv;
    int fd = conn->sock.sock_fd;

    aura_dp_msg_init(&msg);
    aura_dp_msg_attach_inbound_hook(&msg, conn->in_hooks, conn->in_hooks_cnt);
    aura_dp_msg_attach_owner(&msg, (void *)conn);

    /**
     * We choked in the previous tick,
     * flush out first
     */
    if (!aura_sliding_buf_is_empty(&conn->residual_buf)) {
        read_len = aura_sliding_buf_read_len(&conn->residual_buf);
        src = aura_sliding_buf_read_ptr(&conn->residual_buf);

        rv = aura_write(conn->sock.sock_fd, src, read_len);
        if (rv < 0)
            return A_ERR_FATAL;
        else if (rv != read_len) {
            aura_sliding_buf_consume(&conn->residual_buf, rv);
            return A_ERR_AGAIN;
        }

        aura_sliding_buf_consume(&conn->residual_buf, rv);
        /* Try to send close notify if it can be sent */
        aura_conn_send_close_notify(conn);

        /* Move to close conn if applicable */
        if (aura_conn_should_close(conn)) {
            app_debug(true, 0, "CONN CLOSED after residual bytes");
            return A_ERR_NONE;
        }
    }

    /**
     * Initialize msg buffer as we know
     * its x-tics
     */
    if (aura_sliding_buf_init(&msg.buf, conn->mc, A_CONN_PROCESS_BUF_SZ, A_SLIDING_BUF_FL_MOVABLE | A_SLIDING_BUF_FL_COMPACTABLE) < 0)
        return A_ERR_FATAL;

    rv = aura_sliding_buf_append_from_fd(&msg.buf, fd, A_CONN_PROCESS_BUF_SZ);
    if (rv < 0) {
        aura_dp_msg_destroy(&msg);
        return A_ERR_FATAL;
    }

    if (rv == 0) {
        aura_dp_msg_destroy(&msg);
        return A_ERR_AGAIN;
    }

    rv = aura_dp_pipeline_execute(&msg);
    switch (rv) {
    case A_DP_HOOK_WAIT:
        if (aura_sliding_buf_copy(&conn->residual_buf, &msg.buf) < 0) {
            rv = A_ERR_FATAL;
        } else
            rv = A_ERR_AGAIN;
        break;

    case A_DP_HOOK_ERR:
        rv = A_ERR_FATAL;
        break;

    case A_DP_HOOK_DONE:
    default:
        rv = A_ERR_NONE;
        break;
    }

    aura_dp_msg_destroy(&msg);

    /* try and send close notify if applicable */
    if (rv == A_ERR_NONE)
        aura_conn_send_close_notify(conn);

    return rv;
}

void aura_conn_process_active_queue(struct aura_srv_ctx *srv_ctx) {
    struct aura_conn *conn, *_c;
    struct aura_rh_map_key key;
    int64_t rv;

    aura_list_for_each_safe_to_delete(conn, _c, &srv_ctx->queues.active, c_list) {

        rv = aura_conn_process(conn);

        switch (rv) {
        case A_ERR_AGAIN:
            /* Add back */
            break;

        case A_ERR_NONE:
            if (!aura_conn_should_close(conn)) {
                /* Run conn sentinel */
                aura_conn_sen_evaluate(&conn->sen, conn->prot_type);
                break;
            } else {
                aura_list_move(&srv_ctx->queues.reap, &conn->c_list);
                break;
            }

        case A_ERR_FATAL:
            srv_ctx->evt_loop->ops->remove(srv_ctx->evt_loop, conn->sock.sock_fd);
            /* move to reap */
            aura_list_move(&srv_ctx->queues.reap, &conn->c_list);

            /**
             * For client connections
             * Reap conn from conn pool, so worker threads don't
             * enqueue requests for it, defer the complete cleanup
             * in reap queue
             */
            if (!conn->is_server) {
                aura_rh_map_key_init(&key, (uint64_t)conn->server_name.base, conn->server_name.len, A_RH_KEY_STR);
                pthread_mutex_lock(&srv_ctx->conn_pool.mutex);
                aura_rh_map_del(&srv_ctx->conn_pool.pool, &key, NULL);
                pthread_mutex_unlock(&srv_ctx->conn_pool.mutex);

                // aura_h2_cli_conn_transition_state(conn->protocol_ctx, A_CONN_STATE_CLOSING);
            }
            break;

        default:
            break;
        }
    }
}

void aura_conn_process_completions(struct aura_srv_ctx *srv_ctx) {
    struct aura_completion *comp;
    struct aura_conn *conn;
    struct aura_h2_client_conn *c;
    struct aura_h2_stream *stream;
    struct _aura_task *task;
    _Response *resp;
    int rv = -256;

    while (!aura_list_is_empty(&srv_ctx->completions.list)) {
        pthread_mutex_lock(&srv_ctx->completions.lock);
        a_list_dequeue(comp, &srv_ctx->completions.list, c_list);
        pthread_mutex_unlock(&srv_ctx->completions.lock);
        aura_task_dump(comp->task);

        task = comp->task;
        conn = aura_dyn_dense_pool_get_slot(srv_ctx->conn_tab, task->conn_idx);
        if (!conn) {
            aura_completion_destroy(comp);
            return;
        }

        switch (task->protocol) {
        case A_TASK_PROTOCOL_H2:
            c = &conn->h2_client;
            resp = task->res_data;
            aura_rt_resp_dump(resp);
            A_BUG_ON_2(!resp, true);

            stream = aura_h2_conn_find_stream(&c->core, task->stream_id);
            if (!stream) {
                aura_completion_destroy(comp);
                /* update some starts */
                return;
            }

            rv = aura_h2_submit_rt_response(&c->core, stream, resp, srv_ctx->mc);
            aura_completion_destroy(comp);
            if (rv < 0) {
                aura_list_delete(&conn->c_list);
                aura_list_add_tail(&srv_ctx->queues.reap, &conn->c_list);
                aura_conn_transition_state(conn, A_CONN_STATE_CLOSING);
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

    while (!aura_list_is_empty(&srv_ctx->queues.reap)) {
        a_list_dequeue(conn, &srv_ctx->queues.reap, c_list);

        aura_conn_destroy(conn);
    }
}

static inline timer_cb aura_conn_get_next_timer_cb(struct aura_conn *conn) {
    timer_cb next_cb;

    switch (conn->timer_type) {
    case A_DL_CONN_LIFETIME:
    case A_DL_CONN_KEEPALIVE:
    case A_DL_CONN_GOAWAY_GRACIOUS:
    case A_DL_CONN_GOAWAY_FINAL:
        next_cb = aura_conn_timer_cb;
        break;

    case A_DL_CONN_THROTTLE:
    default:
        next_cb = NULL;
    }

    return next_cb;
}

void aura_conn_reschedule_active_timer(struct aura_conn *conn) {
    uint64_t min = UINT64_MAX;
    aura_conn_deadline_t next_type = A_DL_CONN_KEEPALIVE;
    timer_cb next_callback;

#define CHECK(dl, t)                                           \
    if (((dl).flags & A_TIMER_FLAG_ACTIVE) && (dl).at < min) { \
        min = (dl).at;                                         \
        next_type = t;                                         \
    }

    CHECK(conn->deadlines.keep_alive, A_DL_CONN_KEEPALIVE);
    CHECK(conn->deadlines.lifetime, A_DL_CONN_LIFETIME);
    CHECK(conn->deadlines.goaway_gracious, A_DL_CONN_GOAWAY_GRACIOUS);
    CHECK(conn->deadlines.goaway_final, A_DL_CONN_GOAWAY_FINAL);
    CHECK(conn->deadlines.throttle, A_DL_CONN_THROTTLE);

    conn->timer_type = next_type;

    next_callback = aura_conn_get_next_timer_cb(conn);
    aura_timer_modify_callback(&conn->timer, next_callback);
    aura_timer_modify(&conn->srv_ctx->timer_wheel, &conn->timer, min);
}

int aura_conn_update_timer(struct aura_conn *conn, aura_conn_deadline_t type) {
    uint64_t now = aura_now_ms(CLOCK_MONOTONIC);
    uint64_t new_deadline;

    switch (type) {
    case A_DL_CONN_GOAWAY_GRACIOUS:
        new_deadline = now + a_time_s_to_ms(5);
        aura_timer_node_deadline_forward(&conn->deadlines.goaway_gracious, new_deadline);
        break;

    case A_DL_CONN_GOAWAY_FINAL:

    default:
    }

    return 0;
}

void aura_dump_conn(struct aura_conn *conn) {
    app_debug(true, 0, "AURA_GENERIC_CONN");
    app_debug(true, 0, "    Is server: %d", conn->is_server);
    app_debug(true, 0, "    State: %d", conn->state);
    app_debug(true, 0, "    Type: %s", conn->prot_type ? "UDP" : "TCP");
    app_debug(true, 0, "    Sock_fd: %d", conn->sock.sock_fd);
}
