#ifndef AURA_SERVER_H
#define AURA_SERVER_H

#include "../infra/metrics/metrics_srv.h"
#include "../infra/timer/timer_srv.h"
#include "connection.h"
#include "db/db.h"
#include "dense_pool/dynamic.h"
#include "h2/hpack.h"
#include "hashmap/map.h"
#include "host.h"
#include "interned.h"
#include "list_lib.h"
#include "mem.h"
#include "optimizer.h"
#include "pending_req.h"
#include "radix/tree.h"
#include "runtime/completions.h"
#include "socket_srv.h"
#include "tls_srv.h"
#include "types_lib.h"
#include "utils_lib.h"

/* for general null terminated string */

#define AURA_QLEN 4096
#define A_MAX_FDS 65536 /** @todo: get from system */

#define A_CONN_TAB_INVALID_IDX UINT32_MAX
#define A_CONN_TAB_DEFAULT_SZ 512

/* Server queues structure */
struct aura_srv_req_queue {
    struct aura_list_head handshake; /* Hold handhake connections */
    struct aura_list_head active;    /* Hold read ready */
    struct aura_list_head reap;      /* Hold destruction ready */
};

/**
 * Listener config strucure: holds configs shared
 * by all listeners
 */
struct aura_srv_listeners_conf {
    struct aura_srv_listener_pool listeners_pool;
    struct aura_srv_tls_iden_pool tls_pool;
    ptls_t *ptls;
    struct aura_srv_host_conf *fb_host_conf; /* fallback host, if SNI lookup fails */
    aura_rax_tree_t *sni;                    /* radix tree */
};

/* connection pool structure */
struct aura_srv_conn_pool {
    struct aura_rh_map pool;
    pthread_mutex_t mutex;
};

/**
 * Connection table entry
 * Used to coordinate connection
 * async tasks
 */
struct aura_conn_tab_ent {
    struct aura_conn *conn;
    uint32_t generation;
};

/* Server general context structure */
struct aura_srv_ctx {
    struct aura_srv_global_ctx *glob_conf;
    struct aura_srv_conn_pool conn_pool;
    struct aura_dyn_dense_pool *conn_tab;
    struct aura_evt_loop *evt_loop;
    struct aura_mem_ctx *mc;
    struct aura_ipc_peer *dmn_peer; /* Daemon peer connection */
    struct {
        size_t idle_timeouts; /* number of http idle timeouts */
        size_t read_closed;   /* premature close on read */
        size_t write_closed;  /* premature close on write */
        size_t handshake_cnt;
        size_t read_cnt;
        size_t write_cnt;
        size_t timeout_cnt;
        // size_t aura_server_errors[10]; /** @todo: define AURA_SERVER_ERRORS */
    } h2;

    struct aura_req_coordinator req_coord; /* Pending request coordinator */

    struct aura_srv_req_queue queues;         /* Queues according to stage (handshake...etc) */
    struct aura_completion_queue completions; /* List of completions queued by runtime engines */

    uint64_t inflight; /* requests inflight */
    struct aura_timer_wheel timer_wheel;
    struct aura_srv_optimizer optimizer;
    uint64_t next_task_id;
    bool shutdown_requested; /* if shutdown has been requested */
};

/**
 * Global aura server configuration structure
 */
struct aura_srv_global_ctx {
    struct aura_iovec server_name; /* Server name */
    struct aura_srv_ctx *srv_ctx;
    struct aura_srv_listeners_conf listeners;
    struct aura_srv_host_pool host_pool;
    struct aura_mem_ctx mem_ctx;
    struct aura_iovec user;
    time_t boot_time; /* server boot time */
};

/**
 * Mark server has internal request
 */
static inline void aura_set_internal_request_active(struct aura_srv_ctx *ctx) {
    ctx->dmn_peer->active = true;
}

/**
 * Mark server internal request inactive
 */
static inline void aura_set_internal_request_inactive(struct aura_srv_ctx *ctx) {
    ctx->dmn_peer->active = false;
}

#endif