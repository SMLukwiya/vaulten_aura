#ifndef AURA_CONN_H
#define AURA_CONN_H

#include "conn_sentinel.h"
#include "h2/client.h"
#include "h2/server.h"
#include "http_lib.h"
#include "list_lib.h"
#include "picotls.h"
#include "protocol.h"
#include "slab_lib.h"
#include "socket_srv.h"
#include "string_lib.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>

#define A_MAX_SERVER_NAME 256
#define A_HANDSHAKE_BUF_SZ 4096 /* 4KB */

/* conn state */
typedef enum {
    A_CONN_STATE_NONE,
    A_CONN_STATE_CONNECTING,
    A_CONN_STATE_HANDSHAKE,
    A_CONN_STATE_ACTIVE,
    A_CONN_STATE_READ_REQ,
    A_CONN_STATE_SEND_REQ,
    A_CONN_STATE_PROCESS_REQ,
    A_CONN_STATE_READ_RESP,
    A_CONN_STATE_SEND_RESP,
    A_CONN_STATE_CLOSING
} aura_conn_state_t;

/* conn deadlines */
typedef enum {
    A_DL_CONN_KEEPALIVE,
    A_DL_CONN_LIFETIME,
    A_DL_CONN_GOAWAY_GRACIOUS,
    A_DL_CONN_GOAWAY_FINAL,
    A_DL_CONN_THROTTLE,
} aura_conn_deadline_t;

struct aura_conn;

/**
 * Operations to manage the
 * connection itself
 */
struct aura_conn_ops {
    /* called to read data from outside(socket fd) */
    ssize_t (*on_read)(struct aura_conn *conn);
    /* called to write data to the outside */
    ssize_t (*on_write)(const void *data, size_t len);
    /* handle current conn state, invoking prot specific op if needed */
    int (*state_handler)(struct aura_conn *conn);
    /* called on protocol specific events */
    void (*on_event)(struct aura_conn *conn, aura_conn_sen_events_t, void *data);
};

/**
 * Operations to manage the underlying
 * protocol
 */
struct aura_conn_prot_ops {
    /**
     * called to create underlying protocol conn
     */
    int (*init)(struct aura_conn *conn);
    /**
     * called destroy underlying procotol conn
     */
    void (*destroy)(struct aura_conn *conn);
    /**
     * called to process current underlying protocol
     */
    int (*process)(struct aura_conn *conn);
    /**
     * called to handle handshake completion
     * for underlying protocol
     */
    void (*handshake_complete)(struct aura_conn *conn);
};

typedef int (*aura_conn_state_handler)(struct aura_conn *conn);

/* Connection deadlines structure */
struct aura_conn_deadlines {
    struct aura_deadline keep_alive;
    struct aura_deadline lifetime;
    struct aura_deadline goaway_gracious;
    struct aura_deadline goaway_final;
    struct aura_deadline throttle;
};

/* Generic connection structure */
struct aura_conn {
    struct aura_evt_source ev_src;
    struct aura_mem_ctx *mc;
    struct aura_srv_sock sock;    /* socket that accepted this conn */
    uint32_t conn_id;             /* 32 bit generation */
    uint32_t conn_tab_idx;        /* 32 bit index  (indexed into conn table) */
    struct aura_srv_ctx *srv_ctx; /* global server context */
    struct aura_route *route;     /* route that handles this connection */
    union {
        struct aura_tls_ctx tls_ctx; /* TLS context attached to connection*/
    };

    union {
        struct aura_h2_server_conn h2_server;
        struct aura_h2_client_conn h2_client;
    };
    struct aura_conn_ops *ops;           /* Generic conn ops */
    struct aura_conn_prot_ops *prot_ops; /* Protocol ops to manage underlying protocol */
    struct aura_srv_host_conf *host;     /* host configuration */
    a_transport_protocol prot_type;
    aura_conn_state_t state; /* connection state */
    struct aura_conn_sentinel sen;

    ptls_log_conn_state_t ptls_log_state; /* Ptls logging state */
    struct aura_sliding_buf residual_buf; /* Store bytes when sock write chokes on current tick */
    struct aura_sliding_buf plain_read_buf;

    struct aura_list_head c_list; /* for keeping track in queue */
    struct aura_list_head tasks;  /* List of tasks queue for execution */

    struct aura_timer_node timer;         /* Timer node attached to the conn */
    struct aura_conn_deadlines deadlines; /* Deadlines applicable to connection */
    aura_conn_deadline_t timer_type;      /* The timer type that is legible to fire next */

    struct aura_iovec server_name;
    struct aura_dp_pipeline_hook *in_hooks; /* Inbound hooks */
    uint8_t in_hooks_cnt;                   /* Hooks count */
    bool is_server;                         /* Handling client connection */
    bool is_secure;                         /* Encrypted enabled connection */
};

/* Transition connection state */
static inline void aura_conn_transition_state(struct aura_conn *conn, aura_conn_state_t new_state) {
    if (conn->state != new_state)
        conn->state = new_state;
}

/* Transition connection state handler */
static inline void aura_conn_transition_state_handler(struct aura_conn *conn,
                                                      aura_conn_state_handler handler) {
    if (conn->ops->state_handler != handler)
        conn->ops->state_handler = handler;
}

static inline void aura_conn_attach_inbound_hooks(struct aura_conn *conn,
                                                  struct aura_dp_pipeline_hook *hooks,
                                                  uint8_t hook_cnt) {
    conn->in_hooks = hooks;
    conn->in_hooks_cnt = hook_cnt;
}

/* Check if conn should start destruction process */
static inline bool aura_conn_should_close(struct aura_conn *conn) {
    return conn->state == A_CONN_STATE_CLOSING;
}

/* Get conn ptls state */
static inline ptls_log_conn_state_t *a_get_conn_log_state(struct aura_conn *conn) {
    return &conn->ptls_log_state;
}

/**
 * Called by every thread that references
 * connection, last thread to execute
 */
// static inline void aura_conn_release(struct aura_conn *conn) {
//     if (!conn)
//         return;

//     if (atomic_fetch_sub(&conn->ref_cnt, 1) == 1) {
//         close(conn->sock.sock_fd);
//         pthread_mutex_destroy(&conn->mutex);
//         aura_free(conn);
//     }
// }

/**
 * Set server name on connection structure
 * Used by client connections only
 */
static inline void aura_conn_set_server_name(struct aura_conn *conn, const uint8_t *server_name, size_t len) {
    conn->server_name.base = aura_strndup(conn->mc, server_name, len);
    conn->server_name.len = len;
}

/* Create Generic connection */
struct aura_conn *aura_conn_create(struct aura_srv_ctx *s_ctx, bool is_server,
                                   bool is_tls, a_transport_protocol prot);

/* Perform logical destruction on Generic connection */
void aura_conn_destroy(struct aura_conn *);

/**
 * Attach specific protocol callbacks on connection
 */
void aura_conn_prot_attach_ops(struct aura_conn *conn, int protocol);

/**
 * Attach connection callbacks
 */
void aura_conn_attach_ops(struct aura_conn *conn, a_transport_protocol prot);

/**
 * TCP event handler, called by the designated listener
 * when polling returns.
 */
int aura_conn_tcp_listener_event_handler(struct aura_srv_listener *listener, struct aura_srv_ctx *srv_ctx);

/* Process handshake queue */
void aura_conn_process_handshake_queue(struct aura_srv_ctx *srv_ctx);

/* Process ready connection */
void aura_conn_process_active_queue(struct aura_srv_ctx *srv_ctx);

/* Process completions from runtime engines */
void aura_conn_process_completions(struct aura_srv_ctx *srv_ctx);

/* Destroy connections ready for destruction */
void aura_conn_process_reap_queue(struct aura_srv_ctx *srv_ctx);

/* Print connection Details */
void aura_dump_conn(struct aura_conn *conn);

void aura_conn_reschedule_active_timer(struct aura_conn *conn);

#endif