#ifndef AURA_CONN_H
#define AURA_CONN_H

#include "http_lib.h"
#include "list_lib.h"
#include "picotls.h"
#include "slab_lib.h"
#include "socket_srv.h"
#include <stdbool.h>
#include <stdint.h>

#define A_H2_CONNECTION_PREFACE "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

typedef enum {
    A_CONN_STATE_NONE,
    A_CONN_STATE_CONNECTING,
    A_CONN_STATE_TLS_HANDSHAKE,
    A_CONN_STATE_READ_REQ,
    A_CONN_STATE_PROCESS_REQ,
    A_CONN_STATE_SEND_RESP,
    A_CONN_STATE_SEND_REQ,
    A_CONN_STATE_READ_RESP,
    A_CONN_STATE_CLOSING
} aura_conn_state_t;

struct aura_conn;

struct aura_conn_prot_callbacks {
    /**
     * callback to create protocol conn structure
     */
    int (*on_create)(struct aura_conn *conn);
    /**
     * destroy a procotol conn
     */
    void (*on_destroy)(struct aura_conn *conn);
    /**
     * schedule data for protocol
     */
    int (*on_schedule)(struct aura_conn *conn, void *dest);
};

struct aura_conn_callbacks {
    int (*on_read)(struct aura_conn *conn);
    int (*on_write)(struct aura_conn *conn);
    int (*state_handler)(struct aura_conn *conn);
};

typedef int (*aura_conn_state_handler)(struct aura_conn *conn);

/* Generic connection structure */
struct aura_conn {
    struct aura_srv_sock sock; /* socket that accepted this conn */
    struct aura_memory_ctx *mc;
    struct aura_srv_ctx *srv_ctx; /* global server context */
    struct aura_route *route;     /* route that handles this connection */
    struct aura_tls_ctx *tls_ctx;
    struct {
        int (*protocol_state_handler)(void *ctx);
        void *ctx;
    } protocol_ctx;          /* H2, H3 .... */
    aura_conn_state_t state; /* connection state */
    bool is_server;
    struct aura_conn_callbacks callbacks;
    struct aura_conn_prot_callbacks protocol_callbacks;
    aura_conn_state_handler state_handler; /* current state handler function */
    bool in_active;
    bool in_reap;
    union {
        bool tcp;
        bool quic;
    } type;
    uint32_t host_conf_off;          /* offset within the global host list(array) */
    struct aura_srv_host_conf *host; /* host configuration */

    ptls_log_conn_state_t ptls_log_state;
    struct aura_sliding_buf *plain_read_buf;
    struct aura_sliding_buf *plain_write_buf;

    struct aura_list_head c_list; /* for keeping track in queue */
    struct aura_list_head send_iov_list;
    struct aura_list_head tasks; /* List of tasks queue for execution */
    bool in_write_queue;
};

/* Create Generic connection */
struct aura_conn *aura_conn_create(struct aura_memory_ctx *mc, bool is_server, bool is_tls, bool is_quic);

/* Free Generic connection */
void aura_conn_destroy(struct aura_conn *);

/**
 * Attach specific protocol callbacks on connection
 */
void aura_conn_prot_attach_callbacks(struct aura_conn *conn, int protocol);

/**
 * Attach connection callbacks
 */
void aura_conn_attach_callbacks(struct aura_conn *conn, bool is_quic);

/**
 * TCP event handler, called by the designated listener
 * when polling returns.
 */
int aura_conn_tcp_listener_event_handler(struct aura_srv_listener *listener, struct aura_srv_ctx *srv_ctx);
int aura_conn_listener_event_handler(struct aura_srv_listener *listener, struct aura_srv_ctx *srv_ctx);

/* Process ready connection */
void aura_conn_process_active_queue(struct aura_srv_ctx *srv_ctx);

/* Process completions from runtime engines */
void aura_conn_process_completions(struct aura_srv_ctx *srv_ctx);

/* Destroy connections ready for destruction */
void aura_conn_process_reap_queue(struct aura_srv_ctx *srv_ctx);

/* Print connection Details */
void aura_dump_conn(struct aura_conn *conn);

/* Transition connection state */
static inline void aura_conn_transition_state(struct aura_conn *conn, aura_conn_state_t new_state) {
    if (conn->state != new_state)
        conn->state = new_state;
}

/* Transition connection state handler */
static inline void aura_conn_transition_state_handler(struct aura_conn *conn, aura_conn_state_handler handler) {
    if (conn->state_handler != handler)
        conn->state_handler = handler;
}

static inline bool aura_conn_should_close(struct aura_conn *conn) {
    return conn->state == A_CONN_STATE_CLOSING;
}

static inline ptls_log_conn_state_t *a_get_conn_log_state(struct aura_conn *conn) {
    return &conn->ptls_log_state;
}

#endif