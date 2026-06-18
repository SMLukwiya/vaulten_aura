#ifndef AURA_H2_CLIENT_H
#define AURA_H2_CLIENT_H

#include <netdb.h>
#include <netinet/in.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>

#include "http_lib.h"
#include "memory_lib.h"
#include "runtime/js.h"
#include "runtime/request.h"
#include "session.h"
#include "slab_lib.h"

struct aura_h2_client_conn;

typedef int (*aura_h2_cli_state_handler)(struct aura_h2_client_conn *c);

/* H2 client conn structure */
struct aura_h2_client_conn {
    struct aura_h2_core core; /* Core H2 context */
    struct aura_conn *conn;
    aura_h2_conn_state_t state; /* Server state */
    uint32_t flags;
    aura_h2_cli_state_handler state_handler; /* Current routine called on received frames */
    struct {
        struct timespec settings_sent_at;
        struct timespec settings_ack_at;
    } timestamps;
    pthread_mutex_t mutex; /* Client lock */
    atomic_uint ref_cnt;   /* Client ref count */
};

/**
 * Transition H2 client connetion state
 */
static inline void aura_h2_cli_conn_transition_state(struct aura_h2_client_conn *c, aura_h2_conn_state_t state) {
    pthread_mutex_lock(&c->mutex);
    aura_h2_conn_transition_state(&c->state, state);
    pthread_mutex_unlock(&c->mutex);
}

/* called after successful handshake completion */
static inline void aura_h2_cli_on_handshake_complete(struct aura_h2_client_conn *c) {
    aura_h2_cli_conn_transition_state(c, A_H2_CONN_STATE_PREFACE);
}

/* Create h2 client connection */
int aura_h2_client_conn_init(struct aura_h2_client_conn *c, struct aura_mem_ctx *mc);

/* Destroy h2 client connection */
void aura_h2_cli_conn_destroy(struct aura_h2_client_conn *h2_c);

int aura_h2_client_req_create(struct aura_js_fetch_ctx *fetch_ctx, struct aura_srv_ctx *srv_ctx);

#endif