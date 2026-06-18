#ifndef AURA_H2_SRV_H
#define AURA_H2_SRV_H

#include "core.h"
#include "error_lib.h"
#include "h2/session.h"
#include "h2/stream.h"
#include "memory_lib.h"
#include "types_lib.h"

#include <stdint.h>

#define A_H2_SRV_DATA_BUF_SZ 4096 /* 4KB */

struct aura_h2_server_conn;

typedef int (*aura_h2_srv_state_handler)(struct aura_h2_server_conn *c, struct aura_sliding_buf *buf);

/* H2 server conn structure */
struct aura_h2_server_conn {
    struct aura_h2_core core;
    struct aura_conn *conn; /* Generic connection to which protocol belongs */
    aura_h2_conn_state_t state;
    uint32_t flags;
    aura_h2_srv_state_handler state_handler;
    struct {
        struct timespec started_at;
        struct timespec settings_sent_at;
        struct timespec settings_ack_at;
    } timestamps;
};

/* Returns true if this is stream id was created by us */
static inline bool aura_h2_srv_conn_stream_is_local(uint32_t stream_id) {
    if (likely(stream_id == 0))
        return false;

    return aura_h2_stream_is_even_numbered(stream_id);
}

/* Return true if this a new stream id from peer */
static inline bool aura_h2_srv_conn_peer_stream_id_new(struct aura_h2_core *h2_c,
                                                       uint32_t stream_id) {
    if (!aura_h2_srv_conn_stream_is_local(stream_id))
        return false;

    return stream_id > h2_c->max_received_stream_id;
}

static inline bool aura_h2_srv_conn_stream_state_violation(struct aura_h2_core *h2_c,
                                                           uint32_t stream_id) {
    if (aura_h2_srv_conn_stream_is_local(stream_id)) {
        if (stream_id > h2_c->max_sent_stream_id)
            return true;
        return false;
    }

    if (aura_h2_srv_conn_peer_stream_id_new(h2_c, stream_id))
        return true;

    return false;
}

static inline void aura_h2_srv_conn_consume_window(int64_t *avail, uint64_t bytes) {
    *avail -= bytes;
}

/**
 * Test if we can open a new stream on
 * this current connection
 * @todo: both checks may be redundant
 */

static inline bool aura_h2_srv_conn_new_streams_allowed(struct aura_h2_server_conn *c) {
    if (c->state == A_H2_CONN_STATE_CLOSING)
        return false;

    if (aura_h2_conn_max_conc_out_streams_reached(&c->core) ||
        aura_h2_conn_max_conc_in_streams_reached(&c->core))
        return false;

    return aura_h2_conn_new_streams_allowed(&c->core);
}

/* Returns true if error is fatal */
static inline bool aura_h2_conn_error_is_fatal(int err) {
}

/**
 * Create response for error on given stream
 * closing the stream after submitting
 */
int aura_h2_submit_error_response(struct aura_h2_core *h2_conn, struct aura_h2_stream *stream, int status);

/**
 * Construct a response to send to the peer
 */
int aura_h2_submit_rt_response(struct aura_h2_core *h2_conn, struct aura_h2_stream *stream,
                               Response *resp, struct aura_mem_ctx *mc);

/* Create h2 server connection */
struct aura_h2_server_conn *aura_h2_srv_conn_create(struct aura_mem_ctx *mc);
int aura_h2_srv_conn_init(struct aura_h2_server_conn *c, struct aura_mem_ctx *mc);

/* Destroy h2 connection */
void aura_h2_srv_conn_destroy(struct aura_h2_server_conn *h2_c);

/* H2 connection handler */
int aura_h2_srv_process(struct aura_h2_server_conn *c, struct aura_sliding_buf *buf);

/* Change server connection state */
static inline void aura_h2_srv_on_handshake_complete(struct aura_h2_server_conn *c) {
    c->state = A_H2_CONN_STATE_PREFACE;
    c->state_handler = aura_h2_srv_process;
}

#endif