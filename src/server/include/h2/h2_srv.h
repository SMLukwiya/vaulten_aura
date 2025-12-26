#ifndef AURA_H2_H
#define AURA_H2_H

#include "bug_lib.h"
#include "h2/connection.h"
#include "memory_lib.h"
#include "slab_lib.h"

typedef enum {
    A_H2_PROCESS_OK,
    A_H2_PROCESS_DROP,
    A_H2_PROCESS_BACKPRESSURE,
    A_H2_PROCESS_REJECT,
    A_H2_PROCESS_TERMINATE
} aura_h2_process_result_t;

#define A_H2_DEFAULT_OUTPUT_BUF_SIZE 81920          /* connection flow control window plus alpha */
#define A_H2_DEFAULT_OUTPUT_BUF_SOFT_MAX 524288     /* 512KB */
#define A_H2_DEFAULT_OUTPUT_BUF_WRITE_TIMEOUT 60000 /* 60s close if write not complete */

/**
 * Create response for error on given stream
 * closing the stream after submitting
 */
int aura_submit_error_response(struct aura_h2_conn *conn, struct aura_h2_stream *stream, int status);

/**
 * Send tls data or plain data to socket fd
 */
void aura_socket_write(struct aura_srv_sock *sock);

/**
 * Construct a response to send to the peer
 */
size_t aura_submit_response(struct aura_h2_conn *conn, int status, struct aura_http_hdr_set *hdrs,
                            size_t num_of_hdrs, uint32_t stream_id, size_t content_length,
                            struct aura_sliding_buf *buf, bool end_stream);

#endif