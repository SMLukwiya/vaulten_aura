#ifndef AURA_TLS_H
#define AURA_TLS_H

#include "bug_lib.h"
#include "error_lib.h"
#include "memory_lib.h"
#include "picotls.h"

#define A_MAX_RECORD_TLS_RECORD_SIZE 16384

/* Aura tls context structure */
struct aura_tls_ctx {
    ptls_t *ptls;
    size_t record_overhead;
    struct {
        union {
            struct {
                enum {
                    A_ASYNC_RESUMPTION
                } state;
            } server;
            struct {
                const char *server_name;
            } client;
        };
    } handshake;
    struct aura_sliding_buf *encrypted_read_buf;
    struct aura_sliding_buf *encrypted_write_buf;
    struct {
        ptls_buffer_t w_buf;
        bool in_flight;
        bool sock_closed;
    } async;
};

/**
 * Decrypt received bytes using ptls negotiated parameters
 */
int aura_tls_input_decode(ptls_t *ptls, struct aura_sliding_buf *in_buf, struct aura_sliding_buf *out_buf);

/**
 * Encrypt given bytes using ptls for wire transfer
 */
ssize_t aura_tls_input_encode(struct aura_tls_ctx *tls_ctx, struct aura_list_head *head);

void aura_tls_free(struct aura_tls_ctx *tls_ctx);

#endif
