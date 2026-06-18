#ifndef AURA_TLS_H
#define AURA_TLS_H

#include "bug_lib.h"
#include "data_path/data_path.h"
#include "error_lib.h"
#include "memory_lib.h"
#include "picotls.h"
#include "picotls/certificate_compression.h"
#include "picotls/openssl.h"
#include "picotls/pembase64.h"

/** @todo: look into this. */
#define A_MAX_RECORD_TLS_BUFFER_SIZE (16384 + 4096)

#define A_SUGGESTED_TLS_RECORD_PAYLOAD_SZ 1400
#define A_TLS_MAX_RECORD_PAYLOAD_SZ (16 * 1024)
#define A_TLS_LARGE_RECORD_OVERHEAD (5 + 32)
#define A_TLS_SLICE_FLOOR 1200

/* OCSP updater structure */
struct aura_ocsp_updater {
    int timer_fd;
    time_t interval;
    uint32_t max_failures;
};

/* OCSP info structure */
struct aura_tls_ocsp_info {
    char *ocsp_url;
    time_t last_update;
    time_t next_update;
    size_t ocsp_response_len;
    uint8_t *ocsp_response;
};

/* A single identity structure */
struct aura_srv_tls_iden {
    const char *tag; /* TLS tag */
    struct {
        char *cert_file;
        size_t size;
    } cert;

    struct {
        char *key_file;
        size_t size;
    } key;

    struct {
        char *cert_chain_file;
        size_t size;
    } cert_chain;

    struct {
        struct {
            ptls_context_t *ctx;
            ptls_context_t *client_ctx;
            const ptls_openssl_signature_scheme_t *sig_schemes;
        } ptls;
        X509_STORE *store;
    } contexts;

    struct {
        struct aura_tls_ocsp_info ocsp_stapling;
        struct aura_ocsp_updater ocsp_updater;
    } ocsp;

    struct {
        ptls_emit_compressed_certificate_t *emit_ptls;
    } compressed_cert;
};

/* Tls identity pool structure  */
struct aura_srv_tls_iden_pool {
    struct aura_srv_tls_iden *entries;
    size_t cnt;
    size_t cap;
};

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
    struct aura_sliding_buf encrypted_read_buf;
    struct aura_sliding_buf encrypted_write_buf;
    struct {
        ptls_buffer_t w_buf;
        bool in_flight;
        bool sock_closed;
        int wait_fd;
    } async;
};

/**
 * Decrypt received bytes using ptls negotiated parameters
 */
int aura_tls_input_decode(ptls_t *ptls, struct aura_sliding_buf *in_buf, struct aura_sliding_buf *out_buf);
int aura_tls_input_decode2(ptls_t *ptls, struct aura_sliding_buf *buf);

/**
 * Encrypt given bytes using ptls for wire transfer
 */
ssize_t aura_tls_input_encode(struct aura_tls_ctx *tls_ctx, struct aura_list_head *head);
ssize_t aura_tls_encode(struct aura_tls_ctx *tls, uint8_t *data, size_t len,
                        int type, uint32_t stream_id, bool end_stream);

void aura_tls_free(struct aura_tls_ctx *tls_ctx);

#endif
