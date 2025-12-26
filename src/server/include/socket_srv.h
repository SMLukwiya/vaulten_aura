#ifndef AURA_SOCKET_H
#define AURA_SOCKET_H

#include "h2/connection.h"
#include "list_lib.h"
#include "memory_lib.h"
#include "optimization_srv.h"
#include "picotls.h"

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#define A_MAX_READ_PER_CONN (64 * 1024) /* 64KB */

#define A_INVALID_SOCK_FD -1
#define A_SOCK_LISTENER 0x1
#define A_SOCK_HANDSHAKE 0x2
#define A_SOCK_ESTABLISHED 0x4
#define A_SOCK_CLOSED 0x8

#define A_MAX_RECORD_TLS_RECORD_SIZE 16384
#define A_MAX_TRANSMISSION_UNIT_ESTIMATE 1500
#define A_TCP_IPV4_PLUS_IPV6_OVERHEAD_ESTIMATE 100

#define A_TLS_GENERATE_RECORD_ERROR SIZE_MAX

/**
 *
 */
struct aura_sock_tls_ctx {
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
    } async;
    struct aura_tls_record_config tls_config;
};

/**
 * Server socket structure
 */
struct aura_srv_sock {
    struct aura_sock_tls_ctx *tls_ctx; /* for tls handshake */
    int sock_fd;
    socklen_t sock_len;
    uint32_t flags;
    struct sockaddr_storage addr;
    uint32_t host_conf_off;

    union {
        struct aura_h2_conn *h2_conn; /* h2 connection associated with socket */
    };

    ptls_log_conn_state_t ptls_log_state;
    /**/
    struct aura_sliding_buf plain_read_buf;
    struct {
        struct aura_iovec buf;
        size_t pending_off;
    } write;
    size_t bytes_written;

    struct aura_list_head s_list; /* for keeping track in queue */
    bool in_write_queue;
};

/**
 * Allocate slot for new socket and create
 * sock tls context, sock address and buffers
 */
struct aura_srv_sock *aura_socket_create(struct aura_memory_ctx *mc, int fd, struct sockaddr *addr, socklen_t addr_len, int flags);

/**
 * Accept connection on socket descriptor @fd,
 * using these flags
 */
struct aura_srv_sock *aura_socket_accept(struct aura_memory_ctx *mc, int fd, int flags);
void aura_handle_handshake(struct aura_srv_sock *sock, struct aura_srv_ctx *srv_ctx);
void aura_socket_destroy(struct aura_srv_sock *sock);

/** */
ssize_t aura_read(int fd, void *buf, size_t len);

/**
 * Organise tls records and send them over
 */
ssize_t aura_sock_write_tls(struct aura_srv_sock *sock);

ssize_t aura_write(int fd, void *buf, size_t len);

/**/
void aura_conn_proceed(struct aura_srv_sock *sock, struct aura_srv_ctx *srv_ctx);
void aura_h2_proceed(struct aura_srv_sock *sock, struct aura_srv_ctx *srv_ctx);

/**
 * Decode received tls bytes using the negotiated
 * parameters
 */
int aura_decode_tls_input(struct aura_srv_sock *sock);

static inline ptls_log_conn_state_t *a_get_conn_log_state(struct aura_srv_sock *s) {
    return &s->ptls_log_state;
}

#endif