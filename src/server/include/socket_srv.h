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
#define A_SOCK_FLAG_LISTENER 0x1
#define A_SOCK_STATE_HANDSHAKE 0x2
#define A_SOCK_STATE_ESTABLISHED 0x4
#define A_SOCK_STATE_CLOSED 0x8

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
    struct aura_sock_tls_ctx *tls_ctx; /* for tls stuff */
    int sock_fd;
    socklen_t sock_len;
    uint8_t state;
    uint32_t flags;
    bool in_active;
    bool in_reap;
    bool is_idle;
    struct sockaddr_storage addr;
    uint32_t host_conf_off; /* offset within the global host list(array) */

    union {
        struct aura_h2_conn *h2_conn; /* h2 connection associated with socket */
    };

    ptls_log_conn_state_t ptls_log_state;
    /**/
    struct aura_sliding_buf plain_read_buf;
    struct aura_sliding_buf plain_write_buf;
    struct {
        struct aura_iovec buf;
        size_t pending_off;
    } write;
    size_t bytes_written;

    struct aura_list_head s_list; /* for keeping track in queue */
    bool in_write_queue;

    /**
     * @todo:
     * intrusive wheel node: struct aura_list_head wheel_node
     * uin32_t wheel_level (L0/L1/L2/Heap)
     * uin64_t last_activity
     * uin32_t wheel_slot
     * intrusive heap node: struct heap_node hp_node;
     */
} __attribute__((aligned(64)));

/* Wave structure */
struct aura_srv_wave_ctx {
    struct aura_srv_ctx *srv_ctx;
    uint32_t wave_cnt; /* Current wave iteration */
    uint32_t max_wave; /* Max wave iterations */
    uint64_t tick_start;
    uint64_t max_epoch_usec; /* Max epoch cpu time slice */

    /* Per wave work tracking */
    uint32_t all_processed;         /* Total processed */
    uint32_t critical_processed;    /* Total critical processed */
    uint32_t latency_processed;     /* Total latency processed */
    uint32_t throughput_processed;  /* Total tp processed */
    uint32_t max_critical;          /* Max critical per wave */
    uint32_t max_latency;           /* Max Latency per wave */
    uint32_t max_tp_bytes_per_wave; /* Max tp bytes per wave */

    bool critical_empty;
    bool no_new_critical;
    uint32_t time_expired;
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

/**/
int aura_handle_handshake(struct aura_srv_sock *sock, struct aura_srv_ctx *srv_ctx);

/** */
ssize_t aura_read(int fd, void *buf, size_t len);

/**
 * Organise tls records and send them over
 */
ssize_t aura_sock_write_tls(struct aura_srv_sock *sock);

ssize_t aura_write(int fd, void *buf, size_t len);

/**/
void aura_conn_proceed(struct aura_srv_sock *sock, struct aura_srv_ctx *srv_ctx);
int aura_h2_proceed(struct aura_srv_sock *sock, struct aura_srv_ctx *srv_ctx);

/**/
void aura_process_active_queue(struct aura_srv_ctx *srv_ctx);

/**/
void aura_process_reap_queue(struct aura_srv_ctx *srv_ctx);

/**
 * Decode received tls bytes using the negotiated
 * parameters
 */
int aura_decode_tls_input(struct aura_srv_sock *sock);

static inline ptls_log_conn_state_t *a_get_conn_log_state(struct aura_srv_sock *s) {
    return &s->ptls_log_state;
}

#endif