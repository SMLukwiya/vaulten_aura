#ifndef AURA_SOCKET_H
#define AURA_SOCKET_H

// #include "connection.h"
#include "evt_loop_srv.h"
#include "list_lib.h"
#include "memory_lib.h"
#include "optimization_srv.h"
#include "picotls.h"
#include "tls_srv.h"

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

#define A_MAX_TRANSMISSION_UNIT_ESTIMATE 1500
#define A_TCP_IPV4_PLUS_IPV6_OVERHEAD_ESTIMATE 100

#define A_TLS_GENERATE_RECORD_ERROR SIZE_MAX

/* Forward declaration */
struct aura_srv_listener;

/* event handler for this listener type */
typedef int (*listener_event_handler)(struct aura_srv_listener *, struct aura_srv_ctx *);

/* Single listener structure */
struct aura_srv_listener {
    int fd;
    const char *name;
    char *port;
    char *address;
    struct sockaddr addr;
    socklen_t addr_len;
    uint8_t protocol;
    bool tls;
    bool quic;
    listener_event_handler on_event; /* event handler for this listener type */
};

/**
 * Server socket structure
 */
struct aura_srv_sock {
    int sock_fd;
    socklen_t sock_len;
    uint32_t flags;
    struct sockaddr_storage addr;
    size_t bytes_written;
    size_t bytes_read;
};

ssize_t aura_write(int fd, void *buf, size_t len);

int aura_sock_init(struct aura_srv_sock *sock, int fd, struct sockaddr *addr,
                   socklen_t addr_len, int flags);

int aura_socket_accept(struct aura_srv_sock *sock, int sock_fd, bool is_tls, int flags);

#endif