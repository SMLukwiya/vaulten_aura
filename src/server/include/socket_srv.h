#ifndef AURA_SOCKET_H
#define AURA_SOCKET_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "core.h"
#include "evt_loop_srv.h"
#include "list_lib.h"
#include "memory_lib.h"
#include "picotls.h"
#include "tls_srv.h"

#define A_INVALID_SOCK_FD -1

/* Forward declaration */
struct aura_srv_listener;

/* event handler for this listener type */
typedef int (*listener_event_handler)(struct aura_srv_listener *, struct aura_srv_ctx *);

/* Single listener structure */
struct aura_srv_listener {
    /**
     * Event type, MUST be the first field in the
     * since polling loop casts the structure to
     * struct aura_evt_source for comparison
     */
    struct aura_evt_source ev_src;
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

/* Listener pool structure */
struct aura_srv_listener_pool {
    struct aura_srv_listener *entries;
    size_t cnt;
    size_t cap;
};

/**
 * Server socket structure
 */
struct aura_srv_sock {
    int sock_fd;
    socklen_t sock_len;
    sa_family_t family;
    struct sockaddr_storage addr;
};

/* IPC Peer structure */
struct aura_ipc_peer {
    struct aura_evt_source ev_src; /* evt source type */
    int fd;                        /* Daemon fd */
    uint8_t state;
    bool active; /* Internal request from daemon */
};

ssize_t aura_read(int fd, void *buf, size_t len);

ssize_t aura_write(int fd, void *buf, size_t len);

int aura_sock_init(struct aura_srv_sock *sock, int fd, struct sockaddr *addr,
                   socklen_t addr_len, int flags);

int aura_socket_accept(struct aura_srv_sock *sock, int sock_fd, bool is_tls, int flags);

void aura_listener_pool_init(struct aura_srv_listener_pool *pool);

struct aura_srv_listener *aura_listener_conf_create(struct aura_srv_listener_pool *pool);

void aura_listener_pool_destroy(struct aura_srv_listener_pool *pool);

/**/
struct aura_ipc_peer *aura_ipc_peer_create(int fd);

#endif