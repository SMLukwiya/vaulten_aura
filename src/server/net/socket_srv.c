#include "socket_srv.h"
#include "error_lib.h"
#include "server_srv.h"

#define A_USE_ACCEPT_4

static inline int a_set_no_tcp_delay_opt(int fd) {
    int on = 1;
    return setsockopt(fd, IPPROTO_IP, TCP_NODELAY, &on, sizeof(on));
}

int aura_sock_init(struct aura_srv_sock *sock, int fd, struct sockaddr *addr,
                   socklen_t addr_len, int flags) {
    int res;

    memcpy(&sock->addr, addr, sizeof(*addr));
    sock->sock_fd = fd;
    sock->sock_len = addr_len;
    aura_set_fd_flag(sock->sock_fd, O_NONBLOCK | SOCK_NONBLOCK);
    res = a_set_no_tcp_delay_opt(fd);
    if (res != 0) {
        sys_debug(true, errno, "a_socket_init: fd=%d:", fd);
        return -1;
    }

    return 0;
}

/**
 * Accept connection on socket descriptor @fd,
 * using these flags
 */
int aura_sock_accept(struct aura_srv_sock *sock, int sock_fd, bool is_tls, int flags) {
    struct sockaddr_in cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    int cli_fd;

#ifdef A_USE_ACCEPT_4
    cli_fd = accept4(sock_fd, (struct sockaddr *)&cli_addr, &cli_len, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (cli_fd < 0)
        return -1;
#else
    if ((cli_fd = accept(sock_fd, (struct sockaddr *)&cli_addr, &cli_len)) < 0)
        return NULL;
    aura_set_fd_flag(cli_fd, O_NONBLOCK);
    aura_set_fd_flag(cli_fd, FD_CLOEXEC);
#endif
    if (aura_sock_init(sock, cli_fd, (struct sockaddr *)&cli_addr, cli_len, flags) < 0)
        return -1;

    return 0;
}

ssize_t aura_read(int fd, void *buf, size_t len) {
    ssize_t n_read;

    do {
        n_read = recv(fd, buf, len, 0);
    } while (n_read == -1 && errno == EINTR);

    if (n_read == -1) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            return 0;
        } else {
            return -1;
        }
    }

    if (n_read == 0) {
        sys_debug(true, errno, "Client closed conn : %d", errno);
        return -1;
    }

    return n_read;
}

/**
 *
 */
ssize_t aura_write(int fd, void *buf, size_t len) {
    ssize_t n_written;

    do {
        n_written = send(fd, buf, len, 0);
    } while (n_written == -1 && errno == EINTR);

    if (n_written != len) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return n_written == -1 ? 0 : n_written;
        }

        sys_debug(true, errno, "aura write error");
        return -1;
    }

    return n_written;
}

void aura_listener_pool_init(struct aura_srv_listener_pool *pool) {
    memset(pool, 0, sizeof(*pool));
}

struct aura_srv_listener *aura_listener_conf_create(struct aura_srv_listener_pool *pool) {
    struct aura_srv_listener *l;

    if (pool->cnt >= pool->cap) {
        pool->cap = pool->cap == 0 ? 5 : pool->cap * 2;
        pool->entries = realloc(pool->entries, sizeof(*pool->entries) * pool->cap);
        if (!pool->entries) {
            return NULL;
        }
    }

    l = &pool->entries[pool->cnt++];
    l->ev_src.ev_type = A_EV_TYPE_LISTENER;
    return l;
}

void aura_listener_pool_destroy(struct aura_srv_listener_pool *pool) {
    if (!pool)
        return;

    free(pool->entries);
    memset(pool, 0, sizeof(*pool));
}

struct aura_ipc_peer *aura_ipc_peer_create(int fd) {
    struct aura_ipc_peer *peer;

    peer = calloc(1, sizeof(*peer));
    if (!peer)
        return NULL;

    peer->ev_src.ev_type = A_EV_TYPE_IPC;
    peer->fd = fd;
    return peer;
}
