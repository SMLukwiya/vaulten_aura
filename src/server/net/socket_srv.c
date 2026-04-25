#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "socket_srv.h"
#include "bug_lib.h"
#include "core.h"
#include "error_lib.h"
#include "evt_loop_srv.h"
#include "h2/h2_srv.h"
#include "server_srv.h"
#include "slab_lib.h"
#include "types_lib.h"
#include "utils_lib.h"

#include <netinet/tcp.h>

#define USE_ACCEPT_4 1

const struct aura_iovec aura_h2_alpn_protocols[] = {A_H2_APLN_PROTOCOLS};

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
    sock->flags = flags;
    aura_set_fd_flag(sock->sock_fd, O_NONBLOCK | SOCK_NONBLOCK);
    res = a_set_no_tcp_delay_opt(fd);
    if (res != 0) {
        sys_debug(true, errno, "a_socket_accept: aura_socket_create fd=%d:", fd);
        return -1;
    }

    return 0;
}

/**
 * Accept connection on socket descriptor @fd,
 * using these flags
 */
int aura_socket_accept(struct aura_srv_sock *sock, int sock_fd, bool is_tls, int flags) {
    struct sockaddr_in cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    int cli_fd;

#ifdef USE_ACCEPT_4
    cli_fd = accept4(sock_fd, (struct sockaddr *)&cli_addr, &cli_len, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (cli_fd < 0)
        return -1;
#else
    if ((cli_fd = accept(server->sock_fd, (struct sockaddr *)&cli_addr, &cli_len)) < 0)
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
        if (errno == EWOULDBLOCK) {
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

    if (n_written == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }

        sys_debug(true, errno, "aura write error");
        return -1;
    }

    if (n_written == 0) {
        sys_debug(true, errno, "write side closed");
        return -1;
    }

    return n_written;
}
