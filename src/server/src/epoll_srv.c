#include "error_lib.h"
#include "evt_loop_srv.h"
#include "picotls.h"
#include "server_srv.h"
#include "socket_srv.h"
#include <sys/epoll.h>

struct aura_epoll_data {
    int epoll_fd;
    struct epoll_event *ep_events;
};

/**
 *
 */
static void aura_epoll_init(struct aura_evt_loop *evt_loop) {
    struct aura_epoll_data *epoll;

    epoll = malloc(sizeof(*epoll));
    if (!epoll)
        sys_exit(true, errno, "Epoll init failed, no memory");
    memset(epoll, 0, sizeof(*epoll));

    epoll->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll->epoll_fd < 0)
        sys_exit(true, errno, "epoll_create1() fd creation failed");

    epoll->ep_events = malloc(evt_loop->max_fds * sizeof(struct epoll_event));
    if (!epoll->ep_events)
        sys_exit(true, errno, "Epoll init failed, no memory");

    evt_loop->backend = epoll;
    app_info(true, 0, "-> aura_epoll_init()");
}

/**
 *
 */
static void aura_epoll_destroy(struct aura_evt_loop *evt_loop) {
    struct aura_epoll_data *epoll = evt_loop->backend;
    if (epoll) {
        close(epoll->epoll_fd);
        free(epoll->ep_events);
        free(epoll);
    }
}

/**
 *
 */
int aura_epoll_add(struct aura_evt_loop *evt_loop, int fd, int events) {
    struct aura_epoll_data *epoll = evt_loop->backend;
    struct epoll_event ep_ev;
    int res;

    if (!epoll) {
        app_alert(true, 0, "Trying to add fd %d to uninitialized epoll loop", fd);
        return 1;
    }
    memset(&ep_ev, 0, sizeof(ep_ev));
    ep_ev.data.fd = fd;

    if (events & AURA_EVENT_READ)
        ep_ev.events |= EPOLLIN;
    if (events & AURA_EVENT_WRITE)
        ep_ev.events |= EPOLLOUT;

    do {
        res = epoll_ctl(epoll->epoll_fd, EPOLL_CTL_ADD, fd, &ep_ev);
    } while (res != 0 && errno == EINTR);
    return res;
}

/**
 *
 */
static int aura_epoll_modify(struct aura_evt_loop *evt_loop, int fd, int events) {
    struct aura_epoll_data *epoll = evt_loop->backend;
    struct epoll_event ep_ev;
    int res;

    if (!epoll) {
        app_alert(true, 0, "Trying to modify fd %d to uninitialized epoll loop", fd);
        return 1;
    }
    memset(&ep_ev, 0, sizeof(ep_ev));
    ep_ev.data.fd = fd;

    if (events & AURA_EVENT_READ)
        ep_ev.events |= EPOLLIN;
    if (events & AURA_EVENT_WRITE)
        ep_ev.events |= EPOLLOUT;

    do {
        res = epoll_ctl(epoll->epoll_fd, EPOLL_CTL_MOD, fd, &ep_ev);
    } while (res != 0 && errno == EINTR);

    return res;
}

/**
 *
 */
int aura_epoll_remove(struct aura_evt_loop *evt_loop, int fd) {
    struct aura_epoll_data *epoll = evt_loop->backend;
    int res;

    if (!epoll) {
        app_alert(true, 0, "Trying to delete fd %d to uninitialized epoll loop", fd);
        return 1;
    }

    do {
        res = epoll_ctl(epoll->epoll_fd, EPOLL_CTL_DEL, fd, NULL);
    } while (res != 0 && errno == EINTR);

    return res;
}

/**
 *
 */
int aura_epoll_poll(struct aura_evt_loop *evt_loop, int64_t timeout_ms, uint32_t max_accept) {
    int num_of_events, fd, i, j;
    struct aura_srv_sock *sock, *peer_sock;
    struct aura_epoll_data *epoll = evt_loop->backend;

    num_of_events = epoll_wait(epoll->epoll_fd, epoll->ep_events, evt_loop->max_fds, timeout_ms);
    if (num_of_events < 0)
        sys_exit(true, errno, "epoll_wait() server wait failed");

    for (i = 0; i < num_of_events; ++i) {
        fd = epoll->ep_events[i].data.fd;

        if (fd == evt_loop->dmn_fd && (epoll->ep_events[i].events & EPOLLIN)) {
            app_debug(true, 0, "Internal message: %d", fd);
            evt_loop->srv_ctx->batches.internal = true;
            evt_loop->ops->remove(evt_loop, fd);
            continue;
        }

        sock = evt_loop->srv_ctx->glob_conf->fdmap[fd];
        if (!sock) /* should not happen */
            continue;

        if (sock->flags & A_SOCK_LISTENER) {
            for (j = 0; j < max_accept; ++j) {
                peer_sock = aura_socket_accept(&evt_loop->srv_ctx->glob_conf->mem_ctx, fd, A_SOCK_HANDSHAKE);
                if (peer_sock == NULL) {
                    if (errno == EAGAIN) {
                        /* We have exhausted all we can accept */
                        break;
                    } else {
                        sys_debug(true, errno, "Failed to create peer socket");
                        break;
                    }
                }

                /* create tls for new conn */
                peer_sock->tls_ctx->ptls = ptls_server_new(evt_loop->srv_ctx->listener_conf->tls_pool.idens[0].contexts.tls1_3.ctx); // evt_loop->srv_ctx->listener_conf->ptls;
                *ptls_get_data_ptr(peer_sock->tls_ctx->ptls) = peer_sock;
                evt_loop->srv_ctx->glob_conf->fdmap[peer_sock->sock_fd] = peer_sock;
                evt_loop->ops->add(evt_loop, peer_sock->sock_fd, AURA_EVENT_READ);
                a_list_add(&evt_loop->srv_ctx->batches.queues.handshake_queue, &peer_sock->s_list);
            }
            continue;
        }
    }
}

/**
 *
 */
const struct aura_evt_loop_ops epoll_ops = {
  .add = aura_epoll_add,
  .destroy = aura_epoll_destroy,
  .init = aura_epoll_init,
  .modify = aura_epoll_add,
  .remove = aura_epoll_remove,
  .poll = aura_epoll_poll,
};
