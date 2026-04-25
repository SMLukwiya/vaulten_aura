#include "connection.h"
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

    epoll = calloc(1, sizeof(*epoll));
    if (!epoll)
        sys_exit(true, errno, "aura_epoll_init error:");

    epoll->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (epoll->epoll_fd < 0)
        sys_exit(true, errno, "aura_epoll_init: epoll_create1() error:");

    epoll->ep_events = malloc(evt_loop->max_fds * sizeof(struct epoll_event));
    if (!epoll->ep_events)
        sys_exit(true, errno, "aura_epoll_init: ep_events error:");

    evt_loop->backend = epoll;
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
        app_alert(true, 0, "aura_epoll_add: adding %d to uninitialized epoll loop", fd);
        return -1;
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
        app_alert(true, 0, "aura_epoll_modify: modifying fd %d in uninitialized epoll loop", fd);
        return -1;
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
        app_alert(true, 0, "aura_epoll_remove: deleting fd %d to uninitialized epoll loop", fd);
        return -1;
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
    int num_of_events, fd, rv;
    struct aura_conn *conn;
    struct aura_srv_listener *listener;
    struct aura_epoll_data *epoll = evt_loop->backend;
    struct epoll_event ev;

    num_of_events = epoll_wait(epoll->epoll_fd, epoll->ep_events, evt_loop->max_fds, timeout_ms);
    if (num_of_events < 0 && errno != EINTR)
        sys_exit(true, errno, "aura_epoll_poll: epoll_wait error:");

    for (int i = 0; i < num_of_events; ++i) {
        ev = epoll->ep_events[i];
        fd = ev.data.fd;

        if (fd == evt_loop->dmn_fd && (ev.events & EPOLLIN)) {
            evt_loop->srv_ctx->internal = true;
            evt_loop->ops->remove(evt_loop, fd);
            continue;
        }

        if ((listener = aura_check_if_listener(evt_loop->srv_ctx->listener_conf, fd)) != NULL) {
            for (int j = 0; j < max_accept; ++j) {
                if (!listener->on_event)
                    continue;

                rv = listener->on_event(listener, evt_loop->srv_ctx);
                /* error, go to next */
                if (rv < 0) {
                    continue;
                }
                /* nothing to process */
                if (rv == 0) {
                    break;
                }
            }
            continue;
        }

        conn = evt_loop->srv_ctx->glob_conf->conn_map[fd];
        if (!conn) /* should not happen */ {
            continue;
        }

        /* Error or Hangup - immediate critical */
        if (epoll->ep_events[i].events & (EPOLLERR | EPOLLHUP)) {
            /* Remove from whatever list it was previously on */
            a_list_delete(&conn->c_list);
            aura_conn_transition_state(conn, A_CONN_STATE_CLOSING);
            evt_loop->ops->remove(evt_loop, fd);
            a_list_add_tail(&evt_loop->srv_ctx->queues.reap, &conn->c_list);
            continue;
        }

        if (ev.events & EPOLLIN || ev.events & EPOLLOUT) {
            /* delete from whatever queue (even if it's already in the right queue) */
            a_list_delete(&conn->c_list);
            /* Add to appropriate queue */
            conn->in_active = true;
            conn->in_reap = false;
            a_list_add_tail(&evt_loop->srv_ctx->queues.active, &conn->c_list);
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
