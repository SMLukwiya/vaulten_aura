#include "connection.h"
#include "core.h"
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

    epoll->ep_events = calloc(1, evt_loop->max_fds * sizeof(struct epoll_event));
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
int aura_epoll_add(struct aura_evt_loop *evt_loop, int fd, void *data, int events) {
    struct aura_epoll_data *epoll = evt_loop->backend;
    struct epoll_event ep_ev;
    int res;

    if (!epoll) {
        app_alert(true, 0, "aura_epoll_add: adding %d to uninitialized epoll loop", fd);
        return -1;
    }
    memset(&ep_ev, 0, sizeof(ep_ev));
    ep_ev.data.ptr = data;

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
static int aura_epoll_modify(struct aura_evt_loop *evt_loop, int fd, void *data, int events) {
    struct aura_epoll_data *epoll = evt_loop->backend;
    struct epoll_event ep_ev;
    int res;

    if (!epoll) {
        app_alert(true, 0, "aura_epoll_modify: modifying fd %d in uninitialized epoll loop", fd);
        return -1;
    }
    memset(&ep_ev, 0, sizeof(ep_ev));
    ep_ev.data.ptr = data;

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

/**/
int aura_epoll_poll(struct aura_evt_loop *evt_loop, int64_t timeout_ms, uint32_t max_accept) {
    int num_of_events, fd, rv;
    struct aura_conn *conn;
    struct aura_epoll_data *epoll = evt_loop->backend;
    struct epoll_event ev;
    struct aura_evt_source *ev_src;
    struct aura_srv_listener *listener;

    num_of_events = epoll_wait(epoll->epoll_fd, epoll->ep_events, evt_loop->max_fds, timeout_ms);
    if (num_of_events < 0 && errno != EINTR)
        sys_exit(true, errno, "aura_epoll_poll: epoll_wait error:");

    for (int i = 0; i < num_of_events; ++i) {
        ev = epoll->ep_events[i];
        /**
         * cast to evt_source structure as
         * evt_source is the first field on an epoll
         * attached structure
         */
        ev_src = (struct aura_evt_source *)ev.data.ptr;

        switch (ev_src->ev_type) {
        case A_EV_TYPE_IPC:
            if (ev.events & EPOLLIN)
                aura_set_internal_request_active(evt_loop->srv_ctx);
            break;

        case A_EV_TYPE_LISTENER:
            listener = (struct aura_srv_listener *)ev_src;
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
            break;

        case A_EV_TYPE_CONN:
            conn = (struct aura_conn *)ev_src;

            /* Error or Hangup - immediate critical */
            if (ev.events & (EPOLLERR | EPOLLHUP)) {
                /* Remove from whatever list it was previously on */
                aura_conn_transition_state(conn, A_CONN_STATE_CLOSING);
                evt_loop->ops->remove(evt_loop, fd);
                aura_list_move(&evt_loop->srv_ctx->queues.reap, &conn->c_list);
                break;
            }

            if (ev.events & EPOLLIN || ev.events & EPOLLOUT) {
                /**/
            }
            break;

        case A_EV_TYPE_NONE:
            app_debug(true, 0, "aura_epoll_poll: unknown event type: %d", ev_src->ev_type);
            break;
        }
    }
}

/**
 *
 */
const struct aura_evt_loop_ops epoll_ops = {
  .init = aura_epoll_init,
  .add = aura_epoll_add,
  .destroy = aura_epoll_destroy,
  .modify = aura_epoll_modify,
  .remove = aura_epoll_remove,
  .poll = aura_epoll_poll,
};
