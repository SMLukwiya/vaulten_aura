#include "evt_loop_srv.h"
#include "error_lib.h"

#ifdef __linux__
extern const st_aura_evt_loop_ops epoll_ops;
#else
#error only epoll supported currently
#endif

/**
 * Associate a set of loop operations with created loop.
 * After this setup, calls through the eventloop relays
 * to the appropriate backend function
 */
const st_aura_evt_loop_ops *a_get_backend_ops() {
#ifdef __linux__
    return &epoll_ops;
#elif
    return NULL;
#endif
}

/**
 *
 */
st_aura_evt_loop *aura_evt_loop_create(int dmn_sock_fd, int max_fds) {
    app_debug(true, 0, "aura_evt_loop_create <<<");
    st_aura_evt_loop *loop;

    loop = malloc(sizeof(*loop));
    if (!loop)
        return NULL;
    memset(loop, 0, sizeof(*loop));

    loop->ops = a_get_backend_ops();
    if (!loop->ops) {
        free(loop);
        return NULL;
    }
    loop->backend_type;
    loop->dmn_fd = dmn_sock_fd;
    loop->max_fds = max_fds;

    /* initialize backend */
    loop->ops->init(loop);
    return loop;
}

/**
 *
 */
void aura_evt_loop_destroy(st_aura_evt_loop *loop) {
    if (!loop)
        return;

    loop->ops->destroy(loop);
    // free other stuff

    free(loop);
}

/**
 *
 */
int aura_evt_loop_add_timer(st_aura_evt_loop *loop, uint64_t timeout, aura_evt_loop_timer_cb cb) {}

/**
 *
 */
void aura_evt_loop_start(st_aura_evt_loop *loop) {
    loop->running = true;
}

/**
 *
 */
void aura_evt_loop_stop(st_aura_evt_loop *loop) {
    loop->running = false;
}

/**
 *
 */
int aura_evt_loop_add(st_aura_evt_loop *loop, int fd, int events) {
    return loop->ops->add(loop, fd, events);
}

/**
 *
 */
int aura_evt_loop_modify(st_aura_evt_loop *loop, int fd, int events) {
    return loop->ops->modify(loop, fd, events);
}

/**
 *
 */
int aura_evt_loop_remove(st_aura_evt_loop *loop, int fd) {
    return loop->ops->remove(loop, fd);
}

/**
 *
 */
int aura_evt_loop_poll(st_aura_evt_loop *loop, uint64_t timeout_ms, uint32_t max_accept) {
    return loop->ops->poll(loop, timeout_ms, max_accept);
}

/**
 *
 */
int64_t aura_evt_loop_get_timeout(struct aura_timer_wheel *tw) {
    uint64_t now;

    if (tw->next_deadline_ms == UINT64_MAX)
        return -1;

    now = aura_now_ms(CLOCK_MONOTONIC);
    if (tw->next_deadline_ms <= now)
        return 0;

    uint64_t delta = tw->next_deadline_ms - now;
    return delta;
}
