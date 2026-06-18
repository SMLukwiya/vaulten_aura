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

st_aura_evt_loop *aura_evt_loop_create(struct aura_srv_ctx *srv_ctx, int max_fds) {
    st_aura_evt_loop *loop;

    loop = calloc(1, sizeof(*loop));
    if (!loop)
        return NULL;

    loop->ops = a_get_backend_ops();
    if (!loop->ops) {
        free(loop);
        return NULL;
    }
    loop->backend_type;
    loop->max_fds = max_fds;
    loop->srv_ctx = srv_ctx;

    /* initialize backend */
    loop->ops->init(loop);
    return loop;
}

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
int64_t aura_evt_loop_get_timeout(struct aura_timer_wheel *tw) {
    uint64_t now;

    if (tw->next_deadline == UINT64_MAX)
        return -1;

    now = aura_now_ms(CLOCK_MONOTONIC);
    if (tw->next_deadline <= now)
        return 0;

    uint64_t delta = tw->next_deadline - now;
    return delta;
}
