#ifndef AURA_EVT_LOOP_H
#define AURA_EVT_LOOP_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "time_lib.h"
#include "timer/timer.h"

#define AURA_EVENT_READ 0x1
#define AURA_EVENT_WRITE 0x2

typedef struct aura_evt_loop st_aura_evt_loop;
typedef struct aura_evt_loop_ops st_aura_evt_loop_ops;

/* Backend types */
typedef enum {
    USE_AURA_EPOLL,
    USE_AURA_KEVENT
} aura_evt_loop_backend_t;

/* Event loop operations */
struct aura_evt_loop_ops {
    void (*init)(st_aura_evt_loop *);
    int (*add)(st_aura_evt_loop *, int fd, void *data, int events);
    int (*modify)(st_aura_evt_loop *, int fd, void *data, int events);
    int (*remove)(st_aura_evt_loop *, int fd);
    int (*poll)(st_aura_evt_loop *, int64_t timeout_ms, uint32_t max_accept);
    void (*destroy)(st_aura_evt_loop *);
};

/* Event loop core structure */
struct aura_evt_loop {
    /* efficient way to track fd in timeouts, and read and write */
    struct aura_srv_ctx *srv_ctx;
    aura_evt_loop_backend_t backend_type;
    const st_aura_evt_loop_ops *ops;
    void *backend;
    int max_fds;
    bool running;
};

/**/
typedef void (*aura_evt_loop_timer_cb)(st_aura_evt_loop *evloop);

/**/
typedef void (*aura_evt_loop_event_cb)(st_aura_evt_loop *evloop, int fd, int events);

/**
 *
 */
static inline void aura_evt_loop_start(st_aura_evt_loop *loop) {
    loop->running = true;
}

/**
 *
 */
static inline void aura_evt_loop_stop(st_aura_evt_loop *loop) {
    loop->running = false;
}

/**
 *
 */
static inline int aura_evt_loop_add(st_aura_evt_loop *loop, int fd, void *data, int events) {
    return loop->ops->add(loop, fd, data, events);
}

/**
 *
 */
static inline int aura_evt_loop_modify(st_aura_evt_loop *loop, int fd, void *data, int events) {
    return loop->ops->modify(loop, fd, data, events);
}

/**
 *
 */
static inline int aura_evt_loop_remove(st_aura_evt_loop *loop, int fd) {
    return loop->ops->remove(loop, fd);
}

/**
 *
 */
static inline int aura_evt_loop_poll(st_aura_evt_loop *loop, uint64_t timeout_ms, uint32_t max_accept) {
    return loop->ops->poll(loop, timeout_ms, max_accept);
}

/**/
st_aura_evt_loop *aura_evt_loop_create(struct aura_srv_ctx *srv_ctx, int max_fds);

/**/
void aura_evt_loop_destroy(st_aura_evt_loop *);

/**/
int aura_evt_loop_add_timer(st_aura_evt_loop *loop, uint64_t timeout, aura_evt_loop_timer_cb cb);

/** */
int64_t aura_evt_loop_get_timeout(struct aura_timer_wheel *tw);

#endif