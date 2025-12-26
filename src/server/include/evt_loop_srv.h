#ifndef AURA_EVT_LOOP_H
#define AURA_EVT_LOOP_H

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#define AURA_EVENT_READ 0x1
#define AURA_EVENT_WRITE 0x2

typedef struct aura_evt_loop st_aura_evt_loop;
typedef struct aura_evt_loop_ops st_aura_evt_loop_ops;

typedef enum {
    USE_AURA_EPOLL,
    USE_AURA_KEVENT
} aura_evt_loop_backend_t;

/* Event loop operations */
struct aura_evt_loop_ops {
    void (*init)(st_aura_evt_loop *);
    int (*add)(st_aura_evt_loop *, int fd, int events);
    int (*modify)(st_aura_evt_loop *, int fd, int events);
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
    bool running;
    int max_fds;
    int dmn_fd; /* daemon socket file descritor */
};

typedef void (*aura_evt_loop_timer_cb)(st_aura_evt_loop *evloop);
typedef void (*aura_evt_loop_event_cb)(st_aura_evt_loop *evloop, int fd, int events);

st_aura_evt_loop *aura_evt_loop_create(int dmn_sock_fd, int max_fds);
void aura_evt_loop_destroy(st_aura_evt_loop *);
int aura_evt_loop_add(st_aura_evt_loop *loop, int fd, int events);
int aura_evt_loop_modify(st_aura_evt_loop *loop, int fd, int events);
int aura_evt_loop_remove(st_aura_evt_loop *loop, int fd);
int aura_evt_loop_add_timer(st_aura_evt_loop *loop, uint64_t timeout, aura_evt_loop_timer_cb cb);
void aura_evt_loop_start(st_aura_evt_loop *loop);
void aura_evt_loop_stop(st_aura_evt_loop *loop);
int aura_evt_loop_poll(st_aura_evt_loop *loop, uint64_t timeout_ms, uint32_t max_accept);

#endif