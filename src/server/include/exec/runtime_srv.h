#ifndef AURA_SRV_RUNTIME_H
#define AURA_SRV_RUNTIME_H

#include "task_srv.h"

#define A_RT_INITIALIZED 0xA0A0A0A0A0A0A0A0

typedef struct aura_runtime_ops st_aura_runtime_ops;
typedef struct aura_runtime st_aura_runtime;

/** @todo: needs a long thought!! */
struct aura_runtime_ops {
    int (*init)(void *, void *);
    void (*destroy)(void *);
    int (*execute)(void *, struct aura_task *task);
};

/* Runtime generic structure */
struct aura_runtime {
    const st_aura_runtime_ops *ops;
};

/* -------------- QUICKJS -------------- */
typedef struct aura_qjs_state st_aura_js_state;
typedef struct aura_qjs_fn_ctx st_aura_qjs_fn_ctx;
typedef struct aura_intr_ctx st_aura_intr_ctx;
typedef struct aura_qjs_runtime st_aura_qjs_runtime;

#define A_READ 1
#define A_WRITE 2
#define A_OPEN 4
#define A_CLOSE 8

enum {
    QJS_INTERRUPT_KILL
};

struct aura_qjs_state {
    JSRuntime *rt;
    JSContext *ctx;
};

struct event_loop {
    int epoll_fd;
    bool is_running;
};

struct aura_intr_ctx {
    uint8_t actions;
};

struct aura_qjs_fn_ctx {
    size_t mem_limit;
    size_t stack_limit;
    uint32_t flags;
};

struct aura_qjs_runtime {
    JSContext *ctx;
    JSRuntime *rt;
    JSValue func;
    JSValue *entrypoint;
    JSValue *interrupt_handler;
    JSValue stream_obj;
    st_aura_qjs_fn_ctx fn_ctx;
    st_aura_intr_ctx *intr_opaque_data;

    bool _is_part_of_min;
};

/* APIs (js_bindings.c) */
/* Initialize console logging */
void aura_js_console_init(st_aura_qjs_runtime *qrt);

/* Initialize fetch */
int aura_js_fetch_init(st_aura_qjs_runtime *qrt);

#endif