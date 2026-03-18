#ifndef AURA_SRV_RUNTIME_H
#define AURA_SRV_RUNTIME_H

#include "exec/task_srv.h"
#include "quickjs.h"
#include <stdbool.h>

#define A_RT_INITIALIZED 0xA0A0A0A0A0A0A0A0

typedef struct aura_runtime_ops st_aura_runtime_ops;
typedef struct aura_runtime st_aura_runtime;

typedef enum {
    A_WQ_JS = 1
} aura_wq_backend_t;

/* Runtime generic structure */
struct aura_runtime {
    const st_aura_runtime_ops *ops;
    void *rt_data; /* Opaque */
    aura_wq_backend_t backend;
};

/** @todo: needs a long thought!! */
struct aura_runtime_ops {
    int (*init)(st_aura_runtime *, void *);
    int (*execute)(st_aura_runtime *, struct aura_task *task);
    void (*destroy)(st_aura_runtime *);
};

/* -------------- QUICKJS -------------- */
#define A_READ 1
#define A_WRITE 2
#define A_OPEN 4
#define A_CLOSE 8

enum {
    QJS_INTERRUPT_KILL
};

struct aura_qjs_fn_ctx {
    size_t mem_limit;
    size_t stack_limit;
    uint32_t flags;
};

struct aura_qjs_runtime {
    struct aura_memory_ctx *mc;
    JSRuntime *rt;
    JSContext *ctx;
    JSValue func_handler;
    JSValue interrupt_handler;
    struct aura_qjs_fn_ctx *fn_ctx;
    /**
     * This is used to determine if an instance is part
     * of the minimum instance. A list of instances that
     * are never taken shutdown
     */
    bool _is_part_of_min;
};

/* APIs (js_bindings.c) */
/* Initialize console logging */
void aura_js_console_init(struct aura_qjs_runtime *qrt);

/* Initialize fetch */
int aura_js_fetch_init(struct aura_qjs_runtime *qrt);

/**/
JSValue aura_js_std_await(JSContext *ctx, JSValue obj);

/**/
void aura_js_std_dump_error(JSContext *ctx, char *msg);

#endif