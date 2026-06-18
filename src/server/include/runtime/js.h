#ifndef AURA_JS_RUNTIME_H
#define AURA_JS_RUNTIME_H

#include "function_lib.h"
#include "memory_lib.h"
#include "quickjs.h"
#include "runtime/request.h"
#include "task_srv.h"

#define A_READ 1
#define A_WRITE 2
#define A_OPEN 4
#define A_CLOSE 8

/* Fetch ctx structure */
struct aura_js_fetch_ctx {
    int type;
    JSContext *ctx;
    JSValue resolve;
    JSValue reject;
    Request *req;
};

enum {
    QJS_INTERRUPT_KILL
};

struct aura_qjs_fn_ctx {
    size_t mem_limit;
    size_t stack_limit;
    uint32_t flags;
};

struct aura_qjs_rt_thread_state {
    struct aura_srv_ctx *srv_ctx;
};

/* Quick js runtime structure */
struct aura_qjs_runtime {
    struct aura_mem_ctx *mc;
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
void aura_js_console_init(JSRuntime *rt, JSContext *ctx);

/* Initialize fetch */
int aura_js_fetch_init(JSRuntime *rt, JSContext *ctx);

/**/
JSValue aura_js_std_await(JSContext *ctx, JSValue obj);

/**/
void aura_js_std_dump_error(JSContext *ctx, char *msg);

/** */
int aura_qjs_create_fetch_request(struct aura_srv_ctx *s_ctx, JSContext *js_ctx, Request *js_req, JSValue *fns);

/**
 * Create JS runtime and JS context, attach console logging,
 * fetch, and other capabilities based on function config
 */
struct aura_qjs_runtime *aura_qjs_create(struct aura_srv_ctx *s_ctx, struct aura_fn *fn);

int aura_qjs_execute(struct aura_qjs_runtime *qjs, struct aura_task *task);

void aura_qjs_destroy(struct aura_qjs_runtime *r);

struct aura_js_fetch_ctx *aura_qjs_fetch_ctx_create(struct aura_mem_ctx *mc, Request *req,
                                                    JSContext *ctx, JSValue resolve,
                                                    JSValue reject);

void aura_qjs_fetch_ctx_destroy(struct aura_js_fetch_ctx *fetch_ctx);

int aura_qjs_trigger_promise_rejection(JSContext *ctx, JSValue reject_fn, const char *err);

#endif