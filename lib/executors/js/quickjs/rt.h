#ifndef AURA_JS_RUNTIME_H
#define AURA_JS_RUNTIME_H

#include "bindings.h"
#include "event_ctx/context.h"
#include "fn/lib.h"
#include "mem.h"
#include "quickjs.h"
#include "request/req.h"

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

/* Blob structure */
struct aura_js_blob {
    uint8_t *data;
    uint64_t len;
    const char *type;
};

/**
 * Quick js execution context.
 * This contains everything needed to execute
 * a function. We should be able to choose any
 * worker thread execute the function on.
 */
struct aura_qjs_execution_ctx {
    JSRuntime *rt;                        /* Quickjs runtime */
    JSContext *ctx;                       /* Quickjs context */
    JSValue fn_handler;                   /* Callable function */
    JSValue fn_arg;                       /* Function argument */
    struct aura_task *task;               /* Task that created this execution */
    void *opaque;                         /* Opaque attached */
    void (*opaque_destructor_fn)(void *); /* opaque destructor 00*/
    struct aura_list_head node;           /* Link in fn queue */
};

/** */
int aura_qjs_create_fetch_request(struct aura_qjs_rt_data *ts,
                                  JSContext *js_ctx, Request *js_req,
                                  JSValue *fns);

/**
 * Create JS runtime and JS context, attach console logging,
 * fetch, and other capabilities based on function config
 */

void aura_qjs_destroy(struct aura_qjs_runtime *r);

struct aura_qjs_fetch_ctx *aura_qjs_fetch_ctx_create(struct aura_mem_ctx *mc, Request *req,
                                                     JSContext *ctx, JSValue resolve,
                                                     JSValue reject, struct aura_qjs_body_src *b_src);

void aura_qjs_fetch_ctx_destroy(struct aura_qjs_fetch_ctx *fetch_ctx);

int aura_qjs_trigger_promise_rejection(JSContext *ctx, JSValue reject_fn, const char *err);

/* =========== */
/* Initialize Quickjs runtime IDs */
void aura_qjs_class_ids_init(void);

/**
 *
 */
int aura_qjs_write_bytecode(JSContext *ctx, const char *input, uint64_t input_len,
                            const char *module_name, uint8_t **bytecode,
                            uint64_t *bytecode_len);

/**
 *
 */
int aura_qjs_read_bytecode(JSContext *ctx, void *code, uint64_t code_len, JSValue *handler);

/**
 *
 */
int aura_qjs_execution_context_create(struct aura_fn_queue *fn_q, struct aura_mem_ctx *mc);

/**
 *
 */
int aura_qjs_prepare(struct aura_qjs_execution_ctx *exec_ctx, struct aura_task *task,
                     Request *req, Response *res);

/**
 *
 */
JSValue aura_qjs_execute2(void *execution_context);

/**/
void aura_qjs_reset(struct aura_qjs_execution_ctx *exec_ctx);

// JSValue aura_qjs_context_finalize(JSContext *ctx, struct aura_exec_ctx *exec_ctx,
//                                   Request *request, Response *response);

/* ==================== TEST ==================== */
struct aura_qjs_execution_ctx *aura_qjs_exec_ctx_create_test(struct aura_mem_ctx *mc, struct aura_fn *fn);
void aura_qjs_exec_ctx_destroy_test(struct aura_qjs_execution_ctx *exec_ctx);
void aura_qjs_reset_test(struct aura_qjs_execution_ctx *exec_ctx);
JSValue aura_qjs_execute_test(void *execution_context);

#endif