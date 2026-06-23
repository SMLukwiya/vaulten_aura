#include "fn/lib.h"
#include "h2/client.h"
#include "quickjs-libc.h"
#include "quickjs.h"
#include "runtime/js.h"
#include "runtime/runtime.h"
#include "server_srv.h"
#include "task_srv.h"
#include "time_lib.h"
#include "types_lib.h"
#include "url/lib.h"

#include <pthread.h>
#include <stdlib.h>

extern JSClassID req_class_id;
extern JSClassID res_class_id;

extern const JSCFunctionListEntry aura_js_request_proto_funcs[];
extern const uint32_t aura_js_request_proto_funcs_len;

int aura_qjs_interrupt_handler(JSRuntime *js_rt, void *opaque) {
    return 1;
}

struct aura_qjs_runtime *aura_qjs_create(struct aura_srv_ctx *srv_ctx, struct aura_fn *fn) {
    struct aura_qjs_runtime *qjs;
    struct aura_qjs_rt_thread_state *ts;
    JSValue obj, module;

    /* Keep runtime on malloc for now */
    qjs = malloc(sizeof(*qjs));
    if (!qjs)
        return NULL;

    qjs->rt = JS_NewRuntime();
    if (!qjs->rt) {
        goto err_runtime;
    }

    qjs->ctx = JS_NewContext(qjs->rt);
    if (!qjs->ctx) {
        goto err_context;
    }

    ts = malloc(sizeof(*ts));
    if (!ts)
        goto err_context;
    ts->srv_ctx = srv_ctx;

    JS_SetRuntimeOpaque(qjs->rt, ts);

    aura_js_console_init(qjs->rt, qjs->ctx);
    if (aura_js_fetch_init(qjs->rt, qjs->ctx) != 0)
        goto err_object_class;

    obj = JS_ReadObject(qjs->ctx, fn->fn_code, fn->fn_code_len, JS_READ_OBJ_BYTECODE);
    if (JS_IsException(obj)) {
        aura_js_std_dump_error(qjs->ctx, NULL);
        goto err_object_class;
    }

    if (JS_VALUE_GET_TAG(obj) == JS_TAG_MODULE)
        if (JS_ResolveModule(qjs->ctx, obj) < 0) {
            JS_FreeValue(qjs->ctx, obj);
            aura_js_std_dump_error(qjs->ctx, NULL);
            goto err_bytecode;
        }

    /* Verify we have a function */
    module = JS_EvalFunction(qjs->ctx, obj);
    if (JS_IsException(module)) {
        JS_FreeValue(qjs->ctx, obj);
        aura_js_std_dump_error(qjs->ctx, NULL);
        goto err_bytecode;
    }

    module = aura_js_std_await(qjs->ctx, module);
    if (JS_IsException(module)) {
        JS_FreeValue(qjs->ctx, obj);
        aura_js_std_dump_error(qjs->ctx, NULL);
        goto err_bytecode;
    }
    JS_FreeValue(qjs->ctx, module);

    JSModuleDef *m = JS_VALUE_GET_PTR(obj);
    JSValue val = JS_GetModuleNamespace(qjs->ctx, m);
    qjs->func_handler = JS_GetPropertyStr(qjs->ctx, val, "default");
    JS_FreeValue(qjs->ctx, obj);
    JS_FreeValue(qjs->ctx, val);

    if (!JS_IsFunction(qjs->ctx, qjs->func_handler)) {
        aura_js_std_dump_error(qjs->ctx, NULL);
        goto err_bytecode;
    }

    /** @todo: set runtime limitations according to config */
    return qjs;
err_bytecode:
    JS_FreeValue(qjs->ctx, obj);
err_object_class:
    free(ts);
    JS_FreeContext(qjs->ctx);
err_context:
    JS_FreeRuntime(qjs->rt);
err_runtime:
    return NULL;
}

void aura_qjs_destroy(struct aura_qjs_runtime *qjs) {
    if (!qjs)
        return;

    if (!JS_IsUndefined(qjs->func_handler))
        JS_FreeValue(qjs->ctx, qjs->func_handler);

    if (qjs->ctx)
        JS_FreeContext(qjs->ctx);
    if (qjs->rt)
        JS_FreeRuntime(qjs->rt);

    free(qjs);
}

int aura_qjs_execute(struct aura_qjs_runtime *qjs, struct aura_task *task) {
    JSValue val, val1, exception;
    const char *err;
    JSValue js_req, js_res;

    task->started_at = aura_now_ns(CLOCK_MONOTONIC);

    js_req = JS_NewObjectClass(qjs->ctx, req_class_id);
    if (JS_IsException(js_req)) {
        app_debug(true, 0, "aura_qjs_execute: js_req object class");
        return -1;
    }

    js_res = JS_NewObjectClass(qjs->ctx, res_class_id);
    if (JS_IsException(js_res)) {
        app_debug(true, 0, "aura_qjs_execute: js_res object class");
        JS_FreeValue(qjs->ctx, js_req);
        return -1;
    }
    JS_SetOpaque(js_req, task->req_data);
    JS_SetOpaque(js_res, task->res_data);

    JSValue arg[] = {js_req, js_res};
    val = JS_Call(qjs->ctx, qjs->func_handler, JS_UNDEFINED, 2, arg);

    JS_FreeValue(qjs->ctx, arg[0]);
    JS_FreeValue(qjs->ctx, arg[1]);

    if (JS_IsException(val)) {
        aura_js_std_dump_error(qjs->ctx, NULL);
        return -1;
    }
    JS_FreeValue(qjs->ctx, val);

    /** @todo: val is currently freed from inside function, could do better */
    val = aura_js_std_await(qjs->ctx, val);
    if (JS_IsException(val)) {
        return -1;
    }

    task->completed_at = aura_now_ns(CLOCK_MONOTONIC);

    return 0;
}

struct aura_js_fetch_ctx *aura_qjs_fetch_ctx_create(struct aura_mem_ctx *mc, Request *req,
                                                    JSContext *ctx, JSValue resolve,
                                                    JSValue reject) {
    struct aura_js_fetch_ctx *fetch_ctx;

    fetch_ctx = aura_alloc(mc, sizeof(*fetch_ctx));
    if (!fetch_ctx)
        return NULL;

    fetch_ctx->req = req;
    fetch_ctx->ctx = ctx;
    fetch_ctx->resolve = resolve;
    fetch_ctx->reject = reject;
    fetch_ctx->type = A_QJS_REQ_TYPE;

    return fetch_ctx;
}

void aura_qjs_fetch_ctx_destroy(struct aura_js_fetch_ctx *fetch_ctx) {
    if (!fetch_ctx)
        return;

    JS_FreeValue(fetch_ctx->ctx, fetch_ctx->reject);
    JS_FreeValue(fetch_ctx->ctx, fetch_ctx->resolve);

    if (fetch_ctx->req)
        aura_rt_req_destroy(fetch_ctx->req);

    aura_free(fetch_ctx);
}

/**
 * This will take care of destroying the
 * request structure incase of failure
 */
int aura_qjs_create_fetch_request(struct aura_srv_ctx *srv_ctx, JSContext *ctx, Request *js_req, JSValue *fns) {
    struct aura_js_fetch_ctx *fetch_ctx;
    const char *scheme;
    int res;
    JSValue val;

    fetch_ctx = aura_qjs_fetch_ctx_create(srv_ctx->mc, js_req, ctx, fns[0], fns[1]);
    if (!fetch_ctx) {
        aura_rt_req_destroy(js_req);
        return -1;
    }

    if (aura_h2_client_req_create(fetch_ctx, srv_ctx) < 0) {
        /* Req is destroyed by fn */
        aura_qjs_fetch_ctx_destroy(fetch_ctx);
        return -1;
    }

    return 0;
}

int aura_qjs_trigger_promise_rejection(JSContext *ctx, JSValue reject_fn, const char *err) {
    JSValue ret_val, error = JS_NewError(ctx);

    JS_DefinePropertyValueStr(
      ctx,
      error,
      "message",
      JS_NewString(ctx, err),
      JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);

    JSValue argv[] = {error};
    ret_val = JS_Call(ctx, reject_fn, JS_UNDEFINED, 1, argv);
    if (JS_IsException(ret_val))
        return -1;

    JS_FreeValue(ctx, ret_val);
    JS_FreeValue(ctx, error);

    return 0;
}