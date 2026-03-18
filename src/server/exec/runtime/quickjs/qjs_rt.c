#include "exec/runtime_srv.h"
#include "exec/task_srv.h"
#include "function_lib.h"
#include "quickjs-libc.h"
#include "quickjs.h"
#include "time_lib.h"
#include "types_lib.h"

#include <pthread.h>
#include <stdlib.h>

extern JSClassID req_class_id;
extern JSClassID res_class_id;

extern const JSCFunctionListEntry aura_js_request_proto_funcs[];
extern const uint32_t aura_js_request_proto_funcs_len;

int aura_qjs_interrupt_handler(JSRuntime *js_rt, void *opaque) {
    return 1;
}

/**
 * Initialize JS runtime and JS context, attach console logging,
 * fetch, and other capabilities based on function config
 */
int aura_qjs_init(st_aura_runtime *r, void *data) {
    struct aura_qjs_runtime *qjs;
    struct aura_fn *fn;
    JSValue obj, module;
    int res;

    app_debug(true, 0, "aura_qjs_init <<<");
    r->rt_data = NULL;
    qjs = malloc(sizeof(*qjs));
    if (!qjs)
        return -1;

    qjs->rt = JS_NewRuntime();
    if (!qjs->rt) {
        goto err_runtime;
    }

    qjs->ctx = JS_NewContext(qjs->rt);
    if (!qjs->ctx) {
        goto err_context;
    }

    aura_js_console_init(qjs);
    res = aura_js_fetch_init(qjs);
    if (res != 0)
        goto err_object_class;

    fn = data;

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
    r->rt_data = qjs;
    return 0;
err_bytecode:
    JS_FreeValue(qjs->ctx, obj);
err_object_class:
    JS_FreeContext(qjs->ctx);
err_context:
    JS_FreeRuntime(qjs->rt);
err_runtime:
    return 1;
}

void aura_qjs_destroy(struct aura_runtime *r) {
    struct aura_qjs_runtime *qjs;

    qjs = r->rt_data;
    if (!qjs)
        return;

    if (!JS_IsUndefined(qjs->func_handler))
        JS_FreeValue(qjs->ctx, qjs->func_handler);

    if (qjs->ctx)
        JS_FreeContext(qjs->ctx);
    if (qjs->rt)
        JS_FreeRuntime(qjs->rt);
}

int aura_qjs_execute(struct aura_runtime *r, struct aura_task *task) {
    struct aura_qjs_runtime *qjs;
    JSValue val, val1, exception;
    const char *err;
    JSValue js_req, js_res;
    app_debug(true, 0, "aura_qjs_execute <<<");

    task->started_at = aura_now_ns(CLOCK_MONOTONIC);

    qjs = r->rt_data;
    js_req = JS_NewObjectClass(qjs->ctx, req_class_id);
    if (JS_IsException(js_req)) {
        app_debug(true, 0, "aura_qjs_execute: js_req object class");
        return -1;
    }
    JS_SetOpaque(js_req, task->req_data);

    js_res = JS_NewObjectClass(qjs->ctx, res_class_id);
    if (JS_IsException(js_res)) {
        app_debug(true, 0, "aura_qjs_execute: js_res object class");
        goto req_error;
    }
    JS_SetOpaque(js_res, task->res_data);

    JSValue arg[] = {js_req, js_res};
    val = JS_Call(qjs->ctx, qjs->func_handler, JS_UNDEFINED, 2, arg);
    if (JS_IsException(val)) {
        aura_js_std_dump_error(qjs->ctx, NULL);
        goto res_error;
    }
    val1 = aura_js_std_await(qjs->ctx, val);
    if (JS_IsException(val1)) {
        goto call_error;
    }

    task->completed_at = aura_now_ns(CLOCK_MONOTONIC);

    return 0;

call_error:
    JS_FreeValue(qjs->ctx, val);
res_error:
    JS_FreeValue(qjs->ctx, js_res);
req_error:
    JS_FreeValue(qjs->ctx, js_req);
    return -1;
}

st_aura_runtime_ops qjs_ops = {
  .init = aura_qjs_init,
  .destroy = aura_qjs_destroy,
  .execute = aura_qjs_execute,
};