#include "exec/runtime_srv.h"
#include "function_lib.h"
#include "quickjs/quickjs-libc.h"
#include "quickjs/quickjs.h"
#include "time_lib.h"
#include "types_lib.h"

#include <pthread.h>
#include <stdlib.h>

extern JSClassID req_class_id;

extern const JSCFunctionListEntry aura_js_request_proto_funcs[];
extern const uint32_t aura_js_request_proto_funcs_len;

int aura_qjs_interrupt_handler(JSRuntime *js_rt, void *opaque) {
    return 1;
}

/** @todo: fix these function declarations to match the 'st_aura_runtime_ops' decalarations */
int aura_qjs_init(st_aura_qjs_runtime *qjs, struct aura_fn *fn) {
    JSValue bytecode;
    int res;

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
    if (!res)
        goto err_object_class;

    bytecode = JS_ReadObject(qjs->ctx, fn->fn_code, fn->fn_code_len, JS_READ_OBJ_BYTECODE);
    if (JS_IsException(bytecode)) {
        js_std_dump_error(qjs->ctx);
        goto err_object_class;
    }

    qjs->func = JS_EvalFunction(qjs->ctx, bytecode);
    if (JS_IsException(qjs->func)) {
        js_std_dump_error(qjs->ctx);
        goto err_evalfunc;
    }

    /** @todo: set runtime limitations according to config */
    return 0;
err_evalfunc:
    JS_FreeValue(qjs->ctx, bytecode);
err_object_class:
    JS_FreeContext(qjs->ctx);
err_context:
    JS_FreeRuntime(qjs->rt);
err_runtime:
    return 1;
}

void aura_qjs_destroy(st_aura_qjs_runtime *qjs) {
    if (!qjs)
        return;

    if (!JS_IsUndefined(qjs->func))
        JS_FreeValue(qjs->ctx, qjs->func);

    if (qjs->ctx)
        JS_FreeContext(qjs->ctx);
    if (qjs->rt)
        JS_FreeRuntime(qjs->rt);
}

int aura_qjs_execute(st_aura_qjs_runtime *qjs, struct aura_task *task) {
    JSValue val, res, exception;
    const char *err;
    JSValue js_req;
    struct aura_http_req *req;

    task->started_at = aura_now_ns();

    js_req = JS_NewObjectClass(qjs->ctx, req_class_id);
    JS_SetOpaque(js_req, task->data);

    JSValue arg[1] = {js_req};
    res = JS_Call(qjs->ctx, qjs->func, JS_UNDEFINED, 1, arg);
    if (JS_IsException(res)) {
        js_std_dump_error(qjs->ctx);
        exception = JS_GetException(qjs->ctx);
        err = JS_ToCString(qjs->ctx, exception);
        return 1;
    }

    return 0;
}

st_aura_runtime_ops qjs_ops = {
  .init = aura_qjs_init,
  .destroy = aura_qjs_destroy,
  .execute = aura_qjs_execute,
};