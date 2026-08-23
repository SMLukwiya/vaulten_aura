#include "rt.h"
#include "bindings.h"
#include "bug_lib.h"
#include "event_ctx/context.h"
#include "file/lib.h"

/* Context Id */
JSClassID context_id;
/* Context event Id */
JSClassID event_id;
/* Request id */
JSClassID request_id;
/* Response id */
JSClassID response_id;
/* Text encoder id */
JSClassID text_encoder_id;
/* Text decoder id */
JSClassID text_decoder_id;

static bool class_id_init = false;

/* Context class definition */
static JSClassDef context_class = {
  .class_name = "Context",
  .finalizer = NULL,
};

/* Event class definition */
static JSClassDef event_class = {
  .class_name = "Context Events",
};

/* Request class definition */
static JSClassDef request_class = {
  .class_name = "Request",
};

static void a_qjs_response_finalizer(JSRuntime *rt, JSValue val) {
    Response *res = JS_GetOpaque(val, response_id);
    aura_res_destroy(res);
}

/* Response class definition */
static JSClassDef response_class = {
  .class_name = "Response",
  .finalizer = a_qjs_response_finalizer,
};

/* Text encoder class definition */
static JSClassDef text_encoder_class = {
  .class_name = "Text Decoder",
};

static void a_qjs_text_decoder_finalizer(JSRuntime *rt, JSValue val) {
    struct aura_qjs_text_decoder_data *d =
      (struct aura_qjs_text_decoder_data *)JS_GetOpaque(val, text_decoder_id);
    if (d) {
        js_free_rt(rt, d);
    }
}

/* Text decoder class definition */
static JSClassDef text_decoder_class = {
  .class_name = "Text_Decoder",
  .finalizer = a_qjs_text_decoder_finalizer,
};

void aura_qjs_class_ids_init(void) {
    JS_NewClassID(&context_id);
    JS_NewClassID(&event_id);
    JS_NewClassID(&request_id);
    JS_NewClassID(&response_id);
    JS_NewClassID(&text_encoder_id);
    JS_NewClassID(&text_decoder_id);
    class_id_init = true;
}

/**
 * Quickjs custom memory allocation functions
 */
extern JSMallocFunctions aura_qjs_mem_fns;

/**/
static void a_qjs_context_destroy(JSContext *ctx);

/**/
static JSRuntime *a_qjs_runtime_create(struct aura_fn *fn, void *rt_data) {
    JSRuntime *rt;

    rt = JS_NewRuntime2(&aura_qjs_mem_fns, rt_data);
    if (!rt)
        return NULL;

    JS_SetRuntimeOpaque(rt, rt_data);

    JS_NewClass(rt, context_id, &context_class);
    JS_NewClass(rt, event_id, &event_class);
    JS_NewClass(rt, request_id, &request_class);
    JS_NewClass(rt, response_id, &response_class);
    JS_NewClass(rt, text_encoder_id, &text_encoder_class);
    JS_NewClass(rt, text_decoder_id, &text_decoder_class);

    return rt;
}

/**/
static void a_qjs_runtime_destroy(JSRuntime *rt) {
    struct aura_qjs_rt_data *data = JS_GetRuntimeOpaque(rt);
    A_BUG_ON_2(!data, true);
    aura_free(data);
    JS_FreeRuntime(rt);
}

int aura_qjs_write_bytecode(JSContext *ctx, const char *input, uint64_t input_len,
                            const char *module_name, uint8_t **bytecode,
                            uint64_t *bytecode_len) {
    JSValue obj = JS_Eval(
      ctx, input, input_len, module_name, JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
    if (JS_IsException(obj)) {
        aura_js_std_dump_error(ctx, NULL);
        return -1;
    }

    *bytecode = JS_WriteObject(ctx, bytecode_len, obj, JS_WRITE_OBJ_BYTECODE);
    JS_FreeValue(ctx, obj);
    if (!bytecode)
        return -1;

    return 0;
}

int aura_qjs_read_bytecode(JSContext *ctx, void *code, uint64_t code_len, JSValue *handler) {
    JSValue obj, module;

    obj = JS_ReadObject(ctx, code, code_len, JS_READ_OBJ_BYTECODE);
    if (JS_IsException(obj)) {
        aura_js_std_dump_error(ctx, NULL);
        return -1;
    }

    if (JS_VALUE_GET_TAG(obj) == JS_TAG_MODULE)
        if (JS_ResolveModule(ctx, obj) < 0) {
            JS_FreeValue(ctx, obj);
            aura_js_std_dump_error(ctx, NULL);
            return -1;
        }

    /* Verify we have a function */
    module = JS_EvalFunction(ctx, obj);
    if (JS_IsException(module)) {
        JS_FreeValue(ctx, obj);
        aura_js_std_dump_error(ctx, NULL);
        return -1;
    }

    module = aura_js_std_await(ctx, module);
    if (JS_IsException(module)) {
        JS_FreeValue(ctx, obj);
        aura_js_std_dump_error(ctx, NULL);
        return -1;
    }
    JS_FreeValue(ctx, module);

    JSModuleDef *m = JS_VALUE_GET_PTR(obj);
    JSValue val = JS_GetModuleNamespace(ctx, m);
    *handler = JS_GetPropertyStr(ctx, val, "default");
    JS_FreeValue(ctx, obj);
    JS_FreeValue(ctx, val);

    return 0;
}

void aura_qjs_execution_context_destroy(struct aura_qjs_execution_ctx *exec_ctx) {
    aura_list_delete(&exec_ctx->node);
    JS_FreeValue(exec_ctx->ctx, exec_ctx->fn_handler);
    JS_FreeValue(exec_ctx->ctx, exec_ctx->fn_arg);

    a_qjs_context_destroy(exec_ctx->ctx);
    a_qjs_runtime_destroy(exec_ctx->rt);
    aura_free(exec_ctx);
}

extern const JSCFunctionListEntry aura_qjs_event_proto_funcs[];
extern const uint32_t aura_qjs_event_proto_fns_len;

extern const JSCFunctionListEntry aura_qjs_req_proto_funcs[];
extern const uint32_t aura_qjs_req_proto_fns_len;

/**
 *
 */
static int a_qjs_stream_polyfill_init(JSContext *ctx) {
    JSValue val;
    uint8_t *stream_ponyfill;
    char buf[1024];
    uint64_t len;
    int fd, rv = 0;

    if (aura_get_dir_from_file_path(__FILE__, buf, sizeof(buf)) < 0)
        return -1;
    strncat(buf + strlen(buf), "/stream_polyfill.js", sizeof(buf) - strlen(buf));

    fd = open(buf, O_RDONLY);
    stream_ponyfill = aura_load_file(fd, &len);

    val = JS_Eval(ctx, stream_ponyfill, len, "stream_polyfill", JS_EVAL_TYPE_GLOBAL);
    if (JS_IsException(val)) {
        rv = -1;
    }
    JS_FreeValue(ctx, val);

    return rv;
}

/**
 *
 */
static JSContext *a_qjs_context_create(JSRuntime *rt, struct aura_fn *fn, void *evt_ctx,
                                       console_init console_fn, aura_js_fetch_fn fetch_fn) {
    JSContext *ctx;
    JSValue ctx_proto, event_proto;
    JSValue request_proto, response_proto;
    JSValue text_dec_enc_proto, global_obj;

    ctx = JS_NewContext(rt);
    if (!ctx)
        return NULL;

    if (a_qjs_stream_polyfill_init(ctx) < 0) {
        app_debug(true, 0, "FAILED TO INIT STREAM POLYFILL");
        JS_FreeContext(ctx);
        return NULL;
    }

    ctx_proto = JS_NewObject(ctx);
    if (JS_IsException(ctx_proto)) {
        JS_FreeContext(ctx);
        return NULL;
    }

    event_proto = JS_NewObject(ctx);
    if (JS_IsException(event_proto)) {
        ctx = NULL;
        goto fail_ctx_proto;
    }

    request_proto = JS_NewObject(ctx);
    if (JS_IsException(request_proto)) {
        goto fail_evt_proto;
    }

    if (aura_qjs_response_binding_init(ctx) < 0) {
        goto fail_req_proto;
    }

    if (aura_qjs_text_dec_init(ctx) < 0) {
        goto fail_res_obj;
    }

    if (aura_qjs_text_enc_init(ctx) < 0) {
        goto fail_text_dec;
    }

    JS_SetContextOpaque(ctx, evt_ctx);
    JS_SetPropertyFunctionList(ctx, event_proto, aura_qjs_event_proto_funcs, aura_qjs_event_proto_fns_len);
    JS_SetClassProto(ctx, event_id, event_proto);

    JS_SetPropertyFunctionList(ctx, request_proto, aura_qjs_req_proto_funcs, aura_qjs_req_proto_fns_len);
    JS_SetClassProto(ctx, request_id, request_proto);

    /* Dup value needed */
    JS_DefinePropertyValueStr(ctx, event_proto, "request", JS_DupValue(ctx, request_proto), JS_PROP_ENUMERABLE);

    /* console is generic */
    if (console_fn)
        console_fn(ctx);

    /* Fetch is generic */
    if (fetch_fn) {
        global_obj = JS_GetGlobalObject(ctx);
        JS_SetPropertyStr(ctx, global_obj, "fetch", JS_NewCFunction(ctx, fetch_fn, "fetch", 1));
        JS_FreeValue(ctx, global_obj);
    }

    /* Dup value needed! */
    JS_DefinePropertyValueStr(ctx, ctx_proto, "event", JS_DupValue(ctx, event_proto), JS_PROP_ENUMERABLE);
    JS_SetClassProto(ctx, context_id, ctx_proto);

    return ctx;

fail_text_dec:
    aura_qjs_text_dec_destroy(ctx);

fail_res_obj:
    aura_qjs_response_binding_destroy(ctx);

fail_req_proto:
    JS_FreeValue(ctx, request_proto);

fail_evt_proto:
    JS_FreeValue(ctx, event_proto);

fail_ctx_proto:
    JS_FreeValue(ctx, ctx_proto);
    JS_FreeContext(ctx);

    return NULL;
}

void a_qjs_context_destroy(JSContext *ctx) {
    struct aura_exec_ctx *exec_ctx = JS_GetContextOpaque(ctx);
    A_BUG_ON_2(!exec_ctx, true);
    aura_free(exec_ctx);

    JSValue request_proto = JS_GetClassProto(ctx, request_id);
    JS_FreeValue(ctx, request_proto);

    JSValue event_proto = JS_GetClassProto(ctx, event_id);
    JS_FreeValue(ctx, event_proto);

    aura_qjs_text_dec_destroy(ctx);

    aura_qjs_text_enc_destroy(ctx);

    aura_qjs_response_binding_destroy(ctx);

    JSValue ctx_proto = JS_GetClassProto(ctx, context_id);
    JS_FreeValue(ctx, ctx_proto);

    JS_FreeContext(ctx);
}

static inline int a_qjs_context_set_fn_arg(JSContext *ctx, struct aura_exec_ctx *evt_ctx, JSValue *fn_arg) {
    JSValue ctx_obj;

    ctx_obj = JS_NewObjectClass(ctx, context_id);
    if (JS_IsException(ctx_obj))
        return -1;

    JS_SetOpaque(ctx_obj, evt_ctx);
    *fn_arg = ctx_obj;
    return 0;
}

static struct aura_qjs_execution_ctx *
a_qjs_execution_context_create(struct aura_fn *fn, struct aura_mem_ctx *mc,
                               console_init console_fn, aura_js_fetch_fn fetch_fn) {
    struct aura_qjs_execution_ctx *c;
    struct aura_qjs_rt_data *rt_data;
    struct aura_exec_ctx *evt_ctx;
    JSValue obj, module, ctx_obj;

    A_BUG_ON_2(class_id_init == false, true);
    c = aura_alloc(mc, sizeof(*c));
    if (!c)
        return NULL;

    rt_data = aura_alloc(mc, sizeof(*rt_data));
    if (!rt_data) {
        aura_free(c);
        return NULL;
    }
    rt_data->mc = mc;
    rt_data->fetch_ctx = NULL;

    c->rt = a_qjs_runtime_create(fn, rt_data);
    if (!c->rt) {
        aura_free(rt_data);
        aura_free(c);
        return NULL;
    }

    evt_ctx = aura_alloc(mc, sizeof(*evt_ctx));
    if (!evt_ctx) {
        goto fail_rt;
    }

    c->ctx = a_qjs_context_create(c->rt, fn, evt_ctx, console_fn, fetch_fn);
    if (!c->ctx) {
        goto fail_ctx;
    }

    if (aura_qjs_read_bytecode(c->ctx, fn->fn_code, fn->fn_code_len, &c->fn_handler) < 0) {
        goto fail_bc;
    }

    if (a_qjs_context_set_fn_arg(c->ctx, evt_ctx, &c->fn_arg) < 0)
        goto fail_ctx_obj;

    return c;

fail_ctx_obj:
    JS_FreeValue(c->ctx, c->fn_handler);

fail_bc:
    a_qjs_context_destroy(c->ctx);

fail_ctx:
    aura_free(evt_ctx);

fail_rt:
    aura_free(rt_data);
    JS_FreeRuntime(c->rt);
    aura_free(c);

    return NULL;
}

int aura_qjs_execution_context_create(struct aura_fn_queue *fn_q, struct aura_mem_ctx *mc) {

    struct aura_qjs_execution_ctx *c;

    c = a_qjs_execution_context_create(fn_q->fn, mc, aura_js_console_init, aura_js_fetch);
    if (!c)
        return -1;

    aura_list_add(&fn_q->exec_slots, &c->node);
    ++fn_q->nr_exec_slots;
    return 0;
}

/** @todo: There could no need to attach response to exec_ctx anymore as there can be many instances */
int aura_qjs_prepare(struct aura_qjs_execution_ctx *exec_ctx, struct aura_task *task,
                     Request *req, Response *res) {
    struct aura_exec_ctx *event_ctx;
    JSValue arg, ctx_obj;

    event_ctx = JS_GetContextOpaque(exec_ctx->ctx);
    A_BUG_ON_2(!event_ctx, true);

    memset(&event_ctx->event, 0, sizeof(event_ctx->event));
    snprintf((char *)event_ctx->event.source_name, 64, "http");
    event_ctx->event.request = req;
    exec_ctx->task = task;
    return 0;
}

void aura_qjs_reset(struct aura_qjs_execution_ctx *exec_ctx) {
    struct aura_exec_ctx *event_ctx;

    event_ctx = JS_GetContextOpaque(exec_ctx->ctx);
    A_BUG_ON_2(!event_ctx, true);

    if (event_ctx->event.request) {
        aura_stream_provider_destroy(event_ctx->event.request->sp);
        aura_req_destroy(event_ctx->event.request);
    }

    // if (event_ctx->event.response)
    //     aura_res_destroy(event_ctx->event.response);

    event_ctx->event.request = NULL;
    // event_ctx->event.response = NULL;
}

JSValue aura_qjs_execute2(void *execution_context) {
    struct aura_qjs_execution_ctx *ec = execution_context;
    JSValue rv;

    JSValue argv[] = {ec->fn_arg};
    rv = JS_Call(ec->ctx, ec->fn_handler, JS_UNDEFINED, 1, argv);
    if (JS_IsException(rv)) {
        aura_js_std_dump_error(ec->ctx, "");
        rv = JS_GetException(ec->ctx);
        return rv;
    }

    JSValue res = aura_js_std_await(ec->ctx, rv);
    return res;
}

/* ============================== TEST ============================== */
struct aura_qjs_execution_ctx *aura_qjs_exec_ctx_create_test(struct aura_mem_ctx *mc, struct aura_fn *fn) {
    return a_qjs_execution_context_create(fn, mc, aura_js_console_test_init, aura_js_fetch_test_fn);
}

void aura_qjs_exec_ctx_destroy_test(struct aura_qjs_execution_ctx *exec_ctx) {
    JS_FreeValue(exec_ctx->ctx, exec_ctx->fn_handler);
    JS_FreeValue(exec_ctx->ctx, exec_ctx->fn_arg);

    a_qjs_context_destroy(exec_ctx->ctx);
    a_qjs_runtime_destroy(exec_ctx->rt);
    aura_free(exec_ctx);
}

void aura_qjs_reset_test(struct aura_qjs_execution_ctx *exec_ctx) {
    struct aura_qjs_rt_data *rt_data;
    struct aura_exec_ctx *event_ctx;
    Request *req;

    rt_data = JS_GetRuntimeOpaque(exec_ctx->rt);
    event_ctx = JS_GetContextOpaque(exec_ctx->ctx);
    A_BUG_ON_2(!event_ctx, true);
    req = event_ctx->event.request;

    if (req->sp) {
        aura_stream_provider_destroy(req->sp);
        req->sp = NULL;
    }

    struct aura_qjs_bc_consumer_data *bc_data = req->bc.opaque;
    if (bc_data) {
        JS_FreeValue(exec_ctx->ctx, bc_data->promise_reject);
        JS_FreeValue(exec_ctx->ctx, bc_data->promise_resolve);
        if (bc_data->accumulator)
            js_free(bc_data->ctx, bc_data->accumulator);
        js_free(bc_data->ctx, bc_data);
    }

    req->bc.opaque = NULL;

    if (rt_data->fetch_ctx)
        aura_qjs_fetch_ctx_destroy(rt_data->fetch_ctx);

    event_ctx->event.request = NULL;
    rt_data->fetch_ctx = NULL;
}

JSValue aura_qjs_execute_test(void *execution_context) {
    struct aura_qjs_execution_ctx *ec = execution_context;
    JSValue rv, val;
    int promise_state;

    JSValue argv[] = {ec->fn_arg};
    rv = JS_Call(ec->ctx, ec->fn_handler, JS_UNDEFINED, 1, argv);
    /* Reject errors immediately */
    while (JS_ExecutePendingJob(JS_GetRuntime(ec->ctx), NULL) > 0)
        ;

    promise_state = JS_PromiseState(ec->ctx, rv);
    if (promise_state == JS_PROMISE_REJECTED || promise_state == JS_PROMISE_FULFILLED) {
        val = JS_PromiseResult(ec->ctx, rv);
        if (promise_state == JS_PROMISE_REJECTED) {
            JS_Throw(ec->ctx, val);
            JS_FreeValue(ec->ctx, val);
            return JS_EXCEPTION;
        }
        JS_FreeValue(ec->ctx, rv);
        return val;
    }

    return rv;
}
