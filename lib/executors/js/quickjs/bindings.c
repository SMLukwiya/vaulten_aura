#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "bindings.h"
#include "bug_lib.h"
#include "error_lib.h"
#include "event_ctx/context.h"
#include "http_lib.h"
#include "mem.h"
#include "quickjs.h"
#include "quickjs_internals.h"
#include "request/req.h"
#include "string_lib.h"
#include "utils_lib.h"

static int32_t a_qjs_utf8_handler(A_QJS_TEXT_UTF8DecoderState *st, int byte_or_eof, int *restore_byte);

static int a_qjs_consumer_decode_utf8(JSContext *ctx, A_QJS_TEXT_UTF8DecoderState *st,
                                      const uint8_t *data, uint64_t len, uint8_t **data_out,
                                      uint64_t *data_out_len, bool streaming);

/* Check if va id of type array buffer */
static bool A_JS_ISArrayBuffer(JSContext *ctx, JSValue val) {
    JSValue ctor, global;
    bool rv;

    if (JS_VALUE_GET_TAG(val) != JS_TAG_OBJECT)
        return false;

    global = JS_GetGlobalObject(ctx);
    ctor = JS_GetPropertyStr(ctx, global, "ArrayBuffer");
    rv = JS_IsInstanceOf(ctx, val, ctor);

    JS_FreeValue(ctx, ctor);
    JS_FreeValue(ctx, global);

    return rv;
}

/* Check if val is of type Dataview*/
static bool A_JS_ISDataView(JSContext *ctx, JSValue val) {
    JSValue ctor, global;
    bool rv;

    if (JS_VALUE_GET_TAG(val) != JS_TAG_OBJECT)
        return false;

    global = JS_GetGlobalObject(ctx);
    ctor = JS_GetPropertyStr(ctx, global, "DataView");
    rv = JS_IsInstanceOf(ctx, val, ctor);

    JS_FreeValue(ctx, ctor);
    JS_FreeValue(ctx, global);

    return rv;
}

/* Check if val is of type typed array */
static bool A_JS_ISTypedArray(JSContext *ctx, JSValue val) {
    JSValue ctor, global;
    bool rv;

    if (JS_VALUE_GET_TAG(val) != JS_TAG_OBJECT)
        return false;

    global = JS_GetGlobalObject(ctx);
    ctor = JS_GetPropertyStr(ctx, global, "TypedArray");
    rv = JS_IsInstanceOf(ctx, val, ctor);

    JS_FreeValue(ctx, ctor);
    JS_FreeValue(ctx, global);

    return rv;
}

/* Check if val is of type readable stream */
static bool A_JS_ISReadableStream(JSContext *ctx, JSValue val) {
    JSValue ctor, global;
    bool rv;

    if (JS_VALUE_GET_TAG(val) != JS_TAG_OBJECT)
        return false;

    global = JS_GetGlobalObject(ctx);
    ctor = JS_GetPropertyStr(ctx, global, "ReadableStream");
    rv = JS_IsInstanceOf(ctx, val, ctor);

    JS_FreeValue(ctx, ctor);
    JS_FreeValue(ctx, global);

    return rv;
}

/* Check if cal is of type Response */
bool A_JS_ISResponse(JSContext *ctx, JSValue val) {
    JSValue ctor, global;
    bool rv;

    if (JS_VALUE_GET_TAG(val) != JS_TAG_OBJECT)
        return false;

    global = JS_GetGlobalObject(ctx);
    ctor = JS_GetPropertyStr(ctx, global, "Response");
    rv = JS_IsInstanceOf(ctx, val, ctor);

    JS_FreeValue(ctx, ctor);
    JS_FreeValue(ctx, global);

    return rv;
}

struct aura_qjs_fetch_ctx *aura_qjs_fetch_ctx_create(struct aura_mem_ctx *mc, Request *req,
                                                     JSContext *ctx, JSValue resolve,
                                                     JSValue reject, struct aura_qjs_body_src *src) {
    struct aura_qjs_fetch_ctx *fetch_ctx;

    fetch_ctx = aura_alloc(mc, sizeof(*fetch_ctx));
    if (!fetch_ctx)
        return NULL;

    fetch_ctx->req = req;
    fetch_ctx->ctx = ctx;
    fetch_ctx->resolve = resolve;
    fetch_ctx->reject = reject;
    fetch_ctx->type = 1;
    fetch_ctx->data_src = *src;

    return fetch_ctx;
}

void aura_qjs_fetch_ctx_destroy(struct aura_qjs_fetch_ctx *fetch_ctx) {
    if (!fetch_ctx)
        return;

    app_debug(true, 0, "aura_qjs_fetch_ctx_Destroy_A");
    JS_FreeValue(fetch_ctx->ctx, fetch_ctx->reject);
    JS_FreeValue(fetch_ctx->ctx, fetch_ctx->resolve);
    if (fetch_ctx->data_src.type != A_QJS_BODY_TYPE_EMPTY)
        fetch_ctx->data_src.ops->destroy(&fetch_ctx->data_src);
    app_debug(true, 0, "aura_qjs_fetch_ctx_Destroy_D");

    aura_free(fetch_ctx);
}

/* console log */
JSValue aura_js_console_log(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    for (int i = 0; i < argc; ++i) {
        const char *str = JS_ToCString(ctx, argv[i]);
        if (str) {
            syslog(LOG_INFO, "%s", str);
            JS_FreeCString(ctx, str);
        }
    }
    return JS_UNDEFINED;
}

/* console error */
JSValue aura_js_console_error(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    for (int i = 0; i < argc; ++i) {
        const char *str = JS_ToCString(ctx, argv[i]);
        if (str) {
            syslog(LOG_ERR, "%s", str);
            JS_FreeCString(ctx, str);
        }
    }
    return JS_UNDEFINED;
}

/**
 * Setup console structure
 */
void aura_js_console_init(JSContext *ctx) {
    JSValue global_obj;
    JSValue console;

    console = JS_NewObject(ctx);
    global_obj = JS_GetGlobalObject(ctx);

    JS_SetPropertyStr(ctx, console, "log", JS_NewCFunction(ctx, aura_js_console_log, "log", 1));
    JS_SetPropertyStr(ctx, console, "info", JS_NewCFunction(ctx, aura_js_console_log, "info", 1));
    JS_SetPropertyStr(ctx, console, "error", JS_NewCFunction(ctx, aura_js_console_error, "error", 1));
    JS_SetPropertyStr(ctx, console, "warn", JS_NewCFunction(ctx, aura_js_console_error, "warn", 1));

    JS_SetPropertyStr(ctx, global_obj, "console", console);
    JS_FreeValue(ctx, global_obj);
}

/* ---- logger ---- */
void aura_log_structured_error(const char *name, const char *message, const char *stack) {
    syslog(LOG_INFO, "Name; %s", name);
    syslog(LOG_INFO, "Message; %s", message);
    syslog(LOG_INFO, "Stack; %s", stack);
}

/* ---- std dump error */
void aura_js_std_dump_error(JSContext *ctx, char *msg) {
    JSValue exc, name, message, stack;

    if (msg) {
        aura_log_structured_error(NULL, msg, NULL);
    } else {
        exc = JS_GetException(ctx);
        name = JS_GetPropertyStr(ctx, exc, "name");
        message = JS_GetPropertyStr(ctx, exc, "message");
        stack = JS_GetPropertyStr(ctx, exc, "stack");

        aura_log_structured_error(JS_ToCString(ctx, name), JS_ToCString(ctx, message), JS_ToCString(ctx, stack));

        JS_FreeValue(ctx, name);
        JS_FreeValue(ctx, message);
        JS_FreeValue(ctx, stack);
        JS_FreeValue(ctx, exc);
    }
}

/* ---- std await ---- */
JSValue aura_js_std_await(JSContext *ctx, JSValue obj) {
    JSValue rv;
    int state;

    for (;;) {
        state = JS_PromiseState(ctx, obj);
        if (state == JS_PROMISE_FULFILLED) {
            rv = JS_PromiseResult(ctx, obj);
            JS_FreeValue(ctx, obj);
            break;
        } else if (state == JS_PROMISE_REJECTED) {
            rv = JS_Throw(ctx, JS_PromiseResult(ctx, obj));
            JS_FreeValue(ctx, obj);
            break;
        } else if (state == JS_PROMISE_PENDING) {
            int err;
            err = JS_ExecutePendingJob(JS_GetRuntime(ctx), NULL);
            if (err < 0) {
                rv = JS_GetException(ctx);
                JS_FreeValue(ctx, obj);
                break;
            } else if (err == 0) {
                rv = JS_UNDEFINED;
            }
        } else {
            /* not a promise */
            rv = obj;
            break;
        }
    }
    return rv;
}

/**
 * Memory Functions
 */
static void
  __attribute__((format(printf, 2, 3)))
  a_qjs_trace_malloc_printf(JSMallocState *s, const char *fmt, ...) {
    va_list ap;
    int c;

    va_start(ap, fmt);
    while ((c = *fmt++) != '\0') {
        if (c == '%') {
            /* only handle %p and %zd */
            if (*fmt == 'p') {
                uint8_t *ptr = va_arg(ap, void *);
                if (ptr == NULL) {
                    printf("NULL");
                } else {
                    struct aura_slab_obj_hdr *hdr = aura_slab_obj_get_hdr(ptr);
                    printf("%p, a_size=%zu",
                           ptr,
                           aura_slab_obj_get_big_size(ptr));
                }
                fmt++;
                continue;
            }
            if (fmt[0] == 'z' && fmt[1] == 'u') {
                uint64_t sz = va_arg(ap, uint64_t);
                printf("%zu", sz);
                fmt += 2;
                continue;
            }
        }
        putc(c, stdout);
    }
    va_end(ap);
}

static void *a_js_malloc(JSMallocState *s, uint64_t size) {
    struct aura_qjs_rt_data *rdata = s->opaque;
    A_BUG_ON_2(!rdata, true);
    struct aura_mem_ctx *mc = rdata->mc;
    void *ptr;

    if (size == 0)
        return NULL;

    if ((s->malloc_size + size) > s->malloc_limit)
        return NULL;

    ptr = aura_alloc(mc, size);
    struct aura_slab_obj_hdr *hdr = aura_slab_obj_get_hdr(ptr);
    // a_qjs_trace_malloc_printf(s, "Realloc: ptr=%p\n", ptr);
    if (!ptr)
        return NULL;

    ++s->malloc_count;
    s->malloc_size += aura_slab_obj_get_big_size(ptr);

    return ptr;
}

static void *a_js_realloc(JSMallocState *s, void *ptr, uint64_t size) {
    struct aura_qjs_rt_data *rdata = s->opaque;
    A_BUG_ON_2(!rdata, true);
    struct aura_mem_ctx *mc = rdata->mc;
    uint64_t old_size;
    void *new_ptr;

    if (!ptr)
        return a_js_malloc(s, size);

    if (size == 0) {
        aura_free(ptr);
        return NULL;
    }

    /* Since realloc can resuse space */
    old_size = aura_slab_obj_get_big_size(ptr);
    if ((s->malloc_size + size - old_size) > s->malloc_limit)
        return NULL;

    new_ptr = aura_realloc(mc, ptr, size);
    struct aura_slab_obj_hdr *hdr = aura_slab_obj_get_hdr(new_ptr);
    // a_qjs_trace_malloc_printf(s, "Realloc: ptr=%p\n", new_ptr);
    if (!new_ptr)
        return NULL;

    s->malloc_size += aura_slab_obj_get_big_size(new_ptr) - old_size;

    return new_ptr;
}

static void a_js_free(JSMallocState *s, void *ptr) {
    if (!ptr)
        return;

    --s->malloc_count;
    s->malloc_size -= aura_slab_obj_get_big_size(ptr);
    // a_qjs_trace_malloc_printf(s, "Free ptr=%p\n", ptr);
    aura_free(ptr);
}

static uint64_t a_js_malloc_usable_size(const void *ptr) {
    return aura_slab_obj_get_big_size(ptr);
}

/* JS memory functions */
JSMallocFunctions aura_qjs_mem_fns = {
  .js_malloc = a_js_malloc,
  .js_free = a_js_free,
  .js_realloc = a_js_realloc,
  .js_malloc_usable_size = a_js_malloc_usable_size,
};

extern JSClassID context_id;
extern JSClassID event_id;
extern JSClassID request_id;
extern JSClassID response_id;
extern JSClassID text_encoder_id;
extern JSClassID text_decoder_id;

/* req.method */
static JSValue a_js_req_method_get(JSContext *ctx, JSValueConst this_val) {
    struct aura_exec_ctx *ec = JS_GetContextOpaque(ctx);
    A_BUG_ON_2(!ec, true);
    Request *req = ec->event.request;
    const char *method_str = a_http_methods_str[req->method];

    return JS_NewString(ctx, method_str);
}

static int a_qjs_get_method_from_str(const char *method, uint64_t len) {
    if (strncasecmp(method, "GET", len) == 0)
        return A_HTTP_GET;
    else if (strncasecmp(method, "POST", len) == 0)
        return A_HTTP_POST;
    else if (strncasecmp(method, "HEAD", len) == 0)
        return A_HTTP_HEAD;
    else {
        return A_HTTP_NONE;
    }
}

/**/
int a_qjs_stream_init_fn(struct aura_stream_provider *sp, void *ctx) {
    struct aura_stream_provider_src *src = &sp->src;
    Request *req = ctx;
    int rv;

    src->data = req->body;
    src->len = req->body_len;
    src->fd = -1;
    src->off = 0;

    /**
     * Req body is not yet streamed, as such,
     * we add the entire the request body
     */
    rv = aura_stream_provider_enqueue(sp, (void *)src->data, src->len);
    /* We don't expect anymore data */
    sp->flags |= A_STREAM_DONE;
    return rv;
}

int a_qjs_stream_read_fn(struct aura_stream_provider *sp) {
    struct aura_stream_provider_src *src = &sp->src;
    void *data;
    uint64_t len;

    app_debug(true, 0, "a_qjs_stream_read_fn");
    data = (void *)src->data;
    len = src->len;
    sp->flags |= A_STREAM_DONE;

    return aura_stream_provider_enqueue(sp, data, len);
}

int a_qjs_stream_write_fn(struct aura_stream_provider *sp) {
    return 0;
}

void a_qjs_stream_destroy_fn(struct aura_stream_provider *sp) {
    sp->opaque_destructor(sp->opaque);
}

struct aura_stream_src_ops stream_src_ops = {
  .init = a_qjs_stream_init_fn,
  .read = a_qjs_stream_read_fn,
  .write = a_qjs_stream_write_fn,
  .destroy = a_qjs_stream_destroy_fn,
};

/* req.url */
static JSValue a_js_req_url_get(JSContext *ctx, JSValueConst this_val) {
    struct aura_exec_ctx *ec = JS_GetContextOpaque(ctx);
    A_BUG_ON_2(!ec, true);
    Request *req = ec->event.request;

    return JS_NewString(ctx, req->url.base);
}

/* req.body */
struct aura_qjs_stream_provider_opaque {
    JSContext *ctx;
    JSValue stream_obj;
    JSValue async_promise_cb[2];
};

JSValue a_stream_pull(JSContext *ctx, JSValueConst thi_val, int argc, JSValueConst *argv) {
    struct aura_exec_ctx *ec = JS_GetContextOpaque(ctx);
    A_BUG_ON_2(!ec, true);
    Request *req = ec->event.request;
    JSValue val, resolving_fns[2], promise;
    JSValue controller_enqueue_fn, controller_close_fn, controller_err_fn;
    JSValue res, js_chunk, rv;
    struct aura_stream_provider *sp;
    struct aura_qjs_stream_provider_opaque *opaque;
    struct aura_stream_chunk *chunk;

    app_debug(true, 0, "a_stream_pull_A");
    sp = req->sp;
    chunk = aura_stream_provider_dequeue(sp);

    if (chunk) {
        rv = JS_UNDEFINED;

        js_chunk = JS_NewArrayBuffer(ctx, (void *)chunk->data, chunk->len, NULL, NULL, 0);
        if (JS_IsException(js_chunk)) {
            controller_err_fn = JS_GetPropertyStr(ctx, argv[0], "error");
            val = JS_GetException(ctx);

            res = JS_Call(ctx, controller_err_fn, argv[0], 1, &val);
            JS_FreeValue(ctx, val);
            JS_FreeValue(ctx, res);
            JS_FreeValue(ctx, controller_err_fn);
        } else {
            controller_enqueue_fn = JS_GetPropertyStr(ctx, argv[0], "enqueue");
            res = JS_Call(ctx, controller_enqueue_fn, argv[0], 1, &js_chunk);
            JS_FreeValue(ctx, js_chunk);
            JS_FreeValue(ctx, res);
            JS_FreeValue(ctx, controller_enqueue_fn);
        }
        return rv;
    }

    /* Active stream with no data, pull some more data */
    if (!aura_stream_is_done(sp)) {
        if (aura_stream_provider_pull(sp) < 0) {
            controller_err_fn = JS_GetPropertyStr(ctx, argv[0], "error");
            val = JS_ThrowInternalError(ctx, "Internal pull error");

            res = JS_Call(ctx, controller_err_fn, argv[0], 1, &val);
            JS_FreeValue(ctx, val);
            JS_FreeValue(ctx, res);
            JS_FreeValue(ctx, controller_err_fn);
            return JS_UNDEFINED;
        }

        rv = JS_UNDEFINED;
        promise = JS_NewPromiseCapability(ctx, resolving_fns);
        if (JS_IsException(promise)) {
            controller_err_fn = JS_GetPropertyStr(ctx, argv[0], "error");
            val = JS_GetException(ctx);

            res = JS_Call(ctx, controller_err_fn, argv[0], 1, &val);
            JS_FreeValue(ctx, val);
            JS_FreeValue(ctx, res);
            JS_FreeValue(ctx, controller_err_fn);
        } else {
            opaque = sp->opaque;
            opaque->async_promise_cb[0] = JS_DupValue(ctx, resolving_fns[0]);
            opaque->async_promise_cb[1] = JS_DupValue(ctx, resolving_fns[1]);

            rv = promise;
        }

        return rv;
    }

    /* Stream done */
    controller_close_fn = JS_GetPropertyStr(ctx, argv[0], "close");
    res = JS_Call(ctx, controller_close_fn, argv[0], 0, &JS_UNDEFINED);
    JS_FreeValue(ctx, res);
    JS_FreeValue(ctx, controller_close_fn);

    return JS_UNDEFINED;
}

JSValue a_create_readable_stream(JSContext *ctx) {
    JSValue data_source, stream;

    app_debug(true, 0, "a_create_readable_stream");
    /**
     * Create data source and set the pull readable stream function
     */
    data_source = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, data_source, "pull", JS_NewCFunction(ctx, a_stream_pull, "pull", 1));

    JSValue global = JS_GetGlobalObject(ctx);
    JSValue rs_constructor = JS_GetPropertyStr(ctx, global, "ReadableStream");
    stream = JS_CallConstructor(ctx, rs_constructor, 1, (JSValueConst *)&data_source);
    if (JS_IsException(stream)) {
        aura_js_std_dump_error(ctx, "");
        return JS_UNDEFINED;
    }

    /**
     * Attach the readable stream data source to the stream object.
     * SetPropertyStr takes ownership, so we don't have to call
     * JS_FreeValue on it.
     */
    JS_SetPropertyStr(ctx, stream, "__stream", data_source);
    JS_FreeValue(ctx, global);
    JS_FreeValue(ctx, rs_constructor);
    return stream;
}

/* Destroy stream provider opaque */
void a_qjs_stream_opaque_destroy(void *opaque) {
    struct aura_qjs_stream_provider_opaque *op = opaque;
    JS_FreeValue(op->ctx, op->stream_obj);

    if (!JS_IsUndefined(op->async_promise_cb[0]))
        JS_FreeValue(op->ctx, op->async_promise_cb[0]);
    if (!JS_IsUndefined(op->async_promise_cb[1]))
        JS_FreeValue(op->ctx, op->async_promise_cb[1]);

    aura_free(opaque);
}

/* req.body */
static JSValue a_js_req_body_get(JSContext *ctx, JSValueConst this_val) {
    struct aura_qjs_stream_provider_opaque *opaque;
    struct aura_qjs_rt_data *th_data = JS_GetRuntimeOpaque(JS_GetRuntime(ctx));
    A_BUG_ON_2(!th_data, true);
    struct aura_exec_ctx *ec = JS_GetContextOpaque(ctx);
    A_BUG_ON_2(!ec, true);
    Request *req = ec->event.request;
    app_debug(true, 0, "a_js_req_body_get_A");

    /**
     * Create the stream provider on the fly.
     */
    if (!req->sp) {
        opaque = js_malloc(ctx, sizeof(*opaque)); // aura_alloc(th_data->mc, sizeof(*opaque));
        if (!opaque) {
            return JS_ThrowOutOfMemory(ctx);
        }
        opaque->ctx = ctx;
        opaque->stream_obj = JS_UNDEFINED;
        opaque->async_promise_cb[0] = JS_UNDEFINED;
        opaque->async_promise_cb[1] = JS_UNDEFINED;

        if (aura_req_stream_provider_create(
              th_data->mc,
              req,
              &stream_src_ops,
              opaque,
              a_qjs_stream_opaque_destroy) < 0) {
            aura_free(opaque);
            return JS_ThrowInternalError(ctx, "Internal error");
        }
    }

    opaque = req->sp->opaque;
    if (JS_IsUndefined(opaque->stream_obj)) {
        opaque->stream_obj = a_create_readable_stream(ctx);
        if (JS_IsException(opaque->stream_obj)) {
            return JS_ThrowInternalError(ctx, "Internal error");
        }

        opaque->stream_obj = JS_DupValue(ctx, opaque->stream_obj);
    }

    return opaque->stream_obj;
}

/* req.arrayBuffer() *zero-copy */
static JSValue a_js_req_arraybuffer(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    struct aura_exec_ctx *ec = JS_GetContextOpaque(ctx);
    A_BUG_ON_2(!ec, true);
    Request *req = ec->event.request;

    return JS_NewArrayBuffer(ctx, (uint8_t *)req->body, req->body_len, NULL, NULL, false);
}

/* req.text() */
static JSValue a_js_req_body_text(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    struct aura_exec_ctx *ec = JS_GetContextOpaque(ctx);
    A_BUG_ON_2(!ec, true);
    Request *req = ec->event.request;

    struct aura_body_consumer *bc = &req->bc;
    struct aura_qjs_bc_consumer_data *bc_data;
    A_QJS_TEXT_UTF8DecoderState *dec_st_ptr, dec_st = {0};
    uint8_t *out;
    uint64_t out_len;

    aura_req_dump(req);
    if (bc->state == A_BODY_NOT_CONSUMED) {
        if (!bc->opaque)
            dec_st_ptr = &dec_st;
        else {
            bc_data = bc->opaque;
            dec_st_ptr = &bc_data->st;
        }

        if (a_qjs_consumer_decode_utf8(ctx, dec_st_ptr, req->body, req->body_len, &out, &out_len, req->streaming) < 0)
            return JS_ThrowOutOfMemory(ctx);

        /**
         * res->streaming indicates if we should return a promise to the user
         * Decoded data is pointed to by out and out_len
         */
        if (req->streaming) {
            JSValue promise_fn[2];

            /* save the decoder state if we had not yet created one */
            if (!bc->opaque) {
                bc_data = js_malloc(ctx, sizeof(*bc_data));
                if (!bc_data) {
                    js_free(ctx, out);
                    return JS_ThrowOutOfMemory(ctx);
                }

                /* save current decoder state */
                bc_data->st = *dec_st_ptr;
                bc_data->ctx = ctx;
                bc_data->promise_resolve = JS_UNDEFINED;
                bc_data->promise_reject = JS_UNDEFINED;
                //     // bc_data->active_consumer =
            }

            /* Create user promise to return to the user */
            JSValue rv = JS_NewPromiseCapability(ctx, promise_fn);
            if (JS_IsException(rv)) {
                js_free(ctx, out);
                js_free(ctx, bc_data);
                JS_FreeValue(ctx, rv);
                return rv;
            }

            bc_data->promise_resolve = JS_DupValue(ctx, promise_fn[0]);
            bc_data->promise_reject = JS_DupValue(ctx, promise_fn[1]);

            JS_FreeValue(ctx, promise_fn[0]);
            JS_FreeValue(ctx, promise_fn[1]);

            /* store accumulated bytes so far */
            bc_data->accumulator = out;
            bc_data->accumulator_len = out_len;

            bc->state = A_BODY_CONSUMING;
            bc->opaque = (void *)bc_data;
            return rv;
        }

        bc->state = A_BODY_CONSUMED;
        JSValue str = JS_NewStringLen(ctx, (const char *)out, out_len);
        js_free(ctx, out);
        return str;
    } else
        /** @todo: use proper error message */
        return JS_ThrowTypeError(ctx, "Body locked or better error message");
}

/* -------------------------RESPONSE------------------------- */
/* Response readable stream initializer fn */
int a_res_qjs_stream_init_fn(struct aura_stream_provider *sp, void *ctx) {
    struct aura_stream_provider_src *src = &sp->src;
    Response *res = ctx;
    int rv;

    src->data = res->body;
    src->len = res->body_len;
    src->fd = -1;
    src->off = 0;

    /**
     * Req body is not yet streamed, as such,
     * we add the entire the request body
     */
    rv = aura_stream_provider_enqueue(sp, (void *)src->data, src->len);
    /* We don't expect anymore data */
    sp->flags |= A_STREAM_DONE;
    return rv;
}

/* Response stream read more data */
int a_res_qjs_stream_read_fn(struct aura_stream_provider *sp) {
    struct aura_stream_provider_src *src = &sp->src;
    void *data;
    uint64_t len;

    /* All data is treated as available for now */
    data = (void *)src->data;
    len = src->len;
    sp->flags |= A_STREAM_DONE;

    return aura_stream_provider_enqueue(sp, data, len);
}

/* Response stream write fn */
int a_res_qjs_stream_write_fn(struct aura_stream_provider *sp) {
    return 0;
}

/* Destroy response stream structure */
void a_res_qjs_stream_destroy_fn(struct aura_stream_provider *sp) {
    sp->opaque_destructor(sp->opaque);
}

struct aura_stream_src_ops res_stream_src_ops = {
  .init = a_res_qjs_stream_init_fn,
  .read = a_res_qjs_stream_read_fn,
  .write = a_res_qjs_stream_write_fn,
  .destroy = a_res_qjs_stream_destroy_fn,
};

/* res.body */
static JSValue a_qjs_res_body_get(JSContext *ctx, JSValueConst this_val) {
    struct aura_qjs_rt_data *rt_data = JS_GetRuntimeOpaque(JS_GetRuntime(ctx));
    A_BUG_ON_2(!rt_data, true);
    struct aura_qjs_stream_provider_opaque *opaque;
    Response *res = JS_GetOpaque2(ctx, this_val, response_id);
    app_debug(true, 0, "a_js_res_body_get_A");

    /**
     * Create the stream provider on the fly.
     */
    if (!res->sp) {
        opaque = js_malloc(ctx, sizeof(*opaque)); // aura_alloc(rt_data->mc, sizeof(*opaque));
        if (!opaque) {
            return JS_ThrowOutOfMemory(ctx);
        }
        opaque->ctx = ctx;
        opaque->stream_obj = JS_UNDEFINED;
        opaque->async_promise_cb[0] = JS_UNDEFINED;
        opaque->async_promise_cb[1] = JS_UNDEFINED;

        if (aura_res_stream_provider_create(
              rt_data->mc,
              res,
              &res_stream_src_ops,
              opaque,
              a_qjs_stream_opaque_destroy) < 0) {
            aura_free(opaque);
            return JS_ThrowInternalError(ctx, "Internal error");
        }
    }

    opaque = res->sp->opaque;
    if (JS_IsUndefined(opaque->stream_obj)) {
        opaque->stream_obj = a_create_readable_stream(ctx);
        if (JS_IsException(opaque->stream_obj)) {
            return JS_ThrowInternalError(ctx, "Internal error");
        }

        opaque->stream_obj = JS_DupValue(ctx, opaque->stream_obj);
    }

    return opaque->stream_obj;
}

/* res.bodyUsed */
static JSValue a_qjs_res_body_used(JSContext *ctx, JSValueConst this_val) {
    Response *res = JS_GetOpaque2(ctx, this_val, response_id);
    A_BUG_ON_2(!res, true);

    return JS_NewBool(ctx, res->body_used);
}

/* res.ok */
static JSValue a_qjs_res_ok(JSContext *ctx, JSValueConst this_val) {
    Response *res = JS_GetOpaque2(ctx, this_val, response_id);
    A_BUG_ON_2(!res, true);

    return JS_NewBool(ctx, res->ok);
}

/* res.redirected */
static JSValue a_qjs_res_redirected(JSContext *ctx, JSValueConst this_val) {
    Response *res = JS_GetOpaque2(ctx, this_val, response_id);
    A_BUG_ON_2(!res, true);

    return JS_NewBool(ctx, res->redirected);
}

/* res.status */
static JSValue a_qjs_res_get_status(JSContext *ctx, JSValueConst this_val) {
    Response *res = JS_GetOpaque2(ctx, this_val, response_id);
    A_BUG_ON_2(!res, true);

    return JS_NewInt32(ctx, (int32_t)res->status);
}

// static JSValue a_qjs_res_set_status(JSContext *ctx, JSValueConst this_val, JSValueConst status) {
//     Response *res;
//     int _status;

//     res = JS_GetOpaque2(ctx, this_val, response_id);
//     A_BUG_ON_2(!res, true);

//     if (JS_ToUint32(ctx, &_status, status))
//         return JS_EXCEPTION;

//     res->status = _status;
//     return JS_UNDEFINED;
// }

/* res.statusText */
static JSValue a_qjs_res_status_text(JSContext *ctx, JSValueConst this_val) {
    Response *res = JS_GetOpaque2(ctx, this_val, response_id);
    A_BUG_ON_2(!res, true);

    return JS_NewString(ctx, res->status_text);
}

/* res.type */
static JSValue a_qjs_res_type(JSContext *ctx, JSValueConst this_val) {
    Response *res = JS_GetOpaque2(ctx, this_val, response_id);
    A_BUG_ON_2(!res, true);

    return JS_NewString(ctx, "");
}

/* res.url */
static JSValue a_qjs_res_url(JSContext *ctx, JSValueConst this_val) {
    Response *res = JS_GetOpaque2(ctx, this_val, response_id);
    A_BUG_ON_2(!res, true);

    return JS_NewString(ctx, res->url.base);
}

/* res.arrayBuffer() */
static JSValue a_qjs_res_array_buffer(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    Response *res = JS_GetOpaque2(ctx, this_val, response_id);
    A_BUG_ON_2(!res, true);

    return JS_NewArrayBuffer(ctx, (uint8_t *)res->body, res->body_len, NULL, NULL, 0);
}

/* res.bytes() */
static JSValue a_qjs_res_bytes(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    Response *res = JS_GetOpaque2(ctx, this_val, response_id);
    A_BUG_ON_2(!res, true);
    JSValue rv;

    JSValue val = JS_NewArrayBuffer(ctx, (uint8_t *)res->body, res->body_len, NULL, NULL, 0);
    rv = JS_NewTypedArray(ctx, 1, &val, JS_TYPED_ARRAY_UINT8);
    JS_FreeValue(ctx, val);
    return rv;
}

static int a_qjs_consumer_decode_utf8(JSContext *ctx, A_QJS_TEXT_UTF8DecoderState *st,
                                      const uint8_t *data, uint64_t len, uint8_t **data_out,
                                      uint64_t *data_out_len, bool streaming) {

    /* generous upper bound */
    uint64_t max_out = (len + 4) * 3 + 16;
    uint8_t *out = js_malloc(ctx, max_out);
    if (!out)
        return -1;

    uint64_t out_len = 0, pos = 0;

    while (1) {
        int byte_or_eof;
        if (pos < len) {
            byte_or_eof = data[pos++];
        } else if (!streaming) {
            byte_or_eof = -1; /* end-of-queue */
        } else {
            /* streaming the input data, break */
            break;
        }

        int restore_byte = 0;
        int32_t result = a_qjs_utf8_handler(st, byte_or_eof, &restore_byte);

        if (result == A_QJS_TEXT_HANDLER_FINISHED) {
            break;
        } else if (result == A_QJS_TEXT_HANDLER_CONTINUE) {
            continue;
        } else if (result == A_QJS_TEXT_HANDLER_ERROR) {
            /* Replacement mode: emit U+FFFD */
            uint32_t replacement = 0xFFFD;
            out_len += aura_qjs_utf8_encode_cp(out + out_len, replacement);

            if (restore_byte) {
                pos--; /* re-process the byte */
            }
        } else {
            /* result is a code point */
            uint32_t cp = (uint32_t)result;
            out_len += aura_qjs_utf8_encode_cp(out + out_len, cp);
        }
    }

    *data_out = out;
    *data_out_len = out_len;
    return 0;
}

/* res.text() */
static JSValue a_qjs_res_text(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    Response *res = JS_GetOpaque2(ctx, this_val, response_id);
    A_BUG_ON_2(!res, true);
    struct aura_body_consumer *bc = &res->bc;
    struct aura_qjs_bc_consumer_data *bc_data;
    A_QJS_TEXT_UTF8DecoderState *dec_st_ptr, dec_st = {0};
    uint8_t *out;
    uint64_t out_len;

    if (bc->state == A_BODY_NOT_CONSUMED) {
        if (!bc->opaque)
            dec_st_ptr = &dec_st;
        else {
            bc_data = bc->opaque;
            dec_st_ptr = &bc_data->st;
        }

        if (a_qjs_consumer_decode_utf8(ctx, dec_st_ptr, res->body, res->body_len, &out, &out_len, res->streaming) < 0)
            return JS_ThrowOutOfMemory(ctx);

        /**
         * res->streaming indicates if we should return a promise to the user
         * Decoded data is pointed to by out and out_len
         */
        if (res->streaming) {
            JSValue promise_fn[2];

            /* save the decoder state if we had not yet created one */
            if (!bc->opaque) {
                bc_data = js_malloc(ctx, sizeof(*bc_data));
                if (!bc_data) {
                    js_free(ctx, out);
                    return JS_ThrowOutOfMemory(ctx);
                }

                /* save current decoder state */
                bc_data->st = *dec_st_ptr;
                bc_data->ctx = ctx;
                bc_data->promise_resolve = JS_UNDEFINED;
                bc_data->promise_reject = JS_UNDEFINED;
                // bc_data->active_consumer =
            }

            /* Create user promise to return to the user */
            JSValue rv = JS_NewPromiseCapability(ctx, promise_fn);
            if (JS_IsException(rv)) {
                js_free(ctx, out);
                js_free(ctx, bc_data);
                return rv;
            }

            bc_data->promise_resolve = JS_DupValue(ctx, promise_fn[0]);
            bc_data->promise_reject = JS_DupValue(ctx, promise_fn[1]);
            /* store accumulated bytes so far */
            bc_data->accumulator = out;
            bc_data->accumulator_len = out_len;

            bc->state = A_BODY_CONSUMING;
            bc->opaque = (void *)bc_data;

            return rv;
        }

        bc->state = A_BODY_CONSUMED;
        JSValue str = JS_NewStringLen(ctx, (const char *)out, out_len);
        js_free(ctx, out);
        return str;
    } else
        /** @todo: use proper error message */
        return JS_ThrowTypeError(ctx, "Body locked or better error message");
}

/* res.json() */
static JSValue a_qjs_res_json(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    Response *res = JS_GetOpaque2(ctx, this_val, response_id);
    A_BUG_ON_2(!res, true);

    A_QJS_TEXT_UTF8DecoderState st = {0};

    /* generous upper bound */
    uint64_t max_out = (res->body_len + 4) * 3 + 16;
    uint8_t *out = js_malloc(ctx, max_out);
    if (!out)
        return JS_EXCEPTION;

    uint64_t out_len = 0, pos = 0;

    while (1) {
        int byte_or_eof;
        if (pos < res->body_len) {
            byte_or_eof = res->body[pos++];
        } else {
            byte_or_eof = -1; /* end-of-queue */
        }

        int restore_byte = 0;
        int32_t result = a_qjs_utf8_handler(&st, byte_or_eof, &restore_byte);

        if (result == A_QJS_TEXT_HANDLER_FINISHED) {
            break;
        } else if (result == A_QJS_TEXT_HANDLER_CONTINUE) {
            continue;
        } else if (result == A_QJS_TEXT_HANDLER_ERROR) {
            /* Replacement mode: emit U+FFFD */
            uint32_t replacement = 0xFFFD;
            out_len += aura_qjs_utf8_encode_cp(out + out_len, replacement);

            if (restore_byte) {
                pos--; /* re-process the byte */
            }
        } else {
            /* result is a code point */
            uint32_t cp = (uint32_t)result;
            out_len += aura_qjs_utf8_encode_cp(out + out_len, cp);
        }
    }

    out[pos] = '\0';
    JSValue val = JS_ParseJSON(ctx, (const char *)out, out_len, "test");
    js_free(ctx, out);
    return val;
}

// static JSValue a_js_res_set_header(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
//     struct aura_qjs_rt_data *ts;
//     uint64_t name_len, value_len;
//     const char *n, *v;
//     Response *resp;
//     struct aura_kv_iovec *hdr_slot;

//     if (!argc != 2) {
//         return JS_ThrowTypeError(ctx, "set receives two arguments");
//     }

//     resp = JS_GetOpaque2(ctx, this_val, response_id);
//     A_BUG_ON_2(!resp, true);

//     ts = JS_GetRuntimeOpaque(JS_GetRuntime(ctx));
//     A_BUG_ON_2(!ts, true);

//     n = JS_ToCStringLen(ctx, &name_len, argv[0]);
//     if (!n || name_len == 0)
//         return JS_ThrowSyntaxError(ctx, "Header name can not be empty");

//     v = JS_ToCStringLen(ctx, &value_len, argv[1]);
//     if (!v) {
//         JS_FreeCString(ctx, n);
//         return JS_ThrowSyntaxError(ctx, "Header value can not be undefined");
//     }

//     hdr_slot = aura_res_get_kv_slot(ts->mc, resp);
//     if (!hdr_slot) {
//         JS_FreeCString(ctx, n);
//         JS_FreeCString(ctx, v);
//         return JS_ThrowOutOfMemory(ctx);
//     }

//     hdr_slot->key.base = aura_strndup(ts->mc, n, name_len);
//     hdr_slot->key.len = name_len;
//     hdr_slot->value.base = aura_strndup(ts->mc, n, name_len);
//     hdr_slot->value.len = value_len;

//     return JS_UNDEFINED;
// }

/**
 * Create json response from js object
 */
// static JSValue a_js_res_json(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
//     JSValue val;
//     Response *res;
//     struct aura_qjs_rt_data *ts;
//     const char *body;
//     uint64_t len;

//     res = JS_GetOpaque2(ctx, this_val, response_id);
//     A_BUG_ON_2(!res, true);

//     ts = JS_GetRuntimeOpaque(JS_GetRuntime(ctx));
//     A_BUG_ON_2(!ts, true);

//     val = JS_JSONStringify(ctx, argv[0], JS_UNDEFINED, JS_UNDEFINED);
//     if (JS_IsException(val))
//         return val;

//     body = JS_ToCStringLen(ctx, &len, val);
//     JS_FreeValue(ctx, val);

//     res->body = aura_memcpy(ts->mc, (void *)body, len);
//     res->body_len = len;

//     return JS_UNDEFINED;
// }

/* Js fetch implementation */
JSValue aura_js_fetch(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    struct aura_qjs_rt_data *ts;
    JSValue promise, options, val;
    JSValue resolving_funcs[2];
    JSValue js_error, headers;
    JSValue fns[2];
    const char *url, *method, *body;
    uint64_t url_len, method_len, body_len;
    Request *req;
    bool headers_provided;
    int res, _method;
    app_debug(true, 0, "FETCH CALLED <<<<");

    if (argc < 1 || argc > 2)
        return JS_EXCEPTION;

    ts = JS_GetRuntimeOpaque(JS_GetRuntime(ctx));
    if (!ts)
        return JS_EXCEPTION;

    // req = aura_rt_create_req(ts->mc);
    // if (!req)
    //     return JS_EXCEPTION;

    /* format: req(url, {}) */
    if (argc == 1) {
        if (JS_IsObject(argv[0])) {
            /* format: req({...}) */
            options = argv[0];
            val = JS_GetPropertyStr(ctx, options, "url");
            if (JS_IsException(val)) {
                return JS_EXCEPTION;
            }
            if (JS_IsUndefined(val)) {
                return JS_EXCEPTION;
            }
            url = JS_ToCStringLen(ctx, &url_len, val);
            JS_FreeValue(ctx, val);
            options = argv[1];
        } else {
            /* Invalid parameter */
            if (!JS_IsString(argv[0])) {
                return JS_EXCEPTION;
            }
            url = JS_ToCStringLen(ctx, &url_len, argv[0]);
            options = JS_NULL;
        }
    } else {
        /* format: req(url, {...}) */
        if (!JS_IsString(argv[0]) && !JS_IsObject(argv[1])) {
            return JS_EXCEPTION;
        }

        url = JS_ToCStringLen(ctx, &url_len, argv[0]);
        if (url_len == 0)
            return JS_EXCEPTION;

        options = argv[1];
    }

    /* url missing */
    if (!url)
        return JS_EXCEPTION;

    if (aura_url_parse(ts->mc, url, url_len, &req->parsed_url) < 0) {
        JS_FreeCString(ctx, url);
        return JS_EXCEPTION;
    }

    if (JS_IsNull(options)) {
        _method = A_HTTP_GET;
        body = NULL;
        body_len = 0;
    } else {
        val = JS_GetPropertyStr(ctx, options, "method");
        if (JS_IsException(val)) {
            JS_FreeCString(ctx, url);
            return JS_EXCEPTION;
        }
        if (JS_IsUndefined(val)) {
            _method = A_HTTP_GET;
        } else {
            if (!JS_IsString(val)) {
                JS_FreeCString(ctx, url);
                JS_FreeValue(ctx, val);
                return JS_EXCEPTION;
            }
            method = JS_ToCStringLen(ctx, &method_len, val);
            _method = a_qjs_get_method_from_str(method, method_len);
            JS_FreeCString(ctx, method);
        }
        JS_FreeValue(ctx, val);

        val = JS_GetPropertyStr(ctx, options, "body");
        if (JS_IsException(val)) {
            JS_FreeCString(ctx, url);
            return JS_EXCEPTION;
        }
        if (JS_IsUndefined(val)) {
            body = NULL;
            body_len = 0;
        } else {
            if (!JS_IsString(val)) {
                JS_FreeCString(ctx, url);
                JS_FreeValue(ctx, val);
                return JS_EXCEPTION;
            }
            body = JS_ToCStringLen(ctx, &body_len, val);
            JS_FreeValue(ctx, val);
        }

        if ((_method == A_HTTP_POST && !body) || (_method != A_HTTP_POST && body)) {
            JS_FreeCString(ctx, url);
            return JS_EXCEPTION;
        }

        JSPropertyEnum *props;
        uint32_t len;
        headers = JS_GetPropertyStr(ctx, options, "headers");
        headers_provided = false;

        if (JS_IsUndefined(headers)) {
            goto no_header;
        }
        headers_provided = true;

        if (JS_GetOwnPropertyNames(ctx, &props, &len, headers, JS_GPN_ENUM_ONLY | JS_GPN_STRING_MASK) < 0)
            goto err;

        for (int i = 0; i < len; ++i) {
            struct aura_kv_iovec *hdr_slot;
            uint64_t key_len, value_len;

            JSAtom atom = props[i].atom;

            const char *key = JS_AtomToCStringLen(ctx, &key_len, atom);
            // if (!aura_header_name_valid(key)) {
            //     JS_FreeCString(ctx, key);
            //     JS_FreeAtom(ctx, atom);
            //     goto err;
            // }

            // if (aura_header_value_forbidden(key)) {
            //     JS_FreeCString(ctx, key);
            //     JS_FreeAtom(ctx, atom);
            //     goto err;
            // }

            val = JS_GetPropertyStr(ctx, headers, key);
            const char *value = JS_ToCStringLen(ctx, &value_len, val);
            JS_FreeValue(ctx, val);
            JS_FreeAtom(ctx, atom);

            // if (!aura_header_value_valid(value)) {
            //     JS_FreeCString(ctx, key);
            //     JS_FreeCString(ctx, value);
            //     goto err;
            // }

            hdr_slot = aura_req_get_kv_slot(ts->mc, req);
            if (!hdr_slot) {
                JS_FreeCString(ctx, key);
                JS_FreeCString(ctx, value);
                goto err;
            }

            memset(hdr_slot, 0, sizeof(*hdr_slot));
            hdr_slot->key.base = aura_strndup(ts->mc, key, key_len);
            hdr_slot->key.len = key_len;
            hdr_slot->value.base = aura_strndup(ts->mc, value, value_len);
            hdr_slot->value.len = value_len;
            JS_FreeCString(ctx, key);
            JS_FreeCString(ctx, value);
        }
    no_header:
    }

    req->url.base = aura_str_tolowercase(ts->mc, url, url_len);
    req->url.len = url_len;
    req->body = aura_memcpy(ts->mc, body, body_len);
    req->body_len = body_len;

    fns[0] = JS_DupValue(ctx, resolving_funcs[0]);
    fns[1] = JS_DupValue(ctx, resolving_funcs[1]);

    // if (aura_qjs_create_fetch_request(ts, ctx, req, fns) < 0) {
    //     /* Function released req resources internally */
    //     req = NULL;
    //     goto err;
    // }

    promise = JS_NewPromiseCapability(ctx, resolving_funcs);
    return promise;
err:
    JS_FreeCString(ctx, url);
    if (body)
        JS_FreeCString(ctx, body);
    if (headers_provided)
        JS_FreeValue(ctx, headers);
    JS_FreeValue(ctx, fns[0]);
    JS_FreeValue(ctx, fns[1]);
    if (req)
        aura_req_destroy(req);
    js_error = JS_NewString(ctx, "Operation failed");
    JS_Throw(ctx, js_error);
    return JS_EXCEPTION;
}

const JSCFunctionListEntry aura_qjs_req_proto_funcs[] = {
  JS_CGETSET_DEF("method", a_js_req_method_get, NULL),
  JS_CGETSET_DEF("url", a_js_req_url_get, NULL),
  JS_CFUNC_DEF("arrayBuffer", 1, a_js_req_arraybuffer),
  JS_CFUNC_DEF("text", 1, a_js_req_body_text),
  JS_CGETSET_DEF("body", a_js_req_body_get, NULL),
};
const uint32_t aura_qjs_req_proto_fns_len = ARRAY_SIZE(aura_qjs_req_proto_funcs);

const JSCFunctionListEntry aura_js_response_proto_funcs[] = {
  JS_CGETSET_DEF("body", a_qjs_res_body_get, NULL),
  JS_CGETSET_DEF("bodyUsed", a_qjs_res_body_used, NULL),
  JS_CGETSET_DEF("ok", a_qjs_res_ok, NULL),
  JS_CGETSET_DEF("status", a_qjs_res_get_status, NULL),
  JS_CGETSET_DEF("ok", a_qjs_res_ok, NULL),
  JS_CGETSET_DEF("statusText", a_qjs_res_status_text, NULL),
  JS_CGETSET_DEF("type", a_qjs_res_type, NULL),
  JS_CGETSET_DEF("url", a_qjs_res_url, NULL),
  JS_CFUNC_DEF("arrayBuffer", 1, a_qjs_res_array_buffer),
  JS_CFUNC_DEF("bytes", 1, a_qjs_res_bytes),
  JS_CFUNC_DEF("json", 1, a_qjs_res_json),
  JS_CFUNC_DEF("text", 1, a_qjs_res_text),
  //   JS_CFUNC_DEF("set", 1, a_js_res_set_header),
};
const uint32_t aura_qjs_res_proto_fns_len = ARRAY_SIZE(aura_js_response_proto_funcs);

/* Determine response object body type */
static a_qjs_body_t a_qjs_get_body_type(JSContext *ctx, JSValue val) {
    if (A_JS_ISArrayBuffer(ctx, val))
        return A_QJS_BODY_TYPE_ARRAY_BUFFER;
    else if (A_JS_ISDataView(ctx, val))
        return A_QJS_BODY_TYPE_DATA_VIEW;
    else if (A_JS_ISReadableStream(ctx, val))
        return A_QJS_BODY_TYPE_READABLE_STREAM;
    else if (JS_IsString(val))
        return A_QJS_BODY_TYPE_STRING;
    else if (A_JS_ISTypedArray(ctx, val))
        return A_QJS_BODY_TYPE_TYPED_ARRAY;
    else
        return A_QJS_BODY_TYPE_INVALID;
}

/* Response constructor */
static JSValue a_qjs_response_constructor(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    a_qjs_body_t body_type = A_QJS_BODY_TYPE_EMPTY;
    struct aura_qjs_rt_data *rt_data;
    int status;
    const char *status_text;
    JSValue val;

    rt_data = JS_GetRuntimeOpaque(JS_GetRuntime(ctx));
    A_BUG_ON_2(!rt_data, true);

    if (argc > 2)
        return JS_ThrowRangeError(ctx, "Excess arguments provided for response constructor");

    if (argc > 0 && !JS_IsNull(argv[0]) && !JS_IsUndefined(argv[0])) {
        body_type = a_qjs_get_body_type(ctx, argv[0]);
        if (body_type == A_QJS_BODY_TYPE_INVALID)
            return JS_ThrowTypeError(ctx, "Invalid response body provided");
    }

    Response *resp = aura_res_create(rt_data->mc);
    if (!resp)
        return JS_ThrowOutOfMemory(ctx);

    if (body_type != A_QJS_BODY_TYPE_EMPTY) {
        const char *buf;
        uint64_t buf_len;
        uint64_t byte_off, byte_len, bpe;

        switch (body_type) {
        case A_QJS_BODY_TYPE_ARRAY_BUFFER:
            buf = JS_GetArrayBuffer(ctx, &buf_len, argv[0]);
            if (buf && buf_len > 0) {
                resp->body = js_malloc(ctx, buf_len); // aura_alloc(rt_data->mc, buf_len);
                if (!resp->body) {
                    aura_res_destroy(resp);
                    return JS_ThrowOutOfMemory(ctx);
                }

                memcpy((void *)resp->body, buf, buf_len);
            }
            break;

        case A_QJS_BODY_TYPE_TYPED_ARRAY:
            JSValue typed_arr = JS_GetTypedArrayBuffer(ctx, argv[0], &byte_off, &byte_len, &bpe);
            if (JS_IsException(typed_arr))
                return JS_ThrowTypeError(ctx, "Invalid typed array buffer provided");

            buf = JS_GetArrayBuffer(ctx, &buf_len, typed_arr);
            JS_FreeValue(ctx, typed_arr);
            if (buf && byte_len > 0) {
                resp->body = js_malloc(ctx, byte_len); // aura_alloc(rt_data->mc, byte_len);
                if (!resp->body) {
                    aura_res_destroy(resp);
                    return JS_ThrowOutOfMemory(ctx);
                }

                memcpy((void *)resp->body, buf + byte_off, byte_len);
            }
            break;

        case A_QJS_BODY_TYPE_DATA_VIEW:
            JSValue buf_val = JS_GetPropertyStr(ctx, argv[0], "buffer");
            JSValue off_val = JS_GetPropertyStr(ctx, argv[0], "byteOffset");
            JSValue len_val = JS_GetPropertyStr(ctx, argv[0], "byteLength");

            if (JS_IsException(buf_val) || JS_IsException(off_val) || JS_IsException(len_val)) {
                JS_FreeValue(ctx, buf_val);
                JS_FreeValue(ctx, off_val);
                JS_FreeValue(ctx, len_val);
                return JS_EXCEPTION;
            }

            JS_ToUint32(ctx, (uint32_t *)&byte_off, off_val);
            JS_ToUint32(ctx, (uint32_t *)&byte_len, len_val);
            JS_FreeValue(ctx, off_val);
            JS_FreeValue(ctx, len_val);

            buf = JS_GetArrayBuffer(ctx, &buf_len, buf_val);
            JS_FreeValue(ctx, buf_val);
            if (buf && byte_len > 0) {
                resp->body = js_malloc(ctx, byte_len); // aura_alloc(rt_data->mc, byte_len);
                if (!resp->body) {
                    aura_res_destroy(resp);
                    return JS_ThrowOutOfMemory(ctx);
                }

                memcpy((void *)resp->body, buf + byte_off, byte_len);
            }
            break;

        case A_QJS_BODY_TYPE_STRING:
            uint64_t str_len;
            const char *str = JS_ToCStringLen(ctx, &str_len, argv[0]);
            if (str_len > 0) {
                resp->body = aura_strndup(rt_data->mc, str, str_len);
                JS_FreeCString(ctx, str);
                if (!resp->body) {
                    return JS_ThrowOutOfMemory(ctx);
                }
                resp->body_len = str_len;
            }
            break;

        case A_QJS_BODY_TYPE_READABLE_STREAM:
            /* @todo:: */
            break;

        default:
            /* Should not reach */
            break;
        }
    }

    if (argc > 1 && !JS_IsNull(argv[1]) && !JS_IsUndefined(argv[1])) {
        if (!JS_IsObject(argv[1]))
            return JS_ThrowTypeError(ctx, "options parameter is not a valid javascript object");

        /* status */
        val = JS_GetPropertyStr(ctx, argv[1], "status");
        if (!JS_IsUndefined(val)) {
            if (!JS_IsNumber(val)) {
                JS_FreeValue(ctx, val);
                return JS_ThrowTypeError(ctx, "Invalid response status field provided.");
            }
            if (JS_ToInt32(ctx, &status, val) < 0) {
                JS_FreeValue(ctx, val);
                return JS_ThrowRangeError(ctx, "Could not determine provided response status");
            }
            JS_FreeValue(ctx, val);

            if (status < 200 || status > 599)
                return JS_ThrowRangeError(ctx, "Invalid response status %d provided", status);

            resp->status = status;
        }

        /* statusText */
        uint64_t st_len;

        val = JS_GetPropertyStr(ctx, argv[1], "statusText");
        if (!JS_IsUndefined(val)) {
            if (!JS_IsString(val)) {
                JS_FreeValue(ctx, val);
                return JS_ThrowTypeError(ctx, "Invalid response statusText field provided");
            }

            status_text = JS_ToCStringLen(ctx, &st_len, val);
            JS_FreeValue(ctx, val);
            if (st_len > 0) {
                resp->status_text = aura_strndup(rt_data->mc, status_text, st_len);
                if (!resp->status_text) {
                    JS_FreeCString(ctx, status_text);
                    return JS_ThrowOutOfMemory(ctx);
                }
            }
            JS_FreeCString(ctx, status_text);
        }

        /* Headers */
        val = JS_GetPropertyStr(ctx, argv[1], "headers");
        if (!JS_IsUndefined(val)) {
            JSPropertyEnum *props;
            JSValue value, rv;
            uint32_t len;
            uint64_t k_len, v_len;
            struct aura_kv_iovec *hdr_slot;

            if (JS_GetOwnPropertyNames(ctx, &props, &len, val, JS_GPN_ENUM_ONLY | JS_GPN_STRING_MASK) < 0) {
                JS_FreeValue(ctx, val);
                return JS_ThrowReferenceError(ctx, "Failed to get headers provided");
            }

            for (int i = 0; i < len; ++i) {
                JSAtom prop = props[i].atom;

                const char *key = JS_AtomToCStringLen(ctx, &k_len, prop);
                JS_FreeAtom(ctx, prop);

                value = JS_GetPropertyStr(ctx, val, key);
                if (!JS_IsString(value)) {
                    rv = JS_ThrowTypeError(ctx, "Invalid header value for key: %s, provided", key);
                    aura_res_destroy(resp);
                    JS_FreeValue(ctx, value);
                    JS_FreeCString(ctx, key);
                    JS_FreeValue(ctx, val);
                    return rv;
                }

                const char *val_str = JS_ToCStringLen(ctx, &v_len, value);
                JS_FreeValue(ctx, value);

                hdr_slot = aura_res_get_kv_slot(rt_data->mc, resp);
                if (!hdr_slot) {
                    JS_FreeCString(ctx, key);
                    JS_FreeCString(ctx, val_str);
                    JS_FreeValue(ctx, val);
                    aura_res_destroy(resp);
                    return JS_ThrowOutOfMemory(ctx);
                }

                hdr_slot->key.base = aura_strndup(rt_data->mc, key, k_len);
                hdr_slot->key.len = k_len;
                hdr_slot->value.base = aura_strndup(rt_data->mc, val_str, v_len);
                hdr_slot->value.len = v_len;
                JS_FreeCString(ctx, key);
                JS_FreeCString(ctx, val_str);
            }
            JS_FreeValue(ctx, val);
        }
    }

    /* Create object */
    JSValue proto = JS_GetPropertyStr(ctx, this_val, "prototype");
    if (JS_IsException(proto)) {
        aura_res_destroy(resp);
        return JS_EXCEPTION;
    }

    JSValue obj = JS_NewObjectProtoClass(ctx, proto, response_id);
    JS_FreeValue(ctx, proto);
    if (JS_IsException(obj)) {
        aura_res_destroy(resp);
        return JS_EXCEPTION;
    }

    /** @todo: set response on context structure */
    JS_SetOpaque(obj, resp);
    return obj;
}

int aura_qjs_response_binding_init(JSContext *ctx) {
    JSValue global_obj;
    JSValue resp_ctor, resp_proto, resp_proto_ref;

    global_obj = JS_GetGlobalObject(ctx);
    resp_ctor = JS_NewCFunction2(ctx, a_qjs_response_constructor, "Response", 0, JS_CFUNC_constructor, 0);

    resp_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, resp_proto, aura_js_response_proto_funcs, aura_qjs_res_proto_fns_len);
    // JS_DefinePropertyValueStr(ctx, resp_proto, "constructor", JS_DupValue(ctx, resp_ctor), JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
    // JS_SetClassProto(ctx, response_id, resp_proto);

    // resp_proto_ref = JS_GetClassProto(ctx, response_id);
    // JS_DefinePropertyValueStr(ctx, resp_ctor, "prototype", resp_proto_ref, 0);

    // JS_DefinePropertyValueStr(ctx, global_obj, "Response", resp_ctor, JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);

    JS_SetConstructor(ctx, resp_ctor, resp_proto);
    JS_SetClassProto(ctx, response_id, resp_proto);
    JS_SetPropertyStr(ctx, global_obj, "Response", resp_ctor);

    JS_FreeValue(ctx, global_obj);

    return 0;
}

void aura_qjs_response_binding_destroy(JSContext *ctx) {
    JSValue global = JS_GetGlobalObject(ctx);
    JSValue response_proto = JS_GetClassProto(ctx, response_id);
    JS_FreeValue(ctx, response_proto);
    JS_FreeValue(ctx, global);
}

static JSValue a_js_event_get_source(JSContext *ctx, JSValueConst this_val) {
    struct aura_exec_ctx *c = JS_GetContextOpaque(ctx);
    A_BUG_ON_2(!c, true);
    struct aura_exec_ctx_evt *evt = JS_GetOpaque2(ctx, this_val, event_id);

    return JS_NewString(ctx, c->event.source_name);
}

const JSCFunctionListEntry aura_qjs_event_proto_funcs[] = {
  JS_CGETSET_DEF("src", a_js_event_get_source, NULL),
  //   JS_CGETSET_DEF("request", a_js_event_get_request, NULL),
};

const uint32_t aura_qjs_event_proto_fns_len = ARRAY_SIZE(aura_qjs_event_proto_funcs);

/* ---- END FETCH ---- */

/* exit */
void aura_js_std_exit(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    int status;
    if (JS_ToInt32(ctx, &status, argv[0]))
        status = -1;
    exit(status);
}

/* Parse JSON */
JSValue aura_js_parseExtJSON(JSContext *ctx, const char *module_name, const char *buf, uint64_t buf_len) {
    JSValue res;
    int flags;
    const char *str;

    flags = JS_PARSE_JSON_EXT;
    res = JS_ParseJSON2(ctx, buf, buf_len, module_name, flags);
    // js_free(ctx, buf);
    if (JS_IsException(res))
        return JS_EXCEPTION;

    /* Create module */
}

JSValue aura_js_std_file_open(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {}

JSValue aura_js_std_file_close(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {}

JSValue aura_js_std_file_tmpfile(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {}

JSValue aura_js_std_file_flush(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {}

JSValue aura_js_std_file_tell(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {}

JSValue aura_js_std_file_seek(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {}

JSValue aura_js_std_file_eof(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {}

JSValue aura_js_std_file_error(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {}

JSValue aura_js_std_file_clearerr(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {}

JSValue aura_js_std_file_read(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {}

JSValue aura_js_std_file_write(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {}

/* Module loader */
JSModuleDef *aura_js_module_loader(JSContext *ctx, const char *module_name, void *opaque, JSValueConst attributes) {
    JSModuleDef *m;
    int res;

    /**/
}

/* ---- FILE SYSTEM ---- */
struct aura_js_api_map {
    uint32_t flag;
    JSValue (*fn)(JSContext *, JSValueConst, int, JSValueConst *);
    const char *name;
};

struct aura_js_api_map fs_api_map[] = {
  {.flag = A_OPEN, .fn = aura_js_std_file_open, .name = "open"},
  {.flag = A_CLOSE, .fn = aura_js_std_file_close, .name = "close"},
  {.flag = A_READ, .fn = aura_js_std_file_read, .name = "read"},
  {.flag = A_WRITE, .fn = aura_js_std_file_write, .name = "write"},
};

int init_fn_apis(JSContext *ctx, uint32_t flags, uint64_t len) {
    JSValue global_obj;
    JSValue api;
    uint32_t bit_set;

    global_obj = JS_GetGlobalObject(ctx);
    api = JS_NewObject(ctx);

    /* fs api */
    for (int i = 0; i < ARRAY_SIZE(fs_api_map); ++i) {
        bit_set = flags & fs_api_map->flag;
        if (bit_set) {
            JS_SetPropertyStr(ctx, api, fs_api_map[i].name, JS_NewCFunction(ctx, fs_api_map[i].fn, fs_api_map[i].name, 1));
        }
    }

    JS_SetPropertyStr(ctx, global_obj, "fs", api);
    JS_FreeValue(ctx, global_obj);
}

/* ===== TEXT ENCODER/DECODER ===== */

/**
 * Compares trimmed lowercase "input" against
 * "label" which is a null terminated string.
 * Returns true on success, false otherwise
 */
static inline bool a_qjs_text_label_match(const char *input, uint64_t len, const char *label) {
    input = aura_str_trim((void *)input, &len);
    return aura_lc_str_is_eq(input, len, label, strlen(label));
}

/* Try to match label to a supported encoding. Returns -1 on failure. */
static inline int a_qjs_text_get_encoding(const char *label, uint64_t label_len) {
    /* UTF-8 labels per spec */
    static const char *utf8_labels[] = {
      "unicode-1-1-utf-8",
      "unicode11utf8",
      "unicode20utf8",
      "utf-8",
      "utf8",
      "x-unicode20utf8",
      NULL};

    /* UTF-16LE labels per spec */
    static const char *utf16le_labels[] = {
      "csunicode",
      "iso-10646-ucs-2",
      "ucs-2",
      "unicode",
      "unicodefeff",
      "utf-16",
      "utf-16le",
      NULL};

    /* UTF-16BE labels per spec */
    static const char *utf16be_labels[] = {
      "unicodefffe",
      "utf-16be",
      NULL};

    for (const char **p = utf8_labels; *p; p++) {
        if (a_qjs_text_label_match(label, label_len, *p))
            return A_QJS_TEXT_ENCODING_UTF8;
    }
    for (const char **p = utf16le_labels; *p; p++) {
        if (a_qjs_text_label_match(label, label_len, *p))
            return A_QJS_TEXT_ENCODING_UTF16LE;
    }
    for (const char **p = utf16be_labels; *p; p++) {
        if (a_qjs_text_label_match(label, label_len, *p))
            return A_QJS_TEXT_ENCODING_UTF16BE;
    }

    return -1;
}

/* Check if a label matches the "replacement" encoding.
   Per spec, these labels must cause a RangeError. */
static bool a_qjs_text_is_replacement_encoding(const char *label, uint64_t label_len) {
    static const char *replacement_labels[] = {
      "csiso2022kr",
      "hz-gb-2312",
      "iso-2022-cn",
      "iso-2022-cn-ext",
      "iso-2022-kr",
      "replacement",
      NULL,
    };

    for (const char **p = replacement_labels; *p; p++) {
        if (a_qjs_text_label_match(label, label_len, *p))
            return true;
    }

    return false;
}

/* UTF-8 handler: processes one byte, returns a code point value (>=0),
   or A_QJS_TEXT_HANDLER_FINISHED, A_QJS_TEXT_HANDLER_CONTINUE, or A_QJS_TEXT_HANDLER_ERROR.
   When A_QJS_TEXT_HANDLER_ERROR is returned, *restore_byte is set to 1 if the byte
   should be restored to the input queue (re-processed).
*/
static int32_t a_qjs_utf8_handler(A_QJS_TEXT_UTF8DecoderState *st, int byte_or_eof, int *restore_byte) {
    *restore_byte = 0;

    /* End of sequence */
    if (byte_or_eof < 0) {
        if (st->bytes_needed != 0) {
            st->bytes_needed = 0;
            return A_QJS_TEXT_HANDLER_ERROR;
        }
        return A_QJS_TEXT_HANDLER_FINISHED;
    }

    uint8_t byte = (uint8_t)byte_or_eof;

    /* Start of a new sequence */
    if (st->bytes_needed == 0) {
        if (byte <= 0x7F) {
            return (int32_t)byte;
        } else if (byte >= 0xC2 && byte <= 0xDF) {
            st->bytes_needed = 1;
            st->code_point = byte & 0x1F;
        } else if (byte >= 0xE0 && byte <= 0xEF) {
            if (byte == 0xE0)
                st->lower_boundary = 0xA0;
            if (byte == 0xED)
                st->upper_boundary = 0x9F;
            st->bytes_needed = 2;
            st->code_point = byte & 0x0F;
        } else if (byte >= 0xF0 && byte <= 0xF4) {
            if (byte == 0xF0)
                st->lower_boundary = 0x90;
            if (byte == 0xF4)
                st->upper_boundary = 0x8F;
            st->bytes_needed = 3;
            st->code_point = byte & 0x07;
        } else {
            return A_QJS_TEXT_HANDLER_ERROR;
        }
        return A_QJS_TEXT_HANDLER_CONTINUE;
    }

    /* Validate byte sequence and restore byte if needed */
    if (byte < st->lower_boundary || byte > st->upper_boundary) {
        st->code_point = 0;
        st->bytes_needed = 0;
        st->bytes_seen = 0;
        st->lower_boundary = 0x80;
        st->upper_boundary = 0xBF;
        *restore_byte = 1;
        return A_QJS_TEXT_HANDLER_ERROR;
    }

    /* reset boundaries */
    st->lower_boundary = 0x80;
    st->upper_boundary = 0xBF;

    /* accumulate bits */
    st->code_point = (st->code_point << 6) | (byte & 0x3F);

    /* increment bytes_seen */
    st->bytes_seen++;

    if (st->bytes_seen != st->bytes_needed) {
        return A_QJS_TEXT_HANDLER_CONTINUE;
    }

    /* Finalize and reset decoder state */
    uint32_t cp = st->code_point;
    st->code_point = 0;
    st->bytes_needed = 0;
    st->bytes_seen = 0;
    return (int32_t)cp;
}

/* UTF-16 handler: processes one byte at a time.
   Returns a code point (>=0),
   A_QJS_TEXT_HANDLER_FINISHED,
   A_QJS_TEXT_HANDLER_CONTINUE,
   or A_QJS_TEXT_HANDLER_ERROR.
*/
static int32_t a_qjs_utf16_handler(A_QJS_TEXT_UTF16DecoderState *st, int byte_or_eof) {
    /* End-of-queue */
    if (byte_or_eof < 0) {
        if (st->lead_byte != -1 || st->lead_surrogate != -1) {
            st->lead_byte = -1;
            st->lead_surrogate = -1;
            return A_QJS_TEXT_HANDLER_ERROR;
        }
        return A_QJS_TEXT_HANDLER_FINISHED;
    }

    uint8_t byte = (uint8_t)byte_or_eof;

    /* If we have a pending lead_byte, combine to form a code unit */
    if (st->lead_byte == -1) {
        st->lead_byte = byte;
        return A_QJS_TEXT_HANDLER_CONTINUE;
    }

    uint16_t code_unit;
    if (st->be) {
        code_unit = ((uint16_t)st->lead_byte << 8) | byte;
    } else {
        code_unit = ((uint16_t)byte << 8) | (uint16_t)st->lead_byte;
    }
    st->lead_byte = -1;

    /* If we have a pending lead surrogate */
    if (st->lead_surrogate != -1) {
        uint16_t lead = (uint16_t)st->lead_surrogate;
        st->lead_surrogate = -1;
        if (a_qjs_is_lo_surr(code_unit)) {
            return (int32_t)a_qjs_surr_to_cp(lead, code_unit);
        }
        /* Not a trail surrogate — error for the lead surrogate.
           But we need to re-process this code_unit. We handle this
           by checking if it's a lead surrogate itself or a regular code unit. */
        if (a_qjs_is_hi_surr(code_unit)) {
            st->lead_surrogate = code_unit;
            /* Return error for the previous unmatched lead surrogate */
            return A_QJS_TEXT_HANDLER_ERROR;
        }
        /* The current code_unit is a BMP code point. We emit error for
           the unmatched lead, but we also need to emit the current code_unit.
           Since we can only return one thing at a time, we store the result
           and use a special approach: return the error, and the caller
           will need to re-process. However, the spec's "process an item"
           pushes error and continues, so we just mark error and the next
           call will handle this code_unit. But we've already consumed the
           byte pair... We need a different approach.

           The spec's UTF-16 decoder processes 2 bytes at a time forming
           code units, not single bytes. Let me restructure to buffer the
           code unit for re-processing. */

        /* Actually, for simplicity, we'll store the code_unit as needing
           to be re-examined. We'll use a small queue approach. For now,
           let's emit an error. The code_unit is lost, which is a bug.
           Let me handle this properly with a pending_code_unit field. */

        /* FIXME: this is handled below in the decode function by
           using a different approach. For now, signal error. */
        return A_QJS_TEXT_HANDLER_ERROR;
    }

    if (a_qjs_is_hi_surr(code_unit)) {
        st->lead_surrogate = code_unit;
        return A_QJS_TEXT_HANDLER_CONTINUE;
    }

    if (a_qjs_is_lo_surr(code_unit)) {
        return A_QJS_TEXT_HANDLER_ERROR;
    }

    return (int32_t)code_unit;
}

static void a_qjs_text_dec_init_state(struct aura_qjs_text_decoder_data *d) {
    d->bom_seen = false;
    d->do_not_flush = false;

    switch (d->encoding) {
    case A_QJS_TEXT_ENCODING_UTF8:
        a_qjs_text_utf8_dec_reset(&d->state.utf8);
        break;
    case A_QJS_TEXT_ENCODING_UTF16LE:
        a_qjs_text_utf16_dec_reset(&d->state.utf16, 0);
        break;
    case A_QJS_TEXT_ENCODING_UTF16BE:
        a_qjs_text_utf16_dec_reset(&d->state.utf16, 1);
        break;
    }
}

/* Text encoder constructor */
static JSValue a_qjs_text_enc_constructor(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    JSValue proto = JS_GetPropertyStr(ctx, this_val, "prototype");
    if (JS_IsException(proto))
        return JS_EXCEPTION;

    JSValue obj = JS_NewObjectProtoClass(ctx, proto, text_encoder_id);
    JS_FreeValue(ctx, proto);
    return obj;
}

/* Return text encoder encoding. Always returns utf-8 */
static JSValue a_qjs_text_enc_get_encoding(JSContext *ctx, JSValueConst this_val) {
    return JS_NewString(ctx, "utf-8");
}

/**
 * TextEncoder.encode(input)
 * Takes a JS string, converts to UTF-8 with USVString semantics
 * (lone surrogates → U+FFFD), returns a Uint8Array.
 */
static JSValue a_qjs_text_enc_encode(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    JSValue input_val;
    uint16_t *str_utf16;
    uint8_t *str_utf8;
    uint8_t *buf;
    uint64_t len, i = 0, out_size = 0;

    /* Return empty Uint8Array */
    if (argc < 1 || JS_IsUndefined(argv[0])) {
        return JS_NewTypedArray(ctx, 0, NULL, JS_TYPED_ARRAY_UINT8);
    }

    /**
     * JS internal string representation is UTF-16. But quickjs
     * can give us either 8 bit or 16 bit code units.
     * So the check can confirm how we can proceed.
     */
    if (aura_qjs_string_is_wide(ctx, argv[0], &input_val)) {
        uint16_t c;
        uint32_t cp;

        /**
         * If argv[0] was invalid string, then input_val
         * would be an exception.
         */
        if (JS_IsException(input_val))
            return input_val;

        str_utf16 = aura_qjs_get_str16(input_val, &len);
        /**
         * Loop and compute the exact length needed
         */
        while (i < len) {
            c = str_utf16[i++];
            if (a_qjs_is_hi_surr(c) && i < len && a_qjs_is_lo_surr(str_utf16[i])) {
                cp = a_qjs_surr_to_cp(c, str_utf16[i]);
                i++;
            } else if (a_qjs_is_hi_surr(c) || a_qjs_is_lo_surr(c)) {
                /* lone surrogate is replaced by U+FFFD */
                cp = 0xFFFD;
            } else {
                cp = c;
            }
            out_size += aura_qjs_utf8_cp_len(cp);
        }

        /* Allocate output buffer */
        buf = js_malloc(ctx, out_size > 0 ? out_size : 1);
        if (!buf) {
            JS_FreeValue(ctx, input_val);
            return JS_EXCEPTION;
        }

        /* Perform actual encoding */
        uint8_t *p = buf;
        i = 0;
        while (i < len) {
            c = str_utf16[i++];
            if (a_qjs_is_hi_surr(c) && i < len && a_qjs_is_lo_surr(str_utf16[i])) {
                cp = a_qjs_surr_to_cp(c, str_utf16[i]);
                i++;
            } else if (a_qjs_is_hi_surr(c) || a_qjs_is_lo_surr(c)) {
                cp = 0xFFFD;
            } else {
                cp = c;
            }
            p += aura_qjs_utf8_encode_cp(p, cp);
        }
    } else {
        int non_ascii;
        uint8_t c, *p;

        /**
         * If argv[0] was invalid string, then input_val
         * would be an exception.
         */
        if (JS_IsException(input_val))
            return input_val;

        str_utf8 = aura_qjs_get_str8(input_val, &len);

        /**
         * Loop through and count non-ascii characters,
         * see reason why below
         */
        non_ascii = 0;
        for (i = 0; i < len; ++i) {
            non_ascii += str_utf8[i] >> 7;
        }

        /**
         * non-ascii requires two code units per
         * code point, so we add the non-ascii
         * count to get the final buffer.
         */
        out_size = len + non_ascii;
        buf = js_malloc(ctx, out_size > 0 ? out_size : 1);
        if (!buf) {
            JS_FreeValue(ctx, input_val);
            return JS_EXCEPTION;
        }

        /* Perform actual encoding */
        p = buf;
        for (i = 0; i < len; ++i) {
            c = str_utf8[i];
            if (c < 0x80) {
                *p++ = c;
            } else {
                *p++ = (c >> 6) | 0xc0;
                *p++ = (c & 0x3f) | 0x80;
            }
        }
    }

    JS_FreeValue(ctx, input_val);

    /* Create Uint8Array from buffer */
    JSValue rv = JS_NewArrayBuffer(ctx, buf, out_size, NULL, NULL, 0);
    JSValue result = JS_NewTypedArray(ctx, 1, &rv, JS_TYPED_ARRAY_UINT8);
    JS_FreeValue(ctx, rv);
    js_free(ctx, buf);
    return result;
}

/**
 * TextEncoder.encodeInto(source, destination: Uint8Array)
 * Takes a string to encode and a destination to place the
 * encoded string in.
 * Returns an object that contains:
 * { read: number of utf-16 code units converted to utf-8,
 *   written: number of bytes modified in the destination Uint8Array }.
 */
static JSValue a_qjs_text_encoder_encodeInto(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    JSValue input_val;
    uint8_t *str_utf8;
    uint16_t *str_utf16;
    uint64_t len, i = 0;

    if (argc < 2)
        return JS_ThrowTypeError(ctx, "encodeInto requires 2 arguments");

    /* Validate destination is a Uint8Array */
    /* @todo: check for Uint8Array type */
    if (!A_JS_ISTypedArray(ctx, argv[1]))
        return JS_ThrowTypeError(ctx, "encodeInto destination must be a Uint8Array");

    /* Get destination buffer */
    uint64_t dest_byte_offset, dest_byte_length, dest_bpe;
    JSValue dest_ab = JS_GetTypedArrayBuffer(ctx, argv[1], &dest_byte_offset, &dest_byte_length, &dest_bpe);
    if (JS_IsException(dest_ab))
        return JS_EXCEPTION;

    uint64_t ab_size;
    uint8_t *ab_data = JS_GetArrayBuffer(ctx, &ab_size, dest_ab);
    JS_FreeValue(ctx, dest_ab);

    /* Handle detached buffer: ab_data is NULL but byte_length might be 0 */
    uint8_t *dest = ab_data ? (ab_data + dest_byte_offset) : NULL;
    uint64_t dest_len = dest_byte_length;

    uint64_t read_units = 0; /* UTF-16 code units consumed */
    uint64_t written = 0;    /* bytes written to destination */

    if (aura_qjs_string_is_wide(ctx, argv[0], &input_val)) {
        uint16_t c;
        uint32_t cp;
        int code_units_needed; /* how many UTF-16 code units this consumes */

        if (JS_IsException(input_val))
            return input_val;

        str_utf16 = aura_qjs_get_str16(input_val, &len);

        while (i < len) {
            c = str_utf16[i];

            if (a_qjs_is_hi_surr(c) && (i + 1) < len && a_qjs_is_lo_surr(str_utf16[i + 1])) {
                cp = a_qjs_surr_to_cp(c, str_utf16[i + 1]);
                code_units_needed = 2;
            } else if (a_qjs_is_hi_surr(c) || a_qjs_is_lo_surr(c)) {
                cp = 0xFFFD;
                code_units_needed = 1;
            } else {
                cp = c;
                code_units_needed = 1;
            }

            int needed = aura_qjs_utf8_cp_len(cp);
            if (dest_len - written < (uint64_t)needed) {
                break; /* not enough space */
            }

            if (dest) {
                written += aura_qjs_utf8_encode_cp(dest + written, cp);
            } else {
                written += needed;
            }

            i += code_units_needed;
            read_units += code_units_needed;
        }

    } else {
        uint8_t c;
        uint64_t code_units_needed;

        if (JS_IsException(input_val))
            return input_val;

        str_utf8 = aura_qjs_get_str8(input_val, &len);

        for (i = 0; i < len; ++i) {
            c = str_utf8[i];
            if (c < 0x80) {
                code_units_needed = 1;
                if ((dest_len - written) < code_units_needed)
                    /* Not enough space */
                    break;

                if (dest)
                    dest[written] = c;

            } else {
                code_units_needed = 2;
                if ((dest_len - written) < code_units_needed)
                    /* Not enough space */
                    break;

                if (dest) {
                    dest[written] = (c >> 6) | 0xc0;
                    dest[written + 1] = (c & 0x3f) | 0x80;
                }
            }

            written += code_units_needed;
            read_units += 1;
        }
    }

    /* Return { read, written } */
    JSValue result = JS_NewObject(ctx);
    JS_SetPropertyStr(ctx, result, "read", JS_NewInt64(ctx, (int64_t)read_units));
    JS_SetPropertyStr(ctx, result, "written", JS_NewInt64(ctx, (int64_t)written));
    return result;
}

static const JSCFunctionListEntry a_qjs_text_enc_proto_funcs[] = {
  JS_CGETSET_DEF("encoding", a_qjs_text_enc_get_encoding, NULL),
  JS_CFUNC_DEF("encode", 0, a_qjs_text_enc_encode),
  JS_CFUNC_DEF("encodeInto", 2, a_qjs_text_encoder_encodeInto),
};

static JSValue a_qjs_text_dec_constructor(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    JSValue rv;
    /* Parse label (default "utf-8") */
    A_QJS_TextEncodingType enc = A_QJS_TEXT_ENCODING_UTF8;

    if (argc >= 1 && !JS_IsUndefined(argv[0])) {
        uint64_t label_len;
        const char *label = JS_ToCStringLen(ctx, &label_len, argv[0]);
        if (!label)
            return JS_EXCEPTION;

        enc = a_qjs_text_get_encoding(label, label_len);
        if (enc < 0) {
            /* Check if it's a known but unsupported encoding, or replacement */
            if (a_qjs_text_is_replacement_encoding(label, label_len)) {
                rv = JS_ThrowRangeError(ctx, "Unsupported encoding (%s) label provided.", label);
            } else
                rv = JS_ThrowRangeError(ctx, "The encoding label provided is not supported.");

            JS_FreeCString(ctx, label);
            return rv;
        }
        JS_FreeCString(ctx, label);
    }

    /* Parse options */
    bool fatal = 0;
    bool ignore_bom = 0;

    if (argc >= 2 && !JS_IsUndefined(argv[1]) && !JS_IsNull(argv[1])) {
        JSValue fatal_val = JS_GetPropertyStr(ctx, argv[1], "fatal");
        if (JS_IsException(fatal_val))
            return JS_EXCEPTION;
        fatal = JS_ToBool(ctx, fatal_val);
        JS_FreeValue(ctx, fatal_val);

        JSValue ignore_bom_val = JS_GetPropertyStr(ctx, argv[1], "ignoreBOM");
        if (JS_IsException(ignore_bom_val))
            return JS_EXCEPTION;
        ignore_bom = JS_ToBool(ctx, ignore_bom_val);
        JS_FreeValue(ctx, ignore_bom_val);
    }

    /* Allocate opaque data */
    struct aura_qjs_text_decoder_data *dec_data = js_mallocz(ctx, sizeof(*dec_data));
    if (!dec_data)
        return JS_EXCEPTION;

    dec_data->encoding = enc;
    dec_data->fatal = fatal;
    dec_data->ignore_bom = ignore_bom;
    a_qjs_text_dec_init_state(dec_data);

    /* Create object */
    JSValue proto = JS_GetPropertyStr(ctx, this_val, "prototype");
    if (JS_IsException(proto)) {
        js_free(ctx, dec_data);
        return JS_EXCEPTION;
    }

    JSValue obj = JS_NewObjectProtoClass(ctx, proto, text_decoder_id);
    JS_FreeValue(ctx, proto);
    if (JS_IsException(obj)) {
        js_free(ctx, dec_data);
        return JS_EXCEPTION;
    }

    JS_SetOpaque(obj, dec_data);
    return obj;
}

/* ---- TextDecoder property getters ---- */
static JSValue a_qjs_text_dec_get_encoding(JSContext *ctx, JSValueConst this_val) {
    struct aura_qjs_text_decoder_data *d = JS_GetOpaque(this_val, text_decoder_id);
    if (!d)
        return JS_EXCEPTION;
    return JS_NewString(ctx, aura_text_encoding_name(d->encoding));
}

static JSValue a_qjs_text_dec_get_fatal(JSContext *ctx, JSValueConst this_val) {
    struct aura_qjs_text_decoder_data *d = JS_GetOpaque(this_val, text_decoder_id);
    if (!d)
        return JS_EXCEPTION;
    return JS_NewBool(ctx, d->fatal);
}

static JSValue a_qjs_text_dec_get_ignoreBOM(JSContext *ctx, JSValueConst this_val) {
    struct aura_qjs_text_decoder_data *d = JS_GetOpaque(this_val, text_decoder_id);
    if (!d)
        return JS_EXCEPTION;
    return JS_NewBool(ctx, d->ignore_bom);
}

/* ---- UTF-8 decode helper ---- */

/* Decode UTF-8 input bytes to a JS string using the spec's algorithm.
   Handles error mode (replacement vs fatal) and BOM stripping.
   If streaming, the decoder state is preserved across calls.
   Returns JS_EXCEPTION on fatal error.
*/
static JSValue a_qjs_decode_utf8(JSContext *ctx, struct aura_qjs_text_decoder_data *d,
                                 const uint8_t *input, uint64_t input_len, bool stream) {
    A_QJS_TEXT_UTF8DecoderState *st = &d->state.utf8;

    /* Allocate output buffer for scalar values (worst case: each byte → one code point).
       Each code point can be up to 4 bytes in the output JS string (UTF-8 encoded).
       We'll build a UTF-8 string directly. */
    uint64_t max_out = (input_len + 4) * 3 + 16; /* generous upper bound */
    uint8_t *out = js_malloc(ctx, max_out);
    if (!out)
        return JS_EXCEPTION;
    uint64_t out_len = 0;

    uint64_t pos = 0;
    while (1) {
        int byte_or_eof;
        if (pos < input_len) {
            byte_or_eof = input[pos++];
        } else if (!stream) {
            byte_or_eof = -1; /* end-of-queue */
        } else {
            break; /* streaming: don't signal end-of-queue */
        }

        int restore_byte = 0;
        int32_t result = a_qjs_utf8_handler(st, byte_or_eof, &restore_byte);

        if (result == A_QJS_TEXT_HANDLER_FINISHED) {
            break;
        } else if (result == A_QJS_TEXT_HANDLER_CONTINUE) {
            continue;
        } else if (result == A_QJS_TEXT_HANDLER_ERROR) {
            if (d->fatal) {
                js_free(ctx, out);
                return JS_ThrowTypeError(ctx, "The encoded data was not valid.");
            }
            /* Replacement mode: emit U+FFFD */
            uint32_t replacement = 0xFFFD;
            /* BOM filtering for U+FFFD: it's not U+FEFF, so no filtering needed */
            if (!d->bom_seen && !d->ignore_bom &&
                (d->encoding == A_QJS_TEXT_ENCODING_UTF8)) {
                d->bom_seen = 1;
                /* U+FFFD is not BOM, so we emit it */
            }
            out_len += aura_qjs_utf8_encode_cp(out + out_len, replacement);

            if (restore_byte) {
                pos--; /* re-process the byte */
            }
        } else {
            /* result is a code point */
            uint32_t cp = (uint32_t)result;

            /* BOM handling: per "serialize I/O queue" in the spec */
            if (!d->bom_seen && !d->ignore_bom &&
                d->encoding == A_QJS_TEXT_ENCODING_UTF8) {
                d->bom_seen = 1;
                if (cp == 0xFEFF) {
                    continue; /* strip BOM */
                }
            }

            out_len += aura_qjs_utf8_encode_cp(out + out_len, cp);
        }
    }

    JSValue str = JS_NewStringLen(ctx, (const char *)out, out_len);
    js_free(ctx, out);
    return str;
}

/* ---- UTF-16 decode helper ---- */

/* Decode UTF-16 input bytes to a JS string.
   The spec's "shared UTF-16 decoder" processes bytes one at a time,
   pairing them into code units, then handling surrogate pairs.
   For simplicity and correctness, we process the bytes directly. */
static JSValue a_qjs_decode_utf16(JSContext *ctx, struct aura_qjs_text_decoder_data *d,
                                  const uint8_t *input, uint64_t input_len,
                                  int stream) {
    /* For UTF-16: worst case output is input_len code points,
       each up to 3 bytes UTF-8. Plus some for pending state. */
    uint64_t max_out = (input_len + 4) * 3 + 16;
    uint8_t *out = js_malloc(ctx, max_out);
    if (!out)
        return JS_EXCEPTION;
    uint64_t out_len = 0;

    A_QJS_TEXT_UTF16DecoderState *st = &d->state.utf16;

    /* We process bytes forming code units, then handle surrogates.
       To handle the edge case where an unmatched lead surrogate is
       followed by a non-surrogate code unit, we need to be able to
       "re-process" a code unit. We use a small pending queue. */

    /* Collect code units from the byte stream */
    uint64_t pos = 0;
    int have_pending_cu = 0;
    uint16_t pending_cu = 0;

    while (1) {
        uint16_t code_unit;
        int have_cu = 0;

        if (have_pending_cu) {
            code_unit = pending_cu;
            have_cu = 1;
            have_pending_cu = 0;
        } else {
            /* Read two bytes to form a code unit */
            if (st->lead_byte != -1) {
                /* We have a pending byte from a previous call */
                if (pos < input_len) {
                    uint8_t b1 = (uint8_t)st->lead_byte;
                    uint8_t b2 = input[pos++];
                    if (st->be) {
                        code_unit = ((uint16_t)b1 << 8) | b2;
                    } else {
                        code_unit = ((uint16_t)b2 << 8) | b1;
                    }
                    st->lead_byte = -1;
                    have_cu = 1;
                } else {
                    /* No more input bytes; leave lead_byte pending */
                    break;
                }
            } else if (pos + 1 < input_len) {
                uint8_t b1 = input[pos];
                uint8_t b2 = input[pos + 1];
                pos += 2;
                if (st->be) {
                    code_unit = ((uint16_t)b1 << 8) | b2;
                } else {
                    code_unit = ((uint16_t)b2 << 8) | b1;
                }
                have_cu = 1;
            } else if (pos < input_len) {
                /* One byte left — save as lead_byte */
                st->lead_byte = input[pos++];
                break;
            } else {
                /* No more input */
                break;
            }
        }

        if (!have_cu)
            break;

        /* Handle surrogates */
        if (st->lead_surrogate != -1) {
            uint16_t lead = (uint16_t)st->lead_surrogate;
            if (a_qjs_is_lo_surr(code_unit)) {
                st->lead_surrogate = -1;
                uint32_t cp = a_qjs_surr_to_cp(lead, code_unit);

                /* BOM filtering */
                if (!d->bom_seen && !d->ignore_bom) {
                    d->bom_seen = 1;
                    if (cp == 0xFEFF)
                        continue;
                }

                out_len += aura_qjs_utf8_encode_cp(out + out_len, cp);
                continue;
            }
            /* Unmatched lead surrogate */
            st->lead_surrogate = -1;
            if (d->fatal) {
                js_free(ctx, out);
                return JS_ThrowTypeError(ctx, "The encoded data was not valid.");
            }
            /* Emit U+FFFD for the unmatched lead */
            if (!d->bom_seen && !d->ignore_bom) {
                d->bom_seen = 1;
                /* U+FFFD is not BOM */
            }
            out_len += aura_qjs_utf8_encode_cp(out + out_len, 0xFFFD);
            /* Re-process current code_unit */
            have_pending_cu = 1;
            pending_cu = code_unit;
            continue;
        }

        if (a_qjs_is_hi_surr(code_unit)) {
            st->lead_surrogate = code_unit;
            continue;
        }

        if (a_qjs_is_lo_surr(code_unit)) {
            if (d->fatal) {
                js_free(ctx, out);
                return JS_ThrowTypeError(ctx, "The encoded data was not valid.");
            }
            if (!d->bom_seen && !d->ignore_bom) {
                d->bom_seen = 1;
            }
            out_len += aura_qjs_utf8_encode_cp(out + out_len, 0xFFFD);
            continue;
        }

        /* Regular BMP code point */
        if (!d->bom_seen && !d->ignore_bom) {
            d->bom_seen = 1;
            if (code_unit == 0xFEFF)
                continue; /* strip BOM */
        }
        out_len += aura_qjs_utf8_encode_cp(out + out_len, code_unit);
    }

    /* If not streaming, flush pending state */
    if (!stream) {
        if (st->lead_surrogate != -1) {
            if (d->fatal) {
                js_free(ctx, out);
                return JS_ThrowTypeError(ctx, "The encoded data was not valid.");
            }
            out_len += aura_qjs_utf8_encode_cp(out + out_len, 0xFFFD);
            st->lead_surrogate = -1;
        }
        if (st->lead_byte != -1) {
            if (d->fatal) {
                js_free(ctx, out);
                return JS_ThrowTypeError(ctx, "The encoded data was not valid.");
            }
            out_len += aura_qjs_utf8_encode_cp(out + out_len, 0xFFFD);
            st->lead_byte = -1;
        }
    }

    JSValue str = JS_NewStringLen(ctx, (const char *)out, out_len);
    js_free(ctx, out);
    return str;
}

/* TextDecoder.decode() */
static JSValue a_qjs_text_dec_decode(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    struct aura_qjs_text_decoder_data *d = JS_GetOpaque(this_val, text_decoder_id);
    if (!d)
        return JS_EXCEPTION;

    /* Do not reset if we are streaming the text */
    if (!d->do_not_flush) {
        a_qjs_text_dec_init_state(d);
    }

    /* decode(buf, options): Parse options.stream */
    bool stream = false;
    if (argc >= 2 && !JS_IsUndefined(argv[1]) && !JS_IsNull(argv[1])) {
        JSValue stream_val = JS_GetPropertyStr(ctx, argv[1], "stream");
        if (JS_IsException(stream_val))
            return JS_EXCEPTION;
        stream = JS_ToBool(ctx, stream_val);
        JS_FreeValue(ctx, stream_val);
    }
    d->do_not_flush = stream;

    const uint8_t *input = NULL;
    uint64_t input_len = 0;

    /* Get ArrayBuffer/TypedArray/DataView */
    if (argc >= 1 && !JS_IsUndefined(argv[0]) && !JS_IsNull(argv[0])) {
        if (A_JS_ISArrayBuffer(ctx, argv[0])) {
            input = JS_GetArrayBuffer(ctx, &input_len, argv[0]);
        } else {
            uint64_t byte_offset, byte_length, bpe;

            if (aura_qjs_is_typed_array(argv[0], JS_TYPED_ARRAY_UINT8)) {
                uint64_t ab_size;

                JSValue ab = JS_GetTypedArrayBuffer(ctx, argv[0], &byte_offset, &byte_length, &bpe);
                uint8_t *ab_data = JS_GetArrayBuffer(ctx, &ab_size, ab);
                JS_FreeValue(ctx, ab);
                if (ab_data) {
                    input = ab_data + byte_offset;
                    input_len = byte_length;
                } else {
                    input = NULL;
                    input_len = 0;
                }
            } else if (A_JS_ISDataView(ctx, argv[0])) {
                /* Get buffer, byteOffset, byteLength from the DataView */
                JSValue buf_val = JS_GetPropertyStr(ctx, argv[0], "buffer");
                JSValue off_val = JS_GetPropertyStr(ctx, argv[0], "byteOffset");
                JSValue len_val = JS_GetPropertyStr(ctx, argv[0], "byteLength");

                if (JS_IsException(buf_val) || JS_IsException(off_val) || JS_IsException(len_val)) {
                    JS_FreeValue(ctx, buf_val);
                    JS_FreeValue(ctx, off_val);
                    JS_FreeValue(ctx, len_val);
                    return JS_EXCEPTION;
                }

                uint64_t ab_size;
                uint8_t *ab_data = JS_GetArrayBuffer(ctx, &ab_size, buf_val);
                JS_FreeValue(ctx, buf_val);

                uint32_t dv_offset = 0, dv_length = 0;
                JS_ToUint32(ctx, &dv_offset, off_val);
                JS_ToUint32(ctx, &dv_length, len_val);
                JS_FreeValue(ctx, off_val);
                JS_FreeValue(ctx, len_val);

                if (ab_data) {
                    input = ab_data + dv_offset;
                    input_len = dv_length;
                } else {
                    input = NULL;
                    input_len = 0;
                }
            } else {
                return JS_ThrowTypeError(ctx, "The provided value is not of type '(ArrayBuffer or ArrayBufferView)'");
            }
        }
    }

    /* Step 4-5: Decode */
    switch (d->encoding) {
    case A_QJS_TEXT_ENCODING_UTF8:
        return a_qjs_decode_utf8(ctx, d, input ? input : (const uint8_t *)"", input_len, stream);
    case A_QJS_TEXT_ENCODING_UTF16LE:
    case A_QJS_TEXT_ENCODING_UTF16BE:
        return a_qjs_decode_utf16(ctx, d, input ? input : (const uint8_t *)"", input_len, stream);
    }

    return JS_NewString(ctx, "");
}

static const JSCFunctionListEntry a_qjs_text_dec_proto_funcs[] = {
  JS_CGETSET_DEF("encoding", a_qjs_text_dec_get_encoding, NULL),
  JS_CGETSET_DEF("fatal", a_qjs_text_dec_get_fatal, NULL),
  JS_CGETSET_DEF("ignoreBOM", a_qjs_text_dec_get_ignoreBOM, NULL),
  JS_CFUNC_DEF("decode", 0, a_qjs_text_dec_decode),
};

int aura_qjs_text_dec_init(JSContext *ctx) {
    JSValue global_obj;
    JSValue td_ctor, td_proto, td_proto_ref;

    global_obj = JS_GetGlobalObject(ctx);
    td_ctor = JS_NewCFunction2(ctx, a_qjs_text_dec_constructor, "TextDecoder", 0, JS_CFUNC_constructor, 0);

    td_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, td_proto, a_qjs_text_dec_proto_funcs, ARRAY_SIZE(a_qjs_text_dec_proto_funcs));
    // JS_DefinePropertyValueStr(ctx, td_proto, "constructor", JS_DupValue(ctx, td_ctor), JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
    // JS_SetClassProto(ctx, text_decoder_id, td_proto);

    // td_proto_ref = JS_GetClassProto(ctx, text_decoder_id);
    // JS_DefinePropertyValueStr(ctx, td_ctor, "prototype", td_proto_ref, 0);
    // JS_DefinePropertyValueStr(ctx, global_obj, "TextDecoder", td_ctor, JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);

    JS_SetConstructor(ctx, td_ctor, td_proto);
    JS_SetClassProto(ctx, text_decoder_id, td_proto);
    JS_SetPropertyStr(ctx, global_obj, "TextDecoder", td_ctor);

    JS_FreeValue(ctx, global_obj);
}

void aura_qjs_text_dec_destroy(JSContext *ctx) {
    JSValue global = JS_GetGlobalObject(ctx);
    JSValue td_proto = JS_GetClassProto(ctx, text_decoder_id);
    JS_FreeValue(ctx, td_proto);
    JS_FreeValue(ctx, global);
}

/* Initialize TextEncoder */
int aura_qjs_text_enc_init(JSContext *ctx) {
    JSValue global_obj;
    JSValue te_ctor, te_proto;

    global_obj = JS_GetGlobalObject(ctx);
    te_ctor = JS_NewCFunction2(ctx, a_qjs_text_enc_constructor, "TextEncoder", 0, JS_CFUNC_constructor, 0);

    te_proto = JS_NewObject(ctx);
    JS_SetPropertyFunctionList(ctx, te_proto, a_qjs_text_enc_proto_funcs, ARRAY_SIZE(a_qjs_text_enc_proto_funcs));
    // JS_DefinePropertyValueStr(ctx, te_proto, "constructor", JS_DupValue(ctx, te_ctor), JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
    // JS_SetClassProto(ctx, text_encoder_id, te_proto);

    // JSValue te_proto_ref = JS_GetClassProto(ctx, text_encoder_id);
    // JS_DefinePropertyValueStr(ctx, te_ctor, "prototype", te_proto_ref, 0);

    // JS_DefinePropertyValueStr(ctx, global_obj, "TextEncoder", te_ctor, JS_PROP_WRITABLE | JS_PROP_CONFIGURABLE);
    JS_SetConstructor(ctx, te_ctor, te_proto);
    JS_SetClassProto(ctx, text_encoder_id, te_proto);
    JS_SetPropertyStr(ctx, global_obj, "TextEncoder", te_ctor);

    JS_FreeValue(ctx, global_obj);
}

void aura_qjs_text_enc_destroy(JSContext *ctx) {
    JSValue global = JS_GetGlobalObject(ctx);
    JSValue te_proto = JS_GetClassProto(ctx, text_encoder_id);
    JS_FreeValue(ctx, te_proto);
    JS_FreeValue(ctx, global);
}

/*==============================TESTING==============================*/

/* Test console log */
static JSValue aura_js_test_console(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    uint64_t len;
    JSValue rv;

    const char *str = JS_ToCStringLen(ctx, &len, argv[0]);
    rv = JS_NewString(ctx, str);
    JS_FreeCString(ctx, str);
    return rv;
}

void aura_js_console_test_init(JSContext *ctx) {
    JSValue global_obj;
    JSValue console;

    console = JS_NewObject(ctx);
    global_obj = JS_GetGlobalObject(ctx);

    JS_SetPropertyStr(ctx, console, "log", JS_NewCFunction(ctx, aura_js_test_console, "log", 1));
    JS_SetPropertyStr(ctx, console, "info", JS_NewCFunction(ctx, aura_js_test_console, "info", 1));
    JS_SetPropertyStr(ctx, console, "error", JS_NewCFunction(ctx, aura_js_test_console, "error", 1));
    JS_SetPropertyStr(ctx, console, "warn", JS_NewCFunction(ctx, aura_js_test_console, "warn", 1));

    JS_SetPropertyStr(ctx, global_obj, "console", console);
    JS_FreeValue(ctx, global_obj);
}

/**
 * Get string data from the source.
 * We do not make a copy of the data and simply point
 * to the underlying buffer.
 * @nread is received as the maximum size that can be read,
 * and the function adjusts it to the actual size read, which
 * could be smaller than the maximum received.
 */
static int a_qjs_body_src_read_string(struct aura_qjs_body_src *b_src, void **dest, uint64_t *nread) {
    /* Empty OR Done */
    if (!b_src->bytes.data || b_src->bytes.off == b_src->bytes.len) {
        *nread = 0;
        *dest = NULL;
        return 0;
    }

    *nread = a_min(*nread, b_src->bytes.len - b_src->bytes.off);
    *dest = b_src->bytes.data + b_src->bytes.off;
    b_src->bytes.off += *nread;

    return 0;
}

/* Destroy string source */
static void a_qjs_body_src_destroy_string(struct aura_qjs_body_src *b_src) {
    if (b_src->bytes.data)
        js_free(b_src->ctx, b_src->bytes.data);
    b_src->bytes.data = NULL;
}

/* Read array buffer body source */
static int a_qjs_body_src_array_buffer_read(struct aura_qjs_body_src *b_src, void **dest, uint64_t *nread) {
    uint64_t buf_len;
    uint8_t *buf = JS_GetArrayBuffer(b_src->ctx, &buf_len, b_src->js_body.val);

    if (!buf || buf_len == 0 || b_src->js_body.off == buf_len) {
        *nread = 0;
        *dest = NULL;
        return 0;
    }

    *nread = a_min(*nread, buf_len - b_src->js_body.off);
    *dest = buf + b_src->js_body.off;
    b_src->js_body.off += *nread;

    return 0;
}

/* Destroy array buffer source */
static void a_qjs_body_src_array_buffer_destroy(struct aura_qjs_body_src *b_src) {
    JS_FreeValue(b_src->ctx, b_src->js_body.val);
}

/* Read readable stream source */
static int a_qjs_body_src_readable_stream_read(struct aura_qjs_body_src *b_src, void **dest, uint64_t *nread) {
    /* If internal stream chunk is empty, read some more */
    if (b_src->js_body.chunk.off == b_src->js_body.chunk.len) {
        JSValue _data_p = JS_Call(b_src->ctx, b_src->js_body.js_read, JS_UNDEFINED, 0, NULL);
        /* Await promise to resolve */
        JSValue _data = aura_js_std_await(b_src->ctx, _data_p);
        if (JS_IsException(_data)) {
            JS_FreeValue(b_src->ctx, _data);
            return -1;
        }

        JSValue _done = JS_GetPropertyStr(b_src->ctx, _data, "done");
        bool done = JS_ToBool(b_src->ctx, _done);
        JS_FreeValue(b_src->ctx, _done);

        if (done) {
            *nread = 0;
            *dest = NULL;
            return 0;
        }

        /* Add to chunk */
    }
}

/* Destroy readable stream source */
static void a_qjs_body_src_readable_stream_destroy(struct aura_qjs_body_src *b_src) {
    JS_FreeValue(b_src->ctx, b_src->js_body.js_read);
    js_free(b_src->ctx, b_src->js_body.chunk.data);
    JS_FreeValue(b_src->ctx, b_src->js_body.val);
}

/**/
JSValue aura_js_fetch_test_fn(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    const char *url;
    uint64_t url_len;
    struct aura_qjs_rt_data *rt_data = JS_GetRuntimeOpaque(JS_GetRuntime(ctx));
    A_BUG_ON_2(!rt_data, true);
    JSValue promise, promise_fn[2];
    JSValue options = JS_UNDEFINED;
    struct aura_qjs_body_src b_src;
    int req_method;
    a_qjs_body_t body_type;
    struct aura_qjs_fetch_ctx *fetch_ctx;
    app_debug(true, 0, "aura_js_fetch_test_fn <<<<----------A");

    if (argc < 1 || argc > 2)
        return JS_ThrowSyntaxError(ctx, "Incorrect number of fetch arguments provided");

    if (argc == 1) {
        if (!JS_IsString(argv[0]) && !JS_IsObject(argv[0])) {
            JS_ThrowTypeError(ctx, "Incorrect parameter types for fetch");
            return JS_EXCEPTION;
        }
        if (JS_IsObject(argv[0]))
            options = argv[0];
    }

    if (argc > 1) {
        if (!JS_IsString(argv[0]) && !JS_IsObject(argv[1]))
            return JS_ThrowSyntaxError(ctx, "Incorrect argument type for fetch options");
        options = argv[1];
    }

    if (JS_IsString(argv[0])) {
        url = JS_ToCStringLen(ctx, &url_len, argv[0]);
    } else {
        /* object */
        JSValue _url = JS_GetPropertyStr(ctx, options, "url");
        if (JS_IsUndefined(_url))
            return JS_ThrowTypeError(ctx, "missing fetch url");
        url = JS_ToCStringLen(ctx, &url_len, _url);
        JS_FreeValue(ctx, _url);
    }

    if (!url)
        return JS_ThrowTypeError(ctx, "Missing fetch url");

    /* default */
    req_method = A_HTTP_GET;

    memset(&b_src, 0, sizeof(b_src));
    b_src.type = A_QJS_BODY_TYPE_EMPTY;
    if (!JS_IsUndefined(options)) {
        /* method */
        JSValue method = JS_GetPropertyStr(ctx, argv[1], "method");
        if (!JS_IsUndefined(method)) {
            uint64_t method_len;

            const char *method_str = JS_ToCStringLen(ctx, &method_len, method);
            JS_FreeValue(ctx, method);
            if (method_str) {
                req_method = a_qjs_get_method_from_str(method_str, method_len);
                JS_FreeCString(ctx, method_str);
                if (req_method == A_HTTP_OK) {
                    JS_FreeCString(ctx, url);
                    return JS_ThrowTypeError(ctx, "Invalid HTTP method provided");
                }
            }
        }

        /* body */
        if (req_method == A_HTTP_POST) {
            JSValue body = JS_GetPropertyStr(ctx, options, "body");
            if (!JS_IsUndefined(body)) {
                body_type = a_qjs_get_body_type(ctx, body);

                switch (body_type) {
                case A_QJS_BODY_TYPE_STRING:
                    const char *data = JS_ToCStringLen(ctx, &b_src.bytes.len, body);
                    JS_FreeValue(ctx, body);
                    if (!data)
                        return JS_ThrowOutOfMemory(ctx);
                    b_src.type = A_QJS_BODY_TYPE_STRING;
                    b_src.ops->read = a_qjs_body_src_read_string;
                    b_src.ops->destroy = a_qjs_body_src_destroy_string;
                    break;

                case A_QJS_BODY_TYPE_ARRAY_BUFFER:
                    b_src.type = A_QJS_BODY_TYPE_ARRAY_BUFFER;
                    b_src.js_body.val = JS_DupValue(ctx, body);
                    b_src.ops->read = a_qjs_body_src_array_buffer_read;
                    b_src.ops->destroy = a_qjs_body_src_array_buffer_destroy;
                    JS_FreeValue(ctx, body);
                    break;

                case A_QJS_BODY_TYPE_READABLE_STREAM:
                    b_src.type = A_QJS_BODY_TYPE_READABLE_STREAM;
                    b_src.js_body.val = JS_DupValue(ctx, body);
                    JSValue js_reader = JS_GetPropertyStr(ctx, body, "getReader");
                    JSValue js_read = JS_GetPropertyStr(ctx, js_reader, "read");
                    JS_FreeValue(ctx, js_reader);
                    b_src.js_body.js_read = js_read;
                    b_src.ops->read = a_qjs_body_src_readable_stream_read;
                    b_src.ops->destroy = a_qjs_body_src_readable_stream_destroy;
                    JS_FreeValue(ctx, body);
                    break;

                default:
                    JS_FreeValue(ctx, body);
                    return JS_ThrowTypeError(ctx, "Invalid fetch body provided");
                }
            }
        }
    }

    // req = js_malloc(ctx, sizeof(*req));
    // if (!req) {
    //     JS_FreeCString(ctx, url);
    //     aura_qjs_fetch_ctx_destroy(fetch_ctx);
    //     return JS_ThrowOutOfMemory(ctx);
    // }

    // req->opaque_data = fetch_ctx;

    // JSValue req_obj = JS_NewObjectClass(ctx, request_id);
    // if (JS_IsException(req_obj)) {
    //     JS_FreeCString(ctx, url);
    //     aura_qjs_fetch_ctx_destroy(fetch_ctx);
    //     aura_req_destroy(req);
    //     return req_obj;
    // }

    // JS_SetOpaque(req_obj , req);

    promise = JS_NewPromiseCapability(ctx, promise_fn);
    if (JS_IsException(promise)) {
        JS_FreeCString(ctx, url);
    }

    /* Create fetch context */
    fetch_ctx = aura_qjs_fetch_ctx_create(
      rt_data->mc,
      NULL,
      ctx,
      JS_DupValue(ctx, promise_fn[0]),
      JS_DupValue(ctx, promise_fn[1]),
      &b_src);

    JS_FreeValue(ctx, promise_fn[0]);
    JS_FreeValue(ctx, promise_fn[1]);

    if (!fetch_ctx) {
        JS_FreeCString(ctx, url);
        b_src.ops->destroy(&b_src);
    }

    rt_data->fetch_ctx = fetch_ctx;

    return promise;
}

/**/
int aura_qjs_test_consumer_decode_utf8(JSContext *ctx, A_QJS_TEXT_UTF8DecoderState *st,
                                       const uint8_t *data, uint64_t len, uint8_t **data_out,
                                       uint64_t *data_out_len, bool streaming) {
    return a_qjs_consumer_decode_utf8(
      ctx,
      st,
      data,
      len,
      data_out,
      data_out_len,
      streaming);
}