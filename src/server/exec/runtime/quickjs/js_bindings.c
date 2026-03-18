#include "bug_lib.h"
#include "error_lib.h"
#include "exec/runtime_srv.h"
#include "exec/task_srv.h"
#include "list_lib.h"
#include "memory_lib.h"
#include "quickjs.h"
#include "slab_lib.h"
#include "utils_lib.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

typedef enum {
    HTTP_NONE,
    HTTP_GET,
    HTTP_POST,
    HTTP_PUT,
    HTTP_DELETE,
    HTTP_PATCH,
    HTTP_HEAD,
} a_http_method_t;

static JSValue a_response_set_status(JSContext *ctx, JSValueConst this_val, JSValueConst status);

static inline bool a_get_property(JSContext *ctx, JSValue *value, JSValueConst obj, const char *option) {
    JSValue val;
    uint32_t tag;

    val = JS_GetPropertyStr(ctx, obj, option);
    if (JS_IsException(val))
        return false;

    if (!JS_IsUndefined(val)) {
        tag = JS_VALUE_GET_NORM_TAG(val);
        // perhaps use the tags to handle nested objects
        /* extract value */
    }
    JS_FreeValue(ctx, val);
    return true;
}

/* ---- CONSOLE ---- */

/* console log */
JSValue aura_js_console_log(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    for (int i = 0; i < argc; ++i) {
        const char *str = JS_ToCString(ctx, argv[i]);
        if (str) {
            // fprintf(stdout, "%s ", str);
            syslog(LOG_INFO, "%s", str);
            JS_FreeCString(ctx, str);
        }
    }
    // fprintf(stdout, "\n");
    return JS_UNDEFINED;
}

/* console error */
JSValue aura_js_console_error(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    for (int i = 0; i < argc; ++i) {
        const char *str = JS_ToCString(ctx, argv[i]);
        if (str) {
            // fprintf(stderr, "%s ", str);
            syslog(LOG_ERR, "%s", str);
            JS_FreeCString(ctx, str);
        }
    }
    // fprintf(stderr, "\n");
    return JS_UNDEFINED;
}

/** */
void aura_js_console_init(struct aura_qjs_runtime *qrt) {
    JSContext *ctx;
    JSValue global_obj;
    JSValue console;

    ctx = qrt->ctx;
    console = JS_NewObject(ctx);
    global_obj = JS_GetGlobalObject(ctx);

    JS_SetPropertyStr(ctx, console, "log", JS_NewCFunction(ctx, aura_js_console_log, "log", 1));
    JS_SetPropertyStr(ctx, console, "info", JS_NewCFunction(ctx, aura_js_console_log, "info", 1));
    JS_SetPropertyStr(ctx, console, "error", JS_NewCFunction(ctx, aura_js_console_error, "error", 1));
    JS_SetPropertyStr(ctx, console, "warn", JS_NewCFunction(ctx, aura_js_console_error, "warn", 1));

    JS_SetPropertyStr(ctx, global_obj, "console", console);
    JS_FreeValue(ctx, global_obj);
}

/* ---- END CONSOLE ---- */

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
                /* js_std_dump_error(ctx) */
            } else if (err == 0) {
                // js_std_promise_rejection_check(ctx);

                // if (os_poll_func)
                // os_poll_func(ctx);
            }
        } else {
            /* not a promise */
            rv = obj;
            break;
        }
    }
    return rv;
}

/* ---------- FETCH ---------- */
JSClassID req_class_id;
JSClassID res_class_id;
// JSClassID fetch_class_id;

static JSClassDef req_class = {
  .class_name = "Request",
};

static JSClassDef res_class = {
  .class_name = "Response",
};

// static JSClassDef fetch_class = {
//   .class_name = "Fetch"};

static inline int a_js_fetch_new_request(JSContext *ctx, int argc, JSValueConst *argv) {
    JSValueConst args;
    JSValue val;
    Request *req;
    const char *url, *method, *body;
    size_t len;

    if (argc > 1) {
        url = JS_ToCString(ctx, argv[0]);
        args = argv[1];
    } else {
        args = argv[0];
        val = JS_GetPropertyStr(ctx, args, "url");
        if (JS_IsException(val))
            return -1;
        url = JS_ToCString(ctx, val);
        JS_FreeValue(ctx, val);
    }

    if (!url)
        return -1;

    val = JS_GetPropertyStr(ctx, args, "method");
    if (JS_IsException(val))
        goto err_url;
    method = JS_ToCString(ctx, val);
    JS_FreeValue(ctx, val);
    if (!method)
        goto err_url;

    val = JS_GetPropertyStr(ctx, args, "body");
    if (JS_IsException(val))
        goto err_method;
    body = JS_ToCStringLen(ctx, &len, val);
    JS_FreeValue(ctx, val);

    if (strcmp(method, "POST") == 0 && !body) {
        goto err_method;
    }

    /* call c function to create stream */
    // aura_js_fetch_request();

    return 0;

err_method:
    JS_FreeCString(ctx, method);
err_url:
    JS_FreeCString(ctx, url);
    return -1;
}

/* req.method */
static JSValue a_req_method_get(JSContext *ctx, JSValueConst this_val) {
    Request *req;
    const char *method_str;

    req = JS_GetOpaque2(ctx, this_val, req_class_id);
    A_BUG_ON_2(!req, true);

    switch (req->method) {
    case HTTP_GET:
        method_str = "GET";
        break;
    case HTTP_POST:
        method_str = "POST";
        break;
    case HTTP_PUT:
        method_str = "PUT";
        break;
    case HTTP_DELETE:
        method_str = "DELETE";
        break;
    case HTTP_PATCH:
        method_str = "PATCH";
        break;
    default:
        break;
    }

    return JS_NewString(ctx, method_str);
}

/* req.url */
static JSValue a_req_url_get(JSContext *ctx, JSValueConst this_val) {
    Request *req;

    req = JS_GetOpaque2(ctx, this_val, req_class_id);
    A_BUG_ON_2(!req, true);

    return JS_NewString(ctx, req->url);
}

/* res.status */
static JSValue a_fetch_get_status(JSContext *ctx, JSValueConst this_val) {
    Response *res;

    // res = JS_GetOpaque2(ctx, this_val, res_class_id)
    return JS_UNDEFINED;
}

static JSValue a_response_set_status(JSContext *ctx, JSValueConst this_val, JSValueConst status) {
    Response *res;
    int _status;

    res = JS_GetOpaque2(ctx, this_val, res_class_id);
    A_BUG_ON_2(!res, true);

    if (JS_ToUint32(ctx, &_status, status))
        return JS_EXCEPTION;

    res->status = _status;
    return JS_UNDEFINED;
}

/* req.arrayBuffer *zero-copy */
static JSValue a_js_req_arraybuffer(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    Request *req;

    req = JS_GetOpaque2(ctx, this_val, req_class_id);
    A_BUG_ON_2(!req, true);
    // req->body_used = true;

    return JS_NewArrayBuffer(ctx, (uint8_t *)req->body, req->body_len, NULL, NULL, 0);
}

/* req.text */
static JSValue a_req_body_text_get(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    Request *req;

    req = JS_GetOpaque2(ctx, this_val, req_class_id);
    A_BUG_ON_2(!req, true);
    // req->body_used = true;

    return JS_NewStringLen(ctx, req->body, req->body_len);
}

static JSValue a_js_res_json(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    JSValue val;
    Response *res;
    const char *body;
    size_t len;

    res = JS_GetOpaque2(ctx, this_val, res_class_id);
    A_BUG_ON_2(!res, true);

    val = JS_JSONStringify(ctx, argv[0], argv[1], argv[2]);
    if (JS_IsException(val))
        return val;

    body = JS_ToCStringLen(ctx, &len, val);
    JS_FreeValue(ctx, val);

    res->body = body;
    res->body_len = len;

    return JS_UNDEFINED;
}

/* Js fetch implementation */
JSValue aura_js_fetch(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    JSValue promise;
    JSValue resolving_funcs[2];
    int res;

    if (argc < 1 || argc > 2)
        return JS_EXCEPTION;

    res = a_js_fetch_new_request(ctx, argc, argv);
    if (res == -1) {
        return JS_EXCEPTION;
    }

    promise = JS_NewPromiseCapability(ctx, resolving_funcs);
    return promise;
}

const JSCFunctionListEntry aura_js_request_proto_funcs[] = {
  JS_CGETSET_DEF("method", a_req_method_get, NULL),
  JS_CGETSET_DEF("url", a_req_url_get, NULL),
  JS_CFUNC_DEF("arrayBuffer", 1, a_js_req_arraybuffer),
  JS_CFUNC_DEF("text", 1, a_req_body_text_get),
};

const JSCFunctionListEntry aura_js_response_proto_funcs[] = {
  JS_CGETSET_DEF("status", NULL, a_response_set_status),
  JS_CFUNC_DEF("json", 0, a_js_res_json),
};

const uint32_t aura_js_request_proto_funcs_len = ARRAY_SIZE(aura_js_request_proto_funcs);
const uint32_t aura_js_response_proto_funcs_len = ARRAY_SIZE(aura_js_response_proto_funcs);

int aura_js_fetch_init(struct aura_qjs_runtime *qrt) {
    JSContext *ctx;
    JSRuntime *rt;
    JSValue req_proto, res_proto, global;

    ctx = qrt->ctx;
    rt = qrt->rt;
    /**
     * init request protos, shared by all runtimes
     * quickjs will take handle if the class is
     * already created
     */
    /* request */
    JS_NewClassID(&req_class_id);
    JS_NewClass(rt, req_class_id, &req_class);
    /* response */
    JS_NewClassID(&res_class_id);
    JS_NewClass(rt, res_class_id, &res_class);
    /* fetch */
    // JS_NewClassID(&fetch_class_id);
    // JS_NewClass(rt, fetch_class_id, &fetch_class);

    req_proto = JS_NewObject(ctx);
    if (JS_IsException(req_proto)) {
        return -1;
    }

    res_proto = JS_NewObject(ctx);
    if (JS_IsException(res_proto)) {
        JS_FreeValue(ctx, req_proto);
        return -1;
    }

    JS_SetPropertyFunctionList(ctx, req_proto, aura_js_request_proto_funcs, aura_js_request_proto_funcs_len);
    JS_SetClassProto(ctx, req_class_id, req_proto);

    JS_SetPropertyFunctionList(ctx, res_proto, aura_js_response_proto_funcs, aura_js_response_proto_funcs_len);
    JS_SetClassProto(ctx, res_class_id, res_proto);

    global = JS_GetGlobalObject(ctx);
    JS_SetPropertyStr(ctx, global, "fetch", JS_NewCFunction(ctx, aura_js_fetch, "fetch", 1));
    JS_FreeValue(ctx, global);

    return 0;
}

/* ---- END FETCH ---- */

/* exit */
void aura_js_std_exit(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    int status;
    if (JS_ToInt32(ctx, &status, argv[0]))
        status = -1;
    exit(status);
}

/* Parse JSON */
JSValue aura_js_parseExtJSON(JSContext *ctx, const char *module_name, const char *buf, size_t buf_len) {
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

int init_fn_apis(JSContext *ctx, uint32_t flags, size_t len) {
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

// const JSMallocFunctions aura_trace_mf = {
//   aura_alloc,
//   aura_free,
//   aura_realloc,
// };
