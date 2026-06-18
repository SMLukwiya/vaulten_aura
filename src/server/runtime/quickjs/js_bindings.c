#include "bug_lib.h"
#include "error_lib.h"
#include "http_lib.h"
#include "list_lib.h"
#include "memory_lib.h"
#include "quickjs.h"
#include "runtime/js.h"
#include "runtime/runtime.h"
#include "server_srv.h"
#include "slab_lib.h"
#include "string_lib.h"
#include "task_srv.h"
#include "utils_lib.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

/* ---- CONSOLE LOGGING ---- */

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

/** */
void aura_js_console_init(JSRuntime *rt, JSContext *ctx) {
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
JSClassID fetch_class_id;

static JSClassDef req_class = {
  .class_name = "Request",
};

static JSClassDef res_class = {
  .class_name = "Response",
};

static JSClassDef fetch_class = {
  .class_name = "Fetch",
};

/* req.method */
static JSValue a_js_req_method_get(JSContext *ctx, JSValueConst this_val) {
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

static int a_req_method_get_enum(const char *method, size_t len) {
    if (strncasecmp(method, "GET", len) == 0)
        return HTTP_GET;
    else if (strncasecmp(method, "POST", len) == 0)
        return HTTP_POST;
    else if (strncasecmp(method, "HEAD", len) == 0)
        return HTTP_HEAD;
    else {
        return HTTP_NONE;
    }
}

/* req.url */
static JSValue a_js_req_url_get(JSContext *ctx, JSValueConst this_val) {
    Request *req;

    req = JS_GetOpaque2(ctx, this_val, req_class_id);
    A_BUG_ON_2(!req, true);

    return JS_NewString(ctx, req->url.base);
}

/* res.status */
static JSValue a_js_res_set_status(JSContext *ctx, JSValueConst this_val, JSValueConst status) {
    Response *res;
    int _status;

    res = JS_GetOpaque2(ctx, this_val, res_class_id);
    A_BUG_ON_2(!res, true);

    if (JS_ToUint32(ctx, &_status, status))
        return JS_EXCEPTION;

    res->status = _status;
    return JS_UNDEFINED;
}

static JSValue a_js_res_get_status(JSContext *ctx, JSValueConst this_val) {
    Response *res;
    int _status;

    res = JS_GetOpaque2(ctx, this_val, res_class_id);
    A_BUG_ON_2(!res, true);

    return JS_NewInt32(ctx, (int32_t)res->status);
}

static JSValue a_js_res_get_ok(JSContext *ctx, JSValueConst this_val) {
    Response *res;
    int _status;

    res = JS_GetOpaque2(ctx, this_val, res_class_id);
    A_BUG_ON_2(!res, true);

    return JS_NewBool(ctx, res->ok);
}

static JSValue a_js_res_set_header(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    Response *resp;
    size_t name_len, value_len;
    const char *n, *v;
    struct aura_basic_header *hdr_slot;
    struct aura_qjs_rt_thread_state *ts;

    if (!argc != 2) {
        return JS_ThrowTypeError(ctx, "set receives two arguments");
    }

    resp = JS_GetOpaque2(ctx, this_val, res_class_id);
    A_BUG_ON_2(!resp, true);

    ts = JS_GetRuntimeOpaque(JS_GetRuntime(ctx));
    A_BUG_ON_2(!ts, true);

    n = JS_ToCStringLen(ctx, &name_len, argv[0]);
    if (!n || name_len == 0)
        return JS_ThrowSyntaxError(ctx, "Header name can not be empty");

    v = JS_ToCStringLen(ctx, &value_len, argv[1]);
    if (!v) {
        JS_FreeCString(ctx, n);
        return JS_ThrowSyntaxError(ctx, "Header value can not be undefined");
    }

    hdr_slot = aura_rt_res_get_header_slot(ts->srv_ctx->mc, resp);
    if (!hdr_slot) {
        JS_FreeCString(ctx, n);
        JS_FreeCString(ctx, v);
        return JS_ThrowOutOfMemory(ctx);
    }

    hdr_slot->name.base = aura_strndup(ts->srv_ctx->mc, n, name_len);
    hdr_slot->name.len = name_len;
    hdr_slot->value.base = aura_strndup(ts->srv_ctx->mc, n, name_len);
    hdr_slot->value.len = value_len;

    return JS_UNDEFINED;
}

/* req.arrayBuffer *zero-copy */
static JSValue a_js_req_arraybuffer(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    Request *req;

    req = JS_GetOpaque2(ctx, this_val, req_class_id);
    A_BUG_ON_2(!req, true);

    return JS_NewArrayBuffer(ctx, (uint8_t *)req->body, req->body_len, NULL, NULL, 0);
}

/* req.text */
static JSValue a_js_req_body_text_get(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    Request *req;

    req = JS_GetOpaque2(ctx, this_val, req_class_id);
    A_BUG_ON_2(!req, true);

    return JS_NewStringLen(ctx, req->body, req->body_len);
}

/**
 * Create json response from js object
 */
static JSValue a_js_res_json(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    JSValue val;
    Response *res;
    struct aura_qjs_rt_thread_state *ts;
    const char *body;
    size_t len;

    res = JS_GetOpaque2(ctx, this_val, res_class_id);
    A_BUG_ON_2(!res, true);

    ts = JS_GetRuntimeOpaque(JS_GetRuntime(ctx));
    A_BUG_ON_2(!ts, true);

    val = JS_JSONStringify(ctx, argv[0], JS_UNDEFINED, JS_UNDEFINED);
    if (JS_IsException(val))
        return val;

    body = JS_ToCStringLen(ctx, &len, val);
    JS_FreeValue(ctx, val);

    res->body = aura_memcpy(ts->srv_ctx->mc, (void *)body, len);
    ;
    res->body_len = len;

    return JS_UNDEFINED;
}

/* Js fetch implementation */
JSValue aura_js_fetch(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    struct aura_qjs_rt_thread_state *ts;
    JSValue promise, options, val;
    JSValue resolving_funcs[2];
    JSValue js_error, headers;
    JSValue fns[2];
    const char *url, *method, *body;
    size_t url_len, method_len, body_len;
    Request *req;
    bool headers_provided;
    int res, _method;
    app_debug(true, 0, "FETCH CALLED <<<<");

    if (argc < 1 || argc > 2)
        return JS_EXCEPTION;

    ts = JS_GetRuntimeOpaque(JS_GetRuntime(ctx));
    if (!ts)
        return JS_EXCEPTION;

    req = aura_rt_create_req(ts->srv_ctx->mc);
    if (!req)
        return JS_EXCEPTION;

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

    if (aura_url_parse(ts->srv_ctx->mc, url, url_len, &req->parsed_url) < 0) {
        JS_FreeCString(ctx, url);
        return JS_EXCEPTION;
    }

    if (JS_IsNull(options)) {
        _method = HTTP_GET;
        body = NULL;
        body_len = 0;
    } else {
        val = JS_GetPropertyStr(ctx, options, "method");
        if (JS_IsException(val)) {
            JS_FreeCString(ctx, url);
            return JS_EXCEPTION;
        }
        if (JS_IsUndefined(val)) {
            _method = HTTP_GET;
        } else {
            if (!JS_IsString(val)) {
                JS_FreeCString(ctx, url);
                JS_FreeValue(ctx, val);
                return JS_EXCEPTION;
            }
            method = JS_ToCStringLen(ctx, &method_len, val);
            _method = a_req_method_get_enum(method, method_len);
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

        if ((_method == HTTP_POST && !body) || (_method != HTTP_POST && body)) {
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
            struct aura_basic_header *hdr_slot;
            size_t key_len, value_len;

            JSAtom atom = props[i].atom;

            const char *key = JS_AtomToCStringLen(ctx, &key_len, atom);
            if (!aura_header_name_valid(key)) {
                JS_FreeCString(ctx, key);
                JS_FreeAtom(ctx, atom);
                goto err;
            }

            if (aura_header_value_forbidden(key)) {
                JS_FreeCString(ctx, key);
                JS_FreeAtom(ctx, atom);
                goto err;
            }

            val = JS_GetPropertyStr(ctx, headers, key);
            const char *value = JS_ToCStringLen(ctx, &value_len, val);
            JS_FreeValue(ctx, val);
            JS_FreeAtom(ctx, atom);

            if (!aura_header_value_valid(value)) {
                JS_FreeCString(ctx, key);
                JS_FreeCString(ctx, value);
                goto err;
            }

            hdr_slot = aura_rt_req_get_header_slot(ts->srv_ctx->mc, req);
            if (!hdr_slot) {
                JS_FreeCString(ctx, key);
                JS_FreeCString(ctx, value);
                goto err;
            }

            memset(hdr_slot, 0, sizeof(*hdr_slot));
            hdr_slot->name.base = aura_strndup(ts->srv_ctx->mc, key, key_len);
            hdr_slot->name.len = key_len;
            hdr_slot->value.base = aura_strndup(ts->srv_ctx->mc, value, value_len);
            hdr_slot->value.len = value_len;
            JS_FreeCString(ctx, key);
            JS_FreeCString(ctx, value);
        }
    no_header:
    }

    req->url.base = aura_str_tolowercase(ts->srv_ctx->mc, url, url_len);
    req->url.len = url_len;
    req->body = aura_memcpy(ts->srv_ctx->mc, body, body_len);
    req->body_len = body_len;

    fns[0] = JS_DupValue(ctx, resolving_funcs[0]);
    fns[1] = JS_DupValue(ctx, resolving_funcs[1]);

    if (aura_qjs_create_fetch_request(ts->srv_ctx, ctx, req, fns) < 0) {
        /* Function released req resources internally */
        req = NULL;
        goto err;
    }

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
        aura_rt_req_destroy(req);
    js_error = JS_NewString(ctx, "Operation failed");
    JS_Throw(ctx, js_error);
    return JS_EXCEPTION;
}

const JSCFunctionListEntry aura_js_request_proto_funcs[] = {
  JS_CGETSET_DEF("method", a_js_req_method_get, NULL),
  JS_CGETSET_DEF("url", a_js_req_url_get, NULL),
  JS_CFUNC_DEF("arrayBuffer", 1, a_js_req_arraybuffer),
  JS_CFUNC_DEF("text", 1, a_js_req_body_text_get),
};

const JSCFunctionListEntry aura_js_response_proto_funcs[] = {
  JS_CGETSET_DEF("status", a_js_res_get_status, a_js_res_set_status),
  JS_CGETSET_DEF("ok", a_js_res_get_ok, NULL),
  JS_CFUNC_DEF("set", 1, a_js_res_set_header),
  JS_CFUNC_DEF("json", 1, a_js_res_json),
};

const uint32_t aura_js_request_proto_funcs_len = ARRAY_SIZE(aura_js_request_proto_funcs);
const uint32_t aura_js_response_proto_funcs_len = ARRAY_SIZE(aura_js_response_proto_funcs);

/**/
int aura_js_fetch_init(JSRuntime *rt, JSContext *ctx) {
    JSValue req_proto, res_proto, global;

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
