#include "bug_lib.h"
#include "exec/runtime_srv.h"
#include "exec/task_srv.h"
#include "list_lib.h"
#include "memory_lib.h"
#include "quickjs/quickjs.h"
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
            fprintf(stdout, "%s ", str);
            JS_FreeCString(ctx, str);
        }
    }
    fprintf(stdout, "\n");
    return JS_UNDEFINED;
}

/* console error */
JSValue aura_js_console_error(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    for (int i = 0; i < argc; ++i) {
        const char *str = JS_ToCString(ctx, argv[i]);
        if (str) {
            fprintf(stderr, "%s ", str);
            JS_FreeCString(ctx, str);
        }
    }
    fprintf(stderr, "\n");
    return JS_UNDEFINED;
}

/** */
void aura_js_console_init(st_aura_qjs_runtime *qrt) {
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

/* ---------- FETCH ---------- */
JSClassID req_class_id;
JSClassID res_class_id;

static JSClassDef req_class = {
  .class_name = "Edge_Request",
};

static JSClassDef res_class = {
  .class_name = "Edge_Response",
};

static JSValue a_js_fetch_new_request(JSContext *ctx, JSValueConst *argv) {
    JSValue req_obj;
    Request *req;

    req = malloc(sizeof(*req));
    if (!req)
        return JS_EXCEPTION;

    /* extract details from user request object */

    req_obj = JS_NewObjectClass(ctx, req_class_id);
    if (JS_IsException(req_obj))
        return JS_EXCEPTION;

    JS_SetOpaque(req_obj, (void *)req);
    req->obj = JS_DupValue(ctx, req_obj); /* @todo: is duplicating needed */

    /* call c function to create stream*/

    return req_obj;
}

static JSValue a_js_fetch_new_response(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    JSValue res_obj;
    Response *res;

    res = malloc(sizeof(*res));
    if (!res)
        return JS_EXCEPTION;

    /* set defauts */
    res->status = 200;
    // res->headers = create_headers
    res->body = NULL;
    res->body_len = 0;

    if (argc > 0 && !JS_IsUndefined(argv[0])) {
        /* copy over user object to res structure */
    }

    res_obj = JS_NewObjectClass(ctx, res_class_id);
    if (JS_IsException(res_obj))
        return JS_EXCEPTION;

    JS_SetOpaque(res_obj, (void *)res);
    res->obj = JS_DupValue(ctx, res_obj); /* @todo: */

    return res_obj;
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

/* req.arrayBuffer *zero-copy */
static JSValue a_js_req_arraybuffer(JSContext *ctx, JSValueConst this_val) {
    Request *req;

    req = JS_GetOpaque2(ctx, this_val, req_class_id);
    A_BUG_ON_2(!req, true);
    // req->body_used = true;

    return JS_NewArrayBuffer(ctx, (uint8_t *)req->body, req->body_len, NULL, NULL, 0);
}

/* req.text */
static JSValue a_req_body_text_get(JSContext *ctx, JSValueConst this_val) {
    Request *req;

    req = JS_GetOpaque2(ctx, this_val, req_class_id);
    A_BUG_ON_2(!req, true);
    // req->body_used = true;

    return JS_NewStringLen(ctx, req->body, req->body_len);
}

/* Js fetch implementation */
JSValue aura_js_fetch(JSContext *ctx, JSValueConst this_val, int argc, JSValueConst *argv) {
    JSValue req_obj, promise;
    JSValue resolving_funcs[2];

    if (argc < 1 || argc > 2)
        return JS_EXCEPTION;

    promise = JS_NewPromiseCapability(ctx, resolving_funcs);

    req_obj = a_js_fetch_new_request(ctx, argv);
    return promise;
}

const JSCFunctionListEntry aura_js_request_proto_funcs[] = {
  JS_CGETSET_DEF("method", a_req_method_get, NULL),
  JS_CGETSET_DEF("url", a_req_url_get, NULL),
  JS_CGETSET_DEF("arrayBuffer", a_js_req_arraybuffer, NULL),
  JS_CGETSET_DEF("text", a_req_body_text_get, NULL),
};

const uint32_t aura_js_request_proto_funcs_len = ARRAY_SIZE(aura_js_request_proto_funcs);

int aura_js_fetch_init(st_aura_qjs_runtime *qrt) {
    JSContext *ctx;
    JSValue req_proto, global;
    JSRuntime *rt;

    ctx = qrt->ctx;
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

    req_proto = JS_NewObject(ctx);
    if (JS_IsException(req_proto)) {
        JS_FreeValue(ctx, req_proto);
        return 1;
    }
    JS_SetPropertyFunctionList(ctx, req_proto, aura_js_request_proto_funcs, aura_js_request_proto_funcs_len);
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
