#include "executors/js/quickjs/rt.h"
#include "file/lib.h"
#include "http_lib.h"
#include <assert.h>
#include <fcntl.h>

#define A_JS_STR(...) #__VA_ARGS__

static struct aura_fn def_func = {
  .backend = 1,
  .fn_code = NULL,
  .fn_code_len = 0,
  .state = {.is_active = true},
  .stats = {0},
  .config = {0},
  .meta = {0},
};

struct aura_task def_task = {0};

const uint8_t body1[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F, 0x00}; /* Hello */
const uint8_t body2[] = {0xde, 0xad, 0xbe, 0xef};             /* deadbeef */
const uint8_t body3_first[] = {0x48, 0x65, 0x6C};
const uint8_t body3_last[] = {0x6C, 0x6F, 0x00};

Request req = {
  .body = NULL,
  .body_len = 0,
  .method = A_HTTP_GET,
  .url = "http://localhost:3000",
  .scheme = {.base = "HTTP", .len = sizeof("HTTP") - 1},
  .headers = {0},
  .parsed_url = {0},
  .sp = NULL,
  .bc = {
    .opaque = NULL,
    .state = A_BODY_NOT_CONSUMED,
  },
  .streaming = false,
};

Response res = {
  .body = "Response body",
  .body_len = sizeof("Response body") - 1,
  .headers = {0},
  .ok = true,
  .status = 200,
  .bc = {
    .opaque = NULL,
    .state = A_BODY_NOT_CONSUMED,
  },
  .streaming = false,
  .ok = true,
  .redirected = false,
  .status_text = "aura status text",
  .url = "http://remotehost:80/",
  .sp = NULL,
};

struct aura_mem_ctx mc;

/* Runtime to create and read bytecode */
JSRuntime *bc_rt;
/* Context to create and read bytecode */
JSContext *bc_ctx;

static void a_test_resources_create(void) {
    int rv;

    aura_mem_ctx_init(&mc);
    assert(aura_create_dynamic_slab_alloc_caches(&mc) == 0);
    aura_qjs_class_ids_init();
    bc_rt = JS_NewRuntime();
    assert(bc_rt);
    bc_ctx = JS_NewContext(bc_rt);
    assert(bc_ctx);
}

static void a_test_resources_destroy() {
    aura_mem_ctx_destroy(&mc);
    JS_FreeContext(bc_ctx);
    JS_FreeRuntime(bc_rt);
}

/**
 * Fake async for body consumer by feeding
 * data into the system
 */
int a_qjs_test_consumer_feed_data(JSContext *ctx, struct aura_qjs_bc_consumer_data *bc_data,
                                  const uint8_t *data, uint64_t len, bool done) {
    uint8_t *out, *final_buf;
    uint64_t out_len;

    if (aura_qjs_test_consumer_decode_utf8(ctx, &bc_data->st, data, len, &out, &out_len, !done) < 0) {
        return -1;
    }

    final_buf = js_realloc(ctx, bc_data->accumulator, bc_data->accumulator_len + out_len);
    if (!final_buf) {
        return -1;
    }

    memcpy(final_buf + bc_data->accumulator_len, out, out_len);
    bc_data->accumulator_len += out_len;
    return 0;
}

/**
 * Resolve/Reject promise with a string value
 */
static JSValue a_qjs_test_resolve_promise_str(JSContext *ctx, const char *data, uint64_t len,
                                              JSValue resolve_fn, JSValue reject_fn) {
    JSValue val, rv;
    int ret_val, promise_state;

    val = JS_NewStringLen(ctx, data, len);
    if (JS_IsException(val)) {
        rv = JS_Call(ctx, reject_fn, JS_UNDEFINED, 1, &val);
        ret_val = -1;
    } else {
        rv = JS_Call(ctx, resolve_fn, JS_UNDEFINED, 1, &val);
        ret_val = 0;
    }
    JS_FreeValue(ctx, val);

    while (JS_ExecutePendingJob(JS_GetRuntime(ctx), NULL) > 0)
        ;

    promise_state = JS_PromiseState(ctx, rv);
    if (promise_state == JS_PROMISE_FULFILLED) {
        val = JS_PromiseResult(ctx, rv);
    } else if (promise_state == JS_PROMISE_REJECTED) {
        val = JS_Throw(ctx, JS_PromiseResult(ctx, rv));
    }
    const char *_str = JS_ToCString(ctx, val);
    JS_FreeCString(ctx, _str);

    JS_FreeValue(ctx, rv);

    return val;
}

JSValue a_qjs_create_str_response(JSContext *ctx, const char *str_data, uint64_t len) {
    JSValue str_obj = JS_NewStringLen(ctx, str_data, len);
    if (JS_IsException(str_obj))
        return str_obj;

    JSValue global = JS_GetGlobalObject(ctx);
    JSValue resp_constructor = JS_GetPropertyStr(ctx, global, "Response");
    JSValue resp = JS_CallConstructor(ctx, resp_constructor, 1, (JSValueConst *)&str_obj);

    JS_FreeValue(ctx, str_obj);
    JS_FreeValue(ctx, resp_constructor);
    JS_FreeValue(ctx, global);

    return resp;
}

static void a_qjs_test_bytecode_generation(void) {
    JSValue handler;
    uint8_t *bytecode;
    size_t bytecode_len;

    const char *js_code = A_JS_STR(
      export default async function handler(bc_ctx) {
          console.log('Hello Vaulten aura Test');
      });

    assert(aura_qjs_write_bytecode(bc_ctx, js_code, strlen(js_code), "test", &bytecode, &bytecode_len) == 0);
    assert(bytecode != NULL);
    assert(bytecode_len > 0);

    assert(aura_qjs_read_bytecode(bc_ctx, (void *)bytecode, bytecode_len, &handler) == 0);
    assert(JS_IsFunction(bc_ctx, handler) == 1);
    JS_FreeValue(bc_ctx, handler);
}

static void a_qjs_test_console_logging(void) {
    JSRuntime *rt;
    JSContext *ctx;
    JSValue val;

    rt = JS_NewRuntime();
    assert(rt);

    ctx = JS_NewContext(rt);
    assert(ctx);

    aura_js_console_test_init(ctx);

    const char *func_log = A_JS_STR(
      function handler() {
          const res = console.log("console.log");
          return res;
      }

      handler());

    val = JS_Eval(ctx, func_log, strlen(func_log), "func_log", 0);
    assert(JS_IsException(val) == 0);
    assert(strcmp(JS_ToCString(ctx, val), "console.log") == 0);
    JS_FreeValue(ctx, val);

    const char *func_info = A_JS_STR(
      function handler(ctx) {
          const res = console.info("console.info");
          return res;
      }

      handler());

    val = JS_Eval(ctx, func_info, strlen(func_info), "func_info", 0);
    assert(JS_IsException(val) == 0);
    assert(strcmp(JS_ToCString(ctx, val), "console.info") == 0);
    JS_FreeValue(ctx, val);

    const char *func_warn = A_JS_STR(
      function handler(ctx) {
          const res = console.warn("console.warn");
          return res;
      }

      handler());

    val = JS_Eval(ctx, func_warn, strlen(func_warn), "func_warn", 0);
    assert(JS_IsException(val) == 0);
    assert(strcmp(JS_ToCString(ctx, val), "console.warn") == 0);
    JS_FreeValue(ctx, val);

    const char *func_error = A_JS_STR(
      function handler(ctx) {
          const res = console.error("console.error");
          return res;
      }

      handler());

    val = JS_Eval(ctx, func_error, strlen(func_error), "func_error", 0);
    assert(JS_IsException(val) == 0);
    assert(strcmp(JS_ToCString(ctx, val), "console.error") == 0);
    JS_FreeValue(ctx, val);

    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
}

static void a_qjs_test_ctx_evt_source() {
    struct aura_qjs_execution_ctx *exec_ctx;
    JSValue rv;

    const char *js_code = A_JS_STR(
      export default async function handler(ctx) {
          return ctx.event.src;
      });

    assert(aura_qjs_write_bytecode(bc_ctx, js_code, strlen(js_code), "test", (uint8_t **)&def_func.fn_code, &def_func.fn_code_len) == 0);
    assert(def_func.fn_code);
    assert(def_func.fn_code_len > 0);

    exec_ctx = aura_qjs_exec_ctx_create_test(&mc, &def_func);
    assert(exec_ctx);

    assert(aura_qjs_prepare(exec_ctx, &def_task, &req, &res) == 0);

    rv = aura_qjs_execute_test(exec_ctx);
    const char *str = JS_ToCString(exec_ctx->ctx, rv);
    assert(strcmp(str, "http") == 0);
    JS_FreeCString(exec_ctx->ctx, str);
    JS_FreeValue(exec_ctx->ctx, rv);

    aura_qjs_exec_ctx_destroy_test(exec_ctx);
}

static void a_qjs_test_ctx_evt_request(void) {
    struct aura_qjs_execution_ctx *exec_ctx;
    char *js_code;
    JSValue rv;
    const char *str, *str_expected;
    uint64_t str_len;

    /* request.url */
    js_code = A_JS_STR(
      export default async function handler(ctx) {
          return ctx.event.request.url;
      });

    assert(aura_qjs_write_bytecode(bc_ctx, js_code, strlen(js_code), "test", (uint8_t **)&def_func.fn_code, &def_func.fn_code_len) == 0);
    assert(def_func.fn_code);
    assert(def_func.fn_code_len > 0);

    exec_ctx = aura_qjs_exec_ctx_create_test(&mc, &def_func);
    assert(exec_ctx);

    assert(aura_qjs_prepare(exec_ctx, &def_task, &req, &res) == 0);

    rv = aura_qjs_execute_test(exec_ctx);
    const char *url = JS_ToCString(exec_ctx->ctx, rv);
    assert(strcmp(url, "http://localhost:3000") == 0);
    JS_FreeCString(exec_ctx->ctx, url);
    JS_FreeValue(exec_ctx->ctx, rv);

    aura_qjs_exec_ctx_destroy_test(exec_ctx);

    /* request.method */
    js_code = A_JS_STR(
      export default async function handler(ctx) {
          return ctx.event.request.method;
      });

    assert(aura_qjs_write_bytecode(bc_ctx, js_code, strlen(js_code), "test", (uint8_t **)&def_func.fn_code, &def_func.fn_code_len) == 0);
    assert(def_func.fn_code);
    assert(def_func.fn_code_len > 0);

    exec_ctx = aura_qjs_exec_ctx_create_test(&mc, &def_func);
    assert(exec_ctx);

    assert(aura_qjs_prepare(exec_ctx, &def_task, &req, &res) == 0);

    rv = aura_qjs_execute_test(exec_ctx);
    const char *method = JS_ToCString(exec_ctx->ctx, rv);
    assert(strcmp(method, "GET") == 0);
    JS_FreeCString(exec_ctx->ctx, method);
    JS_FreeValue(exec_ctx->ctx, rv);

    aura_qjs_exec_ctx_destroy_test(exec_ctx);

    /* request.arrayBuffer() */
    js_code = A_JS_STR(
      export default async function handler(ctx) {
          return await ctx.event.request.arrayBuffer();
      });

    assert(aura_qjs_write_bytecode(bc_ctx, js_code, strlen(js_code), "test", (uint8_t **)&def_func.fn_code, &def_func.fn_code_len) == 0);
    assert(def_func.fn_code);
    assert(def_func.fn_code_len > 0);

    exec_ctx = aura_qjs_exec_ctx_create_test(&mc, &def_func);
    assert(exec_ctx);

    /* Set request body */
    req.body = body1;
    req.body_len = sizeof(body1);
    assert(aura_qjs_prepare(exec_ctx, &def_task, &req, &res) == 0);

    rv = aura_qjs_execute_test(exec_ctx);
    size_t arr_size;
    uint8_t *buf = JS_GetArrayBuffer(exec_ctx->ctx, &arr_size, rv);
    assert(arr_size == sizeof(body1));
    assert(memcmp(buf, body1, arr_size) == 0);
    JS_FreeValue(exec_ctx->ctx, rv);

    aura_qjs_exec_ctx_destroy_test(exec_ctx);

    js_code = A_JS_STR(
      export default async function handler(ctx) {
          const bytes = new Uint8Array(await ctx.event.request.arrayBuffer());
          return Array.from(bytes).join(",");
      });

    assert(aura_qjs_write_bytecode(bc_ctx, js_code, strlen(js_code), "test", (uint8_t **)&def_func.fn_code, &def_func.fn_code_len) == 0);
    assert(def_func.fn_code);
    assert(def_func.fn_code_len > 0);

    exec_ctx = aura_qjs_exec_ctx_create_test(&mc, &def_func);
    assert(exec_ctx);

    /* Set request body */
    req.body = body2;
    req.body_len = sizeof(body2);
    assert(aura_qjs_prepare(exec_ctx, &def_task, &req, &res) == 0);

    rv = aura_qjs_execute_test(exec_ctx);
    const char *deadbeef = JS_ToCString(exec_ctx->ctx, rv);
    assert(strcmp(deadbeef, "222,173,190,239") == 0); /* "de,ad,be,ef" */
    JS_FreeCString(exec_ctx->ctx, deadbeef);
    JS_FreeValue(exec_ctx->ctx, rv);

    aura_qjs_exec_ctx_destroy_test(exec_ctx);

    /* req.body */
    js_code = A_JS_STR(
      export default async function handler(ctx) {
          const readableStream = ctx.event.request.body;
          const reader = readableStream.getReader();
          let result = "";

          while (true) {
              const {done, value} = await reader.read();
              const str = new TextDecoder();

              if (done) {
                  break;
              }

              result += str.decode(value);
          }

          return result;
      });

    assert(aura_qjs_write_bytecode(bc_ctx, js_code, strlen(js_code), "test", (uint8_t **)&def_func.fn_code, &def_func.fn_code_len) == 0);
    assert(def_func.fn_code);
    assert(def_func.fn_code_len > 0);

    exec_ctx = aura_qjs_exec_ctx_create_test(&mc, &def_func);
    assert(exec_ctx);

    /* Set request body */
    req.body = body1;
    req.body_len = sizeof(body1);
    assert(aura_qjs_prepare(exec_ctx, &def_task, &req, &res) == 0);

    rv = aura_qjs_execute_test(exec_ctx);
    uint64_t len;
    const char *body = JS_ToCStringLen(exec_ctx->ctx, &len, rv);
    assert(strcmp(body, "Hello") == 0);
    JS_FreeCString(exec_ctx->ctx, body);

    JS_FreeValue(exec_ctx->ctx, rv);

    aura_qjs_reset_test(exec_ctx);
    aura_qjs_exec_ctx_destroy_test(exec_ctx);
}

/* req.text() */
static void a_qjs_test_request_text(void) {
    struct aura_qjs_execution_ctx *exec_ctx;
    const char *js_code;
    JSValue rv;
    const char *str, *str_expected;
    uint64_t str_len;

    /* req.text() */
    js_code = A_JS_STR(
      export default async function handler(ctx) {
          return await ctx.event.request.text();
      });

    assert(aura_qjs_write_bytecode(
             bc_ctx,
             js_code,
             strlen(js_code),
             "test",
             (uint8_t **)&def_func.fn_code,
             &def_func.fn_code_len) == 0);
    assert(def_func.fn_code);
    assert(def_func.fn_code_len > 0);

    exec_ctx = aura_qjs_exec_ctx_create_test(&mc, &def_func);
    assert(exec_ctx);

    /* Set request body */
    req.body = body1;
    req.body_len = sizeof(body1);
    assert(aura_qjs_prepare(exec_ctx, &def_task, &req, &res) == 0);

    rv = aura_qjs_execute_test(exec_ctx);
    const char *text = JS_ToCString(exec_ctx->ctx, rv);
    assert(strcmp(text, "Hello") == 0);
    JS_FreeCString(exec_ctx->ctx, text);
    JS_FreeValue(exec_ctx->ctx, rv);

    // aura_qjs_exec_ctx_destroy_test(exec_ctx);

    /* req.text() streaming */
    js_code = A_JS_STR(
      export default async function handler(ctx) {
          return await ctx.event.request.text();
      });

    assert(aura_qjs_write_bytecode(
             bc_ctx,
             js_code,
             strlen(js_code),
             "test",
             (uint8_t **)&def_func.fn_code,
             &def_func.fn_code_len) == 0);
    assert(def_func.fn_code);
    assert(def_func.fn_code_len > 0);

    exec_ctx = aura_qjs_exec_ctx_create_test(&mc, &def_func);
    assert(exec_ctx);

    /* Prepare first part of request */
    req.body = body3_first;
    req.body_len = sizeof(body3_first);
    req.streaming = true;
    req.bc.state = A_BODY_NOT_CONSUMED;
    assert(aura_qjs_prepare(exec_ctx, &def_task, &req, &res) == 0);

    rv = aura_qjs_execute_test(exec_ctx);

    struct aura_qjs_bc_consumer_data *bc_data = req.bc.opaque;
    /* Fake data fetching */
    assert(a_qjs_test_consumer_feed_data(exec_ctx->ctx, bc_data, body3_last, sizeof(body3_last), true) == 0);

    JSValue val = a_qjs_test_resolve_promise_str(
      exec_ctx->ctx,
      bc_data->accumulator,
      bc_data->accumulator_len,
      bc_data->promise_resolve,
      bc_data->promise_reject);
    assert(!JS_IsException(val));

    JS_FreeValue(exec_ctx->ctx, rv);

    str = JS_ToCStringLen(exec_ctx->ctx, &str_len, val);
    JS_FreeValue(exec_ctx->ctx, val);
    str_expected = "Hello";
    assert(strncmp(str, str_expected, str_len) == 0);
    JS_FreeCString(exec_ctx->ctx, str);

    aura_qjs_reset_test(exec_ctx);
    aura_qjs_exec_ctx_destroy_test(exec_ctx);
}

static void a_qjs_test_response() {
    struct aura_qjs_execution_ctx *exec_ctx;
    char *js_code;
    JSValue rv;
    uint64_t str_len;
    const char *str, *str_expect;

    /* response body.arrayBuffer() */
    js_code = A_JS_STR(
      export default async function handler(ctx) {
          const response = new Response("Vaulten");
          const res_buf = await response.arrayBuffer();
          const uint8Array = new Uint8Array(res_buf);
          return uint8Array.toString();
      });

    assert(aura_qjs_write_bytecode(bc_ctx, js_code, strlen(js_code), "test", (uint8_t **)&def_func.fn_code, &def_func.fn_code_len) == 0);
    assert(def_func.fn_code);
    assert(def_func.fn_code_len > 0);

    exec_ctx = aura_qjs_exec_ctx_create_test(&mc, &def_func);
    assert(exec_ctx);

    assert(aura_qjs_prepare(exec_ctx, &def_task, &req, &res) == 0);

    rv = aura_qjs_execute_test(exec_ctx);
    str = JS_ToCStringLen(exec_ctx->ctx, &str_len, rv);
    /* Vaulten => V,a,u,l,t,e,n */
    str_expect = "86,97,117,108,116,101,110";
    assert(strncmp(str, str_expect, str_len) == 0);
    JS_FreeCString(exec_ctx->ctx, str);
    JS_FreeValue(exec_ctx->ctx, rv);

    aura_qjs_exec_ctx_destroy_test(exec_ctx);

    /* response body.bytes() */
    js_code = A_JS_STR(
      export default async function handler(ctx) {
          const response = new Response("Vaulten");
          const uint8Array = await response.bytes();
          return uint8Array.toString();
      });

    assert(aura_qjs_write_bytecode(bc_ctx, js_code, strlen(js_code), "test", (uint8_t **)&def_func.fn_code, &def_func.fn_code_len) == 0);
    assert(def_func.fn_code);
    assert(def_func.fn_code_len > 0);

    exec_ctx = aura_qjs_exec_ctx_create_test(&mc, &def_func);
    assert(exec_ctx);

    assert(aura_qjs_prepare(exec_ctx, &def_task, &req, &res) == 0);

    rv = aura_qjs_execute_test(exec_ctx);
    str = JS_ToCStringLen(exec_ctx->ctx, &str_len, rv);
    /* Vaulten => V,a,u,l,t,e,n */
    str_expect = "86,97,117,108,116,101,110";
    assert(strncmp(str, str_expect, str_len) == 0);
    JS_FreeCString(exec_ctx->ctx, str);
    JS_FreeValue(exec_ctx->ctx, rv);

    aura_qjs_exec_ctx_destroy_test(exec_ctx);

    /* response body.json */
    js_code = A_JS_STR(
      export default async function handler(ctx) {
          const response = new Response('{"Vaulten": "Aura"}');
          return await response.json();
      });

    assert(aura_qjs_write_bytecode(bc_ctx, js_code, strlen(js_code), "test", (uint8_t **)&def_func.fn_code, &def_func.fn_code_len) == 0);
    assert(def_func.fn_code);
    assert(def_func.fn_code_len > 0);

    exec_ctx = aura_qjs_exec_ctx_create_test(&mc, &def_func);
    assert(exec_ctx);

    assert(aura_qjs_prepare(exec_ctx, &def_task, &req, &res) == 0);

    rv = aura_qjs_execute_test(exec_ctx);
    JSValue val = JS_JSONStringify(exec_ctx->ctx, rv, JS_UNDEFINED, JS_UNDEFINED);
    str = JS_ToCStringLen(exec_ctx->ctx, &str_len, val);
    /* NOTE: spaces are stripped */
    str_expect = "{\"Vaulten\":\"Aura\"}";
    assert(strncmp(str, str_expect, str_len) == 0);
    JS_FreeValue(exec_ctx->ctx, val);
    JS_FreeCString(exec_ctx->ctx, str);
    JS_FreeValue(exec_ctx->ctx, rv);

    aura_qjs_exec_ctx_destroy_test(exec_ctx);
}

/* Fetch */
static void a_qjs_test_fetch(void) {
    struct aura_qjs_execution_ctx *ex_ctx;
    struct aura_qjs_rt_data *rt_data;
    const char *js_code;
    JSValue rv;
    const char *str, *str_expected;
    uint64_t str_len;

    js_code = A_JS_STR(
      export default async function handler(ctx) {
          try {
              const res = await fetch("http://example.com/wizzy");
              const data = await res.json();
              return data;
}
catch(err) {
    throw new Error(err);
}
}
    );

    assert(aura_qjs_write_bytecode(
             bc_ctx,
             js_code,
             strlen(js_code),
             "test",
             (uint8_t **)&def_func.fn_code,
             &def_func.fn_code_len) == 0);
    assert(def_func.fn_code);
    assert(def_func.fn_code_len > 0);

    ex_ctx = aura_qjs_exec_ctx_create_test(&mc, &def_func);
    assert(ex_ctx);

    /* Prepare first part of request */
    req.body = body3_first;
    req.body_len = sizeof(body3_first);
    req.streaming = true;
    req.bc.state = A_BODY_NOT_CONSUMED;
    assert(aura_qjs_prepare(ex_ctx, &def_task, &req, &res) == 0);

    rv = aura_qjs_execute_test(ex_ctx);
    assert(!JS_IsException(rv));

    rt_data = JS_GetRuntimeOpaque(ex_ctx->rt);

    /* Fake data fetching */
    str_expected = "{\"Vaulten\":\"aura\"}";
    JSValue resp = a_qjs_create_str_response(ex_ctx->ctx, str_expected, strlen(str_expected));
    assert(!JS_IsException(resp));

    struct aura_qjs_fetch_ctx *fetch_ctx = rt_data->fetch_ctx;
    /* Resolve promise */
    JSValue val = JS_Call(fetch_ctx->ctx, fetch_ctx->resolve, JS_UNDEFINED, 1, &resp);
    JS_FreeValue(ex_ctx->ctx, resp);
    assert(!JS_IsException(val));

    while (JS_ExecutePendingJob(JS_GetRuntime(ex_ctx->ctx), NULL) > 0)
        ;

    int state = JS_PromiseState(ex_ctx->ctx, rv);
    assert(state == JS_PROMISE_FULFILLED);
    JSValue res_obj = JS_PromiseResult(ex_ctx->ctx, rv);
    JS_FreeValue(ex_ctx->ctx, val);
    JS_FreeValue(ex_ctx->ctx, rv);

    val = JS_JSONStringify(ex_ctx->ctx, res_obj, JS_UNDEFINED, JS_UNDEFINED);
    str = JS_ToCStringLen(ex_ctx->ctx, &str_len, val);
    JS_FreeValue(ex_ctx->ctx, val);
    assert(strncmp(str, str_expected, str_len) == 0);
    JS_FreeCString(ex_ctx->ctx, str);
    JS_FreeValue(ex_ctx->ctx, res_obj);

    aura_qjs_reset_test(ex_ctx);
    aura_qjs_exec_ctx_destroy_test(ex_ctx);
    }

    int main(int argc, char *argv[]) {
        a_test_resources_create();
        a_qjs_test_bytecode_generation();
        a_qjs_test_console_logging();
        a_qjs_test_ctx_evt_source();
        a_qjs_test_ctx_evt_request();
        a_qjs_test_request_text();
        a_qjs_test_response();
        a_qjs_test_fetch();
        a_test_resources_destroy();
        return 0;
    }
