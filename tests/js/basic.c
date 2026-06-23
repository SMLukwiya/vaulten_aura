#include "file/lib.h"
#include "runtime/js.h"
#include <assert.h>
#include <fcntl.h>

static void a_qjs_test_fn_bytecode(void) {
    JSRuntime *rt;
    JSContext *ctx;
    const uint8_t *script, *bytecode;
    size_t script_len, bytecode_len;
    int script_fd;

    rt = JS_NewRuntime();
    assert(rt != NULL);

    ctx = JS_NewContext(rt);
    assert(ctx != NULL);

    script_fd = open("/home/lukwiya/studies/C/vaulten_aura/tests/js/script.js", O_RDONLY);
    assert(script_fd != -1);

    script = aura_load_file(script_fd, &script_len);
    assert(script != NULL);

    /* Create bytecode */
    JSValue obj = JS_Eval(ctx, script, script_len, "test_script", JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY);
    assert(JS_IsException(obj) == 0);
    assert(script_len > 0);

    bytecode = JS_WriteObject(ctx, &bytecode_len, obj, JS_WRITE_OBJ_BYTECODE);
    JS_FreeValue(ctx, obj);
    assert(bytecode != NULL);
    assert(bytecode_len > 0);

    /* Read bytecode */
    obj = JS_ReadObject(ctx, bytecode, bytecode_len, JS_READ_OBJ_BYTECODE);
    assert(JS_IsException(obj) == 0);

    /* Verify bytecode is a function */
    JSValue module = JS_EvalFunction(ctx, obj);
    assert(JS_IsException(module) == 0);
    JS_FreeValue(ctx, module);

    JSModuleDef *m = JS_VALUE_GET_PTR(obj);
    JSValue val = JS_GetModuleNamespace(ctx, m);
    JSValue handler = JS_GetPropertyStr(ctx, val, "default");
    JS_FreeValue(ctx, obj);
    JS_FreeValue(ctx, val);

    assert(JS_IsFunction(ctx, handler) == 1);

    JS_FreeValue(ctx, handler);
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
}

int main(int argc, char *argv[]) {
    a_qjs_test_fn_bytecode();
    return 0;
}