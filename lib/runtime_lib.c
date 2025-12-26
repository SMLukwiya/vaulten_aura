#include "runtime_lib.h"

uint8_t *aura_qjs_create_bytecode(JSContext *ctx, const char *script, uint64_t in_len,
                                  const char *module_name, uint64_t *out_len) {
    JSValue val;
    uint8_t *bytecode;
    uint64_t size;

    *out_len = 0;
    val = JS_Eval(ctx, script, in_len, module_name, JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_COMPILE_ONLY | JS_WRITE_OBJ_BYTECODE);
    if (JS_IsException(val))
        return NULL;

    bytecode = JS_WriteObject(ctx, &size, val, JS_WRITE_OBJ_BYTECODE);
    JS_FreeValue(ctx, val);
    if (!bytecode)
        return NULL;

    *out_len = size;
    return bytecode;
}