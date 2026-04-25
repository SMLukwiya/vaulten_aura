#include "file_lib.h"
#include "quickjs.h"

#include <assert.h>
#include <fcntl.h>
#include <stdint.h>

char *file_name = "/home/lukwiya/studies/C/vaulten_aura/examples/hello_fn/index.js";

static void a_test_bytecode_generation() {
    uint8_t *entry_script, *bytecode;
    JSRuntime *rt;
    JSContext *ctx;
    int entry_file_fd;
    size_t bytecode_len, entry_file_len;

    entry_file_fd = open(file_name, O_RDONLY);
    assert(entry_file_fd > 0);

    entry_script = aura_load_file(entry_file_fd, &entry_file_len);
    assert(entry_script != NULL);

    rt = JS_NewRuntime();
    assert(rt != NULL);

    ctx = JS_NewContext(rt);
    assert(ctx != NULL);
    // bytecode = aura_qjs_create_bytecode(ctx, entry_script, entry_file_len, "test.js", &bytecode_len);
    // assert(bytecode != NULL);

    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
    // free(bytecode);
}

int main(int argc, char *argv[]) {
    a_test_bytecode_generation();
    return 0;
}