#ifndef AURA_RUNTIME_LIB_H
#define AURA_RUNTIME_LIB_H

#include "quickjs/quickjs.h"
#include "types_lib.h"

#include <stdlib.h>

/**
 * Generate bytecode represention of js file contents
 */
uint8_t *aura_qjs_create_bytecode(JSContext *ctx, const char *script, uint64_t in_len,
                                  const char *module_name, uint64_t *out_len);

#endif