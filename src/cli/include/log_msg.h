#ifndef AURA_FN_MESSAGES_H
#define AURA_FN_MESSAGES_H

#include "fn/lib.h"
#include "types_lib.h"

static char fn_op_success[] = "\x1B[1;32mSuccess\x1B[0m";
static char fn_op_failed[] = "\x1B[1;31mFailed\x1B[0m";
static char config[] = "\x1B[1;31mFailed. Config error.\x1B[0m";
static char duplicate[] = "\x1B[1;31mFailed. Duplicate function detected.\x1B[0m";
static char not_exist[] = "\x1B[1;31mFailed, Provided Function does not exist.\x1B[0m";

static struct aura_iovec cli_cmd_msg[] = {
  [A_FN_ERROR_NONE] = {.base = fn_op_success, .len = sizeof(fn_op_success) - 1},
  [A_FN_ERROR_GENERIC] = {.base = fn_op_failed, .len = sizeof(fn_op_failed) - 1},
  [A_FN_ERROR_CONFIG] = {.base = config, .len = sizeof(config) - 1},
  [A_FN_ERROR_DUPLICATE] = {.base = duplicate, .len = sizeof(duplicate) - 1},
  [A_FN_ERROR_NOT_EXIST] = {.base = not_exist, .len = sizeof(not_exist) - 1},
};

#endif