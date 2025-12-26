#ifndef AURA_IPC_H
#define AURA_IPC_H

#include "types_lib.h"
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

#define AURA_DEV_DATA_DIR "AURA_DEV_DATA_DIR"

typedef enum {
    AURA_DATA_DIR_PATH,
    AURA_CONFIG_DIR_PATH
} aura_app_paths;

/**
 * Ensure provided app path exists, creating it
 * if it does not exist
 */
bool aura_ensure_app_path(struct aura_iovec *path, int32_t mode);

/**
 * Construct given app path
 */
struct aura_iovec aura_resolve_app_path(const char *env_name, const char *suffix);

#endif