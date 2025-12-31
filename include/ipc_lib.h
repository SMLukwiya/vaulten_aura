#ifndef AURA_IPC_H
#define AURA_IPC_H

#include "types_lib.h"
#include <stdbool.h>
#include <stdint.h>
#include <unistd.h>

typedef enum {
    AURA_DATA_DIR_PATH,
    AURA_CONFIG_DIR_PATH
} aura_app_paths;

/**
 * Ensure provided app path exists, creating it
 * if it does not exist
 */
int aura_setup_app_paths(struct aura_iovec *path);

/**
 * Construct the database file path
 */
int aura_setup_database_file_path(struct aura_iovec *aura_db_path);

/**
 * Construct given app path
 */
struct aura_iovec aura_resolve_app_path(const char *env_name, const char *suffix);

#endif