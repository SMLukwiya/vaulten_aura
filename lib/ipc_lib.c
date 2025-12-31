#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "ipc_lib.h"

#include "errno.h"
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#if defined(__x86_64) || defined(__i386__)
#define read_barrier() __asm__ __volatile__("" ::: "memory")
#define write_barrier() __asm__ __volatile__("" ::: "memory")
#else
#define read_barrier() __sync_synchronize()
#define write_barrier() __sync_synchronize()
#endif

/**
 * Resolve default app path given by 'env_name'
 */
static struct aura_iovec aura_resolve_default_path(const char *env_name, const char *suffix) {
    struct aura_iovec path;
    char *env_value;

    path.base = NULL;
    path.len = 0;

    env_value = getenv(env_name);
    if (env_value) {
        path.base = strdup(env_value);
        path.len = strlen(path.base);
    }

    return path;
}

/**
 * Resolve xdg app paths using for testing
 */
static struct aura_iovec aura_resolve_xdg_path(const char *suffix) {
    struct aura_iovec path;
    char *app_dir, *base;
    int len;

    path.base = NULL;
    path.len = 0;

    base = "/vaulten_aura";
    app_dir = getenv("XDG_DATA_HOME");
    if (!app_dir) {
        /* default */
        app_dir = getenv("HOME");
        if (!app_dir)
            return path;
        base = "/.local/share/vaulten_aura";
    }

    len = strlen(app_dir) + strlen(base) + 2;
    if (suffix) {
        len += strlen(suffix);
    }
    path.base = malloc(len);
    snprintf(path.base, len, "%s%s/%s", app_dir, base, suffix);
    path.len = len;
    return path;
}

struct aura_iovec aura_resolve_app_path(const char *env_name, const char *suffix) {
#ifdef NDEBUG
    return aura_resolve_default_path(env_name, suffix);
#else
    return aura_resolve_xdg_path(suffix);
#endif
}

static bool aura_ensure_app_path(struct aura_iovec *path, int32_t mode) {
    char temp[4096];
    char *p;

    snprintf(temp, sizeof(temp), "%s", path->base);
    if (temp[path->len - 1] == '/')
        temp[path->len - 1] = '\0';

    /* Traverse and create directory */
    for (p = temp + 1; *p; ++p) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(temp, mode) != 0 && errno != EEXIST)
                return false;
            *p = '/';
        }
    }

    if (mkdir(temp, mode) != 0 && errno != EEXIST)
        return -1;

    return true;
}

int aura_setup_app_paths(struct aura_iovec *path) {
    bool res;

    *path = aura_resolve_app_path(AURA_DATA_DIR, NULL);
    if (!path->base)
        return -1;

    res = aura_ensure_app_path(path, S_IRWXU | S_IRGRP | S_IROTH);
    if (res == false)
        return -1;
    return 0;
}

int aura_setup_database_file_path(struct aura_iovec *aura_db_path) {
    size_t len;

    len = aura_db_path->len + strlen(AURA_DB_FILE);
    aura_db_path->base = realloc(aura_db_path->base, len);
    if (!aura_db_path->base)
        return -1;

    aura_db_path->len = len;
    strcat(aura_db_path->base, AURA_DB_FILE);
    return 0;
}