#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "align_lib.h"
#include "error_lib.h"
#include "memory_lib.h"
#include "slab_lib.h"
#include "sliding_buf.h"
#include "utils_lib.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>

void aura_mem_ctx_init(struct aura_mem_ctx *mem_ctx) {
    memset(mem_ctx, 0, sizeof(*mem_ctx));
    aura_list_head_init(&mem_ctx->slab_cache_list);
}

void aura_mem_ctx_destroy(struct aura_mem_ctx *mem_ctx) {
    struct aura_slab_cache *sc, *_sc;

    for (int i = 0; i < 16; ++i) {
        aura_slab_cache_destroy(mem_ctx->dynamic_slab_caches[i]);
    }

    while (!aura_list_is_empty(&mem_ctx->slab_cache_list)) {
        a_list_dequeue(sc, &mem_ctx->slab_cache_list, cache_list);
        aura_slab_cache_destroy(sc);
    }
}

void aura_mem_ctx_dump(struct aura_mem_ctx *mc) {
    struct aura_slab_cache *sc;

    app_debug(true, 0, "AURA MEMORY CONTEXT");
    app_debug(true, 0, "    All Caches");

    a_list_for_each(sc, &mc->slab_cache_list, cache_list) {
        aura_slab_cache_dump(sc);
    }
}

#ifdef __linux
/**
 *
 */
int aura_create_anon_file(const char *name, size_t size) {
    int fd, res;
    uint32_t seal;

    seal = MFD_ALLOW_SEALING;
    fd = memfd_create(name, seal);
    if (fd < 0) {
        sys_alert(true, errno, "Failed to create share memory file memfd_create");
        return -1;
    }

    res = ftruncate(fd, size);
    if (res < 0) {
        close(fd);
        sys_alert(true, errno, "Failed to set size of shared memory area");
        return -1;
    }

    return fd;
}

/**
 *
 */
inline int aura_anon_get_seals(int fd) {
    uint32_t seals;

    seals = fcntl(fd, F_GET_SEALS);
    if (seals < 0) {
        sys_alert(true, errno, "Failed to get seals fd: %d", fd);
        return -1;
    }

    return seals;
}

inline int aura_anon_set_seals(int fd, uint32_t flags) {
    uint32_t seals;
    int res;

    seals = aura_anon_get_seals(fd);
    if (seals < 0)
        goto err_out;

    seals |= flags;
    res = fcntl(fd, F_ADD_SEALS, seals);
    if (res < 0)
        goto err_out;

    return 0;
err_out:
    sys_alert(true, errno, "Failed to set seals for fd: %d", fd);
    return -1;
}

/**
 *
 */

#else
int aura_create_anon_file() {}
inline int aura_anon_set_seals(int fd, uint32_t flags) {}
#endif
