#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "align_lib.h"
#include "error_lib.h"
#include "list_lib.h"
#include "memory_lib.h"
#include "slab_lib.h"
#include "utils_lib.h"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

void aura_memory_ctx_dump(struct aura_memory_ctx *mc) {
    struct aura_slab_cache *sc;

    app_debug(true, 0, "AURA MEMORY CONTEXT");
    app_debug(true, 0, "    spanned pages: %d", mc->spanned_pages);
    app_debug(true, 0, "    valid pages: %d", mc->valid_pages);
    app_debug(true, 0, "    All Caches");

    a_list_for_each(sc, &mc->slab_cache_list, cache_list) {
        aura_slab_cache_dump(sc);
    }
}

void aura_memory_ctx_init(struct aura_memory_ctx *mem_ctx) {
    memset(mem_ctx, 0, sizeof(*mem_ctx));
    mem_ctx->base = NULL;
    a_list_head_init(&mem_ctx->slab_cache_list);
}

void aura_memory_ctx_destroy(struct aura_memory_ctx *mem_ctx) {
    struct aura_slab_cache *sc, *_sc;

    for (int i = 0; i < 16; ++i) {
        aura_slab_cache_destroy(mem_ctx->dynamic_slab_caches[i]);
    }

    a_list_for_each_safe_to_delete(sc, _sc, &mem_ctx->slab_cache_list, cache_list) {
        aura_slab_cache_destroy(sc);
    }
    mem_ctx->base = NULL;
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

/* ---------- SLIDING BUFFER ---------- */
#define A_MIN_SLIDING_BUF_SIZE 1024
#define A_MAX_SLIDING_BUF_SIZE (1024 * 1024 * 16)
#define A_SLIDING_BUF_ALIGNMENT 64

bool aura_sliding_buffer_create(struct aura_memory_ctx *mc, struct aura_sliding_buf *buf, size_t initial_cap) {

    buf->data = NULL;
    if (initial_cap > 0) {
        initial_cap = A_ALIGN(initial_cap, A_SLIDING_BUF_ALIGNMENT);
        if (initial_cap > A_MAX_SLIDING_BUF_SIZE)
            return false;

        buf->data = aura_alloc(mc, initial_cap);
        if (!buf->data)
            return false;
    }

    buf->mem_ctx = mc;
    buf->cap = initial_cap;
    buf->start = buf->end = 0;
    buf->watermark = 0;
    buf->valid = true;

    return true;
}

void aura_sliding_buffer_destroy(struct aura_sliding_buf *buf) {
    if (!buf)
        return;

    if (buf->data)
        aura_free(buf->data);

    memset(buf, 0, sizeof(*buf));
    buf->valid = false;
}

void aura_sliding_buffer_reset(struct aura_sliding_buf *buf) {
    buf->start = buf->end = 0;
    if (buf->watermark > buf->cap / 2)
        buf->watermark = 0;
}

bool aura_sliding_buffer_ensure_capacity(struct aura_sliding_buf *buf, size_t needed) {
    size_t avail_write, avail_total;
    size_t required_cap;

    avail_write = aura_sliding_buffer_available_write(buf);
    if (avail_write >= needed)
        return true;

    /* Try compaction first */
    avail_total = buf->cap - (buf->end - buf->start);
    if (avail_total >= needed) {
        aura_sliding_buffer_compact(buf);
        return true;
    }

    /* Resize otherwise */
    required_cap = buf->end - buf->start + needed;
    return aura_sliding_buffer_resize(buf, required_cap);
}

bool aura_sliding_buffer_resize(struct aura_sliding_buf *buf, size_t new_cap) {
    uint8_t *data;

    if (new_cap > A_MAX_SLIDING_BUF_SIZE)
        return false;

    new_cap = A_ALIGN(new_cap > 0 ? new_cap : A_MIN_SLIDING_BUF_SIZE, A_SLIDING_BUF_ALIGNMENT);
    if (new_cap <= buf->cap)
        return true;

    data = aura_realloc(buf->mem_ctx, buf->data, new_cap);
    if (!data)
        return false;

    buf->data = data;
    buf->cap = new_cap;
    return true;
}

void aura_sliding_buffer_compact(struct aura_sliding_buf *buf) {
    size_t data_len;

    if (buf->start == 0)
        return;

    data_len = buf->end - buf->start;
    if (data_len > 0)
        memmove(buf->data, buf->data + buf->start, data_len);

    buf->start = 0;
    buf->end = data_len;
}

size_t aura_sliding_buffer_append(struct aura_sliding_buf *buf, const uint8_t *data, size_t len) {
    if (!aura_sliding_buffer_ensure_capacity(buf, len))
        return 0;

    memcpy(buf->data + buf->end, data, len);
    buf->end += len;

    if (buf->end > buf->watermark)
        buf->watermark = buf->end;

    return len;
}

size_t aura_sliding_buffer_append_from_fd(struct aura_sliding_buf *buf, int fd, size_t max_len) {
    size_t avail_write, to_read;
    ssize_t bytes_read;

    avail_write = aura_sliding_buffer_available_write(buf);
    if (avail_write == 0) {
        if (!aura_sliding_buffer_ensure_capacity(buf, max_len))
            return 0;
        avail_write = aura_sliding_buffer_available_write(buf);
    }

    to_read = a_min(avail_write, max_len);
    bytes_read = read(fd, buf->data + buf->end, to_read);

    if (bytes_read > 0) {
        buf->end += bytes_read;
        if (buf->end > buf->watermark)
            buf->watermark = buf->end;

        return bytes_read;
    }

    if (bytes_read < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        return 0;

    return -1;
}

size_t aura_sliding_buffer_move_to(struct aura_sliding_buf *dest, struct aura_sliding_buf *src, size_t len) {
    size_t src_avail;

    src_avail = aura_sliding_buffer_available_read(src);
    if (len > src_avail)
        len = src_avail;

    if (!aura_sliding_buffer_ensure_capacity(dest, len))
        return 0;

    memcpy(dest->data + dest->end, src->data + src->start, len);
    dest->end += len;
    src->start += len;

    /* grounds for compaction */
    if (src->start > src->cap / 2)
        aura_sliding_buffer_compact(src);

    return len;
}

void aura_sliding_buffer_consume(struct aura_sliding_buf *buf, size_t len) {
    size_t avail;

    avail = aura_sliding_buffer_available_read(buf);
    if (len > avail)
        len = avail;

    buf->start += len;

    /* Auto compact if buffer is kinda empty */
    if ((buf->start > buf->cap / 4) && buf->start > 4096)
        aura_sliding_buffer_compact(buf);
}

struct iovec aura_sliding_buffer_get_read_iovec(struct aura_sliding_buf *buf, size_t max_len) {
    struct iovec iov = {0};
    size_t avail;

    avail = aura_sliding_buffer_available_read(buf);
    if (avail > 0) {
        iov.iov_base = buf->data + buf->start;
        iov.iov_len = a_min(avail, max_len);
    }

    return iov;
}

struct iovec aura_sliding_buffer_get_write_iovec(struct aura_sliding_buf *buf) {
    struct iovec iov = {0};

    iov.iov_base = buf->data + buf->end;
    iov.iov_len = aura_sliding_buffer_available_write(buf);
    return iov;
}

size_t aura_sliding_buffer_commit_write(struct aura_sliding_buf *buf, size_t len) {
    size_t avail;

    avail = aura_sliding_buffer_available_write(buf);
    if (len > avail)
        len = avail;

    buf->end += len;
    if (buf->end > buf->watermark)
        buf->watermark = buf->end;

    return len;
}

void aura_sliding_buffer_dump(struct aura_sliding_buf *buf) {
    app_debug(true, 0, "AURA SLIDING BUFFER");
    app_debug(true, 0, "    capacity: %zu", buf->cap);
    app_debug(true, 0, "    data: %p", buf->data);
    app_debug(true, 0, "    start: %zu", buf->start);
    app_debug(true, 0, "    end: %zu", buf->end);
    app_debug(true, 0, "    memory context: %p", buf->mem_ctx);
}