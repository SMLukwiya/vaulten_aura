#include "sliding_buf.h"
#include "error_lib.h"
#include "slab_lib.h"
#include <unistd.h>

#define A_MIN_SLIDING_BUF_SIZE 1024
#define A_MAX_SLIDING_BUF_SIZE (1024 * 1024 * 16)
#define A_SLIDING_BUF_ALIGNMENT 64

int aura_sliding_buf_init(struct aura_sliding_buf *buf, struct aura_mem_ctx *mc,
                          uint32_t initial_cap, uint32_t flags) {
    buf->data = NULL;

    memset(buf, 0, sizeof(*buf));
    if (initial_cap > 0) {
        initial_cap = A_ALIGN(initial_cap, A_SLIDING_BUF_ALIGNMENT);
        if (initial_cap > A_MAX_SLIDING_BUF_SIZE) {
            return -1;
        }

        buf->data = aura_alloc(mc, initial_cap);
        if (!buf->data) {
            return -1;
        }
        memset(buf->data, 0, initial_cap);
    }

    buf->mc = mc;
    buf->cap = initial_cap;
    buf->start = buf->end = 0;
    buf->flags = A_SLIDING_BUF_FL_INLINED | flags;

    return 0;
}

struct aura_sliding_buf *aura_sliding_buf_create(struct aura_mem_ctx *mc, uint32_t init_cap, uint32_t flags) {
    struct aura_sliding_buf *buf;

    buf = aura_alloc(mc, sizeof(*buf));
    if (!buf)
        return NULL;

    memset(buf, 0, sizeof(*buf));
    buf->data = NULL;
    if (init_cap > 0) {
        init_cap = A_ALIGN(init_cap, A_SLIDING_BUF_ALIGNMENT);
        if (init_cap > A_MAX_SLIDING_BUF_SIZE) {
            aura_free(buf);
            return NULL;
        }

        buf->data = aura_alloc(mc, init_cap);
        if (!buf->data) {
            aura_free(buf);
            return NULL;
        }
        memset(buf->data, 0, init_cap);
    }

    buf->mc = mc;
    buf->cap = init_cap;
    buf->start = buf->end = 0;
    buf->flags = A_SLIDING_BUG_FL_SHARED | flags;
    buf->allocated.ref_cnt = 1;
    aura_list_head_init(&buf->allocated.link);

    return buf;
}

void aura_sliding_buf_destroy(struct aura_sliding_buf *buf) {
    if (!buf)
        return;

    if (buf->data) {
        if ((buf->flags & A_SLIDING_BUG_FL_SHARED) && --buf->allocated.ref_cnt == 0)
            aura_free(buf->data);
        else
            aura_free(buf->data);
    }

    if (!(buf->flags & A_SLIDING_BUF_FL_INLINED))
        aura_free(buf);
}

/**
 * Resize buf to accomodate new capacity(@new_cap).
 * Returns true if successful otherwise false.
 */
static inline bool a_sliding_buf_resize(struct aura_sliding_buf *buf, uint32_t new_cap) {
    uint8_t *data;

    if (new_cap > A_MAX_SLIDING_BUF_SIZE)
        return false;

    new_cap = A_ALIGN(new_cap > 0 ? new_cap : A_MIN_SLIDING_BUF_SIZE, A_SLIDING_BUF_ALIGNMENT);
    if (new_cap <= buf->cap)
        return true;

    data = aura_realloc(buf->mc, buf->data, new_cap);
    if (!data)
        return false;

    buf->data = data;
    buf->cap = new_cap;
    return true;
}

void aura_sliding_buf_compact(struct aura_sliding_buf *buf) {
    uint32_t data_len;

    data_len = aura_sliding_buf_read_len(buf);
    if (data_len == 0)
        return;

    memmove(buf->data, aura_sliding_buf_read_ptr(buf), data_len);
    buf->start = 0;
    buf->end = data_len;
}

bool aura_sliding_buf_ensure_cap(struct aura_sliding_buf *buf, uint32_t needed) {
    uint32_t write_len, avail_total;
    uint32_t required_cap;

    write_len = aura_sliding_buf_write_len(buf);
    if (write_len >= needed)
        return true;

    /* Compact if allowed */
    if (buf->flags & A_SLIDING_BUF_FL_COMPACTABLE) {
        aura_sliding_buf_compact(buf);
        write_len = aura_sliding_buf_write_len(buf);
        if (write_len >= needed)
            return true;
    }

    /* size can not be adjusted */
    if (buf->flags & A_SLIDING_BUF_FL_FIXED)
        return false;

    /* Resize */
    required_cap = aura_sliding_buf_cap(buf) + needed - write_len;
    return a_sliding_buf_resize(buf, required_cap);
}

int64_t aura_sliding_buf_append(struct aura_sliding_buf *buf, const uint8_t *data, uint32_t len) {
    if (len == 0)
        return 0;

    if (!aura_sliding_buf_ensure_cap(buf, len))
        return -1;

    memcpy(buf->data + buf->end, data, len);
    aura_sliding_buf_commit(buf, len);

    return len;
}

int64_t aura_sliding_buf_append_from_fd(struct aura_sliding_buf *buf, int fd, uint32_t max_len) {
    uint32_t avail_write, to_read;
    uint32_t bytes_read;
    uint8_t *write_ptr;

    avail_write = aura_sliding_buf_write_len(buf);
    write_ptr = aura_sliding_buf_write_ptr(buf);
    if (avail_write == 0) {
        if (!aura_sliding_buf_ensure_cap(buf, max_len))
            return -1;
        avail_write = aura_sliding_buf_write_len(buf);
    }

    to_read = a_min(avail_write, max_len);
    bytes_read = read(fd, write_ptr, to_read);

    if (bytes_read > 0) {
        buf->end += bytes_read;

        return bytes_read;
    }

    if (bytes_read <= 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        return 0;

    return -1;
}

int64_t aura_sliding_buf_move(struct aura_sliding_buf *dest, struct aura_sliding_buf *src, uint32_t len) {
    uint32_t read_len;
    uint8_t *read_ptr;

    read_len = a_min(len, aura_sliding_buf_read_len(src));
    read_ptr = aura_sliding_buf_read_ptr(src);

    if (aura_sliding_buf_append(dest, read_ptr, read_len) < 0)
        return -1;
    aura_sliding_buf_consume(src, read_len);

    return len;
}

int64_t aura_sliding_buf_copy(struct aura_sliding_buf *copy, struct aura_sliding_buf *orig) {
    if (aura_sliding_buf_init(copy, orig->mc, orig->cap, orig->flags) < 0)
        return -1;

    uint32_t len = aura_sliding_buf_read_len(orig);
    memcpy(copy->data, orig->data, len);
    return len;
}

void aura_sliding_buf_consume(struct aura_sliding_buf *buf, uint32_t len) {
    len = a_min(len, aura_sliding_buf_read_len(buf));
    buf->start += len;

    /* Compact if empty */
    if (aura_sliding_buf_is_empty(buf))
        aura_sliding_buf_reset(buf);
}

struct iovec aura_sliding_buf_get_read_iovec(struct aura_sliding_buf *buf, uint32_t len) {
    struct iovec iov = {0};

    len = a_min(len, aura_sliding_buf_read_len(buf));
    if (len > 0) {
        iov.iov_base = buf->data + buf->start;
        iov.iov_len = len;
    }

    return iov;
}

struct iovec aura_sliding_buf_get_write_iovec(struct aura_sliding_buf *buf, uint32_t len) {
    struct iovec iov = {0};

    len = a_min(len, aura_sliding_buf_read_len(buf));
    iov.iov_base = aura_sliding_buf_write_ptr(buf);
    iov.iov_len = len;
    return iov;
}

uint32_t aura_sliding_buf_commit(struct aura_sliding_buf *buf, uint32_t len) {
    len = a_min(len, aura_sliding_buf_write_len(buf));
    buf->end += len;
    return len;
}

uint32_t aura_sliding_buf_uncommit(struct aura_sliding_buf *buf, uint32_t len) {
    len = a_min(len, aura_sliding_buf_read_len(buf));
    buf->end -= len;
    return len;
}

void aura_sliding_buf_dump(struct aura_sliding_buf *buf) {
    app_debug(true, 0, "AURA SLIDING BUFFER");
    app_debug(true, 0, "    capacity: %zu", buf->cap);
    app_debug(true, 0, "    data: %p", buf->data);
    app_debug(true, 0, "    start: %zu", buf->start);
    app_debug(true, 0, "    end: %zu", buf->end);
    app_debug(true, 0, "    memory context: %p", buf->mc);
}