#include "sliding_buf.h"
#include "error_lib.h"
#include "slab.h"
#include <sys/socket.h>
#include <unistd.h>

#define A_MIN_SLIDING_BUF_SIZE 4096
#define A_MAX_SLIDING_BUF_SIZE (1024 * 1024 * 16)
#define A_SLIDING_BUF_ALIGNMENT 64

static inline int a_sliding_buf_init(struct aura_sliding_buf *buf, struct aura_mem_ctx *mc,
                                     uint32_t initial_cap, uint32_t flags) {
    buf->data = NULL;

    memset(buf, 0, sizeof(*buf));
    buf->usable = initial_cap;
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
    buf->flags = flags;
    buf->allocated.ref_cnt = 1;
    aura_list_head_init(&buf->allocated.link);

    return 0;
}

int aura_sliding_buf_init(struct aura_sliding_buf *buf, struct aura_mem_ctx *mc,
                          uint32_t initial_cap, uint32_t flags) {
    flags |= A_SLIDING_BUF_FL_INITIALIZED | A_SLIDING_BUF_FL_INLINED;
    return a_sliding_buf_init(buf, mc, initial_cap, flags);
}

struct aura_sliding_buf *aura_sliding_buf_create(struct aura_mem_ctx *mc, uint32_t init_cap, uint32_t flags) {
    struct aura_sliding_buf *buf;
    int rv;

    buf = aura_alloc(mc, sizeof(*buf));
    if (!buf)
        return NULL;

    memset(buf, 0, sizeof(*buf));
    flags |= A_SLIDING_BUF_FL_INITIALIZED;
    rv = a_sliding_buf_init(buf, mc, init_cap, flags);
    if (rv < 0) {
        aura_free(buf);
        return NULL;
    }

    return buf;
}

void aura_sliding_buf_destroy(struct aura_sliding_buf *buf) {
    if (!buf)
        return;

    if ((buf->flags & A_SLIDING_BUF_FL_SHARED) && --buf->allocated.ref_cnt > 0)
        return;

    if (buf->data) {
        aura_free(buf->data);
    }

    if (!(buf->flags & A_SLIDING_BUF_FL_INLINED)) {
        aura_free(buf);
        return;
    }

    buf->flags = A_SLIDING_BUF_FL_NONE;
    buf->start = buf->end = 0;
    buf->data = NULL;
}

/**
 * Resize buf to accomodate new capacity(@new_cap).
 * Returns true if successful otherwise false.
 */
static inline bool a_sliding_buf_resize(struct aura_sliding_buf *buf, uint32_t new_cap) {
    uint8_t *data;

    if (new_cap > A_MAX_SLIDING_BUF_SIZE)
        return false;

    buf->usable = new_cap;
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
    if (data_len == 0 || !(buf->flags & A_SLIDING_BUF_FL_COMPACTABLE))
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

    /* Resize, make minimum increment 4KB  */
    needed = a_max(needed, A_MIN_SLIDING_BUF_SIZE);
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
    int64_t avail_write, to_read;
    int64_t bytes_read;
    uint8_t *write_ptr;

    avail_write = aura_sliding_buf_write_len(buf);
    write_ptr = aura_sliding_buf_write_ptr(buf);
    if (avail_write == 0) {
        if (!aura_sliding_buf_ensure_cap(buf, max_len))
            return -1;
        avail_write = aura_sliding_buf_write_len(buf);
    }

    to_read = a_min(avail_write, max_len);
    errno = 0;
    do {
        bytes_read = recv(fd, aura_sliding_buf_write_ptr(buf), to_read, 0);
    } while (bytes_read == -1 && errno == EINTR);

    if (bytes_read == -1) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            return 0;
        } else {
            return -1;
        }
    }
    app_debug(true, 0, "aura_sliding_buf_append_from_fd read=%ld, errno=%d", bytes_read, errno);

    if (bytes_read == 0) {
        return -1;
    }
    buf->end += bytes_read;
    return bytes_read;
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

int64_t aura_sliding_buf_copy(struct aura_sliding_buf *dest, struct aura_sliding_buf *src) {
    uint8_t *src_ptr;
    uint32_t len;

    len = aura_sliding_buf_read_len(src);
    src_ptr = aura_sliding_buf_read_ptr(src);

    if (aura_sliding_buf_append(dest, src_ptr, len) != len)
        return -1;

    return 0;
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