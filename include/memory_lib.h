#ifndef AURA_MEMORY_H
#define AURA_MEMORY_H

#include "list_lib.h"
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Sliding buffer structure */
struct aura_sliding_buf {
    struct aura_memory_ctx *mem_ctx;
    uint8_t *data; /* Base pointer for underlying data */
    size_t cap;    /* capacity of buffer */
    size_t start;  /* read offset */
    size_t end;    /* write offset */
    size_t watermark;
    bool valid;    /* if stream is reset while things are still pending inside buffer */
    bool is_fixed; /* size is fixed and can not be changed once created */
};

/* Memory context */
struct aura_memory_ctx {
    uint32_t mem_limit;                              /* memory cap */
    uint32_t spanned_pages;                          /* total pages covered by the context, including holes */
    uint32_t valid_pages;                            /* total pages available for use within the zone */
    uint32_t high_watermark;                         /* point at which to get more memory or try some kind of compaction */
    void *base;                                      /* memory base */
    struct aura_slab_cache *dynamic_slab_caches[16]; /* table for dynamic slab cache (16 in total) */
    struct aura_list_head slab_cache_list;
};

/* Memory ctx APIs */
void aura_memory_ctx_init(struct aura_memory_ctx *mc);
void aura_memory_ctx_destroy(struct aura_memory_ctx *mc);
void aura_memory_ctx_dump(struct aura_memory_ctx *mc);

/* ---------- Sliding Buffer API ---------- */
/**
 * Create sliding buffer with initial capacity
 * Buffers created with is_fixed=true must be created
 * with the final size as the size can not be readjusted
 * later.
 */
struct aura_sliding_buf *aura_sliding_buffer_create(struct aura_memory_ctx *mc, size_t initial_cap, bool is_fixed);
struct aura_sliding_buf aura_sliding_buffer_wrap(uint8_t *data, size_t cap);

/* Free sliding buffer and underlying resources */
void aura_sliding_buffer_destroy(struct aura_sliding_buf *buf);
void aura_sliding_buffer_reset(struct aura_sliding_buf *buf);

/**
 * Ensure buffer has the the required capacity to handle
 * data read of size '@needed'. Tries various ways to get
 * the needed space, returns true if successful, otherwise false
 */
bool aura_sliding_buffer_ensure_capacity(struct aura_sliding_buf *buf, size_t needed);

// bool aura_sliding_buffer_resize(struct aura_sliding_buf *buf, size_t new_cap);

/**
 * Move everything to the start of buffer
 */
void aura_sliding_buffer_compact(struct aura_sliding_buf *buf);

/**
 * Add data of size '@len' to the buffer
 * and adjust the buffer end for the next write action.
 * Returns len appended when successful otherwise
 * returns -1.
 */
ssize_t aura_sliding_buffer_append(struct aura_sliding_buf *buf, const uint8_t *data, size_t len);

/**
 * Add data to buffer from given file descriptor.
 * Returns the bytes read from '@fd', 0 if operation
 * would block and -1 incase of error.
 */
ssize_t aura_sliding_buffer_append_from_fd(struct aura_sliding_buf *buf, int fd, size_t max_len);

/**
 * Move '@len' data from src buf to dest buf.
 * Returns len moved if successful otherwise 0
 */
size_t aura_sliding_buffer_move_to(struct aura_sliding_buf *dest, struct aura_sliding_buf *src, size_t len);

/**
 * Read '@len' data from the buf and adjust
 * the start counter for the next read action
 */
void aura_sliding_buffer_consume(struct aura_sliding_buf *buf, size_t len);

/**
 * Convert the buf into a struct iovec for
 * read action. Returns iovec structure,
 * does not fail.
 */
struct iovec aura_sliding_buffer_get_read_iovec(struct aura_sliding_buf *buf, size_t max_len);

/**
 * Convert the buf into a struct iovec for
 * write action. Returns iovec structure,
 * does not fail.
 */
struct iovec aura_sliding_buffer_get_write_iovec(struct aura_sliding_buf *buf);

/**
 * Update the buf end counter to reflect
 * current/correct size of data,
 * Returns actual len committed, this may be less
 * than len passed as parameter, if the available
 * write was less than the passed len
 */
size_t aura_sliding_buffer_commit_write(struct aura_sliding_buf *buf, size_t len);

/**
 * Dump buf structure
 */
void aura_sliding_buffer_dump(struct aura_sliding_buf *buf);

/* Get available buffer space for read action */
static inline size_t aura_sliding_buffer_available_read(const struct aura_sliding_buf *buf) {
    return buf->end - buf->start;
}

/* Get available buffer space for write function */
static inline size_t aura_sliding_buffer_available_write(const struct aura_sliding_buf *buf) {
    return buf->cap - buf->end;
}

static inline bool aura_sliding_buffer_is_empty(const struct aura_sliding_buf *buf) {
    return buf->start == buf->end;
}

static inline bool aura_sliding_buffer_is_full(const struct aura_sliding_buf *buf) {
    return buf->end == buf->cap;
}

/* Get read location in buffer for the next read action */
static inline uint8_t *aura_sliding_buffer_read_pointer(const struct aura_sliding_buf *buf) {
    return buf->data + buf->start;
}

/* Get write location in buffer for the next action */
static inline uint8_t *aura_sliding_buffer_write_pointer(const struct aura_sliding_buf *buf) {
    return buf->data + buf->end;
}

#endif