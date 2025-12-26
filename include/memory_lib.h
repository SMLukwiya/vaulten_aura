#ifndef AURA_MEMORY_H
#define AURA_MEMORY_H

#include "list_lib.h"
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* Sliding buffer structure */
struct aura_sliding_buf {
    struct aura_memory_ctx *mem_ctx;
    uint8_t *data; /* Base pointer for underlying data */
    size_t cap;    /* capacity of buffer */
    size_t start;  /* read offset */
    size_t end;    /* write offset */
    size_t watermark;
    bool valid; /* if stream is reset while things are still pending inside buffer */
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
bool aura_sliding_buffer_create(struct aura_memory_ctx *mc, struct aura_sliding_buf *buf, size_t initial_cap);
struct aura_sliding_buf aura_sliding_buffer_wrap(uint8_t *data, size_t cap);
void aura_sliding_buffer_destroy(struct aura_sliding_buf *buf);
void aura_sliding_buffer_reset(struct aura_sliding_buf *buf);

bool aura_sliding_buffer_ensure_capacity(struct aura_sliding_buf *buf, size_t needed);
bool aura_sliding_buffer_resize(struct aura_sliding_buf *buf, size_t new_cap);
void aura_sliding_buffer_compact(struct aura_sliding_buf *buf);

size_t aura_sliding_buffer_append(struct aura_sliding_buf *buf, const uint8_t *data, size_t len);
size_t aura_sliding_buffer_append_from_fd(struct aura_sliding_buf *buf, int fd, size_t max_len);
size_t aura_sliding_buffer_move_to(struct aura_sliding_buf *dest, struct aura_sliding_buf *src, size_t len);
void aura_sliding_buffer_consume(struct aura_sliding_buf *buf, size_t len);

struct iovec aura_sliding_buffer_get_read_iovec(struct aura_sliding_buf *buf, size_t max_len);
struct iovec aura_sliding_buffer_get_write_iovec(struct aura_sliding_buf *buf);
size_t aura_sliding_buffer_commit_write(struct aura_sliding_buf *buf, size_t len);
void aura_sliding_buffer_dump(struct aura_sliding_buf *buf);

static inline size_t aura_sliding_buffer_available_read(const struct aura_sliding_buf *buf) {
    return buf->end - buf->start;
}

static inline size_t aura_sliding_buffer_available_write(const struct aura_sliding_buf *buf) {
    return buf->cap - buf->end;
}

static inline bool aura_sliding_buffer_is_empty(const struct aura_sliding_buf *buf) {
    return buf->start == buf->end;
}

static inline bool aura_sliding_buffer_is_full(const struct aura_sliding_buf *buf) {
    return buf->end == buf->cap;
}

static inline uint8_t *aura_sliding_buffer_read_pointer(const struct aura_sliding_buf *buf) {
    return buf->data + buf->start;
}

static inline uint8_t *aura_sliding_buffer_write_pointer(const struct aura_sliding_buf *buf) {
    return buf->data + buf->end;
}

#endif