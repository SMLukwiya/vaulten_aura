#ifndef AURA_SLIDING_BUF_H
#define AURA_SLIDING_BUF_H

#include "list_lib.h"

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>

#ifndef a_min
#define a_min(x, y) ((x) < (y) ? (x) : (y))
#endif

#ifndef a_max
#define a_max(x, y) ((x) > (y) ? (x) : (y))
#endif

/* Sliding buffer structure */
struct aura_sliding_buf {
    struct aura_mem_ctx *mc;
    uint32_t cap;   /* capacity of buffer */
    uint32_t start; /* read offset */
    uint32_t end;   /* write offset */
    union {
        struct {
            struct aura_list_head link; /* Link to buffer list */
            _Atomic(uint8_t) ref_cnt;
        } allocated;
    };
    uint8_t *data; /* Base pointer for underlying data */
    uint8_t flags;
};

/* Sliding buf flags */
typedef enum {
    A_SLIDING_BUF_FL_NONE = 0,
    A_SLIDING_BUF_FL_INITIALIZED = 1,      /* Buffer initialized */
    A_SLIDING_BUF_FL_INLINED = 1 << 1,     /* Embedded as part of a parent structure */
    A_SLIDING_BUG_FL_SHARED = 1 << 2,      /* Shared via ref counting */
    A_SLIDING_BUF_FL_MOVABLE = 1 << 3,     /* can move across structures */
    A_SLIDING_BUF_FL_FIXED = 1 << 4,       /* Size is fixed */
    A_SLIDING_BUF_FL_COMPACTABLE = 1 << 5, /* Data can be compacted without losing meaning */
    A_SLIDING_BUF_FL_CHAINED = 1 << 6      /* Can be chained in a list */
} aura_sliding_buf_flag;

/* Get buffer actual capacity */
static inline uint32_t aura_sliding_buf_cap(struct aura_sliding_buf *buf) {
    return buf->cap;
}

/* Get available buffer space for read action */
static inline uint32_t aura_sliding_buf_read_len(const struct aura_sliding_buf *buf) {
    return buf->end - buf->start;
}

/* Get available buffer space for write function */
static inline uint32_t aura_sliding_buf_write_len(const struct aura_sliding_buf *buf) {
    return buf->cap - buf->end;
}

static inline bool aura_sliding_buf_is_empty(const struct aura_sliding_buf *buf) {
    return buf->start == buf->end;
}

static inline bool aura_sliding_buf_is_full(const struct aura_sliding_buf *buf) {
    return buf->end == buf->cap;
}

/* Get read location in buffer for the next read action */
static inline uint8_t *aura_sliding_buf_read_ptr(const struct aura_sliding_buf *buf) {
    return buf->data + buf->start;
}

/* Get write location in buffer for the next action */
static inline uint8_t *aura_sliding_buf_write_ptr(const struct aura_sliding_buf *buf) {
    return buf->data + buf->end;
}

/* Reset buffer to empty state */
static inline void aura_sliding_buf_reset(struct aura_sliding_buf *buf) {
    buf->start = buf->end = 0;
}

/* Is buffer initialized */
static inline bool aura_sliding_buf_is_initialized(struct aura_sliding_buf *buf) {
    return (buf->flags & A_SLIDING_BUF_FL_INITIALIZED);
}

/**
 * Initialize an embedded sliding buffer with initial capacity
 * The A_SLIDING_BUF_FL_INLINE is added on success
 */
int aura_sliding_buf_init(struct aura_sliding_buf *buf, struct aura_mem_ctx *mc,
                          uint32_t initial_cap, uint32_t flags);

/**
 * Create an allocated sliding buffer
 * The A_SLIDING_BUF_FL_SHARED is added on success
 */
struct aura_sliding_buf *aura_sliding_buf_create(struct aura_mem_ctx *mc, uint32_t init_cap, uint32_t flags);

/* Free sliding buffer and underlying resources */
void aura_sliding_buf_destroy(struct aura_sliding_buf *buf);

/**
 * Ensure buffer has the the required capacity to handle
 * data read of size '@needed'. Tries various ways to get
 * the needed space, returns true if successful, otherwise false
 */
bool aura_sliding_buf_ensure_cap(struct aura_sliding_buf *buf, uint32_t needed);

/**
 * Move everything to the start of buffer
 */
void aura_sliding_buf_compact(struct aura_sliding_buf *buf);

/**
 * Add data of size '@len' to the buffer
 * and adjust the buffer end for the next write action.
 * Returns len appended when successful otherwise
 * returns -1.
 */
int64_t aura_sliding_buf_append(struct aura_sliding_buf *buf, const uint8_t *data, uint32_t len);

/**
 * Add data to buffer from given file descriptor.
 * Returns the bytes read from '@fd', 0 if operation
 * would block and -1 incase of error.
 */
int64_t aura_sliding_buf_append_from_fd(struct aura_sliding_buf *buf, int fd, uint32_t max_len);

/**
 * Move '@len' data from src buf to dest buf.
 * Returns len moved if successful otherwise 0
 */
int64_t aura_sliding_buf_move(struct aura_sliding_buf *dest, struct aura_sliding_buf *src, uint32_t len);

/**
 * Make a copy of @orig into @copy
 * @copy must be a new instance of
 * sliding buf structure
 */
int64_t aura_sliding_buf_copy(struct aura_sliding_buf *copy, struct aura_sliding_buf *orig);

/**
 * Read '@len' data from the buf and adjust
 * the start counter for the next read action
 */
void aura_sliding_buf_consume(struct aura_sliding_buf *buf, uint32_t len);

/**
 * Convert the buf into a struct iovec for
 * read action. Returns iovec structure,
 * does not fail.
 */
struct iovec aura_sliding_buf_get_read_iovec(struct aura_sliding_buf *buf, uint32_t max_len);

/**
 * Convert the buf into a struct iovec for
 * write action. Returns iovec structure,
 * does not fail.
 */
struct iovec aura_sliding_buf_get_write_iovec(struct aura_sliding_buf *buf, uint32_t len);

/**
 * Update the buf end counter to reflect
 * current/correct size of data,
 * Returns actual len committed, this may be less
 * than len passed as parameter, if the available
 * write was less than the passed len
 */
uint32_t aura_sliding_buf_commit(struct aura_sliding_buf *buf, uint32_t len);

/**
 * Update the buf end counter to revert the
 * current size of data,
 * Returns actual len reverted, this may be less
 * than len passed as parameter, if the available
 * read was less than the passed len
 */
uint32_t aura_sliding_buf_uncommit(struct aura_sliding_buf *buf, uint32_t len);

/**
 * Dump buf structure
 */
void aura_sliding_buf_dump(struct aura_sliding_buf *buf);

#endif