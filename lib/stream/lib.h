#ifndef AURA_STREAM_H
#define AURA_STREAM_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "memory/slab.h"

#define A_STREAM_MAX_CHUNK_SZ 8

enum {
    A_STREAM_INTERNAL_PAUSED = 1,
    A_STREAM_USER_PAUSED = 1 << 1,
    A_STREAM_DONE = 1 << 2,
    A_STREAM_LOCKED = 1 << 3,
};

typedef void (*opaque_destructor_fn)(void *opaque);

/* Stream chunk structure */
struct aura_stream_chunk {
    const uint8_t *data; /* chunk data */
    uint32_t len;        /* Data len */
    uint32_t off;        /* Current consumed offset */
};

struct aura_stream_src_ops;
struct aura_stream_provider;

struct aura_stream_provider_src {
    struct aura_stream_src_ops *ops; /* provider source ops */
    const uint8_t *data;             /* Provider buffered source */
    uint32_t len;                    /* Buffered len */
    uint32_t off;                    /* Current buffered read offset */
    int fd;                          /* Source file descriptor */
    uint8_t type;                    /* Source kind */
};

struct aura_stream_src_ops {
    int (*init)(struct aura_stream_provider *p, void *ctx);
    int (*read)(struct aura_stream_provider *);
    int (*write)(struct aura_stream_provider *);
    void (*destroy)(struct aura_stream_provider *);
};

struct aura_stream_provider {
    struct aura_stream_provider_src src;                    /* provider source */
    struct aura_stream_chunk chunks[A_STREAM_MAX_CHUNK_SZ]; /* Provider chunk ring buffer */
    uint32_t head, tail;                                    /* Ring buffer mgt */
    void *opaque;                                           /* Opaque data attached to stream provider */
    opaque_destructor_fn opaque_destructor;                 /* Destructor function for opaque data */
    uint8_t flags;                                          /* Flags */
};

static inline bool aura_stream_is_done(struct aura_stream_provider *p) {
    return p->flags & A_STREAM_DONE;
}

/**
 *
 */
int aura_stream_provider_init(struct aura_stream_provider *p, void *ctx,
                              struct aura_stream_src_ops *ops, void *opaque,
                              opaque_destructor_fn fn);

/** */
void aura_stream_provider_destroy(struct aura_stream_provider *sp);

/**/
int aura_stream_provider_enqueue(struct aura_stream_provider *sp, void *data, uint32_t len);

/**/
struct aura_stream_chunk *aura_stream_provider_dequeue(struct aura_stream_provider *sp);

/**/
int aura_stream_provider_pull(struct aura_stream_provider *sp);

#endif