#include "lib.h"

int aura_stream_provider_init(struct aura_stream_provider *p, void *ctx,
                              struct aura_stream_src_ops *ops, void *opaque,
                              opaque_destructor_fn fn) {
    memset(p, 0, sizeof(*p));
    p->opaque = opaque;
    p->opaque_destructor = fn;

    if (ops->init(p, ctx) < 0)
        return -1;

    p->src.ops = ops;
    return 0;
}

void aura_stream_provider_destroy(struct aura_stream_provider *sp) {
    /* */
    sp->src.ops->destroy(sp);
    aura_free(sp);
}

int aura_stream_provider_enqueue(struct aura_stream_provider *sp, void *data, uint32_t len) {
    struct aura_stream_chunk *slot;

    if (sp->tail - sp->head == A_STREAM_MAX_CHUNK_SZ) {
        sp->flags |= A_STREAM_INTERNAL_PAUSED;
        return 0;
    }

    slot = &sp->chunks[sp->tail++];
    slot->data = data;
    slot->len = len;
    slot->off = 0;

    return 0;
}

struct aura_stream_chunk *aura_stream_provider_dequeue(struct aura_stream_provider *sp) {
    if (sp->tail == sp->head)
        return NULL;

    return &sp->chunks[sp->head++];
}

int aura_stream_provider_pull(struct aura_stream_provider *sp) {
    if (!sp->src.ops)
        return -1;

    return sp->src.ops->read(sp);
}
