#ifndef AURA_SERVER_HEADER
#define AURA_SERVER_HEADER

#include "memory_lib.h"
#include "slab_lib.h"
#include "token_srv.h"
#include "types_lib.h"
#include <stdbool.h>

/* Header key value pairs */
struct aura_http_hdr_set {
    struct aura_iovec *name;
    struct aura_iovec *value;
};

/* Headers vector */
struct aura_http_hdrs {
    struct aura_hdr_nv *entries; /* headers array, could be part of slab */
    size_t cnt;
    size_t cap;
};

bool aura_add_header(struct aura_memory_ctx *mc, struct aura_http_hdrs *hdrs, const struct aura_hdr_nv *nv);

#endif