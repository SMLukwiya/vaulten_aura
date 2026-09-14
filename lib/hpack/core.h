#ifndef AURA_HPACK_CORE_H
#define AURA_HPACK_CORE_H

#include <stdbool.h>
#include <stdint.h>

#include "types_lib.h"

typedef enum {
    A_HPACK_HDR_FIELD_WITH_INDEXING,
    A_HPACK_HDR_FIELD_WITHOUT_INDEXING,
    A_HPACK_HDR_FIELD_NEVER_INDEXED,
} a_hpack_indexing_mode;

/* Receiver buffer for name/value strings */
struct aura_hpack_recv_buf {
    uint8_t *base;
    uint64_t len;
    uint64_t reserved;
};

#endif