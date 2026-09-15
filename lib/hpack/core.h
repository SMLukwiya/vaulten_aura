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

uint64_t aura_hpack_encode_indexed_block(uint8_t *dest, uint64_t idx);

uint64_t aura_hpack_encode_indexed_name(uint8_t *dest, uint64_t dest_len, uint64_t idx,
                                        struct aura_iovec *value, uint8_t ind_mode);

uint64_t aura_hpack_encode_new_name(uint8_t *dest, uint64_t dest_len, struct aura_iovec *name,
                                    struct aura_iovec *value, uint8_t ind_mode);

#endif