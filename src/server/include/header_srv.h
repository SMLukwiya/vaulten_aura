#ifndef AURA_SERVER_HEADER_H
#define AURA_SERVER_HEADER_H

#include "interned.h"
#include "memory_lib.h"
#include "slab_lib.h"
#include "types_lib.h"
#include <stdbool.h>

#define A_HDR_FIELD_FLAG_NAME_INTERNED 1 << 0
#define A_HDR_FIELD_FLAG_VALUE_INTERNED 1 << 1
#define A_HDR_FIELD_FLAG_NO_COMPRESS 1 << 2
#define A_HDR_FIELD_FLAG_NO_INDEX 1 << 3
#define A_HDR_FIELD_FLAG_NO_INTERN 1 << 4
#define A_HDR_FIELD_FLAG_CAN_HUFFMAN 1 << 5
#define A_HDR_FIELD_FLAG_EMIT 1 << 6
#define A_HDR_FIELD_FLAG_FINAL 1 << 7

/* Key value header field structure */
struct aura_basic_header {
    struct aura_iovec name;
    struct aura_iovec value;
};

/* header field structure */
struct aura_header_field {
    struct aura_interned_str *name;
    union {
        struct aura_interned_str *interned;
        struct {
            struct aura_iovec str;
            _Atomic uint32_t ref_cnt;
        } raw;
    } value;
    uint16_t token;
    uint8_t flags;
};

struct aura_header_vector2 {
    struct aura_basic_header *entries;
    size_t cnt;
    size_t cap;
};

int aura_add_header(struct aura_mem_ctx *mc, struct aura_header_vector2 *hdrs, struct aura_header_field *nv);

bool aura_header_name_valid(const char *s);

bool aura_header_value_forbidden(const char *name);

bool aura_header_value_valid(const char *v);

/* Create header field with provided name and value */
struct aura_header_field *aura_header_field_create(struct aura_intern_tab *tab, char *name, size_t name_len, char *value, size_t value_len);
int aura_header_field_create2(struct aura_intern_tab *tab, struct aura_header_field *hdr,
                              char *name, size_t name_len, char *value, size_t value_len);

/* Destroy header field */
void aura_header_field_destroy(struct aura_header_field *header);
void aura_header_field_destroy2(struct aura_header_field *header);

#endif