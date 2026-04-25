#ifndef AURA_SERVER_HEADER
#define AURA_SERVER_HEADER

#include "interned.h"
#include "memory_lib.h"
#include "slab_lib.h"
#include "token_srv.h"
#include "types_lib.h"
#include <stdbool.h>

/* header field structure */
struct aura_header_field {
    union {
        struct aura_interned_str *interned;
    } name;
    union {
        struct aura_interned_str *interned;
        struct {
            struct aura_iovec *str;
            _Atomic uint32_t ref_cnt;
        } raw;
    } value;
    bool name_interned;
    bool value_interned;
    u_int16_t token;
    uint8_t flags;
};

/* Header key value pairs */
struct aura_http_hdr_set {
    struct aura_iovec *name;
    struct aura_iovec *value;
};

/* header vector */
struct aura_header_vector {
    struct aura_header_field *entries;
    size_t cnt;
    size_t cap;
};

int aura_add_header(struct aura_memory_ctx *mc, struct aura_header_vector *hdrs, struct aura_header_field *nv);

bool aura_header_name_valid(const char *s);

bool aura_header_value_forbidden(const char *name);

bool aura_header_value_valid(const char *v);

/* Create header field with provided name and value */
struct aura_header_field *aura_header_field_create(struct aura_intern_tab *tab, char *name, size_t name_len, char *value, size_t value_len);

/* Destroy header field */
void aura_header_field_destroy(struct aura_header_field *header);

#endif