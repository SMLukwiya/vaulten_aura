#ifndef AURA_HPACK_H
#define AURA_HPACK_H

#include "bug_lib.h"
#include "compiler_lib.h"
#include "h2/stream.h"
#include "header_srv.h"
#include "memory_lib.h"
#include "token_srv.h"
#include "types_lib.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>

/* [rfc7541] -> https://datatracker.ietf.org/doc/html/rfc7541 */

/**
 * An integer is represented in two parts: a prefix that fills the
 * current octet and an optional list of octets that are used if the
 * integer value does not fit within the prefix.
 * 1 bytes for prefix length
 * 9 bytes for (9*7 == 63 bits) to represent int64_t
 * 7 bits per byte because the most significant bit of each
 * octet is used as a continuation flag
 */

#define A_H2_ERROR_INVALID_HEADER_CHAR -254 /* an internal error indicating invalid chars in header name or value */

#define A_HPACK_SOFT_ERROR_BIT_INVALID_NAME 0x1
#define A_HPACK_SOFT_ERROR_BIT_INVALID_VALUE 0x2

#define A_HPACK_PARSE_HEADERS_METHOD_EXISTS 1
#define A_HPACK_PARSE_HEADERS_SCHEME_EXISTS 2
#define A_HPACK_PARSE_HEADERS_PATH_EXISTS 4
#define A_HPACK_PARSE_HEADERS_AUTHORITY_EXISTS 8
#define A_HPACK_PARSE_HEADERS_PROTOCOL_EXISTS 16

#define a_horizontal_tab(c) (likely((uint8_t)c == 0x09))

#define A_DYNAMIC_TABLE_UPDATE_SIZE 5
#define A_STATUS_HEADER_SIZE 5
#define A_HEADER_TABLE_ENTRY_OVERHEAD 32
#define A_DYNAMIC_TABLE_HEADER_OFFSET 62
#define UINT64_MAX_STR "18446744073709551615"
#define A_MAX_REQ_LEN 16384 /** @todo: subject to change */

/**/
typedef enum {
    A_HPACK_INDEXED_HDR_FIELD,
    A_HPACK_LITERAL_HDR_FIELD_INCR_INDEXING_INDEXED_NAME,
    A_HPACK_LITERAL_HDR_FIELD_INCR_INDEXING_NEW_NAME,
    A_HPACK_LITERAL_HDR_FIELD_WITHOUT_INDEXING_INDEXED_NAME,
    A_HPACK_LITERAL_HDR_FIELD_WITHOUT_INDEXING_NEW_NAME,
    A_HPACK_LITERAL_HDR_FIELD_NEVER_INDEXED_INDEXED_NAME,
    A_HPACK_LITERAL_HDR_FIELD_NEVER_INDEXED_NEW_NAME,
    A_HPACK_DYNAMIC_TABLE_SIZE_UPDATE
} hpack_binary_format_rep;

/**
 * callback from hpack header parser
 * @conn: connection
 * @stream: stream context being parsed
 * @name: name of the header
 * @value: value associated with the header
 */
typedef int (*hpack_header_cb)(struct aura_h2_ctx *conn, struct aura_h2_stream *stream,
                               const char *name, size_t name_len, const char *value, size_t val_len);

/**
 * This order follows from the callback
 * table define in h2.c.
 * When adding new callbacks, maintain the order,
 * otherwise we are in danger!!
 */
typedef enum {
    A_HPACK_AUTHORITY_CB,
    A_HPACK_METHOD_CB,
    A_HPACK_PATH_CB,
    A_HPACK_SCHEME_CB,
    A_HPACK_STATUS_CB
} aura_hpack_cb_idx;

/* Hpack errors */
typedef enum {
    A_HPACK_OK = 0,
    A_HPACK_INVALID_NAME_ERR,
    A_HPACK_INVALID_VALUE_ERR,
    A_HPACK_SOFT_ERR,
    A_HPACK_COMPRESSION_ERR,
    A_HPACK_PROTOCOL_ERR,
    A_HPACK_TRUNCATED_ERR,
    A_HPACK_PATH_EMPTY_ERR, /* Custom error */
    A_HPACK_INTERNAL_ERR,
} hpack_err_t2;

/* hpack table entry structure */
struct aura_hpack_table_entry {
    struct aura_header_field *header_field;
    int16_t index;
};

/* Hpack dynamic table structure */
struct aura_hpack_dyn_table {
    struct aura_hpack_table_entry *entries; /* Dynamic table entries */
    size_t cnt;                             /* Current number of table entries */
    size_t cap;
    size_t tab_size;          /* (32 + name_len + val_len) * cnt */
    size_t max_size;          /* dynamic size updates value */
    size_t settings_tab_size; /* as determined by SETTINGS_HEADER_TABLE_SIZE setting */
};

struct aura_hpack_static_table {
    struct aura_hpack_table_entry entries[ARRAY_SIZE(rfc_static_table)];
};

/**
 * Parses requests received from the wire using hpack_header_cb
 * to validate some of the received values for correctness
 */
int aura_hpack_parse_request(struct aura_h2_ctx *conn, struct aura_h2_stream *stream,
                             const uint8_t *src, size_t len, hpack_header_cb cb[]);

/**
 * Parses response received from the wire using hpack_header_cb
 * to validate some of the received values for correctness
 */
int aura_hpack_parse_response(struct aura_h2_ctx *h2_ctx, struct aura_h2_stream *stream,
                              const uint8_t *src, size_t len, hpack_header_cb cb[], bool is_trailer);

/* Dispose dynamic hpack table header */
void aura_hpack_header_tab_dispose(struct aura_hpack_dyn_table *hdr_tb);

/**
 * Encode content length
 * literal header without indexing 'Indexed name'
 */
uint8_t *aura_encode_content_length(uint8_t *dest, size_t value);

/**
 * Checks if header entries are to be evicted so
 * that the current size fits within the max table size
 * Encode dynamic table update (for transmission to peer) after evictions
 */
uint8_t *aura_header_table_adjust_size(struct aura_hpack_dyn_table *tb, uint32_t new_cap, uint8_t *dest);

/**
 * Encode status code using literal header indexed
 * and literal header without indexing as fallback
 */
uint8_t *aura_encode_status(uint8_t *dest, int status);

/**
 * Encode the given header set with the most
 * memory appropriate method available
 */
uint8_t *aura_encode_header(struct aura_memory_ctx *mc, struct aura_hpack_static_table *static_tab,
                            struct aura_hpack_dyn_table *dyn_tab, uint8_t *dest, struct aura_header_field *hdr);

/**/
int aura_hpack_load_static_table(struct aura_hpack_static_table *tab, struct aura_intern_tab *intern_tab);

/* Returns true if header value is a pseudo header */
static inline bool aura_hpack_is_pseudo_header(const char *header) {
    return likely(*header == ':');
}
/**
 * Calculate spaces consumed by a single header entry
 */
static inline size_t aura_header_entry_size(size_t name_len, size_t value_len) {
    return name_len + value_len + A_HEADER_TABLE_ENTRY_OVERHEAD;
}

/**
 * Calculate the total space consumed by the given set of headers
 */
static inline size_t aura_get_headers_size(struct aura_header_field *hdrs, size_t num_of_hdrs) {
    struct aura_header_field *hdr;
    size_t size, name_len, value_len;

    if (!hdrs)
        return 0;

    size = 0;
    for (int i = 0; i <= num_of_hdrs; ++i) {
        hdr = &hdrs[i];
        name_len = hdr->name.interned->len;

        if (hdr->value.interned)
            value_len = hdr->value.interned->len;
        else
            value_len = hdr->value.raw.str->len;

        size += aura_header_entry_size(name_len, value_len);
    }
    return size;
}

/**
 * Retrieve static table entry with the given token
 */
static inline struct aura_hpack_table_entry *aura_hpack_static_tab_get_entry(struct aura_hpack_static_table *static_tab, int32_t token) {
    struct aura_hpack_table_entry *entry;

    for (int i = 0; i < ARRAY_SIZE(static_tab->entries); ++i) {
        entry = &static_tab->entries[i];
        if (entry->header_field->token == token)
            return entry;
    }
    return NULL;
}

/**
 * Retrieve header table entry associated
 * with the given index
 */
static inline struct aura_hpack_table_entry *aura_hpack_dyn_header_tab_get_entry(struct aura_hpack_dyn_table *tb, size_t idx) {
    struct aura_hpack_table_entry *entry;

    idx -= A_DYNAMIC_TABLE_HEADER_OFFSET;
    entry = &tb->entries[idx];
    return entry;
}

/* Returns true if index decoded is invalid */
static inline bool aura_hpack_tab_index_invalid(struct aura_hpack_dyn_table *tab, int64_t idx) {
    return (idx < 1 || (idx - A_DYNAMIC_TABLE_HEADER_OFFSET) >= (int64_t)tab->cnt);
}

/**
 * Remove dynamic table entry
 */
static inline void aura_hpack_header_table_evict_one(struct aura_hpack_dyn_table *tb) {
    struct aura_hpack_table_entry *entry;
    char *name, value;
    size_t name_len, value_len;

    A_BUG_ON_2(tb->cnt == 0, true);

    entry = aura_hpack_dyn_header_tab_get_entry(tb, --tb->cnt);
    name_len = entry->header_field->name.interned->len;

    if (entry->header_field->value_interned) {
        value_len = entry->header_field->name.interned->len;
    } else {
        value_len = entry->header_field->value.raw.str->len;
    }

    tb->tab_size -= name_len + value_len + A_HEADER_TABLE_ENTRY_OVERHEAD;

    aura_header_field_destroy(entry->header_field);
    memset(entry, 0, sizeof(*entry));
}

/**
 * Check if header value contains only valid characters
 * Returns false otherwise
 */
static inline bool aura_hpack_header_value_valid(const char *s, size_t len) {
    if (len != 0 && (isspace(s[0]) || a_horizontal_tab(s[0]) || isspace(s[len - 1]) || a_horizontal_tab(s[len - 1])))
        return false;
    return true;
}

static inline bool aura_hpack_static_table_name_exists2(struct aura_hpack_static_table *tab, struct aura_interned_str *str) {
    /**/
}

struct aura_header_field *aura_header_find_or_create(struct aura_memory_ctx *mc, struct aura_hpack_static_table *static_tab,
                                                     struct aura_hpack_dyn_table *dyn_tab, struct aura_intern_tab *intern_tab,
                                                     char *name, size_t name_len, char *val, size_t val_len);

#endif