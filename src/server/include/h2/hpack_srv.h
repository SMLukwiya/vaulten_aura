#ifndef AURA_HPACK_H
#define AURA_HPACK_H

#include "bug_lib.h"
#include "compiler_lib.h"
#include "h2/stream.h"
#include "header_srv.h"
#include "memory_lib.h"
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

#define a_hpack_is_pseudo_header(header) (likely(header[0] == ':'))
#define a_horizontal_tab(c) (likely((uint8_t)c == 0x09))

#define DYNAMIC_TABLE_UPDATE_SIZE 5
#define A_STATUS_HEADER_SIZE 5
#define A_HEADER_TABLE_ENTRY_OVERHEAD 32

/**/
typedef enum {
    HPACK_INDEXED_HDR_FIELD,
    HPACK_LITERAL_HDR_FIELD_INCR_INDEXING_INDEXED_NAME,
    HPACK_LITERAL_HDR_FIELD_INCR_INDEXING_NEW_NAME,
    HPACK_LITERAL_HDR_FIELD_WITHOUT_INDEXING_INDEXED_NAME,
    HPACK_LITERAL_HDR_FIELD_WITHOUT_INDEXING_NEW_NAME,
    HPACK_LITERAL_HDR_FIELD_NEVER_INDEXED_INDEXED_NAME,
    HPACK_LITERAL_HDR_FIELD_NEVER_INDEXED_NEW_NAME,
    HPACK_DYNAMIC_TABLE_SIZE_UPDATE
} hpack_binary_format_rep;

/**
 * callback from hpack header parser
 * @conn: connection
 * @stream: stream context being parsed
 * @name: name of the header
 * @value: value associated with the header
 */
typedef int (*hpack_header_cb)(struct aura_h2_conn *conn, struct aura_h2_stream *stream,
                               struct aura_iovec *name, struct aura_iovec *value);

/**
 * This order follows from the callback
 * table define in h2.c.
 * When adding new callbacks, maintain the order,
 * otherwise you quickly become a danger to society!!
 */
typedef enum {
    HPACK_AUTHORITY_CB,
    HPACK_METHOD_CB,
    HPACK_PATH_CB,
    HPACK_SCHEME_CB,
    HPACK_STATUS_CB
} hpack_cb_idx;

typedef enum {
    HPACK_OK = 0,
    HPACK_ERR_INVALID_NAME,
    HPACK_ERR_INVALID_VALUE,
    HPACK_ERR_CAN_CONTINUE,
    HPACK_ERR_COMPRESSION,
    HPACK_ERR_PROTOCOL,
    HPACK_ERR_TRUNCATED,
    HPACK_ERR_INCOMPLETE, /* not really an error! */
    HPACK_ERR_PATH_EMPTY
} hpack_err_t;

/* Header Name Value Entry */
struct aura_hdr_nv {
    struct aura_iovec *name;
    struct aura_iovec *value;
    int32_t token;
    uint32_t index;
    uint32_t flags;
};

struct aura_hpack_hdr_table {
    struct aura_hdr_nv *entries;
    size_t num_of_entries;
    size_t start_idx; /* start index for dynamic or static tables ([rfc7541]) */
    size_t entry_cap;
    size_t table_size;       /* (32 + entry_name_len + entry_value_len) * num_of_entries: [rfc7541] */
    size_t max_size;         /* as determined by SETTINGS_HEADER_TABLE_SIZE setting */
    size_t max_dynamic_size; /* determined by SETTINGS_HEADER_TABLE_SIZE and dynamic table size update */
};

/* request parser that uses given callback as decoder */
int hpack_parse_request(struct aura_h2_conn *conn, struct aura_h2_stream *stream,
                        const uint8_t *src, size_t len, hpack_header_cb cb[]);

/* response parser that uses given callback as the decoder */
int hpack_parse_response(struct aura_h2_conn *conn, struct aura_h2_stream *stream,
                         const uint8_t *src, size_t len, hpack_header_cb cb[], bool is_trailer);

/* free hpack table header */
void hpack_dispose_header_table(struct aura_hpack_hdr_table *hdr_tb);

/* ---------- */
/**
 * Calculate spaces consumed by a single header entry
 */
static inline size_t header_entry_size(size_t name_len, size_t value_len) {
    return name_len + value_len + A_HEADER_TABLE_ENTRY_OVERHEAD;
}

/**
 * Calculate the total space consumed by the given set of headers
 */
static inline size_t get_headers_size(const struct aura_http_hdr_set *hdrs, size_t num_of_hdrs) {
    const struct aura_http_hdr_set *hdr;
    size_t size;

    if (!hdrs)
        return 0;

    size = 0;
    for (hdr = hdrs; num_of_hdrs != 0; ++hdr, --num_of_hdrs)
        size += header_entry_size(hdr->name->len, hdr->value->len);
    return size;
}

/**
 * Test if supplied value is indexed in
 * the static table
 */
static inline bool value_exists_in_static_table(const struct aura_iovec *value) {
    return &hpack_static_table[1].value <= value &&
           value <= &hpack_static_table[(ARRAY_SIZE(hpack_static_table) - 1)].value;
}

/**
 * Retrieve static table entry with the given token
 */
static inline struct aura_hpack_static_table_entry *hpack_static_header_table_get(int32_t token) {
    struct aura_hpack_static_table_entry *entry;

    for (int i = 0; i < ARRAY_SIZE(hpack_static_table); ++i) {
        entry = &hpack_static_table[i];
        if (entry->token == token)
            return entry;
    }
    return NULL;
}

/**
 * Retrieve header table entry associated
 * with the given index
 */
static inline struct aura_hdr_nv *hpack_header_table_get(struct aura_hpack_hdr_table *tb, size_t idx) {
    struct aura_hdr_nv *entry;
    size_t _idx;

    _idx = (tb->start_idx + idx) % tb->entry_cap;
    entry = &tb->entries[_idx]; // + _idx;
    A_BUG_ON_2(entry->name == NULL, true);
    return entry;
}

/**
 * Remove one dynamic table entry
 */
static inline void hpack_header_table_evict_one(struct aura_hpack_hdr_table *tb) {
    struct aura_hdr_nv *entry;

    A_BUG_ON_2(tb->num_of_entries == 0, true);

    entry = hpack_header_table_get(tb, --tb->num_of_entries);
    tb->table_size -= entry->name->len + entry->value->len + A_HEADER_TABLE_ENTRY_OVERHEAD;

    if (!iovec_is_token(entry->name)) {
        aura_iovec_destroy(entry->name);
    }
    if (!value_exists_in_static_table(entry->value)) {
        aura_iovec_destroy(entry->value);
    }
    memset(entry, 0, sizeof(*entry));
}

/**
 * Encode content length
 * literal header without indexing 'Indexed name'
 */
static inline uint8_t *encode_content_length(uint8_t *dest, size_t value) {
    char buf[32];
    char *p = buf + sizeof(buf);
    size_t l;

    do {
        *--p = '0' + value % 10;
    } while ((value /= 10) != 0);
    l = buf + sizeof(buf) - p;

    *dest++ = 0x0f; /* 15 */
    *dest++ = 0x0d; /* + 13 = 28(index) */
    *dest++ = (uint8_t)l;
    memcpy(dest, p, l);
    dest += l;

    return dest;
}

/**
 * Checks if header entries are to be evicted so
 * that the current size fits within the max table size
 * Encode dynamic table update (for transmission to peer) after evictions
 */
uint8_t *header_table_adjust_size(struct aura_hpack_hdr_table *tb, uint32_t new_cap, uint8_t *dest);

/**
 * Encode status code using literal header indexed
 * and literal header without indexing as fallback
 */
uint8_t *encode_status(uint8_t *dest, int status);

/**
 * Encode the given header set with the most
 * memory appropriate method available
 */
uint8_t *encode_header(struct aura_memory_ctx *mc, struct aura_hpack_hdr_table *tb,
                       uint8_t *dest, struct aura_http_hdr_set *hdr);

#endif