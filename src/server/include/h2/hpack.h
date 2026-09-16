#ifndef AURA_HPACK_H
#define AURA_HPACK_H

#include "bug_lib.h"
#include "compiler_lib.h"
#include "error_lib.h"
#include "h2/stream.h"
#include "header_srv.h"
#include "mem.h"
#include "sliding_buf.h"
#include "token_srv.h"
#include "types_lib.h"
#include "utils_lib.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>

#define A_HPACK_PARSE_FLAGS_METHOD_SEEN 0x1
#define A_HPACK_PARSE_FLAGS_SCHEME_SEEN 0x2
#define A_HPACK_PARSE_FLAGS_PATH_SEEN 0x4
#define A_HPACK_PARSE_FLAGS_AUTHORITY_SEEN 0x8
#define A_HPACK_PARSE_FLAGS_PROTOCOL_SEEN 0x16

#define a_horizontal_tab(c) (likely((uint8_t)c == 0x09))

#define A_HPACK_DYN_TAB_UPDATE_SZ 5
#define A_HPACK_STATUS_HDR_SZ 5
#define A_HPACK_HDR_TAB_ENT_OVERHEAD 32
#define A_HPACK_DYNAMIC_TAB_HEADER_OFFSET 62
#define A_HPACK_STATIC_TAB_LEN 61
#define UINT64_MAX_STR "18446744073709551615"
#define A_HPACK_MAX_CONTENT_LEN_SZ 23
#define A_MAX_REQ_LEN 16384                       /** @todo: subject to change */
#define A_HPACK_MAX_HDR_NV_SZ (1 << 12)           /* 4KB */
#define A_HPACK_MAX_HDR_LIST_SZ (1 << 14)         /* 16KB */
#define A_HPACK_INITIAL_SETTINGS_HDR_SZ (1 << 12) /* 4KB */

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

typedef enum {
    A_HPACK_HDR_FIELD_WITH_INDEXING,
    A_HPACK_HDR_FIELD_WITHOUT_INDEXING,
    A_HPACK_HDR_FIELD_NEVER_INDEXED,
} a_hpack_indexing_mode;

/**
 * callback from hpack header parser
 * @conn: connection
 * @stream: stream context being parsed
 * @name: name of the header
 * @value: value associated with the header
 */
typedef int (*hpack_header_cb)(struct aura_h2_core *conn, struct aura_h2_stream *stream,
                               const char *name, size_t name_len, const char *value,
                               size_t val_len);

/**
 * This order follows from the callback
 * table define in h2.c.
 * When adding new callbacks, maintain the order,
 * otherwise we are in danger!!
 */
typedef enum {
    A_HPACK_METHOD_CB,
    A_HPACK_SCHEME_CB,
    A_HPACK_AUTHORITY_CB,
    A_HPACK_PATH_CB,
    A_HPACK_STATUS_CB,
} aura_hpack_cb_idx;

/**
 * Hpack errors
 * Lower level error can replace upper
 * level error in the decoder.
 * see 'aura_hpack_set_decoder_soft_err' below
 */
typedef enum {
    A_HPACK_OK = 0,
    A_HPACK_INVALID_PATH_ERR = -1,
    A_HPACK_HEADER_SIZE_TOO_LARGE = -2,
    A_HPACK_INVALID_HDR_FIELD_ERR = -3,
    A_HPACK_DUPLICATE_HDR_ERR = -4,
    A_HPACK_INVALID_VALUE_ERR = -5,
    A_HPACK_INVALID_NAME_ERR = -6,
    A_HPACK_SOFT_ERR = -7, /* Soft error boundary */
    A_HPACK_COMPRESSION_ERR = -8,
    A_HPACK_PROTOCOL_ERR = -9,
    A_HPACK_TRUNCATED_ERR = -10,
    A_HPACK_INTERNAL_ERR = -11,
    A_HPACK_INVALID_STATE_ERR = -12
} a_hpack_err_t;

/* Hpack OP Codes */
typedef enum {
    A_HPACK_OP_CODE_NONE,
    A_HPACK_OP_CODE_INDEXED,
    A_HPACK_OP_CODE_INDEXED_NAME,
    A_HPACK_OP_CODE_NEW_NAME,
} a_hpack_op_code;

/* Hpack decoder state */
typedef enum {
    A_HPACK_STATE_DECODE_START,
    A_HPACK_STATE_EXPECT_TAB_SIZE_UPDATE,
    A_HPACK_STATE_READ_TAB_SIZE_UPDATE,
    A_HPACK_STATE_OP_CODE,
    A_HPACK_STATE_READ_INDEX,
    A_HPACK_STATE_READ_NEW_NAME_LEN,
    A_HPACK_STATE_READ_NEW_NAME_HUFF,
    A_HPACK_STATE_READ_NEW_NAME,
    A_HPACK_STATE_READ_VALUE_LEN,
    A_HPACK_STATE_READ_VALUE_HUFF,
    A_HPACK_STATE_READ_VALUE,
} a_hpack_decoder_state;

/* hpack table entry structure */
struct aura_hpack_tab_entry {
    struct aura_header_field header_field;
    uint32_t index;
};

/* Hpack dynamic table structure */
struct aura_hpack_dyn_tab {
    struct aura_hpack_tab_entry *entries; /* Dynamic table entries */
    uint64_t cnt;                         /* Current number of table entries */
    uint64_t cap;                         /* Table capacity */
    uint64_t tab_size;                    /* (32 + name_len + val_len) * cnt */
    uint64_t max_size;                    /* dynamic size updates value */
    uint64_t hdr_tab_max_size;            /* as determined by SETTINGS_HEADER_TABLE_SIZE setting */
};

/* Static table structure */
struct aura_hpack_static_table {
    struct aura_token tokens[A_TOKEN_WWW_AUTHENTICATE - 1];
    struct aura_hpack_tab_entry entries[ARRAY_SIZE(rfc_static_table)];
    struct aura_intern_tab *intern_tab; /* Intern table for hpack static strings */
};

/* Receiver buffer for name/value strings */
struct aura_hpack_dec_recv_buf {
    uint8_t *base;
    size_t len;
    size_t reserved;
};

/* Hpack decoder structure */
struct aura_hpack_decoder {
    struct aura_sliding_buf recv_buf;              /* Receiver buffer for string decoding */
    uint64_t len;                                  /* decoded integer, also acts as accumulator */
    uint64_t index;                                /* decoded index, never acts as accumulator */
    uint64_t shift;                                /* current decoding integer shift */
    struct aura_mem_ctx *mc;                       /* decoder mem ctx */
    struct aura_hpack_dyn_tab dyn_tab;             /* Decoder header table */
    struct aura_hpack_dec_recv_buf name_recv_buf;  /* Name receive buffers for new name */
    struct aura_hpack_dec_recv_buf value_recv_buf; /* Value receive for literal value */
    int8_t soft_error;                             /* soft errors kept until end headers is seen */
    uint8_t state;                                 /* current decoder state */
    uint8_t opcode;                                /* current decoder op code*/
    uint8_t prefix;                                /* decoder integer prefix */
    uint8_t huff_state;                            /* huffman encoding state */
    uint8_t flags;                                 /* decoder flags e.g, emission... */
    uint8_t pseudo_flags;                          /* Pseudo header flags */
    bool huff_encoded;                             /* is string huffman encoded */
    bool new_tab_insert;                           /* should add this entry to the dyn tab */
    bool never_indexed;                            /* should never be indexed */
    bool err_state;                                /* has decoder encountered a hard error */
    bool regular_hdr_field_seen;                   /* Records if then first non pseudo header is seen */
};

/* Hpack encoder structure */
struct aura_hpack_encoder {
    struct aura_hpack_dyn_tab dyn_tab;
    struct aura_mem_ctx *mc;
    struct aura_sliding_buf enc_buf;
    bool send_table_size_update;
};

/**
 * Encode content length
 * literal header without indexing 'Indexed name'
 */
// uint8_t *aura_encode_content_length(uint8_t *dest, size_t value);

/**
 * Encode status code using literal header indexed
 * and literal header without indexing as fallback
 */
uint8_t *aura_encode_status(uint8_t *dest, int status);

/**/
int aura_hpack_load_static_table(struct aura_mem_ctx *mc);

/* Returns true if header value is a pseudo header */
static inline bool aura_hpack_is_pseudo_header(const char *header) {
    return likely(*header == ':');
}
/**
 * Calculate spaces consumed by a single header entry
 */
static inline size_t aura_hpack_hdr_entry_size(size_t name_len, size_t value_len) {
    return name_len + value_len + A_HPACK_HDR_TAB_ENT_OVERHEAD;
}

/**
 * Retrieve static table entry with the given token
 */
static inline const struct aura_hpack_tab_entry *aura_hpack_static_tab_get_by_token(
  const struct aura_hpack_static_table *static_tab, int32_t token) {
    const struct aura_hpack_tab_entry *entry;

    for (int i = 0; i < A_HPACK_DYNAMIC_TAB_HEADER_OFFSET; ++i) {
        entry = &static_tab->entries[i];
        if (entry->header_field.token == token)
            return entry;
    }
    return NULL;
}

/**
 * Retrieve header table entry associated
 * with the given index from static table
 */
static inline struct aura_hpack_tab_entry *aura_hpack_static_tab_get_entry(
  const struct aura_hpack_static_table *static_tab, size_t idx) {
    return (struct aura_hpack_tab_entry *)&static_tab->entries[idx];
}

/**
 * Retrieve header table entry associated
 * with the given index from dynamic table
 */
static inline struct aura_hpack_tab_entry *aura_hpack_dyn_header_tab_get_entry(
  struct aura_hpack_dyn_tab *tb, size_t idx) {
    struct aura_hpack_tab_entry *entry;

    idx -= A_HPACK_DYNAMIC_TAB_HEADER_OFFSET;
    entry = &tb->entries[idx];
    return entry;
}

/* Returns true if index decoded is invalid */
static inline bool aura_hpack_tab_index_invalid(struct aura_hpack_dyn_tab *tab, int64_t idx) {
    return (idx < 1 || (idx - A_HPACK_DYNAMIC_TAB_HEADER_OFFSET) >= (int64_t)tab->cnt);
}

/**
 * Remove dynamic table entry
 */
static inline void aura_hpack_header_table_evict_one(struct aura_hpack_dyn_tab *tb) {
    struct aura_hpack_tab_entry *entry;
    char *name, value;
    size_t name_len, value_len;

    A_BUG_ON_2(tb->cnt == 0, true);

    entry = aura_hpack_dyn_header_tab_get_entry(tb, --tb->cnt + A_HPACK_DYNAMIC_TAB_HEADER_OFFSET);
    name_len = entry->header_field.name->len;

    if (entry->header_field.flags & A_HDR_FIELD_FLAG_VALUE_INTERNED) {
        value_len = entry->header_field.name->len;
    } else {
        value_len = entry->header_field.value.raw.str.len;
    }

    tb->tab_size -= name_len + value_len + A_HPACK_HDR_TAB_ENT_OVERHEAD;

    aura_header_field_destroy2(&entry->header_field);
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

/**
 * Check if the error returned by hpack is fatal
 */
static inline bool aura_hpack_hdr_err_fatal(int error) {
    return error < A_HPACK_SOFT_ERR;
}

/* Initialize hpack decoder */
int aura_hpacK_decoder_init(struct aura_hpack_decoder *dec, struct aura_mem_ctx *mc, size_t tab_max_size);

/* Destroy hpack decoder */
void aura_hpack_decoder_destroy(struct aura_hpack_decoder *dec);

static inline bool aura_hpack_is_static_table_token(int token) {
    return token > 0 && token <= A_TOKEN_WWW_AUTHENTICATE;
}

static inline bool aura_hpack_bin_fmt_hdr_tab_update(const char c) {
    return (c & 0xe0u) == 0x20u;
}

static inline bool aura_hpack_bin_fmt_indexed_field(const char c) {
    return (c & 0x80u) != 0;
}

static inline bool aura_hpack_bin_fmt_new_name(const char c) {
    return (c == 0x40u || c == 0 || c == 0x10u);
}

static inline bool aura_hpack_insert_new_tab_entry(const char c) {
    return (c & 0x40) != 0;
}

static inline int a_hpack_get_max_index(struct aura_hpack_dyn_tab *dyn) {
    return A_HPACK_DYNAMIC_TAB_HEADER_OFFSET + dyn->cnt - 1;
}

static inline void aura_hpack_decoder_reset_for_new_len(struct aura_hpack_decoder *dec, uint8_t c) {
    dec->huff_encoded = (c & 0x80u) != 0;
    dec->len = 0;
    dec->shift = 0;
    dec->prefix = 7;
}

static inline void aura_hpack_init_huff_decode_ctx(struct aura_hpack_decoder *dec) {
    dec->huff_state = 0;
}

static inline void aura_hpack_reset_name_value_recv_buf(struct aura_hpack_decoder *dec) {
    dec->name_recv_buf.base = dec->value_recv_buf.base = NULL;
    dec->name_recv_buf.len = dec->value_recv_buf.len = 0;
}

static inline uint32_t aura_hpack_tab_get_entry_cnt(struct aura_hpack_dyn_tab *tab) {
    return tab->cnt + A_HPACK_STATIC_TAB_LEN;
}

/* update the decoder error if not set */
static inline void aura_hpack_set_decoder_soft_err(struct aura_hpack_decoder *dec, int err) {
    if (err < dec->soft_error)
        dec->soft_error = err;
}

static inline void aura_hpack_decoder_reset(struct aura_hpack_decoder *dec) {
    dec->state = A_HPACK_STATE_DECODE_START;
    dec->soft_error = 0;
    dec->err_state = false;
    dec->pseudo_flags = 0;
}

/**
 * Initialize hpack encoder,
 * @max_size: size of hpack dynamic table
 */
int aura_hpack_encoder_init(struct aura_hpack_encoder *enc, struct aura_mem_ctx *mc, size_t max_size);

/* Destroy hpack encoder */
void aura_hpack_encoder_destroy(struct aura_hpack_encoder *enc);

/* Checks and encodes table size update if applicable */
int aura_hpack_encoder_adjust_tab_size(struct aura_hpack_encoder *enc);

/* Encode method for wire transmission */
int aura_hpack_encode_method(struct aura_hpack_encoder *enc,
                             struct aura_intern_tab *intern_tab,
                             struct aura_iovec value);

/* Encode status for wire transmission */
int aura_hpack_encode_status(struct aura_hpack_encoder *enc,
                             int status);

/* Encode content len for wire transmission */
int aura_hpack_encode_content_length(struct aura_hpack_encoder *enc, uint64_t value);

int aura_hpack_encode_headers(struct aura_hpack_encoder *enc, struct aura_intern_tab *intern_tab,
                              struct aura_basic_header *hdr_field, size_t hdr_cnt);

ssize_t aura_hpack_decode(struct aura_hpack_decoder *dec, const uint8_t *src_in,
                          const uint8_t *end, struct aura_intern_tab *intern_tab,
                          struct aura_header_field *hdr, bool final);

/**
 * Update encoder header table settings
 * Called when SETTINGS frame with
 * SETTINGS_HEADER_TABLE_SIZE is received.
 * The new value represents the new absolute limit
 * of the table
 */
void aura_hpack_enc_update_tab_settings_sz(struct aura_hpack_encoder *enc, size_t max_size);

/**
 * Update decoder header table settings
 * Called when sending SETTINGS frame
 * with SETTINGS_HEADER_TABLE_SIZE
 * The new value represents the new absolute limit
 * of the table
 */
void aura_hpack_dec_update_tab_settings_sz(struct aura_hpack_decoder *dec, size_t max_size);

/* Encode length */
uint64_t aura_hpack_encode_len(uint8_t *dest, uint64_t prefix, uint64_t len);

/* Encode indexed name */
uint64_t aura_hpack_encode_indexed_name(uint8_t *dest, size_t dest_len, size_t idx,
                                        struct aura_iovec *value, a_hpack_indexing_mode ind_mode);

/* Encode new name */
uint64_t aura_hpack_encode_new_name(uint8_t *dest, size_t dest_len, struct aura_iovec *name,
                                    struct aura_iovec *value, a_hpack_indexing_mode ind_mode);

void aura_hpack_tab_dump(struct aura_hpack_dyn_tab *tab);
void aura_hpack_dec_dump(struct aura_hpack_decoder *dec);
void aura_hpack_enc_dump(struct aura_hpack_encoder *enc);

#endif