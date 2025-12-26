#include "h2/hpack_srv.h"
#include "bug_lib.h"
#include "h2/connection.h"
#include "h2/hpack_huffman_tb_srv.h"
#include "h2/stream.h"
#include "memory_lib.h"
#include "slab_lib.h"
#include "token_srv.h"
#include "utils_lib.h"

#define A_HEADER_DYNAMIC_TABLE_OFFSET 62
#define A_DYNAMIC_TABLE_SIZE_UPDATE_MAX_SIZE 5
/* uses Literal Header Field without Indexing (RFC7541 6.2.2) */
#define A_CONTENT_LENGTH_HEADER_MAX_SIZE (3 + sizeof(SIZE_T_LONGEST_STR) - 1)
#define A_MIN_PREFIX_BITS 1
#define A_MAX_PREFIX_BITS 8

/* Error strings */
const char hpack_err_missing_mandatory_pseudo_header[] = "missing mandatory pseudo header";
const char hpack_err_invalid_pseudo_header[] = "invalid pseudo header";
const char hpack_err_found_upper_case_in_header_name[] = "found an upper-case letter in header name";
const char hpack_err_unexpected_connection_specific_header[] = "found an unexpected connection-specific header";
const char hpack_err_invalid_content_length_header[] = "invalid content-length header";
const char hpack_soft_err_found_invalid_char_in_header_name[] = "found an invalid character in header name";
const char hpack_soft_err_found_invalid_char_in_header_value[] = "found an invalid character in header value";

/**
 *
 */
static bool hpack_decode_integer(const uint8_t **src, const uint8_t *src_end, uint8_t prefix_bits, int64_t *out, int *err) {
    uint64_t value;
    int32_t shift;
    uint8_t prefix_max, curr;

    if (prefix_bits < A_MIN_PREFIX_BITS || prefix_bits > A_MAX_PREFIX_BITS) {
        if (err)
            *err = HPACK_ERR_PROTOCOL;
        return false;
    }

    if (*src >= src_end) {
        if (err)
            *err = HPACK_ERR_INCOMPLETE; // or truncated??
        return false;
    }

    prefix_max = (uint8_t)((1u << prefix_bits) - 1u);
    curr = **src;
    value = curr & prefix_max;
    (*src)++;
    /* value can fit in the prefix max */
    if (value < prefix_max) {
        *out = (int64_t)value;
        return true;
    }

    /* decode upto 8 octets(64 bits, excluding prefix), that is guaranteed not to cause overflow */
    shift = 0;
    while (true) {
        if (*src == src_end) {
            if (err)
                *err = HPACK_ERR_INCOMPLETE;
            return false;
        }
        curr = **src;
        (*src)++;

        /* check overflow */
        if (shift >= 56) {
            if (err)
                *err = HPACK_ERR_COMPRESSION;
            return false;
        }

        value += (int64_t)(curr & 127) << shift;
        /* check if this is the last valid byte */
        if ((curr & 128) == 0)
            break;
        shift += 7;
    }
    *out = value;
    return true;
    /** @todo: Test if this extracts 64 bit values correctly */
}

/**
 *
 */
static inline bool huffman_decode4(char **dest, uint8_t in, uint8_t *state, bool *accepting, uint8_t *char_errs, int *err) {
    const nghttp2_huff_decode *entry;
    uint8_t next_state;
    int res;

    entry = huff_decode_table[*state] + in;
    res = entry->flags & NGHTTP2_HUFF_FAIL;
    if (res != 0) {
        if (err)
            *err = HPACK_ERR_COMPRESSION;
        return false;
    }

    next_state = entry->state;
    res = entry->flags & NGHTTP2_HUFF_SYM;
    if (res != 0) {
        *(*dest)++ = entry->sym;
        *char_errs |= (entry->flags & NGHTTP2_HUFF_INVALID_CHARS);
    }

    *state = next_state;
    *accepting = (entry->flags & NGHTTP2_HUFF_ACCEPTED) != 0;

    return true;
}

/**
 *
 */
static inline bool header_value_valid_as_whole(const char *s, size_t len) {
    if (len != 0 && (isspace(s[0]) || a_horizontal_tab(s[0]) || isspace(s[len - 1]) || a_horizontal_tab(s[len - 1])))
        return false;
    return true;
}

/**
 * returns SIZE_MAX if hard fail
 */
size_t hpack_decode_huffman(char *dest, const uint8_t *src, size_t len, bool value_is_name, int *err) {
    char *ptr = dest;
    const uint8_t *src_end = src + len;
    uint8_t state = 0, char_errs = 0;
    bool accepting = true;
    bool res;

    if (value_is_name && len == 0) {
        if (err)
            *err |= HPACK_ERR_INVALID_NAME;
        return SIZE_MAX;
    }

    for (; src < src_end; src++) {
        res = huffman_decode4(&ptr, *src >> 4, &state, &accepting, &char_errs, err);
        if (res == false)
            return SIZE_MAX;
        res = huffman_decode4(&ptr, *src & 0xf, &state, &accepting, &char_errs, err);
        if (res == false)
            return SIZE_MAX;
    }

    if (accepting == false)
        return SIZE_MAX;

    /* validate */
    if (value_is_name) {
        /* pseudo-headers are checked later in 'decode_header' */
        if (!a_hpack_is_pseudo_header(dest) && (char_errs & NGHTTP2_HUFF_INVALID_FOR_HEADER_NAME) != 0) {
            if ((char_errs & NGHTTP2_HUFF_UPPER_CASE_CHAR) != 0) {
                if (err)
                    *err = HPACK_ERR_PROTOCOL;
                return SIZE_MAX;
            }
            *err |= HPACK_ERR_INVALID_NAME;
        }
    } else if ((char_errs & NGHTTP2_HUFF_INVALID_FOR_HEADER_VALUE) != 0 || !header_value_valid_as_whole(dest, ptr - dest))
        if (err)
            *err |= HPACK_ERR_INVALID_VALUE;

    return ptr - dest;
}

bool hpack_validate_header_name(const uint8_t *src, size_t len, int *err) {
    uint8_t ch;

    /* all printable chars, except upper case and separator characters */
    static const char valid_h2_header_name_char[] = {
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /*    0-31 */
      0, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, /*   32-63 */
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, /*   64-95 */
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0, /*  96-127 */
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 128-159 */
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 160-191 */
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 192-223 */
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /* 224-255 */
    };

    if (len == 0)
        *err |= HPACK_ERR_INVALID_NAME;
    else {
        for (; len != 0; ++src, --len) {
            ch = *src;
            if (valid_h2_header_name_char[ch] == 0) {
                if (err)
                    *err |= HPACK_ERR_INVALID_NAME;
                if (isupper(ch)) {
                    return false;
                }
            }
        }
    }
    return true;
}

/**
 *
 */
void hpack_validate_header_value(const uint8_t *src, size_t len, int *err) {
    uint8_t ch;

    /* surrounding whitespaces RFC 9113 8.2.1 */
    if (!header_value_valid_as_whole(src, len))
        goto invalid;

    /* all printable chars + horizontal tab (RFC 7230 3.2) */
    static const char valid_h2_field_value_char[] = {
      0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, /*    0-31 */
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /*   32-63 */
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /*   64-95 */
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, /*  96-127 */
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 128-159 */
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 160-191 */
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 192-223 */
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 224-255 */
    };

    for (; len != 0; ++src, --len) {
        ch = *src;
        if (!valid_h2_field_value_char[ch])
            goto invalid;
    }
    return;

invalid:
    if (err)
        *err = HPACK_ERR_INVALID_VALUE;
}

/**
 *
 */
static struct aura_iovec *hpack_decode_string(struct aura_memory_ctx *mc, const uint8_t **src,
                                              const uint8_t *src_end, bool value_is_name, int *err) {
    struct aura_iovec *str;
    bool is_huffman, res;
    int64_t len;

    if (*src >= src_end)
        return NULL;

    res = hpack_decode_integer(src, src_end, 7, &len, err);
    if (res == false)
        return NULL;

    /* huffman flag (MSB == 1) */
    is_huffman = (**src & 0x80) != 0;

    if (is_huffman) {
        if (len > src_end - *src)
            return NULL;

        str = aura_iovec_init(mc, len * 2); /* huffman max compression ratio is >= 0.5 */
        if (str == NULL)
            return NULL;

        str->len = hpack_decode_huffman(str->base, *src, len, value_is_name, err);
        if (str->len == SIZE_MAX)
            return NULL;

        str->base[str->len] = '\0';
    } else {
        if (len > src_end - *src)
            return NULL;

        if (value_is_name) {
            /* pseudo-headers are checked later in 'decode_header' */
            if ((len == 0 || !a_hpack_is_pseudo_header(*src)) && !hpack_validate_header_name(*src, len, err))
                return NULL;
        } else
            hpack_validate_header_value((char *)*src, len, err);

        str = aura_iovec_init(mc, len + 1);
        if (str == NULL)
            return NULL;

        memcpy(str->base, *src, len);
        str->base[len] = '\0';
    }
    *src += len;
    return str;
}

/**
 *
 */
struct aura_hdr_nv *header_table_add(struct aura_memory_ctx *mc, struct aura_hpack_hdr_table *tb,
                                     size_t add, size_t max_num_entries) {
    struct aura_hdr_nv *old_entries;
    size_t old_cap;

    /* adjust size */
    while (tb->num_of_entries > max_num_entries || (tb->num_of_entries != 0 && tb->table_size + add > tb->max_dynamic_size))
        hpack_header_table_evict_one(tb);

    if (tb->num_of_entries == 0) {
        A_BUG_ON_2(tb->table_size != 0, true);
        if (add > tb->max_dynamic_size)
            return NULL;
    }

    old_entries = tb->entries;
    old_cap = tb->entry_cap;
    /* grow the entries if full */
    if (tb->num_of_entries >= tb->entry_cap) {
        tb->entry_cap = tb->entry_cap < 16 ? 16 : tb->entry_cap * 2;
        tb->entries = aura_realloc(mc, tb->entries, sizeof(*tb->entries) * tb->entry_cap);
        if (tb->entries == NULL) {
            tb->entries = old_entries;
            tb->entry_cap = old_cap;
            return NULL;
        }
    }

    memmove(&tb->entries[1], &tb->entries[0], tb->num_of_entries * sizeof(*tb->entries));
    tb->table_size += add;
    ++tb->num_of_entries;
    return tb->entries;
}

static inline int hpack_determine_binary_format(uint8_t c) {
    if (0x80u & c)
        return HPACK_INDEXED_HDR_FIELD;
    else if (c >= 64) {
        if (0x3f & c)
            return HPACK_LITERAL_HDR_FIELD_INCR_INDEXING_INDEXED_NAME;
        else
            return HPACK_LITERAL_HDR_FIELD_INCR_INDEXING_NEW_NAME;
    } else if ((0xe0u & c) == 0x20u)
        return HPACK_DYNAMIC_TABLE_SIZE_UPDATE;
    else if (c >= 16) {
        if (0x0f & c)
            return HPACK_LITERAL_HDR_FIELD_NEVER_INDEXED_INDEXED_NAME;
        else
            return HPACK_LITERAL_HDR_FIELD_NEVER_INDEXED_NEW_NAME;
    } else {
        if (c > 0)
            return HPACK_LITERAL_HDR_FIELD_WITHOUT_INDEXING_INDEXED_NAME;
        else
            return HPACK_LITERAL_HDR_FIELD_WITHOUT_INDEXING_NEW_NAME;
    }
}

/**
 *
 */
bool hpack_decode_header(struct aura_memory_ctx *mc, struct aura_hpack_hdr_table *hpack_hdr_tb, struct aura_hdr_nv *nv,
                         const uint8_t **const src, const uint8_t *src_end, int *err) {

    struct aura_hdr_nv *entry;
    struct aura_iovec *name = NULL;
    struct aura_iovec *value = NULL;
    bool name_is_indexed;
    bool value_is_indexed;
    bool insert_new_entry;
    int64_t index;
    int64_t new_cap;
    int res, binary_format;
    int32_t prefix_len;
    int32_t token;

    index = 0;
    prefix_len = -1;
    name_is_indexed = false;
    value_is_indexed = false;
    insert_new_entry = false;
    for (; *src < src_end;) {
        /* determine the encoding and proceed */
        binary_format = hpack_determine_binary_format(**src);

        switch (binary_format) {
        case HPACK_INDEXED_HDR_FIELD:
            prefix_len = 7;
            name_is_indexed = true;
            value_is_indexed = true;
            break;

        case HPACK_LITERAL_HDR_FIELD_INCR_INDEXING_INDEXED_NAME:
            prefix_len = 6;
            name_is_indexed = true;
            insert_new_entry = true;
            break;

        case HPACK_LITERAL_HDR_FIELD_INCR_INDEXING_NEW_NAME:
        case HPACK_LITERAL_HDR_FIELD_NEVER_INDEXED_NEW_NAME:
        case HPACK_LITERAL_HDR_FIELD_WITHOUT_INDEXING_NEW_NAME:
            (*src)++;
            break;

        case HPACK_LITERAL_HDR_FIELD_NEVER_INDEXED_INDEXED_NAME:
        case HPACK_LITERAL_HDR_FIELD_WITHOUT_INDEXING_INDEXED_NAME:
            prefix_len = 4;
            name_is_indexed = true;
            break;

        case HPACK_DYNAMIC_TABLE_SIZE_UPDATE:
            res = hpack_decode_integer(src, src_end, 5, &new_cap, err);
            if (res == false && *err > HPACK_ERR_CAN_CONTINUE) {
                *err = HPACK_ERR_COMPRESSION;
                return false;
            }

            if (new_cap > hpack_hdr_tb->max_size) {
                *err = HPACK_ERR_COMPRESSION;
                return false;
            }

            hpack_hdr_tb->max_dynamic_size = (size_t)new_cap;
            while (hpack_hdr_tb->num_of_entries != 0 && hpack_hdr_tb->table_size > hpack_hdr_tb->max_dynamic_size)
                hpack_header_table_evict_one(hpack_hdr_tb);
            continue; /** @todo: test how switch behaves inside for loop with 'continue' */
            // break;
        default:
            /* protocol error */
        }

        if (name_is_indexed) {
            res = hpack_decode_integer(src, src_end, prefix_len, &index, err);
            if (res == false) {
                if (*err > HPACK_ERR_CAN_CONTINUE) {
                    *err = HPACK_ERR_COMPRESSION;
                    return false;
                }
            }

            if ((index - A_HEADER_DYNAMIC_TABLE_OFFSET) >= (int64_t)hpack_hdr_tb->num_of_entries) {
                if (*err)
                    *err = HPACK_ERR_COMPRESSION;
                return false;
            }

            if (index < A_HEADER_DYNAMIC_TABLE_OFFSET) {
                name = &hpack_static_table[index].name;
                token = hpack_static_table[index].token;
            } else {
                entry = hpack_header_table_get(hpack_hdr_tb, index - A_HEADER_DYNAMIC_TABLE_OFFSET);
                name = entry->name;
                token = entry->token;
            }

            if (value_is_indexed) {
                value = &hpack_static_table[index].value;
            } else {
                value = hpack_decode_string(mc, src, src_end, false, err);
                if (value == NULL)
                    return false;
            }
        } else {
            name = hpack_decode_string(mc, src, src_end, true, err);
            if (name == NULL)
                return false;

            value = hpack_decode_string(mc, src, src_end, false, err);
            if (value == NULL)
                return false;

            token = lookup_token(name->base, name->len);
        }

        /* add to dynamic table */
        if (insert_new_entry) {
            entry = header_table_add(mc, hpack_hdr_tb, name->len + value->len + A_HEADER_TABLE_ENTRY_OVERHEAD, 128);
            if (entry != NULL) {
                entry->name = name;
                if (!iovec_is_token(entry->name)) {
                    /* addref to shared mem, a way of sharing the entry */;
                }
                entry->value = value;
                if (!value_exists_in_static_table(entry->value)) {
                    /* add shared memory */;
                }
            }
        }

        nv->name = name;
        nv->value = value;
        nv->token = token;
        nv->index = index;
        if (*err) {
            return false;
        }
        return true;
    }

    if (err)
        *err = HPACK_ERR_COMPRESSION;
    return false;
}

uint8_t *encode_status(uint8_t *dest, int status) {
    A_BUG_ON_2(status < 100 || status > 999, true);

    switch (status) {
#define COMMON_CODE(code, st)  \
    case st:                   \
        *dest++ = 0x80 | code; \
        break;
        COMMON_CODE(8, 200);
        COMMON_CODE(9, 204);
        COMMON_CODE(10, 206);
        COMMON_CODE(11, 304);
        COMMON_CODE(12, 400);
        COMMON_CODE(13, 404);
        COMMON_CODE(14, 500);
#undef COMMON_CODE
    default:
        /* use literal header field without indexing - indexed name */
        *dest++ = 8;
        *dest++ = 3;
        sprintf((char *)dest, "%d", status);
        dest += 3;
        break;
    }
    return dest;
}

/**
 *
 */
void hpack_dispose_header_table(struct aura_hpack_hdr_table *hdr_tb) {
    struct aura_hdr_nv *entry;
    size_t idx;

    if (hdr_tb->num_of_entries != 0) {
        idx = hdr_tb->start_idx;
        do {
            entry = hdr_tb->entries + idx;
            if (!iovec_is_token(entry->name)) {
                aura_iovec_destroy(entry->name);
            }
            if (!value_exists_in_static_table(entry->value)) {
                aura_iovec_destroy(entry->value);
            }
            idx = (idx + 1) % hdr_tb->entry_cap;
        } while (--hdr_tb->num_of_entries > 0);
    }
    free(hdr_tb->entries);
}

int hpack_parse_request(struct aura_h2_conn *conn, struct aura_h2_stream *stream,
                        const uint8_t *src, size_t len, hpack_header_cb cb[]) {
    const uint8_t *end;
    struct aura_hdr_nv nv;
    const char *decode_err;
    uint64_t content_length;
    struct aura_hpack_hdr_table *inbound_hdr_tb;
    struct aura_http_hdrs *req_hdrs;
    int error = 0;
    int res;

    end = src + len;
    content_length = SIZE_MAX;
    inbound_hdr_tb = &conn->input_hdr_table;
    req_hdrs = stream->req.headers;
    while (src != end) {
        decode_err = NULL;
        res = hpack_decode_header(conn->mc, inbound_hdr_tb, &nv, &src, end, &error);
        if (res == false) {
            if (error == HPACK_ERR_INVALID_NAME) {
                /* this is a soft error, we continue parsing, but register only  the first error */
                // if (*err_desc == NULL)
                //     *err_desc = decode_err;
            } else {
                // *err_desc = decode_err;
                return error;
            }
        }

        if (a_hpack_is_pseudo_header(nv.name->base)) {
            switch (nv.token) {
            case A_TOKEN_AUTHORITY:
                res = cb[HPACK_AUTHORITY_CB](conn, stream, nv.name, nv.value);
                if (res != HPACK_OK)
                    return res;
                break;

            case A_TOKEN_METHOD:
                res = cb[HPACK_METHOD_CB](conn, stream, nv.name, nv.value);
                if (res != HPACK_OK)
                    return res;
                break;

            case A_TOKEN_PATH:
                res = cb[HPACK_PATH_CB](conn, stream, nv.name, nv.value);
                if (res != HPACK_OK)
                    return res;
                break;

            case A_TOKEN_SCHEME:
                res = cb[HPACK_SCHEME_CB](conn, stream, nv.name, nv.value);
                if (res != HPACK_OK)
                    return res;
                break;

            case HPACK_STATUS_CB:
                res = cb[HPACK_STATUS_CB](conn, stream, nv.name, nv.value);
                if (res != HPACK_OK)
                    return res;
                break;

            default:
                /* Unknown pseudo header */
                return HPACK_ERR_PROTOCOL;
            }
        } else {
            if (nv.token == A_TOKEN_CONTENT_LENGTH) {
                res = cb[HPACK_METHOD_CB](conn, stream, nv.name, nv.value);
                if (res != HPACK_OK)
                    return res;
                continue;
            } else if (nv.token == A_TOKEN_EXPECT) {
                continue;
            } else if (nv.token == A_TOKEN_HOST) {
                /* HTTP2 allows the use of host header (in place of :authority) */
                res = cb[HPACK_AUTHORITY_CB](conn, stream, nv.name, nv.value);
                if (res != HPACK_OK)
                    return res;
                continue;
            } else if (nv.token == A_TOKEN_TE && aura_lc_str_is_eq(nv.value->base, nv.value->len, str_lit("trailers"))) {
                /* do not reject */
            } else {
                /* rest of the header fields that are marked as special are rejected */
                return HPACK_ERR_PROTOCOL;
            }
            aura_add_header(conn->mc, req_hdrs, &nv);
        }
    }

    if (error) {
        return error;
    }

    return HPACK_OK;
}

/**
 *
 */
int hpack_parse_response(struct aura_h2_conn *conn, struct aura_h2_stream *stream,
                         const uint8_t *src, size_t len, hpack_header_cb *cb, bool is_trailer) {

    struct aura_iovec *name;
    struct aura_iovec value;
    struct aura_hdr_nv nv;
    const uint8_t *end;
    const char *decode_err = NULL;
    struct aura_token *token;
    struct aura_hpack_hdr_table *outbound_hdr_tb;
    struct aura_http_hdrs *res_hdrs;
    int error;
    bool res;

    outbound_hdr_tb = &conn->output_hdr_table;
    res_hdrs = stream->res.headers;
    end = src + len;
    /* detect missing :status header as the first response */
    if (src == end) {
        return HPACK_ERR_PROTOCOL;
    }

    do {
        res = hpack_decode_header(conn->mc, outbound_hdr_tb, &nv, &src, end, &error);
        if (res == false) {
            if (error == A_H2_ERROR_INVALID_HEADER_CHAR) {
                /* this is a soft error, we continue parsing, but register only the first error */
                // if (*err_desc == NULL)
                //     *err_desc = decode_err;
            } else {
                // *err_desc = decode_err;
                return error;
            }
        }

        if (nv.name->base[0] == ':') {
            if (is_trailer) {
                return HPACK_ERR_PROTOCOL; /* Trailers must not include pseudo-header fields */
            }

            if (nv.token != A_TOKEN_STATUS) {
                return HPACK_ERR_PROTOCOL;
            }

            res = cb[HPACK_STATUS_CB](conn, stream, nv.name, nv.value);
            if (res == HPACK_OK) {
                /**/
            }
        } else {
            if (iovec_is_token(name)) {
                /* @todo: reject headers defined in draft-16 8.1.2.2 */
                aura_add_header(conn->mc, res_hdrs, &nv);
            }
        }
    } while (src != end);

    if (error)
        return error;

    return HPACK_OK;
}

/**
 * Determines if value can be packed in a single byte
 */
static inline bool value_is_one_byte(int64_t value, uint32_t prefix_bits) {
    size_t n;

    n = (uint8_t)(1 << prefix_bits) - 1;
    return value < n;
}

size_t hpack_encode_int(uint8_t *dest, int64_t value, uint32_t prefix_bits) {
    uint8_t *start;

    if (value_is_one_byte(value, prefix_bits)) {
        *dest |= value;
        return 1;
    }

    start = dest;
    A_BUG_ON_2(value < 0, true);
    *dest++ |= (uint8_t)(1 << prefix_bits) - 1;
    value -= (uint8_t)(1 << prefix_bits) - 1;
    for (; value >= 128; value >>= 7)
        *dest++ = (uint8_t)(0x80 | value);
    *dest++ = (uint8_t)value;
    return dest - start;
}

/**
 *
 */
bool hpack_encode_huffman(uint8_t *dest, const uint8_t *src, size_t len) {
    const nghttp2_huff_sym *sym;
    const uint8_t *src_end;
    uint8_t *dest_start, *dest_end;
    uint64_t bits = 0;
    int bits_left = 40; /* pack encoded bits, move to dest in byte chunks */

    src_end = src + len;
    dest_start = dest;
    dest_end = dest + len;
    while (src != src_end) {
        sym = huff_sym_table + *src++;
        bits |= (uint64_t)sym->code << (bits_left - sym->nbits);
        bits_left -= sym->nbits;

        while (bits_left <= 32) {
            *dest_start++ = bits >> 32;
            bits <<= 8;
            bits_left += 8;
            if (dest_start == dest_end)
                return false;
        }
    }

    if (bits_left != 40) {
        bits |= ((uint64_t)1 << bits_left) - 1;
        *dest_start++ = bits >> 32;
    }

    if (dest_start == dest_end)
        return false;

    return true;
}

/**
 * encode raw octets without huffman encoding
 */
static inline size_t encode_as_original(uint8_t *dest, const char *s, size_t len) {
    uint8_t *start = dest;
    *dest = '\0';
    dest += hpack_encode_int(dest, len, 7);
    memcpy(dest, s, len);
    dest += len;
    return dest - start;
}

/**
 * Calculate the length consumed by huffman for
 * this given string and len
 */
size_t aura_hd_huff_encode_len(const uint8_t *src, size_t len) {
    size_t i;
    size_t nbits = 0;

    for (i = 0; i < len; ++i) {
        nbits += huff_sym_table[src[i]].nbits;
    }
    /* pad the prefix of EOS (256) */
    return (nbits + 7) / 8;
}

/**
 * Encode string
 */
size_t hpack_encode_string(uint8_t *dest, const char *s, size_t len) {
    size_t huff_len, head_len;
    uint8_t head[8];
    bool can_huffman, res;

    can_huffman = false;
    huff_len = aura_hd_huff_encode_len(s, len);
    if (huff_len < len)
        can_huffman = true;

    if (can_huffman) {
        res = hpack_encode_huffman(dest + 1, (uint8_t *)s, len);

        if (res == true) {
            if (likely(value_is_one_byte(huff_len, 7))) {
                *dest = (uint8_t)(0x80 | huff_len);
                head_len = 1;
            } else {
                head[0] = 1 << 7; // '\x80';                               /* indicate huffman encoded */
                head_len = hpack_encode_int(head, huff_len, 7);
                memmove(dest + head_len, dest + 1, huff_len); /* copy encoded string */
                memcpy(dest, head, head_len);                 /* copy length */
            }
            return head_len + huff_len;
        }
    }

    /* fallback */
    return encode_as_original(dest, s, len);
}

uint8_t *header_table_adjust_size(struct aura_hpack_hdr_table *tb, uint32_t new_cap, uint8_t *dest) {
    /**
     * Do nothing if user-supplied value is greater that the current value.
     * We do not allow the peer to increase the memory limit
     */
    if (new_cap >= tb->max_dynamic_size)
        return dest;

    tb->max_dynamic_size = new_cap;
    /* excess header fields are evicted until we have space hold current fields */
    while (tb->num_of_entries != 0 && tb->table_size > tb->max_dynamic_size)
        hpack_header_table_evict_one(tb);

    /* Encode dynamic table size pattern: | 0 | 0 | 1 | max_size(5+) | */
    *dest = 0x20;
    dest += hpack_encode_int(dest, tb->max_dynamic_size, 5);
    return dest;
}

static void hpack_search_static_table(int token, struct aura_hdr_nv *nv, bool name_only, bool *exact_match) {
    struct aura_hpack_static_table_entry *entry;
    size_t n;

    entry = hpack_static_header_table_get(token);
    if (!entry)
        return;

    nv->name = &entry->name;
    nv->index = entry->index;
    if (name_only)
        return;

    if (aura_mem_is_eq(nv->value->base, nv->value->len, entry->value.base, entry->value.len)) {
        *exact_match = true;
    }
}

/**
 * Some semi-naive way of determining binary format
 */
static hpack_binary_format_rep determine_encode_binary_format(struct aura_hpack_hdr_table *tb,
                                                              struct aura_hdr_nv *nv) {
    struct aura_hdr_nv *tb_entry, *new_tb_entry;
    size_t index, n;
    bool is_exact_match;
    bool is_token;

    is_exact_match = false;
    if (nv->token >= 0 && nv->token <= A_TOKEN_WWW_AUTHENTICATE) {
        hpack_search_static_table(nv->token, nv, false, &is_exact_match);
    } else {
        for (int i = 0; i < tb->num_of_entries; ++i) {
            tb_entry = tb->entries + i;
            if (!aura_mem_is_eq(nv->name->base, nv->name->len, tb_entry->name->base, tb_entry->name->len))
                continue;
            if (nv->index == 0)
                /* try to get index in dynamic table */
                nv->index = i + A_HEADER_DYNAMIC_TABLE_OFFSET;

            /* name matched, check value */
            if (!aura_mem_is_eq(nv->value->base, nv->value->len, tb_entry->value->base, tb_entry->value->len))
                continue;
            /* name and value matched */
            is_exact_match = true;
        }
    }

    if (is_exact_match) {
        return HPACK_INDEXED_HDR_FIELD;
    }

    if (nv->index != 0) {
        if (nv->token == A_TOKEN_AUTHORIZATION || nv->flags & AURA_TOKEN_NO_COMPRESS) {
            return HPACK_LITERAL_HDR_FIELD_NEVER_INDEXED_INDEXED_NAME;
        }

        if (nv->token == A_TOKEN_LOCATION || nv->token == A_TOKEN_CONTENT_LENGTH)
            return HPACK_LITERAL_HDR_FIELD_WITHOUT_INDEXING_INDEXED_NAME;

        return HPACK_LITERAL_HDR_FIELD_INCR_INDEXING_INDEXED_NAME;
    } else {
        return HPACK_LITERAL_HDR_FIELD_INCR_INDEXING_NEW_NAME;
    }
}

/**
 * Encode new value and add to the dynamic header table
 */
static size_t hpack_encode_new_entry(struct aura_memory_ctx *mc, struct aura_hpack_hdr_table *tb,
                                     uint8_t *dest, struct aura_hdr_nv *nv) {
    size_t len;
    struct aura_hdr_nv *new_tb_entry;
    bool is_token;

    is_token = nv->token >= 0 && nv->token <= A_TOKEN_WWW_AUTHENTICATE;
    len = hpack_encode_string(dest, nv->value->base, nv->value->len);
    new_tb_entry = header_table_add(mc, tb, nv->name->len + nv->value->len + A_HEADER_TABLE_ENTRY_OVERHEAD, 32);
    if (new_tb_entry != NULL) {
        if (is_token)
            new_tb_entry->name = nv->name;
        else {
            new_tb_entry->name = aura_iovec_init(mc, nv->name->len + 1);
            new_tb_entry->name->base[nv->name->len] = '\0';
            memcpy(new_tb_entry->name->base, nv->name->base, nv->name->len);
        }
        new_tb_entry->value = aura_iovec_init(mc, nv->value->len + 1);
        new_tb_entry->value->base[nv->value->len] = '\0';
        memcpy(new_tb_entry->value->base, nv->value->base, nv->value->len);
    }

    return len;
}

/**
 *
 */
static uint8_t *_encode_header(struct aura_memory_ctx *mc, struct aura_hpack_hdr_table *tb, uint8_t *dest,
                               int32_t token, struct aura_iovec *name, struct aura_iovec *value) {
    hpack_binary_format_rep binary_format;
    struct aura_hdr_nv nv = {.name = name, .value = value, .token = token};

    binary_format = determine_encode_binary_format(tb, &nv);
    switch (binary_format) {
    case HPACK_INDEXED_HDR_FIELD:
        *dest = 0x80u;
        dest += hpack_encode_int(dest, nv.index, 7);
        break;

    case HPACK_LITERAL_HDR_FIELD_NEVER_INDEXED_INDEXED_NAME:
    case HPACK_LITERAL_HDR_FIELD_WITHOUT_INDEXING_INDEXED_NAME:
        *dest = 0x10u;
        dest += hpack_encode_int(dest, nv.index, 4);
        dest += encode_as_original(dest, nv.value->base, nv.value->len);
        break;

    case HPACK_LITERAL_HDR_FIELD_INCR_INDEXING_INDEXED_NAME:
        // app_debug(true, 0, "HPACK_LITERAL_HDR_FIELD_INCR_INDEXING_INDEXED_NAME: index: %d", nv.index);
        *dest = 0x40u;
        dest += hpack_encode_int(dest, nv.index, 6);
        dest += hpack_encode_new_entry(mc, tb, dest, &nv);
        break;

    default:
        *dest++ = 0x40u;
        dest += hpack_encode_string(dest, nv.name->base, nv.name->len);
        dest += hpack_encode_new_entry(mc, tb, dest, &nv);
        break;
    }

    return dest;
}

uint8_t *encode_header(struct aura_memory_ctx *mc, struct aura_hpack_hdr_table *tb,
                       uint8_t *dest, struct aura_http_hdr_set *hdr) {
    int token;

    token = lookup_token(hdr->name->base, hdr->name->len);
    return _encode_header(mc, tb, dest, token, hdr->name, hdr->value);
}

/**
 *
 */
static uint8_t *encode_method(struct aura_memory_ctx *mc, struct aura_hpack_hdr_table *tb,
                              uint8_t *dest, struct aura_iovec value) {
    if (aura_mem_is_eq(value.base, value.len, str_lit("GET"))) {
        /* direct static table */
        *dest++ = 0x82;
        return dest;
    }

    if (aura_mem_is_eq(value.base, value.len, str_lit("POST"))) {
        /* direct static table */
        *dest++ = 0x83;
        return dest;
    }

    return _encode_header(mc, tb, dest, A_TOKEN_METHOD, NULL, &value);
}

/**
 *
 */
static uint8_t *encode_scheme(struct aura_memory_ctx *mc, struct aura_hpack_hdr_table *tb,
                              uint8_t *dest, struct aura_iovec *scheme) {
    //     *dest++ = 0x87; /* from hpack static table */

    //     *dest++ = 0x86; /* from hpack static table */
}

/**
 *
 */
static uint8_t *encode_path(struct aura_memory_ctx *mc, struct aura_hpack_hdr_table *tb,
                            uint8_t *dest, struct aura_iovec value) {
    if (aura_mem_is_eq(value.base, value.len, str_lit("/"))) {
        *dest++ = 0x84; /* from hpack static table */
        return dest;
    }

    if (aura_mem_is_eq(value.base, value.len, str_lit("/index.html"))) {
        *dest++ = 0x85; /* from hpack static table */
        return dest;
    }

    return _encode_header(mc, tb, dest, A_TOKEN_PATH, NULL, &value);
}

/**
 *
 */
static uint8_t *encode_literal_header_without_indexing(uint8_t *dest, const struct aura_iovec *name, const struct aura_iovec *value) {
    /* Literal header without indexing, pattern: | 0: | */
    *dest++ = 0;
    dest += hpack_encode_string(dest, name->base, name->len);
    dest += hpack_encode_string(dest, value->base, value->len);
    return dest;
}

size_t hpack_stream_produce_data(struct aura_memory_ctx *mc, struct aura_h2_stream *stream,
                                 const uint8_t *data, size_t len, uint8_t flags, bool end_stream) {
    struct aura_h2_out_frame *out_frame;
    size_t remaining, chunk;
    size_t offset;

    remaining = len;
    offset = 0;

    while (remaining > 0) {
        chunk = remaining > stream->conn->peer_settings.max_frame_size ? stream->conn->peer_settings.max_frame_size : remaining;
        out_frame = aura_encode_data_frame(
          mc,
          &stream->data, stream->stream_id,
          end_stream && (remaining == chunk) ? A_H2_FRAME_FLAG_END_STREAM : 0,
          data + offset, chunk, 0);

        /* add to stream outbound queue */
        /* schedule on connection data frame */

        offset += chunk;
        remaining -= chunk;
    }

    return len - remaining;
}
