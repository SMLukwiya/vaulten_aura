#include "h2/hpack_srv.h"
#include "bug_lib.h"
#include "h2/h2_srv.h"
#include "h2/hpack_huffman_tb_srv.h"
#include "h2/stream.h"
#include "memory_lib.h"
#include "server_srv.h"
#include "slab_lib.h"
#include "string_lib.h"
#include "token_srv.h"
#include "utils_lib.h"

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
 * Decode and extract integer into @out
 */
static int a_hpack_decode_integer(const uint8_t **src, const uint8_t *src_end, uint8_t prefix_bits, int64_t *out) {
    uint64_t value;
    int32_t shift;
    uint8_t prefix_max, curr;

    if (prefix_bits < A_MIN_PREFIX_BITS || prefix_bits > A_MAX_PREFIX_BITS)
        return A_HPACK_PROTOCOL_ERR;

    if (*src >= src_end)
        return A_HPACK_COMPRESSION_ERR;

    prefix_max = (uint8_t)((1u << prefix_bits) - 1u);
    curr = **src;
    value = curr & prefix_max;
    (*src)++;
    /* value can fit in the prefix max */
    if (value < prefix_max) {
        *out = (int64_t)value;
        return A_HPACK_OK;
    }

    /* decode upto 8 octets(64 bits, excluding prefix), that is guaranteed not to cause overflow */
    shift = 0;
    while (true) {
        if (*src == src_end)
            return A_HPACK_COMPRESSION_ERR;

        curr = **src;
        (*src)++;

        /* check overflow */
        if (shift >= 56)
            return A_HPACK_COMPRESSION_ERR;

        value += (int64_t)(curr & 127) << shift;
        /* check if this is the last valid byte */
        if ((curr & 128) == 0)
            break;
        shift += 7;
    }
    *out = value;
    return A_HPACK_OK;
}

/**
 * Decodes huffman encoded string,
 * Return the string len on success
 * otherwise returns SIZE_MAX if hard fail
 */
/**
 * Decodes huffman encoded string,
 */
static int a_hpack_decode_huffman(char *dest, const uint8_t *src, size_t len, bool value_is_name, size_t *consumed) {
    char *ptr;
    const uint8_t *src_end;
    uint8_t ch, char_errs = 0;
    const nghttp2_huff_decode e = {0, 0x00, 0}, *entry = &e;

    if (value_is_name && len == 0)
        return A_HPACK_INVALID_NAME_ERR;

    ptr = dest;
    src_end = src + len;
    for (; src < src_end; ++src) {
        ch = *src;
        entry = huff_decode_table[entry->state] + (ch >> 4);
        if (entry->flags & NGHTTP2_HUFF_SYM) {
            *ptr++ = entry->sym;
            char_errs |= (entry->flags & NGHTTP2_HUFF_INVALID_CHARS);
        }
        entry = huff_decode_table[entry->state] + (ch & 0xf);
        if (entry->flags & NGHTTP2_HUFF_SYM) {
            *ptr++ = entry->sym;
            char_errs |= (entry->flags & NGHTTP2_HUFF_INVALID_CHARS);
        }
    }

    if (!(entry->flags & NGHTTP2_HUFF_ACCEPTED))
        return A_HPACK_COMPRESSION_ERR;

    /* validate */
    if (value_is_name) {
        /* pseudo-headers are checked later in 'decode_header' */
        if (!aura_hpack_is_pseudo_header(dest) && (char_errs & NGHTTP2_HUFF_INVALID_FOR_HEADER_NAME) != 0) {
            if ((char_errs & NGHTTP2_HUFF_UPPER_CASE_CHAR) != 0) {
                return A_HPACK_PROTOCOL_ERR;
            }
            return A_HPACK_INVALID_NAME_ERR;
        }
    } else if ((char_errs & NGHTTP2_HUFF_INVALID_FOR_HEADER_VALUE) != 0 || !aura_hpack_header_value_valid(dest, ptr - dest))
        return A_HPACK_INVALID_VALUE_ERR;

    *consumed = ptr - dest;
    return A_HPACK_OK;
}

// static bool a_hpack_validate_header_name(const uint8_t *src, size_t len, int *err) {
static int a_hpack_validate_header_name(const uint8_t *src, size_t len) {
    uint8_t ch;

    /* all printable chars, except upper case and separator characters */
    static const char valid_h2_header_name_char[] = {
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0, /* 0-31 */
      0,
      1,
      0,
      1,
      1,
      1,
      1,
      1,
      0,
      0,
      1,
      1,
      0,
      1,
      1,
      0,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      0,
      0,
      0,
      0,
      0,
      0, /* 32-63 */
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      1,
      1, /* 64-95 */
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      0,
      1,
      0,
      1,
      0, /*  96-127 */
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0, /* 128-159 */
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0, /* 160-191 */
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0, /* 192-223 */
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0, /* 224-255 */
    };

    if (len == 0)
        return A_HPACK_INVALID_NAME_ERR;
    else {
        for (; len != 0; ++src, --len) {
            ch = *src;
            if (valid_h2_header_name_char[ch] == 0) {
                if (isupper(ch)) {
                    return A_HPACK_INVALID_NAME_ERR;
                }
            }
        }
    }
    return A_HPACK_OK;
}

/**
 *
 */
// static void a_hpack_validate_header_value(const uint8_t *src, size_t len, int *err) {
static int a_hpack_validate_header_value(const uint8_t *src, size_t len) {
    uint8_t ch;

    /* surrounding whitespaces RFC 9113 8.2.1 */
    if (!aura_hpack_header_value_valid(src, len))
        goto invalid;

    /* all printable chars + horizontal tab (RFC 7230 3.2) */
    static const char valid_h2_field_value_char[] = {
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      1,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0,
      0, /*    0-31 */
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1, /*   32-63 */
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1, /*   64-95 */
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      0, /*  96-127 */
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1, /* 128-159 */
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1, /* 160-191 */
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1, /* 192-223 */
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1,
      1, /* 224-255 */
    };

    for (; len != 0; ++src, --len) {
        ch = *src;
        if (!valid_h2_field_value_char[ch])
            goto invalid;
    }
    return A_HPACK_OK;

invalid:
    return A_HPACK_INVALID_VALUE_ERR;
}

/** */
static int a_hpack_decode_string(struct aura_memory_ctx *mc, const uint8_t **src, const uint8_t *src_end,
                                 struct aura_iovec **str, bool value_is_name) {
    bool is_huffman;
    int64_t len, consumed;
    int ret;

    if (*src >= src_end)
        return A_HPACK_COMPRESSION_ERR;

    /* huffman flag (MSB == 1) */
    is_huffman = (**src & 0x80) != 0;

    ret = a_hpack_decode_integer(src, src_end, 7, &len);
    if (ret != A_HPACK_OK)
        return ret;

    if (is_huffman) {
        if (len > src_end - *src)
            return A_HPACK_COMPRESSION_ERR;

        *str = aura_iovec_init(mc, len * 2, NULL); /* huffman max compression ratio is >= 0.5 */
        if (!(*str))
            return A_HPACK_PROTOCOL_ERR;
        ret = a_hpack_decode_huffman((*str)->base, *src, len, value_is_name, &(*str)->len);
        if (ret != A_HPACK_OK) {
            aura_iovec_destroy(*str);
            return ret;
        }

        (*str)->base[(*str)->len] = '\0';
    } else {
        if (len > src_end - *src)
            return A_HPACK_COMPRESSION_ERR;

        if (value_is_name) {
            if (len == 0)
                return A_HPACK_COMPRESSION_ERR;
            /* pseudo-headers are checked later in 'decode_header' */
            if (!aura_hpack_is_pseudo_header((void *)*src) && (ret = a_hpack_validate_header_name(*src, len)) != A_HPACK_OK)
                return ret;
        } else {
            ret = a_hpack_validate_header_value((char *)*src, len);
            if (ret != A_HPACK_OK)
                return ret;
        }

        *str = aura_iovec_init(mc, len, NULL);
        if (!(*str))
            return A_HPACK_PROTOCOL_ERR;
        memcpy((*str)->base, *src, len);
        (*str)->base[len] = '\0';
    }
    *src += len;
    return A_HPACK_OK;
}

static struct aura_hpack_table_entry *a_dyn_header_table_get_new_slot(struct aura_memory_ctx *mc, struct aura_hpack_dyn_table *tb,
                                                                      size_t add, size_t max_num_entries) {
    struct aura_hpack_table_entry *old_entries;
    size_t old_cap;

    app_debug(true, 0, "a_dyn_header_table_get_new_slot << A");
    /* adjust size */
    while (tb->cnt > max_num_entries || (tb->cnt != 0 && tb->tab_size + add > tb->max_size))
        aura_hpack_header_table_evict_one(tb);

    if (tb->cnt == 0) {
        A_BUG_ON_2(tb->tab_size != 0, true);
        if (add > tb->max_size)
            return NULL;
    }

    old_entries = tb->entries;
    old_cap = tb->cap;
    /* grow the entries if full */
    if (tb->cnt >= tb->cap) {
        tb->cap = tb->cap < 16 ? 16 : tb->cap * 2;
        tb->entries = aura_realloc(mc, tb->entries, sizeof(*tb->entries) * tb->cap);
        if (tb->entries == NULL) {
            tb->entries = old_entries;
            tb->cap = old_cap;
            return NULL;
        }
    }

    memmove(&tb->entries[1], &tb->entries[0], tb->cnt * sizeof(*tb->entries));
    tb->tab_size += add;
    tb->cnt++;
    return tb->entries;
}

static inline int a_hpack_get_binary_format(uint8_t c) {
    if (0x80u & c)
        return A_HPACK_INDEXED_HDR_FIELD;
    else if (c >= 64) {
        if (0x3f & c)
            return A_HPACK_LITERAL_HDR_FIELD_INCR_INDEXING_INDEXED_NAME;
        else
            return A_HPACK_LITERAL_HDR_FIELD_INCR_INDEXING_NEW_NAME;
    } else if ((0xe0u & c) == 0x20u)
        return A_HPACK_DYNAMIC_TABLE_SIZE_UPDATE;
    else if (c >= 16) {
        if (0x0f & c)
            return A_HPACK_LITERAL_HDR_FIELD_NEVER_INDEXED_INDEXED_NAME;
        else
            return A_HPACK_LITERAL_HDR_FIELD_NEVER_INDEXED_NEW_NAME;
    } else {
        if (c > 0)
            return A_HPACK_LITERAL_HDR_FIELD_WITHOUT_INDEXING_INDEXED_NAME;
        else
            return A_HPACK_LITERAL_HDR_FIELD_WITHOUT_INDEXING_NEW_NAME;
    }
}

static inline struct aura_hpack_table_entry *a_get_static_tab_entry(struct aura_hpack_static_table *static_tab, size_t idx) {
    return &static_tab->entries[idx];
}

static int a_hpack_decode_header(struct aura_memory_ctx *mc, struct aura_hpack_static_table *static_tab,
                                 struct aura_hpack_dyn_table *dyn_tab, struct aura_intern_tab *intern_tab,
                                 struct aura_hpack_table_entry *nv, const uint8_t **const src, const uint8_t *src_end) {
    struct aura_hpack_table_entry *entry;
    struct aura_interned_str *name, *value;
    struct aura_iovec *str_name, *str_val;
    bool name_is_indexed, value_is_indexed, insert_new_entry;
    int64_t index, new_cap;
    int32_t prefix_len, token;
    int ret, binary_format, err;

    index = 0;
    prefix_len = -1;
    name_is_indexed = false;
    value_is_indexed = false;
    insert_new_entry = false;
    name = NULL;
    value = NULL;
    for (; *src < src_end;) {
        /* determine the encoding format */
        binary_format = a_hpack_get_binary_format(**src);

        switch (binary_format) {
        case A_HPACK_INDEXED_HDR_FIELD:
            prefix_len = 7;
            name_is_indexed = true;
            value_is_indexed = true;
            break;

        case A_HPACK_LITERAL_HDR_FIELD_INCR_INDEXING_INDEXED_NAME:
            prefix_len = 6;
            name_is_indexed = true;
            insert_new_entry = true;
            break;

        case A_HPACK_LITERAL_HDR_FIELD_INCR_INDEXING_NEW_NAME:
        case A_HPACK_LITERAL_HDR_FIELD_NEVER_INDEXED_NEW_NAME:
        case A_HPACK_LITERAL_HDR_FIELD_WITHOUT_INDEXING_NEW_NAME:
            (*src)++;
            break;

        case A_HPACK_LITERAL_HDR_FIELD_NEVER_INDEXED_INDEXED_NAME:
        case A_HPACK_LITERAL_HDR_FIELD_WITHOUT_INDEXING_INDEXED_NAME:
            prefix_len = 4;
            name_is_indexed = true;
            break;

        case A_HPACK_DYNAMIC_TABLE_SIZE_UPDATE:
            err = a_hpack_decode_integer(src, src_end, 5, &new_cap);
            if (err != A_HPACK_OK) {
                return err;
            }

            if (new_cap > dyn_tab->max_size) {
                return A_HPACK_COMPRESSION_ERR;
            }

            dyn_tab->max_size = (size_t)new_cap;
            while (dyn_tab->cnt != 0 && dyn_tab->tab_size > dyn_tab->max_size)
                aura_hpack_header_table_evict_one(dyn_tab);
            continue; /** @todo: test how switch behaves inside for loop with 'continue' */
        default:
            /* protocol error */
            return A_HPACK_PROTOCOL_ERR;
        }

        if (name_is_indexed) {
            err = a_hpack_decode_integer(src, src_end, prefix_len, &index);
            if (err != A_HPACK_OK) {
                return err;
            }

            if (aura_hpack_tab_index_invalid(dyn_tab, index)) {
                return A_HPACK_COMPRESSION_ERR;
            }

            if (index < A_DYNAMIC_TABLE_HEADER_OFFSET) {
                entry = a_get_static_tab_entry(static_tab, index);
            } else {
                entry = aura_hpack_dyn_header_tab_get_entry(dyn_tab, index);
            }

            if (!entry) {
                return A_HPACK_PROTOCOL_ERR;
            }

            /* all names guaranteed to be interned */
            nv->header_field->name.interned = entry->header_field->name.interned;
            nv->header_field->token = entry->header_field->token;
            nv->header_field->name_interned = true;
            nv->index = index;

            if (value_is_indexed) {
                if (entry->header_field->value_interned) {
                    nv->header_field->value.interned = entry->header_field->value.interned;
                    nv->header_field->value_interned = true;
                } else {
                    nv->header_field->value.raw = entry->header_field->value.raw;
                    nv->header_field->value.raw.ref_cnt++;
                }
            } else {
                ret = a_hpack_decode_string(mc, src, src_end, &str_val, false);
                if (ret != A_HPACK_OK) { /** @todo: if error is soft, continue and send rst_stream after (but if we need to add to dynamic table, upgrade to connection error) */
                    return ret;
                }

                /** @todo: some values do not need to be interned (look into that) */
                value = aura_interned_str_find_or_add(intern_tab, str_val->base, str_val->len);
                if (value) {
                    /* switch to interned value */
                    nv->header_field->value.interned = value;
                    nv->header_field->value_interned = true;
                    aura_iovec_destroy(str_val);
                } else {
                    /* fallback to raw string */
                    nv->header_field->value.raw.str = str_val;
                    nv->header_field->value_interned = false;
                    /* No one yet have reference to raw string just created */
                    nv->header_field->value.raw.ref_cnt = 0;
                }
            }
        } else {
            ret = a_hpack_decode_string(mc, src, src_end, &str_name, true);
            if (ret != A_HPACK_OK) {
                return ret;
            }
            name = aura_interned_str_find_or_add(intern_tab, str_name->base, str_name->len);
            /* intern all names */
            if (!name) {
                return A_HPACK_INTERNAL_ERR;
            }

            nv->header_field->name.interned = name;
            nv->header_field->name_interned = true;
            aura_iovec_destroy(str_name);

            ret = a_hpack_decode_string(mc, src, src_end, &str_val, false);
            if (ret != A_HPACK_OK) {
                aura_iovec_destroy(str_name);
                return ret;
            }
            /** @todo: some values do not need to be interned (look into that) */
            value = aura_interned_str_find_or_add(intern_tab, str_val->base, str_val->len);
            if (value) {
                /* switch to interned value  */
                nv->header_field->value.interned = value;
                nv->header_field->value_interned = true;
                aura_iovec_destroy(str_val);
            } else {
                /* fallback to raw string */
                nv->header_field->value.raw.str = str_val;
                nv->header_field->value_interned = false;
                /* No one yet have reference to raw string just created */
                nv->header_field->value.raw.ref_cnt = 0;
            }

            token = lookup_token(name->data, name->len);
            nv->header_field->token = token;
            nv->index = -1;
        }

        /* add to dynamic table */
        if (insert_new_entry) {
            size_t name_len, value_len;
            name_len = nv->header_field->name.interned->len;
            if (nv->header_field->value.interned) {
                value_len = nv->header_field->value.interned->len;
            } else {
                value_len = nv->header_field->value.raw.str->len;
            }

            struct aura_hpack_table_entry *entry_slot = a_dyn_header_table_get_new_slot(mc, dyn_tab, name_len + value_len + A_HEADER_TABLE_ENTRY_OVERHEAD, 128);
            if (entry_slot) {
                entry_slot->header_field = aura_alloc(mc, sizeof(*entry_slot->header_field));
                if (!entry_slot->header_field)
                    return A_HPACK_INTERNAL_ERR;
                /* name always interned */
                entry_slot->header_field->name.interned = nv->header_field->name.interned;
                entry_slot->header_field->name_interned = true;

                if (nv->header_field->value.interned) {
                    entry_slot->header_field->value.interned = nv->header_field->value.interned;
                    entry_slot->header_field->value_interned = true;
                } else {
                    entry_slot->header_field->value.raw = nv->header_field->value.raw;
                    entry_slot->header_field->value_interned = false;
                    entry_slot->header_field->value.raw.ref_cnt++;
                }
                entry_slot->header_field->token = nv->header_field->token;
            }
        }

        return A_HPACK_OK;
    }
    return A_HPACK_OK;
}

uint8_t *aura_encode_status(uint8_t *dest, int status) {
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

uint8_t *aura_encode_content_length(uint8_t *dest, size_t value) {
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

void aura_hpack_header_tab_dispose(struct aura_hpack_dyn_table *hdr_tb) {
    struct aura_hpack_table_entry *entry;
    size_t idx;

    if (hdr_tb->cnt > 0) {
        idx = 0;
        do {
            entry = &hdr_tb->entries[idx];

            if (!entry->header_field->value_interned)
                aura_iovec_destroy(entry->header_field->value.raw.str);

            idx = (idx + 1) % hdr_tb->cap;
        } while (--hdr_tb->cnt > 0);
    }
    aura_free(hdr_tb->entries);
}

int aura_hpack_parse_request(struct aura_h2_ctx *h2_ctx, struct aura_h2_stream *stream,
                             const uint8_t *src, size_t len, hpack_header_cb cb[]) {
    struct aura_hpack_table_entry entry;
    struct aura_header_field header_field;
    const uint8_t *end;
    const char *decode_err;
    uint64_t content_length;
    struct aura_hpack_dyn_table *inbound_hdr_tb;
    struct aura_header_vector *req_hdrs;
    const char *name, *value;
    int error = 0;
    size_t name_len, value_len;
    int res, ret_val;
    app_debug(true, 0, "aura_hpack_parse_request <<<<");

    end = src + len;
    content_length = SIZE_MAX;
    inbound_hdr_tb = &h2_ctx->input_hdr_table;
    req_hdrs = &stream->req.headers;
    h2_ctx->conn->srv_ctx;
    entry.header_field = &header_field;
    ret_val = A_HPACK_OK;

    while (src != end) {
        memset(entry.header_field, 0, sizeof(*entry.header_field));
        decode_err = NULL;
        error = a_hpack_decode_header(h2_ctx->conn->mc, &h2_ctx->conn->srv_ctx->static_tab, inbound_hdr_tb, h2_ctx->intern_tab, &entry, &src, end);
        if (error == A_HPACK_INVALID_NAME_ERR) {
            /* this is a soft error, we continue parsing, but register only  the first error */
        } else if (error != A_HPACK_OK) {
            ret_val = error;
            goto err;
        }

        /* name always interned */
        name = entry.header_field->name.interned->data;
        name_len = entry.header_field->name.interned->len;

        if (entry.header_field->value_interned) {
            value = entry.header_field->value.interned->data;
            value_len = entry.header_field->value.interned->len;
        } else {
            value = entry.header_field->value.raw.str->base;
            value_len = entry.header_field->value.raw.str->len;
        }

        if (aura_hpack_is_pseudo_header(name)) {
            switch (entry.header_field->token) {
            case A_TOKEN_AUTHORITY:
                res = cb[A_HPACK_AUTHORITY_CB](h2_ctx, stream, name, name_len, value, value_len);
                if (res != A_HPACK_OK) {
                    ret_val = res;
                    goto err;
                }
                break;

            case A_TOKEN_METHOD:
                res = cb[A_HPACK_METHOD_CB](h2_ctx, stream, name, name_len, value, value_len);
                if (res != A_HPACK_OK) {
                    ret_val = res;
                    goto err;
                }
                break;

            case A_TOKEN_PATH:
                res = cb[A_HPACK_PATH_CB](h2_ctx, stream, name, name_len, value, value_len);
                if (res != A_HPACK_OK) {
                    ret_val = res;
                    goto err;
                }
                break;

            case A_TOKEN_SCHEME:
                res = cb[A_HPACK_SCHEME_CB](h2_ctx, stream, name, name_len, value, value_len);
                if (res != A_HPACK_OK) {
                    ret_val = res;
                    goto err;
                }
                break;

            case A_TOKEN_STATUS:
                res = cb[A_HPACK_STATUS_CB](h2_ctx, stream, name, name_len, value, value_len);
                if (res != A_HPACK_OK) {
                    ret_val = res;
                    goto err;
                }
                break;

            default:
                /* Unknown pseudo header */
                ret_val = A_HPACK_PROTOCOL_ERR;
                goto err;
            }
        } else {
            switch (entry.header_field->token) {
            case A_TOKEN_CONTENT_LENGTH:
                res = cb[A_HPACK_METHOD_CB](h2_ctx, stream, name, name_len, value, value_len);
                if (res != A_HPACK_OK) {
                    ret_val = res;
                    goto err;
                }
                break;

            case A_TOKEN_EXPECT:
            case A_TOKEN_PRIORITY:
            case A_TOKEN_ACCEPT:
            case A_TOKEN_ACCEPT_ENCODING:
            case A_TOKEN_USER_AGENT:
                break;

            case A_TOKEN_HOST:
                /* HTTP2 allows the use of host header (in place of :authority) */
                res = cb[A_HPACK_AUTHORITY_CB](h2_ctx, stream, name, name_len, value, value_len);
                if (res != A_HPACK_OK) {
                    ret_val = res;
                    goto err;
                }
                break;

            case A_TOKEN_TE:
                if (aura_lc_str_is_eq(value, value_len, str_lit("trailers"))) {
                    /**/
                }
                break;

            default:
                /* rest of the header fields that are marked as special are rejected */
                app_debug(true, 0, "hpack unknown special header: %s (ignore)", name);
                ret_val = A_HPACK_PROTOCOL_ERR;
                goto err;
            }
            // aura_add_header(h2_ctx->conn->mc, req_hdrs, entry.header_field);
            aura_add_header(h2_ctx->conn->mc, req_hdrs, entry.header_field);
        }
    }

    goto out;
err:
    /* if raw string, destroy(no one should have reference to it at this point anyway) */
    if (!entry.header_field->value_interned)
        if (entry.header_field->value.raw.str)
            aura_iovec_destroy(entry.header_field->value.raw.str);

out:
    app_debug(true, 0, "DONE WITH HEADER, MOVING ON!!!: ret_val: %d", ret_val);
    return ret_val;
}

struct aura_header_field *aura_header_find_or_create(struct aura_memory_ctx *mc, struct aura_hpack_static_table *static_tab,
                                                     struct aura_hpack_dyn_table *dyn_tab, struct aura_intern_tab *intern_tab,
                                                     char *name, size_t name_len, char *val, size_t val_len) {
    struct aura_header_field *header_field;
    struct aura_hpack_table_entry *tb_entry;
    int token;
    bool name_match_found, value_match_found;

    if (name_len == 0)
        return NULL;

    header_field = aura_alloc(mc, sizeof(*header_field));
    if (!header_field)
        return NULL;
    memset(header_field, 0, sizeof(*header_field));

    token = lookup_token(name, name_len);
    name_match_found = false;
    value_match_found = false;
    /* static table entry */
    if (token > 0 && token <= A_TOKEN_WWW_AUTHENTICATE) {
        tb_entry = aura_hpack_static_tab_get_entry(static_tab, token);
        header_field->name.interned = tb_entry->header_field->name.interned;
        header_field->name_interned = tb_entry->header_field->name_interned;

        /* Confirm value match */
        for (int i = 0; i < ARRAY_SIZE(static_tab->entries); ++i) {
            tb_entry = &static_tab->entries[i];
            if (tb_entry->header_field->token == token) {
                if (tb_entry->header_field->value_interned) {
                    if (aura_mem_is_eq(val, val_len, tb_entry->header_field->value.interned->data, tb_entry->header_field->value.interned->len)) {
                        header_field->value.interned = tb_entry->header_field->value.interned;
                        header_field->value_interned = tb_entry->header_field->value_interned;
                        value_match_found = true;
                        break;
                    }
                } else {
                    // if (aura_mem_is_eq(val, val_len, tb_entry->header_field->value.raw->base, tb_entry->header_field->value.raw->len)) {
                    //     header_field->value.raw = aura_iovec_init(mc, val_len, NULL);
                    //     if (!header_field->value.raw) {
                    //         aura_header_field_destroy(header_field);
                    //         return NULL;
                    //     }
                    //     memcpy(header_field->value.raw->base, val, val_len);
                    //     // header->value.raw = tb_entry->header_field->value.raw;
                    //     header_field->value_interned = false;
                    //     value_match_found = true;
                    //     break;
                    // }
                }
            }
        }

        /* Create new value entry */
        if (!value_match_found) {
            header_field->value.interned = aura_interned_str_find_or_add(intern_tab, val, val_len);
            /* Fallback to raw string */
            if (!header_field->value.interned) {
                header_field->value.raw.str = aura_iovec_init(mc, val_len, NULL);
                if (!header_field->value.raw.str) {
                    aura_header_field_destroy(header_field);
                    return NULL;
                }
                memcpy(header_field->value.raw.str->base, val, val_len);
                header_field->value_interned = false;
                header_field->value.raw.ref_cnt = 1;
                return header_field;
            } else {
                header_field->value_interned = true;
                return header_field;
            }
        }
        return header_field;
    } else {
        for (int i = 0; i < dyn_tab->cap; ++i) {
            tb_entry = &dyn_tab->entries[i];

            // if (!name_match_found) {
            // if (tb_entry->header_field->name_interned) {
            if (!aura_mem_is_eq(name, name_len, tb_entry->header_field->name.interned->data, tb_entry->header_field->name.interned->len)) {
                continue;
            }
            header_field->name.interned = tb_entry->header_field->name.interned;
            header_field->name_interned = tb_entry->header_field->name_interned;
            name_match_found = true;
            // } else {
            // if (aura_mem_is_eq(name, name_len, tb_entry->header_field->name.raw->base, tb_entry->header_field->name.raw->len)) {
            //     header->name.raw = tb_entry->header_field->name.raw;
            //     header->name_interned = false;
            //     name_match_found = true;
            // }
            // }
            // }

            // if (!value_match_found) {
            if (tb_entry->header_field->value_interned) {
                if (aura_mem_is_eq(val, val_len, tb_entry->header_field->value.interned->data, tb_entry->header_field->value.interned->len)) {
                    header_field->value.interned = tb_entry->header_field->value.interned;
                    header_field->value_interned = tb_entry->header_field->value_interned;
                    value_match_found = true;
                    break;
                }
            } else {
                // if (aura_mem_is_eq(val, val_len, tb_entry->header_field->name.raw->base, tb_entry->header_field->name.raw->len)) {
                //     header->value.raw = tb_entry->header_field->value.raw;
                //     header->value_interned = false;
                //     value_match_found = true;
                // }
            }
            // }
        }

        /* name always interned */
        if (!name_match_found)
            return NULL;

        /* Create new name entry */
        // if (!name_match_found) {
        //     header_field->name.interned = aura_interned_str_find_or_add(intern_tab, name, name_len);
        //     /* Fallback to raw string */
        //     if (!header_field->name.interned) {
        //         header_field->name.raw = aura_iovec_init(mc, name_len, NULL);
        //         if (!header_field->name.raw) {
        //             aura_header_field_destroy(header_field);
        //             return NULL;
        //         }
        //         memcpy(header_field->name.raw->base, name, name_len);
        //         name_match_found = true;
        //         header_field->name_interned = false;
        //     } else {
        //         header_field->name_interned = true;
        //         name_match_found = true;
        //     }
        // }

        /* Create value entry */
        if (!value_match_found) {
            header_field->value.interned = aura_interned_str_find_or_add(intern_tab, name, name_len);
            /* Fallback to raw string */
            if (!header_field->value.interned) {
                header_field->value.raw.str = aura_iovec_init(mc, val_len, NULL);
                if (!header_field->value.raw.str) {
                    aura_header_field_destroy(header_field);
                    return NULL;
                }
                memcpy(header_field->value.raw.str->base, val, val_len);
                header_field->value_interned = false;
                header_field->value.raw.ref_cnt = 1;
            } else {
                header_field->value_interned = true;
            }
        }
        return header_field;
    }
}

int aura_hpack_parse_response(struct aura_h2_ctx *h2_ctx, struct aura_h2_stream *stream,
                              const uint8_t *src, size_t len, hpack_header_cb *cb, bool is_trailer) {
    struct aura_header_field *nv;
    const uint8_t *end;
    const char *decode_err = NULL;
    struct aura_token *token;
    struct aura_hpack_dyn_table *outbound_hdr_tb;
    struct aura_http_hdrs *res_hdrs;
    const char *name, *value;
    size_t name_len, value_len;
    int error;
    bool res;

    outbound_hdr_tb = &h2_ctx->output_hdr_table;
    // res_hdrs = &stream->res.headers;
    end = src + len;
    /* detect missing :status header as the first response */
    if (src == end) {
        return A_HPACK_PROTOCOL_ERR;
    }

    do {
        // error = a_hpack_decode_header(h2_ctx->conn->mc, outbound_hdr_tb, &nv, &src, end);
        // error = a_hpack_decode_header(h2_ctx->conn->mc, &h2_ctx->conn->srv_ctx->static_tab, outbound_hdr_tb, h2_ctx->intern_tab, &nv, &src, end);
        if (error == A_H2_ERROR_INVALID_HEADER_CHAR) {
            /* this is a soft error, we continue parsing, but register only the first error */
            // if (*err_desc == NULL)
            //     *err_desc = decode_err;
        } else {
            // *err_desc = decode_err;
            return error;
        }

        if (nv->name_interned) {
            name = nv->name.interned->data;
            name_len = nv->name.interned->len;
        } else {
            // name = nv->name.raw->base;
            // name_len = nv->name.raw->len;
        }

        if (nv->value_interned) {
            value = nv->value.interned->data;
            value_len = nv->value.interned->len;
        } else {
            value = nv->value.raw.str->base;
            value_len = nv->value.raw.str->len;
        }

        // if (nv.name->base[0] == ':') {
        if (aura_hpack_is_pseudo_header(name)) {
            /* Trailers must not include pseudo-header fields */
            if (is_trailer) {
                return A_HPACK_PROTOCOL_ERR;
            }

            // if (nv->token != A_TOKEN_STATUS) {
            //     return A_HPACK_PROTOCOL_ERR;
            // }

            // res = cb[A_HPACK_STATUS_CB](h2_ctx, stream, nv.name, nv.value);
            // if (res == A_HPACK_OK) {
            //     /**/
            // }
        } else {
            // if (aura_hpack_static_table_name_exists(name)) {
            //     /* @todo: reject headers defined in draft-16 8.1.2.2 */
            //     aura_add_header(h2_ctx->conn->mc, res_hdrs, &nv);
            // }
        }
    } while (src != end);

    if (error)
        return error;

    return A_HPACK_OK;
}

/**
 * Determines if value can be packed in a single byte
 */
static inline bool value_is_one_byte(int64_t value, uint32_t prefix_bits) {
    size_t n;

    n = (uint8_t)(1 << prefix_bits) - 1;
    return value < n;
}

size_t a_hpack_encode_int(uint8_t *dest, int64_t value, uint32_t prefix_bits) {
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
static inline size_t a_encode_as_original(uint8_t *dest, const char *s, size_t len) {
    uint8_t *start = dest;
    *dest = '\0';
    dest += a_hpack_encode_int(dest, len, 7);
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
size_t a_hpack_encode_string(uint8_t *dest, const char *s, size_t len) {
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
                head_len = a_hpack_encode_int(head, huff_len, 7);
                memmove(dest + head_len, dest + 1, huff_len); /* copy encoded string */
                memcpy(dest, head, head_len);                 /* copy length */
            }
            return head_len + huff_len;
        }
    }

    /* fallback */
    return a_encode_as_original(dest, s, len);
}

uint8_t *aura_header_table_adjust_size(struct aura_hpack_dyn_table *tb, uint32_t new_cap, uint8_t *dest) {
    /**
     * Do nothing if user-supplied value is greater that the current value.
     * We do not allow the peer to increase the memory limit
     */
    if (new_cap >= tb->max_size)
        return dest;

    tb->max_size = new_cap;
    /* excess header fields are evicted until we have space hold current fields */
    while (tb->cnt != 0 && tb->tab_size > tb->max_size)
        aura_hpack_header_table_evict_one(tb);

    /* Encode dynamic table size pattern: | 0 | 0 | 1 | max_size(5+) | */
    *dest = 0x20;
    dest += a_hpack_encode_int(dest, tb->max_size, 5);
    return dest;
}

static void a_hpack_search_static_table(struct aura_hpack_static_table *static_tab, struct aura_header_field *nv, bool *exact_match) {
    struct aura_hpack_table_entry *entry;
    size_t n;

    entry = aura_hpack_static_tab_get_entry(static_tab, nv->token);
    if (!entry)
        return;

    if (nv->value_interned) {
        *exact_match = entry->header_field->value.interned == nv->value.interned;
        return;
    }

    if (aura_mem_is_eq(nv->value.raw.str->base, nv->value.raw.str->len, entry->header_field->value.raw.str->base, entry->header_field->value.raw.str->len)) {
        *exact_match = true;
    }
}

/**
 * @todo: combine loop to check both name and value, returning a structure of index and exact_match
 */
static struct aura_hpack_table_entry *a_hpack_dyn_tab_search_by_name_or_value(struct aura_hpack_dyn_table *dyn_tab, struct aura_header_field *field, bool is_name) {
    struct aura_hpack_table_entry *entry;

    for (int i = 0; i < dyn_tab->cnt; ++i) {
        entry = &dyn_tab->entries[i];
        entry->index = i + A_DYNAMIC_TABLE_HEADER_OFFSET; /* index in dynamic table */

        if (is_name) {
            if (field->name.interned == entry->header_field->name.interned)
                return entry;
        } else {
            if (entry->header_field->value_interned) {
                if (field->value.interned == entry->header_field->value.interned)
                    return entry;
            } else {
                if (aura_mem_is_eq(field->value.raw.str->base, field->value.raw.str->len, entry->header_field->value.raw.str->base, entry->header_field->value.raw.str->len))
                    return entry;
            }
        }
    }
    return NULL;
}

/**
 * Some semi-naive way of determining binary format
 */
static hpack_binary_format_rep a_determine_encode_binary_format(struct aura_hpack_static_table *static_tab, struct aura_hpack_dyn_table *tb,
                                                                struct aura_header_field *header, int *index) {
    struct aura_hpack_table_entry *tb_entry, *new_tb_entry;
    size_t n;
    bool is_exact_match;

    is_exact_match = false;
    if (header->token > 0 && header->token <= A_TOKEN_WWW_AUTHENTICATE) {
        /* index matches token for now */
        *index = header->token;
        a_hpack_search_static_table(static_tab, header, &is_exact_match);
    } else {
        /* Match header name */
        tb_entry = a_hpack_dyn_tab_search_by_name_or_value(tb, header, true);
        /* Not existent in header table */
        if (!tb_entry)
            *index = 0;
        else
            *index = tb_entry->index;

        if (*index != 0) {
            if (tb_entry->header_field->value_interned) {
                if (header->value.interned == tb_entry->header_field->value.interned)
                    is_exact_match = true;
            } else {
                if (aura_mem_is_eq(header->value.raw.str->base, header->value.raw.str->len, tb_entry->header_field->value.raw.str->base, tb_entry->header_field->value.raw.str->len))
                    is_exact_match = true;
            }
        }

        /* Match header value */
        // tb_entry = a_hpack_dyn_tab_search_by_name_or_value(tb, header, false);
        // if (tb_entry)
        //     is_exact_match = true;

        // for (int i = 0; i < tb->cnt; ++i) {
        //     tb_entry = tb->entries + i;
        //     if (!aura_mem_is_eq(nv->name->base, nv->name->len, tb_entry->name->base, tb_entry->name->len))
        //         continue;
        //     if (nv->index == 0)
        //         /* try to get index in dynamic table */
        //         nv->index = i + A_DYNAMIC_TABLE_HEADER_OFFSET;

        //     /* name matched, check value */
        //     if (!aura_mem_is_eq(nv->value->base, nv->value->len, tb_entry->value->base, tb_entry->value->len))
        //         continue;
        //     /* name and value matched */
        //     is_exact_match = true;
        // }
    }

    if (is_exact_match) {
        return A_HPACK_INDEXED_HDR_FIELD;
    }

    if (*index != 0) {
        if (header->token == A_TOKEN_AUTHORIZATION || header->flags & AURA_TOKEN_NO_COMPRESS) {
            return A_HPACK_LITERAL_HDR_FIELD_NEVER_INDEXED_INDEXED_NAME;
        }

        if (header->token == A_TOKEN_LOCATION || header->token == A_TOKEN_CONTENT_LENGTH)
            return A_HPACK_LITERAL_HDR_FIELD_WITHOUT_INDEXING_INDEXED_NAME;

        return A_HPACK_LITERAL_HDR_FIELD_INCR_INDEXING_INDEXED_NAME;
    } else {
        return A_HPACK_LITERAL_HDR_FIELD_INCR_INDEXING_NEW_NAME;
    }
}

/**
 * Encode new value and add to the dynamic header table
 */
static void a_hpack_dyn_tab_add_new_entry(struct aura_memory_ctx *mc, struct aura_hpack_dyn_table *dyn_tab,
                                          struct aura_header_field *header) {
    struct aura_hpack_table_entry *entry_slot;
    const char *name, *value;
    char *str;
    size_t name_len, value_len;

    if (header) {
        name = header->name.interned->data;
        name_len = header->name.interned->len;

        if (header->value_interned) {
            value = header->value.interned->data;
            value_len = header->value.interned->len;
        } else {
            value = header->value.raw.str->base;
            value_len = header->value.raw.str->len;
        }

        entry_slot = a_dyn_header_table_get_new_slot(mc, dyn_tab, name_len + value_len + A_HEADER_TABLE_ENTRY_OVERHEAD, 128);
        if (entry_slot != NULL) {
            entry_slot->header_field->name.interned = header->name.interned;

            if (header->value_interned) {
                entry_slot->header_field->value.interned = header->value.interned;
                entry_slot->header_field->value_interned = true;
            } else {
                entry_slot->header_field->value.raw = header->value.raw;
                entry_slot->header_field->value.raw.ref_cnt++;
                entry_slot->header_field->value_interned = false;
            }
        }
    }
}

/**
 *
 */
static uint8_t *a_encode_header(struct aura_memory_ctx *mc, struct aura_hpack_static_table *static_tab, struct aura_hpack_dyn_table *dyn_tab,
                                uint8_t *dest, struct aura_header_field *header) {
    hpack_binary_format_rep binary_format;
    int index;

    binary_format = a_determine_encode_binary_format(static_tab, dyn_tab, header, &index);
    switch (binary_format) {
    case A_HPACK_INDEXED_HDR_FIELD:
        *dest = 0x80u;
        dest += a_hpack_encode_int(dest, index, 7);
        break;

    case A_HPACK_LITERAL_HDR_FIELD_NEVER_INDEXED_INDEXED_NAME:
    case A_HPACK_LITERAL_HDR_FIELD_WITHOUT_INDEXING_INDEXED_NAME:
        *dest = 0x10u;
        dest += a_hpack_encode_int(dest, index, 4);
        if (header->value_interned) /* header always interned */
            dest += a_encode_as_original(dest, header->value.interned->data, header->value.interned->len);
        else
            dest += a_encode_as_original(dest, header->value.raw.str->base, header->value.raw.str->len);
        break;

    case A_HPACK_LITERAL_HDR_FIELD_INCR_INDEXING_INDEXED_NAME:
        *dest = 0x40u;
        dest += a_hpack_encode_int(dest, index, 6);
        if (header->value_interned)
            dest += a_hpack_encode_string(dest, header->value.interned->data, header->value.interned->len);
        else
            dest += a_hpack_encode_string(dest, header->value.raw.str->base, header->value.raw.str->len);
        a_hpack_dyn_tab_add_new_entry(mc, dyn_tab, header);
        break;

    default:
        *dest++ = 0x40u;
        dest += a_hpack_encode_string(dest, header->name.interned->data, header->name.interned->len);

        if (header->value_interned)
            dest += a_hpack_encode_string(dest, header->value.interned->data, header->value.interned->len);
        else
            dest += a_hpack_encode_string(dest, header->value.raw.str->base, header->value.raw.str->len);
        a_hpack_dyn_tab_add_new_entry(mc, dyn_tab, header);
        break;
    }

    return dest;
}

uint8_t *aura_encode_header(struct aura_memory_ctx *mc, struct aura_hpack_static_table *static_tab,
                            struct aura_hpack_dyn_table *dyn_tab, uint8_t *dest,
                            struct aura_header_field *header) {
    return a_encode_header(mc, static_tab, dyn_tab, dest, header);
}

/**
 *
 */
static uint8_t *encode_method(struct aura_memory_ctx *mc, struct aura_hpack_static_table *static_tab,
                              struct aura_hpack_dyn_table *dyn_tab, struct aura_intern_tab *intern_tab,
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

    struct aura_header_field *header;
    header = aura_header_find_or_create(mc, static_tab, dyn_tab, intern_tab, str_lit(":method"), value.base, value.len);
    return a_encode_header(mc, static_tab, dyn_tab, dest, header);
}

/**
 *
 */
static uint8_t *encode_scheme(struct aura_memory_ctx *mc, struct aura_hpack_static_table *static_tab,
                              struct aura_hpack_dyn_table *dyn_tab, struct aura_intern_tab *intern_tab,
                              uint8_t *dest, struct aura_iovec *scheme) {

    if (aura_mem_is_eq(scheme->base, scheme->len, str_lit("HTTP"))) {
        /* from hpack static table */
        *dest++ = 0x86;
        return dest;
    }

    if (aura_mem_is_eq(scheme->base, scheme->len, str_lit("HTTPS"))) {
        /* from hpack static table */
        *dest++ = 0x87;
        return dest;
    }

    struct aura_header_field *header;
    header = aura_header_find_or_create(mc, static_tab, dyn_tab, intern_tab, str_lit(":scheme"), scheme->base, scheme->len);
    return a_encode_header(mc, static_tab, dyn_tab, dest, header);
}

/**
 *
 */
static uint8_t *encode_path(struct aura_memory_ctx *mc, struct aura_hpack_static_table *static_tab,
                            struct aura_hpack_dyn_table *dyn_tab, struct aura_intern_tab *intern_tab,
                            uint8_t *dest, struct aura_iovec value) {
    if (aura_mem_is_eq(value.base, value.len, str_lit("/"))) {
        *dest++ = 0x84; /* from hpack static table */
        return dest;
    }

    if (aura_mem_is_eq(value.base, value.len, str_lit("/index.html"))) {
        *dest++ = 0x85; /* from hpack static table */
        return dest;
    }

    struct aura_header_field *header;
    header = aura_header_find_or_create(mc, static_tab, dyn_tab, intern_tab, str_lit(":path"), value.base, value.len);

    return a_encode_header(mc, static_tab, dyn_tab, dest, header);
}

/**
 *
 */
static uint8_t *encode_literal_header_without_indexing(uint8_t *dest, const struct aura_iovec *name, const struct aura_iovec *value) {
    /* Literal header without indexing, pattern: | 0: | */
    *dest++ = 0;
    dest += a_hpack_encode_string(dest, name->base, name->len);
    dest += a_hpack_encode_string(dest, value->base, value->len);
    return dest;
}

int aura_hpack_load_static_table(struct aura_hpack_static_table *tab, struct aura_intern_tab *intern_tab) {
    struct rfc_static_tab_entry entry;
    for (int i = 0; i < ARRAY_SIZE(rfc_static_table); ++i) {
        entry = rfc_static_table[i];
        tab->entries[i].header_field = aura_header_field_create(intern_tab, entry.name.base, entry.name.len, entry.value.base, entry.value.len);
        if (!tab->entries[i].header_field && (entry.name.len || entry.value.len))
            return -1;
        tab->entries[i].index = i;
    }
    return 0;
}